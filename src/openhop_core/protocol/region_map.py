"""Minimal region helpers built on top of transport keys."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence

from .constants import ROUTE_TYPE_FLOOD, ROUTE_TYPE_TRANSPORT_FLOOD
from .packet import Packet
from .transport_keys import calc_transport_code, get_auto_key_for, scope_packet

# Region flags mirror the MeshCore C++ definitions in RegionMap.h
REGION_DENY_FLOOD = 0x01
REGION_DENY_DIRECT = 0x02  # reserved for future use


@dataclass
class RegionEntry:
    """Single region definition."""

    id: int
    parent: int = 0
    flags: int = 0
    name: str = ""
    private_keys: Optional[List[bytes]] = None

    def is_wildcard(self) -> bool:
        """True for the root/wildcard Region (MeshCore ``RegionEntry::isWildcard``)."""
        return self.id == 0


class RegionMap:
    """In-memory region registry with packet→region matching."""

    def __init__(self, regions: Optional[Iterable[RegionEntry]] = None) -> None:
        self._regions: list[RegionEntry] = list(regions or [])
        # Root Region, held outside ``_regions`` exactly as firmware holds it
        # outside ``regions[]``: ``findMatch`` never returns it, but an un-scoped
        # FLOOD is considered to have arrived "under" it unless its flags deny
        # flood. Defaults mirror ``RegionMap::RegionMap`` (id/parent 0, flags 0
        # = allow, name "*"). Applications set ``wildcard.flags`` to configure it.
        #
        # Scope: REGION_DENY_FLOOD here affects only how a *reply* is scoped
        # (see capture_recv_region). Firmware also consults recv_pkt_region in
        # the repeater's allowPacketForward to refuse relaying a flood whose
        # region is unresolved; this port has no repeater allowPacketForward at
        # all (forwarding is the companion's client-repeat gate), so setting the
        # flag does not stop un-scoped floods being relayed.
        self.wildcard: RegionEntry = RegionEntry(id=0, parent=0, flags=0, name="*")

    # ------------------------------------------------------------------
    # Basic CRUD
    # ------------------------------------------------------------------
    def add_region(self, entry: RegionEntry) -> None:
        self._regions.append(entry)

    def extend(self, entries: Sequence[RegionEntry]) -> None:
        self._regions.extend(entries)

    @property
    def regions(self) -> list[RegionEntry]:
        return list(self._regions)

    # ------------------------------------------------------------------
    # Matching helpers
    # ------------------------------------------------------------------
    def _iter_region_keys(self, region: RegionEntry) -> Iterable[bytes]:
        """Yield all transport keys for a region."""
        name = region.name or ""

        # Private region ($): only stored keys are ever used. A private region
        # with no stored key yields nothing and is never auto-hashed, matching
        # MeshCore RegionMap::getTransportKeysFor. Falling through to name
        # hashing would silently turn an unusable private region into a
        # deterministic public "#$name" scope.
        if name.startswith("$"):
            for key in region.private_keys or ():
                if len(key) == 16:
                    yield key
            return

        # Other regions: caller may supply explicit keys (e.g. from secure store)
        if region.private_keys:
            for key in region.private_keys:
                if len(key) == 16:
                    yield key
            return

        if not name:
            return

        # Public hashtag region: firmware treats names starting with '#' as
        # canonical, and everything else as an "implicit hashtag" region.
        if name[0] == "#":
            canonical = name
        else:
            canonical = f"#{name}"

        # Reuse the existing SHA-256 → 16-byte key logic
        try:
            yield get_auto_key_for(canonical)
        except ValueError:
            # Invalid region name; ignore it rather than raising in callers.
            return

    def first_key_for(self, region: Optional[RegionEntry]) -> Optional[bytes]:
        """Return the first transport key for ``region``, or None.

        Mirrors MeshCore ``RegionMap::getTransportKeysFor(..., max_num=1)``: a
        region resolves to at most one key here (the first one yielded), and a
        region with no usable key (e.g. an empty private ``$`` region) yields
        None => the caller replies plain.
        """
        if region is None:
            return None
        for key in self._iter_region_keys(region):
            return key
        return None

    def find_match(self, packet: Packet, *, mask: int = 0) -> Optional[RegionEntry]:
        """Return the first RegionEntry whose scope matches this packet.

        Args:
            packet: Parsed Packet instance with transport_codes populated.
            mask: Bitmask of REGION_DENY_* flags to honour. Regions where
                ``flags & mask != 0`` are skipped (mirrors C++ behaviour).

        Returns:
            The first matching RegionEntry, or None if no match is found.
        """
        # No transport code present → cannot match to a region.
        if not packet.has_transport_codes():
            return None

        code = packet.transport_codes[0]
        if not code:
            return None

        for region in self._regions:
            # Skip regions that explicitly deny this traffic type.
            if region.flags & mask:
                continue
            for key in self._iter_region_keys(region):
                try:
                    expected = calc_transport_code(key, packet)
                except Exception:
                    continue
                if expected == code:
                    return region
        return None


def capture_recv_region(region_map: Optional[RegionMap], pkt: Packet) -> None:
    """Record the region a received packet arrived under, onto the packet.

    Shared by both RX entrypoints (``Dispatcher._process_received_packet`` and
    ``CompanionBridge.process_received_packet``) so capture is identical.
    Mirrors firmware ``recv_pkt_region`` capture (``simple_repeater``'s
    ``MyMesh::onRecvPacket``), which distinguishes three outcomes, not two:

    - ``TRANSPORT_FLOOD``: match against ``REGION_DENY_FLOOD``-honouring regions
      and record that region's (single) key. ``findMatch`` iterates the region
      list only and never returns the wildcard, so an unresolved transport code
      lands in the third case below, not the second.
    - ``FLOOD``: firmware sets ``recv_pkt_region = &getWildcard()`` unless the
      wildcard denies flood. Record that as ``_recv_region_unscoped`` — the
      request chose un-scoped, and :func:`apply_reply_scope` mirrors it.
    - Direct, an unresolved transport code, a region with no usable key, or a
      wildcard that denies flood: firmware leaves ``recv_pkt_region`` NULL (or
      resolves no key), which is *scope unknowable* rather than *un-scoped*.
      Both flags stay clear and the reply falls back to the node default.

    A ``None`` region_map (standalone companion) is a no-op: ``_recv_region_captured``
    stays False, so a reply falls through to the dispatcher default.
    """
    if region_map is None:
        return
    pkt._recv_region_captured = True
    pkt._recv_region_unscoped = False
    route_type = pkt.get_route_type()
    if route_type == ROUTE_TYPE_TRANSPORT_FLOOD:
        entry = region_map.find_match(pkt, mask=REGION_DENY_FLOOD)
        # Firmware tests isWildcard() on the match before resolving any key, and
        # treats a wildcard match as un-scoped. Its findMatch cannot return the
        # wildcard (ids are handed out from next_id, so nothing in regions[] has
        # id 0), but nothing here stops an application registering a RegionEntry
        # with id 0, so honour the same precedence rather than scoping a reply
        # firmware would have sent plain.
        if entry is not None and entry.is_wildcard():
            pkt._recv_region_key = None
            pkt._recv_region_unscoped = True
        else:
            pkt._recv_region_key = region_map.first_key_for(entry)
    elif route_type == ROUTE_TYPE_FLOOD:
        pkt._recv_region_key = None
        pkt._recv_region_unscoped = not (region_map.wildcard.flags & REGION_DENY_FLOOD)
    else:
        pkt._recv_region_key = None


def apply_reply_scope(reply_pkt: Packet, request_pkt: Optional[Packet]) -> None:
    """Scope a freshly-built flood reply to the region its request arrived under.

    Mirrors firmware ``chooseReplyScope`` (``helpers/RoutingPolicy.h``, upstream
    PR #3106) as driven by ``sendFloodReply``. A repeater/room-server reply
    carries the request's region, re-hashing the transport code over the
    *reply's* own payload — never the request's code:

    - Not captured (standalone companion, ``region_map`` None): return without
      marking, so the reply falls through to the dispatcher default. This is
      companion parity: ``BaseChatMesh::onPeerDataRecv`` answers with
      ``sendFloodScoped(from, ...)``, which does consult the node default.
    - ``REPLY_SCOPE_REQUEST`` — captured with a key: scope the reply with it
      (a plain FLOOD becomes TRANSPORT_FLOOD) and mark the decision final.
    - ``REPLY_SCOPE_NONE`` — the request arrived as an un-scoped flood: mirror
      that and mark the decision final, so the node default cannot scope a
      reply on a path that works un-scoped today. (Repeaters that do not hold
      our default Region would drop a scoped reply anyway.)
    - ``REPLY_SCOPE_DEFAULT`` — the request's scope is unknowable (it arrived
      DIRECT and so carried no transport codes, or its code matched no Region):
      leave the reply unmarked, so ``Dispatcher._apply_flood_scope`` applies the
      node's ordinary send precedence at TX time. Replying un-scoped here is the
      bug PR #3106 fixed: repeaters running ``flood.max.unscoped=0`` drop such a
      reply at hop 0. On a repeater that precedence is just the persisted
      default, which is exactly ``sendFloodScoped(default_scope, ...)``; on a
      companion it also honours the transient override and the explicit-unscoped
      flag, which is what firmware's ``sendFloodScoped(recipient)`` — the
      overload ``BaseChatMesh`` answers with — does for the same case. With no
      scope configured at all the send stays plain, firmware's final
      ``REPLY_SCOPE_NONE`` fallback.

    Only the first two decisions set ``_flood_scope_applied``; that mark exists
    to stop the node default reaching a reply whose scope this helper *did*
    decide, so the deferring case must not set it.
    """
    if not getattr(request_pkt, "_recv_region_captured", False):
        return
    key = getattr(request_pkt, "_recv_region_key", None)
    if key is not None:
        if reply_pkt.get_route_type() == ROUTE_TYPE_FLOOD:
            scope_packet(reply_pkt, key)
        reply_pkt._flood_scope_applied = True
        return
    if getattr(request_pkt, "_recv_region_unscoped", False):
        reply_pkt._flood_scope_applied = True
        return
    # REPLY_SCOPE_DEFAULT: deliberately left unmarked -- see the docstring.
