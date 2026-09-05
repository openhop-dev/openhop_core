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

# Firmware helpers/RoutingPolicy.h ReplyScope
REPLY_SCOPE_REQUEST = "request"
REPLY_SCOPE_DEFAULT = "default"
REPLY_SCOPE_NONE = "none"


@dataclass
class RegionEntry:
    """Single region definition."""

    id: int
    parent: int = 0
    flags: int = 0
    name: str = ""
    private_keys: Optional[List[bytes]] = None

    def is_wildcard(self) -> bool:
        """Return whether this is firmware's root/wildcard region."""
        return self.id == 0


class RegionMap:
    """In-memory region registry with packet→region matching."""

    def __init__(self, regions: Optional[Iterable[RegionEntry]] = None) -> None:
        self._regions: list[RegionEntry] = list(regions or [])
        # Firmware keeps the wildcard outside its ordinary region array. A
        # plain FLOOD arrived under this region only when it allows flooding;
        # when denied, reply scope is unknowable and falls back to DEFAULT.
        self.wildcard = RegionEntry(id=0, parent=0, flags=0, name="*")

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


def choose_reply_scope(
    request_scope_known: bool,
    request_was_unscoped_flood: bool,
    default_scope_known: bool,
) -> str:
    """Which transport scope a flooded reply should use.

    Mirrors firmware ``RoutingPolicy.h`` ``chooseReplyScope``:
    known request region → REQUEST; unscoped flood → NONE (mirror the
    requester); otherwise DEFAULT if the node has a default region, else NONE.
    """
    if request_scope_known:
        return REPLY_SCOPE_REQUEST
    if request_was_unscoped_flood:
        return REPLY_SCOPE_NONE
    if default_scope_known:
        return REPLY_SCOPE_DEFAULT
    return REPLY_SCOPE_NONE


def capture_recv_region(region_map: Optional[RegionMap], pkt: Packet) -> None:
    """Record the region a received packet arrived under, onto the packet.

    Shared by both RX entrypoints (``Dispatcher._process_received_packet`` and
    ``CompanionBridge.process_received_packet``) so capture is identical.
    Mirrors firmware ``recv_pkt_region`` capture, which distinguishes three
    outcomes rather than two:

    - ``TRANSPORT_FLOOD``: match against ``REGION_DENY_FLOOD``-honouring regions
      and record that region's (single) key. Firmware tests ``isWildcard()`` on
      the match before resolving any key. Its ``findMatch`` iterates the region
      list only and so cannot return the wildcard -- ids are handed out from
      ``next_id``, so nothing in ``regions[]`` has id 0 -- but nothing here stops
      an application registering a RegionEntry with id 0, so honour the same
      precedence rather than scoping a reply firmware would have sent plain.
    - ``FLOOD``: firmware sets ``recv_pkt_region = &getWildcard()`` unless the
      wildcard denies flood. Recorded as ``_recv_region_unscoped`` -- the
      requester chose un-scoped, and :func:`apply_reply_scope` mirrors it.
    - Direct, an unresolved transport code, a region with no usable key, or a
      wildcard that denies flood: firmware leaves ``recv_pkt_region`` NULL, which
      is *scope unknowable* rather than *un-scoped*. Both flags stay clear and
      the reply defers to the ordinary send precedence.

    A ``None`` region_map (standalone node/companion) is a no-op:
    ``_recv_region_captured`` stays False, so a reply falls through to that same
    precedence.
    """
    if region_map is None:
        return
    if getattr(pkt, "_recv_region_captured", False):
        # Firmware captures ``recv_pkt_region`` exactly once, in onRecvPacket,
        # and every later consumer reads that one decision. Here a Packet can
        # reach two entrypoints -- the dispatcher, then a CompanionBridge the
        # host delegates it to -- with awaits and flood hold time in between,
        # during which the shared RegionMap can be rebuilt (the repeater
        # hot-reloads it on a transport-key change). Keep the first capture: it
        # is the one taken against the map that was live when the packet
        # actually arrived.
        return
    pkt._recv_region_captured = True
    pkt._recv_region_unscoped = False
    route_type = pkt.get_route_type()
    if route_type == ROUTE_TYPE_TRANSPORT_FLOOD:
        entry = region_map.find_match(pkt, mask=REGION_DENY_FLOOD)
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
    """Scope a freshly-built flood reply per firmware ``chooseReplyScope``.

    Re-hashes the transport code over the reply's own payload -- never copies
    the request's code.

    Rows are :func:`choose_reply_scope`'s, which is the literal firmware
    predicate (``RoutingPolicy.h``); this function decides the two the capture
    can answer on its own and defers the other two:

    1. ``REPLY_SCOPE_REQUEST`` -- captured with a key: scope the reply with it
       and mark the decision final.
    2. ``REPLY_SCOPE_NONE``, un-scoped flood: mirror that and mark it final, so
       a node default cannot scope a reply on a path that demonstrably works
       un-scoped today.
    3/4. ``REPLY_SCOPE_DEFAULT``, and the ``REPLY_SCOPE_NONE`` firmware reaches
       for want of any default: these turn on whether a scope is configured,
       which is the send layer's to know. Return unmarked and let it answer.

    Not captured at all (standalone node, ``region_map`` None) also returns
    unmarked, so the reply falls through to that same precedence.

    Only rows 1 and 2 set ``_flood_scope_applied``. That mark stops the node
    default reaching a reply whose scope *this* helper decided, so the deferring
    rows must not set it.

    Why rows 3 and 4 defer. Firmware splits them by role. A repeater resolves
    DEFAULT as ``sendFloodScoped(default_scope, ...)``
    (``simple_repeater/MyMesh.cpp``), while a companion answers the same case
    with ``sendFloodScoped(recipient, ...)``, which is ``send_unscoped`` first,
    then ``send_scope``, else ``default_scope``
    (``companion_radio/MyMesh.cpp``). One helper here serves both roles, and
    ``Dispatcher._apply_flood_scope`` / ``CompanionBase._apply_flood_scope``
    already implement that precedence -- including firmware's final NONE, since
    a node with nothing configured leaves the packet a plain flood. Deciding
    here would duplicate the chain and, by marking the packet, suppress it: an
    operator's explicit-unscoped flag and transient override would both be
    silently overridden. It would also bind the reply to the default as it
    stood at RX rather than at TX.

    Caller contract: the reply must reach the radio through one of those two
    resolvers. Every send path in this tree does -- a handler reply travels
    ``Dispatcher.send_packet``, and a ``CompanionBridge`` reply travels the
    host's packet injector, which for the repeater ends at the same call. An
    application that serializes a deferred reply straight to a radio would put
    it on air plain.

    Known divergence, deliberate: rows 3 and 4 reach a precedence that also
    honours the transient override and the explicit-unscoped flag, because the
    companion role requires it. Firmware's *repeater* has neither concept, so a
    node holding a RegionMap and an override but no default would send the
    reply scoped where firmware's repeater sends it plain. No topology here
    reaches that state -- ``CompanionBridge`` never writes those dispatcher
    fields, and a ``CompanionRadio`` owns its own dispatcher, where honouring
    them is the correct companion behaviour.

    Replying un-scoped in rows 3/4 is the bug MeshCore PR #3106 fixed: a
    repeater on the way back running ``flood.max.unscoped=0`` drops such a reply
    at hop 0. The fix is that a configured default now reaches it -- which it
    does through the send layer.
    """
    if not getattr(request_pkt, "_recv_region_captured", False):
        return
    req_key = getattr(request_pkt, "_recv_region_key", None)
    if req_key is not None:
        # Row 1: REPLY_SCOPE_REQUEST.
        if reply_pkt.get_route_type() == ROUTE_TYPE_FLOOD:
            scope_packet(reply_pkt, req_key)
        reply_pkt._flood_scope_applied = True
        return
    if getattr(request_pkt, "_recv_region_unscoped", False):
        # Row 2: REPLY_SCOPE_NONE, mirroring the requester's un-scoped choice.
        reply_pkt._flood_scope_applied = True
        return
    # Rows 3 and 4: left unmarked for the send layer.
