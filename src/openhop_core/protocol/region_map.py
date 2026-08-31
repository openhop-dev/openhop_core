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


def capture_recv_region(
    region_map: Optional[RegionMap],
    pkt: Packet,
    default_key: Optional[bytes] = None,
) -> None:
    """Record the region a received packet arrived under, onto the packet.

    Shared by both RX entrypoints (``Dispatcher._process_received_packet`` and
    ``CompanionBridge.process_received_packet``) so capture is identical.
    Mirrors firmware ``recv_pkt_region`` capture:

    - ``TRANSPORT_FLOOD``: match against ``REGION_DENY_FLOOD``-honouring regions
      and record that region's (single) key.
    - ``FLOOD``: record whether the wildcard permits it. An allowed wildcard
      mirrors the request as unscoped; a denied wildcard falls back to DEFAULT.
    - Direct or unresolved transport scope: fall back to ``default_key``.

    A ``None`` region_map (standalone companion) is a no-op: ``_recv_region_captured``
    stays False, so a reply falls through to the dispatcher default.
    """
    if region_map is None:
        return
    if default_key is None and getattr(pkt, "_recv_region_captured", False):
        # The host dispatcher may already have captured a valid default before
        # handing this same Packet to a CompanionBridge. Do not erase that
        # snapshot merely because the bridge has no duplicate key configured.
        default_key = getattr(pkt, "_recv_default_scope_key", None)
    pkt._recv_region_captured = True
    pkt._recv_default_scope_key = default_key
    pkt._recv_region_unscoped = False
    if pkt.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD:
        entry = region_map.find_match(pkt, mask=REGION_DENY_FLOOD)
        if entry is not None and entry.is_wildcard():
            pkt._recv_region_key = None
            pkt._recv_region_unscoped = True
        else:
            pkt._recv_region_key = region_map.first_key_for(entry)
    elif pkt.get_route_type() == ROUTE_TYPE_FLOOD:
        pkt._recv_region_key = None
        pkt._recv_region_unscoped = not (region_map.wildcard.flags & REGION_DENY_FLOOD)
    else:
        pkt._recv_region_key = None


def apply_reply_scope(
    reply_pkt: Packet,
    request_pkt: Optional[Packet],
    default_key: Optional[bytes] = None,
) -> None:
    """Scope a freshly-built flood reply per firmware ``chooseReplyScope``.

    Re-hashes the transport code over the reply's own payload — never the
    request's code.

    - Not captured (standalone companion, ``region_map`` None): return without
      marking, so the reply falls through to the dispatcher default.
    - Captured + known request region: REQUEST (scope with that key).
    - Captured + unscoped flood: NONE (plain, marked so a node default cannot
      override the requester's choice).
    - Captured + direct / unresolved region: DEFAULT if a default key is
      available (argument or snapshotted at capture), else NONE (plain).

    In every captured case the reply is marked ``_flood_scope_applied`` so the
    dispatcher's node-default scope cannot override this decision.
    """
    if not getattr(request_pkt, "_recv_region_captured", False):
        return
    req_key = getattr(request_pkt, "_recv_region_key", None)
    if default_key is None:
        default_key = getattr(request_pkt, "_recv_default_scope_key", None)
    scope = choose_reply_scope(
        req_key is not None,
        bool(getattr(request_pkt, "_recv_region_unscoped", False)),
        default_key is not None,
    )
    if (
        scope == REPLY_SCOPE_REQUEST
        and req_key is not None
        and reply_pkt.get_route_type() == ROUTE_TYPE_FLOOD
    ):
        scope_packet(reply_pkt, req_key)
    elif (
        scope == REPLY_SCOPE_DEFAULT
        and default_key is not None
        and reply_pkt.get_route_type() == ROUTE_TYPE_FLOOD
    ):
        scope_packet(reply_pkt, default_key)
    reply_pkt._flood_scope_applied = True
