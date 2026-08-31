"""Tests for the lightweight RegionMap helper."""

from __future__ import annotations

from openhop_core.protocol import LocalIdentity, Packet, PacketBuilder
from openhop_core.protocol.constants import (
    ROUTE_TYPE_DIRECT,
    ROUTE_TYPE_FLOOD,
    ROUTE_TYPE_TRANSPORT_FLOOD,
)
from openhop_core.protocol.region_map import (
    REGION_DENY_FLOOD,
    REPLY_SCOPE_DEFAULT,
    REPLY_SCOPE_NONE,
    REPLY_SCOPE_REQUEST,
    RegionEntry,
    RegionMap,
    apply_reply_scope,
    capture_recv_region,
    choose_reply_scope,
)
from openhop_core.protocol.transport_keys import calc_transport_code, get_auto_key_for


def _make_scoped_packet(region_name: str) -> Packet:
    """Create a transport-flood advert tagged for the given public region."""
    identity = LocalIdentity()
    pkt = PacketBuilder.create_advert(
        local_identity=identity,
        name="test",
        route_type="flood",
    )
    # Derive key/code exactly as CompanionBase._apply_flood_scope does
    if not region_name.startswith("#"):
        region_name = f"#{region_name}"
    key = get_auto_key_for(region_name)
    code = calc_transport_code(key, pkt)
    pkt.transport_codes[0] = code
    pkt.transport_codes[1] = 0
    pkt.header = (pkt.header & ~0x03) | ROUTE_TYPE_TRANSPORT_FLOOD
    return pkt


class TestRegionMapMatching:
    def test_match_explicit_hashtag_name(self):
        region = RegionEntry(id=1, name="#nl-li")
        rmap = RegionMap([region])
        pkt = _make_scoped_packet("#nl-li")

        match = rmap.find_match(pkt)

        assert match is not None
        assert match.id == 1
        assert match.name == "#nl-li"

    def test_match_implicit_hashtag_name(self):
        # Firmware treats "name" and "#name" the same for auto regions.
        region = RegionEntry(id=2, name="nl-li")
        rmap = RegionMap([region])
        pkt = _make_scoped_packet("nl-li")

        match = rmap.find_match(pkt)

        assert match is not None
        assert match.id == 2
        assert match.name == "nl-li"

    def test_respects_region_deny_flag(self):
        """Region with REGION_DENY_FLOOD is ignored when mask requests flood filtering."""
        allowed = RegionEntry(id=3, name="#allowed")
        denied = RegionEntry(id=4, name="#denied", flags=REGION_DENY_FLOOD)
        rmap = RegionMap([denied, allowed])

        pkt = _make_scoped_packet("#denied")

        # With mask=0, the denied region is still eligible and should match.
        match_any = rmap.find_match(pkt, mask=0)
        assert match_any is not None
        assert match_any.id == 4

        # With REGION_DENY_FLOOD mask, denied region is skipped → no match.
        match_filtered = rmap.find_match(pkt, mask=REGION_DENY_FLOOD)
        assert match_filtered is None


class TestChooseReplyScope:
    """Firmware RoutingPolicy.h chooseReplyScope vectors."""

    def test_mirrors_known_request_scope(self):
        assert choose_reply_scope(True, False, False) == REPLY_SCOPE_REQUEST
        assert choose_reply_scope(True, False, True) == REPLY_SCOPE_REQUEST

    def test_unscoped_flood_stays_none_even_with_default(self):
        assert choose_reply_scope(False, True, True) == REPLY_SCOPE_NONE

    def test_falls_back_to_default_when_request_scope_unknown(self):
        assert choose_reply_scope(False, False, True) == REPLY_SCOPE_DEFAULT

    def test_none_when_no_scope_available(self):
        assert choose_reply_scope(False, False, False) == REPLY_SCOPE_NONE
        assert choose_reply_scope(False, True, False) == REPLY_SCOPE_NONE


class TestApplyReplyScopeDefault:
    def test_direct_request_uses_captured_default_key(self):
        default_key = get_auto_key_for("#default-region")
        req = Packet()
        req.header = ROUTE_TYPE_DIRECT
        req._recv_region_captured = True
        req._recv_region_key = None
        req._recv_default_scope_key = default_key

        reply = PacketBuilder.create_advert(
            local_identity=LocalIdentity(), name="x", route_type="flood"
        )
        apply_reply_scope(reply, req)
        assert reply.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD
        assert reply.transport_codes[0] == calc_transport_code(default_key, reply)
        assert reply._flood_scope_applied is True


class TestCaptureRecvRegion:
    def test_second_capture_without_default_preserves_dispatcher_snapshot(self):
        """Bridge delegation must not erase a default captured by the dispatcher."""
        default_key = get_auto_key_for("#default-region")
        req = Packet()
        req.header = ROUTE_TYPE_DIRECT

        capture_recv_region(RegionMap(), req, default_key=default_key)
        capture_recv_region(RegionMap(), req, default_key=None)

        assert req._recv_default_scope_key == default_key

    def test_plain_flood_uses_default_when_wildcard_denies_flood(self):
        default_key = get_auto_key_for("#default-region")
        region_map = RegionMap()
        region_map.wildcard.flags |= REGION_DENY_FLOOD
        req = Packet()
        req.header = ROUTE_TYPE_FLOOD

        capture_recv_region(region_map, req, default_key=default_key)
        assert req._recv_region_unscoped is False

        reply = PacketBuilder.create_advert(
            local_identity=LocalIdentity(), name="x", route_type="flood"
        )
        apply_reply_scope(reply, req)
        assert reply.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD
        assert reply.transport_codes[0] == calc_transport_code(default_key, reply)
