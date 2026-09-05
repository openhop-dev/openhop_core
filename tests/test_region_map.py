"""Tests for the lightweight RegionMap helper."""

from __future__ import annotations

from openhop_core.node.dispatcher import Dispatcher
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


class _MockRadio:
    """Minimal radio so a Dispatcher can be built for its TX-time scoping."""

    def set_rx_callback(self, callback):
        pass

    async def send(self, data: bytes) -> bool:
        return True


def _resolve_at_tx(reply, *, default_key=None, override=None, unscoped=False):
    """Run a built reply through the send layer, as an actual TX would.

    ``apply_reply_scope`` defers the DEFAULT case, so a test that wants to see
    the resulting scope has to ask the layer that decides it.
    """
    dispatcher = Dispatcher(_MockRadio())
    dispatcher.default_flood_transport_key = default_key
    dispatcher.flood_transport_key = override
    dispatcher.flood_unscoped = unscoped
    dispatcher._apply_flood_scope(reply)
    return reply


def _flood_reply():
    return PacketBuilder.create_advert(local_identity=LocalIdentity(), name="x", route_type="flood")


class TestApplyReplyScopeDefault:
    """REPLY_SCOPE_DEFAULT is deferred to the send layer, not resolved here."""

    def test_direct_request_defers_to_the_send_layer(self):
        """A DIRECT request carries no transport codes, so its scope is
        unknowable. The helper must leave the reply unmarked so the ordinary
        precedence runs -- marking it would suppress that chain entirely."""
        req = Packet()
        req.header = ROUTE_TYPE_DIRECT
        capture_recv_region(RegionMap(), req)

        reply = _flood_reply()
        apply_reply_scope(reply, req)

        assert reply._flood_scope_applied is False
        assert reply.get_route_type() == ROUTE_TYPE_FLOOD

    def test_deferred_direct_request_then_takes_the_node_default(self):
        """Firmware's repeater answers this case with
        ``sendFloodScoped(default_scope, ...)``; here the same key arrives via
        the send layer. This is the behaviour MeshCore PR #3106 added -- an
        un-scoped reply is dropped at hop 0 by ``flood.max.unscoped=0``."""
        default_key = get_auto_key_for("#default-region")
        req = Packet()
        req.header = ROUTE_TYPE_DIRECT
        capture_recv_region(RegionMap(), req)

        reply = _flood_reply()
        apply_reply_scope(reply, req)
        _resolve_at_tx(reply, default_key=default_key)

        assert reply.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD
        assert reply.transport_codes[0] == calc_transport_code(default_key, reply)

    def test_deferred_direct_request_honours_explicit_unscoped(self):
        """A node told to force un-scoped floods keeps doing so. Firmware's
        companion overload checks ``send_unscoped`` before any scope; resolving
        DEFAULT inside the helper would silently override the operator."""
        default_key = get_auto_key_for("#default-region")
        req = Packet()
        req.header = ROUTE_TYPE_DIRECT
        capture_recv_region(RegionMap(), req)

        reply = _flood_reply()
        apply_reply_scope(reply, req)
        _resolve_at_tx(reply, default_key=default_key, unscoped=True)

        assert reply.get_route_type() == ROUTE_TYPE_FLOOD
        assert reply.transport_codes == [0, 0]

    def test_deferred_direct_request_honours_the_transient_override(self):
        """``send_scope`` beats ``default_scope`` in firmware's companion
        overload, so the reply must carry the override, not the default."""
        default_key = get_auto_key_for("#default-region")
        override = get_auto_key_for("#override-region")
        req = Packet()
        req.header = ROUTE_TYPE_DIRECT
        capture_recv_region(RegionMap(), req)

        reply = _flood_reply()
        apply_reply_scope(reply, req)
        _resolve_at_tx(reply, default_key=default_key, override=override)

        assert reply.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD
        assert reply.transport_codes[0] == calc_transport_code(override, reply)

    def test_deferred_direct_request_with_no_scope_stays_plain(self):
        """Firmware's final ``REPLY_SCOPE_NONE``: nothing configured, so the
        reply goes out a plain flood."""
        req = Packet()
        req.header = ROUTE_TYPE_DIRECT
        capture_recv_region(RegionMap(), req)

        reply = _flood_reply()
        apply_reply_scope(reply, req)
        _resolve_at_tx(reply)

        assert reply.get_route_type() == ROUTE_TYPE_FLOOD


class TestCaptureRecvRegion:
    def test_wildcard_denying_flood_makes_the_scope_unknowable(self):
        """Firmware leaves ``recv_pkt_region`` NULL when the wildcard denies
        FLOOD, which is *unknowable*, not *un-scoped*: the reply must defer
        rather than mirror the request as plain."""
        default_key = get_auto_key_for("#default-region")
        region_map = RegionMap()
        region_map.wildcard.flags |= REGION_DENY_FLOOD
        req = Packet()
        req.header = ROUTE_TYPE_FLOOD

        capture_recv_region(region_map, req)
        assert req._recv_region_unscoped is False

        reply = _flood_reply()
        apply_reply_scope(reply, req)
        assert reply._flood_scope_applied is False

        _resolve_at_tx(reply, default_key=default_key)
        assert reply.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD
        assert reply.transport_codes[0] == calc_transport_code(default_key, reply)

    def test_allowed_wildcard_flood_is_mirrored_as_unscoped(self):
        """An allowed wildcard means the requester chose un-scoped. That is a
        decision, so it is marked final and a node default cannot override it."""
        default_key = get_auto_key_for("#default-region")
        req = Packet()
        req.header = ROUTE_TYPE_FLOOD

        capture_recv_region(RegionMap(), req)
        assert req._recv_region_unscoped is True

        reply = _flood_reply()
        apply_reply_scope(reply, req)
        assert reply._flood_scope_applied is True

        _resolve_at_tx(reply, default_key=default_key)
        assert reply.get_route_type() == ROUTE_TYPE_FLOOD
