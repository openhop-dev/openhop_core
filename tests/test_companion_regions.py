"""Tests for companion flood-scope / region support."""

from __future__ import annotations

import asyncio

import pytest

from openhop_core.companion import CompanionBridge, CompanionRadio
from openhop_core.companion.models import Channel
from openhop_core.protocol import LocalIdentity, Packet, PacketBuilder
from openhop_core.protocol.constants import (
    ROUTE_TYPE_DIRECT,
    ROUTE_TYPE_FLOOD,
    ROUTE_TYPE_TRANSPORT_FLOOD,
)
from openhop_core.protocol.transport_keys import calc_transport_code, get_auto_key_for

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_flood_packet() -> Packet:
    """Create a minimal flood-routed advert packet for testing."""
    identity = LocalIdentity()
    return PacketBuilder.create_advert(
        local_identity=identity,
        name="test",
        route_type="flood",
    )


def _make_direct_packet() -> Packet:
    """Create a minimal direct-routed advert packet for testing."""
    identity = LocalIdentity()
    return PacketBuilder.create_advert(
        local_identity=identity,
        name="test",
        route_type="direct",
    )


class MockRadio:
    """Minimal mock radio for CompanionRadio."""

    def __init__(self):
        self.rx_callback = None
        self.sent: list[bytes] = []

    def set_rx_callback(self, callback):
        self.rx_callback = callback

    async def send(self, data: bytes) -> bool:
        self.sent.append(data)
        return True


def _make_companion() -> CompanionRadio:
    """Create a CompanionRadio with a mock radio for testing."""
    radio = MockRadio()
    identity = LocalIdentity()
    return CompanionRadio(radio=radio, identity=identity, node_name="test")


# ---------------------------------------------------------------------------
# _apply_flood_scope unit tests
# ---------------------------------------------------------------------------


class TestApplyFloodScope:
    def test_sets_transport_codes_on_flood_packet(self):
        companion = _make_companion()
        key = get_auto_key_for("#usa")
        companion.set_flood_scope(key)
        pkt = _make_flood_packet()

        companion._apply_flood_scope(pkt)

        assert pkt.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD
        assert pkt.transport_codes[0] != 0
        assert pkt.transport_codes[1] == 0

    def test_transport_code_matches_calc(self):
        companion = _make_companion()
        key = get_auto_key_for("#test-region")
        companion.set_flood_scope(key)
        pkt = _make_flood_packet()

        expected_code = calc_transport_code(key, pkt)
        companion._apply_flood_scope(pkt)

        assert pkt.transport_codes[0] == expected_code

    def test_noop_when_no_key_set(self):
        companion = _make_companion()
        pkt = _make_flood_packet()
        original_header = pkt.header

        companion._apply_flood_scope(pkt)

        assert pkt.header == original_header
        assert pkt.get_route_type() == ROUTE_TYPE_FLOOD
        assert pkt.transport_codes == [0, 0]

    def test_noop_on_direct_packet(self):
        companion = _make_companion()
        key = get_auto_key_for("#usa")
        companion.set_flood_scope(key)
        pkt = _make_direct_packet()
        original_header = pkt.header

        companion._apply_flood_scope(pkt)

        assert pkt.header == original_header
        assert pkt.get_route_type() == ROUTE_TYPE_DIRECT
        assert pkt.transport_codes == [0, 0]


# ---------------------------------------------------------------------------
# set_flood_region tests
# ---------------------------------------------------------------------------


class TestSetFloodRegion:
    def test_derives_key_with_hash_prefix(self):
        companion = _make_companion()
        companion.set_flood_region("#usa")
        assert companion._flood_transport_key == get_auto_key_for("#usa")

    def test_auto_adds_hash_prefix(self):
        companion = _make_companion()
        companion.set_flood_region("usa")
        assert companion._flood_transport_key == get_auto_key_for("#usa")

    def test_clear_with_none(self):
        companion = _make_companion()
        companion.set_flood_region("usa")
        assert companion._flood_transport_key is not None
        companion.set_flood_region(None)
        assert companion._flood_transport_key is None

    def test_same_key_with_or_without_prefix(self):
        c1 = _make_companion()
        c2 = _make_companion()
        c1.set_flood_region("europe")
        c2.set_flood_region("#europe")
        assert c1._flood_transport_key == c2._flood_transport_key


# ---------------------------------------------------------------------------
# set_flood_scope tests
# ---------------------------------------------------------------------------


class TestSetFloodScope:
    def test_stores_16_byte_key(self):
        companion = _make_companion()
        key = b"\x01" * 16
        companion.set_flood_scope(key)
        assert companion._flood_transport_key == key

    def test_truncates_longer_key(self):
        companion = _make_companion()
        key = b"\x02" * 32
        companion.set_flood_scope(key)
        assert companion._flood_transport_key == b"\x02" * 16

    def test_clear_with_none(self):
        companion = _make_companion()
        companion.set_flood_scope(b"\x01" * 16)
        companion.set_flood_scope(None)
        assert companion._flood_transport_key is None


# ---------------------------------------------------------------------------
# CompanionRadio dispatcher sync
# ---------------------------------------------------------------------------


class TestRadioDispatcherSync:
    def test_set_flood_scope_syncs_to_dispatcher(self):
        companion = _make_companion()
        key = get_auto_key_for("#test")
        companion.set_flood_scope(key)
        assert companion.node.dispatcher.flood_transport_key == key

    def test_set_flood_region_syncs_to_dispatcher(self):
        companion = _make_companion()
        companion.set_flood_region("test")
        expected = get_auto_key_for("#test")
        assert companion.node.dispatcher.flood_transport_key == expected

    def test_clear_syncs_to_dispatcher(self):
        companion = _make_companion()
        companion.set_flood_scope(b"\x01" * 16)
        assert companion.node.dispatcher.flood_transport_key is not None
        companion.set_flood_scope(None)
        assert companion.node.dispatcher.flood_transport_key is None

    def test_set_flood_unscoped_clears_dispatcher_mirror(self):
        companion = _make_companion()
        companion.set_flood_scope(b"\x01" * 16)
        companion.set_flood_unscoped()
        assert companion.node.dispatcher.flood_transport_key is None


# ---------------------------------------------------------------------------
# Explicit-unscoped mode (firmware CMD_SET_FLOOD_SCOPE_KEY mode 1, FW #2492)
# ---------------------------------------------------------------------------


class TestFloodUnscoped:
    def test_unscoped_leaves_plain_flood_and_marks_packet(self):
        companion = _make_companion()
        companion.set_flood_scope(b"\x01" * 16)
        companion.set_flood_unscoped()
        pkt = _make_flood_packet()

        companion._apply_flood_scope(pkt)

        assert pkt.get_route_type() == ROUTE_TYPE_FLOOD
        assert pkt.transport_codes == [0, 0]
        assert pkt._flood_scope_applied

    def test_dispatcher_skips_companion_marked_packet(self):
        """A stale dispatcher-level key must not re-scope a packet the
        companion layer deliberately left as plain flood."""
        companion = _make_companion()
        dispatcher = companion.node.dispatcher
        dispatcher.flood_transport_key = b"\x01" * 16
        pkt = _make_flood_packet()
        pkt._flood_scope_applied = True

        dispatcher._apply_flood_scope(pkt)

        assert pkt.get_route_type() == ROUTE_TYPE_FLOOD
        assert pkt.transport_codes == [0, 0]

    @pytest.mark.asyncio
    async def test_unscoped_send_stays_plain_flood_end_to_end(self):
        """set_flood_scope(K) then unscoped mode: the transmitted packet must
        be a plain flood (firmware checks send_unscoped before send_scope)."""
        radio = MockRadio()
        identity = LocalIdentity()
        companion = CompanionRadio(radio=radio, identity=identity, node_name="unscoped")
        companion.channels.set(0, Channel(name="test-ch", secret=b"\xAB" * 16))
        companion.set_flood_region("usa")
        companion.set_flood_unscoped()

        await companion.start()
        try:
            await companion.send_channel_message(0, "hello")
        finally:
            await companion.stop()

        assert len(radio.sent) > 0
        raw = radio.sent[-1]
        pkt = Packet()
        pkt.read_from(raw)
        assert pkt.get_route_type() == ROUTE_TYPE_FLOOD
        assert pkt.transport_codes == [0, 0]


# ---------------------------------------------------------------------------
# Default flood scope semantics
# ---------------------------------------------------------------------------


class TestDefaultFloodScope:
    def test_zero_key_default_is_reported_but_null_at_send(self):
        """Firmware persists and echoes a named default with an all-zero key
        (GET checks only the name); the null-key check happens at send time."""
        companion = _make_companion()
        companion.set_default_flood_scope("usa", b"\x00" * 16)

        assert companion.get_default_flood_scope() == ("usa", b"\x00" * 16)
        assert companion._resolve_flood_transport_key() is None

        pkt = _make_flood_packet()
        companion._apply_flood_scope(pkt)
        assert pkt.get_route_type() == ROUTE_TYPE_FLOOD

    def test_default_scope_used_when_no_override(self):
        companion = _make_companion()
        key = get_auto_key_for("#usa")
        companion.set_default_flood_scope("usa", key)
        pkt = _make_flood_packet()

        expected_code = calc_transport_code(key, pkt)
        companion._apply_flood_scope(pkt)

        assert pkt.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD
        assert pkt.transport_codes[0] == expected_code

    def test_apply_default_flood_scope_ignores_override(self):
        companion = _make_companion()
        default_key = get_auto_key_for("#usa")
        companion.set_default_flood_scope("usa", default_key)
        companion.set_flood_region("europe")  # transient override
        pkt = _make_flood_packet()

        expected_code = calc_transport_code(default_key, pkt)
        companion._apply_default_flood_scope(pkt)

        assert pkt.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD
        assert pkt.transport_codes[0] == expected_code

    def test_apply_default_flood_scope_null_default_stays_plain(self):
        companion = _make_companion()
        companion.set_flood_region("europe")  # transient override, no default
        pkt = _make_flood_packet()

        companion._apply_default_flood_scope(pkt)

        assert pkt.get_route_type() == ROUTE_TYPE_FLOOD
        assert pkt.transport_codes == [0, 0]
        assert pkt._flood_scope_applied


# ---------------------------------------------------------------------------
# Integration: advertise with flood scope
# ---------------------------------------------------------------------------


class TestAdvertiseWithFloodScope:
    @pytest.mark.asyncio
    async def test_advertise_flood_uses_default_scope(self):
        """Flood adverts are scoped with the persisted default scope (firmware
        CMD_SEND_SELF_ADVERT builds the scope from prefs.default_scope_key)."""
        radio = MockRadio()
        identity = LocalIdentity()
        companion = CompanionRadio(radio=radio, identity=identity, node_name="scoped")
        companion.set_default_flood_scope("usa", get_auto_key_for("#usa"))

        await companion.start()
        try:
            await companion.advertise(flood=True)
        finally:
            await companion.stop()

        assert len(radio.sent) > 0
        raw = radio.sent[-1]
        pkt = Packet()
        pkt.read_from(raw)
        assert pkt.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD
        assert pkt.transport_codes[0] != 0
        assert pkt.transport_codes[1] == 0

    @pytest.mark.asyncio
    async def test_advertise_flood_ignores_transient_override(self):
        """Firmware flood adverts bypass the transient send_scope override:
        with an override set but no default scope, the advert stays plain."""
        radio = MockRadio()
        identity = LocalIdentity()
        companion = CompanionRadio(radio=radio, identity=identity, node_name="scoped")
        companion.set_flood_region("usa")  # transient override only

        await companion.start()
        try:
            await companion.advertise(flood=True)
        finally:
            await companion.stop()

        assert len(radio.sent) > 0
        raw = radio.sent[-1]
        pkt = Packet()
        pkt.read_from(raw)
        assert pkt.get_route_type() == ROUTE_TYPE_FLOOD
        assert pkt.transport_codes == [0, 0]

    @pytest.mark.asyncio
    async def test_advertise_flood_without_scope_sends_normal_flood(self):
        radio = MockRadio()
        identity = LocalIdentity()
        companion = CompanionRadio(radio=radio, identity=identity, node_name="noscope")
        # No flood scope set

        await companion.start()
        try:
            await companion.advertise(flood=True)
        finally:
            await companion.stop()

        assert len(radio.sent) > 0
        raw = radio.sent[-1]
        pkt = Packet()
        pkt.read_from(raw)
        assert pkt.get_route_type() == ROUTE_TYPE_FLOOD
        assert pkt.transport_codes == [0, 0]


# ---------------------------------------------------------------------------
# Integration: GRP_TXT channel message with flood scope (firmware compat)
# ---------------------------------------------------------------------------


class TestChannelMessageFloodScope:
    """Verify send_channel_message produces firmware-compatible scoped packets.

    This is the key integration test: when set_flood_region("#nl-li") is used
    and a channel message is sent, the outgoing packet must be TRANSPORT_FLOOD
    and the transport code must match calc_transport_code(#nl-li key, packet).

    A firmware repeater's findMatch() re-derives the code from the region key
    and the received payload — if they don't match the packet is dropped.
    """

    @pytest.mark.asyncio
    async def test_channel_message_produces_transport_flood(self):
        radio = MockRadio()
        identity = LocalIdentity()
        companion = CompanionRadio(radio=radio, identity=identity, node_name="scoped")
        companion.channels.set(0, Channel(name="test-ch", secret=b"\xAB" * 16))
        companion.set_flood_region("#nl-li")

        await companion.start()
        try:
            await companion.send_channel_message(0, "hello")
        finally:
            await companion.stop()

        assert len(radio.sent) > 0, "Expected at least one packet sent"
        raw = radio.sent[-1]
        pkt = Packet()
        pkt.read_from(raw)
        assert pkt.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD
        assert pkt.transport_codes[0] != 0
        assert pkt.transport_codes[1] == 0

    @pytest.mark.asyncio
    async def test_channel_message_transport_code_matches_nl_li_key(self):
        """Transport code stored in the packet must equal what the repeater would compute.

        This is the definitive firmware-compatibility test for GRP_TXT scoping.
        The repeater calls calcTransportCode(get_auto_key_for("#nl-li"), pkt)
        and compares with pkt.transport_codes[0]. If they differ, the packet is dropped.
        """
        radio = MockRadio()
        identity = LocalIdentity()
        companion = CompanionRadio(radio=radio, identity=identity, node_name="scoped")
        companion.channels.set(0, Channel(name="test-ch", secret=b"\xAB" * 16))
        companion.set_flood_region("#nl-li")

        await companion.start()
        try:
            await companion.send_channel_message(0, "hello")
        finally:
            await companion.stop()

        assert len(radio.sent) > 0
        raw = radio.sent[-1]
        pkt = Packet()
        pkt.read_from(raw)

        key = get_auto_key_for("#nl-li")
        expected_code = calc_transport_code(key, pkt)
        assert pkt.transport_codes[0] == expected_code, (
            f"Transport code mismatch: stored {pkt.transport_codes[0]:#06x}, "
            f"computed {expected_code:#06x}. "
            "The companion is not using the #nl-li key for GRP_TXT packets."
        )

    @pytest.mark.asyncio
    async def test_channel_message_no_scope_sends_normal_flood(self):
        radio = MockRadio()
        identity = LocalIdentity()
        companion = CompanionRadio(radio=radio, identity=identity, node_name="noscope")
        companion.channels.set(0, Channel(name="test-ch", secret=b"\xAB" * 16))
        # No flood scope

        await companion.start()
        try:
            await companion.send_channel_message(0, "hello")
        finally:
            await companion.stop()

        assert len(radio.sent) > 0
        raw = radio.sent[-1]
        pkt = Packet()
        pkt.read_from(raw)
        assert pkt.get_route_type() == ROUTE_TYPE_FLOOD
        assert pkt.transport_codes == [0, 0]


# ---------------------------------------------------------------------------
# Per-message flood scope override (openHop extension; no firmware equivalent)
# ---------------------------------------------------------------------------

PRIVATE_KEY = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")


def _make_bridge(injector):
    """A CompanionBridge with one channel, sending through ``injector``."""
    bridge = CompanionBridge(LocalIdentity(), injector, node_name="scoped")
    bridge.channels.set(0, Channel(name="test-ch", secret=b"\xAB" * 16))
    return bridge


def _capturing_bridge():
    """A bridge plus the list of packets its injector receives."""
    sent: list[Packet] = []

    async def injector(pkt, **kwargs):
        sent.append(pkt)
        return True

    return _make_bridge(injector), sent


async def _send_via_radio(companion, *args, **kwargs) -> Packet:
    """Run one send through CompanionRadio and parse the packet off the wire."""
    await companion.start()
    try:
        await companion.send_channel_message(*args, **kwargs)
    finally:
        await companion.stop()
    assert companion._radio.sent, "expected a packet on the wire"
    pkt = Packet()
    pkt.read_from(companion._radio.sent[-1])
    return pkt


def _scoped_radio_companion() -> CompanionRadio:
    companion = CompanionRadio(radio=MockRadio(), identity=LocalIdentity(), node_name="scoped")
    companion.channels.set(0, Channel(name="test-ch", secret=b"\xAB" * 16))
    return companion


class TestExplicitFloodScopeHelper:
    """``_apply_explicit_flood_scope`` unit behaviour."""

    def test_scopes_flood_packet_with_given_key(self):
        companion = _make_companion()
        pkt = _make_flood_packet()
        key = get_auto_key_for("#USA")
        expected = calc_transport_code(key, pkt)

        companion._apply_explicit_flood_scope(pkt, key)

        assert pkt.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD
        assert pkt.transport_codes[0] == expected
        assert pkt.transport_codes[1] == 0
        assert pkt._flood_scope_applied

    def test_leaves_direct_packet_alone(self):
        companion = _make_companion()
        pkt = _make_direct_packet()

        companion._apply_explicit_flood_scope(pkt, get_auto_key_for("#USA"))

        assert pkt.get_route_type() == ROUTE_TYPE_DIRECT
        assert pkt.transport_codes == [0, 0]

    def test_does_not_override_an_existing_decision(self):
        """A packet a reply helper already decided keeps that decision."""
        companion = _make_companion()
        pkt = _make_flood_packet()
        pkt._flood_scope_applied = True

        companion._apply_explicit_flood_scope(pkt, get_auto_key_for("#USA"))

        assert pkt.get_route_type() == ROUTE_TYPE_FLOOD
        assert pkt.transport_codes == [0, 0]

    @pytest.mark.parametrize(
        "bad_key",
        [b"", b"\x01" * 15, b"\x01" * 17, bytes(16), None],
        ids=["empty", "short", "long", "all-zero", "none"],
    )
    def test_rejects_bad_keys(self, bad_key):
        companion = _make_companion()
        pkt = _make_flood_packet()

        with pytest.raises(ValueError):
            companion._apply_explicit_flood_scope(pkt, bad_key)

        assert pkt.get_route_type() == ROUTE_TYPE_FLOOD
        assert pkt.transport_codes == [0, 0]

    def test_accepts_bytes_like(self):
        companion = _make_companion()
        pkt = _make_flood_packet()

        companion._apply_explicit_flood_scope(pkt, bytearray(get_auto_key_for("#USA")))

        assert pkt.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD


class TestSendChannelMessageExplicitScope:
    """``send_channel_message(flood_scope_key=...)`` on the wire."""

    @pytest.mark.asyncio
    async def test_produces_transport_flood_with_matching_code(self):
        companion = _scoped_radio_companion()
        key = get_auto_key_for("#USA")

        pkt = await _send_via_radio(companion, 0, "hello", flood_scope_key=key)

        assert pkt.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD
        assert pkt.transport_codes[0] == calc_transport_code(key, pkt)
        assert pkt.transport_codes[1] == 0

    @pytest.mark.asyncio
    async def test_payload_identical_to_unscoped_send(self):
        """Scoping changes the route and codes -- never the encrypted payload."""
        key = get_auto_key_for("#USA")
        timestamp = 1700000000

        plain = await _send_via_radio(_scoped_radio_companion(), 0, "hello", timestamp)
        scoped = await _send_via_radio(
            _scoped_radio_companion(), 0, "hello", timestamp, flood_scope_key=key
        )

        assert scoped.get_payload_type() == plain.get_payload_type()
        assert bytes(scoped.get_payload()) == bytes(plain.get_payload())
        assert plain.get_route_type() == ROUTE_TYPE_FLOOD
        assert scoped.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD

    @pytest.mark.asyncio
    async def test_region_name_case_is_not_folded(self):
        """#USA and #usa are different MeshCore regions, not one region."""
        upper = get_auto_key_for("#USA")
        lower = get_auto_key_for("#usa")
        assert upper != lower

        pkt_upper = await _send_via_radio(
            _scoped_radio_companion(), 0, "hello", 1700000000, flood_scope_key=upper
        )
        pkt_lower = await _send_via_radio(
            _scoped_radio_companion(), 0, "hello", 1700000000, flood_scope_key=lower
        )

        assert pkt_upper.transport_codes[0] == calc_transport_code(upper, pkt_upper)
        assert pkt_lower.transport_codes[0] == calc_transport_code(lower, pkt_lower)
        assert pkt_upper.transport_codes[0] != pkt_lower.transport_codes[0]

    @pytest.mark.asyncio
    async def test_private_key_used_verbatim(self):
        """A key from a private region is not derived from anything."""
        companion = _scoped_radio_companion()

        pkt = await _send_via_radio(companion, 0, "hello", flood_scope_key=PRIVATE_KEY)

        assert pkt.transport_codes[0] == calc_transport_code(PRIVATE_KEY, pkt)

    @pytest.mark.asyncio
    async def test_overrides_transient_region(self):
        companion = _scoped_radio_companion()
        companion.set_flood_region("#nl-li")
        key = get_auto_key_for("#USA")

        pkt = await _send_via_radio(companion, 0, "hello", flood_scope_key=key)

        assert pkt.transport_codes[0] == calc_transport_code(key, pkt)
        assert pkt.transport_codes[0] != calc_transport_code(get_auto_key_for("#nl-li"), pkt)

    @pytest.mark.asyncio
    async def test_overrides_persisted_default(self):
        companion = _scoped_radio_companion()
        companion.set_default_flood_scope("nl-li", get_auto_key_for("#nl-li"))
        key = get_auto_key_for("#USA")

        pkt = await _send_via_radio(companion, 0, "hello", flood_scope_key=key)

        assert pkt.transport_codes[0] == calc_transport_code(key, pkt)

    @pytest.mark.asyncio
    async def test_overrides_force_unscoped(self):
        """The explicit key outranks the sticky send_unscoped flag."""
        companion = _scoped_radio_companion()
        companion.set_default_flood_scope("nl-li", get_auto_key_for("#nl-li"))
        companion.set_flood_unscoped()
        key = get_auto_key_for("#USA")

        pkt = await _send_via_radio(companion, 0, "hello", flood_scope_key=key)

        assert pkt.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD
        assert pkt.transport_codes[0] == calc_transport_code(key, pkt)

    @pytest.mark.asyncio
    async def test_leaves_node_scope_state_untouched(self):
        companion = _scoped_radio_companion()
        companion.set_default_flood_scope("nl-li", get_auto_key_for("#nl-li"))
        companion.set_flood_region("#europe")
        companion.set_flood_unscoped()
        before = (
            companion._flood_transport_key,
            companion._flood_unscoped,
            companion.prefs.default_scope_name,
            companion.prefs.default_scope_key,
        )

        await _send_via_radio(companion, 0, "hello", flood_scope_key=get_auto_key_for("#USA"))

        assert (
            companion._flood_transport_key,
            companion._flood_unscoped,
            companion.prefs.default_scope_name,
            companion.prefs.default_scope_key,
        ) == before

    @pytest.mark.asyncio
    async def test_next_send_returns_to_node_scope(self):
        """The override lasts exactly one message."""
        companion = _scoped_radio_companion()
        companion.set_flood_region("#nl-li")
        nl_key = get_auto_key_for("#nl-li")

        await _send_via_radio(companion, 0, "one", flood_scope_key=get_auto_key_for("#USA"))
        pkt = await _send_via_radio(companion, 0, "two")

        assert pkt.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD
        assert pkt.transport_codes[0] == calc_transport_code(nl_key, pkt)

    @pytest.mark.asyncio
    async def test_without_keyword_is_unchanged(self):
        companion = _scoped_radio_companion()

        pkt = await _send_via_radio(companion, 0, "hello")

        assert pkt.get_route_type() == ROUTE_TYPE_FLOOD
        assert pkt.transport_codes == [0, 0]

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "bad_key",
        [b"", b"\x01" * 15, b"\x01" * 17, bytes(16)],
        ids=["empty", "short", "long", "all-zero"],
    )
    async def test_bad_key_raises_before_any_rf(self, bad_key):
        """ValueError must reach the caller, not be swallowed into `False`."""
        companion = _scoped_radio_companion()

        await companion.start()
        try:
            with pytest.raises(ValueError):
                await companion.send_channel_message(0, "hello", flood_scope_key=bad_key)
        finally:
            await companion.stop()

        assert companion._radio.sent == []

    @pytest.mark.asyncio
    async def test_missing_channel_returns_false_without_rf(self):
        companion = _scoped_radio_companion()

        await companion.start()
        try:
            ok = await companion.send_channel_message(
                9, "hello", flood_scope_key=get_auto_key_for("#USA")
            )
        finally:
            await companion.stop()

        assert ok.success is False
        assert companion._radio.sent == []


class TestExplicitScopeOnBridge:
    """The same behaviour through CompanionBridge's packet injector."""

    @pytest.mark.asyncio
    async def test_injected_packet_is_scoped(self):
        bridge, sent = _capturing_bridge()
        key = get_auto_key_for("#USA")

        assert (await bridge.send_channel_message(0, "hello", flood_scope_key=key)).success is True

        assert len(sent) == 1
        assert sent[0].get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD
        assert sent[0].transport_codes[0] == calc_transport_code(key, sent[0])

    @pytest.mark.asyncio
    async def test_marked_applied_so_host_dispatcher_cannot_replace_it(self):
        """A repeater's dispatcher re-scopes floods; the mark is what stops it."""
        bridge, sent = _capturing_bridge()

        await bridge.send_channel_message(0, "hello", flood_scope_key=get_auto_key_for("#USA"))

        assert sent[0]._flood_scope_applied is True

    @pytest.mark.asyncio
    async def test_concurrent_sends_do_not_cross_contaminate(self):
        """Three overlapping sends, three different scopes, one packet each."""
        release = asyncio.Event()
        sent: list[Packet] = []

        async def injector(pkt, **kwargs):
            await release.wait()
            sent.append(pkt)
            return True

        bridge = _make_bridge(injector)
        bridge.set_flood_region("#nl-li")
        usa, europe = get_auto_key_for("#USA"), get_auto_key_for("#europe")

        tasks = [
            asyncio.create_task(bridge.send_channel_message(0, "a", 1, flood_scope_key=usa)),
            asyncio.create_task(bridge.send_channel_message(0, "b", 2, flood_scope_key=europe)),
            asyncio.create_task(bridge.send_channel_message(0, "c", 3)),
        ]
        await asyncio.sleep(0)
        release.set()
        assert all(await asyncio.gather(*tasks))

        assert len(sent) == 3
        for pkt in sent:
            assert pkt.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD

        # Match each packet to the key that explains its code rather than to
        # the key at its position: completion order is not send order, so
        # zipping the two would pass on a mismatch and fail on a correct run.
        keys = {"usa": usa, "europe": europe, "node": get_auto_key_for("#nl-li")}
        matched = []
        for pkt in sent:
            owners = [
                name
                for name, key in keys.items()
                if calc_transport_code(key, pkt) == pkt.transport_codes[0]
            ]
            assert len(owners) == 1, f"packet matched {owners or 'no'} key(s)"
            matched.append(owners[0])

        assert sorted(matched) == ["europe", "node", "usa"], "concurrent sends shared a scope"

    @pytest.mark.asyncio
    async def test_cancelled_send_leaves_no_residue(self):
        """A send cancelled mid-injection must not alter the next send's scope."""
        started = asyncio.Event()
        sent: list[Packet] = []

        async def injector(pkt, **kwargs):
            started.set()
            await asyncio.sleep(3600)
            sent.append(pkt)  # pragma: no cover - cancelled first
            return True

        bridge = _make_bridge(injector)
        task = asyncio.create_task(
            bridge.send_channel_message(0, "a", flood_scope_key=get_auto_key_for("#USA"))
        )
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert bridge._flood_transport_key is None
        assert bridge._flood_unscoped is False

    @pytest.mark.asyncio
    async def test_injector_failure_reports_false(self):
        async def injector(pkt, **kwargs):
            return False

        bridge = _make_bridge(injector)

        ok = await bridge.send_channel_message(0, "hello", flood_scope_key=get_auto_key_for("#USA"))

        assert ok.success is False


class TestTrailingNulDivergence:
    """Pin the one place text handling departs from firmware byte-for-byte.

    Firmware's command 3 passes the client's byte count straight into
    ``sendGroupMessage`` and encrypts any trailing NULs with it. openHop's
    *frame handlers* strip them first -- both command 3 and the scoped
    extension -- so for a padded frame the two stacks encrypt different lengths.

    ``send_channel_message`` itself does not strip: it encrypts whatever string
    it is handed, which is what this test shows. Combined with
    ``test_openhop_scoped_send_strips_trailing_nuls`` in the frame-server suite
    (a padded frame reaches the bridge as ``"hello"``), that pins the whole
    divergence: openHop emits the shorter form where firmware emits the longer.

    The decrypted string matches either way, so interoperability is unaffected
    -- but "identical RF bytes" holds only for text without trailing NULs.
    """

    @pytest.mark.asyncio
    async def test_send_api_encrypts_trailing_nuls_frame_layer_strips_them(self):
        key = get_auto_key_for("#USA")
        bare = await _send_via_radio(
            _scoped_radio_companion(), 0, "hi", 1700000000, flood_scope_key=key
        )
        padded = await _send_via_radio(
            _scoped_radio_companion(), 0, "hi\x00\x00", 1700000000, flood_scope_key=key
        )

        # Core strips, so the two are the same packet; firmware would emit a
        # longer ciphertext for the padded one.
        assert bytes(padded.get_payload()) != bytes(bare.get_payload())
        assert len(padded.get_payload()) > len(bare.get_payload())
