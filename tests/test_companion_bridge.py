"""Tests for CompanionBridge (repeater-integrated companion with packet_injector)."""

import asyncio
from typing import Optional
from unittest.mock import AsyncMock, patch

import pytest

from openhop_core.companion import CompanionBridge
from openhop_core.companion.constants import ADV_TYPE_CHAT, AUTOADD_CHAT
from openhop_core.companion.models import Contact, MessageEvent, QueuedMessage
from openhop_core.companion.timing import estimate_airtime_ms
from openhop_core.node.events import MeshEvents
from openhop_core.protocol import CryptoUtils, Identity, LocalIdentity, Packet, PacketBuilder
from openhop_core.protocol.constants import (
    PAYLOAD_TYPE_ACK,
    PAYLOAD_TYPE_ADVERT,
    PAYLOAD_TYPE_ANON_REQ,
    PAYLOAD_TYPE_PATH,
    PAYLOAD_TYPE_RAW_CUSTOM,
    PAYLOAD_TYPE_RESPONSE,
    PAYLOAD_TYPE_TXT_MSG,
    REQ_TYPE_GET_TELEMETRY_DATA,
    ROUTE_TYPE_DIRECT,
    ROUTE_TYPE_FLOOD,
    TELEM_PERM_BASE,
)
from openhop_core.protocol.packet_utils import PathUtils


def _make_peer_contact(name: str) -> Contact:
    """Return a contact with a valid Ed25519 public key (required for packet encryption)."""
    peer = LocalIdentity()
    return Contact(public_key=peer.get_public_key(), name=name)


async def _drain_events() -> None:
    """Allow the EventService task a handler published to run to completion."""
    for _ in range(3):
        await asyncio.sleep(0)


class MockPacketInjector:
    """Records injected packets and returns True by default."""

    def __init__(self):
        self.calls: list[tuple] = []
        self.expected_crcs: list[Optional[int]] = []

    async def __call__(
        self, pkt: Packet, wait_for_ack: bool = False, expected_crc: Optional[int] = None
    ) -> bool:
        self.calls.append((pkt, wait_for_ack))
        self.expected_crcs.append(expected_crc)
        return True


# ---------------------------------------------------------------------------
# Init
# ---------------------------------------------------------------------------


class TestCompanionBridgeInit:
    def test_init_creates_stores(self):
        injector = MockPacketInjector()
        identity = LocalIdentity()
        bridge = CompanionBridge(identity, injector, node_name="BridgeNode")
        assert bridge.contacts is not None
        assert bridge.contacts.get_count() == 0
        assert bridge.channels is not None
        assert bridge.stats is not None
        assert bridge.prefs.node_name == "BridgeNode"
        assert bridge.get_public_key() == identity.get_public_key()
        assert injector.calls == []

    def test_init_with_authenticate_callback(self):
        def auth_cb(*args, **kwargs):
            return (True, 0)

        injector = MockPacketInjector()
        bridge = CompanionBridge(
            LocalIdentity(),
            injector,
            authenticate_callback=auth_cb,
        )
        assert bridge._handlers is not None

    def test_login_handler_reads_and_clears_contact_out_path(self):
        """Production bridge wiring exposes its contact route to login replies."""
        bridge = CompanionBridge(LocalIdentity(), MockPacketInjector())
        peer = LocalIdentity()
        path_len = PathUtils.encode_path_len(1, 2)
        contact = Contact(
            public_key=peer.get_public_key(),
            out_path_len=path_len,
            out_path=b"\x11\x22",
        )
        assert bridge.contacts.add(contact) is True

        handler = bridge._handlers[PAYLOAD_TYPE_ANON_REQ]
        peer_identity = Identity(peer.get_public_key())
        assert handler.get_out_path(peer_identity) == (b"\x11\x22", path_len)

        handler.clear_out_path(peer_identity)
        updated = bridge.contacts.get_by_key(peer.get_public_key())
        assert updated is not None
        assert updated.out_path_len == -1
        assert updated.out_path == b""

    def test_set_other_params_propagates_multi_acks(self):
        """set_other_params pushes the multi_acks pref into the text handler."""
        bridge = CompanionBridge(LocalIdentity(), MockPacketInjector(), node_name="Test")
        text_handler = bridge._get_text_handler()
        assert text_handler is not None

        bridge.set_other_params(manual_add=0, telemetry_modes=0, advert_loc_policy=0, multi_acks=1)
        assert bridge.prefs.multi_acks == 1
        assert text_handler.multi_acks == 1

        bridge.set_other_params(manual_add=0, telemetry_modes=0, advert_loc_policy=0, multi_acks=0)
        assert text_handler.multi_acks == 0

    def test_host_radio_settings_are_reported_but_not_mutable(self):
        host_settings = {
            "frequency": 915_000_000,
            "bandwidth": 250_000,
            "spreading_factor": 10,
            "coding_rate": 5,
            "tx_power": 14,
            "max_tx_power_dbm": 17,
        }
        bridge = CompanionBridge(LocalIdentity(), MockPacketInjector(), radio_config=host_settings)

        assert bridge.get_radio_params() == {
            "frequency_hz": 915_000_000,
            "bandwidth_hz": 250_000,
            "spreading_factor": 10,
            "coding_rate": 5,
            "tx_power_dbm": 14,
            "rx_delay_base": 0.0,
            "airtime_factor": 1.0,
        }
        assert bridge.get_max_tx_power_dbm() == 17

        before = bridge.get_self_info()
        assert bridge.set_radio_params(868_000_000, 125_000, 7, 8) is False
        assert bridge.set_tx_power(20) is False
        assert bridge.get_self_info() == before

        # Administrative host updates remain visible without granting the
        # virtual companion permission to make the update itself.
        host_settings.update({"frequency": 868_000_000, "tx_power": 20})
        current = bridge.get_self_info()
        assert current.frequency_hz == 868_000_000
        assert current.tx_power_dbm == 20

    def test_radio_capability_getters_override_host_mapping(self):
        host_settings = {
            "frequency": 915_000_000,
            "bandwidth": 250_000,
            "spreading_factor": 10,
            "coding_rate": 5,
            "tx_power": 14,
        }
        bridge = CompanionBridge(
            LocalIdentity(),
            MockPacketInjector(),
            radio_settings_getter=lambda: host_settings,
            max_tx_power_getter=lambda: 19,
        )

        assert bridge.get_self_info().tx_power_dbm == 14
        assert bridge.get_max_tx_power_dbm() == 19

    def test_radio_capability_uses_generic_fallback_when_host_has_none(self):
        bridge = CompanionBridge(LocalIdentity(), MockPacketInjector(), radio_config={})

        assert bridge.get_max_tx_power_dbm() == 22


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCompanionBridgeLifecycle:
    async def test_start_stop(self):
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        assert bridge.is_running is False
        await bridge.start()
        assert bridge.is_running is True
        await bridge.stop()
        assert bridge.is_running is False


# ---------------------------------------------------------------------------
# Channel updated callback
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCompanionBridgeChannelUpdated:
    async def test_set_channel_and_remove_channel_fire_channel_updated(self):
        """set_channel and remove_channel fire on_channel_updated(idx, channel_or_none)."""
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        events = []

        def on_channel_updated(idx: int, ch) -> None:
            events.append((idx, ch))

        bridge.on_channel_updated(on_channel_updated)
        await bridge.start()

        ok = bridge.set_channel(0, "General", b"secret_________________________")
        assert ok is True
        await asyncio.sleep(0)
        assert len(events) == 1
        assert events[0][0] == 0
        assert events[0][1] is not None
        assert events[0][1].name == "General"

        ok = bridge.remove_channel(0)
        assert ok is True
        await asyncio.sleep(0)
        assert len(events) == 2
        assert events[1] == (0, None)

        await bridge.stop()


# ---------------------------------------------------------------------------
# process_received_packet
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCompanionBridgeFloodCopyFeed:
    """The host-wired pre-dedup feed that lets the teacher pick the best route.

    A bridge owns no dispatcher, and the host delivers only the *first* copy of a
    flood reply to ``process_received_packet`` — later copies die in the host's
    seen-table. Observed on a live mesh: four copies of one login reply over
    ~1.8 s, the teach going out 0.4 s in on the marginal first route, and the
    peer's later direct replies then failing while flood replies kept working.
    So the host wires ``dispatcher.add_raw_packet_subscriber(bridge.note_flood_copy)``
    and this method has to reach the teacher.
    """

    def _flood_response_to(self, bridge, *, in_path: bytes, rssi: int) -> Packet:
        pkt = Packet()
        pkt.header = (PAYLOAD_TYPE_RESPONSE << 2) | ROUTE_TYPE_FLOOD
        # payload[0] must be OUR dest hash for the teacher to record the copy.
        pkt.payload = bytearray([bridge._identity.get_public_key()[0], 0x5A]) + bytearray(
            b"\xcc" * 12
        )
        pkt.payload_len = len(pkt.payload)
        pkt.path = bytearray(in_path)
        pkt.path_len = PathUtils.encode_path_len(1, len(in_path))
        pkt._rssi = rssi
        return pkt

    async def test_note_flood_copy_reaches_the_return_path_teacher(self):
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        teacher = bridge._get_protocol_response_handler().return_path_teacher
        # The teacher ignores copies until a transmit path is wired.
        teacher.set_injector(injector)

        first = self._flood_response_to(bridge, in_path=b"\xaa\xbb\xcc", rssi=-100)
        better = self._flood_response_to(bridge, in_path=b"\xdd", rssi=-40)
        bridge.note_flood_copy(first)
        bridge.note_flood_copy(better)

        # Both copies of the same reply share a packet hash; the stronger,
        # shorter route must be the one retained.
        assert len(teacher._recent_copies) == 1
        kept = next(iter(teacher._recent_copies.values()))
        assert kept.path == b"\xdd"
        assert kept.rssi == -40

    async def test_note_flood_copy_is_safe_without_a_teacher(self):
        """It runs on the host's hot RX path; a missing handler must not raise."""
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        bridge._protocol_response_handler = None
        bridge.note_flood_copy(self._flood_response_to(bridge, in_path=b"\xaa", rssi=-50))


class TestCompanionBridgeProcessReceivedPacket:
    async def test_process_packet_records_rx_stats(self):
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        await bridge.start()
        pkt = Packet()
        pkt.header = (ROUTE_TYPE_FLOOD << 0) | (PAYLOAD_TYPE_ADVERT << 2)
        pkt.path_len = 0
        pkt.path = bytearray()
        pkt.payload = bytearray()
        pkt.payload_len = 0
        await bridge.process_received_packet(pkt)
        tot = bridge.stats.get_totals()
        assert tot["flood_rx"] == 1
        await bridge.stop()

    async def test_process_unknown_type_no_crash(self):
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        pkt = Packet()
        pkt.header = (ROUTE_TYPE_FLOOD << 0) | (15 << 2)
        pkt.path_len = 0
        pkt.path = bytearray()
        pkt.payload = bytearray()
        pkt.payload_len = 0
        await bridge.process_received_packet(pkt)
        assert True

    async def test_process_received_packet_fires_raw_data_received(self):
        """CompanionBridge fires on_raw_data_received(payload, snr, rssi) for RAW_CUSTOM packets."""
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        raw_calls = []

        def on_raw(payload: bytes, snr, rssi) -> None:
            raw_calls.append((payload, snr, rssi))

        bridge.on_raw_data_received(on_raw)
        await bridge.start()

        pkt = Packet()
        pkt.header = PAYLOAD_TYPE_RAW_CUSTOM << 2  # version 0
        pkt.payload = bytearray(b"\x01\x02\x03\x04")
        pkt.payload_len = 4
        pkt.path_len = 0
        pkt._snr = 6.0
        pkt._rssi = -75

        await bridge.process_received_packet(pkt)
        await bridge.stop()

        assert len(raw_calls) == 1
        payload_bytes, snr, rssi = raw_calls[0]
        assert payload_bytes == b"\x01\x02\x03\x04"
        assert snr == 6.0
        assert rssi == -75

    async def test_bridge_receiving_own_advert_adds_no_contact(self):
        """A repeater re-flooding our advert delivers it straight back; the handler
        drops it the way Mesh::onRecvPacket does (Mesh.cpp:263), so we never become
        a contact of ourselves."""
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        await bridge.start()

        await bridge.process_received_packet(PacketBuilder.create_advert(bridge._identity, "Me"))
        await _drain_events()
        await bridge.stop()

        assert bridge.contacts.get_count() == 0

    async def test_peer_advert_still_stored_after_self_guard(self):
        """Control for the self-advert guard: a peer's advert through the same
        entrypoint is still discovered and stored exactly once."""
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        await bridge.start()
        discovered_calls = []
        bridge.on_node_discovered(discovered_calls.append)

        peer = LocalIdentity()
        await bridge.process_received_packet(PacketBuilder.create_advert(peer, "Peer"))
        await _drain_events()
        await bridge.stop()

        assert len(discovered_calls) == 1
        assert bridge.contacts.get_by_key(peer.get_public_key()) is not None


# ---------------------------------------------------------------------------
# Advertise
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCompanionBridgeAdvertise:
    async def test_advertise_injects_packet(self):
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        result = await bridge.advertise(flood=True)
        assert result is True
        assert len(injector.calls) == 1
        pkt, wait_for_ack = injector.calls[0]
        assert pkt is not None
        assert (pkt.header >> 2) & 0x0F == PAYLOAD_TYPE_ADVERT
        assert wait_for_ack is False
        assert bridge.stats.get_totals()["flood_tx"] == 1


# ---------------------------------------------------------------------------
# Send text, share contact
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCompanionBridgeSendAndShare:
    async def test_send_text_message_no_contact(self, caplog):
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        result = await bridge.send_text_message(b"\x00" * 32, "Hi")
        assert result.success is False
        assert len(injector.calls) == 0

    async def test_send_text_message_with_contact_injects_packet(self):
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        contact = _make_peer_contact("Alice")
        bridge.contacts.add(contact)
        result = await bridge.send_text_message(contact.public_key, "Hello")
        assert len(injector.calls) >= 1
        pkt, _ = injector.calls[0]
        assert (pkt.header >> 2) & 0x0F == PAYLOAD_TYPE_TXT_MSG
        assert injector.expected_crcs[0] == result.expected_ack

    async def test_peer_with_matching_display_name_is_queued(self):
        """Group traffic has no sender identity, so a matching name is still inbound."""
        bridge = CompanionBridge(LocalIdentity(), MockPacketInjector(), node_name="Twin")
        assert bridge.set_channel(0, "Public", b"\x11" * 16)
        packet = PacketBuilder.create_group_datagram(
            "Public",
            LocalIdentity(),
            "hello",
            "Twin",
            bridge.channels.get_channels(),
            timestamp=1_700_000_000,
        )

        await bridge.process_received_packet(packet)

        queued = bridge.sync_next_message()
        assert queued is not None
        assert queued.is_channel is True
        assert queued.channel_idx == 0
        assert queued.text == "Twin: hello"

    async def test_outgoing_group_message_is_marked_before_injector_loopback(self):
        """A bridge's locally injected packet must not reappear as an inbound message."""
        bridge: CompanionBridge

        async def loopback_injector(packet: Packet, **_kwargs) -> bool:
            await bridge.process_received_packet(packet)
            return True

        bridge = CompanionBridge(LocalIdentity(), loopback_injector, node_name="Self")
        assert bridge.set_channel(0, "Public", b"\x11" * 16)

        assert await bridge.send_channel_message(0, "hello", timestamp=1_700_000_000)
        assert bridge.message_queue.count == 0

    async def test_outgoing_group_data_is_marked_before_injector_loopback(self):
        """Binary channel data follows the same loopback suppression rule."""
        bridge: CompanionBridge

        async def loopback_injector(packet: Packet, **_kwargs) -> bool:
            await bridge.process_received_packet(packet)
            return True

        bridge = CompanionBridge(LocalIdentity(), loopback_injector, node_name="Self")
        assert bridge.set_channel(0, "Public", b"\x11" * 16)

        assert await bridge.send_channel_data(0, 0x1234, b"\xaa\xbb")
        assert bridge.message_queue.count == 0

    async def test_share_contact_not_found(self):
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        result = await bridge.share_contact(b"\x00" * 32)
        assert result is False
        assert len(injector.calls) == 0

    async def test_share_contact_success(self):
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        remote = LocalIdentity()
        key = remote.get_public_key()
        blob = PacketBuilder.create_advert(remote, "Bob", route_type="direct").write_to()
        bridge.contacts.add(
            Contact(public_key=key, name="Bob", adv_type=1, last_advert_packet=blob)
        )
        result = await bridge.share_contact(key)
        assert result is True
        assert len(injector.calls) == 1
        pkt, _ = injector.calls[0]
        assert bytes(pkt.payload[:32]) == key

    async def test_send_raw_data_direct_injects_packet(self):
        """send_raw_data_direct builds RAW_CUSTOM packet and sends via injector."""
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        await bridge.start()
        path = b"\x42"
        payload = b"\x01\x02\x03\x04"
        result = await bridge.send_raw_data_direct(path, payload)
        await bridge.stop()
        assert result.success is True
        assert len(injector.calls) == 1
        pkt, wait_for_ack = injector.calls[0]
        assert (pkt.header >> 2) & 0x0F == PAYLOAD_TYPE_RAW_CUSTOM
        assert pkt.path == bytearray(path)
        assert pkt.path_len == len(path)
        assert bytes(pkt.payload) == payload
        assert wait_for_ack is False

    async def test_send_raw_packet_parses_and_injects(self):
        """send_raw_packet parses on-air bytes into a Packet and sends them verbatim."""
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        await bridge.start()
        # Build a real on-air packet and serialize it to wire bytes.
        source = PacketBuilder.create_raw_data(b"\x01\x02\x03\x04")
        raw_bytes = source.write_to()
        result = await bridge.send_raw_packet(0, raw_bytes)
        await bridge.stop()
        assert result.success is True
        assert len(injector.calls) == 1
        pkt, wait_for_ack = injector.calls[0]
        # The injected packet round-trips the original wire bytes.
        assert pkt.write_to() == raw_bytes
        assert wait_for_ack is False

    async def test_send_raw_packet_unparseable_returns_illegal_arg(self):
        """Parse failure is illegal_arg (not send_failed / table-full)."""
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        await bridge.start()
        # Header byte only: read_from has no path_len/payload to parse -> failure.
        result = await bridge.send_raw_packet(0, b"\x00")
        await bridge.stop()
        assert result.success is False
        assert result.error == "illegal_arg"
        assert injector.calls == []


# ---------------------------------------------------------------------------
# Path discovery, trace, control data
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCompanionBridgePathAndControl:
    async def test_send_path_discovery_req_no_contact(self):
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        result = await bridge.send_path_discovery_req(b"\x00" * 32)
        assert result.success is False
        assert result.error == "not_found"

    async def test_send_path_discovery_req_send_failure(self):
        injector = AsyncMock(return_value=False)
        bridge = CompanionBridge(LocalIdentity(), injector)
        contact = _make_peer_contact("Target")
        bridge.contacts.add(contact)

        result = await bridge.send_path_discovery_req(contact.public_key)

        assert result.success is False
        assert result.error == "send_failed"

    async def test_send_path_discovery_req_success(self):
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        contact = _make_peer_contact("Target")
        bridge.contacts.add(contact)
        result = await bridge.send_path_discovery_req(contact.public_key)
        assert result.success is True
        assert len(injector.calls) == 1
        assert result.timeout_ms == 10000

    async def test_send_path_discovery_req_matches_wire_tag_and_response(self, monkeypatch):
        injector = MockPacketInjector()
        local_identity = LocalIdentity()
        peer_identity = LocalIdentity()
        bridge = CompanionBridge(local_identity, injector)
        contact = Contact(public_key=peer_identity.get_public_key(), name="Target")
        bridge.contacts.add(contact)
        monkeypatch.setattr(
            "openhop_core.companion.base_send.random.getrandbits",
            lambda bits: 0xA1B2C3D4,
        )

        callbacks = []
        bridge.on_path_discovery_response(lambda *args: callbacks.append(args))
        result = await bridge.send_path_discovery_req(contact.public_key)

        assert result.success is True
        assert result.expected_ack is not None
        packet, _ = injector.calls[0]
        shared_secret = Identity(peer_identity.get_public_key()).calc_shared_secret(
            local_identity.get_private_key()
        )
        plaintext = CryptoUtils.mac_then_decrypt(
            shared_secret[:16], shared_secret, bytes(packet.payload[2:])
        )
        expected_request = (
            result.expected_ack.to_bytes(4, "little")
            + bytes([REQ_TYPE_GET_TELEMETRY_DATA, (~TELEM_PERM_BASE) & 0xFF, 0, 0, 0])
            + bytes.fromhex("d4c3b2a1")
        )
        assert plaintext[: len(expected_request)] == expected_request

        handled = await bridge._try_handle_path_discovery(
            result.expected_ack.to_bytes(4, "little"),
            (0x01, b"\x0a", 0x01, b"\x0b", contact.public_key),
        )
        assert handled is True
        assert len(callbacks) == 1
        # (tag_bytes, contact_pubkey, out_len_byte, out_path, in_len_byte, in_path)
        assert callbacks[0][0] == result.expected_ack.to_bytes(4, "little")
        assert callbacks[0][1] == contact.public_key
        assert callbacks[0][2] == 0x01
        assert callbacks[0][3] == b"\x0a"
        assert callbacks[0][4] == 0x01
        assert callbacks[0][5] == b"\x0b"

    async def test_send_trace_path_raw(self):
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        result = await bridge.send_trace_path_raw(0x12345678, 0xABCD, 0, bytes([0x01, 0x02]))
        assert result.success is True
        assert len(injector.calls) == 1
        # Firmware reports the trace SENT frame as direct, tagged with the trace tag.
        assert result.is_flood is False
        assert result.expected_ack == 0x12345678

    async def test_send_trace_path_raw_est_timeout_matches_firmware(self):
        """est_timeout = calcDirectTimeoutMillisFor(airtime(raw_len), path_len >> path_sz).

        Firmware appends the trace path to the payload and zeroes path_len
        (Mesh.cpp sendDirect), so its ``payload_len + path_len + 2`` is exactly
        this packet's raw on-air length.
        """
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        # flags=0 -> 1-byte hashes, so a 2-byte path is 2 hops.
        result = await bridge.send_trace_path_raw(0x12345678, 0xABCD, 0, bytes([0x01, 0x02]))
        pkt, _ = injector.calls[0]
        raw_len = pkt.get_raw_length()
        assert raw_len == 2 + 9 + 2  # header + path_len byte, tag/auth/flags, trace path
        airtime = estimate_airtime_ms(raw_len, 10, 250000, 5)
        assert result.timeout_ms == int(500 + (6.0 * airtime + 250) * (2 + 1))

    async def test_send_trace_path_raw_est_timeout_scales_with_hash_width(self):
        """Hop count is path bytes // (1 << (flags & 3)), not the raw byte count."""
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        # flags=1 -> 2-byte hashes, so a 4-byte path is 2 hops (not 4).
        result = await bridge.send_trace_path_raw(0x11, 0x22, 1, bytes([1, 2, 3, 4]))
        pkt, _ = injector.calls[0]
        airtime = estimate_airtime_ms(pkt.get_raw_length(), 10, 250000, 5)
        assert result.timeout_ms == int(500 + (6.0 * airtime + 250) * (2 + 1))

    async def test_send_trace_path_raw_send_failure(self):
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        with patch.object(bridge, "_send_packet", AsyncMock(return_value=False)):
            result = await bridge.send_trace_path_raw(0x12345678, 0xABCD, 0, bytes([0x01]))
        assert result.success is False
        assert result.error == "send_failed"

    async def test_send_control_data_valid_payload(self):
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        result = await bridge.send_control_data(bytes([0x80, 0x01]))
        assert result is True
        assert len(injector.calls) == 1
        pkt, _ = injector.calls[0]
        assert pkt.payload_len == 2
        assert list(pkt.payload) == [0x80, 0x01]

    async def test_send_control_data_rejects_no_high_bit(self):
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        result = await bridge.send_control_data(bytes([0x00, 0x01]))
        assert result is False
        assert len(injector.calls) == 0

    async def test_send_control_data_rejects_oversized_payload(self):
        from openhop_core.protocol.constants import MAX_PACKET_PAYLOAD

        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        oversized = bytes([0x80]) + bytes(MAX_PACKET_PAYLOAD)  # 1 + 184 = 185
        result = await bridge.send_control_data(oversized)
        assert result is False
        assert len(injector.calls) == 0


# ---------------------------------------------------------------------------
# Binary request
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCompanionBridgeBinaryReq:
    async def test_send_binary_req_no_contact(self):
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        result = await bridge.send_binary_req(b"\x00" * 32, bytes([0x01]))
        assert result.success is False
        assert result.error == "not_found"

    async def test_send_binary_req_send_failure(self):
        injector = AsyncMock(return_value=False)
        bridge = CompanionBridge(LocalIdentity(), injector)
        contact = _make_peer_contact("Rpt")
        bridge.contacts.add(contact)

        result = await bridge.send_binary_req(contact.public_key, bytes([0x01]))

        assert result.success is False
        assert result.error == "send_failed"

    async def test_send_binary_req_with_contact(self):
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        contact = _make_peer_contact("Rpt")
        bridge.contacts.add(contact)
        result = await bridge.send_binary_req(
            contact.public_key, bytes([0x01]), timeout_seconds=5.0
        )
        assert result.success is True
        assert result.expected_ack is not None
        assert len(injector.calls) == 1


# ---------------------------------------------------------------------------
# NODE_DISCOVERED -> advert pipeline (contact store + advert_received)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCompanionBridgeNodeDiscoveredAdvertPipeline:
    async def test_node_discovered_adds_contact_and_fires_advert_received(self):
        """Single path: NODE_DISCOVERED event drives store + advert_received (Bridge and Radio)."""
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        peer = LocalIdentity()
        pub_key_hex = peer.get_public_key().hex()
        event_data = {
            "public_key": pub_key_hex,
            "name": "DiscoveredNode",
            "contact_type": ADV_TYPE_CHAT,
            "lat": 52.0,
            "lon": -1.0,
            "advert_timestamp": 1000,
            "timestamp": 1001,
            "snr": 5.0,
            "rssi": -80,
        }
        advert_received_calls = []

        def on_advert(c):
            advert_received_calls.append(c)

        bridge.on_advert_received(on_advert)
        await bridge._handle_mesh_event(MeshEvents.NODE_DISCOVERED, event_data)
        assert bridge.contacts.get_count() == 1
        assert len(advert_received_calls) == 1
        assert advert_received_calls[0].name == "DiscoveredNode"
        assert advert_received_calls[0].public_key == peer.get_public_key()

    async def test_node_discovered_for_own_public_key_is_ignored(self):
        """The event seam is public: however a NODE_DISCOVERED carrying our own key
        was produced, we must never contact-book or path-cache ourselves."""
        injector = MockPacketInjector()
        identity = LocalIdentity()
        bridge = CompanionBridge(identity, injector)
        advert_received_calls = []
        discovered_calls = []
        bridge.on_advert_received(advert_received_calls.append)
        bridge.on_node_discovered(discovered_calls.append)
        event_data = {
            "public_key": identity.get_public_key().hex(),
            "name": "Myself",
            "contact_type": ADV_TYPE_CHAT,
            "lat": 0.0,
            "lon": 0.0,
            "advert_timestamp": 1000,
            "timestamp": 1000,
            "snr": 0.0,
            "rssi": 0,
        }
        await bridge._handle_mesh_event(MeshEvents.NODE_DISCOVERED, event_data)
        assert advert_received_calls == []
        assert discovered_calls == []
        assert bridge.contacts.get_count() == 0

    async def test_one_node_discovered_event_produces_exactly_one_advert_received(self):
        """Single-path guarantee: one NODE_DISCOVERED event yields exactly one
        advert_received callback (no duplicate path, no duplicate push frames).
        """
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        peer = LocalIdentity()
        event_data = {
            "public_key": peer.get_public_key().hex(),
            "name": "SinglePathNode",
            "contact_type": ADV_TYPE_CHAT,
            "lat": 0.0,
            "lon": 0.0,
            "advert_timestamp": 1000,
            "timestamp": 1000,
            "snr": 0.0,
            "rssi": 0,
        }
        advert_received_calls = []
        bridge.on_advert_received(advert_received_calls.append)
        await bridge._handle_mesh_event(MeshEvents.NODE_DISCOVERED, event_data)
        assert len(advert_received_calls) == 1
        assert advert_received_calls[0].name == "SinglePathNode"

    async def test_auto_add_chat_contact_does_not_inherit_wire_flags(self):
        """Wire protocol advert flags (ADVERT_FLAG_IS_CHAT_NODE=0x01) must not be
        stored as local contact flags (bit 0 = favourite).  Regression test for the
        bug where auto-added chat companions appeared as favourites."""
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        peer = LocalIdentity()
        # Simulate the real event_data produced by advert.py, which includes the
        # raw wire flags byte (0x81 = IS_CHAT_NODE | HAS_NAME).
        event_data = {
            "public_key": peer.get_public_key().hex(),
            "name": "ChatNode",
            "contact_type": ADV_TYPE_CHAT,
            "flags": 0x81,  # ADVERT_FLAG_IS_CHAT_NODE | ADVERT_FLAG_HAS_NAME
            "lat": 0.0,
            "lon": 0.0,
            "advert_timestamp": 1000,
            "timestamp": 1001,
            "snr": 0.0,
            "rssi": 0,
        }
        await bridge._handle_mesh_event(MeshEvents.NODE_DISCOVERED, event_data)
        contact = bridge.contacts.get_by_key(peer.get_public_key())
        assert contact is not None
        assert contact.flags == 0, (
            f"Auto-added contact should have flags=0, got {contact.flags:#x}. "
            "Wire protocol flags must not bleed into local contact flags."
        )
        assert (contact.flags & 0x01) == 0, "Contact must not be marked as favourite after auto-add"

    @staticmethod
    def _advert_event(peer, *, name, advert_timestamp, lat=0.0, lon=0.0):
        return {
            "public_key": peer.get_public_key().hex(),
            "name": name,
            "contact_type": ADV_TYPE_CHAT,
            "lat": lat,
            "lon": lon,
            "advert_timestamp": advert_timestamp,
            "timestamp": advert_timestamp,
            "snr": 0.0,
            "rssi": 0,
        }

    async def test_newer_advert_updates_existing_contact(self):
        """An advert with a strictly newer timestamp updates the stored contact."""
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        peer = LocalIdentity()
        await bridge._handle_mesh_event(
            MeshEvents.NODE_DISCOVERED,
            self._advert_event(peer, name="Original", advert_timestamp=1000),
        )
        advert_received_calls = []
        bridge.on_advert_received(advert_received_calls.append)
        await bridge._handle_mesh_event(
            MeshEvents.NODE_DISCOVERED,
            self._advert_event(peer, name="Renamed", advert_timestamp=2000),
        )
        contact = bridge.contacts.get_by_key(peer.get_public_key())
        assert contact is not None
        assert contact.name == "Renamed"
        assert contact.last_advert_timestamp == 2000
        assert len(advert_received_calls) == 1

    async def test_equal_timestamp_advert_is_rejected_as_replay(self):
        """An advert with a timestamp equal to the stored one is ignored (replay)."""
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        peer = LocalIdentity()
        await bridge._handle_mesh_event(
            MeshEvents.NODE_DISCOVERED,
            self._advert_event(peer, name="Original", advert_timestamp=1000),
        )
        advert_received_calls = []
        node_discovered_calls = []
        bridge.on_advert_received(advert_received_calls.append)
        bridge.on_node_discovered(node_discovered_calls.append)
        await bridge._handle_mesh_event(
            MeshEvents.NODE_DISCOVERED,
            self._advert_event(peer, name="Replayed", advert_timestamp=1000),
        )
        contact = bridge.contacts.get_by_key(peer.get_public_key())
        assert contact is not None
        assert contact.name == "Original"
        assert contact.last_advert_timestamp == 1000
        assert advert_received_calls == []
        assert node_discovered_calls == []

    async def test_older_advert_is_rejected_as_replay(self):
        """An advert with an older timestamp cannot overwrite a newer contact."""
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        peer = LocalIdentity()
        await bridge._handle_mesh_event(
            MeshEvents.NODE_DISCOVERED,
            self._advert_event(peer, name="Newer", advert_timestamp=2000, lat=52.0),
        )
        advert_received_calls = []
        bridge.on_advert_received(advert_received_calls.append)
        await bridge._handle_mesh_event(
            MeshEvents.NODE_DISCOVERED,
            self._advert_event(peer, name="Stale", advert_timestamp=1000, lat=10.0),
        )
        contact = bridge.contacts.get_by_key(peer.get_public_key())
        assert contact is not None
        assert contact.name == "Newer"
        assert contact.last_advert_timestamp == 2000
        assert advert_received_calls == []

    async def test_autoadd_max_hops_rejects_distant_new_contact(self):
        """A new contact whose advert is at least autoadd_max_hops away is not
        auto-added, but the client is still notified (firmware onAdvertRecv)."""
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        bridge.prefs.autoadd_max_hops = 2
        peer = LocalIdentity()
        node_discovered_calls = []
        bridge.on_node_discovered(node_discovered_calls.append)
        event = self._advert_event(peer, name="Faraway", advert_timestamp=1000)
        event["path_len_encoded"] = PathUtils.encode_path_len(1, 2)  # 2 hops
        await bridge._handle_mesh_event(MeshEvents.NODE_DISCOVERED, event)
        assert bridge.contacts.get_by_key(peer.get_public_key()) is None
        assert len(node_discovered_calls) == 1

    async def test_autoadd_max_hops_allows_closer_new_contact(self):
        """A new contact within the hop limit is auto-added."""
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        bridge.prefs.autoadd_max_hops = 2
        peer = LocalIdentity()
        event = self._advert_event(peer, name="Nearby", advert_timestamp=1000)
        event["path_len_encoded"] = PathUtils.encode_path_len(1, 1)  # 1 hop
        await bridge._handle_mesh_event(MeshEvents.NODE_DISCOVERED, event)
        assert bridge.contacts.get_by_key(peer.get_public_key()) is not None

    async def test_autoadd_max_hops_zero_means_no_limit(self):
        """max_hops == 0 disables the distance test (default behavior)."""
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        bridge.prefs.autoadd_max_hops = 0
        peer = LocalIdentity()
        event = self._advert_event(peer, name="Distant", advert_timestamp=1000)
        event["path_len_encoded"] = PathUtils.encode_path_len(1, 10)  # 10 hops
        await bridge._handle_mesh_event(MeshEvents.NODE_DISCOVERED, event)
        assert bridge.contacts.get_by_key(peer.get_public_key()) is not None

    async def test_autoadd_max_hops_does_not_block_existing_contact_update(self):
        """An existing contact is still updated even when the advert is beyond the
        hop limit (the cap only gates new auto-adds)."""
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        peer = LocalIdentity()
        # First advert (0 hops) adds the contact while the cap is off.
        await bridge._handle_mesh_event(
            MeshEvents.NODE_DISCOVERED,
            self._advert_event(peer, name="Original", advert_timestamp=1000),
        )
        bridge.prefs.autoadd_max_hops = 1  # direct-only from now on
        event = self._advert_event(peer, name="Renamed", advert_timestamp=2000)
        event["path_len_encoded"] = PathUtils.encode_path_len(1, 5)  # 5 hops away
        await bridge._handle_mesh_event(MeshEvents.NODE_DISCOVERED, event)
        contact = bridge.contacts.get_by_key(peer.get_public_key())
        assert contact is not None
        assert contact.name == "Renamed"

    async def test_path_packet_updates_contact_path_and_fires_contact_path_updated_once(self):
        """PATH packet that decrypts updates contact out_path and fires contact_path_updated."""
        injector = MockPacketInjector()
        local_identity = LocalIdentity()
        peer_identity = LocalIdentity()
        peer_pubkey = peer_identity.get_public_key()
        bridge = CompanionBridge(local_identity, injector)
        bridge.contacts.add(Contact(public_key=peer_pubkey, name="Peer"))

        path_len_byte = 2
        path_bytes = bytes([0x01, 0x02])
        extra_type = PAYLOAD_TYPE_RESPONSE
        extra = bytes([0, 0, 0, 0, 0x00])
        plaintext = bytes([path_len_byte]) + path_bytes + bytes([extra_type]) + extra
        peer_id = Identity(peer_pubkey)
        shared_secret = peer_id.calc_shared_secret(local_identity.get_private_key())
        aes_key = shared_secret[:16]
        encrypted = CryptoUtils.encrypt_then_mac(aes_key, shared_secret, plaintext)
        our_hash = local_identity.get_public_key()[0]
        src_hash = peer_pubkey[0]
        payload = bytes([our_hash, src_hash]) + encrypted

        pkt = Packet()
        pkt.header = (ROUTE_TYPE_FLOOD << 0) | (PAYLOAD_TYPE_PATH << 2)
        pkt.path_len = 0
        pkt.path = bytearray()
        pkt.payload = bytearray(payload)
        pkt.payload_len = len(payload)

        path_updated_calls = []

        async def on_path_updated(contact):
            path_updated_calls.append(contact)

        bridge.on_contact_path_updated(on_path_updated)
        result = await bridge.process_received_packet(pkt)

        assert result.authenticated is True
        assert len(path_updated_calls) == 1
        assert path_updated_calls[0].public_key == peer_pubkey
        assert path_updated_calls[0].out_path_len == path_len_byte
        assert path_updated_calls[0].out_path == path_bytes
        contact = bridge.contacts.get_by_key(peer_pubkey)
        assert contact is not None
        assert contact.out_path_len == path_len_byte
        assert contact.out_path == path_bytes

    async def test_path_packet_with_ack_uses_encoded_path_byte_len_for_2byte_and_3byte_hashes(self):
        """PATH ACK extraction uses PathUtils.get_path_byte_len so 2- and 3-byte hashes work."""
        injector = MockPacketInjector()
        local_identity = LocalIdentity()
        peer_identity = LocalIdentity()
        peer_pubkey = peer_identity.get_public_key()
        bridge = CompanionBridge(local_identity, injector)
        bridge.contacts.add(Contact(public_key=peer_pubkey, name="Peer"))

        ack_crc_expected = 0x12345678
        peer_id = Identity(peer_pubkey)
        shared_secret = peer_id.calc_shared_secret(local_identity.get_private_key())
        aes_key = shared_secret[:16]
        our_hash = local_identity.get_public_key()[0]
        src_hash = peer_pubkey[0]

        def build_path_packet(path_len_byte: int, path_bytes: bytes) -> Packet:
            plaintext = (
                bytes([path_len_byte])
                + path_bytes
                + bytes([PAYLOAD_TYPE_ACK])
                + ack_crc_expected.to_bytes(4, "little")
            )
            encrypted = CryptoUtils.encrypt_then_mac(aes_key, shared_secret, plaintext)
            payload = bytes([our_hash, src_hash]) + encrypted
            pkt = Packet()
            pkt.header = (ROUTE_TYPE_FLOOD << 0) | (PAYLOAD_TYPE_PATH << 2)
            pkt.path_len = 0
            pkt.path = bytearray()
            pkt.payload = bytearray(payload)
            pkt.payload_len = len(payload)
            return pkt

        send_confirmed_calls = []
        bridge.on_send_confirmed(lambda crc, *a: send_confirmed_calls.append(crc))
        bridge._track_pending_ack(ack_crc_expected)

        # 2-byte path hash: 1 hop -> 2 path bytes (encoded 0x41)
        path_len_2 = PathUtils.encode_path_len(2, 1)
        assert PathUtils.get_path_byte_len(path_len_2) == 2
        pkt2 = build_path_packet(path_len_2, bytes([0xAA, 0xBB]))
        await bridge.process_received_packet(pkt2)
        assert len(send_confirmed_calls) == 1
        assert send_confirmed_calls[0] == ack_crc_expected

        # 3-byte path hash: 1 hop -> 3 path bytes (encoded 0x81)
        path_len_3 = PathUtils.encode_path_len(3, 1)
        assert PathUtils.get_path_byte_len(path_len_3) == 3
        send_confirmed_calls.clear()
        ack_crc_3 = 0xDEADBEEF
        bridge._track_pending_ack(ack_crc_3)
        plaintext_3 = (
            bytes([path_len_3])
            + bytes([0x11, 0x22, 0x33])
            + bytes([PAYLOAD_TYPE_ACK])
            + ack_crc_3.to_bytes(4, "little")
        )
        encrypted_3 = CryptoUtils.encrypt_then_mac(aes_key, shared_secret, plaintext_3)
        payload_3 = bytes([our_hash, src_hash]) + encrypted_3
        pkt3 = Packet()
        pkt3.header = (ROUTE_TYPE_FLOOD << 0) | (PAYLOAD_TYPE_PATH << 2)
        pkt3.path_len = 0
        pkt3.path = bytearray()
        pkt3.payload = bytearray(payload_3)
        pkt3.payload_len = len(payload_3)
        await bridge.process_received_packet(pkt3)
        assert len(send_confirmed_calls) == 1
        assert send_confirmed_calls[0] == ack_crc_3

    async def test_pending_ack_table_evicts_oldest_when_full(self):
        """When the pending-ACK table is full, the oldest entry is evicted so a
        current send is always tracked (firmware circular expected_ack_table)."""
        from openhop_core.companion.constants import MAX_PENDING_ACK_CRCS

        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        for crc in range(MAX_PENDING_ACK_CRCS):
            bridge._track_pending_ack(crc)
        assert len(bridge._pending_ack_crcs) == MAX_PENDING_ACK_CRCS

        # One more send evicts the oldest (crc 0), never the newest.
        newest = MAX_PENDING_ACK_CRCS
        bridge._track_pending_ack(newest)
        assert len(bridge._pending_ack_crcs) == MAX_PENDING_ACK_CRCS
        assert 0 not in bridge._pending_ack_crcs
        assert newest in bridge._pending_ack_crcs

        # The newest send can still be confirmed.
        confirmed = []
        bridge.on_send_confirmed(lambda crc, *a: confirmed.append(crc))
        assert await bridge._try_confirm_send(newest) is True
        assert confirmed == [newest]

    async def test_send_confirmed_reports_trip_time(self):
        """send_confirmed passes the round-trip time (now - send time) in ms."""
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        calls = []
        bridge.on_send_confirmed(lambda crc, trip_ms=0: calls.append((crc, trip_ms)))
        crc = 0x1234ABCD
        bridge._track_pending_ack(crc)
        # Backdate the recorded send time by ~50 ms so the trip is measurable.
        bridge._pending_ack_crcs[crc] -= 0.05
        assert await bridge._try_confirm_send(crc) is True
        assert len(calls) == 1
        assert calls[0][0] == crc
        assert calls[0][1] >= 50

    async def test_discrete_six_byte_ack_fires_send_confirmed(self):
        """A direct-route plain-DM ACK is 6 bytes (4-byte hash + ext-attempt +
        random byte). The bridge must accept it and correlate on the first 4
        bytes; folding all 6 bytes or requiring exactly 4 would never match the
        4-byte expected CRC and send_confirmed would silently never fire."""
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        confirmed = []
        bridge.on_send_confirmed(lambda crc, *a: confirmed.append(crc))

        ack_crc = 0x1A2B3C4D
        bridge._track_pending_ack(ack_crc)

        payload = ack_crc.to_bytes(4, "little") + bytes([0x07, 0xF3])
        pkt = Packet()
        pkt.header = ROUTE_TYPE_DIRECT | (PAYLOAD_TYPE_ACK << 2)
        pkt.path_len = 0
        pkt.path = bytearray()
        pkt.payload = bytearray(payload)
        pkt.payload_len = len(payload)

        await bridge.process_received_packet(pkt)

        assert confirmed == [ack_crc]

    async def test_discrete_ack_does_not_confirm_unpending_crc(self):
        """The extended tail bytes are not part of correlation and must not be
        able to produce a false confirm: a 6-byte ACK whose first 4 bytes are
        not a pending CRC leaves send_confirmed unfired."""
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        confirmed = []
        bridge.on_send_confirmed(lambda crc, *a: confirmed.append(crc))

        bridge._track_pending_ack(0x1A2B3C4D)

        payload = (0xDEADBEEF).to_bytes(4, "little") + bytes([0x01, 0x02])
        pkt = Packet()
        pkt.header = ROUTE_TYPE_DIRECT | (PAYLOAD_TYPE_ACK << 2)
        pkt.path_len = 0
        pkt.path = bytearray()
        pkt.payload = bytearray(payload)
        pkt.payload_len = len(payload)

        await bridge.process_received_packet(pkt)

        assert confirmed == []

    async def test_node_discovered_fires_node_discovered_even_when_filtered(self):
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        bridge.prefs.manual_add_contacts = 1
        bridge.prefs.autoadd_config = AUTOADD_CHAT
        peer = LocalIdentity()
        event_data = {
            "public_key": peer.get_public_key().hex(),
            "name": "RepeaterNode",
            "contact_type": 2,
            "lat": 0.0,
            "lon": 0.0,
            "advert_timestamp": 1000,
            "timestamp": 1000,
            "snr": 0.0,
            "rssi": 0,
        }
        node_discovered_calls = []
        advert_received_calls = []

        def on_node(contact):
            node_discovered_calls.append(contact)

        def on_advert(c):
            advert_received_calls.append(c)

        bridge.on_node_discovered(on_node)
        bridge.on_advert_received(on_advert)
        await bridge._handle_mesh_event(MeshEvents.NODE_DISCOVERED, event_data)
        assert bridge.contacts.get_count() == 0
        assert len(advert_received_calls) == 0
        assert len(node_discovered_calls) == 1
        assert node_discovered_calls[0].name == "RepeaterNode"
        assert isinstance(node_discovered_calls[0], Contact)

    async def test_node_discovered_event_path_adds_contact_and_fires_advert_received(self):
        """Event path with optional inbound_path: store updated, advert_received fired once."""
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        peer = LocalIdentity()
        pub_key_hex = peer.get_public_key().hex()
        event_data = {
            "public_key": pub_key_hex,
            "name": "AdvertNode",
            "contact_type": ADV_TYPE_CHAT,
            "lat": 0.0,
            "lon": 0.0,
            "advert_timestamp": 1000,
            "timestamp": 1000,
            "snr": 0.0,
            "rssi": 0,
            "inbound_path": b"\x01\x02\x03",
        }
        advert_received_calls = []

        def on_advert(c):
            advert_received_calls.append(c)

        bridge.on_advert_received(on_advert)
        await bridge._handle_mesh_event(MeshEvents.NODE_DISCOVERED, event_data)
        assert bridge.contacts.get_count() == 1
        assert len(advert_received_calls) == 1
        assert advert_received_calls[0].name == "AdvertNode"
        # Second event (same contact, newer timestamp): update, still one contact,
        # advert_received again. A newer timestamp is required to pass replay protection.
        newer_event = {**event_data, "advert_timestamp": 2000, "timestamp": 2000}
        await bridge._handle_mesh_event(MeshEvents.NODE_DISCOVERED, newer_event)
        assert bridge.contacts.get_count() == 1
        assert len(advert_received_calls) == 2

    async def test_stored_contact_fires_both_advert_received_and_node_discovered(self):
        """Firmware parity (onDiscoveredContact fires for every advert): a stored contact
        fires advert_received (persist) AND node_discovered (client frame push)."""
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        peer = LocalIdentity()
        event_data = {
            "public_key": peer.get_public_key().hex(),
            "name": "StoredNode",
            "contact_type": ADV_TYPE_CHAT,
            "lat": 0.0,
            "lon": 0.0,
            "advert_timestamp": 1000,
            "timestamp": 1000,
            "snr": 0.0,
            "rssi": 0,
        }
        node_discovered_calls = []
        advert_received_calls = []

        bridge.on_node_discovered(lambda c: node_discovered_calls.append(c))
        bridge.on_advert_received(lambda c: advert_received_calls.append(c))
        await bridge._handle_mesh_event(MeshEvents.NODE_DISCOVERED, event_data)
        assert bridge.contacts.get_count() == 1
        assert len(advert_received_calls) == 1
        assert len(node_discovered_calls) == 1
        assert node_discovered_calls[0].name == "StoredNode"


# ---------------------------------------------------------------------------
# Deduplication (direct messages by packet_hash)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCompanionBridgeDeduplication:
    async def test_direct_message_deduplicated_by_packet_hash(self):
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        key_hex = LocalIdentity().get_public_key().hex()
        same_hash = "A1B2C3D4E5F6"
        data = {
            "contact_pubkey": key_hex,
            "message_text": "Hello",
            "timestamp": 1000,
            "txt_type": 0,
            "packet_hash": same_hash,
        }
        await bridge._handle_mesh_event(MeshEvents.NEW_MESSAGE, data)
        await bridge._handle_mesh_event(MeshEvents.NEW_MESSAGE, data)
        await bridge._handle_mesh_event(MeshEvents.NEW_MESSAGE, data)
        assert bridge.message_queue.count == 1
        msg = bridge.sync_next_message()
        assert msg is not None
        assert msg.text == "Hello"
        assert bridge.sync_next_message() is None

    @pytest.mark.parametrize("path_len", [0xFF, 0x01, 0x42, 0x83])
    async def test_message_path_len_reaches_queue_and_callback(self, path_len):
        """The companion-format route byte survives event fan-out unchanged."""
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        key_hex = LocalIdentity().get_public_key().hex()
        callback_metadata = []
        bridge.on_message_received(lambda *args: callback_metadata.append(args[-2:]))

        await bridge._handle_mesh_event(
            MeshEvents.NEW_MESSAGE,
            {
                "contact_pubkey": key_hex,
                "message_text": "direct",
                "timestamp": 1000,
                "txt_type": 0,
                "packet_hash": "B1C2D3E4",
                "path_len": path_len,
            },
        )

        queued = bridge.sync_next_message()
        assert queued is not None
        assert queued.path_len == path_len
        assert callback_metadata == [(path_len, True)]

    async def test_rejected_message_is_reported_without_displacing_direct_message(self):
        """Queue rejection is visible to persistence callbacks and callers."""
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector, offline_queue_size=1)
        key_hex = LocalIdentity().get_public_key().hex()
        queue_results = []
        bridge.on_message_received(lambda *args: queue_results.append(args[-1]))

        for packet_hash, text in (("A1B2C3D4", "first"), ("B1C2D3E4", "second")):
            await bridge._handle_mesh_event(
                MeshEvents.NEW_MESSAGE,
                {
                    "contact_pubkey": key_hex,
                    "message_text": text,
                    "timestamp": 1000,
                    "txt_type": 0,
                    "packet_hash": packet_hash,
                    "path_len": 0xFF,
                },
            )

        assert queue_results == [True, False]
        retained = bridge.sync_next_message()
        assert retained is not None
        assert retained.text == "first"

    async def test_message_event_callback_receives_single_event_object(self):
        """New-style subscribers get one MessageEvent instead of positional args."""
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        key_hex = LocalIdentity().get_public_key().hex()
        events = []
        bridge.on_message_event(events.append)

        await bridge._handle_mesh_event(
            MeshEvents.NEW_MESSAGE,
            {
                "contact_pubkey": key_hex,
                "message_text": "hello",
                "timestamp": 1000,
                "txt_type": 0,
                "packet_hash": "C1D2E3F4",
                "path_len": 0x42,
            },
        )

        assert len(events) == 1
        event = events[0]
        assert isinstance(event, MessageEvent)
        assert event.text == "hello"
        assert event.timestamp == 1000
        assert event.packet_hash == "C1D2E3F4"
        assert event.path_len == 0x42
        assert event.queued is True
        # A queued push carries the exact in-memory queue entry by identity.
        assert event.queue_entry is bridge.message_queue.peek()

    async def test_message_event_queue_entry_none_when_push_rejected(self):
        """A rejected protected-queue push carries queue_entry=None."""
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        # Fill the protected (all-direct) queue so the next direct push is rejected.
        bridge.message_queue._max_size = 1
        bridge.message_queue.push(QueuedMessage(sender_key=b"\x09" * 32, text="held"))
        key_hex = LocalIdentity().get_public_key().hex()
        events = []
        bridge.on_message_event(events.append)

        await bridge._handle_mesh_event(
            MeshEvents.NEW_MESSAGE,
            {
                "contact_pubkey": key_hex,
                "message_text": "rejected",
                "timestamp": 2000,
                "txt_type": 0,
                "packet_hash": "DEADBEEF",
            },
        )

        assert len(events) == 1
        assert events[0].queued is False
        assert events[0].queue_entry is None

    async def test_legacy_async_message_callback_receives_positional_form(self):
        """The deprecated on_message_received adapter preserves the positional
        signature (sender_key, text, timestamp, txt_type, packet_hash, snr,
        rssi, sender_prefix, path_len, queued) and awaits async callbacks."""
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        sender = LocalIdentity()
        key_hex = sender.get_public_key().hex()
        received = []

        async def legacy_callback(*args):
            received.append(args)

        bridge.on_message_received(legacy_callback)

        await bridge._handle_mesh_event(
            MeshEvents.NEW_MESSAGE,
            {
                "contact_pubkey": key_hex,
                "message_text": "legacy",
                "timestamp": 2000,
                "txt_type": 0,
                "packet_hash": "D1E2F3A4",
                "path_len": 0xFF,
            },
        )

        assert received == [
            (
                sender.get_public_key(),
                "legacy",
                2000,
                0,
                "D1E2F3A4",
                0.0,
                0,
                b"",
                0xFF,
                True,
            )
        ]


# ---------------------------------------------------------------------------
# Request retry / total-timeout cap
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestRequestTimeoutCap:
    """The `timeout` argument caps the total wait across retries."""

    def _bridge_with_contact(self):
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector)
        contact = _make_peer_contact("Repeater")
        bridge.contacts.add(contact)
        return bridge, injector, contact

    async def test_status_request_stops_at_total_timeout(self):
        bridge, injector, contact = self._bridge_with_contact()
        # Fixed short per-attempt timeout; no response ever arrives.
        bridge._response_timeout_s = lambda pkt, proxy: 0.05
        result = await bridge.send_status_request(contact.public_key, timeout=0.08)
        assert result["success"] is False
        # Budget (0.08s) allows the first attempt (0.05s) plus a clipped second
        # attempt — never all DEFAULT_MAX_ATTEMPTS.
        assert 1 <= len(injector.calls) <= 2

    async def test_status_request_retries_without_cap_pressure(self):
        from openhop_core.companion.timing import DEFAULT_MAX_ATTEMPTS

        bridge, injector, contact = self._bridge_with_contact()
        bridge._response_timeout_s = lambda pkt, proxy: 0.01
        result = await bridge.send_status_request(contact.public_key, timeout=10.0)
        assert result["success"] is False
        assert len(injector.calls) == DEFAULT_MAX_ATTEMPTS

    async def test_telemetry_request_stops_at_total_timeout(self):
        bridge, injector, contact = self._bridge_with_contact()
        bridge._response_timeout_s = lambda pkt, proxy: 0.05
        result = await bridge.send_telemetry_request(contact.public_key, timeout=0.08)
        assert result["success"] is False
        assert 1 <= len(injector.calls) <= 2

    async def test_started_status_request_reports_meshcore_sent_metadata(self):
        bridge, injector, contact = self._bridge_with_contact()
        contact.out_path_len = 0
        bridge.contacts.update(contact)
        bridge._response_timeout_s = lambda pkt, proxy: 0.01

        started = await bridge._start_status_request(contact.public_key)

        assert started["success"] is True
        sent = started["sent"]
        assert sent.is_flood is False
        assert sent.expected_ack is not None
        assert sent.timeout_ms == 10
        result = await started["task"]
        assert result["success"] is False

    async def test_started_status_request_reports_send_failure(self):
        from unittest.mock import AsyncMock

        injector = AsyncMock(return_value=False)
        bridge = CompanionBridge(LocalIdentity(), injector)
        contact = _make_peer_contact("Repeater")
        bridge.contacts.add(contact)

        started = await bridge._start_status_request(contact.public_key)

        assert started == {"success": False, "error": "send_failed", "reason": "Send failed"}
        injector.assert_awaited_once()


# ---------------------------------------------------------------------------
# Room server posts (TXT_TYPE_SIGNED_PLAIN) end-to-end
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestSignedRoomPostEndToEnd:
    async def test_room_post_roundtrip_matches_firmware_frame(self):
        """A pushed room post (SIGNED_PLAIN) survives RX -> queue -> app frame
        with the text intact and the author prefix as a separate field."""
        import struct
        from types import SimpleNamespace

        from openhop_core.companion.constants import RESP_CODE_CONTACT_MSG_RECV
        from openhop_core.companion.frame_server import CompanionFrameServer
        from openhop_core.protocol.constants import PAYLOAD_TYPE_TXT_MSG, TXT_TYPE_SIGNED_PLAIN

        injector = MockPacketInjector()
        room = LocalIdentity()  # the room server
        companion = LocalIdentity()  # our virtual companion
        bridge = CompanionBridge(companion, injector)
        bridge.contacts.add(Contact(public_key=room.get_public_key(), name="Room"))

        # Build the packet exactly as firmware pushPostToClient does:
        # timestamp(4) + [(SIGNED_PLAIN << 2) | attempt](1) + author_prefix(4) + text
        author_prefix = bytes([0x12, 0x34, 0x56, 0x78])
        ts = 1_700_000_042
        flags = (TXT_TYPE_SIGNED_PLAIN << 2) | 1
        plaintext = struct.pack("<I", ts) + bytes([flags]) + author_prefix + b"hello room"
        recv_contact = SimpleNamespace(
            public_key=companion.get_public_key().hex(), out_path=[], out_path_len=-1
        )
        payload, _, _ = PacketBuilder._create_encrypted_payload(recv_contact, room, plaintext)
        pkt = Packet()
        pkt.header = PacketBuilder._create_header(PAYLOAD_TYPE_TXT_MSG, "direct", False)
        pkt.path_len, pkt.path = 0, bytearray()
        pkt.payload = bytearray(payload)
        pkt.payload_len = len(payload)

        await bridge.process_received_packet(pkt)
        for _ in range(100):
            if bridge.message_queue.count:
                break
            await asyncio.sleep(0.01)

        msg = bridge.sync_next_message()
        assert msg is not None
        assert msg.text == "hello room"  # first 4 characters intact
        assert msg.txt_type == TXT_TYPE_SIGNED_PLAIN
        assert msg.sender_prefix == author_prefix
        assert msg.timestamp == ts

        # The app frame must match firmware queueMessage byte-for-byte:
        # code + room_pubkey_prefix(6) + path_len + txt_type + timestamp(4)
        # + author_prefix(4) + text
        server = CompanionFrameServer(bridge, "hash", port=0)
        server._app_target_ver = 0
        frame = server._build_message_frame(msg)
        assert frame == (
            bytes([RESP_CODE_CONTACT_MSG_RECV])
            + room.get_public_key()[:6]
            + bytes([msg.path_len, TXT_TYPE_SIGNED_PLAIN])
            + struct.pack("<I", ts)
            + author_prefix
            + b"hello room"
        )
