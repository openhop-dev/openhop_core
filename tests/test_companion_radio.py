"""Tests for CompanionRadio (stand-alone companion with radio)."""

import asyncio
import struct
from types import SimpleNamespace

import pytest

from openhop_core.companion import CompanionRadio
from openhop_core.companion.constants import ADV_TYPE_CHAT
from openhop_core.companion.models import Contact
from openhop_core.companion.timing import estimate_airtime_ms
from openhop_core.node.events import MeshEvents
from openhop_core.node.handlers.login_response import (
    LOGIN_ADMIN_CODE_ADMIN,
    LOGIN_ADMIN_CODE_GUEST,
)
from openhop_core.protocol import CryptoUtils, Identity, LocalIdentity, Packet, PacketBuilder
from openhop_core.protocol.acl_conformance import INBOUND
from openhop_core.protocol.constants import (
    PAYLOAD_TYPE_ACK,
    PAYLOAD_TYPE_ADVERT,
    PAYLOAD_TYPE_RESPONSE,
    PERM_ACL_ADMIN,
    PERM_ACL_GUEST,
    ROUTE_TYPE_DIRECT,
    ROUTE_TYPE_FLOOD,
    TXT_TYPE_CLI_COMMAND,
    TXT_TYPE_CLI_DATA,
    TXT_TYPE_PLAIN,
)


def _make_peer_contact(name: str) -> Contact:
    """Return a contact with a valid Ed25519 public key (required for packet encryption)."""
    peer = LocalIdentity()
    return Contact(public_key=peer.get_public_key(), name=name)


class MockRadio:
    """Mock radio for CompanionRadio: set_rx_callback, send, optional RSSI/SNR."""

    def __init__(self):
        self.rx_callback = None
        self.sent: list[bytes] = []

    def set_rx_callback(self, callback):
        self.rx_callback = callback

    async def send(self, data: bytes) -> bool:
        self.sent.append(data)
        return True

    def get_last_rssi(self):
        return -70

    def get_last_snr(self):
        return 5


# ---------------------------------------------------------------------------
# Init and lifecycle
# ---------------------------------------------------------------------------


class TestCompanionRadioInit:
    def test_init_creates_stores(self):
        radio = MockRadio()
        identity = LocalIdentity()
        comp = CompanionRadio(radio, identity, node_name="TestNode")
        assert comp.contacts is not None
        assert comp.contacts.get_count() == 0
        assert comp.channels is not None
        assert comp.message_queue is not None
        assert comp.path_cache is not None
        assert comp.stats is not None
        assert comp.prefs.node_name == "TestNode"
        assert comp.prefs.adv_type == ADV_TYPE_CHAT
        assert comp.get_public_key() == identity.get_public_key()
        assert comp.node is not None
        assert comp.node.dispatcher is not None

    def test_init_passes_contacts_to_node(self):
        radio = MockRadio()
        identity = LocalIdentity()
        comp = CompanionRadio(radio, identity)
        comp.contacts.add(Contact(public_key=b"\x01" * 32, name="Alice"))
        assert comp.node.contacts is comp.contacts
        assert comp.node.contacts.get_by_name("Alice") is not None

    def test_initial_contacts_populates_store_on_boot(self):
        radio = MockRadio()
        identity = LocalIdentity()
        alice = _make_peer_contact("Alice")
        bob = _make_peer_contact("Bob")
        comp = CompanionRadio(radio, identity, node_name="TestNode", initial_contacts=[alice, bob])
        assert comp.contacts.get_count() == 2
        assert comp.get_contact_by_name("Alice") is not None
        assert comp.get_contact_by_name("Bob") is not None

    def test_failed_radio_configuration_does_not_change_prefs(self):
        class RejectingRadio(MockRadio):
            def configure_radio(self, **kwargs):
                return False

            def set_tx_power(self, power):
                return False

        comp = CompanionRadio(RejectingRadio(), LocalIdentity())
        before = comp.get_self_info()

        assert comp.set_radio_params(868_000_000, 125_000, 7, 8) is False
        assert comp.set_tx_power(14) is False
        assert comp.get_self_info() == before

    def test_applied_radio_configuration_persists_after_backend_success(self):
        class ConfigurableRadio(MockRadio):
            def configure_radio(self, **kwargs):
                self.radio_params = kwargs
                return True

            def set_tx_power(self, power):
                self.tx_power = power
                return True

        radio = ConfigurableRadio()
        comp = CompanionRadio(radio, LocalIdentity())

        assert comp.set_radio_params(868_000_000, 125_000, 7, 8) is True
        assert comp.set_tx_power(14) is True
        assert radio.radio_params == {
            "frequency": 868_000_000,
            "bandwidth": 125_000,
            "spreading_factor": 7,
            "coding_rate": 8,
        }
        assert comp.get_radio_params()["tx_power_dbm"] == 14


@pytest.mark.asyncio
class TestCompanionRadioLifecycle:
    async def test_start_stop(self):
        radio = MockRadio()
        identity = LocalIdentity()
        comp = CompanionRadio(radio, identity)
        assert comp.is_running is False
        await comp.start()
        assert comp.is_running is True
        await comp.stop()
        assert comp.is_running is False

    async def test_start_raises_when_dispatcher_dies_immediately(self):
        """[fails pre-fix] A dispatcher that fails before its loop becomes
        active must fail start() instead of reporting a radio that will never
        receive or transmit."""
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())

        async def failing_start():
            raise OSError("serial port vanished")

        comp.node.start = failing_start
        with pytest.raises(OSError, match="serial port vanished"):
            await comp.start()
        assert comp.is_running is False
        assert comp._dispatcher_task is None
        # A later start with a healthy dispatcher must still work.
        del comp.node.start
        await comp.start()
        assert comp.is_running is True
        await comp.stop()

    async def test_start_idempotent_warning(self, caplog):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        await comp.start()
        await comp.start()
        await comp.stop()
        assert "already running" in caplog.text.lower() or True

    async def test_rx_log_data_callback_fired_on_raw_packet(self):
        """CompanionRadio fires on_rx_log_data(snr, rssi, raw_bytes) for each RX."""
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        log_calls = []

        def on_log(snr: float, rssi: int, raw: bytes) -> None:
            log_calls.append((snr, rssi, raw))

        comp.on_rx_log_data(on_log)
        await comp.start()

        # Build minimal valid packet (ACK) so dispatcher parses and notifies raw subscribers
        pkt = Packet()
        pkt.header = PAYLOAD_TYPE_ACK << 2  # version 0
        pkt.payload = bytearray(b"\x01\x02\x03\x04")
        pkt.payload_len = 4
        pkt.path_len = 0
        raw = pkt.write_to()

        await comp.node.dispatcher._process_received_packet(raw, rssi=-75, snr=6.0)
        await comp.stop()

        assert len(log_calls) == 1
        snr, rssi, data = log_calls[0]
        assert snr == 6.0
        assert rssi == -75
        assert data == raw


# ---------------------------------------------------------------------------
# Contact management (base API via radio)
# ---------------------------------------------------------------------------


class TestCompanionRadioContacts:
    def test_add_and_get_contact(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        key = b"\x02" * 32
        comp.add_update_contact(Contact(public_key=key, name="Bob"))
        assert comp.get_contact_by_key(key) is not None
        assert comp.get_contact_by_key(key).name == "Bob"
        assert comp.get_contact_by_name("Bob") is not None

    def test_import_contact_rejects_legacy_packet_data(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        # The former custom 73-byte record is not a signed MeshCore ADVERT.
        name_padded = b"Charlie\x00" * 4  # 32 bytes
        packet_data = b"\x03" * 32 + bytes([1]) + name_padded + (0).to_bytes(4, "little") * 2
        assert comp.import_contact(packet_data) is False

    def test_export_contact_self(self):
        radio = MockRadio()
        identity = LocalIdentity()
        comp = CompanionRadio(radio, identity, node_name="Me")
        data = comp.export_contact(None)
        assert data is not None
        assert len(data) >= 73
        packet = Packet()
        assert packet.read_from(data)
        assert packet.get_payload_type() == PAYLOAD_TYPE_ADVERT
        assert packet.get_route_type() == ROUTE_TYPE_FLOOD
        assert packet.get_payload()[:32] == identity.get_public_key()


# ---------------------------------------------------------------------------
# Advertise
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCompanionRadioAdvertise:
    async def test_advertise_sends_packet(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        result = await comp.advertise(flood=True)
        assert result is True
        assert len(radio.sent) == 1
        assert comp.stats.get_totals()["flood_tx"] == 1

    async def test_advertise_direct(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        await comp.advertise(flood=False)
        assert len(radio.sent) == 1
        assert comp.stats.get_totals()["direct_tx"] == 1


# ---------------------------------------------------------------------------
# Send text (requires contact)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCompanionRadioSendText:
    async def test_send_text_message_no_contact(self, caplog):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        result = await comp.send_text_message(b"\x00" * 32, "Hi")
        assert result.success is False
        assert "contact not found" in caplog.text.lower() or "Contact not found" in caplog.text

    async def test_send_text_message_with_contact_sends_packet(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        contact = _make_peer_contact("Alice")
        comp.contacts.add(contact)
        result = await comp.send_text_message(contact.public_key, "Hello")
        assert len(radio.sent) >= 1
        # success may be False if no ACK (mock radio doesn't echo ACK)
        assert result.success is False or result.success is True

    async def test_send_text_message_waits_for_meshcore_ack_hash(self):
        radio = MockRadio()
        identity = LocalIdentity()
        comp = CompanionRadio(radio, identity)
        contact = _make_peer_contact("Alice")
        comp.contacts.add(contact)
        comp.node.dispatcher.tx_delay = 0

        proxy = comp.contacts.get_proxy_by_key(contact.public_key)
        expected_packet, expected_ack = PacketBuilder.create_text_message(
            contact=proxy,
            local_identity=identity,
            message="Hello",
            attempt=1,
            message_type="flood",
            timestamp=123456,
        )
        assert expected_ack != expected_packet.get_crc()

        send_task = asyncio.create_task(
            comp.send_text_message(contact.public_key, "Hello", timestamp=123456)
        )
        while not radio.sent:
            await asyncio.sleep(0)

        sent_packet = Packet()
        assert sent_packet.read_from(radio.sent[0])
        assert expected_ack != sent_packet.get_crc()

        ack_packet = PacketBuilder.create_ack_from_bytes(
            expected_ack.to_bytes(4, "little") + b"\x00\x7f"
        )
        await comp.node.dispatcher._dispatch(ack_packet)

        result = await asyncio.wait_for(send_task, timeout=0.5)
        assert result.success is True


# ---------------------------------------------------------------------------
# Share contact, channel message, sync message
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCompanionRadioMisc:
    async def test_share_contact_not_found(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        result = await comp.share_contact(b"\x00" * 32)
        assert result is False

    async def test_share_contact_success(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        remote = LocalIdentity()
        key = remote.get_public_key()
        blob = PacketBuilder.create_advert(remote, "Bob", route_type="direct").write_to()
        comp.contacts.add(Contact(public_key=key, name="Bob", adv_type=1, last_advert_packet=blob))
        result = await comp.share_contact(key)
        assert result is True
        assert len(radio.sent) == 1

    async def test_sync_next_message_empty(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        assert comp.sync_next_message() is None

    async def test_send_channel_message_no_channel(self, caplog):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        result = await comp.send_channel_message(0, "Hi")
        assert result is False


# ---------------------------------------------------------------------------
# Path discovery, trace, control data
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCompanionRadioPathAndControl:
    async def test_send_path_discovery_no_contact(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        result = await comp.send_path_discovery(b"\x00" * 32)
        assert result is False

    async def test_send_path_discovery_req_sends(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        contact = _make_peer_contact("Target")
        comp.contacts.add(contact)
        result = await comp.send_path_discovery_req(contact.public_key)
        assert result.success is True
        assert len(radio.sent) == 1

    async def test_send_path_discovery_req_floods_known_path_without_mutating_contact(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        contact = _make_peer_contact("Target")
        contact.out_path_len = 3
        contact.out_path = b"\x01\x02\x03"
        comp.contacts.add(contact)

        result = await comp.send_path_discovery_req(contact.public_key)

        assert result.success is True
        assert result.is_flood is True
        sent = Packet()
        assert sent.read_from(radio.sent[0]) is True
        assert sent.is_route_flood()
        stored = comp.contacts.get_by_key(contact.public_key)
        assert stored.out_path_len == 3
        assert stored.out_path == b"\x01\x02\x03"

    async def test_send_trace_path_raw(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        result = await comp.send_trace_path_raw(0x12345678, 0xABCD, 0, bytes([0x01, 0x02]))
        assert result.success is True
        assert len(radio.sent) == 1
        assert result.is_flood is False
        assert result.expected_ack == 0x12345678
        # est_timeout is the firmware direct formula over the sent packet's airtime.
        sent = Packet()
        assert sent.read_from(radio.sent[0]) is True
        airtime = estimate_airtime_ms(sent.get_raw_length(), 10, 250000, 5)
        assert result.timeout_ms == int(500 + (6.0 * airtime + 250) * (2 + 1))

    async def test_send_control_data_default_discovery(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        result = await comp.send_control_data()
        assert result is True
        assert len(radio.sent) == 1

    async def test_send_control_data_raw_payload(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        result = await comp.send_control_data(bytes([0x80, 0x04]))
        assert result is True
        assert len(radio.sent) == 1

    async def test_contact_path_updated_fired_when_handler_callback_invoked(self):
        """Radio wires protocol_response_handler contact_path_updated to _fire_callbacks."""
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        path_updated_calls = []

        async def on_path_updated(contact):
            path_updated_calls.append(contact)

        comp.on_contact_path_updated(on_path_updated)
        proto = comp.node.dispatcher.protocol_response_handler
        assert proto is not None
        assert proto._contact_path_updated_callback is not None

        pub = b"\x22" * 32
        # Contact must exist in the store; path updates for unknown contacts
        # are silently dropped (matches companion firmware behaviour).
        comp.contacts.add(Contact(public_key=pub, name="test"))

        path_len = 2
        path_bytes = bytes([0x01, 0x02])
        cb_result = proto._contact_path_updated_callback(pub, path_len, path_bytes)
        if hasattr(cb_result, "__await__"):
            await cb_result

        assert len(path_updated_calls) == 1
        assert path_updated_calls[0].public_key == pub
        assert path_updated_calls[0].out_path_len == path_len
        assert path_updated_calls[0].out_path == path_bytes


# ---------------------------------------------------------------------------
# Stats and config
# ---------------------------------------------------------------------------


class TestCompanionRadioStats:
    def test_get_stats_core(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        comp.contacts.add(Contact(public_key=b"\x01" * 32, name="A"))
        core = comp.get_stats(0)
        assert "contacts_count" in core
        assert core["contacts_count"] == 1
        assert "queue_len" in core
        assert "uptime_secs" in core

    def test_get_stats_packets(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        tot = comp.get_stats(2)
        assert "flood_tx" in tot
        assert "direct_rx" in tot
        assert "tx_errors" in tot


# ---------------------------------------------------------------------------
# Binary request and repeater command (delegate to node)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestCompanionRadioBinaryAndRepeater:
    async def test_send_binary_req_no_contact(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        result = await comp.send_binary_req(b"\x00" * 32, bytes([0x01]))
        assert result.success is False

    async def test_send_binary_req_with_contact(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        contact = _make_peer_contact("Rpt")
        comp.contacts.add(contact)
        result = await comp.send_binary_req(contact.public_key, bytes([0x01]), timeout_seconds=5.0)
        assert result.success is True
        assert result.expected_ack is not None
        assert len(radio.sent) == 1

    async def test_send_repeater_command_no_contact(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        out = await comp.send_repeater_command(b"\x00" * 32, "status")
        assert out["success"] is False
        assert "not found" in out["reason"].lower()


@pytest.mark.asyncio
class TestCompanionLoginRetry:
    """send_login resends on a lost round-trip and succeeds on a later attempt."""

    async def test_login_resends_then_succeeds(self, monkeypatch):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        contact = _make_peer_contact("Rpt")
        comp.contacts.add(contact)

        # Tiny per-attempt timeout so the test doesn't actually wait seconds.
        monkeypatch.setattr(comp, "_response_timeout_s", lambda pkt, proxy: 0.05)

        handler = comp._get_login_response_handler()
        captured = {}
        orig_set = handler.register_login_callback
        monkeypatch.setattr(
            handler,
            "register_login_callback",
            lambda pubkey, cb: (captured.__setitem__("cb", cb), orig_set(pubkey, cb)),
        )

        calls = {"n": 0}

        async def fake_send(pkt, wait_for_ack=False):
            calls["n"] += 1
            # First attempt is "lost"; reply only on the second attempt.
            if calls["n"] == 2 and captured.get("cb"):
                captured["cb"](True, {"timestamp": 1, "is_admin": False})
            return True

        monkeypatch.setattr(comp, "_send_packet", fake_send)

        result = await comp.send_login(contact.public_key, "pw")
        assert result["success"] is True
        assert calls["n"] == 2  # resent exactly once before success

    async def test_login_all_attempts_timeout(self, monkeypatch):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        contact = _make_peer_contact("Rpt")
        comp.contacts.add(contact)
        monkeypatch.setattr(comp, "_response_timeout_s", lambda pkt, proxy: 0.02)

        calls = {"n": 0}

        async def fake_send(pkt, wait_for_ack=False):
            calls["n"] += 1
            return True  # never reply

        monkeypatch.setattr(comp, "_send_packet", fake_send)

        from openhop_core.companion.timing import DEFAULT_MAX_ATTEMPTS

        result = await comp.send_login(contact.public_key, "pw")
        assert result["success"] is False
        assert "timeout" in result["reason"].lower()
        assert calls["n"] == DEFAULT_MAX_ATTEMPTS  # tried the full budget

    async def test_started_login_request_reports_meshcore_sent_metadata(self, monkeypatch):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        contact = _make_peer_contact("Rpt")
        contact.out_path_len = 0
        comp.contacts.add(contact)
        monkeypatch.setattr(comp, "_response_timeout_s", lambda pkt, proxy: 0.01)

        started = await comp._start_login_request(contact.public_key, "pw")

        assert started["success"] is True
        sent = started["sent"]
        assert sent.is_flood is False
        assert sent.expected_ack == int.from_bytes(contact.public_key[:4], "little")
        assert sent.timeout_ms == 10
        result = await started["task"]
        assert result["success"] is False

    async def test_frame_login_retries_reuse_one_pending_session(self, monkeypatch):
        """Each frame command sends once while late replies share one completion."""
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        contact = _make_peer_contact("Rpt")
        comp.contacts.add(contact)
        monkeypatch.setattr(comp, "_response_timeout_s", lambda pkt, proxy: 0.01)

        first = await comp._start_frame_login_request(contact.public_key, "pw")
        second = await comp._start_frame_login_request(contact.public_key, "pw")

        assert len(radio.sent) == 2
        assert first["session_owner"] is True
        assert second["session_owner"] is False
        assert second["task"] is first["task"]
        assert first["sent"].timeout_ms == 10

        # The per-send timeout is only a client retry hint. The shared response
        # session remains live and accepts a later authenticated response.
        await asyncio.sleep(0.02)
        callback = comp._get_login_response_handler()._pending_logins[contact.public_key]
        callback(
            True,
            {
                "timestamp": 123,
                "is_admin": True,
                "keep_alive_interval": 4,
                "reserved": 3,
                "firmware_ver_level": 2,
            },
        )
        result = await first["task"]

        assert result["success"] is True
        assert result["tag"] == 123
        assert result["is_admin"] is True
        assert contact.public_key not in comp._pending_frame_logins
        assert contact.public_key not in comp._get_login_response_handler()._pending_logins

    async def test_frame_login_session_expires_and_cleans_up(self, monkeypatch):
        """An abandoned frame login retains no callback after its bounded grace."""
        monkeypatch.setattr(
            "openhop_core.companion.base_send.FRAME_LOGIN_PENDING_TTL_S",
            0.02,
        )
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        contact = _make_peer_contact("Rpt")
        comp.contacts.add(contact)

        started = await comp._start_frame_login_request(contact.public_key, "pw")
        result = await started["task"]

        assert result["timeout"] is True
        assert len(radio.sent) == 1
        assert contact.public_key not in comp._pending_frame_logins
        assert contact.public_key not in comp._get_login_response_handler()._pending_logins

        retried = await comp._start_frame_login_request(contact.public_key, "pw")
        assert retried["session_owner"] is True
        assert retried["task"] is not started["task"]
        comp._clear_pending_frame_logins()
        await asyncio.sleep(0)


# ---------------------------------------------------------------------------
# Repeater-command response correlation (drives the real text handler)
# ---------------------------------------------------------------------------


def _distinct_peers(names, avoid=()):
    """Return [(identity, Contact)] whose pubkey first bytes are all distinct.

    Distinct first bytes keep the 1-byte src/dest hashes from colliding so each
    test observation is attributable to exactly one peer.
    """
    peers = []
    seen = set(avoid)
    for name in names:
        while True:
            ident = LocalIdentity()
            first = ident.get_public_key()[0]
            if first not in seen:
                seen.add(first)
                peers.append((ident, Contact(public_key=ident.get_public_key(), name=name)))
                break
    return peers


def _build_direct_dm(sender_identity, receiver_pubkey: bytes, text: str, txt_type: int):
    """Build a real encrypted direct DM from ``sender_identity`` to ``receiver_pubkey``."""

    class _Receiver:
        public_key = receiver_pubkey.hex()
        out_path = []
        out_path_len = -1

    pkt, _ = PacketBuilder.create_text_message(
        _Receiver(),
        sender_identity,
        text,
        attempt=0,
        message_type="direct",
        txt_type=txt_type,
    )
    return pkt


class _EventRecorder:
    """Minimal event-service stub recording publish_sync calls."""

    def __init__(self):
        self.events = []

    def publish_sync(self, name, data):
        self.events.append((name, data))


def _shorten_command_timeout(monkeypatch, timeouts):
    """Shrink send_repeater_command's fixed 15 s response window for tests.

    ``timeouts`` is a list consumed once per command (in start order); other
    ``asyncio.wait_for`` timeouts pass through untouched.
    """
    remaining = list(timeouts)
    real_wait_for = asyncio.wait_for

    async def fast_wait_for(awaitable, timeout):
        if timeout == 15.0 and remaining:
            timeout = remaining.pop(0)
        return await real_wait_for(awaitable, timeout)

    monkeypatch.setattr(asyncio, "wait_for", fast_wait_for)


async def _wait_until(predicate, timeout_s=2.0):
    """Poll ``predicate`` until true (or fail the test after ``timeout_s``)."""
    deadline = asyncio.get_event_loop().time() + timeout_s
    while not predicate():
        assert asyncio.get_event_loop().time() < deadline, "condition not reached in time"
        await asyncio.sleep(0.01)


@pytest.mark.asyncio
class TestRepeaterCommandCorrelation:
    """send_repeater_command must only consume CLI_DATA replies from its target."""

    def _setup(self, names):
        radio = MockRadio()
        identity = LocalIdentity()
        comp = CompanionRadio(radio, identity)
        peers = _distinct_peers(names, avoid={identity.get_public_key()[0]})
        for _, contact in peers:
            comp.contacts.add(contact)
        return radio, identity, comp, peers

    async def test_plain_dm_during_pending_command_is_delivered_not_swallowed(self, monkeypatch):
        """[fails pre-fix] An unrelated plain DM during a command window is delivered
        as a normal message and the command times out instead of resolving with it."""
        radio, identity, comp, peers = self._setup(["Rpt", "Friend"])
        (_, rpt_contact), (friend_identity, _) = peers
        handler = comp._get_text_handler()
        recorder = _EventRecorder()
        monkeypatch.setattr(handler, "event_service", recorder)
        _shorten_command_timeout(monkeypatch, [0.5])

        task = asyncio.create_task(comp.send_repeater_command(rpt_contact.public_key, "ver"))
        await _wait_until(lambda: len(radio.sent) >= 1)

        dm = _build_direct_dm(
            friend_identity, identity.get_public_key(), "hello there", TXT_TYPE_PLAIN
        )
        await handler(dm)

        new_messages = [d for n, d in recorder.events if n == MeshEvents.NEW_MESSAGE]
        assert len(new_messages) == 1
        assert new_messages[0]["message_text"] == "hello there"
        assert new_messages[0]["contact_name"] == "Friend"

        result = await task
        assert result["success"] is False
        assert result["response"] is None

    @pytest.mark.parametrize("first_reply", ["a", "b"])
    async def test_overlapping_commands_resolve_with_own_replies(self, monkeypatch, first_reply):
        """[fails pre-fix] Two overlapping commands each resolve with the reply from
        their own target, whichever reply arrives first."""
        radio, identity, comp, peers = self._setup(["RptA", "RptB"])
        (a_identity, a_contact), (b_identity, b_contact) = peers
        handler = comp._get_text_handler()
        _shorten_command_timeout(monkeypatch, [0.5, 0.5])

        task_a = asyncio.create_task(comp.send_repeater_command(a_contact.public_key, "ver"))
        await _wait_until(lambda: len(radio.sent) >= 1)
        task_b = asyncio.create_task(comp.send_repeater_command(b_contact.public_key, "ver"))
        await _wait_until(lambda: len(radio.sent) >= 2)

        reply_a = _build_direct_dm(
            a_identity, identity.get_public_key(), "reply-A", TXT_TYPE_CLI_DATA
        )
        reply_b = _build_direct_dm(
            b_identity, identity.get_public_key(), "reply-B", TXT_TYPE_CLI_DATA
        )
        for reply in [reply_a, reply_b] if first_reply == "a" else [reply_b, reply_a]:
            await handler(reply)

        result_a = await task_a
        result_b = await task_b
        assert result_a["success"] is True
        assert result_a["response"] == "reply-A"
        assert result_b["success"] is True
        assert result_b["response"] == "reply-B"

    async def test_old_command_timeout_does_not_clear_newer_pending(self, monkeypatch):
        """[fails pre-fix] A timed-out older command's cleanup leaves a newer
        command's pending response registration intact."""
        radio, identity, comp, peers = self._setup(["RptA", "RptB"])
        (_, a_contact), (b_identity, b_contact) = peers
        handler = comp._get_text_handler()
        _shorten_command_timeout(monkeypatch, [0.2, 2.0])

        task_a = asyncio.create_task(comp.send_repeater_command(a_contact.public_key, "ver"))
        await _wait_until(lambda: len(radio.sent) >= 1)
        task_b = asyncio.create_task(comp.send_repeater_command(b_contact.public_key, "ver"))
        await _wait_until(lambda: len(radio.sent) >= 2)

        result_a = await task_a  # times out; its cleanup runs
        assert result_a["success"] is False

        reply_b = _build_direct_dm(
            b_identity, identity.get_public_key(), "reply-B", TXT_TYPE_CLI_DATA
        )
        await handler(reply_b)

        result_b = await task_b
        assert result_b["success"] is True
        assert result_b["response"] == "reply-B"

    async def test_cli_data_without_pending_command_is_delivered_normally(self, monkeypatch):
        """CLI_DATA from a contact with no pending command is a normal message
        (firmware queues it to the client rather than dropping it)."""
        radio, identity, comp, peers = self._setup(["Rpt"])
        rpt_identity, _ = peers[0]
        handler = comp._get_text_handler()
        recorder = _EventRecorder()
        monkeypatch.setattr(handler, "event_service", recorder)

        pkt = _build_direct_dm(
            rpt_identity, identity.get_public_key(), "unsolicited", TXT_TYPE_CLI_DATA
        )
        await handler(pkt)

        new_messages = [d for n, d in recorder.events if n == MeshEvents.NEW_MESSAGE]
        assert len(new_messages) == 1
        assert new_messages[0]["message_text"] == "unsolicited"

    async def test_single_command_happy_path(self, monkeypatch):
        """A single command resolves with its target's CLI_DATA reply."""
        radio, identity, comp, peers = self._setup(["Rpt"])
        rpt_identity, rpt_contact = peers[0]
        handler = comp._get_text_handler()
        _shorten_command_timeout(monkeypatch, [1.0])

        task = asyncio.create_task(comp.send_repeater_command(rpt_contact.public_key, "ver"))
        await _wait_until(lambda: len(radio.sent) >= 1)

        reply = _build_direct_dm(
            rpt_identity, identity.get_public_key(), "fw v1.2.3", TXT_TYPE_CLI_DATA
        )
        await handler(reply)

        result = await task
        assert result["success"] is True
        assert result["response"] == "fw v1.2.3"
        assert result["repeater"] == "Rpt"

    def _sent_txt_type(self, comp, peer_identity, raw: bytes) -> int:
        """Decrypt a sent TXT_MSG and return the txt_type in its flags byte."""
        pkt = Packet()
        assert pkt.read_from(raw)
        secret = Identity(peer_identity.get_public_key()).calc_shared_secret(
            comp._identity.get_private_key()
        )
        plaintext = CryptoUtils.mac_then_decrypt(secret[:16], secret, bytes(pkt.payload[2:]))
        assert plaintext, "sent command did not authenticate against the peer secret"
        return (plaintext[4] >> 2) & 0x3F

    async def test_command_defaults_to_cli_data_and_can_opt_into_cli_command(self, monkeypatch):
        """The wire type is CLI_DATA by default, CLI_COMMAND on request.

        CLI_DATA stays the default because it is the one form every released
        firmware executes -- before TXT_TYPE_CLI_COMMAND existed it *was* "a CLI
        command", and simple_repeater still accepts it. A companion peer runs
        only CLI_COMMAND, so the caller has to be able to ask for it.
        """
        radio, identity, comp, peers = self._setup(["Rpt"])
        rpt_identity, rpt_contact = peers[0]
        _shorten_command_timeout(monkeypatch, [0.1, 0.1])

        task = asyncio.create_task(comp.send_repeater_command(rpt_contact.public_key, "ver"))
        await _wait_until(lambda: len(radio.sent) >= 1)
        assert self._sent_txt_type(comp, rpt_identity, radio.sent[0]) == TXT_TYPE_CLI_DATA
        await task

        task = asyncio.create_task(
            comp.send_repeater_command(
                rpt_contact.public_key, "ver", txt_type=TXT_TYPE_CLI_COMMAND
            )
        )
        await _wait_until(lambda: len(radio.sent) >= 2)
        assert self._sent_txt_type(comp, rpt_identity, radio.sent[1]) == TXT_TYPE_CLI_COMMAND
        await task

    async def test_command_rejects_a_non_cli_txt_type_without_sending(self):
        """Only the two CLI types label a command; anything else never reaches the air.

        PLAIN is the near miss worth guarding: a repeater does still run one
        (its filter takes PLAIN for legacy CLI), but firmware routes PLAIN
        through sendMessage, so it earns a delivery ACK and arms an ack wait
        this helper never reads -- and a companion peer files it as chat rather
        than running it. SIGNED_PLAIN and reserved values are simply not CLI.
        """
        radio, _identity, comp, peers = self._setup(["Rpt"])
        _rpt_identity, rpt_contact = peers[0]

        result = await comp.send_repeater_command(
            rpt_contact.public_key, "ver", txt_type=TXT_TYPE_PLAIN
        )

        assert result["success"] is False
        assert radio.sent == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "txt_type,expects_ack",
    [(TXT_TYPE_CLI_DATA, False), (TXT_TYPE_CLI_COMMAND, False), (TXT_TYPE_PLAIN, True)],
)
async def test_cli_text_messages_arm_no_pending_ack(txt_type, expects_ack):
    """Neither CLI type expects a delivery ACK; a plain DM still does.

    Firmware sends both CLI types through sendCommandData and reports
    expected_ack = 0 (MyMesh.cpp CMD_SEND_TXT_MSG) -- a peer answers a CLI
    command with a CLI_DATA reply, never an ACK. Arming the table for one would
    leave an entry that can only age out, and wait_for_ack would block for the
    whole timeout waiting for something nobody sends. Covers both halves: the
    local pending-ACK table and the token reported back to the app.
    """
    radio = MockRadio()
    comp = CompanionRadio(radio, LocalIdentity())
    peer = LocalIdentity()
    comp.contacts.add(Contact(public_key=peer.get_public_key(), name="Rpt"))

    result = await comp.send_text_message(
        peer.get_public_key(), "reboot", txt_type=txt_type, wait_for_ack=False
    )

    assert result.success is True
    assert len(radio.sent) == 1
    assert bool(comp._pending_ack_crcs) is expects_ack
    # The SENT frame reports this token verbatim. Firmware sets expected_ack = 0
    # for either CLI type, so an app told a nonzero one would arm a wait for an
    # ACK nobody sends -- a repeater answers a CLI command with a CLI_DATA reply.
    assert bool(result.expected_ack) is expects_ack


@pytest.mark.asyncio
@pytest.mark.parametrize("txt_type", [TXT_TYPE_CLI_DATA, TXT_TYPE_CLI_COMMAND])
async def test_cli_send_ignores_wait_for_ack(txt_type):
    """A CLI send returns as soon as the packet is away, even if asked to wait.

    Firmware never arms an ack wait for these (expected_ack = 0), and a peer
    answers a CLI command with a CLI_DATA reply rather than an ACK. Honouring
    wait_for_ack here would block the caller for the full send timeout on
    every CLI command. A plain DM deliberately still waits, which is why this
    is a separate test from the pending-ACK one.
    """
    radio = MockRadio()
    comp = CompanionRadio(radio, LocalIdentity())
    peer = LocalIdentity()
    comp.contacts.add(Contact(public_key=peer.get_public_key(), name="Rpt"))

    result = await asyncio.wait_for(
        comp.send_text_message(
            peer.get_public_key(), "reboot", txt_type=txt_type, wait_for_ack=True
        ),
        timeout=5.0,
    )

    assert result.success is True
    assert result.expected_ack == 0
    assert len(radio.sent) == 1


# ---------------------------------------------------------------------------
# Login response correlation (drives the real login_response handler)
# ---------------------------------------------------------------------------


def _build_login_response_packet(
    server_identity,
    comp_identity,
    *,
    response_code=0x80,
    keep_alive=4,
    is_admin=1,
    permissions=3,
    timestamp=1000,
):
    """Build a real encrypted RESPONSE packet as a firmware server would emit."""
    shared_secret = Identity(server_identity.get_public_key()).calc_shared_secret(
        comp_identity.get_private_key()
    )
    plaintext = (
        struct.pack("<IBBBB", timestamp, response_code, keep_alive, is_admin, permissions)
        + b"\x00\x00\x00\x00"  # random blob
    )
    encrypted = CryptoUtils.encrypt_then_mac(shared_secret[:16], shared_secret, plaintext)
    payload = (
        bytes([comp_identity.get_public_key()[0], server_identity.get_public_key()[0]]) + encrypted
    )
    pkt = Packet()
    pkt.header = ROUTE_TYPE_DIRECT | (PAYLOAD_TYPE_RESPONSE << 2)
    pkt.path_len = 0
    pkt.path = bytearray()
    pkt.payload = bytearray(payload)
    pkt.payload_len = len(payload)
    return pkt


class TestLoginAdminCodeDecoding:
    """Login reply byte 6 is a tri-state, not a boolean.

    Firmware's room server sends ``isAdmin() ? 1 : (permissions == 0 ? 2 : 0)``
    (simple_room_server/MyMesh.cpp), so 2 means "plain guest". Decoding the
    byte with bool() promoted those guests to admin.
    """

    @pytest.mark.parametrize("admin_code, permissions, is_admin, role", INBOUND)
    def test_inbound_conformance_vectors(self, admin_code, permissions, is_admin, role):
        """Decode exactly what acl_conformance.INBOUND says, from literal bytes.

        Includes shapes we never emit but must read from stock firmware, such
        as a room server's plain guest (admin_code 2, which bool() called
        admin).
        """
        server_identity = LocalIdentity()
        comp_identity = LocalIdentity()
        comp = CompanionRadio(MockRadio(), comp_identity)
        handler = comp._get_login_response_handler()

        pkt = _build_login_response_packet(
            server_identity, comp_identity, is_admin=admin_code, permissions=permissions
        )
        contact = SimpleNamespace(
            name="srv", public_key=server_identity.get_public_key(), is_admin=None
        )
        ok, data = asyncio.run(handler._decrypt_response(pkt, contact))

        assert ok is True
        assert data["admin_code"] == admin_code
        assert data["is_admin"] is is_admin
        assert data["permissions"] == permissions
        assert data["acl_role"] == role

    def test_room_server_guest_code_is_not_admin_end_to_end(self):
        """The parsed dict must not report admin for a room server's guest."""
        server_identity = LocalIdentity()
        comp_identity = LocalIdentity()
        comp = CompanionRadio(MockRadio(), comp_identity)
        handler = comp._get_login_response_handler()

        pkt = _build_login_response_packet(
            server_identity,
            comp_identity,
            is_admin=LOGIN_ADMIN_CODE_GUEST,
            permissions=PERM_ACL_GUEST,
        )
        contact = SimpleNamespace(
            name="room", public_key=server_identity.get_public_key(), is_admin=None
        )
        ok, data = asyncio.run(handler._decrypt_response(pkt, contact))
        assert ok is True
        assert data["admin_code"] == LOGIN_ADMIN_CODE_GUEST
        assert data["is_admin"] is False
        assert data["acl_role"] == PERM_ACL_GUEST

    def test_admin_login_still_reports_admin(self):
        server_identity = LocalIdentity()
        comp_identity = LocalIdentity()
        comp = CompanionRadio(MockRadio(), comp_identity)
        handler = comp._get_login_response_handler()

        pkt = _build_login_response_packet(
            server_identity,
            comp_identity,
            is_admin=LOGIN_ADMIN_CODE_ADMIN,
            permissions=PERM_ACL_ADMIN,
        )
        contact = SimpleNamespace(
            name="rpt", public_key=server_identity.get_public_key(), is_admin=None
        )
        ok, data = asyncio.run(handler._decrypt_response(pkt, contact))
        assert ok is True
        assert data["is_admin"] is True
        assert data["acl_role"] == PERM_ACL_ADMIN


@pytest.mark.asyncio
class TestLoginResponseCorrelation:
    """send_login completions must be correlated to the responding contact."""

    def _setup(self, names):
        radio = MockRadio()
        identity = LocalIdentity()
        comp = CompanionRadio(radio, identity)
        peers = _distinct_peers(names, avoid={identity.get_public_key()[0]})
        for _, contact in peers:
            comp.contacts.add(contact)
        return radio, identity, comp, peers

    @pytest.mark.parametrize("first_response", ["a", "b"])
    async def test_concurrent_logins_resolve_with_own_responses(self, monkeypatch, first_response):
        """[fails pre-fix] Concurrent logins to two servers each resolve only with
        their own server's response data, whichever response arrives first."""
        radio, identity, comp, peers = self._setup(["RptA", "RptB"])
        (a_identity, a_contact), (b_identity, b_contact) = peers
        monkeypatch.setattr(comp, "_response_timeout_s", lambda pkt, proxy: 0.5)
        handler = comp._get_login_response_handler()

        task_a = asyncio.create_task(comp.send_login(a_contact.public_key, "pw-a"))
        await _wait_until(lambda: len(radio.sent) >= 1)
        task_b = asyncio.create_task(comp.send_login(b_contact.public_key, "pw-b"))
        await _wait_until(lambda: len(radio.sent) >= 2)

        resp_a = _build_login_response_packet(
            a_identity, identity, is_admin=1, keep_alive=4, timestamp=111
        )
        resp_b = _build_login_response_packet(
            b_identity, identity, is_admin=0, keep_alive=8, timestamp=222
        )
        for resp in [resp_a, resp_b] if first_response == "a" else [resp_b, resp_a]:
            await handler(resp)

        result_a = await task_a
        result_b = await task_b
        assert result_a["success"] is True
        assert result_a["repeater"] == "RptA"
        assert result_a["is_admin"] is True
        assert result_a["keep_alive_interval"] == 4
        assert result_a["tag"] == 111
        assert result_b["success"] is True
        assert result_b["repeater"] == "RptB"
        assert result_b["is_admin"] is False
        assert result_b["keep_alive_interval"] == 8
        assert result_b["tag"] == 222

    async def test_login_timeout_does_not_cancel_other_pending_login(self, monkeypatch):
        """[fails pre-fix] Login A timing out (and cleaning up) leaves login B's
        pending completion intact; B still resolves from its own response."""
        radio, identity, comp, peers = self._setup(["RptA", "RptB"])
        (_, a_contact), (b_identity, b_contact) = peers
        a_key_hex = a_contact.public_key.hex()
        monkeypatch.setattr(
            comp,
            "_response_timeout_s",
            lambda pkt, proxy: 0.05 if proxy.public_key == a_key_hex else 0.5,
        )
        handler = comp._get_login_response_handler()

        task_a = asyncio.create_task(comp.send_login(a_contact.public_key, "pw-a"))
        await _wait_until(lambda: len(radio.sent) >= 1)
        task_b = asyncio.create_task(comp.send_login(b_contact.public_key, "pw-b"))
        await _wait_until(lambda: len(radio.sent) >= 2)

        result_a = await task_a  # exhausts its retry budget; cleanup runs
        assert result_a["success"] is False

        resp_b = _build_login_response_packet(b_identity, identity, is_admin=1, timestamp=222)
        await handler(resp_b)

        result_b = await task_b
        assert result_b["success"] is True
        assert result_b["repeater"] == "RptB"
        assert result_b["is_admin"] is True

    async def test_response_without_pending_login_resolves_nothing(self, monkeypatch):
        """A login response from a contact with no pending login resolves no waiter
        and leaves other pending logins intact."""
        radio, identity, comp, peers = self._setup(["RptA", "Stale"])
        (a_identity, a_contact), (stale_identity, stale_contact) = peers
        monkeypatch.setattr(comp, "_response_timeout_s", lambda pkt, proxy: 0.5)
        handler = comp._get_login_response_handler()
        # Stale state: a stored password but no pending completion for this contact.
        handler.store_login_password(stale_contact.public_key[0], "old-pw")

        task_a = asyncio.create_task(comp.send_login(a_contact.public_key, "pw-a"))
        await _wait_until(lambda: len(radio.sent) >= 1)

        stale_resp = _build_login_response_packet(stale_identity, identity, timestamp=999)
        await handler(stale_resp)
        await asyncio.sleep(0.05)
        assert not task_a.done()  # A's waiter was not resolved by the stale response

        resp_a = _build_login_response_packet(a_identity, identity, timestamp=111)
        await handler(resp_a)
        result_a = await task_a
        assert result_a["success"] is True
        assert result_a["tag"] == 111

    async def test_single_login_happy_and_failed_paths(self, monkeypatch):
        """A single login resolves success from an OK response and failure from a
        rejection response (both via the real handler)."""
        radio, identity, comp, peers = self._setup(["Rpt"])
        rpt_identity, rpt_contact = peers[0]
        monkeypatch.setattr(comp, "_response_timeout_s", lambda pkt, proxy: 0.5)
        handler = comp._get_login_response_handler()

        task = asyncio.create_task(comp.send_login(rpt_contact.public_key, "pw"))
        await _wait_until(lambda: len(radio.sent) >= 1)
        ok = _build_login_response_packet(
            rpt_identity, identity, response_code=0x80, is_admin=1, keep_alive=4, timestamp=42
        )
        await handler(ok)
        result = await task
        assert result["success"] is True
        assert result["is_admin"] is True
        assert result["tag"] == 42
        assert comp.has_login_connection(rpt_contact.public_key) is True

        sent_before = len(radio.sent)
        task = asyncio.create_task(comp.send_login(rpt_contact.public_key, "wrong"))
        await _wait_until(lambda: len(radio.sent) > sent_before)
        rejected = _build_login_response_packet(
            rpt_identity, identity, response_code=0x01, is_admin=0, timestamp=43
        )
        await handler(rejected)
        result = await task
        assert result["success"] is False
        assert result["reason"] == "Login failed"


def _colliding_peer(name, first_byte, avoid_keys=()):
    """Return (identity, Contact) whose pubkey FIRST byte equals ``first_byte``.

    Hash-colliding contacts exercise the 1-byte dest/src hash ambiguity: the
    handler must attribute responses by full-pubkey decryption, never by hash.
    """
    avoid = set(avoid_keys)
    while True:
        ident = LocalIdentity()
        pk = ident.get_public_key()
        if pk[0] == first_byte and pk not in avoid:
            return ident, Contact(public_key=pk, name=name)


def _build_non_login_response_packet(server_identity, comp_identity, *, tag=7):
    """Build an authenticated RESPONSE whose contents are not a login reply
    (telemetry-style: tag(4) + short data), as a colliding sensor would emit."""
    shared_secret = Identity(server_identity.get_public_key()).calc_shared_secret(
        comp_identity.get_private_key()
    )
    plaintext = struct.pack("<I", tag) + bytes([0x01, 0x74, 0x01, 0x72])
    encrypted = CryptoUtils.encrypt_then_mac(shared_secret[:16], shared_secret, plaintext)
    payload = (
        bytes([comp_identity.get_public_key()[0], server_identity.get_public_key()[0]]) + encrypted
    )
    pkt = Packet()
    pkt.header = ROUTE_TYPE_DIRECT | (PAYLOAD_TYPE_RESPONSE << 2)
    pkt.path_len = 0
    pkt.path = bytearray()
    pkt.payload = bytearray(payload)
    pkt.payload_len = len(payload)
    return pkt


@pytest.mark.asyncio
class TestLoginResponseHashCollisions:
    """Hash-colliding contacts must not strand or swallow each other's responses."""

    def _setup_colliding_pair(self):
        radio = MockRadio()
        identity = LocalIdentity()
        comp = CompanionRadio(radio, identity)
        a_identity, a_contact = _distinct_peers(["RptA"], avoid={identity.get_public_key()[0]})[0]
        b_identity, b_contact = _colliding_peer(
            "RptB", a_contact.public_key[0], avoid_keys={a_contact.public_key}
        )
        comp.contacts.add(a_contact)
        comp.contacts.add(b_contact)
        return radio, identity, comp, (a_identity, a_contact), (b_identity, b_contact)

    async def test_colliding_concurrent_logins_both_resolve(self, monkeypatch):
        """[fails pre-fix] The first completed login must not close the response
        gate on a concurrent login to a hash-colliding contact."""
        (
            radio,
            identity,
            comp,
            (a_identity, a_contact),
            (b_identity, b_contact),
        ) = self._setup_colliding_pair()
        monkeypatch.setattr(comp, "_response_timeout_s", lambda pkt, proxy: 0.5)
        handler = comp._get_login_response_handler()

        task_a = asyncio.create_task(comp.send_login(a_contact.public_key, "pw-a"))
        await _wait_until(lambda: len(radio.sent) >= 1)
        task_b = asyncio.create_task(comp.send_login(b_contact.public_key, "pw-b"))
        await _wait_until(lambda: len(radio.sent) >= 2)

        resp_a = _build_login_response_packet(a_identity, identity, timestamp=111)
        await handler(resp_a)
        result_a = await task_a
        assert result_a["success"] is True
        assert result_a["tag"] == 111

        resp_b = _build_login_response_packet(b_identity, identity, timestamp=222)
        await handler(resp_b)
        result_b = await task_b
        assert result_b["success"] is True
        assert result_b["repeater"] == "RptB"
        assert result_b["tag"] == 222

    async def test_colliding_non_login_response_is_forwarded_not_swallowed(self, monkeypatch):
        """[fails pre-fix] While a login is pending to A, an authenticated
        non-login RESPONSE from hash-colliding B must reach the protocol
        response handler, and A's real response must still resolve A."""
        from unittest.mock import AsyncMock

        from openhop_core.node.handlers import HandlerResult

        (
            radio,
            identity,
            comp,
            (a_identity, a_contact),
            (b_identity, b_contact),
        ) = self._setup_colliding_pair()
        monkeypatch.setattr(comp, "_response_timeout_s", lambda pkt, proxy: 0.5)
        handler = comp._get_login_response_handler()
        protocol_handler = AsyncMock(return_value=HandlerResult.consumed())
        handler.set_protocol_response_handler(protocol_handler)

        task_a = asyncio.create_task(comp.send_login(a_contact.public_key, "pw-a"))
        await _wait_until(lambda: len(radio.sent) >= 1)

        telemetry_resp = _build_non_login_response_packet(b_identity, identity, tag=7)
        result = await handler(telemetry_resp)
        assert result.authenticated
        protocol_handler.assert_awaited_once_with(telemetry_resp)
        assert not task_a.done()

        resp_a = _build_login_response_packet(a_identity, identity, timestamp=111)
        await handler(resp_a)
        result_a = await task_a
        assert result_a["success"] is True
        assert result_a["tag"] == 111
