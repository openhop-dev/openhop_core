import asyncio
import struct
import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from openhop_core.node.events import MeshEvents
from openhop_core.node.handlers import (
    AckHandler,
    AdvertHandler,
    BaseHandler,
    GroupTextHandler,
    LoginResponseHandler,
    MultipartAckHandler,
    PathHandler,
    ProtocolRequestHandler,
    ProtocolResponseHandler,
    TextMessageHandler,
    TraceHandler,
)
from openhop_core.node.handlers.login_server import FIRMWARE_VER_LEVEL
from openhop_core.node.handlers.result import HandlerResult
from openhop_core.protocol import CryptoUtils, Identity, LocalIdentity, Packet, PacketBuilder
from openhop_core.protocol.acl_conformance import OUTBOUND
from openhop_core.protocol.constants import (
    PAYLOAD_TYPE_ACK,
    PAYLOAD_TYPE_ADVERT,
    PAYLOAD_TYPE_ANON_REQ,
    PAYLOAD_TYPE_GRP_TXT,
    PAYLOAD_TYPE_MULTIPART,
    PAYLOAD_TYPE_PATH,
    PAYLOAD_TYPE_REQ,
    PAYLOAD_TYPE_RESPONSE,
    PAYLOAD_TYPE_TRACE,
    PAYLOAD_TYPE_TXT_MSG,
    PERM_ACL_GUEST,
    PUB_KEY_SIZE,
    ROUTE_TYPE_DIRECT,
    ROUTE_TYPE_FLOOD,
    ROUTE_TYPE_TRANSPORT_FLOOD,
    SIGNATURE_SIZE,
    TIMESTAMP_SIZE,
    TXT_TYPE_CLI_COMMAND,
    TXT_TYPE_CLI_DATA,
    TXT_TYPE_PLAIN,
    TXT_TYPE_SIGNED_PLAIN,
)
from openhop_core.protocol.packet_utils import PathUtils
from openhop_core.protocol.utils import decode_appdata


# Mock classes for testing
class MockContact:
    def __init__(self, public_key="0123456789abcdef0123456789abcdef", name="mock"):
        self.public_key = public_key
        self.name = name
        self.last_advert = 0
        self.sync_since = 0


class MockContactBook:
    def __init__(self):
        self.contacts = []
        self.added_contacts = []

    def add_contact(self, contact_data):
        self.added_contacts.append(contact_data)


class MockDispatcher:
    def __init__(self):
        self.local_identity = LocalIdentity()
        self.contact_book = MockContactBook()
        self._waiting_acks = {}
        self._find_contact_by_hash = AsyncMock(return_value=MockContact())


class MockEventService:
    def __init__(self):
        self.publish = AsyncMock()
        self.publish_sync = MagicMock()


def _build_direct_dm(sender_identity, receiver_identity, text, txt_type=TXT_TYPE_PLAIN):
    """Build a real encrypted direct DM packet from sender to receiver."""

    class _SendContact:
        def __init__(self, pubkey_hex):
            self.public_key = pubkey_hex
            self.out_path = []
            self.out_path_len = -1

    receiver_contact = _SendContact(receiver_identity.get_public_key().hex())
    packet, _ = PacketBuilder.create_text_message(
        receiver_contact,
        sender_identity,
        text,
        attempt=0,
        message_type="direct",
        txt_type=txt_type,
    )
    return packet


# Base Handler Tests
def test_base_handler_is_abstract():
    """Test that BaseHandler cannot be instantiated directly."""
    with pytest.raises(TypeError):
        BaseHandler()


# ACK Handler Tests
class TestAckHandler:
    def setup_method(self):
        self.log_fn = MagicMock()
        self.dispatcher = MockDispatcher()
        self.handler = AckHandler(self.log_fn, self.dispatcher)
        self.handler.set_dispatcher(self.dispatcher)

    def test_payload_type(self):
        """Test ACK handler payload type."""
        assert AckHandler.payload_type() == PAYLOAD_TYPE_ACK

    def test_ack_handler_initialization(self):
        """Test ACK handler initialization."""
        assert self.handler.log == self.log_fn
        assert self.handler.dispatcher == self.dispatcher
        assert self.handler._ack_received_callback is None

    def test_set_ack_received_callback(self):
        """Test setting ACK received callback."""
        callback = MagicMock()
        self.handler.set_ack_received_callback(callback)
        assert self.handler._ack_received_callback == callback

    @pytest.mark.asyncio
    async def test_process_discrete_ack_valid(self):
        """Test processing a valid discrete ACK packet."""
        # Create packet with 4-byte CRC payload
        packet = Packet()
        packet.payload = bytearray(b"\x78\x56\x34\x12")  # CRC 0x12345678

        crc = await self.handler.process_discrete_ack(packet)
        assert crc == 0x12345678
        self.log_fn.assert_called()

    @pytest.mark.asyncio
    async def test_process_discrete_ack_invalid_length(self):
        """Test processing ACK packet with invalid length."""
        packet = Packet()
        packet.payload = bytearray(b"\x12\x34")  # Too short

        crc = await self.handler.process_discrete_ack(packet)
        assert crc is None
        self.log_fn.assert_called()

    @pytest.mark.asyncio
    async def test_process_discrete_ack_six_bytes(self):
        """Firmware emits 6-byte ACKs (hash + ext-attempt + random); match first 4 bytes."""
        packet = Packet()
        # 4-byte CRC 0x12345678 followed by an ext-attempt byte and a random byte
        packet.payload = bytearray(b"\x78\x56\x34\x12\x02\xab")

        crc = await self.handler.process_discrete_ack(packet)
        assert crc == 0x12345678
        self.log_fn.assert_called()

    @pytest.mark.asyncio
    async def test_call_discrete_ack(self):
        """Test calling ACK handler with discrete ACK packet."""
        # Create packet with 4-byte CRC payload
        packet = Packet()
        packet.payload = bytearray(b"\x78\x56\x34\x12")  # CRC 0x12345678

        callback = MagicMock()
        self.handler.set_ack_received_callback(callback)

        await self.handler(packet)

        callback.assert_called_once_with(0x12345678)


# Text Message Handler Tests
class TestMultipartAckHandler:
    def setup_method(self):
        self.log_fn = MagicMock()
        self.callback = AsyncMock()
        self.handler = MultipartAckHandler(self.log_fn)
        self.handler.set_ack_received_callback(self.callback)

    def test_payload_type(self):
        assert MultipartAckHandler.payload_type() == PAYLOAD_TYPE_MULTIPART

    @pytest.mark.asyncio
    async def test_extracts_embedded_ack(self):
        """A MULTIPART ACK notifies the callback with the embedded 4-byte CRC."""
        packet = Packet()
        # wrapper byte (remaining=1, inner=ACK) + 4-byte CRC + extra bytes
        packet.payload = bytearray(
            bytes([(1 << 4) | PAYLOAD_TYPE_ACK]) + b"\x78\x56\x34\x12\x00\xab"
        )

        await self.handler(packet)
        self.callback.assert_awaited_once_with(0x12345678)

    @pytest.mark.asyncio
    async def test_too_short_ignored(self):
        """Payload without a full embedded CRC notifies nothing."""
        packet = Packet()
        packet.payload = bytearray(bytes([(1 << 4) | PAYLOAD_TYPE_ACK]) + b"\x12\x34")

        await self.handler(packet)
        self.callback.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_non_ack_inner_type_ignored(self):
        """A MULTIPART whose inner type is not ACK notifies nothing."""
        packet = Packet()
        packet.payload = bytearray(bytes([(1 << 4) | 0x02]) + b"\x78\x56\x34\x12")

        await self.handler(packet)
        self.callback.assert_not_awaited()


class TestTextMessageHandler:
    def setup_method(self):
        self.local_identity = LocalIdentity()
        self.contacts = MockContactBook()
        self.log_fn = MagicMock()
        self.send_packet_fn = AsyncMock()
        self.event_service = MockEventService()
        self.handler = TextMessageHandler(
            self.local_identity,
            self.contacts,
            self.log_fn,
            self.send_packet_fn,
            self.event_service,
        )

    def test_payload_type(self):
        """Test text message handler payload type."""
        assert TextMessageHandler.payload_type() == PAYLOAD_TYPE_TXT_MSG

    def test_text_handler_initialization(self):
        """Test text message handler initialization."""
        assert self.handler.local_identity == self.local_identity
        assert self.handler.contacts == self.contacts
        assert self.handler.log == self.log_fn
        assert self.handler.send_packet == self.send_packet_fn
        assert self.handler.event_service == self.event_service

    def test_register_command_response(self):
        """Registering/unregistering a command response is keyed by full pubkey."""
        callback = MagicMock()
        pubkey = bytes(range(32))
        self.handler.register_command_response(pubkey, callback)
        assert self.handler._pending_command_responses[pubkey] is callback
        # Identity-guarded removal: a different callback does not clear the entry.
        self.handler.unregister_command_response(pubkey, MagicMock())
        assert self.handler._pending_command_responses[pubkey] is callback
        self.handler.unregister_command_response(pubkey, callback)
        assert pubkey not in self.handler._pending_command_responses

    @pytest.mark.asyncio
    async def test_cli_data_reply_completes_pending_command_one_shot(self):
        """A CLI_DATA reply from the pending sender is captured exactly once."""
        sender = LocalIdentity()
        self.contacts.contacts = [MockContact(public_key=sender.get_public_key().hex(), name="rpt")]
        captured = []
        self.handler.register_command_response(
            sender.get_public_key(), lambda text, contact: captured.append(text)
        )

        pkt = _build_direct_dm(sender, self.local_identity, "reply one", TXT_TYPE_CLI_DATA)
        result = await self.handler(pkt)
        assert result.authenticated is True
        assert captured == ["reply one"]
        # One reply completes one command: the entry is gone and the next
        # CLI_DATA from the same sender is delivered as a normal message.
        assert sender.get_public_key() not in self.handler._pending_command_responses
        self.event_service.publish_sync.assert_not_called()

        pkt2 = _build_direct_dm(sender, self.local_identity, "reply two", TXT_TYPE_CLI_DATA)
        await self.handler(pkt2)
        assert captured == ["reply one"]
        self.event_service.publish_sync.assert_called_once()
        event_name, event_data = self.event_service.publish_sync.call_args.args
        assert event_name == MeshEvents.NEW_MESSAGE
        assert event_data["message_text"] == "reply two"

    @pytest.mark.asyncio
    async def test_plain_dm_from_pending_sender_not_intercepted(self):
        """A plain DM is delivered normally even while its sender has a pending command."""
        sender = LocalIdentity()
        self.contacts.contacts = [MockContact(public_key=sender.get_public_key().hex(), name="rpt")]
        captured = []
        self.handler.register_command_response(
            sender.get_public_key(), lambda text, contact: captured.append(text)
        )

        pkt = _build_direct_dm(sender, self.local_identity, "just a dm", TXT_TYPE_PLAIN)
        await self.handler(pkt)

        assert captured == []
        assert sender.get_public_key() in self.handler._pending_command_responses
        self.event_service.publish_sync.assert_called_once()
        event_name, event_data = self.event_service.publish_sync.call_args.args
        assert event_name == MeshEvents.NEW_MESSAGE
        assert event_data["message_text"] == "just a dm"

    @pytest.mark.asyncio
    async def test_cli_data_from_other_contact_delivered_normally(self):
        """CLI_DATA from a contact with no pending command flows to normal delivery."""
        target = LocalIdentity()
        other = LocalIdentity()
        self.contacts.contacts = [
            MockContact(public_key=target.get_public_key().hex(), name="rpt"),
            MockContact(public_key=other.get_public_key().hex(), name="other"),
        ]
        captured = []
        self.handler.register_command_response(
            target.get_public_key(), lambda text, contact: captured.append(text)
        )

        pkt = _build_direct_dm(other, self.local_identity, "unrelated cli", TXT_TYPE_CLI_DATA)
        await self.handler(pkt)

        assert captured == []
        # The target's pending entry is untouched.
        assert target.get_public_key() in self.handler._pending_command_responses
        self.event_service.publish_sync.assert_called_once()
        event_name, event_data = self.event_service.publish_sync.call_args.args
        assert event_name == MeshEvents.NEW_MESSAGE
        assert event_data["message_text"] == "unrelated cli"

    @pytest.mark.asyncio
    async def test_call_with_short_payload(self):
        """Test calling text handler with payload too short to decrypt."""
        packet = Packet()
        packet.payload = bytearray(b"\x12\x34")  # Too short

        await self.handler(packet)

        # Should return early without processing
        self.log_fn.assert_called()

    @pytest.mark.asyncio
    async def test_direct_ack_roundtrip_matches_sender_crc(self):
        """Receiver-emitted ACK[:4] equals the sender's expected ack_crc (firmware parity)."""
        import asyncio

        from openhop_core.protocol.packet_builder import PacketBuilder

        sender = LocalIdentity()
        receiver = self.local_identity  # handler's identity

        class _SendContact:
            def __init__(self, pubkey_hex):
                self.public_key = pubkey_hex
                self.out_path = []
                self.out_path_len = -1

        # Sender composes a DIRECT DM addressed to the receiver
        receiver_contact = _SendContact(receiver.get_public_key().hex())
        packet, ack_crc = PacketBuilder.create_text_message(
            receiver_contact,
            sender,
            "hello round trip",
            attempt=0,
            message_type="direct",
        )

        # Receiver knows the sender as a contact (32-byte pubkey)
        self.contacts.contacts = [
            MockContact(public_key=sender.get_public_key().hex(), name="sender")
        ]

        await self.handler(packet)

        # ACK is emitted after a delay via a background task; poll for it.
        for _ in range(80):
            if self.send_packet_fn.called:
                break
            await asyncio.sleep(0.05)

        assert self.send_packet_fn.called
        ack_packet = self.send_packet_fn.call_args.args[0]
        assert ack_packet.get_payload_type() == PAYLOAD_TYPE_ACK
        assert len(ack_packet.payload) == 6
        assert int.from_bytes(ack_packet.payload[:4], "little") == ack_crc

    def test_ack_response_delays_use_fixed_txt_ack_delay(self):
        """Receiver ACK responses use the firmware TXT_ACK_DELAY (200 ms), with the
        multi-ack staggered +300 ms — not an airtime/route-timeout estimate."""
        import types

        from openhop_core.node.handlers.text import MULTI_ACK_STAGGER_MS, TXT_ACK_DELAY_MS
        from openhop_core.protocol.packet_utils import PathUtils

        ack_hash = bytes(range(6))
        base = TXT_ACK_DELAY_MS / 1000.0

        # DIRECT with a known out_path, no multi-ack: single ACK at 200 ms.
        contact = types.SimpleNamespace(
            out_path_len=PathUtils.encode_path_len(1, 1), out_path=b"\x05"
        )
        self.handler.multi_acks = 0
        res = self.handler._build_ack_responses(
            packet=Packet(),
            matched_contact=contact,
            shared_secret=b"\x00" * 32,
            pubkey=b"\x01" * 32,
            ack_hash=ack_hash,
            is_flood=False,
        )
        assert len(res) == 1
        assert res[0][1] == base

        # DIRECT known path with multi-ack: multi at 200 ms, ACK at 500 ms.
        self.handler.multi_acks = 1
        res = self.handler._build_ack_responses(
            packet=Packet(),
            matched_contact=contact,
            shared_secret=b"\x00" * 32,
            pubkey=b"\x01" * 32,
            ack_hash=ack_hash,
            is_flood=False,
        )
        assert len(res) == 2
        assert res[0][1] == base
        assert res[1][1] == (TXT_ACK_DELAY_MS + MULTI_ACK_STAGGER_MS) / 1000.0

        # DIRECT with unknown out_path: flooded ACK at 200 ms.
        self.handler.multi_acks = 0
        contact_nopath = types.SimpleNamespace(out_path_len=-1, out_path=b"")
        res = self.handler._build_ack_responses(
            packet=Packet(),
            matched_contact=contact_nopath,
            shared_secret=b"\x00" * 32,
            pubkey=b"\x01" * 32,
            ack_hash=ack_hash,
            is_flood=False,
        )
        assert len(res) == 1
        assert res[0][1] == base

    def test_flood_ack_response_uses_txt_ack_delay(self):
        """A flood DM's PATH-return ACK is scheduled at TXT_ACK_DELAY (200 ms)."""
        from openhop_core.node.handlers.text import TXT_ACK_DELAY_MS

        sender = LocalIdentity()
        shared = Identity(sender.get_public_key()).calc_shared_secret(
            self.local_identity.get_private_key()
        )
        pkt = Packet()
        pkt.path = bytearray([0x01, 0x02])
        pkt.path_len = 2
        res = self.handler._build_ack_responses(
            packet=pkt,
            matched_contact=MockContact(public_key=sender.get_public_key().hex()),
            shared_secret=shared,
            pubkey=sender.get_public_key(),
            ack_hash=bytes(range(6)),
            is_flood=True,
        )
        assert len(res) == 1
        assert res[0][1] == TXT_ACK_DELAY_MS / 1000.0

    def _flood_ack_inner(self, pkt, sender, shared):
        """Decrypt the inner payload of the PATH-return ACK built for ``pkt``."""
        res = self.handler._build_ack_responses(
            packet=pkt,
            matched_contact=MockContact(public_key=sender.get_public_key().hex()),
            shared_secret=shared,
            pubkey=sender.get_public_key(),
            ack_hash=bytes(range(6)),
            is_flood=True,
        )
        return CryptoUtils.mac_then_decrypt(shared[:16], shared, bytes(res[0][0].payload[2:]))

    def test_flood_ack_path_return_preserves_multibyte_hash_width(self):
        """The taught path keeps the DM's declared width and is trimmed to it.

        The path bytes and the path_len declaring their width are one decision:
        taking the whole buffer while declaring only the first two hops makes
        create_path_return reject the pair.
        """
        sender = LocalIdentity()
        shared = Identity(sender.get_public_key()).calc_shared_secret(
            self.local_identity.get_private_key()
        )
        pkt = Packet()
        # 2 hops of 2-byte hashes, plus slack the declared length excludes.
        pkt.path = bytearray([0xA1, 0xA2, 0xB1, 0xB2, 0xFF, 0xFF])
        pkt.path_len = PathUtils.encode_path_len(2, 2)

        plaintext = self._flood_ack_inner(pkt, sender, shared)
        assert plaintext[0] == PathUtils.encode_path_len(2, 2)
        assert plaintext[1:5] == bytes([0xA1, 0xA2, 0xB1, 0xB2])
        assert plaintext[5] == PAYLOAD_TYPE_ACK  # extra_type

    def test_flood_ack_path_return_drops_a_path_of_undecodable_width(self):
        """An undecodable path_len teaches no path rather than guessing a width.

        Unreachable from the wire — Packet.from_bytes rejects an invalid
        path_len — but the two halves must stay consistent regardless of how the
        packet was constructed.
        """
        sender = LocalIdentity()
        shared = Identity(sender.get_public_key()).calc_shared_secret(
            self.local_identity.get_private_key()
        )
        pkt = Packet()
        pkt.path = bytearray([0x01, 0x02, 0x03, 0x04])
        pkt.path_len = 0xFF  # hash_size 4 is reserved: no decodable width

        plaintext = self._flood_ack_inner(pkt, sender, shared)
        assert plaintext[0] == 0  # zero hops, nothing taught
        assert plaintext[1] == PAYLOAD_TYPE_ACK

    @pytest.mark.asyncio
    async def test_received_text_stops_at_first_nul(self):
        """The delivered message text ends at the first NUL: AES zero padding and the
        hidden extended-attempt byte (attempt > 3) must not leak into the content."""
        from openhop_core.protocol.packet_builder import PacketBuilder

        sender = LocalIdentity()

        class _SendContact:
            def __init__(self, pubkey_hex):
                self.public_key = pubkey_hex
                self.out_path = []
                self.out_path_len = -1

        receiver_contact = _SendContact(self.local_identity.get_public_key().hex())
        # attempt=4 appends NUL + attempt byte after the text, on top of AES padding.
        packet, _ = PacketBuilder.create_text_message(
            receiver_contact, sender, "hello", attempt=4, message_type="direct"
        )
        self.contacts.contacts = [
            MockContact(public_key=sender.get_public_key().hex(), name="sender")
        ]

        await self.handler(packet)

        assert self.event_service.publish_sync.called
        message_data = self.event_service.publish_sync.call_args.args[1]
        assert message_data["message_text"] == "hello"

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("route", "path", "path_len"),
        [
            pytest.param("direct", b"", 0xFF, id="direct-out-path-unknown-ff"),
            pytest.param("flood", b"\xaa", 0x01, id="flood-one-byte-hash-01"),
            pytest.param(
                "flood",
                b"\xaa\xbb\xcc\xdd",
                0x42,
                id="flood-two-byte-hashes-42",
            ),
            pytest.param(
                "transport_flood",
                b"\xaa\xbb\xcc\xdd\xee\xff\x10\x20\x30",
                0x83,
                id="transport-flood-three-byte-hashes-83",
            ),
        ],
    )
    async def test_received_text_publishes_companion_route_path_len(self, route, path, path_len):
        """Firmware-compatible companion route-byte vectors reach the event.

        MeshCore's queueMessage() passes a flood packet's encoded path_len
        unchanged and uses OUT_PATH_UNKNOWN (0xFF) for any direct route.
        The literal vectors include hash-width bits, so a conversion to raw
        path bytes would fail this compatibility check.
        """
        sender = LocalIdentity()
        packet_route = "flood" if path else route
        packet = self._build_dm_to_self(sender, route=packet_route)
        if route == "transport_flood":
            route_type = packet.header & ~0x03
            packet.header = route_type | ROUTE_TYPE_TRANSPORT_FLOOD
        if path:
            packet.set_path(path, path_len)
        sender_key = sender.get_public_key().hex()
        self.contacts.contacts = [MockContact(public_key=sender_key, name="sender")]

        await self.handler(packet)

        message_data = self.event_service.publish_sync.call_args.args[1]
        assert message_data["path_len"] == path_len

    # -- consume-vs-forward return contract (#353) --------------------------

    def _build_dm_to_self(self, sender, text="hi", route="flood"):
        """Build a DM addressed to this handler's identity, sent by ``sender``."""
        from openhop_core.protocol.packet_builder import PacketBuilder

        class _SendContact:
            def __init__(self, pubkey_hex):
                self.public_key = pubkey_hex
                self.out_path = []
                self.out_path_len = -1

        receiver_contact = _SendContact(self.local_identity.get_public_key().hex())
        packet, _ = PacketBuilder.create_text_message(
            receiver_contact, sender, text, attempt=0, message_type=route
        )
        return packet

    @pytest.mark.asyncio
    async def test_returns_true_when_decrypted_for_known_contact(self):
        """A DM that decrypts for a known contact is genuinely ours -> consume (True)."""
        sender = LocalIdentity()
        packet = self._build_dm_to_self(sender)
        self.contacts.contacts = [
            MockContact(public_key=sender.get_public_key().hex(), name="sender")
        ]
        assert (await self.handler(packet)).authenticated is True

    @pytest.mark.asyncio
    async def test_returns_false_when_sender_unknown(self):
        """No contact matches the src hash: can't decrypt -> forward (False)."""
        sender = LocalIdentity()
        packet = self._build_dm_to_self(sender)
        self.contacts.contacts = []
        assert (await self.handler(packet)).authenticated is False

    @pytest.mark.asyncio
    async def test_returns_false_on_decrypt_failure_collision(self):
        """src hash matches a contact but HMAC fails (collision): forward (False) (#353)."""
        sender = LocalIdentity()
        packet = self._build_dm_to_self(sender)
        self.contacts.contacts = [
            MockContact(public_key=sender.get_public_key().hex(), name="sender")
        ]
        packet.payload[-1] ^= 0xFF  # corrupt ciphertext/MAC so decryption fails
        assert (await self.handler(packet)).authenticated is False

    def _make_direct_dm_with_path(self, text="multi ack route"):
        """Build a direct DM addressed to the handler, with the sender registered as a
        contact that has a known multi-hop out_path. Returns (packet, ack_crc, out_path,
        out_path_len)."""
        sender = LocalIdentity()
        receiver = self.local_identity

        class _SendContact:
            def __init__(self, pubkey_hex):
                self.public_key = pubkey_hex
                self.out_path = []
                self.out_path_len = -1

        receiver_contact = _SendContact(receiver.get_public_key().hex())
        packet, ack_crc = PacketBuilder.create_text_message(
            receiver_contact, sender, text, attempt=0, message_type="direct"
        )

        # Sender contact known to the receiver, with a 2-hop out_path
        out_path = bytes([0x11, 0x22])
        out_path_len = PathUtils.encode_path_len(1, 2)
        contact = MockContact(public_key=sender.get_public_key().hex(), name="sender")
        contact.out_path = out_path
        contact.out_path_len = out_path_len
        self.contacts.contacts = [contact]
        return packet, ack_crc, out_path, out_path_len

    async def _wait_for_sends(self, count):
        import asyncio

        for _ in range(120):
            if self.send_packet_fn.call_count >= count:
                break
            await asyncio.sleep(0.05)

    @pytest.mark.asyncio
    async def test_direct_known_path_routes_ack(self):
        """With a known out_path and multi_acks off, the ACK is routed along the path."""
        self.handler.set_multi_acks(0)
        packet, ack_crc, out_path, out_path_len = self._make_direct_dm_with_path()

        await self.handler(packet)
        await self._wait_for_sends(1)

        assert self.send_packet_fn.call_count == 1
        ack_packet = self.send_packet_fn.call_args_list[0].args[0]
        assert ack_packet.get_payload_type() == PAYLOAD_TYPE_ACK
        assert bytes(ack_packet.path) == out_path
        assert ack_packet.path_len == out_path_len
        assert int.from_bytes(ack_packet.payload[:4], "little") == ack_crc

    @pytest.mark.asyncio
    async def test_direct_unknown_path_floods_ack(self):
        """With an unknown reverse out_path, the ACK is flood-routed (not path-less direct)."""
        sender = LocalIdentity()
        receiver = self.local_identity

        class _SendContact:
            def __init__(self, pubkey_hex):
                self.public_key = pubkey_hex
                self.out_path = []
                self.out_path_len = -1

        receiver_contact = _SendContact(receiver.get_public_key().hex())
        packet, ack_crc = PacketBuilder.create_text_message(
            receiver_contact,
            sender,
            "no reverse path",
            attempt=0,
            message_type="direct",
        )
        # Sender is a known contact but with an UNKNOWN out_path back to it.
        self.contacts.contacts = [
            MockContact(public_key=sender.get_public_key().hex(), name="sender")
        ]

        await self.handler(packet)
        await self._wait_for_sends(1)

        assert self.send_packet_fn.call_count == 1
        ack_packet = self.send_packet_fn.call_args_list[0].args[0]
        assert ack_packet.get_payload_type() == PAYLOAD_TYPE_ACK
        assert (ack_packet.header & 0x03) == ROUTE_TYPE_FLOOD  # flooded, not direct
        assert ack_packet.path_len == 0  # no path
        assert int.from_bytes(ack_packet.payload[:4], "little") == ack_crc

    @pytest.mark.asyncio
    async def test_signed_plain_advances_contact_sync_since(self):
        """Signed plain traffic should advance contact.sync_since (firmware parity)."""
        sender = LocalIdentity()
        receiver = self.local_identity

        class _SendContact:
            def __init__(self, pubkey_hex):
                self.public_key = pubkey_hex
                self.out_path = []
                self.out_path_len = -1

        receiver_contact = _SendContact(receiver.get_public_key().hex())
        signed_timestamp = 0x12345678
        packet, _ = PacketBuilder.create_text_message(
            receiver_contact,
            sender,
            "signed update",
            attempt=0,
            message_type="direct",
            txt_type=0x02,
            timestamp=signed_timestamp,
        )
        contact = MockContact(public_key=sender.get_public_key().hex(), name="sender")
        self.contacts.contacts = [contact]

        await self.handler(packet)

        assert contact.sync_since == signed_timestamp

    @pytest.mark.asyncio
    async def test_signed_plain_emits_delivery_ack(self):
        """Signed plain traffic should emit an ACK (room-server push compatibility)."""
        sender = LocalIdentity()
        receiver = self.local_identity

        class _SendContact:
            def __init__(self, pubkey_hex):
                self.public_key = pubkey_hex
                self.out_path = []
                self.out_path_len = -1

        receiver_contact = _SendContact(receiver.get_public_key().hex())
        packet, _ = PacketBuilder.create_text_message(
            receiver_contact,
            sender,
            "signed ack",
            attempt=0,
            message_type="direct",
            txt_type=0x02,
            timestamp=0x12345679,
        )
        contact = MockContact(public_key=sender.get_public_key().hex(), name="sender")
        contact.type = 3  # room server
        self.contacts.contacts = [contact]

        await self.handler(packet)
        await self._wait_for_sends(1)

        assert self.send_packet_fn.call_count == 1
        ack_packet = self.send_packet_fn.call_args_list[0].args[0]
        assert ack_packet.get_payload_type() == PAYLOAD_TYPE_ACK

    @pytest.mark.asyncio
    async def test_direct_multi_ack_emits_multipart_then_ack(self):
        """With multi_acks on and a known path, a MULTIPART fires before the normal ACK."""
        self.handler.set_multi_acks(1)
        packet, ack_crc, out_path, out_path_len = self._make_direct_dm_with_path()

        await self.handler(packet)
        await self._wait_for_sends(2)

        assert self.send_packet_fn.call_count == 2
        first = self.send_packet_fn.call_args_list[0].args[0]
        second = self.send_packet_fn.call_args_list[1].args[0]

        # multipart is staggered earlier, so it is sent first
        assert first.get_payload_type() == PAYLOAD_TYPE_MULTIPART
        assert second.get_payload_type() == PAYLOAD_TYPE_ACK

        # both carry the out_path and the same embedded CRC
        assert bytes(first.path) == out_path and first.path_len == out_path_len
        assert bytes(second.path) == out_path and second.path_len == out_path_len
        assert (first.payload[0] & 0x0F) == PAYLOAD_TYPE_ACK
        assert int.from_bytes(first.payload[1:5], "little") == ack_crc
        assert int.from_bytes(second.payload[:4], "little") == ack_crc

    # ------------------------------------------------------------------
    # Text types -- firmware BaseChatMesh::onPeerDataRecv
    # ------------------------------------------------------------------

    def _typed_dm(
        self, txt_type: int, *, flood: bool, text: str = "ping", timestamp: int = 0x5EEDBEEF
    ):
        """A real encrypted DM addressed to us, carrying ``txt_type``.

        Returns (packet, sender_identity); the sender is registered as a known
        contact so the handler decrypts it.
        """
        sender = LocalIdentity()

        class _Receiver:
            public_key = self.local_identity.get_public_key().hex()
            out_path: list = []
            out_path_len = -1

        packet, _ = PacketBuilder.create_text_message(
            _Receiver(),
            sender,
            text,
            attempt=0,
            message_type="flood" if flood else "direct",
            txt_type=txt_type,
            timestamp=timestamp,
        )
        contact = MockContact(public_key=sender.get_public_key().hex(), name="peer")
        self.contacts.contacts = [contact]
        return packet, sender

    @pytest.mark.asyncio
    async def test_flood_cli_data_sends_nothing_back(self):
        """A flood CLI_DATA earns no ACK and no reciprocal path.

        Firmware used to answer one with a bare createPathReturn, but that call
        left BaseChatMesh::onPeerDataRecv when the CLI_DATA branch became the
        reply-only path (afb969cc): it now just hands the text to
        onCommandDataRecv. CLI_DATA is also on the no-delivery-ACK list, so the
        whole branch is silent on the air.
        """
        packet, _sender = self._typed_dm(TXT_TYPE_CLI_DATA, flood=True)

        result = await self.handler(packet)
        await self._wait_for_sends(1)

        assert result.authenticated is True
        assert self.send_packet_fn.call_count == 0
        assert self.event_service.publish_sync.called

    @pytest.mark.asyncio
    async def test_flood_cli_command_is_delivered_and_sends_nothing_back(self):
        """CLI_COMMAND reaches the app verbatim and, like CLI_DATA, is silent.

        Firmware routes it to onCLICommandRecv, which runs the command only for
        a sender flagged isRemoteCLIAllowed() and otherwise queues it for the
        app. Core has no CLI to run, so the queue-for-the-app branch is all of
        it -- and no ACK or path return either way.
        """
        packet, _sender = self._typed_dm(TXT_TYPE_CLI_COMMAND, flood=True, text="reboot")

        result = await self.handler(packet)
        await self._wait_for_sends(1)

        assert result.authenticated is True
        assert self.send_packet_fn.call_count == 0
        self.event_service.publish_sync.assert_called_once()
        _event, data = self.event_service.publish_sync.call_args.args
        assert data["txt_type"] == TXT_TYPE_CLI_COMMAND
        assert data["message_text"] == "reboot"

    @pytest.mark.asyncio
    async def test_cli_command_does_not_resolve_a_pending_command_waiter(self):
        """Only a CLI_DATA *reply* completes a command we sent.

        A CLI_COMMAND travels the other way -- it is someone asking us to run
        something -- so letting it resolve the waiter would hand
        send_repeater_command an inbound command as if it were the answer.
        """
        packet, sender = self._typed_dm(TXT_TYPE_CLI_COMMAND, flood=False, text="reboot")
        replies = []
        self.handler.register_command_response(
            sender.get_public_key(), lambda text, contact: replies.append(text)
        )

        await self.handler(packet)

        assert replies == []
        assert self.event_service.publish_sync.called

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "txt_type",
        [TXT_TYPE_PLAIN, TXT_TYPE_CLI_DATA, TXT_TYPE_SIGNED_PLAIN, TXT_TYPE_CLI_COMMAND],
    )
    async def test_decrypted_carries_the_text_type(self, txt_type):
        """packet.decrypted publishes the type alongside the text.

        A downstream repeater or room server dispatches on it -- firmware's
        simple_repeater and simple_room_server both gate their CLI on
        {PLAIN, CLI_DATA, CLI_COMMAND}, and the room server tells a post from a
        command by type, not by reading the text. Once this handler has decoded
        the plaintext, the type is not recoverable from the packet.
        """
        packet, _sender = self._typed_dm(txt_type, flood=False, text="ver")

        await self.handler(packet)

        assert packet.decrypted["txt_type"] == txt_type
        assert packet.decrypted["text"] == "ver"
        # The sender's clock, not ours: a server uses it as a replay watermark.
        assert packet.decrypted["sender_timestamp"] == 0x5EEDBEEF

    @pytest.mark.asyncio
    async def test_decrypted_is_published_even_when_a_waiter_consumes_the_reply(self):
        """[fails pre-fix] The intercepted CLI_DATA path publishes it too.

        A CLI_DATA that resolves a pending command waiter returns early, before
        the normal delivery block. Leaving packet.decrypted unset there hands
        anything downstream of the handler an empty dict instead of the shape
        the rest of the codebase relies on.
        """
        packet, sender = self._typed_dm(TXT_TYPE_CLI_DATA, flood=False, text="fw v1")
        self.handler.register_command_response(sender.get_public_key(), lambda *_: None)

        result = await self.handler(packet)

        assert result.authenticated is True
        assert packet.decrypted == {
            "text": "fw v1",
            "txt_type": TXT_TYPE_CLI_DATA,
            "sender_timestamp": 0x5EEDBEEF,
        }

    @pytest.mark.asyncio
    @pytest.mark.parametrize("text_len", [0, 11, 27])
    async def test_body_with_no_terminator_decodes_and_acks(self, text_len):
        """A body that exactly fills its cipher blocks has no NUL to stop at.

        `5 + text_len` at 11 and 27 is a whole number of blocks, so nothing is
        padded and the text runs to the end of the plaintext -- the case the
        sender's old trailing NUL used to paper over. The handler has to fall
        back on the decrypted length the way firmware's `data[len] = 0` does,
        for both the text it shows and the ACK hash it answers with. 0 is the
        other edge: an empty body.
        """
        sender = LocalIdentity()

        class _Receiver:
            public_key = self.local_identity.get_public_key().hex()
            out_path: list = []
            out_path_len = -1

        text = "x" * text_len
        packet, crc = PacketBuilder.create_text_message(
            _Receiver(), sender, text, attempt=0, message_type="direct", txt_type=TXT_TYPE_PLAIN
        )
        self.contacts.contacts = [
            MockContact(public_key=sender.get_public_key().hex(), name="peer")
        ]

        await self.handler(packet)
        await self._wait_for_sends(1)

        assert self.event_service.publish_sync.call_args.args[1]["message_text"] == text
        assert self.send_packet_fn.call_count == 1
        ack = self.send_packet_fn.call_args_list[0].args[0]
        # The receiver's ACK must be the one the sender is waiting on.
        assert int.from_bytes(ack.payload[:4], "little") == crc

    @pytest.mark.asyncio
    async def test_unsupported_txt_type_is_dropped_whole(self):
        """[fails pre-fix] A type with no firmware branch reaches neither app nor air.

        BaseChatMesh::onPeerDataRecv runs off the end of its if/else-if chain
        for anything outside {PLAIN, CLI_DATA, SIGNED_PLAIN, CLI_COMMAND} and
        only logs "unsupported message type". The payload layout past the flags
        byte is undefined for such a type, so decoding it as text would publish
        AES padding as message content.
        """
        packet, _sender = self._typed_dm(0x2A, flood=True, text="future")

        result = await self.handler(packet)
        await self._wait_for_sends(1)

        # Consumed, not forwarded: it decrypted for us, so it is ours to drop.
        assert result.authenticated is True
        assert self.send_packet_fn.call_count == 0
        self.event_service.publish_sync.assert_not_called()


# Advert Handler Tests
class TestAdvertHandler:
    def setup_method(self):
        self.log_fn = MagicMock()
        self.handler = AdvertHandler(self.log_fn)

    def _build_signed_advert_packet(self, appdata: bytes) -> Packet:
        identity = LocalIdentity()
        timestamp = 1234567890
        pubkey = identity.get_public_key()
        ts_bytes = struct.pack("<I", timestamp)
        signature = identity.sign(pubkey + ts_bytes + appdata)
        packet = Packet()
        packet.header = PacketBuilder._create_header(PAYLOAD_TYPE_ADVERT, route_type="flood")
        packet.payload = bytearray(pubkey + ts_bytes + signature + appdata)
        packet.payload_len = len(packet.payload)
        return packet

    def test_payload_type(self):
        """Test advert handler payload type."""
        assert AdvertHandler.payload_type() == PAYLOAD_TYPE_ADVERT

    def test_advert_handler_initialization(self):
        """Test advert handler initialization."""
        assert self.handler.log == self.log_fn

    @pytest.mark.asyncio
    async def test_advert_handler_accepts_valid_signature(self):
        remote_identity = LocalIdentity()
        packet = PacketBuilder.create_advert(remote_identity, "RemoteNode")

        result = await self.handler(packet)

        assert result is not None
        assert result["valid"] is True
        assert result["public_key"] == remote_identity.get_public_key().hex()
        assert result["name"] == "RemoteNode"

    @pytest.mark.asyncio
    async def test_advert_handler_rejects_invalid_signature(self):
        remote_identity = LocalIdentity()
        packet = PacketBuilder.create_advert(remote_identity, "RemoteNode")
        appdata_offset = PUB_KEY_SIZE + TIMESTAMP_SIZE + SIGNATURE_SIZE + 5
        if appdata_offset >= packet.payload_len:
            appdata_offset = packet.payload_len - 1
        packet.payload[appdata_offset] ^= 0x01

        result = await self.handler(packet)

        assert result is None
        assert any(
            "invalid signature" in call.args[0].lower()
            for call in self.log_fn.call_args_list
            if call.args
        )

    @pytest.mark.asyncio
    async def test_advert_handler_ignores_self_advert(self):
        """Without a local identity the handler cannot know an advert is its own,
        so it parses normally (the registry always supplies one — see
        test_advert_handler_drops_self_advert_when_identity_known)."""
        local_identity = LocalIdentity()
        packet = PacketBuilder.create_advert(local_identity, "SelfNode")

        result = await self.handler(packet)

        # Handler should still return parsed data; dispatcher filters self-adverts
        assert result is not None
        assert result["name"] == "SelfNode"

    @pytest.mark.asyncio
    async def test_advert_handler_drops_self_advert_when_identity_known(self):
        """Mesh::onRecvPacket (Mesh.cpp:263) never reads our own advert back in."""
        local_identity = LocalIdentity()
        event_service = MockEventService()
        handler = AdvertHandler(
            self.log_fn, event_service=event_service, local_identity=local_identity
        )
        packet = PacketBuilder.create_advert(local_identity, "SelfNode")

        result = await handler(packet)

        assert result is None
        event_service.publish_sync.assert_not_called()

    @pytest.mark.asyncio
    async def test_self_advert_is_still_retransmittable(self):
        """The self-advert guard is read-side only: it never marks the packet, so
        the forwarding decision stays what it is for a freshly parsed copy."""
        local_identity = LocalIdentity()
        handler = AdvertHandler(self.log_fn, local_identity=local_identity)
        packet = PacketBuilder.create_advert(local_identity, "SelfNode")
        fresh = Packet()
        assert fresh.read_from(packet.write_to())

        assert await handler(packet) is None

        assert packet.is_marked_do_not_retransmit() == fresh.is_marked_do_not_retransmit()
        assert packet.is_marked_do_not_retransmit() is False

    def test_registry_wires_local_identity_into_the_advert_handler(self):
        """The factory is the only place production code supplies the identity, so
        if this kwarg is ever dropped the self-advert guard goes inert everywhere
        (Dispatcher, CompanionBridge, CompanionRadio) with the suite still green."""
        from openhop_core.companion.contact_store import ContactStore
        from openhop_core.node.handlers.registry import create_core_handlers

        identity = LocalIdentity()

        handlers = create_core_handlers(
            identity=identity,
            contacts=ContactStore(5),
            channels=None,
            event_service=None,
            send_packet_fn=lambda *a, **k: None,
            log_fn=self.log_fn,
            node_name="test",
        )

        assert handlers.advert_handler.local_identity is identity

    def test_decode_appdata_rejects_truncated_optional_fields(self):
        with pytest.raises(ValueError, match="truncated"):
            decode_appdata(bytes([0x10, 0x01, 0x02, 0x03, 0x04]))

    @pytest.mark.asyncio
    async def test_advert_handler_preserves_invalid_utf8_name(self):
        appdata = bytes([0x80]) + b"Bad\xffName"
        packet = self._build_signed_advert_packet(appdata)

        result = await self.handler(packet)

        assert result is not None
        assert result["name"] == "Bad�Name"
        assert result["valid"] is True


# Path Handler Tests
class TestPathHandler:
    def setup_method(self):
        self.log_fn = MagicMock()
        self.ack_handler = AckHandler(self.log_fn)
        self.protocol_response_handler = MagicMock()
        self.handler = PathHandler(self.log_fn, self.ack_handler, self.protocol_response_handler)

    def test_payload_type(self):
        """Test path handler payload type."""
        assert PathHandler.payload_type() == PAYLOAD_TYPE_PATH

    def test_path_handler_initialization(self):
        """Test path handler initialization."""
        assert self.handler._log == self.log_fn
        assert self.handler._ack_handler == self.ack_handler
        assert self.handler._protocol_response_handler == self.protocol_response_handler

    @pytest.mark.asyncio
    async def test_authenticated_subhandler_result_marks_path_consumed(self):
        protocol_handler = AsyncMock(return_value=HandlerResult.consumed())
        login_handler = AsyncMock(return_value=HandlerResult.not_for_us())
        ack_handler = MagicMock()
        ack_handler.process_path_ack_variants = AsyncMock(return_value=None)
        handler = PathHandler(self.log_fn, ack_handler, protocol_handler, login_handler)

        result = await handler(Packet())

        assert result.authenticated is True


# Group Text Handler Tests
class TestGroupTextHandler:
    def setup_method(self):
        self.local_identity = LocalIdentity()
        self.contacts = MockContactBook()
        self.log_fn = MagicMock()
        self.send_packet_fn = AsyncMock()
        self.event_service = MockEventService()
        self.handler = GroupTextHandler(
            self.local_identity,
            self.contacts,
            self.log_fn,
            self.send_packet_fn,
            channel_db=None,
            event_service=self.event_service,
        )

    def test_payload_type(self):
        """Test group text handler payload type."""
        assert GroupTextHandler.payload_type() == PAYLOAD_TYPE_GRP_TXT

    def test_group_text_handler_initialization(self):
        """Test group text handler initialization."""
        assert self.handler.local_identity == self.local_identity
        assert self.handler.contacts == self.contacts
        assert self.handler.log == self.log_fn
        assert self.handler.send_packet == self.send_packet_fn

    def _grp_plaintext(self, flag_byte: int, text: bytes, pad: int = 0) -> bytes:
        """timestamp(4) + flag byte + text (+ optional trailing NUL padding)."""
        return (1234).to_bytes(4, "little") + bytes([flag_byte]) + text + b"\x00" * pad

    def _group_packet(self, sender_name: str = "InitialName", text: str = "hello") -> Packet:
        channels = [{"name": "Public", "secret": "11" * 32}]
        self.handler.channel_db = MagicMock()
        self.handler.channel_db.get_channels.return_value = channels
        return PacketBuilder.create_group_datagram(
            "Public",
            self.local_identity,
            text,
            sender_name,
            channels,
            timestamp=1_700_000_000,
        )

    @pytest.mark.asyncio
    async def test_peer_with_matching_display_name_is_published(self):
        """A display-name collision is not evidence that the packet is ours."""
        packet = self._group_packet(sender_name="InitialName")

        await self.handler(packet)

        self.event_service.publish.assert_awaited_once()
        event, data = self.event_service.publish.await_args.args
        assert event == MeshEvents.NEW_CHANNEL_MESSAGE
        assert data["sender_name"] == "InitialName"
        assert data["message_text"] == "hello"
        assert data["is_outgoing"] is False

    @pytest.mark.asyncio
    async def test_exact_outgoing_packet_hash_suppresses_its_echo(self):
        packet = self._group_packet()
        self.handler.mark_outgoing_packet(packet)

        await self.handler(packet)

        self.event_service.publish.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_received_group_packet_is_published_once_per_packet_hash(self):
        packet = self._group_packet(sender_name="Peer")

        await self.handler(packet)
        await self.handler(packet)

        self.event_service.publish.assert_awaited_once()

    def test_group_parse_ignores_attempt_low_bits(self):
        """The low two bits of the group flag byte are an attempt number, not a
        subtype: values 1, 2, 3 are still plain text (firmware onGroupDataRecv)."""
        for attempt in range(4):
            parsed = self.handler._parse_plaintext_message(
                self._grp_plaintext(attempt, b"Alice: hi", pad=3)
            )
            assert parsed is not None
            assert parsed["message_type"] == "plain_text"
            assert parsed["content"] == "Alice: hi"

    def test_group_parse_drops_unsupported_type(self):
        """A flag byte with any of the upper six bits set is an unsupported group
        text type and is dropped, matching the firmware."""
        parsed = self.handler._parse_plaintext_message(
            self._grp_plaintext(0x04, b"Alice: hi")  # (1 << 2): upper bits non-zero
        )
        assert parsed is None

    def test_group_parse_stops_at_first_nul(self):
        """Visible group text ends at the first NUL (no trailing padding leaks)."""
        parsed = self.handler._parse_plaintext_message(
            self._grp_plaintext(0x00, b"Bob: hey", pad=7)
        )
        assert parsed is not None
        assert parsed["content"] == "Bob: hey"


class TestPendingLoginDoesNotSwallowOtherReplies:
    """A pending login must not claim an unrelated reply from the same contact.

    Observed live: three login attempts to a repeater timed out at the client,
    leaving a login waiter alive (openHop keeps one for
    ``FRAME_LOGIN_PENDING_TTL_S`` so a late flood login reply can still
    complete). A neighbours fetch to that repeater then answered normally — and
    the 148-byte reply was consumed here and logged as ``Login failed to
    'Hillcrest' (code: 0x2F)``. 0x2F is 47, the low byte of that response's
    ``neighbours_count``: the login parser had read a neighbour count as a
    response code, and the fetch reported failure with the data discarded.

    Firmware has the same contact-based ambiguity but a one-response window
    (``MyMesh::onContactResponse`` clears ``pending_login`` on the first reply),
    so at most one packet can be misread. The discriminator is the reflected
    request tag, which firmware's own source points at:
    ``// FUTURE: tag == pending_status``.
    """

    def setup_method(self):
        self.contacts = MockContactBook()
        self.local_identity = LocalIdentity()
        self.server = LocalIdentity()
        self.server_key = self.server.get_public_key()
        # LoginResponseHandler iterates ``contacts.contacts`` looking for a
        # pubkey whose first byte matches the responding hash.
        server_contact = type("_C", (), {"public_key": self.server_key, "name": "FarRepeater"})()
        self.contacts.contacts.append(server_contact)
        self.handler = LoginResponseHandler(self.local_identity, self.contacts, MagicMock())
        self.forwarded = []

        class _Proto:
            _response_waiters: dict = {}

            async def __call__(_self, pkt):
                self.forwarded.append(pkt)
                return HandlerResult.consumed()

        self.proto = _Proto()
        self.handler.set_protocol_response_handler(self.proto)

    def _reply(self, plaintext: bytes) -> Packet:
        """A RESPONSE datagram from the server to us carrying ``plaintext``."""
        shared = Identity(self.server_key).calc_shared_secret(self.local_identity.get_private_key())
        enc = CryptoUtils.encrypt_then_mac(shared[:16], shared, plaintext)
        pkt = Packet()
        pkt.header = (PAYLOAD_TYPE_RESPONSE << 2) | ROUTE_TYPE_DIRECT
        pkt.payload = bytearray(
            [self.local_identity.get_public_key()[0], self.server_key[0]]
        ) + bytearray(enc)
        pkt.payload_len = len(pkt.payload)
        pkt.path = bytearray()
        pkt.path_len = 0
        return pkt

    def _neighbours_reply(self, tag: int) -> Packet:
        """tag(4) + neighbours_count(2)=47 + results_count(2) + entries."""
        body = struct.pack("<IHH", tag, 47, 2) + bytes(range(18))
        return self._reply(body)

    def _login_reply(self, tag: int) -> Packet:
        """tag(4) + code(1)=OK + keep_alive(1) + is_admin(1) + perms(1) + rand(4) + ver(1)."""
        return self._reply(struct.pack("<IBBBB", tag, 0, 0, 1, 0x03) + b"\x00\x00\x00\x00\x07")

    @pytest.mark.asyncio
    async def test_neighbours_reply_is_forwarded_not_read_as_a_login(self):
        tag = 0x11223344
        login_cb = MagicMock()
        self.handler.register_login_callback(self.server_key, login_cb)
        self.handler.set_foreign_request_probe(lambda t, key: t == tag and key == self.server_key)

        result = await self.handler(self._neighbours_reply(tag))

        assert self.forwarded, "the neighbours reply must reach the protocol handler"
        assert result.authenticated is True
        login_cb.assert_not_called()  # and must NOT be reported as a login result

    @pytest.mark.asyncio
    async def test_a_real_login_reply_still_completes_while_a_request_is_pending(self):
        """The probe must not divert the login reply it was meant to protect."""
        login_cb = MagicMock()
        self.handler.register_login_callback(self.server_key, login_cb)
        # Some *other* tag is pending; this reply reflects the login's own tag.
        self.handler.set_foreign_request_probe(lambda t, key: t == 0xAAAAAAAA)

        await self.handler(self._login_reply(0x55667788))

        assert self.forwarded == []
        login_cb.assert_called_once()
        assert login_cb.call_args[0][0] is True

    @pytest.mark.asyncio
    async def test_without_a_probe_behaviour_is_unchanged(self):
        """A standalone handler (no companion wiring) keeps its old behaviour."""
        login_cb = MagicMock()
        self.handler.register_login_callback(self.server_key, login_cb)

        await self.handler(self._neighbours_reply(0x11223344))

        assert self.forwarded == []
        login_cb.assert_called_once()  # the pre-fix misread, still reachable

    @pytest.mark.asyncio
    async def test_probe_covers_pending_binary_requests_via_the_companion(self):
        """End-to-end wiring: CompanionBase.has_pending_request_tag is the probe."""
        from openhop_core.companion.companion_bridge import CompanionBridge

        async def _injector(pkt, wait_for_ack=False, expected_crc=None):
            return True

        bridge = CompanionBridge(LocalIdentity(), _injector, node_name="b")
        tag = 0x0BADF00D
        assert bridge.has_pending_request_tag(tag, self.server_key) is False
        bridge.register_binary_request(
            tag.to_bytes(4, "little").hex(), request_type=0x06, timeout_seconds=30
        )
        assert bridge.has_pending_request_tag(tag, self.server_key) is True
        # An expired registration must stop diverting replies.
        bridge.register_binary_request(
            tag.to_bytes(4, "little").hex(), request_type=0x06, timeout_seconds=-1
        )
        assert bridge.has_pending_request_tag(tag, self.server_key) is False


# Login Response Handler Tests
class TestLoginResponseHandler:
    def setup_method(self):
        self.contacts = MockContactBook()
        self.log_fn = MagicMock()
        self.send_packet_fn = AsyncMock()
        self.local_identity = LocalIdentity()
        self.handler = LoginResponseHandler(self.local_identity, self.contacts, self.log_fn)

    def test_payload_type(self):
        """Test login response handler payload type."""
        assert LoginResponseHandler.payload_type() == PAYLOAD_TYPE_RESPONSE

    def test_login_response_handler_initialization(self):
        """Test login response handler initialization."""
        assert self.handler.contacts == self.contacts
        assert self.handler.log == self.log_fn
        assert self.handler.local_identity == self.local_identity
        assert self.handler.local_identity == self.local_identity

    def test_register_login_callback_identity_guard(self):
        """Pending logins are keyed by full pubkey; removal is identity-guarded."""
        callback = MagicMock()
        pubkey = bytes(range(32))
        self.handler.register_login_callback(pubkey, callback)
        assert self.handler._pending_logins[pubkey] is callback
        # A different callback (e.g. a newer login's cleanup racing an older
        # one) must not clear this entry.
        self.handler.remove_login_callback(pubkey, MagicMock())
        assert self.handler._pending_logins[pubkey] is callback
        self.handler.remove_login_callback(pubkey, callback)
        assert pubkey not in self.handler._pending_logins


# Protocol Response Handler Tests
class TestProtocolResponseHandler:
    def setup_method(self):
        self.contacts = MockContactBook()
        self.log_fn = MagicMock()
        self.send_packet_fn = AsyncMock()
        self.local_identity = LocalIdentity()
        self.handler = ProtocolResponseHandler(self.log_fn, self.local_identity, self.contacts)

    def test_payload_type(self):
        """Test protocol response handler payload type."""
        assert ProtocolResponseHandler.payload_type() == PAYLOAD_TYPE_PATH

    def test_protocol_response_handler_initialization(self):
        """Test protocol response handler initialization."""
        assert self.handler._contact_book == self.contacts
        assert self.handler._log == self.log_fn
        assert self.handler._local_identity == self.local_identity

    def test_parse_telemetry_response_tag_plus_lpp(self):
        """Parse tag(4) + CayenneLPP matches repeater firmware format; raw_bytes is LPP only."""
        # Repeater sends: tag(4) + LPP. Tag is 4-byte reflected_timestamp (little-endian).
        # MeshCore first record: addVoltage(TELEM_CHANNEL_SELF=1, v)
        # → channel=1, type=0x74 (LPP_VOLTAGE), 2 bytes 0.01V big-endian. 3.7V → 370 → 0x01 0x72
        tag = b"\x01\x00\x00\x00"  # LE 1
        lpp = bytes([0x01, 0x74, 0x01, 0x72])  # ch 1, Voltage, 370 (3.70 V)
        data = tag + lpp
        result = self.handler._parse_telemetry_response(data)
        assert result is not None
        assert result["type"] == "telemetry"
        assert result["reflected_timestamp"] == 1
        assert result["raw_bytes"] == lpp
        assert result["sensor_count"] == 1
        sensor = result["sensors"][0]
        assert sensor["channel"] == 1
        assert sensor["type"] == "Voltage"
        assert sensor["type_id"] == 0x74
        assert abs(sensor["value"] - 3.7) < 0.001

    def test_parse_telemetry_response_rejects_non_telemetry(self):
        """Payload without channel=1, type=0x74 signature is not classified as telemetry."""
        tag = b"\x00\x00\x00\x00"  # LE 0
        # Not starting with 0x01 0x74
        data = tag + bytes([0x01, 0x67, 0x00, 0x00])  # ch 1, Temperature, 0°C
        result = self.handler._parse_telemetry_response(data)
        assert result is None

    def test_set_contact_path_updated_callback(self):
        """set_contact_path_updated_callback stores the callback."""
        cb = MagicMock()
        self.handler.set_contact_path_updated_callback(cb)
        assert self.handler._contact_path_updated_callback is cb
        self.handler.set_contact_path_updated_callback(None)
        assert self.handler._contact_path_updated_callback is None

    @pytest.mark.asyncio
    async def test_contact_path_updated_callback_invoked_on_path_update(self):
        """PATH decrypts and updates contact path; contact_path_updated callback is invoked."""
        from openhop_core.companion.contact_store import ContactStore
        from openhop_core.companion.models import Contact

        local_identity = LocalIdentity()
        peer_identity = LocalIdentity()
        peer_pubkey = peer_identity.get_public_key()
        contacts = ContactStore(5)
        contacts.add(Contact(public_key=peer_pubkey, name="Peer"))
        log_fn = MagicMock()
        handler = ProtocolResponseHandler(log_fn, local_identity, contacts)
        handler.set_binary_response_callback(lambda *a, **k: None)

        path_len_byte = 2
        path_bytes = bytes([0x01, 0x02])
        extra_type = PAYLOAD_TYPE_RESPONSE
        extra = bytes([0, 0, 0, 0, 0x00])  # tag(4) + 1 byte (not login response)
        plaintext = bytes([path_len_byte]) + path_bytes + bytes([extra_type]) + extra

        peer_id = Identity(peer_pubkey)
        shared_secret = peer_id.calc_shared_secret(local_identity.get_private_key())
        aes_key = shared_secret[:16]
        encrypted = CryptoUtils.encrypt_then_mac(aes_key, shared_secret, plaintext)

        our_hash = local_identity.get_public_key()[0]
        src_hash = peer_pubkey[0]
        payload = bytes([our_hash, src_hash]) + encrypted

        pkt = Packet()
        pkt.header = (0 << 0) | (PAYLOAD_TYPE_PATH << 2)
        pkt.path_len = 0
        pkt.path = bytearray()
        pkt.payload = bytearray(payload)
        pkt.payload_len = len(payload)

        callback_calls = []

        async def on_path_updated(pub: bytes, path_len: int, path_bytes_arg: bytes) -> None:
            callback_calls.append((pub, path_len, path_bytes_arg))

        handler.set_contact_path_updated_callback(on_path_updated)

        await handler(pkt)
        await handler.wait_for_pending_reciprocals()

        assert len(callback_calls) == 1
        assert callback_calls[0][0] == peer_pubkey
        assert callback_calls[0][1] == path_len_byte
        assert callback_calls[0][2] == path_bytes

    @pytest.mark.asyncio
    async def test_response_authenticates_without_pending_callback(self):
        """A valid RESPONSE MAC proves ownership even when no waiter is registered."""
        from openhop_core.companion.contact_store import ContactStore
        from openhop_core.companion.models import Contact

        local_identity = LocalIdentity()
        peer_identity = LocalIdentity()
        peer_pubkey = peer_identity.get_public_key()
        contacts = ContactStore(5)
        contacts.add(Contact(public_key=peer_pubkey, name="Peer"))
        handler = ProtocolResponseHandler(MagicMock(), local_identity, contacts)

        shared_secret = Identity(peer_pubkey).calc_shared_secret(local_identity.get_private_key())
        encrypted = CryptoUtils.encrypt_then_mac(
            shared_secret[:16], shared_secret, b"\x01\x02\x03\x04\x99"
        )
        pkt = Packet()
        pkt.header = PAYLOAD_TYPE_RESPONSE << 2
        pkt.path_len = 0
        pkt.path = bytearray()
        pkt.payload = bytearray(
            bytes([local_identity.get_public_key()[0], peer_pubkey[0]]) + encrypted
        )
        pkt.payload_len = len(pkt.payload)

        result = await handler(pkt)

        assert isinstance(result, HandlerResult)
        assert result.authenticated is True

    @pytest.mark.asyncio
    async def test_response_with_wrong_destination_is_forwardable(self):
        """A valid MAC for another destination must not be consumed locally."""
        from openhop_core.companion.contact_store import ContactStore
        from openhop_core.companion.models import Contact

        local_identity = LocalIdentity()
        peer_identity = LocalIdentity()
        peer_pubkey = peer_identity.get_public_key()
        contacts = ContactStore(5)
        contacts.add(Contact(public_key=peer_pubkey, name="Peer"))
        handler = ProtocolResponseHandler(MagicMock(), local_identity, contacts)

        shared_secret = Identity(peer_pubkey).calc_shared_secret(local_identity.get_private_key())
        encrypted = CryptoUtils.encrypt_then_mac(shared_secret[:16], shared_secret, b"response")
        pkt = Packet()
        pkt.header = PAYLOAD_TYPE_RESPONSE << 2
        pkt.path_len = 0
        pkt.path = bytearray()
        pkt.payload = bytearray(bytes([0xFF, peer_pubkey[0]]) + encrypted)
        pkt.payload_len = len(pkt.payload)

        result = await handler(pkt)

        assert result.authenticated is False

    @pytest.mark.asyncio
    async def test_authenticated_path_with_invalid_envelope_remains_forwardable(self):
        """MAC success is not enough when a PATH envelope is malformed."""
        from openhop_core.companion.contact_store import ContactStore
        from openhop_core.companion.models import Contact

        local_identity = LocalIdentity()
        peer_identity = LocalIdentity()
        peer_pubkey = peer_identity.get_public_key()
        contacts = ContactStore(5)
        contacts.add(Contact(public_key=peer_pubkey, name="Peer"))
        handler = ProtocolResponseHandler(MagicMock(), local_identity, contacts)

        shared_secret = Identity(peer_pubkey).calc_shared_secret(local_identity.get_private_key())
        encrypted = CryptoUtils.encrypt_then_mac(shared_secret[:16], shared_secret, b"\x7f")
        pkt = Packet()
        pkt.header = PAYLOAD_TYPE_PATH << 2
        pkt.path_len = 0
        pkt.path = bytearray()
        pkt.payload = bytearray(
            bytes([local_identity.get_public_key()[0], peer_pubkey[0]]) + encrypted
        )
        pkt.payload_len = len(pkt.payload)

        result = await handler(pkt)

        assert result.authenticated is False

    @pytest.mark.asyncio
    async def test_contact_path_updated_with_2byte_hashes(self):
        """PATH with 2-byte hashes decrypts and updates contact path correctly."""
        from openhop_core.companion.contact_store import ContactStore
        from openhop_core.companion.models import Contact
        from openhop_core.protocol.packet_utils import PathUtils

        local_identity = LocalIdentity()
        peer_identity = LocalIdentity()
        peer_pubkey = peer_identity.get_public_key()
        contacts = ContactStore(5)
        contacts.add(Contact(public_key=peer_pubkey, name="Peer"))
        log_fn = MagicMock()
        handler = ProtocolResponseHandler(log_fn, local_identity, contacts)
        handler.set_binary_response_callback(lambda *a, **k: None)

        # 2 hops × 2-byte hashes = 4 bytes of path data
        path_len_byte = PathUtils.encode_path_len(2, 2)  # 0x42
        path_bytes = bytes([0x01, 0x02, 0x03, 0x04])
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
        pkt.header = (0 << 0) | (PAYLOAD_TYPE_PATH << 2)
        pkt.path_len = 0
        pkt.path = bytearray()
        pkt.payload = bytearray(payload)
        pkt.payload_len = len(payload)

        callback_calls = []

        async def on_path_updated(pub: bytes, path_len: int, path_bytes_arg: bytes) -> None:
            callback_calls.append((pub, path_len, path_bytes_arg))

        handler.set_contact_path_updated_callback(on_path_updated)

        await handler(pkt)

        assert len(callback_calls) == 1
        assert callback_calls[0][0] == peer_pubkey
        assert callback_calls[0][1] == path_len_byte  # encoded byte, not raw count
        assert callback_calls[0][2] == path_bytes  # all 4 bytes of path data

    @pytest.mark.asyncio
    async def test_login_path_return_learns_path_without_waiter(self):
        """Zero-hop login PATH-return must trigger path learning + reciprocal PATH
        even with no stats/telemetry waiter registered (Fix B).

        During login no response callback exists yet, so the old guard dropped the
        PATH-return before path learning could run, leaving out_path_len == -1 and
        forcing the follow-up stats REQ to flood. The PATH branch must always decrypt
        so _update_contact_path + reciprocal PATH run (firmware onContactPathRecv)."""
        from openhop_core.companion.contact_store import ContactStore
        from openhop_core.companion.models import Contact

        local_identity = LocalIdentity()  # companion
        server_identity = LocalIdentity()  # firmware repeater
        server_pubkey = server_identity.get_public_key()
        contacts = ContactStore(5)
        contacts.add(Contact(public_key=server_pubkey, name="Repeater"))
        handler = ProtocolResponseHandler(MagicMock(), local_identity, contacts)

        # Login state: no response waiter and no binary callback registered.
        injector = AsyncMock()
        handler.set_packet_injector(injector)
        path_updates = []

        async def on_path_updated(pub, path_len, path_bytes_arg):
            path_updates.append((pub, path_len, path_bytes_arg))

        handler.set_contact_path_updated_callback(on_path_updated)

        # Firmware zero-hop login reply: 13-byte login response embedded in a
        # flood PATH-return with an empty (0-hop) path.
        reply = bytearray(13)
        struct.pack_into("<I", reply, 0, 1234)  # timestamp
        reply[4] = 0x00  # RESP_SERVER_LOGIN_OK
        client_hash = local_identity.get_public_key()[0]
        server_hash = server_pubkey[0]
        secret = Identity(server_pubkey).calc_shared_secret(local_identity.get_private_key())
        pkt = PacketBuilder.create_path_return(
            dest_hash=client_hash,
            src_hash=server_hash,
            secret=secret,
            path=[],
            extra_type=PAYLOAD_TYPE_RESPONSE,
            extra=bytes(reply),
        )
        assert pkt.is_route_flood()

        await handler(pkt)
        await handler.wait_for_pending_reciprocals()

        # Path learned as zero-hop direct (out_path_len == 0).
        assert len(path_updates) == 1
        assert path_updates[0][0] == server_pubkey
        assert path_updates[0][1] == 0
        learned = contacts.get_by_key(server_pubkey)
        assert learned.out_path_len == 0
        # Reciprocal PATH sent back so the repeater learns its route to us.
        injector.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_login_path_completes_before_blocked_reciprocal_tx(self):
        """A valid PATH login response must not wait behind the radio TX path."""
        from openhop_core.companion.contact_store import ContactStore
        from openhop_core.companion.models import Contact

        local_identity = LocalIdentity()
        server_identity = LocalIdentity()
        server_pubkey = server_identity.get_public_key()
        contacts = ContactStore(5)
        contacts.add(Contact(public_key=server_pubkey, name="Repeater"))
        protocol_handler = ProtocolResponseHandler(MagicMock(), local_identity, contacts)
        login_handler = LoginResponseHandler(local_identity, contacts, MagicMock())

        injector_started = asyncio.Event()
        release_injector = asyncio.Event()

        async def blocked_injector(_packet):
            injector_started.set()
            await release_injector.wait()

        protocol_handler.set_packet_injector(blocked_injector)
        login_completed = asyncio.Event()
        path_seen_by_callback = {}

        def on_login(_success, _data):
            contact = contacts.get_by_key(server_pubkey)
            path_seen_by_callback["len"] = contact.out_path_len
            path_seen_by_callback["path"] = contact.out_path
            login_completed.set()

        login_handler.register_login_callback(server_pubkey, on_login)

        reply = bytearray(13)
        struct.pack_into("<I", reply, 0, 1234)
        reply[4] = 0x00
        reply[12] = 2
        secret = Identity(server_pubkey).calc_shared_secret(local_identity.get_private_key())
        packet = PacketBuilder.create_path_return(
            dest_hash=local_identity.get_public_key()[0],
            src_hash=server_pubkey[0],
            secret=secret,
            path=[0xA1],
            extra_type=PAYLOAD_TYPE_RESPONSE,
            extra=bytes(reply),
            path_len_encoded=PathUtils.encode_path_len(1, 1),
        )
        packet.set_path(b"\xb2", PathUtils.encode_path_len(1, 1))

        result = await asyncio.wait_for(
            PathHandler(
                MagicMock(),
                protocol_response_handler=protocol_handler,
                login_response_handler=login_handler,
            )(packet),
            timeout=0.1,
        )

        assert result.authenticated is True
        assert login_completed.is_set()
        assert path_seen_by_callback == {
            "len": PathUtils.encode_path_len(1, 1),
            "path": b"\xa1",
        }
        # The reciprocal is genuinely in flight (queued, not awaited inline).
        await asyncio.wait_for(injector_started.wait(), timeout=0.1)
        release_injector.set()
        await protocol_handler.wait_for_pending_reciprocals()


class TestProtocolRequestHandler:
    """Tests for ProtocolRequestHandler._build_response (firmware-consistent)."""

    def setup_method(self):
        self.local_identity = LocalIdentity()
        self.contacts = MockContactBook()
        self.log_fn = MagicMock()
        self.handler = ProtocolRequestHandler(
            self.local_identity, self.contacts, log_fn=self.log_fn
        )

    def _client_with_key(self, pubkey_bytes: bytes):
        """Return a minimal client object with public_key (no .id to use public_key path)."""

        class Client:
            pass

        c = Client()
        c.public_key = pubkey_bytes
        c.out_path = b""
        c.out_path_len = -1
        return c

    @pytest.mark.asyncio
    async def test_call_not_for_us_returns_for_us_false(self):
        """A REQ whose dest hash does not match ours is not for us."""
        packet = Packet()
        packet.header = (ROUTE_TYPE_FLOOD & 0x03) | (PAYLOAD_TYPE_REQ << 2)
        our_hash = self.local_identity.get_public_key()[0]
        wrong_dest = our_hash ^ 0xFF
        packet.payload = bytes([wrong_dest, 0x01, 0x02, 0x03])

        result = await self.handler(packet)

        assert result.authenticated is False
        assert result.response is None

    @pytest.mark.asyncio
    async def test_call_prefix_match_but_undecryptable_returns_for_us_false(self):
        """Dest prefix collides with ours but no client authenticates."""
        packet = Packet()
        packet.header = (ROUTE_TYPE_FLOOD & 0x03) | (PAYLOAD_TYPE_REQ << 2)
        our_hash = self.local_identity.get_public_key()[0]
        # dest matches us, but MockContactBook has no matching client / secret,
        # so decryption cannot succeed -> must report not-for-us for forwarding.
        packet.payload = bytes([our_hash, 0x01]) + b"\x00" * 16

        result = await self.handler(packet)

        assert result.authenticated is False
        assert result.response is None

    @pytest.mark.asyncio
    async def test_call_short_payload_returns_for_us_false(self):
        packet = Packet()
        packet.header = (ROUTE_TYPE_FLOOD & 0x03) | (PAYLOAD_TYPE_REQ << 2)
        packet.payload = b"\x01"

        result = await self.handler(packet)

        assert result.authenticated is False

    def _req_handler_with_client(self, request_handlers=None):
        """Build a handler wired to one ACL-style client that shares last_timestamp."""
        from openhop_core.node.handlers.protocol_request import REQ_TYPE_GET_STATUS
        from openhop_core.protocol.identity import Identity

        peer = LocalIdentity()
        secret = Identity(peer.get_public_key()).calc_shared_secret(
            self.local_identity.get_private_key()
        )

        class Client:
            pass

        client = Client()
        client.id = Identity(peer.get_public_key())
        client.public_key = peer.get_public_key()
        client.shared_secret = secret
        client.last_timestamp = 0
        client.last_activity = 0
        client.out_path = b""
        client.out_path_len = -1

        handler = ProtocolRequestHandler(
            self.local_identity,
            self.contacts,
            get_clients_fn=lambda h: [client],
            request_handlers=request_handlers
            or {REQ_TYPE_GET_STATUS: lambda c, ts, data: b"\x02\x02"},
            log_fn=self.log_fn,
        )

        our_hash = self.local_identity.get_public_key()[0]
        src_hash = peer.get_public_key()[0]

        def build_req(ts, req_type=REQ_TYPE_GET_STATUS):
            plaintext = struct.pack("<I", ts) + bytes([req_type])
            enc = CryptoUtils.encrypt_then_mac(secret[:16], secret, plaintext)
            pkt = Packet()
            pkt.header = (ROUTE_TYPE_DIRECT & 0x03) | (PAYLOAD_TYPE_REQ << 2)
            pkt.path_len = 0
            pkt.path = bytearray()
            pkt.payload = bytes([our_hash, src_hash]) + enc
            pkt.payload_len = len(pkt.payload)
            return pkt

        return handler, client, build_req

    @pytest.mark.asyncio
    async def test_req_replay_is_rejected(self):
        """A REQ is accepted only when strictly newer than the client's last accepted
        timestamp; replays and older timestamps are rejected (firmware parity)."""
        handler, client, build_req = self._req_handler_with_client()

        r1 = await handler(build_req(1000))
        assert r1.authenticated is True
        assert r1.response is not None
        assert client.last_timestamp == 1000

        # Exact replay: rejected, no response, watermark unchanged.
        r2 = await handler(build_req(1000))
        assert r2.authenticated is True
        assert r2.response is None
        assert client.last_timestamp == 1000

        # Older timestamp: rejected.
        r3 = await handler(build_req(999))
        assert r3.response is None
        assert client.last_timestamp == 1000

        # Strictly newer: accepted, watermark advances.
        r4 = await handler(build_req(1001))
        assert r4.response is not None
        assert client.last_timestamp == 1001

    @pytest.mark.asyncio
    async def test_req_invalid_command_does_not_advance_watermark(self):
        """An unhandled request type produces no reply and must not move the watermark,
        so a later valid request with a lower timestamp is still accepted."""
        handler, client, build_req = self._req_handler_with_client()

        r = await handler(build_req(1000, req_type=0x99))  # no handler for 0x99
        assert r.response is None
        assert client.last_timestamp == 0

        r = await handler(build_req(500))  # default req_type has a handler
        assert r.response is not None
        assert client.last_timestamp == 500

    @pytest.mark.asyncio
    async def test_direct_req_flood_fallback_accumulates_at_request_hash_width(self):
        """With no out_path the RESPONSE floods at the REQ's hash width.

        Firmware: sendFloodReply(reply, SERVER_RESPONSE_DELAY,
        packet->getPathHashSize()) (simple_repeater onPeerDataRecv, the
        OUT_PATH_UNKNOWN branch). A DIRECT request that reached us has had its
        hops consumed, but removeSelfFromPath only decrements the count, so
        path_len bits 6-7 still carry the width it was routed at.
        """
        handler, client, build_req = self._req_handler_with_client()
        assert client.out_path_len == -1  # no known route: forces the flood fallback

        pkt = build_req(1000)
        pkt.path_len = PathUtils.encode_path_len(3, 0)  # 3-byte hashes, hops consumed

        reply = (await handler(pkt)).response
        assert reply.get_route_type() == ROUTE_TYPE_FLOOD
        assert PathUtils.get_path_hash_size(reply.path_len) == 3
        assert PathUtils.get_path_hash_count(reply.path_len) == 0
        # Marked so the dispatcher's node default cannot stamp over the mirror
        # (see test_dispatcher.py: applied marker is not overwritten).
        assert getattr(reply, "_path_hash_mode_applied", False) is True

    @pytest.mark.asyncio
    async def test_direct_req_reply_keeps_the_out_path_hash_width(self):
        """A routed reply keeps its out_path's width; the mirror is flood-only.

        The out_path here is zero-hop, so nothing but the branch guard stops the
        mirror from rewriting a path_len that belongs to the stored route.
        """
        handler, client, build_req = self._req_handler_with_client()
        client.out_path = b""
        client.out_path_len = PathUtils.encode_path_len(2, 0)  # zero-hop, 2-byte hashes

        pkt = build_req(1000)
        pkt.path_len = PathUtils.encode_path_len(3, 0)  # request used a different width

        reply = (await handler(pkt)).response
        assert reply.get_route_type() == ROUTE_TYPE_DIRECT
        assert reply.path_len == PathUtils.encode_path_len(2, 0)

    def test_advance_client_watermark_is_monotonic(self):
        """The watermark never moves backwards: if another accepted request
        advanced it between the replay check and the write, an older (but
        already-validated) timestamp must not regress it."""
        handler, client, _ = self._req_handler_with_client()

        client.last_timestamp = 2000
        handler._advance_client_watermark(client, 1500)
        assert client.last_timestamp == 2000

        handler._advance_client_watermark(client, 2500)
        assert client.last_timestamp == 2500

    def test_flood_req_returns_path_packet(self):
        """REQ via flood → path-return PATH packet (firmware createPathReturn + sendFlood)."""
        peer_identity = LocalIdentity()
        client = self._client_with_key(peer_identity.get_public_key())
        client_hash = peer_identity.get_public_key()[0]
        our_hash = self.local_identity.get_public_key()[0]

        # Incoming REQ via flood with 1-hop path
        original = Packet()
        original.header = (ROUTE_TYPE_FLOOD & 0x03) | (PAYLOAD_TYPE_REQ << 2)
        original.path_len = 1
        original.path = bytearray([0xAA])
        assert original.is_route_flood()

        response_data = b"\x39\x30\x00\x00\x00"  # timestamp LE + req_type 0
        shared_secret = peer_identity.calc_shared_secret(self.local_identity.get_private_key())

        result = self.handler._build_response(original, client, response_data, shared_secret)

        assert result is not None
        assert result.get_payload_type() == PAYLOAD_TYPE_PATH
        assert result.is_route_flood()
        assert result.payload[0] == client_hash
        assert result.payload[1] == our_hash

    def test_flood_req_applies_path_hash_mode(self):
        """Path-return packet preserves incoming path hash size (2-byte hashes)."""
        from openhop_core.protocol.packet_utils import PathUtils

        peer_identity = LocalIdentity()
        client = self._client_with_key(peer_identity.get_public_key())
        shared_secret = peer_identity.calc_shared_secret(self.local_identity.get_private_key())

        original = Packet()
        original.header = (ROUTE_TYPE_FLOOD & 0x03) | (PAYLOAD_TYPE_REQ << 2)
        # 2 hops × 2-byte hashes → encoded path_len
        original.path_len = PathUtils.encode_path_len(2, 2)
        original.path = bytearray([0x01, 0x02, 0x03, 0x04])
        response_data = b"\x00\x00\x00\x00\x00"

        result = self.handler._build_response(original, client, response_data, shared_secret)

        assert result is not None
        assert result.get_payload_type() == PAYLOAD_TYPE_PATH
        # path_len high bits = (2-1)<<6 = 0x40 for 2-byte hash size, 0 hops
        assert result.path_len == 0x40

    def test_direct_req_no_out_path_returns_response_flood(self):
        """Direct REQ and no client out_path → RESPONSE via flood (no reversed path)."""
        peer_identity = LocalIdentity()
        client = self._client_with_key(peer_identity.get_public_key())
        client.out_path = b""
        client.out_path_len = -1
        shared_secret = peer_identity.calc_shared_secret(self.local_identity.get_private_key())

        original = Packet()
        original.header = (ROUTE_TYPE_DIRECT & 0x03) | (PAYLOAD_TYPE_REQ << 2)
        original.path_len = 1
        original.path = bytearray([0xBB])
        assert not original.is_route_flood()

        response_data = b"\x01\x00\x00\x00\x00"
        result = self.handler._build_response(original, client, response_data, shared_secret)

        assert result is not None
        assert result.get_payload_type() == PAYLOAD_TYPE_RESPONSE
        assert result.is_route_flood()
        assert result.path_len == 0

    def test_direct_req_with_out_path_returns_response_direct(self):
        """Direct REQ and client has out_path → RESPONSE via direct with that path."""
        peer_identity = LocalIdentity()
        client = self._client_with_key(peer_identity.get_public_key())
        client.out_path = bytes([0x01, 0x02])
        client.out_path_len = 2
        shared_secret = peer_identity.calc_shared_secret(self.local_identity.get_private_key())

        original = Packet()
        original.header = (ROUTE_TYPE_DIRECT & 0x03) | (PAYLOAD_TYPE_REQ << 2)
        original.path_len = 0
        original.path = bytearray()

        response_data = b"\x02\x00\x00\x00\x00"
        result = self.handler._build_response(original, client, response_data, shared_secret)

        assert result is not None
        assert result.get_payload_type() == PAYLOAD_TYPE_RESPONSE
        assert result.is_route_direct()
        assert result.path_len == 2
        assert bytes(result.path) == b"\x01\x02"


class TestTraceHandler:
    def setup_method(self):
        self.log_fn = MagicMock()
        self.local_identity = LocalIdentity()
        self.handler = TraceHandler(self.log_fn)

    def test_payload_type(self):
        """Test trace handler payload type."""
        assert TraceHandler.payload_type() == PAYLOAD_TYPE_TRACE

    def test_trace_handler_initialization(self):
        """Test trace handler initialization."""
        assert self.handler._log == self.log_fn

    def test_parse_trace_payload_one_byte_hashes(self):
        """flags=0: 1 byte per hop; path 0x01 0x02 = two hops."""
        payload = struct.pack("<IIB", 0x11111111, 0x22222222, 0x00) + bytes([0x01, 0x02])
        r = self.handler._parse_trace_payload(payload)
        assert r["valid"]
        assert r["path_hash_width"] == 1
        assert r["path_hop_count"] == 2
        assert r["trace_hops"] == [b"\x01", b"\x02"]
        assert r["trace_path_bytes"] == b"\x01\x02"
        assert r["trace_path"] == [0x01, 0x02]

    def test_parse_trace_payload_two_byte_hashes(self):
        """flags=0x01: 2 bytes per hop; 0x01 0x02 = one hop 0x0102."""
        payload = struct.pack("<IIB", 1, 2, 0x01) + bytes([0x01, 0x02])
        r = self.handler._parse_trace_payload(payload)
        assert r["valid"]
        assert r["path_hash_width"] == 2
        assert r["path_hop_count"] == 1
        assert r["trace_hops"] == [b"\x01\x02"]
        assert r["trace_path"] == [0x01]

    def test_format_trace_response_multibyte_hops(self):
        parsed = {
            "valid": True,
            "tag": 0xC88E314F,
            "auth_code": 0,
            "flags": 1,
            "trace_hops": [b"\x01\x02"],
            "snr": 11.8,
            "rssi": -45,
        }
        s = self.handler._format_trace_response(parsed)
        assert "0x0102" in s
        assert "path=[0x0102]" in s


# Integration Tests
@pytest.mark.asyncio
async def test_all_handlers_have_correct_payload_types():
    """Test that all handlers have unique and correct payload types."""
    handlers = [
        (AckHandler, PAYLOAD_TYPE_ACK),
        (TextMessageHandler, PAYLOAD_TYPE_TXT_MSG),
        (AdvertHandler, PAYLOAD_TYPE_ADVERT),
        (PathHandler, PAYLOAD_TYPE_PATH),
        (GroupTextHandler, PAYLOAD_TYPE_GRP_TXT),
        (LoginResponseHandler, PAYLOAD_TYPE_RESPONSE),
        (
            ProtocolResponseHandler,
            PAYLOAD_TYPE_PATH,
        ),  # Protocol responses come as PATH packets
        (TraceHandler, PAYLOAD_TYPE_TRACE),
    ]

    payload_types = []
    for handler_class, expected_type in handlers:
        payload_type = handler_class.payload_type()
        assert payload_type == expected_type
        payload_types.append(payload_type)

    # Check for uniqueness (except for LoginResponseHandler and
    # ProtocolResponseHandler which share RESPONSE)
    unique_types = set(payload_types)
    assert (
        len(unique_types) == len(payload_types) - 1
    )  # -1 because two handlers share RESPONSE type


@pytest.mark.asyncio
async def test_handlers_can_be_called():
    """Test that all handlers can be instantiated and called without errors."""
    local_identity = LocalIdentity()
    contacts = MockContactBook()
    log_fn = MagicMock()
    send_packet_fn = AsyncMock()
    event_service = MockEventService()

    handlers = [
        AckHandler(log_fn),
        TextMessageHandler(local_identity, contacts, log_fn, send_packet_fn, event_service),
        AdvertHandler(log_fn),
        PathHandler(log_fn),
        GroupTextHandler(local_identity, contacts, log_fn, send_packet_fn),
        LoginResponseHandler(local_identity, contacts, log_fn),
        ProtocolResponseHandler(log_fn, local_identity, contacts),
        TraceHandler(log_fn),
    ]

    # Create a minimal packet for testing
    packet = Packet()
    packet.payload = bytearray(b"test_payload")

    # All handlers should be callable without raising exceptions
    for handler in handlers:
        try:
            await handler(packet)
        except Exception as e:
            # Some handlers may raise exceptions due to incomplete setup,
            # but they should be callable
            assert isinstance(e, (ValueError, AttributeError, TypeError))  # Expected exceptions


# AnonReqResponseHandler Tests (separate from LoginResponseHandler)
def test_anon_req_response_handler():
    """Test AnonReqResponseHandler can be imported and has correct payload type."""
    from openhop_core.node.handlers import AnonReqResponseHandler

    # Should have same payload type as anonymous requests
    assert AnonReqResponseHandler.payload_type() == PAYLOAD_TYPE_ANON_REQ


# LoginServerHandler Tests — verify parity with C++ simple_repeater
class TestLoginServerHandler:
    """
    Tests for the server-side login handler.

    Validates that behavior matches C++ MeshCore/examples/simple_repeater:
    - Flood login → PATH packet response (login reply as extra data)
    - Direct login → RESPONSE datagram flooded back
    - Failed auth → no response sent
    - Response payload is 13 bytes with correct structure
    """

    def setup_method(self):
        from openhop_core.node.handlers.login_server import LoginServerHandler

        self.server_identity = LocalIdentity()
        self.client_identity_local = LocalIdentity()
        self.log_fn = MagicMock()

        # Default: successful auth returning admin permissions (0x03)
        self.auth_callback = MagicMock(return_value=(True, 0x03))

        self.handler = LoginServerHandler(
            local_identity=self.server_identity,
            log_fn=self.log_fn,
            authenticate_callback=self.auth_callback,
            is_room_server=False,
        )

        # Capture sent packets
        self.sent_packets = []

        def capture_send(pkt, delay_ms):
            self.sent_packets.append((pkt, delay_ms))

        self.handler.set_send_packet_callback(capture_send)

    def _build_login_packet(self, password="admin123", route_type="flood", path=None):
        """Build an ANON_REQ login packet the same way the client does."""
        client_pubkey = self.client_identity_local.get_public_key()
        server_pubkey = self.server_identity.get_public_key()

        # Calculate shared secret (client side)
        server_id = Identity(server_pubkey)
        shared_secret = server_id.calc_shared_secret(self.client_identity_local.get_private_key())
        aes_key = shared_secret[:16]

        # Repeater format plaintext: timestamp(4) + password + null
        timestamp = int(time.time())
        plaintext = struct.pack("<I", timestamp) + password.encode("utf-8") + b"\x00"
        encrypted = CryptoUtils.encrypt_then_mac(aes_key, shared_secret, plaintext)

        # ANON_REQ payload: dest_hash(1) + client_pubkey(32) + encrypted_data
        dest_hash = server_pubkey[0]
        payload = bytes([dest_hash]) + client_pubkey + encrypted

        # Build packet with appropriate route type
        if route_type == "flood":
            header = (PAYLOAD_TYPE_ANON_REQ << 2) | ROUTE_TYPE_FLOOD
        else:
            header = (PAYLOAD_TYPE_ANON_REQ << 2) | ROUTE_TYPE_DIRECT

        pkt = Packet()
        pkt.header = header
        pkt.payload = bytearray(payload)
        pkt.payload_len = len(payload)

        if path:
            pkt.path = bytearray(path)
            pkt.path_len = len(path)
        else:
            pkt.path = bytearray()
            pkt.path_len = 0

        return pkt

    def test_payload_type(self):
        """LoginServerHandler handles ANON_REQ packets."""
        from openhop_core.node.handlers.login_server import LoginServerHandler

        assert LoginServerHandler.payload_type() == PAYLOAD_TYPE_ANON_REQ

    # -- consume-vs-forward return contract (#353) --------------------------

    @pytest.mark.asyncio
    async def test_returns_true_when_decrypted_for_us(self):
        """A login that decrypts for us is consumed (True), even on auth failure."""
        assert (
            await self.handler(self._build_login_packet(password="admin123"))
        ).authenticated is True
        # Wrong password still decrypted for us — it's ours to reject, not a collision.
        self.auth_callback.return_value = (False, 0x00)
        assert (await self.handler(self._build_login_packet(password="nope"))).authenticated is True

    @pytest.mark.asyncio
    async def test_returns_false_on_dest_hash_mismatch(self):
        """A login addressed to a different identity is not ours (forward)."""
        pkt = self._build_login_packet()
        pkt.payload[0] = (pkt.payload[0] + 1) & 0xFF
        assert (await self.handler(pkt)).authenticated is False

    @pytest.mark.asyncio
    async def test_returns_false_on_decrypt_failure_collision(self):
        """dest hash matches ours but HMAC fails (collision): forward (False) (#353)."""
        pkt = self._build_login_packet()
        pkt.payload[-1] ^= 0xFF  # corrupt ciphertext/MAC
        assert (await self.handler(pkt)).authenticated is False
        assert self.sent_packets == []

    @pytest.mark.asyncio
    async def test_flood_login_sends_path_packet(self):
        """Flood login → PATH packet response (matches C++ createPathReturn path)."""
        pkt = self._build_login_packet(password="admin123", route_type="flood")
        await self.handler(pkt)

        assert len(self.sent_packets) == 1
        response_pkt, delay_ms = self.sent_packets[0]

        # C++ uses SERVER_RESPONSE_DELAY = 300
        assert delay_ms == 300

        # Must be PAYLOAD_TYPE_PATH — the C++ flood path
        assert response_pkt.get_payload_type() == PAYLOAD_TYPE_PATH

        # Must be flood routed (createPathReturn sets flood)
        assert response_pkt.is_route_flood()

        # PATH payload: dest_hash(1) + src_hash(1) + encrypted(...)
        assert len(response_pkt.payload) > 2
        # dest_hash should be client's hash
        client_hash = self.client_identity_local.get_public_key()[0]
        assert response_pkt.payload[0] == client_hash
        # src_hash should be server's hash
        server_hash = self.server_identity.get_public_key()[0]
        assert response_pkt.payload[1] == server_hash

    @pytest.mark.asyncio
    async def test_direct_login_sends_response_datagram(self):
        """Direct login: RESPONSE datagram via flood (C++ sendFlood/createDatagram)."""
        pkt = self._build_login_packet(password="admin123", route_type="direct")
        await self.handler(pkt)

        assert len(self.sent_packets) == 1
        response_pkt, delay_ms = self.sent_packets[0]

        assert delay_ms == 300

        # Must be PAYLOAD_TYPE_RESPONSE — regular datagram, NOT a PATH packet
        assert response_pkt.get_payload_type() == PAYLOAD_TYPE_RESPONSE

        # C++ sends the datagram via flood when reply_path_len < 0
        assert response_pkt.is_route_flood()

    @pytest.mark.asyncio
    async def test_flood_login_response_decryptable_with_login_reply(self):
        """PATH response from flood login contains the 13-byte login reply as extra data."""
        pkt = self._build_login_packet(password="admin123", route_type="flood")
        await self.handler(pkt)

        response_pkt, _ = self.sent_packets[0]

        # Decrypt the PATH payload to verify inner structure
        client_id = Identity(self.client_identity_local.get_public_key())
        shared_secret = client_id.calc_shared_secret(self.server_identity.get_private_key())
        aes_key = shared_secret[:16]

        # PATH payload: dest_hash(1) + src_hash(1) + mac_and_ciphertext
        encrypted_part = bytes(response_pkt.payload[2:])
        plaintext = CryptoUtils.mac_then_decrypt(aes_key, shared_secret, encrypted_part)

        # Inner: path_len(1) + path_bytes(0 for no path) + extra_type(1) + extra(13)
        path_len_byte = plaintext[0]
        # With no path hops, path_len_byte is 0
        assert path_len_byte == 0

        extra_type = plaintext[1]
        assert extra_type == PAYLOAD_TYPE_RESPONSE

        # 13-byte login reply: timestamp(4) + resp_code(1) + keepalive(1) +
        #                      is_admin(1) + perms(1) + random(4) + fw_ver(1)
        # AES block padding may add trailing zero bytes — take exactly 13
        login_reply = plaintext[2:15]
        assert len(login_reply) == 13

        resp_code = login_reply[4]
        assert resp_code == 0x00  # RESP_SERVER_LOGIN_OK

        keepalive = login_reply[5]
        assert keepalive == 0  # Legacy, always 0

        is_admin = login_reply[6]
        assert is_admin == 1  # role 0x03 == PERM_ACL_ADMIN

        perms = login_reply[7]
        assert perms == 0x03

        fw_ver = login_reply[12]
        assert fw_ver == FIRMWARE_VER_LEVEL

    @pytest.mark.asyncio
    async def test_failed_auth_sends_no_response(self):
        """Failed authentication → no response sent (C++ returns 0 from handleLoginReq)."""
        self.auth_callback.return_value = (False, 0)

        pkt = self._build_login_packet(password="wrongpass", route_type="flood")
        await self.handler(pkt)

        assert len(self.sent_packets) == 0

    @pytest.mark.asyncio
    async def test_packet_too_short_ignored(self):
        """Packets with payload < 34 bytes are silently dropped."""
        pkt = Packet()
        pkt.header = (PAYLOAD_TYPE_ANON_REQ << 2) | ROUTE_TYPE_FLOOD
        pkt.payload = bytearray(b"\x00" * 10)
        pkt.payload_len = 10
        pkt.path = bytearray()
        pkt.path_len = 0

        await self.handler(pkt)

        assert len(self.sent_packets) == 0

    @pytest.mark.asyncio
    async def test_wrong_dest_hash_ignored(self):
        """Packets addressed to a different server are silently ignored."""
        pkt = self._build_login_packet(password="admin123", route_type="flood")
        # Corrupt dest_hash to not match our identity
        pkt.payload[0] = (self.server_identity.get_public_key()[0] + 1) & 0xFF

        await self.handler(pkt)

        assert len(self.sent_packets) == 0

    async def _login_reply_for(self, permissions: int) -> bytes:
        """Run a flood login returning ``permissions`` and decrypt the 13-byte reply."""
        self.auth_callback.return_value = (True, permissions)
        self.sent_packets.clear()

        pkt = self._build_login_packet(password="pw", route_type="flood")
        await self.handler(pkt)

        response_pkt, _ = self.sent_packets[0]
        client_id = Identity(self.client_identity_local.get_public_key())
        shared_secret = client_id.calc_shared_secret(self.server_identity.get_private_key())
        aes_key = shared_secret[:16]
        encrypted_part = bytes(response_pkt.payload[2:])
        plaintext = CryptoUtils.mac_then_decrypt(aes_key, shared_secret, encrypted_part)
        # skip path_len(1) + extra_type(1), take 13
        return plaintext[2:15]

    @pytest.mark.asyncio
    async def test_guest_permissions_is_admin_zero(self):
        """Guest login (role 0) → is_admin = 0 in response (matches C++ isAdmin())."""
        login_reply = await self._login_reply_for(PERM_ACL_GUEST)

        assert login_reply[6] == 0
        assert login_reply[7] == PERM_ACL_GUEST

    @pytest.mark.asyncio
    async def test_outbound_conformance_vectors(self):
        """Emit exactly the bytes in acl_conformance.OUTBOUND.

        Literal expectations on purpose: keying this off PERM_ACL_* would make
        the test follow the constants wherever they drift, and constants that
        drifted away from the mesh are the whole of #388.
        """
        for server_type, credential, admin_code, permissions in OUTBOUND:
            login_reply = await self._login_reply_for(permissions)
            label = f"{server_type}/{credential}"
            assert login_reply[6] == admin_code, f"{label}: admin_code"
            assert login_reply[7] == permissions, f"{label}: permissions"

    @pytest.mark.asyncio
    async def test_admin_code_is_an_equality_test_over_the_whole_byte(self):
        """Only role 3 is admin, for every value of the reserved upper bits.

        A bit test on 0x02 also matches READ_WRITE (2), which is what stock
        clients decode as non-admin while our byte 6 claimed admin.
        """
        for reserved in (0x00, 0x04, 0x40, 0xFC):
            for role in (0x00, 0x01, 0x02, 0x03):
                login_reply = await self._login_reply_for(role | reserved)
                expected = 1 if role == 0x03 else 0
                assert login_reply[6] == expected, f"role {role} reserved {reserved:#04x}"
                assert login_reply[7] == role | reserved

    @pytest.mark.asyncio
    async def test_no_send_callback_logs_error(self):
        """Without send callback, logs error but doesn't crash."""
        self.handler.set_send_packet_callback(None)

        pkt = self._build_login_packet(password="admin123", route_type="flood")
        await self.handler(pkt)

        # Should have logged the error
        log_calls = [str(c) for c in self.log_fn.call_args_list]
        assert any("No send packet callback" in c for c in log_calls)

    @pytest.mark.asyncio
    async def test_flood_login_with_path_includes_path_in_response(self):
        """Flood login with path hashes → PATH response includes those hashes."""
        path_hashes = [0xAA, 0xBB]
        pkt = self._build_login_packet(password="admin123", route_type="flood", path=path_hashes)
        # path_len encodes hash size and count: (hash_size-1)<<6 | count
        # For 1-byte hashes with 2 hops: (0<<6) | 2 = 2
        pkt.path_len = 2

        await self.handler(pkt)

        assert len(self.sent_packets) == 1
        response_pkt, _ = self.sent_packets[0]
        assert response_pkt.get_payload_type() == PAYLOAD_TYPE_PATH

        # Decrypt and verify path is included
        client_id = Identity(self.client_identity_local.get_public_key())
        shared_secret = client_id.calc_shared_secret(self.server_identity.get_private_key())
        aes_key = shared_secret[:16]
        encrypted_part = bytes(response_pkt.payload[2:])
        plaintext = CryptoUtils.mac_then_decrypt(aes_key, shared_secret, encrypted_part)

        # Inner: path_len_encoded(1) + path(2 bytes) + extra_type(1) + extra(13)
        path_len_encoded = plaintext[0]
        assert path_len_encoded == 2  # 2 hops, 1-byte hashes
        assert plaintext[1] == 0xAA
        assert plaintext[2] == 0xBB
        assert plaintext[3] == PAYLOAD_TYPE_RESPONSE  # extra_type

    @pytest.mark.asyncio
    async def test_flood_login_reply_accumulates_at_request_hash_width(self):
        """The PATH-return accumulates hops at the *request's* hash width.

        Firmware: sendFloodReply(path, SERVER_RESPONSE_DELAY,
        packet->getPathHashSize()) (simple_repeater onAnonDataRecv). The reply's
        own path_len declares the width repeaters use on the way back, which is
        separate from the width declared for the path carried inside it.
        """
        pkt = self._build_login_packet(
            password="admin123", route_type="flood", path=[0xAA, 0xBB, 0xCC, 0xDD]
        )
        pkt.path_len = PathUtils.encode_path_len(2, 2)  # 2 hops of 2-byte hashes

        await self.handler(pkt)

        response_pkt, _ = self.sent_packets[0]
        assert response_pkt.get_payload_type() == PAYLOAD_TYPE_PATH
        # Outer: reply starts at zero hops but declares the inbound width.
        assert PathUtils.get_path_hash_size(response_pkt.path_len) == 2
        assert PathUtils.get_path_hash_count(response_pkt.path_len) == 0
        # Marked so the dispatcher's node default cannot stamp over the mirror
        # (see test_dispatcher.py: applied marker is not overwritten).
        assert getattr(response_pkt, "_path_hash_mode_applied", False) is True

        # Inner: the taught path keeps its own 2-byte declaration and bytes.
        client_id = Identity(self.client_identity_local.get_public_key())
        shared_secret = client_id.calc_shared_secret(self.server_identity.get_private_key())
        plaintext = CryptoUtils.mac_then_decrypt(
            shared_secret[:16], shared_secret, bytes(response_pkt.payload[2:])
        )
        assert plaintext[0] == PathUtils.encode_path_len(2, 2)
        assert plaintext[1:5] == bytes([0xAA, 0xBB, 0xCC, 0xDD])

    @pytest.mark.asyncio
    async def test_direct_login_flood_reply_accumulates_at_request_hash_width(self):
        """The direct-login flood RESPONSE mirrors the width too.

        Firmware runs this branch through the same sendFloodReply(...,
        packet->getPathHashSize()) call (simple_repeater onAnonDataRecv, the
        ``reply_path_len < 0`` case). A direct request that reached us has had
        its hops consumed but still carries the width in path_len bits 6-7.
        """
        pkt = self._build_login_packet(password="admin123", route_type="direct")
        pkt.path_len = PathUtils.encode_path_len(3, 0)  # 3-byte hashes, hops consumed

        await self.handler(pkt)

        response_pkt, _ = self.sent_packets[0]
        assert response_pkt.get_payload_type() == PAYLOAD_TYPE_RESPONSE
        assert PathUtils.get_path_hash_size(response_pkt.path_len) == 3
        assert PathUtils.get_path_hash_count(response_pkt.path_len) == 0
        assert getattr(response_pkt, "_path_hash_mode_applied", False) is True


# ---------------------------------------------------------------------------
# TXT_TYPE_SIGNED_PLAIN (room server posts)
# ---------------------------------------------------------------------------


def _make_signed_room_post(
    sender,
    receiver,
    text=b"room post",
    author_prefix=b"\xde\xad\xbe\xef",
    ts=1_700_000_000,
    attempt=1,
):
    """Encrypted TXT_MSG exactly as a room server pushes a post (firmware
    simple_room_server pushPostToClient): plaintext = timestamp(4) +
    [(TXT_TYPE_SIGNED_PLAIN << 2) | attempt](1) + author_pubkey_prefix(4) + text."""
    import struct as _struct
    from types import SimpleNamespace

    from openhop_core.protocol.constants import TXT_TYPE_SIGNED_PLAIN

    flags = (TXT_TYPE_SIGNED_PLAIN << 2) | (attempt & 3)
    plaintext = _struct.pack("<I", ts) + bytes([flags]) + author_prefix + text
    receiver_contact = SimpleNamespace(
        public_key=receiver.get_public_key().hex(), out_path=[], out_path_len=-1
    )
    payload, _secret, _aes = PacketBuilder._create_encrypted_payload(
        receiver_contact, sender, plaintext
    )
    pkt = Packet()
    pkt.header = PacketBuilder._create_header(PAYLOAD_TYPE_TXT_MSG, "direct", False)
    pkt.path_len, pkt.path = 0, bytearray()
    pkt.payload = bytearray(payload)
    pkt.payload_len = len(payload)
    return pkt, plaintext


class TestSignedPlainMessages:
    """TXT_TYPE_SIGNED_PLAIN carries a 4-byte author pubkey prefix before the
    text (BaseChatMesh::onPeerDataRecv -> onSignedMessageRecv(&data[5], &data[9]))."""

    def setup_method(self):
        self.local_identity = LocalIdentity()
        self.contacts = MockContactBook()
        self.log_fn = MagicMock()
        self.send_packet_fn = AsyncMock()
        self.event_service = MockEventService()
        self.handler = TextMessageHandler(
            self.local_identity,
            self.contacts,
            self.log_fn,
            self.send_packet_fn,
            self.event_service,
        )

    @pytest.mark.asyncio
    async def test_author_prefix_separated_from_text(self):
        """The 4-byte author prefix must not leak into the message text."""
        sender = LocalIdentity()
        prefix = bytes([0xDE, 0xAD, 0xBE, 0xEF])
        pkt, _ = _make_signed_room_post(sender, self.local_identity, b"room post", prefix)
        self.contacts.contacts = [
            MockContact(public_key=sender.get_public_key().hex(), name="Room")
        ]

        await self.handler(pkt)

        assert self.event_service.publish_sync.called
        _event, data = self.event_service.publish_sync.call_args.args
        # AES block padding (NULs) is stripped downstream (base_events rstrip),
        # exactly like the PLAIN path; the author prefix must not be in the text.
        assert data["message_text"].rstrip("\x00") == "room post"
        assert data["sender_prefix"] == prefix.hex()
        assert data["txt_type"] == 2
        assert pkt.decrypted["text"].rstrip("\x00") == "room post"

    @pytest.mark.asyncio
    async def test_signed_message_acked_with_firmware_hash(self):
        """Signed messages get the firmware 4-byte ACK keyed with OUR pubkey."""
        import asyncio

        sender = LocalIdentity()
        prefix = bytes([1, 2, 3, 4])
        pkt, plaintext = _make_signed_room_post(sender, self.local_identity, b"hi room", prefix)
        self.contacts.contacts = [
            MockContact(public_key=sender.get_public_key().hex(), name="Room")
        ]

        await self.handler(pkt)
        for _ in range(80):
            if self.send_packet_fn.called:
                break
            await asyncio.sleep(0.05)

        assert self.send_packet_fn.called
        ack_packet = self.send_packet_fn.call_args.args[0]
        assert ack_packet.get_payload_type() == PAYLOAD_TYPE_ACK
        # Firmware: sha256(decrypted[0 : 9 + strlen(text)] || our pubkey)[:4]
        expected = CryptoUtils.sha256(plaintext + self.local_identity.get_public_key())[:4]
        assert bytes(ack_packet.payload) == expected
