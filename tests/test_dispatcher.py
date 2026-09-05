import asyncio
import logging
from unittest.mock import AsyncMock, Mock, patch

import pytest

from openhop_core.node.dispatcher import Dispatcher, DispatcherState
from openhop_core.protocol import Packet
from openhop_core.protocol.constants import (
    PAYLOAD_TYPE_ACK,
    PAYLOAD_TYPE_ADVERT,
    PAYLOAD_TYPE_GRP_TXT,
    PAYLOAD_TYPE_MULTIPART,
    PAYLOAD_TYPE_TRACE,
    PAYLOAD_TYPE_TXT_MSG,
    ROUTE_TYPE_DIRECT,
    ROUTE_TYPE_FLOOD,
)
from openhop_core.protocol.packet_filter import PacketFilter
from openhop_core.protocol.packet_utils import PathUtils

# Literal MeshCore Packet::writeTo vectors: header | [transport codes] |
# path_len | path | payload.  Keep path_len literal rather than deriving it
# through OpenHop's PathUtils so these stay independent firmware fixtures.
FIRMWARE_MAX_DIRECT_PATH_VECTORS = (
    pytest.param(
        b"\x0A\x3F" + b"\xAB" + b"\x11" * 62 + b"\xA1",
        0x0A,
        0x3F,
        b"\xAB" + b"\x11" * 62,
        1,
        63,
        id="direct-1-byte-63-hop-0x3f",
    ),
    pytest.param(
        b"\x0A\x60" + b"\xAB\xCD" + b"\x11" * 62 + b"\xA2",
        0x0A,
        0x60,
        b"\xAB\xCD" + b"\x11" * 62,
        2,
        32,
        id="direct-2-byte-32-hop-0x60",
    ),
    pytest.param(
        b"\x0A\x95" + b"\xAB\xCD\xEF" + b"\x11" * 60 + b"\xA3",
        0x0A,
        0x95,
        b"\xAB\xCD\xEF" + b"\x11" * 60,
        3,
        21,
        id="direct-3-byte-21-hop-0x95",
    ),
    pytest.param(
        b"\x0B\x34\x12\x78\x56\x60" + b"\xAB\xCD" + b"\x11" * 62 + b"\xA4",
        0x0B,
        0x60,
        b"\xAB\xCD" + b"\x11" * 62,
        2,
        32,
        id="transport-direct-2-byte-32-hop-0x60",
    ),
)


def create_test_packet(payload_type: int, payload: bytes) -> bytes:
    """Create a simple test packet bytes for testing."""
    packet = Packet()
    # Ensure payload_type is valid (0-15)
    if payload_type > 15:
        payload_type = 15  # Max valid payload type
    # Bits: version (6-7) = 0, payload type (2-5), route type (0-1) = 0.
    # (The old value OR'd in (1 << 6), which sets the *version* field to 1, not
    # the route type; version 1 is a reserved/unsupported wire format and is now
    # rejected on parse, so the header must leave the version bits clear.)
    packet.header = payload_type << 2
    packet.payload = bytearray(payload)
    packet.payload_len = len(payload)
    packet.path_len = 0  # No path
    return packet.write_to()


class MockRadio:
    """Mock radio for testing dispatcher."""

    def __init__(self):
        self.tx_data = None
        self.rx_callback = None
        self.state = "idle"

    async def transmit(self, data: bytes) -> bool:
        if hasattr(self, "_should_fail") and self._should_fail:
            raise Exception("Radio transmit failed")
        self.tx_data = data
        return True

    async def send(self, data: bytes) -> bool:
        """Alias for transmit to match dispatcher interface."""
        return await self.transmit(data)

    async def wait_for_rx(self):
        # Mock receiving data
        return b"mock_received_data"

    def set_rx_callback(self, callback):
        self.rx_callback = callback

    def get_state(self):
        return self.state

    def get_last_rssi(self):
        return -70

    def get_last_snr(self):
        return 30


class MockHandler:
    """Mock handler for testing."""

    def __init__(self, payload_type: int):
        self.payload_type = payload_type
        self.call_count = 0
        self.last_packet = None

    @staticmethod
    def payload_type():
        return 99  # Mock payload type

    async def __call__(self, packet: Packet):
        self.call_count += 1
        self.last_packet = packet


class MockContactBook:
    """Mock contact book for testing."""

    def __init__(self):
        self.contacts = []


class MockIdentity:
    """Mock identity for testing."""

    def __init__(self):
        self.public_key = b"0123456789abcdef0123456789abcdef"

    def get_public_key(self):
        return self.public_key


@pytest.fixture
def mock_radio():
    return MockRadio()


@pytest.fixture
def mock_identity():
    return MockIdentity()


@pytest.fixture
def mock_contact_book():
    return MockContactBook()


@pytest.fixture
def mock_logger():
    return Mock()


@pytest.fixture
def dispatcher(mock_radio, mock_identity, mock_contact_book, mock_logger):
    packet_filter = PacketFilter()
    dispatcher = Dispatcher(radio=mock_radio, packet_filter=packet_filter, log_fn=mock_logger)
    # Set additional attributes that are normally set by the node
    dispatcher.local_identity = mock_identity
    dispatcher.contact_book = mock_contact_book
    return dispatcher


class TestDispatcherInitialization:
    """Test dispatcher initialization and setup."""

    def test_dispatcher_creation(self, mock_radio, mock_identity, mock_contact_book, mock_logger):
        """Test creating a dispatcher with valid parameters."""
        packet_filter = PacketFilter()
        dispatcher = Dispatcher(radio=mock_radio, packet_filter=packet_filter, log_fn=mock_logger)
        # Set additional attributes that are normally set by the node
        dispatcher.local_identity = mock_identity
        dispatcher.contact_book = mock_contact_book

        assert dispatcher.radio == mock_radio
        assert dispatcher.local_identity == mock_identity
        assert dispatcher.contact_book == mock_contact_book
        assert dispatcher.packet_filter == packet_filter
        assert dispatcher.state == DispatcherState.IDLE
        assert isinstance(dispatcher._handlers, dict)
        assert isinstance(dispatcher._waiting_acks, dict)
        assert isinstance(dispatcher._recent_acks, dict)

    def test_dispatcher_initial_state(self, dispatcher):
        """Test dispatcher starts in IDLE state."""
        assert dispatcher.state == DispatcherState.IDLE

    def test_dispatcher_default_handlers_registration(self, dispatcher):
        """Test that default handlers can be registered."""
        # Initially no handlers
        assert len(dispatcher._handlers) == 0

        # Register default handlers
        dispatcher.register_default_handlers(
            contacts=None, local_identity=dispatcher.local_identity, event_service=None
        )

        # Should now have handlers
        assert len(dispatcher._handlers) > 0
        # Check that ACK handler is registered
        assert PAYLOAD_TYPE_ACK in dispatcher._handlers

    def test_dispatcher_handler_registration(self, dispatcher):
        """Test registering custom handlers."""
        mock_handler = MockHandler(100)
        dispatcher.register_handler(100, mock_handler)

        assert 100 in dispatcher._handlers
        assert dispatcher._handlers[100] == mock_handler

    @pytest.mark.asyncio
    async def test_multipart_ack_releases_waiting_send(self, dispatcher):
        """A received MULTIPART ack is routed into _register_ack_received and releases a
        waiting send, just like a discrete ACK."""
        dispatcher.register_default_handlers(
            contacts=None, local_identity=dispatcher.local_identity, event_service=None
        )
        assert PAYLOAD_TYPE_MULTIPART in dispatcher._handlers

        crc = 0x12345678
        evt = asyncio.Event()
        dispatcher._waiting_acks[crc] = evt

        # wrapper byte (remaining=1, inner=ACK) + 4-byte CRC (little-endian 0x12345678)
        payload = bytes([(1 << 4) | PAYLOAD_TYPE_ACK]) + b"\x78\x56\x34\x12"
        data = create_test_packet(PAYLOAD_TYPE_MULTIPART, payload)
        await dispatcher._process_received_packet(data)

        assert evt.is_set()
        assert crc not in dispatcher._waiting_acks


class TestDispatcherRxArming:
    """RX arming behavior for radios without a push callback interface."""

    def test_warns_when_radio_lacks_set_rx_callback(self, caplog):
        """A radio with no set_rx_callback yields a silent no-RX dispatcher;
        construction must say so loudly instead of quietly never receiving."""

        class PullOnlyRadio:
            async def send(self, data):
                return {}

            async def wait_for_rx(self):
                return b""

        with caplog.at_level(logging.WARNING, logger="Dispatcher"):
            Dispatcher(radio=PullOnlyRadio(), packet_filter=PacketFilter())
        assert any("set_rx_callback" in rec.message for rec in caplog.records)

    def test_no_warning_when_radio_supports_set_rx_callback(self, mock_radio, caplog):
        with caplog.at_level(logging.WARNING, logger="Dispatcher"):
            Dispatcher(radio=mock_radio, packet_filter=PacketFilter())
        assert not [rec for rec in caplog.records if "set_rx_callback" in rec.message]


class TestDispatcherPacketProcessing:
    """Test packet processing and routing."""

    @pytest.mark.asyncio
    async def test_process_received_packet_valid(self, dispatcher):
        """Test processing a valid received packet."""
        # Create a mock packet
        payload = b"test_payload"
        packet_data = create_test_packet(PAYLOAD_TYPE_TXT_MSG, payload)

        # Register a mock handler
        mock_handler = MockHandler(PAYLOAD_TYPE_TXT_MSG)
        dispatcher.register_handler(PAYLOAD_TYPE_TXT_MSG, mock_handler)

        # Process the packet
        await dispatcher._process_received_packet(packet_data)

        # Verify handler was called
        assert mock_handler.call_count == 1
        assert mock_handler.last_packet is not None

    @pytest.mark.asyncio
    async def test_process_received_packet_unknown_type(self, dispatcher):
        """Test processing packet with unknown payload type."""
        # Create packet with unknown payload type
        payload = b"test_payload"
        packet_data = create_test_packet(999, payload)  # Unknown type

        # Process the packet (should not crash)
        await dispatcher._process_received_packet(packet_data)

        # Should still work without registered handler

    @pytest.mark.asyncio
    async def test_process_received_packet_invalid_data(self, dispatcher):
        """Test processing invalid packet data."""
        invalid_data = b"invalid_packet_data"

        # Should handle gracefully
        await dispatcher._process_received_packet(invalid_data)

    @pytest.mark.asyncio
    async def test_process_received_packet_duplicate(self, dispatcher):
        """Test duplicate packet filtering."""
        # Create a packet
        payload = b"test_payload"
        packet_data = create_test_packet(PAYLOAD_TYPE_TXT_MSG, payload)

        # Register handler
        mock_handler = MockHandler(PAYLOAD_TYPE_TXT_MSG)
        dispatcher.register_handler(PAYLOAD_TYPE_TXT_MSG, mock_handler)

        # Process same packet twice
        await dispatcher._process_received_packet(packet_data)
        await dispatcher._process_received_packet(packet_data)

        # Handler should only be called once due to deduplication
        assert mock_handler.call_count == 1


class TestDispatcherACKSystem:
    """Test ACK system functionality."""

    @pytest.mark.asyncio
    async def test_ack_waiting_and_receipt(self, dispatcher):
        """Test waiting for ACK and receiving it."""
        crc = 0x12345678

        # Start waiting for ACK
        ack_event = asyncio.Event()
        dispatcher._waiting_acks[crc] = ack_event

        # Simulate receiving ACK
        await dispatcher._register_ack_received(crc)

        # Event should be set
        assert ack_event.is_set()
        # ACK should be removed from waiting list
        assert crc not in dispatcher._waiting_acks
        # ACK should be in recent ACKs
        assert crc in dispatcher._recent_acks

    @pytest.mark.asyncio
    async def test_ack_timeout_cleanup(self, dispatcher):
        """Test ACK timeout and cleanup."""
        crc = 0x12345678
        dispatcher._waiting_acks[crc] = asyncio.Event()

        # Simulate the cleanup logic from run_forever without the infinite loop
        # Clean out old ACK CRCs (older than 5 seconds)
        now = asyncio.get_event_loop().time()
        old_time = now - 10  # 10 seconds ago
        dispatcher._recent_acks[crc] = old_time

        # Simulate cleanup (this is what run_forever does)
        dispatcher._recent_acks = {
            crc_key: ts for crc_key, ts in dispatcher._recent_acks.items() if now - ts < 5
        }

        # Old ACK should be cleaned up
        assert crc not in dispatcher._recent_acks

    def test_recent_ack_cleanup(self, dispatcher):
        """Test cleanup of old recent ACKs."""
        crc = 0x12345678
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        old_time = loop.time() - 10  # 10 seconds ago
        dispatcher._recent_acks[crc] = old_time

        # Simulate cleanup
        try:
            now = loop.time()
            dispatcher._recent_acks = {
                crc: ts for crc, ts in dispatcher._recent_acks.items() if now - ts < 5
            }
        finally:
            loop.close()

        # Old ACK should be cleaned up
        assert crc not in dispatcher._recent_acks


class TestDispatcherWaitForAckCleanup:
    """wait_for_ack() must never leak entries in `_waiting_acks`, on any exit path."""

    @pytest.mark.asyncio
    async def test_timeout_path_removes_waiting_ack(self, dispatcher):
        """A wait_for_ack() call that times out must clean up its own registration."""
        crc = 0xAABBCCDD

        result = await dispatcher.wait_for_ack(crc, timeout=0.01)

        assert result is False
        assert crc not in dispatcher._waiting_acks

    @pytest.mark.asyncio
    async def test_cancellation_removes_waiting_ack(self, dispatcher):
        """A wait_for_ack() task that is cancelled mid-wait must clean up its
        own registration rather than leaking it forever."""
        crc = 0xAABBCCDD

        task = asyncio.create_task(dispatcher.wait_for_ack(crc, timeout=10))
        await asyncio.sleep(0)  # let the task register and start waiting
        assert crc in dispatcher._waiting_acks

        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert crc not in dispatcher._waiting_acks

    @pytest.mark.asyncio
    async def test_stale_waiter_does_not_remove_newer_registration(self, dispatcher):
        """If a stale waiter's cleanup runs after a *different* Event has been
        registered under the same CRC (e.g. a fresh wait_for_ack() call took
        over that slot), the stale cleanup must be a no-op rather than
        deleting the newer registration out from under it."""
        crc = 0xAABBCCDD

        task = asyncio.create_task(dispatcher.wait_for_ack(crc, timeout=10))
        await asyncio.sleep(0)  # let the task register
        stale_event = dispatcher._waiting_acks[crc]

        # Simulate a newer waiter taking over the same CRC slot.
        newer_event = asyncio.Event()
        dispatcher._waiting_acks[crc] = newer_event
        assert stale_event is not newer_event

        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        # The stale task's finally-block cleanup must not have clobbered
        # the newer registration.
        assert dispatcher._waiting_acks.get(crc) is newer_event

    @pytest.mark.asyncio
    async def test_normal_ack_receipt_still_works_and_cleans_up_once(self, dispatcher):
        """The happy path (ACK arrives while waiting) must still return True
        and leave `_waiting_acks` clean, with no double-delete errors."""
        crc = 0xAABBCCDD

        task = asyncio.create_task(dispatcher.wait_for_ack(crc, timeout=5))
        await asyncio.sleep(0)  # let the task register
        assert crc in dispatcher._waiting_acks

        await dispatcher._register_ack_received(crc)

        result = await task
        assert result is True
        assert crc not in dispatcher._waiting_acks

    @pytest.mark.asyncio
    async def test_cached_ack_early_fire_does_not_leak(self, dispatcher):
        """expect_ack() fires its Event immediately when the CRC is already in
        the recent-ACK cache (e.g. the ACK arrived just before we started
        waiting). wait_for_ack() must still clean up its registration in that
        case instead of leaving a permanently orphaned entry."""
        crc = 0xAABBCCDD
        dispatcher._recent_acks[crc] = asyncio.get_event_loop().time()

        result = await dispatcher.wait_for_ack(crc, timeout=5)

        assert result is True
        assert crc not in dispatcher._waiting_acks


class TestDispatcherStateManagement:
    """Test dispatcher state management."""

    def test_state_transitions(self, dispatcher):
        """Test state transitions."""
        # Start in IDLE
        assert dispatcher.state == DispatcherState.IDLE

        # Change to TRANSMIT
        dispatcher.state = DispatcherState.TRANSMIT
        assert dispatcher.state == DispatcherState.TRANSMIT

        # Change to WAIT
        dispatcher.state = DispatcherState.WAIT
        assert dispatcher.state == DispatcherState.WAIT

        # Back to IDLE
        dispatcher.state = DispatcherState.IDLE
        assert dispatcher.state == DispatcherState.IDLE

    @pytest.mark.asyncio
    async def test_state_based_rx_handling(self, dispatcher):
        """Test RX handling based on state."""
        # Mock radio without callback support
        dispatcher.radio = Mock()
        dispatcher.radio.set_rx_callback = Mock(side_effect=AttributeError)

        # Set state to IDLE
        dispatcher.state = DispatcherState.IDLE
        dispatcher.radio.wait_for_rx = AsyncMock(return_value=b"test_data")
        dispatcher._process_received_packet = AsyncMock()

        # Run RX once
        await dispatcher._rx_once()

        # Should have called wait_for_rx and process_received_packet
        dispatcher.radio.wait_for_rx.assert_called_once()
        dispatcher._process_received_packet.assert_called_once_with(b"test_data")


class TestDispatcherSendPacket:
    """Test packet sending functionality."""

    @pytest.mark.asyncio
    async def test_send_packet_success(self, dispatcher):
        """Test successful packet sending."""
        # Create a proper Packet object
        packet = Packet()
        packet.header = (
            (0 << 6) | (0 << 4) | (PAYLOAD_TYPE_ADVERT << 2) | 0
        )  # Version 0, reserved 0, type, route 0
        packet.payload = bytearray(b"test_packet_data")
        packet.payload_len = len(packet.payload)
        packet.path_len = 0

        dispatcher.radio.transmit = AsyncMock(return_value=True)

        result = await dispatcher.send_packet(packet)

        assert result is True
        dispatcher.radio.transmit.assert_called_once()

    @pytest.mark.asyncio
    async def test_default_path_hash_mode_applied_to_flood_packet(self, dispatcher):
        """When path_hash_mode is set, flood packets with 0 hops get path_len bits 6-7 set."""
        from openhop_core.protocol.constants import PH_TYPE_SHIFT

        dispatcher.set_default_path_hash_mode(1)  # 2-byte hashes
        pkt = Packet()
        pkt.header = (1 << 6) | (PAYLOAD_TYPE_ADVERT << PH_TYPE_SHIFT) | ROUTE_TYPE_FLOOD
        pkt.path_len = 0
        pkt.path = bytearray()
        pkt.payload = bytearray(b"advert_payload")
        pkt.payload_len = len(pkt.payload)

        await dispatcher.send_packet(pkt)

        raw = dispatcher.radio.tx_data
        assert raw is not None
        path_len_byte = raw[1]
        assert path_len_byte == 0x40

    @pytest.mark.asyncio
    async def test_path_hash_mode_not_overwritten_when_companion_applied(self, dispatcher):
        """Packet with _path_hash_mode_applied is not overwritten by dispatcher default."""
        from openhop_core.protocol.constants import PH_TYPE_SHIFT

        dispatcher.set_default_path_hash_mode(2)  # 3-byte
        pkt = Packet()
        pkt.header = (1 << 6) | (PAYLOAD_TYPE_ADVERT << PH_TYPE_SHIFT) | ROUTE_TYPE_FLOOD
        pkt.path_len = 0
        pkt.path = bytearray()
        pkt.payload = bytearray(b"x")
        pkt.payload_len = 1
        pkt.apply_path_hash_mode(1, mark_applied=True)

        await dispatcher.send_packet(pkt)

        raw = dispatcher.radio.tx_data
        assert raw is not None
        path_len_byte = raw[1]
        assert path_len_byte == 0x40

    @pytest.mark.asyncio
    async def test_server_reply_width_survives_to_the_wire(self, dispatcher):
        """A handler's mirrored reply width reaches the radio, node default and all.

        The seam test for the rest of this behaviour: LoginServerHandler marks
        ``_path_hash_mode_applied`` and the dispatcher honours the marker, but
        each half is otherwise asserted in its own file. This drives a real
        handler-built login reply through ``send_packet`` with a *conflicting*
        node default and checks the serialized ``path_len`` byte, so a future
        change that reconstructs the reply between handler and radio -- dropping
        an attribute that is not part of the wire format -- fails here rather
        than silently reverting to the node's own width on the air.
        """
        import struct
        import time

        from openhop_core.node.handlers.login_server import LoginServerHandler
        from openhop_core.protocol import CryptoUtils, Identity, LocalIdentity
        from openhop_core.protocol.constants import PAYLOAD_TYPE_ANON_REQ, PH_TYPE_SHIFT

        server, client = LocalIdentity(), LocalIdentity()
        secret = Identity(server.get_public_key()).calc_shared_secret(client.get_private_key())

        sent = []
        handler = LoginServerHandler(
            server, lambda *_: None, authenticate_callback=lambda *a, **k: (True, 0x03)
        )
        handler.set_send_packet_callback(lambda pkt, delay: sent.append(pkt))

        # Flood login carrying two hops of 3-byte hashes.
        plaintext = struct.pack("<I", int(time.time())) + b"admin123\x00"
        login = Packet()
        login.header = (PAYLOAD_TYPE_ANON_REQ << PH_TYPE_SHIFT) | ROUTE_TYPE_FLOOD
        login.payload = bytearray(
            bytes([server.get_public_key()[0]])
            + client.get_public_key()
            + CryptoUtils.encrypt_then_mac(secret[:16], secret, plaintext)
        )
        login.payload_len = len(login.payload)
        login.path = bytearray(range(6))
        login.path_len = PathUtils.encode_path_len(3, 2)

        await handler(login)
        assert len(sent) == 1

        # Node prefers 1-byte; the request's 3-byte width must win on the wire.
        dispatcher.set_default_path_hash_mode(0)
        await dispatcher.send_packet(sent[0])

        raw = dispatcher.radio.tx_data
        assert raw is not None
        assert PathUtils.get_path_hash_size(raw[1]) == 3
        assert PathUtils.get_path_hash_count(raw[1]) == 0

    @pytest.mark.asyncio
    async def test_trace_flood_rejected(self, dispatcher):
        """TRACE payload with flood route is rejected; send_packet returns False and no TX."""
        from openhop_core.protocol.constants import PH_TYPE_SHIFT

        pkt = Packet()
        pkt.header = (1 << 6) | (PAYLOAD_TYPE_TRACE << PH_TYPE_SHIFT) | ROUTE_TYPE_FLOOD
        pkt.path_len = 0
        pkt.path = bytearray()
        pkt.payload = bytearray(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00")  # tag, auth, flags
        pkt.payload_len = len(pkt.payload)

        result = await dispatcher.send_packet(pkt)

        assert result is False
        assert dispatcher.radio.tx_data is None

    @pytest.mark.asyncio
    async def test_trace_direct_still_sends(self, dispatcher):
        """TRACE with direct route is still sent (no regression)."""
        from openhop_core.protocol.constants import PH_TYPE_SHIFT

        pkt = Packet()
        pkt.header = (1 << 6) | (PAYLOAD_TYPE_TRACE << PH_TYPE_SHIFT) | ROUTE_TYPE_DIRECT
        pkt.path_len = 0
        pkt.path = bytearray()
        pkt.payload = bytearray(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00")
        pkt.payload_len = len(pkt.payload)

        result = await dispatcher.send_packet(pkt, wait_for_ack=False)

        assert result is True
        assert dispatcher.radio.tx_data is not None

    def test_set_default_path_hash_mode_validates(self, dispatcher):
        """set_default_path_hash_mode accepts None, 0, 1, 2 and rejects other values."""
        dispatcher.set_default_path_hash_mode(None)
        assert dispatcher.path_hash_mode is None
        for mode in (0, 1, 2):
            dispatcher.set_default_path_hash_mode(mode)
            assert dispatcher.path_hash_mode == mode
        with pytest.raises(ValueError, match="path_hash_mode must be None, 0, 1, or 2"):
            dispatcher.set_default_path_hash_mode(3)
        with pytest.raises(ValueError, match="path_hash_mode must be None, 0, 1, or 2"):
            dispatcher.set_default_path_hash_mode(-1)

    @pytest.mark.asyncio
    async def test_send_packet_failure(self, dispatcher):
        """Test packet sending failure."""
        # Create a proper Packet object
        packet = Packet()
        packet.header = (
            (0 << 6) | (0 << 4) | (PAYLOAD_TYPE_ADVERT << 2) | 0
        )  # Version 0, reserved 0, type, route 0
        packet.payload = bytearray(b"test_packet_data")
        packet.payload_len = len(packet.payload)
        packet.path_len = 0

        dispatcher.radio.transmit = AsyncMock(side_effect=Exception("Radio transmit failed"))

        result = await dispatcher.send_packet(packet)

        assert result is False
        dispatcher.radio.transmit.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_packet_with_ack_waiting(self, dispatcher):
        """Test sending packet and waiting for ACK."""
        # Create a proper Packet object
        packet = Packet()
        packet.header = (
            (0 << 6) | (0 << 4) | (PAYLOAD_TYPE_ADVERT << 2) | 0
        )  # Version 0, reserved 0, type, route 0
        packet.payload = bytearray(b"test_packet_data")
        packet.payload_len = len(packet.payload)
        packet.path_len = 0

        # expected_crc = 0x12345678  # Not currently used

        # Mock radio
        dispatcher.radio.transmit = AsyncMock(return_value=True)

        # Mock ACK waiting
        dispatcher._waiting_acks = {}
        dispatcher._handle_ack_received = AsyncMock()

        # Send packet
        result = await dispatcher.send_packet(packet)

        assert result is True

    @pytest.mark.asyncio
    async def test_send_packet_returns_false_when_radio_send_returns_none(self, dispatcher):
        """If radio.send returns None, dispatcher must fail the send."""
        packet = Packet()
        packet.header = (0 << 6) | (0 << 4) | (PAYLOAD_TYPE_ADVERT << 2) | 0
        packet.payload = bytearray(b"test_packet_data")
        packet.payload_len = len(packet.payload)
        packet.path_len = 0

        dispatcher.radio.send = AsyncMock(return_value=None)

        result = await dispatcher.send_packet(packet, wait_for_ack=False)

        assert result is False

    @pytest.mark.asyncio
    async def test_advert_with_colliding_first_byte_reaches_handler(self, dispatcher):
        """A genuine peer advert whose payload[0] happens to equal our pubkey hash
        (1-byte hash collision) is no longer dropped by a payload-based "own
        packet" heuristic — only the seen table suppresses loopback now."""
        mock_handler = MockHandler(PAYLOAD_TYPE_ADVERT)
        dispatcher.register_handler(PAYLOAD_TYPE_ADVERT, mock_handler)

        our_hash = dispatcher.local_identity.get_public_key()[0]
        # Peer pubkey collides with ours in the first byte, but this packet
        # was never sent by us, so it must not be in the seen table.
        peer_pubkey = bytes([our_hash]) + bytes(31)
        packet_data = create_test_packet(PAYLOAD_TYPE_ADVERT, peer_pubkey + b"\x00" * 8)

        await dispatcher._process_received_packet(packet_data)

        assert mock_handler.call_count == 1

    @pytest.mark.asyncio
    async def test_txt_msg_with_colliding_src_hash_reaches_handler(self, dispatcher):
        """A genuine peer TXT_MSG whose payload[1] (src hash) collides with our
        pubkey hash is no longer dropped as "own" — it was never sent by us."""
        mock_handler = MockHandler(PAYLOAD_TYPE_TXT_MSG)
        dispatcher.register_handler(PAYLOAD_TYPE_TXT_MSG, mock_handler)

        our_hash = dispatcher.local_identity.get_public_key()[0]
        payload = bytes([0, our_hash]) + b"test"  # dest_hash=0, src_hash=our_hash
        packet_data = create_test_packet(PAYLOAD_TYPE_TXT_MSG, payload)

        await dispatcher._process_received_packet(packet_data)

        assert mock_handler.call_count == 1

    @pytest.mark.asyncio
    async def test_ack_with_colliding_crc_byte_reaches_handler(self, dispatcher):
        """ACK payload byte 1 is CRC data, not a sender hash; a peer ACK whose
        CRC byte happens to equal our pubkey hash must still be dispatched."""
        mock_handler = MockHandler(PAYLOAD_TYPE_ACK)
        dispatcher.register_handler(PAYLOAD_TYPE_ACK, mock_handler)

        our_hash = dispatcher.local_identity.get_public_key()[0]
        payload = bytes([0x11, our_hash, 0x22, 0x33])
        packet_data = create_test_packet(PAYLOAD_TYPE_ACK, payload)

        await dispatcher._process_received_packet(packet_data)

        assert mock_handler.call_count == 1

    @pytest.mark.asyncio
    async def test_sent_advert_dropped_on_loopback(self, dispatcher):
        """Guard: our own genuinely-sent advert fed back is still dropped, via
        the seen-table mark applied at send time (not a payload heuristic)."""
        mock_handler = MockHandler(PAYLOAD_TYPE_ADVERT)
        dispatcher.register_handler(PAYLOAD_TYPE_ADVERT, mock_handler)

        our_pubkey = dispatcher.local_identity.get_public_key()
        pkt = Packet()
        pkt.header = PAYLOAD_TYPE_ADVERT << 2  # version 0
        pkt.payload = bytearray(our_pubkey + b"\x00" * 40)
        pkt.payload_len = len(pkt.payload)
        pkt.path_len = 0
        pkt.path = bytearray()

        assert await dispatcher.send_packet(pkt, wait_for_ack=False) is True

        await dispatcher._process_received_packet(pkt.write_to())

        assert mock_handler.call_count == 0


class TestDispatcherCallbacks:
    """Test callback system."""

    @pytest.mark.asyncio
    async def test_raw_packet_callback(self, dispatcher):
        """Test raw packet callback."""
        callback_called = False
        received_packet = None
        received_data = None
        received_analysis = None

        def test_callback(packet, data, analysis):
            nonlocal callback_called, received_packet, received_data, received_analysis
            callback_called = True
            received_packet = packet
            received_data = data
            received_analysis = analysis

        # Set callback
        dispatcher.set_raw_packet_callback(test_callback)

        # Create and process packet
        packet_data = create_test_packet(PAYLOAD_TYPE_TXT_MSG, b"test_payload")

        await dispatcher._process_received_packet(packet_data)

        # Callback should have been called
        assert callback_called
        assert received_packet is not None
        assert received_data == packet_data

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "packet_data,header,path_len,expected_path,hash_size,hop_count",
        FIRMWARE_MAX_DIRECT_PATH_VECTORS,
    )
    async def test_firmware_maximum_direct_path_is_not_marked_do_not_retransmit(
        self, dispatcher, packet_data, header, path_len, expected_path, hash_size, hop_count
    ):
        """MeshCore direct frames at every valid maximum remain forwardable."""
        received_packet = None

        def capture(packet, data, analysis):
            nonlocal received_packet
            received_packet = packet

        dispatcher.set_raw_packet_callback(capture)

        await dispatcher._process_received_packet(packet_data)

        assert received_packet is not None
        assert received_packet.is_marked_do_not_retransmit() is False
        assert received_packet.header == header
        assert received_packet.path_len == path_len
        assert received_packet.get_path_hash_count() == hop_count
        assert received_packet.get_path_byte_len() == hash_size * hop_count
        assert bytes(received_packet.path) == expected_path

    @pytest.mark.asyncio
    async def test_async_callback(self, dispatcher):
        """Test async callback."""
        callback_called = False

        async def async_callback(packet, data, analysis):
            nonlocal callback_called
            callback_called = True
            await asyncio.sleep(0.01)  # Simulate async work

        # Set async callback
        dispatcher.set_raw_packet_callback(async_callback)

        # Create and process packet
        packet_data = create_test_packet(PAYLOAD_TYPE_TXT_MSG, b"test_payload")

        await dispatcher._process_received_packet(packet_data)

        # Callback should have been called
        assert callback_called


class TestDispatcherMaintenance:
    """Test maintenance functionality."""

    @pytest.mark.asyncio
    async def test_run_forever_cleanup(self, dispatcher):
        """Test run_forever maintenance loop."""
        # Add some old ACKs
        old_time = asyncio.get_event_loop().time() - 10
        dispatcher._recent_acks[0x12345678] = old_time

        # Mock the cleanup calls
        dispatcher.packet_filter.cleanup_old_hashes = Mock()

        # Run maintenance (will run for a short time due to callback support)
        # In real scenario, this would run indefinitely

        # Simulate the cleanup that happens in run_forever
        now = asyncio.get_event_loop().time()
        dispatcher._recent_acks = {
            crc: ts for crc, ts in dispatcher._recent_acks.items() if now - ts < 5
        }

        # Old ACK should be cleaned up
        assert 0x12345678 not in dispatcher._recent_acks

    @pytest.mark.asyncio
    async def test_packet_filter_cleanup(self, dispatcher):
        """Test packet filter cleanup."""
        dispatcher.packet_filter.cleanup_old_hashes = Mock()

        # Simulate cleanup call
        dispatcher.packet_filter.cleanup_old_hashes()

        # Verify cleanup was called
        dispatcher.packet_filter.cleanup_old_hashes.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_forever_health_check_uses_to_thread(self, dispatcher):
        """Health checks should run via asyncio.to_thread to avoid loop blocking."""
        dispatcher.radio.check_radio_health = Mock(return_value=True)

        wait_calls = {"count": 0}

        async def fake_wait_for(awaitable, timeout=None):
            wait_calls["count"] += 1
            if wait_calls["count"] >= 60:
                # Close the awaitable to avoid "coroutine was never awaited"
                # when we cancel out of the maintenance wait.
                if hasattr(awaitable, "close"):
                    awaitable.close()
                raise asyncio.CancelledError()
            # Maintenance tick: treat as timeout so the loop continues
            if hasattr(awaitable, "close"):
                awaitable.close()
            raise asyncio.TimeoutError()

        to_thread_mock = AsyncMock(return_value=True)

        with (
            patch("openhop_core.node.dispatcher.asyncio.wait_for", side_effect=fake_wait_for),
            patch("openhop_core.node.dispatcher.asyncio.to_thread", to_thread_mock),
        ):
            with pytest.raises(asyncio.CancelledError):
                await dispatcher.run_forever()

        to_thread_mock.assert_awaited_once_with(dispatcher.radio.check_radio_health)


class TestDispatcherErrorHandling:
    """Test error handling."""

    @pytest.mark.asyncio
    async def test_radio_tx_error_handling(self, dispatcher):
        """Test handling radio transmit errors."""
        # Create a proper Packet object
        packet = Packet()
        packet.header = PAYLOAD_TYPE_ADVERT << 2  # version 0; ADVERT packets don't wait for ACK
        packet.payload = bytearray(b"test_data")
        packet.payload_len = len(packet.payload)
        packet.path_len = 0

        dispatcher.radio.transmit = AsyncMock(side_effect=Exception("Radio error"))

        result = await dispatcher.send_packet(packet)

        # Should return False on error
        assert not result

    @pytest.mark.asyncio
    async def test_radio_rx_error_handling(self, dispatcher):
        """Test handling radio receive errors."""
        dispatcher.radio.wait_for_rx = AsyncMock(side_effect=Exception("RX error"))

        # Should handle error gracefully
        await dispatcher._rx_once()

        # Should not crash

    @pytest.mark.asyncio
    async def test_callback_error_handling(self, dispatcher):
        """Test handling callback errors."""

        def failing_callback(packet, data, analysis):
            raise Exception("Callback error")

        # Set failing callback
        dispatcher.set_raw_packet_callback(failing_callback)

        # Create and process packet
        packet_data = create_test_packet(PAYLOAD_TYPE_TXT_MSG, b"test_payload")

        # Should handle callback error gracefully
        await dispatcher._process_received_packet(packet_data)

        # Should not crash

    @pytest.mark.asyncio
    async def test_enhanced_raw_callback_raise_invoked_once(self, dispatcher):
        """A 3-arg callback that raises must not be retried with 2 args."""
        calls = []

        def failing_callback(packet, data, analysis):
            calls.append(len([packet, data, analysis]))
            raise RuntimeError("handler failed")

        dispatcher.set_raw_packet_callback(failing_callback)
        packet_data = create_test_packet(PAYLOAD_TYPE_TXT_MSG, b"test_payload")
        await dispatcher._process_received_packet(packet_data)

        assert calls == [3]

    @pytest.mark.asyncio
    async def test_variadic_raw_callback_raise_invoked_once(self, dispatcher):
        """Variadic callbacks must not double-fire when the enhanced call raises."""
        calls = []

        def failing_callback(*args):
            calls.append(len(args))
            if len(args) == 3:
                raise RuntimeError("enhanced path failed")

        dispatcher.set_raw_packet_callback(failing_callback)
        packet_data = create_test_packet(PAYLOAD_TYPE_TXT_MSG, b"test_payload")
        await dispatcher._process_received_packet(packet_data)

        assert calls == [3]

    @pytest.mark.asyncio
    async def test_legacy_two_arg_raw_callback(self, dispatcher):
        """Strict 2-arg callbacks still receive (pkt, data) once."""
        calls = []

        def legacy_callback(packet, data):
            calls.append((packet, data))

        dispatcher.set_raw_packet_callback(legacy_callback)
        packet_data = create_test_packet(PAYLOAD_TYPE_TXT_MSG, b"test_payload")
        await dispatcher._process_received_packet(packet_data)

        assert len(calls) == 1
        assert calls[0][1] == packet_data

    @pytest.mark.asyncio
    async def test_bare_decorator_two_arg_raw_callback_rescued(self, dispatcher):
        """Bare *args wrappers around 2-arg handlers must still run (TypeError rescue)."""
        calls = []

        def wrap(fn):
            def wrapper(*args, **kwargs):
                return fn(*args, **kwargs)

            return wrapper

        @wrap
        def legacy(packet, data):
            calls.append((packet, data))

        dispatcher.set_raw_packet_callback(legacy)
        packet_data = create_test_packet(PAYLOAD_TYPE_TXT_MSG, b"test_payload")
        await dispatcher._process_received_packet(packet_data)

        assert len(calls) == 1
        assert calls[0][1] == packet_data

    @pytest.mark.asyncio
    async def test_bare_decorator_three_arg_raise_invoked_once(self, dispatcher):
        """Bare wrapper around 3-arg that raises RuntimeError must not 2-arg retry."""
        calls = []

        def wrap(fn):
            def wrapper(*args, **kwargs):
                return fn(*args, **kwargs)

            return wrapper

        @wrap
        def enhanced(packet, data, analysis):
            calls.append(len([packet, data, analysis]))
            raise RuntimeError("handler failed")

        dispatcher.set_raw_packet_callback(enhanced)
        packet_data = create_test_packet(PAYLOAD_TYPE_TXT_MSG, b"test_payload")
        await dispatcher._process_received_packet(packet_data)

        assert calls == [3]

    @pytest.mark.asyncio
    async def test_variadic_typeerror_falls_back_to_two_arg(self, dispatcher):
        """Variadic arity miss (TypeError on 3-arg) still rescues with 2-arg."""
        calls = []

        def callback(*args):
            calls.append(len(args))
            if len(args) == 3:
                raise TypeError("takes 2 positional arguments but 3 were given")

        dispatcher.set_raw_packet_callback(callback)
        packet_data = create_test_packet(PAYLOAD_TYPE_TXT_MSG, b"test_payload")
        await dispatcher._process_received_packet(packet_data)

        assert calls == [3, 2]


class TestDispatcherIntegration:
    """Integration tests for dispatcher."""

    @pytest.mark.asyncio
    async def test_full_packet_flow(self, dispatcher):
        """Test complete packet receive and process flow."""
        # Create a text message packet
        payload = b"Hello, World!"
        packet_data = create_test_packet(PAYLOAD_TYPE_TXT_MSG, payload)

        # Register a handler
        mock_handler = MockHandler(PAYLOAD_TYPE_TXT_MSG)
        dispatcher.register_handler(PAYLOAD_TYPE_TXT_MSG, mock_handler)

        # Process the packet
        await dispatcher._process_received_packet(packet_data)

        # Verify handler was called with correct packet
        assert mock_handler.call_count == 1
        assert mock_handler.last_packet.payload == payload

    @pytest.mark.asyncio
    async def test_multiple_handlers(self, dispatcher):
        """Test multiple handlers for different payload types."""
        # Create handlers for different types
        text_handler = MockHandler(PAYLOAD_TYPE_TXT_MSG)
        ack_handler = MockHandler(PAYLOAD_TYPE_ACK)

        dispatcher.register_handler(PAYLOAD_TYPE_TXT_MSG, text_handler)
        dispatcher.register_handler(PAYLOAD_TYPE_ACK, ack_handler)

        # Create and process text packet
        text_packet_data = create_test_packet(PAYLOAD_TYPE_TXT_MSG, b"text message")

        # Create and process ACK packet
        ack_packet_data = create_test_packet(PAYLOAD_TYPE_ACK, b"\x78\x56\x34\x12")  # CRC

        # Process both packets
        await dispatcher._process_received_packet(text_packet_data)
        await dispatcher._process_received_packet(ack_packet_data)

        # Both handlers should have been called
        assert text_handler.call_count == 1
        assert ack_handler.call_count == 1

    def test_packet_filter_stats(self, dispatcher):
        """Test getting packet filter statistics."""
        stats = dispatcher.get_filter_stats()
        assert isinstance(stats, dict)

    def test_clear_packet_filter(self, dispatcher):
        """Test clearing packet filter."""
        dispatcher.clear_packet_filter()
        # Should not crash


class TestDispatcherPayloadBasedDedup:
    """Test that dedup uses payload-based hash (matching firmware), not raw-frame hash."""

    @pytest.mark.asyncio
    async def test_same_payload_different_paths_deduplicated(self, dispatcher):
        """Packets with same payload but different paths are caught as duplicates."""
        mock_handler = MockHandler(PAYLOAD_TYPE_TXT_MSG)
        dispatcher.register_handler(PAYLOAD_TYPE_TXT_MSG, mock_handler)

        # Packet 1: 1-byte hash mode, 0 hops
        pkt1 = Packet()
        pkt1.header = (PAYLOAD_TYPE_TXT_MSG << 2) | ROUTE_TYPE_FLOOD  # version 0
        pkt1.path_len = PathUtils.encode_path_len(1, 0)
        pkt1.path = bytearray()
        pkt1.payload = bytearray(b"Hello mesh!")
        pkt1.payload_len = len(pkt1.payload)
        data1 = pkt1.write_to()

        # Packet 2: same payload, 2 hops in path
        pkt2 = Packet()
        pkt2.header = (PAYLOAD_TYPE_TXT_MSG << 2) | ROUTE_TYPE_FLOOD  # version 0
        pkt2.path_len = PathUtils.encode_path_len(1, 2)
        pkt2.path = bytearray(b"\xAA\xBB")
        pkt2.payload = bytearray(b"Hello mesh!")
        pkt2.payload_len = len(pkt2.payload)
        data2 = pkt2.write_to()

        # Raw bytes must differ (path is different)
        assert data1 != data2

        await dispatcher._process_received_packet(data1)
        await dispatcher._process_received_packet(data2)

        # Second packet should be deduplicated — handler called only once
        assert mock_handler.call_count == 1

    @pytest.mark.asyncio
    async def test_different_payloads_not_deduplicated(self, dispatcher):
        """Packets with different payloads are processed independently."""
        mock_handler = MockHandler(PAYLOAD_TYPE_TXT_MSG)
        dispatcher.register_handler(PAYLOAD_TYPE_TXT_MSG, mock_handler)

        data1 = create_test_packet(PAYLOAD_TYPE_TXT_MSG, b"message_one")
        data2 = create_test_packet(PAYLOAD_TYPE_TXT_MSG, b"message_two")

        await dispatcher._process_received_packet(data1)
        await dispatcher._process_received_packet(data2)

        assert mock_handler.call_count == 2

    @pytest.mark.asyncio
    async def test_malformed_packet_blacklisted_by_raw_hash(self, dispatcher):
        """Malformed packets are blacklisted by raw hash and rejected on repeat."""
        bad_data = b"\xFF"

        await dispatcher._process_received_packet(bad_data)

        # Should be blacklisted by raw hash
        raw_hash = dispatcher.packet_filter.generate_hash(bad_data)
        assert dispatcher.packet_filter.is_blacklisted(raw_hash)

        # Second attempt should be rejected at blacklist check (not re-parsed)
        await dispatcher._process_received_packet(bad_data)


class TestDispatcherSendMarksSeen:
    """Sending a packet marks it seen in the packet filter, matching firmware's
    hasSeen() call right before sendPacket() in Mesh::sendFlood/sendDirect/
    sendZeroHop: a neighbor rebroadcasting our own packet back to us must be
    dropped as a duplicate rather than dispatched to handlers."""

    @pytest.mark.asyncio
    async def test_sent_flood_packet_dropped_on_loopback(self, dispatcher):
        """Identical bytes fed back through the receive path are deduplicated."""
        mock_handler = MockHandler(PAYLOAD_TYPE_TXT_MSG)
        dispatcher.register_handler(PAYLOAD_TYPE_TXT_MSG, mock_handler)

        pkt = Packet()
        pkt.header = (PAYLOAD_TYPE_TXT_MSG << 2) | ROUTE_TYPE_FLOOD  # version 0
        pkt.path_len = 0
        pkt.path = bytearray()
        pkt.payload = bytearray(b"outbound message")
        pkt.payload_len = len(pkt.payload)

        assert await dispatcher.send_packet(pkt, wait_for_ack=False) is True

        looped_data = pkt.write_to()
        await dispatcher._process_received_packet(looped_data)

        assert mock_handler.call_count == 0

    @pytest.mark.asyncio
    async def test_sent_flood_packet_dropped_on_loopback_with_mutated_path(self, dispatcher):
        """A rebroadcast copy with a different path/path_len is still recognized as
        our own send, since calculate_packet_hash() excludes path for non-TRACE."""
        mock_handler = MockHandler(PAYLOAD_TYPE_TXT_MSG)
        dispatcher.register_handler(PAYLOAD_TYPE_TXT_MSG, mock_handler)

        pkt = Packet()
        pkt.header = (PAYLOAD_TYPE_TXT_MSG << 2) | ROUTE_TYPE_FLOOD  # version 0
        pkt.path_len = 0
        pkt.path = bytearray()
        pkt.payload = bytearray(b"outbound message")
        pkt.payload_len = len(pkt.payload)

        assert await dispatcher.send_packet(pkt, wait_for_ack=False) is True

        looped = Packet()
        looped.header = (PAYLOAD_TYPE_TXT_MSG << 2) | ROUTE_TYPE_FLOOD  # version 0
        looped.path_len = 2
        looped.path = bytearray(b"\xAA\xBB")
        looped.payload = bytearray(b"outbound message")
        looped.payload_len = len(looped.payload)

        await dispatcher._process_received_packet(looped.write_to())

        assert mock_handler.call_count == 0

    @pytest.mark.asyncio
    async def test_distinct_inbound_packet_not_suppressed_after_send(self, dispatcher):
        """A genuinely different inbound packet is not caught by the send-time mark."""
        mock_handler = MockHandler(PAYLOAD_TYPE_TXT_MSG)
        dispatcher.register_handler(PAYLOAD_TYPE_TXT_MSG, mock_handler)

        pkt = Packet()
        pkt.header = (PAYLOAD_TYPE_TXT_MSG << 2) | ROUTE_TYPE_FLOOD  # version 0
        pkt.path_len = 0
        pkt.path = bytearray()
        pkt.payload = bytearray(b"outbound message")
        pkt.payload_len = len(pkt.payload)

        assert await dispatcher.send_packet(pkt, wait_for_ack=False) is True

        other_data = create_test_packet(PAYLOAD_TYPE_TXT_MSG, b"a completely different message")
        await dispatcher._process_received_packet(other_data)

        assert mock_handler.call_count == 1

    @pytest.mark.asyncio
    async def test_sent_group_packet_dropped_on_loopback(self, dispatcher):
        """GRP_TXT: _is_own_packet always returns False for group payload types, so
        this loopback would previously reach handlers — the send-time seen-table
        mark is the only thing that catches it."""
        mock_handler = MockHandler(PAYLOAD_TYPE_GRP_TXT)
        dispatcher.register_handler(PAYLOAD_TYPE_GRP_TXT, mock_handler)

        pkt = Packet()
        pkt.header = (PAYLOAD_TYPE_GRP_TXT << 2) | ROUTE_TYPE_FLOOD  # version 0
        pkt.path_len = 0
        pkt.path = bytearray()
        pkt.payload = bytearray(b"\x11" * 4 + b"group message ciphertext")
        pkt.payload_len = len(pkt.payload)

        assert await dispatcher.send_packet(pkt, wait_for_ack=False) is True

        await dispatcher._process_received_packet(pkt.write_to())

        assert mock_handler.call_count == 0

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "break_the_radio",
        [
            lambda radio: setattr(radio, "send", AsyncMock(side_effect=RuntimeError("radio gone"))),
            lambda radio: setattr(radio, "send", AsyncMock(return_value=None)),
        ],
        ids=["send_raises", "send_returns_none"],
    )
    async def test_send_that_never_reached_the_air_does_not_suppress_later_copies(
        self, dispatcher, break_the_radio
    ):
        """The mark is a bet that the send happens; a failed send must take it back.

        Otherwise this node drops every later copy of a packet it never put on
        the air — for the whole dedup window — which is exactly the case where
        another node's copy is still worth processing.
        """
        mock_handler = MockHandler(PAYLOAD_TYPE_TXT_MSG)
        dispatcher.register_handler(PAYLOAD_TYPE_TXT_MSG, mock_handler)

        pkt = Packet()
        pkt.header = (PAYLOAD_TYPE_TXT_MSG << 2) | ROUTE_TYPE_FLOOD  # version 0
        pkt.path_len = 0
        pkt.path = bytearray()
        pkt.payload = bytearray(b"never made it out")
        pkt.payload_len = len(pkt.payload)

        break_the_radio(dispatcher.radio)
        assert await dispatcher.send_packet(pkt, wait_for_ack=False) is False

        await dispatcher._process_received_packet(pkt.write_to())

        assert mock_handler.call_count == 1

    @pytest.mark.asyncio
    async def test_failed_send_does_not_lift_the_suppression_of_a_sent_packet(self, dispatcher):
        """Releasing must be keyed on the failed packet, not on recent state.

        A release that is not keyed would let the earlier packet's own echo
        back through, which is the loopback the mark exists to stop.
        """
        mock_handler = MockHandler(PAYLOAD_TYPE_TXT_MSG)
        dispatcher.register_handler(PAYLOAD_TYPE_TXT_MSG, mock_handler)

        sent = Packet()
        sent.header = (PAYLOAD_TYPE_TXT_MSG << 2) | ROUTE_TYPE_FLOOD  # version 0
        sent.path_len = 0
        sent.path = bytearray()
        sent.payload = bytearray(b"this one really went out")
        sent.payload_len = len(sent.payload)
        assert await dispatcher.send_packet(sent, wait_for_ack=False) is True

        failed = Packet()
        failed.header = (PAYLOAD_TYPE_TXT_MSG << 2) | ROUTE_TYPE_FLOOD  # version 0
        failed.path_len = 0
        failed.path = bytearray()
        failed.payload = bytearray(b"this one did not")
        failed.payload_len = len(failed.payload)
        dispatcher.radio.send = AsyncMock(return_value=None)
        assert await dispatcher.send_packet(failed, wait_for_ack=False) is False

        await dispatcher._process_received_packet(sent.write_to())

        assert mock_handler.call_count == 0
