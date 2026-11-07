"""MeshCore 1.18 direct ACK regeneration and multipart forwarding."""

import asyncio
import hashlib
import time
from unittest.mock import AsyncMock

import pytest

from openhop_core.companion import CompanionRadio
from openhop_core.node.dispatcher import Dispatcher
from openhop_core.node.handlers.ack import AckHandler
from openhop_core.node.handlers.multipart import MultipartAckHandler
from openhop_core.protocol import LocalIdentity, Packet, PacketBuilder
from openhop_core.protocol.constants import (
    MAX_PACKET_PAYLOAD,
    PAYLOAD_TYPE_ACK,
    PAYLOAD_TYPE_MULTIPART,
    ROUTE_TYPE_DIRECT,
    ROUTE_TYPE_FLOOD,
    ROUTE_TYPE_TRANSPORT_DIRECT,
)
from openhop_core.protocol.packet_utils import PathUtils

ACK = b"\x12\x34\x56\x78\x03\x99"
REAL_SLEEP = asyncio.sleep


class Radio:
    def __init__(self):
        self.sent = []

    def set_rx_callback(self, callback):
        self.rx_callback = callback

    async def send(self, data):
        self.sent.append(bytes(data))
        return {"ok": True}


@pytest.fixture
def dispatcher():
    d = Dispatcher(Radio())
    d.local_identity = LocalIdentity()
    d.set_client_repeat_enabled(True)
    return d


@pytest.fixture
def clock(monkeypatch):
    now = [time.monotonic()]

    async def sleep(seconds):
        now[0] += seconds + 1e-9

    monkeypatch.setattr("openhop_core.node.dispatcher.time.monotonic", lambda: now[0])
    monkeypatch.setattr("openhop_core.node.dispatcher.asyncio.sleep", sleep)
    return now


def routed_ack(d, remaining=None, width=1, hops=2):
    path = d.local_identity.get_public_key()[:width] + b"\xee" * width * (hops - 1)
    kwargs = {"path": path, "path_len_encoded": PathUtils.encode_path_len(width, hops)}
    if remaining is None:
        return PacketBuilder.create_ack_from_bytes(ACK, **kwargs)
    return PacketBuilder.create_multi_ack(ACK, remaining, **kwargs)


@pytest.mark.asyncio
@pytest.mark.parametrize("width", [1, 2, 3])
@pytest.mark.parametrize("hops", [1, 2])
@pytest.mark.parametrize("incoming_remaining", [None, 0, 1, 3])
@pytest.mark.parametrize("extra", [0, 2])
@pytest.mark.parametrize("route", [ROUTE_TYPE_DIRECT, ROUTE_TYPE_TRANSPORT_DIRECT])
async def test_regenerated_sequence_matches_firmware(
    dispatcher, clock, width, hops, incoming_remaining, extra, route
):
    d = dispatcher
    d.set_multi_acks(extra)
    incoming = routed_ack(d, incoming_remaining, width, hops)
    incoming.header = (incoming.header & ~3) | route
    incoming.transport_codes = [0x1234, 0x5678]
    incoming._rx_radio_id = "radio-B"
    original_wire = incoming.write_to()
    forwarded = d._build_client_repeat_forward(incoming)
    sent = []

    async def send(packet, wait_for_ack):
        assert wait_for_ack is False
        sent.append((clock[0], packet))
        # TX completion must not add another 300ms to each queue deadline.
        clock[0] += 0.1
        return True

    d.send_packet = send
    d._client_repeat_delay_ms = lambda pkt: 125
    start = clock[0]
    await d._client_repeat_transmit(forwarded, received_pkt=incoming)
    first_ms = 125 + (0 if incoming_remaining is None else (incoming_remaining + 1) * 300)
    assert len(sent) == extra + 1
    for index, (when, packet) in enumerate(sent):
        assert when - start == pytest.approx(first_ms / 1000 + index * 0.3)
        assert packet.get_route_type() == ROUTE_TYPE_DIRECT
        assert not packet.has_transport_codes()
        assert packet.path == b"\xee" * width * (hops - 1)
        assert packet.get_path_hash_size() == width
        assert packet.get_path_hash_count() == hops - 1
        assert packet._rx_radio_id == "radio-B"
        if index < extra:
            assert packet.get_payload_type() == PAYLOAD_TYPE_MULTIPART
            assert packet.payload == bytes([((extra - index) << 4) | PAYLOAD_TYPE_ACK]) + ACK
        else:
            assert packet.get_payload_type() == PAYLOAD_TYPE_ACK
            assert packet.payload == ACK
        decoded = Packet()
        assert decoded.read_from(packet.write_to())
        assert decoded.path_len == packet.path_len
        assert decoded.payload == packet.payload
    assert incoming.write_to() == original_wire


@pytest.mark.asyncio
async def test_multipart_copies_deduplicate_before_regeneration(dispatcher):
    d = dispatcher
    d._client_repeat_transmit = AsyncMock()
    for remaining in (3, 2, 1, 0):
        await d._process_received_packet(routed_ack(d, remaining).write_to(), -70, 8)
    for _ in range(4):
        await REAL_SLEEP(0)
    assert d._client_repeat_transmit.await_count == 1
    # Firmware keeps MULTIPART+unwrapped ACK and ordinary ACK as distinct hashes.
    await d._process_received_packet(routed_ack(d).write_to(), -70, 8)
    for _ in range(4):
        await REAL_SLEEP(0)
    assert d._client_repeat_transmit.await_count == 2


@pytest.mark.asyncio
async def test_overheard_multipart_does_not_poison_next_hop_claim(dispatcher):
    d = dispatcher
    d._client_repeat_transmit = AsyncMock()
    overheard = routed_ack(d, 2)
    overheard.path[:1] = b"\xff"
    await d._process_received_packet(overheard.write_to(), -70, 8)
    await d._process_received_packet(routed_ack(d, 1).write_to(), -70, 8)
    for _ in range(4):
        await REAL_SLEEP(0)
    assert d._client_repeat_transmit.await_count == 1


@pytest.mark.asyncio
async def test_zero_hop_multi_ack_confirms_once_without_forwarding(dispatcher):
    d = dispatcher
    handler = MultipartAckHandler(d._log)
    received = AsyncMock()
    handler.set_ack_received_callback(received)
    d.register_handler(PAYLOAD_TYPE_MULTIPART, handler)
    d._client_repeat_transmit = AsyncMock()
    for remaining in (2, 1, 0):
        packet = PacketBuilder.create_multi_ack(ACK, remaining)
        await d._process_received_packet(packet.write_to(), -70, 8)
    received.assert_awaited_once_with(int.from_bytes(ACK[:4], "little"))
    d._client_repeat_transmit.assert_not_called()


@pytest.mark.asyncio
async def test_locally_consumed_direct_ack_is_not_regenerated(dispatcher):
    d = dispatcher
    handler = AckHandler(d._log, d)
    handler.set_ack_received_callback(d._register_ack_received)
    d.register_handler(PAYLOAD_TYPE_ACK, handler)
    crc = int.from_bytes(ACK[:4], "little")
    waiter = asyncio.Event()
    d._waiting_acks[crc] = [waiter]
    d._client_repeat_transmit = AsyncMock()
    await d._process_received_packet(routed_ack(d).write_to(), -70, 8)
    assert waiter.is_set()
    d._client_repeat_transmit.assert_not_called()


@pytest.mark.parametrize("payload", [b"", b"\x23", b"\x23abc", b"\x24abcd"])
def test_invalid_multipart_is_not_forwarded(dispatcher, payload):
    packet = routed_ack(dispatcher, 2)
    packet.payload = bytearray(payload)
    packet.payload_len = len(payload)
    assert dispatcher._build_client_repeat_forward(packet) is None


@pytest.mark.parametrize("inner_type", [PAYLOAD_TYPE_ACK, 4])
def test_flood_multipart_is_not_repeated(dispatcher, inner_type):
    packet = routed_ack(dispatcher, 2)
    packet.payload[0] = 0x20 | inner_type
    packet.header = (packet.header & ~3) | ROUTE_TYPE_FLOOD
    assert dispatcher._build_client_repeat_forward(packet) is None


@pytest.mark.parametrize("payload", [b"", b"x", b"xyz"])
def test_truncated_ack_is_not_repeated(dispatcher, payload):
    packet = routed_ack(dispatcher)
    packet.payload = bytearray(payload)
    packet.payload_len = len(payload)
    assert dispatcher._build_client_repeat_forward(packet) is None


@pytest.mark.asyncio
async def test_regeneration_does_not_claim_a_later_inbound_plain_ack(dispatcher, clock):
    d = dispatcher
    d.set_multi_acks(2)
    d._client_repeat_delay_ms = lambda pkt: 0
    await d._process_received_packet(routed_ack(d, 2).write_to(), -70, 8)
    for _ in range(3):
        await REAL_SLEEP(0)
    assert len(d.radio.sent) == 3
    await d._process_received_packet(routed_ack(d).write_to(), -70, 8)
    for _ in range(3):
        await REAL_SLEEP(0)
    assert len(d.radio.sent) == 6
    # Both receive-side claims remain, rather than each regenerated wrapper.
    assert len(d.packet_filter._packet_hashes) == 2


@pytest.mark.asyncio
async def test_each_regenerated_frame_uses_airtime_budget(dispatcher, clock):
    d = dispatcher
    d.set_multi_acks(2)
    d._reset_tx_budget()
    d._tx_budget_ms = 0
    d._tx_next_time = clock[0] + 0.5
    d._client_repeat_delay_ms = lambda pkt: 0
    debited = []
    original_debit = d._debit_tx_budget

    def debit(packet):
        assert d._tx_lock.locked()
        debited.append(packet.get_payload_type())
        original_debit(packet)

    d._debit_tx_budget = debit
    incoming = routed_ack(d, 1)
    await d._client_repeat_transmit(d._build_client_repeat_forward(incoming), received_pkt=incoming)
    assert len(d.radio.sent) == 3
    assert debited == [PAYLOAD_TYPE_MULTIPART, PAYLOAD_TYPE_MULTIPART, PAYLOAD_TYPE_ACK]
    assert d._tx_budget_ms >= 0


@pytest.mark.asyncio
async def test_transmit_and_receive_share_canonical_multipart_hash(dispatcher):
    d = dispatcher
    received = AsyncMock()
    d.register_handler(PAYLOAD_TYPE_MULTIPART, received)
    packet = PacketBuilder.create_multi_ack(ACK, 2)
    assert await d.send_packet(packet, wait_for_ack=False)
    canonical = hashlib.sha256(bytes([PAYLOAD_TYPE_MULTIPART]) + ACK).hexdigest()[:16]
    assert set(d.packet_filter._packet_hashes) == {canonical}
    for remaining in (2, 1, 0):
        echo = PacketBuilder.create_multi_ack(ACK, remaining)
        await d._process_received_packet(echo.write_to(), -70, 8)
    received.assert_not_called()
    assert set(d.packet_filter._packet_hashes) == {canonical}


@pytest.mark.asyncio
@pytest.mark.parametrize("length", [4, 6, MAX_PACKET_PAYLOAD - 1, MAX_PACKET_PAYLOAD])
async def test_ack_size_boundary_preserves_ordinary_ack(dispatcher, clock, length):
    d = dispatcher
    d.set_multi_acks(2)
    d._client_repeat_delay_ms = lambda pkt: 0
    payload = b"\xa5" * length
    incoming = routed_ack(d)
    incoming.payload = bytearray(payload)
    incoming.payload_len = length
    await d._client_repeat_transmit(d._build_client_repeat_forward(incoming), received_pkt=incoming)
    expected_count = 1 if length == MAX_PACKET_PAYLOAD else 3
    assert len(d.radio.sent) == expected_count
    for wire in d.radio.sent:
        packet = Packet()
        assert packet.read_from(wire)
        if packet.get_payload_type() == PAYLOAD_TYPE_MULTIPART:
            assert packet.payload[1:] == payload
        else:
            assert packet.payload == payload
    assert packet.get_payload_type() == PAYLOAD_TYPE_ACK


@pytest.mark.asyncio
@pytest.mark.parametrize("budget_wait", [False, True])
async def test_disabling_client_repeat_cancels_scheduled_sequence(
    dispatcher, monkeypatch, budget_wait
):
    d = dispatcher
    d.set_multi_acks(2)
    d._client_repeat_delay_ms = lambda pkt: 0
    waiting = asyncio.Event()
    release = asyncio.Event()

    async def wait_for_delay(seconds):
        assert not d._tx_lock.locked()
        waiting.set()
        await release.wait()

    if budget_wait:
        monkeypatch.setattr(d, "_await_tx_budget", wait_for_delay)
        packet = routed_ack(d)
    else:
        monkeypatch.setattr("openhop_core.node.dispatcher.asyncio.sleep", wait_for_delay)
        packet = routed_ack(d, 1)
    await d._process_received_packet(packet.write_to(), -70, 8)
    await asyncio.wait_for(waiting.wait(), timeout=1)
    assert len(d._client_repeat_tasks) == 1
    d.set_client_repeat_enabled(False)
    await REAL_SLEEP(0)
    await REAL_SLEEP(0)
    assert not d._client_repeat_tasks
    assert not d._regenerated_acks_in_flight
    assert not d.radio.sent


def test_companion_multi_ack_preference_reaches_forwarder():
    companion = CompanionRadio(Radio(), LocalIdentity())
    companion.set_other_params(0, 0, 0, 3)
    assert companion.node.dispatcher.multi_acks == 3
    assert companion.node.dispatcher.text_message_handler.multi_acks == 3
    companion.set_other_params(0, 0, 0, 0)
    assert companion.node.dispatcher.multi_acks == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("value", [0, 1, 2, 16, 255])
async def test_runtime_uint8_preference_matches_firmware_sequence(dispatcher, clock, value):
    d = dispatcher
    d.set_multi_acks(value)
    sent = []

    async def capture(packet, wait_for_ack):
        sent.append(packet)
        return True

    d.send_packet = capture
    d._client_repeat_delay_ms = lambda pkt: 0
    incoming = routed_ack(d)
    await d._client_repeat_transmit(d._build_client_repeat_forward(incoming), received_pkt=incoming)
    assert len(sent) == value + 1
    assert [p.payload[0] >> 4 for p in sent[:-1]] == [n & 0x0F for n in range(value, 0, -1)]
    assert all(p.payload[1:] == ACK for p in sent[:-1])
    assert sent[-1].get_payload_type() == PAYLOAD_TYPE_ACK
    assert sent[-1].payload == ACK
