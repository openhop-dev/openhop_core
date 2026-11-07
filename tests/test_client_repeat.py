"""Client-repeat forwarding in the Core dispatcher.

Mirrors the forwarding branches of MeshCore ``Mesh::onRecvPacket``: flood
append-own-hash, routed-direct strip-self, and direct TRACE append-SNR, plus
the RX dedupe/loopback interplay that stops a node re-forwarding its own
retransmit.
"""

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from openhop_core.companion.models import Contact
from openhop_core.node.dispatcher import Dispatcher
from openhop_core.node.handlers import HandlerResult, TextMessageHandler
from openhop_core.protocol import LocalIdentity, Packet, PacketBuilder
from openhop_core.protocol.constants import (
    PAYLOAD_TYPE_ADVERT,
    PAYLOAD_TYPE_TRACE,
    PAYLOAD_TYPE_TXT_MSG,
    ROUTE_TYPE_DIRECT,
    ROUTE_TYPE_FLOOD,
)
from openhop_core.protocol.packet_utils import PathUtils

# MockIdentity public key: first byte 0x30 ("0") is this node's 1-byte hash.
SELF_KEY = b"0123456789abcdef0123456789abcdef"
SELF_HASH = SELF_KEY[0]  # 0x30


class CountingRadio:
    """Minimal radio: counts sends, remembers the last frame, feeds RX back."""

    def __init__(self):
        self.rx_callback = None
        self.tx_data = None
        self.send_count = 0

    def set_rx_callback(self, callback):
        self.rx_callback = callback

    async def send(self, data: bytes):
        self.send_count += 1
        self.tx_data = data
        return {"ok": True}  # non-None TX metadata

    def get_last_rssi(self):
        return -70

    def get_last_snr(self):
        return 8.0


class MockIdentity:
    def get_public_key(self):
        return SELF_KEY


def _make_dispatcher(enabled=True):
    radio = CountingRadio()
    d = Dispatcher(radio, dedupe_enabled=True)
    d.local_identity = MockIdentity()
    d.set_client_repeat_enabled(enabled)
    return d, radio


def _flood_txt(dest_hash, path=b"", path_len=0):
    p = Packet()
    p.header = (PAYLOAD_TYPE_TXT_MSG << 2) | ROUTE_TYPE_FLOOD
    # payload: dest_hash, src_hash, MAC + ciphertext (opaque here)
    p.payload = bytearray([dest_hash, 0x99]) + bytearray(b"\xAA" * 12)
    p.payload_len = len(p.payload)
    p.path = bytearray(path)
    p.path_len = path_len
    return p


def _direct_txt(path, path_len, dest_hash=0x77):
    p = Packet()
    p.header = (PAYLOAD_TYPE_TXT_MSG << 2) | ROUTE_TYPE_DIRECT
    # payload: dest_hash, src_hash, MAC + ciphertext (opaque here). The hash is
    # path-independent, so every route variant of this payload hashes alike.
    p.payload = bytearray([dest_hash, 0x99]) + bytearray(b"\xAA" * 12)
    p.payload_len = len(p.payload)
    p.path = bytearray(path)
    p.path_len = path_len
    return p


# --------------------------------------------------------------------------- #
# Pure forward-builder behaviour
# --------------------------------------------------------------------------- #


def test_flood_forward_appends_own_hash_one_byte():
    d, _ = _make_dispatcher()
    pkt = _flood_txt(dest_hash=0x77)  # addressed elsewhere
    fwd = d._build_client_repeat_forward(pkt)
    assert fwd is not None
    assert bytes(fwd.path) == SELF_KEY[:1]
    assert fwd.path_len == PathUtils.encode_path_len(1, 1)
    # Payload is untouched: the packet hash (path-excluded) stays identical.
    assert fwd.calculate_packet_hash() == pkt.calculate_packet_hash()


def test_flood_forward_appends_own_hash_two_byte_width():
    d, _ = _make_dispatcher()
    pkt = _flood_txt(
        dest_hash=0x77,
        path=b"\xAB\xCD",
        path_len=PathUtils.encode_path_len(2, 1),
    )
    fwd = d._build_client_repeat_forward(pkt)
    assert fwd is not None
    assert bytes(fwd.path) == b"\xAB\xCD" + SELF_KEY[:2]
    assert fwd.path_len == PathUtils.encode_path_len(2, 2)


def test_flood_forward_built_regardless_of_dest_hash():
    # The builder no longer inspects the destination-hash byte: a bare byte
    # match must NOT suppress the forward. Consumption is decided post-dispatch
    # via the do-not-retransmit mark (firmware markDoNotRetransmit on decrypt).
    d, _ = _make_dispatcher()
    pkt = _flood_txt(dest_hash=SELF_HASH)  # byte-collides with our hash
    fwd = d._build_client_repeat_forward(pkt)
    assert fwd is not None
    assert bytes(fwd.path) == SELF_KEY[:1]


def test_flood_forward_built_for_advert_no_self_special_case():
    # No own-advert special case in the builder: an advert always builds a
    # forward. Own-advert echoes are dropped by the RX seen-table instead.
    d, _ = _make_dispatcher()
    pkt = Packet()
    pkt.header = (PAYLOAD_TYPE_ADVERT << 2) | ROUTE_TYPE_FLOOD
    pkt.payload = bytearray(SELF_KEY) + bytearray(b"\x00" * 8)
    pkt.payload_len = len(pkt.payload)
    fwd = d._build_client_repeat_forward(pkt)
    assert fwd is not None
    assert bytes(fwd.path) == SELF_KEY[:1]


def test_flood_forward_foreign_advert_is_reflooded():
    d, _ = _make_dispatcher()
    pkt = Packet()
    pkt.header = (PAYLOAD_TYPE_ADVERT << 2) | ROUTE_TYPE_FLOOD
    pkt.payload = bytearray(b"\xFF" * 32) + bytearray(b"\x00" * 8)
    pkt.payload_len = len(pkt.payload)
    fwd = d._build_client_repeat_forward(pkt)
    assert fwd is not None
    assert bytes(fwd.path) == SELF_KEY[:1]


def test_flood_forward_stops_at_hop_cap():
    d, _ = _make_dispatcher()
    # 63 one-byte hops already present: appending a 64th is not allowed.
    pkt = _flood_txt(
        dest_hash=0x77,
        path=b"\x11" * 63,
        path_len=PathUtils.encode_path_len(1, 63),
    )
    assert d._build_client_repeat_forward(pkt) is None


def test_direct_forward_strips_self_when_next_hop():
    d, _ = _make_dispatcher()
    pkt = Packet()
    pkt.header = (PAYLOAD_TYPE_TXT_MSG << 2) | ROUTE_TYPE_DIRECT
    pkt.path = bytearray(SELF_KEY[:1]) + bytearray(b"\xBB")
    pkt.path_len = PathUtils.encode_path_len(1, 2)
    pkt.payload = bytearray([0x77, 0x99]) + bytearray(b"\xAA" * 12)
    pkt.payload_len = len(pkt.payload)
    fwd = d._build_client_repeat_forward(pkt)
    assert fwd is not None
    assert bytes(fwd.path) == b"\xBB"
    assert fwd.path_len == PathUtils.encode_path_len(1, 1)


def test_direct_forward_dropped_when_not_next_hop():
    d, _ = _make_dispatcher()
    pkt = Packet()
    pkt.header = (PAYLOAD_TYPE_TXT_MSG << 2) | ROUTE_TYPE_DIRECT
    pkt.path = bytearray(b"\xEE\xBB")  # first hop is not us
    pkt.path_len = PathUtils.encode_path_len(1, 2)
    pkt.payload = bytearray([0x77, 0x99]) + bytearray(b"\xAA" * 12)
    pkt.payload_len = len(pkt.payload)
    assert d._build_client_repeat_forward(pkt) is None


def test_direct_forward_two_byte_width_strips_self():
    d, _ = _make_dispatcher()
    pkt = Packet()
    pkt.header = (PAYLOAD_TYPE_TXT_MSG << 2) | ROUTE_TYPE_DIRECT
    pkt.path = bytearray(SELF_KEY[:2]) + bytearray(b"\xBB\xCC")
    pkt.path_len = PathUtils.encode_path_len(2, 2)
    pkt.payload = bytearray([0x77, 0x99]) + bytearray(b"\xAA" * 12)
    pkt.payload_len = len(pkt.payload)
    fwd = d._build_client_repeat_forward(pkt)
    assert fwd is not None
    assert bytes(fwd.path) == b"\xBB\xCC"
    assert fwd.path_len == PathUtils.encode_path_len(2, 1)


def test_trace_forward_appends_snr_byte():
    d, _ = _make_dispatcher()
    pkt = Packet()
    pkt.header = (PAYLOAD_TYPE_TRACE << 2) | ROUTE_TYPE_DIRECT
    # trace_tag(4) auth(4) flags(1, path_sz=0 -> 1-byte hashes) then path hashes.
    # No SNR bytes recorded yet (path_len == 0), next hop at offset 0 is us.
    pkt.payload = bytearray(b"\x01\x02\x03\x04" + b"\x05\x06\x07\x08" + b"\x00") + bytearray(
        SELF_KEY[:1]
    )
    pkt.payload_len = len(pkt.payload)
    pkt.path = bytearray()
    pkt.path_len = 0
    pkt._snr = 8.0  # scaled SNR byte = int(8*4) = 32
    fwd = d._build_client_repeat_forward(pkt)
    assert fwd is not None
    assert fwd.path_len == 1
    assert fwd.path[0] == 32
    # TRACE hash folds in path_len, so the forward differs from the received copy.
    assert fwd.calculate_packet_hash() != pkt.calculate_packet_hash()


def test_trace_forward_dropped_when_not_next_hop():
    d, _ = _make_dispatcher()
    pkt = Packet()
    pkt.header = (PAYLOAD_TYPE_TRACE << 2) | ROUTE_TYPE_DIRECT
    pkt.payload = bytearray(b"\x01\x02\x03\x04" + b"\x05\x06\x07\x08" + b"\x00") + bytearray(
        b"\xEE"
    )
    pkt.payload_len = len(pkt.payload)
    pkt.path = bytearray()
    pkt.path_len = 0
    assert d._build_client_repeat_forward(pkt) is None


# --------------------------------------------------------------------------- #
# RX integration: flag gating, scheduling, dedupe/loopback
# --------------------------------------------------------------------------- #


async def _drain_tasks():
    # Let the create_task'd forward run (delay patched to 0).
    for _ in range(5):
        await asyncio.sleep(0)


@pytest.mark.asyncio
@pytest.mark.parametrize("hash_size", [1, 2, 3])
async def test_direct_ack_jitter_uses_received_path_before_stripping_self(hash_size):
    from openhop_core.protocol.packet_utils import calculate_lora_airtime_ms

    dispatcher, radio = _make_dispatcher()
    packet = PacketBuilder.create_ack_from_bytes(
        b"\x11\x22\x33\x44\x00\x99",
        path=SELF_KEY[:hash_size] + b"\xaa" * hash_size,
        path_len_encoded=PathUtils.encode_path_len(hash_size, 2),
    )
    received_len = packet.get_path_byte_len() + packet.payload_len + 2
    expected_airtime = calculate_lora_airtime_ms(received_len, 10, 250000, 5, 8)
    delay_paths = []
    original_delay = dispatcher._client_repeat_delay_ms

    def capture_delay_path(pkt):
        delay_paths.append(bytes(pkt.path))
        return original_delay(pkt)

    dispatcher._client_repeat_delay_ms = capture_delay_path
    with patch("openhop_core.node.dispatcher.random.randint", return_value=0) as rng:
        await dispatcher._process_received_packet(packet.write_to(), -70, 8.0)
        await _drain_tasks()

    rng.assert_called_once_with(0, int(5 * (expected_airtime * 0.2)))
    assert delay_paths == [SELF_KEY[:hash_size] + b"\xaa" * hash_size]
    assert radio.send_count == 1
    forwarded = Packet()
    forwarded.read_from(radio.tx_data)
    assert forwarded.path == b"\xaa" * hash_size
    assert forwarded.get_path_hash_count() == 1
    assert forwarded.payload == packet.payload


@pytest.mark.asyncio
@pytest.mark.parametrize("route", ["flood", "trace"])
async def test_flood_and_trace_jitter_use_the_appended_path(route):
    dispatcher, radio = _make_dispatcher()
    if route == "flood":
        packet = _flood_txt(dest_hash=0x77)
        expected_path = SELF_KEY[:1]
    else:
        packet = Packet()
        packet.header = (PAYLOAD_TYPE_TRACE << 2) | ROUTE_TYPE_DIRECT
        packet.payload = bytearray(bytes(range(1, 9)) + b"\x00" + SELF_KEY[:1])
        packet.payload_len = len(packet.payload)
        expected_path = bytes([32])  # received SNR 8 dB, scaled by four
    delay_paths = []

    def capture_delay_path(pkt):
        delay_paths.append(bytes(pkt.path))
        return 0

    dispatcher._client_repeat_delay_ms = capture_delay_path
    await dispatcher._process_received_packet(packet.write_to(), -70, 8.0)
    await _drain_tasks()

    assert delay_paths == [expected_path]
    assert radio.send_count == 1


@pytest.mark.asyncio
async def test_flag_off_forwards_nothing():
    d, radio = _make_dispatcher(enabled=False)
    d._client_repeat_delay_ms = lambda pkt: 0.0
    data = _flood_txt(dest_hash=0x77).write_to()
    await d._process_received_packet(data, -70, 8.0)
    await _drain_tasks()
    assert radio.send_count == 0


@pytest.mark.asyncio
async def test_flag_on_forwards_once_and_suppresses_second_copy():
    d, radio = _make_dispatcher(enabled=True)
    d._client_repeat_delay_ms = lambda pkt: 0.0
    data = _flood_txt(dest_hash=0x77).write_to()

    await d._process_received_packet(data, -70, 8.0)
    await _drain_tasks()
    assert radio.send_count == 1  # forwarded once

    # A second RF copy of the same packet is a duplicate: no second forward.
    await d._process_received_packet(data, -70, 8.0)
    await _drain_tasks()
    assert radio.send_count == 1


@pytest.mark.asyncio
async def test_own_retransmit_echo_is_suppressed():
    d, radio = _make_dispatcher(enabled=True)
    d._client_repeat_delay_ms = lambda pkt: 0.0
    data = _flood_txt(dest_hash=0x77).write_to()

    await d._process_received_packet(data, -70, 8.0)
    await _drain_tasks()
    assert radio.send_count == 1
    echoed = radio.tx_data  # our forwarded frame, with our hash appended

    # Hearing our own retransmit back over RF must not forward again: the send
    # funnel tracked the (path-excluded) hash before TX, so RX dedupe drops it.
    await d._process_received_packet(echoed, -70, 8.0)
    await _drain_tasks()
    assert radio.send_count == 1


@pytest.mark.asyncio
async def test_overheard_direct_variant_does_not_suppress_owned_relay():
    """Overhearing a longer route variant must not poison the seen table so
    that the self-stripped copy this node is the next hop for is dropped as a
    duplicate (MeshCore marks a routed-direct packet seen only when it is the
    next hop)."""
    d, radio = _make_dispatcher(enabled=True)
    d._client_repeat_delay_ms = lambda pkt: 0.0

    # Overheard earlier variant: first hop is another node, so we are not the
    # next hop. Same payload as the copy we will later own -> identical hash.
    overheard = _direct_txt(
        path=bytes([0xEE, SELF_HASH, 0xBB]),
        path_len=PathUtils.encode_path_len(1, 3),
    )
    await d._process_received_packet(overheard.write_to(), -70, 8.0)
    await _drain_tasks()
    assert radio.send_count == 0  # not ours to relay, and not tracked as seen

    # The upstream hop strips itself; now we are the next hop for the same
    # payload. It must be forwarded, not dropped as a duplicate.
    owned = _direct_txt(
        path=bytes([SELF_HASH, 0xBB]),
        path_len=PathUtils.encode_path_len(1, 2),
    )
    await d._process_received_packet(owned.write_to(), -70, 8.0)
    await _drain_tasks()
    assert radio.send_count == 1


@pytest.mark.asyncio
async def test_owned_direct_relay_still_deduplicates_second_copy():
    """A genuine duplicate of the copy this node is the next hop for is still
    suppressed: dedup is only bypassed for packets we do not own."""
    d, radio = _make_dispatcher(enabled=True)
    d._client_repeat_delay_ms = lambda pkt: 0.0
    owned = _direct_txt(
        path=bytes([SELF_HASH, 0xBB]),
        path_len=PathUtils.encode_path_len(1, 2),
    )

    await d._process_received_packet(owned.write_to(), -70, 8.0)
    await _drain_tasks()
    assert radio.send_count == 1

    await d._process_received_packet(owned.write_to(), -70, 8.0)
    await _drain_tasks()
    assert radio.send_count == 1


# --------------------------------------------------------------------------- #
# Mark-on-consume: firmware markDoNotRetransmit gates the flood forward
# --------------------------------------------------------------------------- #


class _FakeHandler:
    """Handler whose authenticated verdict is fixed, to drive the mark wiring."""

    def __init__(self, authenticated: bool):
        self._authenticated = authenticated

    async def __call__(self, pkt):
        return HandlerResult(authenticated=self._authenticated)


@pytest.mark.asyncio
async def test_consumed_flood_is_not_forwarded():
    # A handler that authenticates the packet marks it do-not-retransmit
    # (firmware markDoNotRetransmit), so the flood forward is suppressed.
    d, radio = _make_dispatcher(enabled=True)
    d._client_repeat_delay_ms = lambda pkt: 0.0
    d.register_handler(PAYLOAD_TYPE_TXT_MSG, _FakeHandler(authenticated=True))
    await d._process_received_packet(_flood_txt(dest_hash=SELF_HASH).write_to(), -70, 8.0)
    await _drain_tasks()
    assert radio.send_count == 0


@pytest.mark.asyncio
async def test_unauthenticated_flood_is_forwarded():
    # A handler that does NOT authenticate (e.g. a dest-hash byte collision that
    # fails to decrypt) leaves the packet unmarked, so it is re-flooded.
    d, radio = _make_dispatcher(enabled=True)
    d._client_repeat_delay_ms = lambda pkt: 0.0
    d.register_handler(PAYLOAD_TYPE_TXT_MSG, _FakeHandler(authenticated=False))
    await d._process_received_packet(_flood_txt(dest_hash=SELF_HASH).write_to(), -70, 8.0)
    await _drain_tasks()
    assert radio.send_count == 1


class _Contacts:
    def __init__(self, items):
        self.contacts = list(items)


def _make_dispatcher_with_text_handler(peer_contacts):
    """Dispatcher wired with a real TextMessageHandler over ``peer_contacts``."""
    radio = CountingRadio()
    identity = LocalIdentity()
    d = Dispatcher(radio, dedupe_enabled=True)
    d.local_identity = identity
    d.set_client_repeat_enabled(True)
    d._client_repeat_delay_ms = lambda pkt: 0.0
    handler = TextMessageHandler(
        local_identity=identity,
        contacts=_Contacts(peer_contacts),
        log_fn=lambda *a, **k: None,
        send_packet_fn=AsyncMock(return_value=True),
        event_service=None,
    )
    d.register_handler(PAYLOAD_TYPE_TXT_MSG, handler)
    return d, radio, identity


@pytest.mark.asyncio
async def test_real_handler_genuine_flood_message_not_forwarded():
    # A flood TXT genuinely encrypted for us decrypts (authenticated) -> marked
    # -> not re-flooded, matching firmware's data-packet markDoNotRetransmit.
    peer = LocalIdentity()
    d, radio, me = _make_dispatcher_with_text_handler([Contact(public_key=peer.get_public_key())])
    me_contact = Contact(public_key=me.get_public_key().hex())
    pkt, _crc = PacketBuilder.create_text_message(me_contact, peer, "hi", message_type="flood")
    await d._process_received_packet(pkt.write_to(), -70, 8.0)
    await _drain_tasks()
    assert radio.send_count == 0


@pytest.mark.asyncio
async def test_real_handler_colliding_flood_message_is_forwarded():
    # dest-hash byte collides with our hash but the payload is not decryptable
    # for any contact -> not authenticated -> not marked -> re-flooded.
    d, radio, me = _make_dispatcher_with_text_handler([])  # no contacts to match
    collide = Packet()
    collide.header = (PAYLOAD_TYPE_TXT_MSG << 2) | ROUTE_TYPE_FLOOD
    dest_byte = me.get_public_key()[0]
    collide.payload = bytearray([dest_byte, 0x99]) + bytearray(b"\xAA" * 12)
    collide.payload_len = len(collide.payload)
    await d._process_received_packet(collide.write_to(), -70, 8.0)
    await _drain_tasks()
    assert radio.send_count == 1


@pytest.mark.asyncio
async def test_own_advert_echo_is_deduped_not_reforwarded():
    # No own-advert special case: a foreign advert re-floods, and our own advert
    # heard back over RF is dropped by the seen-table (same hash), not forwarded
    # twice — proving the seen-table covers the own-advert route.
    d, radio = _make_dispatcher(enabled=True)
    d._client_repeat_delay_ms = lambda pkt: 0.0
    advert = Packet()
    advert.header = (PAYLOAD_TYPE_ADVERT << 2) | ROUTE_TYPE_FLOOD
    advert.payload = bytearray(SELF_KEY) + bytearray(b"\x00" * 8)
    advert.payload_len = len(advert.payload)
    data = advert.write_to()

    await d._process_received_packet(data, -70, 8.0)
    await _drain_tasks()
    assert radio.send_count == 1  # forwarded once (no advert handler marks it)

    # The echo of the same advert is a seen-table duplicate: not re-forwarded.
    await d._process_received_packet(radio.tx_data, -70, 8.0)
    await _drain_tasks()
    assert radio.send_count == 1
