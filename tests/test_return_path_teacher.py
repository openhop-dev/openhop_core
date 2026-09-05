"""Return-path teaching parity with MeshCore's BaseChatMesh::handleReturnPathRetry.

A MeshCore server answers a DIRECT request from the ``out_path`` stored in its
ACL, never by reversing the inbound path. A client that never teaches that route
leaves the server replying into a dead route, which is what breaks CLI/protocol
requests over a user-forced path: the login goes out DIRECT, so the server
answers with a plain flood RESPONSE rather than the flood PATH that normally
carries the reciprocal, and nothing else in the stack teaches the route back.
"""

import asyncio

import pytest

from openhop_core.companion.base_send import _SendOpsMixin
from openhop_core.companion.contact_store import ContactStore
from openhop_core.companion.models import Contact
from openhop_core.node.handlers.login_response import LoginResponseHandler
from openhop_core.node.handlers.protocol_response import ProtocolResponseHandler
from openhop_core.node.handlers.registry import create_core_handlers
from openhop_core.node.handlers.return_path import ReturnPathTeacher
from openhop_core.protocol import CryptoUtils, Identity, LocalIdentity, Packet
from openhop_core.protocol.constants import (
    PAYLOAD_TYPE_PATH,
    PAYLOAD_TYPE_RESPONSE,
    ROUTE_TYPE_DIRECT,
    ROUTE_TYPE_FLOOD,
)
from openhop_core.protocol.packet_utils import PathUtils

LOCAL_IDENTITY = LocalIdentity(bytes(32))
PEER = LocalIdentity(bytes([0x5A]) + bytes(31))
PEER_HASH = PEER.get_public_key()[0]
PEER_KEY = PEER.get_public_key()

# Route from us to the peer (what a user's "force path" sets).
OUT_PATH = bytes([0xAA, 0xBB])
OUT_PATH_LEN = PathUtils.encode_path_len(1, 2)

# Route the peer's flood reply accumulated on its way back to us. Deliberately
# different from OUT_PATH so a test can tell the embedded path (peer -> us) from
# the routing path (us -> peer); swapping the two is the classic failure here.
IN_PATH = bytes([0xCC, 0xDD])
IN_PATH_LEN = PathUtils.encode_path_len(1, 2)


def _shared_secret():
    return Identity(PEER_KEY).calc_shared_secret(LOCAL_IDENTITY.get_private_key())


def _contacts(out_path=OUT_PATH, out_path_len=OUT_PATH_LEN):
    contacts = ContactStore()
    contact = Contact(public_key=PEER_KEY, name="FarRepeater")
    contact.out_path = out_path
    contact.out_path_len = out_path_len
    contacts.add(contact)
    return contacts


def _response_packet(*, flood: bool, in_path=IN_PATH, in_path_len=IN_PATH_LEN, tag=0x11223344):
    """A PAYLOAD_TYPE_RESPONSE from PEER addressed to us."""
    secret = _shared_secret()
    plaintext = tag.to_bytes(4, "little") + b"ok"
    packet = Packet()
    packet.header = (PAYLOAD_TYPE_RESPONSE << 2) | (
        ROUTE_TYPE_FLOOD if flood else ROUTE_TYPE_DIRECT
    )
    packet.path = bytearray(in_path) if flood else bytearray()
    packet.path_len = in_path_len if flood else 0
    packet.payload = bytearray(
        bytes([LOCAL_IDENTITY.get_public_key()[0], PEER_HASH])
        + CryptoUtils.encrypt_then_mac(secret[:16], secret, plaintext)
    )
    packet.payload_len = len(packet.payload)
    return packet


def _decode_teach(packet: Packet):
    """Return (embedded_path_len_byte, embedded_path) from a teach packet."""
    secret = _shared_secret()
    plaintext = CryptoUtils.mac_then_decrypt(secret[:16], secret, bytes(packet.payload[2:]))
    assert plaintext, "teach packet did not authenticate against the peer secret"
    path_len_byte = plaintext[0]
    byte_len = PathUtils.get_path_byte_len(path_len_byte)
    return path_len_byte, bytes(plaintext[1 : 1 + byte_len])


class _Injector:
    """Captures injected packets; can be made to fail or to block.

    ``slow=True`` models a real transmit path (TX lock, airtime budget, on-air
    time) so tests can observe behaviour across the injector's await point.
    """

    def __init__(self, fail=False, slow=False):
        self.packets = []
        self.fail = fail
        self._gate = asyncio.Event() if slow else None

    def release(self) -> None:
        if self._gate is not None:
            self._gate.set()

    async def __call__(self, packet, *args, **kwargs):
        if self._gate is not None:
            await asyncio.sleep(0)  # let concurrent callers all reach here
            if not self._gate.is_set():
                await asyncio.wait_for(self._gate.wait(), timeout=2.0)
        if self.fail:
            raise RuntimeError("radio down")
        self.packets.append(packet)
        return True


def _teacher(contacts=None, injector=None, **kwargs):
    # Default the settle window off so tests do not sleep; the settle behaviour
    # itself is covered explicitly by overriding _settle.
    kwargs.setdefault("settle_s", 0.0)
    teacher = ReturnPathTeacher(
        lambda _m: None, LOCAL_IDENTITY, contacts if contacts is not None else _contacts(), **kwargs
    )
    teacher.set_injector(injector if injector is not None else _Injector())
    return teacher


def _copy_of(pkt: Packet, *, in_path: bytes, rssi: int, len_byte: int = None) -> Packet:
    """Another flood copy of the SAME reply: identical payload (hence identical
    packet hash), differing only in the accumulated path and last-hop RSSI —
    exactly how one flooded reply reaches us over several routes. ``len_byte``
    overrides the path_len encoding when the copy has a different hop count."""
    copy = Packet()
    copy.header = pkt.header
    copy.path = bytearray(in_path)
    copy.path_len = pkt.path_len if len_byte is None else len_byte
    copy.payload = bytearray(pkt.payload)
    copy.payload_len = pkt.payload_len
    copy._rssi = rssi
    return copy


# Two-byte-hash routes of differing length, sharing no bytes so a test can tell
# which one was taught. SHORT is 2 hops, LONG is that route plus a strong final
# hop (the "desk repeater adds a hop" case).
# encode_path_len(hash_size, hash_count): both routes use 2-byte hashes.
SHORT_2HOP = bytes([0x11, 0x22, 0x33, 0x44])
SHORT_2HOP_LEN = PathUtils.encode_path_len(2, 2)  # 2 hops
LONG_3HOP = bytes([0x11, 0x22, 0x33, 0x44, 0xEC, 0xF4])
LONG_3HOP_LEN = PathUtils.encode_path_len(2, 3)  # 3 hops


async def _teach_flood(teacher, **kwargs):
    """Trigger a flood-reply teach and wait for it to reach the injector."""
    sent = await teacher.maybe_teach_from_flood_reply(
        _response_packet(flood=True, **kwargs), PEER_KEY, PEER_HASH, reason="test"
    )
    await teacher.wait_for_pending()
    return sent


# --------------------------------------------------------------------------- #
# Flood-reply trigger (firmware parity)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_flood_reply_teaches_inbound_path_routed_via_out_path():
    """The teach embeds the peer->us path and is routed along the us->peer path."""
    injector = _Injector()
    teacher = _teacher(injector=injector)

    assert await _teach_flood(teacher) is True
    assert len(injector.packets) == 1
    teach = injector.packets[0]

    # Shape: a PATH packet sent DIRECT (firmware sendDirect of createPathReturn).
    assert teach.get_payload_type() == PAYLOAD_TYPE_PATH
    assert teach.get_route_type() == ROUTE_TYPE_DIRECT
    # Routed along OUR out_path so it actually reaches the peer.
    assert bytes(teach.path) == OUT_PATH
    assert teach.path_len == OUT_PATH_LEN
    # Addressed to the peer, from us.
    assert teach.payload[0] == PEER_HASH
    assert teach.payload[1] == LOCAL_IDENTITY.get_public_key()[0]
    # Embedded: the route the peer should use to reach us == the inbound path.
    embedded_len, embedded_path = _decode_teach(teach)
    assert embedded_path == IN_PATH
    assert embedded_len == IN_PATH_LEN


@pytest.mark.asyncio
async def test_flood_reply_teach_preserves_two_byte_hash_encoding():
    """path_len encodes hash_size in bits 6-7; a 2-byte-hash route must survive
    both the embedded payload and the outer routing path intact."""
    out_path = bytes([0x11, 0x22, 0x33, 0x44])
    out_len = PathUtils.encode_path_len(2, 2)
    in_path = bytes([0xA1, 0xA2, 0xB1, 0xB2])
    in_len = PathUtils.encode_path_len(2, 2)

    injector = _Injector()
    teacher = _teacher(contacts=_contacts(out_path, out_len), injector=injector)

    assert await _teach_flood(teacher, in_path=in_path, in_path_len=in_len) is True
    teach = injector.packets[0]
    assert bytes(teach.path) == out_path
    assert teach.path_len == out_len
    embedded_len, embedded_path = _decode_teach(teach)
    assert embedded_path == in_path
    assert embedded_len == in_len
    assert PathUtils.get_path_hash_size(embedded_len) == 2


@pytest.mark.asyncio
async def test_direct_reply_does_not_teach():
    """Only a flood reply signals the peer has no route back (firmware guard)."""
    injector = _Injector()
    teacher = _teacher(injector=injector)

    sent = await teacher.maybe_teach_from_flood_reply(
        _response_packet(flood=False), PEER_KEY, PEER_HASH, reason="test"
    )
    await teacher.wait_for_pending()

    assert sent is False
    assert injector.packets == []


@pytest.mark.asyncio
async def test_unknown_out_path_does_not_teach():
    """OUT_PATH_UNKNOWN (-1): flood replies are expected, and we have no route
    to send a direct teach down anyway."""
    injector = _Injector()
    teacher = _teacher(contacts=_contacts(out_path=b"", out_path_len=-1), injector=injector)

    assert await _teach_flood(teacher) is False
    assert injector.packets == []


@pytest.mark.asyncio
async def test_zero_hop_out_path_is_known_and_teaches():
    """out_path_len == 0 is a known zero-hop route, NOT unknown. Truth-testing
    the value instead of range-checking it would silently skip direct
    neighbours."""
    injector = _Injector()
    teacher = _teacher(contacts=_contacts(out_path=b"", out_path_len=0), injector=injector)

    assert await _teach_flood(teacher) is True
    assert bytes(injector.packets[0].path) == b""


@pytest.mark.asyncio
async def test_out_path_shorter_than_declared_length_is_rejected():
    """A truncated stored path must not be transmitted as a routing path."""
    injector = _Injector()
    teacher = _teacher(
        contacts=_contacts(out_path=bytes([0xAA]), out_path_len=PathUtils.encode_path_len(1, 3)),
        injector=injector,
    )
    assert await _teach_flood(teacher) is False
    assert injector.packets == []


@pytest.mark.asyncio
async def test_no_injector_is_a_no_op():
    teacher = ReturnPathTeacher(lambda _m: None, LOCAL_IDENTITY, _contacts())
    assert teacher.enabled is False
    assert await _teach_flood(teacher) is False


# --------------------------------------------------------------------------- #
# Best-copy selection by last-hop RSSI (openHop, no firmware equivalent)
# --------------------------------------------------------------------------- #

# A second route the same reply can arrive on, distinct from IN_PATH so a test
# can tell which copy was taught. 2-byte hash, one hop — matches IN_PATH_LEN.
STRONG_PATH = bytes([0xEE, 0xFF])


@pytest.mark.asyncio
async def test_teaches_from_best_rssi_copy_not_the_first_arrived():
    """The bug this fixes: dedup hands the handler the first-arrived copy, which
    on a real mesh is often the weakest route. A stronger copy seen pre-dedup by
    note_flood_copy must win."""
    injector = _Injector()
    teacher = _teacher(injector=injector)

    base = _response_packet(flood=True, in_path=IN_PATH)
    strong = _copy_of(base, in_path=STRONG_PATH, rssi=-20)
    weak = _copy_of(base, in_path=IN_PATH, rssi=-100)

    # The strong copy arrives (pre-dedup) before the weak one triggers the teach.
    teacher.note_flood_copy(strong)
    assert await teacher.maybe_teach_from_flood_reply(weak, PEER_KEY, PEER_HASH, reason="test")
    await teacher.wait_for_pending()

    assert len(injector.packets) == 1
    _, embedded = _decode_teach(injector.packets[0])
    assert embedded == STRONG_PATH, "taught the marginal first-arrived route, not the best one"


@pytest.mark.asyncio
async def test_first_copy_wins_when_no_better_copy_is_seen():
    """With nothing better recorded, the teach falls back to the triggering
    (first-arrived) copy — preserving behaviour where no subscriber is wired."""
    injector = _Injector()
    teacher = _teacher(injector=injector)

    assert await _teach_flood(teacher) is True
    _, embedded = _decode_teach(injector.packets[0])
    assert embedded == IN_PATH


@pytest.mark.asyncio
async def test_settle_window_lets_a_later_stronger_copy_win():
    """Firmware's sendDirect(...,3000) is a settle window; a stronger copy that
    lands during it must be the one taught."""
    injector = _Injector()
    teacher = _teacher(injector=injector)

    base = _response_packet(flood=True, in_path=IN_PATH)
    weak = _copy_of(base, in_path=IN_PATH, rssi=-100)
    strong = _copy_of(base, in_path=STRONG_PATH, rssi=-20)

    async def fake_settle(_seconds):
        # A stronger copy arrives while we are holding for the settle window.
        teacher.note_flood_copy(strong)

    teacher._settle_s = 3.0
    teacher._settle = fake_settle

    assert await teacher.maybe_teach_from_flood_reply(weak, PEER_KEY, PEER_HASH, reason="t")
    await teacher.wait_for_pending()

    _, embedded = _decode_teach(injector.packets[0])
    assert embedded == STRONG_PATH


@pytest.mark.asyncio
async def test_note_flood_copy_ignores_direct_and_misaddressed_and_nonresponse():
    injector = _Injector()
    teacher = _teacher(injector=injector)

    direct = _response_packet(flood=False)
    direct._rssi = -10
    teacher.note_flood_copy(direct)  # direct is never a teach trigger

    other = _response_packet(flood=True, in_path=STRONG_PATH)
    other.payload[0] = (LOCAL_IDENTITY.get_public_key()[0] + 1) & 0xFF  # addressed elsewhere
    other._rssi = -10
    teacher.note_flood_copy(other)

    assert not teacher._recent_copies


def test_note_flood_copy_is_a_noop_without_injector():
    teacher = ReturnPathTeacher(lambda _m: None, LOCAL_IDENTITY, _contacts(), settle_s=0.0)
    pkt = _response_packet(flood=True)
    pkt._rssi = -10
    teacher.note_flood_copy(pkt)
    assert not teacher._recent_copies


def test_recorded_copies_are_pruned_by_ttl():
    clock = {"t": 0.0}
    teacher = _teacher(time_fn=lambda: clock["t"])
    teacher._copy_ttl_s = 8.0

    a = _response_packet(flood=True, in_path=IN_PATH)
    teacher.note_flood_copy(_copy_of(a, in_path=IN_PATH, rssi=-40))
    assert len(teacher._recent_copies) == 1

    clock["t"] += 100.0  # well past the TTL
    b = _response_packet(flood=True, in_path=STRONG_PATH)
    teacher.note_flood_copy(_copy_of(b, in_path=STRONG_PATH, rssi=-40))
    assert len(teacher._recent_copies) == 1  # the stale entry was dropped


# --------------------------------------------------------------------------- #
# Copy selection by decodability margin, then hop count
#
# LoRa decodes on SNR margin over the demodulator limit, not on absolute RSSI:
# measured here, four copies of one reply spanned 86 dB of RSSI while all
# reported ~+11.5 dB SNR, i.e. all equally decodable. So dB only decide inside
# the waterfall; above it, hop count does.
# --------------------------------------------------------------------------- #


async def _teach_choosing_between(teacher, short_rssi, long_rssi):
    """Record a 2-hop and a 3-hop copy of one reply, trigger the teach, and
    return the embedded path the teacher chose."""
    injector = teacher._injector
    base = _response_packet(flood=True)
    teacher.note_flood_copy(
        _copy_of(base, in_path=SHORT_2HOP, rssi=short_rssi, len_byte=SHORT_2HOP_LEN)
    )
    teacher.note_flood_copy(
        _copy_of(base, in_path=LONG_3HOP, rssi=long_rssi, len_byte=LONG_3HOP_LEN)
    )
    # Trigger with a weak first-arrived copy; selection must come from the table.
    trigger = _copy_of(base, in_path=SHORT_2HOP, rssi=-120, len_byte=SHORT_2HOP_LEN)
    assert await teacher.maybe_teach_from_flood_reply(trigger, PEER_KEY, PEER_HASH, reason="t")
    await teacher.wait_for_pending()
    _, embedded = _decode_teach(injector.packets[-1])
    return embedded


@pytest.mark.asyncio
async def test_shorter_route_wins_when_extra_hop_buys_little_signal():
    """The ECF4-on-the-desk case: a 3-hop copy at -13 must NOT beat a 2-hop copy
    at -15 — 2 dB is not worth an extra hop (10 dB/hop default)."""
    teacher = _teacher(injector=_Injector())
    embedded = await _teach_choosing_between(teacher, short_rssi=-15, long_rssi=-13)
    assert embedded == SHORT_2HOP


@pytest.mark.asyncio
async def test_zero_hop_copy_beats_materially_stronger_one_hop_copy():
    """A healthy direct route must not be replaced by a nearby relay.

    Captured regression: HOWL Repeater's flood reply arrived zero-hop at
    -46 dBm, then through B5B5 at -12 dBm. The routed-dependency plus per-hop
    penalties preserve the direct route.
    """
    injector = _Injector()
    teacher = _teacher(injector=injector)
    direct_len = PathUtils.encode_path_len(2, 0)
    relayed_len = PathUtils.encode_path_len(2, 1)
    base = _response_packet(flood=True)
    direct = _copy_of(base, in_path=b"", rssi=-46, len_byte=direct_len)
    relayed = _copy_of(base, in_path=b"\xb5\xb5", rssi=-12, len_byte=relayed_len)

    async def fake_settle(_seconds):
        teacher.note_flood_copy(relayed)

    teacher._settle_s = 3.0
    teacher._settle = fake_settle

    assert await teacher.maybe_teach_from_flood_reply(direct, PEER_KEY, PEER_HASH, reason="test")
    await teacher.wait_for_pending()

    embedded_len, embedded = _decode_teach(injector.packets[-1])
    assert embedded_len == direct_len
    assert embedded == b""


@pytest.mark.asyncio
async def test_materially_stronger_one_hop_copy_beats_tenuous_zero_hop_copy():
    """The direct preference is finite, not an absolute zero-hop rule.

    A direct copy near -120 dBm is tenuous enough that a one-hop copy at
    -60 dBm pays both routing penalties and still wins.
    """
    injector = _Injector()
    teacher = _teacher(injector=injector)
    direct_len = PathUtils.encode_path_len(2, 0)
    relayed_len = PathUtils.encode_path_len(2, 1)
    base = _response_packet(flood=True)
    direct = _copy_of(base, in_path=b"", rssi=-120, len_byte=direct_len)
    relayed = _copy_of(base, in_path=b"\xb5\xb5", rssi=-60, len_byte=relayed_len)

    async def fake_settle(_seconds):
        teacher.note_flood_copy(relayed)

    teacher._settle_s = 3.0
    teacher._settle = fake_settle

    assert await teacher.maybe_teach_from_flood_reply(direct, PEER_KEY, PEER_HASH, reason="test")
    await teacher.wait_for_pending()

    embedded_len, embedded = _decode_teach(injector.packets[-1])
    assert embedded_len == relayed_len
    assert embedded == b"\xb5\xb5"


@pytest.mark.asyncio
async def test_longer_route_wins_only_when_the_shorter_one_is_marginal():
    """A hop is bought when the short route is inside the waterfall, not merely
    when the long route reads stronger.

    -60 dBm is ~55 dB above this mesh's decode threshold, so under the threshold
    model the 2-hop copy is reliable and hop count decides. Only when the shorter
    copy drops into the steep region does the extra hop earn its place.
    """
    teacher = _teacher(injector=_Injector())
    # Both reliable: fewest hops wins even though the 3-hop copy is 47 dB stronger.
    embedded = await _teach_choosing_between(teacher, short_rssi=-60, long_rssi=-13)
    assert embedded == SHORT_2HOP

    # Now the 2-hop copy is marginal (-114 dBm is ~1.5 dB of margin against the
    # assumed -108 floor at SF7), so the reliable 3-hop copy takes over.
    teacher2 = _teacher(injector=_Injector())
    embedded = await _teach_choosing_between(teacher2, short_rssi=-114, long_rssi=-13)
    assert embedded == LONG_3HOP


@pytest.mark.asyncio
async def test_extra_db_above_the_waterfall_never_buys_a_hop():
    """Two reliable copies: no RSSI gap, however large, promotes the longer one."""
    for long_rssi in (-13, -5, 0):
        teacher = _teacher(injector=_Injector())
        embedded = await _teach_choosing_between(teacher, short_rssi=-70, long_rssi=long_rssi)
        assert embedded == SHORT_2HOP, f"a {long_rssi} dBm 3-hop copy displaced a healthy 2-hop"


def test_copy_below_the_demod_floor_is_not_recorded_at_all():
    """Below the waterfall a copy is not a route, so it is not a candidate.

    At SF7 the demodulator limit is -7.5 dB SNR; against the assumed -108 dBm
    floor that puts the decode threshold near -115.5 dBm.
    """
    teacher = _teacher()
    base = _response_packet(flood=True)
    teacher.note_flood_copy(_copy_of(base, in_path=SHORT_2HOP, rssi=-120, len_byte=SHORT_2HOP_LEN))
    assert teacher._recent_copies == {}

    teacher.note_flood_copy(_copy_of(base, in_path=SHORT_2HOP, rssi=-100, len_byte=SHORT_2HOP_LEN))
    assert len(teacher._recent_copies) == 1


def test_margin_uses_snr_when_it_is_the_pessimistic_estimate():
    """SNR is the real decodability measure; RSSI is the fallback.

    A copy can look strong in RSSI while its SNR says it is barely decodable
    (a loud interferer raises both). The pessimistic estimate must win, so such a
    copy is not treated as reliable.
    """
    teacher = _teacher()
    limit = teacher._demod_limit_db()  # -7.5 at SF7

    strong_rssi_bad_snr = teacher._copy_margin_db(rssi=-20, snr=limit + 1.0)
    assert strong_rssi_bad_snr == pytest.approx(1.0)  # SNR binds, not the -20 dBm

    weak_rssi_good_snr = teacher._copy_margin_db(rssi=-120, snr=limit + 20.0)
    assert weak_rssi_good_snr < 0  # RSSI binds


def test_margin_tracks_the_spreading_factor():
    """The same signal is more decodable at a higher SF, so the limit must follow
    the radio rather than being baked in."""
    sf = {"v": 7}
    teacher = _teacher(sf_getter=lambda: sf["v"])
    assert teacher._demod_limit_db() == pytest.approx(-7.5)

    at_sf7 = teacher._copy_margin_db(rssi=-40, snr=-6.0)
    sf["v"] = 12
    at_sf12 = teacher._copy_margin_db(rssi=-40, snr=-6.0)
    assert at_sf7 == pytest.approx(1.5)  # marginal at SF7
    assert at_sf12 == pytest.approx(14.0)  # comfortable at SF12
    assert at_sf12 > teacher._reliable_margin_db > at_sf7


def test_unknown_spreading_factor_falls_back_to_sf7():
    teacher = _teacher(sf_getter=lambda: 99)
    assert teacher._demod_limit_db() == pytest.approx(-7.5)
    broken = _teacher(sf_getter=lambda: (_ for _ in ()).throw(RuntimeError("no radio")))
    assert broken._demod_limit_db() == pytest.approx(-7.5)


# --------------------------------------------------------------------------- #
# Rate limiting and dispatch
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_cooldown_suppresses_immediate_second_teach():
    clock = {"t": 1000.0}
    injector = _Injector()
    teacher = _teacher(injector=injector, cooldown_s=5.0, time_fn=lambda: clock["t"])

    assert await _teach_flood(teacher) is True
    clock["t"] += 1.0
    assert await _teach_flood(teacher) is False
    clock["t"] += 5.0
    assert await _teach_flood(teacher) is True
    assert len(injector.packets) == 2


@pytest.mark.asyncio
async def test_concurrent_triggers_transmit_only_one_teach():
    """The cooldown is claimed synchronously, before anything is awaited, so two
    triggers racing across the injector's await point cannot both transmit."""
    injector = _Injector(slow=True)
    teacher = _teacher(injector=injector, cooldown_s=5.0)

    results = await asyncio.gather(
        *[
            teacher.maybe_teach_from_flood_reply(
                _response_packet(flood=True), PEER_KEY, PEER_HASH, reason="t"
            )
            for _ in range(3)
        ]
    )
    injector.release()
    await teacher.wait_for_pending()

    assert sum(1 for r in results if r) == 1
    assert len(injector.packets) == 1


@pytest.mark.asyncio
async def test_teach_does_not_block_on_the_injector():
    """Firmware queues this send; awaiting it inline would stall the RX path and
    delay the very reply that triggered the teach."""
    injector = _Injector(slow=True)
    teacher = _teacher(injector=injector)

    assert await teacher.maybe_teach_from_flood_reply(
        _response_packet(flood=True), PEER_KEY, PEER_HASH, reason="t"
    )
    # Returned while the injector is still blocked.
    assert injector.packets == []

    injector.release()
    await teacher.wait_for_pending()
    assert len(injector.packets) == 1


@pytest.mark.asyncio
async def test_failed_inject_releases_cooldown_for_the_next_trigger():
    """A teach that never made it onto the radio must be retried on the next
    trigger, not muted for the cooldown window."""
    clock = {"t": 0.0}
    teacher = _teacher(injector=_Injector(fail=True), cooldown_s=5.0, time_fn=lambda: clock["t"])

    await _teach_flood(teacher)

    working = _Injector()
    teacher.set_injector(working)
    assert await _teach_flood(teacher) is True
    assert len(working.packets) == 1


# --------------------------------------------------------------------------- #
# No guessing: only observed paths are ever taught
# --------------------------------------------------------------------------- #


def test_teacher_exposes_no_way_to_teach_an_unobserved_path():
    """The symmetry guess is gone, not merely unused.

    An earlier revision taught the reverse of our own out_path on a request
    timeout. Real routes are frequently asymmetric, and onPeerPathRecv overwrites
    client->out_path unconditionally, so a wrong guess replaced a working route
    with a dead one and the peer then answered DIRECT into a void — with no flood
    reply left to correct it. The timeout case is handled by flooding the retry
    (_SendOpsMixin._build_retry_packet) so a real inbound path can be observed.
    """
    teacher = _teacher()
    assert not hasattr(teacher, "maybe_teach_reverse_of_out_path")
    # The only public teach trigger takes a received packet to learn from.
    assert hasattr(teacher, "maybe_teach_from_flood_reply")


@pytest.mark.asyncio
async def test_note_evidence_teach_claims_the_cooldown():
    """Another handler's teach suppresses an immediate duplicate from this one."""
    clock = {"t": 1000.0}
    injector = _Injector()
    teacher = _teacher(injector=injector, cooldown_s=5.0, time_fn=lambda: clock["t"])

    teacher.note_evidence_teach(PEER_KEY)
    clock["t"] += 1.0
    assert await _teach_flood(teacher) is False
    assert injector.packets == []

    clock["t"] += 5.0
    assert await _teach_flood(teacher) is True
    assert len(injector.packets) == 1


def _flood_path_packet(inner_path=OUT_PATH, inner_len=OUT_PATH_LEN):
    """A flood PAYLOAD_TYPE_PATH carrying a RESPONSE — what a *flood* login gets.

    Inner layout: path_len(1) + path(N) + extra_type(1) + extra.
    """
    secret = _shared_secret()
    response = (0x11223344).to_bytes(4, "little") + b"ok"
    inner = bytes([inner_len]) + inner_path + bytes([PAYLOAD_TYPE_RESPONSE]) + response
    packet = Packet()
    packet.header = (PAYLOAD_TYPE_PATH << 2) | ROUTE_TYPE_FLOOD
    packet.path = bytearray(IN_PATH)
    packet.path_len = IN_PATH_LEN
    packet.payload = bytearray(
        bytes([LOCAL_IDENTITY.get_public_key()[0], PEER_HASH])
        + CryptoUtils.encrypt_then_mac(secret[:16], secret, inner)
    )
    packet.payload_len = len(packet.payload)
    return packet


@pytest.mark.asyncio
async def test_flood_path_reciprocal_reports_itself_to_the_teacher():
    """End-to-end: the flood-PATH reciprocal teaches from a real inbound path and
    reports itself, so the teacher does not immediately send a second teach for
    the same contact and route."""
    injector = _Injector()
    handler = ProtocolResponseHandler(lambda _m: None, LOCAL_IDENTITY, _contacts())
    handler.set_packet_injector(injector)
    # No settle: the corrective re-teach has its own tests below.
    handler.return_path_teacher._settle_s = 0.0

    await handler(_flood_path_packet())
    await handler.wait_for_pending_reciprocals()
    await handler.return_path_teacher.wait_for_pending()

    # Exactly one packet: the reciprocal. The RESPONSE-branch teach must not
    # also fire for a PATH packet, and with no better copy recorded the
    # corrective re-teach must transmit nothing.
    assert len(injector.packets) == 1
    assert PEER_KEY in handler.return_path_teacher._last_taught

    # A flood RESPONSE arriving inside the cooldown is not re-taught.
    assert await _teach_flood(handler.return_path_teacher) is False
    assert len(injector.packets) == 1


# --------------------------------------------------------------------------- #
# Correcting a teach sent from the first-arrived copy
# --------------------------------------------------------------------------- #


def _reteach_kwargs(pkt, *, taught_path, taught_len_byte, hash_key=None):
    return dict(
        contact_pubkey=PEER_KEY,
        dest_hash=PEER_HASH,
        taught_path=taught_path,
        taught_len_byte=taught_len_byte,
        out_path=OUT_PATH,
        out_path_len=OUT_PATH_LEN,
        shared_secret=_shared_secret(),
        hash_key=hash_key if hash_key is not None else bytes(pkt.calculate_packet_hash()),
        reason="test",
    )


@pytest.mark.asyncio
async def test_note_flood_copy_now_records_flood_path_copies():
    """A flood login is answered with a PATH, so PATH copies must be collected.

    Before this, only RESPONSE copies were recorded, so the single most
    consequential teach — the reciprocal after a flood login, which decides the
    route the peer uses for every later direct reply — had no copies to choose
    from and always embedded the first-arrived route.
    """
    teacher = _teacher()
    first = _flood_path_packet()
    first._rssi = -100
    better = _copy_of(first, in_path=SHORT_2HOP, rssi=-40, len_byte=SHORT_2HOP_LEN)

    teacher.note_flood_copy(first)
    teacher.note_flood_copy(better)

    assert len(teacher._recent_copies) == 1
    kept = next(iter(teacher._recent_copies.values()))
    assert kept.path == SHORT_2HOP
    assert kept.rssi == -40


@pytest.mark.asyncio
async def test_reteach_sends_the_better_copy_and_keeps_routing_via_out_path():
    injector = _Injector()
    teacher = _teacher(injector=injector)
    pkt = _flood_path_packet()
    pkt._rssi = -100
    teacher.note_flood_copy(pkt)
    teacher.note_flood_copy(_copy_of(pkt, in_path=SHORT_2HOP, rssi=-40, len_byte=SHORT_2HOP_LEN))

    sent = await teacher.maybe_reteach_better_copy(
        **_reteach_kwargs(pkt, taught_path=IN_PATH, taught_len_byte=IN_PATH_LEN)
    )

    assert sent is True
    assert len(injector.packets) == 1
    teach = injector.packets[0]
    assert teach.get_payload_type() == PAYLOAD_TYPE_PATH
    assert teach.get_route_type() == ROUTE_TYPE_DIRECT
    # Still routed along OUR out_path; only the embedded route changed.
    assert bytes(teach.path) == OUT_PATH
    len_byte, embedded = _decode_teach(teach)
    assert embedded == SHORT_2HOP
    assert len_byte == SHORT_2HOP_LEN


@pytest.mark.asyncio
async def test_reteach_is_silent_when_the_first_copy_was_already_best():
    """The common case must cost no airtime at all."""
    injector = _Injector()
    teacher = _teacher(injector=injector)
    pkt = _flood_path_packet()
    pkt._rssi = -40
    teacher.note_flood_copy(pkt)
    teacher.note_flood_copy(_copy_of(pkt, in_path=LONG_3HOP, rssi=-95, len_byte=LONG_3HOP_LEN))

    sent = await teacher.maybe_reteach_better_copy(
        **_reteach_kwargs(pkt, taught_path=IN_PATH, taught_len_byte=IN_PATH_LEN)
    )

    assert sent is False
    assert injector.packets == []


@pytest.mark.asyncio
async def test_reteach_is_silent_when_no_copies_were_collected():
    injector = _Injector()
    teacher = _teacher(injector=injector)
    pkt = _flood_path_packet()

    sent = await teacher.maybe_reteach_better_copy(
        **_reteach_kwargs(pkt, taught_path=IN_PATH, taught_len_byte=IN_PATH_LEN)
    )

    assert sent is False
    assert injector.packets == []


@pytest.mark.asyncio
async def test_reteach_ignores_the_cooldown_claimed_by_the_teach_it_corrects():
    """It corrects a teach that just claimed the cooldown, so it must not be
    throttled by it — otherwise the peer keeps the marginal first route."""
    clock = {"t": 1000.0}
    injector = _Injector()
    teacher = _teacher(injector=injector, cooldown_s=5.0, time_fn=lambda: clock["t"])
    pkt = _flood_path_packet()
    pkt._rssi = -100
    teacher.note_flood_copy(pkt)
    teacher.note_flood_copy(_copy_of(pkt, in_path=SHORT_2HOP, rssi=-40, len_byte=SHORT_2HOP_LEN))

    teacher.note_evidence_teach(PEER_KEY)  # the immediate reciprocal claims it
    clock["t"] += 0.5

    sent = await teacher.maybe_reteach_better_copy(
        **_reteach_kwargs(pkt, taught_path=IN_PATH, taught_len_byte=IN_PATH_LEN)
    )

    assert sent is True
    assert len(injector.packets) == 1


@pytest.mark.asyncio
async def test_reciprocal_end_to_end_corrects_itself_to_the_best_copy():
    """The whole path: flood-PATH login reply -> immediate teach from the copy in
    hand -> corrective teach from the best copy collected pre-dedup."""
    injector = _Injector()
    handler = ProtocolResponseHandler(lambda _m: None, LOCAL_IDENTITY, _contacts())
    handler.set_packet_injector(injector)
    teacher = handler.return_path_teacher
    teacher._settle_s = 0.0

    first = _flood_path_packet()
    first._rssi = -100
    # A stronger, shorter copy of the same reply lands pre-dedup (raw subscriber).
    teacher.note_flood_copy(first)
    teacher.note_flood_copy(_copy_of(first, in_path=SHORT_2HOP, rssi=-40, len_byte=SHORT_2HOP_LEN))

    await handler(first)
    await handler.wait_for_pending_reciprocals()
    await teacher.wait_for_pending()

    assert len(injector.packets) == 2, "expected the immediate teach plus one correction"
    _, first_taught = _decode_teach(injector.packets[0])
    _, corrected = _decode_teach(injector.packets[1])
    assert first_taught == bytes(first.path)  # the copy in hand
    assert corrected == SHORT_2HOP  # the best copy collected


# --------------------------------------------------------------------------- #
# End-to-end through the handlers
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_protocol_response_handler_teaches_on_flood_response():
    injector = _Injector()
    handler = ProtocolResponseHandler(lambda _m: None, LOCAL_IDENTITY, _contacts())
    handler.set_packet_injector(injector)
    handler.return_path_teacher._settle_s = 0.0  # don't sleep the real settle window

    await handler(_response_packet(flood=True))
    await handler.return_path_teacher.wait_for_pending()

    assert len(injector.packets) == 1
    assert injector.packets[0].get_payload_type() == PAYLOAD_TYPE_PATH
    _, embedded_path = _decode_teach(injector.packets[0])
    assert embedded_path == IN_PATH


@pytest.mark.asyncio
async def test_protocol_response_handler_does_not_teach_on_direct_response():
    injector = _Injector()
    handler = ProtocolResponseHandler(lambda _m: None, LOCAL_IDENTITY, _contacts())
    handler.set_packet_injector(injector)

    await handler(_response_packet(flood=False))
    await handler.return_path_teacher.wait_for_pending()

    assert injector.packets == []


def _login_reply_packet(flood=True):
    """Firmware handleLoginReq reply_data: timestamp(4) + RESP_SERVER_LOGIN_OK +
    keep_alive + is_admin + permissions + random(4) + firmware_ver_level."""
    login_reply = (
        (0x01020304).to_bytes(4, "little") + bytes([0x80, 0x00, 0x01, 0x03]) + b"\x00" * 4 + b"\x05"
    )
    secret = _shared_secret()
    packet = Packet()
    packet.header = (PAYLOAD_TYPE_RESPONSE << 2) | (
        ROUTE_TYPE_FLOOD if flood else ROUTE_TYPE_DIRECT
    )
    packet.path = bytearray(IN_PATH) if flood else bytearray()
    packet.path_len = IN_PATH_LEN if flood else 0
    packet.payload = bytearray(
        bytes([LOCAL_IDENTITY.get_public_key()[0], PEER_HASH])
        + CryptoUtils.encrypt_then_mac(secret[:16], secret, login_reply)
    )
    packet.payload_len = len(packet.payload)
    return packet


@pytest.mark.asyncio
async def test_login_response_handler_teaches_on_flood_login_response():
    """The forced-path regression: a DIRECT login is answered with a flood
    RESPONSE, and that is the only chance to teach before the first CLI REQ."""
    injector = _Injector()
    handler = LoginResponseHandler(LOCAL_IDENTITY, _contacts(), lambda _m: None)
    handler.set_packet_injector(injector)
    handler.return_path_teacher._settle_s = 0.0  # don't sleep the real settle window

    completions = []
    handler.register_login_callback(PEER_KEY, lambda success, data: completions.append(success))

    await handler(_login_reply_packet())
    await handler.return_path_teacher.wait_for_pending()

    assert completions == [True], "login response should still be delivered"
    assert len(injector.packets) == 1
    _, embedded_path = _decode_teach(injector.packets[0])
    assert embedded_path == IN_PATH


# --------------------------------------------------------------------------- #
# Wiring
# --------------------------------------------------------------------------- #


def _core(contacts=None):
    return create_core_handlers(
        identity=LOCAL_IDENTITY,
        contacts=contacts if contacts is not None else _contacts(),
        channels=None,
        event_service=None,
        send_packet_fn=lambda *a, **k: None,
        log_fn=lambda _m: None,
        node_name="test",
    )


def test_factory_shares_one_teacher_between_response_handlers():
    """A shared instance keeps the per-contact cooldown and the evidence guard
    honest — two handlers each with their own teacher would double the transmit
    rate and lose the guard."""
    core = _core()
    assert core.protocol_response_handler.return_path_teacher is core.return_path_teacher
    assert core.login_response_handler.return_path_teacher is core.return_path_teacher


def test_set_packet_injector_also_wires_the_teacher():
    """Existing companion wiring calls only set_packet_injector; the teacher has
    to pick the transmit path up from there or it silently never fires."""
    core = _core()
    assert core.return_path_teacher.enabled is False
    core.protocol_response_handler.set_packet_injector(_Injector())
    assert core.return_path_teacher.enabled is True
    assert core.login_response_handler.return_path_teacher.enabled is True


def test_login_handler_can_wire_its_own_injector_standalone():
    handler = LoginResponseHandler(LOCAL_IDENTITY, _contacts(), lambda _m: None)
    assert handler.return_path_teacher.enabled is False
    handler.set_packet_injector(_Injector())
    assert handler.return_path_teacher.enabled is True


# --------------------------------------------------------------------------- #
# base_send retry: flood instead of guessing a return path
# --------------------------------------------------------------------------- #


class _Proxy:
    """Stand-in for ContactProxy: only the route fields matter here."""

    def __init__(self, out_path=OUT_PATH, out_path_len=OUT_PATH_LEN):
        self.out_path = out_path
        self.out_path_len = out_path_len


class _RetrySender(_SendOpsMixin):
    """Carrier for the retry loops with radio/timing stubbed out.

    ``_apply_flood_scope`` records rather than resolves: the region a request
    ends up with is the companion resolver's business, but *whether* the loop
    hands every attempt to it is this file's.
    """

    def __init__(self):
        self.sent = []
        self.scoped = []

    def _apply_flood_scope(self, pkt):
        self.scoped.append(pkt)

    def _apply_path_hash_mode(self, pkt):
        return None

    def _response_timeout_s(self, pkt, proxy):
        return 0.001

    async def _send_packet(self, pkt, wait_for_ack=False, expected_crc=None):
        self.sent.append(pkt)
        return True


def _req_builder(proxy):
    """Build a REQ the way PacketBuilder does: route chosen from out_path_len."""

    def _build():
        pkt = Packet()
        route = ROUTE_TYPE_DIRECT if proxy.out_path_len >= 0 else ROUTE_TYPE_FLOOD
        pkt.header = (PAYLOAD_TYPE_RESPONSE << 2) | route
        pkt.payload = bytearray(b"\x00" * 8)
        pkt.payload_len = 8
        if route == ROUTE_TYPE_DIRECT and proxy.out_path_len > 0:
            pkt.path = bytearray(proxy.out_path)
            pkt.path_len = proxy.out_path_len
        else:
            pkt.path = bytearray()
            pkt.path_len = 0
        return pkt, None

    return _build


async def _always_timeout(_timeout):
    return {"timeout": True}


def test_retry_packet_floods_a_contact_that_has_a_direct_path():
    """Mirrors firmware's own way of forcing one request to flood: mask
    out_path_len to OUT_PATH_UNKNOWN around the build, then restore it."""
    proxy = _Proxy()
    sender = _RetrySender()

    pkt, _tag = sender._build_retry_packet(_req_builder(proxy), proxy, "REQ")

    assert pkt.is_route_flood()
    assert bytes(pkt.path) == b""
    assert pkt.path_len == 0
    # The stored route is masked, never cleared: every other caller still sees it.
    assert proxy.out_path_len == OUT_PATH_LEN
    assert proxy.out_path == OUT_PATH


def test_forced_flood_retry_takes_the_nodes_flood_scope():
    """[fails pre-fix] The retry is scoped like any other flood send.

    Masking ``out_path_len`` is the whole of firmware's trick: ``sendRequest``
    then takes its ``sendFloodScoped(recipient, pkt)`` branch, which resolves the
    region exactly as every other companion flood does. The retry must therefore
    reach the send-time resolver un-marked, so the node's override (or, failing
    that, its default) lands on it. Marking it plain-flood instead strands the
    retry at hop 0 on any mesh running ``flood.max.unscoped = 0`` -- which is
    exactly the set of meshes that scope their traffic in the first place.
    """
    from openhop_core.node.dispatcher import Dispatcher
    from openhop_core.protocol.constants import ROUTE_TYPE_TRANSPORT_FLOOD
    from openhop_core.protocol.transport_keys import calc_transport_code, get_auto_key_for

    proxy = _Proxy()
    sender = _RetrySender()

    pkt, _tag = sender._build_retry_packet(_req_builder(proxy), proxy, "REQ")
    assert pkt.is_route_flood()
    assert getattr(pkt, "_flood_scope_applied", False) is False

    class _Radio:
        def set_rx_callback(self, cb):
            pass

    override_key = get_auto_key_for("#region-a")
    dispatcher = Dispatcher(_Radio())
    dispatcher.flood_transport_key = override_key
    dispatcher.default_flood_transport_key = get_auto_key_for("#region-b")
    dispatcher._apply_flood_scope(pkt)

    assert pkt.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD
    assert pkt.transport_codes[0] == calc_transport_code(override_key, pkt)


def test_retry_packet_restores_the_stored_path_when_the_builder_raises():
    proxy = _Proxy()
    sender = _RetrySender()

    def _boom():
        raise RuntimeError("builder exploded")

    with pytest.raises(RuntimeError):
        sender._build_retry_packet(_boom, proxy, "REQ")
    assert proxy.out_path_len == OUT_PATH_LEN


def test_retry_packet_leaves_an_already_flooding_contact_alone():
    proxy = _Proxy(out_path=b"", out_path_len=-1)
    sender = _RetrySender()

    pkt, _tag = sender._build_retry_packet(_req_builder(proxy), proxy, "REQ")

    assert pkt.is_route_flood()
    assert proxy.out_path_len == -1


def test_retry_packet_tolerates_a_proxy_that_cannot_be_masked():
    """A non-settable contact object must not break the retry."""

    class _Frozen:
        __slots__ = ("out_path", "out_path_len")

        def __init__(self):
            self.out_path = OUT_PATH
            self.out_path_len = OUT_PATH_LEN

    proxy = _Frozen()
    sender = _RetrySender()

    def _build():
        pkt = Packet()
        pkt.header = (PAYLOAD_TYPE_RESPONSE << 2) | ROUTE_TYPE_DIRECT
        pkt.payload = bytearray(b"\x00" * 8)
        pkt.payload_len = 8
        pkt.path = bytearray()
        pkt.path_len = 0
        return pkt, None

    pkt, _tag = sender._build_retry_packet(_build, proxy, "REQ")
    assert pkt is not None
    assert proxy.out_path_len == OUT_PATH_LEN


@pytest.mark.asyncio
async def test_request_retry_loop_floods_every_attempt_after_the_first():
    """Covers the wiring in _request_with_retries: the first attempt keeps the
    contact's route, every retry floods so a reply can be observed."""
    proxy = _Proxy()
    sender = _RetrySender()

    result = await sender._request_with_retries(
        _req_builder(proxy), _always_timeout, proxy, log_label="REQ"
    )

    assert result["timeout"] is True
    assert len(sender.sent) >= 2
    assert not sender.sent[0].is_route_flood(), "first attempt keeps the stored route"
    assert all(p.is_route_flood() for p in sender.sent[1:]), "every retry floods"
    assert proxy.out_path_len == OUT_PATH_LEN
    # Firmware sends every one of these through sendFloodScoped(recipient, pkt),
    # so every attempt -- retries included -- must reach the scope resolver.
    assert sender.scoped == sender.sent


@pytest.mark.asyncio
async def test_started_request_retry_loop_floods_every_retry():
    """Same coverage for the background continuation used by the frame-server
    API path (_finish_started_request), whose first attempt is already sent."""
    proxy = _Proxy()
    sender = _RetrySender()

    await sender._finish_started_request(
        _req_builder(proxy),
        _always_timeout,
        proxy,
        first_timeout_s=0.001,
        deadline=None,
        log_label="REQ",
        cleanup=None,
        response_tag_registered=None,
    )

    assert sender.sent, "the continuation must retry"
    assert all(p.is_route_flood() for p in sender.sent), "every retry floods"
    assert proxy.out_path_len == OUT_PATH_LEN
    assert sender.scoped == sender.sent
