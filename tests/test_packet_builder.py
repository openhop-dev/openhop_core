import pytest

from openhop_core import LocalIdentity
from openhop_core.protocol import CryptoUtils
from openhop_core.protocol.constants import (
    MAX_PACKET_PAYLOAD,
    MAX_TEXT_LEN,
    PAYLOAD_TYPE_ACK,
    PAYLOAD_TYPE_ADVERT,
    PAYLOAD_TYPE_ANON_REQ,
    PAYLOAD_TYPE_GRP_DATA,
    PAYLOAD_TYPE_PATH,
    PAYLOAD_TYPE_RAW_CUSTOM,
)
from openhop_core.protocol.identity import Identity
from openhop_core.protocol.packet import Packet
from openhop_core.protocol.packet_builder import PacketBuilder
from openhop_core.protocol.packet_utils import PathUtils


# PacketBuilder tests
def test_packet_builder_create_ack():
    """Test creating ACK packets."""
    identity = LocalIdentity()
    timestamp = 1234567890
    attempt = 1
    text = "test_ack"

    ack_packet = PacketBuilder.create_ack(identity.get_public_key(), timestamp, attempt, text)

    assert ack_packet is not None
    assert ack_packet.get_payload_type() == PAYLOAD_TYPE_ACK
    # Firmware-compatible ACKs are 6 bytes: 4-byte hash + ext-attempt + random byte
    assert len(ack_packet.payload) == 6


def test_calc_text_ack_hash_matches_firmware_layout():
    """calc_text_ack_hash[:4] == sha256(timestamp || flags || text || pubkey)[:4]."""
    import struct

    identity = LocalIdentity()
    pubkey = identity.get_public_key()
    timestamp = 1234567890
    flags_byte = 0x00  # TXT_TYPE_PLAIN, attempt 0
    text = b"hello world"

    frag1 = struct.pack("<I", timestamp) + bytes([flags_byte]) + text
    expected_hash4 = CryptoUtils.sha256(frag1 + pubkey)[:4]

    ack = PacketBuilder.calc_text_ack_hash(
        pubkey, timestamp, flags_byte, text, ext_attempt=2, randomize=False
    )
    assert len(ack) == 6
    assert ack[:4] == expected_hash4
    assert ack[4] == 2  # ext-attempt byte
    assert ack[5] == 0  # randomize=False → deterministic zero

    # Randomized output keeps the same first 5 bytes, only the 6th differs
    rand = PacketBuilder.calc_text_ack_hash(pubkey, timestamp, flags_byte, text, ext_attempt=2)
    assert rand[:5] == ack[:5]


def test_create_ack_from_bytes_wraps_raw_payload():
    """create_ack_from_bytes copies raw bytes into an ACK packet payload."""
    raw = bytes([0x78, 0x56, 0x34, 0x12, 0x00, 0xAB])
    pkt = PacketBuilder.create_ack_from_bytes(raw)
    assert pkt.get_payload_type() == PAYLOAD_TYPE_ACK
    assert bytes(pkt.payload) == raw
    # path-less by default
    assert pkt.path_len == 0


def test_create_ack_from_bytes_with_path():
    """create_ack_from_bytes routes the ACK along a given out_path."""
    raw = bytes([0x78, 0x56, 0x34, 0x12, 0x00, 0xAB])
    out_path = bytes([0x11, 0x22])
    out_path_len = PathUtils.encode_path_len(1, 2)
    pkt = PacketBuilder.create_ack_from_bytes(raw, path=out_path, path_len_encoded=out_path_len)
    assert pkt.get_payload_type() == PAYLOAD_TYPE_ACK
    assert bytes(pkt.payload) == raw
    assert bytes(pkt.path) == out_path
    assert pkt.path_len == out_path_len


def test_create_multi_ack_layout():
    """create_multi_ack mirrors firmware createMultiAck byte layout."""
    from openhop_core.protocol.constants import PAYLOAD_TYPE_MULTIPART

    ack = bytes([0x78, 0x56, 0x34, 0x12, 0x07, 0xAB])
    pkt = PacketBuilder.create_multi_ack(ack, remaining=1)
    assert pkt.get_payload_type() == PAYLOAD_TYPE_MULTIPART
    assert pkt.payload[0] == ((1 << 4) | PAYLOAD_TYPE_ACK)
    assert bytes(pkt.payload[1:]) == ack
    assert int.from_bytes(pkt.payload[1:5], "little") == 0x12345678

    # remaining counter occupies the upper nibble
    pkt3 = PacketBuilder.create_multi_ack(ack, remaining=3)
    assert pkt3.payload[0] == ((3 << 4) | PAYLOAD_TYPE_ACK)


def test_create_multi_ack_with_path():
    """create_multi_ack carries the routing path for direct forwarding."""
    ack = bytes([0x78, 0x56, 0x34, 0x12])
    out_path = bytes([0x11, 0x22])
    out_path_len = PathUtils.encode_path_len(1, 2)
    pkt = PacketBuilder.create_multi_ack(
        ack, remaining=1, path=out_path, path_len_encoded=out_path_len
    )
    assert bytes(pkt.path) == out_path
    assert pkt.path_len == out_path_len


def test_packet_builder_create_advert():
    """Test creating advertisement packets."""
    identity = LocalIdentity()
    advert_packet = PacketBuilder.create_advert(identity, "test_data", 1)

    assert advert_packet is not None
    assert advert_packet.get_payload_type() == PAYLOAD_TYPE_ADVERT


def test_packet_builder_create_self_advert():
    """Test creating self-advertisement packets."""
    identity = LocalIdentity()
    self_advert = PacketBuilder.create_self_advert(identity, "TestNode", 1)

    assert self_advert is not None
    assert self_advert.get_payload_type() == PAYLOAD_TYPE_ADVERT


def test_packet_builder_create_flood_advert():
    """Test creating flood advertisement packets."""
    identity = LocalIdentity()
    flood_advert = PacketBuilder.create_flood_advert(identity, "TestNode", 1)

    assert flood_advert is not None
    assert flood_advert.get_payload_type() == PAYLOAD_TYPE_ADVERT


def test_packet_builder_create_direct_advert():
    """Test creating direct advertisement packets."""
    identity = LocalIdentity()
    direct_advert = PacketBuilder.create_direct_advert(identity, "TestNode", 1)

    assert direct_advert is not None
    assert direct_advert.get_payload_type() == PAYLOAD_TYPE_ADVERT


def test_packet_builder_create_raw_data():
    """Test creating raw custom packets (PAYLOAD_TYPE_RAW_CUSTOM)."""
    data = b"\x01\x02\x03\x04"
    pkt = PacketBuilder.create_raw_data(data)
    assert pkt is not None
    assert pkt.get_payload_type() == PAYLOAD_TYPE_RAW_CUSTOM
    assert pkt.payload == bytearray(data)
    assert pkt.payload_len == len(data)
    assert pkt.path_len == 0
    assert pkt.path == bytearray()


def test_packet_builder_create_raw_data_too_large_raises():
    """Test create_raw_data raises when data exceeds MAX_PACKET_PAYLOAD."""
    import pytest

    data = bytes(MAX_PACKET_PAYLOAD + 1)
    with pytest.raises(ValueError, match="exceeds MAX_PACKET_PAYLOAD"):
        PacketBuilder.create_raw_data(data)


def test_packet_builder_create_path_return_encoded_path_len():
    """Inner payload first byte must be encoded path_len (hash size + hop count),
    not path byte count.

    With 2-byte hashes and 2 hops, path is 4 bytes. Encoded path_len = 0x42.
    Without path_len_encoded, first byte would be 4 (wrong: decoded as 4 hops × 1-byte).
    """
    path_len_encoded = PathUtils.encode_path_len(2, 2)  # 0x42: 2-byte hashes, 2 hops
    assert path_len_encoded == 0x42
    path_byte_len = PathUtils.get_path_byte_len(path_len_encoded)
    assert path_byte_len == 4

    path = list(bytes(range(4)))  # 4 path bytes
    secret = bytes(32)  # 32-byte shared secret
    pkt = PacketBuilder.create_path_return(
        dest_hash=0xAB,
        src_hash=0xCD,
        secret=secret,
        path=path,
        extra_type=0xFF,
        extra=b"",
        path_len_encoded=path_len_encoded,
    )
    assert pkt.get_payload_type() == PAYLOAD_TYPE_PATH
    assert pkt.payload[0] == 0xAB
    assert pkt.payload[1] == 0xCD

    aes_key = secret[:16]
    cipher = bytes(pkt.payload[2:])
    decrypted = CryptoUtils.mac_then_decrypt(aes_key, secret, cipher)
    assert decrypted[0] == 0x42, "first byte must be encoded path_len 0x42, not path byte count 4"
    assert PathUtils.get_path_hash_size(decrypted[0]) == 2
    assert PathUtils.get_path_hash_count(decrypted[0]) == 2
    assert decrypted[1:5] == bytes(path)
    assert decrypted[5] == 0xFF  # extra_type


def test_packet_builder_create_path_return_requires_encoded_len_for_nonempty_path():
    """A non-empty path without path_len_encoded is ambiguous, so it must raise.

    3 bytes is either three 1-byte hashes or one 3-byte hash, and guessing
    wrong teaches the peer a route that resolves to nobody until a flood login
    resets it (firmware onPeerPathRecv stores the taught path verbatim).
    """
    with pytest.raises(ValueError, match="path_len_encoded is required"):
        PacketBuilder.create_path_return(
            dest_hash=0x01,
            src_hash=0x02,
            secret=bytes(32),
            path=[0x11, 0x22, 0x33],
            extra_type=0xFF,
            extra=b"",
            path_len_encoded=None,
        )


def test_packet_builder_create_path_return_one_byte_hashes_declared_explicitly():
    """1-byte hashes still work; the caller just has to say so."""
    path = [0x11, 0x22, 0x33]  # three 1-byte hashes
    secret = bytes(32)
    pkt = PacketBuilder.create_path_return(
        dest_hash=0x01,
        src_hash=0x02,
        secret=secret,
        path=path,
        extra_type=0xFF,
        extra=b"",
        path_len_encoded=PathUtils.encode_path_len(1, 3),
    )
    aes_key = secret[:16]
    decrypted = CryptoUtils.mac_then_decrypt(aes_key, secret, bytes(pkt.payload[2:]))
    assert PathUtils.get_path_hash_size(decrypted[0]) == 1
    assert PathUtils.get_path_hash_count(decrypted[0]) == 3
    assert decrypted[1:4] == bytes(path)
    # No extra payload: 0xFF dummy type followed by 4 random uniqueness bytes.
    assert decrypted[4] == 0xFF
    assert len(decrypted) >= 4 + 1 + 4


def test_packet_builder_create_path_return_empty_path_needs_no_encoded_len():
    """An empty path is unambiguous, so path_len_encoded stays optional."""
    secret = bytes(32)
    pkt = PacketBuilder.create_path_return(
        dest_hash=0x01,
        src_hash=0x02,
        secret=secret,
        path=[],
        extra_type=0xFF,
        extra=b"",
    )
    decrypted = CryptoUtils.mac_then_decrypt(secret[:16], secret, bytes(pkt.payload[2:]))
    assert decrypted[0] == 0


def test_packet_builder_create_path_return_rejects_invalid_encoded_len():
    """An invalid encoded path_len must raise, not fall back to a byte count."""
    with pytest.raises(ValueError, match="invalid path_len_encoded"):
        PacketBuilder.create_path_return(
            dest_hash=0x01,
            src_hash=0x02,
            secret=bytes(32),
            path=[0x11] * 4,
            extra_type=0xFF,
            extra=b"",
            path_len_encoded=0xFF,  # hash_size 4 is reserved
        )


def test_packet_builder_create_path_return_empty_extra_is_unique():
    """Two identical empty-extra PATH returns must differ (random filler),
    matching MeshCore Mesh::createPathReturn."""
    path = [0x11, 0x22, 0x33]
    secret = bytes(32)
    kwargs = dict(
        dest_hash=0x01,
        src_hash=0x02,
        secret=secret,
        path=path,
        extra=b"",
        path_len_encoded=PathUtils.encode_path_len(1, 3),
    )
    a = PacketBuilder.create_path_return(**kwargs)
    b = PacketBuilder.create_path_return(**kwargs)
    assert bytes(a.payload) != bytes(b.payload)
    # Both remain valid and decrypt with the shared secret.
    for pkt in (a, b):
        dec = CryptoUtils.mac_then_decrypt(secret[:16], secret, bytes(pkt.payload[2:]))
        assert dec[0] == 3
        assert dec[1:4] == bytes(path)
        assert dec[4] == 0xFF


def test_create_text_message_cli_data_flags_byte():
    """TXT_TYPE_CLI_DATA sets upper bits of flags; ACK crc includes full flags byte."""
    local = LocalIdentity()
    other = LocalIdentity()
    contact = type(
        "Contact",
        (),
        {
            "public_key": other.get_public_key().hex(),
            "out_path": [],
            "out_path_len": -1,
        },
    )()
    pkt_plain, crc_plain = PacketBuilder.create_text_message(
        contact, local, "cmd", 1, "direct", None, 0
    )
    pkt_cli, crc_cli = PacketBuilder.create_text_message(
        contact, local, "cmd", 1, "direct", None, 1
    )
    peer_pub = local.get_public_key()
    secret = Identity(peer_pub).calc_shared_secret(other.get_private_key())
    aes_key = secret[:16]

    def _dec_txt(p):
        return CryptoUtils.mac_then_decrypt(aes_key, secret, bytes(p.payload[2:]))

    dec_p = _dec_txt(pkt_plain)
    dec_c = _dec_txt(pkt_cli)
    assert dec_p[4] == 0x01  # PLAIN: (0 << 2) | attempt 1
    assert dec_c[4] == 0x05  # CLI_DATA: (1 << 2) | attempt 1
    assert crc_plain != crc_cli


def test_create_text_message_extended_attempt_hidden_in_tail():
    """attempt > 3 hides the full attempt byte after the text's NUL terminator so
    retries whose low two bits repeat still produce a unique packet (composeMsgPacket)."""
    local = LocalIdentity()
    other = LocalIdentity()
    contact = type(
        "Contact",
        (),
        {"public_key": other.get_public_key().hex(), "out_path": [], "out_path_len": -1},
    )()
    peer_pub = local.get_public_key()
    secret = Identity(peer_pub).calc_shared_secret(other.get_private_key())
    aes_key = secret[:16]

    def _dec(p):
        return CryptoUtils.mac_then_decrypt(aes_key, secret, bytes(p.payload[2:]))

    text = "hi"
    ts = 1000  # pin the timestamp so attempt 0 and 4 are comparable
    pkt4, crc4 = PacketBuilder.create_text_message(
        contact, local, text, 4, "direct", None, 0, timestamp=ts
    )
    dec4 = _dec(pkt4)
    # Low two bits of attempt live in the flag byte: 4 & 3 == 0
    assert dec4[4] == 0x00
    # Layout: timestamp(4) + flags(1) + text + NUL + attempt
    tail_start = 5 + len(text.encode("utf-8"))
    assert dec4[tail_start] == 0x00  # C-string terminator
    assert dec4[tail_start + 1] == 4  # hidden full attempt byte

    # attempt <= 3 carries no hidden attempt byte (only the terminator + padding).
    pkt0, crc0 = PacketBuilder.create_text_message(
        contact, local, text, 0, "direct", None, 0, timestamp=ts
    )
    dec0 = _dec(pkt0)
    assert dec0[tail_start] == 0x00
    assert dec0[tail_start + 1] == 0x00  # AES zero padding, not an attempt byte

    # The ACK CRC is computed over timestamp+flags+text only, so attempt 0 and 4
    # (same low bits, same text) expect the same ACK, but the packets differ.
    assert crc0 == crc4
    assert bytes(pkt0.payload) != bytes(pkt4.payload)

    # Extended attempt shrinks the text budget by two bytes.
    long_text = "x" * (MAX_TEXT_LEN - 1)
    with pytest.raises(ValueError):
        PacketBuilder.create_text_message(contact, local, long_text, 4, "direct", None, 0)
    # The same length is still fine for attempt <= 3.
    ok_pkt, _ = PacketBuilder.create_text_message(contact, local, long_text, 1, "direct", None, 0)
    assert ok_pkt is not None


def test_create_text_message_truncated_path_path_len_consistency():
    """When contact has 64-byte path but out_path_len encodes more than 64 bytes
    (e.g. 33 hops × 2-byte = 66), do not use contact_path_len; use 1-byte
    encoding and cap path at 63 so path_len never declares more bytes than present.
    """
    local = LocalIdentity()
    other = LocalIdentity()
    # 64-byte path, but encoded as 33 hops × 2-byte = 66 (invalid to use)
    contact_path_len_66 = PathUtils.encode_path_len(2, 33)  # 0x61, 66 bytes
    assert PathUtils.get_path_byte_len(contact_path_len_66) == 66
    contact = type(
        "Contact",
        (),
        {
            "public_key": other.get_public_key().hex(),
            "out_path": list(range(64)),
            "out_path_len": contact_path_len_66,
        },
    )()
    pkt, _ = PacketBuilder.create_text_message(contact, local, "hi", 0, "direct", out_path=None)
    # Must not have used contact_path_len (66 > 64); path should be 63 bytes, 1-byte encoding
    assert pkt.get_path_byte_len() <= len(pkt.path)
    assert pkt.get_path_byte_len() == 63
    assert len(pkt.path) == 63


def test_create_protocol_request_truncated_path_path_len_consistency():
    """When contact out_path is > 64 bytes and out_path_len encodes > 64 bytes,
    truncate path and do not use out_path_len; cap at 63 and use 1-byte encoding.
    """
    local = LocalIdentity()
    other = LocalIdentity()
    out_path_len_66 = PathUtils.encode_path_len(2, 33)  # 66 bytes
    contact = type(
        "Contact",
        (),
        {
            "public_key": other.get_public_key().hex(),
            "out_path": bytes(range(70)),
            "out_path_len": out_path_len_66,
        },
    )()
    packet, _ = PacketBuilder.create_protocol_request(contact, local, 0x01, b"")
    assert packet.get_path_byte_len() <= len(packet.path)
    assert packet.get_path_byte_len() == 63
    assert len(packet.path) == 63


def test_create_login_packet_truncated_path_path_len_consistency():
    """Same as create_protocol_request: truncated path must not use out_path_len
    when it would imply more bytes than present.
    """
    local = LocalIdentity()
    other = LocalIdentity()
    out_path_len_66 = PathUtils.encode_path_len(2, 33)
    contact = type(
        "Contact",
        (),
        {
            "public_key": other.get_public_key().hex(),
            "out_path": bytes(range(70)),
            "out_path_len": out_path_len_66,
        },
    )()
    pkt = PacketBuilder.create_login_packet(contact, local, "secret")
    assert pkt.get_path_byte_len() <= len(pkt.path)
    assert pkt.get_path_byte_len() == 63
    assert len(pkt.path) == 63


def test_truncated_path_packet_round_trip():
    """Packet built with truncated path and safe path_len must write_to/read_from
    without error and without 'truncated path'."""
    local = LocalIdentity()
    other = LocalIdentity()
    out_path_len_66 = PathUtils.encode_path_len(2, 33)
    contact = type(
        "Contact",
        (),
        {
            "public_key": other.get_public_key().hex(),
            "out_path": bytes(range(70)),
            "out_path_len": out_path_len_66,
        },
    )()
    packet, _ = PacketBuilder.create_protocol_request(contact, local, 0x01, b"data")
    raw = packet.write_to()
    pkt2 = Packet()
    ok = pkt2.read_from(raw)
    assert ok
    assert pkt2.get_path_byte_len() == len(pkt2.path)
    assert pkt2.get_path_byte_len() == 63


def _make_contact(other, out_path=b"", out_path_len=-1):
    return type(
        "Contact",
        (),
        {
            "public_key": other.get_public_key().hex(),
            "out_path": out_path,
            "out_path_len": out_path_len,
        },
    )()


def _decrypt_anon(pkt, sender_local, recipient_local):
    """Decrypt an ANON_REQ packet: payload = dest_hash(1)+sender_pubkey(32)+cipher."""
    assert pkt.payload[1:33] == bytes(sender_local.get_public_key())
    cipher = bytes(pkt.payload[33:])
    secret = Identity(sender_local.get_public_key()).calc_shared_secret(
        recipient_local.get_private_key()
    )
    return CryptoUtils.mac_then_decrypt(secret[:16], secret, cipher)


def test_create_anon_request_is_anon_payload_type_no_subtype_prefix():
    """Regression: anon requests must be PAYLOAD_TYPE_ANON_REQ with the client's
    sub-type byte at offset 4 (after the 4-byte timestamp) - NOT a PAYLOAD_TYPE_REQ
    with 0x07 prepended (which repeaters read as REQ_TYPE_GET_OWNER_INFO)."""
    local = LocalIdentity()
    other = LocalIdentity()
    contact = _make_contact(other, out_path=b"", out_path_len=0)  # zero-hop neighbour
    # ANON_REQ_TYPE_REGIONS (0x01) + reply-path byte (0 = empty path)
    req_data = bytes([0x01, 0x00])
    pkt, ts = PacketBuilder.create_anon_request(contact, local, req_data)

    assert pkt.get_payload_type() == PAYLOAD_TYPE_ANON_REQ
    plaintext = _decrypt_anon(pkt, local, other)
    assert int.from_bytes(plaintext[:4], "little") == ts
    # sub-type byte sits immediately after the timestamp, with no 0x07 prefix
    assert plaintext[4] == 0x01
    # (trailing bytes are AES block padding, ignored by the responder)
    assert plaintext[4 : 4 + len(req_data)] == req_data


def test_create_anon_request_zero_hop_is_direct():
    """out_path_len == 0 (zero-hop direct neighbour) must route DIRECT so the
    firmware regions handler (which requires isRouteDirect()) answers."""
    local = LocalIdentity()
    other = LocalIdentity()
    contact = _make_contact(other, out_path=b"", out_path_len=0)
    pkt, _ = PacketBuilder.create_anon_request(contact, local, bytes([0x01, 0x00]))
    assert pkt.is_route_direct()
    assert not pkt.is_route_flood()


def test_create_anon_request_unknown_path_is_flood():
    """out_path_len == -1 (unknown) must route FLOOD."""
    local = LocalIdentity()
    other = LocalIdentity()
    contact = _make_contact(other, out_path=b"", out_path_len=-1)
    pkt, _ = PacketBuilder.create_anon_request(contact, local, bytes([0x01, 0x00]))
    assert pkt.is_route_flood()


def test_create_protocol_request_zero_hop_is_direct():
    """out_path_len == 0 (zero-hop direct neighbour, empty path) must route DIRECT.

    After login establishes the path, stats/telemetry requests must use sendDirect
    so the firmware repeater answers directly instead of flooding (matches firmware
    BaseChatMesh::sendRequest and create_anon_request)."""
    local = LocalIdentity()
    other = LocalIdentity()
    contact = _make_contact(other, out_path=b"", out_path_len=0)
    pkt, _ = PacketBuilder.create_protocol_request(contact, local, 0x01, b"")
    assert pkt.is_route_direct()
    assert not pkt.is_route_flood()
    # Zero-hop direct packet carries an empty path (firmware sendDirect(pkt, path, 0)).
    assert pkt.path_len == 0


def test_create_protocol_request_unknown_path_is_flood():
    """out_path_len == -1 (unknown) must route FLOOD."""
    local = LocalIdentity()
    other = LocalIdentity()
    contact = _make_contact(other, out_path=b"", out_path_len=-1)
    pkt, _ = PacketBuilder.create_protocol_request(contact, local, 0x01, b"")
    assert pkt.is_route_flood()


def test_create_protocol_request_can_force_flood_for_known_path():
    """A request may explicitly flood without changing the stored contact path."""
    local = LocalIdentity()
    other = LocalIdentity()
    path = b"\x01\x02\x03"
    contact = _make_contact(other, out_path=path, out_path_len=3)
    pkt, _ = PacketBuilder.create_protocol_request(contact, local, 0x01, b"", route_type="flood")

    assert pkt.is_route_flood()
    assert pkt.path_len == 0
    assert bytes(pkt.path) == b""
    assert contact.out_path_len == 3
    assert contact.out_path == path


def test_create_telem_request_honors_explicit_route_type():
    """Telemetry requests use the same explicit routing override as protocol requests."""
    local = LocalIdentity()
    other = LocalIdentity()
    contact = _make_contact(other, out_path=b"\x01\x02\x03", out_path_len=3)

    pkt, _ = PacketBuilder.create_telem_request(contact, local, route_type="flood")

    assert pkt.is_route_flood()
    assert pkt.path_len == 0
    assert bytes(pkt.path) == b""


def test_advert_timestamp_uses_wall_time_not_the_unique_request_clock():
    """Adverts carry plain wall time (firmware Mesh::createAdvert uses
    getCurrentTime, not getCurrentTimeUnique). If the advert shared the
    strictly-increasing request clock, a burst of requests would inflate the
    advert timestamp into the future and peers would drop this node's later
    wall-time adverts as replays until real time caught up."""
    import struct
    from unittest.mock import patch

    with patch("time.time", return_value=1_700_000_000.0):
        # Inflate the shared request clock well past the frozen wall time.
        for _ in range(5):
            PacketBuilder._get_timestamp()
        assert PacketBuilder._last_unique_timestamp > 1_700_000_000

        identity = LocalIdentity()
        pkt = PacketBuilder.create_advert(identity, "TestNode", 1)

        # Advert payload: pubkey(32) + timestamp(4 LE) + signature + appdata.
        advert_ts = struct.unpack("<I", bytes(pkt.payload[32:36]))[0]
        assert advert_ts == 1_700_000_000


def test_advert_timestamps_follow_the_wall_clock():
    """Two adverts in successive seconds carry those wall-clock seconds; two in
    the same second may carry the same value (getCurrentTime semantics)."""
    import struct
    from unittest.mock import patch

    identity = LocalIdentity()
    stamps = []
    for now in (2_000_000_000.0, 2_000_000_000.0, 2_000_000_001.0):
        with patch("time.time", return_value=now):
            pkt = PacketBuilder.create_advert(identity, "TestNode", 1)
        stamps.append(struct.unpack("<I", bytes(pkt.payload[32:36]))[0])

    assert stamps == [2_000_000_000, 2_000_000_000, 2_000_000_001]


def test_get_timestamp_is_strictly_monotonic_within_same_second():
    """Back-to-back tags must strictly increase even within one wall-clock second.

    Firmware repeaters drop a REQ/login whose timestamp is not strictly greater
    than the client's last stored timestamp (replay guard). Mirrors firmware
    getCurrentTimeUnique so a login + immediate stats request don't collide and
    get silently ignored."""
    ts = [PacketBuilder._get_timestamp() for _ in range(5)]
    assert ts == sorted(ts)
    assert len(set(ts)) == 5  # all unique
    assert all(b == a + 1 or b > a for a, b in zip(ts, ts[1:]))


def test_login_then_stats_tags_strictly_increase():
    """A login followed immediately by a stats request must carry strictly
    increasing timestamps so the firmware repeater accepts the stats REQ."""
    local = LocalIdentity()
    other = LocalIdentity()
    contact = _make_contact(other, out_path=b"", out_path_len=0)
    login_pkt = PacketBuilder.create_login_packet(
        contact=contact, local_identity=local, password="x"
    )
    _, stats_ts = PacketBuilder.create_protocol_request(contact, local, 0x01, b"")
    login_ts = int.from_bytes(_decrypt_anon(login_pkt, local, other)[:4], "little")
    assert stats_ts > login_ts


def test_create_text_message_uses_explicit_timestamp():
    """An explicit timestamp is used verbatim (the host msg_timestamp), so retries of the
    same message keep a stable timestamp — mirroring firmware sendMessage."""
    import struct

    sender = LocalIdentity()
    recipient = LocalIdentity()
    contact = _make_contact(recipient)
    ts = 1700000000
    attempt = 2
    text = "retry me"

    _, crc = PacketBuilder.create_text_message(
        contact, sender, text, attempt=attempt, message_type="direct", timestamp=ts
    )
    flags_byte = attempt & 0x03
    expected = int.from_bytes(
        CryptoUtils.sha256(
            struct.pack("<I", ts)
            + bytes([flags_byte])
            + text.encode("utf-8")
            + sender.get_public_key()
        )[:4],
        "little",
    )
    assert crc == expected

    # Same timestamp + attempt + text => identical ACK CRC (stable retry identity).
    _, crc2 = PacketBuilder.create_text_message(
        contact, sender, text, attempt=attempt, message_type="direct", timestamp=ts
    )
    assert crc2 == crc

    # No explicit timestamp => a fresh one is minted => different CRC.
    _, crc3 = PacketBuilder.create_text_message(
        contact, sender, text, attempt=attempt, message_type="direct"
    )
    assert crc3 != crc


def _decrypt_group_content(pkt: Packet, secret: bytes) -> bytes:
    """Return the '<sender>: <text>' content of a group datagram payload."""
    # Payload layout: channel_hash (1) + MAC (2) + ciphertext
    ciphertext = bytes(pkt.payload[3:])
    plaintext = CryptoUtils._aes_decrypt(secret[:16], ciphertext)
    # Skip timestamp (4) + flags (1); strip AES zero-padding like receivers do.
    return plaintext[5:].rstrip(b"\x00")


def test_create_group_datagram_truncates_content_to_max_text_len():
    """Firmware sendGroupMessage caps '<sender>: <text>' at MAX_TEXT_LEN bytes."""
    secret = b"\x11" * 16
    channels = [{"name": "general", "secret": secret}]
    sender = "Alice"

    pkt = PacketBuilder.create_group_datagram(
        "general", LocalIdentity(), "x" * 500, sender, channels
    )

    content = _decrypt_group_content(pkt, secret)
    assert len(content) == MAX_TEXT_LEN
    prefix = f"{sender}: "
    assert content.decode("utf-8") == prefix + "x" * (MAX_TEXT_LEN - len(prefix))


def test_create_group_datagram_short_message_not_truncated():
    secret = b"\x11" * 16
    channels = [{"name": "general", "secret": secret}]

    pkt = PacketBuilder.create_group_datagram(
        "general", LocalIdentity(), "hello", "Alice", channels
    )

    assert _decrypt_group_content(pkt, secret) == b"Alice: hello"


def test_create_group_datagram_truncation_keeps_utf8_valid():
    """A multi-byte char split at the byte cap is dropped, not corrupted."""
    secret = b"\x11" * 16
    channels = [{"name": "general", "secret": secret}]

    # Prefix "A: " is 3 bytes; 157 remaining is odd, so a 2-byte char straddles the cut.
    pkt = PacketBuilder.create_group_datagram("general", LocalIdentity(), "é" * 200, "A", channels)

    content = _decrypt_group_content(pkt, secret)
    assert len(content) <= MAX_TEXT_LEN
    assert content.decode("utf-8") == "A: " + "é" * ((MAX_TEXT_LEN - 3) // 2)


def test_addressed_builders_retain_the_destination_key():
    """Addressed packets keep the full destination key in memory.

    The wire format keeps only a 1-3 byte prefix of it, so a host that needs to
    know *which* key a packet is addressed to cannot recover it from the packet
    afterwards.
    """
    sender = LocalIdentity()
    recipient = LocalIdentity()
    contact = _make_contact(recipient)
    dest = Identity(recipient.get_public_key())
    secret = dest.calc_shared_secret(sender.get_private_key())
    expected = recipient.get_public_key()

    text_packet, _ = PacketBuilder.create_text_message(
        contact=contact, local_identity=sender, message="hello"
    )
    req_packet, _ = PacketBuilder.create_protocol_request(contact, sender, 0x01)
    anon_packet, _ = PacketBuilder.create_anon_request(contact, sender, b"\x01")

    for name, packet in (
        ("create_datagram", PacketBuilder.create_datagram(0, dest, sender, secret, b"x")),
        ("create_text_message", text_packet),
        ("create_protocol_request", req_packet),
        ("create_anon_req", PacketBuilder.create_anon_req(dest, sender, secret, b"x")),
        ("create_anon_request", anon_packet),
        ("create_login_packet", PacketBuilder.create_login_packet(contact, sender, "pw")),
    ):
        assert packet._dest_pubkey == expected, name


def test_broadcast_builders_leave_the_destination_key_unset():
    """Payloads with no single addressee must not claim one.

    An advert is self-signed and group payloads use a channel key, so there is
    no destination key to retain.
    """
    import hashlib

    sender = LocalIdentity()
    channel_secret = bytes(range(16))

    advert = PacketBuilder.create_self_advert(sender, "node")
    group = PacketBuilder.create_group_data_packet(
        PAYLOAD_TYPE_GRP_DATA,
        channel_hash=hashlib.sha256(channel_secret).digest()[0],
        channel_secret=channel_secret,
        plaintext=b"\x34\x12\x02\xaa\xbb",
        secret=channel_secret,
    )
    trace = PacketBuilder.create_trace(tag=1, auth_code=2, flags=0, path=[])
    ack = PacketBuilder.create_ack_from_bytes(b"\x01\x02\x03\x04")

    for name, packet in (
        ("create_self_advert", advert),
        ("create_group_data_packet", group),
        ("create_trace", trace),
        ("create_ack_from_bytes", ack),
    ):
        assert packet._dest_pubkey is None, name
