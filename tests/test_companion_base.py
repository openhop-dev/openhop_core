"""Tests for companion base: ResponseWaiter, adv_type_to_flags, and base API via CompanionRadio."""

import hashlib

import pytest

from openhop_core.companion import CompanionBridge
from openhop_core.companion.companion_base import ResponseWaiter, adv_type_to_flags
from openhop_core.companion.constants import (
    ADV_TYPE_CHAT,
    ADV_TYPE_REPEATER,
    ADV_TYPE_ROOM,
    ADV_TYPE_SENSOR,
)
from openhop_core.companion.models import Contact
from openhop_core.protocol import CryptoUtils, Identity, LocalIdentity, Packet, PacketBuilder
from openhop_core.protocol.constants import (
    ADVERT_FLAG_IS_CHAT_NODE,
    ADVERT_FLAG_IS_REPEATER,
    ADVERT_FLAG_IS_ROOM_SERVER,
    ADVERT_FLAG_IS_SENSOR,
    PAYLOAD_TYPE_GRP_DATA,
    PAYLOAD_TYPE_TRACE,
    ROUTE_TYPE_DIRECT,
    ROUTE_TYPE_FLOOD,
    ROUTE_TYPE_TRANSPORT_DIRECT,
    ROUTE_TYPE_TRANSPORT_FLOOD,
)
from openhop_core.protocol.utils import determine_contact_type_from_flags, get_contact_type_name

# ---------------------------------------------------------------------------
# ResponseWaiter
# ---------------------------------------------------------------------------


class TestResponseWaiter:
    def test_initial_state(self):
        w = ResponseWaiter()
        assert w.data["success"] is False
        assert w.data["text"] is None
        assert w.data["parsed"] == {}

    def test_callback_sets_data_and_event(self):
        w = ResponseWaiter()
        w.callback(True, "hello", {"k": "v"})
        assert w.data["success"] is True
        assert w.data["text"] == "hello"
        assert w.data["parsed"] == {"k": "v"}
        assert w.event.is_set()

    @pytest.mark.asyncio
    async def test_wait_returns_after_callback(self):
        w = ResponseWaiter()
        w.callback(True, "done", {"x": 1})
        result = await w.wait(timeout=1.0)
        assert result["success"] is True
        assert result["text"] == "done"
        assert result["parsed"] == {"x": 1}
        assert "timeout" not in result

    @pytest.mark.asyncio
    async def test_wait_timeout(self):
        w = ResponseWaiter()
        result = await w.wait(timeout=0.05)
        assert result["timeout"] is True
        assert result["success"] is False


# ---------------------------------------------------------------------------
# adv_type_to_flags
# ---------------------------------------------------------------------------


class TestAdvTypeToFlags:
    def test_chat(self):
        assert adv_type_to_flags(ADV_TYPE_CHAT) == ADVERT_FLAG_IS_CHAT_NODE

    def test_repeater(self):
        assert adv_type_to_flags(ADV_TYPE_REPEATER) == ADVERT_FLAG_IS_REPEATER

    def test_room(self):
        assert adv_type_to_flags(ADV_TYPE_ROOM) == ADVERT_FLAG_IS_ROOM_SERVER

    def test_sensor(self):
        assert adv_type_to_flags(ADV_TYPE_SENSOR) == ADVERT_FLAG_IS_SENSOR

    def test_unknown_defaults_to_chat(self):
        assert adv_type_to_flags(99) == ADVERT_FLAG_IS_CHAT_NODE
        assert adv_type_to_flags(0) == ADVERT_FLAG_IS_CHAT_NODE


class TestDetermineContactTypeFromFlags:
    """Wire advert flags (low nibble) map to ADV_TYPE_* (1=chat, 2=repeater, 3=room, 4=sensor)."""

    def test_sensor_flags_map_to_adv_type_sensor(self):
        assert determine_contact_type_from_flags(0x04) == ADV_TYPE_SENSOR
        assert determine_contact_type_from_flags(0x14) == ADV_TYPE_SENSOR  # with HAS_LOCATION
        assert get_contact_type_name(4) == "Sensor"

    def test_all_node_types(self):
        assert determine_contact_type_from_flags(0x01) == ADV_TYPE_CHAT
        assert determine_contact_type_from_flags(0x02) == ADV_TYPE_REPEATER
        assert determine_contact_type_from_flags(0x03) == ADV_TYPE_ROOM
        assert determine_contact_type_from_flags(0x04) == ADV_TYPE_SENSOR

    def test_unknown(self):
        assert determine_contact_type_from_flags(0x05) == 0
        assert determine_contact_type_from_flags(0) == 0


# ---------------------------------------------------------------------------
# _apply_path_hash_mode
# ---------------------------------------------------------------------------


def _make_bridge(path_hash_mode: int = 0) -> CompanionBridge:
    """Create a minimal CompanionBridge for testing _apply_path_hash_mode."""

    async def _noop_injector(pkt, wait_for_ack=False):
        return True

    bridge = CompanionBridge(LocalIdentity(), _noop_injector, node_name="Test")
    bridge.prefs.path_hash_mode = path_hash_mode
    return bridge


class TestApplyPathHashMode:
    def test_encodes_on_zero_hops(self):
        """path_hash_mode=1 on a fresh packet (0 hops) → path_len=0x40."""
        bridge = _make_bridge(path_hash_mode=1)
        pkt = Packet()
        pkt.header = 0x06
        pkt.path_len = 0
        pkt.path = bytearray()
        pkt.payload = bytearray(b"test")
        pkt.payload_len = 4

        bridge._apply_path_hash_mode(pkt)

        assert pkt.path_len == 0x40  # (1 << 6) | 0 = 0x40
        assert pkt.get_path_hash_size() == 2
        assert pkt.get_path_hash_count() == 0

    def test_skips_nonzero_hops(self):
        """Packets with existing hops (stored contact path) are untouched."""
        bridge = _make_bridge(path_hash_mode=2)
        pkt = Packet()
        pkt.header = 0x06
        # 3 hops with 1-byte hashes
        pkt.set_path(b"\xaa\xbb\xcc")
        pkt.payload = bytearray(b"test")
        pkt.payload_len = 4

        original_path_len = pkt.path_len
        bridge._apply_path_hash_mode(pkt)

        # path_len unchanged — the contact path is preserved
        assert pkt.path_len == original_path_len
        assert pkt.get_path_hash_count() == 3

    def test_all_modes(self):
        """Verify mode 0→0x00, mode 1→0x40, mode 2→0x80 on fresh packets."""
        expected = {
            0: (0x00, 1),  # (path_len, hash_size)
            1: (0x40, 2),
            2: (0x80, 3),
        }
        for mode, (expected_path_len, expected_hash_size) in expected.items():
            bridge = _make_bridge(path_hash_mode=mode)
            pkt = Packet()
            pkt.header = 0x06
            pkt.path_len = 0
            pkt.path = bytearray()
            pkt.payload = bytearray(b"x")
            pkt.payload_len = 1

            bridge._apply_path_hash_mode(pkt)

            assert pkt.path_len == expected_path_len, (
                f"mode={mode}: expected path_len=0x{expected_path_len:02X}, "
                f"got 0x{pkt.path_len:02X}"
            )
            assert pkt.get_path_hash_size() == expected_hash_size, (
                f"mode={mode}: expected hash_size={expected_hash_size}, "
                f"got {pkt.get_path_hash_size()}"
            )

    def test_skips_trace_packets(self):
        """Trace packets use path for SNR values, not routing hashes."""
        bridge = _make_bridge(path_hash_mode=1)
        pkt = Packet()
        # Trace packet: payload_type=PAYLOAD_TYPE_TRACE, route_type=ROUTE_TYPE_DIRECT
        pkt.header = (PAYLOAD_TYPE_TRACE << 2) | ROUTE_TYPE_DIRECT
        pkt.path_len = 0
        pkt.path = bytearray()
        pkt.payload = bytearray(b"trace_data")
        pkt.payload_len = 10

        bridge._apply_path_hash_mode(pkt)

        # path_len must stay 0 — NOT 0x40
        assert pkt.path_len == 0
        assert pkt.get_path_hash_size() == 1
        assert pkt.get_path_hash_count() == 0

    def test_sets_path_hash_mode_applied_marker(self):
        """Companion sets _path_hash_mode_applied so dispatcher does not overwrite."""
        bridge = _make_bridge(path_hash_mode=1)
        pkt = Packet()
        pkt.header = 0x06
        pkt.path_len = 0
        pkt.path = bytearray()
        pkt.payload = bytearray(b"x")
        pkt.payload_len = 1

        bridge._apply_path_hash_mode(pkt)

        assert getattr(pkt, "_path_hash_mode_applied", False) is True


# ---------------------------------------------------------------------------
# set_advert_name — 31-byte firmware field (char node_name[32], NodePrefs.h),
# truncation is on UTF-8 bytes, not Python characters.
# ---------------------------------------------------------------------------


class TestSetAdvertName:
    def test_ascii_name_longer_than_limit_truncates_to_31_bytes(self):
        bridge = _make_bridge()
        bridge.set_advert_name("a" * 40)
        assert bridge.prefs.node_name == "a" * 31
        assert len(bridge.prefs.node_name.encode("utf-8")) == 31

    def test_ascii_name_exactly_at_limit_is_unchanged(self):
        bridge = _make_bridge()
        name = "a" * 31
        bridge.set_advert_name(name)
        assert bridge.prefs.node_name == name
        assert len(bridge.prefs.node_name.encode("utf-8")) == 31

    def test_multibyte_utf8_name_straddling_boundary_cuts_at_codepoint(self):
        """30 ASCII bytes + one 3-byte codepoint (e.g. 'ééé' would be

        2 bytes each; use a 3-byte char, e.g. '☃' SNOWMAN, so it can only
        fit whole or not at all across the 31-byte boundary.
        """
        bridge = _make_bridge()
        # 30 'a' bytes + a 3-byte snowman = 33 raw bytes; the snowman straddles
        # byte 31 and must be dropped whole, never split into invalid UTF-8.
        name = ("a" * 30) + "☃" + "b"
        bridge.set_advert_name(name)
        stored = bridge.prefs.node_name
        encoded = stored.encode("utf-8")
        assert len(encoded) <= 31
        # Round-trips cleanly (no partial multi-byte sequence survived).
        assert encoded.decode("utf-8") == stored
        # The snowman didn't fit in the remaining 1 byte, so it (and the
        # trailing 'b') were dropped; only the 30 leading ASCII bytes remain.
        assert stored == "a" * 30

    def test_multibyte_utf8_name_that_fits_is_preserved_whole(self):
        """A multi-byte codepoint that fits cleanly within 31 bytes is kept intact."""
        bridge = _make_bridge()
        name = ("a" * 28) + "☃"  # 28 + 3 = 31 bytes exactly
        bridge.set_advert_name(name)
        assert bridge.prefs.node_name == name
        assert len(bridge.prefs.node_name.encode("utf-8")) == 31


# ---------------------------------------------------------------------------
# share_contact — replay cached ADVERT blob (firmware shareContactZeroHop)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_share_contact_returns_false_without_cached_blob():
    """No last_advert_packet → cannot replay (matches firmware empty getBlobByKey)."""

    async def _inj(pkt, wait_for_ack=False):
        return True

    bridge = CompanionBridge(LocalIdentity(), _inj)
    key = bytes([0xAB] * 32)
    bridge.contacts.add(Contact(public_key=key, name="OnlyManual", adv_type=1))
    ok = await bridge.share_contact(key)
    assert ok is False


@pytest.mark.asyncio
@pytest.mark.parametrize("route_type", ["flood", "direct", "transport_flood", "transport_direct"])
async def test_share_contact_replays_remote_pubkey_zero_hop(route_type):
    """Contact shares retain the signed advert and use transport-direct codes {0, 0}."""

    remote = LocalIdentity()
    sent = []

    async def _capture(pkt, wait_for_ack=False):
        sent.append(pkt)
        return True

    bridge = CompanionBridge(LocalIdentity(), _capture)
    original = PacketBuilder.create_advert(remote, "RemoteName", route_type=route_type)
    original.transport_codes = [0x1234, 0x5678]
    original.set_path(bytearray(b"\x11\x22"), 0x41)
    blob = original.write_to()
    bridge.contacts.add(
        Contact(
            public_key=remote.get_public_key(),
            name="RemoteName",
            adv_type=1,
            last_advert_packet=blob,
        )
    )
    ok = await bridge.share_contact(remote.get_public_key())
    assert ok is True
    assert len(sent) == 1
    out = sent[0]
    assert bytes(out.payload[:32]) == remote.get_public_key()
    assert out.get_route_type() == ROUTE_TYPE_TRANSPORT_DIRECT
    assert out.transport_codes == [0, 0]
    assert out.path_len == 0
    assert len(out.path) == 0
    assert bytes(out.payload) == bytes(original.payload)
    assert bridge.contacts.get_by_key(remote.get_public_key()).last_advert_packet == blob
    wire = out.write_to()
    assert wire == bytes([out.header]) + b"\x00" * 5 + bytes(original.payload)
    decoded = Packet()
    assert decoded.read_from(wire)
    assert decoded.get_route_type() == ROUTE_TYPE_TRANSPORT_DIRECT
    assert decoded.transport_codes == [0, 0]
    assert bytes(decoded.payload) == bytes(original.payload)


@pytest.mark.asyncio
async def test_send_anon_req_to_non_contact_creates_transient_and_sends_direct():
    """PR #2672: anon req to an unknown pubkey creates a zero-hop transient contact."""
    remote = LocalIdentity()
    sent = []

    async def _capture(pkt, wait_for_ack=False):
        sent.append(pkt)
        return True

    bridge = CompanionBridge(LocalIdentity(), _capture)
    pub_key = remote.get_public_key()
    assert bridge.contacts.get_by_key(pub_key) is None

    result = await bridge.send_anon_req(pub_key, b"\x07")

    assert result.success is True
    assert result.is_flood is False  # zero-hop direct, not flood
    assert len(sent) == 1
    # Transient contact recorded with ADV_TYPE_NONE, zero-hop direct path...
    transient = bridge.contacts.get_by_key(pub_key)
    assert transient is not None
    assert transient.adv_type == 0
    assert transient.out_path_len == 0
    # ...but excluded from the app-facing contact sync and from persistence.
    assert all(c.public_key != pub_key for c in bridge.get_contacts())
    assert all(d["public_key"] != pub_key.hex() for d in bridge.contacts.to_dicts())


@pytest.mark.asyncio
async def test_send_anon_req_returns_failure_when_anon_pool_full():
    """When add_transient fails the request reports failure (-> ERR_CODE_TABLE_FULL)."""
    bridge = CompanionBridge(LocalIdentity(), lambda *a, **k: None)
    pub_key = LocalIdentity().get_public_key()
    bridge.contacts.add_transient = lambda c: False  # simulate full anon pool
    result = await bridge.send_anon_req(pub_key, b"\x07")
    assert result.success is False


def test_apply_flood_scope_uses_default_scope_when_transient_unset():
    """Persisted default scope key applies transport flooding when transient scope is unset."""
    bridge = _make_bridge(path_hash_mode=0)
    key = bytes(range(16))
    assert bridge.set_default_flood_scope("region1", key) is True
    bridge.set_flood_scope(None)

    pkt = Packet()
    pkt.header = (PAYLOAD_TYPE_TRACE << 2) | 0x01  # route type FLOOD
    pkt.path_len = 0
    pkt.path = bytearray()
    pkt.payload = bytearray(b"abc")
    pkt.payload_len = 3

    bridge._apply_flood_scope(pkt)
    assert pkt.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD
    assert pkt.transport_codes[0] != 0


def test_set_flood_scope_zero_key_resets_to_default_scope():
    """An all-zero key is firmware's null override, so default scope still applies."""
    bridge = _make_bridge(path_hash_mode=0)
    default_key = b"\x22" * 16
    assert bridge.set_default_flood_scope("region1", default_key) is True
    key = b"\x11" * 16
    bridge.set_flood_scope(key)
    assert bridge._resolve_flood_transport_key() == key

    bridge.set_flood_scope(b"\x00" * 16)

    assert bridge._flood_transport_key is None
    assert bridge._resolve_flood_transport_key() == default_key

    pkt = _make_flood_pkt()
    bridge._apply_flood_scope(pkt)
    assert pkt.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD


def test_set_flood_scope_none_after_zero_key_uses_default_scope():
    """Mode 0 without a key resets the null override and lets default scope apply."""
    bridge = _make_bridge(path_hash_mode=0)
    assert bridge.set_default_flood_scope("region1", b"\x22" * 16) is True
    assert bridge._resolve_flood_transport_key() == b"\x22" * 16

    bridge.set_flood_scope(b"\x00" * 16)
    assert bridge._resolve_flood_transport_key() == b"\x22" * 16
    bridge.set_flood_scope(None)
    assert bridge._resolve_flood_transport_key() == b"\x22" * 16

    pkt = _make_flood_pkt()
    bridge._apply_flood_scope(pkt)
    assert pkt.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD

    pkt2 = _make_flood_pkt()
    bridge._apply_flood_scope(pkt2)
    assert pkt2.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD


def test_set_flood_scope_none_clears_sticky_unscoped_state():
    """Mode 0 set/reset cancels sticky unscoped, so the default scope applies again."""
    bridge = _make_bridge(path_hash_mode=0)
    assert bridge.set_default_flood_scope("region1", b"\x33" * 16) is True
    bridge.set_flood_unscoped()

    bridge.set_flood_scope(None)

    assert bridge._resolve_flood_transport_key() == b"\x33" * 16
    pkt = _make_flood_pkt()
    bridge._apply_flood_scope(pkt)
    assert pkt.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD


def _make_flood_pkt() -> Packet:
    pkt = Packet()
    pkt.header = (PAYLOAD_TYPE_TRACE << 2) | 0x01  # route type FLOOD
    pkt.path_len = 0
    pkt.path = bytearray()
    pkt.payload = bytearray(b"abc")
    pkt.payload_len = 3
    return pkt


def test_set_flood_unscoped_overrides_default_scope_sticky():
    """FW #2492: explicit unscoped forces a plain flood, bypassing the default scope."""
    bridge = _make_bridge(path_hash_mode=0)
    assert bridge.set_default_flood_scope("region1", bytes(range(16))) is True

    bridge.set_flood_unscoped()
    pkt = _make_flood_pkt()
    bridge._apply_flood_scope(pkt)
    # Stays a plain flood — no transport scoping applied.
    assert pkt.get_route_type() == ROUTE_TYPE_FLOOD
    assert pkt.transport_codes[0] == 0

    # Sticky: following floods stay plain until mode 0 sets/resets scope.
    pkt2 = _make_flood_pkt()
    bridge._apply_flood_scope(pkt2)
    assert pkt2.get_route_type() == ROUTE_TYPE_FLOOD
    assert pkt2.transport_codes[0] == 0


def test_set_flood_scope_cancels_pending_unscoped():
    """Setting/resetting a scope clears a pending explicit-unscoped request."""
    bridge = _make_bridge(path_hash_mode=0)
    assert bridge.set_default_flood_scope("region1", bytes(range(16))) is True
    bridge.set_flood_unscoped()
    bridge.set_flood_scope(None)  # cancels the unscoped request
    pkt = _make_flood_pkt()
    bridge._apply_flood_scope(pkt)
    assert pkt.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD


@pytest.mark.asyncio
async def test_group_data_packet_is_queued_for_sync():
    """Incoming GRP_DATA decrypts and queues a binary channel message."""
    sent = []

    async def _inj(pkt, wait_for_ack=False):
        sent.append(pkt)
        return True

    bridge = CompanionBridge(LocalIdentity(), _inj, node_name="Test")
    assert bridge.set_channel(0, "Public", b"\x11" * 32)

    ch = bridge.get_channel(0)
    plaintext = b"\x34\x12\x02\xaa\xbb"  # data_type=0x1234, len=2, payload=AABB
    pkt = PacketBuilder.create_group_data_packet(
        PAYLOAD_TYPE_GRP_DATA,
        channel_hash=hashlib.sha256(ch.secret).digest()[0],
        channel_secret=ch.secret,
        plaintext=plaintext,
        secret=ch.secret,
    )

    await bridge.process_received_packet(pkt)
    queued = bridge.sync_next_message()
    assert queued is not None
    assert queued.is_channel is True
    assert queued.channel_idx == 0
    assert queued.channel_data_type == 0x1234
    assert queued.channel_data_payload == b"\xaa\xbb"


# ---------------------------------------------------------------------------
# Same-name contact disambiguation (re-keyed node regression)
# ---------------------------------------------------------------------------
#
# Regression for: a node that re-keys (e.g. a device that corrupts its memory and
# is re-imported with a new public key) leaves two contacts with the *same name*
# but different public keys in the store. Outbound sends must address the contact
# the caller actually asked for (by public key), never the first one that happens
# to share the name. Previously send_* resolved the proxy via get_by_name(), so
# every DM to the new key was encrypted and routed to the old key.


def _identity_with_distinct_first_byte(taken: set[int]) -> LocalIdentity:
    """Generate a LocalIdentity whose public-key first byte (the on-wire dest hash)
    is not already in ``taken``, so the two contacts are distinguishable by hash."""
    for _ in range(1000):
        idn = LocalIdentity()
        first = idn.get_public_key()[0]
        if first not in taken:
            taken.add(first)
            return idn
    raise RuntimeError("could not generate a distinct-first-byte identity")


def _decrypt_dm(pkt: Packet, sender_pubkey: bytes, recipient: LocalIdentity) -> bytes:
    """Decrypt a direct TXT_MSG payload as the intended recipient would.

    Mirrors TextMessageHandler: payload is [dest_hash, src_hash] + cipher, decrypted
    with ECDH(sender_pub, recipient_priv). Raises if the HMAC is invalid (i.e. the
    packet was encrypted to a different key).
    """
    payload = bytes(pkt.payload)[2:]
    ss = Identity(sender_pubkey).calc_shared_secret(recipient.get_private_key())
    return CryptoUtils.mac_then_decrypt(ss[:16], ss, payload)


@pytest.mark.asyncio
async def test_send_text_addresses_exact_key_when_names_collide():
    """DM to the new key of a re-keyed contact must encrypt/route to that key,
    not to an older same-named contact inserted earlier."""
    sent: list[Packet] = []

    async def _capture(pkt, wait_for_ack=False):
        sent.append(pkt)
        return True

    bridge = CompanionBridge(LocalIdentity(), _capture, node_name="Local")
    sender_pub = bridge._identity.get_public_key()

    taken: set[int] = {sender_pub[0]}
    old = _identity_with_distinct_first_byte(taken)  # corrupted/old "Cheddar"
    new = _identity_with_distinct_first_byte(taken)  # re-imported "Cheddar"

    # Insert the OLD contact first so a name lookup would return it (the bug).
    # Give each a distinct direct out_path so routing is observable too.
    assert bridge.contacts.add(
        Contact(
            public_key=old.get_public_key(),
            name="Cheddar",
            adv_type=ADV_TYPE_CHAT,
            out_path_len=2,
            out_path=b"\x11\x22",
            lastmod=1,
        )
    )
    assert bridge.contacts.add(
        Contact(
            public_key=new.get_public_key(),
            name="Cheddar",
            adv_type=ADV_TYPE_CHAT,
            out_path_len=1,
            out_path=b"\x99",
            lastmod=2,
        )
    )
    # Precondition: a name lookup is ambiguous and returns the OLD contact.
    assert bridge.contacts.get_by_name("Cheddar").public_key == old.get_public_key().hex()

    result = await bridge.send_text_message(
        new.get_public_key(), "hello cheddar", wait_for_ack=False
    )
    assert result.success is True
    assert len(sent) == 1
    pkt = sent[0]

    # Addressed to the NEW contact: dest hash byte and routing path both match it.
    assert pkt.payload[0] == new.get_public_key()[0]
    assert bytes(pkt.path) == b"\x99"

    # Encrypted to the NEW key: the new recipient can decrypt, the old one cannot.
    decrypted = _decrypt_dm(pkt, sender_pub, new)
    assert b"hello cheddar" in decrypted
    with pytest.raises(Exception):
        _decrypt_dm(pkt, sender_pub, old)


@pytest.mark.asyncio
async def test_send_text_to_old_key_still_addresses_old_key():
    """The symmetric case: addressing the older same-named contact still works."""
    sent: list[Packet] = []

    async def _capture(pkt, wait_for_ack=False):
        sent.append(pkt)
        return True

    bridge = CompanionBridge(LocalIdentity(), _capture, node_name="Local")
    sender_pub = bridge._identity.get_public_key()

    taken = {sender_pub[0]}
    old = _identity_with_distinct_first_byte(taken)
    new = _identity_with_distinct_first_byte(taken)

    assert bridge.contacts.add(
        Contact(
            public_key=old.get_public_key(),
            name="Cheddar",
            adv_type=ADV_TYPE_CHAT,
            out_path_len=2,
            out_path=b"\x11\x22",
            lastmod=1,
        )
    )
    assert bridge.contacts.add(
        Contact(
            public_key=new.get_public_key(),
            name="Cheddar",
            adv_type=ADV_TYPE_CHAT,
            out_path_len=1,
            out_path=b"\x99",
            lastmod=2,
        )
    )

    result = await bridge.send_text_message(
        old.get_public_key(), "for the old one", wait_for_ack=False
    )
    assert result.success is True
    pkt = sent[0]

    assert pkt.payload[0] == old.get_public_key()[0]
    assert bytes(pkt.path) == b"\x11\x22"
    assert b"for the old one" in _decrypt_dm(pkt, sender_pub, old)
    with pytest.raises(Exception):
        _decrypt_dm(pkt, sender_pub, new)


# ---------------------------------------------------------------------------
# Login-session connection registry (mirrors BaseChatMesh connections[])
# ---------------------------------------------------------------------------


def test_login_connection_registry_note_has_clear():
    bridge = CompanionBridge(LocalIdentity(), lambda *a, **k: None)
    pubkey = b"\x11" * 32
    assert bridge.has_login_connection(pubkey) is False
    bridge.note_login_connection(pubkey, 4)  # 4 * 16 = 64s window
    assert bridge.has_login_connection(pubkey) is True
    bridge.clear_login_connection(pubkey)
    assert bridge.has_login_connection(pubkey) is False


def test_login_connection_zero_interval_not_recorded():
    """Firmware only startConnection() with keep_alive_secs > 0 (MyMesh.cpp:688)."""
    bridge = CompanionBridge(LocalIdentity(), lambda *a, **k: None)
    pubkey = b"\x12" * 32
    bridge.note_login_connection(pubkey, 0)
    assert bridge.has_login_connection(pubkey) is False


def test_login_connection_expires(monkeypatch):
    """Expiry window is 2.5x the keep-alive interval (BaseChatMesh.cpp:749)."""
    import openhop_core.companion.base_send as base_send

    clock = {"now": 500.0}
    monkeypatch.setattr(base_send.time, "monotonic", lambda: clock["now"])
    bridge = CompanionBridge(LocalIdentity(), lambda *a, **k: None)
    pubkey = b"\x13" * 32
    bridge.note_login_connection(pubkey, 4)  # 64s keep-alive -> 160s window
    clock["now"] = 500.0 + 159.9
    assert bridge.has_login_connection(pubkey) is True
    clock["now"] = 500.0 + 160.1
    assert bridge.has_login_connection(pubkey) is False
