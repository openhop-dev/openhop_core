"""Tests for CompanionFrameServer and advert push frame construction."""

import asyncio
import logging
import socket
import struct
import sys
from unittest.mock import AsyncMock, Mock

import pytest
from openhop_core.companion.constants import (
    CMD_GET_CUSTOM_VARS,
    CMD_GET_DEVICE_TIME,
    CMD_GET_TUNING_PARAMS,
    CMD_HAS_CONNECTION,
    CMD_IMPORT_PRIVATE_KEY,
    CMD_LOGOUT,
    CMD_SET_ADVERT_NAME,
    CMD_SET_TUNING_PARAMS,
    CMD_SIGN_DATA,
    CMD_SIGN_FINISH,
    CMD_SIGN_START,
    ERR_CODE_BAD_STATE,
    ERR_CODE_ILLEGAL_ARG,
    ERR_CODE_NOT_FOUND,
    ERR_CODE_TABLE_FULL,
    ERR_CODE_UNSUPPORTED_CMD,
    FRAME_OUTBOUND_PREFIX,
    MAX_PATH_SIZE,
    MAX_PAYLOAD_SIZE,
    MAX_SIGN_DATA_SIZE,
    PUB_KEY_SIZE,
    PUSH_CODE_ADVERT,
    PUSH_CODE_BINARY_RESPONSE,
    PUSH_CODE_MSG_WAITING,
    PUSH_CODE_NEW_ADVERT,
    PUSH_CODE_PATH_DISCOVERY_RESPONSE,
    RESP_CODE_ALLOWED_REPEAT_FREQ,
    RESP_CODE_CHANNEL_DATA_RECV,
    RESP_CODE_CHANNEL_INFO,
    RESP_CODE_CHANNEL_MSG_RECV,
    RESP_CODE_CHANNEL_MSG_RECV_V3,
    RESP_CODE_CONTACT,
    RESP_CODE_CONTACT_MSG_RECV,
    RESP_CODE_CONTACT_MSG_RECV_V3,
    RESP_CODE_CONTACTS_START,
    RESP_CODE_CURR_TIME,
    RESP_CODE_CUSTOM_VARS,
    RESP_CODE_DEFAULT_FLOOD_SCOPE,
    RESP_CODE_DISABLED,
    RESP_CODE_END_OF_CONTACTS,
    RESP_CODE_ERR,
    RESP_CODE_NO_MORE_MESSAGES,
    RESP_CODE_OK,
    RESP_CODE_SELF_INFO,
    RESP_CODE_SENT,
    RESP_CODE_SIGN_START,
    RESP_CODE_SIGNATURE,
    RESP_CODE_STATS,
    STATS_TYPE_RADIO,
    RESP_CODE_TUNING_PARAMS,
    STATS_TYPE_PACKETS,
)
from openhop_core.companion.frame_server import (
    CompanionFrameServer,
    _build_advert_push_frames,
)
from openhop_core.companion.models import (
    Channel,
    Contact,
    MessageEvent,
    NodePrefs,
    QueuedMessage,
    SentResult,
)
from openhop_core.protocol.packet_utils import PathUtils


def test_build_advert_push_frames_short_only_when_no_name():
    """Contact with empty name yields only short frame; full is None."""
    pubkey = bytes(range(32))
    contact = Contact(public_key=pubkey, name="")
    short, full = _build_advert_push_frames(contact)
    assert full is None
    assert len(short) == 1 + PUB_KEY_SIZE
    assert short[0] == PUSH_CODE_ADVERT
    assert short[1:33] == pubkey


def test_build_advert_push_frames_short_and_full_when_has_name():
    """Contact with name yields short frame and full NEW_ADVERT frame."""
    pubkey = bytes(range(32))
    contact = Contact(
        public_key=pubkey,
        name="Alice",
        adv_type=1,
        flags=2,
        out_path_len=0,
        out_path=b"",
        last_advert_timestamp=1000,
        lastmod=2000,
        gps_lat=52.5,
        gps_lon=-1.7,
    )
    short, full = _build_advert_push_frames(contact)
    assert full is not None
    # Short frame
    assert len(short) == 1 + PUB_KEY_SIZE
    assert short[0] == PUSH_CODE_ADVERT
    assert short[1:33] == pubkey
    # Full frame: code(1) + pubkey(32) + adv_type,flags,opl(3) + path(64) + name(32)
    # + last_advert(4) + gps_lat(4) + gps_lon(4) + lastmod(4)
    expected_full_len = 1 + 32 + 3 + MAX_PATH_SIZE + 32 + 4 + 4 + 4 + 4
    assert len(full) == expected_full_len
    assert full[0] == PUSH_CODE_NEW_ADVERT
    assert full[1:33] == pubkey
    assert full[33] == 1  # adv_type
    assert full[34] == 2  # flags
    assert full[35] == 0  # opl_byte (out_path_len 0)
    out_path = full[36 : 36 + MAX_PATH_SIZE]
    assert out_path == b"\x00" * MAX_PATH_SIZE
    name_b = full[36 + MAX_PATH_SIZE : 36 + MAX_PATH_SIZE + 32]
    assert name_b.startswith(b"Alice")
    assert name_b.rstrip(b"\x00") == b"Alice"
    offset = 36 + MAX_PATH_SIZE + 32
    assert struct.unpack("<I", full[offset : offset + 4])[0] == 1000
    assert struct.unpack("<i", full[offset + 4 : offset + 8])[0] == int(52.5 * 1e6)
    assert struct.unpack("<i", full[offset + 8 : offset + 12])[0] == int(-1.7 * 1e6)
    assert struct.unpack("<I", full[offset + 12 : offset + 16])[0] == 2000


def test_build_advert_push_frames_pubkey_padded_if_short():
    """Public key shorter than 32 bytes is zero-padded."""
    short_key = bytes([0xAB] * 16)
    contact = Contact(public_key=short_key, name="")
    short, full = _build_advert_push_frames(contact)
    assert short[1:17] == short_key
    assert short[17:33] == b"\x00" * 16


def test_build_advert_push_frames_out_path_len_negative_becomes_0xff():
    """out_path_len < 0 encodes as opl_byte 0xFF."""
    pubkey = bytes(range(32))
    contact = Contact(
        public_key=pubkey,
        name="Bob",
        out_path_len=-1,
    )
    _, full = _build_advert_push_frames(contact)
    assert full is not None
    assert full[35] == 0xFF


@pytest.mark.asyncio
async def test_node_discovered_pushes_new_advert_when_auto_add_filtered():
    """Chat node filtered by selective auto-add still pushes NEW_ADVERT to client."""
    from unittest.mock import AsyncMock

    from openhop_core.companion.companion_bridge import CompanionBridge
    from openhop_core.companion.constants import AUTOADD_REPEATER
    from openhop_core.node.events import MeshEvents
    from openhop_core.protocol import LocalIdentity

    injector = AsyncMock(return_value=True)
    bridge = CompanionBridge(LocalIdentity(), injector)
    bridge.prefs.manual_add_contacts = 1
    bridge.prefs.autoadd_config = AUTOADD_REPEATER

    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_queue = asyncio.Queue(maxsize=256)
    server._setup_push_callbacks()

    peer = LocalIdentity()
    event_data = {
        "public_key": peer.get_public_key().hex(),
        "name": "Meshcore_Jetson_Node",
        "contact_type": 1,
        "lat": 0.0,
        "lon": 0.0,
        "advert_timestamp": 1000,
        "timestamp": 1000,
        "snr": 12.5,
        "rssi": -38,
    }
    await bridge._handle_mesh_event(MeshEvents.NODE_DISCOVERED, event_data)

    assert bridge.contacts.get_count() == 0
    assert server._write_queue.qsize() == 1
    frame = server._write_queue.get_nowait()
    # Queued frames carry a 3-byte outbound header (FRAME_OUTBOUND_PREFIX + uint16 length)
    # prepended by _enqueue_frame; the push code and payload start after it.
    data = frame[3:]
    assert data[0] == PUSH_CODE_NEW_ADVERT
    name_offset = 1 + 32 + 3 + MAX_PATH_SIZE
    name_b = data[name_offset : name_offset + 32]
    assert name_b.startswith(b"Meshcore_Jetson_Node")


@pytest.mark.asyncio
async def test_node_discovered_pushes_short_advert_for_stored_contact():
    """A stored (auto-added) contact's advert pushes the short ADVERT only, mirroring
    firmware onDiscoveredContact(is_new=false)."""
    from unittest.mock import AsyncMock

    from openhop_core.companion.companion_bridge import CompanionBridge
    from openhop_core.node.events import MeshEvents
    from openhop_core.protocol import LocalIdentity

    injector = AsyncMock(return_value=True)
    bridge = CompanionBridge(LocalIdentity(), injector)
    bridge.prefs.manual_add_contacts = 0  # auto-add all types

    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_queue = asyncio.Queue(maxsize=256)
    server._setup_push_callbacks()

    peer = LocalIdentity()
    event_data = {
        "public_key": peer.get_public_key().hex(),
        "name": "StoredNode",
        "contact_type": 1,
        "lat": 0.0,
        "lon": 0.0,
        "advert_timestamp": 1000,
        "timestamp": 1000,
        "snr": 12.5,
        "rssi": -38,
    }
    await bridge._handle_mesh_event(MeshEvents.NODE_DISCOVERED, event_data)

    assert bridge.contacts.get_count() == 1  # stored
    assert server._write_queue.qsize() == 1
    frame = server._write_queue.get_nowait()
    data = frame[3:]  # strip the 3-byte outbound header
    assert data[0] == PUSH_CODE_ADVERT  # short frame only (no full NEW_ADVERT)
    assert len(data) == 1 + PUB_KEY_SIZE


@pytest.mark.asyncio
async def test_self_advert_pushes_no_frame_to_client():
    """Our own advert, heard back off a repeater, is dropped like Mesh::onRecvPacket
    does (Mesh.cpp:263): the client sees neither ADVERT nor NEW_ADVERT."""
    from unittest.mock import AsyncMock

    from openhop_core.companion.companion_bridge import CompanionBridge
    from openhop_core.protocol import LocalIdentity, PacketBuilder

    injector = AsyncMock(return_value=True)
    identity = LocalIdentity()
    bridge = CompanionBridge(identity, injector)

    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_queue = asyncio.Queue(maxsize=256)
    server._setup_push_callbacks()

    await bridge.process_received_packet(PacketBuilder.create_advert(identity, "Me"))
    for _ in range(3):
        await asyncio.sleep(0)

    push_codes = [server._write_queue.get_nowait()[3] for _ in range(server._write_queue.qsize())]
    assert PUSH_CODE_ADVERT not in push_codes
    assert PUSH_CODE_NEW_ADVERT not in push_codes
    assert bridge.contacts.get_count() == 0


def test_build_advert_push_frames_name_truncated_to_32_bytes():
    """Long name is truncated to 32 bytes in full frame."""
    pubkey = bytes(range(32))
    long_name = "A" * 64
    contact = Contact(public_key=pubkey, name=long_name)
    _, full = _build_advert_push_frames(contact)
    assert full is not None
    name_slice = full[36 + MAX_PATH_SIZE : 36 + MAX_PATH_SIZE + 32]
    assert len(name_slice) == 32
    assert name_slice == b"A" * 32


class _MockBridgeSendRawDirect:
    """Minimal bridge for CMD_SEND_RAW_DATA tests."""

    def __init__(self, success: bool = True):
        self.calls = []
        self._success = success

    async def send_raw_data_direct(
        self, path: bytes, payload: bytes, *, path_len_encoded: int = None
    ):
        self.calls.append((path, payload, path_len_encoded))
        return SentResult(success=self._success)


class _MockBridgeChannelData:
    """Minimal bridge for CMD_SEND_CHANNEL_DATA/default-scope tests."""

    def __init__(self, send_ok: bool = True):
        self._send_ok = send_ok
        self._channel = object()
        self.calls = []
        self.default_scope = None

    def get_channel(self, idx: int):
        return self._channel if idx == 1 else None

    async def send_channel_data(
        self, channel_idx, data_type, payload, *, path=None, path_len_encoded=None
    ):
        self.calls.append((channel_idx, data_type, payload, path, path_len_encoded))
        return self._send_ok

    def set_default_flood_scope(self, name, key):
        if not name or not key:
            self.default_scope = None
            return True
        self.default_scope = (name, bytes(key))
        return True

    def get_default_flood_scope(self):
        return self.default_scope


@pytest.mark.asyncio
async def test_cmd_send_raw_data_valid_writes_ok():
    """Valid CMD_SEND_RAW_DATA -> _write_ok."""
    bridge = _MockBridgeSendRawDirect(success=True)
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_ok = Mock()
    server._write_err = Mock()
    data = bytes([1, 0x42]) + b"\x01\x02\x03\x04"
    await server._cmd_send_raw_data(data)
    assert len(bridge.calls) == 1
    path, payload, path_len_enc = bridge.calls[0]
    assert path == b"\x42"
    assert payload == b"\x01\x02\x03\x04"
    assert path_len_enc == 1  # 1-byte hash, 1 hop
    server._write_ok.assert_called_once()
    server._write_err.assert_not_called()


@pytest.mark.asyncio
async def test_cmd_send_channel_data_valid_direct_path():
    """CMD_SEND_CHANNEL_DATA parses path/data_type/payload and delegates to bridge."""
    from openhop_core.protocol.packet_utils import PathUtils

    bridge = _MockBridgeChannelData(send_ok=True)
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_ok = Mock()
    server._write_err = Mock()

    path_len = PathUtils.encode_path_len(1, 2)  # two 1-byte hops
    payload = b"\xde\xad\xbe"
    data = bytes([1, path_len, 0x10, 0x20, 0x34, 0x12]) + payload
    await server._cmd_send_channel_data(data)

    assert bridge.calls == [(1, 0x1234, payload, b"\x10\x20", path_len)]
    server._write_ok.assert_called_once()
    server._write_err.assert_not_called()


@pytest.mark.asyncio
async def test_cmd_send_channel_data_invalid_type_zero():
    """CMD_SEND_CHANNEL_DATA rejects DATA_TYPE_RESERVED (0)."""
    bridge = _MockBridgeChannelData(send_ok=True)
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_ok = Mock()
    server._write_err = Mock()

    # channel=1, flood path (0xFF), data_type=0x0000, payload=b"x"
    await server._cmd_send_channel_data(bytes([1, 0xFF, 0x00, 0x00, 0x78]))
    server._write_err.assert_called_once_with(ERR_CODE_ILLEGAL_ARG)
    server._write_ok.assert_not_called()


@pytest.mark.asyncio
async def test_cmd_send_channel_data_unknown_channel():
    """CMD_SEND_CHANNEL_DATA returns NOT_FOUND for unknown channel index."""
    bridge = _MockBridgeChannelData(send_ok=True)
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_err = Mock()

    await server._cmd_send_channel_data(bytes([2, 0xFF, 0x34, 0x12]))
    server._write_err.assert_called_once_with(ERR_CODE_NOT_FOUND)


@pytest.mark.asyncio
async def test_cmd_add_update_contact_writes_single_ok_response():
    """CMD_ADD_UPDATE_CONTACT should emit one response frame (OK only)."""
    bridge = Mock()
    bridge.add_update_contact = Mock(return_value=True)
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._save_contacts = AsyncMock()
    frames: list[bytes] = []
    server._write_frame = lambda f: frames.append(f)
    server._write_err = Mock()

    pubkey = bytes(range(32))
    adv_type = 1
    flags = 0x01
    out_path_len = 0
    out_path = b"\x00" * MAX_PATH_SIZE
    name = b"Alice".ljust(32, b"\x00")
    last_advert = struct.pack("<I", 123)
    gps_lat = struct.pack("<i", int(52.5 * 1e6))
    gps_lon = struct.pack("<i", int(-1.7 * 1e6))
    lastmod = struct.pack("<I", 456)
    data = (
        pubkey
        + bytes([adv_type, flags, out_path_len & 0xFF])
        + out_path
        + name
        + last_advert
        + gps_lat
        + gps_lon
        + lastmod
    )

    await server._cmd_add_update_contact(data)

    bridge.add_update_contact.assert_called_once()
    assert frames == [bytes([RESP_CODE_OK])]
    server._write_err.assert_not_called()
    server._save_contacts.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("encoded_path_len", "path"),
    [
        (PathUtils.encode_path_len(1, 2), b"\xa1\x00"),
        (PathUtils.encode_path_len(2, 2), b"\x10\x00\x20\x00"),
        (PathUtils.encode_path_len(3, 2), b"\x30\x00\x32\x40\x41\x00"),
        (0, b""),
        (0xFF, b""),
    ],
)
async def test_cmd_add_update_contact_preserves_exact_encoded_path_bytes(encoded_path_len, path):
    """The 64-byte field is padded, but zero bytes inside its encoded path are data."""
    bridge = Mock()
    bridge.add_update_contact = Mock(return_value=True)
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._save_contacts = AsyncMock()
    server._write_frame = Mock()

    data = (
        bytes(range(32))
        + bytes([1, 0x01, encoded_path_len])
        + path.ljust(MAX_PATH_SIZE, b"\x00")
        + b"Alice".ljust(32, b"\x00")
        + struct.pack("<IiiI", 123, int(52.5 * 1e6), int(-1.7 * 1e6), 456)
    )

    await server._cmd_add_update_contact(data)

    contact = bridge.add_update_contact.call_args.args[0]
    assert contact.out_path_len == (-1 if encoded_path_len == 0xFF else encoded_path_len)
    assert contact.out_path == path


@pytest.mark.asyncio
async def test_cmd_send_raw_data_short_of_min_payload_writes_unsupported():
    """path_len=0 but fewer than 4 payload bytes -> ERR_CODE_UNSUPPORTED_CMD.

    Previously this was rejected by a blanket `len(data) < 6` guard; now it
    falls through to the path-aware bounds check (1 + path_byte_len + 4 >
    len(data)), which rejects it for the same reason firmware does
    (MyMesh.cpp: `i + path_len + 4 <= len` fails) with the same error code.
    """
    bridge = _MockBridgeSendRawDirect()
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_ok = Mock()
    server._write_err = Mock()
    await server._cmd_send_raw_data(b"\x00\x00\x00")
    assert len(bridge.calls) == 0
    server._write_err.assert_called_once_with(ERR_CODE_UNSUPPORTED_CMD)
    server._write_ok.assert_not_called()


@pytest.mark.asyncio
async def test_cmd_send_raw_data_zero_hop_minimum_frame_is_accepted():
    """Firmware minimum: path_len=0 (zero-hop, empty path) + 4-byte payload.

    MyMesh.cpp: `len >= 6` (len includes the command byte) with path_len=0
    reduces to `i + 0 + 4 <= len` i.e. exactly 6 bytes total, which is
    len(data) == 5 once the command byte is stripped. This must reach the
    send path, not be rejected as unsupported.
    """
    bridge = _MockBridgeSendRawDirect(success=True)
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_ok = Mock()
    server._write_err = Mock()
    data = bytes([0]) + b"\x01\x02\x03\x04"  # path_len=0, 4-byte payload
    await server._cmd_send_raw_data(data)
    assert len(bridge.calls) == 1
    path, payload, path_len_enc = bridge.calls[0]
    assert path == b""
    assert payload == b"\x01\x02\x03\x04"
    assert path_len_enc == 0
    server._write_ok.assert_called_once()
    server._write_err.assert_not_called()


@pytest.mark.asyncio
async def test_cmd_send_raw_data_empty_payload_writes_unsupported():
    """0-byte data (no path_len byte at all) -> ERR_CODE_UNSUPPORTED_CMD, no send.

    Firmware: `len >= 6` requires at least the command byte, path_len byte,
    and 4-byte payload; a frame with nothing after the command byte fails
    that condition and falls through the else-if chain to the catch-all
    `writeErrFrame(ERR_CODE_UNSUPPORTED_CMD)` (MyMesh.cpp ~L1996). Here we
    must guard against indexing data[0] on empty data and reject the same way.
    """
    bridge = _MockBridgeSendRawDirect()
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_ok = Mock()
    server._write_err = Mock()
    await server._cmd_send_raw_data(b"")
    assert len(bridge.calls) == 0
    server._write_err.assert_called_once_with(ERR_CODE_UNSUPPORTED_CMD)
    server._write_ok.assert_not_called()


@pytest.mark.asyncio
async def test_cmd_send_raw_data_send_failure_writes_table_full():
    """send_raw_data_direct returns False -> ERR_CODE_TABLE_FULL."""
    bridge = _MockBridgeSendRawDirect(success=False)
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_ok = Mock()
    server._write_err = Mock()
    data = bytes([1, 0x42]) + b"\x01\x02\x03\x04"
    await server._cmd_send_raw_data(data)
    assert len(bridge.calls) == 1
    server._write_err.assert_called_once_with(ERR_CODE_TABLE_FULL)
    server._write_ok.assert_not_called()


@pytest.mark.asyncio
async def test_cmd_send_raw_data_2byte_hashes():
    """CMD_SEND_RAW_DATA with 2-byte hash path encoding."""
    from openhop_core.protocol.packet_utils import PathUtils

    bridge = _MockBridgeSendRawDirect(success=True)
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_ok = Mock()
    server._write_err = Mock()
    # path_len_encoded=0x42 → 2-byte hashes, 2 hops → 4 bytes of path
    path_len_byte = PathUtils.encode_path_len(2, 2)  # 0x42
    path_data = b"\x01\x02\x03\x04"
    payload_data = b"\xaa\xbb\xcc\xdd"
    data = bytes([path_len_byte]) + path_data + payload_data
    await server._cmd_send_raw_data(data)
    assert len(bridge.calls) == 1
    path, payload, path_len_enc = bridge.calls[0]
    assert path == path_data
    assert payload == payload_data
    assert path_len_enc == path_len_byte
    server._write_ok.assert_called_once()


@pytest.mark.asyncio
async def test_cmd_send_raw_data_invalid_path_encoding():
    """CMD_SEND_RAW_DATA with reserved hash_size=4 encoding → error."""
    bridge = _MockBridgeSendRawDirect()
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_ok = Mock()
    server._write_err = Mock()
    # 0xC1 = hash_size 4 (reserved), should fail validation
    data = bytes([0xC1]) + b"\x00" * 10
    await server._cmd_send_raw_data(data)
    assert len(bridge.calls) == 0
    server._write_err.assert_called_once_with(ERR_CODE_UNSUPPORTED_CMD)


@pytest.mark.asyncio
async def test_cmd_send_raw_data_truncated_multibyte_path():
    """CMD_SEND_RAW_DATA with not enough path bytes for 2-byte encoding → error."""
    from openhop_core.protocol.packet_utils import PathUtils

    bridge = _MockBridgeSendRawDirect()
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_ok = Mock()
    server._write_err = Mock()
    # 0x43 = 2-byte hashes, 3 hops → needs 6 path bytes + 4 payload = 11 total
    # But only provide 8 bytes after path_len (not enough)
    path_len_byte = PathUtils.encode_path_len(2, 3)  # 0x43
    data = bytes([path_len_byte]) + b"\x00" * 8  # only 8 bytes, need 6+4=10
    await server._cmd_send_raw_data(data)
    assert len(bridge.calls) == 0
    server._write_err.assert_called_once_with(ERR_CODE_UNSUPPORTED_CMD)


@pytest.mark.asyncio
async def test_default_flood_scope_set_get_and_clear():
    """Default flood scope commands encode/decode firmware-compatible payloads."""
    bridge = _MockBridgeChannelData()
    server = CompanionFrameServer(bridge, "hash", port=0)
    frames = []
    server._write_frame = lambda f: frames.append(f)
    server._write_ok = Mock()
    server._write_err = Mock()

    scope_name = "regionA"
    name_field = scope_name.encode("utf-8").ljust(31, b"\x00")
    key = bytes(range(16))

    await server._cmd_set_default_flood_scope(name_field + key)
    server._write_ok.assert_called_once()
    assert bridge.default_scope == (scope_name, key)

    await server._cmd_get_default_flood_scope(b"")
    assert frames[-1][0] == RESP_CODE_DEFAULT_FLOOD_SCOPE
    assert frames[-1][1:32].split(b"\x00", 1)[0] == scope_name.encode("utf-8")
    assert frames[-1][32:48] == key

    await server._cmd_set_default_flood_scope(b"")
    assert bridge.default_scope is None
    await server._cmd_get_default_flood_scope(b"")
    assert frames[-1] == bytes([RESP_CODE_DEFAULT_FLOOD_SCOPE])


def test_build_message_frame_channel_data_v15():
    """Queued binary channel data encodes as RESP_CODE_CHANNEL_DATA_RECV."""
    bridge = Mock()
    bridge.get_time = Mock(return_value=0)
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._app_target_ver = 3
    msg = QueuedMessage(
        sender_key=b"",
        txt_type=0,
        timestamp=0,
        text="",
        is_channel=True,
        channel_idx=4,
        path_len=0xFF,
        snr=2.0,
        rssi=-90,
        channel_data_type=0x1234,
        channel_data_payload=b"\xaa\xbb",
    )
    frame = server._build_message_frame(msg)
    assert frame[0] == RESP_CODE_CHANNEL_DATA_RECV
    assert frame[4] == 4
    assert frame[5] == 0xFF
    assert frame[6:8] == b"\x34\x12"
    assert frame[8] == 2
    assert frame[9:11] == b"\xaa\xbb"


@pytest.mark.asyncio
async def test_push_trace_data_enqueues_frame():
    """push_trace_data enqueues a correctly formatted trace frame."""
    bridge = _MockBridgeSendRawDirect()
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_queue = asyncio.Queue(maxsize=256)

    server.push_trace_data(
        path_len=1,
        flags=0,
        tag=1,
        auth_code=0,
        path_hashes=b"\x00",
        path_snrs=b"\x00",
        final_snr_byte=0,
    )
    assert not server._write_queue.empty()
    frame = server._write_queue.get_nowait()
    # Frame format: FRAME_OUTBOUND_PREFIX + 2-byte LE length + payload
    assert frame[0] == 0x3E  # FRAME_OUTBOUND_PREFIX
    _ = struct.unpack("<H", frame[1:3])[0]  # payload length
    assert frame[3] == 0x89  # PUSH_CODE_TRACE_DATA


@pytest.mark.asyncio
async def test_push_rx_raw_enqueues_frame():
    """push_rx_raw enqueues a correctly formatted RX raw frame."""
    bridge = _MockBridgeSendRawDirect()
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_queue = asyncio.Queue(maxsize=256)

    server.push_rx_raw(snr=-5.0, rssi=-100, raw=b"abc")
    assert not server._write_queue.empty()
    frame = server._write_queue.get_nowait()
    assert frame[0] == 0x3E  # FRAME_OUTBOUND_PREFIX
    assert frame[3] == 0x88  # PUSH_CODE_LOG_RX_DATA


@pytest.mark.asyncio
async def test_push_burst_all_enqueued():
    """Multiple rapid pushes all land in the queue."""
    bridge = _MockBridgeSendRawDirect()
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_queue = asyncio.Queue(maxsize=256)

    for i in range(5):
        server.push_rx_raw(snr=0.0, rssi=-80, raw=bytes([i]))
    assert server._write_queue.qsize() == 5


def test_push_rx_raw_sync_enqueues_immediately():
    """Sync push_rx_raw() enqueues immediately with no event loop scheduling."""
    bridge = _MockBridgeSendRawDirect()
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_queue = asyncio.Queue(maxsize=256)

    server.push_rx_raw(snr=-5.0, rssi=-100, raw=b"abc")
    assert server._write_queue.qsize() == 1


def test_push_trace_data_sync_enqueues_immediately():
    """Sync push_trace_data() enqueues immediately with no event loop scheduling."""
    bridge = _MockBridgeSendRawDirect()
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_queue = asyncio.Queue(maxsize=256)

    server.push_trace_data(
        path_len=1,
        flags=0,
        tag=1,
        auth_code=0,
        path_hashes=b"\x00",
        path_snrs=b"\x00",
        final_snr_byte=0,
    )
    assert server._write_queue.qsize() == 1


@pytest.mark.asyncio
async def test_writer_loop_writes_and_drains():
    """_writer_loop writes enqueued frames and drains."""
    bridge = Mock()
    bridge.get_time = Mock(return_value=12345)
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_queue = asyncio.Queue(maxsize=256)

    writer = Mock()
    writer.write = Mock()
    writer.drain = AsyncMock()
    writer.is_closing = Mock(return_value=False)
    writer.close = Mock()

    # Enqueue a frame only; schedule sentinel after a yield so the queue
    # appears empty when _writer_loop checks after writing the frame,
    # which triggers the drain path.
    server._enqueue_frame(bytes([0x01]))

    async def _send_sentinel():
        await asyncio.sleep(0)  # Yield so writer loop processes frame first
        server._write_queue.put_nowait(None)

    asyncio.create_task(_send_sentinel())

    await server._writer_loop(writer)

    writer.write.assert_called_once()
    writer.drain.assert_awaited_once()


# ---------------------------------------------------------------------------
# CMD_SET_PATH_HASH_MODE tests
# ---------------------------------------------------------------------------


class _MockBridgePathHashMode:
    """Minimal bridge for CMD_SET_PATH_HASH_MODE tests."""

    def __init__(self):
        self.calls = []

    def set_path_hash_mode(self, mode: int) -> None:
        self.calls.append(mode)


@pytest.mark.asyncio
async def test_cmd_set_path_hash_mode_valid():
    """Valid CMD_SET_PATH_HASH_MODE for each mode (0, 1, 2) → _write_ok."""
    for mode in (0, 1, 2):
        bridge = _MockBridgePathHashMode()
        server = CompanionFrameServer(bridge, "hash", port=0)
        server._write_ok = Mock()
        server._write_err = Mock()
        await server._cmd_set_path_hash_mode(bytes([0, mode]))
        assert bridge.calls == [mode]
        server._write_ok.assert_called_once()
        server._write_err.assert_not_called()


@pytest.mark.asyncio
async def test_cmd_set_path_hash_mode_invalid_mode():
    """CMD_SET_PATH_HASH_MODE with mode >= 3 → ERR_CODE_ILLEGAL_ARG."""
    from openhop_core.companion.constants import ERR_CODE_ILLEGAL_ARG

    bridge = _MockBridgePathHashMode()
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_ok = Mock()
    server._write_err = Mock()
    await server._cmd_set_path_hash_mode(bytes([0, 3]))
    assert len(bridge.calls) == 0
    server._write_err.assert_called_once_with(ERR_CODE_ILLEGAL_ARG)


@pytest.mark.asyncio
async def test_cmd_set_path_hash_mode_wrong_subtype():
    """CMD_SET_PATH_HASH_MODE with subtype != 0 → ERR_CODE_ILLEGAL_ARG."""
    from openhop_core.companion.constants import ERR_CODE_ILLEGAL_ARG

    bridge = _MockBridgePathHashMode()
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_ok = Mock()
    server._write_err = Mock()
    await server._cmd_set_path_hash_mode(bytes([1, 0]))
    assert len(bridge.calls) == 0
    server._write_err.assert_called_once_with(ERR_CODE_ILLEGAL_ARG)


@pytest.mark.asyncio
async def test_cmd_set_path_hash_mode_too_short():
    """CMD_SET_PATH_HASH_MODE with only 1 byte → ERR_CODE_ILLEGAL_ARG."""
    from openhop_core.companion.constants import ERR_CODE_ILLEGAL_ARG

    bridge = _MockBridgePathHashMode()
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_ok = Mock()
    server._write_err = Mock()
    await server._cmd_set_path_hash_mode(bytes([0]))
    assert len(bridge.calls) == 0
    server._write_err.assert_called_once_with(ERR_CODE_ILLEGAL_ARG)


@pytest.mark.asyncio
async def test_device_info_includes_path_hash_mode():
    """RESP_CODE_DEVICE_INFO frame includes path_hash_mode at byte [81]."""
    from openhop_core.companion.constants import RESP_CODE_DEVICE_INFO
    from openhop_core.companion.models import NodePrefs

    prefs = NodePrefs()
    prefs.path_hash_mode = 2  # 3-byte hashes

    bridge = Mock()
    bridge.get_self_info = Mock(return_value=prefs)
    bridge.contacts = Mock(max_contacts=100)
    bridge.channels = Mock(max_channels=8)

    server = CompanionFrameServer(bridge, "hash", port=0)
    frames = []
    server._write_frame = lambda f: frames.append(f)

    await server._cmd_device_query(bytes([10]))  # app_ver = 10

    assert len(frames) == 1
    frame = frames[0]
    assert frame[0] == RESP_CODE_DEVICE_INFO
    assert len(frame) == 82  # 81 bytes (old) + 1 byte path_hash_mode
    assert frame[81] == 2  # path_hash_mode at last byte


@pytest.mark.asyncio
async def test_autoadd_config_set_and_get_round_trips_max_hops():
    """CMD_SET_AUTOADD_CONFIG stores the optional max-hop byte (capped at 64) and
    CMD_GET_AUTOADD_CONFIG returns config + max_hops (firmware parity)."""
    from openhop_core.companion.companion_bridge import CompanionBridge
    from openhop_core.companion.constants import RESP_CODE_AUTOADD_CONFIG
    from openhop_core.protocol import LocalIdentity

    bridge = CompanionBridge(LocalIdentity(), AsyncMock(return_value=True))
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_ok = Mock()
    frames = []
    server._write_frame = lambda f: frames.append(f)

    # data excludes the command byte: [config, max_hops]
    await server._cmd_set_autoadd_config(bytes([0x06, 3]))
    server._write_ok.assert_called_once()
    assert bridge.prefs.autoadd_config == 0x06
    assert bridge.prefs.autoadd_max_hops == 3

    await server._cmd_get_autoadd_config(b"")
    assert frames == [bytes([RESP_CODE_AUTOADD_CONFIG, 0x06, 3])]

    # max-hop byte is capped at 64.
    await server._cmd_set_autoadd_config(bytes([0x06, 200]))
    assert bridge.prefs.autoadd_max_hops == 64

    # config-only frame leaves the stored max-hop value unchanged.
    await server._cmd_set_autoadd_config(bytes([0x02]))
    assert bridge.prefs.autoadd_config == 0x02
    assert bridge.prefs.autoadd_max_hops == 64


@pytest.mark.asyncio
async def test_set_other_params_preserves_omitted_fields():
    """CMD_SET_OTHER_PARAMS is backward-compatible: a short frame updates only the
    fields it carries and leaves newer, omitted fields untouched (firmware parity)."""
    from openhop_core.companion.companion_bridge import CompanionBridge
    from openhop_core.protocol import LocalIdentity

    bridge = CompanionBridge(LocalIdentity(), AsyncMock(return_value=True))
    # Seed non-default values for every optional field.
    bridge.prefs.manual_add_contacts = 0
    bridge.prefs.telemetry_mode_base = 1
    bridge.prefs.telemetry_mode_location = 2
    bridge.prefs.telemetry_mode_environment = 3
    bridge.prefs.advert_loc_policy = 7
    bridge.prefs.multi_acks = 4

    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_ok = Mock()
    server._write_err = Mock()

    # data excludes the command byte. len==1: only manual_add changes.
    await server._cmd_set_other_params(bytes([1]))
    server._write_ok.assert_called_once()
    assert bridge.prefs.manual_add_contacts == 1
    assert bridge.prefs.telemetry_mode_base == 1
    assert bridge.prefs.telemetry_mode_location == 2
    assert bridge.prefs.telemetry_mode_environment == 3
    assert bridge.prefs.advert_loc_policy == 7
    assert bridge.prefs.multi_acks == 4

    # len==2: telemetry byte present (base=2, loc=1, env=0), others preserved.
    telem = (2 & 0x03) | ((1 & 0x03) << 2) | ((0 & 0x03) << 4)
    await server._cmd_set_other_params(bytes([1, telem]))
    assert bridge.prefs.telemetry_mode_base == 2
    assert bridge.prefs.telemetry_mode_location == 1
    assert bridge.prefs.telemetry_mode_environment == 0
    assert bridge.prefs.advert_loc_policy == 7  # still preserved
    assert bridge.prefs.multi_acks == 4  # still preserved

    # len==3: advert_loc_policy present; multi_acks preserved.
    await server._cmd_set_other_params(bytes([1, telem, 9]))
    assert bridge.prefs.advert_loc_policy == 9
    assert bridge.prefs.multi_acks == 4  # still preserved

    # len==4: multi_acks present.
    await server._cmd_set_other_params(bytes([1, telem, 9, 5]))
    assert bridge.prefs.multi_acks == 5


# ---------------------------------------------------------------------------
# CMD_SEND_STATUS_REQ / CMD_SEND_TELEMETRY_REQ — send result and response push
# ---------------------------------------------------------------------------


async def _return_result(result: dict) -> dict:
    return result


@pytest.mark.asyncio
async def test_cmd_send_login_timeout_does_not_emit_failure_push():
    from openhop_core.companion.constants import PUSH_CODE_LOGIN_FAIL

    pubkey = bytes(range(32))
    bridge = Mock()
    bridge._start_frame_login_request = AsyncMock(
        return_value={
            "success": True,
            "sent": SentResult(success=True, is_flood=True, expected_ack=0x1122, timeout_ms=9000),
            "task": asyncio.create_task(
                _return_result(
                    {"success": False, "timeout": True, "reason": "Login response timeout"}
                )
            ),
        }
    )
    server = CompanionFrameServer(bridge, "hash", port=0)
    frames: list[bytes] = []
    server._write_frame = lambda f: frames.append(f)

    await server._cmd_send_login(pubkey + b"pw")
    await asyncio.sleep(0)

    assert frames == [bytes([RESP_CODE_SENT, 1]) + struct.pack("<II", 0x1122, 9000)]
    assert not any(frame[0] == PUSH_CODE_LOGIN_FAIL for frame in frames)


@pytest.mark.asyncio
async def test_cmd_send_login_retry_has_one_completion_writer():
    """Repeated commands each get SENT, but one logical session emits one push."""
    from openhop_core.companion.constants import PUSH_CODE_LOGIN_SUCCESS

    pubkey = bytes(range(32))
    result_task = asyncio.create_task(
        _return_result(
            {
                "success": True,
                "is_admin": True,
                "tag": 123,
                "acl_permissions": 3,
                "firmware_ver_level": 2,
            }
        )
    )
    sent = SentResult(success=True, is_flood=True, expected_ack=0x1122, timeout_ms=9000)
    bridge = Mock()
    bridge._start_frame_login_request = AsyncMock(
        side_effect=[
            {
                "success": True,
                "sent": sent,
                "task": result_task,
                "session_owner": True,
            },
            {
                "success": True,
                "sent": sent,
                "task": result_task,
                "session_owner": False,
            },
        ]
    )
    server = CompanionFrameServer(bridge, "hash", port=0)
    frames: list[bytes] = []
    server._write_frame = lambda frame: frames.append(frame)

    await server._cmd_send_login(pubkey + b"pw")
    await server._cmd_send_login(pubkey + b"pw")
    await asyncio.sleep(0)

    assert sum(frame[0] == RESP_CODE_SENT for frame in frames) == 2
    assert sum(frame[0] == PUSH_CODE_LOGIN_SUCCESS for frame in frames) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "result_extra, expected_byte",
    [
        # Admin: byte 1 is 1, as before.
        ({"is_admin": True, "admin_code": 1, "acl_permissions": 3}, 1),
        # Room server "plain guest": firmware sends 2 on this byte and our
        # companion forwards it verbatim rather than collapsing it to 0/1.
        ({"is_admin": False, "admin_code": 2, "acl_permissions": 0}, 2),
        ({"is_admin": False, "admin_code": 0, "acl_permissions": 2}, 0),
        # No admin_code (older bridge result): fall back to the boolean.
        ({"is_admin": True, "acl_permissions": 3}, 1),
    ],
)
async def test_login_success_push_forwards_the_raw_admin_byte(result_extra, expected_byte):
    """PUSH_CODE_LOGIN_SUCCESS byte 1 mirrors the server's reply byte 6.

    companion_radio does `out_frame[i++] = data[6]`, and a room server uses
    that byte as a tri-state (admin=1, plain guest=2, other=0).
    """
    from openhop_core.companion.constants import PUSH_CODE_LOGIN_SUCCESS

    pubkey = bytes(range(32))
    result = {"success": True, "tag": 123, "firmware_ver_level": 2, **result_extra}
    sent = SentResult(success=True, is_flood=True, expected_ack=0x1122, timeout_ms=9000)
    bridge = Mock()
    bridge._start_frame_login_request = AsyncMock(
        return_value={
            "success": True,
            "sent": sent,
            "task": asyncio.create_task(_return_result(result)),
            "session_owner": True,
        }
    )
    server = CompanionFrameServer(bridge, "hash", port=0)
    frames: list[bytes] = []
    server._write_frame = lambda f: frames.append(f)

    await server._cmd_send_login(pubkey + b"pw")
    await asyncio.sleep(0)

    pushes = [f for f in frames if f[0] == PUSH_CODE_LOGIN_SUCCESS]
    assert len(pushes) == 1
    assert pushes[0][1] == expected_byte
    # Byte 7 of the reply still rides along as the authoritative ACL byte.
    assert pushes[0][12] == result["acl_permissions"]


@pytest.mark.asyncio
async def test_cmd_send_status_req_failure_no_empty_push():
    """A failed status send returns an error and no SENT frame."""
    from openhop_core.companion.constants import PUSH_CODE_STATUS_RESPONSE

    bridge = Mock()
    bridge._start_status_request = AsyncMock(
        return_value={"success": False, "error": "send_failed", "reason": "Send failed"}
    )
    server = CompanionFrameServer(bridge, "hash", port=0)
    frames: list[bytes] = []
    server._write_frame = lambda f: frames.append(f)

    pubkey = bytes(range(32))
    await server._cmd_send_status_req(pubkey)

    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_TABLE_FULL])]
    assert not any(f[0] == PUSH_CODE_STATUS_RESPONSE for f in frames)


@pytest.mark.asyncio
async def test_cmd_send_status_req_empty_raw_bytes_no_push():
    """Status response with empty raw_bytes must NOT send PUSH_CODE_STATUS_RESPONSE."""
    from openhop_core.companion.constants import PUSH_CODE_STATUS_RESPONSE

    bridge = Mock()
    bridge._start_status_request = AsyncMock(
        return_value={
            "success": True,
            "sent": SentResult(success=True, is_flood=False, expected_ack=0x1122, timeout_ms=9000),
            "task": asyncio.create_task(
                _return_result({"success": True, "stats": {"raw_bytes": b""}})
            ),
        }
    )
    server = CompanionFrameServer(bridge, "hash", port=0)
    frames: list[bytes] = []
    server._write_frame = lambda f: frames.append(f)

    pubkey = bytes(range(32))
    await server._cmd_send_status_req(pubkey)
    await asyncio.sleep(0)

    assert frames == [bytes([RESP_CODE_SENT, 0]) + struct.pack("<II", 0x1122, 9000)]
    assert not any(f[0] == PUSH_CODE_STATUS_RESPONSE for f in frames)


@pytest.mark.asyncio
async def test_cmd_send_status_req_success_sends_push_with_data():
    """Successful status request with data sends PUSH_CODE_STATUS_RESPONSE with raw_bytes."""
    from openhop_core.companion.constants import PUSH_CODE_STATUS_RESPONSE

    raw = b"\x01" * 56
    bridge = Mock()
    bridge._start_status_request = AsyncMock(
        return_value={
            "success": True,
            "sent": SentResult(success=True, is_flood=True, expected_ack=0x3344, timeout_ms=7000),
            "task": asyncio.create_task(
                _return_result({"success": True, "stats": {"raw_bytes": raw}})
            ),
        }
    )
    server = CompanionFrameServer(bridge, "hash", port=0)
    frames: list[bytes] = []
    server._write_frame = lambda f: frames.append(f)

    pubkey = bytes(range(32))
    await server._cmd_send_status_req(pubkey)
    await asyncio.sleep(0)

    status_frames = [f for f in frames if f[0] == PUSH_CODE_STATUS_RESPONSE]
    assert frames[0] == bytes([RESP_CODE_SENT, 1]) + struct.pack("<II", 0x3344, 7000)
    assert len(status_frames) == 1
    # Frame: cmd(1) + reserved(1) + pubkey_prefix(6) + raw_bytes(56) = 64
    assert len(status_frames[0]) == 64
    assert status_frames[0][8:] == raw


@pytest.mark.asyncio
async def test_cmd_send_telemetry_req_failure_no_empty_push():
    """A failed telemetry send returns an error and no SENT frame."""
    from openhop_core.companion.constants import PUSH_CODE_TELEMETRY_RESPONSE

    bridge = Mock()
    bridge._start_telemetry_request = AsyncMock(
        return_value={"success": False, "error": "send_failed", "reason": "Send failed"}
    )
    server = CompanionFrameServer(bridge, "hash", port=0)
    frames: list[bytes] = []
    server._write_frame = lambda f: frames.append(f)

    # CMD_SEND_TELEMETRY_REQ expects 3 reserved bytes + 32-byte pubkey
    pubkey = bytes(range(32))
    data = bytes(3) + pubkey
    await server._cmd_send_telemetry_req(data)

    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_TABLE_FULL])]
    assert not any(f[0] == PUSH_CODE_TELEMETRY_RESPONSE for f in frames)


@pytest.mark.asyncio
async def test_cmd_send_telemetry_req_self_form_pushes_local_telemetry():
    """Self form (data == 3) pushes voltage floor + sensor LPP synchronously.

    Firmware MyMesh.cpp:1642-1656. 4200 mV -> CayenneLPP voltage entry
    [channel=0x01][type=0x74][value big-endian]; value = int(4.2f * 100) = 419
    (0x01A3) because firmware computes value*multiplier in single-precision
    float and truncates.
    """
    from openhop_core.companion.constants import PUSH_CODE_TELEMETRY_RESPONSE

    self_pubkey = bytes(range(100, 132))
    sensor_lpp = b"\x02\x67\x01\x10"  # arbitrary known sensor LPP bytes
    bridge = Mock()
    bridge.get_public_key = Mock(return_value=self_pubkey)
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._get_batt_and_storage = lambda: (4200, 0, 0)
    server._get_self_telemetry_lpp = lambda: sensor_lpp
    frames: list[bytes] = []
    server._write_frame = lambda f: frames.append(f)

    await server._cmd_send_telemetry_req(b"\x00\x00\x00")

    expected_voltage = bytes([0x01, 0x74, 0x01, 0xA3])
    assert frames == [
        bytes([PUSH_CODE_TELEMETRY_RESPONSE, 0x00])
        + self_pubkey[:6]
        + expected_voltage
        + sensor_lpp
    ]


@pytest.mark.asyncio
async def test_cmd_send_telemetry_req_self_form_voltage_floor_when_no_sensors():
    """Self form still pushes the voltage-only floor when there is no sensor data."""
    from openhop_core.companion.constants import PUSH_CODE_TELEMETRY_RESPONSE

    self_pubkey = bytes(range(32))
    bridge = Mock()
    bridge.get_public_key = Mock(return_value=self_pubkey)
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._get_batt_and_storage = lambda: (3700, 0, 0)
    server._get_self_telemetry_lpp = lambda: b""
    frames: list[bytes] = []
    server._write_frame = lambda f: frames.append(f)

    await server._cmd_send_telemetry_req(b"\x00\x00\x00")

    # 3700 mV -> 3.7f * 100 = 370 (0x0172).
    expected_voltage = bytes([0x01, 0x74, 0x01, 0x72])
    assert frames == [
        bytes([PUSH_CODE_TELEMETRY_RESPONSE, 0x00]) + self_pubkey[:6] + expected_voltage
    ]


@pytest.mark.asyncio
async def test_cmd_send_telemetry_req_mid_length_unsupported():
    """A frame length that matches neither form -> UNSUPPORTED_CMD (else-if fall-through)."""
    bridge = Mock()
    server = CompanionFrameServer(bridge, "hash", port=0)
    frames: list[bytes] = []
    server._write_frame = lambda f: frames.append(f)

    await server._cmd_send_telemetry_req(b"\x00" * 10)

    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_UNSUPPORTED_CMD])]


@pytest.mark.asyncio
async def test_cmd_send_telemetry_req_empty_unsupported():
    """An empty frame -> UNSUPPORTED_CMD (else-if fall-through)."""
    bridge = Mock()
    server = CompanionFrameServer(bridge, "hash", port=0)
    frames: list[bytes] = []
    server._write_frame = lambda f: frames.append(f)

    await server._cmd_send_telemetry_req(b"")

    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_UNSUPPORTED_CMD])]


@pytest.mark.asyncio
async def test_cmd_send_telemetry_req_remote_form_unchanged():
    """Remote/contact form (data >= 35) still sends a SENT result + deferred push."""
    from openhop_core.companion.constants import PUSH_CODE_TELEMETRY_RESPONSE

    pubkey = bytes(range(32))
    raw = b"\x01" * 20
    bridge = Mock()
    bridge._start_telemetry_request = AsyncMock(
        return_value={
            "success": True,
            "sent": SentResult(success=True, is_flood=False, expected_ack=0x5566, timeout_ms=8000),
            "task": asyncio.create_task(
                _return_result({"success": True, "telemetry_data": {"raw_bytes": raw}})
            ),
        }
    )
    server = CompanionFrameServer(bridge, "hash", port=0)
    frames: list[bytes] = []
    server._write_frame = lambda f: frames.append(f)

    await server._cmd_send_telemetry_req(bytes(3) + pubkey)
    await asyncio.sleep(0)

    assert frames[0] == bytes([RESP_CODE_SENT, 0]) + struct.pack("<II", 0x5566, 8000)
    telem_frames = [f for f in frames if f[0] == PUSH_CODE_TELEMETRY_RESPONSE]
    assert len(telem_frames) == 1
    assert telem_frames[0] == bytes([PUSH_CODE_TELEMETRY_RESPONSE, 0]) + pubkey[:6] + raw


class _BlockingReader:
    """Reader that blocks until released, then returns EOF."""

    def __init__(self, release_event: asyncio.Event):
        self._release_event = release_event

    async def read(self, _n: int) -> bytes:
        await self._release_event.wait()
        return b""

    async def readexactly(self, n: int) -> bytes:
        raise asyncio.IncompleteReadError(partial=b"", expected=n)


class _NeverReader:
    """Reader that never returns (for idle-timeout path)."""

    async def read(self, _n: int) -> bytes:
        await asyncio.sleep(3600)
        return b""

    async def readexactly(self, n: int) -> bytes:
        raise asyncio.IncompleteReadError(partial=b"", expected=n)


class _RaisingReader:
    """Reader that raises a socket-style exception on read()."""

    def __init__(self, exc: Exception):
        self._exc = exc

    async def read(self, _n: int) -> bytes:
        raise self._exc

    async def readexactly(self, n: int) -> bytes:
        raise self._exc


class _DummyWriter:
    """Minimal writer for _handle_client tests."""

    def __init__(self):
        self.closed = False

    def get_extra_info(self, _name):
        return None

    def write(self, _data: bytes) -> None:
        return None

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None

    def is_closing(self) -> bool:
        return self.closed


@pytest.mark.asyncio
async def test_evicted_handler_cleanup_does_not_cancel_new_writer_task():
    """Old handler finally block must not tear down new client writer state."""
    bridge = Mock()
    bridge.get_time = Mock(return_value=0)
    server = CompanionFrameServer(bridge, "hash", port=0, client_idle_timeout_sec=None)

    first_release = asyncio.Event()
    second_release = asyncio.Event()
    reader1 = _BlockingReader(first_release)
    reader2 = _BlockingReader(second_release)
    writer1 = _DummyWriter()
    writer2 = _DummyWriter()

    task1 = asyncio.create_task(server._handle_client(reader1, writer1))
    for _ in range(50):
        if server._client_writer is writer1 and server._writer_task is not None:
            break
        await asyncio.sleep(0)
    assert server._client_writer is writer1

    task2 = asyncio.create_task(server._handle_client(reader2, writer2))
    for _ in range(50):
        if server._client_writer is writer2 and server._writer_task is not None:
            break
        await asyncio.sleep(0)
    assert server._client_writer is writer2

    writer2_task = server._writer_task
    assert writer2_task is not None
    assert not writer2_task.done()

    # Release old handler; its finally should not cancel the new handler writer task.
    first_release.set()
    await task1

    assert server._writer_task is writer2_task
    assert not writer2_task.done()

    # Cleanly exit task2.
    second_release.set()
    await task2


@pytest.mark.asyncio
async def test_handle_client_idle_timeout_disconnects_cleanly(caplog):
    """Idle timeout disconnect path leaves no active client state."""
    caplog.set_level(logging.INFO, logger="CompanionFrameServer")
    bridge = Mock()
    bridge.get_time = Mock(return_value=0)
    server = CompanionFrameServer(bridge, "hash", port=0, client_idle_timeout_sec=0.01)

    await server._handle_client(_NeverReader(), _DummyWriter())

    assert server._client_writer is None
    assert server._client_reader is None
    assert server._writer_task is None
    assert any("idle_timeout" in rec.message for rec in caplog.records)


@pytest.mark.asyncio
async def test_handle_client_connection_reset_disconnects_cleanly(caplog):
    """ConnectionResetError path leaves no active client state."""
    caplog.set_level(logging.INFO, logger="CompanionFrameServer")
    bridge = Mock()
    bridge.get_time = Mock(return_value=0)
    server = CompanionFrameServer(bridge, "hash", port=0, client_idle_timeout_sec=None)

    await server._handle_client(_RaisingReader(ConnectionResetError("boom")), _DummyWriter())

    assert server._client_writer is None
    assert server._client_reader is None
    assert server._writer_task is None
    assert any("ConnectionResetError" in rec.message for rec in caplog.records)


class _FakeSocket:
    """Records setsockopt calls; raises AttributeError for a missing constant."""

    def __init__(self):
        self.calls = []

    def setsockopt(self, level, optname, value):
        self.calls.append((level, optname, value))


class _SocketWriter:
    """Minimal writer exposing a fake underlying socket via get_extra_info."""

    def __init__(self, sock):
        self._sock = sock

    def get_extra_info(self, name):
        return self._sock if name == "socket" else None


def test_configure_socket_survives_missing_tcp_keepalive_constant(monkeypatch, caplog):
    """A Python build lacking socket.TCP_KEEPALIVE must not crash client setup.

    Some Python/macOS builds do not expose socket.TCP_KEEPALIVE at all, so
    referencing it raises AttributeError rather than the OSError the platform
    branch already guards against.
    """
    caplog.set_level(logging.DEBUG, logger="CompanionFrameServer")
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.delattr(socket, "TCP_KEEPALIVE", raising=False)

    sock = _FakeSocket()
    writer = _SocketWriter(sock)

    CompanionFrameServer._configure_socket(writer)  # must not raise

    # TCP_NODELAY and SO_KEEPALIVE are independent of TCP_KEEPALIVE and must
    # still be applied.
    assert (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1) in sock.calls
    assert (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1) in sock.calls


@pytest.mark.asyncio
async def test_cmd_get_allowed_repeat_freq_returns_ranges():
    """CMD_GET_ALLOWED_REPEAT_FREQ replies with (lower,upper) u32le kHz pairs."""
    bridge = Mock()
    bridge.get_allowed_repeat_freqs.return_value = ((433000, 433000), (918000, 918000))
    server = CompanionFrameServer(bridge, "hash", port=0)
    frames: list[bytes] = []
    server._write_frame = lambda f: frames.append(f)
    await server._cmd_get_allowed_repeat_freq(b"")
    assert frames == [
        bytes([RESP_CODE_ALLOWED_REPEAT_FREQ])
        + struct.pack("<II", 433000, 433000)
        + struct.pack("<II", 918000, 918000)
    ]


@pytest.mark.asyncio
async def test_cmd_send_raw_packet_unsupported_without_bridge_method():
    """CMD_SEND_RAW_PACKET returns UNSUPPORTED when the bridge can't inject packets."""
    bridge = Mock(spec=[])  # no send_raw_packet attribute
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_err = Mock()
    server._write_ok = Mock()
    await server._cmd_send_raw_packet(bytes([0x00, 0xAA, 0xBB]))
    server._write_err.assert_called_once_with(ERR_CODE_UNSUPPORTED_CMD)
    server._write_ok.assert_not_called()


@pytest.mark.asyncio
async def test_cmd_send_raw_packet_delegates_to_bridge():
    """CMD_SEND_RAW_PACKET parses [priority][raw...] and delegates to the bridge."""
    bridge = Mock()
    bridge.send_raw_packet = AsyncMock(return_value=True)
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_ok = Mock()
    server._write_err = Mock()
    await server._cmd_send_raw_packet(bytes([0x05, 0xDE, 0xAD, 0xBE]))
    bridge.send_raw_packet.assert_awaited_once_with(0x05, b"\xde\xad\xbe")
    server._write_ok.assert_called_once()
    server._write_err.assert_not_called()


@pytest.mark.asyncio
async def test_cmd_send_raw_packet_too_short():
    """CMD_SEND_RAW_PACKET rejects a frame with no packet body."""
    server = CompanionFrameServer(Mock(), "hash", port=0)
    server._write_err = Mock()
    await server._cmd_send_raw_packet(bytes([0x00]))
    server._write_err.assert_called_once_with(ERR_CODE_ILLEGAL_ARG)


def test_parse_binary_response_regions():
    """Anon REGIONS response decodes clock + comma-separated region names."""
    from openhop_core.companion import binary_parsing
    from openhop_core.companion.constants import (
        ANON_REQ_TYPE_REGIONS,
        PROTOCOL_CODE_ANON_REQ,
    )

    # response_data (tag already stripped) = clock(4) + null-terminated name list
    data = struct.pack("<I", 0x11223344) + b"home,usa,*\x00"
    parsed = binary_parsing.parse_binary_response(
        PROTOCOL_CODE_ANON_REQ, data, context={"anon_sub_type": ANON_REQ_TYPE_REGIONS}
    )
    assert parsed["type"] == "regions"
    assert parsed["clock"] == 0x11223344
    assert parsed["regions"] == ["home", "usa", "*"]


def test_parse_binary_response_anon_not_mistaken_for_owner_info():
    """A REGIONS anon response must NOT be parsed as REQ owner-info, even though
    both carry numeric type 0x07."""
    from openhop_core.companion import binary_parsing
    from openhop_core.companion.constants import (
        ANON_REQ_TYPE_REGIONS,
        PROTOCOL_CODE_ANON_REQ,
    )

    data = struct.pack("<I", 0) + b"alpha\x00"
    parsed = binary_parsing.parse_binary_response(
        PROTOCOL_CODE_ANON_REQ, data, context={"anon_sub_type": ANON_REQ_TYPE_REGIONS}
    )
    assert parsed["type"] == "regions"
    assert "owner_info" not in parsed


def test_device_info_reports_firmware_ver_code_13():
    """Companion advertises FIRMWARE_VER_CODE 13 (PR #2672 non-contact anon requests)."""
    from openhop_core.companion.constants import FIRMWARE_VER_CODE

    assert FIRMWARE_VER_CODE == 13


class _MockBridgeAnonReq:
    """Minimal bridge for CMD_SEND_ANON_REQ tests."""

    def __init__(self, result: SentResult):
        self._result = result
        self.calls = []

    async def send_anon_req(self, pub_key: bytes, data: bytes):
        self.calls.append((pub_key, data))
        return self._result


@pytest.mark.asyncio
async def test_cmd_send_anon_req_failure_writes_table_full():
    """PR #2672: anon-req failure maps to ERR_CODE_TABLE_FULL, not NOT_FOUND."""
    bridge = _MockBridgeAnonReq(SentResult(success=False))
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_err = Mock()
    server._write_frame = Mock()
    await server._cmd_send_anon_req(b"\x01" * 32 + b"\x07")
    assert len(bridge.calls) == 1
    server._write_err.assert_called_once_with(ERR_CODE_TABLE_FULL)
    server._write_frame.assert_not_called()


@pytest.mark.asyncio
async def test_cmd_send_anon_req_success_writes_sent():
    """Successful anon req emits a RESP_CODE_SENT frame (direct => flood byte 0)."""
    from openhop_core.companion.constants import RESP_CODE_SENT

    bridge = _MockBridgeAnonReq(
        SentResult(success=True, is_flood=False, expected_ack=0x11223344, timeout_ms=4000)
    )
    server = CompanionFrameServer(bridge, "hash", port=0)
    frames = []
    server._write_frame = Mock(side_effect=lambda f: frames.append(f))
    server._write_err = Mock()
    await server._cmd_send_anon_req(b"\x02" * 32 + b"\x07")
    server._write_err.assert_not_called()
    assert len(frames) == 1
    assert frames[0][0] == RESP_CODE_SENT
    assert frames[0][1] == 0  # not flood
    assert struct.unpack("<I", frames[0][2:6])[0] == 0x11223344
    assert 0x11223344 in server._companion_binary_tags


def test_binary_response_push_only_for_owned_tag():
    """Unowned non-region responses are ignored; owned and region responses pass."""
    bridge = Mock()
    for cb_name in (
        "on_message_event",
        "on_channel_message_event",
        "on_channel_data_event",
        "on_send_confirmed",
        "on_advert_received",
        "on_node_discovered",
        "on_contact_path_updated",
        "on_binary_response",
        "on_path_discovery_response",
        "on_contact_deleted",
        "on_contacts_full",
        "on_raw_data_received",
    ):
        setattr(bridge, cb_name, Mock())
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_queue = asyncio.Queue(maxsize=16)
    server._setup_push_callbacks()

    on_binary = bridge.on_binary_response.call_args[0][0]
    tag = 0x11223344
    tag_bytes = struct.pack("<I", tag)

    # Unowned response is ignored.
    on_binary(tag_bytes, b"\xaa\xbb")
    assert server._write_queue.qsize() == 0

    # Unowned regions response is allowed for compatibility.
    on_binary(tag_bytes, b"\xaa\xbb", {"type": "regions"}, 7)
    assert server._write_queue.qsize() == 1
    compat_frame = server._write_queue.get_nowait()
    compat_payload = compat_frame[3:]
    assert compat_payload[0] == PUSH_CODE_BINARY_RESPONSE
    assert compat_payload[2:6] == tag_bytes
    assert compat_payload[6:] == b"\xaa\xbb"

    # Owned response is pushed and tag ownership is consumed.
    server._companion_binary_tags.add(tag)
    on_binary(tag_bytes, b"\xaa\xbb")
    assert server._write_queue.qsize() == 1
    frame = server._write_queue.get_nowait()
    payload = frame[3:]  # strip outbound frame prefix+len
    assert payload[0] == PUSH_CODE_BINARY_RESPONSE
    assert payload[2:6] == tag_bytes
    assert payload[6:] == b"\xaa\xbb"
    assert tag not in server._companion_binary_tags


def _path_discovery_server():
    """Build a frame server with a queue for path-discovery push tests."""
    bridge = Mock()
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_queue = asyncio.Queue(maxsize=16)
    return server


def _path_push_payload(frame):
    """Strip the outbound frame prefix (1 byte code + 2 byte len) from a queued frame."""
    return frame[3:]


def test_path_discovery_push_preserves_encoded_len_2byte():
    """2-byte-hash paths re-announce the ENCODED path_len byte verbatim, not a raw
    byte count. Firmware writes out_path_len / in_path_len directly
    (MyMesh.cpp:757-765)."""
    server = _path_discovery_server()
    pubkey = bytes(range(32))
    out_path = bytes([0x11, 0x22, 0x33, 0x44])  # encoded 0x42 = size 2, count 2
    in_path = bytes([0xAA, 0xBB])  # encoded 0x41 = size 2, count 1
    server._on_path_discovery_response(b"\x00\x00\x00\x00", pubkey, 0x42, out_path, 0x41, in_path)
    assert server._write_queue.qsize() == 1
    payload = _path_push_payload(server._write_queue.get_nowait())
    assert payload == (
        bytes([PUSH_CODE_PATH_DISCOVERY_RESPONSE, 0])
        + pubkey[:6]
        + bytes([0x42])
        + out_path
        + bytes([0x41])
        + in_path
    )


def test_path_discovery_push_1byte_unchanged():
    """1-byte-hash paths (encoded byte == raw hop count) are unchanged (backward-compat)."""
    server = _path_discovery_server()
    pubkey = bytes(range(32))
    out_path = bytes([0x01, 0x02, 0x03])  # encoded 0x03 = size 1, count 3
    in_path = bytes([0x04, 0x05, 0x06])
    server._on_path_discovery_response(b"\x00\x00\x00\x00", pubkey, 0x03, out_path, 0x03, in_path)
    payload = _path_push_payload(server._write_queue.get_nowait())
    assert payload == (
        bytes([PUSH_CODE_PATH_DISCOVERY_RESPONSE, 0])
        + pubkey[:6]
        + bytes([0x03])
        + out_path
        + bytes([0x03])
        + in_path
    )


def test_path_discovery_push_3byte():
    """3-byte-hash paths (encoded 0x83 = size 3, count 3 -> 9 path bytes) round-trip."""
    server = _path_discovery_server()
    pubkey = bytes(range(32))
    out_path = bytes(range(0x10, 0x19))  # 9 bytes
    in_path = bytes(range(0x20, 0x29))  # 9 bytes
    server._on_path_discovery_response(b"\x00\x00\x00\x00", pubkey, 0x83, out_path, 0x83, in_path)
    payload = _path_push_payload(server._write_queue.get_nowait())
    assert payload == (
        bytes([PUSH_CODE_PATH_DISCOVERY_RESPONSE, 0])
        + pubkey[:6]
        + bytes([0x83])
        + out_path
        + bytes([0x83])
        + in_path
    )


def test_path_discovery_push_zero_hop():
    """Zero-hop (encoded 0x00) paths carry no path bytes in either direction."""
    server = _path_discovery_server()
    pubkey = bytes(range(32))
    server._on_path_discovery_response(b"\x00\x00\x00\x00", pubkey, 0x00, b"", 0x00, b"")
    payload = _path_push_payload(server._write_queue.get_nowait())
    assert payload == (
        bytes([PUSH_CODE_PATH_DISCOVERY_RESPONSE, 0]) + pubkey[:6] + bytes([0x00]) + bytes([0x00])
    )


def test_path_discovery_push_invalid_len_suppressed():
    """Invalid encoded path_len (0xC0 = reserved hash_size 4) suppresses the whole
    frame, mirroring the isValidPathLen guard at MyMesh.cpp:754-755."""
    server = _path_discovery_server()
    pubkey = bytes(range(32))
    server._on_path_discovery_response(b"\x00\x00\x00\x00", pubkey, 0xC0, b"", 0x00, b"")
    assert server._write_queue.qsize() == 0


@pytest.mark.asyncio
async def test_maybe_persist_contact_skips_transient():
    """_maybe_persist_contact guards transient (ADV_TYPE_NONE) entries even when a
    subclass overrides _persist_contact (e.g. the repeater's SQLite upsert)."""
    from types import SimpleNamespace

    server = CompanionFrameServer(object(), "hash", port=0)
    persisted = []
    server._persist_contact = AsyncMock(side_effect=lambda c: persisted.append(c))

    await server._maybe_persist_contact(SimpleNamespace(adv_type=0))  # ADV_TYPE_NONE
    assert persisted == []  # skipped
    server._persist_contact.assert_not_called()

    real = SimpleNamespace(adv_type=1)  # ADV_TYPE_CHAT
    await server._maybe_persist_contact(real)
    assert persisted == [real]  # persisted


@pytest.mark.asyncio
async def test_cmd_set_flood_scope_dispatches_mode_byte():
    """CMD_SET_FLOOD_SCOPE_KEY: mode 1 -> unscoped, mode 0 -> set/reset scope (FW #2492)."""
    bridge = Mock()
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_ok = Mock()
    server._write_err = Mock()

    # mode 1 (v12+): force unscoped
    await server._cmd_set_flood_scope(bytes([0x01]))
    bridge.set_flood_unscoped.assert_called_once()
    bridge.set_flood_scope.assert_not_called()

    # mode 0 with a 16-byte key: set scope override (key from data[1:17])
    bridge.reset_mock()
    key = bytes(range(16))
    await server._cmd_set_flood_scope(bytes([0x00]) + key)
    bridge.set_flood_scope.assert_called_once_with(key)
    bridge.set_flood_unscoped.assert_not_called()

    # mode 0, short: reset scope
    bridge.reset_mock()
    await server._cmd_set_flood_scope(bytes([0x00]))
    bridge.set_flood_scope.assert_called_once_with(None)

    # unknown mode: firmware falls through to unsupported command
    bridge.reset_mock()
    server._write_ok.reset_mock()
    await server._cmd_set_flood_scope(bytes([0x02]) + bytes(range(16)))
    bridge.set_flood_scope.assert_not_called()
    bridge.set_flood_unscoped.assert_not_called()
    server._write_ok.assert_not_called()
    server._write_err.assert_called_once_with(ERR_CODE_UNSUPPORTED_CMD)


@pytest.mark.asyncio
async def test_cmd_set_flood_scope_empty_frame_is_unsupported():
    """Empty CMD_SET_FLOOD_SCOPE_KEY frame (firmware len < 2) is UNSUPPORTED_CMD, not a scope reset.

    Firmware requires len >= 2 (MyMesh.cpp CMD_SET_FLOOD_SCOPE_KEY); a bare
    cmd byte with no mode byte falls through the else-if chain to the
    catch-all writeErrFrame(ERR_CODE_UNSUPPORTED_CMD). This is distinct from
    a frame with just the mode byte (mode 0, no key), which firmware DOES
    accept and treats as a scope-override reset -- see
    test_cmd_set_flood_scope_dispatches_mode_byte above, which must keep
    passing unchanged.
    """
    bridge = Mock()
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_ok = Mock()
    server._write_err = Mock()

    await server._cmd_set_flood_scope(b"")
    bridge.set_flood_scope.assert_not_called()
    bridge.set_flood_unscoped.assert_not_called()
    server._write_ok.assert_not_called()
    server._write_err.assert_called_once_with(ERR_CODE_UNSUPPORTED_CMD)


def test_max_frame_size_is_176():
    """Companion frame size tracks firmware PR #2022 (172 -> 176)."""
    from openhop_core.companion.constants import (
        MAX_CHANNEL_DATA_LENGTH,
        MAX_FRAME_SIZE,
        MAX_PAYLOAD_SIZE,
    )

    assert MAX_FRAME_SIZE == 176
    assert MAX_PAYLOAD_SIZE == 176
    assert MAX_CHANNEL_DATA_LENGTH == 167


@pytest.mark.asyncio
async def test_cmd_send_txt_msg_threads_host_timestamp():
    """Plain DM: the host-supplied msg_timestamp (data[2:6]) is passed through verbatim so
    retries share a stable timestamp (mirrors firmware sendMessage)."""
    from unittest.mock import AsyncMock

    from openhop_core.companion.companion_bridge import CompanionBridge
    from openhop_core.companion.constants import (
        TXT_TYPE_CLI_COMMAND,
        TXT_TYPE_CLI_DATA,
        TXT_TYPE_PLAIN,
    )
    from openhop_core.companion.models import Contact, SentResult
    from openhop_core.protocol import LocalIdentity

    bridge = CompanionBridge(LocalIdentity(), AsyncMock(return_value=True))
    peer = LocalIdentity()
    pubkey = peer.get_public_key()
    bridge.contacts.add(Contact(public_key=pubkey, name="Peer"))
    bridge.send_text_message = AsyncMock(
        return_value=SentResult(
            success=True, is_flood=False, expected_ack=0x11223344, timeout_ms=5000
        )
    )

    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_queue = asyncio.Queue(maxsize=256)

    host_ts = 1700000000
    # data: txt_type(1) + attempt(1) + msg_timestamp(4, LE) + pubkey_prefix(6) + text
    data = bytes([TXT_TYPE_PLAIN, 0]) + struct.pack("<I", host_ts) + pubkey[:6] + b"hello"
    await server._cmd_send_txt_msg(data)

    bridge.send_text_message.assert_awaited_once()
    assert bridge.send_text_message.call_args.kwargs["timestamp"] == host_ts

    # Both CLI types mint a fresh timestamp (timestamp=None): firmware overrides
    # msg_timestamp with its own RTC for either before calling sendCommandData,
    # so a host clock that lags cannot trip the receiver's replay guard.
    for cli_type in (TXT_TYPE_CLI_DATA, TXT_TYPE_CLI_COMMAND):
        bridge.send_text_message.reset_mock()
        data_cli = bytes([cli_type, 0]) + struct.pack("<I", host_ts) + pubkey[:6] + b"cmd"
        await server._cmd_send_txt_msg(data_cli)
        assert bridge.send_text_message.call_args.kwargs["timestamp"] is None
        assert bridge.send_text_message.call_args.kwargs["txt_type"] == cli_type


@pytest.mark.asyncio
async def test_cmd_send_txt_msg_zero_host_timestamp_mints_fresh():
    """A zero/omitted host timestamp falls back to a fresh timestamp (timestamp=None)."""
    from unittest.mock import AsyncMock

    from openhop_core.companion.companion_bridge import CompanionBridge
    from openhop_core.companion.constants import TXT_TYPE_PLAIN
    from openhop_core.companion.models import Contact, SentResult
    from openhop_core.protocol import LocalIdentity

    bridge = CompanionBridge(LocalIdentity(), AsyncMock(return_value=True))
    peer = LocalIdentity()
    pubkey = peer.get_public_key()
    bridge.contacts.add(Contact(public_key=pubkey, name="Peer"))
    bridge.send_text_message = AsyncMock(
        return_value=SentResult(success=True, is_flood=False, expected_ack=0, timeout_ms=5000)
    )

    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_queue = asyncio.Queue(maxsize=256)

    data = bytes([TXT_TYPE_PLAIN, 0]) + struct.pack("<I", 0) + pubkey[:6] + b"hi"
    await server._cmd_send_txt_msg(data)
    assert bridge.send_text_message.call_args.kwargs["timestamp"] is None


# ---------------------------------------------------------------------------
# Command dispatch (_handle_cmd)
# ---------------------------------------------------------------------------


def _make_capture_server(bridge, **kwargs):
    """Server whose outbound frames (responses and errors) land in a list."""
    server = CompanionFrameServer(bridge, "hash", port=0, **kwargs)
    frames: list[bytes] = []
    server._write_frame = lambda f: frames.append(f)
    return server, frames


@pytest.mark.asyncio
async def test_handle_cmd_empty_payload_is_illegal_arg():
    server, frames = _make_capture_server(Mock())
    await server._handle_cmd(b"")
    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_ILLEGAL_ARG])]


@pytest.mark.asyncio
async def test_handle_cmd_unknown_cmd_is_unsupported():
    server, frames = _make_capture_server(Mock())
    await server._handle_cmd(bytes([0xEE]))
    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_UNSUPPORTED_CMD])]


@pytest.mark.asyncio
async def test_import_private_key_reports_disabled_without_changing_identity():
    """Virtual-companion rekeying remains disabled, as in MeshCore's build."""
    from openhop_core.companion import CompanionBridge
    from openhop_core.protocol import LocalIdentity

    identity = LocalIdentity()
    bridge = CompanionBridge(identity, AsyncMock(return_value=True))
    server, frames = _make_capture_server(bridge)
    original_public_key = bridge.get_public_key()

    await server._handle_cmd(bytes([CMD_IMPORT_PRIVATE_KEY]) + b"\xa5" * 64)

    assert frames == [bytes([RESP_CODE_DISABLED])]
    assert bridge.get_public_key() == original_public_key


@pytest.mark.asyncio
async def test_short_private_key_import_is_unsupported():
    server, frames = _make_capture_server(Mock())

    await server._handle_cmd(bytes([CMD_IMPORT_PRIVATE_KEY]) + b"\xa5" * 63)

    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_UNSUPPORTED_CMD])]


@pytest.mark.asyncio
async def test_companion_signing_command_lifecycle_matches_firmware():
    """SIGN_START/DATA/FINISH expose the bridge's 8 KiB signing session."""
    from openhop_core.companion import CompanionBridge
    from openhop_core.protocol import LocalIdentity

    identity = LocalIdentity()
    bridge = CompanionBridge(identity, AsyncMock(return_value=True))
    server, frames = _make_capture_server(bridge)

    await server._handle_cmd(bytes([CMD_SIGN_START]))
    await server._handle_cmd(bytes([CMD_SIGN_DATA]) + b"hello ")
    await server._handle_cmd(bytes([CMD_SIGN_DATA]) + b"world")
    await server._handle_cmd(bytes([CMD_SIGN_FINISH]))

    assert frames[:3] == [
        bytes([RESP_CODE_SIGN_START, 0]) + struct.pack("<I", MAX_SIGN_DATA_SIZE),
        bytes([RESP_CODE_OK]),
        bytes([RESP_CODE_OK]),
    ]
    assert frames[3][0] == RESP_CODE_SIGNATURE
    assert len(frames[3]) == 65
    assert identity.verify(b"hello world", frames[3][1:])

    await server._handle_cmd(bytes([CMD_SIGN_FINISH]))
    assert frames[4] == bytes([RESP_CODE_ERR, ERR_CODE_BAD_STATE])


@pytest.mark.asyncio
async def test_companion_signing_matches_meshcore_golden_wire_vector():
    """A literal MeshCore command sequence produces its known response frames."""
    from openhop_core.companion import CompanionBridge
    from openhop_core.protocol import LocalIdentity

    # This 64-byte key was generated by meshcore-keygen.  The expected
    # signature was generated independently by MeshCore lib/ed25519/sign.c
    # for raw bytes 00 4f 70 65 6e 48 6f 70 20 73 69 67 6e 20 76 65 63 74
    # 6f 72 ff, then embedded as a wire vector.
    identity = LocalIdentity(
        bytes.fromhex(
            "a8cdb06cef221ef0ee4e5e9d9d0829499cd304ca1bba47af2ea17d83b316726b"
            "e232b1da0388a2eb142d9a16ed66d4994a7ac40339ec1fbc3937f3b81f5dc62b"
        )
    )
    server, frames = _make_capture_server(CompanionBridge(identity, AsyncMock(return_value=True)))

    # MeshCore ignores extra bytes on SIGN_START and SIGN_FINISH.  The two
    # SIGN_DATA commands concatenate raw bytes, including NUL and 0xFF.
    await server._handle_cmd(bytes.fromhex("21a55a"))
    await server._handle_cmd(bytes.fromhex("22004f70656e486f7020"))
    await server._handle_cmd(bytes.fromhex("227369676e20766563746f72ff"))
    await server._handle_cmd(bytes.fromhex("23dead"))

    assert frames == [
        bytes.fromhex("130000200000"),
        bytes.fromhex("00"),
        bytes.fromhex("00"),
        bytes.fromhex(
            "144b70fa7948edae31e1253c9495b14e213e76fd65cc811707425664bf491ad34c"
            "7fce909510cd10fea6aefb4f26c531e0abf24deb9a5c2dbe0db359d67694e40b"
        ),
    ]


@pytest.mark.asyncio
async def test_companion_signing_reports_firmware_state_and_capacity_errors():
    """Empty, state-less, and over-capacity SIGN_DATA frames have distinct errors."""
    from openhop_core.companion import CompanionBridge
    from openhop_core.protocol import LocalIdentity

    identity = LocalIdentity()
    bridge = CompanionBridge(identity, AsyncMock(return_value=True))
    server, frames = _make_capture_server(bridge)

    await server._handle_cmd(bytes([CMD_SIGN_DATA]) + b"x")
    await server._handle_cmd(bytes([CMD_SIGN_FINISH]))
    await server._handle_cmd(bytes([CMD_SIGN_DATA]))
    await server._handle_cmd(bytes([CMD_SIGN_START]))
    await server._handle_cmd(bytes([CMD_SIGN_DATA]) + b"x" * MAX_SIGN_DATA_SIZE)
    await server._handle_cmd(bytes([CMD_SIGN_DATA]) + b"y")
    await server._handle_cmd(bytes([CMD_SIGN_FINISH]))

    assert frames[:3] == [
        bytes([RESP_CODE_ERR, ERR_CODE_BAD_STATE]),
        bytes([RESP_CODE_ERR, ERR_CODE_BAD_STATE]),
        bytes([RESP_CODE_ERR, ERR_CODE_UNSUPPORTED_CMD]),
    ]
    assert frames[4] == bytes([RESP_CODE_OK])
    assert frames[5] == bytes([RESP_CODE_ERR, ERR_CODE_TABLE_FULL])
    assert frames[6][0] == RESP_CODE_SIGNATURE
    assert identity.verify(b"x" * MAX_SIGN_DATA_SIZE, frames[6][1:])


@pytest.mark.asyncio
async def test_companion_sign_start_replaces_unfinished_session():
    """A second SIGN_START discards the prior buffer, as firmware frees it."""
    from openhop_core.companion import CompanionBridge
    from openhop_core.protocol import LocalIdentity

    identity = LocalIdentity()
    bridge = CompanionBridge(identity, AsyncMock(return_value=True))
    server, frames = _make_capture_server(bridge)

    await server._handle_cmd(bytes([CMD_SIGN_START]))
    await server._handle_cmd(bytes([CMD_SIGN_DATA]) + b"old")
    await server._handle_cmd(bytes([CMD_SIGN_START]))
    await server._handle_cmd(bytes([CMD_SIGN_DATA]) + b"new")
    await server._handle_cmd(bytes([CMD_SIGN_FINISH]))

    assert frames[-1][0] == RESP_CODE_SIGNATURE
    assert identity.verify(b"new", frames[-1][1:])
    assert not identity.verify(b"old", frames[-1][1:])


class _MockBridgeCustomVars:
    """Minimal bridge exposing an ordered custom-vars dict for CMD_GET_CUSTOM_VARS."""

    def __init__(self, custom_vars: dict[str, str]):
        self._custom_vars = custom_vars

    def get_custom_vars(self) -> dict[str, str]:
        return dict(self._custom_vars)


@pytest.mark.asyncio
async def test_get_custom_vars_ascii_exact_fit_returns_everything():
    """An ASCII payload landing exactly on the 140-byte budget is returned whole."""
    custom_vars = {"k1": "v" * 66, "k2": "v" * 67}
    bridge = _MockBridgeCustomVars(custom_vars)
    server, frames = _make_capture_server(bridge)

    await server._handle_cmd(bytes([CMD_GET_CUSTOM_VARS]))

    expected = ",".join(f"{k}:{v}" for k, v in custom_vars.items())
    assert len(expected) == 140  # sanity check on the fixture itself
    assert frames == [bytes([RESP_CODE_CUSTOM_VARS]) + expected.encode("utf-8")]


@pytest.mark.asyncio
async def test_get_custom_vars_multibyte_values_respect_encoded_byte_budget():
    """Regression for BUG-090: the 140 budget applies to encoded UTF-8 bytes, not
    Python characters.

    MyMesh.cpp's CMD_GET_CUSTOM_VARS handler (examples/companion_radio/MyMesh.cpp
    lines 1784-1797) tracks `dp - (char*)&out_frame[1]`, i.e. bytes already written,
    against the 140 threshold. The old OpenHop code instead joined all entries into
    one string and sliced it with Python's `[:140]`, which counts *characters* -- with
    multi-byte values that character-based cut can retain far more than 140 encoded
    bytes. This fixture's 30 four-byte-each "é" x4 values produce a 269-character
    joined string; the old `csv[:140]` slice alone would encode to 201 bytes -- past
    even MAX_FRAME_SIZE (176, see constants.py), so firmware/clients would have
    silently dropped the oversized frame. The fixed incremental encoder must keep the
    payload well clear of that.
    """
    custom_vars = {f"k{i:02d}": "é" * 4 for i in range(30)}
    bridge = _MockBridgeCustomVars(custom_vars)
    server, frames = _make_capture_server(bridge)

    await server._handle_cmd(bytes([CMD_GET_CUSTOM_VARS]))

    # Sanity-check the bug this fixture reproduces: the old character-based slice
    # would have exceeded the 140-byte budget (and the 176-byte transport frame max).
    old_buggy_csv = ",".join(f"{k}:{v}" for k, v in custom_vars.items())[:140]
    assert len(old_buggy_csv.encode("utf-8")) > 140
    assert 1 + len(old_buggy_csv.encode("utf-8")) > 176  # RESP code byte + payload

    assert len(frames) == 1
    payload = frames[0]
    assert payload[0] == RESP_CODE_CUSTOM_VARS
    body = payload[1:]
    # Fully decodable UTF-8 -- no mid-character truncation.
    body.decode("utf-8")
    # Overshoot-by-one-entry parity with firmware (see docstring): the budget check
    # happens before appending an entry, using the length already written, so the
    # final included entry may push the total past 140 but not by more than one
    # entry's worth of bytes.
    assert len(body) > 140
    assert 1 + len(body) <= 176  # RESP code byte + payload stays inside the frame cap
    # Exact expected bytes: each entry "kNN:éééé" is 12 encoded bytes plus a
    # 1-byte comma separator, so the written length before entry i is 13i-1;
    # the check-before-append (>= 140) first blocks entry 11, leaving entries
    # 0..10 written in full (13*11 - 1 = 142 bytes, an overshoot of 2).
    expected = ",".join(f"k{i:02d}:" + "é" * 4 for i in range(11)).encode("utf-8")
    assert len(expected) == 142
    assert body == expected


@pytest.mark.asyncio
async def test_get_custom_vars_overshoots_budget_by_one_entry_like_firmware():
    """The budget check happens BEFORE appending an entry and compares against bytes
    already written (MyMesh.cpp examples/companion_radio/MyMesh.cpp lines 1786-1787:
    `dp - (char*)&out_frame[1] < 140` is checked at the top of the for loop, before
    that iteration's comma/name/value are written). So an entry that starts under
    budget is written in full even if it crosses 140 -- and the loop then stops,
    dropping any later entries entirely rather than skipping just the oversized one.
    """
    custom_vars = {
        "a": "x" * 58,  # entry "a:xxx...x" -> 60 bytes
        "b": "y" * 58,  # entry -> 60 bytes; running total after b = 121 (< 140)
        "c": "z" * 22,  # entry -> 24 bytes + comma = 25; running total = 146 (> 140)
        "d": "w",  # never reached: loop already stopped after c
    }
    bridge = _MockBridgeCustomVars(custom_vars)
    server, frames = _make_capture_server(bridge)

    await server._handle_cmd(bytes([CMD_GET_CUSTOM_VARS]))

    assert len(frames) == 1
    body = frames[0][1:]
    assert len(body) == 146
    text = body.decode("utf-8")
    assert text == ",".join(
        [f"a:{custom_vars['a']}", f"b:{custom_vars['b']}", f"c:{custom_vars['c']}"]
    )
    assert "d:" not in text


@pytest.mark.asyncio
async def test_handle_cmd_handler_exception_maps_to_illegal_arg():
    server, frames = _make_capture_server(Mock())

    async def boom(data):
        raise RuntimeError("boom")

    server._cmd_handlers[CMD_GET_DEVICE_TIME] = boom
    await server._handle_cmd(bytes([CMD_GET_DEVICE_TIME]))
    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_ILLEGAL_ARG])]


@pytest.mark.asyncio
async def test_handle_cmd_dispatches_to_registered_handler():
    bridge = Mock()
    bridge.get_time = Mock(return_value=1_700_000_000)
    server, frames = _make_capture_server(bridge)
    await server._handle_cmd(bytes([CMD_GET_DEVICE_TIME]))
    assert frames == [bytes([RESP_CODE_CURR_TIME]) + struct.pack("<I", 1_700_000_000)]


# ---------------------------------------------------------------------------
# CMD_APP_START / self info
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cmd_app_start_self_info_layout():
    prefs = NodePrefs(node_name="TestNode", latitude=12.5, longitude=-3.25, tx_power_dbm=14)
    pubkey = bytes(range(32))
    bridge = Mock()
    bridge.get_self_info = Mock(return_value=prefs)
    bridge.get_public_key = Mock(return_value=pubkey)
    bridge.get_max_tx_power_dbm = Mock(return_value=19)
    server, frames = _make_capture_server(bridge)
    # Version is negotiated only via DEVICE_QUERY; APP_START must not change it.
    server._app_target_ver = 5

    await server._cmd_app_start(bytes(7) + b"TestApp")

    (frame,) = frames
    assert frame[0] == RESP_CODE_SELF_INFO
    assert frame[2:4] == bytes([14, 19])
    assert frame[4:36] == pubkey
    lat, lon = struct.unpack_from("<ii", frame, 36)
    assert lat == int(12.5 * 1e6)
    assert lon == int(-3.25 * 1e6)
    assert frame.endswith(b"TestNode")
    assert server._app_target_ver == 5


@pytest.mark.asyncio
async def test_cmd_app_start_self_info_packs_telemetry_env_nibble():
    # Firmware MyMesh.cpp CMD_APP_START handler packs the telemetry byte as
    # (telemetry_mode_env << 4) | (telemetry_mode_loc << 2) | telemetry_mode_base.
    # base=1, env=2 -> 0b00100001 == 0x21.
    prefs = NodePrefs(
        node_name="TestNode",
        telemetry_mode_base=1,
        telemetry_mode_location=0,
        telemetry_mode_environment=2,
    )
    bridge = Mock()
    bridge.get_self_info = Mock(return_value=prefs)
    bridge.get_public_key = Mock(return_value=bytes(32))
    bridge.get_max_tx_power_dbm = Mock(return_value=19)
    server, frames = _make_capture_server(bridge)

    await server._cmd_app_start(bytes(7) + b"TestApp")

    (frame,) = frames
    # telemetry byte offset: RESP_CODE(1)+ADV_TYPE(1)+tx_power(1)+max_tx(1)
    # + pubkey(32) + lat(4)+lon(4) + multi_acks(1)+advert_loc_policy(1) = 46
    assert frame[46] == 0x21


@pytest.mark.asyncio
async def test_cmd_app_start_self_info_env_zero_matches_old_single_nibble_byte():
    # With telemetry_mode_environment left at its default (0), the packed byte
    # is unchanged from the pre-fix base|location-only packing.
    prefs = NodePrefs(
        node_name="TestNode",
        telemetry_mode_base=1,
        telemetry_mode_location=2,
        telemetry_mode_environment=0,
    )
    bridge = Mock()
    bridge.get_self_info = Mock(return_value=prefs)
    bridge.get_public_key = Mock(return_value=bytes(32))
    bridge.get_max_tx_power_dbm = Mock(return_value=19)
    server, frames = _make_capture_server(bridge)

    await server._cmd_app_start(bytes(7) + b"TestApp")

    (frame,) = frames
    assert frame[46] == (1 | (2 << 2))
    assert frame[46] == 0x09


@pytest.mark.asyncio
async def test_cmd_app_start_self_info_packs_all_three_telemetry_nibbles():
    # All three fields non-zero at once: base=1, loc=2, env=3 ->
    # (3 << 4) | (2 << 2) | 1 == 0x39.
    prefs = NodePrefs(
        node_name="TestNode",
        telemetry_mode_base=1,
        telemetry_mode_location=2,
        telemetry_mode_environment=3,
    )
    bridge = Mock()
    bridge.get_self_info = Mock(return_value=prefs)
    bridge.get_public_key = Mock(return_value=bytes(32))
    bridge.get_max_tx_power_dbm = Mock(return_value=19)
    server, frames = _make_capture_server(bridge)

    await server._cmd_app_start(bytes(7) + b"TestApp")

    (frame,) = frames
    assert frame[46] == 0x39


@pytest.mark.asyncio
async def test_cmd_app_start_rejects_short_frame():
    bridge = Mock()
    server, frames = _make_capture_server(bridge)
    server._write_err = Mock()

    await server._cmd_app_start(bytes(6))

    server._write_err.assert_called_once_with(ERR_CODE_ILLEGAL_ARG)
    assert frames == []


# ---------------------------------------------------------------------------
# Contact list / lookup frames
# ---------------------------------------------------------------------------


def _contact(name="alice", first_byte=0x42, **overrides) -> Contact:
    defaults = dict(
        public_key=bytes([first_byte]) + bytes(31),
        name=name,
        adv_type=1,
        flags=0,
        out_path_len=-1,
        out_path=b"",
        last_advert_timestamp=1_600_000_000,
        lastmod=1_600_000_100,
        gps_lat=47.5,
        gps_lon=-122.25,
    )
    defaults.update(overrides)
    return Contact(**defaults)


@pytest.mark.asyncio
async def test_cmd_get_contacts_start_body_end_sequence():
    c1 = _contact("alice", 0x42, lastmod=100)
    c2 = _contact("bob", 0x43, lastmod=200)
    c3 = _contact("carol", 0x44, lastmod=300)
    # The 'since' filter narrows the emitted frames, but CONTACTS_START must
    # report the total table count (firmware getNumContacts()), not the count
    # of the filtered result.
    bridge = Mock()
    bridge.get_contacts = Mock(side_effect=lambda since=0: [c2, c3] if since else [c1, c2, c3])
    bridge.get_contact_count = Mock(return_value=3)
    server, frames = _make_capture_server(bridge)

    await server._cmd_get_contacts(struct.pack("<I", 50))

    assert frames[0] == bytes([RESP_CODE_CONTACTS_START]) + struct.pack("<I", 3)
    assert frames[1][0] == RESP_CODE_CONTACT
    assert frames[2][0] == RESP_CODE_CONTACT
    assert len(frames) == 4
    assert frames[3] == bytes([RESP_CODE_END_OF_CONTACTS]) + struct.pack("<I", 300)


@pytest.mark.asyncio
async def test_write_contact_frame_layout():
    contact = _contact("alice", 0x42, out_path_len=2, out_path=b"\x0a\x0b")
    bridge = Mock()
    bridge.contacts.get_by_key = Mock(return_value=contact)
    server, frames = _make_capture_server(bridge)

    await server._cmd_get_contact_by_key(contact.public_key)

    (frame,) = frames
    assert frame[0] == RESP_CODE_CONTACT
    assert frame[1:33] == contact.public_key
    assert frame[33] == contact.adv_type
    assert frame[34] == contact.flags
    assert frame[35] == 2  # out_path_len
    assert frame[36 : 36 + MAX_PATH_SIZE] == b"\x0a\x0b".ljust(MAX_PATH_SIZE, b"\x00")
    name_field = frame[36 + MAX_PATH_SIZE : 36 + MAX_PATH_SIZE + 32]
    assert name_field == b"alice".ljust(32, b"\x00")
    last_advert, lat, lon, lastmod = struct.unpack("<IiiI", frame[36 + MAX_PATH_SIZE + 32 :])
    assert last_advert == contact.last_advert_timestamp
    assert lat == int(contact.gps_lat * 1e6)
    assert lon == int(contact.gps_lon * 1e6)
    assert lastmod == contact.lastmod


@pytest.mark.asyncio
async def test_write_contact_frame_unknown_path_encodes_0xff():
    contact = _contact("alice", out_path_len=-1)
    bridge = Mock()
    bridge.contacts.get_by_key = Mock(return_value=contact)
    server, frames = _make_capture_server(bridge)
    await server._cmd_get_contact_by_key(contact.public_key)
    assert frames[0][35] == 0xFF


@pytest.mark.asyncio
async def test_cmd_get_contact_by_key_not_found_and_short_data():
    bridge = Mock()
    bridge.contacts.get_by_key = Mock(return_value=None)
    server, frames = _make_capture_server(bridge)
    await server._cmd_get_contact_by_key(bytes(32))
    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_NOT_FOUND])]
    frames.clear()
    await server._cmd_get_contact_by_key(b"\x01\x02")
    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_ILLEGAL_ARG])]


@pytest.mark.asyncio
async def test_cmd_remove_contact_saves_on_success():
    bridge = Mock()
    bridge.remove_contact = Mock(return_value=True)
    server, frames = _make_capture_server(bridge)
    server._save_contacts = AsyncMock()
    await server._cmd_remove_contact(bytes(32))
    assert frames == [bytes([RESP_CODE_OK])]
    server._save_contacts.assert_awaited_once()

    bridge.remove_contact = Mock(return_value=False)
    frames.clear()
    server._save_contacts.reset_mock()
    await server._cmd_remove_contact(bytes(32))
    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_NOT_FOUND])]
    server._save_contacts.assert_not_awaited()


# ---------------------------------------------------------------------------
# CMD_SEND_TXT_MSG error/success frames
# ---------------------------------------------------------------------------


def _txt_bridge(contact, result):
    bridge = Mock()
    bridge.contacts.get_by_key_prefix = Mock(return_value=contact)
    bridge.send_text_message = AsyncMock(return_value=result)
    return bridge


@pytest.mark.asyncio
async def test_cmd_send_txt_msg_success_sent_frame_fields():
    contact = _contact()
    result = SentResult(success=True, is_flood=True, expected_ack=0xAABBCCDD, timeout_ms=7000)
    server, frames = _make_capture_server(_txt_bridge(contact, result))
    data = bytes([0, 0]) + struct.pack("<I", 123) + contact.public_key[:6] + b"hi"
    await server._cmd_send_txt_msg(data)
    (frame,) = frames
    assert frame[0] == RESP_CODE_SENT
    assert frame[1] == 1  # flood
    ack, timeout = struct.unpack("<II", frame[2:10])
    assert ack == 0xAABBCCDD
    assert timeout == 7000


@pytest.mark.asyncio
async def test_cmd_send_txt_msg_unknown_contact_and_failure():
    server, frames = _make_capture_server(_txt_bridge(None, SentResult(True)))
    data = bytes([0, 0]) + struct.pack("<I", 1) + bytes(6) + b"hi"
    await server._cmd_send_txt_msg(data)
    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_NOT_FOUND])]

    contact = _contact()
    server, frames = _make_capture_server(_txt_bridge(contact, SentResult(False)))
    data = bytes([0, 0]) + struct.pack("<I", 1) + contact.public_key[:6] + b"hi"
    await server._cmd_send_txt_msg(data)
    # Firmware maps MSG_SEND_FAILED to TABLE_FULL (not BAD_STATE)
    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_TABLE_FULL])]

    server, frames = _make_capture_server(_txt_bridge(contact, SentResult(True)))
    await server._cmd_send_txt_msg(b"\x00\x00")  # too short
    # Firmware: a length-check failure falls through the else-if chain to the
    # catch-all `else { writeErrFrame(ERR_CODE_UNSUPPORTED_CMD); }`, not ILLEGAL_ARG.
    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_UNSUPPORTED_CMD])]


@pytest.mark.asyncio
async def test_cmd_send_txt_msg_rejects_zero_text_bytes():
    """Firmware requires `len >= 14` (cmd byte + 12 header bytes + >=1 text byte).
    `data` here has the command byte already stripped, so the minimum is 13: a
    12-byte header (txt_type, attempt, timestamp, pubkey_prefix) with zero text
    bytes must be rejected with ERR_CODE_UNSUPPORTED_CMD, matching the firmware's
    else-if fall-through, and must not reach the send pipeline."""
    contact = _contact()
    bridge = _txt_bridge(contact, SentResult(True))
    server, frames = _make_capture_server(bridge)

    data = bytes([0, 0]) + struct.pack("<I", 1) + contact.public_key[:6]
    assert len(data) == 12
    await server._cmd_send_txt_msg(data)

    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_UNSUPPORTED_CMD])]
    bridge.send_text_message.assert_not_awaited()


@pytest.mark.asyncio
async def test_cmd_send_txt_msg_accepts_one_text_byte():
    """A 13-byte frame (12-byte header + exactly 1 text byte) passes the length
    gate and proceeds to normal handling -- it must not be rejected as
    ERR_CODE_UNSUPPORTED_CMD."""
    contact = _contact()
    result = SentResult(success=True, is_flood=False, expected_ack=0, timeout_ms=1000)
    bridge = _txt_bridge(contact, result)
    server, frames = _make_capture_server(bridge)

    data = bytes([0, 0]) + struct.pack("<I", 1) + contact.public_key[:6] + b"h"
    assert len(data) == 13
    await server._cmd_send_txt_msg(data)

    bridge.send_text_message.assert_awaited_once()
    assert bridge.send_text_message.call_args.args[1] == "h"
    assert frames and frames[0][0] == RESP_CODE_SENT


@pytest.mark.asyncio
async def test_cmd_send_txt_msg_rejects_reserved_txt_type_known_contact():
    """Firmware (MyMesh.cpp CMD_SEND_TXT_MSG) only sends for txt_type ==
    TXT_TYPE_PLAIN, TXT_TYPE_CLI_DATA or TXT_TYPE_CLI_COMMAND; anything else --
    including TXT_TYPE_SIGNED_PLAIN (not supported by this command) and fully
    reserved/unknown byte values -- falls into the `else` branch. With a known
    recipient, that branch's ternary picks ERR_CODE_UNSUPPORTED_CMD, and the
    send pipeline must not be touched."""
    from openhop_core.companion.constants import TXT_TYPE_SIGNED_PLAIN

    contact = _contact()
    for reserved_type in (TXT_TYPE_SIGNED_PLAIN, 4, 255):
        bridge = _txt_bridge(contact, SentResult(True))
        server, frames = _make_capture_server(bridge)
        data = bytes([reserved_type, 0]) + struct.pack("<I", 1) + contact.public_key[:6] + b"hi"
        await server._cmd_send_txt_msg(data)
        assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_UNSUPPORTED_CMD])]
        bridge.send_text_message.assert_not_awaited()


@pytest.mark.asyncio
async def test_cmd_send_txt_msg_reserved_txt_type_unknown_contact_is_not_found():
    """Firmware's else-branch ternary is `recipient == NULL ? ERR_CODE_NOT_FOUND
    : ERR_CODE_UNSUPPORTED_CMD` (MyMesh.cpp ~L1119-1121) -- an unknown recipient
    takes priority over an invalid txt_type, so this must report NOT_FOUND, not
    UNSUPPORTED_CMD, preserving the firmware's error precedence."""
    from openhop_core.companion.constants import TXT_TYPE_SIGNED_PLAIN

    bridge = _txt_bridge(None, SentResult(True))
    server, frames = _make_capture_server(bridge)
    data = bytes([TXT_TYPE_SIGNED_PLAIN, 0]) + struct.pack("<I", 1) + bytes(6) + b"hi"
    await server._cmd_send_txt_msg(data)
    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_NOT_FOUND])]
    bridge.send_text_message.assert_not_awaited()


@pytest.mark.asyncio
async def test_cmd_send_txt_msg_supported_txt_types_still_sent():
    """The three types firmware supports for CMD_SEND_TXT_MSG -- PLAIN, CLI_DATA
    and CLI_COMMAND -- must all reach the send pipeline, with the txt_type
    forwarded verbatim so it lands in the flags byte."""
    from openhop_core.companion.constants import (
        TXT_TYPE_CLI_COMMAND,
        TXT_TYPE_CLI_DATA,
        TXT_TYPE_PLAIN,
    )

    contact = _contact()
    for supported_type in (TXT_TYPE_PLAIN, TXT_TYPE_CLI_DATA, TXT_TYPE_CLI_COMMAND):
        result = SentResult(success=True, is_flood=False, expected_ack=0, timeout_ms=1000)
        bridge = _txt_bridge(contact, result)
        server, frames = _make_capture_server(bridge)
        data = bytes([supported_type, 0]) + struct.pack("<I", 1) + contact.public_key[:6] + b"hi"
        await server._cmd_send_txt_msg(data)
        bridge.send_text_message.assert_awaited_once()
        assert bridge.send_text_message.call_args.kwargs["txt_type"] == supported_type
        assert frames and frames[0][0] == RESP_CODE_SENT


# ---------------------------------------------------------------------------
# CMD_SEND_CONTROL_DATA
# ---------------------------------------------------------------------------


def _control_bridge(result=True):
    bridge = Mock()
    bridge.send_control_data = AsyncMock(return_value=result)
    return bridge


@pytest.mark.asyncio
async def test_cmd_send_control_data_rejects_empty_payload():
    """Firmware requires `len >= 2` (cmd byte + >=1 control byte). `data` here has
    the command byte already stripped, so an empty payload is one byte short of
    the firmware's minimum. A length-check failure falls through the else-if
    chain to the catch-all `else { writeErrFrame(ERR_CODE_UNSUPPORTED_CMD); }`,
    not ILLEGAL_ARG."""
    bridge = _control_bridge()
    server, frames = _make_capture_server(bridge)

    await server._cmd_send_control_data(b"")

    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_UNSUPPORTED_CMD])]
    bridge.send_control_data.assert_not_awaited()


@pytest.mark.asyncio
async def test_cmd_send_control_data_accepts_one_byte_high_bit_set():
    """A one-byte payload with the high bit set (e.g. 0x80) is the firmware's
    minimum valid control body and must pass the length gate and reach the
    send path."""
    bridge = _control_bridge(result=True)
    server, frames = _make_capture_server(bridge)

    await server._cmd_send_control_data(bytes([0x80]))

    bridge.send_control_data.assert_awaited_once_with(bytes([0x80]))
    assert frames == [bytes([RESP_CODE_OK])]


@pytest.mark.asyncio
async def test_cmd_send_control_data_rejects_high_bit_clear():
    """Firmware still requires `(cmd_frame[1] & 0x80) != 0`; a first byte with
    the high bit clear must be rejected as ERR_CODE_UNSUPPORTED_CMD (the same
    else-if fall-through as a too-short frame), and must not reach the send
    path."""
    bridge = _control_bridge()
    server, frames = _make_capture_server(bridge)

    await server._cmd_send_control_data(bytes([0x7F]))

    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_UNSUPPORTED_CMD])]
    bridge.send_control_data.assert_not_awaited()


# ---------------------------------------------------------------------------
# CMD_SEND_CHANNEL_TXT_MSG
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cmd_send_channel_txt_msg_paths():
    bridge = Mock()
    bridge.get_channel = Mock(return_value=Channel(name="general", secret=bytes(16)))
    bridge.send_channel_message = AsyncMock(return_value=True)
    server, frames = _make_capture_server(bridge)

    # App-supplied timestamp is passed through to the bridge (PR #93)
    data = bytes([0, 1]) + struct.pack("<I", 1234) + b"hello"
    await server._cmd_send_channel_txt_msg(data)
    assert frames == [bytes([RESP_CODE_OK])]
    bridge.send_channel_message.assert_awaited_once_with(1, "hello", timestamp=1234)

    # Non-plain txt_type is rejected before channel lookup
    frames.clear()
    await server._cmd_send_channel_txt_msg(bytes([1, 1]) + struct.pack("<I", 0) + b"x")
    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_UNSUPPORTED_CMD])]

    # Unknown channel
    bridge.get_channel = Mock(return_value=None)
    frames.clear()
    await server._cmd_send_channel_txt_msg(bytes([0, 9]) + struct.pack("<I", 0) + b"x")
    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_NOT_FOUND])]

    # Send failure: firmware reports NOT_FOUND (not BAD_STATE) for channel sends
    bridge.get_channel = Mock(return_value=Channel(name="general", secret=bytes(16)))
    bridge.send_channel_message = AsyncMock(return_value=False)
    frames.clear()
    await server._cmd_send_channel_txt_msg(bytes([0, 1]) + struct.pack("<I", 0) + b"x")
    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_NOT_FOUND])]


# ---------------------------------------------------------------------------
# CMD_SEND_BINARY_REQ
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cmd_send_binary_req_success_and_unsupported():
    bridge = Mock()
    bridge.send_binary_req = AsyncMock(
        return_value=SentResult(success=True, is_flood=False, expected_ack=0x1122, timeout_ms=9000)
    )
    server, frames = _make_capture_server(bridge)
    await server._cmd_send_binary_req(bytes(32) + b"\x01\x02")
    (frame,) = frames
    assert frame[0] == RESP_CODE_SENT
    tag, timeout = struct.unpack("<II", frame[2:10])
    assert (tag, timeout) == (0x1122, 9000)

    no_method = Mock(spec=[])
    server, frames = _make_capture_server(no_method)
    await server._cmd_send_binary_req(bytes(32) + b"\x01")
    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_UNSUPPORTED_CMD])]


@pytest.mark.asyncio
async def test_cmd_send_binary_req_maps_missing_and_send_failures_like_firmware():
    bridge = Mock()
    bridge.send_binary_req = AsyncMock(return_value=SentResult(success=False, error="not_found"))
    server, frames = _make_capture_server(bridge)

    await server._handle_cmd(bytes.fromhex("32") + bytes(32) + b"\x01")
    assert frames == [bytes.fromhex("0102")]

    bridge.send_binary_req = AsyncMock(return_value=SentResult(success=False, error="send_failed"))
    frames.clear()
    await server._handle_cmd(bytes.fromhex("32") + bytes(32) + b"\x01")
    assert frames == [bytes.fromhex("0103")]


@pytest.mark.asyncio
async def test_cmd_send_path_discovery_maps_missing_and_send_failures_like_firmware():
    bridge = Mock()
    bridge.send_path_discovery_req = AsyncMock(
        return_value=SentResult(success=False, error="not_found")
    )
    server, frames = _make_capture_server(bridge)
    command = b"\x00" + bytes(32)

    await server._handle_cmd(bytes.fromhex("34") + command)
    assert frames == [bytes.fromhex("0102")]

    bridge.send_path_discovery_req = AsyncMock(
        return_value=SentResult(success=False, error="send_failed")
    )
    frames.clear()
    await server._handle_cmd(bytes.fromhex("34") + command)
    assert frames == [bytes.fromhex("0103")]


# ---------------------------------------------------------------------------
# CMD_SYNC_NEXT_MESSAGE and _build_message_frame variants
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cmd_sync_next_message_empty_queue():
    bridge = Mock()
    bridge.sync_next_message = Mock(return_value=None)
    server, frames = _make_capture_server(bridge)
    await server._cmd_sync_next_message(b"")
    assert frames == [bytes([RESP_CODE_NO_MORE_MESSAGES])]


@pytest.mark.asyncio
async def test_cmd_sync_next_message_returns_bridge_message():
    msg = QueuedMessage(
        sender_key=bytes([0x42]) + bytes(31), txt_type=0, timestamp=1_650_000_000, text="hi"
    )
    bridge = Mock()
    bridge.sync_next_message = Mock(return_value=msg)
    server, frames = _make_capture_server(bridge)
    await server._cmd_sync_next_message(b"")
    assert frames == [server._build_message_frame(msg)]


@pytest.mark.asyncio
async def test_cmd_sync_next_message_falls_back_to_persistence():
    msg = QueuedMessage(sender_key=bytes(32), timestamp=5, text="persisted")
    bridge = Mock()
    bridge.sync_next_message = Mock(return_value=None)
    server, frames = _make_capture_server(bridge)
    server._sync_next_from_persistence = lambda: msg
    await server._cmd_sync_next_message(b"")
    assert frames == [server._build_message_frame(msg)]


def test_build_message_frame_contact_v1_and_v3():
    server = CompanionFrameServer(Mock(), "hash", port=0)
    # txt_type=1 (CLI_DATA): any non-signed type — SIGNED_PLAIN (2) adds an
    # author-prefix field and is covered by its own tests below.
    msg = QueuedMessage(
        sender_key=bytes([0xAA] * 32),
        txt_type=1,
        timestamp=1_650_000_000,
        text="hey",
        path_len=3,
        snr=2.0,
    )
    server._app_target_ver = 0
    frame = server._build_message_frame(msg)
    assert frame == (
        bytes([RESP_CODE_CONTACT_MSG_RECV])
        + bytes([0xAA] * 6)
        + bytes([3, 1])
        + struct.pack("<I", 1_650_000_000)
        + b"hey"
    )

    server._app_target_ver = 3
    frame_v3 = server._build_message_frame(msg)
    assert frame_v3[0] == RESP_CODE_CONTACT_MSG_RECV_V3
    assert frame_v3[1] == 8  # snr * 4
    assert frame_v3[4:10] == bytes([0xAA] * 6)
    assert frame_v3.endswith(b"hey")


@pytest.mark.asyncio
@pytest.mark.parametrize("path_len", [0xFF, 0x01, 0x42, 0x83])
async def test_message_push_preserves_path_len_for_persistence(path_len):
    """The message push callback must persist the route byte unchanged."""
    bridge = Mock()
    server = CompanionFrameServer(bridge, "hash", port=0)
    persisted = []

    async def persist(msg_dict, queue_entry=None):
        persisted.append(msg_dict)

    server._persist_companion_message = persist
    server._enqueue_frame = Mock()

    await server._on_message_event(
        MessageEvent(
            sender_key=b"\x01" * 32,
            text="direct",
            timestamp=1234,
            txt_type=0,
            path_len=path_len,
        )
    )

    assert persisted == [
        {
            "sender_key": b"\x01" * 32,
            "text": "direct",
            "timestamp": 1234,
            "txt_type": 0,
            "is_channel": False,
            "channel_idx": 0,
            "path_len": path_len,
            "packet_hash": None,
            "snr": None,
            "rssi": None,
            "sender_prefix": b"",
        }
    ]


@pytest.mark.asyncio
async def test_rejected_message_push_skips_persistence_but_notifies_client():
    """A rejected protected-queue insertion must not evict an older message."""
    server = CompanionFrameServer(Mock(), "hash", port=0)
    persist = AsyncMock()
    server._persist_companion_message = persist
    server._enqueue_frame = Mock()

    await server._on_message_event(
        MessageEvent(
            sender_key=b"\x01" * 32,
            text="rejected",
            timestamp=1234,
            txt_type=0,
            queued=False,
        )
    )

    persist.assert_not_awaited()
    server._enqueue_frame.assert_called_once_with(bytes([PUSH_CODE_MSG_WAITING]))


def test_build_message_frame_channel_v1_and_v3():
    server = CompanionFrameServer(Mock(), "hash", port=0)
    msg = QueuedMessage(
        sender_key=b"",
        timestamp=7,
        text="ch",
        is_channel=True,
        channel_idx=2,
        path_len=1,
    )
    server._app_target_ver = 0
    frame = server._build_message_frame(msg)
    assert frame == (bytes([RESP_CODE_CHANNEL_MSG_RECV, 2, 1, 0]) + struct.pack("<I", 7) + b"ch")

    server._app_target_ver = 3
    frame_v3 = server._build_message_frame(msg)
    assert frame_v3[0] == RESP_CODE_CHANNEL_MSG_RECV_V3
    assert frame_v3[4] == 2  # channel_idx
    assert frame_v3[5] == 1  # path_len
    assert frame_v3.endswith(b"ch")


# ---------------------------------------------------------------------------
# CMD_GET_CHANNEL / CMD_SET_CHANNEL
# ---------------------------------------------------------------------------


def _channel_bridge(channels: dict, max_channels: int = 4):
    bridge = Mock()
    bridge.channels = Mock(max_channels=max_channels)
    bridge.get_channel = Mock(side_effect=channels.get)
    bridge.set_channel = Mock(return_value=True)
    return bridge


@pytest.mark.asyncio
async def test_cmd_get_channel_single():
    bridge = _channel_bridge({1: Channel(name="general", secret=b"\x01" * 16)})
    server, frames = _make_capture_server(bridge)
    await server._cmd_get_channel(bytes([1]))
    (frame,) = frames
    assert frame[0] == RESP_CODE_CHANNEL_INFO
    assert frame[1] == 1
    assert frame[2:34].rstrip(b"\x00") == b"general"
    assert frame[34:50] == b"\x01" * 16


@pytest.mark.asyncio
async def test_cmd_get_channel_full_list_and_out_of_range():
    bridge = _channel_bridge({0: Channel(name="a", secret=bytes(16))})
    server, frames = _make_capture_server(bridge)
    await server._cmd_get_channel(b"")
    assert len(frames) == 4  # one frame per slot, empty slots zero-filled
    assert all(f[0] == RESP_CODE_CHANNEL_INFO for f in frames)

    frames.clear()
    await server._cmd_get_channel(bytes([200]))
    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_NOT_FOUND])]


@pytest.mark.asyncio
async def test_cmd_set_channel_secret_encodings():
    bridge = _channel_bridge({})
    server, frames = _make_capture_server(bridge)
    server._save_channels = AsyncMock()

    # 16-byte raw secret
    await server._cmd_set_channel(bytes([2]) + b"general".ljust(32, b"\x00") + b"\x05" * 16)
    assert frames == [bytes([RESP_CODE_OK])]
    bridge.set_channel.assert_called_with(2, "general", b"\x05" * 16)
    server._save_channels.assert_awaited_once()

    # 64-char hex secret
    secret = bytes(range(32))
    frames.clear()
    await server._cmd_set_channel(
        bytes([0]) + b"hex".ljust(32, b"\x00") + secret.hex().encode("ascii")
    )
    assert frames == [bytes([RESP_CODE_OK])]
    bridge.set_channel.assert_called_with(0, "hex", secret)

    # Too short
    frames.clear()
    await server._cmd_set_channel(bytes([0]) + b"x" * 8)
    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_ILLEGAL_ARG])]


# ---------------------------------------------------------------------------
# CMD_GET_STATS
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cmd_get_stats_packets_layout_and_invalid_type():
    bridge = Mock()
    bridge.get_stats = Mock(return_value={})
    server, frames = _make_capture_server(bridge)
    await server._cmd_get_stats(bytes([STATS_TYPE_PACKETS]))
    (frame,) = frames
    assert frame[0] == RESP_CODE_STATS
    assert frame[1] == STATS_TYPE_PACKETS
    assert len(frame) == 2 + 7 * 4

    frames.clear()
    await server._cmd_get_stats(bytes([9]))
    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_ILLEGAL_ARG])]


@pytest.mark.asyncio
async def test_cmd_get_stats_radio_frame_encodes_cached_noise_floor():
    """Protocol-level: a real CompanionRadio with a cached-noise-floor backend
    produces a STATS_TYPE_RADIO frame whose packed noise-floor field carries the
    measurement; without one the field keeps its firmware-compatible 0 fallback.
    """
    from openhop_core.companion import CompanionRadio
    from openhop_core.protocol import LocalIdentity

    class _StatsRadio:
        def set_rx_callback(self, callback):
            self.rx_callback = callback

        async def send(self, data: bytes) -> bool:
            return True

        def get_last_rssi(self):
            return -70

        def get_last_snr(self):
            return 5.0

        def get_cached_noise_floor(self):
            return -117.4

    comp = CompanionRadio(_StatsRadio(), LocalIdentity())
    server, frames = _make_capture_server(comp)
    await server._cmd_get_stats(bytes([STATS_TYPE_RADIO]))
    (frame,) = frames
    assert frame[0] == RESP_CODE_STATS
    assert frame[1] == STATS_TYPE_RADIO
    (noise_floor,) = struct.unpack("<h", frame[2:4])
    assert noise_floor == -117  # int(-117.4): the measurement, not the 0 fallback

    # No measurement yet -> the packed field stays at the existing 0 fallback.
    class _NoMeasurementRadio(_StatsRadio):
        def get_cached_noise_floor(self):
            return None

    comp2 = CompanionRadio(_NoMeasurementRadio(), LocalIdentity())
    server2, frames2 = _make_capture_server(comp2)
    await server2._cmd_get_stats(bytes([STATS_TYPE_RADIO]))
    (frame2,) = frames2
    (noise_floor2,) = struct.unpack("<h", frame2[2:4])
    assert noise_floor2 == 0


@pytest.mark.asyncio
async def test_cmd_get_stats_empty_frame_is_unsupported():
    """Empty CMD_GET_STATS frame (firmware len < 2) is UNSUPPORTED_CMD, not a default stats dump.

    Firmware requires len >= 2 (MyMesh.cpp CMD_GET_STATS); a bare cmd byte
    with no stats-type subtype byte falls through the else-if chain to the
    catch-all writeErrFrame(ERR_CODE_UNSUPPORTED_CMD).
    """
    bridge = Mock()
    server, frames = _make_capture_server(bridge)
    await server._cmd_get_stats(b"")
    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_UNSUPPORTED_CMD])]
    bridge.get_stats.assert_not_called()


@pytest.mark.asyncio
async def test_cmd_get_stats_uses_stats_getter():
    async def getter(stats_type):
        return {"recv": 5, "sent": 6}

    server, frames = _make_capture_server(Mock(), stats_getter=getter)
    await server._cmd_get_stats(bytes([STATS_TYPE_PACKETS]))
    recv, sent = struct.unpack_from("<II", frames[0], 2)
    assert (recv, sent) == (5, 6)


# ---------------------------------------------------------------------------
# _enqueue_frame framing rules
# ---------------------------------------------------------------------------


def test_enqueue_frame_header_format():
    server = CompanionFrameServer(Mock(), "hash", port=0)
    server._write_queue = asyncio.Queue(maxsize=8)
    server._enqueue_frame(b"\x01\x02\x03")
    raw = server._write_queue.get_nowait()
    assert raw == bytes([FRAME_OUTBOUND_PREFIX]) + struct.pack("<H", 3) + b"\x01\x02\x03"


def test_send_confirmed_push_includes_trip_time():
    """PUSH_CODE_SEND_CONFIRMED carries the elapsed ms after the 4-byte CRC."""
    from openhop_core.companion.constants import PUSH_CODE_SEND_CONFIRMED

    server = CompanionFrameServer(Mock(), "hash", port=0)
    server._write_queue = asyncio.Queue(maxsize=8)
    server._on_send_confirmed(0xAABBCCDD, 1234)
    raw = server._write_queue.get_nowait()
    payload = raw[3:]  # strip FRAME_OUTBOUND_PREFIX + uint16 length
    assert payload[0] == PUSH_CODE_SEND_CONFIRMED
    assert payload[1:5] == struct.pack("<I", 0xAABBCCDD)
    assert struct.unpack("<I", payload[5:9])[0] == 1234


def test_enqueue_frame_drops_oversize_payload():
    server = CompanionFrameServer(Mock(), "hash", port=0)
    server._write_queue = asyncio.Queue(maxsize=8)
    # Firmware writeFrame refuses an over-size frame; we drop rather than
    # truncate (a truncated frame would corrupt the response).
    server._enqueue_frame(bytes(MAX_PAYLOAD_SIZE + 1))
    assert server._write_queue.empty()


def test_enqueue_frame_allows_max_payload():
    server = CompanionFrameServer(Mock(), "hash", port=0)
    server._write_queue = asyncio.Queue(maxsize=8)
    server._enqueue_frame(bytes(MAX_PAYLOAD_SIZE))
    raw = server._write_queue.get_nowait()
    assert struct.unpack("<H", raw[1:3])[0] == MAX_PAYLOAD_SIZE


def test_enqueue_frame_no_queue_and_queue_full_are_safe():
    server = CompanionFrameServer(Mock(), "hash", port=0)
    server._write_queue = None
    server._enqueue_frame(b"\x01")  # must not raise

    server._write_queue = asyncio.Queue(maxsize=1)
    server._enqueue_frame(b"\x01")
    server._enqueue_frame(b"\x02")  # dropped, must not raise
    assert server._write_queue.qsize() == 1


# ---------------------------------------------------------------------------
# Simple device commands
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cmd_set_device_time():
    bridge = Mock()
    bridge.set_time = Mock(return_value=True)
    server, frames = _make_capture_server(bridge)
    await server._cmd_set_device_time(struct.pack("<I", 1_700_000_123))
    assert frames == [bytes([RESP_CODE_OK])]
    bridge.set_time.assert_called_once_with(1_700_000_123)

    frames.clear()
    await server._cmd_set_device_time(b"\x01")  # too short
    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_ILLEGAL_ARG])]


@pytest.mark.asyncio
async def test_cmd_set_advert_name_strips_nulls():
    bridge = Mock()
    server, frames = _make_capture_server(bridge)
    await server._cmd_set_advert_name(b"NewName\x00")
    assert frames == [bytes([RESP_CODE_OK])]
    bridge.set_advert_name.assert_called_once_with("NewName")


@pytest.mark.asyncio
async def test_cmd_set_advert_name_empty_frame_is_unsupported():
    """Empty CMD_SET_ADVERT_NAME frame (firmware len < 2) is UNSUPPORTED_CMD, not a name clear.

    Firmware requires len >= 2 (MyMesh.cpp CMD_SET_ADVERT_NAME); a bare cmd
    byte with no name bytes falls through the else-if chain to the catch-all
    writeErrFrame(ERR_CODE_UNSUPPORTED_CMD).
    """
    bridge = Mock()
    server, frames = _make_capture_server(bridge)
    await server._cmd_set_advert_name(b"")
    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_UNSUPPORTED_CMD])]
    bridge.set_advert_name.assert_not_called()


@pytest.mark.asyncio
async def test_handle_cmd_routes_empty_set_advert_name_to_unsupported():
    """Same empty-frame rejection, but through the _handle_cmd dispatch path:
    a full inbound payload of just the CMD_SET_ADVERT_NAME byte must route to
    the handler and come back as UNSUPPORTED_CMD, proving the wiring end to
    end rather than only the handler in isolation."""
    bridge = Mock()
    server, frames = _make_capture_server(bridge)
    await server._handle_cmd(bytes([CMD_SET_ADVERT_NAME]))
    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_UNSUPPORTED_CMD])]
    bridge.set_advert_name.assert_not_called()


@pytest.mark.asyncio
async def test_handle_cmd_set_advert_name_truncates_multibyte_end_to_end():
    """CMD_SET_ADVERT_NAME through _handle_cmd with a real CompanionBridge:
    the stored node name is capped at 31 UTF-8 bytes with a straddling
    codepoint dropped whole (firmware caps the memcpy at
    sizeof(node_name) - 1; the codepoint-clean cut is our deliberate
    UTF-8-safe divergence)."""
    from openhop_core.companion import CompanionBridge
    from openhop_core.protocol import LocalIdentity

    bridge = CompanionBridge(LocalIdentity(), AsyncMock(return_value=True))
    server, frames = _make_capture_server(bridge)

    name = "a" * 30 + "☃"  # 30 ASCII bytes + 3-byte snowman = 33 bytes
    await server._handle_cmd(bytes([CMD_SET_ADVERT_NAME]) + name.encode("utf-8"))

    assert frames == [bytes([RESP_CODE_OK])]
    stored = bridge.get_self_info().node_name
    assert stored == "a" * 30  # snowman straddles the 31-byte cut -> dropped whole
    assert len(stored.encode("utf-8")) <= 31


@pytest.mark.asyncio
async def test_cmd_send_self_advert_flood_flag():
    bridge = Mock()
    bridge.advertise = AsyncMock(return_value=True)
    server, frames = _make_capture_server(bridge)
    await server._cmd_send_self_advert(bytes([1]))
    assert frames == [bytes([RESP_CODE_OK])]
    bridge.advertise.assert_awaited_once_with(flood=True)

    bridge.advertise.reset_mock()
    frames.clear()
    await server._cmd_send_self_advert(b"")
    bridge.advertise.assert_awaited_once_with(flood=False)

    bridge.advertise = AsyncMock(return_value=False)
    frames.clear()
    await server._handle_cmd(bytes.fromhex("07"))
    assert frames == [bytes.fromhex("0103")]


@pytest.mark.asyncio
async def test_cmd_set_radio_params_validates_ranges():
    bridge = Mock()
    server, frames = _make_capture_server(bridge)

    bad_freq = struct.pack("<II", 50, 250_000) + bytes([10, 5])
    await server._cmd_set_radio_params(bad_freq)
    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_ILLEGAL_ARG])]
    bridge.set_radio_params.assert_not_called()

    frames.clear()
    good = struct.pack("<II", 915_000, 250_000) + bytes([10, 5])
    await server._cmd_set_radio_params(good)
    assert frames == [bytes([RESP_CODE_OK])]
    bridge.set_radio_params.assert_called_once_with(915_000_000, 250_000, 10, 5)


@pytest.mark.asyncio
async def test_cmd_set_radio_params_acknowledges_virtual_companion_without_mutation():
    from openhop_core.companion import CompanionBridge
    from openhop_core.protocol import LocalIdentity

    bridge = CompanionBridge(LocalIdentity(), AsyncMock(return_value=True))
    server, frames = _make_capture_server(bridge)
    before = bridge.get_self_info()

    await server._cmd_set_radio_params(struct.pack("<II", 915_000, 250_000) + bytes([10, 5]))

    assert frames == [bytes([RESP_CODE_OK])]
    assert bridge.get_self_info() == before


@pytest.mark.asyncio
async def test_cmd_set_tx_power_acknowledges_virtual_companion_without_mutation():
    from openhop_core.companion import CompanionBridge
    from openhop_core.protocol import LocalIdentity

    bridge = CompanionBridge(LocalIdentity(), AsyncMock(return_value=True))
    server, frames = _make_capture_server(bridge)
    before = bridge.get_self_info()

    await server._cmd_set_tx_power(bytes([14]))

    assert frames == [bytes([RESP_CODE_OK])]
    assert bridge.get_self_info() == before


@pytest.mark.asyncio
async def test_virtual_radio_noops_do_not_block_identity_updates():
    """A combined client save can update identity fields after radio no-ops."""
    from openhop_core.companion import CompanionBridge
    from openhop_core.protocol import LocalIdentity

    bridge = CompanionBridge(LocalIdentity(), AsyncMock(return_value=True))
    server, frames = _make_capture_server(bridge)
    radio_before = bridge.get_radio_params()

    await server._cmd_set_radio_params(struct.pack("<II", 915_000, 250_000) + bytes([10, 5]))
    await server._cmd_set_tx_power(bytes([14]))
    await server._cmd_set_advert_name(b"NewName")
    await server._cmd_set_advert_latlon(struct.pack("<ii", 12_500_000, -3_250_000))

    assert frames == [bytes([RESP_CODE_OK])] * 4
    prefs = bridge.get_self_info()
    assert prefs.node_name == "NewName"
    assert (prefs.latitude, prefs.longitude) == (12.5, -3.25)
    assert bridge.get_radio_params() == radio_before


@pytest.mark.asyncio
async def test_cmd_set_radio_params_reports_backend_failure():
    bridge = Mock()
    bridge.supports_radio_params_mutation.return_value = True
    bridge.set_radio_params.return_value = False
    server, frames = _make_capture_server(bridge)

    await server._cmd_set_radio_params(struct.pack("<II", 915_000, 250_000) + bytes([10, 5]))

    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_BAD_STATE])]
    bridge.set_radio_params.assert_called_once_with(915_000_000, 250_000, 10, 5)


@pytest.mark.asyncio
async def test_cmd_set_radio_params_frequency_lower_bound_is_150mhz():
    """Firmware parity: 149,999 kHz is rejected, 150,000 kHz is accepted."""
    bridge = Mock()
    bridge.get_allowed_repeat_freqs.return_value = ()
    server, frames = _make_capture_server(bridge)

    await server._cmd_set_radio_params(struct.pack("<II", 149_999, 250_000) + bytes([10, 5]))
    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_ILLEGAL_ARG])]
    bridge.set_radio_params.assert_not_called()

    frames.clear()
    await server._cmd_set_radio_params(struct.pack("<II", 150_000, 250_000) + bytes([10, 5]))
    assert frames == [bytes([RESP_CODE_OK])]
    bridge.set_radio_params.assert_called_once_with(150_000_000, 250_000, 10, 5)


@pytest.mark.asyncio
async def test_cmd_set_radio_params_parses_optional_repeat_byte():
    """The extended 11-byte frame's repeat byte is parsed and persisted."""
    bridge = Mock()
    bridge.get_allowed_repeat_freqs.return_value = ((433000, 433000),)
    server, frames = _make_capture_server(bridge)

    # No repeat byte -> persisted as 0 (firmware resets client_repeat).
    await server._cmd_set_radio_params(struct.pack("<II", 433_000, 250_000) + bytes([10, 5]))
    assert frames == [bytes([RESP_CODE_OK])]
    bridge.set_client_repeat.assert_called_once_with(0)

    bridge.set_client_repeat.reset_mock()
    frames.clear()
    # Repeat byte = 1 on an allowed frequency -> persisted as 1.
    await server._cmd_set_radio_params(struct.pack("<II", 433_000, 250_000) + bytes([10, 5, 1]))
    assert frames == [bytes([RESP_CODE_OK])]
    bridge.set_client_repeat.assert_called_once_with(1)


@pytest.mark.asyncio
async def test_cmd_set_radio_params_repeat_on_disallowed_freq_is_illegal_arg():
    bridge = Mock()
    bridge.get_allowed_repeat_freqs.return_value = ((433000, 433000), (918000, 918000))
    server, frames = _make_capture_server(bridge)

    # 868,000 kHz is a valid general frequency but not an allowed repeat freq.
    await server._cmd_set_radio_params(struct.pack("<II", 868_000, 250_000) + bytes([10, 5, 1]))
    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_ILLEGAL_ARG])]
    bridge.set_radio_params.assert_not_called()
    bridge.set_client_repeat.assert_not_called()


@pytest.mark.asyncio
async def test_cmd_set_radio_params_repeat_persists_and_byte80_roundtrips():
    """repeat=1 on an allowed freq persists and DEVICE_QUERY byte 80 reflects it."""
    from openhop_core.companion import CompanionRadio
    from openhop_core.protocol import LocalIdentity

    class ConfigurableRadio:
        def set_rx_callback(self, cb):
            pass

        def configure_radio(self, **kwargs):
            return True

        async def send(self, data):
            return True

        def get_last_rssi(self):
            return -70

        def get_last_snr(self):
            return 5

    comp = CompanionRadio(ConfigurableRadio(), LocalIdentity())
    server, frames = _make_capture_server(comp)

    await server._cmd_set_radio_params(struct.pack("<II", 433_000, 250_000) + bytes([10, 5, 1]))
    assert frames == [bytes([RESP_CODE_OK])]
    assert comp.prefs.client_repeat == 1
    assert comp.node.dispatcher._client_repeat_enabled is True

    frames.clear()
    await server._cmd_device_query(bytes([3]))
    assert frames[0][80] == 1


@pytest.mark.asyncio
async def test_cmd_set_radio_params_bridge_acks_but_ignores_repeat():
    """A virtual companion acks the save but never enables client-repeat."""
    from openhop_core.companion import CompanionBridge
    from openhop_core.protocol import LocalIdentity

    bridge = CompanionBridge(LocalIdentity(), AsyncMock(return_value=True))
    server, frames = _make_capture_server(bridge)

    await server._cmd_set_radio_params(struct.pack("<II", 433_000, 250_000) + bytes([10, 5, 1]))
    assert frames == [bytes([RESP_CODE_OK])]
    assert bridge.get_self_info().client_repeat == 0

    frames.clear()
    await server._cmd_device_query(bytes([3]))
    assert frames[0][80] == 0


@pytest.mark.asyncio
async def test_cmd_get_allowed_repeat_freq_default_table_bytes():
    """The default table serialises to the three firmware repeat bands."""
    from openhop_core.companion import CompanionRadio
    from openhop_core.protocol import LocalIdentity

    class _Radio:
        def set_rx_callback(self, cb):
            pass

        async def send(self, data):
            return True

    comp = CompanionRadio(_Radio(), LocalIdentity())
    server, frames = _make_capture_server(comp)
    await server._cmd_get_allowed_repeat_freq(b"")
    assert frames == [
        bytes([RESP_CODE_ALLOWED_REPEAT_FREQ])
        + struct.pack("<II", 433000, 433000)
        + struct.pack("<II", 869495, 869495)
        + struct.pack("<II", 918000, 918000)
    ]


@pytest.mark.asyncio
async def test_cmd_set_tx_power_reports_backend_failure():
    bridge = Mock()
    bridge.supports_tx_power_mutation.return_value = True
    bridge.set_tx_power.return_value = False
    server, frames = _make_capture_server(bridge)

    await server._cmd_set_tx_power(bytes([14]))

    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_BAD_STATE])]
    bridge.set_tx_power.assert_called_once_with(14)


@pytest.mark.asyncio
async def test_cmd_set_tx_power_rejects_above_advertised_hardware_max():
    """Firmware (MyMesh.cpp CMD_SET_RADIO_TX_POWER) rejects power >
    MAX_LORA_TX_POWER, the same target-specific limit SELF_INFO advertises.
    A backend that only advertises 19 dBm must reject a 20 dBm request even
    though it is below the generic 30 dBm ceiling."""
    bridge = Mock()
    bridge.supports_tx_power_mutation.return_value = True
    bridge.get_max_tx_power_dbm = Mock(return_value=19)
    server, frames = _make_capture_server(bridge)

    await server._cmd_set_tx_power(bytes([20]))

    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_ILLEGAL_ARG])]
    bridge.set_tx_power.assert_not_called()


@pytest.mark.asyncio
async def test_cmd_set_tx_power_accepts_value_exactly_at_advertised_max():
    """Firmware's comparison is `power > MAX_LORA_TX_POWER`, so the max value
    itself is inclusive and must be accepted."""
    bridge = Mock()
    bridge.supports_tx_power_mutation.return_value = True
    bridge.get_max_tx_power_dbm = Mock(return_value=19)
    bridge.set_tx_power.return_value = True
    server, frames = _make_capture_server(bridge)

    await server._cmd_set_tx_power(bytes([19]))

    assert frames == [bytes([RESP_CODE_OK])]
    bridge.set_tx_power.assert_called_once_with(19)


@pytest.mark.asyncio
async def test_cmd_set_tx_power_floor_boundary():
    """Firmware's lower bound is `power < -9` -> ILLEGAL_ARG, so -9 itself is
    the lowest accepted value and -10 is rejected."""
    bridge = Mock()
    bridge.supports_tx_power_mutation.return_value = True
    bridge.get_max_tx_power_dbm = Mock(return_value=19)
    bridge.set_tx_power.return_value = True
    server, frames = _make_capture_server(bridge)

    await server._cmd_set_tx_power(struct.pack("<b", -10))
    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_ILLEGAL_ARG])]
    bridge.set_tx_power.assert_not_called()

    frames.clear()
    await server._cmd_set_tx_power(struct.pack("<b", -9))
    assert frames == [bytes([RESP_CODE_OK])]
    bridge.set_tx_power.assert_called_once_with(-9)


@pytest.mark.asyncio
async def test_cmd_set_tx_power_accepts_normal_value_below_max():
    """No regression: a normal in-range request below the advertised max is
    still accepted and applied."""
    bridge = Mock()
    bridge.supports_tx_power_mutation.return_value = True
    bridge.get_max_tx_power_dbm = Mock(return_value=22)
    bridge.set_tx_power.return_value = True
    server, frames = _make_capture_server(bridge)

    await server._cmd_set_tx_power(bytes([14]))

    assert frames == [bytes([RESP_CODE_OK])]
    bridge.set_tx_power.assert_called_once_with(14)


@pytest.mark.asyncio
async def test_cmd_set_tx_power_above_max_leaves_real_bridge_radio_unchanged():
    """End-to-end with a real CompanionBridge (default advertised max 22 dBm):
    a request above the hardware limit is rejected and the active tx power
    is left untouched."""
    from openhop_core.companion import CompanionBridge
    from openhop_core.protocol import LocalIdentity

    bridge = CompanionBridge(LocalIdentity(), AsyncMock(return_value=True))
    server, frames = _make_capture_server(bridge)
    before = bridge.get_self_info().tx_power_dbm

    await server._cmd_set_tx_power(bytes([23]))

    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_ILLEGAL_ARG])]
    assert bridge.get_self_info().tx_power_dbm == before


# ---------------------------------------------------------------------------
# TXT_TYPE_SIGNED_PLAIN (room server posts): author prefix in the frame
# ---------------------------------------------------------------------------


def test_build_message_frame_signed_plain_inserts_author_prefix():
    """Signed messages carry the 4-byte author prefix between timestamp and
    text, matching firmware queueMessage(extra=sender_prefix, extra_len=4)."""
    from openhop_core.companion.constants import TXT_TYPE_SIGNED_PLAIN

    server = CompanionFrameServer(Mock(), "hash", port=0)
    msg = QueuedMessage(
        sender_key=bytes([0xAA] * 32),
        txt_type=TXT_TYPE_SIGNED_PLAIN,
        timestamp=1_650_000_000,
        text="room post",
        path_len=2,
        sender_prefix=b"\xde\xad\xbe\xef",
    )

    server._app_target_ver = 0
    frame = server._build_message_frame(msg)
    assert frame == (
        bytes([RESP_CODE_CONTACT_MSG_RECV])
        + bytes([0xAA] * 6)
        + bytes([2, TXT_TYPE_SIGNED_PLAIN])
        + struct.pack("<I", 1_650_000_000)
        + b"\xde\xad\xbe\xef"
        + b"room post"
    )

    server._app_target_ver = 3
    frame_v3 = server._build_message_frame(msg)
    assert frame_v3[0] == RESP_CODE_CONTACT_MSG_RECV_V3
    assert frame_v3[4:10] == bytes([0xAA] * 6)
    assert frame_v3[10] == 2  # path_len
    assert frame_v3[11] == TXT_TYPE_SIGNED_PLAIN
    assert frame_v3[12:16] == struct.pack("<I", 1_650_000_000)
    assert frame_v3[16:20] == b"\xde\xad\xbe\xef"
    assert frame_v3[20:] == b"room post"


def test_build_message_frame_signed_plain_pads_missing_prefix():
    """A missing author prefix is zero-padded so the app's 4-byte strip never
    eats message text; plain messages get no extra field at all."""
    from openhop_core.companion.constants import TXT_TYPE_SIGNED_PLAIN

    server = CompanionFrameServer(Mock(), "hash", port=0)
    server._app_target_ver = 0

    signed = QueuedMessage(
        sender_key=bytes(32), txt_type=TXT_TYPE_SIGNED_PLAIN, timestamp=7, text="hi"
    )
    frame = server._build_message_frame(signed)
    assert frame[9:13] == struct.pack("<I", 7)
    assert frame[13:17] == b"\x00\x00\x00\x00"  # padded author prefix
    assert frame[17:] == b"hi"

    plain = QueuedMessage(sender_key=bytes(32), txt_type=0, timestamp=7, text="hi")
    frame = server._build_message_frame(plain)
    assert frame[9:13] == struct.pack("<I", 7)
    assert frame[13:] == b"hi"  # no extra field for plain


# ---------------------------------------------------------------------------
# CMD_GET_TUNING_PARAMS (43) and CMD_HAS_CONNECTION (28)
# ---------------------------------------------------------------------------


def _tuning_bridge():
    from openhop_core.companion.companion_bridge import CompanionBridge
    from openhop_core.protocol import LocalIdentity

    return CompanionBridge(LocalIdentity(), AsyncMock(return_value=True))


@pytest.mark.asyncio
async def test_cmd_get_tuning_params_roundtrip():
    """SET then GET returns exactly the values that were set (ms units)."""
    server, frames = _make_capture_server(_tuning_bridge())
    await server._handle_cmd(bytes([CMD_SET_TUNING_PARAMS]) + struct.pack("<II", 250, 1500))
    frames.clear()
    await server._handle_cmd(bytes([CMD_GET_TUNING_PARAMS]))
    assert frames == [bytes([RESP_CODE_TUNING_PARAMS]) + struct.pack("<II", 250, 1500)]


@pytest.mark.asyncio
async def test_cmd_get_tuning_params_defaults():
    """A fresh bridge reports the firmware defaults (rx 0.0, airtime factor 1.0)."""
    server, frames = _make_capture_server(_tuning_bridge())
    await server._handle_cmd(bytes([CMD_GET_TUNING_PARAMS]))
    assert frames == [bytes([RESP_CODE_TUNING_PARAMS]) + struct.pack("<II", 0, 1000)]


@pytest.mark.asyncio
async def test_cmd_get_tuning_params_ignores_extra_bytes():
    """Firmware (MyMesh.cpp:1428) has no length guard: trailing bytes are
    ignored and the fixed 9-byte frame is still returned."""
    server, frames = _make_capture_server(_tuning_bridge())
    await server._handle_cmd(bytes([CMD_SET_TUNING_PARAMS]) + struct.pack("<II", 250, 1500))
    frames.clear()
    await server._handle_cmd(bytes([CMD_GET_TUNING_PARAMS]) + b"\xff\xff\xff")
    assert frames == [bytes([RESP_CODE_TUNING_PARAMS]) + struct.pack("<II", 250, 1500)]


@pytest.mark.asyncio
async def test_cmd_has_connection_short_frame_unsupported():
    """A pub key shorter than 32 bytes fails the firmware length guard
    (MyMesh.cpp:1678) and falls through to ERR_CODE_UNSUPPORTED_CMD."""
    server, frames = _make_capture_server(_tuning_bridge())
    await server._handle_cmd(bytes([CMD_HAS_CONNECTION]) + b"\x01" * 31)
    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_UNSUPPORTED_CMD])]


@pytest.mark.asyncio
async def test_cmd_has_connection_not_found():
    """A full pub key with no live login session returns ERR_CODE_NOT_FOUND."""
    server, frames = _make_capture_server(_tuning_bridge())
    await server._handle_cmd(bytes([CMD_HAS_CONNECTION]) + b"\x02" * PUB_KEY_SIZE)
    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_NOT_FOUND])]


@pytest.mark.asyncio
async def test_cmd_has_connection_ok_after_login():
    """After the wired login-success path records a connection, HAS_CONNECTION
    reports RESP_CODE_OK."""
    bridge = _tuning_bridge()
    server, frames = _make_capture_server(bridge)
    pubkey = b"\x03" * PUB_KEY_SIZE
    # note_login_connection is the method fired by the login-response path
    # (_format_login_result). keep_alive_interval byte 4 -> 64s window.
    bridge.note_login_connection(pubkey, 4)
    await server._handle_cmd(bytes([CMD_HAS_CONNECTION]) + pubkey)
    assert frames == [bytes([RESP_CODE_OK])]


@pytest.mark.asyncio
async def test_cmd_has_connection_zero_keep_alive_not_recorded():
    """Firmware only calls startConnection when keep_alive_secs > 0
    (MyMesh.cpp:688), so a zero interval records nothing."""
    bridge = _tuning_bridge()
    server, frames = _make_capture_server(bridge)
    pubkey = b"\x04" * PUB_KEY_SIZE
    bridge.note_login_connection(pubkey, 0)
    await server._handle_cmd(bytes([CMD_HAS_CONNECTION]) + pubkey)
    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_NOT_FOUND])]


@pytest.mark.asyncio
async def test_cmd_has_connection_cleared_on_logout():
    """CMD_LOGOUT clears the connection (stopConnection, BaseChatMesh.cpp:695),
    so a subsequent HAS_CONNECTION reports NOT_FOUND."""
    bridge = _tuning_bridge()
    server, frames = _make_capture_server(bridge)
    pubkey = b"\x05" * PUB_KEY_SIZE
    bridge.note_login_connection(pubkey, 4)
    await server._handle_cmd(bytes([CMD_LOGOUT]) + pubkey)
    frames.clear()
    await server._handle_cmd(bytes([CMD_HAS_CONNECTION]) + pubkey)
    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_NOT_FOUND])]


@pytest.mark.asyncio
async def test_cmd_has_connection_expires(monkeypatch):
    """A connection expires 2.5x the keep-alive window after login, mirroring
    firmware checkConnections (BaseChatMesh.cpp:749)."""
    import openhop_core.companion.base_send as base_send

    bridge = _tuning_bridge()
    server, frames = _make_capture_server(bridge)
    pubkey = b"\x06" * PUB_KEY_SIZE

    clock = {"now": 1000.0}
    monkeypatch.setattr(base_send.time, "monotonic", lambda: clock["now"])

    # keep_alive_interval 4 -> 64s keep-alive -> 160s expiry window.
    bridge.note_login_connection(pubkey, 4)
    clock["now"] = 1000.0 + 159.0
    await server._handle_cmd(bytes([CMD_HAS_CONNECTION]) + pubkey)
    assert frames == [bytes([RESP_CODE_OK])]

    frames.clear()
    clock["now"] = 1000.0 + 161.0
    await server._handle_cmd(bytes([CMD_HAS_CONNECTION]) + pubkey)
    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_NOT_FOUND])]


# ---------------------------------------------------------------------------
# CMD_SEND_TRACE_PATH
# ---------------------------------------------------------------------------


def _trace_bridge(result):
    bridge = Mock()
    bridge.send_trace_path_raw = AsyncMock(return_value=result)
    return bridge


def _trace_frame(tag=0x11223344, auth=0x55667788, flags=0, path=b"\x01\x02"):
    """CMD_SEND_TRACE_PATH payload as the handler sees it (command byte stripped)."""
    return struct.pack("<II", tag, auth) + bytes([flags]) + path


@pytest.mark.asyncio
async def test_cmd_send_trace_path_reports_bridge_est_timeout():
    """The SENT frame carries the trace tag and the bridge's est_timeout verbatim.

    Firmware writes RESP_CODE_SENT with the flood byte hardcoded to 0 and
    est_timeout = calcDirectTimeoutMillisFor(...) (MyMesh.cpp:1764-1772).
    """
    result = SentResult(success=True, is_flood=False, expected_ack=0x11223344, timeout_ms=3848)
    server, frames = _make_capture_server(_trace_bridge(result))
    await server._cmd_send_trace_path(_trace_frame())
    assert frames == [bytes([RESP_CODE_SENT, 0]) + struct.pack("<II", 0x11223344, 3848)]


@pytest.mark.asyncio
async def test_cmd_send_trace_path_passes_frame_fields_to_bridge():
    result = SentResult(success=True, expected_ack=0xAABBCCDD, timeout_ms=1234)
    bridge = _trace_bridge(result)
    server, _frames = _make_capture_server(bridge)
    await server._cmd_send_trace_path(
        _trace_frame(tag=0xAABBCCDD, auth=0x99, flags=1, path=b"\x01\x02\x03\x04")
    )
    bridge.send_trace_path_raw.assert_awaited_once_with(0xAABBCCDD, 0x99, 1, b"\x01\x02\x03\x04")


@pytest.mark.asyncio
async def test_cmd_send_trace_path_no_synthetic_push_for_self_terminated_path():
    """A path ending in our own hash must not fabricate a TRACE_DATA push.

    Firmware never emits PUSH_CODE_TRACE_DATA from the send handler; completion
    is delivered by the receive pipeline when the echoed trace reaches the end
    of its path (Mesh.cpp:54 -> onTraceRecv). The old shortcut also compared a
    single byte against multi-byte hash entries, so it fired on suffix
    collisions.
    """
    result = SentResult(success=True, expected_ack=0x11223344, timeout_ms=3848)
    server, frames = _make_capture_server(_trace_bridge(result), local_hash=0x02)
    server.push_trace_data = Mock()
    await server._cmd_send_trace_path(_trace_frame(path=b"\x01\x02"))
    server.push_trace_data.assert_not_called()
    assert [f[0] for f in frames] == [RESP_CODE_SENT]


@pytest.mark.asyncio
async def test_cmd_send_trace_path_no_synthetic_push_on_multibyte_suffix_collision():
    """flags=1 -> 2-byte hashes; a final hash of 0x0102 must not match local 0x02."""
    result = SentResult(success=True, expected_ack=0x11223344, timeout_ms=999)
    server, frames = _make_capture_server(_trace_bridge(result), local_hash=0x02)
    server.push_trace_data = Mock()
    await server._cmd_send_trace_path(_trace_frame(flags=1, path=b"\xaa\xbb\x01\x02"))
    server.push_trace_data.assert_not_called()
    assert [f[0] for f in frames] == [RESP_CODE_SENT]


@pytest.mark.asyncio
async def test_cmd_send_trace_path_send_failure_is_table_full():
    result = SentResult(success=False, error="send_failed")
    server, frames = _make_capture_server(_trace_bridge(result))
    await server._cmd_send_trace_path(_trace_frame())
    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_TABLE_FULL])]


@pytest.mark.asyncio
async def test_cmd_send_trace_path_short_frame_is_illegal_arg():
    """Firmware requires len > 10 (cmd byte + tag/auth/flags + >= 1 path byte)."""
    bridge = _trace_bridge(SentResult(success=True))
    server, frames = _make_capture_server(bridge)
    await server._cmd_send_trace_path(_trace_frame(path=b""))
    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_ILLEGAL_ARG])]
    bridge.send_trace_path_raw.assert_not_awaited()


@pytest.mark.asyncio
async def test_cmd_send_trace_path_validates_path_against_hash_width():
    """Firmware: (path_len >> path_sz) > MAX_PATH_SIZE or path_len % (1 << path_sz)."""
    bridge = _trace_bridge(SentResult(success=True))
    server, frames = _make_capture_server(bridge)

    # flags=1 -> 2-byte hashes; an odd path length is not a whole number of hops.
    await server._cmd_send_trace_path(_trace_frame(flags=1, path=b"\x01\x02\x03"))
    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_ILLEGAL_ARG])]

    # 65 one-byte hops exceeds MAX_PATH_SIZE.
    frames.clear()
    await server._cmd_send_trace_path(_trace_frame(path=bytes(MAX_PATH_SIZE + 1)))
    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_ILLEGAL_ARG])]

    bridge.send_trace_path_raw.assert_not_awaited()


@pytest.mark.asyncio
async def test_cmd_send_trace_path_missing_bridge_method_is_unsupported():
    bridge = Mock(spec=[])
    server, frames = _make_capture_server(bridge)
    await server._cmd_send_trace_path(_trace_frame())
    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_UNSUPPORTED_CMD])]


@pytest.mark.asyncio
async def test_cmd_send_trace_path_bridge_exception_is_illegal_arg():
    bridge = Mock()
    bridge.send_trace_path_raw = AsyncMock(side_effect=RuntimeError("boom"))
    server, frames = _make_capture_server(bridge)
    await server._cmd_send_trace_path(_trace_frame())
    assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_ILLEGAL_ARG])]
