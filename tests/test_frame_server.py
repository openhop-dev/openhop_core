"""Tests for CompanionFrameServer and advert push frame construction."""

import asyncio
import logging
import struct
from unittest.mock import AsyncMock, Mock

import pytest

from openhop_core.companion.constants import (
    ERR_CODE_ILLEGAL_ARG,
    ERR_CODE_NOT_FOUND,
    ERR_CODE_TABLE_FULL,
    ERR_CODE_UNSUPPORTED_CMD,
    MAX_PATH_SIZE,
    PUB_KEY_SIZE,
    PUSH_CODE_ADVERT,
    PUSH_CODE_NEW_ADVERT,
    RESP_CODE_ALLOWED_REPEAT_FREQ,
    RESP_CODE_CHANNEL_DATA_RECV,
    RESP_CODE_DEFAULT_FLOOD_SCOPE,
    RESP_CODE_OK,
)
from openhop_core.companion.frame_server import CompanionFrameServer, _build_advert_push_frames
from openhop_core.companion.models import Contact, QueuedMessage, SentResult


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
async def test_cmd_send_raw_data_invalid_len_writes_unsupported():
    """Invalid CMD_SEND_RAW_DATA len < 6 -> ERR_CODE_UNSUPPORTED_CMD."""
    bridge = _MockBridgeSendRawDirect()
    server = CompanionFrameServer(bridge, "hash", port=0)
    server._write_ok = Mock()
    server._write_err = Mock()
    await server._cmd_send_raw_data(b"\x00\x00\x00")
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


# ---------------------------------------------------------------------------
# CMD_SEND_STATUS_REQ / CMD_SEND_TELEMETRY_REQ — no empty push on failure
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cmd_send_status_req_failure_no_empty_push():
    """Failed status request must NOT send PUSH_CODE_STATUS_RESPONSE (matches firmware)."""
    from openhop_core.companion.constants import PUSH_CODE_STATUS_RESPONSE, RESP_CODE_SENT

    bridge = Mock()
    bridge.send_status_request = AsyncMock(return_value={"success": False, "reason": "timeout"})
    server = CompanionFrameServer(bridge, "hash", port=0)
    frames: list[bytes] = []
    server._write_frame = lambda f: frames.append(f)

    pubkey = bytes(range(32))
    await server._cmd_send_status_req(pubkey)

    # Should have sent RESP_CODE_SENT but NOT PUSH_CODE_STATUS_RESPONSE
    assert any(f[0] == RESP_CODE_SENT for f in frames)
    assert not any(f[0] == PUSH_CODE_STATUS_RESPONSE for f in frames)


@pytest.mark.asyncio
async def test_cmd_send_status_req_empty_raw_bytes_no_push():
    """Status response with empty raw_bytes must NOT send PUSH_CODE_STATUS_RESPONSE."""
    from openhop_core.companion.constants import PUSH_CODE_STATUS_RESPONSE, RESP_CODE_SENT

    bridge = Mock()
    bridge.send_status_request = AsyncMock(
        return_value={"success": True, "stats": {"raw_bytes": b""}}
    )
    server = CompanionFrameServer(bridge, "hash", port=0)
    frames: list[bytes] = []
    server._write_frame = lambda f: frames.append(f)

    pubkey = bytes(range(32))
    await server._cmd_send_status_req(pubkey)

    assert any(f[0] == RESP_CODE_SENT for f in frames)
    assert not any(f[0] == PUSH_CODE_STATUS_RESPONSE for f in frames)


@pytest.mark.asyncio
async def test_cmd_send_status_req_success_sends_push_with_data():
    """Successful status request with data sends PUSH_CODE_STATUS_RESPONSE with raw_bytes."""
    from openhop_core.companion.constants import PUSH_CODE_STATUS_RESPONSE

    raw = b"\x01" * 56
    bridge = Mock()
    bridge.send_status_request = AsyncMock(
        return_value={"success": True, "stats": {"raw_bytes": raw}}
    )
    server = CompanionFrameServer(bridge, "hash", port=0)
    frames: list[bytes] = []
    server._write_frame = lambda f: frames.append(f)

    pubkey = bytes(range(32))
    await server._cmd_send_status_req(pubkey)

    status_frames = [f for f in frames if f[0] == PUSH_CODE_STATUS_RESPONSE]
    assert len(status_frames) == 1
    # Frame: cmd(1) + reserved(1) + pubkey_prefix(6) + raw_bytes(56) = 64
    assert len(status_frames[0]) == 64
    assert status_frames[0][8:] == raw


@pytest.mark.asyncio
async def test_cmd_send_telemetry_req_failure_no_empty_push():
    """Failed telemetry request must NOT send PUSH_CODE_TELEMETRY_RESPONSE."""
    from openhop_core.companion.constants import PUSH_CODE_TELEMETRY_RESPONSE, RESP_CODE_SENT

    bridge = Mock()
    bridge.send_telemetry_request = AsyncMock(return_value={"success": False})
    server = CompanionFrameServer(bridge, "hash", port=0)
    frames: list[bytes] = []
    server._write_frame = lambda f: frames.append(f)

    # CMD_SEND_TELEMETRY_REQ expects 3 reserved bytes + 32-byte pubkey
    pubkey = bytes(range(32))
    data = bytes(3) + pubkey
    await server._cmd_send_telemetry_req(data)

    assert any(f[0] == RESP_CODE_SENT for f in frames)
    assert not any(f[0] == PUSH_CODE_TELEMETRY_RESPONSE for f in frames)


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


@pytest.mark.asyncio
async def test_cmd_get_allowed_repeat_freq_empty_list():
    """CMD_GET_ALLOWED_REPEAT_FREQ replies with the response code and no ranges."""
    server = CompanionFrameServer(Mock(), "hash", port=0)
    frames: list[bytes] = []
    server._write_frame = lambda f: frames.append(f)
    await server._cmd_get_allowed_repeat_freq(b"")
    assert frames == [bytes([RESP_CODE_ALLOWED_REPEAT_FREQ])]


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
    from openhop_core.companion.constants import ANON_REQ_TYPE_REGIONS, PROTOCOL_CODE_ANON_REQ

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
    from openhop_core.companion.constants import ANON_REQ_TYPE_REGIONS, PROTOCOL_CODE_ANON_REQ

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


def test_max_frame_size_is_176():
    """Companion frame size tracks firmware PR #2022 (172 -> 176)."""
    from openhop_core.companion.constants import (
        MAX_CHANNEL_DATA_LENGTH,
        MAX_FRAME_SIZE,
        MAX_PAYLOAD_SIZE,
    )

    assert MAX_FRAME_SIZE == 176
    assert MAX_PAYLOAD_SIZE == 173
    assert MAX_CHANNEL_DATA_LENGTH == 167


@pytest.mark.asyncio
async def test_cmd_send_txt_msg_threads_host_timestamp():
    """Plain DM: the host-supplied msg_timestamp (data[2:6]) is passed through verbatim so
    retries share a stable timestamp (mirrors firmware sendMessage)."""
    from unittest.mock import AsyncMock

    from openhop_core.companion.companion_bridge import CompanionBridge
    from openhop_core.companion.constants import TXT_TYPE_CLI_DATA, TXT_TYPE_PLAIN
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

    # CLI_DATA mints a fresh timestamp (timestamp=None), matching firmware's RTC override.
    bridge.send_text_message.reset_mock()
    data_cli = bytes([TXT_TYPE_CLI_DATA, 0]) + struct.pack("<I", host_ts) + pubkey[:6] + b"cmd"
    await server._cmd_send_txt_msg(data_cli)
    assert bridge.send_text_message.call_args.kwargs["timestamp"] is None


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
