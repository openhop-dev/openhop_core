"""
CompanionFrameServer - Standard MeshCore Companion Radio Protocol over TCP.

Implements the full companion frame protocol: command dispatch, push callbacks,
and contact/message/channel management.  Persistence is handled through
overridable hook methods so the base class works standalone (in-memory only)
while subclasses can add SQLite or other storage backends.

Frame format:
    Outbound (radio → app): ``>`` (0x3E) + 2-byte LE length + data
    Inbound  (app → radio): ``<`` (0x3C) + 2-byte LE length + data
"""

import asyncio
import logging
import socket
import struct
import sys
import time
from typing import Any, Callable, Optional

from ..protocol import CryptoUtils
from ..protocol.packet_utils import PathUtils
from .constants import (
    ADV_TYPE_CHAT,
    ADV_TYPE_NONE,
    CMD_ADD_UPDATE_CONTACT,
    CMD_APP_START,
    CMD_DEVICE_QUERY,
    CMD_EXPORT_CONTACT,
    CMD_EXPORT_PRIVATE_KEY,
    CMD_GET_ADVERT_PATH,
    CMD_GET_ALLOWED_REPEAT_FREQ,
    CMD_GET_AUTOADD_CONFIG,
    CMD_GET_BATT_AND_STORAGE,
    CMD_GET_CHANNEL,
    CMD_GET_CONTACT_BY_KEY,
    CMD_GET_CONTACTS,
    CMD_GET_CUSTOM_VARS,
    CMD_GET_DEFAULT_FLOOD_SCOPE,
    CMD_GET_DEVICE_TIME,
    CMD_GET_STATS,
    CMD_IMPORT_CONTACT,
    CMD_IMPORT_PRIVATE_KEY,
    CMD_LOGOUT,
    CMD_REMOVE_CONTACT,
    CMD_RESET_PATH,
    CMD_SEND_ANON_REQ,
    CMD_SEND_BINARY_REQ,
    CMD_SEND_CHANNEL_DATA,
    CMD_SEND_CHANNEL_TXT_MSG,
    CMD_SEND_CONTROL_DATA,
    CMD_SEND_LOGIN,
    CMD_SEND_PATH_DISCOVERY_REQ,
    CMD_SEND_RAW_DATA,
    CMD_SEND_RAW_PACKET,
    CMD_SEND_SELF_ADVERT,
    CMD_SEND_STATUS_REQ,
    CMD_SEND_TELEMETRY_REQ,
    CMD_SEND_TRACE_PATH,
    CMD_SEND_TXT_MSG,
    CMD_SET_ADVERT_LATLON,
    CMD_SET_ADVERT_NAME,
    CMD_SET_AUTOADD_CONFIG,
    CMD_SET_CHANNEL,
    CMD_SET_CUSTOM_VAR,
    CMD_SET_DEFAULT_FLOOD_SCOPE,
    CMD_SET_DEVICE_TIME,
    CMD_SET_FLOOD_SCOPE,
    CMD_SET_OTHER_PARAMS,
    CMD_SET_PATH_HASH_MODE,
    CMD_SET_RADIO_PARAMS,
    CMD_SET_RADIO_TX_POWER,
    CMD_SET_TUNING_PARAMS,
    CMD_SHARE_CONTACT,
    CMD_SYNC_NEXT_MESSAGE,
    ERR_CODE_BAD_STATE,
    ERR_CODE_ILLEGAL_ARG,
    ERR_CODE_NOT_FOUND,
    ERR_CODE_TABLE_FULL,
    ERR_CODE_UNSUPPORTED_CMD,
    FIRMWARE_VER_CODE,
    FRAME_INBOUND_PREFIX,
    FRAME_OUTBOUND_PREFIX,
    MAX_CHANNEL_DATA_LENGTH,
    MAX_FRAME_SIZE,
    MAX_PATH_SIZE,
    MAX_PAYLOAD_SIZE,
    OUT_PATH_UNKNOWN,
    PUB_KEY_SIZE,
    PUSH_CODE_ADVERT,
    PUSH_CODE_BINARY_RESPONSE,
    PUSH_CODE_CONTACT_DELETED,
    PUSH_CODE_CONTACTS_FULL,
    PUSH_CODE_CONTROL_DATA,
    PUSH_CODE_LOG_RX_DATA,
    PUSH_CODE_LOGIN_FAIL,
    PUSH_CODE_LOGIN_SUCCESS,
    PUSH_CODE_MSG_WAITING,
    PUSH_CODE_NEW_ADVERT,
    PUSH_CODE_PATH_DISCOVERY_RESPONSE,
    PUSH_CODE_PATH_UPDATED,
    PUSH_CODE_RAW_DATA,
    PUSH_CODE_SEND_CONFIRMED,
    PUSH_CODE_STATUS_RESPONSE,
    PUSH_CODE_TELEMETRY_RESPONSE,
    PUSH_CODE_TRACE_DATA,
    RESP_CODE_ADVERT_PATH,
    RESP_CODE_ALLOWED_REPEAT_FREQ,
    RESP_CODE_AUTOADD_CONFIG,
    RESP_CODE_BATT_AND_STORAGE,
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
    RESP_CODE_DEVICE_INFO,
    RESP_CODE_END_OF_CONTACTS,
    RESP_CODE_ERR,
    RESP_CODE_EXPORT_CONTACT,
    RESP_CODE_NO_MORE_MESSAGES,
    RESP_CODE_OK,
    RESP_CODE_PRIVATE_KEY,
    RESP_CODE_SELF_INFO,
    RESP_CODE_SENT,
    RESP_CODE_STATS,
    STATS_TYPE_CORE,
    STATS_TYPE_PACKETS,
    STATS_TYPE_RADIO,
    TXT_TYPE_CLI_DATA,
)
from .models import Contact, QueuedMessage

logger = logging.getLogger("CompanionFrameServer")


def _build_advert_push_frames(contact: Contact) -> tuple[bytes, Optional[bytes]]:
    """Build PUSH_CODE_ADVERT short frame and optional PUSH_CODE_NEW_ADVERT
    full frame from contact.  Thread-safe for ``asyncio.to_thread``."""
    pubkey_b = contact.public_key
    if isinstance(pubkey_b, bytes):
        pubkey_b = pubkey_b[:32].ljust(32, b"\x00")
    else:
        pubkey_b = b"\x00" * 32
    short = bytes([PUSH_CODE_ADVERT]) + pubkey_b
    if not contact.name:
        return (short, None)
    op = contact.out_path if isinstance(contact.out_path, bytes) else bytes(contact.out_path or [])
    op = op[:MAX_PATH_SIZE].ljust(MAX_PATH_SIZE, b"\x00")
    nb = (
        contact.name.encode("utf-8", errors="replace")
        if isinstance(contact.name, str)
        else (contact.name if isinstance(contact.name, bytes) else b"")
    )[:32].ljust(32, b"\x00")
    opl_byte = 0xFF if contact.out_path_len < 0 else min(contact.out_path_len, 255)
    full = (
        bytes([PUSH_CODE_NEW_ADVERT])
        + pubkey_b
        + bytes([contact.adv_type, contact.flags, opl_byte])
        + op
        + nb
        + struct.pack("<I", contact.last_advert_timestamp)
        + struct.pack("<i", int(contact.gps_lat * 1e6))
        + struct.pack("<i", int(contact.gps_lon * 1e6))
        + struct.pack("<I", contact.lastmod)
    )
    return (short, full)


class CompanionFrameServer:
    """TCP server for the MeshCore companion frame protocol.

    One client per companion at a time.  If a new connection arrives while
    one is already active, the existing connection is closed and the new
    one is accepted (eviction). An optional idle read timeout
    (client_idle_timeout_sec) frees the slot when no data is received; pass
    None to disable (no disconnect on idle, matching firmware behaviour).
    Persistence is handled through
    overridable hook methods; the base class works with in-memory stores only.
    """

    def __init__(
        self,
        bridge: Any,
        companion_hash: str,
        port: int = 5000,
        bind_address: str = "0.0.0.0",
        *,
        device_model: str = "pyMC-Companion",
        device_version: Optional[str] = None,
        build_date: str = "",
        local_hash: Optional[int] = None,
        stats_getter: Optional[Callable] = None,
        control_handler: Optional[Any] = None,
        heartbeat_interval: int = 15,
        client_idle_timeout_sec: Optional[int] = 8 * 60 * 60,
    ):
        self.bridge = bridge
        self.companion_hash = companion_hash
        self.port = port
        self.bind_address = bind_address
        self.local_hash = local_hash
        self.stats_getter = stats_getter
        self._control_handler = control_handler
        self._heartbeat_interval = heartbeat_interval
        self._client_idle_timeout_sec = client_idle_timeout_sec
        self._server: Optional[asyncio.Server] = None
        self._client_writer: Optional[asyncio.StreamWriter] = None
        self._client_reader: Optional[asyncio.StreamReader] = None
        self._write_queue: Optional[asyncio.Queue] = None
        self._writer_task: Optional[asyncio.Task] = None
        self._app_target_ver = 0

        # Pre-compute padded device info bytes for _cmd_device_query. Version string
        # should reflect FIRMWARE_VER_CODE so clients that parse it see 9+ (owner/anon).
        if device_version is None:
            # At least 2 chars so client substring(0, 2) etc. doesn't RangeError
            device_version = f"{FIRMWARE_VER_CODE}.0"
        self._build_date_bytes = (build_date.encode("utf-8") + b"\x00")[:12].ljust(12, b"\x00")
        self._model_bytes = (device_model.encode("utf-8") + b"\x00")[:40].ljust(40, b"\x00")
        self._version_bytes = (device_version.encode("utf-8") + b"\x00")[:20].ljust(20, b"\x00")

        # Command dispatch registry: cmd byte -> async handler(data)
        self._cmd_handlers = {
            CMD_APP_START: self._cmd_app_start,
            CMD_DEVICE_QUERY: self._cmd_device_query,
            CMD_GET_CONTACTS: self._cmd_get_contacts,
            CMD_GET_CONTACT_BY_KEY: self._cmd_get_contact_by_key,
            CMD_SEND_TXT_MSG: self._cmd_send_txt_msg,
            CMD_SEND_CHANNEL_TXT_MSG: self._cmd_send_channel_txt_msg,
            CMD_SEND_CHANNEL_DATA: self._cmd_send_channel_data,
            CMD_SYNC_NEXT_MESSAGE: self._cmd_sync_next_message,
            CMD_SEND_LOGIN: self._cmd_send_login,
            CMD_SEND_STATUS_REQ: self._cmd_send_status_req,
            CMD_SEND_TELEMETRY_REQ: self._cmd_send_telemetry_req,
            CMD_SEND_SELF_ADVERT: self._cmd_send_self_advert,
            CMD_SET_ADVERT_NAME: self._cmd_set_advert_name,
            CMD_SET_ADVERT_LATLON: self._cmd_set_advert_latlon,
            CMD_ADD_UPDATE_CONTACT: self._cmd_add_update_contact,
            CMD_REMOVE_CONTACT: self._cmd_remove_contact,
            CMD_RESET_PATH: self._cmd_reset_path,
            CMD_GET_BATT_AND_STORAGE: self._cmd_get_batt_and_storage,
            CMD_GET_STATS: self._cmd_get_stats,
            CMD_GET_ADVERT_PATH: self._cmd_get_advert_path,
            CMD_IMPORT_CONTACT: self._cmd_import_contact,
            CMD_GET_CHANNEL: self._cmd_get_channel,
            CMD_SET_CHANNEL: self._cmd_set_channel,
            CMD_SEND_BINARY_REQ: self._cmd_send_binary_req,
            CMD_SEND_ANON_REQ: self._cmd_send_anon_req,
            CMD_SEND_PATH_DISCOVERY_REQ: self._cmd_send_path_discovery_req,
            CMD_SEND_CONTROL_DATA: self._cmd_send_control_data,
            CMD_SEND_TRACE_PATH: self._cmd_send_trace_path,
            CMD_SET_FLOOD_SCOPE: self._cmd_set_flood_scope,
            CMD_SET_DEFAULT_FLOOD_SCOPE: self._cmd_set_default_flood_scope,
            CMD_GET_DEFAULT_FLOOD_SCOPE: self._cmd_get_default_flood_scope,
            CMD_GET_DEVICE_TIME: self._cmd_get_device_time,
            CMD_SET_DEVICE_TIME: self._cmd_set_device_time,
            CMD_SET_RADIO_PARAMS: self._cmd_set_radio_params,
            CMD_SET_RADIO_TX_POWER: self._cmd_set_tx_power,
            CMD_SHARE_CONTACT: self._cmd_share_contact,
            CMD_EXPORT_CONTACT: self._cmd_export_contact,
            CMD_EXPORT_PRIVATE_KEY: self._cmd_export_private_key,
            CMD_IMPORT_PRIVATE_KEY: self._cmd_import_private_key,
            CMD_SET_TUNING_PARAMS: self._cmd_set_tuning_params,
            CMD_LOGOUT: self._cmd_logout,
            CMD_GET_CUSTOM_VARS: self._cmd_get_custom_vars,
            CMD_SET_CUSTOM_VAR: self._cmd_set_custom_var,
            CMD_SET_AUTOADD_CONFIG: self._cmd_set_autoadd_config,
            CMD_GET_AUTOADD_CONFIG: self._cmd_get_autoadd_config,
            CMD_SET_OTHER_PARAMS: self._cmd_set_other_params,
            CMD_SEND_RAW_DATA: self._cmd_send_raw_data,
            CMD_SEND_RAW_PACKET: self._cmd_send_raw_packet,
            CMD_SET_PATH_HASH_MODE: self._cmd_set_path_hash_mode,
            CMD_GET_ALLOWED_REPEAT_FREQ: self._cmd_get_allowed_repeat_freq,
        }

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

    async def start(self) -> None:
        """Start the TCP server."""
        self._server = await asyncio.start_server(
            self._handle_client,
            self.bind_address,
            self.port,
        )
        addr = (
            self._server.sockets[0].getsockname()
            if self._server.sockets
            else (self.bind_address, self.port)
        )
        # Repeater passes hash as hex (first byte of pubkey, e.g. "f5"); accept decimal or hex.
        try:
            hash_int = int(self.companion_hash)
        except ValueError:
            hash_int = int(self.companion_hash, 16)
        logger.info(
            "Companion frame server listening on %s:%s (hash=0x%02x)",
            addr[0],
            addr[1],
            hash_int,
        )

    async def stop(self) -> None:
        """Stop the TCP server and disconnect any client."""
        # Signal writer task to stop and wait for it
        if self._write_queue is not None:
            try:
                self._write_queue.put_nowait(None)  # Sentinel
            except asyncio.QueueFull:
                pass
        if self._writer_task is not None:
            self._writer_task.cancel()
            try:
                await self._writer_task
            except asyncio.CancelledError:
                pass
            self._writer_task = None
        self._write_queue = None
        if self._client_writer:
            try:
                self._client_writer.close()
                await self._client_writer.wait_closed()
            except Exception:
                pass
            self._client_writer = None
            self._client_reader = None
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        logger.info("Companion frame server stopped (port=%s)", self.port)

    # -------------------------------------------------------------------------
    # Persistence hooks (override in subclasses for SQLite, etc.)
    # -------------------------------------------------------------------------

    async def _persist_companion_message(self, msg_dict: dict) -> None:
        """Hook: persist a received message.  Default is a no-op — the message
        stays in the bridge's in-memory queue for ``sync_next_message``."""

    def _sync_next_from_persistence(self) -> Optional[QueuedMessage]:
        """Hook: pop a persisted message when the bridge queue is empty.
        Default returns ``None``."""
        return None

    async def _maybe_persist_contact(self, contact) -> None:
        """Dispatch to :meth:`_persist_contact`, skipping transient/anon entries.

        Transient contacts (ADV_TYPE_NONE) created for non-contact anon requests
        are never persisted, mirroring the firmware save_filter. The guard lives
        here rather than in _persist_contact so it still applies when a subclass
        overrides the persistence hook (e.g. the repeater's SQLite upsert).
        """
        if getattr(contact, "adv_type", None) == ADV_TYPE_NONE:
            return
        await self._persist_contact(contact)

    async def _persist_contact(self, contact) -> None:
        """Hook: persist a single contact.  Default is a no-op.

        Subclasses should override to do a fast single-row upsert rather
        than rewriting the entire contact list.
        """

    async def _save_contacts(self) -> None:
        """Hook: persist the full contact list.  Default is a no-op."""

    async def _save_channels(self) -> None:
        """Hook: persist the full channel list.  Default is a no-op."""

    def _get_batt_and_storage(self) -> tuple[int, int, int]:
        """Hook: return (millivolts, used_kb, total_kb).  Default: all zeros."""
        return (0, 0, 0)

    # -------------------------------------------------------------------------
    # Push callbacks
    # -------------------------------------------------------------------------

    def _setup_push_callbacks(self) -> None:
        """Subscribe to bridge events and send PUSH frames to connected client."""
        # Clear any callbacks registered by a previous connection so they
        # don't accumulate across reconnections.
        self.bridge.clear_push_callbacks()

        def _write_push(data: bytes) -> None:
            """Enqueue a push frame. Sync, non-blocking."""
            self._enqueue_frame(data)

        async def on_message_received(
            sender_key, text, timestamp, txt_type, packet_hash=None, snr=None, rssi=None
        ):
            msg_dict = {
                "sender_key": sender_key,
                "text": text,
                "timestamp": timestamp,
                "txt_type": txt_type,
                "is_channel": False,
                "channel_idx": 0,
                "path_len": 0,
                "packet_hash": packet_hash,
                "snr": snr,
                "rssi": rssi,
            }
            await self._persist_companion_message(msg_dict)
            _write_push(bytes([PUSH_CODE_MSG_WAITING]))

        def on_send_confirmed(crc):
            data = struct.pack(
                "<B4sI",
                PUSH_CODE_SEND_CONFIRMED,
                struct.pack("<I", crc)[:4],
                0,
            )
            _write_push(data)

        async def _push_advert_frames(contact: Contact, *, is_new: bool) -> None:
            """Push the advert frame for a contact, mirroring firmware onDiscoveredContact:
            the full NEW_ADVERT when the contact was not stored (``is_new``), otherwise the
            short ADVERT (pubkey only) for a stored contact.
            """
            pubkey = contact.public_key
            if not isinstance(pubkey, bytes) or len(pubkey) < 32:
                return
            short, full = await asyncio.to_thread(_build_advert_push_frames, contact)
            if is_new:
                if full is not None:
                    _write_push(full)
            else:
                _write_push(short)

        async def on_advert_received(contact):
            """Stored advert: persist the contact. The client frame push is handled by
            on_node_discovered (firmware onDiscoveredContact)."""
            try:
                if not isinstance(contact, Contact):
                    logger.warning(
                        "advert_received: expected Contact, got %s — converting",
                        type(contact).__name__,
                    )
                    contact = Contact.from_dict(contact) if isinstance(contact, dict) else contact
                await self._maybe_persist_contact(contact)
            except Exception as e:
                logger.exception("advert_received callback error: %s", e)

        async def on_node_discovered(contact_or_data):
            """Firmware onDiscoveredContact: fires for every valid advert. Pushes the full
            NEW_ADVERT when the contact was not stored, else the short ADVERT for a stored
            contact. "Stored" is determined by whether the contact is in the contact book
            (the advert pipeline has already applied any auto-add by this point)."""
            try:
                if isinstance(contact_or_data, Contact):
                    contact = contact_or_data
                elif isinstance(contact_or_data, dict):
                    contact = Contact.from_dict(contact_or_data, now=int(time.time()))
                else:
                    return
                if not contact.name:
                    return
                is_new = self.bridge.contacts.get_by_key(contact.public_key) is None
                await _push_advert_frames(contact, is_new=is_new)
            except Exception as e:
                logger.exception("node_discovered callback error: %s", e)

        async def on_contact_path_updated(contact):
            # Defense-in-depth: only push PATH and persist for known contacts
            # (mirrors firmware which does not send PATH for non-contacts).
            if not (
                hasattr(contact, "public_key")
                and isinstance(contact.public_key, bytes)
                and len(contact.public_key) >= 32
            ):
                return
            if not self.bridge.contacts.get_by_key(contact.public_key):
                return
            _write_push(bytes([PUSH_CODE_PATH_UPDATED]) + contact.public_key[:32])
            try:
                await self._maybe_persist_contact(contact)
            except Exception as e:
                logger.warning("Persist contact after path update failed: %s", e)

        async def on_channel_message_received(
            channel_name,
            sender_name,
            message_text,
            timestamp,
            path_len=0,
            channel_idx=0,
            packet_hash=None,
            snr=None,
            rssi=None,
        ):
            msg_dict = {
                "sender_key": b"",
                "text": message_text,
                "timestamp": timestamp,
                "txt_type": 0,
                "is_channel": True,
                "channel_idx": channel_idx,
                "path_len": path_len,
                "packet_hash": packet_hash,
                "snr": snr,
                "rssi": rssi,
            }
            await self._persist_companion_message(msg_dict)
            _write_push(bytes([PUSH_CODE_MSG_WAITING]))

        async def on_channel_data_received(
            channel_idx,
            path_len,
            data_type,
            payload,
            packet_hash=None,
            snr=None,
            rssi=None,
        ):
            msg_dict = {
                "sender_key": b"",
                "text": "",
                "timestamp": 0,
                "txt_type": 0,
                "is_channel": True,
                "channel_idx": channel_idx,
                "path_len": path_len,
                "packet_hash": packet_hash,
                "snr": snr,
                "rssi": rssi,
                "channel_data_type": data_type,
                "channel_data_payload": bytes(payload or b""),
            }
            await self._persist_companion_message(msg_dict)
            _write_push(bytes([PUSH_CODE_MSG_WAITING]))

        def on_binary_response(tag_bytes, response_data, parsed=None, request_type=None):
            frame = (
                bytes([PUSH_CODE_BINARY_RESPONSE, 0])
                + (tag_bytes if isinstance(tag_bytes, bytes) else struct.pack("<I", tag_bytes))
                + response_data
            )
            _write_push(frame)

        def on_path_discovery_response(tag_bytes, contact_pubkey, out_path, in_path):
            pub_key_prefix = (
                contact_pubkey
                if isinstance(contact_pubkey, bytes)
                else bytes.fromhex(contact_pubkey)
            )[:6]
            out_path = out_path if isinstance(out_path, bytes) else bytes(out_path)
            in_path = in_path if isinstance(in_path, bytes) else bytes(in_path)
            frame = (
                bytes([PUSH_CODE_PATH_DISCOVERY_RESPONSE, 0])
                + pub_key_prefix
                + bytes([len(out_path)])
                + out_path
                + bytes([len(in_path)])
                + in_path
            )
            _write_push(frame)

        def on_contact_deleted(pub_key):
            if isinstance(pub_key, bytes) and len(pub_key) >= 32:
                _write_push(bytes([PUSH_CODE_CONTACT_DELETED]) + pub_key[:32])

        def on_contacts_full():
            _write_push(bytes([PUSH_CODE_CONTACTS_FULL]))

        def on_raw_data_received(payload_bytes: bytes, snr: float, rssi: int) -> None:
            """Push PUSH_CODE_RAW_DATA (0x84): code, SNR byte, RSSI byte, 0xFF, payload."""
            snr_byte = max(-128, min(127, int(round(snr * 4))))
            rssi_byte = max(-128, min(127, int(rssi)))
            payload_len = min(len(payload_bytes), MAX_PAYLOAD_SIZE - 4)
            data = (
                bytes([PUSH_CODE_RAW_DATA])
                + struct.pack("<bb", snr_byte, rssi_byte)
                + bytes([0xFF])
                + payload_bytes[:payload_len]
            )
            _write_push(data)

        self.bridge.on_message_received(on_message_received)
        self.bridge.on_channel_message_received(on_channel_message_received)
        self.bridge.on_channel_data_received(on_channel_data_received)
        self.bridge.on_send_confirmed(on_send_confirmed)
        self.bridge.on_advert_received(on_advert_received)
        self.bridge.on_node_discovered(on_node_discovered)
        self.bridge.on_contact_path_updated(on_contact_path_updated)
        self.bridge.on_binary_response(on_binary_response)
        self.bridge.on_path_discovery_response(on_path_discovery_response)
        self.bridge.on_contact_deleted(on_contact_deleted)
        self.bridge.on_contacts_full(on_contacts_full)
        self.bridge.on_raw_data_received(on_raw_data_received)

    # -------------------------------------------------------------------------
    # Public push methods (called directly by host application)
    # -------------------------------------------------------------------------

    def push_trace_data(
        self,
        path_len: int,
        flags: int,
        tag: int,
        auth_code: int,
        path_hashes: bytes,
        path_snrs: bytes,
        final_snr_byte: int,
    ) -> None:
        """Push PUSH_CODE_TRACE_DATA (0x89) to client.  Matches firmware
        ``onTraceRecv()`` frame format.

        Sync, non-blocking.  Safe to call from any context (async or sync),
        like :pymethod:`push_rx_raw`.
        """
        if self._write_queue is None:
            return
        path_sz = flags & 0x03
        expected_snr_len = path_len >> path_sz
        if len(path_snrs) != expected_snr_len:
            logger.debug(
                "push_trace_data: path_snrs len %s != expected %s",
                len(path_snrs),
                expected_snr_len,
            )
            return
        data = (
            bytes([PUSH_CODE_TRACE_DATA, 0, path_len, flags])
            + struct.pack("<II", tag & 0xFFFFFFFF, auth_code & 0xFFFFFFFF)
            + path_hashes
            + path_snrs
            + bytes([final_snr_byte & 0xFF])
        )
        self._enqueue_frame(data)

    async def push_trace_data_async(
        self,
        path_len: int,
        flags: int,
        tag: int,
        auth_code: int,
        path_hashes: bytes,
        path_snrs: bytes,
        final_snr_byte: int,
    ) -> None:
        """Async wrapper for code that must ``await`` a coroutine (same as
        :pymethod:`push_trace_data`).
        """
        self.push_trace_data(
            path_len,
            flags,
            tag,
            auth_code,
            path_hashes,
            path_snrs,
            final_snr_byte,
        )

    def push_rx_raw(self, snr: float, rssi: int, raw: bytes) -> None:
        """Push raw RX packet to client (PUSH_CODE_LOG_RX_DATA 0x88).

        Sync, non-blocking.  Safe to call from any context (async or sync).
        """
        if self._write_queue is None:
            return
        snr_byte = max(-128, min(127, int(round(snr * 4))))
        rssi_byte = max(-128, min(127, int(rssi)))
        if snr_byte < 0:
            snr_byte += 256
        if rssi_byte < 0:
            rssi_byte += 256
        payload_len = min(len(raw), MAX_PAYLOAD_SIZE - 3)  # 3 = code + snr + rssi
        data = bytes([PUSH_CODE_LOG_RX_DATA, snr_byte & 0xFF, rssi_byte & 0xFF]) + raw[:payload_len]
        self._enqueue_frame(data)

    async def push_rx_raw_async(self, snr: float, rssi: int, raw: bytes) -> None:
        """Push raw RX packet to client.  Async wrapper for backward compatibility."""
        self.push_rx_raw(snr, rssi, raw)

    async def push_control_data(
        self,
        snr: float,
        rssi: int,
        path_len: int,
        path_bytes: bytes,
        payload: bytes,
    ) -> None:
        """Push CONTROL packet to client (PUSH_CODE_CONTROL_DATA 0x8E).

        Kept as ``async def`` for backward-compatible call sites that
        ``await`` it, but the body is synchronous (just enqueues).
        """
        if self._write_queue is None:
            logger.warning("Push control data skipped: no client connection")
            return
        # Discovery response (0x90): clear the no-op callback
        if self._control_handler and len(payload) >= 6 and (payload[0] & 0xF0) == 0x90:
            tag = struct.unpack("<I", payload[2:6])[0]
            self._control_handler.clear_response_callback(tag)
        snr_val = snr if isinstance(snr, (int, float)) else 0.0
        rssi_val = rssi if isinstance(rssi, (int, float)) else 0
        snr_byte = max(-128, min(127, int(round(float(snr_val) * 4))))
        rssi_byte = max(-128, min(127, int(rssi_val)))
        if snr_byte < 0:
            snr_byte += 256
        if rssi_byte < 0:
            rssi_byte += 256
        path_len_byte = max(0, min(255, int(path_len) if path_len is not None else 0))
        payload_max = MAX_PAYLOAD_SIZE - 4  # 4 = code + snr + rssi + path_len_byte
        payload_slice = bytes(payload[:payload_max]) if payload else b""
        data = (
            bytes(
                [
                    PUSH_CODE_CONTROL_DATA,
                    snr_byte & 0xFF,
                    rssi_byte & 0xFF,
                    path_len_byte,
                ]
            )
            + payload_slice
        )
        self._enqueue_frame(data)
        logger.debug("Pushed control data 0x8E to client: payload_len=%s", len(payload_slice))

    def _enqueue_frame(self, data: bytes) -> None:
        """Build an outbound frame and enqueue it for the writer task.

        Sync, non-blocking.  On ``QueueFull`` the frame is dropped with a
        warning — this provides natural backpressure shedding.
        """
        if self._write_queue is None:
            return
        if len(data) > MAX_PAYLOAD_SIZE:
            logger.warning(
                "Outbound frame payload truncated from %s to %s (MAX_FRAME_SIZE=%s)",
                len(data),
                MAX_PAYLOAD_SIZE,
                MAX_FRAME_SIZE,
            )
            data = data[:MAX_PAYLOAD_SIZE]
        frame = bytes([FRAME_OUTBOUND_PREFIX]) + struct.pack("<H", len(data)) + data
        try:
            self._write_queue.put_nowait(frame)
        except asyncio.QueueFull:
            logger.warning("Write queue full (%s); dropping frame", self._write_queue.maxsize)

    def _write_frame(self, data: bytes) -> None:
        """Alias for ``_enqueue_frame``; retained for subclass compatibility."""
        self._enqueue_frame(data)

    def _write_ok(self) -> None:
        self._write_frame(bytes([RESP_CODE_OK]))

    def _write_err(self, err_code: int) -> None:
        self._write_frame(bytes([RESP_CODE_ERR, err_code]))

    # -------------------------------------------------------------------------
    # Writer task
    # -------------------------------------------------------------------------

    # Must exceed DEFAULT_MAX_CONTACTS (+2 for START/END) so that
    # _cmd_get_contacts can enqueue the full contact dump without drops.
    _WRITE_QUEUE_MAXSIZE = 2048
    # Drain after every frame so clients that count one TCP receive per response
    # (e.g. _receive_count per data_received()) stay in sync with sends.
    _DRAIN_BATCH = 1

    async def _writer_loop(self, writer: asyncio.StreamWriter) -> None:
        """Single writer task: pull frames from the queue, write to the
        ``StreamWriter``, and drain periodically.

        Integrates heartbeat via timeout on :pymethod:`asyncio.Queue.get` —
        when no frames arrive within ``_heartbeat_interval`` seconds a
        ``RESP_CODE_CURR_TIME`` heartbeat frame is generated automatically,
        eliminating the need for a separate heartbeat task.

        On any write/drain error the writer is closed, which causes the read
        loop in :pymethod:`_handle_client` to receive EOF → clean disconnect.
        """
        frames_since_drain = 0
        try:
            while True:
                # Wait for a frame, or timeout for heartbeat ---------
                try:
                    frame = await asyncio.wait_for(
                        self._write_queue.get(),
                        timeout=self._heartbeat_interval,
                    )
                except asyncio.TimeoutError:
                    # Heartbeat: send RESP_CODE_CURR_TIME
                    now = self.bridge.get_time()
                    hb_data = bytes([RESP_CODE_CURR_TIME]) + struct.pack("<I", now)
                    frame = (
                        bytes([FRAME_OUTBOUND_PREFIX]) + struct.pack("<H", len(hb_data)) + hb_data
                    )

                if frame is None:  # Sentinel → orderly shutdown
                    break

                # Write the frame ------------------------------------
                writer.write(frame)
                frames_since_drain += 1

                # Drain when queue empties (natural batching) or every N frames
                if self._write_queue.empty() or frames_since_drain >= self._DRAIN_BATCH:
                    await writer.drain()
                    frames_since_drain = 0
        except asyncio.CancelledError:
            pass
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            logger.warning("Writer loop connection lost: %s", e)
        except Exception as e:
            logger.error("Writer loop error: %s", e, exc_info=True)
        finally:
            try:
                if not writer.is_closing():
                    writer.close()
            except Exception:
                pass

    # -------------------------------------------------------------------------
    # Client handling
    # -------------------------------------------------------------------------

    @staticmethod
    def _configure_socket(writer: asyncio.StreamWriter) -> None:
        """Configure TCP keepalive and low-latency options on the underlying socket."""
        sock = writer.get_extra_info("socket")
        if sock is None:
            return
        try:
            # Disable Nagle's algorithm for real-time frame delivery (important
            # over VPN/Tailscale where latency is higher and small-write
            # coalescing can compound delays).
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError as e:
            logger.debug("Could not set TCP_NODELAY: %s", e)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            if sys.platform == "linux":
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 15)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 5)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
            elif sys.platform == "darwin":
                # TCP_KEEPALIVE is the macOS equivalent of TCP_KEEPIDLE
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPALIVE, 15)
                try:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 5)
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
                except (AttributeError, OSError):
                    pass  # older macOS may lack KEEPINTVL/KEEPCNT
        except OSError as e:
            logger.debug("Could not set TCP keepalive: %s", e)

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle a new client connection.  One client at a time.
        If a client is already connected, the existing connection is closed
        and the new one is accepted (eviction). An idle read timeout also
        frees the slot when no data is received for client_idle_timeout_sec.
        """
        if self._client_writer:
            logger.info(
                "Companion already has a client; evicting previous connection (port=%s)",
                self.port,
            )
            old_writer = self._client_writer
            old_writer_task = self._writer_task
            # Cancel and await the old writer task so it's fully gone before we replace
            # the queue and create a new task (avoids the new task being mistaken for
            # a failed writer when the old task had already exited).
            if old_writer_task is not None:
                old_writer_task.cancel()
                try:
                    await old_writer_task
                except asyncio.CancelledError:
                    pass
                if self._writer_task is old_writer_task:
                    self._writer_task = None
            try:
                old_writer.close()
                await old_writer.wait_closed()
            except Exception:
                pass

        self._client_reader = reader
        self._client_writer = writer
        self._configure_socket(writer)
        local_write_queue: asyncio.Queue = asyncio.Queue(maxsize=self._WRITE_QUEUE_MAXSIZE)
        self._write_queue = local_write_queue
        self._setup_push_callbacks()
        logger.info("Companion client connected (port=%s)", self.port)

        local_writer_task = asyncio.create_task(self._writer_loop(writer))
        self._writer_task = local_writer_task
        disconnect_reason: Optional[str] = None
        try:
            while True:
                try:
                    prefix = await asyncio.wait_for(
                        reader.read(1), timeout=self._client_idle_timeout_sec
                    )
                except asyncio.TimeoutError:
                    disconnect_reason = "idle_timeout"
                    break
                if not prefix:
                    disconnect_reason = "empty_read"
                    break
                if prefix[0] != FRAME_INBOUND_PREFIX:
                    logger.warning("Invalid frame prefix: 0x%02x", prefix[0])
                    continue
                len_bytes = await reader.readexactly(2)
                frame_len = struct.unpack("<H", len_bytes)[0]
                if frame_len > MAX_FRAME_SIZE:
                    logger.warning("Frame too long: %s", frame_len)
                    disconnect_reason = "frame_too_long"
                    break
                payload = await reader.readexactly(frame_len)
                await self._handle_cmd(payload)
                if local_writer_task.done():
                    disconnect_reason = "writer_failed"
                    if not local_writer_task.cancelled():
                        exc = local_writer_task.exception()
                        if exc is not None:
                            logger.error(
                                "Writer task failed (port=%s): %s",
                                self.port,
                                exc,
                                exc_info=True,
                            )
                    break
        except asyncio.IncompleteReadError:
            disconnect_reason = "incomplete_read"
        except (ConnectionResetError, BrokenPipeError) as e:
            disconnect_reason = type(e).__name__
        except Exception as e:
            disconnect_reason = f"other: {type(e).__name__}: {e}"
            logger.error("Client handler error: %s", e, exc_info=True)
        finally:
            if self._write_queue is local_write_queue:
                try:
                    local_write_queue.put_nowait(None)  # Sentinel
                except asyncio.QueueFull:
                    pass
            else:
                logger.debug(
                    "Skipping stale queue cleanup for disconnected client (port=%s)",
                    self.port,
                )
            if self._writer_task is local_writer_task:
                local_writer_task.cancel()
                try:
                    await local_writer_task
                except asyncio.CancelledError:
                    pass
                self._writer_task = None
            else:
                logger.debug(
                    "Skipping stale writer cleanup for disconnected client (port=%s)",
                    self.port,
                )
            if self._write_queue is local_write_queue:
                self._write_queue = None
            if self._client_writer is writer:
                self._client_writer = None
                self._client_reader = None
                logger.info(
                    "Companion client disconnected (port=%s): %s",
                    self.port,
                    disconnect_reason or "unknown",
                )

    # -------------------------------------------------------------------------
    # Command dispatch
    # -------------------------------------------------------------------------

    async def _handle_cmd(self, payload: bytes) -> None:
        """Dispatch command to handler."""
        if not payload:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        cmd = payload[0]
        data = payload[1:]
        logger.info("Companion cmd 0x%02x (%s) len=%s", cmd, cmd, len(payload))
        if cmd in (CMD_GET_CHANNEL, CMD_SET_CHANNEL):
            logger.debug(
                "Companion cmd 0x%02x (%s), payload_len=%s",
                cmd,
                "GET_CHANNEL" if cmd == CMD_GET_CHANNEL else "SET_CHANNEL",
                len(payload),
            )

        try:
            handler = self._cmd_handlers.get(cmd)
            if handler is not None:
                await handler(data)
            else:
                logger.warning(
                    "Companion unsupported cmd 0x%02x (%s) len=%s",
                    cmd,
                    cmd,
                    len(payload),
                )
                self._write_err(ERR_CODE_UNSUPPORTED_CMD)
        except Exception as e:
            logger.error("Cmd 0x%02x error: %s", cmd, e, exc_info=True)
            self._write_err(ERR_CODE_ILLEGAL_ARG)

    # -------------------------------------------------------------------------
    # Command handlers
    # -------------------------------------------------------------------------

    async def _cmd_app_start(self, data: bytes) -> None:
        if len(data) >= 1:
            self._app_target_ver = data[0]
        prefs = self.bridge.get_self_info()
        pubkey = self.bridge.get_public_key()
        name = prefs.node_name.encode("utf-8", errors="replace")
        lat = int(getattr(prefs, "latitude", 0) * 1e6)
        lon = int(getattr(prefs, "longitude", 0) * 1e6)
        frame = (
            bytes([RESP_CODE_SELF_INFO, ADV_TYPE_CHAT, prefs.tx_power_dbm, 22])
            + pubkey
            + struct.pack("<ii", lat, lon)
            + bytes(
                [
                    getattr(prefs, "multi_acks", 0),
                    getattr(prefs, "advert_loc_policy", 0),
                ]
            )
            + bytes(
                [
                    getattr(prefs, "telemetry_mode_base", 0)
                    | (getattr(prefs, "telemetry_mode_location", 0) << 2)
                ]
            )
            + bytes([getattr(prefs, "manual_add_contacts", 0)])
            + struct.pack(
                "<II",
                prefs.frequency_hz // 1000,
                prefs.bandwidth_hz,
            )
            + bytes([prefs.spreading_factor, prefs.coding_rate])
            + name
        )
        self._write_frame(frame)

    async def _cmd_device_query(self, data: bytes) -> None:
        # Layout must match MeshCore companion_radio MyMesh.cpp handleCmdFrame() CMD_DEVICE_QUEURY:
        # [0]=RESP_CODE_DEVICE_INFO, [1]=FIRMWARE_VER_CODE, [2]=MAX_CONTACTS/2,
        # [3]=MAX_GROUP_CHANNELS, [4..7]=ble_pin, [8..19]=build_date(12), [20..59]=manufacturer(40),
        # [60..79]=version(20), [80]=client_repeat, [81]=path_hash_mode (v10+).
        if len(data) >= 1:
            self._app_target_ver = data[0]
        firmware_ver = FIRMWARE_VER_CODE
        max_contacts = getattr(getattr(self.bridge, "contacts", None), "max_contacts", 1000)
        max_channels_val = getattr(getattr(self.bridge, "channels", None), "max_channels", 40)
        max_contacts_div_2 = min(max_contacts // 2, 255)
        max_channels = min(max_channels_val, 255)
        ble_pin = 0
        try:
            prefs = self.bridge.get_self_info()
            client_repeat = getattr(prefs, "client_repeat", 0) & 0xFF
            path_hash_mode = getattr(prefs, "path_hash_mode", 0) & 0xFF
        except Exception:
            client_repeat = 0
            path_hash_mode = 0
        frame = (
            bytes(
                [
                    RESP_CODE_DEVICE_INFO,
                    firmware_ver,
                    max_contacts_div_2,
                    max_channels,
                ]
            )
            + struct.pack("<I", ble_pin)
            + self._build_date_bytes
            + self._model_bytes
            + self._version_bytes
            + bytes([client_repeat & 0xFF, path_hash_mode & 0xFF])
        )
        version_str = self._version_bytes.split(b"\x00")[0].decode("utf-8", errors="replace")
        logger.info(
            "Companion device info sent: FIRMWARE_VER_CODE=%s (byte at index 1), "
            "version string=%r, frame_len=%s",
            firmware_ver,
            version_str,
            len(frame),
        )
        self._write_frame(frame)

    async def _cmd_get_contacts(self, data: bytes) -> None:
        since = struct.unpack("<I", data[:4])[0] if len(data) >= 4 else 0
        contacts = self.bridge.get_contacts(since=since)
        self._write_frame(bytes([RESP_CODE_CONTACTS_START]) + struct.pack("<I", len(contacts)))
        for i, c in enumerate(contacts):
            self._write_contact_frame(c)
        most_recent = max((c.lastmod for c in contacts), default=0)
        self._write_frame(bytes([RESP_CODE_END_OF_CONTACTS]) + struct.pack("<I", most_recent))

    def _write_contact_frame(self, c: Contact) -> None:
        """Encode and write a single RESP_CODE_CONTACT frame."""
        pubkey = c.public_key if isinstance(c.public_key, bytes) else bytes.fromhex(c.public_key)
        name = (c.name.encode("utf-8")[:32] if isinstance(c.name, str) else c.name[:32]).ljust(
            32, b"\x00"
        )
        opl_byte = 0xFF if c.out_path_len < 0 else min(c.out_path_len, 255)
        frame = (
            bytes([RESP_CODE_CONTACT, *pubkey, c.adv_type, c.flags, opl_byte])
            + (c.out_path[:MAX_PATH_SIZE] if c.out_path else b"").ljust(MAX_PATH_SIZE, b"\x00")
            + name
            + struct.pack("<I", c.last_advert_timestamp)
            + struct.pack("<i", int(c.gps_lat * 1e6))
            + struct.pack("<i", int(c.gps_lon * 1e6))
            + struct.pack("<I", c.lastmod)
        )
        self._write_frame(frame)

    async def _cmd_get_contact_by_key(self, data: bytes) -> None:
        if len(data) < PUB_KEY_SIZE:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        pubkey = data[:PUB_KEY_SIZE]
        contact = (
            self.bridge.contacts.get_by_key(pubkey)
            if hasattr(self.bridge.contacts, "get_by_key")
            else None
        )
        if not contact:
            self._write_err(ERR_CODE_NOT_FOUND)
            return
        self._write_contact_frame(contact)

    async def _cmd_send_txt_msg(self, data: bytes) -> None:
        if len(data) < 12:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        txt_type = data[0]
        attempt = data[1]
        # data[2:6] = host-supplied msg_timestamp (LE uint32). Used as-is for plain DMs so
        # retries of the same message share a stable timestamp (mirrors firmware sendMessage).
        # For CLI_DATA — or when the host omits it (0) — mint a fresh timestamp instead,
        # matching firmware which overrides CLI_DATA with the RTC to avoid replay protection.
        host_timestamp = int.from_bytes(data[2:6], "little")
        use_timestamp = (
            None if (txt_type == TXT_TYPE_CLI_DATA or host_timestamp == 0) else host_timestamp
        )
        pubkey_prefix = data[6:12]
        text = data[12:].decode("utf-8", errors="replace").rstrip("\x00")
        contact = self.bridge.contacts.get_by_key_prefix(pubkey_prefix)
        if not contact:
            self._write_err(ERR_CODE_NOT_FOUND)
            return
        pubkey = (
            contact.public_key
            if isinstance(contact.public_key, bytes)
            else bytes.fromhex(contact.public_key)
        )
        result = await self.bridge.send_text_message(
            pubkey,
            text,
            txt_type=txt_type,
            attempt=attempt,
            wait_for_ack=False,
            timestamp=use_timestamp,
        )
        if result.success:
            ack = result.expected_ack or 0
            timeout = result.timeout_ms or 5000
            frame = bytes([RESP_CODE_SENT, 1 if result.is_flood else 0]) + struct.pack(
                "<II", ack, timeout
            )
            self._write_frame(frame)
        else:
            self._write_err(ERR_CODE_BAD_STATE)

    async def _cmd_send_channel_txt_msg(self, data: bytes) -> None:
        if len(data) < 6:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        txt_type = data[0]
        channel_idx = data[1]
        text = data[6:].decode("utf-8", errors="replace").rstrip("\x00")
        if txt_type != 0:
            self._write_err(ERR_CODE_UNSUPPORTED_CMD)
            return
        if self.bridge.get_channel(channel_idx) is None:
            self._write_err(ERR_CODE_NOT_FOUND)
            return
        ok = await self.bridge.send_channel_message(channel_idx, text)
        self._write_ok() if ok else self._write_err(ERR_CODE_BAD_STATE)

    async def _cmd_send_channel_data(self, data: bytes) -> None:
        """Handle CMD_SEND_CHANNEL_DATA (62)."""
        if len(data) < 4:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        channel_idx = data[0]
        path_len = data[1]
        if self.bridge.get_channel(channel_idx) is None:
            self._write_err(ERR_CODE_NOT_FOUND)
            return
        offset = 2
        path = b""
        if path_len != OUT_PATH_UNKNOWN:
            if not PathUtils.is_valid_path_len(path_len):
                self._write_err(ERR_CODE_ILLEGAL_ARG)
                return
            path_byte_len = PathUtils.get_path_byte_len(path_len)
            if len(data) < offset + path_byte_len + 2:
                self._write_err(ERR_CODE_ILLEGAL_ARG)
                return
            path = data[offset : offset + path_byte_len]
            offset += path_byte_len
        if len(data) < offset + 2:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        data_type = int.from_bytes(data[offset : offset + 2], "little")
        payload = data[offset + 2 :]
        if data_type == 0 or len(payload) > MAX_CHANNEL_DATA_LENGTH:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        send_channel_data = getattr(self.bridge, "send_channel_data", None)
        if not send_channel_data:
            self._write_err(ERR_CODE_UNSUPPORTED_CMD)
            return
        ok = await send_channel_data(
            channel_idx,
            data_type,
            payload,
            path=path if path_len != OUT_PATH_UNKNOWN else None,
            path_len_encoded=path_len,
        )
        if ok:
            self._write_ok()
        else:
            self._write_err(ERR_CODE_TABLE_FULL)

    async def _cmd_send_binary_req(self, data: bytes) -> None:
        if len(data) < 33:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        pubkey = data[:32]
        req_data = data[32:]
        send_binary_req = getattr(self.bridge, "send_binary_req", None)
        if not send_binary_req:
            self._write_err(ERR_CODE_UNSUPPORTED_CMD)
            return
        try:
            result = await send_binary_req(pubkey, req_data)
        except Exception as e:
            logger.error("send_binary_req error: %s", e, exc_info=True)
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        if not result.success:
            self._write_err(ERR_CODE_NOT_FOUND)
            return
        tag = result.expected_ack if result.expected_ack is not None else 0
        timeout_ms = result.timeout_ms if result.timeout_ms is not None else 10000
        frame = bytes([RESP_CODE_SENT, 1 if result.is_flood else 0]) + struct.pack(
            "<II", tag, timeout_ms
        )
        self._write_frame(frame)

    async def _cmd_send_anon_req(self, data: bytes) -> None:
        if len(data) < 33:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        pubkey = data[:32]
        req_data = data[32:]
        send_anon_req = getattr(self.bridge, "send_anon_req", None)
        if not send_anon_req:
            self._write_err(ERR_CODE_UNSUPPORTED_CMD)
            return
        try:
            result = await send_anon_req(pubkey, req_data)
        except Exception as e:
            logger.error("send_anon_req error: %s", e, exc_info=True)
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        if not result.success:
            # FW PR #2672: anon req no longer returns NOT_FOUND. Both "couldn't add
            # transient contact" and "send failed" map to ERR_CODE_TABLE_FULL.
            self._write_err(ERR_CODE_TABLE_FULL)
            return
        tag = result.expected_ack if result.expected_ack is not None else 0
        timeout_ms = result.timeout_ms if result.timeout_ms is not None else 10000
        frame = bytes([RESP_CODE_SENT, 1 if result.is_flood else 0]) + struct.pack(
            "<II", tag, timeout_ms
        )
        self._write_frame(frame)

    async def _cmd_send_control_data(self, data: bytes) -> None:
        if len(data) < 2:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        if (data[0] & 0x80) == 0:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        # Discovery request: register a no-op response callback
        if self._control_handler and len(data) >= 6 and (data[0] & 0xF0) == 0x80:
            tag = struct.unpack("<I", data[2:6])[0]
            self._control_handler.set_response_callback(tag, lambda _: None)
        send_control = getattr(self.bridge, "send_control_data", None)
        if not send_control:
            self._write_err(ERR_CODE_UNSUPPORTED_CMD)
            return
        try:
            ok = await send_control(data)
        except Exception as e:
            logger.error("send_control_data error: %s", e, exc_info=True)
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        if ok:
            self._write_ok()
        else:
            self._write_err(ERR_CODE_TABLE_FULL)

    async def _cmd_send_path_discovery_req(self, data: bytes) -> None:
        logger.info(
            "Path discovery request received (cmd 52), data_len=%s",
            len(data),
        )
        if len(data) < 33:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        pub_key = data[1:33]
        send_req = getattr(self.bridge, "send_path_discovery_req", None)
        if not send_req:
            self._write_err(ERR_CODE_UNSUPPORTED_CMD)
            return
        try:
            result = await send_req(pub_key)
        except Exception as e:
            logger.error("send_path_discovery_req error: %s", e, exc_info=True)
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        if not result.success:
            self._write_err(ERR_CODE_NOT_FOUND)
            return
        tag = result.expected_ack if result.expected_ack is not None else 0
        timeout_ms = result.timeout_ms if result.timeout_ms is not None else 10000
        frame = bytes([RESP_CODE_SENT, 1 if result.is_flood else 0]) + struct.pack(
            "<II", tag, timeout_ms
        )
        self._write_frame(frame)

    async def _cmd_send_trace_path(self, data: bytes) -> None:
        if len(data) < 10:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        tag = struct.unpack_from("<I", data, 0)[0]
        auth_code = struct.unpack_from("<I", data, 4)[0]
        flags = data[8]
        path_bytes = data[9:]
        path_len = len(path_bytes)
        path_sz = flags & 0x03
        if (path_len >> path_sz) > MAX_PATH_SIZE or (path_len % (1 << path_sz)) != 0:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        send_raw = getattr(self.bridge, "send_trace_path_raw", None)
        if not send_raw:
            self._write_err(ERR_CODE_UNSUPPORTED_CMD)
            return
        try:
            ok = await send_raw(tag, auth_code, flags, path_bytes)
        except Exception as e:
            logger.error("send_trace_path error: %s", e, exc_info=True)
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        if not ok:
            self._write_err(ERR_CODE_TABLE_FULL)
            return
        est_timeout_ms = 5000 + (path_len * 200)
        frame = bytes([RESP_CODE_SENT, 0]) + struct.pack("<II", tag, est_timeout_ms)
        self._write_frame(frame)
        # If we are the final hop, push trace data immediately
        if path_bytes and self.local_hash is not None and path_bytes[-1] == self.local_hash:
            path_sz = flags & 0x03
            snr_len = path_len >> path_sz
            path_snrs = bytes(snr_len)
            final_snr_byte = 0
            self.push_trace_data(
                path_len,
                flags,
                tag,
                auth_code,
                path_bytes,
                path_snrs,
                final_snr_byte,
            )

    def _build_message_frame(self, msg: "QueuedMessage") -> bytes:
        """Encode a QueuedMessage into a response frame (shared by base and subclasses)."""
        snr_byte = max(-128, min(127, int(round(getattr(msg, "snr", 0) * 4))))
        if snr_byte < 0:
            snr_byte += 256
        if msg.is_channel:
            path_len_byte = msg.path_len if msg.path_len < 256 else 0xFF
            if getattr(msg, "channel_data_type", 0):
                payload = bytes(getattr(msg, "channel_data_payload", b"") or b"")
                payload = payload[:MAX_CHANNEL_DATA_LENGTH]
                return (
                    bytes(
                        [
                            RESP_CODE_CHANNEL_DATA_RECV,
                            snr_byte & 0xFF,
                            0,
                            0,
                            msg.channel_idx,
                            path_len_byte,
                        ]
                    )
                    + struct.pack("<H", msg.channel_data_type & 0xFFFF)
                    + bytes([len(payload)])
                    + payload
                )
            txt_type = 0
            text_bytes = (msg.text or "").rstrip("\x00").encode("utf-8", errors="replace")
            if self._app_target_ver >= 3:
                return (
                    bytes(
                        [
                            RESP_CODE_CHANNEL_MSG_RECV_V3,
                            snr_byte & 0xFF,
                            0,
                            0,
                            msg.channel_idx,
                            path_len_byte,
                            txt_type,
                        ]
                    )
                    + struct.pack("<I", msg.timestamp)
                    + text_bytes
                )
            return (
                bytes(
                    [
                        RESP_CODE_CHANNEL_MSG_RECV,
                        msg.channel_idx,
                        path_len_byte,
                        txt_type,
                    ]
                )
                + struct.pack("<I", msg.timestamp)
                + text_bytes
            )
        prefix = (
            msg.sender_key[:6] if len(msg.sender_key) >= 6 else msg.sender_key.ljust(6, b"\x00")
        )
        path_len_byte = msg.path_len if msg.path_len < 256 else 0xFF
        text_bytes = msg.text.encode("utf-8", errors="replace")
        if self._app_target_ver >= 3:
            return (
                bytes([RESP_CODE_CONTACT_MSG_RECV_V3, snr_byte & 0xFF, 0, 0])
                + prefix
                + bytes([path_len_byte, msg.txt_type])
                + struct.pack("<I", msg.timestamp)
                + text_bytes
            )
        return (
            bytes([RESP_CODE_CONTACT_MSG_RECV])
            + prefix
            + bytes([path_len_byte, msg.txt_type])
            + struct.pack("<I", msg.timestamp)
            + text_bytes
        )

    async def _cmd_sync_next_message(self, data: bytes) -> None:
        msg = self.bridge.sync_next_message()
        if msg is None:
            msg = await asyncio.to_thread(self._sync_next_from_persistence)
        if msg is None:
            self._write_frame(bytes([RESP_CODE_NO_MORE_MESSAGES]))
            return
        self._write_frame(self._build_message_frame(msg))

    async def _cmd_send_login(self, data: bytes) -> None:
        if len(data) < 32:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        pubkey = data[:32]
        password = (
            data[32:].decode("utf-8", errors="replace").rstrip("\x00") if len(data) > 32 else ""
        )
        self._write_frame(bytes([RESP_CODE_SENT, 1]) + struct.pack("<II", 0, 10000))
        result = await self.bridge.send_login(pubkey, password)
        if result.get("success"):
            # Layout matches MeshCore companion_radio onContactResponse
            fw_level = result.get("firmware_ver_level")
            if fw_level is None:
                fw_level = FIRMWARE_VER_CODE  # fallback so app sees >= 2 for owner info
            self._write_frame(
                bytes(
                    [
                        PUSH_CODE_LOGIN_SUCCESS,
                        1 if result.get("is_admin") else 0,
                    ]
                )
                + pubkey[:6]
                + struct.pack("<I", result.get("tag", 0))
                + bytes([result.get("acl_permissions", 0)])
                + bytes([min(255, max(0, int(fw_level)))])
            )
        else:
            self._write_frame(bytes([PUSH_CODE_LOGIN_FAIL, 0]) + pubkey[:6])

    async def _cmd_send_status_req(self, data: bytes) -> None:
        if len(data) < 32:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        pubkey = data[0:32]
        self._write_frame(bytes([RESP_CODE_SENT, 0]) + struct.pack("<II", 0, 15000))
        result = await self.bridge.send_status_request(pubkey)
        if not result.get("success"):
            logger.debug("Status request failed for %s; no push sent)", pubkey[:6].hex())
            return
        stats_data = result.get("stats", {})
        raw_bytes = stats_data.get("raw_bytes", b"")
        if not raw_bytes:
            logger.debug(
                "Status response had no raw_bytes for %s; no push sent",
                pubkey[:6].hex(),
            )
            return
        self._write_frame(bytes([PUSH_CODE_STATUS_RESPONSE, 0]) + pubkey[:6] + raw_bytes)

    async def _cmd_send_telemetry_req(self, data: bytes) -> None:
        # Protocol: CMD_SEND_TELEMETRY_REQ has reserved bytes(3) then pub_key bytes(32).
        # See MeshCore Companion-Radio-Protocol: CMD_SEND_TELEMETRY_REQ frame format.
        if len(data) < 35:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        pubkey = data[3:35]
        flags = 0x07  # request all: base + location + environment
        want_base = bool(flags & 0x01)
        want_location = bool(flags & 0x02)
        want_environment = bool(flags & 0x04)
        self._write_frame(bytes([RESP_CODE_SENT, 0]) + struct.pack("<II", 0, 15000))
        result = await self.bridge.send_telemetry_request(
            pubkey,
            want_base=want_base,
            want_location=want_location,
            want_environment=want_environment,
        )
        if not result.get("success"):
            logger.debug("Telemetry request failed for %s; no push sent", pubkey[:6].hex())
            return
        telem_data = result.get("telemetry_data", {})
        raw_bytes = telem_data.get("raw_bytes", b"")
        if not raw_bytes:
            logger.debug(
                "Telemetry response had no raw_bytes for %s; no push sent",
                pubkey[:6].hex(),
            )
            return
        self._write_frame(bytes([PUSH_CODE_TELEMETRY_RESPONSE, 0]) + pubkey[:6] + raw_bytes)
        logger.info("Telemetry push sent to client: %d bytes LPP", len(raw_bytes))

    async def _cmd_send_self_advert(self, data: bytes) -> None:
        flood = len(data) >= 1 and data[0] == 1
        ok = await self.bridge.advertise(flood=flood)
        self._write_ok() if ok else self._write_err(ERR_CODE_BAD_STATE)

    async def _cmd_set_advert_name(self, data: bytes) -> None:
        name = data.decode("utf-8", errors="replace").rstrip("\x00")
        self.bridge.set_advert_name(name)
        self._write_ok()

    async def _cmd_set_advert_latlon(self, data: bytes) -> None:
        if len(data) < 8:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        lat, lon = struct.unpack_from("<ii", data, 0)
        self.bridge.set_advert_latlon(lat / 1e6, lon / 1e6)
        self._write_ok()

    async def _cmd_add_update_contact(self, data: bytes) -> None:
        if len(data) < 36:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        pubkey = data[0:32]
        adv_type = data[32]
        flags = data[33]
        out_path_len = struct.unpack_from("<b", data, 34)[0]
        out_path_end = 35 + MAX_PATH_SIZE
        if len(data) >= out_path_end:
            out_path = data[35:out_path_end].rstrip(b"\x00")
        else:
            out_path = data[35 : len(data)].rstrip(b"\x00") if len(data) > 35 else b""
        name_start = 35 + MAX_PATH_SIZE
        name_end = name_start + 32
        if len(data) >= name_end:
            name_raw = data[name_start:name_end]
        elif len(data) > name_start:
            name_raw = data[name_start : len(data)].ljust(32, b"\x00")
        else:
            name_raw = b"\x00" * 32
        name = name_raw.split(b"\x00")[0].decode("utf-8", errors="replace")
        last_advert = 0
        if len(data) >= name_end + 4:
            last_advert = struct.unpack_from("<I", data, name_end)[0]
        gps_lat, gps_lon = 0.0, 0.0
        if len(data) >= name_end + 4 + 8:
            gps_lat = struct.unpack_from("<i", data, name_end + 4)[0] / 1e6
            gps_lon = struct.unpack_from("<i", data, name_end + 8)[0] / 1e6
        lastmod = int(time.time())
        if len(data) >= name_end + 4 + 12:
            lastmod = struct.unpack_from("<I", data, name_end + 12)[0]
        contact = Contact(
            public_key=pubkey,
            name=name,
            adv_type=adv_type,
            flags=flags,
            out_path_len=out_path_len,
            out_path=out_path,
            last_advert_timestamp=last_advert,
            lastmod=lastmod,
            gps_lat=gps_lat,
            gps_lon=gps_lon,
        )
        ok = self.bridge.add_update_contact(contact)
        # Keep command/response parity: return a single frame for CMD_ADD_UPDATE_CONTACT.
        # Sending an extra RESP_CODE_CONTACT frame can desync some companion clients.
        self._write_ok() if ok else self._write_err(ERR_CODE_TABLE_FULL)
        if ok:
            try:
                await self._save_contacts()
            except Exception as e:
                logger.warning("Save contacts after add/update failed: %s", e)

    async def _cmd_remove_contact(self, data: bytes) -> None:
        if len(data) < 32:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        pubkey = data[:32]
        ok = self.bridge.remove_contact(pubkey)
        if ok:
            try:
                await self._save_contacts()
            except Exception as e:
                logger.warning("Save contacts after remove failed: %s", e)
        self._write_ok() if ok else self._write_err(ERR_CODE_NOT_FOUND)

    async def _cmd_reset_path(self, data: bytes) -> None:
        if len(data) < 32:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        pubkey = data[:32]
        ok = self.bridge.reset_path(pubkey)
        self._write_ok() if ok else self._write_err(ERR_CODE_NOT_FOUND)

    async def _cmd_get_batt_and_storage(self, data: bytes) -> None:
        millivolts, used_kb, total_kb = self._get_batt_and_storage()
        frame = (
            bytes([RESP_CODE_BATT_AND_STORAGE])
            + struct.pack("<H", millivolts)
            + struct.pack("<II", used_kb, total_kb)
        )
        self._write_frame(frame)

    async def _cmd_get_stats(self, data: bytes) -> None:
        stats_type = data[0] if len(data) >= 1 else STATS_TYPE_PACKETS
        if stats_type not in (
            STATS_TYPE_CORE,
            STATS_TYPE_RADIO,
            STATS_TYPE_PACKETS,
        ):
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        if self.stats_getter:
            if asyncio.iscoroutinefunction(self.stats_getter):
                stats = await self.stats_getter(stats_type)
            else:
                stats = await asyncio.to_thread(self.stats_getter, stats_type)
        else:
            stats = None
        stats = stats or self.bridge.get_stats(stats_type)
        frame = bytes([RESP_CODE_STATS, stats_type])
        if stats_type == STATS_TYPE_CORE:
            battery_mv = int(stats.get("battery_mv", 0))
            uptime_secs = int(stats.get("uptime_secs", 0))
            errors = int(stats.get("errors", 0))
            queue_len = min(255, max(0, int(stats.get("queue_len", 0))))
            frame += struct.pack("<H I H B", battery_mv, uptime_secs, errors, queue_len)
        elif stats_type == STATS_TYPE_RADIO:
            noise_floor = int(stats.get("noise_floor", 0))
            last_rssi = max(-128, min(127, int(stats.get("last_rssi", 0))))
            last_snr_scaled = max(
                -128,
                min(
                    127,
                    int(round((stats.get("last_snr") or 0) * 4)),
                ),
            )
            tx_air_secs = int(stats.get("tx_air_secs", 0))
            rx_air_secs = int(stats.get("rx_air_secs", 0))
            frame += struct.pack(
                "<h b b I I",
                noise_floor,
                last_rssi,
                last_snr_scaled,
                tx_air_secs,
                rx_air_secs,
            )
        else:
            recv = int(stats.get("recv", 0))
            sent = int(stats.get("sent", 0))
            flood_tx = int(stats.get("flood_tx", 0))
            direct_tx = int(stats.get("direct_tx", 0))
            flood_rx = int(stats.get("flood_rx", 0))
            direct_rx = int(stats.get("direct_rx", 0))
            recv_errors = int(stats.get("recv_errors", 0))
            frame += struct.pack(
                "<I I I I I I I",
                recv,
                sent,
                flood_tx,
                direct_tx,
                flood_rx,
                direct_rx,
                recv_errors,
            )
        self._write_frame(frame)

    async def _cmd_get_advert_path(self, data: bytes) -> None:
        if len(data) < 1 + PUB_KEY_SIZE:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        pub_key = data[1 : 1 + PUB_KEY_SIZE]
        prefix = pub_key[:7]
        # Bridge methods used from command handlers must not block the event loop;
        # if a subclass adds sync I/O here, run it via asyncio.to_thread().
        found = (
            self.bridge.get_advert_path(prefix)
            if getattr(self.bridge, "get_advert_path", None)
            else None
        )
        if not found:
            self._write_err(ERR_CODE_NOT_FOUND)
            return
        path_bytes = getattr(found, "path", None) or b""
        if not isinstance(path_bytes, bytes):
            path_bytes = bytes(path_bytes)
        path_len_encoded = getattr(found, "path_len", 0) or 0
        path_byte_len = PathUtils.get_path_byte_len(path_len_encoded)
        recv_ts = getattr(found, "recv_timestamp", 0)
        frame = (
            bytes([RESP_CODE_ADVERT_PATH])
            + struct.pack("<I", recv_ts)
            + bytes([path_len_encoded])
            + path_bytes[:path_byte_len]
        )
        self._write_frame(frame)

    async def _cmd_import_contact(self, data: bytes) -> None:
        ok = self.bridge.import_contact(data)
        self._write_ok() if ok else self._write_err(ERR_CODE_ILLEGAL_ARG)

    async def _cmd_get_channel(self, data: bytes) -> None:
        get_full_list = len(data) == 0
        channel_idx = data[0] if not get_full_list else 0
        max_channels_val = getattr(getattr(self.bridge, "channels", None), "max_channels", 40)

        def _channel_info_frame(idx: int, ch) -> bytes:
            if ch is None:
                name = b"\x00" * 32
                secret = b"\x00" * 16
            else:
                name = ch.name.encode("utf-8", errors="replace")[:32].ljust(32, b"\x00")
                secret = (ch.secret[:16] if ch.secret else b"\x00" * 16).ljust(16, b"\x00")
            return bytes([RESP_CODE_CHANNEL_INFO, idx]) + name + secret

        if get_full_list:
            for idx in range(max_channels_val):
                ch = self.bridge.get_channel(idx)
                frame = _channel_info_frame(idx, ch)
                self._write_frame(frame)
            if max_channels_val == 0:
                # Send at least one frame so client always gets a response per command
                self._write_frame(_channel_info_frame(0, None))
            return

        if channel_idx < 0 or channel_idx >= max_channels_val:
            self._write_err(ERR_CODE_NOT_FOUND)
            return
        ch = self.bridge.get_channel(channel_idx)
        frame = _channel_info_frame(channel_idx, ch)
        self._write_frame(frame)

    async def _cmd_set_channel(self, data: bytes) -> None:
        if len(data) < 34:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        channel_idx = data[0]
        name_raw = data[1:33]
        name = name_raw.split(b"\x00")[0].decode("utf-8", errors="replace").strip()
        if len(data) >= 97:
            try:
                secret = bytes.fromhex(data[33:97].decode("ascii"))
            except (ValueError, UnicodeDecodeError):
                self._write_err(ERR_CODE_ILLEGAL_ARG)
                return
        elif len(data) >= 65:
            secret = data[33:65]
        elif len(data) >= 49:
            secret = data[33:49]
        else:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        ok = self.bridge.set_channel(channel_idx, name, secret)
        if ok:
            try:
                await self._save_channels()
            except Exception as e:
                logger.warning("Save channels after set failed: %s", e)
        self._write_ok() if ok else self._write_err(ERR_CODE_NOT_FOUND)

    async def _cmd_set_flood_scope(self, data: bytes) -> None:
        """Delegate flood scope to the bridge (CMD_SET_FLOOD_SCOPE_KEY).

        Wire format after the cmd byte is stripped: [mode (1)] [key (16)].
        The firmware (MyMesh.cpp:1909) treats data[0] as a mode selector:
          * mode 0: set the scope override key (data[1:17]) when present, else
            reset the override; cancels any pending explicit-unscoped request.
          * mode 1 (FIRMWARE_VER_CODE 12+, PR #2492): force following floods to
            be unscoped, ignoring the configured default scope until mode 0.
        Older apps always sent mode 0, so this is backward compatible.
        """
        mode = data[0] if len(data) >= 1 else 0
        if mode == 1:
            self.bridge.set_flood_unscoped()
            self._write_ok()
            return
        if mode == 0:
            if len(data) >= 17:
                self.bridge.set_flood_scope(data[1:17])
            else:
                self.bridge.set_flood_scope(None)
            self._write_ok()
            return
        self._write_err(ERR_CODE_UNSUPPORTED_CMD)

    async def _cmd_set_default_flood_scope(self, data: bytes) -> None:
        """Handle CMD_SET_DEFAULT_FLOOD_SCOPE (63)."""
        if len(data) < 31 + 16:
            self.bridge.set_default_flood_scope(None, None)
            self._write_ok()
            return
        name_raw = data[:31]
        key = data[31 : 31 + 16]
        scope_name = name_raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace").strip()
        if not scope_name or len(scope_name) >= 31:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        if not self.bridge.set_default_flood_scope(scope_name, key):
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        self._write_ok()

    async def _cmd_get_default_flood_scope(self, data: bytes) -> None:
        """Handle CMD_GET_DEFAULT_FLOOD_SCOPE (64)."""
        scope = self.bridge.get_default_flood_scope()
        if scope is None:
            self._write_frame(bytes([RESP_CODE_DEFAULT_FLOOD_SCOPE]))
            return
        name, key = scope
        name_field = name.encode("utf-8", errors="replace")[:30].ljust(31, b"\x00")
        key_field = bytes(key[:16]).ljust(16, b"\x00")
        self._write_frame(bytes([RESP_CODE_DEFAULT_FLOOD_SCOPE]) + name_field + key_field)

    # -------------------------------------------------------------------------
    # Time, radio, tuning, share/export, logout, custom vars, autoadd
    # -------------------------------------------------------------------------

    async def _cmd_get_device_time(self, data: bytes) -> None:
        now = self.bridge.get_time()
        self._write_frame(bytes([RESP_CODE_CURR_TIME]) + struct.pack("<I", now))

    async def _cmd_set_device_time(self, data: bytes) -> None:
        if len(data) < 4:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        secs = struct.unpack("<I", data[:4])[0]
        if self.bridge.set_time(secs):
            self._write_ok()
        else:
            self._write_err(ERR_CODE_ILLEGAL_ARG)

    async def _cmd_set_radio_params(self, data: bytes) -> None:
        if len(data) < 10:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        # Frequency in kHz (match firmware self-info; client sends same encoding)
        freq_khz = struct.unpack_from("<I", data, 0)[0]
        bw = struct.unpack_from("<I", data, 4)[0]
        sf = data[8]
        cr = data[9]
        if not (100_000 <= freq_khz <= 2_500_000):
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        if not (7000 <= bw <= 500000):
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        if not (5 <= sf <= 12) or not (5 <= cr <= 8):
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        self.bridge.set_radio_params(freq_khz * 1000, bw, sf, cr)
        self._write_ok()

    async def _cmd_set_tx_power(self, data: bytes) -> None:
        if len(data) < 1:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        power = struct.unpack_from("<b", data, 0)[0]
        if power < -9 or power >= 30:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        self.bridge.set_tx_power(power)
        self._write_ok()

    async def _cmd_share_contact(self, data: bytes) -> None:
        if len(data) < PUB_KEY_SIZE:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        pubkey = data[:PUB_KEY_SIZE]
        ok = await self.bridge.share_contact(pubkey)
        self._write_ok() if ok else self._write_err(ERR_CODE_NOT_FOUND)

    async def _cmd_export_contact(self, data: bytes) -> None:
        if len(data) < PUB_KEY_SIZE:
            raw = self.bridge.export_contact(None)
            if raw is None:
                self._write_err(ERR_CODE_NOT_FOUND)
                return
            pubkey = raw[:32]
            name_raw = raw[33:65].split(b"\x00")[0]
            lat, lon = struct.unpack_from("<ii", raw, 65)
            flags = 0x01  # IS_CHAT_NODE
            loc_bytes = b""
            if lat != 0 or lon != 0:
                flags |= 0x10  # HAS_LOCATION
                loc_bytes = struct.pack("<ii", lat, lon)
            max_name = 32 - 1 - len(loc_bytes)
            name_bytes = name_raw[:max_name]
            if name_bytes:
                flags |= 0x80  # HAS_NAME
            appdata = bytes([flags]) + loc_bytes + name_bytes
            timestamp = int(time.time()) & 0xFFFFFFFF
            ts_bytes = struct.pack("<I", timestamp)
            to_sign = pubkey + ts_bytes + appdata
            try:
                sig = self.bridge._identity.sign(to_sign)
                if not sig or len(sig) != 64:
                    self._write_err(ERR_CODE_NOT_FOUND)
                    return
            except Exception as e:
                logger.warning("export_contact: signing failed: %s", e)
                self._write_err(ERR_CODE_NOT_FOUND)
                return
            packet = bytes([0x11, 0x00]) + pubkey + ts_bytes + sig + appdata
            self._write_frame(bytes([RESP_CODE_EXPORT_CONTACT]) + packet)
        else:
            raw = self.bridge.export_contact(data[:PUB_KEY_SIZE])
            if raw is None:
                self._write_err(ERR_CODE_NOT_FOUND)
                return
            try:
                sig = self.bridge._identity.sign(raw)
                if sig and len(sig) == 64:
                    raw = raw + sig
            except Exception as e:
                logger.warning("export_contact: signing failed: %s", e)
            self._write_frame(bytes([RESP_CODE_EXPORT_CONTACT]) + raw)

    async def _cmd_export_private_key(self, data: bytes) -> None:
        """Export private/signing key as 64-byte MeshCore format (RESP_CODE_PRIVATE_KEY + 64 bytes).

        For PyNaCl 32-byte seeds we expand to MeshCore 64-byte format (SHA-512 + clamp) so
        the client's ed25519_derive_pub yields the same public key and signing works.
        """
        identity = self.bridge._identity
        key_bytes = identity.get_signing_key_bytes()
        if len(key_bytes) == 32:
            key_bytes = CryptoUtils.ed25519_expand_seed_to_meshcore_64(key_bytes)
        elif len(key_bytes) < 64:
            key_bytes = key_bytes.ljust(64, b"\x00")
        else:
            key_bytes = key_bytes[:64]
        self._write_frame(bytes([RESP_CODE_PRIVATE_KEY]) + key_bytes)

    async def _cmd_import_private_key(self, data: bytes) -> None:
        """Stub/no-op: private key is set from config; dynamic import may be supported later."""
        self._write_ok()

    async def _cmd_set_tuning_params(self, data: bytes) -> None:
        if len(data) < 8:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        rx_ms = struct.unpack_from("<I", data, 0)[0]
        af_ms = struct.unpack_from("<I", data, 4)[0]
        self.bridge.set_tuning_params(rx_ms / 1000.0, af_ms / 1000.0)
        self._write_ok()

    async def _cmd_logout(self, data: bytes) -> None:
        if len(data) < PUB_KEY_SIZE:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        pubkey = data[:PUB_KEY_SIZE]
        await self.bridge.send_logout(pubkey)
        self._write_ok()

    async def _cmd_get_custom_vars(self, data: bytes) -> None:
        custom_vars = self.bridge.get_custom_vars()
        parts = [f"{k}:{v}" for k, v in custom_vars.items()]
        csv = ",".join(parts)[:140]
        self._write_frame(bytes([RESP_CODE_CUSTOM_VARS]) + csv.encode("utf-8", errors="replace"))

    async def _cmd_set_custom_var(self, data: bytes) -> None:
        if len(data) < 3:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        text = data.split(b"\x00")[0].decode("utf-8", errors="replace")
        sep = text.find(":")
        if sep < 1:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        name = text[:sep]
        value = text[sep + 1 :]
        ok = self.bridge.set_custom_var(name, value)
        self._write_ok() if ok else self._write_err(ERR_CODE_ILLEGAL_ARG)

    async def _cmd_set_autoadd_config(self, data: bytes) -> None:
        if len(data) < 1:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        self.bridge.set_autoadd_config(data[0])
        self._write_ok()

    async def _cmd_get_autoadd_config(self, data: bytes) -> None:
        config = self.bridge.get_autoadd_config()
        self._write_frame(bytes([RESP_CODE_AUTOADD_CONFIG, config & 0xFF]))

    async def _cmd_set_other_params(self, data: bytes) -> None:
        """Handle CMD_SET_OTHER_PARAMS (0x26). Mirrors MyMesh.cpp:1290-1305."""
        if len(data) < 1:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        manual_add = data[0]
        telemetry_modes = data[1] if len(data) >= 2 else 0
        advert_loc_policy = data[2] if len(data) >= 3 else 0
        multi_acks = data[3] if len(data) >= 4 else 0
        self.bridge.set_other_params(manual_add, telemetry_modes, advert_loc_policy, multi_acks)
        self._write_ok()

    async def _cmd_send_raw_data(self, data: bytes) -> None:
        """Handle CMD_SEND_RAW_DATA (25).
        Format: [path_len_encoded][path][payload] (min 4-byte payload)."""
        if len(data) < 6:
            self._write_err(ERR_CODE_UNSUPPORTED_CMD)
            return
        path_len_byte = data[0]
        if not PathUtils.is_valid_path_len(path_len_byte):
            self._write_err(ERR_CODE_UNSUPPORTED_CMD)
            return
        path_byte_len = PathUtils.get_path_byte_len(path_len_byte)
        if 1 + path_byte_len + 4 > len(data):
            self._write_err(ERR_CODE_UNSUPPORTED_CMD)
            return
        path = data[1 : 1 + path_byte_len]
        payload = data[1 + path_byte_len :]
        result = await self.bridge.send_raw_data_direct(
            path, payload, path_len_encoded=path_len_byte
        )
        if result.success:
            self._write_ok()
        else:
            self._write_err(ERR_CODE_TABLE_FULL)

    async def _cmd_set_path_hash_mode(self, data: bytes) -> None:
        """Handle CMD_SET_PATH_HASH_MODE (61). Format: [subtype(0), mode(0-2)].

        Mirrors MyMesh.cpp:1320-1327.  Subtype byte must be 0; mode values
        0, 1, 2 select 1-byte, 2-byte, 3-byte path hashes respectively.
        """
        if len(data) < 2 or data[0] != 0:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        mode = data[1]
        if mode >= 3:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        self.bridge.set_path_hash_mode(mode)
        self._write_ok()

    async def _cmd_get_allowed_repeat_freq(self, data: bytes) -> None:
        """Handle CMD_GET_ALLOWED_REPEAT_FREQ (60).

        Firmware (MyMesh.cpp:1958) replies with RESP_ALLOWED_REPEAT_FREQ followed
        by zero or more (lower_freq, upper_freq) little-endian u32 pairs. The
        virtual companion does not model regional repeat-frequency restrictions,
        so it advertises an empty range list (response code with no pairs).
        """
        self._write_frame(bytes([RESP_CODE_ALLOWED_REPEAT_FREQ]))

    async def _cmd_send_raw_packet(self, data: bytes) -> None:
        """Handle CMD_SEND_RAW_PACKET (65). Format: [priority(1)][raw_packet...].

        Mirrors MyMesh.cpp:1967: inject a low-level packet with a TX priority.
        Delegates to the bridge's ``send_raw_packet`` if available.
        """
        if len(data) < 3:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        priority = data[0]
        packet_bytes = data[1:]
        send_raw_packet = getattr(self.bridge, "send_raw_packet", None)
        if not send_raw_packet:
            self._write_err(ERR_CODE_UNSUPPORTED_CMD)
            return
        try:
            ok = await send_raw_packet(priority, packet_bytes)
        except Exception as e:
            logger.error("send_raw_packet error: %s", e, exc_info=True)
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        if ok:
            self._write_ok()
        else:
            self._write_err(ERR_CODE_TABLE_FULL)
