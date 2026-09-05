"""Messaging command handlers: text/channel sends, sync-next-message,
login/status/telemetry, binary/anon/control/trace/raw requests."""

import asyncio
import logging
import struct

from ...protocol.cayenne_lpp import TELEM_CHANNEL_SELF, encode_voltage
from ...protocol.constants import TELEM_PERM_BASE, TELEM_PERM_ENVIRONMENT, TELEM_PERM_LOCATION
from ...protocol.packet_utils import PathUtils
from ..constants import (
    ERR_CODE_BAD_STATE,
    ERR_CODE_ILLEGAL_ARG,
    ERR_CODE_NOT_FOUND,
    ERR_CODE_TABLE_FULL,
    ERR_CODE_UNSUPPORTED_CMD,
    FIRMWARE_VER_CODE,
    LOGIN_TIMEOUT_HINT_MS,
    MAX_CHANNEL_DATA_LENGTH,
    MAX_GROUP_DATA_LENGTH,
    MAX_PATH_SIZE,
    OUT_PATH_UNKNOWN,
    PUB_KEY_SIZE,
    PUSH_CODE_LOGIN_FAIL,
    PUSH_CODE_LOGIN_SUCCESS,
    PUSH_CODE_STATUS_RESPONSE,
    PUSH_CODE_TELEMETRY_RESPONSE,
    RESP_CODE_CHANNEL_DATA_RECV,
    RESP_CODE_CHANNEL_MSG_RECV,
    RESP_CODE_CHANNEL_MSG_RECV_V3,
    RESP_CODE_CONTACT_MSG_RECV,
    RESP_CODE_CONTACT_MSG_RECV_V3,
    RESP_CODE_NO_MORE_MESSAGES,
    STATUS_TIMEOUT_HINT_MS,
    TELEMETRY_TIMEOUT_HINT_MS,
    TXT_MSG_TIMEOUT_HINT_MS,
    TXT_TYPE_CLI_DATA,
    TXT_TYPE_PLAIN,
    TXT_TYPE_SIGNED_PLAIN,
)
from ..models import QueuedMessage

logger = logging.getLogger("CompanionFrameServer")


def _encode_lpp_voltage(channel: int, millivolts: int) -> bytes:
    """Encode a CayenneLPP voltage entry the way the firmware does.

    Firmware: `telemetry.addVoltage(TELEM_CHANNEL_SELF, battMilliVolts/1000.0f)`
    (MyMesh.cpp:1644). CayenneLPP computes `uint32_t v = value * multiplier`
    entirely in single-precision float and truncates toward zero, so the float
    rounding is reproduced here (e.g. 4200 mV -> 4.2f*100 = 419.99998 -> 419)
    to stay byte-identical. Unknown battery (0 mV) still emits a 0 V entry.
    """
    return encode_voltage(channel, millivolts / 1000.0)


class _MessagingCommandsMixin:
    """Messaging and request _cmd_* handlers of :class:`CompanionFrameServer`."""

    def _spawn_request_task(self, coro, label: str) -> asyncio.Task:
        """Track request completion on a real companion, with a test-safe fallback."""
        spawn = getattr(self.bridge, "_spawn_background_task", None)
        if getattr(spawn, "__self__", None) is self.bridge:
            return spawn(coro, label)
        return asyncio.create_task(coro)

    def _write_request_start_error(self, started: dict) -> None:
        error = started.get("error")
        if error == "not_found":
            code = ERR_CODE_NOT_FOUND
        elif error == "send_failed":
            code = ERR_CODE_TABLE_FULL
        else:
            code = ERR_CODE_BAD_STATE
        self._write_err(code)

    async def _cmd_send_txt_msg(self, data: bytes) -> None:
        # Firmware: `cmd_frame[0] == CMD_SEND_TXT_MSG && len >= 14` (MyMesh.cpp
        # handleCmdFrame), where len includes the command byte. `data` here has
        # already had the command byte stripped, so the equivalent minimum is
        # 13: 12 header bytes (txt_type, attempt, timestamp, pubkey_prefix)
        # plus at least 1 text byte. Frames that fail this length check don't
        # match any `else if` branch and fall through to the catch-all
        # `else { writeErrFrame(ERR_CODE_UNSUPPORTED_CMD); }` at the end of
        # handleCmdFrame, so that's the code we mirror here (not ILLEGAL_ARG).
        if len(data) < 13:
            self._write_err(ERR_CODE_UNSUPPORTED_CMD)
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
        # Firmware (MyMesh.cpp CMD_SEND_TXT_MSG) only sends for TXT_TYPE_PLAIN
        # and TXT_TYPE_CLI_DATA; any other txt_type (e.g. reserved/unknown
        # values, or TXT_TYPE_SIGNED_PLAIN which this command doesn't support)
        # falls into the `else` branch. That branch picks
        # ERR_CODE_NOT_FOUND if the recipient lookup failed, else
        # ERR_CODE_UNSUPPORTED_CMD for the unsupported txt_type — so the
        # not-found check above must run first, and this check second.
        if txt_type not in (TXT_TYPE_PLAIN, TXT_TYPE_CLI_DATA):
            self._write_err(ERR_CODE_UNSUPPORTED_CMD)
            return
        result = await self.bridge.send_text_message(
            contact.public_key_bytes,
            text,
            txt_type=txt_type,
            attempt=attempt,
            wait_for_ack=False,
            timestamp=use_timestamp,
        )
        if result.success:
            self._write_sent_result(result, default_timeout_ms=TXT_MSG_TIMEOUT_HINT_MS)
        else:
            # Firmware maps MSG_SEND_FAILED to TABLE_FULL (MyMesh.cpp
            # CMD_SEND_TXT_MSG), so strictly-compatible clients expect it.
            self._write_err(ERR_CODE_TABLE_FULL)

    async def _cmd_send_channel_txt_msg(self, data: bytes) -> None:
        if len(data) < 6:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        txt_type = data[0]
        channel_idx = data[1]
        msg_timestamp = struct.unpack("<I", data[2:6])[0]
        text = data[6:].decode("utf-8", errors="replace").rstrip("\x00")
        if txt_type != 0:
            self._write_err(ERR_CODE_UNSUPPORTED_CMD)
            return
        if self.bridge.get_channel(channel_idx) is None:
            self._write_err(ERR_CODE_NOT_FOUND)
            return
        ok = await self.bridge.send_channel_message(channel_idx, text, timestamp=msg_timestamp)
        # Firmware reports any channel-send failure as NOT_FOUND (MyMesh.cpp
        # CMD_SEND_CHANNEL_TXT_MSG), so strictly-compatible clients expect it.
        self._write_ok() if ok else self._write_err(ERR_CODE_NOT_FOUND)

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
        if data_type == 0 or len(payload) > MAX_GROUP_DATA_LENGTH:
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
        if len(data) < PUB_KEY_SIZE + 1:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        pubkey = data[:PUB_KEY_SIZE]
        req_data = data[PUB_KEY_SIZE:]
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
            self._write_err(
                ERR_CODE_NOT_FOUND if result.error == "not_found" else ERR_CODE_TABLE_FULL
            )
            return
        self._write_sent_result(result, own_binary_tag=True)

    async def _cmd_send_anon_req(self, data: bytes) -> None:
        if len(data) < PUB_KEY_SIZE + 1:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        pubkey = data[:PUB_KEY_SIZE]
        req_data = data[PUB_KEY_SIZE:]
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
        self._write_sent_result(result, own_binary_tag=True)

    async def _cmd_send_control_data(self, data: bytes) -> None:
        # Firmware: `len >= 2 && (cmd_frame[1] & 0x80) != 0`, where `len` includes
        # the command byte. `data` here has the command byte already stripped, so
        # the minimum is 1 byte, and `data[0]` is the firmware's `cmd_frame[1]`.
        # A failure of either condition falls through the else-if chain to the
        # catch-all `else { writeErrFrame(ERR_CODE_UNSUPPORTED_CMD); }`, not
        # ILLEGAL_ARG.
        if len(data) < 1 or (data[0] & 0x80) == 0:
            self._write_err(ERR_CODE_UNSUPPORTED_CMD)
            return
        # Discovery request: register a no-op response callback
        if self._control_handler and len(data) >= 6 and (data[0] & 0xF0) == 0x80:
            tag = struct.unpack("<I", data[2:6])[0]
            self._companion_discovery_tags.add(tag)
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
        if len(data) < 1 + PUB_KEY_SIZE:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        pub_key = data[1 : 1 + PUB_KEY_SIZE]
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
            self._write_err(
                ERR_CODE_NOT_FOUND if result.error == "not_found" else ERR_CODE_TABLE_FULL
            )
            return
        self._write_sent_result(result)

    async def _cmd_send_trace_path(self, data: bytes) -> None:
        if len(data) < 10:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        tag = struct.unpack_from("<I", data, 0)[0]
        auth_code = struct.unpack_from("<I", data, 4)[0]
        flags = data[8]
        path_bytes = data[9:]
        path_len = len(path_bytes)
        hash_width = PathUtils.trace_payload_hash_width(flags)
        if (path_len // hash_width) > MAX_PATH_SIZE or (path_len % hash_width) != 0:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        send_raw = getattr(self.bridge, "send_trace_path_raw", None)
        if not send_raw:
            self._write_err(ERR_CODE_UNSUPPORTED_CMD)
            return
        try:
            result = await send_raw(tag, auth_code, flags, path_bytes)
        except Exception as e:
            logger.error("send_trace_path error: %s", e, exc_info=True)
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        if not result.success:
            self._write_err(ERR_CODE_TABLE_FULL)
            return
        # Firmware CMD_SEND_TRACE_PATH only sends and returns SENT with the
        # est_timeout hint (MyMesh.cpp:1750-1775); trace completion (the
        # PUSH_CODE_TRACE_DATA frame) is produced by the receive pipeline when the
        # echoed trace reaches the end of its path (Mesh.cpp:41-64 -> onTraceRecv),
        # never synthesised here at send time.
        self._write_sent_response(result.is_flood, tag, result.timeout_ms)

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
        extra = b""
        if msg.txt_type == TXT_TYPE_SIGNED_PLAIN:
            # Firmware queueMessage() inserts the 4-byte author pubkey prefix
            # between the timestamp and the text for signed (room server)
            # messages; the app consumes these 4 bytes to attribute the author.
            author = bytes(getattr(msg, "sender_prefix", b"") or b"")
            extra = author[:4].ljust(4, b"\x00")
        if self._app_target_ver >= 3:
            return (
                bytes([RESP_CODE_CONTACT_MSG_RECV_V3, snr_byte & 0xFF, 0, 0])
                + prefix
                + bytes([path_len_byte, msg.txt_type])
                + struct.pack("<I", msg.timestamp)
                + extra
                + text_bytes
            )
        return (
            bytes([RESP_CODE_CONTACT_MSG_RECV])
            + prefix
            + bytes([path_len_byte, msg.txt_type])
            + struct.pack("<I", msg.timestamp)
            + extra
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
        if len(data) < PUB_KEY_SIZE:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        pubkey = data[:PUB_KEY_SIZE]
        password = (
            data[PUB_KEY_SIZE:].decode("utf-8", errors="replace").rstrip("\x00")
            if len(data) > PUB_KEY_SIZE
            else ""
        )
        started = await self.bridge._start_frame_login_request(pubkey, password)
        if not started.get("success"):
            self._write_request_start_error(started)
            return
        self._write_sent_result(started["sent"], default_timeout_ms=LOGIN_TIMEOUT_HINT_MS)
        if not started.get("session_owner", True):
            # A previous command already owns the one completion writer for this
            # logical login session. This retry only sends another radio packet.
            return

        async def _write_login_result() -> None:
            result = await started["task"]
            if result.get("timeout"):
                logger.debug("Login request timed out for %s; no login push sent", pubkey[:6].hex())
                return
            if result.get("success"):
                # Layout matches MeshCore companion_radio onContactResponse
                fw_level = result.get("firmware_ver_level")
                if fw_level is None:
                    fw_level = FIRMWARE_VER_CODE  # fallback so app sees >= 2 for owner info
                # Byte 1 is the server's raw reply byte 6, forwarded verbatim
                # the way companion_radio does (`out_frame[i++] = data[6]`): a
                # room server distinguishes admin (1) from a plain guest (2),
                # and collapsing it to a boolean would drop that.
                admin_code = result.get("admin_code")
                if admin_code is None:
                    admin_code = 1 if result.get("is_admin") else 0
                self._write_frame(
                    bytes(
                        [
                            PUSH_CODE_LOGIN_SUCCESS,
                            min(255, max(0, int(admin_code))),
                        ]
                    )
                    + pubkey[:6]
                    + struct.pack("<I", result.get("tag", 0))
                    + bytes([result.get("acl_permissions", 0)])
                    + bytes([min(255, max(0, int(fw_level)))])
                )
            else:
                self._write_frame(bytes([PUSH_CODE_LOGIN_FAIL, 0]) + pubkey[:6])

        self._spawn_request_task(_write_login_result(), "companion login response")

    async def _cmd_send_status_req(self, data: bytes) -> None:
        if len(data) < PUB_KEY_SIZE:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        pubkey = data[0:PUB_KEY_SIZE]
        started = await self.bridge._start_status_request(pubkey)
        if not started.get("success"):
            self._write_request_start_error(started)
            return
        self._write_sent_result(started["sent"], default_timeout_ms=STATUS_TIMEOUT_HINT_MS)

        async def _write_status_result() -> None:
            result = await started["task"]
            if not result.get("success"):
                logger.debug("Status request failed for %s; no push sent", pubkey[:6].hex())
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

        self._spawn_request_task(_write_status_result(), "companion status response")

    async def _cmd_send_telemetry_req(self, data: bytes) -> None:
        # Firmware CMD_SEND_TELEMETRY_REQ has two forms, split by frame length
        # (MyMesh.cpp:1622-1656). Frame length includes the command byte;
        # OpenHop's `data` is cmd-byte-stripped, so subtract one from each guard:
        #   - remote/contact form: firmware `len >= 4 + PUB_KEY_SIZE` -> data >= 35
        #     (3 reserved bytes then a 32-byte pub key).
        #   - self form: firmware `len == 4` -> data == 3 (3 reserved/unused bytes).
        #     Firmware builds local telemetry synchronously and pushes it.
        # Anything else falls through the else-if chain to the catch-all
        # writeErrFrame(ERR_CODE_UNSUPPORTED_CMD).
        if len(data) == 3:
            self._push_self_telemetry()
            return
        if len(data) < 3 + PUB_KEY_SIZE:
            self._write_err(ERR_CODE_UNSUPPORTED_CMD)
            return
        pubkey = data[3 : 3 + PUB_KEY_SIZE]
        # Request all: base + location + environment
        flags = TELEM_PERM_BASE | TELEM_PERM_LOCATION | TELEM_PERM_ENVIRONMENT
        want_base = bool(flags & TELEM_PERM_BASE)
        want_location = bool(flags & TELEM_PERM_LOCATION)
        want_environment = bool(flags & TELEM_PERM_ENVIRONMENT)
        started = await self.bridge._start_telemetry_request(
            pubkey,
            want_base=want_base,
            want_location=want_location,
            want_environment=want_environment,
        )
        if not started.get("success"):
            self._write_request_start_error(started)
            return
        self._write_sent_result(started["sent"], default_timeout_ms=TELEMETRY_TIMEOUT_HINT_MS)

        async def _write_telemetry_result() -> None:
            result = await started["task"]
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

        self._spawn_request_task(_write_telemetry_result(), "companion telemetry response")

    def _push_self_telemetry(self) -> None:
        """Build and synchronously push this node's own telemetry.

        Mirrors the firmware 'self' telemetry request (MyMesh.cpp:1642-1656):
        it seeds a CayenneLPP buffer with a battery-voltage entry
        (`telemetry.addVoltage(TELEM_CHANNEL_SELF, battMilliVolts/1000)`),
        appends any local sensor LPP bytes (`sensors.querySensors(0xFF, ...)`),
        and writes a single push frame
        `[PUSH_CODE_TELEMETRY_RESPONSE][0x00][self pubkey[0:6]][CayenneLPP]`.
        The push is always emitted, even with no sensors (voltage-only floor),
        and is written synchronously in the handler like the firmware.
        """
        millivolts = self._get_batt_and_storage()[0]
        lpp = _encode_lpp_voltage(TELEM_CHANNEL_SELF, millivolts)
        lpp += self._get_self_telemetry_lpp()
        pubkey_prefix = self.bridge.get_public_key()[:6]
        self._write_frame(bytes([PUSH_CODE_TELEMETRY_RESPONSE, 0]) + pubkey_prefix + lpp)
        logger.info("Self telemetry push sent to client: %d bytes LPP", len(lpp))

    async def _cmd_has_connection(self, data: bytes) -> None:
        # Firmware MyMesh.cpp:1678-1684 gates this branch on
        # `len >= 1 + PUB_KEY_SIZE` (length includes the command byte). OpenHop's
        # `data` is cmd-byte-stripped, so a full pub key is 32 bytes; a shorter
        # frame fails the guard and falls through the else-if chain to
        # writeErrFrame(ERR_CODE_UNSUPPORTED_CMD).
        if len(data) < PUB_KEY_SIZE:
            self._write_err(ERR_CODE_UNSUPPORTED_CMD)
            return
        pubkey = data[:PUB_KEY_SIZE]
        # hasConnectionTo (BaseChatMesh.cpp:707-712): OK if a live login
        # connection exists, else ERR_CODE_NOT_FOUND.
        if self.bridge.has_login_connection(pubkey):
            self._write_ok()
        else:
            self._write_err(ERR_CODE_NOT_FOUND)

    async def _cmd_logout(self, data: bytes) -> None:
        if len(data) < PUB_KEY_SIZE:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        pubkey = data[:PUB_KEY_SIZE]
        # Firmware CMD_LOGOUT (MyMesh.cpp:1685-1688) calls stopConnection before
        # writeOKFrame, unconditionally clearing the connection slot.
        self.bridge.clear_login_connection(pubkey)
        await self.bridge.send_logout(pubkey)
        self._write_ok()

    async def _cmd_send_raw_data(self, data: bytes) -> None:
        """Handle CMD_SEND_RAW_DATA (25).
        Format: [path_len_encoded][path][payload] (min 4-byte payload).

        Firmware (MyMesh.cpp handleCmdFrame, `dev` / 0cce9197):
        - Frame never enters the branch (`len < 6`, command byte included) →
          catch-all ``ERR_CODE_UNSUPPORTED_CMD``.
        - Invalid encoded ``path_len`` → ``ERR_CODE_UNSUPPORTED_CMD``.
        - Valid path, then remaining payload (or path bytes) short of 4 →
          ``ERR_CODE_ILLEGAL_ARG`` (``writePath`` then ``i + 4 > len``).

        ``data`` is command-stripped, so ``len(data) < 5`` is the ``len < 6``
        case. A zero-hop frame (path_len=0, 4-byte payload → len(data) == 5)
        is the firmware minimum and must not be rejected here.
        """
        if len(data) < 5:
            self._write_err(ERR_CODE_UNSUPPORTED_CMD)
            return
        path_len_byte = data[0]
        if not PathUtils.is_valid_path_len(path_len_byte):
            self._write_err(ERR_CODE_UNSUPPORTED_CMD)
            return
        path_byte_len = PathUtils.get_path_byte_len(path_len_byte)
        if 1 + path_byte_len + 4 > len(data):
            self._write_err(ERR_CODE_ILLEGAL_ARG)
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
            result = await send_raw_packet(priority, packet_bytes)
        except Exception as e:
            logger.error("send_raw_packet error: %s", e, exc_info=True)
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        # Firmware: tryParsePacket fail → releasePacket + ILLEGAL_ARG;
        # obtainNewPacket fail / send fail → TABLE_FULL.
        if result is True or getattr(result, "success", False):
            self._write_ok()
            return
        if getattr(result, "error", None) == "illegal_arg":
            self._write_err(ERR_CODE_ILLEGAL_ARG)
        else:
            self._write_err(ERR_CODE_TABLE_FULL)
