"""Device command handlers: app start/device query, time, radio params,
stats, flood scope, custom vars, autoadd, keys, tuning."""

import asyncio
import inspect
import logging
import struct

from ...protocol import SIGNATURE_SIZE, CryptoUtils
from ..constants import (
    ADV_TYPE_CHAT,
    DEFAULT_MAX_TX_POWER_DBM,
    ERR_CODE_BAD_STATE,
    ERR_CODE_ILLEGAL_ARG,
    ERR_CODE_TABLE_FULL,
    ERR_CODE_UNSUPPORTED_CMD,
    FIRMWARE_VER_CODE,
    RESP_CODE_ALLOWED_REPEAT_FREQ,
    RESP_CODE_AUTOADD_CONFIG,
    RESP_CODE_BATT_AND_STORAGE,
    RESP_CODE_CLI_REPLY,
    RESP_CODE_CURR_TIME,
    RESP_CODE_CUSTOM_VARS,
    RESP_CODE_DEFAULT_FLOOD_SCOPE,
    RESP_CODE_DEVICE_INFO,
    RESP_CODE_DISABLED,
    RESP_CODE_PRIVATE_KEY,
    RESP_CODE_SELF_INFO,
    RESP_CODE_SIGN_START,
    RESP_CODE_SIGNATURE,
    RESP_CODE_STATS,
    RESP_CODE_TUNING_PARAMS,
    STATS_TYPE_CORE,
    STATS_TYPE_PACKETS,
    STATS_TYPE_RADIO,
)

logger = logging.getLogger("CompanionFrameServer")


class _DeviceCommandsMixin:
    """Device and configuration _cmd_* handlers of :class:`CompanionFrameServer`."""

    def _max_tx_power_dbm_value(self) -> int:
        """Return the advertised maximum TX-power capability, in raw dBm.

        Shared source of truth for the SELF_INFO maximum TX-power byte and the
        CMD_SET_RADIO_TX_POWER upper-bound validation, matching firmware's
        target-specific ``MAX_LORA_TX_POWER`` (MyMesh.cpp).
        """
        try:
            value = int(self.bridge.get_max_tx_power_dbm())
        except (TypeError, ValueError):
            value = DEFAULT_MAX_TX_POWER_DBM
        except Exception:
            logger.warning(
                "Could not get maximum TX power from companion integration", exc_info=True
            )
            value = DEFAULT_MAX_TX_POWER_DBM
        return value

    def _max_tx_power_byte(self) -> int:
        """Return the signed, one-byte SELF_INFO maximum TX-power field."""
        return max(-9, min(127, self._max_tx_power_dbm_value())) & 0xFF

    def _radio_mutation_supported(self, capability: str) -> bool:
        """Check an optional integration capability while retaining old adapters."""
        checker = getattr(self.bridge, capability, None)
        return True if not callable(checker) else bool(checker())

    async def _cmd_app_start(self, data: bytes) -> None:
        # MeshCore CMD_APP_START requires the full 7-byte reserved prefix (total
        # frame len >= 8). Those bytes are reserved for future use, not a version:
        # the protocol version is negotiated only through DEVICE_QUERY.
        if len(data) < 7:
            # OpenHop deliberately uses ILLEGAL_ARG here; firmware falls through to UNSUPPORTED_CMD.
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        prefs = self.bridge.get_self_info()
        pubkey = self.bridge.get_public_key()
        name = prefs.node_name.encode("utf-8", errors="replace")
        lat = int(getattr(prefs, "latitude", 0) * 1e6)
        lon = int(getattr(prefs, "longitude", 0) * 1e6)
        frame = (
            bytes(
                [
                    RESP_CODE_SELF_INFO,
                    ADV_TYPE_CHAT,
                    prefs.tx_power_dbm & 0xFF,
                    self._max_tx_power_byte(),
                ]
            )
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
                    (getattr(prefs, "telemetry_mode_base", 0) & 0x03)
                    | ((getattr(prefs, "telemetry_mode_location", 0) & 0x03) << 2)
                    | ((getattr(prefs, "telemetry_mode_environment", 0) & 0x03) << 4)
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
        try:
            prefs = self.bridge.get_self_info()
            ble_pin = int(getattr(prefs, "ble_pin", 0)) & 0xFFFFFFFF
            client_repeat = getattr(prefs, "client_repeat", 0) & 0xFF
            path_hash_mode = getattr(prefs, "path_hash_mode", 0) & 0xFF
        except Exception:
            ble_pin = 0
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

    async def _cmd_send_self_advert(self, data: bytes) -> None:
        flood = len(data) >= 1 and data[0] == 1
        ok = await self.bridge.advertise(flood=flood)
        self._write_ok() if ok else self._write_err(ERR_CODE_TABLE_FULL)

    async def _cmd_set_advert_name(self, data: bytes) -> None:
        # Firmware (MyMesh.cpp: CMD_SET_ADVERT_NAME) requires len >= 2 (frame len
        # including cmd byte), i.e. at least one name byte after the cmd byte.
        # Shorter frames fall through to the catch-all UNSUPPORTED_CMD.
        if len(data) < 1:
            self._write_err(ERR_CODE_UNSUPPORTED_CMD)
            return
        name = data.decode("utf-8", errors="replace").rstrip("\x00")
        self.bridge.set_advert_name(name)
        self._write_ok()

    async def _cmd_set_device_pin(self, data: bytes) -> None:
        # Firmware (MyMesh.cpp: CMD_SET_DEVICE_PIN) needs frame len >= 5; shorter
        # frames fall through to the catch-all UNSUPPORTED_CMD. The PIN must be
        # 0 (none) or six digits.
        if len(data) < 4:
            self._write_err(ERR_CODE_UNSUPPORTED_CMD)
            return
        (pin,) = struct.unpack_from("<I", data, 0)
        if pin != 0 and not 100000 <= pin <= 999999:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        self.bridge.set_device_pin(pin)
        self._write_ok()

    async def _cmd_run_cli_command(self, data: bytes) -> None:
        # Firmware (MyMesh.cpp: CMD_RUN_CLI_COMMAND, v14+) needs frame len >= 3.
        # The reply is always RESP_CODE_CLI_REPLY carrying the CLI's text, never
        # an error frame -- an unknown command answers "Unknown command".
        run = getattr(self.bridge, "run_cli_command", None)
        if len(data) < 2 or not callable(run):
            self._write_err(ERR_CODE_UNSUPPORTED_CMD)
            return
        # Firmware reads the text as a C string: it ends at the first NUL.
        command = data.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        reply = run(command, 0)
        cli = getattr(self.bridge, "cli", None)
        if getattr(cli, "last_command_rebooted", False) is True:
            return  # `reboot`: firmware never answers; the client is being dropped
        self._write_frame(bytes([RESP_CODE_CLI_REPLY]) + reply.encode("utf-8"))

    async def _cmd_reboot(self, data: bytes) -> None:
        # Firmware (MyMesh.cpp: CMD_REBOOT) checks the 6-byte "reboot" magic
        # (memcmp, so trailing bytes are ignored) and never replies: the device
        # resets. Here the companion reloads its
        # settings and the ``reboot`` push drops the client, so the app
        # reconnects and re-syncs as it would after a real reboot.
        reboot = getattr(self.bridge, "request_reboot", None)
        if data[:6] != b"reboot" or not callable(reboot):
            self._write_err(ERR_CODE_UNSUPPORTED_CMD)
            return
        reboot()

    async def _cmd_set_advert_latlon(self, data: bytes) -> None:
        if len(data) < 8:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        lat, lon = struct.unpack_from("<ii", data, 0)
        self.bridge.set_advert_latlon(lat / 1e6, lon / 1e6)
        self._write_ok()

    async def _cmd_get_batt_and_storage(self, data: bytes) -> None:
        millivolts, used_kb, total_kb = self._get_batt_and_storage()
        frame = (
            bytes([RESP_CODE_BATT_AND_STORAGE])
            + struct.pack("<H", millivolts)
            + struct.pack("<II", used_kb, total_kb)
        )
        self._write_frame(frame)

    async def _cmd_get_stats(self, data: bytes) -> None:
        # Firmware (MyMesh.cpp: CMD_GET_STATS) requires len >= 2 (frame len
        # including cmd byte), i.e. the stats-type subtype byte must be present.
        # Shorter frames fall through to the catch-all UNSUPPORTED_CMD.
        if len(data) < 1:
            self._write_err(ERR_CODE_UNSUPPORTED_CMD)
            return
        stats_type = data[0]
        if stats_type not in (
            STATS_TYPE_CORE,
            STATS_TYPE_RADIO,
            STATS_TYPE_PACKETS,
        ):
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        if self.stats_getter:
            if inspect.iscoroutinefunction(self.stats_getter):
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

    async def _cmd_set_flood_scope(self, data: bytes) -> None:
        """Delegate flood scope to the bridge (CMD_SET_FLOOD_SCOPE_KEY).

        Wire format after the cmd byte is stripped: [mode (1)] [key (16)].
        The firmware (MyMesh.cpp:1909) treats data[0] as a mode selector:
          * mode 0: set the scope override key (data[1:17]) when present, else
            reset the override; cancels any pending explicit-unscoped request.
          * mode 1 (FIRMWARE_VER_CODE 12+, PR #2492): force following floods to
            be unscoped, ignoring the configured default scope until mode 0.
        Older apps always sent mode 0, so this is backward compatible.

        Firmware (MyMesh.cpp: CMD_SET_FLOOD_SCOPE_KEY) requires len >= 2 (frame
        len including cmd byte), i.e. the mode byte must be present. A frame
        with no bytes at all falls through to the catch-all UNSUPPORTED_CMD;
        a frame with just the mode byte (mode 0) is valid and resets the
        scope override, matching firmware's `len >= 2 + 16` else-branch.
        """
        if len(data) < 1:
            self._write_err(ERR_CODE_UNSUPPORTED_CMD)
            return
        mode = data[0]
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
        # Optional repeat byte (FIRMWARE_VER_CODE 9+): enables client-repeat.
        repeat = data[10] if len(data) > 10 else 0
        # Firmware lower bound is 150,000 kHz (MyMesh.cpp CMD_SET_RADIO_PARAMS).
        if not (150_000 <= freq_khz <= 2_500_000):
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        if not (7000 <= bw <= 500000):
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        if not (5 <= sf <= 12) or not (5 <= cr <= 8):
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        # Firmware rejects enabling repeat on a frequency outside the allowed
        # repeat table, and does so before any device-specific gating.
        if repeat and not self._repeat_freq_allowed(freq_khz):
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        if not self._radio_mutation_supported("supports_radio_params_mutation"):
            # Companion apps submit radio and identity settings as one save
            # transaction and abandon subsequent updates after an error. A
            # virtual companion cannot alter its host's shared radio, but a
            # valid radio update must be acknowledged as a no-op so settings
            # such as the name and position can still be saved.
            self._write_ok()
            return
        apply_async = getattr(self.bridge, "set_radio_params_async", None)
        if inspect.iscoroutinefunction(apply_async):
            applied = await apply_async(freq_khz * 1000, bw, sf, cr)
        else:
            applied = self.bridge.set_radio_params(freq_khz * 1000, bw, sf, cr)
        if not applied:
            self._write_err(ERR_CODE_BAD_STATE)
            return
        # Firmware persists client_repeat alongside the radio params (0 when the
        # byte is absent). A companion that cannot repeat acks the save but
        # never stores a nonzero preference (ack-but-ignore).
        if self._radio_mutation_supported("supports_client_repeat"):
            self.bridge.set_client_repeat(repeat)
        self._write_ok()

    def _repeat_freq_allowed(self, freq_khz: int) -> bool:
        """Whether ``freq_khz`` falls in the companion's allowed-repeat ranges."""
        getter = getattr(self.bridge, "get_allowed_repeat_freqs", None)
        ranges = getter() if callable(getter) else ()
        return any(lower <= freq_khz <= upper for lower, upper in ranges)

    async def _cmd_set_tx_power(self, data: bytes) -> None:
        if len(data) < 1:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        power = struct.unpack_from("<b", data, 0)[0]
        # Firmware (MyMesh.cpp CMD_SET_RADIO_TX_POWER, ~L1409): reject below the
        # -9 dBm floor or above the target-specific MAX_LORA_TX_POWER ceiling,
        # the same capability advertised in SELF_INFO. Upper bound is inclusive.
        max_power = self._max_tx_power_dbm_value()
        if power < -9 or power > max_power:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        if not self._radio_mutation_supported("supports_tx_power_mutation"):
            # See _cmd_set_radio_params: acknowledge valid shared-radio
            # writes without persisting or applying them for client
            # transaction compatibility.
            self._write_ok()
            return
        if self.bridge.set_tx_power(power):
            self._write_ok()
        else:
            self._write_err(ERR_CODE_BAD_STATE)

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
        """Report private-key import as unavailable without changing identity."""
        # MeshCore only reaches the disabled-import branch for a complete
        # 64-byte key payload. Short frames fall through to UNSUPPORTED_CMD.
        if len(data) < 64:
            self._write_err(ERR_CODE_UNSUPPORTED_CMD)
            return
        self._write_frame(bytes([RESP_CODE_DISABLED]))

    async def _cmd_sign_start(self, data: bytes) -> None:
        """Start or replace the current 8 KiB companion signing session."""
        sign_start = getattr(self.bridge, "sign_start", None)
        if not callable(sign_start):
            self._write_err(ERR_CODE_UNSUPPORTED_CMD)
            return
        max_size = sign_start()
        self._write_frame(bytes([RESP_CODE_SIGN_START, 0]) + struct.pack("<I", max_size))

    async def _cmd_sign_data(self, data: bytes) -> None:
        """Append a non-empty chunk to the current companion signing session."""
        # Firmware does not match CMD_SIGN_DATA with an empty payload, so it
        # falls through to the generic unsupported-command response.
        if not data:
            self._write_err(ERR_CODE_UNSUPPORTED_CMD)
            return
        sign_data = getattr(self.bridge, "sign_data", None)
        if not callable(sign_data):
            self._write_err(ERR_CODE_UNSUPPORTED_CMD)
            return
        is_signing = getattr(self.bridge, "is_signing", None)
        if callable(is_signing) and not is_signing():
            self._write_err(ERR_CODE_BAD_STATE)
            return
        if not sign_data(data):
            self._write_err(ERR_CODE_TABLE_FULL)
            return
        self._write_ok()

    async def _cmd_sign_finish(self, data: bytes) -> None:
        """Finish the active signing session and return its Ed25519 signature."""
        sign_finish = getattr(self.bridge, "sign_finish", None)
        if not callable(sign_finish):
            self._write_err(ERR_CODE_UNSUPPORTED_CMD)
            return
        signature = sign_finish()
        if signature is None or len(signature) != SIGNATURE_SIZE:
            self._write_err(ERR_CODE_BAD_STATE)
            return
        self._write_frame(bytes([RESP_CODE_SIGNATURE]) + signature)

    async def _cmd_set_tuning_params(self, data: bytes) -> None:
        if len(data) < 8:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        rx_ms = struct.unpack_from("<I", data, 0)[0]
        af_ms = struct.unpack_from("<I", data, 4)[0]
        self.bridge.set_tuning_params(rx_ms / 1000.0, af_ms / 1000.0)
        self._write_ok()

    async def _cmd_get_tuning_params(self, data: bytes) -> None:
        # Firmware MyMesh.cpp:1428-1434: no length guard; responds with
        # RESP_CODE_TUNING_PARAMS followed by uint32le(rx_delay_base * 1000) and
        # uint32le(airtime_factor * 1000). The C floats truncate toward zero on
        # the cast to uint32, so use int() (truncation), not round().
        rx_delay_base, airtime_factor = self.bridge.get_tuning_params()
        self._write_frame(
            bytes([RESP_CODE_TUNING_PARAMS])
            + struct.pack("<II", int(rx_delay_base * 1000), int(airtime_factor * 1000))
        )

    async def _cmd_get_custom_vars(self, data: bytes) -> None:
        # Mirrors MyMesh.cpp's CMD_GET_CUSTOM_VARS handler (examples/companion_radio/
        # MyMesh.cpp lines ~1784-1797): it writes directly into the byte buffer and
        # checks the *already-written* byte length against the 140 budget before
        # appending each entry, so an entry that starts under budget is written in
        # full even if it pushes the total past 140 (overshoot-by-one-entry).
        custom_vars = self.bridge.get_custom_vars()
        out = bytearray()
        for i, (name, value) in enumerate(custom_vars.items()):
            if len(out) >= 140:
                break
            entry = f"{name}:{value}"
            if i > 0:
                out += b","
            out += entry.encode("utf-8", errors="replace")
        self._write_frame(bytes([RESP_CODE_CUSTOM_VARS]) + bytes(out))

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
        # Firmware CMD_SET_AUTOADD_CONFIG: config byte plus an optional max-hop
        # byte (capped at 64 by the setter).
        max_hops = data[1] if len(data) >= 2 else None
        self.bridge.set_autoadd_config(data[0], max_hops)
        self._write_ok()

    async def _cmd_get_autoadd_config(self, data: bytes) -> None:
        config = self.bridge.get_autoadd_config()
        max_hops = self.bridge.get_autoadd_max_hops()
        self._write_frame(bytes([RESP_CODE_AUTOADD_CONFIG, config & 0xFF, max_hops & 0xFF]))

    async def _cmd_set_other_params(self, data: bytes) -> None:
        """Handle CMD_SET_OTHER_PARAMS (0x26). Mirrors MyMesh.cpp:1290-1305."""
        if len(data) < 1:
            self._write_err(ERR_CODE_ILLEGAL_ARG)
            return
        # Firmware CMD_SET_OTHER_PARAMS is backward-compatible: manual_add is
        # always set, but the telemetry byte, advert-location policy, and
        # multi-acks are only updated when their bytes are present. A short frame
        # from an older client must leave the newer fields untouched, so read the
        # current preferences and only override each optional field when supplied.
        prefs = self.bridge.get_self_info()
        manual_add = data[0]
        if len(data) >= 2:
            telemetry_modes = data[1]
        else:
            telemetry_modes = (
                (getattr(prefs, "telemetry_mode_base", 0) & 0x03)
                | ((getattr(prefs, "telemetry_mode_location", 0) & 0x03) << 2)
                | ((getattr(prefs, "telemetry_mode_environment", 0) & 0x03) << 4)
            )
        advert_loc_policy = data[2] if len(data) >= 3 else getattr(prefs, "advert_loc_policy", 0)
        multi_acks = data[3] if len(data) >= 4 else getattr(prefs, "multi_acks", 0)
        self.bridge.set_other_params(manual_add, telemetry_modes, advert_loc_policy, multi_acks)
        self._write_ok()

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

        Firmware (MyMesh.cpp:1973) replies with RESP_ALLOWED_REPEAT_FREQ followed
        by zero or more (lower_freq, upper_freq) little-endian u32 pairs (in kHz).
        """
        getter = getattr(self.bridge, "get_allowed_repeat_freqs", None)
        ranges = getter() if callable(getter) else ()
        frame = bytearray([RESP_CODE_ALLOWED_REPEAT_FREQ])
        for lower, upper in ranges:
            frame += struct.pack("<II", lower, upper)
        self._write_frame(bytes(frame))
