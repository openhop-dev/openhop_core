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
from typing import Any, Callable, Optional

from ..constants import (
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
    CMD_GET_TUNING_PARAMS,
    CMD_HAS_CONNECTION,
    CMD_IMPORT_CONTACT,
    CMD_IMPORT_PRIVATE_KEY,
    CMD_LOGOUT,
    CMD_REBOOT,
    CMD_REMOVE_CONTACT,
    CMD_RESET_PATH,
    CMD_RUN_CLI_COMMAND,
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
    CMD_SET_DEVICE_PIN,
    CMD_SET_DEVICE_TIME,
    CMD_SET_FLOOD_SCOPE,
    CMD_SET_OTHER_PARAMS,
    CMD_SET_PATH_HASH_MODE,
    CMD_SET_RADIO_PARAMS,
    CMD_SET_RADIO_TX_POWER,
    CMD_SET_TUNING_PARAMS,
    CMD_SHARE_CONTACT,
    CMD_SIGN_DATA,
    CMD_SIGN_FINISH,
    CMD_SIGN_START,
    CMD_SYNC_NEXT_MESSAGE,
    ERR_CODE_ILLEGAL_ARG,
    ERR_CODE_UNSUPPORTED_CMD,
    FIRMWARE_VER_CODE,
)
from ..models import QueuedMessage
from .commands_channels import _ChannelCommandsMixin
from .commands_contacts import _ContactCommandsMixin
from .commands_device import _DeviceCommandsMixin
from .commands_messaging import _MessagingCommandsMixin
from .push import _PushMixin
from .transport import _FrameTransportMixin

logger = logging.getLogger("CompanionFrameServer")


class CompanionFrameServer(
    _FrameTransportMixin,
    _PushMixin,
    _ContactCommandsMixin,
    _ChannelCommandsMixin,
    _MessagingCommandsMixin,
    _DeviceCommandsMixin,
):
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
        # Track discovery tags for no-op callbacks created by this frame server,
        # so we only clear callbacks we own and never remove repeater-level
        # discovery callbacks that are still collecting responses.
        self._companion_discovery_tags: set[int] = set()
        # Track anon/binary request tags originated by this frame server so only
        # this virtual companion consumes the matching PUSH_CODE_BINARY_RESPONSE.
        self._companion_binary_tags: set[int] = set()
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
            CMD_SIGN_START: self._cmd_sign_start,
            CMD_SIGN_DATA: self._cmd_sign_data,
            CMD_SIGN_FINISH: self._cmd_sign_finish,
            CMD_SET_TUNING_PARAMS: self._cmd_set_tuning_params,
            CMD_GET_TUNING_PARAMS: self._cmd_get_tuning_params,
            CMD_HAS_CONNECTION: self._cmd_has_connection,
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
            CMD_SET_DEVICE_PIN: self._cmd_set_device_pin,
            CMD_RUN_CLI_COMMAND: self._cmd_run_cli_command,
            CMD_REBOOT: self._cmd_reboot,
        }

        # `board` on the companion's CLI answers what DEVICE_INFO says.
        cli = getattr(bridge, "cli", None)
        if callable(getattr(cli, "set_device_info", None)):
            cli.set_device_info(
                self._model_bytes.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
            )

    # -------------------------------------------------------------------------
    # Persistence hooks (override in subclasses for SQLite, etc.)
    # -------------------------------------------------------------------------

    async def _persist_companion_message(self, msg_dict: dict, queue_entry=None) -> None:
        """Hook: persist a received message.  Default is a no-op — the message
        stays in the bridge's in-memory queue for ``sync_next_message``.

        ``queue_entry`` is the exact in-memory queue entry this message came from,
        so an overriding persistence layer can remove it by identity."""

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

    def _get_self_telemetry_lpp(self) -> bytes:
        """Hook: return local sensor telemetry as CayenneLPP bytes.

        Mirrors the firmware self-telemetry `sensors.querySensors(0xFF, ...)`
        (MyMesh.cpp:1646) with permission mask 0xFF. Concrete deployments with
        a modem should override to return `KissModemWrapper.get_sensors(0xFF)`.
        Default is no sensor data; the battery-voltage floor is still emitted.
        """
        return b""

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
        logger.debug("Companion cmd 0x%02x (%s) len=%s", cmd, cmd, len(payload))
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
