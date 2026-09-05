"""
CompanionBridge - Repeater-integrated companion mode.

Provides the same API as CompanionRadio but uses a shared dispatcher via
packet_injector. No radio ownership; host (repeater) injects packets via
process_received_packet and TX goes through packet_injector.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Mapping
from typing import Any, Callable, Iterable, Optional

from ..node.handlers import create_core_handlers
from ..node.handlers.crypto_helpers import iter_decrypt_by_src_hash
from ..node.handlers.login_server import LoginServerHandler
from ..node.handlers.result import HandlerResult
from ..protocol import Identity, LocalIdentity, Packet
from ..protocol.constants import (
    PAYLOAD_TYPE_ACK,
    PAYLOAD_TYPE_ADVERT,
    PAYLOAD_TYPE_ANON_REQ,
    PAYLOAD_TYPE_GRP_DATA,
    PAYLOAD_TYPE_GRP_TXT,
    PAYLOAD_TYPE_PATH,
    PAYLOAD_TYPE_RAW_CUSTOM,
    PAYLOAD_TYPE_RESPONSE,
    PAYLOAD_TYPE_TXT_MSG,
    ROUTE_TYPE_FLOOD,
    ROUTE_TYPE_TRANSPORT_FLOOD,
)
from ..protocol.packet_utils import PathUtils
from ..protocol.region_map import RegionMap, capture_recv_region
from .companion_base import CompanionBase
from .constants import (
    ADV_TYPE_CHAT,
    DEFAULT_MAX_CHANNELS,
    DEFAULT_MAX_CONTACTS,
    DEFAULT_OFFLINE_QUEUE_SIZE,
)
from .radio_capabilities import resolve_max_tx_power_dbm

logger = logging.getLogger("CompanionBridge")


# ---------------------------------------------------------------------------
# Bridge ACK handler: fires send_confirmed when ACK CRC matches a pending send
# ---------------------------------------------------------------------------


class _BridgeAckHandler:
    """Handles ACK packets (discrete and PATH-carried).
    Fires send_confirmed when ACK CRC matches."""

    def __init__(self, bridge: "CompanionBridge") -> None:
        self._bridge = bridge

    @staticmethod
    def payload_type() -> int:
        return PAYLOAD_TYPE_ACK

    async def __call__(self, packet: Packet) -> None:
        # Firmware emits 6-byte ACKs for plain DMs (4-byte hash + ext-attempt +
        # random byte); accept >= 4 and correlate on the first 4 bytes only,
        # matching the shared AckHandler.
        if not packet.payload or len(packet.payload) < 4:
            return
        crc = int.from_bytes(packet.payload[:4], "little")
        await self._apply_ack(crc)

    async def _apply_ack(self, crc: int) -> None:
        """If CRC is pending, clear it and fire send_confirmed."""
        await self._bridge._try_confirm_send(crc)

    async def process_path_ack_variants(self, packet: Packet) -> Optional[int]:
        """Decrypt PATH payload and return ACK CRC if present.

        Path update and contact_path_updated are handled by ProtocolResponseHandler;
        this only extracts ACK for send_confirmed.
        """
        payload = packet.payload
        if not payload or len(payload) < 2 + 6:
            return None
        dest_hash = payload[0]
        src_hash = payload[1]
        our_hash = self._bridge._identity.get_public_key()[0]
        if dest_hash != our_hash:
            return None
        encrypted = bytes(payload[2:])
        # Try each contact with matching src_hash until decryption succeeds
        decrypt_attempts = iter_decrypt_by_src_hash(
            self._bridge.contacts.contacts,
            src_hash,
            self._bridge._identity,
            encrypted,
        )
        decrypted_any = False
        for _contact, _pub, _secret, decrypted in decrypt_attempts:
            decrypted_any = True
            if len(decrypted) < 2:
                logger.debug(
                    "process_path_ack_variants: decrypted too short (%d) for src=0x%02x",
                    len(decrypted),
                    src_hash,
                )
                continue
            path_len_byte = decrypted[0]
            if not PathUtils.is_valid_path_len(path_len_byte):
                logger.debug(
                    "process_path_ack_variants: invalid path_len byte 0x%02x for src=0x%02x",
                    path_len_byte,
                    src_hash,
                )
                continue
            path_byte_len = PathUtils.get_path_byte_len(path_len_byte)
            if 1 + path_byte_len > len(decrypted):
                logger.debug(
                    "process_path_ack_variants: path_byte_len=%d exceeds decrypted len=%d "
                    "for src=0x%02x",
                    path_byte_len,
                    len(decrypted),
                    src_hash,
                )
                continue
            # Path update and contact_path_updated are handled by ProtocolResponseHandler
            # If this PATH carries an ACK, return it so send_confirmed can fire
            extra_start = 1 + path_byte_len
            if len(decrypted) >= extra_start + 1 + 4 and decrypted[extra_start] == PAYLOAD_TYPE_ACK:
                return int.from_bytes(decrypted[extra_start + 1 : extra_start + 5], "little")
            return None
        logger.debug(
            "process_path_ack_variants: no contact yielded a usable PATH payload "
            "for src=0x%02x (decrypted_any=%s)",
            src_hash,
            decrypted_any,
        )
        return None

    async def _notify_ack_received(self, crc: int) -> None:
        """Called by path handler when PATH packet contained an ACK."""
        await self._apply_ack(crc)


# ---------------------------------------------------------------------------
# Raw custom payload handler: fires raw_data_received (PUSH 0x84)
# ---------------------------------------------------------------------------


class _RawCustomHandler:
    """Handles PAYLOAD_TYPE_RAW_CUSTOM packets; fires raw_data_received(payload, snr, rssi)."""

    def __init__(self, bridge: "CompanionBridge") -> None:
        self._bridge = bridge

    @staticmethod
    def payload_type() -> int:
        return PAYLOAD_TYPE_RAW_CUSTOM

    async def __call__(self, packet: Packet) -> None:
        payload_bytes = bytes(packet.payload) if packet.payload else b""
        snr = packet.get_snr() if hasattr(packet, "get_snr") else getattr(packet, "_snr", 0)
        rssi = packet.rssi if hasattr(packet, "rssi") else getattr(packet, "_rssi", 0)
        await self._bridge._fire_callbacks("raw_data_received", payload_bytes, snr, rssi)


# ---------------------------------------------------------------------------
# Main CompanionBridge class
# ---------------------------------------------------------------------------


class CompanionBridge(CompanionBase):
    """Repeater-integrated companion: shared dispatcher, packet_injector for TX.

    No MeshNode, no radio. Host calls process_received_packet when packets
    destined for this companion arrive. All TX goes through packet_injector.
    """

    def __init__(
        self,
        identity: LocalIdentity,
        packet_injector: Callable[..., Any],
        node_name: str = "pyMC",
        adv_type: int = ADV_TYPE_CHAT,
        max_contacts: int = DEFAULT_MAX_CONTACTS,
        max_channels: int = DEFAULT_MAX_CHANNELS,
        offline_queue_size: int = DEFAULT_OFFLINE_QUEUE_SIZE,
        radio_config: Optional[dict] = None,
        authenticate_callback: Optional[Callable[..., tuple[bool, int]]] = None,
        initial_contacts: Optional[Iterable[Any]] = None,
        radio_settings_getter: Optional[Callable[[], Mapping[str, Any]]] = None,
        max_tx_power_getter: Optional[Callable[[], Optional[int]]] = None,
    ) -> None:
        """Initialise the companion bridge."""
        self._radio_settings_getter = radio_settings_getter
        self._max_tx_power_getter = max_tx_power_getter
        self._init_companion_stores(
            identity=identity,
            node_name=node_name,
            adv_type=adv_type,
            max_contacts=max_contacts,
            max_channels=max_channels,
            offline_queue_size=offline_queue_size,
            radio_config=radio_config,
            initial_contacts=initial_contacts,
        )
        self._packet_injector = packet_injector

        # Region registry for reply-region capture. None by default so a
        # standalone bridge captures nothing (replies fall through to the
        # ordinary send precedence). A host repeater points this at its
        # dispatcher's region_map so incoming request regions are captured and
        # mirrored onto replies.
        self.region_map: Optional[RegionMap] = None

        async def _handler_send_packet(pkt: Packet, wait_for_ack: bool = False) -> bool:
            return await self._packet_injector(pkt, wait_for_ack=wait_for_ack)

        def _login_send_callback(pkt: Packet, delay_ms: int) -> None:
            async def _delayed_send() -> None:
                await asyncio.sleep(delay_ms / 1000.0)
                await self._packet_injector(pkt, wait_for_ack=False)

            self._spawn_background_task(_delayed_send(), "login delayed send")

        def _log(msg: str) -> None:
            logger.debug("[CompanionBridge] %s", msg)

        ack_handler = _BridgeAckHandler(self)

        # Use shared factory for the core protocol handlers
        core = create_core_handlers(
            identity=identity,
            contacts=self.contacts,
            channels=self.channels,
            event_service=self._event_service,
            send_packet_fn=_handler_send_packet,
            log_fn=_log,
            node_name=node_name,
            radio_config=self._radio_config,
            ack_handler=ack_handler,
            group_packet_seen_callback=self._check_and_track_group_packet,
        )

        # Bridge-specific: LoginServerHandler for incoming login requests
        auth_cb = authenticate_callback
        if auth_cb is None:

            def _reject_all(*args, **kwargs) -> tuple[bool, int]:
                return (False, 0)

            auth_cb = _reject_all

        def _get_login_out_path(client_identity: Identity) -> Optional[tuple[bytes, int]]:
            contact = self.contacts.get_by_key(client_identity.get_public_key())
            if contact is None or contact.out_path_len < 0:
                return None
            return (bytes(contact.out_path or b""), contact.out_path_len)

        def _clear_login_out_path(client_identity: Identity) -> None:
            self.reset_path(client_identity.get_public_key())

        login_server_handler = LoginServerHandler(
            identity,
            _log,
            authenticate_callback=auth_cb,
            is_room_server=False,
            get_out_path=_get_login_out_path,
            clear_out_path=_clear_login_out_path,
        )
        login_server_handler.set_send_packet_callback(_login_send_callback)

        self._handlers: dict[int, Any] = {
            PAYLOAD_TYPE_ACK: ack_handler,
            PAYLOAD_TYPE_TXT_MSG: core.text_handler,
            PAYLOAD_TYPE_ADVERT: core.advert_handler,
            PAYLOAD_TYPE_PATH: core.path_handler,
            PAYLOAD_TYPE_ANON_REQ: login_server_handler,
            PAYLOAD_TYPE_GRP_TXT: core.group_text_handler,
            PAYLOAD_TYPE_RESPONSE: core.login_response_handler,
            PAYLOAD_TYPE_RAW_CUSTOM: _RawCustomHandler(self),
        }

        self._protocol_response_handler = core.protocol_response_handler
        self._login_response_handler = core.login_response_handler
        self._text_handler_ref = core.text_handler
        # A pending login must not let the login handler claim an unrelated
        # status/telemetry/neighbours reply from the same contact.
        core.login_response_handler.set_foreign_request_probe(self.has_pending_request_tag)
        core.protocol_response_handler.set_binary_response_callback(self._on_binary_response)
        core.protocol_response_handler.set_packet_injector(self._packet_injector)
        core.protocol_response_handler.set_contact_path_updated_callback(
            self._on_contact_path_updated
        )

    # -------------------------------------------------------------------------
    # Pre-dedup flood-copy feed (host-wired)
    # -------------------------------------------------------------------------

    def note_flood_copy(self, pkt: Packet, data: Any = None, analysis: Any = None) -> None:
        """Feed one pre-dedup copy of a flood reply to the return-path teacher.

        The host must wire this into its dispatcher's raw subscribers::

            dispatcher.add_raw_packet_subscriber(bridge.note_flood_copy)

        A bridge does not own a dispatcher, and the host delivers only the
        *first* copy of a flood reply to :meth:`process_received_packet` — later
        copies are dropped by the host's own seen-table before they get here. So
        without this hook the teacher only ever sees the first-arrived route,
        which on a live mesh is routinely the worst one: observed here, four
        copies of one login reply landed over ~1.8 s and the teach went out
        0.4 s in, embedding the marginal first route. See
        :meth:`ReturnPathTeacher.note_flood_copy` for the selection itself.

        Best-effort and never raises: this runs on the host's hot RX path.
        """
        teacher = getattr(self._protocol_response_handler, "return_path_teacher", None)
        if teacher is None:
            return
        teacher.note_flood_copy(pkt, data, analysis)

    # -------------------------------------------------------------------------
    # Handler accessors (used by CompanionBase concrete send methods)
    # -------------------------------------------------------------------------

    def _get_protocol_response_handler(self) -> Any:
        return self._protocol_response_handler

    def _get_login_response_handler(self) -> Any:
        return self._login_response_handler

    def _get_text_handler(self) -> Any:
        return self._text_handler_ref

    def set_other_params(
        self,
        manual_add: int,
        telemetry_modes: int,
        advert_loc_policy: int,
        multi_acks: int,
    ) -> None:
        """Set other params and sync the multi_acks pref to the text handler."""
        super().set_other_params(manual_add, telemetry_modes, advert_loc_policy, multi_acks)
        self._apply_multi_acks_pref()

    # -------------------------------------------------------------------------
    # Repeater-owned radio state
    # -------------------------------------------------------------------------

    def _get_host_radio_settings(self) -> Mapping[str, Any]:
        """Return the host's current radio settings without granting mutation."""
        if self._radio_settings_getter is None:
            return self._radio_config
        try:
            settings = self._radio_settings_getter()
        except Exception as e:
            logger.warning("Could not read host radio settings: %s", e)
            return self._radio_config
        if not isinstance(settings, Mapping):
            logger.warning(
                "Host radio settings getter returned %s, not a mapping", type(settings).__name__
            )
            return self._radio_config
        return settings

    @staticmethod
    def _set_pref_from_host(prefs: Any, field: str, value: Any) -> None:
        """Set one integer radio preference when the host returned a valid value."""
        try:
            setattr(prefs, field, int(value))
        except (TypeError, ValueError):
            logger.warning("Ignoring invalid host radio value for %s: %r", field, value)

    def get_self_info(self):
        """Return identity prefs with radio fields sourced from the host.

        A bridge does not own RF state. Its persisted identity preferences
        therefore cannot override the repeater's current radio settings.
        """
        prefs = super().get_self_info()
        settings = self._get_host_radio_settings()
        for field, keys in (
            ("frequency_hz", ("frequency",)),
            ("bandwidth_hz", ("bandwidth",)),
            ("spreading_factor", ("spreading_factor",)),
            ("coding_rate", ("coding_rate",)),
            ("tx_power_dbm", ("power", "tx_power")),
        ):
            for key in keys:
                if key in settings:
                    self._set_pref_from_host(prefs, field, settings[key])
                    break
        return prefs

    def get_radio_params(self) -> dict:
        """Return the host's current radio configuration, not bridge prefs."""
        prefs = self.get_self_info()
        return {
            "frequency_hz": prefs.frequency_hz,
            "bandwidth_hz": prefs.bandwidth_hz,
            "spreading_factor": prefs.spreading_factor,
            "coding_rate": prefs.coding_rate,
            "tx_power_dbm": prefs.tx_power_dbm,
            "rx_delay_base": prefs.rx_delay_base,
            "airtime_factor": prefs.airtime_factor,
        }

    def get_max_tx_power_dbm(self) -> int:
        """Return the host-provided TX capability for companion SELF_INFO."""
        if self._max_tx_power_getter is not None:
            try:
                value = self._max_tx_power_getter()
            except Exception as e:
                logger.warning("Could not get host maximum TX power: %s", e)
            else:
                if value is not None:
                    try:
                        return int(value)
                    except (TypeError, ValueError):
                        logger.warning("Host returned invalid maximum TX power: %r", value)
                        return super().get_max_tx_power_dbm()
        value = resolve_max_tx_power_dbm(None, self._get_host_radio_settings())
        if value is not None:
            return value
        return super().get_max_tx_power_dbm()

    def supports_radio_params_mutation(self) -> bool:
        """A virtual companion must not reconfigure the shared repeater radio."""
        return False

    def supports_tx_power_mutation(self) -> bool:
        """A virtual companion must not change shared repeater TX power."""
        return False

    def supports_client_repeat(self) -> bool:
        """A virtual companion must not enable client-repeat on the shared host."""
        return False

    def set_radio_params(self, freq_hz: int, bw_hz: int, sf: int, cr: int) -> bool:
        """Reject shared-radio changes without mutating companion preferences."""
        return False

    def set_tx_power(self, power_dbm: int) -> bool:
        """Reject shared-radio TX-power changes without mutating preferences."""
        return False

    def _get_advert_handler(self):
        """Return the normal ADVERT handler used for contact-import loopback."""
        return self._handlers.get(PAYLOAD_TYPE_ADVERT)

    # -------------------------------------------------------------------------
    # RX Entry Point
    # -------------------------------------------------------------------------

    async def process_received_packet(self, packet: Packet) -> HandlerResult:
        """Process a packet destined for this companion.

        Returns an authenticated HandlerResult only when a handler authenticated
        (MAC-verified/decrypted) the packet for this companion identity and
        consumed it. Returns a not-for-us result when no handler claimed it —
        e.g. a one-byte dest-hash collision where the packet actually belongs to
        another node — so the caller may still forward it instead of swallowing it.

        Handlers that successfully MAC-verify packets for this identity return an
        authenticated HandlerResult, including PATH and RESPONSE handlers.
        Broadcast-style handlers (advert, ack, group) remain non-authoritative
        for the caller's forwarding decision.
        """
        ptype = packet.get_payload_type()
        route_type = packet.get_route_type()
        is_flood = route_type in (ROUTE_TYPE_FLOOD, ROUTE_TYPE_TRANSPORT_FLOOD)
        self.stats.record_rx(is_flood=is_flood)

        # Capture the region this request arrived under before the handler
        # builds any reply, so a flood reply is scoped to that region (or plain).
        # No-op when no RegionMap is configured (standalone bridge).
        capture_recv_region(self.region_map, packet)

        handler = self._handlers.get(ptype)
        if handler:
            try:
                result = await handler(packet)
                return result if isinstance(result, HandlerResult) else HandlerResult.not_for_us()
            except Exception as e:
                logger.error("Handler error for type %02X: %s", ptype, e)
                return HandlerResult.not_for_us()
        elif ptype == PAYLOAD_TYPE_GRP_DATA:
            try:
                await self._handle_group_data_packet(packet)
            except Exception as e:
                logger.error("Group data handler error: %s", e)

        # NOTE: PATH packets are already delivered to protocol_response_handler
        # via PathHandler.__call__ (path.py), which runs as the handler above.
        # No duplicate call here — it would cause double decryption and could
        # deliver the result to response waiters twice.
        return HandlerResult.not_for_us()

    # -------------------------------------------------------------------------
    # Abstract method implementations
    # -------------------------------------------------------------------------

    async def _send_packet(
        self,
        pkt: Packet,
        wait_for_ack: bool = False,
        expected_crc: Optional[int] = None,
    ) -> bool:
        """Send a packet via the packet_injector."""
        if expected_crc is None:
            return await self._packet_injector(pkt, wait_for_ack=wait_for_ack)
        return await self._packet_injector(
            pkt, wait_for_ack=wait_for_ack, expected_crc=expected_crc
        )

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

    async def start(self) -> None:
        self._running = True
        self._apply_multi_acks_pref()
        logger.info(
            "CompanionBridge started: name=%s, key=%s...",
            self.prefs.node_name,
            self._identity.get_public_key().hex()[:16],
        )

    async def stop(self) -> None:
        self._running = False
        self._clear_pending_frame_logins()
        protocol_handler = self._get_protocol_response_handler()
        if protocol_handler is not None:
            protocol_handler.cancel_pending_reciprocals()
            await protocol_handler.wait_for_pending_reciprocals()
        logger.info("CompanionBridge stopped")

    @property
    def is_running(self) -> bool:
        return self._running

    # -------------------------------------------------------------------------
    # Key Management
    # -------------------------------------------------------------------------

    def import_private_key(self, key: bytes) -> bool:
        try:
            self._identity = LocalIdentity(seed=key)
            logger.info("Imported new identity: %s...", self._identity.get_public_key().hex()[:16])
            return True
        except Exception as e:
            logger.error("Error importing private key: %s", e)
            return False
