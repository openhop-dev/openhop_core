"""
MeshCore Companion Radio - Python-native implementation.

Provides the same feature set as the MeshCore companion radio firmware
(meshcore-dev/MeshCore/examples/companion_radio), implemented as a
high-level wrapper around MeshNode with in-memory contact, channel,
message queue, path cache, and statistics management.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Iterable, Optional

from ..node.node import MeshNode
from ..protocol import LocalIdentity, Packet
from ..protocol.constants import (
    PAYLOAD_TYPE_ADVERT,
    PAYLOAD_TYPE_GRP_DATA,
    ROUTE_TYPE_FLOOD,
    ROUTE_TYPE_TRANSPORT_FLOOD,
)
from ..protocol.packet_utils import PathUtils
from .companion_base import CompanionBase
from .constants import (
    ADV_TYPE_CHAT,
    DEFAULT_MAX_CHANNELS,
    DEFAULT_MAX_CONTACTS,
    DEFAULT_OFFLINE_QUEUE_SIZE,
)
from .radio_capabilities import resolve_max_tx_power_dbm

logger = logging.getLogger("CompanionRadio")


class CompanionRadio(CompanionBase):
    """Python-native MeshCore companion radio.

    Wraps MeshNode and augments it with application-layer state and services
    that the C++ companion radio firmware provides: contact management,
    messaging with offline queue, advertisement broadcasting, channel
    management, path tracking, signing, telemetry, statistics, and device
    configuration.

    Example:
        ```python
        from openhop_core import CompanionRadio, LocalIdentity
        from openhop_core.hardware import KissModemWrapper

        radio = KissModemWrapper("/dev/ttyUSB0")
        radio.connect()
        identity = LocalIdentity()
        companion = CompanionRadio(radio, identity, node_name="myNode")

        async def main():
            await companion.start()
            print(f"Key: {companion.get_public_key().hex()}")
            await companion.advertise()
            await companion.stop()

        asyncio.run(main())
        ```
    """

    def __init__(
        self,
        radio: Any,
        identity: LocalIdentity,
        node_name: str = "pyMC",
        adv_type: int = ADV_TYPE_CHAT,
        max_contacts: int = DEFAULT_MAX_CONTACTS,
        max_channels: int = DEFAULT_MAX_CHANNELS,
        offline_queue_size: int = DEFAULT_OFFLINE_QUEUE_SIZE,
        radio_config: Optional[dict] = None,
        initial_contacts: Optional[Iterable[Any]] = None,
    ) -> None:
        """Initialise the companion radio."""
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
        self._radio = radio
        self._dispatcher_task: Optional[asyncio.Task] = None

        self.node = MeshNode(
            radio=radio,
            local_identity=identity,
            config={
                "node": {"name": node_name},
                "radio": self._radio_config,
            },
            contacts=self.contacts,
            channel_db=self.channels,
            event_service=self._event_service,
        )
        self.node.dispatcher.group_text_handler.set_packet_seen_callback(
            self._check_and_track_group_packet
        )
        self._setup_packet_callbacks()

    # -------------------------------------------------------------------------
    # Abstract method implementations
    # -------------------------------------------------------------------------

    async def _send_packet(
        self,
        pkt: Packet,
        wait_for_ack: bool = False,
        expected_crc: Optional[int] = None,
    ) -> bool:
        """Send a packet via the MeshNode dispatcher."""
        return await self.node.dispatcher.send_packet(
            pkt, wait_for_ack=wait_for_ack, expected_crc=expected_crc
        )

    # -------------------------------------------------------------------------
    # Handler accessors (used by CompanionBase concrete send methods)
    # -------------------------------------------------------------------------

    def _get_protocol_response_handler(self) -> Any:
        return self.node.dispatcher.protocol_response_handler

    def _get_login_response_handler(self) -> Any:
        return self.node.dispatcher.login_response_handler

    def _get_text_handler(self) -> Any:
        return self.node.dispatcher.text_message_handler

    def _get_advert_handler(self) -> Any:
        return self.node.dispatcher._handler_instances.get(PAYLOAD_TYPE_ADVERT)

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

    async def start(self) -> None:
        if self._running:
            logger.warning("CompanionRadio already running")
            return
        self._running = True
        self.node.dispatcher.set_default_path_hash_mode(self.prefs.path_hash_mode)
        self.node.dispatcher.rx_delay_base = self.prefs.rx_delay_base
        # Seed the flood-scope mirrors from persisted prefs at boot: the
        # default, the transient override and the sticky unscoped flag. Without
        # this, a companion booted with only a persisted default would send every
        # dispatcher-scoped packet as plain flood until the first set_* call.
        self.node.dispatcher.default_flood_transport_key = self._default_scope_key()
        self.node.dispatcher.flood_transport_key = self._flood_transport_key
        self.node.dispatcher.flood_unscoped = self._flood_unscoped
        # Sync the airtime budget factor before arming the bucket so the initial
        # duty cycle is correct when client-repeat starts enabled.
        self.node.dispatcher.airtime_budget_factor = self.prefs.airtime_factor
        self.node.dispatcher.set_client_repeat_enabled(bool(self.prefs.client_repeat))
        self._apply_multi_acks_pref()
        self._dispatcher_task = asyncio.create_task(self.node.start())
        # Wait until the dispatcher loop is active so a following stop() cannot
        # lose a race where run_forever clears the stop event before starting.
        while not self.node.dispatcher._run_forever_active:
            if self._dispatcher_task.done():
                # The dispatcher died before its loop became active (e.g. a
                # radio failure). Surface that instead of reporting a started
                # radio that will never receive or transmit.
                task = self._dispatcher_task
                self._dispatcher_task = None
                self._running = False
                try:
                    exc = task.exception()
                except asyncio.CancelledError:
                    raise RuntimeError("Dispatcher task was cancelled during startup") from None
                if exc is not None:
                    logger.error("CompanionRadio start failed: %s", exc)
                    raise exc
                break
            await asyncio.sleep(0)
        logger.info(
            "CompanionRadio started: name=%s, key=%s...",
            self.prefs.node_name,
            self._identity.get_public_key().hex()[:16],
        )

    async def stop(self) -> None:
        self._running = False
        self._clear_pending_frame_logins()
        try:
            self.node.dispatcher.remove_raw_packet_subscriber(self._on_raw_packet_rx_log)
            protocol_handler = self.node.dispatcher.protocol_response_handler
            teacher = getattr(protocol_handler, "return_path_teacher", None)
            if teacher is not None:
                self.node.dispatcher.remove_raw_packet_subscriber(teacher.note_flood_copy)
            if protocol_handler is not None:
                protocol_handler.cancel_pending_reciprocals()
                await protocol_handler.wait_for_pending_reciprocals()
        except Exception:
            logger.debug("Remove raw packet subscriber during stop failed", exc_info=True)
        await self.node.stop()
        if self._dispatcher_task:
            try:
                await self._dispatcher_task
            except asyncio.CancelledError:
                pass
            self._dispatcher_task = None
        logger.info("CompanionRadio stopped")

    @property
    def is_running(self) -> bool:
        return self._running

    # -------------------------------------------------------------------------
    # Flood Scope (sync to dispatcher)
    # -------------------------------------------------------------------------

    def set_flood_scope(self, transport_key: Optional[bytes] = None) -> None:
        """Set or clear the transient flood scope and propagate to the dispatcher.

        Clears the dispatcher's explicit-unscoped mirror too (base
        ``set_flood_scope`` clears ``_flood_unscoped``), re-enabling the
        override/default scope path.
        """
        super().set_flood_scope(transport_key)
        self.node.dispatcher.flood_transport_key = self._flood_transport_key
        self.node.dispatcher.flood_unscoped = False

    def set_flood_region(self, region_name: Optional[str] = None) -> None:
        """Set flood region and propagate to the dispatcher (clears unscoped)."""
        super().set_flood_region(region_name)
        self.node.dispatcher.flood_transport_key = self._flood_transport_key
        self.node.dispatcher.flood_unscoped = False

    def set_flood_unscoped(self) -> None:
        """Force unscoped floods and mirror the sticky flag to the dispatcher.

        Firmware's send_unscoped flag suppresses scoping on every flood send,
        so the dispatcher must stop applying both the transient override and the
        persisted default. The override mirror is cleared and the flag set; the
        default mirror is deliberately NOT nulled (the flag suppresses it, and a
        later set_flood_scope()/set_flood_region() clears the flag to re-enable
        the default path).
        """
        super().set_flood_unscoped()
        self.node.dispatcher.flood_transport_key = None
        self.node.dispatcher.flood_unscoped = True

    def set_default_flood_scope(
        self,
        scope_name: Optional[str],
        transport_key: Optional[bytes],
    ) -> bool:
        """Persist the default flood scope and mirror it to the dispatcher.

        The mirror is the resolved key (``_default_scope_key`` maps an all-zero
        or short key to None => plain flood), so sends that rely on the
        dispatcher to scope at TX time carry the default too.
        """
        result = super().set_default_flood_scope(scope_name, transport_key)
        self.node.dispatcher.default_flood_transport_key = self._default_scope_key()
        return result

    def set_path_hash_mode(self, mode: int) -> None:
        """Set path hash mode and sync to dispatcher default."""
        super().set_path_hash_mode(mode)
        self.node.dispatcher.set_default_path_hash_mode(self.prefs.path_hash_mode)

    def set_tuning_params(self, rx_delay: float, airtime_factor: float) -> None:
        """Set tuning params and sync the RX delay base to the dispatcher."""
        super().set_tuning_params(rx_delay, airtime_factor)
        self.node.dispatcher.rx_delay_base = self.prefs.rx_delay_base
        # Keep the live airtime duty-cycle factor in sync (firmware reads
        # getAirtimeBudgetFactor = prefs.airtime_factor on every budget update).
        self.node.dispatcher.airtime_budget_factor = self.prefs.airtime_factor

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
    # Device Configuration (overrides for radio hardware)
    # -------------------------------------------------------------------------

    def set_advert_name(self, name: str) -> None:
        super().set_advert_name(name)
        self.node.node_name = self.prefs.node_name

    def supports_radio_params_mutation(self) -> bool:
        """Whether the owned backend can reconfigure radio parameters."""
        return callable(getattr(self._radio, "configure_radio", None))

    def supports_tx_power_mutation(self) -> bool:
        """Whether the owned backend can set its TX power."""
        return callable(getattr(self._radio, "set_tx_power", None))

    def supports_client_repeat(self) -> bool:
        """A radio-owning companion can act as a client repeater."""
        return True

    def set_client_repeat(self, value: int) -> None:
        """Persist the client-repeat preference and toggle forwarding live."""
        super().set_client_repeat(value)
        self.node.dispatcher.set_client_repeat_enabled(bool(self.prefs.client_repeat))

    def get_max_tx_power_dbm(self) -> int:
        """Return a backend-declared TX limit when one is available."""
        value = resolve_max_tx_power_dbm(self._radio)
        if value is not None:
            return value
        return super().get_max_tx_power_dbm()

    def set_radio_params(self, freq_hz: int, bw_hz: int, sf: int, cr: int) -> bool:
        """Apply parameters to owned hardware before persisting the change."""
        if not (5 <= sf <= 12):
            raise ValueError(f"Spreading factor out of range: {sf}")
        if not (5 <= cr <= 8):
            raise ValueError(f"Coding rate out of range: {cr}")
        configure = getattr(self._radio, "configure_radio", None)
        if not callable(configure):
            return False
        try:
            applied = configure(
                frequency=freq_hz,
                bandwidth=bw_hz,
                spreading_factor=sf,
                coding_rate=cr,
            )
        except Exception as e:
            logger.error("Error configuring radio: %s", e)
            return False
        if applied is False:
            return False
        return super().set_radio_params(freq_hz, bw_hz, sf, cr)

    def set_tx_power(self, power_dbm: int) -> bool:
        """Apply TX power to owned hardware before persisting the change."""
        set_power = getattr(self._radio, "set_tx_power", None)
        if not callable(set_power):
            return False
        try:
            applied = set_power(power_dbm)
        except Exception as e:
            logger.error("Error setting TX power: %s", e)
            return False
        if applied is False:
            return False
        return super().set_tx_power(power_dbm)

    # -------------------------------------------------------------------------
    # Key Management
    # -------------------------------------------------------------------------

    def import_private_key(self, key: bytes) -> bool:
        try:
            self._identity = LocalIdentity(seed=key)
            self._pending_ack_crcs.clear()
            self.node = MeshNode(
                radio=self._radio,
                local_identity=self._identity,
                config={
                    "node": {"name": self.prefs.node_name},
                    "radio": self._radio_config,
                },
                contacts=self.contacts,
                channel_db=self.channels,
                event_service=self._event_service,
            )
            self._setup_packet_callbacks()
            logger.info("Imported new identity: %s...", self._identity.get_public_key().hex()[:16])
            return True
        except Exception as e:
            logger.error("Error importing private key: %s", e)
            return False

    # -------------------------------------------------------------------------
    # Statistics (override for radio hardware)
    # -------------------------------------------------------------------------

    def _get_radio_stats(self) -> dict:
        radio_stats = super()._get_radio_stats()
        if hasattr(self._radio, "get_last_rssi"):
            radio_stats["last_rssi"] = self._radio.get_last_rssi()
        if hasattr(self._radio, "get_last_snr"):
            radio_stats["last_snr"] = self._radio.get_last_snr()
        return radio_stats

    # -------------------------------------------------------------------------
    # Internal
    # -------------------------------------------------------------------------

    def _setup_packet_callbacks(self) -> None:
        dispatcher = self.node.dispatcher
        dispatcher.set_packet_received_callback(self._on_packet_received)
        dispatcher.set_packet_sent_callback(self._on_packet_sent)
        dispatcher.set_ack_received_listener(self._on_ack_received)
        dispatcher.add_raw_packet_subscriber(self._on_raw_packet_rx_log)
        dispatcher.raw_data_received_callback = self._on_raw_custom_received
        login_handler = getattr(dispatcher, "login_response_handler", None)
        if login_handler is not None:
            # See CompanionBridge: keep a pending login from swallowing an
            # unrelated reply from the same contact.
            login_handler.set_foreign_request_probe(self.has_pending_request_tag)
        if dispatcher.protocol_response_handler:
            dispatcher.protocol_response_handler.set_binary_response_callback(
                self._on_binary_response
            )
            dispatcher.protocol_response_handler.set_contact_path_updated_callback(
                self._on_contact_path_updated
            )
            # Wire the TX path so the handler can send reciprocal PATH packets
            # (firmware onContactPathRecv behaviour). Without this the remote
            # repeater never learns its route back to us and floods every reply.
            dispatcher.protocol_response_handler.set_packet_injector(self._send_packet)
            # Feed the return-path teacher every flood reply copy pre-dedup so it
            # teaches from the best-received route, not the first-arrived one (see
            # ReturnPathTeacher.note_flood_copy). Dedup below would otherwise hide
            # every copy but the first from the handlers.
            teacher = getattr(dispatcher.protocol_response_handler, "return_path_teacher", None)
            if teacher is not None:
                dispatcher.add_raw_packet_subscriber(teacher.note_flood_copy)
        # When a direct trace reaches the end of its path, push completion data
        # to connected clients (firmware onTraceRecv -> PUSH_CODE_TRACE_DATA).
        if getattr(dispatcher, "trace_handler", None):
            dispatcher.trace_handler.on_trace_complete = self._on_trace_complete

    async def _on_packet_received(self, pkt: Any) -> None:
        route_type = pkt.get_route_type()
        is_flood = route_type in (ROUTE_TYPE_FLOOD, ROUTE_TYPE_TRANSPORT_FLOOD)
        self.stats.record_rx(is_flood=is_flood)
        if pkt.get_payload_type() == PAYLOAD_TYPE_GRP_DATA:
            await self._handle_group_data_packet(pkt)

    async def _on_raw_packet_rx_log(self, pkt: Any, data: bytes, analysis: Any) -> None:
        """Dispatcher raw-packet subscriber: fire rx_log_data(snr, rssi, raw_bytes)."""
        snr = getattr(pkt, "snr", getattr(pkt, "_snr", 0.0))
        rssi = getattr(pkt, "rssi", getattr(pkt, "_rssi", 0))
        await self._fire_callbacks("rx_log_data", snr, rssi, data)

    async def _on_ack_received(self, crc: int) -> bool:
        """Called by dispatcher when an ACK CRC is received; fire send_confirmed if pending.

        Returns whether the CRC matched a pending app-side send, so the ACK
        handler can mark the packet do-not-retransmit (firmware onAckRecv).
        """
        return await self._try_confirm_send(crc)

    async def _on_raw_custom_received(self, pkt: Packet) -> None:
        """Dispatcher RAW_CUSTOM handler: fire raw_data_received(payload, snr, rssi)."""
        payload = bytes(pkt.payload) if pkt.payload else b""
        snr = pkt.get_snr() if hasattr(pkt, "get_snr") else getattr(pkt, "_snr", 0)
        rssi = pkt.rssi if hasattr(pkt, "rssi") else getattr(pkt, "_rssi", 0)
        await self._fire_callbacks("raw_data_received", payload, snr, rssi)

    async def _on_packet_sent(self, pkt: Any) -> None:
        pass

    async def _on_trace_complete(self, pkt: Packet, parsed_data: dict) -> None:
        """Trace reached the end of its path: fire trace_received with the
        assembled PUSH_CODE_TRACE_DATA fields (firmware onTraceRecv layout)."""
        path_hashes = parsed_data.get("trace_path_bytes") or b""
        if not path_hashes:
            return
        flags = parsed_data.get("flags", 0)
        hash_len = len(path_hashes)
        expected_snr_len = hash_len // PathUtils.trace_payload_hash_width(flags)
        if expected_snr_len <= 0:
            return
        snr_scaled = max(-128, min(127, int(round(pkt.get_snr() * 4))))
        snr_byte = snr_scaled if snr_scaled >= 0 else (256 + snr_scaled)
        # Firmware copies path_snrs from pkt->path (length hash_len >> path_sz).
        path_snrs = bytes(pkt.path)[:expected_snr_len]
        if len(path_snrs) < expected_snr_len:
            path_snrs = path_snrs + b"\x00" * (expected_snr_len - len(path_snrs))
        await self._fire_callbacks(
            "trace_received",
            {
                "path_len": hash_len,
                "flags": flags,
                "tag": parsed_data.get("tag", 0),
                "auth_code": parsed_data.get("auth_code", 0),
                "path_hashes": path_hashes,
                "path_snrs": path_snrs,
                "final_snr_byte": snr_byte,
            },
        )
