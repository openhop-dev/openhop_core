from __future__ import annotations

import asyncio
import enum
import inspect
import logging
import random
import time
from typing import Any, Awaitable, Callable, List, Optional

from ..protocol import Packet
from ..protocol.constants import (  # Payload types
    MAX_PATH_SIZE,
    PAYLOAD_TYPE_ACK,
    PAYLOAD_TYPE_ADVERT,
    PAYLOAD_TYPE_TRACE,
    ROUTE_TYPE_FLOOD,
    ROUTE_TYPE_TRANSPORT_FLOOD,
)
from ..protocol.packet_utils import PathUtils, calculate_lora_airtime_ms, flood_rx_metrics
from ..protocol.region_map import RegionMap, capture_recv_region
from ..protocol.transport_keys import scope_packet
from ..protocol.utils import PAYLOAD_TYPES, ROUTE_TYPES
from ..util.callbacks import AckReceivedCallback, invoke_maybe_awaitable

# Import handler classes
from .handlers import (
    AckHandler,
    AnonReqResponseHandler,
    ControlHandler,
    HandlerResult,
    MultipartAckHandler,
    TraceHandler,
    create_core_handlers,
)

ACK_TIMEOUT = 5.0  # seconds to wait for an ACK

# Flood reception-quality delay bounds (MeshCore Dispatcher::checkRecv):
# delays under the threshold process immediately, longer ones are capped.
MIN_RX_DELAY_MS = 50.0
MAX_RX_DELAY_MS = 32000.0

# TX airtime duty-cycle budget (MeshCore Dispatcher.cpp / Dispatcher.h). The
# leaky bucket refills at the duty cycle 1/(1+airtime_factor) over a rolling
# window and is spent on each transmit's estimated airtime. These reproduce the
# firmware constants; the bucket is active only while client-repeat is enabled.
DUTY_CYCLE_WINDOW_MS = 3_600_000  # Dispatcher.h getDutyCycleWindowMs() (1 hour)
MIN_TX_BUDGET_RESERVE_MS = 100  # Dispatcher.cpp MIN_TX_BUDGET_RESERVE_MS
MIN_TX_BUDGET_AIRTIME_DIV = 2  # Dispatcher.cpp MIN_TX_BUDGET_AIRTIME_DIV
MAX_TRANS_UNIT = 255  # MeshCore.h MAX_TRANS_UNIT (worst-case reserve packet size)
# NodePrefs default airtime_factor for the companion (MyMesh.cpp: "one half"),
# i.e. a 50% duty cycle. Live value comes from prefs.airtime_factor.
DEFAULT_AIRTIME_BUDGET_FACTOR = 1.0


class DispatcherState(str, enum.Enum):
    """Simple state machine for managing radio transmission."""

    IDLE = "IDLE"
    TRANSMIT = "TRANSMIT"
    WAIT = "WAIT"


class Dispatcher:
    """Handles all the packet routing and radio communication.

    This class doesn't do much packet processing itself - it just routes
    incoming packets to the right handler that knows what to do with them.

    RF Fabric: ``Dispatcher(existing_radio)`` is unchanged. A radio may
    optionally be wrapped as ``FabricRadio → RFFabric → Dispatcher`` for one or
    many physical radios. The fabric adapter presents the same
    ``set_rx_callback`` surface, so legacy receive callbacks fire exactly once
    per physical RX. Cross-radio mesh dedup uses the existing packet filter.
    TX may optionally target ``radio_id`` when the radio/fabric supports it;
    there is no automatic multi-radio TX fanout.
    """

    # ------------------------------------------------------------------
    # Setup and configuration
    # ------------------------------------------------------------------

    def __init__(
        self,
        radio,
        *,
        tx_delay: float = 0.05,
        log_fn: Optional[Callable[[str], None]] = None,
        packet_filter: Optional[Any] = None,
        dedupe_enabled: bool = True,
    ) -> None:
        # tx_delay: seconds to wait after TX before starting ACK wait (only when wait_for_ack).
        # Round-trip latency can also be increased by: modem CSMA (TXDELAY/SlotTime in
        # firmware), handler response delays (e.g. login_server 300 ms), and serial/
        # event-loop scheduling. KISS wrapper relies on modem CSMA by default (no host LBT).
        self.radio = radio
        self.tx_delay = tx_delay
        self.state: DispatcherState = DispatcherState.IDLE

        self.packet_received_callback: Optional[Callable[[Packet], Awaitable[None] | None]] = None
        self.packet_sent_callback: Optional[Callable[[Packet], Awaitable[None] | None]] = None

        # Optional listener for ACK received (e.g. companion send_confirmed)
        self._ack_received_listener: Optional[AckReceivedCallback] = None

        # Optional callback for PAYLOAD_TYPE_RAW_CUSTOM (companion raw_data_received)
        self.raw_data_received_callback: Optional[Callable[[Packet], Awaitable[None]]] = None

        # Raw packet callbacks: single callback (legacy) and list of subscribers (after parse).
        # Callbacks accept (pkt, data) or (pkt, data, analysis).
        self.raw_packet_callback: Optional[Callable[..., Awaitable[None] | None]] = None
        self._raw_packet_subscribers: List[Callable[..., Any]] = []
        # Raw RX subscribers: notified for every reception (data, rssi, snr) before duplicate/parse
        self._raw_rx_subscribers: List[Callable[..., Any]] = []

        self._handlers: dict[int, Any] = {}  # Keep track of packet handlers
        self._handler_instances: dict[int, Any] = (
            {}
        )  # Store actual handler objects for method access
        # Payload types whose handler consumes the payload for this node (as
        # opposed to routing or observing it). Populated via
        # register_handler(..., local_delivery=True); read by
        # _is_transit_direct_delivery.
        self._local_delivery_types: set[int] = set()

        # Handler references for companion-layer access; populated by
        # register_default_handlers(). Declared here so callers can rely on
        # the attributes existing (None until handlers are registered).
        self.text_message_handler: Optional[Any] = None
        self.protocol_response_handler: Optional[Any] = None
        self.login_response_handler: Optional[Any] = None
        self.group_text_handler: Optional[Any] = None
        self.telemetry_response_handler: Optional[Any] = None

        # Keep our identity handy for detecting our own packets
        self.local_identity: Optional[Any] = None

        # Contact book for decrypting messages (set by the node later)
        self.contact_book = None

        # Flood scope: 16-byte transport key for region-scoped flooding.
        # When set, flood packets are tagged with a transport code and sent
        # as ROUTE_TYPE_TRANSPORT_FLOOD.  Set via companion set_flood_scope().
        # This is the transient send-scope OVERRIDE mirror.
        self.flood_transport_key: Optional[bytes] = None
        # Persisted default flood scope mirror. Firmware
        # sendFloodScoped(recipient) falls back to prefs.default_scope_key when
        # no transient override is set; the companion applies that at its layer,
        # but several sends build the packet and rely on the dispatcher to scope
        # it at TX time. Mirror the default here so those sends carry it too.
        # A null/short default resolves to None (=> plain flood).
        self.default_flood_transport_key: Optional[bytes] = None
        # Explicit-unscoped flag mirror (firmware send_unscoped, FW #2492). When
        # True it suppresses BOTH the override and the default at TX time; it is
        # not nulled by the default mirror, only cleared by a later
        # set_flood_scope()/set_flood_region().
        self.flood_unscoped: bool = False

        # Optional region registry for reply-region capture. Standalone
        # nodes/companions leave this None (no capture); the repeater populates
        # it so replies carry the incoming request's region.
        self.region_map: Optional[RegionMap] = None

        # Default path hash mode for flood packets with 0 hops that have not
        # had path hash mode set by the companion. 0=1-byte, 1=2-byte, 2=3-byte.
        # When None, no default is applied.
        self.path_hash_mode: Optional[int] = None

        # Base for the flood reception-quality delay (MeshCore rx_delay_base,
        # the "set rxdelay" tuning param). 0 disables the delay, which is the
        # firmware default. Synced from prefs/config by the owning layer.
        self.rx_delay_base: float = 0.0

        # Client-repeat forwarding (MeshCore _prefs.client_repeat). Off by
        # default; only CompanionRadio.set_client_repeat toggles it. Nodes that
        # do their own forwarding (e.g. the repeater) leave this False.
        self._client_repeat_enabled: bool = False

        # TX airtime duty-cycle budget (MeshCore getAirtimeBudgetFactor =
        # prefs.airtime_factor). The leaky bucket is consulted ONLY while
        # client-repeat is enabled; when disabled the send path is untouched.
        # Synced from prefs by the owning layer (CompanionRadio).
        self.airtime_budget_factor: float = DEFAULT_AIRTIME_BUDGET_FACTOR
        self._tx_budget_ms: float = 0.0
        self._tx_budget_last_update: float = 0.0
        self._tx_next_time: float = 0.0

        self._logger = logging.getLogger("Dispatcher")
        self._current_expected_crc: Optional[int] = None
        self._recent_acks: dict[int, float] = {}  # {crc: timestamp}
        self._waiting_acks = {}
        self.dedupe_enabled = dedupe_enabled

        # Simple TX lock to prevent concurrent transmissions
        self._tx_lock = asyncio.Lock()

        # Use provided packet filter or create default
        if packet_filter is not None:
            self.packet_filter = packet_filter
        else:
            # Create simple packet filter for routing decisions
            from ..protocol.packet_filter import PacketFilter

            self.packet_filter = PacketFilter()

        # Let the node register for packet analysis if it wants
        self.packet_analysis_callback: Optional[Callable[[Any, bytes], None]] = None

        # Initialize fallback handler
        self._fallback_handler = None

        # Cooperative shutdown for run_forever / MeshNode.stop. Events are
        # created lazily on the running loop because __init__ may run before
        # the test/app event loop exists.
        self._stop_event: Optional[asyncio.Event] = None
        self._stopped_event: Optional[asyncio.Event] = None
        self._run_forever_active = False
        self._rx_enabled = True

        # Hook up the radio's receive callback - all radios should support this
        self._arm_rx()

    def _ensure_lifecycle_events(self) -> tuple:
        """Create stop/stopped events on the running loop if needed."""
        if self._stop_event is None:
            self._stop_event = asyncio.Event()
            self._stopped_event = asyncio.Event()
            self._stopped_event.set()
        return self._stop_event, self._stopped_event

    def _arm_rx(self) -> None:
        """Register the RX callback and allow new packet tasks."""
        self._rx_enabled = True
        if self.radio is None:
            return
        if hasattr(self.radio, "set_rx_callback"):
            self.radio.set_rx_callback(self._on_packet_received)
            self._logger.info("Registered RX callback with radio")
        else:
            self._logger.warning(
                "Radio %s has no set_rx_callback; the dispatcher will never "
                "receive packets from this radio",
                type(self.radio).__name__,
            )

    def _disarm_rx(self) -> None:
        """Stop spawning new packet tasks; best-effort clear the radio callback."""
        self._rx_enabled = False
        if self.radio is not None and hasattr(self.radio, "set_rx_callback"):
            try:
                self.radio.set_rx_callback(None)
            except Exception:
                self._logger.debug("Clearing radio RX callback failed", exc_info=True)

    def set_contact_book(self, contact_book):
        """Set the contact book for decryption operations."""
        self.contact_book = contact_book

    # ------------------------------------------------------------------
    # Public interface - registering handlers and callbacks
    # ------------------------------------------------------------------

    def register_handler(
        self, payload_type: int, handler_instance, *, local_delivery: bool = False
    ) -> None:
        """Register a handler for a specific type of packet.

        ``local_delivery`` marks a handler that *consumes* the payload for this
        node (decrypt, ACK, display) as opposed to one that routes or observes
        it. Only those are gated by the firmware rule in
        :meth:`_is_transit_direct_delivery`: MeshCore never hands a routed-direct
        packet with hops still on its path to payload processing. It defaults to
        False so an application handler — a repeater's router, which must see
        exactly those transit packets — keeps receiving everything, and so an
        application override of a core payload type takes over that decision.
        """
        # Keep the handler instance around so we can call methods on it
        self._handler_instances[payload_type] = handler_instance
        if local_delivery:
            self._local_delivery_types.add(payload_type)
        else:
            self._local_delivery_types.discard(payload_type)

        # Figure out what function to call when we get this packet type
        if hasattr(handler_instance, "handle_packet"):
            self._handlers[payload_type] = handler_instance.handle_packet
        elif callable(handler_instance):
            # Assume it's already a proper handler function
            handler_func = handler_instance
            self._handlers[payload_type] = handler_func
        else:
            raise ValueError(
                f"Handler for payload type {payload_type} must be callable "
                f"or have handle_packet method"
            )

        self._logger.info(f"Registered handler for payload type {payload_type}")

    def get_handler_instance(self, payload_type: int) -> Optional[Any]:
        """Return the registered handler instance for a payload type, or None."""
        return self._handler_instances.get(payload_type)

    def register_fallback_handler(self, handler: Callable[[Packet], Awaitable[None]]):
        """Register a fallback handler for unhandled payload types."""
        self._fallback_handler = handler
        self._logger.info("Registered fallback handler for unknown payload types.")

    def register_default_handlers(
        self,
        *,
        contacts=None,
        local_identity=None,
        channel_db=None,
        event_service=None,
        node_name=None,
        radio_config=None,
    ) -> None:
        """Quick setup for all the standard packet handlers."""
        # Keep our identity handy for detecting our own packets
        self.local_identity = local_identity

        # --- ACK handler (dispatcher-specific wiring) ---
        # Deliberately NOT local_delivery: firmware peeks at a routed-direct ACK
        # while it is still in transit ("early received ACK", Mesh::onRecvPacket)
        # before the next-hop check, and CRC correlation is idempotent.
        ack_handler = AckHandler(self._log, self)
        ack_handler.set_ack_received_callback(self._register_ack_received)
        self.register_handler(AckHandler.payload_type(), ack_handler)

        # --- Multi-ack handler: extract the embedded ACK from MULTIPART packets ---
        # Also left un-gated: it only correlates an embedded ACK CRC, the same
        # idempotent peek as the ACK handler above.
        multipart_ack_handler = MultipartAckHandler(self._log)
        multipart_ack_handler.set_ack_received_callback(self._register_ack_received)
        self.register_handler(MultipartAckHandler.payload_type(), multipart_ack_handler)

        # --- Core handlers via shared factory ---
        core = create_core_handlers(
            identity=local_identity,
            contacts=contacts,
            channels=channel_db,
            event_service=event_service,
            send_packet_fn=self.send_packet,
            log_fn=self._log,
            node_name=node_name,
            radio_config=radio_config,
            ack_handler=ack_handler,
        )

        # Keep references for companion layer access
        self.text_message_handler = core.text_handler
        self.protocol_response_handler = core.protocol_response_handler
        self.login_response_handler = core.login_response_handler
        self.group_text_handler = core.group_text_handler
        # Backward compat alias
        self.telemetry_response_handler = core.protocol_response_handler

        # Register core handlers by payload type
        from .handlers import AdvertHandler as _Adv
        from .handlers import GroupTextHandler as _Grp
        from .handlers import LoginResponseHandler as _Login
        from .handlers import PathHandler as _Path
        from .handlers import TextMessageHandler as _Txt

        # These consume the payload for this node, so they are gated by the
        # firmware transit rule (see _is_transit_direct_delivery).
        self.register_handler(_Adv.payload_type(), core.advert_handler, local_delivery=True)
        self.register_handler(_Txt.payload_type(), core.text_handler, local_delivery=True)
        self.register_handler(_Grp.payload_type(), core.group_text_handler, local_delivery=True)
        self.register_handler(_Path.payload_type(), core.path_handler, local_delivery=True)
        self.register_handler(
            _Login.payload_type(), core.login_response_handler, local_delivery=True
        )

        # --- Dispatcher-only handlers ---
        self.register_handler(
            AnonReqResponseHandler.payload_type(),
            AnonReqResponseHandler(local_identity, contacts, self._log),
            local_delivery=True,
        )

        # TRACE is not gated: firmware handles a direct TRACE in its own branch
        # ahead of the routed-direct block, and this handler owns the path bytes
        # (they carry per-hop SNR, not routing hashes).
        trace_handler = TraceHandler(self._log, core.protocol_response_handler)
        self.register_handler(TraceHandler.payload_type(), trace_handler)
        self.trace_handler = trace_handler

        control_handler = ControlHandler(self._log)
        self.register_handler(ControlHandler.payload_type(), control_handler, local_delivery=True)
        self.control_handler = control_handler

        # --- RAW_CUSTOM handler: deliver to companion if direct and callback set ---
        from ..protocol.constants import PAYLOAD_TYPE_RAW_CUSTOM

        async def raw_custom_handler(pkt: Packet) -> None:
            if not pkt.is_route_direct():
                return
            if self.raw_data_received_callback:
                await self._invoke_callback(self.raw_data_received_callback, pkt)

        self.register_handler(PAYLOAD_TYPE_RAW_CUSTOM, raw_custom_handler, local_delivery=True)

        self._logger.info("Default handlers registered.")

        # Set up a fallback handler for unknown packet types
        async def fallback_handler(pkt):
            # Get payload type for logging
            try:
                ptype = pkt.get_payload_type()
                type_name = PAYLOAD_TYPES.get(ptype, f"unknown_{ptype}")
            except Exception:
                type_name = "unknown"
            self._logger.info(f"Fallback handler: Unhandled payload type {type_name}")
            # Optionally, call the packet_received_callback to pass downstream
            if self.packet_received_callback:
                await self._invoke_callback(self.packet_received_callback, pkt)

        self.register_fallback_handler(fallback_handler)

    def _get_handler(self, ptype: int):
        """Get handler for payload type, or fallback if not found."""
        return self._handlers.get(ptype, self._fallback_handler)

    def set_packet_received_callback(
        self, callback: Callable[[Packet], Awaitable[None] | None]
    ) -> None:
        self.packet_received_callback = callback

    def set_packet_sent_callback(
        self, callback: Callable[[Packet], Awaitable[None] | None]
    ) -> None:
        self.packet_sent_callback = callback

    def set_ack_received_listener(
        self,
        callback: Optional[AckReceivedCallback],
    ) -> None:
        """Set optional listener for received ACK CRCs (e.g. a companion's send_confirmed).

        See :data:`AckReceivedCallback`: the listener returns whether the CRC matched one of
        this node's own pending sends (truthy = consumed, drives do-not-retransmit; False/None =
        not mine). A ``None``-returning listener keeps the older notify-only behaviour.
        """
        self._ack_received_listener = callback

    def set_raw_packet_callback(self, callback: Callable[..., Awaitable[None] | None]) -> None:
        """Set callback for raw packet data.

        Callback receives ``(pkt, data)`` or ``(pkt, data, analysis)``.
        """
        self.raw_packet_callback = callback

    def add_raw_packet_subscriber(self, callback: Callable[..., Any]) -> None:
        """Subscribe to every raw packet. Callback (pkt, data) or (pkt, data, analysis).
        Forward raw RX to clients to track repeats by packet hash.
        """
        if callback not in self._raw_packet_subscribers:
            self._raw_packet_subscribers.append(callback)

    def remove_raw_packet_subscriber(self, callback: Callable[..., Any]) -> None:
        """Unsubscribe from raw packet notifications (after parse)."""
        try:
            self._raw_packet_subscribers.remove(callback)
        except ValueError:
            pass

    def add_raw_rx_subscriber(
        self, callback: Callable[[bytes, int, float], Awaitable[None] | None]
    ) -> None:
        """Subscribe to every incoming raw RX. Callback receives (data, rssi, snr).
        Called before duplicate/blacklist so clients get every repeat.
        """
        if callback not in self._raw_rx_subscribers:
            self._raw_rx_subscribers.append(callback)

    def remove_raw_rx_subscriber(self, callback: Callable[..., Any]) -> None:
        """Unsubscribe from raw RX notifications."""
        try:
            self._raw_rx_subscribers.remove(callback)
        except ValueError:
            pass

    def _on_packet_received(
        self,
        data: bytes,
        rssi: Optional[int] = None,
        snr: Optional[float] = None,
    ) -> None:
        """Called by the radio when a packet comes in. rssi/snr are per-packet when provided."""
        if not self._rx_enabled:
            return
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self._process_received_packet(data, rssi, snr))
        except RuntimeError:
            self._log("No event loop running, cannot process received packet")

    def calc_rx_delay(self, score: float, air_time_ms: float) -> float:
        """Reception-quality delay in ms before a flood packet is processed.

        Matches the MeshCore node firmwares' calcRxDelay override: disabled
        (0) when rx_delay_base <= 0, otherwise scaled so poorly received
        packets wait longer, in units of the packet's airtime.
        """
        if self.rx_delay_base <= 0.0:
            return 0.0
        return (self.rx_delay_base ** (0.85 - score) - 1.0) * air_time_ms

    def _flood_rx_delay_ms(self, frame_len: int, snr: float) -> float:
        """Effective hold time for a flood packet, 0 when it should process now.

        Scores the reception against the live radio settings and applies the
        firmware thresholds: below 50 ms processes immediately, above 32 s is
        capped. Radios that don't expose their LoRa settings fall back to the
        same assumptions as the firmware base wrapper (SF10) and the default
        MeshCore preset.
        """
        metrics = flood_rx_metrics(
            frame_len,
            snr,
            getattr(self.radio, "spreading_factor", 10),
            getattr(self.radio, "bandwidth", 250000),
            getattr(self.radio, "coding_rate", 5),
            getattr(self.radio, "preamble_length", 8),
            rx_delay_base=self.rx_delay_base,
            min_delay_ms=MIN_RX_DELAY_MS,
            max_delay_ms=MAX_RX_DELAY_MS,
        )
        return metrics.delay_ms

    async def _hold_flood_packet(self, delay_ms: float) -> None:
        """Wait out a flood reception delay (overridable by tests/subclasses)."""
        await asyncio.sleep(delay_ms / 1000.0)

    async def _process_received_packet(
        self,
        data: bytes,
        rssi: Optional[int] = None,
        snr: Optional[float] = None,
    ) -> None:
        """Process received packet. rssi/snr are per-packet when provided."""
        # Notify raw RX subscribers so clients can track repeats
        if rssi is not None:
            rssi_val = rssi
        elif hasattr(self.radio, "get_last_rssi"):
            rssi_val = self.radio.get_last_rssi()
        else:
            rssi_val = 0
        if snr is not None:
            snr_val = snr
        elif hasattr(self.radio, "get_last_snr"):
            snr_val = self.radio.get_last_snr()
        else:
            snr_val = 0.0
        for cb in self._raw_rx_subscribers:
            try:
                await invoke_maybe_awaitable(cb, data, rssi_val, snr_val)
            except Exception as e:
                self._log(f"Raw RX subscriber error: {e}")

        # Blacklist check uses raw-frame hash (catches known-bad bytes before parsing)
        raw_hash = self.packet_filter.generate_hash(data)
        if self.packet_filter.is_blacklisted(raw_hash):
            self._log("[RX DEBUG] Packet blacklisted, skipping")
            return

        # Parse before dedup — calculate_packet_hash() needs a parsed packet
        pkt = Packet()
        try:
            pkt.read_from(data)
        except Exception as err:
            self._log(f"Malformed packet: {err}")
            self.packet_filter.blacklist(raw_hash)
            self._log(f"Blacklisted malformed packet (raw hash: {raw_hash})")
            return

        # Use per-packet rssi/snr when provided (avoids race); else fall back to radio last values
        pkt._rssi = rssi if rssi is not None else self.radio.get_last_rssi()
        pkt._snr = snr if snr is not None else self.radio.get_last_snr()
        # Multi-radio: stamp which fabric radio delivered this frame (if known).
        rx_radio_id = getattr(self.radio, "last_rx_radio_id", None)
        if rx_radio_id is None:
            fabric = getattr(self.radio, "fabric", None)
            if fabric is not None:
                rx_radio_id = getattr(fabric, "last_rx_radio_id", None)
        if rx_radio_id is not None:
            pkt._rx_radio_id = rx_radio_id

        # Capture the region this packet arrived under before any handler
        # runs, so a reply builder can scope its reply to that region. No-op when
        # no RegionMap is configured (standalone node/companion).
        capture_recv_region(self.region_map, pkt)

        # Let the node know about this packet for analysis (statistics, caching, etc.)
        if self.packet_analysis_callback:
            try:
                await invoke_maybe_awaitable(self.packet_analysis_callback, pkt, data)
                self._log("[RX DEBUG] Packet analysis callback completed")
            except Exception as e:
                self._log(f"Error in packet analysis callback: {e}")

        # Notify raw packet subscribers (e.g. companion clients for PUSH_CODE_LOG_RX_DATA)
        # This fires BEFORE dedup so the UI sees all path variants for logging
        analysis = {}
        for callback in self._raw_packet_subscribers:
            await self._invoke_enhanced_raw_callback(callback, pkt, data, analysis)
        if self.raw_packet_callback:
            await self._invoke_enhanced_raw_callback(self.raw_packet_callback, pkt, data, {})
        if self._raw_packet_subscribers or self.raw_packet_callback:
            self._log("[RX DEBUG] Raw packet callback completed")

        # MeshCore holds flood packets for a reception-quality delay before
        # processing: a better-received copy (shorter delay, here or at
        # another node) processes first, and the dedupe check below — which
        # must run after the hold, like firmware's hasSeen — then drops this
        # copy when it wakes. Direct routes are never delayed, and the
        # firmware-default rx_delay_base of 0 keeps processing immediate.
        if pkt.is_route_flood():
            delay_ms = self._flood_rx_delay_ms(len(data), snr_val)
            if delay_ms > 0.0:
                self._log(f"Holding flood packet {delay_ms:.0f}ms (reception-quality delay)")
                await self._hold_flood_packet(delay_ms)

        # When disabled, packet_filter still tracks hashes for stats/visibility.
        packet_hash = pkt.calculate_packet_hash().hex()[:16]
        # MeshCore records a routed-direct packet in its seen table only when
        # this node is the next hop (Mesh::onRecvPacket). A node that overhears
        # an earlier route variant must not mark the path-independent hash seen,
        # or it would later drop the self-stripped copy it is asked to relay.
        # Flood, zero-hop direct and direct TRACE keep unconditional dedup: the
        # first two match firmware's up-front markSeen, and the TRACE hash folds
        # in path_len so its per-hop copies never collide.
        if not self._is_transit_direct_not_next_hop(pkt):
            if self.dedupe_enabled and self.packet_filter.is_duplicate(packet_hash):
                self._log(f"Duplicate packet ignored (hash: {packet_hash})")
                return
            self.packet_filter.track_packet(packet_hash)

        # Client-repeat: build the retransmit from the just-received packet
        # BEFORE handlers run, so a copy is taken while path/payload are intact
        # (no Core handler mutates the received packet's path/payload). The
        # forward is only scheduled after _dispatch so a flood packet consumed
        # by this node (a handler marked it do-not-retransmit, mirroring
        # firmware Mesh::onRecvPacket) is not re-flooded. Direct/TRACE forwards
        # keep their next-hop guards and are unaffected by the mark, matching
        # firmware which forwards those before payload processing. Our own
        # retransmit re-tracks the same hash in the send funnel, so a copy
        # echoed back over RF is dropped by the dedupe check above.
        forward_pkt = None
        if self._client_repeat_enabled:
            forward_pkt = self._build_client_repeat_forward(pkt)

        # Handle ACK matching for waiting senders
        await self._dispatch(pkt)

        if forward_pkt is not None and not (
            forward_pkt.is_route_flood() and pkt.is_marked_do_not_retransmit()
        ):
            asyncio.create_task(self._client_repeat_transmit(forward_pkt))

    # ------------------------------------------------------------------
    # Public interface - sending and receiving packets
    # ------------------------------------------------------------------

    def _scope_packet(self, pkt: Packet, key: bytes) -> None:
        """Attach transport codes for ``key`` and switch FLOOD -> TRANSPORT_FLOOD.

        Delegates to the shared :func:`scope_packet` primitive so the dispatcher
        and companion resolvers compute the wire format identically.
        """
        scope_packet(pkt, key)

    def _apply_flood_scope(self, pkt: Packet) -> None:
        """Apply flood scope transport codes to a packet in-place at TX time.

        Mirrors firmware ``sendFloodScoped(recipient)`` precedence
        (companion_radio/MyMesh.cpp): a packet the companion/reply layer already
        decided is left untouched; explicit-unscoped wins first; otherwise the
        transient override is used, else the persisted default. A null default
        (None) leaves the packet a plain flood.

        Packets the companion layer already scoped (or deliberately left as
        plain flood, e.g. explicit-unscoped mode or default-scoped adverts) —
        and replies whose region the reply helper already decided — are marked
        ``_flood_scope_applied`` and skipped here.
        """
        # Checked FIRST: a companion/reply decision is authoritative and must
        # never be re-scoped, even when the node has an override/default set.
        if getattr(pkt, "_flood_scope_applied", False):
            return
        if pkt.get_route_type() != ROUTE_TYPE_FLOOD:
            return
        # Explicit-unscoped wins (firmware checks send_unscoped before scope).
        if self.flood_unscoped:
            return
        # Transient override else persisted default (override else DEFAULT).
        key = (
            self.flood_transport_key
            if self.flood_transport_key is not None
            else self.default_flood_transport_key
        )
        if key is None:
            return
        self._scope_packet(pkt, key)

    def set_default_path_hash_mode(self, mode: Optional[int]) -> None:
        """Set or clear the default path hash mode for flood packets with 0 hops.

        When set, packets sent via send_packet() that have not already had path
        hash mode applied (e.g. by the companion) will get path_len bits 6-7
        set from this mode. Companion-originated packets are never overwritten.

        Args:
            mode: 0=1-byte, 1=2-byte, 2=3-byte per hop; None to disable.
        """
        if mode is not None and mode not in (0, 1, 2):
            raise ValueError(f"path_hash_mode must be None, 0, 1, or 2, got {mode}")
        self.path_hash_mode = mode

    def _apply_default_path_hash_mode(self, pkt: Packet) -> None:
        """Apply dispatcher default path hash mode if set and packet is eligible."""
        if self.path_hash_mode is None:
            return
        route_type = pkt.get_route_type()
        if route_type not in (ROUTE_TYPE_FLOOD, ROUTE_TYPE_TRANSPORT_FLOOD):
            return
        if pkt.get_path_hash_count() != 0:
            return
        if getattr(pkt, "_path_hash_mode_applied", False):
            return
        pkt.apply_path_hash_mode(self.path_hash_mode, mark_applied=False)

    # ------------------------------------------------------------------
    # Client-repeat forwarding (MeshCore Mesh::onRecvPacket forward paths)
    # ------------------------------------------------------------------

    def set_client_repeat_enabled(self, enabled: bool) -> None:
        """Enable/disable client-repeat forwarding of received packets.

        Enabling also arms the TX airtime budget (firmware Dispatcher::begin
        starts the bucket full at ``window * duty_cycle``).
        """
        enabled = bool(enabled)
        if enabled and not self._client_repeat_enabled:
            self._reset_tx_budget()
        self._client_repeat_enabled = enabled

    # ------------------------------------------------------------------
    # TX airtime duty-cycle budget (MeshCore Dispatcher budget mechanics)
    # ------------------------------------------------------------------

    def _duty_cycle(self) -> float:
        """duty_cycle = 1/(1+airtime_factor) (Dispatcher.cpp updateTxBudget)."""
        return 1.0 / (1.0 + max(0.0, float(self.airtime_budget_factor)))

    def _reset_tx_budget(self) -> None:
        """Start the bucket full, matching Dispatcher::begin()."""
        now = time.monotonic()
        self._tx_budget_ms = DUTY_CYCLE_WINDOW_MS * self._duty_cycle()
        self._tx_budget_last_update = now
        self._tx_next_time = now

    def _refill_tx_budget(self, now: float) -> None:
        """Accrue budget at the duty cycle, capped at the window max.

        Mirrors Dispatcher::updateTxBudget: ``refill = elapsed * duty_cycle``
        added to ``tx_budget_ms`` and clamped to ``window * duty_cycle``.
        """
        duty = self._duty_cycle()
        max_budget = DUTY_CYCLE_WINDOW_MS * duty
        elapsed_ms = (now - self._tx_budget_last_update) * 1000.0
        refill = elapsed_ms * duty
        if refill > 0.0:
            self._tx_budget_ms = min(self._tx_budget_ms + refill, max_budget)
            self._tx_budget_last_update = now

    def _tx_est_airtime_ms(self, byte_len: int) -> float:
        """Estimated LoRa airtime for ``byte_len`` on-air bytes (live radio settings)."""
        return calculate_lora_airtime_ms(
            byte_len,
            getattr(self.radio, "spreading_factor", 10),
            getattr(self.radio, "bandwidth", 250000),
            getattr(self.radio, "coding_rate", 5),
            getattr(self.radio, "preamble_length", 8),
        )

    def _tx_budget_wait_s(self) -> float:
        """Seconds this transmit must wait for the airtime budget; <= 0 admits.

        Reproduces the Dispatcher::checkSend TX gate synchronously: refill, then
        require at least ``est_airtime(MAX_TRANS_UNIT) / MIN_TX_BUDGET_AIRTIME_DIV``
        of budget and honour the ``next_tx_time`` pacing the send-complete path
        set when the budget last dipped below MIN_TX_BUDGET_RESERVE_MS. The
        shortfall is scaled by ``1/duty_cycle`` to the firmware-computed
        ``needed / duty_cycle`` wait. Refill is the only budget mutation here and
        is monotonically increasing, so this is safe to call both before and
        again under ``_tx_lock`` as the admission recheck.
        """
        now = time.monotonic()
        self._refill_tx_budget(now)
        reserve_ms = self._tx_est_airtime_ms(MAX_TRANS_UNIT) / MIN_TX_BUDGET_AIRTIME_DIV
        wait_ms = 0.0
        if self._tx_budget_ms < reserve_ms:
            wait_ms = (reserve_ms - self._tx_budget_ms) / self._duty_cycle()
        # next_tx_time pacing from the previous debit.
        pace_s = self._tx_next_time - now
        return max(wait_ms / 1000.0, pace_s)

    async def _await_tx_budget(self, packet: Packet) -> None:
        """Sleep (never under ``_tx_lock``) until the airtime budget admits; never drops.

        This is the pre-lock throttle only; admission is re-decided under
        ``_tx_lock`` in ``send_packet`` (via ``_tx_budget_wait_s``) so a snapshot
        taken here can never authorise a transmit past a debit another task
        committed under the lock. Because only ``_tx_lock`` holders debit and the
        sole out-of-lock mutation (``_refill_tx_budget``) is monotonically
        increasing, an under-lock pass cannot be invalidated before ``radio.send``.
        Sleeps happen only here, off the lock, so a throttled forward never
        blocks other transmits and ``asyncio.sleep`` stays cancellation-safe. A
        client-repeat toggle mid-wait releases the waiter after its current sleep.
        """
        while self._client_repeat_enabled:
            wait_s = self._tx_budget_wait_s()
            if wait_s <= 0.0:
                return
            await asyncio.sleep(wait_s)

    def _debit_tx_budget(self, packet: Packet) -> None:
        """Spend this transmit's estimated airtime (Dispatcher send-complete path).

        Mirrors the isSendComplete block: refill, subtract the airtime (clamped
        at zero), then set ``next_tx_time`` so the next send waits when the
        budget fell below MIN_TX_BUDGET_RESERVE_MS.
        """
        now = time.monotonic()
        self._refill_tx_budget(now)
        airtime_ms = self._tx_est_airtime_ms(packet.get_raw_length())
        if airtime_ms > self._tx_budget_ms:
            self._tx_budget_ms = 0.0
        else:
            self._tx_budget_ms -= airtime_ms
        duty = self._duty_cycle()
        if self._tx_budget_ms < MIN_TX_BUDGET_RESERVE_MS:
            needed = MIN_TX_BUDGET_RESERVE_MS - self._tx_budget_ms
            self._tx_next_time = now + (needed / duty) / 1000.0
        else:
            self._tx_next_time = now

    def _copy_packet_for_forward(self, pkt: Packet) -> Packet:
        """Copy a received packet for retransmission with an independent path buffer.

        Marks the copy as already-scoped and already-hash-moded so the send
        funnel retransmits it verbatim (never re-scoping a forwarded flood or
        overwriting the path hash width we set here).
        """
        fwd = Packet()
        fwd.header = pkt.header
        fwd.path_len = pkt.path_len
        fwd.path = bytearray(pkt.path)
        fwd.payload = bytearray(pkt.payload[: pkt.payload_len])
        fwd.payload_len = pkt.payload_len
        fwd.transport_codes = list(pkt.transport_codes)
        fwd._snr = pkt._snr
        fwd._rssi = pkt._rssi
        fwd._flood_scope_applied = True
        fwd._path_hash_mode_applied = True
        return fwd

    def _is_transit_direct_not_next_hop(self, pkt: Packet) -> bool:
        """True for a routed-direct packet this node is not the next hop for.

        Mirrors MeshCore ``Mesh::onRecvPacket``, which records a routed-direct
        packet in the seen table only inside the
        ``isHashMatch(path) && allowPacketForward`` branch. Such packets must be
        left out of dedup so an overheard longer-path variant does not suppress
        the self-stripped copy this node is later the next hop for. Direct TRACE
        is excluded (its hash folds in ``path_len``, so per-hop copies never
        collide) as are flood and zero-hop-direct packets.
        """
        if not pkt.is_route_direct() or pkt.get_path_hash_count() <= 0:
            return False
        if pkt.get_payload_type() == PAYLOAD_TYPE_TRACE:
            return False
        if self.local_identity is None:
            return False
        self_key = self.local_identity.get_public_key()
        hash_size = pkt.get_path_hash_size()
        if len(pkt.path) < hash_size:
            return False
        return bytes(pkt.path[:hash_size]) != self_key[:hash_size]

    def _build_client_repeat_forward(self, pkt: Packet) -> Optional[Packet]:
        """Build the retransmit packet for a received packet, or None to drop.

        Mirrors the forwarding branches of MeshCore ``Mesh::onRecvPacket``:
        direct TRACE appends an SNR byte, routed-direct traffic strips self and
        retransmits, and flood traffic appends our hash unless it was consumed
        by this node. ``allowPacketForward`` (``_prefs.client_repeat != 0``) is
        the ``_client_repeat_enabled`` gate checked by the caller.
        """
        if self.local_identity is None:
            return None
        self_key = self.local_identity.get_public_key()
        ptype = pkt.get_payload_type()

        if pkt.is_route_direct() and ptype == PAYLOAD_TYPE_TRACE:
            return self._build_trace_forward(pkt, self_key)
        if pkt.is_route_direct() and pkt.get_path_hash_count() > 0:
            return self._build_direct_forward(pkt, self_key)
        if pkt.is_route_flood():
            return self._build_flood_forward(pkt, self_key)
        return None

    def _build_flood_forward(self, pkt: Packet, self_key: bytes) -> Optional[Packet]:
        """Append this node's hash to a flood path (Mesh::routeRecvPacket).

        Whether the forward is actually sent is decided after ``_dispatch``:
        firmware's ``!isMarkedDoNotRetransmit()`` guard is honoured there via
        the do-not-retransmit mark a handler sets when it genuinely consumes the
        packet (a real decrypt, not a bare dest-hash collision). Own-advert
        echoes and any other copy we hear back are dropped earlier by the RX
        seen-table (the TX-side track_packet), matching firmware's hasSeen; a
        self-advert is never re-received without this node first transmitting
        (and thus tracking) it, so no self-advert special case is needed here.
        """
        hash_size = pkt.get_path_hash_size()
        hop_count = pkt.get_path_hash_count()
        # Firmware guards: (n+1)*hashSize <= MAX_PATH_SIZE and the 6-bit hop cap.
        if hop_count >= 63:
            return None
        if (hop_count + 1) * hash_size > MAX_PATH_SIZE:
            return None
        fwd = self._copy_packet_for_forward(pkt)
        fwd.path.extend(self_key[:hash_size])
        fwd.path_len = PathUtils.encode_path_len(hash_size, hop_count + 1)
        return fwd

    def _build_direct_forward(self, pkt: Packet, self_key: bytes) -> Optional[Packet]:
        """Strip self and retransmit a routed-direct packet when we are the next hop."""
        hash_size = pkt.get_path_hash_size()
        if len(pkt.path) < hash_size:
            return None
        if bytes(pkt.path[:hash_size]) != self_key[:hash_size]:
            return None  # this node is not the next hop
        hop_count = pkt.get_path_hash_count()
        fwd = self._copy_packet_for_forward(pkt)
        fwd.path = bytearray(fwd.path[hash_size:])
        fwd.path_len = PathUtils.encode_path_len(hash_size, hop_count - 1)
        return fwd

    def _build_trace_forward(self, pkt: Packet, self_key: bytes) -> Optional[Packet]:
        """Append this node's scaled SNR to a direct TRACE (Mesh::onRecvPacket TRACE)."""
        if pkt.path_len >= MAX_PATH_SIZE:
            return None
        # payload: trace_tag(4) auth_code(4) flags(1), then the routing hashes.
        if pkt.payload_len < 9:
            return None
        flags = pkt.payload[8]
        path_sz = flags & 0x03
        hash_width = 1 << path_sz
        header_len = 9
        length = pkt.payload_len - header_len
        offset = pkt.path_len << path_sz
        if offset >= length:
            return None  # TRACE has reached the end of its path (consume, not forward)
        start = header_len + offset
        if bytes(pkt.payload[start : start + hash_width]) != self_key[:hash_width]:
            return None  # not the next hop in the trace path
        fwd = self._copy_packet_for_forward(pkt)
        snr_byte = int(pkt.get_snr() * 4) & 0xFF
        while len(fwd.path) <= fwd.path_len:
            fwd.path.append(0)
        fwd.path[fwd.path_len] = snr_byte
        fwd.path_len += 1
        return fwd

    def _client_repeat_delay_ms(self, pkt: Packet) -> float:
        """Random retransmit jitter for a forward (MyMesh getRetransmitDelay).

        Flood uses t = estAirtime*0.5, direct uses t = estAirtime*0.2, and the
        delay is uniform in [0, 5*t] ms. Airtime is estimated over the on-air
        length (path bytes + payload + 2) against the live radio settings.
        """
        frame_len = pkt.get_path_byte_len() + pkt.payload_len + 2
        airtime_ms = calculate_lora_airtime_ms(
            frame_len,
            getattr(self.radio, "spreading_factor", 10),
            getattr(self.radio, "bandwidth", 250000),
            getattr(self.radio, "coding_rate", 5),
            getattr(self.radio, "preamble_length", 8),
        )
        factor = 0.5 if pkt.is_route_flood() else 0.2
        t = airtime_ms * factor
        if t <= 0:
            return 0.0
        return float(random.randint(0, int(5 * t)))

    async def _client_repeat_transmit(self, pkt: Packet) -> None:
        """Wait out the retransmit jitter then send the forward through the funnel.

        Stage 2 airtime budgeting slots in here / in the send funnel: the
        forward is a plain send_packet, so a budget gate can suppress it.
        """
        try:
            delay_ms = self._client_repeat_delay_ms(pkt)
            if delay_ms > 0:
                await asyncio.sleep(delay_ms / 1000.0)
            await self.send_packet(pkt, wait_for_ack=False)
        except asyncio.CancelledError:
            raise
        except Exception as err:
            self._log(f"Client-repeat forward failed: {err}")

    async def send_packet(
        self,
        packet: Packet,
        wait_for_ack: bool = True,
        expected_crc: Optional[int] = None,
        radio_id: Optional[str] = None,
    ) -> bool:
        """
        Send a packet and optionally wait for an ACK.
        Uses a lock to serialize transmissions instead of dropping packets.

        Args:
            packet: The packet to send
            wait_for_ack: Whether to wait for an ACK
            expected_crc: The expected CRC for ACK matching.
                If None, will be calculated from packet.
        """
        # TRACE is only sent via sendDirect() in firmware; flood TRACE is unsupported.
        route_type = packet.get_route_type()
        if route_type in (ROUTE_TYPE_FLOOD, ROUTE_TYPE_TRANSPORT_FLOOD):
            if packet.get_payload_type() == PAYLOAD_TYPE_TRACE:
                self._log("TRACE not supported for flood; dropping")
                return False
        self._apply_flood_scope(packet)
        self._apply_default_path_hash_mode(packet)
        # Airtime duty-cycle budget: only while client-repeat is on. When
        # disabled the send path is unchanged (a recorded deliberate deferral).
        if not self._client_repeat_enabled:
            async with self._tx_lock:  # Wait our turn
                tx_ok, ack_event, ack_crc = await self._transmit_locked(
                    packet, wait_for_ack, expected_crc, radio_id=radio_id
                )
        else:
            # Throttle off-lock, then re-decide admission under the lock so a
            # snapshot taken before queueing cannot transmit past a debit another
            # task committed under _tx_lock. _debit_tx_budget runs only under the
            # lock and the sole out-of-lock mutation (_refill_tx_budget) only
            # increases the budget, so an under-lock pass holds until radio.send.
            # Livelock is bounded: every debit sets _tx_next_time pacing that all
            # later admissions honour (firmware's next_tx_time property). Never
            # sleep under the lock -- fall out of the async with to wait again.
            while True:
                await self._await_tx_budget(packet)
                async with self._tx_lock:  # Wait our turn
                    if not self._client_repeat_enabled or self._tx_budget_wait_s() <= 0.0:
                        tx_ok, ack_event, ack_crc = await self._transmit_locked(
                            packet, wait_for_ack, expected_crc, radio_id=radio_id
                        )
                        break

        # Wait for the ACK OUTSIDE _tx_lock so relay traffic and other sends can
        # use the funnel during the up-to-ACK_TIMEOUT window. Firmware's
        # Dispatcher::loop frees the radio when the physical send completes and
        # services its outbound queue independently of ACK correlation; holding
        # the funnel through the ACK wait was the divergence. The waiter was
        # registered under the lock (and _register_ack_received also caches into
        # _recent_acks), so an ACK arriving the instant the lock frees is caught.
        if not tx_ok:
            return False
        if ack_event is None:
            return True
        try:
            # Unchanged from the pre-shrink path except that it no longer runs
            # under _tx_lock: the waiter is already registered, so an ACK landing
            # during this pause is matched rather than raced.
            await asyncio.sleep(self.tx_delay)
            ack_received = await self._await_ack_event(ack_event, ack_crc, ACK_TIMEOUT)
            if ack_received:
                self._log(f"[>>acK] received for CRC {ack_crc:08X}")
            else:
                self._log(f"ACK timeout for CRC {ack_crc:08X}")
            return ack_received
        finally:
            self.state = DispatcherState.IDLE
            self._current_expected_crc = None
            # Registration now happens under _tx_lock, one await earlier than the
            # wait that owns its cleanup, so this scope -- not _await_ack_event --
            # is the one that spans every exit path. Without this, a cancel during
            # the tx_delay pause would strand the CRC in _waiting_acks forever
            # (nothing prunes it, unlike _recent_acks), leaving relayed ACKs for
            # that CRC permanently marked do-not-retransmit. Identity-guarded and
            # idempotent: a no-op once the ACK path or _await_ack_event removed it.
            if self._waiting_acks.get(ack_crc) is ack_event:
                del self._waiting_acks[ack_crc]

    def _resolve_tx_radio_id_for_log(
        self, raw: bytes, radio_id: Optional[str] = None
    ) -> Optional[str]:
        """Best-effort TX radio id for log lines (multi-radio / fabric).

        Prefers an explicit ``radio_id``, then RFFabric.resolve_tx_radio_id /
        default_radio_id when the radio is a FabricRadio or exposes a fabric.
        Returns None for legacy single-radio stacks so logs stay unchanged.
        """
        if radio_id is not None and str(radio_id).strip():
            return str(radio_id)

        radio = self.radio
        if radio is None:
            return None

        # FabricRadio exposes .fabric; some stacks may pass RFFabric directly.
        fabric = getattr(radio, "fabric", None)
        if fabric is None and hasattr(radio, "resolve_tx_radio_id"):
            fabric = radio
        if fabric is None:
            return None

        try:
            if hasattr(fabric, "resolve_tx_radio_id"):
                rid = fabric.resolve_tx_radio_id(raw, None)
                if rid:
                    return str(rid)
        except Exception:
            pass

        for attr in ("default_radio_id", "last_rx_radio_id", "radio_id"):
            try:
                rid = getattr(fabric, attr, None)
                if callable(rid):
                    continue
                if rid:
                    return str(rid)
            except Exception:
                continue
        return None

    async def _transmit_locked(
        self,
        packet: Packet,
        wait_for_ack: bool = True,
        expected_crc: Optional[int] = None,
        radio_id: Optional[str] = None,
    ) -> tuple[bool, Optional[asyncio.Event], Optional[int]]:
        """Transmit the packet; assumes ``_tx_lock`` is held.

        Returns ``(tx_ok, ack_event, ack_crc)``. When an ACK wait is needed the
        waiter is registered here — before the caller releases ``_tx_lock`` — and
        the event is returned so the caller can await it OUTSIDE the lock, freeing
        the send funnel during the wait. ``ack_event`` is ``None`` when no wait is
        needed (ADVERT/ACK, ``wait_for_ack`` False, or a transmit failure).
        """
        payload_type = packet.get_payload_type()

        # Mark this packet seen before transmitting, matching firmware's
        # hasSeen() call right before sendPacket() in Mesh::sendFlood/
        # sendDirect/sendZeroHop: if a neighbor rebroadcasts it back to us,
        # the RX-path dedupe check (packet_filter.is_duplicate) must catch
        # it. Uses the same hash the RX path tracks with, so a returned copy
        # with a mutated path (path excluded from the hash) still matches.
        packet_hash = packet.calculate_packet_hash().hex()[:16]
        self.packet_filter.track_packet(packet_hash)

        # ------------------------------------------------------------------ #
        #  Send the packet (lock ensures only one transmission at a time)
        # ------------------------------------------------------------------ #
        self.state = DispatcherState.TRANSMIT
        raw = packet.write_to()
        tx_metadata = None
        # Resolve which fabric/radio endpoint will TX for log clarity (multi-radio).
        tx_radio_id = self._resolve_tx_radio_id_for_log(raw, radio_id)
        try:
            # Prefer fabric/radio multi-radio send(data, radio_id=...) when
            # available; fall back to the legacy single-arg send(raw).
            send_fn = self.radio.send
            if radio_id is not None:
                try:
                    tx_metadata = await send_fn(raw, radio_id=radio_id)
                except TypeError:
                    tx_metadata = await send_fn(raw)
            else:
                tx_metadata = await send_fn(raw)
        except Exception as e:
            radio_label = f" radio={tx_radio_id}" if tx_radio_id else ""
            self._log(f"Radio transmit error{radio_label}: {e}")
            self.state = DispatcherState.IDLE
            return (False, None, None)
        if tx_metadata is None:
            radio_label = f" radio={tx_radio_id}" if tx_radio_id else ""
            self._log(f"Radio transmit returned no confirmation metadata{radio_label}")
            self.state = DispatcherState.IDLE
            return (False, None, None)
        # Spend the airtime budget on the completed transmit (client-repeat only).
        if self._client_repeat_enabled:
            self._debit_tx_budget(packet)
        # Prefer radio_id returned in metadata when present (authoritative).
        if isinstance(tx_metadata, dict):
            meta_rid = tx_metadata.get("radio_id") or tx_metadata.get("tx_radio_id")
            if meta_rid:
                tx_radio_id = str(meta_rid)
        # Log what we sent (include radio id when multi-radio / fabric).
        type_name = PAYLOAD_TYPES.get(payload_type, f"UNKNOWN_{payload_type}")
        route_name = ROUTE_TYPES.get(packet.get_route_type(), f"UNKNOWN_{packet.get_route_type()}")
        if tx_radio_id:
            self._log(
                f"TX {tx_radio_id} {packet.get_raw_length()} bytes "
                f"(type={type_name}, route={route_name})"
            )
        else:
            self._log(f"TX {packet.get_raw_length()} bytes (type={type_name}, route={route_name})")

        # Store metadata on packet for access by handlers
        if tx_metadata:
            packet._tx_metadata = tx_metadata

        if self.packet_sent_callback:
            await self._invoke_callback(self.packet_sent_callback, packet)

        # Skip waiting for ACK if not needed
        if payload_type in {PAYLOAD_TYPE_ADVERT, PAYLOAD_TYPE_ACK} or not wait_for_ack:
            self.state = DispatcherState.IDLE
            return (True, None, None)

        # ACK wait needed. Register the waiter now, while _tx_lock is still held,
        # so an ACK arriving the instant the caller releases the lock is not
        # missed; the caller awaits the event off-lock (see send_packet).
        crc = expected_crc if expected_crc is not None else packet.get_crc()
        self._current_expected_crc = crc
        ack_event = self.expect_ack(crc)
        self.state = DispatcherState.WAIT
        self._log(f"Waiting for ACK with CRC {crc:08X} (timeout: {ACK_TIMEOUT}s)")
        return (True, ack_event, crc)

    async def wait_for_ack(self, crc: int, timeout: float = ACK_TIMEOUT) -> bool:
        """Wait for a specific ACK CRC for up to `timeout` seconds."""
        event = self.expect_ack(crc)
        return await self._await_ack_event(event, crc, timeout)

    async def _await_ack_event(
        self, event: asyncio.Event, crc: int, timeout: float = ACK_TIMEOUT
    ) -> bool:
        """Await an already-registered ACK event, cleaning up on every exit.

        Split out of :meth:`wait_for_ack` so :meth:`send_packet` can register the
        waiter under ``_tx_lock`` and await it after releasing the lock.
        """
        try:
            await asyncio.wait_for(event.wait(), timeout)
            return True
        except asyncio.TimeoutError:
            self._log(f"wait_for_ack() timeout for CRC {crc:08X}")
            return False
        finally:
            # Clean up our registration on every exit path (normal return,
            # timeout, or cancellation) so `_waiting_acks` never leaks.
            # Identity-guarded: if the receive path already popped our entry
            # (the normal-ACK case) this is a no-op; if a *different* waiter
            # has since registered under the same CRC, don't delete theirs.
            if self._waiting_acks.get(crc) is event:
                del self._waiting_acks[crc]

    # ------------------------------------------------------------------#
    # ACK tracking and management
    # ------------------------------------------------------------------#
    def expect_ack(self, crc: int) -> asyncio.Event:
        """
        Register an ACK CRC we're waiting for and return an asyncio.Event
        that will be set as soon as the ACK arrives (or is already cached).
        """
        evt = self._waiting_acks.get(crc)
        if evt is None:
            evt = asyncio.Event()
            self._waiting_acks[crc] = evt

            # ACK might already be in the recent-ACK cache -> fire instantly
        if crc in self._recent_acks:
            evt.set()
        return evt

    # RX path for every incoming packet
    async def _dispatch(self, pkt: Packet) -> None:
        payload_type = pkt.get_payload_type()
        type_name = PAYLOAD_TYPES.get(payload_type, f"UNKNOWN_{payload_type}")
        payload_preview = (
            pkt.payload[: min(10, pkt.payload_len)].hex() if pkt.payload_len > 0 else ""
        )
        # Multi-radio: include which fabric radio delivered this frame when known.
        rx_radio_id = getattr(pkt, "_rx_radio_id", None)
        if rx_radio_id is None:
            rx_radio_id = getattr(self.radio, "last_rx_radio_id", None)
            if rx_radio_id is None:
                fabric = getattr(self.radio, "fabric", None)
                if fabric is not None:
                    rx_radio_id = getattr(fabric, "last_rx_radio_id", None)
        radio_prefix = f"{rx_radio_id} " if rx_radio_id else ""
        if payload_preview:
            self._log(
                f"RX {radio_prefix}{type_name} ({payload_type}) "
                f"len={pkt.payload_len} payload={payload_preview}"
            )
        else:
            self._log(f"RX {radio_prefix}{type_name} ({payload_type}) len={pkt.payload_len}")

        self._logger.debug(f"Received packet type {type_name}, payload length: {pkt.payload_len}")
        if pkt.payload_len > 0:
            self._logger.debug(f"Payload preview: {pkt.payload[: min(10, pkt.payload_len)].hex()}")

        handler = self._get_handler(payload_type)
        if not handler:
            self._log(f"No handler for payload {type_name}")
            return

        try:
            if self._is_transit_direct_delivery(pkt, payload_type):
                # Firmware releases this packet without payload processing; the
                # forwarding decision is made independently (see
                # _build_client_repeat_forward / an application router).
                self._log(
                    f"Transit {type_name}: routed-direct with "
                    f"{pkt.get_path_hash_count()} hop(s) left, not delivered locally"
                )
            else:
                result = await handler(pkt)
                # Mirror firmware Mesh::onRecvPacket markDoNotRetransmit: a data or
                # anon packet genuinely decrypted for this identity is consumed and
                # must not be re-flooded. HandlerResult.authenticated is that
                # verdict (False on a bare dest-hash collision), so the client-repeat
                # flood forward is suppressed only on real consumption. ACK marking
                # is done inside AckHandler (it does not return a HandlerResult).
                if isinstance(result, HandlerResult) and result.authenticated:
                    pkt.mark_do_not_retransmit()
            if self.packet_received_callback:
                await self._invoke_callback(self.packet_received_callback, pkt)
        except Exception as err:
            self._log(f"Handler error for {type_name}: {err}")

    def _is_transit_direct_delivery(self, pkt: Packet, payload_type: int) -> bool:
        """True when a local-delivery handler must be skipped for a transit packet.

        MeshCore ``Mesh::onRecvPacket`` never runs payload processing for a
        routed-direct packet that still has hops on its path: it peeks at an
        early ACK, forwards the packet if this node is the next hop (stripping
        itself first, so delivery only ever happens at hop count 0), and
        otherwise releases it. Payload delivery for a direct packet therefore
        only happens once the path is exhausted.

        openHop's ``_dispatch`` serves both local delivery and, for applications
        like the repeater, routing — so the rule is applied only to handlers
        registered with ``local_delivery=True``. Without it a node that hears
        both a peer's pre-relay transmission and the relay's retransmission
        delivers the same DM twice: the copies share a path-independent packet
        hash, and dedup no longer suppresses the un-stripped one (it must not,
        or an overheard route variant would suppress a copy this node owns).
        """
        if payload_type not in self._local_delivery_types:
            return False
        return pkt.is_route_direct() and pkt.get_path_hash_count() > 0

    # ------------------------------------------------------------------
    # ACK registration system
    #
    # Simple interface for handlers to notify dispatcher when ACKs are received.
    # All ACK processing logic is delegated to the AckHandler.
    # ------------------------------------------------------------------

    async def _register_ack_received(self, crc: int) -> bool:
        """Record that an ACK with the given CRC was received.

        Returns whether an application listener reported consuming the CRC
        (matched a send it tracks app-side), so the ACK handler can mark the
        packet do-not-retransmit (firmware onAckRecv). A dispatcher-level
        waiter is reported separately by the handler via ``_waiting_acks``.
        """
        ts = asyncio.get_running_loop().time()
        self._recent_acks[crc] = ts

        # Notify waiting sender if this CRC matches
        if evt := self._waiting_acks.pop(crc, None):
            self._log(f"ACK matched! CRC {crc:08X}")
            evt.set()

        if self._ack_received_listener:
            return bool(await self._invoke_ack_listener(crc))
        return False

    async def run_forever(self) -> None:
        """Run the dispatcher maintenance loop until :meth:`stop` is awaited.

        Call this in an asyncio task. Re-arming RX on entry supports restart
        after a previous stop. The loop exits cooperatively when the stop
        event is set (checked at least once per second).
        """
        # Sync prelude runs until the first await below, so a concurrent
        # stop() cannot interleave between these assignments.
        stop_event, stopped_event = self._ensure_lifecycle_events()
        stop_event.clear()
        stopped_event.clear()
        self._run_forever_active = True
        self._arm_rx()
        health_check_counter = 0
        try:
            while not stop_event.is_set():
                # Clean out old ACK CRCs (older than 5 seconds)
                now = asyncio.get_running_loop().time()
                self._recent_acks = {
                    crc: ts for crc, ts in self._recent_acks.items() if now - ts < 5
                }

                # Clean old packet hashes for deduplication
                self.packet_filter.cleanup_old_hashes()

                # Simple health check every 60 seconds
                health_check_counter += 1
                if health_check_counter >= 60:
                    health_check_counter = 0
                    if hasattr(self.radio, "check_radio_health"):
                        await asyncio.to_thread(self.radio.check_radio_health)

                # Wait for stop or the next maintenance tick
                try:
                    await asyncio.wait_for(stop_event.wait(), timeout=1.0)
                except asyncio.TimeoutError:
                    pass
        finally:
            self._run_forever_active = False
            self._disarm_rx()
            stopped_event.set()

    async def stop(self) -> None:
        """Disarm RX and exit :meth:`run_forever` cooperatively. Idempotent.

        Does not cancel in-flight packet tasks or close the radio; callers
        own hardware lifecycle. If the maintenance loop is not running,
        returns after disarming without waiting.
        """
        stop_event, stopped_event = self._ensure_lifecycle_events()
        self._disarm_rx()
        stop_event.set()
        if not self._run_forever_active:
            # A just-scheduled run_forever may clear the stop event during its
            # sync prelude; yield and re-assert so that race still exits.
            await asyncio.sleep(0)
            stop_event.set()
            self._disarm_rx()
            if not self._run_forever_active:
                return
        await stopped_event.wait()

    # ------------------------------------------------------------------
    # Internal helper methods
    # ------------------------------------------------------------------

    async def _rx_once(self) -> None:
        """Fallback RX method for radios that don't support callbacks."""
        try:
            data = await self.radio.wait_for_rx()
        except Exception as err:
            self._log(f"Radio RX error: {err}")
            return

        # Process the received packet using the same method as callbacks
        await self._process_received_packet(data)

    async def _invoke_callback(self, cb, pkt: Packet) -> None:
        await invoke_maybe_awaitable(cb, pkt)

    async def _invoke_ack_listener(self, crc: int) -> Optional[bool]:
        """Invoke the ack-received listener (sync or async) and return its result.

        Per :data:`AckReceivedCallback`, the listener reports whether the CRC matched one of this
        node's own pending sends; the caller propagates that to the do-not-retransmit decision.
        """
        cb = self._ack_received_listener
        if cb is None:
            return None
        return bool(await invoke_maybe_awaitable(cb, crc))

    async def _invoke_enhanced_raw_callback(
        self, callback, pkt: Packet, data: bytes, analysis: dict
    ) -> None:
        """Call raw packet callback with extra analysis data.

        Concrete signatures (no *args/**kwargs) are bound once so a handler
        exception is never retried as a 2-arg call. Variadic or uninspectable
        callables try the enhanced form first and fall back to 2-arg only on
        TypeError, so bare decorators around legacy 2-arg handlers still work.
        """
        try:
            # signature() follows __wrapped__ when present (functools.wraps).
            sig = inspect.signature(callback)
            is_variadic = any(
                p.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)
                for p in sig.parameters.values()
            )
        except (ValueError, TypeError):
            sig = None
            is_variadic = True

        if not is_variadic:
            use_enhanced = True
            try:
                sig.bind(pkt, data, analysis)
            except TypeError:
                try:
                    sig.bind(pkt, data)
                    use_enhanced = False
                except TypeError:
                    use_enhanced = True
            try:
                if use_enhanced:
                    await invoke_maybe_awaitable(callback, pkt, data, analysis)
                else:
                    await invoke_maybe_awaitable(callback, pkt, data)
            except Exception as e:
                self._log(f"Raw callback error: {e}")
            return

        # Variadic / uninspectable: try enhanced, TypeError-only 2-arg rescue.
        try:
            await invoke_maybe_awaitable(callback, pkt, data, analysis)
        except TypeError as e:
            self._log(f"Raw callback error: {e}")
            try:
                await invoke_maybe_awaitable(callback, pkt, data)
            except Exception as e2:
                self._log(f"Fallback raw callback error: {e2}")
        except Exception as e:
            self._log(f"Raw callback error: {e}")

    # ------------------------------------------------------------------
    # Logging helper
    # ------------------------------------------------------------------
    def _log(self, msg: str) -> None:
        self._logger.info(msg)

    def get_filter_stats(self) -> dict:
        """Get current packet filter statistics."""
        stats = self.packet_filter.get_stats()
        stats["tx_lock_locked"] = self._tx_lock.locked()
        return stats

    def clear_packet_filter(self) -> None:
        """Clear packet filter data."""
        self.packet_filter.clear()
        self._log("Packet filter cleared")

    async def _find_contact_by_hash(self, src_hash: int):
        """Find contact by source hash. Returns None if not found or no contacts available."""
        if not self.contact_book:
            self._log("Contact book not available for PATH decryption")
            return None

        for contact in self.contact_book.contacts:
            try:
                if contact.public_key:
                    if bytes.fromhex(contact.public_key)[0] == src_hash:
                        return contact
            except Exception:
                continue
        return None

    def cleanup(self):
        """Sync signal to stop the maintenance loop and disarm RX.

        Does not await loop exit. Prefer ``await stop()`` for awaitable
        shutdown from an async caller.
        """
        self._disarm_rx()
        if self._stop_event is not None:
            self._stop_event.set()
        self._log("Dispatcher cleanup completed")
