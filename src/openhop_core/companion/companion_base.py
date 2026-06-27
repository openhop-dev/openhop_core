"""
CompanionBase - Shared logic for CompanionRadio and CompanionBridge.

Provides stores, event handling, contact management, device configuration,
and push callbacks. Subclasses implement TX via MeshNode or packet_injector.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import logging
import random
import struct
import time
from abc import ABC, abstractmethod
from collections import OrderedDict
from typing import Any, Callable, Iterable, Optional

from ..node.events import EventService, EventSubscriber, MeshEvents
from ..protocol import LocalIdentity, Packet, PacketBuilder
from ..protocol.constants import (
    ADVERT_FLAG_HAS_LOCATION,
    ADVERT_FLAG_HAS_NAME,
    ADVERT_FLAG_IS_CHAT_NODE,
    ADVERT_FLAG_IS_REPEATER,
    ADVERT_FLAG_IS_ROOM_SERVER,
    ADVERT_FLAG_IS_SENSOR,
    MAX_PACKET_PAYLOAD,
    MAX_PATH_SIZE,
    PAYLOAD_TYPE_ADVERT,
    PAYLOAD_TYPE_CONTROL,
    PAYLOAD_TYPE_GRP_DATA,
    PH_ROUTE_MASK,
    PUB_KEY_SIZE,
    REQ_TYPE_GET_STATUS,
    REQ_TYPE_GET_TELEMETRY_DATA,
    ROUTE_TYPE_DIRECT,
    ROUTE_TYPE_FLOOD,
    ROUTE_TYPE_TRANSPORT_FLOOD,
    TELEM_PERM_BASE,
)
from ..protocol.crypto import CryptoUtils
from ..protocol.packet_utils import PathUtils
from ..protocol.transport_keys import calc_transport_code, get_auto_key_for
from .channel_store import ChannelStore
from .constants import (
    ADV_TYPE_CHAT,
    ADV_TYPE_NONE,
    ADV_TYPE_REPEATER,
    ADV_TYPE_ROOM,
    ADV_TYPE_SENSOR,
    ADVERT_LOC_SHARE,
    AUTOADD_CHAT,
    AUTOADD_OVERWRITE_OLDEST,
    AUTOADD_REPEATER,
    AUTOADD_ROOM,
    AUTOADD_SENSOR,
    DEFAULT_MAX_CHANNELS,
    DEFAULT_MAX_CONTACTS,
    DEFAULT_OFFLINE_QUEUE_SIZE,
    DEFAULT_RESPONSE_TIMEOUT_MS,
    MAX_PENDING_ACK_CRCS,
    MAX_SIGN_DATA_SIZE,
    PROTOCOL_CODE_ANON_REQ,
    PROTOCOL_CODE_BINARY_REQ,
    PROTOCOL_CODE_RAW_DATA,
    PUSH_CODE_TELEMETRY_RESPONSE,
    STATS_TYPE_CORE,
    STATS_TYPE_PACKETS,
    STATS_TYPE_RADIO,
    TXT_TYPE_CLI_DATA,
    TXT_TYPE_PLAIN,
)
from .contact_store import ContactStore
from .message_queue import MessageQueue
from .models import AdvertPath, Channel, Contact, NodePrefs, QueuedMessage, SentResult
from .path_cache import PathCache
from .stats_collector import StatsCollector
from .timing import DEFAULT_MAX_ATTEMPTS, response_timeout_ms

logger = logging.getLogger("CompanionBase")

ZERO_FLOOD_SCOPE_KEY = b"\x00" * 16


def _fmt_path(out_path_len: int, out_path: Any) -> str:
    """Format a contact's out_path for [PATHDIAG] logs without ambiguity.

    ``out_path_len`` is the firmware-encoded path_len byte, not a hop count:
    the top 2 bits are (hash_size - 1) and the low 6 bits are the hop count.
    E.g. 0x42 == hash_size 2, 2 hops -> 4 path bytes. Render the decoded form
    plus the path as hex so the byte value is never misread as a hop count.
    """
    if out_path_len is None or out_path_len < 0:
        return "unknown (out_path_len=-1, flood)"
    if isinstance(out_path, (bytes, bytearray)):
        path_hex = bytes(out_path).hex()
    elif isinstance(out_path, (list, tuple)):
        path_hex = bytes(int(b) & 0xFF for b in out_path).hex()
    else:
        path_hex = str(out_path)
    return (
        f"path_len_byte=0x{out_path_len & 0xFF:02X} "
        f"(hash_size={PathUtils.get_path_hash_size(out_path_len)}, "
        f"hops={PathUtils.get_path_hash_count(out_path_len)}) "
        f"path={path_hex or '(empty)'}"
    )


PUSH_CALLBACK_KEYS = [
    "message_received",
    "channel_message_received",
    "channel_data_received",
    "advert_received",
    "contact_path_updated",
    "send_confirmed",
    "trace_received",
    "node_discovered",
    "login_result",
    "telemetry_response",
    "status_response",
    "raw_data_received",
    "rx_log_data",  # raw RX with SNR/RSSI (CompanionRadio only; matches PUSH 0x88)
    "binary_response",
    "path_discovery_response",
    "contact_deleted",
    "contacts_full",
    "channel_updated",
]


class ResponseWaiter:
    """Helper for awaiting async protocol/login responses."""

    def __init__(self) -> None:
        self.event = asyncio.Event()
        self.data: dict = {"success": False, "text": None, "parsed": {}}

    def callback(
        self,
        success: bool,
        text: str,
        parsed_data: Optional[dict] = None,
    ) -> None:
        self.data["success"] = success
        self.data["text"] = text
        self.data["parsed"] = parsed_data or {}
        self.event.set()

    async def wait(self, timeout: float = 10.0) -> dict:
        try:
            await asyncio.wait_for(self.event.wait(), timeout=timeout)
            return self.data
        except asyncio.TimeoutError:
            return {**self.data, "timeout": True}


class _CompanionEventSubscriber(EventSubscriber):
    """Bridges event service to companion push callbacks."""

    def __init__(self, companion: CompanionBase) -> None:
        self._companion = companion

    async def handle_event(self, event_type: str, data: dict) -> None:
        await self._companion._handle_mesh_event(event_type, data)


def adv_type_to_flags(adv_type: int) -> int:
    """Convert ADV_TYPE_* constant to advertisement flags byte."""
    if adv_type == ADV_TYPE_CHAT:
        return ADVERT_FLAG_IS_CHAT_NODE
    elif adv_type == ADV_TYPE_REPEATER:
        return ADVERT_FLAG_IS_REPEATER
    elif adv_type == ADV_TYPE_ROOM:
        return ADVERT_FLAG_IS_ROOM_SERVER
    elif adv_type == ADV_TYPE_SENSOR:
        return ADVERT_FLAG_IS_SENSOR
    return ADVERT_FLAG_IS_CHAT_NODE


class CompanionBase(ABC):
    """Abstract base class for companion implementations.

    Provides shared stores, event handling, contact management, device config,
    and push callbacks. Subclasses implement TX (via node or packet_injector).
    """

    def _init_companion_stores(
        self,
        identity: LocalIdentity,
        node_name: str = "pyMC",
        adv_type: int = ADV_TYPE_CHAT,
        max_contacts: int = DEFAULT_MAX_CONTACTS,
        max_channels: int = DEFAULT_MAX_CHANNELS,
        offline_queue_size: int = DEFAULT_OFFLINE_QUEUE_SIZE,
        radio_config: Optional[dict] = None,
        initial_contacts: Optional[Iterable[Contact]] = None,
    ) -> None:
        """Initialize shared stores, prefs, event service, and push callbacks."""
        self._identity = identity
        self._radio_config = radio_config or {}
        self._running = False

        self.contacts = ContactStore(max_contacts)
        self.channels = ChannelStore(max_channels)
        self.message_queue = MessageQueue(offline_queue_size)
        self.path_cache = PathCache()
        self.stats = StatsCollector()

        self.prefs = NodePrefs(
            node_name=node_name,
            adv_type=adv_type,
            tx_power_dbm=self._radio_config.get(
                "power", self._radio_config.get("tx_power", 20)
            ),
            frequency_hz=self._radio_config.get("frequency", 915000000),
            bandwidth_hz=self._radio_config.get("bandwidth", 250000),
            spreading_factor=self._radio_config.get("spreading_factor", 10),
            coding_rate=self._radio_config.get("coding_rate", 5),
        )

        self._custom_vars: dict[str, str] = {}
        self._sign_buffer: Optional[bytearray] = None
        self._flood_transport_key: Optional[bytes] = None
        # Sticky "force unscoped flood" flag (FW PR #2492 / FIRMWARE_VER_CODE 12+):
        # when set, floods ignore the default scope until a scope override/reset.
        self._flood_unscoped: bool = False
        self._time_offset: float = 0.0

        self._event_service = EventService()
        self._event_subscriber = _CompanionEventSubscriber(self)
        self._event_service.subscribe_all(self._event_subscriber)

        self._push_callbacks: dict[str, list[Callable]] = {
            k: [] for k in PUSH_CALLBACK_KEYS
        }

        # Pending binary requests by tag (hex) for matching responses
        self._pending_binary_requests: dict[str, dict] = {}
        # Pending path discovery tags for matching responses
        self._pending_discovery_tags: set[int] = set()
        # Pending ACK CRCs for send_confirmed (Bridge and Radio)
        self._pending_ack_crcs: set[int] = set()

        # GRP_TXT dedup by packet hash: match Mesh.cpp (!_tables->hasSeen(pkt));
        # companion queues one frame per logical message like the firmware.
        self._seen_grp_txt: OrderedDict[str, float] = OrderedDict()
        self._seen_grp_txt_ttl = 300
        self._seen_grp_txt_max = 1000
        # TXT_MSG (direct) dedup by packet hash so reconnects don't re-queue same packet.
        self._seen_txt: OrderedDict[str, float] = OrderedDict()
        self._seen_txt_ttl = 300
        self._seen_txt_max = 1000
        # GRP_DATA dedup by packet hash so sync_next_message only returns one entry per packet.
        self._seen_grp_data: OrderedDict[str, float] = OrderedDict()
        self._seen_grp_data_ttl = 300
        self._seen_grp_data_max = 1000

        # Allow subclasses to restore persisted preferences on startup.
        self._load_prefs()

        # Optional bulk load of contacts (e.g. from persistence on boot).
        if initial_contacts is not None:
            self.contacts.load_from(initial_contacts)

    # -------------------------------------------------------------------------
    # Preference Persistence Hooks
    # -------------------------------------------------------------------------

    def _save_prefs(self) -> None:
        """Hook: persist the current :attr:`prefs` to stable storage.

        The default implementation is a no-op — preferences live only in
        memory.  Subclasses that need persistence (e.g. backed by SQLite or
        a JSON file) should override this method.

        Called automatically after any preference-mutating method
        (``set_radio_params``, ``set_tx_power``, ``set_tuning_params``,
        ``set_autoadd_config``, ``set_other_params``,
        ``set_advert_name``, ``set_advert_latlon``).
        """

    def _load_prefs(self) -> None:
        """Hook: restore :attr:`prefs` from stable storage on startup.

        The default implementation is a no-op.  Subclasses should override
        to populate :attr:`self.prefs` fields from their persistence layer.

        Called once at the end of :meth:`_init_companion_stores`.
        """

    # -------------------------------------------------------------------------
    # Contact Management
    # -------------------------------------------------------------------------

    def get_contacts(self, since: int = 0) -> list[Contact]:
        """Return all contacts, optionally filtered by modification time.

        Transient/anon contacts (ADV_TYPE_NONE) created for non-contact anon
        requests are excluded — they are never synced to the app, mirroring the
        firmware contacts iterator in MyMesh::checkSerialInterface.
        """
        return [
            c for c in self.contacts.get_all(since=since) if c.adv_type != ADV_TYPE_NONE
        ]

    def get_contact_by_key(self, pub_key: bytes) -> Optional[Contact]:
        """Look up a contact by its full 32-byte public key."""
        return self.contacts.get_by_key(pub_key)

    def get_contact_by_name(self, name: str) -> Optional[Contact]:
        """Look up a contact by name, returning the full Contact or None."""
        proxy = self.contacts.get_by_name(name)
        if proxy:
            return self.contacts.get_by_key(bytes.fromhex(proxy.public_key))
        return None

    def add_update_contact(self, contact: Contact) -> bool:
        """Add or update a contact, setting lastmod if unset."""
        if contact.lastmod == 0:
            contact.lastmod = int(time.time())
        return self.contacts.add(contact)

    def remove_contact(self, pub_key: bytes) -> bool:
        """Remove a contact by public key."""
        return self.contacts.remove(pub_key)

    def export_contact(self, pub_key: Optional[bytes] = None) -> Optional[bytes]:
        """Export a contact (or self) as a 73-byte binary packet."""
        if pub_key is None:
            key = self._identity.get_public_key()
            name = self.prefs.node_name.encode("utf-8")[:32]
            name = name + b"\x00" * (32 - len(name))
            lat = int(self.prefs.latitude * 1e6)
            lon = int(self.prefs.longitude * 1e6)
            return struct.pack(
                "<32sB32sii",
                key,
                self.prefs.adv_type,
                name,
                lat,
                lon,
            )
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return None
        name = contact.name.encode("utf-8")[:32]
        name = name + b"\x00" * (32 - len(name))
        lat = int(contact.gps_lat * 1e6)
        lon = int(contact.gps_lon * 1e6)
        return struct.pack(
            "<32sB32sii",
            contact.public_key,
            contact.adv_type,
            name,
            lat,
            lon,
        )

    def import_contact(self, packet_data: bytes) -> bool:
        """Import a contact from a 73-byte binary packet."""
        if len(packet_data) < 73:
            logger.warning(f"Import data too short: {len(packet_data)} bytes")
            return False
        try:
            pub_key = packet_data[:32]
            adv_type = packet_data[32]
            name_raw = packet_data[33:65]
            lat, lon = struct.unpack_from("<ii", packet_data, 65)
            name = name_raw.split(b"\x00")[0].decode("utf-8", errors="replace")
            contact = Contact(
                public_key=pub_key,
                name=name,
                adv_type=adv_type,
                gps_lat=lat / 1e6,
                gps_lon=lon / 1e6,
                lastmod=int(time.time()),
            )
            return self.contacts.add(contact)
        except Exception as e:
            logger.error(f"Error importing contact: {e}")
            return False

    # -------------------------------------------------------------------------
    # Device Configuration
    # -------------------------------------------------------------------------

    def set_advert_name(self, name: str) -> None:
        """Set the node's advertised name (max 31 chars)."""
        self.prefs.node_name = name[:31]
        self._save_prefs()
        self._sync_our_node_name_to_handlers()

    def _get_group_text_handler(self) -> Optional[Any]:
        """Return the group text handler for name sync, or None. Override in Radio/Bridge."""
        return None

    def _sync_our_node_name_to_handlers(self) -> None:
        """Sync node name to group text handler for echo detection."""
        handler = self._get_group_text_handler()
        if handler is not None:
            handler.set_our_node_name(self.prefs.node_name)

    def set_advert_latlon(self, lat: float, lon: float) -> None:
        """Set the GPS coordinates included in advertisements."""
        if not (-90.0 <= lat <= 90.0):
            raise ValueError(f"Latitude out of range: {lat}")
        if not (-180.0 <= lon <= 180.0):
            raise ValueError(f"Longitude out of range: {lon}")
        self.prefs.latitude = lat
        self.prefs.longitude = lon
        self._save_prefs()

    def set_radio_params(self, freq_hz: int, bw_hz: int, sf: int, cr: int) -> bool:
        """Set radio parameters (frequency, bandwidth, SF, CR)."""
        if not (5 <= sf <= 12):
            raise ValueError(f"Spreading factor out of range: {sf}")
        if not (5 <= cr <= 8):
            raise ValueError(f"Coding rate out of range: {cr}")
        self.prefs.frequency_hz = freq_hz
        self.prefs.bandwidth_hz = bw_hz
        self.prefs.spreading_factor = sf
        self.prefs.coding_rate = cr
        self._save_prefs()
        return True

    def set_tx_power(self, power_dbm: int) -> bool:
        """Set the transmit power in dBm."""
        self.prefs.tx_power_dbm = power_dbm
        self._save_prefs()
        return True

    def set_tuning_params(self, rx_delay: float, airtime_factor: float) -> None:
        """Set RX delay and airtime factor tuning parameters."""
        self.prefs.rx_delay_base = rx_delay
        self.prefs.airtime_factor = airtime_factor
        self._save_prefs()

    def get_tuning_params(self) -> tuple[float, float]:
        """Return the current (rx_delay, airtime_factor) tuning parameters."""
        return (self.prefs.rx_delay_base, self.prefs.airtime_factor)

    def get_radio_params(self) -> dict:
        """Return current radio configuration (frequency, bandwidth, SF, CR, TX power, tuning).

        Use this to fetch the radio configuration details. Keys match the arguments
        to set_radio_params/set_tx_power/set_tuning_params: frequency_hz, bandwidth_hz,
        spreading_factor, coding_rate, tx_power_dbm, rx_delay_base, airtime_factor.
        """
        return {
            "frequency_hz": self.prefs.frequency_hz,
            "bandwidth_hz": self.prefs.bandwidth_hz,
            "spreading_factor": self.prefs.spreading_factor,
            "coding_rate": self.prefs.coding_rate,
            "tx_power_dbm": self.prefs.tx_power_dbm,
            "rx_delay_base": self.prefs.rx_delay_base,
            "airtime_factor": self.prefs.airtime_factor,
        }

    def get_time(self) -> int:
        """Return the current device time as a Unix timestamp."""
        return int(time.time() + self._time_offset)

    def set_time(self, secs: int) -> bool:
        """Set the device time.  Returns False if *secs* is in the past."""
        current = self.get_time()
        if secs < current:
            return False
        self._time_offset = secs - time.time()
        return True

    def set_other_params(
        self,
        manual_add: int,
        telemetry_modes: int,
        advert_loc_policy: int,
        multi_acks: int,
    ) -> None:
        """Set additional node parameters (manual add, telemetry, location, multi-acks)."""
        self.prefs.manual_add_contacts = manual_add
        self.prefs.telemetry_mode_base = telemetry_modes & 0x03
        self.prefs.telemetry_mode_location = (telemetry_modes >> 2) & 0x03
        self.prefs.telemetry_mode_environment = (telemetry_modes >> 4) & 0x03
        self.prefs.advert_loc_policy = advert_loc_policy
        self.prefs.multi_acks = multi_acks
        self._save_prefs()

    def set_path_hash_mode(self, mode: int) -> None:
        """Set path hash encoding mode (0=1-byte, 1=2-byte, 2=3-byte hashes)."""
        self.prefs.path_hash_mode = mode
        self._save_prefs()

    def get_self_info(self) -> NodePrefs:
        """Return a copy of the current node preferences."""
        return copy.copy(self.prefs)

    def get_public_key(self) -> bytes:
        """Return this node's 32-byte Ed25519 public key."""
        return self._identity.get_public_key()

    # -------------------------------------------------------------------------
    # Path & Routing
    # -------------------------------------------------------------------------

    def reset_path(self, pub_key: bytes) -> bool:
        """Reset the outbound routing path for a contact."""
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return False
        contact.out_path_len = -1
        contact.out_path = b""
        self.contacts.update(contact)
        return True

    def get_advert_path(self, pub_key_prefix: bytes) -> Optional[AdvertPath]:
        """Look up a cached advert path by public key prefix."""
        return self.path_cache.get_by_prefix(pub_key_prefix)

    # -------------------------------------------------------------------------
    # Channel Management
    # -------------------------------------------------------------------------

    def get_channel(self, idx: int) -> Optional[Channel]:
        """Return the channel at the given index, or None."""
        return self.channels.get(idx)

    def set_channel(self, idx: int, name: str, secret: bytes) -> bool:
        """Set a channel at the given index with name and 32-byte secret."""
        # MeshCore DataStore uses 32-byte secret; GroupTextHandler uses up to 32 for HMAC
        if len(secret) < 32:
            secret = secret + b"\x00" * (32 - len(secret))
        elif len(secret) > 32:
            secret = secret[:32]
        ok = self.channels.set(idx, Channel(name=name[:32], secret=secret))
        if ok:
            ch = self.channels.get(idx)
            self._schedule_fire_callbacks("channel_updated", idx, ch)
        return ok

    def remove_channel(self, idx: int) -> bool:
        """Remove the channel at the given index. Fires on_channel_updated(idx, None)."""
        ok = self.channels.remove(idx)
        if ok:
            self._schedule_fire_callbacks("channel_updated", idx, None)
        return ok

    # -------------------------------------------------------------------------
    # Signing Pipeline
    # -------------------------------------------------------------------------

    def sign_start(self) -> int:
        """Begin a signing session; returns the maximum sign buffer size."""
        self._sign_buffer = bytearray()
        return MAX_SIGN_DATA_SIZE

    def sign_data(self, data: bytes) -> bool:
        """Append data to the signing buffer."""
        if self._sign_buffer is None:
            logger.warning("sign_data called without sign_start")
            return False
        if len(self._sign_buffer) + len(data) > MAX_SIGN_DATA_SIZE:
            logger.warning("Sign data would overflow buffer")
            return False
        self._sign_buffer.extend(data)
        return True

    def sign_finish(self) -> Optional[bytes]:
        if self._sign_buffer is None:
            logger.warning("sign_finish called without sign_start")
            return None
        try:
            return self._identity.sign(bytes(self._sign_buffer))
        except Exception as e:
            logger.error(f"Signing error: {e}")
            return None
        finally:
            self._sign_buffer = None

    # -------------------------------------------------------------------------
    # Key Management
    # -------------------------------------------------------------------------

    def export_private_key(self) -> bytes:
        """Return the raw signing key bytes for backup/export."""
        return self._identity.get_signing_key_bytes()

    # -------------------------------------------------------------------------
    # Flood Scope
    # -------------------------------------------------------------------------

    def set_flood_scope(self, transport_key: Optional[bytes] = None) -> None:
        """Set or clear the transient flood scope override.

        Also cancels any pending explicit-unscoped request (firmware sets
        ``send_unscoped = false`` whenever a scope override is set or reset).
        """
        self._flood_unscoped = False

        if transport_key and len(transport_key) >= 16:
            key = bytes(transport_key[:16])
            self._flood_transport_key = None if key == ZERO_FLOOD_SCOPE_KEY else key
            return

        self._flood_transport_key = None

    def set_flood_unscoped(self) -> None:
        """Force following floods to be unscoped, bypassing the default scope.

        Mirrors firmware CMD_SET_FLOOD_SCOPE_KEY mode 1 (FW PR #2492): a sticky
        flag cleared by the next scope override/reset.
        """
        self._flood_unscoped = True

    def set_default_flood_scope(
        self,
        scope_name: Optional[str],
        transport_key: Optional[bytes],
    ) -> bool:
        """Persist default flood scope (v1.15 companion protocol semantics)."""
        if not scope_name or not transport_key or len(transport_key) < 16:
            self.prefs.default_scope_name = ""
            self.prefs.default_scope_key = b""
            self._save_prefs()
            return True
        normalized = scope_name[:30].strip()
        if not normalized:
            return False
        self.prefs.default_scope_name = normalized
        self.prefs.default_scope_key = bytes(transport_key[:16])
        self._save_prefs()
        return True

    def get_default_flood_scope(self) -> Optional[tuple[str, bytes]]:
        """Return (name, key) for persisted default scope, or None if unset."""
        name = (getattr(self.prefs, "default_scope_name", "") or "").strip()
        key = getattr(self.prefs, "default_scope_key", b"") or b""
        key = bytes(key[:16]).ljust(16, b"\x00") if key else b""
        if not name or key == b"\x00" * 16:
            return None
        return (name, key)

    def set_flood_region(self, region_name: Optional[str] = None) -> None:
        """Set flood scope from a region name (e.g., ``'#usa'``) or clear it.

        Derives the 16-byte transport key automatically via SHA-256 of the
        region name.  A leading ``#`` is added if not already present.
        Pass ``None`` to clear this transient region override.
        """
        if region_name:
            if not region_name.startswith("#"):
                region_name = f"#{region_name}"
            self._flood_transport_key = get_auto_key_for(region_name)
            self._flood_unscoped = False
        else:
            self._flood_transport_key = None
            self._flood_unscoped = False

    def _resolve_flood_transport_key(self) -> Optional[bytes]:
        """Resolve effective flood key: transient override first, then default."""
        if self._flood_transport_key is not None:
            return self._flood_transport_key
        default_scope = self.get_default_flood_scope()
        if default_scope is None:
            return None
        return default_scope[1]

    def _apply_flood_scope(self, pkt: Packet) -> None:
        """Apply flood scope transport codes to a packet in-place.

        If ``_flood_transport_key`` is set and the packet uses flood routing,
        calculates the transport code, attaches it to the packet, and changes
        the route type to ``ROUTE_TYPE_TRANSPORT_FLOOD``.

        Matches firmware ``sendFloodScoped()`` in ``BaseChatMesh.cpp``.
        """
        route_type = pkt.get_route_type()
        if route_type != ROUTE_TYPE_FLOOD:
            return  # only scope flood packets, not direct
        if self._flood_unscoped:
            # App explicitly requested unscoped (FW #2492): leave as plain flood,
            # ignoring any default scope until a scope override/reset.
            return
        effective_key = self._resolve_flood_transport_key()
        if effective_key is None:
            return
        code = calc_transport_code(effective_key, pkt)
        pkt.transport_codes[0] = code
        pkt.transport_codes[1] = 0  # reserved for home region (firmware TODO)
        # Switch route type from FLOOD -> TRANSPORT_FLOOD
        pkt.header = (pkt.header & ~0x03) | ROUTE_TYPE_TRANSPORT_FLOOD

    def _apply_path_hash_mode(self, pkt: Packet) -> None:
        """Encode the device's path_hash_mode in originated packets.

        When a packet has 0 hops (freshly originated), sets bits 6-7 of
        ``path_len`` to encode the hash size from ``prefs.path_hash_mode``.
        Packets with existing hops (stored contact paths) are untouched.
        Trace packets are excluded because the repeater's trace handler uses
        ``path``/``path_len`` to store SNR values, not routing hashes.
        Sets ``_path_hash_mode_applied`` so the dispatcher does not overwrite.
        """
        pkt.apply_path_hash_mode(self.prefs.path_hash_mode, mark_applied=True)

    # -------------------------------------------------------------------------
    # Statistics (subclasses may override _get_radio_stats for STATS_TYPE_RADIO)
    # -------------------------------------------------------------------------

    def get_stats(self, stats_type: int = STATS_TYPE_PACKETS) -> dict:
        """Return statistics of the requested type (core, radio, or packets)."""
        if stats_type == STATS_TYPE_CORE:
            return {
                "uptime_secs": self.stats.get_uptime_secs(),
                "queue_len": self.message_queue.count,
                "contacts_count": self.contacts.get_count(),
                "channels_count": self.channels.get_count(),
            }
        elif stats_type == STATS_TYPE_RADIO:
            return self._get_radio_stats()
        return self.stats.get_totals()

    def _get_radio_stats(self) -> dict:
        """Override in CompanionRadio for hardware RSSI/SNR. Default: prefs only."""
        return {
            "frequency_hz": self.prefs.frequency_hz,
            "bandwidth_hz": self.prefs.bandwidth_hz,
            "spreading_factor": self.prefs.spreading_factor,
            "coding_rate": self.prefs.coding_rate,
            "tx_power_dbm": self.prefs.tx_power_dbm,
        }

    # -------------------------------------------------------------------------
    # Custom Variables
    # -------------------------------------------------------------------------

    def get_custom_vars(self) -> dict[str, str]:
        """Return a copy of all custom variables."""
        return dict(self._custom_vars)

    def set_custom_var(self, name: str, value: str) -> bool:
        """Set a custom variable by name."""
        self._custom_vars[name] = value
        return True

    # -------------------------------------------------------------------------
    # Auto-Add Configuration
    # -------------------------------------------------------------------------

    def get_autoadd_config(self) -> int:
        """Return the current auto-add configuration bitmask."""
        return self.prefs.autoadd_config

    def set_autoadd_config(self, config: int) -> None:
        """Set the auto-add configuration bitmask."""
        self.prefs.autoadd_config = config
        self._save_prefs()

    # Map ADV_TYPE_* → AUTOADD_* bitmask bits (mirrors C++ shouldAutoAddContactType)
    _AUTOADD_TYPE_MAP: dict[int, int] = {
        ADV_TYPE_CHAT: AUTOADD_CHAT,  # 1 → 0x02
        ADV_TYPE_REPEATER: AUTOADD_REPEATER,  # 2 → 0x04
        ADV_TYPE_ROOM: AUTOADD_ROOM,  # 3 → 0x08
        ADV_TYPE_SENSOR: AUTOADD_SENSOR,  # 4 → 0x10
    }

    def should_auto_add_contact_type(self, contact_type: int) -> bool:
        """Check if a contact type should be auto-added based on current preferences.

        Mirrors C++ MyMesh::shouldAutoAddContactType (MyMesh.cpp:281-304).
        """
        # manual_add_contacts bit 0 == 0  →  auto-add ALL types
        if (self.prefs.manual_add_contacts & 1) == 0:
            return True
        # Selective mode: check the type-specific bit in autoadd_config
        type_bit = self._AUTOADD_TYPE_MAP.get(contact_type, 0)
        return bool(self.prefs.autoadd_config & type_bit) if type_bit else False

    def should_overwrite_when_full(self) -> bool:
        """Check if overwrite-oldest is enabled. Mirrors C++ shouldOverwriteWhenFull."""
        return bool(self.prefs.autoadd_config & AUTOADD_OVERWRITE_OLDEST)

    async def _apply_advert_to_stores(
        self,
        contact: Contact,
        inbound_path: Optional[bytes] = None,
        *,
        path_len_encoded: Optional[int] = None,
    ) -> Optional[Contact]:
        """Apply advert to ContactStore and PathCache. Shared by Bridge and NODE_DISCOVERED.

        Mirrors C++ BaseChatMesh::onAdvertRecv (existing update, auto-add filter,
        overwrite when full). Returns the Contact if added or updated, None otherwise.
        Path cache is updated for all valid contacts (pub_key >= 7, name non-empty).

        Args:
            path_len_encoded: Encoded path_len byte from the packet. If None,
                falls back to len(inbound_path) (assumes 1-byte hashes).
        """
        try:
            if len(contact.public_key) < 7 or not contact.name:
                return None
            inbound_path = inbound_path or b""
            advert_path_len = (
                path_len_encoded if path_len_encoded is not None else len(inbound_path)
            )
            self.path_cache.update(
                AdvertPath(
                    public_key_prefix=contact.public_key[:7],
                    name=contact.name,
                    path_len=advert_path_len,
                    path=inbound_path,
                    recv_timestamp=int(time.time()),
                )
            )
            existing = self.contacts.get_by_key(contact.public_key)
            if existing is not None:
                contact.out_path_len = existing.out_path_len
                contact.out_path = existing.out_path
                contact.flags = existing.flags
                contact.sync_since = existing.sync_since
                if contact.last_advert_packet is None:
                    contact.last_advert_packet = existing.last_advert_packet
                self.contacts.update(contact)
                return contact
            if not self.should_auto_add_contact_type(contact.adv_type):
                logger.debug("Auto-add filtered: type %d not allowed", contact.adv_type)
                return None
            if self.should_overwrite_when_full() and self.contacts.is_full():
                ok, overwritten = self.contacts.add_or_overwrite(contact)
                if ok and overwritten:
                    await self._fire_callbacks("contact_deleted", overwritten)
                elif not ok:
                    await self._fire_callbacks("contacts_full")
                return contact if ok else None
            added = self.contacts.add(contact)
            if not added and self.contacts.is_full():
                await self._fire_callbacks("contacts_full")
            return contact if added else None
        except Exception as e:
            logger.error("Error applying advert to stores: %s", e)
            return None

    # -------------------------------------------------------------------------
    # Push Callbacks
    # -------------------------------------------------------------------------

    def clear_push_callbacks(self) -> None:
        """Remove all registered push callbacks.

        Called by FrameServer between client connections so that stale
        closures from a previous connection are not invoked on the next one.
        """
        for key in self._push_callbacks:
            self._push_callbacks[key].clear()

    def on_message_received(self, callback: Callable) -> None:
        self._push_callbacks["message_received"].append(callback)

    def on_channel_message_received(self, callback: Callable) -> None:
        self._push_callbacks["channel_message_received"].append(callback)

    def on_channel_data_received(self, callback: Callable) -> None:
        self._push_callbacks["channel_data_received"].append(callback)

    def on_advert_received(self, callback: Callable) -> None:
        self._push_callbacks["advert_received"].append(callback)

    def on_contact_path_updated(self, callback: Callable) -> None:
        self._push_callbacks["contact_path_updated"].append(callback)

    async def _on_contact_path_updated(
        self, pub: bytes, path_len: int, path_bytes: bytes
    ) -> None:
        """Called by ProtocolResponseHandler when contact's out_path is updated from a PATH packet.

        Matches companion firmware behaviour: PATH updates are only applied
        (and pushed to the client) for contacts that already exist in the
        store.  Unknown public keys are silently ignored.
        """
        contact = self.get_contact_by_key(pub)
        if contact is None:
            logger.debug(
                "[PATHDIAG] _on_contact_path_updated: no contact for pub=%s (ignored)",
                pub[:4].hex(),
            )
            return  # Firmware does not send PATH for non-contacts
        logger.debug(
            "[PATHDIAG] _on_contact_path_updated pub=%s name=%s %s",
            pub[:4].hex(),
            getattr(contact, "name", "?"),
            _fmt_path(path_len, path_bytes),
        )
        contact.out_path_len = path_len
        contact.out_path = path_bytes
        self.contacts.update(contact)
        await self._fire_callbacks("contact_path_updated", contact)

    def on_send_confirmed(self, callback: Callable) -> None:
        self._push_callbacks["send_confirmed"].append(callback)

    def on_trace_received(self, callback: Callable) -> None:
        self._push_callbacks["trace_received"].append(callback)

    def on_node_discovered(self, callback: Callable) -> None:
        self._push_callbacks["node_discovered"].append(callback)

    def on_login_result(self, callback: Callable) -> None:
        self._push_callbacks["login_result"].append(callback)

    def on_telemetry_response(self, callback: Callable) -> None:
        self._push_callbacks["telemetry_response"].append(callback)

    def on_status_response(self, callback: Callable) -> None:
        self._push_callbacks["status_response"].append(callback)

    def on_raw_data_received(self, callback: Callable) -> None:
        self._push_callbacks["raw_data_received"].append(callback)

    def on_rx_log_data(self, callback: Callable) -> None:
        """Register callback for raw RX with SNR/RSSI (CompanionRadio only).

        Callback(snr: float, rssi: int, raw_bytes: bytes). Same data as
        PUSH_CODE_LOG_RX_DATA (0x88). Only fired when using CompanionRadio;
        CompanionBridge does not own the radio.
        """
        self._push_callbacks["rx_log_data"].append(callback)

    def on_binary_response(self, callback: Callable) -> None:
        """Register callback for PUSH 0x8C. Callback(tag_bytes, response_data)."""
        self._push_callbacks["binary_response"].append(callback)

    def on_path_discovery_response(self, callback: Callable) -> None:
        """Register callback for path discovery 0x8D. (tag_bytes, pubkey, out_path, in_path)."""
        self._push_callbacks["path_discovery_response"].append(callback)

    def on_contact_deleted(self, callback: Callable) -> None:
        """Register callback for PUSH 0x8F (contact overwritten). Callback(pub_key_bytes)."""
        self._push_callbacks["contact_deleted"].append(callback)

    def on_contacts_full(self, callback: Callable) -> None:
        """Register callback for PUSH 0x90 (contacts store full). Callback()."""
        self._push_callbacks["contacts_full"].append(callback)

    def on_channel_updated(self, callback: Callable) -> None:
        """Register callback for channel set/remove. Callback(idx: int, channel_or_none)."""
        self._push_callbacks["channel_updated"].append(callback)

    def register_binary_request(
        self,
        tag_hex: str,
        request_type: int,
        timeout_seconds: float,
        pubkey_prefix: str = "",
        context: Optional[dict] = None,
    ) -> None:
        """Register a pending binary request. Call cleanup_expired_requests first."""
        self._pending_binary_requests[tag_hex] = {
            "request_type": request_type,
            "pubkey_prefix": pubkey_prefix,
            "expires_at": time.time() + timeout_seconds,
            "context": context or {},
        }

    def cleanup_expired_binary_requests(self) -> None:
        """Remove expired entries from _pending_binary_requests."""
        now = time.time()
        expired = [
            tag
            for tag, info in self._pending_binary_requests.items()
            if now > info["expires_at"]
        ]
        for tag in expired:
            del self._pending_binary_requests[tag]

    async def _on_binary_response(
        self,
        tag_bytes: bytes,
        response_data: bytes,
        path_info: Optional[tuple] = None,
    ) -> None:
        """Called when binary response (tag + data, optional path) received."""
        if path_info is not None:
            if await self._try_handle_path_discovery(tag_bytes, path_info):
                return
        self.cleanup_expired_binary_requests()
        tag_hex = tag_bytes.hex()
        info = self._pending_binary_requests.pop(tag_hex, None)
        if not info:
            # A decryptable response arrived but no request is waiting for this tag.
            # This is the signature of "response arrived but we already timed out"
            # (or a tag mismatch); distinct from "no response arrived at all".
            logger.debug(
                "[PATHDIAG] anon/binary response UNMATCHED tag=%s (%dB) — no pending "
                "request (arrived after timeout, or tag mismatch). pending=%s",
                tag_hex,
                len(response_data),
                list(self._pending_binary_requests.keys()),
            )
            await self._fire_callbacks("binary_response", tag_bytes, response_data)
            return
        request_type = info["request_type"]
        logger.debug(
            "[PATHDIAG] anon/binary response MATCHED tag=%s type=%s (%dB)",
            tag_hex,
            request_type,
            len(response_data),
        )
        pubkey_prefix = info.get("pubkey_prefix", "")
        context = info.get("context", {})
        parsed = None
        try:
            from . import binary_parsing

            parsed = binary_parsing.parse_binary_response(
                request_type,
                response_data,
                pubkey_prefix=pubkey_prefix,
                context=context,
            )
        except Exception as e:
            logger.debug(f"Binary response parse for type {request_type}: {e}")
        await self._fire_callbacks(
            "binary_response", tag_bytes, response_data, parsed, request_type
        )

    async def _try_handle_path_discovery(
        self, tag_bytes: bytes, path_info: tuple
    ) -> bool:
        """If tag is pending path discovery, fire path_discovery_response and return True."""
        out_path, in_path, contact_pubkey = path_info
        tag_int = int.from_bytes(tag_bytes, "little")
        if tag_int not in self._pending_discovery_tags:
            return False
        self._pending_discovery_tags.discard(tag_int)
        await self._fire_callbacks(
            "path_discovery_response",
            tag_bytes,
            contact_pubkey,
            out_path,
            in_path,
        )
        return True

    # -------------------------------------------------------------------------
    # Abstract methods (subclasses must implement)
    # -------------------------------------------------------------------------

    @abstractmethod
    async def _send_packet(self, pkt: Packet, wait_for_ack: bool = False) -> bool:
        """Send a packet via the subclass transport (radio or packet_injector)."""

    @abstractmethod
    async def start(self) -> None:
        """Start the companion."""

    @abstractmethod
    async def stop(self) -> None:
        """Stop the companion."""

    @property
    @abstractmethod
    def is_running(self) -> bool:
        """Return whether the companion is currently running."""

    @abstractmethod
    def import_private_key(self, key: bytes) -> bool:
        """Import a private key and rebuild the identity."""

    def _get_protocol_response_handler(self) -> Any:
        """Return the protocol response handler, or ``None``.

        Subclasses that support request/response methods (telemetry, status,
        binary request, etc.) must override this to return their handler.
        """
        return None

    def _get_login_response_handler(self) -> Any:
        """Return the login response handler, or ``None``."""
        return None

    def _get_text_handler(self) -> Any:
        """Return the text message handler, or ``None``."""
        return None

    def _apply_multi_acks_pref(self) -> None:
        """Push the current ``multi_acks`` pref into the text handler (best-effort)."""
        th = self._get_text_handler()
        if th is not None and hasattr(th, "set_multi_acks"):
            th.set_multi_acks(getattr(self.prefs, "multi_acks", 0))

    # -------------------------------------------------------------------------
    # Unified TX methods (shared between Radio and Bridge)
    # -------------------------------------------------------------------------

    async def advertise(self, flood: bool = True) -> bool:
        """Broadcast an advertisement packet."""
        flags = adv_type_to_flags(self.prefs.adv_type)
        flags |= ADVERT_FLAG_HAS_NAME
        lat, lon = 0.0, 0.0
        if self.prefs.advert_loc_policy == ADVERT_LOC_SHARE:
            lat, lon = self.prefs.latitude, self.prefs.longitude
            if lat != 0.0 or lon != 0.0:
                flags |= ADVERT_FLAG_HAS_LOCATION
        route = "flood" if flood else "direct"
        pkt = PacketBuilder.create_advert(
            local_identity=self._identity,
            name=self.prefs.node_name,
            lat=lat,
            lon=lon,
            flags=flags,
            route_type=route,
        )
        self._apply_flood_scope(pkt)
        self._apply_path_hash_mode(pkt)
        success = await self._send_packet(pkt, wait_for_ack=False)
        if success:
            self.stats.record_tx(is_flood=flood)
        else:
            self.stats.record_tx_error()
        return success

    async def share_contact(self, pub_key: bytes) -> bool:
        """Share a contact's advert on zero hops (direct route, empty path).

        Matches firmware ``BaseChatMesh::shareContactZeroHop``: replay the last stored
        raw ADVERT wire bytes for this contact (see ``Contact.last_advert_packet``),
        with ``Mesh::sendZeroHop``-style header/path normalization. Does not re-sign with
        the companion identity. If no blob is stored (never heard an advert for this
        contact), returns ``False``.
        """
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return False
        blob = contact.last_advert_packet
        if not blob:
            return False
        try:
            pkt = Packet()
            if not pkt.read_from(bytes(blob)):
                return False
            if pkt.get_payload_type() != PAYLOAD_TYPE_ADVERT:
                return False
            if len(pkt.payload) >= PUB_KEY_SIZE:
                embedded = bytes(pkt.payload[:PUB_KEY_SIZE])
                if embedded != pub_key:
                    logger.warning(
                        "Cached advert pubkey does not match contact key; refusing share"
                    )
                    return False
            # Mesh::sendZeroHop (non-transport): direct route, path_len=0, empty path
            pkt.header = (pkt.header & ~PH_ROUTE_MASK) | ROUTE_TYPE_DIRECT
            pkt.transport_codes = [0, 0]
            pkt.path_len = 0
            pkt.path = bytearray()
            return await self._send_packet(pkt, wait_for_ack=False)
        except Exception as e:
            logger.error(f"Error sharing contact: {e}")
            return False

    async def send_trace_path_raw(
        self,
        tag: int,
        auth_code: int,
        flags: int,
        path_bytes: bytes,
    ) -> bool:
        """Send a trace packet with an explicit path."""
        try:
            path_list = list(path_bytes)
            pkt = PacketBuilder.create_trace(tag, auth_code, flags, path=path_list)
            self._apply_flood_scope(pkt)
            self._apply_path_hash_mode(pkt)
            return await self._send_packet(pkt, wait_for_ack=False)
        except Exception as e:
            logger.error(f"Error sending trace (raw path): {e}")
            return False

    async def send_binary_req(
        self, pub_key: bytes, data: bytes, timeout_seconds: float = 15.0
    ) -> SentResult:
        """Send binary request (CMD_SEND_BINARY_REQ).

        data = request_type(1) + optional payload.
        Returns SentResult with expected_ack (4-byte tag as int) and timeout_ms.
        """
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return SentResult(success=False)
        # Resolve by exact public key, not name: two contacts can share a name
        # (e.g. a re-keyed node) and get_by_name returns the first match, which
        # would encrypt/route to the wrong key.
        proxy = self.contacts.get_proxy_by_key(pub_key)
        if not proxy:
            return SentResult(success=False)
        request_type = data[0] if len(data) >= 1 else 0
        # C++ companion pattern (BaseChatMesh::sendRequest):
        #   tag = getRTCClock()->getCurrentTimeUnique()
        #   memcpy(temp, &tag, 4);  memcpy(&temp[4], req_data, data_len);
        # create_protocol_request packs: timestamp(4) + protocol_code(1) + extra_data.
        # The repeater echoes sender_timestamp (bytes 0-3) in the response.
        # So the timestamp IS the tag — we capture it from create_protocol_request.
        protocol_code = request_type
        req_payload = data[1:]  # request params only; timestamp provides uniqueness
        self.cleanup_expired_binary_requests()
        try:
            pkt, timestamp = PacketBuilder.create_protocol_request(
                contact=proxy,
                local_identity=self._identity,
                protocol_code=protocol_code,
                data=req_payload,
            )
            # Use the timestamp as the tag — matches what the repeater echoes back
            tag_int = timestamp
            tag_bytes = tag_int.to_bytes(4, "little")
            tag_hex = tag_bytes.hex()
            self.register_binary_request(
                tag_hex,
                request_type=request_type,
                timeout_seconds=timeout_seconds,
                pubkey_prefix=pub_key[:6].hex(),
            )
            self._apply_flood_scope(pkt)
            self._apply_path_hash_mode(pkt)
            success = await self._send_packet(pkt, wait_for_ack=False)
        except Exception as e:
            logger.error(f"Binary request send error: {e}")
            if "tag_hex" in locals():
                self._pending_binary_requests.pop(tag_hex, None)
            return SentResult(success=False)
        if not success:
            self._pending_binary_requests.pop(tag_hex, None)
            return SentResult(success=False)
        return SentResult(
            success=True,
            is_flood=contact.out_path_len <= 0,
            expected_ack=tag_int,
            timeout_ms=DEFAULT_RESPONSE_TIMEOUT_MS,
        )

    async def send_anon_req(
        self, pub_key: bytes, data: bytes, timeout_seconds: float = 15.0
    ) -> SentResult:
        """Send anonymous request (CMD_SEND_ANON_REQ), e.g. owner info.

        data = request payload (e.g. [0x07] for GET_OWNER_INFO). Response is
        delivered via on_binary_response (PUSH_CODE_BINARY_RESPONSE) like binary req.
        """
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            # FIRMWARE_VER_CODE 13+ (PR #2672): allow non-contact anon requests by
            # creating a transient zero-hop contact. Mirrors firmware sendAnonReq:
            # out_path_len=0 => direct zero-hop, type=ADV_TYPE_NONE (unknown).
            contact = Contact(
                public_key=pub_key,
                name="",
                adv_type=ADV_TYPE_NONE,
                out_path_len=0,
                out_path=b"",
                lastmod=int(time.time()),
            )
            if not self.contacts.add_transient(contact):
                return SentResult(success=False)
        # Resolve the proxy by key (anon contacts have an empty name, which
        # get_by_name would mis-match against any other empty-named contact).
        proxy = self.contacts.get_proxy_by_key(pub_key)
        if not proxy:
            return SentResult(success=False)
        request_type = PROTOCOL_CODE_ANON_REQ
        req_payload = data  # no random tag; timestamp provides uniqueness
        # The first byte is the ANON_REQ_TYPE_* sub-type (e.g. REGIONS/OWNER);
        # record it so the response can be parsed by sub-type rather than being
        # mistaken for a binary REQ_TYPE_GET_OWNER_INFO (both use code 0x07).
        anon_sub_type = req_payload[0] if len(req_payload) >= 1 else None
        self.cleanup_expired_binary_requests()
        try:
            pkt, timestamp = PacketBuilder.create_anon_request(
                contact=proxy,
                local_identity=self._identity,
                req_data=req_payload,
            )
            # Use the timestamp as the tag — matches what the repeater echoes back
            tag_int = timestamp
            tag_bytes = tag_int.to_bytes(4, "little")
            tag_hex = tag_bytes.hex()
            self._apply_flood_scope(pkt)
            self._apply_path_hash_mode(pkt)
            # Adaptive timeout (firmware calcFlood/DirectTimeoutMillisFor). This is
            # fire-and-forget: the response arrives async via the binary-response
            # push, and the client retries on this timeout hint — the same model
            # firmware uses for anon/discovery (it returns est_timeout and the host
            # app re-issues). A short adaptive hint => fast client-driven retry.
            timeout_s = self._response_timeout_s(pkt, proxy)
            self.register_binary_request(
                tag_hex,
                request_type=request_type,
                timeout_seconds=max(timeout_seconds, timeout_s * DEFAULT_MAX_ATTEMPTS),
                pubkey_prefix=pub_key[:6].hex(),
                context={"anon_sub_type": anon_sub_type},
            )
            success = await self._send_packet(pkt, wait_for_ack=False)
        except Exception as e:
            logger.error(f"Anon request send error: {e}")
            if "tag_hex" in locals():
                self._pending_binary_requests.pop(tag_hex, None)
            return SentResult(success=False)
        if not success:
            self._pending_binary_requests.pop(tag_hex, None)
            return SentResult(success=False)
        return SentResult(
            success=True,
            # Direct (incl. zero-hop, out_path_len == 0) when the path is known;
            # flood only when the out_path is unknown (-1). Mirrors create_anon_request.
            is_flood=contact.out_path_len < 0,
            expected_ack=tag_int,
            timeout_ms=int(timeout_s * 1000),
        )

    async def send_path_discovery(self, pub_key: bytes) -> bool:
        """Legacy: send path discovery without returning tag. Prefer send_path_discovery_req."""
        result = await self.send_path_discovery_req(pub_key)
        return result.success

    async def send_path_discovery_req(self, pub_key: bytes) -> SentResult:
        """Send path discovery (flood telemetry request with tag).

        Returns SentResult for RESP_CODE_SENT. When path return arrives with
        matching tag, path_discovery_response is fired (PUSH 0x8D).
        """
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return SentResult(success=False)
        # Resolve by exact public key, not name: two contacts can share a name
        # (e.g. a re-keyed node) and get_by_name returns the first match, which
        # would encrypt/route to the wrong key.
        proxy = self.contacts.get_proxy_by_key(pub_key)
        if not proxy:
            return SentResult(success=False)
        tag_int = random.randint(0, 0xFFFFFFFF)
        tag_bytes = tag_int.to_bytes(4, "little")
        inv_perm = 0xFF & ~TELEM_PERM_BASE
        req_payload = tag_bytes + bytes(
            [REQ_TYPE_GET_TELEMETRY_DATA, inv_perm, 0, 0, 0]
        )
        old_path_len = contact.out_path_len
        old_path = contact.out_path
        contact.out_path_len = -1
        contact.out_path = b""
        self.contacts.update(contact)
        try:
            pkt, _ = PacketBuilder.create_protocol_request(
                contact=proxy,
                local_identity=self._identity,
                protocol_code=REQ_TYPE_GET_TELEMETRY_DATA,
                data=req_payload,
            )
            self._apply_flood_scope(pkt)
            self._apply_path_hash_mode(pkt)
            success = await self._send_packet(pkt, wait_for_ack=False)
            if success:
                self._pending_discovery_tags.add(tag_int)
            return SentResult(
                success=success,
                is_flood=True,
                expected_ack=tag_int,
                timeout_ms=DEFAULT_RESPONSE_TIMEOUT_MS,
            )
        except Exception as e:
            logger.error(f"Error in path discovery: {e}")
            return SentResult(success=False)
        finally:
            current = self.contacts.get_by_key(pub_key)
            if current and current.out_path_len == -1:
                current.out_path_len = old_path_len
                current.out_path = old_path
                self.contacts.update(current)

    async def send_text_message(
        self,
        pub_key: bytes,
        text: str,
        txt_type: int = TXT_TYPE_PLAIN,
        attempt: int = 1,
        wait_for_ack: bool = True,
        timestamp: Optional[int] = None,
    ) -> SentResult:
        """Send a direct text message to a contact.

        When wait_for_ack is True (default), blocks until ACK or timeout.
        When wait_for_ack is False, returns as soon as the packet is handed off;
        ACK (if any) is still tracked and will trigger send_confirmed later.
        For ``txt_type == TXT_TYPE_CLI_DATA``, delivery ACK is not used on MeshCore
        repeaters; ``wait_for_ack`` is treated as False and pending ACK is not tracked.
        """
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            logger.warning(f"Contact not found for key {pub_key.hex()[:12]}...")
            return SentResult(success=False)
        # Resolve by exact public key, not name: two contacts can share a name
        # (e.g. a re-keyed node) and get_by_name returns the first match, which
        # would encrypt/route to the wrong key.
        proxy = self.contacts.get_proxy_by_key(pub_key)
        if not proxy:
            return SentResult(success=False)
        try:
            is_flood = proxy.out_path_len < 0
            msg_type = "flood" if is_flood else "direct"
            pkt, ack_crc = PacketBuilder.create_text_message(
                contact=proxy,
                local_identity=self._identity,
                message=text,
                attempt=attempt,
                message_type=msg_type,
                txt_type=txt_type,
                timestamp=timestamp,
            )
            self._apply_flood_scope(pkt)
            self._apply_path_hash_mode(pkt)
            effective_wait_ack = wait_for_ack and txt_type != TXT_TYPE_CLI_DATA
            if txt_type != TXT_TYPE_CLI_DATA:
                self._track_pending_ack(ack_crc)
            if effective_wait_ack:
                success = await self._send_packet(pkt, wait_for_ack=True)
                if success:
                    self.stats.record_tx(is_flood=is_flood)
                else:
                    self.stats.record_tx_error()
                return SentResult(
                    success=success,
                    is_flood=is_flood,
                    expected_ack=ack_crc,
                    timeout_ms=None,
                )
            success = await self._send_packet(pkt, wait_for_ack=False)
            if success:
                self.stats.record_tx(is_flood=is_flood)
            else:
                self.stats.record_tx_error()
            return SentResult(
                success=success,
                is_flood=is_flood,
                expected_ack=ack_crc,
                timeout_ms=DEFAULT_RESPONSE_TIMEOUT_MS,
            )
        except Exception as e:
            logger.error(f"Error sending text message: {e}")
            self.stats.record_tx_error()
            return SentResult(success=False)

    async def send_channel_message(self, channel_idx: int, text: str) -> bool:
        """Send a message to a channel."""
        channel = self.channels.get(channel_idx)
        if not channel:
            logger.warning(f"Channel {channel_idx} not found")
            return False
        try:
            pkt = PacketBuilder.create_group_datagram(
                group_name=channel.name,
                local_identity=self._identity,
                message=text,
                sender_name=self.prefs.node_name,
                channels_config=self.channels.get_channels(),
            )
            self._apply_flood_scope(pkt)
            self._apply_path_hash_mode(pkt)
            success = await self._send_packet(pkt, wait_for_ack=False)
            if success:
                self.stats.record_tx(is_flood=True)
            else:
                self.stats.record_tx_error()
            return success
        except Exception as e:
            logger.error(f"Error sending channel message: {e}")
            self.stats.record_tx_error()
            return False

    async def send_channel_data(
        self,
        channel_idx: int,
        data_type: int,
        payload: bytes,
        *,
        path: Optional[bytes] = None,
        path_len_encoded: Optional[int] = None,
    ) -> bool:
        """Send a group binary datagram (PAYLOAD_TYPE_GRP_DATA)."""
        channel = self.channels.get(channel_idx)
        if not channel or data_type <= 0 or data_type > 0xFFFF:
            return False
        payload = bytes(payload or b"")
        if len(payload) > 255:
            return False
        try:
            secret_bytes = bytes(channel.secret or b"")
            if len(secret_bytes) < 32:
                secret_bytes = secret_bytes + b"\x00" * (32 - len(secret_bytes))
            else:
                secret_bytes = secret_bytes[:32]

            hash_input = (
                secret_bytes[:16]
                if len(secret_bytes) >= 32 and secret_bytes[16:32] == b"\x00" * 16
                else secret_bytes
            )
            channel_hash = hashlib.sha256(hash_input).digest()[0]
            plaintext = struct.pack("<HB", data_type & 0xFFFF, len(payload)) + payload
            pkt = PacketBuilder.create_group_data_packet(
                PAYLOAD_TYPE_GRP_DATA,
                channel_hash,
                secret_bytes,
                plaintext,
                secret_bytes,
            )

            is_flood = path_len_encoded in (None, 0xFF)
            if is_flood:
                self._apply_flood_scope(pkt)
            else:
                pkt.header = (pkt.header & ~PH_ROUTE_MASK) | ROUTE_TYPE_DIRECT
                pkt.set_path(path or b"", path_len_encoded=path_len_encoded)
            self._apply_path_hash_mode(pkt)

            success = await self._send_packet(pkt, wait_for_ack=False)
            if success:
                self.stats.record_tx(is_flood=is_flood)
            else:
                self.stats.record_tx_error()
            return success
        except Exception as e:
            logger.error(f"Error sending channel data: {e}")
            self.stats.record_tx_error()
            return False

    async def send_raw_data(
        self,
        dest_key: bytes,
        data: bytes,
        path: Optional[bytes] = None,
    ) -> SentResult:
        """Send raw data to a contact via a protocol request."""
        contact = self.contacts.get_by_key(dest_key)
        if not contact:
            return SentResult(success=False)
        # Resolve the proxy by the exact public key, not by name: two contacts can
        # share a name (e.g. a node that re-keyed) and get_by_name returns the first
        # match, which would encrypt/route to the wrong key.
        proxy = self.contacts.get_proxy_by_key(dest_key)
        if not proxy:
            return SentResult(success=False)
        try:
            pkt, _ = PacketBuilder.create_protocol_request(
                contact=proxy,
                local_identity=self._identity,
                protocol_code=PROTOCOL_CODE_RAW_DATA,
                data=data,
            )
            self._apply_path_hash_mode(pkt)
            success = await self._send_packet(pkt, wait_for_ack=False)
            return SentResult(success=success)
        except Exception as e:
            logger.error(f"Error sending raw data: {e}")
            return SentResult(success=False)

    async def send_raw_data_direct(
        self, path: bytes, payload: bytes, *, path_len_encoded: int = None
    ) -> SentResult:
        """Send a raw custom packet (PAYLOAD_TYPE_RAW_CUSTOM) on the given direct path.

        No encryption or contact lookup; path and payload are supplied by the caller.
        Matches firmware CMD_SEND_RAW_DATA behaviour.

        Args:
            path_len_encoded: Encoded path_len byte. If None, assumes 1-byte hashes.
        """
        if len(payload) < 4:
            return SentResult(success=False)
        if len(path) > MAX_PATH_SIZE:
            return SentResult(success=False)
        if len(payload) > MAX_PACKET_PAYLOAD:
            return SentResult(success=False)
        try:
            pkt = PacketBuilder.create_raw_data(payload)
            pkt.set_path(path, path_len_encoded)
            success = await self._send_packet(pkt, wait_for_ack=False)
            if success:
                self.stats.record_tx(is_flood=False)
            else:
                self.stats.record_tx_error()
            return SentResult(success=success)
        except Exception as e:
            logger.error(f"Error sending raw data direct: {e}")
            return SentResult(success=False)

    async def send_raw_packet(self, priority: int, packet_bytes: bytes) -> bool:
        """Inject a fully-formed on-air packet for transmission (CMD_SEND_RAW_PACKET).

        Mirrors firmware ``MyMesh.cpp`` ``CMD_SEND_RAW_PACKET``: parse the raw
        on-air bytes into a :class:`Packet` (``tryParsePacket``) and enqueue it
        for TX (``sendPacket``).  ``packet_bytes`` is the complete wire packet
        (header, optional transport codes, path, payload) as produced by
        :meth:`Packet.write_to`; it is sent verbatim, with no encryption,
        contact lookup, flood-scope, or path-hash-mode rewriting.

        The ``priority`` argument is accepted for protocol compatibility but is
        currently ignored: the bridge's low-level send path
        (:meth:`_send_packet`) does not expose a prioritized TX queue.

        Returns True if the packet parsed and was handed off for transmission,
        False on parse failure or send error (the frame_server handler maps
        False to ``ERR_CODE_TABLE_FULL``).
        """
        try:
            pkt = Packet()
            if not pkt.read_from(bytes(packet_bytes)):
                return False
        except Exception as e:
            logger.warning(f"send_raw_packet: failed to parse packet: {e}")
            return False
        try:
            success = await self._send_packet(pkt, wait_for_ack=False)
            if success:
                self.stats.record_tx(is_flood=False)
            else:
                self.stats.record_tx_error()
            return success
        except Exception as e:
            logger.error(f"Error sending raw packet: {e}")
            self.stats.record_tx_error()
            return False

    async def send_trace_path(
        self,
        pub_key: bytes,
        tag: int,
        auth_code: int,
        flags: int = 0,
    ) -> bool:
        """Send a trace path request to a contact."""
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return False
        path = list(contact.out_path) if contact.out_path else []
        if not path:
            path = [contact.public_key[0]]
        try:
            pkt = PacketBuilder.create_trace(tag, auth_code, flags, path=path)
            self._apply_path_hash_mode(pkt)
            return await self._send_packet(pkt, wait_for_ack=False)
        except Exception as e:
            logger.error(f"Error sending trace: {e}")
            return False

    async def send_control_data(self, data: Any = None) -> bool:
        """Send a CONTROL packet (e.g. discovery request).

        If *data* is provided it must be 1-254 bytes with the first byte having
        the 0x80 bit set (e.g. ``DISCOVER_REQ``).  Returns ``False`` for
        invalid payloads.

        When called with no *data* (or ``None``), a default discovery request
        is sent for backward compatibility.
        """
        try:
            if data and len(data) <= 254 and (data[0] & 0x80) != 0:
                pkt = Packet()
                pkt.header = PacketBuilder._create_header(
                    PAYLOAD_TYPE_CONTROL, route_type="direct"
                )
                pkt.path_len = 0
                pkt.path = bytearray()
                pkt.payload = bytearray(data)
                pkt.payload_len = len(data)
                self._apply_path_hash_mode(pkt)
                return await self._send_packet(pkt, wait_for_ack=False)
            elif data is not None:
                # data was provided but invalid
                return False
            # No data: send default discovery request
            tag = random.randint(0, 0xFFFFFFFF)
            pkt = PacketBuilder.create_discovery_request(tag, filter_mask=0x04)
            self._apply_path_hash_mode(pkt)
            return await self._send_packet(pkt, wait_for_ack=False)
        except Exception as e:
            logger.error(f"Error sending control data: {e}")
            return False

    async def send_login(self, pub_key: bytes, password: str) -> dict:
        """Send a login request to a repeater and wait for the response."""
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return {"success": False, "reason": "Contact not found"}
        # Resolve by exact public key, not name: two contacts can share a name
        # (e.g. a re-keyed node) and get_by_name returns the first match, which
        # would encrypt/route to the wrong key.
        proxy = self.contacts.get_proxy_by_key(pub_key)
        if not proxy:
            return {"success": False, "reason": "Contact not found"}
        login_handler = self._get_login_response_handler()
        if not login_handler:
            return {"success": False, "reason": "Login handler not available"}
        dest_hash = bytes.fromhex(proxy.public_key)[0]
        login_handler.store_login_password(dest_hash, password)
        login_result: dict = {"success": False, "data": {}}
        login_event = asyncio.Event()

        def _login_cb(success: bool, data: dict) -> None:
            login_result["success"] = success
            login_result["data"] = data
            login_event.set()

        login_handler.set_login_callback(_login_cb)
        try:
            # The login callback fires on any decryptable login response from this
            # repeater (keyed by password/dest_hash, not by tag), so we can resend
            # a freshly-built login packet each attempt and a single event resolves
            # whichever attempt's reply arrives. Each attempt waits one adaptive
            # timeout (firmware cadence) instead of a single fixed 10s wait.
            for attempt in range(DEFAULT_MAX_ATTEMPTS):
                pkt = PacketBuilder.create_login_packet(
                    contact=proxy, local_identity=self._identity, password=password
                )
                self._apply_path_hash_mode(pkt)
                timeout_s = self._response_timeout_s(pkt, proxy)
                logger.debug(
                    "[PATHDIAG] login -> 0x%02X (%s) route=%s attempt=%d/%d "
                    "timeout=%.1fs out_path_len=%s; listening for reply",
                    dest_hash,
                    contact.name,
                    "FLOOD" if pkt.is_route_flood() else "DIRECT",
                    attempt + 1,
                    DEFAULT_MAX_ATTEMPTS,
                    timeout_s,
                    getattr(proxy, "out_path_len", -1),
                )
                await self._send_packet(pkt, wait_for_ack=False)
                try:
                    await asyncio.wait_for(login_event.wait(), timeout=timeout_s)
                    break  # got a response
                except asyncio.TimeoutError:
                    logger.debug(
                        "[PATHDIAG] login to 0x%02X attempt %d/%d TIMEOUT after %.1fs — "
                        "no decryptable login response arrived",
                        dest_hash,
                        attempt + 1,
                        DEFAULT_MAX_ATTEMPTS,
                        timeout_s,
                    )
            if not login_event.is_set():
                return {"success": False, "reason": "Login response timeout"}
            data = login_result["data"]
            return {
                "success": login_result["success"],
                "repeater": contact.name,
                "is_admin": data.get("is_admin", False),
                "keep_alive_interval": data.get("keep_alive_interval", 0),
                "tag": data.get("timestamp", 0),
                "acl_permissions": data.get("reserved", data.get("permissions", 0)),
                "firmware_ver_level": data.get("firmware_ver_level"),
                "reason": "Login successful"
                if login_result["success"]
                else "Login failed",
            }
        except Exception as e:
            logger.error(f"Login error: {e}")
            return {"success": False, "reason": str(e)}
        finally:
            login_handler.set_login_callback(None)
            login_handler.clear_login_password(dest_hash)

    async def send_logout(self, pub_key: bytes) -> bool:
        """Send a logout / disconnect to a repeater contact."""
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return False
        try:
            pkt, _ = PacketBuilder.create_logout_packet(
                contact=contact, local_identity=self._identity
            )
            self._apply_path_hash_mode(pkt)
            await self._send_packet(pkt, wait_for_ack=False)
            return True
        except Exception as e:
            logger.error(f"Logout error: {e}")
            return False

    def _response_timeout_s(self, pkt: Packet, proxy: Any) -> float:
        """Adaptive response timeout (seconds) for a request packet.

        Mirrors firmware calcFloodTimeoutMillisFor / calcDirectTimeoutMillisFor
        using the radio's SF/BW/CR and the packet's on-air length, so a lost
        round-trip is retried on a ~3s cadence instead of a fixed 10-15s wait.
        """
        try:
            out_path_len = getattr(proxy, "out_path_len", -1)
            ms = response_timeout_ms(
                raw_length=pkt.get_raw_length(),
                is_flood=pkt.is_route_flood(),
                out_path_len=out_path_len,
                sf=int(getattr(self.prefs, "spreading_factor", 10)),
                bw_hz=int(getattr(self.prefs, "bandwidth_hz", 250000)),
                cr=int(getattr(self.prefs, "coding_rate", 5)),
            )
            return ms / 1000.0
        except Exception:
            return 5.0  # safe fallback

    async def _wait_for_path_propagation(self, proxy: Any, request_type: str) -> None:
        """Log the pre-send path; no longer sleeps.

        Firmware sends the request immediately and relies on the reciprocal PATH
        (which openHop already sends at login time, see ProtocolResponseHandler).
        The previous 0.5s/hop sleep added up to ~1.5s+ of latency per request for
        multi-hop contacts with no reliability benefit and has been removed; the
        adaptive timeout + internal resend now handle a lost first attempt.
        """
        out_path_len = getattr(proxy, "out_path_len", -1)
        out_path = getattr(proxy, "out_path", b"") or b""
        logger.debug(
            "[PATHDIAG] %s pre-send: %s",
            request_type,
            _fmt_path(out_path_len, out_path),
        )

    async def send_status_request(self, pub_key: bytes, timeout: float = 15.0) -> dict:
        """Send a protocol request for repeater status/stats."""
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return {"success": False, "reason": "Contact not found"}
        # Resolve by exact public key, not name: two contacts can share a name
        # (e.g. a re-keyed node) and get_by_name returns the first match, which
        # would encrypt/route to the wrong key.
        proxy = self.contacts.get_proxy_by_key(pub_key)
        if not proxy:
            return {"success": False, "reason": "Contact not found"}
        proto_handler = self._get_protocol_response_handler()
        if not proto_handler:
            return {"success": False, "reason": "Protocol handler not available"}
        contact_hash = bytes.fromhex(proxy.public_key)[0]
        waiter = ResponseWaiter()
        proto_handler.set_response_callback(contact_hash, waiter.callback)
        try:
            await self._wait_for_path_propagation(proxy, "stats request")
            # Status responses resolve the waiter by contact_hash (not tag), so a
            # fresh REQ each attempt is fine and dodges the repeater's flood dedup.
            # Each attempt waits one adaptive timeout (firmware cadence); a late
            # reply that lands between attempts resolves the waiter immediately.
            result: dict = {"timeout": True}
            for attempt in range(DEFAULT_MAX_ATTEMPTS):
                pkt, _ = PacketBuilder.create_protocol_request(
                    contact=proxy,
                    local_identity=self._identity,
                    protocol_code=REQ_TYPE_GET_STATUS,
                    data=b"",
                )
                self._apply_path_hash_mode(pkt)
                timeout_s = self._response_timeout_s(pkt, proxy)
                logger.debug(
                    "[PATHDIAG] stats REQ: route=%s attempt=%d/%d timeout=%.1fs "
                    "path_len_byte=0x%02X (hops=%s) path=%s",
                    "FLOOD" if pkt.is_route_flood() else "DIRECT",
                    attempt + 1,
                    DEFAULT_MAX_ATTEMPTS,
                    timeout_s,
                    pkt.path_len & 0xFF,
                    pkt.get_path_hash_count() if pkt.path_len else 0,
                    (
                        bytes(pkt.path[: pkt.get_path_byte_len()]).hex()
                        if pkt.path_len
                        else "(empty)"
                    ),
                )
                await self._send_packet(pkt, wait_for_ack=False)
                result = await waiter.wait(timeout_s)
                if not result.get("timeout"):
                    break
            return {
                "success": result.get("success", False),
                "repeater": contact.name,
                "stats": result.get("parsed", {}),
                "response_text": result.get("text"),
                "reason": "Stats received"
                if result.get("success")
                else "Stats request failed",
            }
        except Exception as e:
            logger.error(f"Status request error: {e}")
            return {"success": False, "reason": str(e)}
        finally:
            proto_handler.clear_response_callback(contact_hash)

    async def send_telemetry_request(
        self,
        pub_key: bytes,
        want_base: bool = True,
        want_location: bool = True,
        want_environment: bool = True,
        timeout: float = 10.0,
    ) -> dict:
        """Send a telemetry request to a contact and wait for the response."""
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return {"success": False, "reason": "Contact not found"}
        # Resolve by exact public key, not name: two contacts can share a name
        # (e.g. a re-keyed node) and get_by_name returns the first match, which
        # would encrypt/route to the wrong key.
        proxy = self.contacts.get_proxy_by_key(pub_key)
        if not proxy:
            return {"success": False, "reason": "Contact not found"}
        proto_handler = self._get_protocol_response_handler()
        if not proto_handler:
            return {"success": False, "reason": "Protocol handler not available"}
        contact_hash = bytes.fromhex(proxy.public_key)[0]
        waiter = ResponseWaiter()
        proto_handler.set_response_callback(contact_hash, waiter.callback)
        try:
            await self._wait_for_path_propagation(proxy, "telemetry request")
            inv = PacketBuilder._compute_inverse_perm_mask(
                want_base, want_location, want_environment
            )
            result: dict = {"timeout": True}
            for attempt in range(DEFAULT_MAX_ATTEMPTS):
                pkt, _ = PacketBuilder.create_protocol_request(
                    contact=proxy,
                    local_identity=self._identity,
                    protocol_code=REQ_TYPE_GET_TELEMETRY_DATA,
                    data=bytes([inv]),
                )
                self._apply_path_hash_mode(pkt)
                timeout_s = self._response_timeout_s(pkt, proxy)
                await self._send_packet(pkt, wait_for_ack=False)
                result = await waiter.wait(timeout_s)
                if not result.get("timeout"):
                    break
            telemetry_data = dict(result.get("parsed", {}))
            raw_bytes = telemetry_data.get("raw_bytes", b"")
            if raw_bytes and len(pub_key) >= 6:
                # Companion-style frame: 0x8B + reserved + 6-byte pubkey prefix + LPP
                telemetry_data["frame_bytes"] = (
                    bytes([PUSH_CODE_TELEMETRY_RESPONSE, 0]) + pub_key[:6] + raw_bytes
                )
            return {
                "success": result.get("success", False),
                "contact": contact.name,
                "telemetry_data": telemetry_data,
                "response_text": result.get("text"),
                "reason": (
                    "Telemetry received"
                    if result.get("success")
                    else "Telemetry failed"
                ),
            }
        except Exception as e:
            logger.error(f"Telemetry error: {e}")
            return {"success": False, "reason": str(e)}
        finally:
            proto_handler.clear_response_callback(contact_hash)

    async def send_binary_request(self, pub_key: bytes, data: bytes) -> dict:
        """Legacy: send binary request and wait.

        Prefer ``send_binary_req`` + ``on_binary_response``.
        """
        return await self._send_protocol_request(
            pub_key, PROTOCOL_CODE_BINARY_REQ, data
        )

    async def send_anon_request(self, pub_key: bytes, data: bytes) -> dict:
        """Send an anonymous request to a contact and wait for the response."""
        return await self._send_protocol_request(pub_key, PROTOCOL_CODE_ANON_REQ, data)

    async def _send_protocol_request(
        self, pub_key: bytes, protocol_code: int, data: bytes
    ) -> dict:
        """Build and send a protocol request, waiting for the response."""
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return {"success": False, "reason": "Contact not found"}
        # Resolve by exact public key, not name: two contacts can share a name
        # (e.g. a re-keyed node) and get_by_name returns the first match, which
        # would encrypt/route to the wrong key.
        proxy = self.contacts.get_proxy_by_key(pub_key)
        if not proxy:
            return {"success": False, "reason": "Contact not found"}
        proto_handler = self._get_protocol_response_handler()
        if not proto_handler:
            return {"success": False, "reason": "Protocol handler not available"}
        contact_hash = bytes.fromhex(proxy.public_key)[0]
        waiter = ResponseWaiter()
        proto_handler.set_response_callback(contact_hash, waiter.callback)
        try:
            result: dict = {"timeout": True}
            for _attempt in range(DEFAULT_MAX_ATTEMPTS):
                pkt, _ = PacketBuilder.create_protocol_request(
                    contact=proxy,
                    local_identity=self._identity,
                    protocol_code=protocol_code,
                    data=data,
                )
                self._apply_path_hash_mode(pkt)
                timeout_s = self._response_timeout_s(pkt, proxy)
                await self._send_packet(pkt, wait_for_ack=False)
                result = await waiter.wait(timeout_s)
                if not result.get("timeout"):
                    break
            return {
                "success": result.get("success", False),
                "response": result.get("text"),
                "parsed_data": result.get("parsed", {}),
                "reason": "Success" if result.get("success") else "Failed",
            }
        except Exception as e:
            logger.error(f"Protocol request error: {e}")
            return {"success": False, "reason": str(e)}
        finally:
            proto_handler.clear_response_callback(contact_hash)

    async def send_repeater_command(
        self, pub_key: bytes, command: str, parameters: Optional[str] = None
    ) -> dict:
        """Send a text-based command to a repeater and wait for the response."""
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return {"success": False, "reason": "Contact not found"}
        # Resolve by exact public key, not name: two contacts can share a name
        # (e.g. a re-keyed node) and get_by_name returns the first match, which
        # would encrypt/route to the wrong key.
        proxy = self.contacts.get_proxy_by_key(pub_key)
        if not proxy:
            return {"success": False, "reason": "Contact not found"}
        text_handler = self._get_text_handler()
        if not text_handler:
            return {"success": False, "reason": "Text handler not available"}
        full_command = command
        if parameters:
            full_command += f" {parameters}"
        response_data: dict = {"text": None, "success": False}
        response_event = asyncio.Event()

        def _response_cb(message_text: str, sender_contact: Any) -> None:
            response_data["text"] = message_text
            response_data["success"] = True
            response_event.set()

        text_handler.set_command_response_callback(_response_cb)
        try:
            msg_type = "flood" if proxy.out_path_len < 0 else "direct"
            pkt, _ = PacketBuilder.create_text_message(
                contact=proxy,
                local_identity=self._identity,
                message=full_command,
                attempt=1,
                message_type=msg_type,
                txt_type=TXT_TYPE_CLI_DATA,
            )
            self._apply_path_hash_mode(pkt)
            await self._send_packet(pkt, wait_for_ack=False)
            try:
                await asyncio.wait_for(response_event.wait(), timeout=15.0)
            except asyncio.TimeoutError:
                pass
            return {
                "success": response_data["success"],
                "repeater": contact.name,
                "command": command,
                "response": response_data["text"],
                "reason": (
                    "Command successful" if response_data["success"] else "No response"
                ),
            }
        except Exception as e:
            logger.error(f"Repeater command error: {e}")
            return {"success": False, "reason": str(e)}
        finally:
            text_handler.set_command_response_callback(None)

    def _track_pending_ack(self, ack_crc: int) -> None:
        """Track pending ACK CRC for send_confirmed (capped)."""
        if len(self._pending_ack_crcs) < MAX_PENDING_ACK_CRCS:
            self._pending_ack_crcs.add(ack_crc)

    async def _try_confirm_send(self, crc: int) -> bool:
        """If CRC is pending, discard it and fire send_confirmed. Returns True if fired."""
        if crc not in self._pending_ack_crcs:
            return False
        self._pending_ack_crcs.discard(crc)
        await self._fire_callbacks("send_confirmed", crc)
        return True

    def sync_next_message(self) -> Optional[QueuedMessage]:
        """Pop and return the next queued message, or None."""
        return self.message_queue.pop()

    # -------------------------------------------------------------------------
    # Dedup Helper
    # -------------------------------------------------------------------------

    def _check_dedup(
        self, cache: OrderedDict, key: str, ttl: float, max_size: int
    ) -> bool:
        """Return True if *key* is a duplicate. Evicts expired entries."""
        now = time.time()
        if key in cache:
            return True
        expired = [k for k, ts in cache.items() if now - ts > ttl]
        for k in expired:
            del cache[k]
        cache[key] = now
        if len(cache) > max_size:
            cache.popitem(last=False)
        return False

    # -------------------------------------------------------------------------
    # Event Handling (shared)
    # -------------------------------------------------------------------------

    async def _handle_mesh_event(self, event_type: str, data: dict) -> None:
        try:
            if event_type == MeshEvents.NEW_MESSAGE:
                await self._handle_new_message(data)
            elif event_type == MeshEvents.NEW_CHANNEL_MESSAGE:
                await self._handle_new_channel_message(data)
            elif event_type == MeshEvents.NEW_CONTACT:
                await self._fire_callbacks("node_discovered", data)
            elif event_type == MeshEvents.CONTACT_UPDATED:
                pass
            elif event_type == MeshEvents.NODE_DISCOVERED:
                # Advert pipeline (single path): all adverts applied here; one event
                # -> one store update and at most one advert_received (Bridge and Radio).
                now = int(time.time())
                contact = Contact.from_dict(data, now=now)
                # Wire advert flags (ADVERT_FLAG_IS_CHAT_NODE=0x01, etc.) must not
                # be stored as local contact flags (bit 0 = favourite).  For new
                # contacts the flags start at 0; for existing contacts
                # _apply_advert_to_stores restores the persisted value (line 708).
                contact.flags = 0
                raw_blob = data.get("raw_advert_packet")
                if isinstance(raw_blob, (bytes, bytearray)) and len(raw_blob) > 0:
                    contact.last_advert_packet = bytes(raw_blob)
                if len(contact.public_key) >= 7 and contact.name:
                    inbound_path = data.get("inbound_path")
                    path_len_encoded = data.get("path_len_encoded")
                    applied = await self._apply_advert_to_stores(
                        contact, inbound_path, path_len_encoded=path_len_encoded
                    )
                    if applied is not None:
                        # Stored (existing or newly auto-added): persist + app contact update.
                        await self._fire_callbacks("advert_received", applied)
                    # Firmware parity (BaseChatMesh::onAdvertRecv -> onDiscoveredContact):
                    # notify the client for *every* valid advert (stored or not). The frame
                    # layer decides full NEW_ADVERT vs short ADVERT by whether the contact
                    # ended up in the store.
                    disc_contact = applied if applied is not None else contact
                    await self._fire_callbacks("node_discovered", disc_contact)
            elif event_type == MeshEvents.TELEMETRY_UPDATED:
                await self._fire_callbacks("telemetry_response", data)
        except Exception as e:
            logger.error(f"Error handling mesh event {event_type}: {e}")

    async def _handle_new_message(self, data: dict) -> None:
        # Deduplicate by packet hash so reconnects don't queue the same packet multiple times.
        pkt_hash = data.get("packet_hash")
        if pkt_hash and self._check_dedup(
            self._seen_txt, pkt_hash, self._seen_txt_ttl, self._seen_txt_max
        ):
            return

        sender_key_hex = data.get("contact_pubkey", "")
        sender_key = bytes.fromhex(sender_key_hex) if sender_key_hex else b""
        # Handler publishes "message_text"; accept "text" for compatibility
        message_text = (data.get("message_text") or data.get("text") or "").rstrip(
            "\x00"
        )
        # Extract SNR/RSSI from network info if available (same as channel path)
        network_info = data.get("network_info", {})
        snr = network_info.get("snr")
        rssi = network_info.get("rssi")
        msg = QueuedMessage(
            sender_key=sender_key,
            txt_type=data.get("txt_type", data.get("flags", 0)),
            timestamp=data.get("timestamp", int(time.time())),
            text=message_text,
            is_channel=False,
            path_len=0,
            snr=snr if snr is not None else 0.0,
            rssi=rssi if rssi is not None else 0,
        )
        self.message_queue.push(msg)
        await self._fire_callbacks(
            "message_received",
            sender_key,
            message_text,
            msg.timestamp,
            msg.txt_type,
            pkt_hash,
            snr if snr is not None else 0.0,
            rssi if rssi is not None else 0,
        )

    async def _handle_new_channel_message(self, data: dict) -> None:
        # Do not push our own (outgoing) channel messages to the client as incoming.
        if data.get("is_outgoing"):
            return

        # Deduplicate by packet hash so we queue one frame per logical message, matching
        # firmware: Mesh.cpp only calls onChannelMessageRecv when !_tables->hasSeen(pkt).
        pkt_hash = data.get("packet_hash")
        if pkt_hash and self._check_dedup(
            self._seen_grp_txt, pkt_hash, self._seen_grp_txt_ttl, self._seen_grp_txt_max
        ):
            return

        path_len = data.get("path_len", 0)
        channel_name = data.get("channel_name", "")
        # Resolve channel index so sync_next_message returns correct channel_idx in the frame
        channel_idx = 0
        if getattr(self, "channels", None) and hasattr(self.channels, "find_by_name"):
            idx = self.channels.find_by_name(channel_name)
            if idx is not None:
                channel_idx = idx
        # MeshCore client expects "SenderName: Message" format in text field; it parses to show
        # sender and message separately. Use full_content (not message_text) so client can split.
        # Strip trailing nulls so frame matches firmware (exact string length, no padding).
        display_text = (
            data.get("full_content", data.get("message_text", "")) or ""
        ).rstrip("\x00")
        # Extract SNR/RSSI from network info if available
        network_info = data.get("network_info", {})
        snr = network_info.get("snr")
        rssi = network_info.get("rssi")

        msg = QueuedMessage(
            sender_key=b"",
            txt_type=0,
            timestamp=data.get("timestamp", int(time.time())),
            text=display_text,
            is_channel=True,
            channel_idx=channel_idx,
            path_len=path_len,
            snr=snr if snr is not None else 0.0,
            rssi=rssi if rssi is not None else 0,
        )
        self.message_queue.push(msg)

        await self._fire_callbacks(
            "channel_message_received",
            data.get("channel_name", ""),
            data.get("sender_name", ""),
            display_text,
            msg.timestamp,
            path_len,
            channel_idx,
            pkt_hash,
            snr,
            rssi,
        )

    def _get_channel_candidates_by_hash(
        self, channel_hash: int
    ) -> list[tuple[int, Channel]]:
        """Return channel candidates that match the 1-byte channel hash."""
        matches: list[tuple[int, Channel]] = []
        max_channels = getattr(self.channels, "max_channels", 40)
        for idx in range(max_channels):
            channel = self.channels.get(idx)
            if channel is None:
                continue
            secret = bytes(channel.secret or b"")
            if len(secret) < 32:
                secret = secret + b"\x00" * (32 - len(secret))
            else:
                secret = secret[:32]
            hash_input = secret[:16] if secret[16:32] == b"\x00" * 16 else secret
            if hashlib.sha256(hash_input).digest()[0] == channel_hash:
                matches.append((idx, channel))
        return matches

    async def _handle_group_data_packet(self, packet: Packet) -> None:
        """Parse and queue incoming PAYLOAD_TYPE_GRP_DATA for sync_next_message."""
        payload = packet.get_payload()
        if len(payload) < 4:
            return
        packet_hash = packet.calculate_packet_hash().hex().upper()
        if self._check_dedup(
            self._seen_grp_data,
            packet_hash,
            self._seen_grp_data_ttl,
            self._seen_grp_data_max,
        ):
            return

        channel_hash = payload[0]
        cipher_mac = payload[1:3]
        ciphertext = payload[3:]
        selected_idx: Optional[int] = None
        plaintext: Optional[bytes] = None

        for idx, channel in self._get_channel_candidates_by_hash(channel_hash):
            secret = bytes(channel.secret or b"")
            if len(secret) < 32:
                secret = secret + b"\x00" * (32 - len(secret))
            else:
                secret = secret[:32]
            try:
                plaintext = CryptoUtils.mac_then_decrypt(
                    hashlib.sha256(secret).digest(), secret, cipher_mac + ciphertext
                )
            except Exception:
                plaintext = None
            if plaintext is not None:
                selected_idx = idx
                break

        if selected_idx is None or plaintext is None or len(plaintext) < 3:
            return
        data_type = struct.unpack_from("<H", plaintext, 0)[0]
        data_len = plaintext[2]
        if data_type == 0 or len(plaintext) < 3 + data_len:
            return
        blob = bytes(plaintext[3 : 3 + data_len])

        route_type = packet.get_route_type()
        path_len = (
            packet.path_len
            if route_type in (ROUTE_TYPE_FLOOD, ROUTE_TYPE_TRANSPORT_FLOOD)
            else 0xFF
        )
        snr = (
            packet.get_snr()
            if hasattr(packet, "get_snr")
            else getattr(packet, "_snr", 0.0)
        )
        rssi = packet.rssi if hasattr(packet, "rssi") else getattr(packet, "_rssi", 0)
        queued = QueuedMessage(
            sender_key=b"",
            txt_type=0,
            timestamp=0,
            text="",
            is_channel=True,
            channel_idx=selected_idx,
            path_len=path_len,
            snr=snr if snr is not None else 0.0,
            rssi=rssi if rssi is not None else 0,
            channel_data_type=data_type,
            channel_data_payload=blob,
        )
        self.message_queue.push(queued)
        await self._fire_callbacks(
            "channel_data_received",
            selected_idx,
            path_len,
            data_type,
            blob,
            packet_hash,
            snr,
            rssi,
        )

    async def _fire_callbacks(self, event_name: str, *args: Any) -> None:
        for callback in self._push_callbacks.get(event_name, []):
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(*args)
                else:
                    callback(*args)
            except Exception as e:
                logger.error(f"Error in {event_name} callback: {e}")

    def _schedule_fire_callbacks(self, event_name: str, *args: Any) -> None:
        """Schedule _fire_callbacks from sync code (e.g. set_channel). No-op if no running loop."""
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self._fire_callbacks(event_name, *args))
        except RuntimeError:
            pass
