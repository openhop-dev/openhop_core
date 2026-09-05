"""Device configuration, signing, flood scope, and stats of CompanionBase."""

from __future__ import annotations

import copy
import logging
import time
from typing import Optional

from ..protocol import Packet
from ..protocol.constants import ROUTE_TYPE_FLOOD
from ..protocol.transport_keys import get_auto_key_for, scope_packet
from .constants import (
    DEFAULT_ALLOWED_REPEAT_FREQ_RANGES,
    DEFAULT_MAX_TX_POWER_DBM,
    MAX_SIGN_DATA_SIZE,
    NODE_NAME_MAX_BYTES,
    STATS_TYPE_CORE,
    STATS_TYPE_PACKETS,
    STATS_TYPE_RADIO,
    ZERO_FLOOD_SCOPE_KEY,
)
from .models import NodePrefs

logger = logging.getLogger("CompanionBase")


class _DeviceConfigMixin:
    """Part of :class:`CompanionBase` (see companion_base.py)."""

    # -------------------------------------------------------------------------
    # Device Configuration
    # -------------------------------------------------------------------------

    def set_advert_name(self, name: str) -> None:
        """Set the node's advertised name.

        Firmware stores this in a fixed ``char node_name[32]`` (NodePrefs.h),
        so the limit is 31 *bytes* of UTF-8, not 31 characters. Truncate on
        the encoded bytes and decode leniently so a multi-byte codepoint
        straddling the cut is dropped whole rather than split.
        """
        self.prefs.node_name = name.encode("utf-8")[:NODE_NAME_MAX_BYTES].decode(
            "utf-8", errors="ignore"
        )
        self._save_prefs()

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

    def supports_radio_params_mutation(self) -> bool:
        """Return whether this companion can apply radio-parameter changes."""
        return True

    def supports_tx_power_mutation(self) -> bool:
        """Return whether this companion can apply TX-power changes."""
        return True

    def supports_client_repeat(self) -> bool:
        """Return whether this companion can act as a client repeater.

        A concrete companion that owns a radio can forward mesh traffic
        (MeshCore ``_prefs.client_repeat``). Host-shared virtual companions
        must override this to False.
        """
        return True

    def get_allowed_repeat_freqs(self) -> tuple:
        """Return the (lower_khz, upper_khz) ranges where client-repeat is allowed.

        Mirrors firmware's ``repeat_freq_ranges`` (MyMesh.cpp). Defaults to the
        three single-frequency LoRa bands; a companion can override the set via
        the ``allowed_repeat_freq_ranges`` key of its ``radio_config`` dict.
        """
        ranges = self._radio_config.get(
            "allowed_repeat_freq_ranges", DEFAULT_ALLOWED_REPEAT_FREQ_RANGES
        )
        return tuple((int(lower), int(upper)) for lower, upper in ranges)

    def set_client_repeat(self, value: int) -> None:
        """Persist the client-repeat preference (advertised in DEVICE_QUERY byte 80)."""
        self.prefs.client_repeat = int(value) & 0xFF
        self._save_prefs()

    def get_max_tx_power_dbm(self) -> int:
        """Return the maximum supported TX power for companion SELF_INFO.

        A concrete radio or host integration can override this capability.
        ``max_tx_power_dbm`` is intentionally separate from the current
        ``tx_power`` preference: lowering the active power must not lower the
        radio's advertised capability.
        """
        value = self._radio_config.get("max_tx_power_dbm", DEFAULT_MAX_TX_POWER_DBM)
        try:
            return int(value)
        except (TypeError, ValueError):
            return DEFAULT_MAX_TX_POWER_DBM

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
    # Signing Pipeline
    # -------------------------------------------------------------------------

    def sign_start(self) -> int:
        """Begin a signing session; returns the maximum sign buffer size."""
        self._sign_buffer = bytearray()
        return MAX_SIGN_DATA_SIZE

    def is_signing(self) -> bool:
        """Return whether a companion signing session is active."""
        return self._sign_buffer is not None

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
            logger.error("Signing error: %s", e)
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
        """Return (name, key) for persisted default scope, or None if unset.

        A non-empty name means "set" even when the key is all zeros: firmware
        CMD_GET_DEFAULT_FLOOD_SCOPE checks only ``strlen(default_scope_name)``
        and echoes the stored key as-is.  The null-key check happens at send
        time instead (``TransportKey::isNull()``).
        """
        name = (getattr(self.prefs, "default_scope_name", "") or "").strip()
        if not name:
            return None
        key = getattr(self.prefs, "default_scope_key", b"") or b""
        return (name, bytes(key[:16]).ljust(16, b"\x00"))

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

    def _default_scope_key(self) -> Optional[bytes]:
        """Default scope key for sends, or None when unset or null (all zeros)."""
        default_scope = self.get_default_flood_scope()
        if default_scope is None or default_scope[1] == ZERO_FLOOD_SCOPE_KEY:
            return None
        return default_scope[1]

    def _resolve_flood_transport_key(self) -> Optional[bytes]:
        """Resolve effective flood key: transient override first, then default."""
        if self._flood_transport_key is not None:
            return self._flood_transport_key
        return self._default_scope_key()

    def _scope_packet(self, pkt: Packet, key: bytes) -> None:
        """Attach transport codes for ``key`` and switch FLOOD -> TRANSPORT_FLOOD.

        Delegates to the shared :func:`scope_packet` primitive so the companion
        and dispatcher resolvers compute the wire format identically.
        """
        scope_packet(pkt, key)

    def _apply_flood_scope(self, pkt: Packet) -> None:
        """Apply flood scope transport codes to a packet in-place.

        If ``_flood_transport_key`` is set and the packet uses flood routing,
        calculates the transport code, attaches it to the packet, and changes
        the route type to ``ROUTE_TYPE_TRANSPORT_FLOOD``.

        Matches firmware ``sendFloodScoped()`` in ``BaseChatMesh.cpp``.  Marks
        the packet scope-applied even when it stays a plain flood (unscoped
        request, or no key configured) so the dispatcher's node-level scope
        cannot override that decision.
        """
        # Checked FIRST, as Dispatcher._apply_flood_scope does: a scope the
        # reply helper already decided outranks this node's send state, and a
        # reply deliberately left plain (chooseReplyScope NONE, mirroring an
        # un-scoped request) must not be scoped here. Every call site below
        # builds its packet immediately before calling this, so a fresh packet
        # is never affected.
        if getattr(pkt, "_flood_scope_applied", False):
            return
        route_type = pkt.get_route_type()
        if route_type != ROUTE_TYPE_FLOOD:
            return  # only scope flood packets, not direct
        pkt._flood_scope_applied = True
        if self._flood_unscoped:
            # App explicitly requested unscoped (FW #2492): leave as plain flood,
            # ignoring any default scope until a scope override/reset.
            return
        effective_key = self._resolve_flood_transport_key()
        if effective_key is None:
            return
        self._scope_packet(pkt, effective_key)

    def _apply_default_flood_scope(self, pkt: Packet) -> None:
        """Scope a flood packet with the persisted default scope only.

        Firmware CMD_SEND_SELF_ADVERT builds the scope directly from
        ``prefs.default_scope_key``, bypassing both the transient send_scope
        override and the send_unscoped flag; a null default means plain flood.
        """
        if pkt.get_route_type() != ROUTE_TYPE_FLOOD:
            return
        pkt._flood_scope_applied = True
        key = self._default_scope_key()
        if key is None:
            return
        self._scope_packet(pkt, key)

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
