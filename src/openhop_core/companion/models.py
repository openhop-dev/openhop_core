"""Data models for companion radio state objects."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Optional

from .constants import (
    CONTACT_FLAG_FAVOURITE,
    CONTACT_FLAG_REMOTE_CLI,
    CONTACT_FLAG_TELEM_BASE,
    CONTACT_FLAG_TELEM_ENV,
    CONTACT_FLAG_TELEM_LOC,
)


@dataclass
class Contact:
    """Represents a mesh network contact."""

    public_key: bytes  # 32 bytes (Ed25519)
    name: str = ""  # up to 32 chars
    adv_type: int = 0  # ADV_TYPE_CHAT/REPEATER/ROOM/SENSOR
    flags: int = 0  # bitfield
    out_path_len: int = -1  # -1 = unknown, 0 = direct, >0 = multi-hop
    out_path: bytes = b""  # routing path bytes
    last_advert_timestamp: int = 0  # remote timestamp
    lastmod: int = 0  # local modification timestamp
    gps_lat: float = 0.0  # degrees
    gps_lon: float = 0.0  # degrees
    sync_since: int = 0  # for filtered iteration
    # Last on-wire ADVERT packet bytes (Packet.write_to),
    # for CMD_SHARE_CONTACT replay (firmware blob).
    last_advert_packet: Optional[bytes] = None

    @property
    def public_key_bytes(self) -> bytes:
        """Public key as raw bytes (tolerates hex-string storage)."""
        pk = self.public_key
        return pk if isinstance(pk, bytes) else bytes.fromhex(pk)

    @property
    def dest_hash(self) -> int:
        """First public-key byte — the destination hash used on the wire."""
        return self.public_key_bytes[0]

    @property
    def is_favourite(self) -> bool:
        return bool(self.flags & CONTACT_FLAG_FAVOURITE)

    @property
    def is_telem_base_allowed(self) -> bool:
        return bool(self.flags & CONTACT_FLAG_TELEM_BASE)

    @property
    def is_telem_loc_allowed(self) -> bool:
        return bool(self.flags & CONTACT_FLAG_TELEM_LOC)

    @property
    def is_telem_env_allowed(self) -> bool:
        return bool(self.flags & CONTACT_FLAG_TELEM_ENV)

    @property
    def is_remote_cli_allowed(self) -> bool:
        return bool(self.flags & CONTACT_FLAG_REMOTE_CLI)

    @classmethod
    def from_dict(
        cls,
        d: dict[str, Any],
        *,
        now: Optional[int] = None,
    ) -> "Contact":
        """Build a Contact from a dict (event_data, advert_data, or serialized Contact).

        event_data uses: public_key, name, contact_type (id), lat, lon,
        advert_timestamp, timestamp.
        advert_data uses: public_key, name, contact_type_id, latitude, longitude,
        flags, advert_timestamp, timestamp.
        Serialized Contact dicts (ContactStore.to_dicts) use the same keys as the
        dataclass: gps_lat, gps_lon, last_advert_timestamp, lastmod, out_path,
        out_path_len, sync_since.
        """
        if now is None:
            now = int(time.time())
        pub = d.get("public_key", b"")
        if isinstance(pub, str):
            pub = bytes.fromhex(pub) if pub else b""
        elif not isinstance(pub, bytes):
            pub = b""
        pub = pub[:32].ljust(32, b"\x00")
        name = (d.get("name") or "") or ""
        adv_type_raw = d.get("contact_type_id", d.get("adv_type", d.get("contact_type", 0)))
        if isinstance(adv_type_raw, int):
            adv_type = adv_type_raw
        elif adv_type_raw is None:
            adv_type = 0
        else:
            try:
                adv_type = int(adv_type_raw)
            except (TypeError, ValueError):
                adv_type = 0
        gps_lat = float(d.get("lat", d.get("latitude", d.get("gps_lat", 0.0))))
        gps_lon = float(d.get("lon", d.get("longitude", d.get("gps_lon", 0.0))))
        last_advert_ts = d.get("advert_timestamp", d.get("last_advert_timestamp", 0))
        last_advert_ts = int(last_advert_ts) if last_advert_ts is not None else 0
        if last_advert_ts > now:
            last_advert_ts = now
        lastmod_val = d.get("timestamp", d.get("lastmod", now))
        lastmod_val = int(lastmod_val) if lastmod_val is not None else now
        flags_val = d.get("flags", 0)
        flags_val = int(flags_val) if flags_val is not None else 0
        out_path = d.get("out_path", b"")
        if isinstance(out_path, str):
            out_path = bytes.fromhex(out_path) if out_path else b""
        elif isinstance(out_path, (list, bytearray)):
            out_path = bytes(out_path)
        else:
            out_path = bytes(out_path) if out_path else b""
        out_path_len_val = d.get("out_path_len", -1)
        out_path_len_val = int(out_path_len_val) if out_path_len_val is not None else -1
        sync_since_val = d.get("sync_since", 0)
        sync_since_val = int(sync_since_val) if sync_since_val is not None else 0
        lap = d.get("last_advert_packet")
        if isinstance(lap, str) and lap:
            try:
                last_advert_packet = bytes.fromhex(lap)
            except ValueError:
                last_advert_packet = None
        elif isinstance(lap, (bytes, bytearray)):
            last_advert_packet = bytes(lap)
        else:
            last_advert_packet = None
        return cls(
            public_key=pub,
            name=name,
            adv_type=adv_type,
            flags=flags_val,
            out_path_len=out_path_len_val,
            out_path=out_path,
            last_advert_timestamp=last_advert_ts,
            lastmod=lastmod_val,
            gps_lat=gps_lat,
            gps_lon=gps_lon,
            sync_since=sync_since_val,
            last_advert_packet=last_advert_packet,
        )


@dataclass
class Channel:
    """Represents a group communication channel."""

    name: str  # up to 32 chars
    secret: bytes  # 16-byte PSK


@dataclass
class NodePrefs:
    """Node configuration preferences (equivalent to firmware NodePrefs)."""

    node_name: str = "pyMC"
    adv_type: int = 1  # ADV_TYPE_CHAT
    tx_power_dbm: int = 20
    frequency_hz: int = 915000000
    bandwidth_hz: int = 250000
    spreading_factor: int = 10
    coding_rate: int = 5
    latitude: float = 0.0
    longitude: float = 0.0
    advert_loc_policy: int = 0  # ADVERT_LOC_NONE
    multi_acks: int = 0
    telemetry_mode_base: int = 0  # TELEM_MODE_DENY
    telemetry_mode_location: int = 0
    telemetry_mode_environment: int = 0
    manual_add_contacts: int = 0
    autoadd_config: int = 0
    # Max hops away an advert may be for automatic contact creation. 0 = no
    # limit; N rejects adverts N or more hops away (firmware getAutoAddMaxHops).
    autoadd_max_hops: int = 0
    rx_delay_base: float = 0.0
    # Firmware companion default (NodePrefs airtime_factor 1.0 = 50% TX duty).
    airtime_factor: float = 1.0
    # Reported in CMD_DEVICE_QUERY device info frame (byte 80).
    client_repeat: int = 0
    path_hash_mode: int = 0  # 0=1-byte, 1=2-byte, 2=3-byte hashes
    default_scope_name: str = ""
    default_scope_key: bytes = b""
    # Reported in DEVICE_INFO bytes 4..7 and set by CMD_SET_DEVICE_PIN or the CLI
    # `set pin`. 0 = none. The TCP transport has no PIN; this is stored parity.
    ble_pin: int = 0
    # Hours from UTC for the node's local time display (CLI `tz.offset`, -12..14).
    tz_offset: int = 0
    # Listen-before-talk (CLI `cad`, firmware `cad_enabled`), for a companion
    # that owns its radio. None = never set: the radio keeps its configured mode.
    cad_enabled: Optional[bool] = None


@dataclass
class SentResult:
    """Result of a message send operation."""

    success: bool
    is_flood: bool = False
    expected_ack: Optional[int] = None
    timeout_ms: Optional[int] = None
    error: Optional[str] = None


@dataclass
class PacketStats:
    """Packet transmission/reception statistics."""

    flood_tx: int = 0
    flood_rx: int = 0
    direct_tx: int = 0
    direct_rx: int = 0
    tx_errors: int = 0


@dataclass
class AdvertPath:
    """Recently heard advertiser path information."""

    public_key_prefix: bytes  # 7 bytes
    name: str = ""
    path_len: int = 0
    path: bytes = b""
    recv_timestamp: int = 0


@dataclass
class QueuedMessage:
    """A message stored in the offline queue."""

    sender_key: bytes  # 32 bytes
    txt_type: int = 0
    timestamp: int = 0
    text: str = ""
    is_channel: bool = False
    channel_idx: int = 0  # only meaningful if is_channel
    path_len: int = 0
    snr: float = 0.0
    rssi: int = 0
    channel_data_type: int = 0
    channel_data_payload: bytes = b""
    # 4-byte author pubkey prefix for TXT_TYPE_SIGNED_PLAIN (room server posts);
    # emitted between timestamp and text in the CONTACT_MSG_RECV frame.
    sender_prefix: bytes = b""


@dataclass(frozen=True)
class MessageEvent:
    """A received direct message with its delivery metadata.

    Passed as the single argument to ``on_message_event`` callbacks so new
    metadata fields never change the callback signature. ``queued`` is False
    when the protected offline queue could not retain the message.
    """

    sender_key: bytes  # 32 bytes
    text: str
    timestamp: int
    txt_type: int
    packet_hash: Optional[str] = None
    snr: Optional[float] = None
    rssi: Optional[int] = None
    # 4-byte author pubkey prefix for TXT_TYPE_SIGNED_PLAIN (room server posts).
    sender_prefix: bytes = b""
    # Companion-format route byte: encoded path_len for floods, 0xFF for direct.
    path_len: int = 0
    queued: bool = True
    # The exact in-memory offline-queue entry this event describes, so a
    # persistence layer can remove that entry by identity instead of guessing.
    # None when the protected queue rejected the push.
    queue_entry: Optional[QueuedMessage] = None


@dataclass(frozen=True)
class ChannelMessageEvent:
    """A received channel text message (single ``on_channel_message_event`` argument)."""

    channel_name: str
    sender_name: str
    text: str
    timestamp: int
    path_len: int = 0
    channel_idx: int = 0
    packet_hash: Optional[str] = None
    snr: Optional[float] = None
    rssi: Optional[int] = None
    queued: bool = True
    # The exact in-memory offline-queue entry this event describes, so a
    # persistence layer can remove that entry by identity instead of guessing.
    # None when the protected queue rejected the push.
    queue_entry: Optional[QueuedMessage] = None


@dataclass(frozen=True)
class ChannelDataEvent:
    """A received binary channel payload (single ``on_channel_data_event`` argument)."""

    channel_idx: int
    path_len: int
    data_type: int
    payload: bytes
    packet_hash: Optional[str] = None
    snr: Optional[float] = None
    rssi: Optional[int] = None
    queued: bool = True
    # The exact in-memory offline-queue entry this event describes, so a
    # persistence layer can remove that entry by identity instead of guessing.
    # None when the protected queue rejected the push.
    queue_entry: Optional[QueuedMessage] = None
