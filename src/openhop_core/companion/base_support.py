"""Shared helpers for the CompanionBase mixin modules."""

from __future__ import annotations

import asyncio
import logging
import time
from collections import OrderedDict
from typing import Any, Optional

from ..async_primitives import LazyAsyncEvent
from ..protocol.constants import (
    ADVERT_FLAG_IS_CHAT_NODE,
    ADVERT_FLAG_IS_REPEATER,
    ADVERT_FLAG_IS_ROOM_SERVER,
    ADVERT_FLAG_IS_SENSOR,
)
from ..protocol.packet_utils import PathUtils
from .constants import ADV_TYPE_CHAT, ADV_TYPE_REPEATER, ADV_TYPE_ROOM, ADV_TYPE_SENSOR

logger = logging.getLogger("CompanionBase")


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


def _fmt_path_len(out_path_len: Any) -> str:
    """Render the firmware-encoded path_len byte in decoded form for [PATHDIAG] logs.

    ``out_path_len`` is neither a hop count nor a byte count: the top 2 bits are
    (hash_size - 1) and the low 6 bits are the hop count. E.g. 0x42 -> 2-byte
    hashes, 2 hops, 4 path bytes. -1 means the out_path is unknown (flood), so
    the raw byte value is never mistaken for a hop count.
    """
    if out_path_len is None or out_path_len < 0:
        return "-1 (unknown, flood)"
    return (
        f"0x{out_path_len & 0xFF:02X} "
        f"({PathUtils.get_path_hash_count(out_path_len)} hops, "
        f"{PathUtils.get_path_hash_size(out_path_len)}B hashes, "
        f"{PathUtils.get_path_byte_len(out_path_len)} bytes)"
    )


PUSH_CALLBACK_KEYS = [
    # Message events carry a single event object (MessageEvent,
    # ChannelMessageEvent, ChannelDataEvent); the legacy positional
    # on_*_received registrations adapt onto these same lists.
    "message_event",
    "channel_message_event",
    "channel_data_event",
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
        self.event = LazyAsyncEvent()
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


class _SeenCache:
    """TTL- and size-bounded set of recently seen packet hashes for dedup."""

    def __init__(self, ttl: float = 300.0, max_size: int = 1000):
        self._entries: OrderedDict[str, float] = OrderedDict()
        self._ttl = ttl
        self._max_size = max_size

    def check_and_add(self, key: str) -> bool:
        """Return True if *key* is a duplicate; otherwise record it.

        Expired entries are evicted on each call, and the oldest entry is
        dropped once the cache exceeds ``max_size``.
        """
        now = time.time()
        if key in self._entries:
            return True
        expired = [k for k, ts in self._entries.items() if now - ts > self._ttl]
        for k in expired:
            del self._entries[k]
        self._entries[key] = now
        if len(self._entries) > self._max_size:
            self._entries.popitem(last=False)
        return False


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
