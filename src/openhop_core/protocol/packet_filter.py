"""
Simple packet filter for dispatcher-level routing decisions.

This handles only the essential routing concerns:
- Duplicate detection
- Packet blacklisting for malformed packets
- Basic packet hash tracking
"""

import hashlib
import time
from collections import OrderedDict
from typing import Dict


class PacketFilter:
    """Lightweight packet filter for dispatcher routing decisions."""

    # Bounds for the malformed-frame blacklist: a peer that keeps varying
    # invalid bytes must not be able to grow this structure without limit.
    BLACKLIST_MAX_ENTRIES = 4096
    BLACKLIST_TTL_SECONDS = 300.0

    def __init__(self, window_seconds: int = 30):
        self.window_seconds = window_seconds
        self._packet_hashes: Dict[str, float] = {}  # packet_hash -> timestamp
        # packet_hash -> insert timestamp; OrderedDict gives FIFO eviction at
        # capacity and lets re-blacklisting move an entry to the end.
        self._blacklist: "OrderedDict[str, float]" = OrderedDict()

    def generate_hash(self, data: bytes) -> str:
        """Generate a hash for packet data."""
        return hashlib.sha256(data).hexdigest()[:16]

    def is_duplicate(self, packet_hash: str) -> bool:
        """Check if we've seen this packet recently."""
        now = time.time()
        if packet_hash in self._packet_hashes:
            age = now - self._packet_hashes[packet_hash]
            if age < self.window_seconds:
                return True
        return False

    def track_packet(self, packet_hash: str) -> None:
        """Track a packet hash with current timestamp."""
        self._packet_hashes[packet_hash] = time.time()

    def untrack_packet(self, packet_hash: str) -> None:
        """Drop a tracked hash.

        Counterpart to :meth:`track_packet` for a transmission that was
        tracked before it started and then never reached the air: keeping the
        hash would suppress the copies that are still worth processing.
        """
        self._packet_hashes.pop(packet_hash, None)

    def blacklist(self, packet_hash: str) -> None:
        """Add a packet hash to the blacklist.

        Re-blacklisting an already-present hash refreshes its timestamp and
        moves it to the most-recently-inserted end. Once the structure is at
        capacity (`BLACKLIST_MAX_ENTRIES`), the oldest entry is evicted (FIFO)
        to make room, bounding memory even under sustained varied malformed
        traffic.
        """
        self._blacklist[packet_hash] = time.time()
        self._blacklist.move_to_end(packet_hash)
        if len(self._blacklist) > self.BLACKLIST_MAX_ENTRIES:
            self._blacklist.popitem(last=False)

    def is_blacklisted(self, packet_hash: str) -> bool:
        """Check if a packet hash is blacklisted.

        Pure read: does not mutate the blacklist (no timestamp refresh, no
        deletion of expired entries). Expired entries are pruned separately
        by `cleanup_old_hashes`.
        """
        inserted_at = self._blacklist.get(packet_hash)
        if inserted_at is None:
            return False
        return (time.time() - inserted_at) < self.BLACKLIST_TTL_SECONDS

    def cleanup_old_hashes(self) -> None:
        """Clean up old packet hashes beyond the deduplication window, and
        prune blacklist entries older than `BLACKLIST_TTL_SECONDS`."""
        current_time = time.time()
        old_hashes = [
            h for h, ts in self._packet_hashes.items() if current_time - ts > self.window_seconds
        ]
        for h in old_hashes:
            del self._packet_hashes[h]

        expired_blacklist = [
            h for h, ts in self._blacklist.items() if current_time - ts > self.BLACKLIST_TTL_SECONDS
        ]
        for h in expired_blacklist:
            del self._blacklist[h]

    def get_stats(self) -> dict:
        """Get basic filter statistics."""
        return {
            "tracked_packets": len(self._packet_hashes),
            "blacklisted_packets": len(self._blacklist),
            "window_seconds": self.window_seconds,
        }

    def clear(self) -> None:
        """Clear all tracked data."""
        self._packet_hashes.clear()
        self._blacklist.clear()


class PacketHashCache:
    """Bounded TTL cache for full packet-hash keys.

    This is intended for application-level message de-duplication, where a
    full hash avoids treating two distinct packets as the same message.
    """

    def __init__(self, ttl_seconds: float = 60.0, max_entries: int = 4096):
        if ttl_seconds < 0:
            raise ValueError("ttl_seconds must be non-negative")
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self._entries: OrderedDict[str, float] = OrderedDict()

    def _evict_expired(self, now: float) -> None:
        while self._entries:
            _, seen_at = next(iter(self._entries.items()))
            if now - seen_at <= self.ttl_seconds:
                break
            self._entries.popitem(last=False)

    def check_and_add(self, packet_hash: str) -> bool:
        """Return whether *packet_hash* is still cached, otherwise store it.

        A hit refreshes the entry, so suppression of a key extends while
        duplicates keep arriving; an entry only expires after a full quiet
        TTL. MeshCore's seen table has no expiry at all (a cyclic buffer of
        160 hashes displaced by newer traffic), so refreshing keeps this
        bounded cache closer to firmware behavior than a fixed window.
        """
        now = time.monotonic()
        self._evict_expired(now)
        hit = packet_hash in self._entries
        self._entries[packet_hash] = now
        self._entries.move_to_end(packet_hash)
        if len(self._entries) > self.max_entries:
            self._entries.popitem(last=False)
        return hit
