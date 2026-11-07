from __future__ import annotations

from typing import Callable, Optional

from ...protocol import Packet
from ...protocol.constants import (
    CIPHER_BLOCK_SIZE,
    PAYLOAD_TYPE_GRP_TXT,
    ROUTE_TYPE_FLOOD,
    ROUTE_TYPE_TRANSPORT_FLOOD,
)
from ...protocol.crypto import CryptoUtils
from ...protocol.packet_filter import PacketHashCache
from ...protocol.utils import derive_channel_hash
from .base import BaseHandler


class GroupTextHandler(BaseHandler):
    @staticmethod
    def payload_type() -> int:
        return PAYLOAD_TYPE_GRP_TXT

    def __init__(
        self,
        local_identity,
        contacts,
        log_fn,
        send_packet_fn,
        channel_db=None,
        event_service=None,
        packet_seen_callback: Optional[Callable[[Packet], bool]] = None,
    ):
        self.local_identity = local_identity
        self.contacts = contacts
        self.log = log_fn
        self.send_packet = send_packet_fn
        self.channel_db = channel_db  # Live database instead of static config
        self.event_service = event_service
        self._packet_seen_callback = packet_seen_callback
        # MeshCore's seen table never expires (cyclic displacement only), so
        # keep the window generous: echoes arriving via slow multi-hop paths
        # or store-and-forward must still match the send-time mark.
        self._seen_group_packets = PacketHashCache(ttl_seconds=600.0, max_entries=4096)

    @staticmethod
    def _packet_hash(packet: Packet) -> str:
        """Return the full packet hash used for application-level de-duplication."""
        return packet.calculate_packet_hash().hex()

    def set_packet_seen_callback(self, callback: Optional[Callable[[Packet], bool]]) -> None:
        """Share the companion's group-packet cache when one is available."""
        self._packet_seen_callback = callback

    def mark_outgoing_packet(self, packet: Packet) -> None:
        """Record a locally-originated group text before it can loop back.

        Group text has no authenticated sender identity. MeshCore marks the
        packet in its seen table before transmission, so an echoed packet is
        identified by its packet hash rather than its display-name prefix.
        Suppression lasts the cache TTL from the last sighting (hits refresh
        the entry); an echo arriving after a full quiet TTL is delivered as
        incoming, unlike firmware's never-expiring (but smaller) seen table.
        """
        if packet.get_payload_type() != PAYLOAD_TYPE_GRP_TXT:
            return
        self._is_duplicate_packet(packet)

    def _is_duplicate_packet(self, packet: Packet) -> bool:
        """Record a packet and report whether its full hash was recently seen."""
        if self._packet_seen_callback is not None:
            return self._packet_seen_callback(packet)
        return self._seen_group_packets.check_and_add(self._packet_hash(packet))

    def _get_channel_by_hash(self, channel_hash: int) -> Optional[dict]:
        """Find a channel by its hash (first byte of SHA256) from database.

        Returns the first matching channel.  See also
        :meth:`_get_channels_by_hash` which returns *all* matches (needed
        because the hash is only 1 byte and collisions are expected).
        """
        matches = self._get_channels_by_hash(channel_hash)
        return matches[0] if matches else None

    def _get_channels_by_hash(self, channel_hash: int) -> list[dict]:
        """Return **all** channels whose derived hash matches *channel_hash*.

        The channel hash is only 1 byte, so collisions between channels
        with different PSKs are expected (~0.4 % per foreign channel).
        The firmware handles this by trying each match until HMAC validates;
        we do the same.
        """
        if not self.channel_db:
            self.log("No channel database available")
            return []

        try:
            channels = self.channel_db.get_channels()
            matches = []
            for channel in channels:
                if "secret" in channel:
                    calculated_hash = self._derive_channel_hash(channel["secret"])
                    if calculated_hash == channel_hash:
                        matches.append(channel)
            return matches
        except Exception as e:
            self.log(f"Error querying channel database: {e}")
            return []

    def _secret_bytes_for_hash(self, channel_secret: str) -> bytes:
        """Normalize secret to bytes used for channel hash (match MeshCore firmware).
        Firmware hashes only first 16 bytes when second 16 are zero (128-bit key)."""
        try:
            secret_bytes = bytes.fromhex(channel_secret)
        except ValueError:
            secret_bytes = channel_secret.encode("utf-8")
        if len(secret_bytes) >= 32 and secret_bytes[16:32] == b"\x00" * 16:
            return secret_bytes[:16]
        if len(secret_bytes) > 32:
            return secret_bytes[:32]
        return secret_bytes

    def _derive_channel_hash(self, channel_secret: str) -> int:
        """Derive channel hash (first byte of SHA256) to match MeshCore firmware."""
        try:
            secret_bytes = bytes.fromhex(channel_secret)
        except ValueError:
            secret_bytes = channel_secret.encode("utf-8")
        return derive_channel_hash(secret_bytes)

    def _derive_channel_keys(self, channel_secret: str) -> tuple:
        """Derive all necessary keys from channel secret."""
        import hashlib

        secret_bytes = self._secret_bytes_for_hash(channel_secret)
        master_key = hashlib.sha256(secret_bytes).digest()

        # Split into different keys
        channel_hash = master_key[0]  # First byte for channel identification
        aes_key = master_key[:16]  # First 16 bytes for AES encryption
        hmac_key = master_key[16:32]  # Next 16 bytes for HMAC

        return channel_hash, aes_key, hmac_key

    def _decrypt_channel_message(
        self, channel_secret: str, mac: bytes, ciphertext: bytes
    ) -> Optional[bytes]:
        """Attempt to decrypt a channel message using *channel_secret*.

        Returns the plaintext on success, or ``None`` if the HMAC does not
        validate (which is expected during candidate iteration when multiple
        channels share the same 1-byte hash).
        """
        if not ciphertext or len(ciphertext) % CIPHER_BLOCK_SIZE:
            return None
        try:
            # Convert hex secret to bytes
            try:
                secret_bytes = bytes.fromhex(channel_secret)
            except ValueError:
                secret_bytes = channel_secret.encode("utf-8")

            # Ensure we have PUB_KEY_SIZE (32 bytes) for the secret
            if len(secret_bytes) < 32:
                secret_bytes = secret_bytes + b"\x00" * (32 - len(secret_bytes))
            elif len(secret_bytes) > 32:
                secret_bytes = secret_bytes[:32]

            expected_mac = CryptoUtils._hmac_sha256(secret_bytes, ciphertext)[:2]

            if mac != expected_mac:
                return None  # HMAC mismatch — normal during candidate iteration

            return CryptoUtils._aes_decrypt(secret_bytes[:16], ciphertext)

        except Exception as e:
            self.log(f"Channel message decryption error: {e}")
            return None

    def _parse_plaintext_message(self, plaintext: bytes) -> Optional[dict]:
        """Parse the decrypted plaintext according to the spec."""
        if len(plaintext) < 5:  # timestamp(4) + flags(1) minimum
            return None

        try:
            timestamp = int.from_bytes(plaintext[:4], "little")
            flags = plaintext[4]
            # Firmware onGroupDataRecv: only plain group text is supported. The
            # upper six bits of the flag byte must be zero; a non-zero value is an
            # unsupported type and the packet is dropped. The low two bits are an
            # attempt number and carry no display meaning (group text has no CLI
            # or signed subtypes and no binary sender prefix — the sender name is
            # embedded in the text itself).
            if (flags >> 2) != 0:
                self.log(f"Dropping unsupported group text type: {flags}")
                return None

            # Body is a C string: the visible text ends at the first NUL (the rest
            # is AES zero padding).
            body = plaintext[5:]
            nul = body.find(b"\x00")
            if nul >= 0:
                body = body[:nul]
            message_content = body.decode("utf-8", errors="replace")

            return {
                "timestamp": timestamp,
                "flags": flags,
                "message_type": "plain_text",
                "content": message_content,
            }

        except Exception as e:
            self.log(f"Failed to parse plaintext message: {e}")
            return None

    def _extract_sender_from_message(self, message_content: str) -> tuple:
        """Extract sender name and message body from '<sender>: <message>' format."""
        if ": " in message_content:
            parts = message_content.split(": ", 1)
            if len(parts) == 2:
                return parts[0], parts[1]
        return "Unknown", message_content

    async def __call__(self, packet: Packet) -> None:
        """Handle incoming group text messages according to the specification."""
        try:
            payload = packet.get_payload()

            if len(payload) < 4:  # Minimum: channel_hash(1) + cipher_mac(2) + ciphertext(1+)
                self.log("Group text packet too short, ignoring")
                return

            channel_hash = payload[0]
            cipher_mac = payload[1:3]
            ciphertext = payload[3:]

            # Find all channels whose 1-byte hash matches (collisions are
            # expected; the firmware tries up to 4 candidates).
            candidates = self._get_channels_by_hash(channel_hash)
            if not candidates:
                self.log(f"Unknown channel hash: {channel_hash:02X}")
                return

            # Try each candidate until HMAC validates (matches firmware behaviour).
            channel = None
            plaintext = None
            for candidate in candidates:
                result = self._decrypt_channel_message(candidate["secret"], cipher_mac, ciphertext)
                if result is not None:
                    channel = candidate
                    plaintext = result
                    break

            if channel is None or plaintext is None:
                # No candidate validated — the packet is for a channel we
                # don't have the key for (hash collision with 1-byte hash).
                self.log(
                    f"GRP_TXT hash {channel_hash:02X} matched "
                    f"{len(candidates)} local channel(s) but HMAC failed "
                    f"for all — unknown channel"
                )
                return

            channel_name = channel.get("name", f"Channel-{channel_hash:02X}")
            self.log(f"Received group message for channel: {channel_name}")

            # Parse the decrypted message
            parsed_message = self._parse_plaintext_message(plaintext)
            if not parsed_message:
                self.log("Failed to parse decrypted message")
                return

            # Cache only authenticated, parseable traffic. Unlike firmware,
            # invalid packets cannot evict useful application-level entries.
            if self._is_duplicate_packet(packet):
                self.log("Duplicate group message ignored by packet hash")
                return

            # Extract sender and message from the content
            sender_name, message_body = self._extract_sender_from_message(parsed_message["content"])

            # Store the parsed message for event consumers.
            packet.decrypted["group_text_data"] = {
                "text": message_body,
                "sender_name": sender_name,
                "channel_name": channel_name,
                "channel_hash": channel_hash,
                "message_type": parsed_message["message_type"],
                "timestamp": parsed_message["timestamp"],
                "flags": parsed_message["flags"],
                "full_content": parsed_message["content"],
            }

            # Log the group message
            self.log(f"<<< Channel [{channel_name}] {sender_name}: {message_body} >>>")

            # Save to database and broadcast to websockets
            await self._save_and_broadcast_group_message(
                packet,
                sender_name,
                message_body,
                channel_name,
                parsed_message["timestamp"],
            )

            # Note: Group messages are unverified according to spec, so no ACK needed

        except Exception as e:
            self.log(f"Error processing group text message: {e}")
            import traceback

            self.log(f"Traceback: {traceback.format_exc()}")

    async def _save_and_broadcast_group_message(
        self, packet, sender_name, message_body, channel_name, timestamp
    ):
        """Save the group message to database and broadcast via WebSocket."""
        try:
            message_id = packet.get_packet_hash_hex(16)

            # Publish channel message event if available
            if self.event_service:
                try:
                    from ..events import MeshEvents

                    channel_hash = f"{packet.get_payload()[0]:02X}"

                    # Extract path from packet (list of node hashes)
                    path = list(packet.path) if hasattr(packet, "path") and packet.path else None
                    # path_len: flood packets use actual path length; direct uses 0xFF
                    route_type = packet.get_route_type()
                    if route_type in (ROUTE_TYPE_FLOOD, ROUTE_TYPE_TRANSPORT_FLOOD):
                        path_len = getattr(packet, "path_len", 0) or len(packet.path or [])
                    else:
                        path_len = 0xFF

                    # Use a custom message type for single channel message addition
                    message_data = {
                        "message_id": message_id,
                        "channel_name": channel_name,
                        "channel_hash": channel_hash,
                        "sender_name": sender_name,
                        "message_text": message_body,
                        "timestamp": timestamp,
                        "message_type": "group_text",
                        "flags": 0,
                        "path_len": path_len,
                        "packet_hash": packet.calculate_packet_hash().hex().upper(),
                        "full_content": packet.decrypted.get("group_text_data", {}).get(
                            "full_content"
                        ),
                        "is_outgoing": False,
                        "path": path,
                        "network_info": {
                            "header": f"0x{packet.header:02X}",
                            "payload_type": packet.get_payload_type(),
                            "payload_len": packet.payload_len,
                            "rssi": getattr(packet, "_rssi", None),
                            "snr": getattr(packet, "_snr", None),
                        },
                    }

                    # Publish channel message event (await so queued and MSG_WAITING sent)
                    await self.event_service.publish(MeshEvents.NEW_CHANNEL_MESSAGE, message_data)
                    self.log("Published group message event")
                except Exception as publish_error:
                    self.log(f"Failed to publish group message event: {publish_error}")
            else:
                self.log(f"No event service available for group message: {channel_name}")

        except Exception as e:
            self.log(f"Error saving/broadcasting group message: {e}")
            import traceback

            self.log(f"Traceback: {traceback.format_exc()}")
