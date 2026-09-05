import asyncio

from ...protocol import CryptoUtils, Identity, Packet, PacketBuilder, PathUtils
from ...protocol.constants import (
    PAYLOAD_TYPE_ACK,
    PAYLOAD_TYPE_TXT_MSG,
    TXT_TYPE_CLI_DATA,
    TXT_TYPE_PLAIN,
    TXT_TYPE_SIGNED_PLAIN,
)
from ...protocol.region_map import apply_reply_scope
from .base import BaseHandler
from .result import HandlerResult

# Fixed delay before a received DM's ACK response is transmitted, mirroring the
# firmware TXT_ACK_DELAY (BaseChatMesh.cpp). This is the receiver's response delay
# and is deliberately independent of the sender's airtime/route-timeout ACK-wait
# estimation.
TXT_ACK_DELAY_MS = 200

# Stagger between a multi-ack and the normal ACK on a known direct route, mirroring the
# firmware's `d += 300` in BaseChatMesh::sendAckTo.
MULTI_ACK_STAGGER_MS = 300


class TextMessageHandler(BaseHandler):
    @staticmethod
    def payload_type() -> int:
        return PAYLOAD_TYPE_TXT_MSG

    def __init__(
        self,
        local_identity,
        contacts,
        log_fn,
        send_packet_fn,
        event_service=None,
        radio_config=None,
    ):
        self.local_identity = local_identity
        self.contacts = contacts
        self.log = log_fn
        self.send_packet = send_packet_fn
        self.event_service = event_service  # Event service for broadcasting
        # Pending repeater-command responses keyed by the target contact's full
        # public key (32 bytes). A CLI_DATA reply is delivered to the waiter for
        # its authenticated sender only; every other message flows to normal
        # delivery, mirroring firmware BaseChatMesh (only TXT_TYPE_CLI_DATA from a
        # known contact reaches onCommandDataRecv, which is the reply path).
        # TXT_TYPE_CLI_COMMAND travels the other way — it is a command someone
        # sent *to* us — so it never resolves one of these waiters.
        self._pending_command_responses = {}  # pubkey bytes -> callback
        self.radio_config = radio_config or {}  # Radio configuration for airtime calculations
        self.multi_acks = 0  # multi_acks pref (0=off); set via set_multi_acks()

    def register_command_response(self, pubkey: bytes, callback):
        """Register a callback to receive the next CLI_DATA reply from ``pubkey``.

        Keyed by the target's full public key (not the 1-byte dest hash, which
        collides). One reply completes one command: the entry is removed when the
        matching reply arrives.
        """
        self._pending_command_responses[bytes(pubkey)] = callback

    def unregister_command_response(self, pubkey: bytes, callback) -> None:
        """Remove the pending entry for ``pubkey`` only if it is ``callback``.

        Identity-guarded so a timed-out command never clears a different command's
        pending entry.
        """
        key = bytes(pubkey)
        if self._pending_command_responses.get(key) is callback:
            del self._pending_command_responses[key]

    def set_multi_acks(self, value: int) -> None:
        """Set the ``multi_acks`` preference (mirrors firmware getExtraAckTransmitCount)."""
        self.multi_acks = int(value) if value else 0

    def _contact_pubkey_bytes(self, contact) -> bytes:
        """Return contact's public key as 32 bytes (handles hex str or bytes)."""
        pk = contact.public_key
        return bytes.fromhex(pk) if isinstance(pk, str) else bytes(pk)

    @staticmethod
    def _text_len(message_body: bytes) -> int:
        """Length of the C-string text portion (up to the first NUL, if any)."""
        nul = message_body.find(b"\x00")
        return nul if nul >= 0 else len(message_body)

    def _calc_ack_hash(
        self, txt_type: int, decrypted, message_body, pubkey: bytes, timestamp_int: int, flags: int
    ):
        """Compute the firmware-compatible ACK hash for a received message.

        Returns None for types that get no delivery ACK (e.g. CLI_DATA).
        Mirrors ``BaseChatMesh::onPeerDataRecv``:

        - TXT_TYPE_PLAIN: 6-byte ack — sha256(timestamp||flags||text||sender_pubkey)[:4]
          + extended-attempt byte + random byte.
        - TXT_TYPE_SIGNED_PLAIN: 4-byte ack —
          sha256(decrypted[0 : 9 + strlen(text)] || OUR pubkey)[:4].
        """
        text_len = self._text_len(message_body)
        if txt_type == TXT_TYPE_PLAIN:
            ext_attempt = message_body[text_len + 1] if (text_len + 1) < len(message_body) else 0
            return PacketBuilder.calc_text_ack_hash(
                pubkey, timestamp_int, flags, message_body[:text_len], ext_attempt
            )
        if txt_type == TXT_TYPE_SIGNED_PLAIN:
            signed_span = bytes(decrypted[: 9 + text_len])
            return CryptoUtils.sha256(signed_span + self.local_identity.get_public_key())[:4]
        return None

    def _build_ack_responses(
        self,
        *,
        packet,
        matched_contact,
        shared_secret,
        pubkey,
        ack_hash,
        is_flood,
    ) -> list:
        """Build the ACK packet(s) to emit for a received DM.

        Returns a list of ``(packet, delay_seconds)`` tuples. Mirrors MeshCore
        ``BaseChatMesh::onPeerDataRecv`` / ``sendAckTo``:

        - FLOOD: a PATH-return packet carrying the ACK hash as its extra payload.
        - DIRECT with a known out_path: the ACK routed along that path, plus (when
          ``multi_acks`` is enabled) a multi-ack emitted ~300ms earlier so repeaters can
          forward the embedded ACK.
        - DIRECT with unknown out_path: a flood-routed discrete ACK (so it can reach the
          sender without a known reverse path).
        """

        if is_flood:
            # One decision for both halves: the path bytes and the path_len byte
            # declaring their hash width have to agree, or create_path_return
            # rejects the pair. Deriving them from separate guards let an invalid
            # path_len yield a non-empty path with no declared width. That cannot
            # reach here from the wire (Packet.from_bytes rejects an invalid
            # path_len), but the correct handling is to teach no path rather than
            # one whose hash width we would be guessing.
            in_path_len = getattr(packet, "path_len", 0) or 0
            if PathUtils.is_valid_path_len(in_path_len):
                path_len_encoded = in_path_len
                raw_path = bytes(getattr(packet, "path", b"") or b"")
                incoming_path = list(raw_path[: PathUtils.get_path_byte_len(in_path_len)])
            else:
                path_len_encoded = None
                incoming_path = []
            ack_packet = PacketBuilder.create_path_return(
                dest_hash=PacketBuilder._hash_byte(pubkey),
                src_hash=PacketBuilder._hash_byte(self.local_identity.get_public_key()),
                secret=shared_secret,
                path=incoming_path,
                extra_type=PAYLOAD_TYPE_ACK,
                extra=ack_hash,
                path_len_encoded=path_len_encoded,
            )
            # Firmware sends the flood PATH-return (carrying the ACK) via
            # sendFloodScoped(from, path, TXT_ACK_DELAY): scope the reply to the
            # region the request arrived under, decided synchronously here from
            # the request packet before the delayed send task runs.
            apply_reply_scope(ack_packet, packet)
            self.log(f"FLOOD ACK timing - delay:{TXT_ACK_DELAY_MS}ms")
            return [(ack_packet, TXT_ACK_DELAY_MS / 1000.0)]

        # DIRECT
        out_path_len = getattr(matched_contact, "out_path_len", -1)
        out_path_raw = getattr(matched_contact, "out_path", b"") or b""
        has_known_path = (
            out_path_len is not None
            and out_path_len >= 0
            and PathUtils.is_valid_path_len(out_path_len)
        )

        if not has_known_path:
            # out_path unknown: flood the discrete ACK so it can reach the sender without a
            # known reverse path (mirrors firmware sendAckTo OUT_PATH_UNKNOWN -> sendFloodScoped;
            # a path-less direct ACK would not be relayed past direct neighbours). The
            # dispatcher applies flood scope at send time.
            ack_packet = PacketBuilder.create_ack_from_bytes(ack_hash, route_type="flood")
            # Firmware sendAckTo with OUT_PATH_UNKNOWN floods the ACK at TXT_ACK_DELAY.
            # Scope the discrete flood ACK to the request's region.
            apply_reply_scope(ack_packet, packet)
            self.log(f"FLOOD ACK timing (no out_path) - delay:{TXT_ACK_DELAY_MS}ms")
            return [(ack_packet, TXT_ACK_DELAY_MS / 1000.0)]

        out_path = bytes(out_path_raw)
        path_hops = PathUtils.get_path_hash_count(out_path_len)
        ack_packet = PacketBuilder.create_ack_from_bytes(
            ack_hash, path=out_path, path_len_encoded=out_path_len
        )
        # Firmware sendAckTo (known out_path) sends the routed ACK at TXT_ACK_DELAY.
        base_delay_ms = TXT_ACK_DELAY_MS

        if self.multi_acks <= 0:
            self.log(f"DIRECT ACK timing (routed) - delay:{base_delay_ms}ms, hops:{path_hops}")
            return [(ack_packet, base_delay_ms / 1000.0)]

        # multi-ack fires at TXT_ACK_DELAY; the normal ACK is staggered +300ms later
        # (firmware sendAckTo: d = TXT_ACK_DELAY, then d += 300 for the second send).
        multi_packet = PacketBuilder.create_multi_ack(
            ack_hash, remaining=1, path=out_path, path_len_encoded=out_path_len
        )
        self.log(f"DIRECT multi-ack timing - base_delay:{base_delay_ms}ms, hops:{path_hops}")
        return [
            (multi_packet, base_delay_ms / 1000.0),
            (ack_packet, (base_delay_ms + MULTI_ACK_STAGGER_MS) / 1000.0),
        ]

    async def _send_delayed_ack(self, pkt, delay_s, timestamp_int) -> None:
        """Send a single ACK packet after ``delay_s`` seconds (best-effort)."""
        await asyncio.sleep(delay_s)
        try:
            await self.send_packet(pkt, wait_for_ack=False)
            self.log(
                f"ACK packet sent successfully (delayed {delay_s * 1000:.1f}ms) "
                f"for timestamp {timestamp_int}"
            )
        except Exception as ack_send_error:
            self.log(f"Failed to send ACK packet: {ack_send_error}")

    async def __call__(self, packet: Packet) -> HandlerResult:
        """Process an inbound TXT_MSG.

        Returns an authenticated HandlerResult when the message was decrypted for
        one of our contacts — i.e. it is genuinely addressed to this identity and
        the caller should consume it. Returns a not-for-us result when it could
        not be decrypted (payload too short, unknown sender, or HMAC failure from
        a dest-hash collision), so the caller may forward/re-flood it instead of
        dropping it.
        """
        if len(packet.payload) < 4:
            self.log("TXT_MSG payload too short to decrypt")
            return HandlerResult.not_for_us()

        src_hash = packet.payload[1]
        # Collect all contacts whose public key first byte matches src_hash (hash collision
        # possible)
        candidates = []
        for contact in self.contacts.contacts:
            try:
                pk = self._contact_pubkey_bytes(contact)
                if len(pk) >= 1 and pk[0] == src_hash:
                    candidates.append(contact)
            except Exception as err:
                self.log(f"Error reading contact key: {err}")

        if not candidates:
            self.log(f"No contact found for src hash: {src_hash:02X}")
            return HandlerResult.not_for_us()

        payload = packet.payload[2:]  # Skip dest_hash and src_hash
        matched_contact = None
        decrypted = None
        shared_secret = None
        for contact in candidates:
            try:
                pubkey_bytes = self._contact_pubkey_bytes(contact)
                if len(pubkey_bytes) != 32:
                    continue
                peer_id = Identity(pubkey_bytes)
                ss = peer_id.calc_shared_secret(self.local_identity.get_private_key())
                aes_key = ss[:16]
                decrypted = CryptoUtils.mac_then_decrypt(aes_key, ss, payload)
                matched_contact = contact
                shared_secret = ss
                break
            except Exception:
                continue

        if matched_contact is None or decrypted is None:
            self.log(
                f"Decryption failed: Invalid HMAC for all {len(candidates)} contact(s) "
                f"with src hash {src_hash:02X}"
            )
            return HandlerResult.not_for_us()

        # Decryption succeeded: this message is genuinely for us. From here on we
        # return a consumed result so the caller keeps it even if the plaintext
        # turns out to be malformed — forwarding a packet that is cryptographically
        # ours is wrong.
        if len(decrypted) < 5:  # timestamp(4) + flags(1) minimum
            self.log("Decrypted message too short for CRC calculation")
            return HandlerResult.consumed()

        # Extract fields from decrypted data
        timestamp = decrypted[:4]  # First 4 bytes are the timestamp
        flags = decrypted[4]  # 5th byte contains flags
        txt_type = (flags >> 2) & 0x3F  # Upper 6 bits are txt_type
        message_body = decrypted[5:]  # Rest is the message content
        sender_prefix = b""
        if txt_type == TXT_TYPE_SIGNED_PLAIN:
            # Signed plain text (e.g. room server posts): a 4-byte author
            # pubkey prefix precedes the text (BaseChatMesh::onPeerDataRecv ->
            # onSignedMessageRecv(&data[5], &data[9])).
            if len(decrypted) < 9:
                self.log("Signed message too short for author prefix")
                return HandlerResult.consumed()
            sender_prefix = bytes(decrypted[5:9])
            message_body = decrypted[9:]

        sender_pubkey = self._contact_pubkey_bytes(matched_contact)
        timestamp_int = int.from_bytes(timestamp, "little")

        # Determine message routing type from packet header. Both plain flood
        # (ROUTE_TYPE_FLOOD) and transport-scoped flood (ROUTE_TYPE_TRANSPORT_FLOOD)
        # count as flood, matching MeshCore Packet::isRouteFlood.
        route_type = packet.get_route_type()
        is_flood = packet.is_route_flood()

        self.log(
            f"Processing message - route_type: {route_type}, is_flood: {is_flood}, "
            f"timestamp: {timestamp_int}, txt_type: {txt_type}"
        )

        # Firmware parity (BaseChatMesh::onPeerDataRecv): signed plain traffic
        # advances the sender contact's sync_since watermark.
        if txt_type == TXT_TYPE_SIGNED_PLAIN:
            try:
                previous_sync = int(getattr(matched_contact, "sync_since", 0) or 0)
            except Exception:
                previous_sync = 0
            if timestamp_int > previous_sync:
                try:
                    matched_contact.sync_since = timestamp_int
                    backing_contact = getattr(matched_contact, "_contact", None)
                    if backing_contact is not None:
                        backing_contact.sync_since = timestamp_int
                        if hasattr(self.contacts, "update"):
                            self.contacts.update(backing_contact)
                    self.log(
                        f"Updated contact sync_since to {timestamp_int} "
                        f"for {getattr(matched_contact, 'name', '?')}"
                    )
                except Exception as sync_err:
                    self.log(f"Failed to update contact sync_since: {sync_err}")

        # Firmware ACKs plain DMs (6-byte, sender-keyed) and signed messages
        # (4-byte, keyed with OUR pubkey); CLI_DATA replies get no delivery ACK.
        ack_hash = self._calc_ack_hash(
            txt_type, decrypted, message_body, sender_pubkey, timestamp_int, flags
        )

        if ack_hash is not None:
            scheduled = self._build_ack_responses(
                packet=packet,
                matched_contact=matched_contact,
                shared_secret=shared_secret,
                pubkey=sender_pubkey,
                ack_hash=ack_hash,
                is_flood=is_flood,
            )
            # Schedule each ACK to be sent after its delay (non-blocking)
            for pkt, delay_s in scheduled:
                asyncio.create_task(self._send_delayed_ack(pkt, delay_s, timestamp_int))
        else:
            self.log(f"Skipping ACK for txt_type={txt_type} (non-delivery-acked type)")

        # For signed plain the 4-byte author prefix was already split off into
        # ``sender_prefix`` above, so ``message_body`` is the bare text here.
        # Firmware treats the body as a C string (BaseChatMesh::onPeerDataRecv):
        # the visible text ends at the first NUL. Everything after it — the AES
        # zero padding and, for attempt > 3, the hidden extended-attempt byte —
        # is not message content and must not be delivered to the app.
        visible_len = self._text_len(message_body)
        decoded_msg = message_body[:visible_len].decode("utf-8", "replace")
        self.log(f"Received TXT_MSG: {decoded_msg}")

        # Intercept as a repeater-command response only for CLI_DATA replies whose
        # authenticated sender has a pending command (firmware routes only
        # TXT_TYPE_CLI_DATA from a known contact to onCommandDataRecv; everything
        # else is delivered normally). Match on the full sender public key so a
        # dest-hash collision cannot cross-resolve. Plain DMs and CLI_DATA with no
        # pending command fall through to normal delivery.
        #
        # TXT_TYPE_CLI_COMMAND falls through too. Firmware hands it to
        # onCLICommandRecv, which runs the command locally only when the sender
        # is flagged isRemoteCLIAllowed() and otherwise queues it for the app
        # (companion_radio/MyMesh.cpp). Core has no CLI of its own to run, so the
        # queue-for-the-app branch is the whole of its behaviour: the command is
        # published as a message carrying txt_type 3, and whoever is driving the
        # node decides whether to answer it (with a CLI_DATA reply).
        if txt_type == TXT_TYPE_CLI_DATA:
            callback = self._pending_command_responses.get(sender_pubkey)
            if callback is not None:
                # One reply completes one command: remove the entry before
                # delivering so a second reply within the window is delivered
                # normally rather than swallowed.
                del self._pending_command_responses[sender_pubkey]
                try:
                    callback(decoded_msg, matched_contact)
                    self.log(
                        f"Command response captured from {matched_contact.name}: {decoded_msg}"
                    )
                    # Don't save command responses to regular message database
                    return HandlerResult.consumed()
                except Exception as e:
                    self.log(f"Error in command response callback: {e}")
                    # Continue with normal message processing if callback fails

        # Save the incoming message by publishing event for app to handle
        message_timestamp = timestamp_int

        # Create message event data for the app to handle storage and deduplication
        normalized_timestamp = (message_timestamp // 1000) * 1000
        content_hash = (
            hash(f"{matched_contact.name}_{decoded_msg}_{normalized_timestamp}") & 0xFFFFFFFF
        )
        message_id = f"rx_{normalized_timestamp}_{content_hash:08x}"

        # Publish new message event - let app handle storage and deduplication
        if self.event_service:
            try:
                from ..events import MeshEvents

                message_data = {
                    "message_id": message_id,
                    "contact_name": matched_contact.name,
                    "contact_pubkey": matched_contact.public_key,
                    "message_text": decoded_msg,
                    "sender_prefix": sender_prefix.hex(),
                    "txt_type": txt_type,
                    "is_outgoing": False,
                    "timestamp": message_timestamp,
                    "delivery_status": "received",
                    # Companion queueMessage() preserves the encoded flood path
                    # length, but marks every direct route as unknown (0xFF).
                    # Keep the encoded byte rather than deriving a byte count
                    # from packet.path: the high bits carry the hash width.
                    "path_len": packet.path_len if is_flood else 0xFF,
                    "network_info": {
                        "rssi": packet.rssi,
                        "snr": packet.snr,
                        "hops": 1,
                    },
                    "sender_name": matched_contact.name,
                    "is_read": False,
                    "packet_hash": packet.calculate_packet_hash().hex().upper(),
                }

                # Publish new message event for app to handle database storage
                self.event_service.publish_sync(MeshEvents.NEW_MESSAGE, message_data)
                self.log(f"TextHandler: Published new message event: {message_id}")

            except Exception as broadcast_error:
                self.log(f"Failed to publish new message event: {broadcast_error}")

        # Set packet.decrypted for ACK processing
        packet.decrypted = {"text": decoded_msg}
        return HandlerResult.consumed()
