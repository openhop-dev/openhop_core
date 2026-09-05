"""
Protocol request handler for authenticated client requests.

Handles REQ packets and sends RESPONSE packets with requested data.
"""

import struct
import time
from typing import Callable, Optional

from openhop_core.protocol import PacketBuilder
from openhop_core.protocol.constants import MAX_PATH_SIZE, PAYLOAD_TYPE_REQ, PAYLOAD_TYPE_RESPONSE
from openhop_core.protocol.crypto import CryptoUtils
from openhop_core.protocol.packet_utils import PathUtils
from openhop_core.protocol.region_map import apply_reply_scope

from .result import HandlerResult

# Request type codes (matching C++ implementation)
REQ_TYPE_GET_STATUS = 0x01
REQ_TYPE_KEEP_ALIVE = 0x02
REQ_TYPE_GET_TELEMETRY_DATA = 0x03
REQ_TYPE_GET_ACCESS_LIST = 0x05
REQ_TYPE_GET_NEIGHBOURS = 0x06
REQ_TYPE_GET_OWNER_INFO = 0x07  # Variable-length: tag(4) + "version\nname\nowner"

# Response delay (matching C++ SERVER_RESPONSE_DELAY)
SERVER_RESPONSE_DELAY_MS = 500


class ProtocolRequestHandler:
    """
    Handler for protocol request packets (PAYLOAD_TYPE_REQ).

    Processes encrypted request packets from authenticated clients and sends
    appropriate RESPONSE packets. Request handling is delegated to callbacks
    for application-specific logic.
    """

    @staticmethod
    def payload_type():
        """Return the payload type this handler processes."""
        return PAYLOAD_TYPE_REQ

    def __init__(
        self,
        local_identity,
        contacts,
        get_client_fn: Optional[Callable] = None,
        get_clients_fn: Optional[Callable] = None,
        request_handlers: Optional[dict] = None,
        log_fn: Optional[Callable] = None,
    ):
        """
        Initialize protocol request handler.

        Args:
            local_identity: LocalIdentity for this handler
            contacts: Contact manager or wrapper providing client lookup
            get_client_fn: Optional function to get client info by hash
            request_handlers: Dict mapping request type codes to handler functions
            log_fn: Optional logging function
        """
        self.local_identity = local_identity
        self.contacts = contacts
        self.get_client_fn = get_client_fn
        self.get_clients_fn = get_clients_fn
        self.request_handlers = request_handlers or {}
        self.log = log_fn if log_fn else lambda msg: None

    async def __call__(self, packet) -> HandlerResult:
        """
        Process a protocol request packet.

        Args:
            packet: Packet instance with REQ payload

        Returns:
            HandlerResult: ``authenticated`` is True once the REQ has been
            MAC-verified and decrypted for a concrete local client (the caller
            must consume it even when no response is produced); False when the
            one-byte dest prefix collided with ours but no local client
            authenticated it, so the caller must leave the packet for the
            forwarding engine. ``response`` carries the RESPONSE packet to send,
            or None.
        """
        # Flipped to True once decryption succeeds; used so a post-decrypt error
        # still counts as "for us" while a pre-decrypt error is forwarded.
        for_us = False
        try:
            if len(packet.payload) < 2:
                return HandlerResult.not_for_us()

            dest_hash = packet.payload[0]
            src_hash = packet.payload[1]

            # Verify this packet is for us
            our_hash = self.local_identity.get_public_key()[0]
            if dest_hash != our_hash:
                return HandlerResult.not_for_us()

            self.log(f"Processing REQ from 0x{src_hash:02X}")

            # Resolve client by trying all same-hash candidates until decrypt succeeds.
            clients = self._get_clients(src_hash)
            if not clients:
                self.log(f"REQ from unknown client 0x{src_hash:02X}")
                return HandlerResult.not_for_us()

            # Decrypt request
            encrypted_data = packet.payload[2:]
            client = None
            shared_secret = None
            plaintext = None
            decrypt_attempted = 0
            for candidate in clients:
                candidate_secret = self._get_shared_secret(candidate)
                if not candidate_secret:
                    continue
                decrypt_attempted += 1
                try:
                    candidate_plaintext = CryptoUtils.mac_then_decrypt(
                        candidate_secret[:16], candidate_secret, bytes(encrypted_data)
                    )
                except Exception:
                    continue
                client = candidate
                shared_secret = candidate_secret
                plaintext = candidate_plaintext
                break

            if client is None or shared_secret is None or plaintext is None:
                if decrypt_attempted == 0:
                    self.log(f"No shared secret for client 0x{src_hash:02X}")
                else:
                    self.log(
                        f"Failed to decrypt REQ for all {decrypt_attempted} candidate(s) "
                        f"with src hash 0x{src_hash:02X}"
                    )
                return HandlerResult.not_for_us()

            # MAC verified for a concrete client: this REQ is genuinely for us.
            # Consume it from here on even if parsing fails or no response is built —
            # forwarding a packet that is cryptographically ours would be wrong.
            for_us = True

            # Parse request
            if len(plaintext) < 5:
                self.log("REQ packet too short")
                return HandlerResult.consumed()

            timestamp = struct.unpack("<I", plaintext[0:4])[0]
            req_type = plaintext[4]
            req_data = plaintext[5:] if len(plaintext) > 5 else b""

            self.log(f"REQ type=0x{req_type:02X}, timestamp={timestamp}")

            # Replay protection (simple_repeater onPeerDataRecv PAYLOAD_TYPE_REQ):
            # accept only a strictly newer timestamp than the last accepted request
            # from this authenticated client, so a captured admin REQ cannot be
            # replayed. Enforced here in the core handler, not left to app code.
            last_ts = self._get_last_req_ts(client)
            if timestamp <= last_ts:
                self.log(
                    f"Possible REQ replay from 0x{src_hash:02X}: "
                    f"timestamp={timestamp} <= last={last_ts}"
                )
                return HandlerResult.consumed()

            # Handle request
            response_data = await self._handle_request(client, timestamp, req_type, req_data)

            # Firmware advances last_timestamp only after a valid command (reply_len > 0):
            # an unhandled/invalid request must not move the replay watermark.
            if not response_data:
                return HandlerResult.consumed()

            self._advance_client_watermark(client, timestamp)
            return HandlerResult.consumed(
                self._build_response(packet, client, response_data, shared_secret)
            )

        except Exception as e:
            self.log(f"Error processing REQ: {e}")
            return HandlerResult(authenticated=for_us)

    def _get_clients(self, src_hash: int):
        """Get all client candidates by source hash."""
        if self.get_clients_fn:
            clients = self.get_clients_fn(src_hash)
            if clients is None:
                return []
            if isinstance(clients, (list, tuple)):
                return [c for c in clients if c is not None]
            return [clients]

        if self.get_client_fn:
            client = self.get_client_fn(src_hash)
            return [client] if client is not None else []

        # Fallback: search in contacts
        matches = []
        if hasattr(self.contacts, "contacts"):
            for contact in self.contacts.contacts:
                if hasattr(contact, "public_key"):
                    pk = (
                        bytes.fromhex(contact.public_key)
                        if isinstance(contact.public_key, str)
                        else contact.public_key
                    )
                    if pk[0] == src_hash:
                        matches.append(contact)

        return matches

    def _get_shared_secret(self, client):
        """Get shared secret for client."""
        if hasattr(client, "shared_secret"):
            return client.shared_secret

        if hasattr(client, "public_key"):
            pk = (
                bytes.fromhex(client.public_key)
                if isinstance(client.public_key, str)
                else client.public_key
            )
            from openhop_core.protocol.identity import Identity

            identity = Identity(pk)
            return identity.calc_shared_secret(self.local_identity.get_private_key())

        return None

    def _get_last_req_ts(self, client) -> int:
        """Last accepted REQ timestamp for this client (0 if none).

        Reads the client's own ``last_timestamp`` (firmware
        ``client->last_timestamp``) so REQ shares the login/ACL replay watermark.
        """
        ts = getattr(client, "last_timestamp", 0)
        try:
            return int(ts) if ts is not None else 0
        except (TypeError, ValueError):
            return 0

    def _advance_client_watermark(self, client, timestamp: int) -> None:
        """Advance the replay watermark (and last_activity) after a valid REQ."""
        try:
            # Monotonic: the watermark must never move backwards, even if
            # another accepted request advanced it between our replay check
            # and this write.
            client.last_timestamp = max(self._get_last_req_ts(client), timestamp)
            if hasattr(client, "last_activity"):
                client.last_activity = int(time.time())
        except Exception:
            pass

    async def _handle_request(self, client, timestamp: int, req_type: int, req_data: bytes):
        """
        Handle request and generate response.

        Args:
            client: Client info object
            timestamp: Request timestamp
            req_type: Request type code
            req_data: Request payload

        Returns:
            bytes: Response data (timestamp + payload) or None
        """
        # Build response with reflected timestamp
        response = bytearray(struct.pack("<I", timestamp))

        # Check if we have a handler for this request type
        if req_type in self.request_handlers:
            handler = self.request_handlers[req_type]
            payload = handler(client, timestamp, req_data)
            if payload is not None:
                response.extend(payload)
                return bytes(response)

        # Default handlers
        if req_type == REQ_TYPE_KEEP_ALIVE:
            return bytes(response)

        self.log(f"No handler for request type 0x{req_type:02X}")
        return None

    def _build_response(self, original_packet, client, response_data: bytes, shared_secret: bytes):
        """
        Build RESPONSE packet to send back to client.

        Matches simple_repeater firmware: REQ via flood → path-return PATH via flood;
        REQ via direct → RESPONSE via direct (if client out_path) else RESPONSE via flood.
        """
        try:
            # Get client identity
            from openhop_core.protocol.identity import Identity

            if hasattr(client, "id") and hasattr(client.id, "get_public_key"):
                client_identity = client.id
            else:
                pk = (
                    bytes.fromhex(client.public_key)
                    if isinstance(client.public_key, str)
                    else client.public_key
                )
                client_identity = Identity(pk)

            client_hash = client_identity.get_public_key()[0]
            our_hash = self.local_identity.get_public_key()[0]

            # REQ via flood → path-return PATH (firmware: createPathReturn + sendFlood)
            if getattr(original_packet, "is_route_flood", lambda: False)():
                path_len_byte = getattr(original_packet, "path_len", 0)
                path_byte_len = (
                    PathUtils.get_path_byte_len(path_len_byte)
                    if PathUtils.is_valid_path_len(path_len_byte)
                    else 0
                )
                raw_path = getattr(original_packet, "path", None) or b""
                path_list = list(raw_path[:path_byte_len]) if path_byte_len else []
                path_len_encoded_arg = (
                    path_len_byte if PathUtils.is_valid_path_len(path_len_byte) else None
                )
                reply_packet = PacketBuilder.create_path_return(
                    dest_hash=client_hash,
                    src_hash=our_hash,
                    secret=shared_secret,
                    path=path_list,
                    extra_type=PAYLOAD_TYPE_RESPONSE,
                    extra=response_data,
                    path_len_encoded=path_len_encoded_arg,
                )
                hash_size = (
                    PathUtils.get_path_hash_size(path_len_byte)
                    if PathUtils.is_valid_path_len(path_len_byte)
                    else 1
                )
                # mark_applied: without it the dispatcher's node-default
                # path_hash_mode (_apply_default_path_hash_mode, called from
                # send_packet) overwrites this mirror on the way out, and the
                # reply accumulates at the node's own width instead of the
                # request's — which is what firmware's sendFloodReply(...,
                # packet->getPathHashSize()) exists to avoid.
                reply_packet.apply_path_hash_mode(hash_size - 1, mark_applied=True)
                # Scope the flood PATH-return to the region the REQ arrived
                # under: TRANSPORT_FLOOD with the code re-hashed over this
                # reply's payload, or plain when the request was unscoped/direct.
                apply_reply_scope(reply_packet, original_packet)
                self.log(f"PATH (path-return) built for 0x{client_hash:02X} via FLOOD")
                return reply_packet

            # REQ via direct: use client out_path if set, else flood
            route_type = "flood"
            path_bytes = None
            path_len_encoded = None
            if (
                hasattr(client, "out_path_len")
                and client.out_path_len >= 0
                and hasattr(client, "out_path")
                and PathUtils.is_valid_path_len(client.out_path_len)
            ):
                route_type = "direct"
                path_bytes = client.out_path[:MAX_PATH_SIZE]
                path_len_encoded = client.out_path_len

            reply_packet = PacketBuilder.create_datagram(
                ptype=PAYLOAD_TYPE_RESPONSE,
                dest=client_identity,
                local_identity=self.local_identity,
                secret=shared_secret,
                plaintext=response_data,
                route_type=route_type,
            )
            if path_bytes is not None and path_len_encoded is not None:
                reply_packet.set_path(path_bytes, path_len_encoded)
            if route_type == "flood":
                # Same sendFloodReply call as the PATH-return above, same third
                # argument: accumulate at the REQ's hash width, not this node's
                # own preference. A DIRECT request that reached us has had its
                # hops consumed, but removeSelfFromPath only decrements the
                # count — path_len bits 6-7 still carry the width it was routed
                # at. Only the flood branch: the direct branch's path_len comes
                # from the client's out_path above and must not be stamped over.
                in_path_len = getattr(original_packet, "path_len", 0) or 0
                in_hash_size = (
                    PathUtils.get_path_hash_size(in_path_len)
                    if PathUtils.is_valid_path_len(in_path_len)
                    else 1
                )
                reply_packet.apply_path_hash_mode(in_hash_size - 1, mark_applied=True)
                # No out_path, so this RESPONSE floods via sendFloodReply.
                # chooseReplyScope: an unscoped-flood request is mirrored plain
                # and marked final here. A DIRECT or unresolved request is
                # REPLY_SCOPE_DEFAULT, which is left to the send layer -- as is
                # a node with no RegionMap at all, where this is simply inert.
                # Either way the ordinary precedence supplies the key
                # (BaseChatMesh sendFloodScoped).
                apply_reply_scope(reply_packet, original_packet)

            self.log(f"RESPONSE built for 0x{client_hash:02X} via {route_type.upper()}")
            return reply_packet

        except Exception as e:
            self.log(f"Error building RESPONSE: {e}")
            return None
