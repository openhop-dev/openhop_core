"""Server-side login handler for mesh network authentication.

Handles ANON_REQ login packets from clients, decrypts credentials, and sends
authentication responses based on application-provided authentication logic.

This is the server-side counterpart to login_response.py (client-side).

Note: This is a pure protocol handler. Authentication logic (password validation,
ACL management) should be implemented in the application.
See examples/login_server.py for a complete implementation.
"""

import random
import struct
import time
from typing import Any, Callable, Optional

from ...protocol import CryptoUtils, Identity, Packet, PacketBuilder, PathUtils
from ...protocol.constants import PAYLOAD_TYPE_ANON_REQ, PAYLOAD_TYPE_RESPONSE, acl_is_admin
from ...protocol.region_map import apply_reply_scope
from .base import BaseHandler
from .result import HandlerResult

# Response codes
RESP_SERVER_LOGIN_OK = 0x00  # Login successful
RESP_SERVER_LOGIN_FAILED = 0x01  # Login failed

# Firmware version
FIRMWARE_VER_LEVEL = 2


class LoginServerHandler(BaseHandler):
    """
    Server-side handler for ANON_REQ login packets.

    This handler performs protocol-level operations:
    - Decrypts login requests
    - Calls application authentication callback
    - Builds and sends encrypted responses

    Authentication logic (passwords, ACL, permissions) is delegated to the application.

    Expected request format from client:
    - dest_hash (1 byte): Server's public key hash
    - client_pubkey (32 bytes): Client's public key
    - encrypted_data: Contains timestamp (4 bytes) + password (variable)

    Response format sent to client:
    - timestamp (4 bytes): Server response timestamp
    - response_code (1 byte): RESP_SERVER_LOGIN_OK (0x00) for success
    - keep_alive_interval (1 byte): Legacy field, set to 0
    - is_admin (1 byte): 1 when the ACL role is ADMIN, else 0
    - permissions (1 byte): Full ACL byte; role in the low two bits
      (PERM_ACL_GUEST=0, READ_ONLY=1, READ_WRITE=2, ADMIN=3)
    - random_blob (4 bytes): Random data for packet uniqueness
    - firmware_version (1 byte): Firmware version level
    """

    @staticmethod
    def payload_type() -> int:
        return PAYLOAD_TYPE_ANON_REQ

    def __init__(
        self,
        local_identity,
        log_fn: Callable[[str], None],
        authenticate_callback: Callable[[Identity, bytes, str, int], tuple[bool, int]],
        is_room_server: bool = False,
        get_client_fn: Optional[Callable[[bytes], Any]] = None,
    ):
        """
        Initialize login server handler.

        Args:
            local_identity: Server's local identity
            log_fn: Logging function
            authenticate_callback: Function(client_identity, shared_secret, password, timestamp)
                                   Returns: (success: bool, permissions: int).
                                   ``permissions`` must carry the role in its low
                                   two bits using the firmware ClientACL values
                                   (see PERM_ACL_* in protocol.constants).
            is_room_server: True if this identity is a room server (expects sync_since field),
                           False if repeater (no sync_since field)
            get_client_fn: Optional ACL lookup, ``fn(client_pubkey) -> client``, mirroring
                firmware ``acl.getClient(sender.pub_key, PUB_KEY_SIZE)``. The client is
                expected to expose ``out_path``/``out_path_len``. Supplying it lets a
                DIRECT login be answered along the stored return path instead of by
                flooding (see :meth:`_send_login_response`). Left None the handler keeps
                the pre-#3106 behaviour and floods those replies. Note that the lookup is
                by *full public key*, unlike ``ProtocolRequestHandler.get_client_fn``,
                which is a one-byte-hash lookup.
        """
        self.local_identity = local_identity
        self.log = log_fn
        self.authenticate = authenticate_callback
        self.is_room_server = is_room_server
        self.get_client_fn = get_client_fn
        self._send_packet_callback: Optional[Callable[[Packet, int], None]] = None

    def set_send_packet_callback(self, callback: Callable[[Packet, int], None]):
        """Set callback for sending response packets."""
        self._send_packet_callback = callback

    async def __call__(self, packet: Packet) -> HandlerResult:
        """Handle ANON_REQ login packet from client.

        Returns an authenticated HandlerResult when the request was decrypted for
        this identity — i.e. it is genuinely addressed to us and the caller should
        consume it (a failed password is still ours to reject, not a collision).
        Returns a not-for-us result when it was not for us (wrong dest hash, or an
        HMAC failure from a dest-hash collision), so the caller may forward/re-flood
        it instead of dropping it.
        """
        # Flipped to True once decryption succeeds; used by the outer handler so a
        # post-decrypt error still counts as "for us" while a pre-decrypt error forwards.
        for_us = False
        try:
            # Debug: Log packet routing info
            path_data = packet.get_path_hashes_hex() if packet.path_len > 0 else []
            self.log(
                f"[LoginServer] Packet route flood: {packet.is_route_flood()}, "
                f"path_len: {packet.path_len}, path: {path_data}"
            )

            # Parse ANON_REQ structure: dest_hash(1) + client_pubkey(32) + encrypted_data
            if len(packet.payload) < 34:
                self.log("[LoginServer] ANON_REQ packet too short")
                return HandlerResult.not_for_us()

            dest_hash = packet.payload[0]
            client_pubkey = bytes(packet.payload[1:33])
            encrypted_data = bytes(packet.payload[33:])

            # Verify this is for us
            our_hash = self.local_identity.get_public_key()[0]
            if dest_hash != our_hash:
                return HandlerResult.not_for_us()  # Not for us

            # Create client identity and calculate shared secret
            client_identity = Identity(client_pubkey)
            shared_secret = client_identity.calc_shared_secret(
                self.local_identity.get_private_key()
            )
            aes_key = shared_secret[:16]

            # Decrypt the login request
            try:
                plaintext = CryptoUtils.mac_then_decrypt(aes_key, shared_secret, encrypted_data)
            except Exception as e:
                self.log(f"[LoginServer] Failed to decrypt login request: {e}")
                return HandlerResult.not_for_us()

            # Decryption succeeded: this ANON_REQ is genuinely for us. Consume it
            # from here on regardless of parse/auth outcome.
            for_us = True

            if len(plaintext) < 4:
                self.log("[LoginServer] Decrypted data too short")
                return HandlerResult.consumed()

            # Parse plaintext - two formats:
            # Repeater format: timestamp(4) + password(variable) + null
            # Room server format: timestamp(4) + sync_since(4) + password(variable) + null
            client_timestamp = struct.unpack("<I", plaintext[:4])[0]

            # Debug logging
            self.log(f"[LoginServer] Plaintext hex: {plaintext.hex()}")
            self.log(f"[LoginServer] Plaintext length: {len(plaintext)} bytes")

            # Use explicit identity type to determine format
            sync_since = None
            if self.is_room_server:
                # Room server format: sync_since(4) + password
                if len(plaintext) < 8:
                    self.log("[LoginServer] Room server packet too short for sync_since field")
                    return HandlerResult.consumed()
                sync_since = struct.unpack("<I", plaintext[4:8])[0]

                # Find null terminator AFTER sync_since field (starting from byte 8)
                null_idx = plaintext.find(b"\x00", 8)
                if null_idx == -1:
                    null_idx = len(plaintext)

                password_bytes = plaintext[8:null_idx]
                self.log(
                    f"[LoginServer] Room server: sync_since={sync_since}, "
                    f"password from byte 8 to {null_idx}"
                )
                self.log(
                    f"[LoginServer] Password hex: "
                    f"{password_bytes.hex() if password_bytes else '(empty)'}"
                )
            else:
                # Repeater format: password only
                # Find null terminator after timestamp (starting from byte 4)
                null_idx = plaintext.find(b"\x00", 4)
                if null_idx == -1:
                    null_idx = len(plaintext)

                password_bytes = plaintext[4:null_idx]
                self.log(f"[LoginServer] Repeater format: password from byte 4 to {null_idx}")

            # Null-terminate password
            null_idx = password_bytes.find(b"\x00")
            if null_idx >= 0:
                password_bytes = password_bytes[:null_idx]
            password = password_bytes.decode("utf-8", errors="ignore")

            self.log(
                f"[LoginServer] Login request from {client_pubkey[:6].hex()}... "
                f"password={'<empty>' if not password else '<provided>'}"
            )

            # Call application authentication logic with optional sync_since parameter
            # For backwards compatibility, check if authenticate accepts sync_since
            import inspect

            sig = inspect.signature(self.authenticate)
            if "sync_since" in sig.parameters:
                success, permissions = self.authenticate(
                    client_identity,
                    shared_secret,
                    password,
                    client_timestamp,
                    sync_since,
                )
            else:
                # Old signature without sync_since
                success, permissions = self.authenticate(
                    client_identity, shared_secret, password, client_timestamp
                )

            if success:
                self.log("[LoginServer] Authentication successful")
                # Send success response
                await self._send_login_response(
                    client_identity,
                    shared_secret,
                    packet.is_route_flood(),
                    RESP_SERVER_LOGIN_OK,
                    permissions,
                    packet,
                )
            else:
                self.log("[LoginServer] Authentication failed")
                # Optionally send failure response (or just ignore)
                # Most implementations just ignore failed attempts

            return HandlerResult.consumed()

        except Exception as e:
            self.log(f"[LoginServer] Error handling login packet: {e}")
            return HandlerResult(authenticated=for_us)

    def _lookup_client(self, client_identity: Identity):
        """Return the ACL entry for this client, or None (never raises)."""
        if self.get_client_fn is None:
            return None
        try:
            return self.get_client_fn(client_identity.get_public_key())
        except Exception as e:  # an app ACL must not be able to kill the reply
            self.log(f"[LoginServer] Client lookup failed: {e}")
            return None

    def _invalidate_out_path_on_flood(self, client) -> None:
        """Forget a stale return path after a flood login.

        Firmware ``handleLoginReq``: ``if (is_flood) client->out_path_len =
        OUT_PATH_UNKNOWN;`` — the client reached us by flooding, so whatever path
        we last stored for it is no longer trustworthy and must be rediscovered.
        This does not affect the reply now being built (a flood login is always
        answered with a PATH return); it keeps the *next* DIRECT request from
        being answered along a dead path.
        """
        if client is None:
            return
        try:
            # Probe inside the try: hasattr only swallows AttributeError, so an
            # ACL property raising anything else would escape and, via the
            # caller's except, cost the reply entirely.
            if not hasattr(client, "out_path_len"):
                # Never graft a routing field onto an app object that does not
                # model one.
                return
            if getattr(client, "out_path_len", -1) >= 0:
                self.log("[LoginServer] Flood login: clearing stored out_path")
            client.out_path_len = -1
            # Clear the buffer too, so nothing else reading the pair sees a
            # half-cleared record (firmware's ClientInfo owns both fields).
            if hasattr(client, "out_path"):
                client.out_path = type(client.out_path)()
        except Exception as e:
            self.log(f"[LoginServer] Could not clear stored out_path: {e}")

    def _known_out_path(self, client) -> tuple[Optional[bytes], int]:
        """Return ``(out_path, encoded_len)`` for a client, or ``(None, -1)``.

        Mirrors firmware's ``client->out_path_len != OUT_PATH_UNKNOWN`` test.
        Beyond it, two guards, because ``out_path``/``out_path_len`` are supplied
        by the application's ACL and firmware's fixed ``ClientInfo`` gives no
        equivalent freedom:

        * the encoded length must decode (``is_valid_path_len``);
        * the stored bytes must cover the hop count that length declares.
          ``Packet.set_path`` stores the buffer verbatim while ``path_len`` keeps
          the declared count, and ``Packet.write_to`` rejects the mismatch with
          ``ValueError: path_len mismatch`` — so an over- or under-long buffer
          means the reply is never transmitted at all.

        Anything unusable falls back to ``(None, -1)`` and the caller floods, so
        a malformed ACL entry costs the direct route but never the reply itself.
        Note that ``ProtocolRequestHandler`` and the text-ACK path apply only the
        first of these two guards today, and ``ReturnPathHandler._known_out_path``
        applies both -- four near-identical copies of this validation live in the
        tree. Consolidating them into one ``PathUtils`` helper is worth doing, but
        it reaches well past this port.
        """
        if client is None:
            return None, -1
        try:
            raw_len = getattr(client, "out_path_len", -1)
            out_path_len = -1 if raw_len is None else int(raw_len)
            if out_path_len < 0 or not PathUtils.is_valid_path_len(out_path_len):
                return None, -1
            out_path = bytes(getattr(client, "out_path", b"") or b"")
            expected = PathUtils.get_path_byte_len(out_path_len)
            if len(out_path) < expected:
                self.log(
                    f"[LoginServer] Stored out_path is {len(out_path)}B but path_len "
                    f"0x{out_path_len:02X} declares {expected}B -- flooding instead"
                )
                return None, -1
            return out_path[:expected], out_path_len
        except Exception as e:
            # An application ACL must not be able to kill the login reply --
            # same invariant _lookup_client states. e.g. an out_path persisted
            # as a hex string (contact_store's on-disk shape) would raise here.
            self.log(f"[LoginServer] Unusable stored out_path ({e}) -- flooding instead")
            return None, -1

    async def _send_login_response(
        self,
        client_identity: Identity,
        shared_secret: bytes,
        is_flood: bool,
        response_code: int,
        permissions: int,
        original_packet: Packet = None,
    ):
        """Build and send login response packet to client."""
        if self._send_packet_callback is None:
            self.log("[LoginServer] No send packet callback set, cannot send response")
            return

        try:
            # Build response data (13 bytes total)
            # timestamp(4) + response_code(1) + keep_alive(1) + is_admin(1) +
            # permissions(1) + random(4) + firmware_ver(1)
            reply_data = bytearray(13)
            current_time = int(time.time())

            struct.pack_into("<I", reply_data, 0, current_time)  # timestamp
            reply_data[4] = response_code  # response code
            reply_data[5] = 0  # legacy keep-alive interval
            # is_admin mirrors firmware ClientInfo::isAdmin(): the role is the
            # low two bits and ADMIN is 3, so this is an equality test, not a
            # bit test. Testing 0x02 would also flag READ_WRITE (2) as admin.
            reply_data[6] = 1 if acl_is_admin(permissions) else 0
            reply_data[7] = permissions  # full permissions byte
            struct.pack_into("<I", reply_data, 8, random.randint(0, 0xFFFFFFFF))  # random blob
            reply_data[12] = FIRMWARE_VER_LEVEL  # firmware version

            # Create response packet, mirroring firmware ``chooseReplyRoute``
            # (``helpers/RoutingPolicy.h``, upstream PR #3106) as applied by
            # ``simple_repeater``'s ``onAnonDataRecv``:
            #  - REPLY_ROUTE_PATH_RETURN  flood login: a PATH packet carrying the
            #    response, so the sender learns the path TO here and can sendDirect.
            #  - REPLY_ROUTE_DIRECT_OUT_PATH  direct login and we hold an out_path
            #    for this client: reply DIRECT along it.
            #  - REPLY_ROUTE_FLOOD  direct login, no path known: flood the reply.
            # (REPLY_ROUTE_DIRECT_SUPPLIED cannot arise here: ``handleLoginReq``
            # never sets ``reply_path_len``, so a login carries no supplied path.
            # The discovery sub-types that do are handled by AnonRequestHandler.)
            client = self._lookup_client(client_identity)
            out_path, out_path_len = None, -1
            if is_flood:
                self._invalidate_out_path_on_flood(client)
            else:
                out_path, out_path_len = self._known_out_path(client)

            if is_flood:
                client_hash = client_identity.get_public_key()[0]
                server_hash = self.local_identity.get_public_key()[0]
                path_list = (
                    list(original_packet.path[: original_packet.get_path_byte_len()])
                    if original_packet and original_packet.path_len > 0
                    else []
                )

                self.log(
                    f"[LoginServer] Creating PATH response: "
                    f"client_hash=0x{client_hash:02X}, "
                    f"server_hash=0x{server_hash:02X}, path={path_list}"
                )

                path_len_encoded_arg = (
                    original_packet.path_len
                    if original_packet and original_packet.path_len > 0
                    else None
                )
                response_pkt = PacketBuilder.create_path_return(
                    dest_hash=client_hash,
                    src_hash=server_hash,
                    secret=shared_secret,
                    path=path_list,
                    extra_type=PAYLOAD_TYPE_RESPONSE,
                    extra=bytes(reply_data),
                    path_len_encoded=path_len_encoded_arg,
                )
                packet_type_name = "PATH"
            elif out_path is not None:
                # Direct login with a stored out_path: reply DIRECT along it.
                # Flooding here is the bug PR #3106 fixed -- the reply is dropped
                # at hop 0 by any repeater running flood.max.unscoped=0.
                response_pkt = PacketBuilder.create_datagram(
                    ptype=PAYLOAD_TYPE_RESPONSE,
                    dest=client_identity,
                    local_identity=self.local_identity,
                    secret=shared_secret,
                    plaintext=bytes(reply_data),
                    route_type="direct",
                )
                response_pkt.set_path(out_path, out_path_len)
                packet_type_name = "RESPONSE(direct)"
                self.log(
                    "[LoginServer] Creating RESPONSE datagram (direct login, "
                    f"{PathUtils.get_path_hash_count(out_path_len)}-hop out_path)"
                )
            else:
                # Direct login and no return path known: flood, as firmware's
                # REPLY_ROUTE_FLOOD fallback does.
                response_pkt = PacketBuilder.create_datagram(
                    ptype=PAYLOAD_TYPE_RESPONSE,
                    dest=client_identity,
                    local_identity=self.local_identity,
                    secret=shared_secret,
                    plaintext=bytes(reply_data),
                    route_type="flood",
                )
                packet_type_name = "RESPONSE(flood)"
                self.log("[LoginServer] Creating RESPONSE datagram (direct login, flood reply)")

            # Flood replies only. Accumulate the reply's path at the *request's*
            # hash width, not this node's own preference: firmware sends both
            # flood branches through sendFloodReply(..., packet->getPathHashSize())
            # (simple_repeater onAnonDataRecv), while the node's path_hash_mode
            # governs only packets it originates itself (sendFloodScoped(
            # default_scope, ..., _prefs.path_hash_mode + 1)). Marked applied so
            # the dispatcher's node default cannot stamp over the mirror, the same
            # way apply_reply_scope protects the region decision below.
            #
            # The out_path branch is excluded deliberately: its path_len came from
            # the stored path and already carries that path's own hash width, so
            # stamping the request's width over it would misdescribe the bytes.
            # ProtocolRequestHandler skips its direct branch for the same reason.
            if out_path is None:
                in_path_len = getattr(original_packet, "path_len", 0) if original_packet else 0
                in_hash_size = (
                    PathUtils.get_path_hash_size(in_path_len)
                    if PathUtils.is_valid_path_len(in_path_len)
                    else 1
                )
                response_pkt.apply_path_hash_mode(in_hash_size - 1, mark_applied=True)

            # Debug: Log packet details
            self.log(
                f"[LoginServer] RESPONSE packet details: "
                f"header=0x{response_pkt.header:02X}, "
                f"payload_len={response_pkt.payload_len}, "
                f"path_len={response_pkt.path_len}, "
                f"payload[0:2]={bytes(response_pkt.payload[:2]).hex()}"
            )

            # Scope the flood reply (PATH-return for a flood login, or the flood
            # RESPONSE datagram for a direct login with no known path) to the
            # region the request arrived under. Skipped for the out_path branch:
            # that is a sendDirect, which firmware never routes through
            # sendFloodReply and which carries no transport codes.
            #
            # Belt and braces as things stand -- on a DIRECT packet the helper
            # can only set _flood_scope_applied, which the dispatcher ignores for
            # anything that is not a plain FLOOD. The guard states the intent, so
            # that stays true if apply_reply_scope grows a wider effect.
            if out_path is None:
                apply_reply_scope(response_pkt, original_packet)

            # Send with delay (matches C++ SERVER_RESPONSE_DELAY)
            delay_ms = 300
            self._send_packet_callback(response_pkt, delay_ms)

            self.log(
                f"[LoginServer] Sent login response ({packet_type_name}) to "
                f"{client_identity.get_public_key()[:6].hex()}..."
            )

        except Exception as e:
            self.log(f"[LoginServer] Failed to send login response: {e}")
