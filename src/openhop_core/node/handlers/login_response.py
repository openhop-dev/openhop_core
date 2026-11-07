import struct
from typing import Callable, Optional

from ...protocol import CryptoUtils, Identity, Packet
from ...protocol.constants import (
    PAYLOAD_TYPE_ANON_REQ,
    PAYLOAD_TYPE_PATH,
    PAYLOAD_TYPE_RESPONSE,
    acl_role,
)
from ...protocol.packet_utils import PathUtils
from ...util.callbacks import invoke_maybe_awaitable
from .base import BaseHandler
from .result import HandlerResult
from .return_path import ReturnPathTeacher

# Response codes from C++ server
# Login reply byte 6, the legacy admin flag. Firmware's room server overloads
# it into three states (simple_room_server/MyMesh.cpp):
#     reply_data[6] = isAdmin() ? 1 : (permissions == 0 ? 2 : 0)
# so 2 means "plain guest", NOT admin. Repeaters and sensors only ever send
# 0 or 1. Treating this byte as a boolean makes a stock room server's guests
# look like admins.
LOGIN_ADMIN_CODE_NOT_ADMIN = 0
LOGIN_ADMIN_CODE_ADMIN = 1
LOGIN_ADMIN_CODE_GUEST = 2

RESP_SERVER_LOGIN_OK = 0x80
# Alternative success code observed in practice
RESP_SERVER_LOGIN_SUCCESS_ALT = 0x00


class LoginResponseHandler(BaseHandler):
    """
    Handles PAYLOAD_TYPE_RESPONSE packets for login authentication responses.

    Expected response format from C++ server:
    - timestamp (4 bytes): Server response timestamp
    - response_code (1 byte): RESP_SERVER_LOGIN_OK (0x80) for success
    - keep_alive_interval (1 byte): Recommended keep-alive interval (secs / 16)
    - admin_code (1 byte): legacy admin flag; 1 = admin, 2 = plain guest on a
      room server, 0 otherwise. Only 1 means admin.
    - permissions (1 byte): ACL byte; role in the low two bits (v7+ servers)
    - random_blob (4 bytes): Random data for packet uniqueness

    """

    @staticmethod
    def payload_type() -> int:
        return PAYLOAD_TYPE_RESPONSE

    def __init__(self, local_identity, contacts, log_fn, *, return_path_teacher=None):
        self.local_identity = local_identity
        self.contacts = contacts
        self.log = log_fn
        # Shared with ProtocolResponseHandler by the factory; constructed here
        # when absent so standalone use still works (see :mod:`.return_path`).
        self.return_path_teacher = return_path_teacher or ReturnPathTeacher(
            log_fn, local_identity, contacts
        )
        # Pending login completions keyed by the target contact's full public key
        # (32 bytes). A response is dispatched only to the waiter whose target
        # matches the authenticated sender, mirroring the firmware sender gate
        # (companion_radio MyMesh.cpp: pending_login compared against the
        # responding contact's pubkey) generalized to concurrent logins.
        self._pending_logins = {}  # pubkey bytes -> callback
        # Store login passwords persistently (not tied to contact objects)
        self._active_login_passwords = {}  # dest_hash -> password
        # Protocol response handler for forwarding telemetry responses
        self._protocol_response_handler = None
        # See set_foreign_request_probe: distinguishes a login reply from any
        # other reply that happens to arrive while a login is pending.
        self._foreign_request_probe: Optional[Callable[[int, bytes], bool]] = None

    def set_packet_injector(self, injector) -> None:
        """Wire the transmit path used for return-path teaching.

        Companion layers normally reach the shared teacher through
        ``ProtocolResponseHandler.set_packet_injector``; this exists so a
        standalone ``LoginResponseHandler`` can teach too, instead of silently
        no-opping.
        """
        self.return_path_teacher.set_injector(injector)

    def set_protocol_response_handler(self, protocol_response_handler):
        """Set protocol response handler for forwarding telemetry responses."""
        self._protocol_response_handler = protocol_response_handler

    def register_login_callback(self, pubkey: bytes, callback: Callable[[bool, dict], None]):
        """Register a completion for a login to the contact with ``pubkey``.

        Keyed by the target's full public key (not the 1-byte dest hash, which
        collides). The callback accepts (success: bool, response_data: dict).
        """
        self._pending_logins[bytes(pubkey)] = callback

    def expects_login_response(self, pubkey: bytes, tag: int) -> bool:
        """Whether this sender's response belongs to a pending login."""
        key = bytes(pubkey)
        if key not in self._pending_logins:
            return False
        if self._foreign_request_probe is not None:
            try:
                if self._foreign_request_probe(tag, key):
                    return False
            except Exception as e:
                self.log(f"Foreign-request probe failed: {e}")
        return True

    def remove_login_callback(self, pubkey: bytes, callback) -> None:
        """Remove the pending login for ``pubkey`` only if it is ``callback``.

        Identity-guarded so a timed-out login never clears a concurrent login's
        pending completion.
        """
        key = bytes(pubkey)
        if self._pending_logins.get(key) is callback:
            del self._pending_logins[key]

    @staticmethod
    def _pubkey_bytes(contact) -> bytes:
        """Return a contact's public key as 32 raw bytes (hex str or bytes)."""
        pk = contact.public_key
        return pk if isinstance(pk, bytes) else bytes.fromhex(pk)

    def _is_foreign_request_reply(self, response_data: Optional[dict], contact) -> bool:
        """True when this reply answers some *other* pending request, not a login.

        Best-effort: with no probe wired, or no decodable tag, behaviour is
        unchanged (the login branch decides), so a standalone handler keeps
        working exactly as before.
        """
        if self._foreign_request_probe is None or not response_data:
            return False
        tag = response_data.get("timestamp")
        if tag is None:
            return False
        try:
            if not self._foreign_request_probe(int(tag) & 0xFFFFFFFF, self._pubkey_bytes(contact)):
                return False
        except Exception as e:
            self.log(f"Foreign-request probe failed: {e}")
            return False
        self.log(
            f"Response from '{getattr(contact, 'name', '?')}' reflects tag "
            f"0x{int(tag) & 0xFFFFFFFF:08X} of a pending request, not a login; forwarding"
        )
        return True

    def _has_pending_login_for_hash(self, lookup_hash: int) -> bool:
        """True when any pending login (or stored password) targets this hash."""
        if lookup_hash in self._active_login_passwords:
            return True
        return any(key and key[0] == lookup_hash for key in self._pending_logins)

    async def _forward_to_protocol_handler(self, packet) -> HandlerResult:
        """Route a RESPONSE that is not a pending login onward.

        Telemetry/status responses correlate in the protocol response handler.
        PATH packets are skipped: PathHandler already invoked the protocol
        response handler for them before we were called.
        """
        if self._protocol_response_handler:
            if packet.get_payload_type() == PAYLOAD_TYPE_PATH:
                return HandlerResult.not_for_us()
            try:
                result = await self._protocol_response_handler(packet)
                return result if isinstance(result, HandlerResult) else HandlerResult.not_for_us()
            except Exception as e:
                self.log("Error forwarding RESPONSE packet to " f"protocol response handler: {e}")
        return HandlerResult.not_for_us()

    def store_login_password(self, dest_hash: int, password: str):
        """Store password for response decryption by destination hash."""
        self._active_login_passwords[dest_hash] = password

    def clear_login_password(self, dest_hash: int):
        """Clear stored password for destination hash."""
        if dest_hash in self._active_login_passwords:
            del self._active_login_passwords[dest_hash]

    def set_foreign_request_probe(self, probe: Optional[Callable[[int, bytes], bool]]) -> None:
        """Wire a check for "this reflected tag belongs to some other request".

        ``probe(tag, contact_pubkey)`` returns True when the tag matches a pending
        binary/protocol request rather than a login. Without it, a pending login
        makes this handler claim *every* authenticated RESPONSE from that contact,
        because a login reply and a status/telemetry/neighbours reply are
        indistinguishable by contact alone.

        Firmware has the same ambiguity but a one-response window — MyMesh
        ``onContactResponse`` clears ``pending_login`` on the first response from
        the contact, so at most one packet can be misread. openHop deliberately
        keeps a login waiter alive far longer (``FRAME_LOGIN_PENDING_TTL_S``, so a
        late flood login reply still completes), which without this probe turns
        that one-packet window into a two-minute one: observed live, a 148-byte
        neighbours reply was consumed here and reported as ``Login failed (code:
        0x2F)`` — 0x2F being the low byte of its ``neighbours_count`` of 47.

        The reflected request tag is the discriminator firmware itself points at
        (``// FUTURE: tag == pending_status``): every protocol/binary request
        reflects its timestamp in the response's first four bytes, and the sender
        registered that tag when it sent the request.
        """
        self._foreign_request_probe = probe

    async def __call__(self, packet: Packet) -> HandlerResult:
        """Handle RESPONSE/ANON_REQ packets and report MAC ownership."""
        if len(packet.payload) < 4:
            return HandlerResult.not_for_us()

        # Determine packet structure: ANON_REQ has our pubkey at bytes 1-33
        if (
            len(packet.payload) >= 34
            and packet.payload[1:33] == self.local_identity.get_public_key()
        ):
            # ANON_REQ format: dest_hash(1) + pubkey(32) + encrypted_data
            dest_hash = packet.payload[0]
            encrypted_start = 33
            lookup_hash = dest_hash  # For ANON_REQ, look up by destination hash
        else:
            # RESPONSE format: dest_hash(1) + src_hash(1) + encrypted_data
            dest_hash = packet.payload[0]
            src_hash = packet.payload[1]
            encrypted_start = 2
            lookup_hash = src_hash  # For RESPONSE, look up by source hash

        # Check the on-air destination before trying any candidate secret.
        if dest_hash != self.local_identity.get_public_key()[0]:
            return HandlerResult.not_for_us()

        # Gate: only attempt login processing while a login is actually pending
        # for this 1-byte hash. The full-pubkey pending map is authoritative so
        # one login completing cannot close the gate on a concurrent login to a
        # hash-colliding contact; the legacy per-hash password store is kept as
        # a compatibility gate.
        if not self._has_pending_login_for_hash(lookup_hash):
            # Not a login response (e.g. telemetry/status); route onward.
            return await self._forward_to_protocol_handler(packet)

        # Collect all contacts whose public_key first byte matches (hash collision / multiple peers)
        candidates = []
        for contact in self.contacts.contacts:
            try:
                pk = contact.public_key
                contact_pubkey = pk if isinstance(pk, bytes) else bytes.fromhex(pk)
                if len(contact_pubkey) == 32 and contact_pubkey[0] == lookup_hash:
                    candidates.append(contact)
            except Exception:
                continue

        if not candidates:
            # No contact matches the responding key: nothing to correlate to a
            # waiter (firmware ignores a response from a non-matching contact).
            self.log("No contact found for login response (src_hash=0x%02x)" % lookup_hash)
            return HandlerResult.not_for_us()

        # Try each candidate until one decrypts successfully (same shared-secret as firmware)
        authenticated = False
        response_data = None
        matched_contact = None
        for contact in candidates:
            authenticated, response_data = await self._decrypt_response(
                packet, contact, encrypted_start
            )
            if authenticated:
                matched_contact = contact
                break

        if authenticated and matched_contact:
            # A reply whose reflected tag belongs to a pending binary/protocol
            # request is not a login reply, even though a login is pending for
            # this contact. Checked before the login branch so the payload is
            # never parsed with the login layout — doing so reads a foreign field
            # as a response code and reports a bogus login failure, and the real
            # request's data is lost. Forwarding also leaves the return-path teach
            # to the protocol handler, which does it for its own responses.
            if self._is_foreign_request_reply(response_data, matched_contact):
                return await self._forward_to_protocol_handler(packet)
            if self._pubkey_bytes(matched_contact) not in self._pending_logins:
                # Authenticated, but this contact has no login pending: not a
                # login response. Mirrors firmware onContactResponse, where a
                # pending_login pubkey mismatch falls through to the status/
                # telemetry matchers instead of being treated as a login.
                return await self._forward_to_protocol_handler(packet)
            # Firmware parity (BaseChatMesh::onPeerDataRecv RESPONSE branch):
            # a login sent DIRECT down a forced path is answered by the server
            # with a *flood* RESPONSE (simple_repeater MyMesh::onAnonDataRecv,
            # the reply_path_len < 0 branch). That is the tell that the server
            # holds no usable out_path for us, and it is the only signal we get
            # before the first CLI request goes out — so teach the route back
            # now, or every subsequent REQ is answered down a dead route.
            # PATH-shaped responses are excluded: the reciprocal for those is
            # already sent by ProtocolResponseHandler.
            if packet.get_payload_type() == PAYLOAD_TYPE_RESPONSE:
                await self.return_path_teacher.maybe_teach_from_flood_reply(
                    packet,
                    self._pubkey_bytes(matched_contact),
                    lookup_hash,
                    reason="flood login RESPONSE",
                )
            if response_data is None:
                self.log("Authenticated login response had invalid or incomplete contents")
                return HandlerResult.consumed()
            await self._process_login_response(response_data, matched_contact)
            self.clear_login_password(lookup_hash)
            return HandlerResult.consumed()
        # Decryption failed for every candidate: the response is not authentically
        # ours, so no waiter is resolved (firmware ignores it).
        self.log("Failed to decrypt login response")
        return HandlerResult.not_for_us()

    async def _decrypt_response(
        self, packet: Packet, contact, encrypted_start: int = 2
    ) -> tuple[bool, Optional[dict]]:
        """Decrypt the login response and separately report MAC authentication."""
        try:
            # Extract encrypted portion (skip the header part)
            encrypted_data = packet.payload[encrypted_start:]

            # Calculate X25519 ECDH shared secret
            pk = contact.public_key
            contact_pubkey = pk if isinstance(pk, bytes) else bytes.fromhex(pk)
            contact_identity = Identity(contact_pubkey)
            shared_secret = contact_identity.calc_shared_secret(
                self.local_identity.get_private_key()
            )

            # Verify MAC and decrypt using X25519 shared secret
            aes_key = shared_secret[:16]
            plaintext = CryptoUtils.mac_then_decrypt(aes_key, shared_secret, encrypted_data)

            if not plaintext:
                return False, None

            # If this is a PATH packet, unwrap the path-return envelope to get
            # the inner response.  PATH format after decryption:
            #   path_len(1) + path(N) + extra_type(1) + extra_data(M)
            pkt_type = packet.get_payload_type()
            if pkt_type == PAYLOAD_TYPE_PATH:
                if len(plaintext) < 1 or not PathUtils.is_valid_path_len(plaintext[0]):
                    return False, None
                path_len_byte = plaintext[0]
                path_byte_len = PathUtils.get_path_byte_len(path_len_byte)
                inner_offset = 1 + path_byte_len + 1  # skip path_len + path + extra_type
                if len(plaintext) < inner_offset:
                    return False, None
                extra_type = plaintext[1 + path_byte_len] & 0x0F
                if extra_type != PAYLOAD_TYPE_RESPONSE or len(plaintext) <= inner_offset:
                    return True, None
                plaintext = plaintext[inner_offset:]

            if len(plaintext) < 12:
                return True, None

            # Parse the C++ response format (handleLoginReq reply_data):
            # timestamp(4) + response_code(1) + keep_alive(1) + admin_code(1) +
            # permissions(1) + random(4) + [firmware_ver_level(1) at index 12]
            timestamp, response_code, keep_alive, admin_code, permissions = struct.unpack(
                "<IBBBB", plaintext[:8]
            )
            random_blob = plaintext[8:12]
            firmware_ver_level = int(plaintext[12]) if len(plaintext) >= 13 else None

            return True, {
                "timestamp": timestamp,
                "response_code": response_code,
                "keep_alive_interval": keep_alive,
                # Only 1 is admin: a room server sends 2 for a plain guest,
                # and bool(2) would promote that guest to admin.
                "is_admin": admin_code == LOGIN_ADMIN_CODE_ADMIN,
                "admin_code": admin_code,
                "reserved": permissions,  # legacy key, kept for callers
                "permissions": permissions,
                "acl_role": acl_role(permissions),
                "random_blob": random_blob,
                "firmware_ver_level": firmware_ver_level,
                "contact": contact,
            }

        except Exception:
            return False, None

    async def _process_login_response(self, response_data: dict, contact):
        """Process the decrypted login response."""
        response_code = response_data["response_code"]
        success = response_code in (RESP_SERVER_LOGIN_OK, RESP_SERVER_LOGIN_SUCCESS_ALT)

        if success:
            self.log(f"Login successful to '{contact.name}' " f"(code: 0x{response_code:02X})")
            contact.last_login_success = response_data["timestamp"]
            contact.is_admin = response_data["is_admin"]
        else:
            self.log(f"Login failed to '{contact.name}' " f"(code: 0x{response_code:02X})")

        # Dispatch ONLY to the waiter whose target matches this authenticated
        # sender's full public key. No pending login for this contact → resolve
        # nothing (firmware ignores a response from a non-pending contact).
        callback = self._pending_logins.get(self._pubkey_bytes(contact))
        if callback is not None:
            await self._safe_callback(callback, success, response_data)
        else:
            self.log(f"No pending login for '{contact.name}' - login response ignored")

    async def _safe_callback(self, callback, success: bool, data: dict):
        """Safely invoke a login completion callback without blocking."""
        try:
            await invoke_maybe_awaitable(callback, success, data)
        except Exception as e:
            self.log(f"Error in login callback: {e}")


class AnonReqResponseHandler(BaseHandler):
    """Handler for ANON_REQ packets that might be login responses."""

    @staticmethod
    def payload_type() -> int:
        return PAYLOAD_TYPE_ANON_REQ

    def __init__(self, local_identity, contacts, log_fn):
        self.local_identity = local_identity
        self.contacts = contacts
        self.log = log_fn
        self.login_response_handler = LoginResponseHandler(local_identity, contacts, log_fn)

    def register_login_callback(self, pubkey: bytes, callback):
        self.login_response_handler.register_login_callback(pubkey, callback)

    def remove_login_callback(self, pubkey: bytes, callback):
        self.login_response_handler.remove_login_callback(pubkey, callback)

    def store_login_password(self, dest_hash: int, password: str):
        self.login_response_handler.store_login_password(dest_hash, password)

    def clear_login_password(self, dest_hash: int):
        self.login_response_handler.clear_login_password(dest_hash)

    async def __call__(self, packet: Packet) -> None:
        """Check if this ANON_REQ is actually a login response."""
        if (
            len(packet.payload) >= 34
            and packet.payload[1:33] == self.local_identity.get_public_key()
        ):
            await self.login_response_handler(packet)
