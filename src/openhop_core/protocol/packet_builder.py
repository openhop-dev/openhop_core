import hashlib
import logging
import os
import struct
import threading
import time
from typing import Any, Optional, Sequence, Union

from . import CryptoUtils, Packet
from .constants import (
    ADVERT_FLAG_HAS_FEATURE1,
    ADVERT_FLAG_HAS_FEATURE2,
    ADVERT_FLAG_HAS_LOCATION,
    ADVERT_FLAG_HAS_NAME,
    ADVERT_FLAG_IS_CHAT_NODE,
    CIPHER_BLOCK_SIZE,
    CONTACT_TYPE_ROOM_SERVER,
    MAX_ADVERT_DATA_SIZE,
    MAX_PACKET_PAYLOAD,
    MAX_PATH_SIZE,
    MAX_TEXT_LEN,
    PAYLOAD_TYPE_ACK,
    PAYLOAD_TYPE_ADVERT,
    PAYLOAD_TYPE_ANON_REQ,
    PAYLOAD_TYPE_CONTROL,
    PAYLOAD_TYPE_GRP_DATA,
    PAYLOAD_TYPE_GRP_TXT,
    PAYLOAD_TYPE_MULTIPART,
    PAYLOAD_TYPE_PATH,
    PAYLOAD_TYPE_RAW_CUSTOM,
    PAYLOAD_TYPE_REQ,
    PAYLOAD_TYPE_RESPONSE,
    PAYLOAD_TYPE_TRACE,
    PAYLOAD_TYPE_TXT_MSG,
    PAYLOAD_VER_1,
    REQ_TYPE_GET_TELEMETRY_DATA,
    TELEM_PERM_BASE,
    TELEM_PERM_ENVIRONMENT,
    TELEM_PERM_LOCATION,
    TXT_TYPE_CLI_COMMAND,
    TXT_TYPE_CLI_DATA,
    TXT_TYPE_SIGNED_PLAIN,
)
from .identity import Identity, LocalIdentity
from .packet_utils import (
    PacketDataUtils,
    PacketHeaderUtils,
    PacketValidationUtils,
    PathUtils,
    RouteTypeUtils,
)

logger = logging.getLogger(__name__)


class PacketBuilder:
    """
    Factory class for building mesh network packets with encryption and routing.

    Provides static methods to construct various types of mesh network packets
    including text messages, advertisements, acknowledgements, and protocol requests.
    Handles encryption, authentication, and proper packet formatting for the mesh protocol.

    All methods are static and thread-safe. Packets are constructed with proper
    headers, encryption, and routing information for reliable mesh communication.
    """

    # Monotonic timestamp state (mirrors firmware getCurrentTimeUnique).  Shared
    # across all packet types so every request/login tag is strictly increasing.
    _last_unique_timestamp: int = 0
    _timestamp_lock = threading.Lock()

    @staticmethod
    def _hash_byte(pubkey: bytes) -> int:
        """Compute hash byte from public key for packet addressing."""
        return PacketDataUtils.hash_byte(pubkey)

    @staticmethod
    def _create_packet(header: int, payload: bytes) -> Packet:
        """Create a packet with the given header and payload."""
        PacketValidationUtils.validate_payload_size(len(payload))
        pkt = Packet()
        pkt.header = header
        pkt.payload = bytearray(payload)
        pkt.payload_len = len(payload)
        return pkt

    @staticmethod
    def _hash_bytes(pubkey: bytes, local_identity: LocalIdentity) -> bytearray:
        """Compute hash bytes for packet authentication using public key and local identity."""
        return PacketDataUtils.hash_bytes(pubkey, local_identity.get_public_key())

    @staticmethod
    def _encrypt_payload(aes_key: bytes, shared_secret: bytes, plaintext: bytes) -> bytes:
        """Encrypt plaintext payload using AES key and shared secret."""
        return CryptoUtils.encrypt_then_mac(aes_key, shared_secret, plaintext)

    @staticmethod
    def _get_route_type_value(route_type: str, has_routing_path: bool = False) -> int:
        """Get route type value with optional routing path flag."""
        return RouteTypeUtils.get_route_type_value(route_type, has_routing_path)

    @staticmethod
    def _get_timestamp() -> int:
        """Get a strictly-increasing timestamp (epoch seconds) for packet tags.

        Mirrors firmware ``RTCClock::getCurrentTimeUnique`` (MeshCore.h): returns
        the current epoch second, but if called more than once within the same
        second it bumps by 1 so every request carries a unique, strictly-greater
        tag.  Firmware repeaters drop a REQ/login whose timestamp is not strictly
        greater than the client's last stored timestamp (replay guard), so two
        whole-second ``time.time()`` values from back-to-back requests (e.g. a
        login immediately followed by a stats request) would collide and the
        second packet would be silently ignored.
        """
        with PacketBuilder._timestamp_lock:
            t = int(time.time())
            if t <= PacketBuilder._last_unique_timestamp:
                t = PacketBuilder._last_unique_timestamp + 1
            PacketBuilder._last_unique_timestamp = t
            return t

    @staticmethod
    def _calc_shared_secret_and_key(
        contact: Any, local_identity: LocalIdentity
    ) -> tuple[bytes, bytes]:
        """Calculate shared secret and AES key from contact - reduces duplication."""
        pubkey = bytes.fromhex(contact.public_key)
        peer_identity = Identity(pubkey)
        shared_secret = peer_identity.calc_shared_secret(local_identity.get_private_key())
        aes_key = shared_secret[:16]
        return shared_secret, aes_key

    @staticmethod
    def _create_header(
        payload_type: int,
        route_type: str = "direct",
        has_routing_path: bool = False,
        version: int = PAYLOAD_VER_1,
    ) -> int:
        """Create packet header with payload type, route type, and version."""
        route_value = RouteTypeUtils.get_route_type_value(route_type, has_routing_path)
        return PacketHeaderUtils.create_header(payload_type, route_value, version)

    @staticmethod
    def _create_encrypted_payload(
        contact: Any, local_identity: LocalIdentity, plaintext: bytes
    ) -> tuple[bytes, bytes, bytes]:
        """Create encrypted payload for contact-based packets with authentication."""
        shared_secret, aes_key = PacketBuilder._calc_shared_secret_and_key(contact, local_identity)
        encrypted = PacketBuilder._encrypt_payload(aes_key, shared_secret, plaintext)
        payload = (
            PacketBuilder._hash_bytes(bytes.fromhex(contact.public_key), local_identity) + encrypted
        )
        return payload, shared_secret, aes_key

    @staticmethod
    def _pack_timestamp_data(timestamp: int, *data_parts) -> bytes:
        """Pack timestamp with additional data parts into bytes."""
        return PacketDataUtils.pack_timestamp_data(timestamp, *data_parts)

    @staticmethod
    def _validate_routing_path(routing_path: list) -> list:
        """Extract and centralize the 30-line path validation logic."""
        return PacketValidationUtils.validate_routing_path(routing_path)

    @staticmethod
    def _encode_advert_data(
        name: str,
        lat: float = 0.0,
        lon: float = 0.0,
        feature1: int = 0,
        feature2: int = 0,
        flags: int = 0,
    ) -> bytes:
        """Encodes advertisement metadata including location and features."""
        buf = bytearray()

        # Set flags based on what data is provided
        final_flags = flags
        if lat != 0.0 or lon != 0.0:
            final_flags |= ADVERT_FLAG_HAS_LOCATION
        if feature1 != 0:
            final_flags |= ADVERT_FLAG_HAS_FEATURE1
        if feature2 != 0:
            final_flags |= ADVERT_FLAG_HAS_FEATURE2
        if name:
            final_flags |= ADVERT_FLAG_HAS_NAME

        buf.append(final_flags)

        # Add location data if present
        if final_flags & ADVERT_FLAG_HAS_LOCATION:
            lat_int = int(lat * 1000000)
            lon_int = int(lon * 1000000)
            buf += struct.pack("<i", lat_int)
            buf += struct.pack("<i", lon_int)

        # Add feature data if present
        if final_flags & ADVERT_FLAG_HAS_FEATURE1:
            buf += struct.pack("<H", feature1)

        if final_flags & ADVERT_FLAG_HAS_FEATURE2:
            buf += struct.pack("<H", feature2)

        # Add name if present
        if final_flags & ADVERT_FLAG_HAS_NAME:
            name_bytes = name.encode("utf-8")
            # Copy name bytes up to remaining space in MAX_ADVERT_DATA_SIZE
            remaining = MAX_ADVERT_DATA_SIZE - len(buf)
            buf += name_bytes[:remaining]

        return bytes(buf)

    @staticmethod
    def create_ack(
        pubkey: bytes, timestamp: int, attempt: int, text: Union[str, bytes, memoryview]
    ) -> Packet:
        """
        Create an acknowledgement packet for message delivery confirmation.

        Generates a compact ACK packet that confirms receipt of a message with
        the specified timestamp and attempt number. The ACK includes a truncated
        hash for efficient validation.

        Args:
            pubkey: 32-byte public key of the message sender.
            timestamp: Unix timestamp from the original message.
            attempt: Retry attempt number (0-3) from the original message.
            text: Confirmation text or additional ACK data.

        Returns:
            Packet: ACK packet ready for transmission.

        Raises:
            ValueError: If pubkey is not exactly 32 bytes.

        Example:
            ```python
            pubkey = bytes(32)  # 32-byte public key
            packet = PacketBuilder.create_ack(pubkey, 1234567890, 0, "delivered")
            packet.get_payload_type()
            # Returns: 2
            ```
        """
        if not isinstance(pubkey, bytes) or len(pubkey) != 32:
            raise ValueError("pubkey must be 32 bytes")

        text_bytes = (
            text.strip("\x00").encode("utf-8")
            if isinstance(text, str)
            else bytes(text).strip(b"\x00")
        )
        ack_hash = PacketBuilder.calc_text_ack_hash(pubkey, timestamp, attempt, text_bytes)
        return PacketBuilder.create_ack_from_bytes(ack_hash)

    @staticmethod
    def calc_text_ack_hash(
        pubkey: bytes,
        timestamp: int,
        flags_byte: int,
        text: Union[str, bytes, memoryview],
        ext_attempt: int = 0,
        randomize: bool = True,
    ) -> bytes:
        """
        Compute the firmware-compatible 6-byte ACK hash for a plain text message.

        Mirrors MeshCore ``BaseChatMesh::onPeerDataRecv`` (TXT_TYPE_PLAIN): the ACK is
        ``sha256(timestamp || flags_byte || text || pubkey)[:4]`` followed by an
        extended-attempt byte and a random byte. Only the first 4 bytes are matched by
        the sender; bytes 4-5 exist solely to give each emitted ACK packet a unique
        packet hash (so mesh dedup never drops a legitimate ACK).

        Args:
            pubkey: 32-byte public key of the message sender.
            timestamp: Unix timestamp from the original message.
            flags_byte: The original message's full flags byte (``(txt_type << 2) | attempt``).
                For TXT_TYPE_PLAIN this equals the attempt number.
            text: Message text (without the null terminator).
            ext_attempt: Extended-attempt byte (the byte after the text's null terminator
                in the decrypted payload); 0 for normal messages.
            randomize: When True the 6th byte is random (firmware behaviour); set False for
                deterministic output in tests.

        Returns:
            bytes: 6-byte ACK hash.
        """
        text_bytes = text.encode("utf-8") if isinstance(text, str) else bytes(text)
        temp = PacketBuilder._pack_timestamp_data(timestamp, flags_byte & 0xFF, text_bytes)
        digest = CryptoUtils.sha256(temp + pubkey)
        last_byte = os.urandom(1) if randomize else b"\x00"
        return digest[:4] + bytes([ext_attempt & 0xFF]) + last_byte

    @staticmethod
    def create_ack_from_bytes(
        ack_bytes: bytes,
        path: Optional[Sequence[int]] = None,
        path_len_encoded: Optional[int] = None,
        route_type: str = "direct",
    ) -> Packet:
        """
        Wrap raw ACK bytes into a PAYLOAD_TYPE_ACK packet.

        Mirror of firmware ``Mesh::createAck(const uint8_t* ack, uint8_t len)`` which simply
        copies the raw ACK bytes into the packet payload.

        Args:
            ack_bytes: Raw ACK payload bytes.
            path: Optional routing path (one byte per hop) to send the ACK directly along
                a known ``out_path`` (mirrors firmware ``sendDirect``). When omitted the
                ACK is a path-less packet.
            path_len_encoded: Optional pre-encoded path_len byte (for 2/3-byte hashes).
            route_type: ``"direct"`` (default) or ``"flood"``. Use ``"flood"`` when the
                reverse path is unknown so the ACK can propagate without a path (mirrors
                firmware ``sendAckTo`` falling back to ``sendFloodScoped``). The dispatcher
                applies flood scope to flood-routed packets at send time.
        """
        has_path = bool(path)
        header = PacketBuilder._create_header(
            PAYLOAD_TYPE_ACK, route_type=route_type, has_routing_path=has_path
        )
        pkt = PacketBuilder._create_packet(header, bytes(ack_bytes))
        if has_path:
            pkt.set_path(bytes(path), path_len_encoded)
        return pkt

    @staticmethod
    def create_multi_ack(
        ack_bytes: bytes,
        remaining: int = 1,
        path: Optional[Sequence[int]] = None,
        path_len_encoded: Optional[int] = None,
    ) -> Packet:
        """
        Wrap raw ACK bytes into a PAYLOAD_TYPE_MULTIPART packet ("multi-ack").

        Mirror of firmware ``Mesh::createMultiAck(ack, len, remaining)``: the payload is a
        one-byte header ``(remaining << 4) | PAYLOAD_TYPE_ACK`` followed by the raw ACK
        bytes. Intermediate repeaters forward this packet and extract the embedded ACK
        early, improving delivery-confirmation reliability on multi-hop direct routes.

        Args:
            ack_bytes: Raw ACK payload bytes (embedded after the wrapper byte).
            remaining: Number of additional multi-acks still to be sent in the sequence
                (encoded in the upper nibble of the wrapper byte).
            path: Optional routing path to send directly along a known ``out_path``.
            path_len_encoded: Optional pre-encoded path_len byte (for 2/3-byte hashes).
        """
        has_path = bool(path)
        header = PacketBuilder._create_header(
            PAYLOAD_TYPE_MULTIPART, route_type="direct", has_routing_path=has_path
        )
        payload = bytes([((remaining & 0x0F) << 4) | PAYLOAD_TYPE_ACK]) + bytes(ack_bytes)
        pkt = PacketBuilder._create_packet(header, payload)
        if has_path:
            pkt.set_path(bytes(path), path_len_encoded)
        return pkt

    @staticmethod
    def create_self_advert(
        local_identity: Any,
        name: str,
        lat: float = 0.0,
        lon: float = 0.0,
        feature1: int = 0,
        feature2: int = 0,
        route_type: str = "flood",
    ) -> Packet:
        """
        Create a self-advertisement packet for the local node.

        Convenience method that creates an advertisement packet with the
        IS_CHAT_NODE flag set, announcing the local node's presence.

        Args:
            local_identity: Local node identity for signing.
            name: Display name for the node.
            lat: Latitude in decimal degrees.
            lon: Longitude in decimal degrees.
            feature1: First feature flag value.
            feature2: Second feature flag value.
            route_type: Routing method ("flood" or "direct").

        Returns:
            Packet: Signed advertisement packet with chat node flag.
        """
        return PacketBuilder.create_advert(
            local_identity,
            name,
            lat,
            lon,
            feature1,
            feature2,
            ADVERT_FLAG_IS_CHAT_NODE,
            route_type,
        )

    @staticmethod
    def create_advert(
        local_identity: Any,
        name: str,
        lat: float = 0.0,
        lon: float = 0.0,
        feature1: int = 0,
        feature2: int = 0,
        flags: int = ADVERT_FLAG_IS_CHAT_NODE,
        route_type: str = "flood",
    ) -> Packet:
        """
        Create a user advertisement packet with location and feature information.

        Generates a signed advertisement packet announcing the node's presence,
        location, and capabilities to the mesh network. The packet includes
        cryptographic signatures for authenticity.

        Args:
            local_identity: Local node identity for signing the advertisement.
            name: Display name for the node (max 31 characters).
            lat: Latitude in decimal degrees (optional).
            lon: Longitude in decimal degrees (optional).
            feature1: First feature flag value (optional).
            feature2: Second feature flag value (optional).
            flags: Advertisement flags (default: chat node).
            route_type: Routing method ("flood" or "direct").

        Returns:
            Packet: Signed advertisement packet ready for broadcast.

        Example:
            ```python
            from openhop_core.protocol.identity import LocalIdentity
            identity = LocalIdentity()
            packet = PacketBuilder.create_advert(identity, "MyNode", 37.7749, -122.4194)
            packet.get_payload_type()
            # Returns: 3
            ```
        """
        # Plain wall time, matching firmware Mesh::createAdvert's getCurrentTime().
        # The strictly-increasing _get_timestamp() is reserved for request/login
        # tags: sharing it here would let a burst of requests inflate the counter
        # past real time, and peers would then drop this node's later wall-time
        # adverts as replays until the clock caught up.
        timestamp = int(time.time())
        pubkey = local_identity.get_public_key()
        ts_bytes = struct.pack("<I", timestamp)
        appdata = PacketBuilder._encode_advert_data(name, lat, lon, feature1, feature2, flags)
        if len(appdata) > MAX_ADVERT_DATA_SIZE:
            raise ValueError(
                f"advert appdata too large: {len(appdata)} bytes (max {MAX_ADVERT_DATA_SIZE})"
            )

        # Sign the payload (pubkey + timestamp + appdata)
        body_to_sign = pubkey + ts_bytes + appdata
        signature = local_identity.sign(body_to_sign)

        # Create payload: pubkey + timestamp + signature + appdata
        payload = pubkey + ts_bytes + signature + appdata

        header = PacketBuilder._create_header(PAYLOAD_TYPE_ADVERT, route_type)
        return PacketBuilder._create_packet(header, payload)

    @staticmethod
    def create_flood_advert(*args, **kwargs) -> Packet:
        """
        Create an advertisement packet with flood routing.

        Convenience method that creates an advertisement with route_type="flood".
        All other arguments are passed through to create_advert().

        Returns:
            Packet: Advertisement packet configured for flood routing.
        """
        return PacketBuilder.create_advert(*args, **kwargs, route_type="flood")

    @staticmethod
    def create_direct_advert(*args, **kwargs) -> Packet:
        """
        Create an advertisement packet with direct routing.

        Convenience method that creates an advertisement with route_type="direct".
        All other arguments are passed through to create_advert().

        Returns:
            Packet: Advertisement packet configured for direct routing.
        """
        return PacketBuilder.create_advert(*args, **kwargs, route_type="direct")

    @staticmethod
    def create_datagram(
        ptype: int,
        dest: Identity,
        local_identity: LocalIdentity,
        secret: bytes,
        plaintext: bytes,
        route_type: str = "direct",
    ) -> Packet:
        """
        Create an encrypted datagram packet for secure communication.

        Generates a generic encrypted packet for text messages, requests, or responses
        with end-to-end encryption using the provided secret.

        Args:
            ptype: Payload type (TXT_MSG, REQ, or RESPONSE).
            dest: Destination identity for the packet.
            local_identity: Local node identity for authentication.
            secret: Shared secret for encryption.
            plaintext: Unencrypted payload data.
            route_type: Routing method ("direct" or "flood").

        Returns:
            Packet: Encrypted datagram packet ready for transmission.

        Raises:
            ValueError: If payload type is not supported.

        Example:
            ```python
            from openhop_core.protocol.identity import Identity, LocalIdentity
            dest = Identity(bytes(32))
            local = LocalIdentity()
            secret = bytes(32)
            packet = PacketBuilder.create_datagram(0, dest, local, secret, b"hello")
            packet.get_payload_type()
            # Returns: 0
            ```
        """
        if ptype not in (PAYLOAD_TYPE_TXT_MSG, PAYLOAD_TYPE_REQ, PAYLOAD_TYPE_RESPONSE):
            raise ValueError("invalid payload type")

        aes_key = secret[:16]
        cipher = PacketBuilder._encrypt_payload(aes_key, secret, plaintext)
        payload = PacketBuilder._hash_bytes(dest.get_public_key(), local_identity) + cipher

        header = PacketBuilder._create_header(ptype, route_type)
        pkt = PacketBuilder._create_packet(header, payload)
        pkt.path_len = 0
        pkt.path = bytearray()
        return pkt

    @staticmethod
    def create_anon_req(
        dest: Any,
        local_identity: LocalIdentity,
        shared_secret: bytes,
        plaintext: bytes,
        route_type: str = "transport_flood",
    ) -> Packet:
        """
        Create an anonymous request packet for unauthenticated communication.

        Generates a packet for anonymous requests that don't require full
        authentication, such as initial contact or public services.

        Args:
            dest: Destination identity or contact.
            local_identity: Local node identity.
            shared_secret: Pre-computed shared secret for encryption.
            plaintext: Unencrypted request data.
            route_type: Routing method (default: transport_flood).

        Returns:
            Packet: Anonymous request packet with encryption.
        """
        header = PacketBuilder._create_header(PAYLOAD_TYPE_ANON_REQ, route_type)

        dest_hash = PacketBuilder._hash_byte(dest.get_public_key())
        aes_key = shared_secret[:16]
        cipher = PacketBuilder._encrypt_payload(aes_key, shared_secret, plaintext)
        payload = bytearray([dest_hash]) + local_identity.get_public_key() + cipher

        pkt = PacketBuilder._create_packet(header, payload)
        pkt.path_len = 0
        pkt.path = bytearray()
        return pkt

    @staticmethod
    def create_anon_request(
        contact: Any,
        local_identity: LocalIdentity,
        req_data: bytes = b"",
        timestamp: Optional[int] = None,
    ) -> tuple[Packet, int]:
        """Create a PAYLOAD_TYPE_ANON_REQ packet for an anonymous request.

        Unlike ``create_protocol_request`` (which builds a PAYLOAD_TYPE_REQ and
        relies on the recipient already knowing the sender), this emits a true
        anonymous request: ``dest_hash(1) + sender_pubkey(32) + cipher`` under a
        PAYLOAD_TYPE_ANON_REQ header. The decrypted plaintext is
        ``timestamp(4) + req_data`` with ``req_data`` passed through verbatim
        (e.g. ``[ANON_REQ_TYPE_REGIONS][reply_path_byte][reply_path...]``); no
        protocol/sub-type byte is prepended.

        Routing mirrors firmware ``BaseChatMesh::sendAnonReq``: direct when the
        out_path is known (``out_path_len >= 0``, including ``0`` for a zero-hop
        direct neighbour) and flood when unknown (``-1``). The firmware regions
        handler only answers ``isRouteDirect()`` packets, so zero-hop discovery
        requires direct routing.

        Returns:
            tuple: (packet, timestamp) - the packet and the timestamp used as the
            request tag (echoed back by the responder).
        """
        if timestamp is None:
            timestamp = PacketBuilder._get_timestamp()

        plaintext = PacketBuilder._pack_timestamp_data(timestamp, req_data)

        contact_pubkey = bytes.fromhex(contact.public_key)
        shared_secret, aes_key = PacketBuilder._calc_shared_secret_and_key(contact, local_identity)
        cipher = PacketBuilder._encrypt_payload(aes_key, shared_secret, plaintext)
        dest_hash = PacketBuilder._hash_byte(contact_pubkey)
        payload = bytearray([dest_hash]) + local_identity.get_public_key() + cipher

        out_path_len = getattr(contact, "out_path_len", -1)
        out_path = getattr(contact, "out_path", b"") or b""
        # Direct (incl. zero-hop, out_path_len == 0) when the path is known;
        # flood only when the out_path is unknown (-1 / OUT_PATH_UNKNOWN).
        route_type = "direct" if out_path_len >= 0 else "flood"

        header = PacketBuilder._create_header(PAYLOAD_TYPE_ANON_REQ, route_type)
        packet = PacketBuilder._create_packet(header, payload)
        packet.path_len = 0
        packet.path = bytearray()

        if route_type == "direct" and len(out_path) > 0:
            path_bytes = out_path[:MAX_PATH_SIZE]
            encoded_len = None
            if PathUtils.is_valid_path_len(out_path_len) and PathUtils.get_path_byte_len(
                out_path_len
            ) <= len(path_bytes):
                encoded_len = out_path_len
            elif len(path_bytes) == 64:
                path_bytes = path_bytes[:63]
            packet.set_path(path_bytes, encoded_len)

        return packet, timestamp

    @staticmethod
    def create_login_packet(contact: Any, local_identity: LocalIdentity, password: str) -> Packet:
        """
        Create a login packet for repeater authentication.

        Generates an encrypted login packet containing credentials for
        authenticating with a repeater node or room server.

        Args:
            contact: Contact information for the repeater.
            local_identity: Local node identity for encryption.
            password: Authentication password (truncated to 15 chars).

        Returns:
            Packet: Encrypted login packet ready for transmission.
        """
        timestamp = PacketBuilder._get_timestamp()
        # Firmware BaseChatMesh::sendLogin bounds the password at 15 *bytes* of the
        # encoded buffer (strlen + memcpy). Encode first, then truncate so a
        # multibyte character cannot push the field past the wire limit.
        password_bytes = password.encode("utf-8")[:15]

        is_room = getattr(contact, "type", 0) == CONTACT_TYPE_ROOM_SERVER

        if is_room:
            sync_since = getattr(contact, "sync_since", 0)  # Use contact's sync_since or 0
            plaintext = PacketBuilder._pack_timestamp_data(
                timestamp, struct.pack("<I", sync_since), password_bytes
            )
        else:
            plaintext = PacketBuilder._pack_timestamp_data(timestamp, password_bytes)

        contact_pubkey = bytes.fromhex(contact.public_key)
        contact_identity = Identity(contact_pubkey)
        shared_secret = contact_identity.calc_shared_secret(local_identity.get_private_key())

        out_path_len = getattr(contact, "out_path_len", -1)
        if out_path_len < 0:
            route_type = "flood"
        else:
            route_type = "direct"

        pkt = PacketBuilder.create_anon_req(
            contact_identity, local_identity, shared_secret, plaintext, route_type
        )

        if route_type == "direct" and out_path_len > 0:
            out_path = getattr(contact, "out_path", b"")
            if out_path:
                path_bytes = out_path[:MAX_PATH_SIZE]
                encoded_len = None
                if PathUtils.is_valid_path_len(out_path_len) and PathUtils.get_path_byte_len(
                    out_path_len
                ) <= len(path_bytes):
                    encoded_len = out_path_len
                elif len(path_bytes) == 64:
                    path_bytes = path_bytes[:63]
                pkt.set_path(path_bytes, encoded_len)

        return pkt

    @staticmethod
    def create_group_datagram(
        group_name: str,
        local_identity: LocalIdentity,
        message: str,
        sender_name: str = "Unknown",
        channels_config: Optional[Any] = None,
        timestamp: Optional[int] = None,
    ) -> Packet:
        """
        Create an encrypted group message for a specified channel.

        Generates a group message packet encrypted with the channel's shared secret,
        allowing secure communication within a named group or channel.

        Args:
            group_name: Name of the channel to send the message to.
            local_identity: Local node identity (unused in group messages).
            message: Message text to send to the group.
            sender_name: Display name of the sender (default: "Unknown").
            channels_config: List of channel configurations with secrets.

        Returns:
            Packet: Encrypted group message packet.

        Raises:
            ValueError: If channels_config is None or channel not found.

        Example:
            ```python
            channels = [{"name": "general", "secret": "secret123"}]
            from openhop_core.protocol.identity import LocalIdentity
            identity = LocalIdentity()
            packet = PacketBuilder.create_group_datagram(
                "general", identity, "Hello group!", "Alice", channels)
            packet.get_payload_type()
            # Returns: 6
            ```
        """
        if channels_config is None:
            raise ValueError(
                "channels_config parameter is required - protocol layer cannot access database"
            )

        channel = next((ch for ch in channels_config if ch.get("name") == group_name), None)
        if not channel:
            raise ValueError(f"Channel '{group_name}' not in provided channels_config")

        secret_bytes = (
            bytes.fromhex(channel["secret"])
            if isinstance(channel["secret"], str)
            else (
                channel["secret"]
                if isinstance(channel["secret"], bytes)
                else channel["secret"].encode("utf-8")
            )
        )
        # Same channel hash as GroupTextHandler (hash first 16 when key has second 16 zero)
        hash_input = (
            secret_bytes[:16]
            if len(secret_bytes) >= 32 and secret_bytes[16:32] == b"\x00" * 16
            else (secret_bytes[:32] if len(secret_bytes) > 32 else secret_bytes)
        )
        channel_hash = hashlib.sha256(hash_input).digest()[0]
        secret_bytes = (secret_bytes + b"\x00" * 32)[:32]

        if timestamp is None:
            timestamp = PacketBuilder._get_timestamp()
        flags = 0x00
        # Firmware sendGroupMessage caps "<sender>: <text>" at MAX_TEXT_LEN bytes,
        # truncating the text (never the prefix). Re-encode after the byte cut so a
        # multi-byte UTF-8 sequence split at the boundary is dropped, not corrupted.
        prefix = f"{sender_name}: ".encode("utf-8")
        text_bytes = message.encode("utf-8")
        max_text = max(MAX_TEXT_LEN - len(prefix), 0)
        if len(text_bytes) > max_text:
            text_bytes = text_bytes[:max_text].decode("utf-8", errors="ignore").encode("utf-8")
        content = prefix + text_bytes
        plaintext = PacketBuilder._pack_timestamp_data(timestamp, flags, content)

        ciphertext = CryptoUtils._aes_encrypt(secret_bytes[:16], plaintext)
        mac = CryptoUtils._hmac_sha256(secret_bytes, ciphertext)[:2]
        payload = bytearray([channel_hash]) + mac + ciphertext

        header = PacketBuilder._create_header(PAYLOAD_TYPE_GRP_TXT, route_type="flood")
        return PacketBuilder._create_packet(header, payload)

    @staticmethod
    def create_group_data_packet(
        ptype: int,
        channel_hash: int,
        channel_secret: bytes,
        plaintext: bytes,
        secret: bytes,
    ) -> Packet:
        """
        Create a group packet with generic encrypted data.

        Generates a group packet for text messages or data with channel-specific
        encryption using the provided shared secret.

        Args:
            ptype: Payload type (GRP_TXT or GRP_DATA).
            channel_hash: Single byte hash identifying the channel.
            channel_secret: Channel-specific encryption secret.
            plaintext: Unencrypted data to send.
            secret: Additional secret for encryption.

        Returns:
            Packet: Encrypted group data packet.

        Raises:
            ValueError: If payload type is not supported for groups.
        """
        if ptype not in (PAYLOAD_TYPE_GRP_TXT, PAYLOAD_TYPE_GRP_DATA):
            raise ValueError("invalid payload type")

        aes_key = secret[:16]
        cipher = PacketBuilder._encrypt_payload(aes_key, secret, plaintext)
        payload = bytearray([channel_hash]) + cipher

        header = PacketBuilder._create_header(ptype, route_type="flood")
        return PacketBuilder._create_packet(header, payload)

    @staticmethod
    def create_trace(
        tag: int, auth_code: int, flags: int, path: Optional[Sequence[int]] = None
    ) -> Packet:
        """
        Create a trace packet for network diagnostics and path discovery.

        Generates a trace packet that can follow network paths for debugging
        and network topology discovery. Compatible with C++ implementation.

        Args:
            tag: Random identifier set by initiator (uint32_t).
            auth_code: Optional authentication code (uint32_t).
            flags: Control flags for trace behavior (uint8_t).
            path: Optional list of node IDs for the trace path.

        Returns:
            Packet: Trace packet with proper wire format.

        Example:
            ```python
            packet = PacketBuilder.create_trace(12345, 0, 1, [1, 2, 3])
            packet.get_payload_type()
            # Returns: 7
            ```
        """
        # Create base payload: tag(4) + auth_code(4) + flags(1)
        payload = struct.pack("<IIB", tag, auth_code, flags)

        # Append path to payload if provided
        if path:
            payload += bytes(path)

        # Create packet with proper structure
        pkt = Packet()
        pkt.header = PacketBuilder._create_header(PAYLOAD_TYPE_TRACE, route_type="direct")
        pkt.path_len = 0  # No routing path in packet path field
        pkt.path = bytearray()  # Empty routing path
        pkt.payload = bytearray(payload)
        pkt.payload_len = len(payload)
        return pkt

    @staticmethod
    def create_raw_data(data: bytes) -> Packet:
        """
        Create a raw custom packet (PAYLOAD_TYPE_RAW_CUSTOM) with no encryption.

        Route type is always DIRECT (consistent with firmware CMD_SEND_RAW_DATA).
        Caller must set pkt.path and pkt.path_len for direct routing.
        """
        if len(data) > MAX_PACKET_PAYLOAD:
            raise ValueError(
                f"Raw data length {len(data)} exceeds MAX_PACKET_PAYLOAD ({MAX_PACKET_PAYLOAD})"
            )
        header = PacketBuilder._create_header(PAYLOAD_TYPE_RAW_CUSTOM, route_type="direct")
        return PacketBuilder._create_packet(header, data)

    @staticmethod
    def create_path_return(
        dest_hash: int,
        src_hash: int,
        secret: bytes,
        path: Sequence[int],
        extra_type: int = 0xFF,
        extra: bytes = b"",
        path_len_encoded: Optional[int] = None,
    ) -> Packet:
        """
        Create a secure return path packet with optional metadata.

        Generates an encrypted packet containing a return path for secure
        two-way communication, with optional additional data.

        The inner payload first byte is the encoded path_len (bits 6-7 = hash
        size - 1, bits 0-5 = hop count), so ``path_len_encoded`` is required
        for a non-empty path: ``path`` is a flat byte sequence and its length
        alone cannot distinguish N 1-byte hashes from one N-byte hash.

        Guessing 1-byte semantics here is unrecoverable in the field.  Firmware
        stores a taught path verbatim (``simple_repeater`` ``onPeerPathRecv``:
        ``client->out_path_len = copyPath(...)``), persists it to flash, and
        never re-derives it — ``onPeerPathRecv`` is its only writer.  A path
        taught with the wrong hash size therefore makes the peer answer down a
        route that resolves to nobody, for every subsequent DIRECT exchange,
        until something re-teaches it or a *flood* login resets it
        (``handleLoginReq``: ``if (is_flood) client->out_path_len =
        OUT_PATH_UNKNOWN;``).  Failing loudly at build time is the only place
        the mistake is still cheap.

        Args:
            dest_hash: Destination node hash (1 byte).
            src_hash: Source node hash (1 byte).
            secret: Shared secret for encryption.
            path: Sequence of node hashes for the return path.
            extra_type: Type identifier for extra data (default: 0xFF).
            extra: Additional binary data to include.
            path_len_encoded: Encoded path_len byte, normally the ``path_len``
                of the packet the path was observed on.  Required whenever
                ``path`` is non-empty; for a 1-byte-hash path pass
                ``PathUtils.encode_path_len(1, hop_count)``.  May be None only
                for an empty path.

        Returns:
            Packet: Encrypted return path packet.

        Raises:
            ValueError: If combined path and extra data exceed packet limits,
                if path_len_encoded is omitted for a non-empty path, if it is
                not a valid encoded path_len, or if it disagrees with the
                actual path length.
        """
        if len(path) + len(extra) + 5 > (MAX_PACKET_PAYLOAD - 2 - CIPHER_BLOCK_SIZE):
            raise ValueError("Combined path/extra too long")

        if path_len_encoded is None:
            if len(path) > 0:
                raise ValueError(
                    f"path_len_encoded is required for a non-empty path "
                    f"({len(path)} bytes): the byte count cannot distinguish "
                    f"N 1-byte hashes from one N-byte hash. Pass the observed "
                    f"packet's path_len, or PathUtils.encode_path_len(hash_size, hops)."
                )
            first_byte = 0
        else:
            if not PathUtils.is_valid_path_len(path_len_encoded):
                raise ValueError(f"invalid path_len_encoded 0x{path_len_encoded:02X}")
            expected_len = PathUtils.get_path_byte_len(path_len_encoded)
            if len(path) != expected_len:
                raise ValueError(
                    f"path length {len(path)} does not match path_len_encoded "
                    f"(expected {expected_len} bytes)"
                )
            first_byte = path_len_encoded

        if extra:
            inner = bytes([first_byte]) + bytes(path) + bytes([extra_type]) + extra
        else:
            # No extra payload: MeshCore Mesh::createPathReturn appends 0xFF and
            # four RNG bytes so repeated PATH returns for the same path do not
            # encrypt to identical packets (and identical packet hashes).
            inner = bytes([first_byte]) + bytes(path) + b"\xff" + os.urandom(4)
        aes_key = secret[:16]
        cipher = PacketBuilder._encrypt_payload(aes_key, secret, inner)
        payload = bytearray([dest_hash, src_hash]) + cipher

        header = PacketBuilder._create_header(
            PAYLOAD_TYPE_PATH, route_type="flood", has_routing_path=False
        )
        return PacketBuilder._create_packet(header, payload)

    @staticmethod
    def create_text_message(
        contact: Any,
        local_identity: LocalIdentity,
        message: str,
        attempt: int = 0,
        message_type: str = "direct",
        out_path: Optional[list] = None,
        txt_type: int = 0,
        timestamp: Optional[int] = None,
    ) -> tuple[Packet, int]:
        """
        Create a secure text message with encryption and CRC validation.

        Generates an encrypted text message packet with proper authentication,
        CRC calculation for ACK verification, and optional routing path.

        Args:
            contact: The contact to send the message to.
            local_identity: The local node identity for encryption.
            message: The message text to send.
            attempt: The attempt number for retries (0-3).
            message_type: The message routing type ("direct" or "flood").
            out_path: The optional routing path for directed messages.
            txt_type: Text type in upper 6 bits of the flags byte (0=PLAIN, 1=CLI_DATA, …),
                combined with attempt as ``(txt_type << 2) | (attempt & 3)``. Matches MeshCore
                ``TXT_TYPE_*`` so repeaters skip delivery ACK for CLI_DATA.
            timestamp: Optional message timestamp. When provided (e.g. the host-supplied
                ``msg_timestamp`` from CMD_SEND_TXT_MSG), it is used as-is so that retries
                of the same message share a stable timestamp — mirroring firmware
                ``sendMessage``, which uses the app timestamp for plain DMs. When None a
                fresh strictly-increasing timestamp is generated.

        Returns:
            tuple: (packet, crc) - The encrypted packet and CRC for ACK verification.

        Example:
            ```python
            from openhop_core.protocol.identity import LocalIdentity
            identity = LocalIdentity()
            contact = type('Contact', (), {'public_key': '00'*32, 'out_path': []})()
            packet, crc = PacketBuilder.create_text_message(
                contact, identity, "Hello!", 0, "direct")
            packet.get_payload_type()
            # Returns: 0
            ```
        """
        # Firmware composeMsgPacket stores only the low two bits of the attempt in
        # the flag byte (temp[4] = attempt & 3); the full attempt is preserved for
        # the tail below so retries above three still produce unique packets.
        attempt_full = attempt & 0xFF
        txt_type &= 0x3F
        flags_byte = (txt_type << 2) | (attempt_full & 0x03)
        timestamp = timestamp if timestamp is not None else PacketBuilder._get_timestamp()

        # The CLI types take firmware's sendCommandData path, which -- unlike
        # composeMsgPacket -- has no extended-attempt tail and so no shrunken
        # text budget to go with it. A CLI message earns no delivery ACK, so
        # there are no repeated attempt hashes for the tail to disambiguate.
        is_cli = txt_type in (TXT_TYPE_CLI_DATA, TXT_TYPE_CLI_COMMAND)

        # The body is a C string to firmware: composeMsgPacket and
        # sendCommandData both size it with ``strlen(text)``, so an embedded NUL
        # ends the message. Keeping the bytes past it would send text no
        # receiver can display -- ours stops at the first NUL too -- and would
        # hash an expected ACK over a span the receiver never reproduces, so
        # send_confirmed could never fire.
        nul = message.find("\x00")
        if nul >= 0:
            message = message[:nul]

        # Firmware BaseChatMesh::composeMsgPacket rejects text longer than
        # MAX_TEXT_LEN (measured in bytes). Match it on the UTF-8 encoded length
        # so a valid MeshCore peer can build the same packet. For attempt > 3 the
        # tail carries an extra NUL + attempt byte, so the text budget shrinks by
        # two (composeMsgPacket: attempt > 3 && text_len > MAX_TEXT_LEN-2).
        text_len = len(message.encode("utf-8"))
        if text_len > MAX_TEXT_LEN:
            raise ValueError(f"text message too long: {text_len} bytes (max {MAX_TEXT_LEN})")
        if not is_cli and attempt_full > 3 and text_len > MAX_TEXT_LEN - 2:
            raise ValueError(
                f"text message too long for extended attempt: {text_len} bytes "
                f"(max {MAX_TEXT_LEN - 2})"
            )

        signed_sender_prefix = (
            local_identity.get_public_key()[:4] if txt_type == TXT_TYPE_SIGNED_PLAIN else b""
        )

        # The body ends at the text: firmware writes the C-string terminator into
        # its scratch buffer (``memcpy(&temp[5], text, text_len + 1)``) but hands
        # ``createDatagram`` only ``5 + text_len``, so the NUL is never on the
        # wire. It does not need to be — the receiver null-terminates past the
        # decrypted length itself (``data[len] = 0``), and AES zero-padding
        # supplies a terminator for every length that is not already a whole
        # number of blocks.
        #
        # The one exception is a plain retry above attempt 3: composeMsgPacket
        # then appends the terminator *and* the full attempt byte, so retries
        # whose low two bits repeat (4 → 0, 5 → 1, …) still hash uniquely.
        # sendCommandData -- the CLI path -- has no such tail.
        extended = attempt_full > 3 and not is_cli
        tail = b"\x00" + bytes([attempt_full]) if extended else b""
        plaintext = PacketBuilder._pack_timestamp_data(
            timestamp, flags_byte, signed_sender_prefix, message, tail
        )

        # Use  encryption and payload creation
        payload, shared_secret, aes_key = PacketBuilder._create_encrypted_payload(
            contact, local_identity, plaintext
        )

        # Calculate CRC using centralized packing.
        #
        # Which key salts the hash depends on the type, because the receiver
        # salts it differently. For plain text both sides use the *sender's*
        # key: composeMsgPacket hashes with `self_id.pub_key` and the receiver
        # answers with `from.id.pub_key` (BaseChatMesh::onPeerDataRecv). Signed
        # text inverts that -- the receiver hashes with its own key
        # (`self_id.pub_key` on the receiving side), so a sender predicting the
        # ACK has to use the *recipient's* key, exactly as firmware's room
        # server does when it pushes a post
        # (simple_room_server::pushPostToClient: `client->id.pub_key`).
        crc_input = PacketBuilder._pack_timestamp_data(
            timestamp, flags_byte, signed_sender_prefix, message
        )
        ack_key = (
            bytes.fromhex(contact.public_key)
            if txt_type == TXT_TYPE_SIGNED_PLAIN
            else local_identity.get_public_key()
        )
        ack_crc = int.from_bytes(
            CryptoUtils.sha256(crc_input + ack_key)[:4],
            "little",
        )

        # Use  path validation
        routing_path = (
            out_path if out_path is not None else (contact.out_path if contact.out_path else [])
        )
        routing_path = PacketBuilder._validate_routing_path(routing_path)

        # Create packet with validated path
        pkt = Packet()
        has_path = bool(routing_path and len(routing_path) > 0)
        pkt.header = PacketBuilder._create_header(PAYLOAD_TYPE_TXT_MSG, message_type, has_path)

        if routing_path and len(routing_path) > 0:
            if len(routing_path) > MAX_PATH_SIZE:
                logger.warning(
                    f"Path length {len(routing_path)} exceeds maximum {MAX_PATH_SIZE}, truncating"
                )
                routing_path = routing_path[:MAX_PATH_SIZE]
            # Preserve encoded path_len from contact when using its stored path
            contact_path_len = getattr(contact, "out_path_len", -1) if contact else -1
            if (
                out_path is None
                and contact_path_len >= 0
                and PathUtils.is_valid_path_len(contact_path_len)
                and PathUtils.get_path_byte_len(contact_path_len) <= len(routing_path)
            ):
                pkt.set_path(bytearray(routing_path), contact_path_len)
            else:
                # path_len encodes hop count in 6 bits (0-63); 64 would encode as 0
                if len(routing_path) == 64:
                    logger.warning(
                        "Path length 64 exceeds encodable hop count 63 (1-byte hashes), "
                        "truncating to 63 bytes"
                    )
                    routing_path = routing_path[:63]
                pkt.set_path(bytearray(routing_path))
        else:
            pkt.path_len, pkt.path = 0, bytearray()

        pkt.payload = bytearray(payload)
        pkt.payload_len = len(payload)

        # Enhanced debug logging with packet details
        route_type_names = {
            0: "TRANSPORT_FLOOD",
            1: "FLOOD",
            2: "DIRECT",
            3: "TRANSPORT_DIRECT",
        }
        header_route_type = pkt.header & 0x03
        logger.debug("Created TXT_MSG packet:")
        logger.debug(
            f"  Header: 0x{pkt.header:02X} (route_type={header_route_type}="
            f"{route_type_names.get(header_route_type, 'UNKNOWN')})"
        )
        logger.debug(f"  Path: {list(pkt.path)} (len={pkt.path_len})")
        logger.debug(f"  Payload: {len(pkt.payload)} bytes, first 10: {list(pkt.payload[:10])}")
        logger.debug(
            f"  Message: '{message}', attempt={attempt}, txt_type={txt_type}, "
            f"flags=0x{flags_byte:02X}, timestamp={timestamp}"
        )
        logger.debug(f"  CRC: 0x{ack_crc:08X}")

        return pkt, ack_crc

    @staticmethod
    def create_protocol_request(
        contact: Any,
        local_identity: LocalIdentity,
        protocol_code: int,
        data: bytes = b"",
        timestamp: Optional[int] = None,
        route_type: Optional[str] = None,
    ) -> tuple[Packet, int]:
        """
        Create a protocol request packet for repeater commands.

        Generates an encrypted protocol request for administrative commands
        or special operations with repeaters and infrastructure nodes.

        Args:
            contact: The repeater contact to send the request to.
            local_identity: The local node identity for encryption.
            protocol_code: The protocol command code.
            data: Additional binary data for the request.
            timestamp: Optional timestamp (uses current time if None).
            route_type: Optional explicit routing mode ("direct" or "flood").
                When omitted, routing is selected from the contact's known path.

        Returns:
            tuple: (packet, timestamp) - The created packet and the timestamp used.

        Example:
            ```python
            from openhop_core.protocol.identity import LocalIdentity
            identity = LocalIdentity()
            contact = type('Contact', (), {'public_key': '00'*32})()
            packet, ts = PacketBuilder.create_protocol_request(
                contact, identity, 1, b"data")
            packet.get_payload_type()
            # Returns: 4
            ```
        """
        if timestamp is None:
            timestamp = PacketBuilder._get_timestamp()

        # Use  timestamp+data packing
        plaintext = PacketBuilder._pack_timestamp_data(timestamp, protocol_code, data)

        # Use  encryption and payload creation
        payload, shared_secret, aes_key = PacketBuilder._create_encrypted_payload(
            contact, local_identity, plaintext
        )

        out_path_len = getattr(contact, "out_path_len", -1)
        out_path = getattr(contact, "out_path", b"") or b""
        # Direct (incl. zero-hop, out_path_len == 0 with an empty path) when the
        # path is known; flood only when the out_path is unknown (-1). Mirrors
        # create_anon_request and firmware sendRequest (OUT_PATH_UNKNOWN -> flood,
        # else sendDirect, which works with a 0-length path).
        route_type = route_type or ("direct" if out_path_len >= 0 else "flood")

        header = PacketBuilder._create_header(PAYLOAD_TYPE_REQ, route_type)
        packet = PacketBuilder._create_packet(header, payload)

        if route_type == "direct" and len(out_path) > 0:
            path_bytes = out_path[:MAX_PATH_SIZE]
            encoded_len = None
            if PathUtils.is_valid_path_len(out_path_len) and PathUtils.get_path_byte_len(
                out_path_len
            ) <= len(path_bytes):
                encoded_len = out_path_len
            elif len(path_bytes) == 64:
                path_bytes = path_bytes[:63]
            packet.set_path(path_bytes, encoded_len)

        return packet, timestamp

    @staticmethod
    def create_logout_packet(contact: Any, local_identity: LocalIdentity) -> tuple[Packet, int]:
        """
        Create a logout packet for repeater authentication.

        Generates a logout message to terminate an authenticated session
        with a repeater node.

        Args:
            contact: The repeater contact to logout from.
            local_identity: The local node identity for encryption.

        Returns:
            tuple: (packet, crc) - The logout packet and CRC for verification.
        """
        # CLI_DATA (1): MeshCore repeaters do not send delivery ACK for CLI text.
        return PacketBuilder.create_text_message(
            contact,
            local_identity,
            "logout",
            attempt=0,
            message_type="direct",
            txt_type=1,  # TXT_TYPE_CLI_DATA
        )

    # ---------- Telemetry  ----------

    @staticmethod
    def _compute_inverse_perm_mask(
        want_base=True, want_location=True, want_environment=True
    ) -> int:
        remove_mask = 0
        if not want_base:
            remove_mask |= TELEM_PERM_BASE
        if not want_location:
            remove_mask |= TELEM_PERM_LOCATION
        if not want_environment:
            remove_mask |= TELEM_PERM_ENVIRONMENT
        return remove_mask & 0xFF

    @staticmethod
    def create_telem_request(
        contact: Any,
        local_identity: LocalIdentity,
        *,
        want_base: bool = True,
        want_location: bool = True,
        want_environment: bool = True,
        include_entropy: bool = True,
        route_type: Optional[str] = None,
    ) -> tuple[Packet, int]:
        """
        Create a telemetry request packet for sensor data collection.

        Generates a request for telemetry data from a node, allowing selective
        retrieval of base metrics, location data, and environmental sensors.

        Args:
            contact: The node to request telemetry from.
            local_identity: The local node identity for encryption.
            want_base: Include basic telemetry metrics.
            want_location: Include location/GPS data.
            want_environment: Include environmental sensors.
            include_entropy: Include entropy/randomness data.
            route_type: Optional routing override ("direct" or "flood").
                When omitted, routing is selected from the contact's known path.

        Returns:
            tuple: (packet, timestamp) - The telemetry request packet and timestamp.

        Example:
            ```python
            from openhop_core.protocol.identity import LocalIdentity
            identity = LocalIdentity()
            contact = type('Contact', (), {'public_key': '00'*32})()
            packet, ts = PacketBuilder.create_telem_request(
                contact, identity, want_location=False)
            packet.get_payload_type()
            # Returns: 4
            ```
        """
        inv = PacketBuilder._compute_inverse_perm_mask(want_base, want_location, want_environment)

        return PacketBuilder.create_protocol_request(
            contact=contact,
            local_identity=local_identity,
            protocol_code=REQ_TYPE_GET_TELEMETRY_DATA,
            data=bytes([inv]),  # Just the permission mask as additional data
            route_type=route_type,
        )

    # ---------- Control/Discovery Packets ----------

    @staticmethod
    def create_discovery_request(
        tag: int,
        filter_mask: int,
        since: int = 0,
        prefix_only: bool = False,
    ) -> Packet:
        """Create a node discovery request packet.

        Generates a control packet to discover nearby nodes on the mesh network.
        This is a zero-hop broadcast packet that nearby nodes will respond to.

        Args:
            tag: Random identifier to match responses (uint32_t).
            filter_mask: Bitmask of node types to discover; the bit at position `node_type` is set
                to select that type (e.g., for ADV_TYPE_REPEATER=2, use (1 << 2) == 0x04).
            since: Optional timestamp - only nodes modified after this respond (uint32_t).
            prefix_only: Request 8-byte key prefix instead of full 32-byte key.

        Returns:
            Packet: Discovery request packet ready to send as zero-hop.

        Example:
            ```python
            import random
            tag = random.randint(0, 0xFFFFFFFF)
            # Filter for repeaters: ADV_TYPE_REPEATER=2, so (1 << 2) = 0x04
            packet = PacketBuilder.create_discovery_request(tag, filter_mask=0x04)
            # Send as zero-hop broadcast
            ```
        """
        # Build payload: type+flags(1) + filter(1) + tag(4) + since(4, optional)
        payload = bytearray()

        # First byte: CTL_TYPE_NODE_DISCOVER_REQ (0x80) + flags
        flags = 0x01 if prefix_only else 0x00
        payload.append(0x80 | flags)

        # Filter byte
        payload.append(filter_mask & 0xFF)

        # Tag (4 bytes, little-endian)
        payload.extend(struct.pack("<I", tag))

        # Optional since timestamp (4 bytes, little-endian)
        if since > 0:
            payload.extend(struct.pack("<I", since))

        # Create packet with direct routing (will be sent as zero-hop)
        pkt = Packet()
        pkt.header = PacketBuilder._create_header(PAYLOAD_TYPE_CONTROL, route_type="direct")
        pkt.path_len = 0
        pkt.path = bytearray()
        pkt.payload = payload
        pkt.payload_len = len(payload)
        return pkt

    @staticmethod
    def create_discovery_response(
        tag: int,
        node_type: int,
        inbound_snr: float,
        pub_key: bytes,
        prefix_only: bool = False,
    ) -> Packet:
        """Create a node discovery response packet.

        Generates a control packet in response to a discovery request.
        This is sent as a zero-hop packet to the requester.

        Args:
            tag: Tag from the discovery request to match.
            node_type: Type of this node (0-15, e.g., 1 for repeater).
            inbound_snr: SNR of the received request (will be multiplied by 4).
            pub_key: Node's public key (32 bytes).
            prefix_only: Send only 8-byte key prefix instead of full key.

        Returns:
            Packet: Discovery response packet ready to send as zero-hop.

        Example:
            ```python
            identity = LocalIdentity()
            packet = PacketBuilder.create_discovery_response(
                tag=0x12345678,
                node_type=1,  # Repeater
                inbound_snr=8.5,
                pub_key=identity.get_public_key()
            )
            ```
        """
        # Build payload: type+node_type(1) + snr(1) + tag(4) + pub_key(8 or 32)
        payload = bytearray()

        # First byte: CTL_TYPE_NODE_DISCOVER_RESP (0x90) + node_type (lower 4 bits)
        payload.append(0x90 | (node_type & 0x0F))

        # SNR byte (multiply by 4, clamp to signed int8_t range, and encode as unsigned byte)
        snr_byte = max(-128, min(127, int(inbound_snr * 4)))
        payload.append(snr_byte & 0xFF)

        # Tag (4 bytes, little-endian)
        payload.extend(struct.pack("<I", tag))

        # Public key (8 or 32 bytes)
        if prefix_only:
            payload.extend(pub_key[:8])
        else:
            payload.extend(pub_key[:32])

        # Create packet with direct routing (will be sent as zero-hop)
        pkt = Packet()
        pkt.header = PacketBuilder._create_header(PAYLOAD_TYPE_CONTROL, route_type="direct")
        pkt.path_len = 0
        pkt.path = bytearray()
        pkt.payload = payload
        pkt.payload_len = len(payload)
        return pkt
