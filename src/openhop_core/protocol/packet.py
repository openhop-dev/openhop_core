from typing import ByteString, Optional

from .constants import (
    MAX_SUPPORTED_PAYLOAD_VERSION,
    PAYLOAD_TYPE_TRACE,
    PH_ROUTE_MASK,
    PH_TYPE_MASK,
    PH_TYPE_SHIFT,
    PH_VER_MASK,
    PH_VER_SHIFT,
    PUB_KEY_SIZE,
    ROUTE_TYPE_DIRECT,
    ROUTE_TYPE_FLOOD,
    ROUTE_TYPE_TRANSPORT_DIRECT,
    ROUTE_TYPE_TRANSPORT_FLOOD,
    SIGNATURE_SIZE,
    TIMESTAMP_SIZE,
)
from .packet_utils import PacketDataUtils, PacketHashingUtils, PacketValidationUtils, PathUtils

"""
╔═══════════════════════════════════════════════════════════════════════════╗
║                          MESH PACKET STRUCTURE OVERVIEW                   ║
╠════════════════════╦══════════════════════════════════════════════════════╣
║ Field              ║ Description                                          ║
╠════════════════════╬══════════════════════════════════════════════════════╣
║ Header (1 byte)    ║ Encodes route type (2 bits), payload type (4 bits),  ║
║                    ║ and version (2 bits).                                ║
╠════════════════════╬══════════════════════════════════════════════════════╣
║ Transport Codes    ║ Two 16-bit codes (4 bytes total). Only present for   ║
║ (0 or 4 bytes)     ║ TRANSPORT_FLOOD and TRANSPORT_DIRECT route types.    ║
╠════════════════════╬══════════════════════════════════════════════════════╣
║ Path Length (1 B)  ║ Encoded: bits 0-5 = hash count (hops), bits 6-7 =    ║
║                    ║ (hash_size - 1). Actual bytes = count × hash_size.   ║
╠════════════════════╬══════════════════════════════════════════════════════╣
║ Path (N bytes)     ║ Node hashes (1-3 bytes each), N = count × hash_size  ║
╠════════════════════╬══════════════════════════════════════════════════════╣
║ Payload (N bytes)  ║ Actual encrypted or plain payload. Max: 184 bytes    ║
╠════════════════════╬══════════════════════════════════════════════════════╣
║ Total Size         ║ Bounded by MAX_PACKET_PAYLOAD for the payload field   ║
╚════════════════════╩══════════════════════════════════════════════════════╝

Header Layout (1 byte):
╔═══════════╦════════════╦════════════════════════════════╗
║ Bits      ║ Name       ║ Meaning                        ║
╠═══════════╬════════════╬════════════════════════════════╣
║ 0–1       ║ RouteType  ║ 00: TransportFlood,            ║
║           ║            ║ 01: Flood, 10: Direct,         ║
║           ║            ║ 11: TransportDirect            ║
╠═══════════╬════════════╬════════════════════════════════╣
║ 2–5       ║ PayloadType║ See PAYLOAD_TYPE_* constants   ║
╠═══════════╬════════════╬════════════════════════════════╣
║ 6–7       ║ Version    ║ Packet format version (0–3)    ║
╚═══════════╩════════════╩════════════════════════════════╝

Notes:
- `write_to()` and `read_from()` enforce the exact structure used in firmware.
- Transport codes are included only for route types 0x00 and 0x03.
- Payload size must be ≤ MAX_PACKET_PAYLOAD (currently 184).
- `calculate_packet_hash()` includes payload type + path_len (only for TRACE).
"""


class Packet:
    """
    Represents a mesh network packet with header, transport codes, path, and payload components.

    This class handles serialization and deserialization of packets in the mesh protocol,
    providing methods for packet validation, hashing, and data extraction. It maintains
    compatibility with C++ packet formats for cross-platform interoperability.

    Attributes:
        header (int): Single byte header containing packet type and flags.
        transport_codes (list): Two 16-bit transport codes for TRANSPORT route types.
        path_len (int): Encoded path length byte (bits 0-5 = hash count, bits 6-7 = hash size - 1).
        path (bytearray): Variable-length path data for routing (hash_count × hash_size bytes).
        payload (bytearray): Variable-length payload data.
        payload_len (int): Actual length of payload data.
        _rssi (int): Raw RSSI signal strength value from firmware.
        _snr (int): Raw SNR value from firmware.

    Example:
        ```python
        packet = Packet()
        packet.header = 0x01  # Flood routing
        packet.set_path(b"\\xAA\\xBB\\xCC")  # 3 hops, 1-byte hashes
        packet.payload = b"Hello World"
        packet.payload_len = len(packet.payload)
        data = packet.write_to()
        # data can be transmitted over the mesh network
        ```
    """

    """
    Python replica of mesh::Packet (compatible with C++ writeTo/readFrom).

    Provides:
    - Header parsing (route type, payload type/version)
    - Serialization (write_to) and deserialization (read_from)
    - Packet hashing (for ACKs, deduplication, validation)
    - Raw signal info (SNR, RSSI)
    """

    __slots__ = (
        "header",
        "path_len",
        "decrypted",
        "payload_len",
        "path",
        "payload",
        "transport_codes",
        "_snr",
        "_rssi",
        "_rx_radio_id",
        "_do_not_retransmit",
        "drop_reason",
        "_tx_metadata",
        "_path_hash_mode_applied",
        "_flood_scope_applied",
        "_injected_for_tx",
        "_injected_origin_hash",
        "_recv_region_captured",
        "_recv_region_key",
        "_recv_region_unscoped",
        "_recv_default_scope_key",
    )

    def __init__(self):
        """
        Initialize a new empty packet with default values.

        Sets up the packet structure with zero-initialized fields ready for
        population with actual packet data. All fields are initialized to
        safe default values to prevent undefined behavior.
        """
        self.header = 0x00
        self.path = bytearray()
        self.payload = bytearray()
        self.decrypted = {}
        self.path_len = 0
        self.payload_len = 0
        self.transport_codes = [0, 0]  # Array of two 16-bit transport codes
        self._snr = 0
        self._rssi = 0
        self._rx_radio_id = None
        # Repeater flag to prevent retransmission and log drop reason
        self._do_not_retransmit = False
        self.drop_reason = None  # Optional: reason for dropping packet
        self._path_hash_mode_applied = False
        # Set once the companion layer has decided this flood packet's scoping
        # (scoped or deliberately plain); the dispatcher must not re-scope it.
        self._flood_scope_applied = False
        self._injected_for_tx = False  # Set by repeater inject path; skip engine on route
        # Companion that originated this injected TX, as the "0xHH" hash string the
        # host keys its frame servers by (None for host-originated injects). Set by
        # the repeater inject path so the companion fan-out can withhold the packet
        # from its own sender -- a node never hears its own transmission.
        self._injected_origin_hash: Optional[str] = None
        # Region captured from this packet on receive. Only set True when
        # a RegionMap was actually consulted; the matched region key (or None)
        # plus the snapshotted default key are read by region_map.apply_reply_scope
        # when a handler builds a flood reply (chooseReplyScope REQUEST / DEFAULT /
        # NONE). Lives on the Packet, never a shared dispatcher member, because
        # replies are sent from background tasks that would race.
        self._recv_region_captured: bool = False
        self._recv_region_key: Optional[bytes] = None
        self._recv_region_unscoped: bool = False
        self._recv_default_scope_key: Optional[bytes] = None

    def get_route_type(self) -> int:
        """
        Extract the 2-bit route type from the packet header.

        Returns:
            int: Route type value (0-3) indicating routing method:
                - 0: Transport flood routing (with transport codes)
                - 1: Flood routing
                - 2: Direct routing
                - 3: Transport direct routing (with transport codes)
        """
        return self.header & PH_ROUTE_MASK

    def get_payload_type(self) -> int:
        """
        Extract the 4-bit payload type from the packet header.

        Returns:
            int: Payload type value indicating the type of data in the packet:
                - 0: Plain text message
                - 1: Encrypted message
                - 2: ACK packet
                - 3: Advertisement
                - 4: Login request/response
                - 5: Protocol control
                - 6-15: Reserved for future use
        """
        return (self.header >> PH_TYPE_SHIFT) & PH_TYPE_MASK

    def get_payload_ver(self) -> int:
        """
        Extract the 2-bit payload version from the packet header.

        Returns:
            int: Version number (0-3) indicating the packet format version.
                Higher versions may include additional features or format changes.
        """
        return (self.header >> PH_VER_SHIFT) & PH_VER_MASK

    def has_transport_codes(self) -> bool:
        """
        Check if this packet includes transport codes in its format.

        Returns:
            bool: True if the packet uses transport flood or transport direct
                routing, which includes 4 bytes of transport codes after the header.
        """
        route_type = self.get_route_type()
        return route_type == ROUTE_TYPE_TRANSPORT_FLOOD or route_type == ROUTE_TYPE_TRANSPORT_DIRECT

    def is_route_flood(self) -> bool:
        """
        Check if this packet uses flood routing (with or without transport codes).

        Returns:
            bool: True if the packet uses any form of flood routing.
        """
        route_type = self.get_route_type()
        return route_type == ROUTE_TYPE_TRANSPORT_FLOOD or route_type == ROUTE_TYPE_FLOOD

    def is_route_direct(self) -> bool:
        """
        Check if this packet uses direct routing (with or without transport codes).

        Returns:
            bool: True if the packet uses any form of direct routing.
        """
        route_type = self.get_route_type()
        return route_type == ROUTE_TYPE_TRANSPORT_DIRECT or route_type == ROUTE_TYPE_DIRECT

    def get_path_hash_size(self) -> int:
        """Extract per-hop hash size (1, 2, or 3) from the encoded path_len byte."""
        return PathUtils.get_path_hash_size(self.path_len)

    def get_path_hash_count(self) -> int:
        """Extract hop count (0-63) from the encoded path_len byte."""
        return PathUtils.get_path_hash_count(self.path_len)

    def get_path_byte_len(self) -> int:
        """Calculate actual path byte length from the encoded path_len byte."""
        return PathUtils.get_path_byte_len(self.path_len)

    def apply_path_hash_mode(
        self,
        mode: int,
        *,
        mark_applied: bool = False,
    ) -> None:
        """Set path_len bits 6-7 from path_hash_mode for 0-hop packets (skip TRACE).

        Used by companion, handlers and dispatcher so the rule lives in one place.
        TRACE packets are excluded because the repeater's trace handler uses
        path/path_len for SNR values, not routing hashes.

        Args:
            mode: Path hash mode: 0=1-byte, 1=2-byte, 2=3-byte per hop.
            mark_applied: If True, set ``_path_hash_mode_applied``, which stops
                ``Dispatcher._apply_default_path_hash_mode`` overwriting this
                width with the node default on the way out. Three callers claim
                it, for the same reason -- the width was decided by something
                that outranks the node preference:

                * the companion applying its own configured preference
                  (``base_config._apply_path_hash_mode``);
                * a server handler mirroring the width of the request it is
                  answering, which is what firmware's ``sendFloodReply(...,
                  packet->getPathHashSize())`` does -- the node preference
                  governs only self-originated floods;
                * the dispatcher itself on a packet being forwarded, whose width
                  belongs to the originator.

                Leave it False to let the node default decide (the dispatcher's
                own call site, which is that default).

        Note:
            ``_path_hash_mode_applied`` is an in-memory attribute, not part of
            the wire format, so it does not survive a serialize/parse round trip.
            Anything between a handler and the radio must pass the Packet object
            itself, or the marked width is silently replaced by the node default.

        Raises:
            ValueError: If mode not in (0, 1, 2).
        """
        if mode not in (0, 1, 2):
            raise ValueError(f"path_hash_mode must be 0, 1, or 2, got {mode}")
        if self.get_payload_type() == PAYLOAD_TYPE_TRACE:
            return
        if self.get_path_hash_count() != 0:
            return
        self.path_len = PathUtils.encode_path_len(mode + 1, 0)
        if mark_applied:
            self._path_hash_mode_applied = True

    def get_path_hashes(self) -> list:
        """Return path as a list of per-hop hash entries (1, 2, or 3 bytes each).

        Groups the raw ``self.path`` bytearray using the hash size encoded in
        ``self.path_len``.  Each entry in the returned list is a ``bytes``
        object whose length equals ``get_path_hash_size()``.

        Returns:
            list[bytes]: One entry per hop.  Empty list when hop count is 0.
        """
        hash_size = self.get_path_hash_size()
        count = self.get_path_hash_count()
        result = []
        for i in range(count):
            start = i * hash_size
            end = start + hash_size
            if end <= len(self.path):
                result.append(bytes(self.path[start:end]))
        return result

    def get_path_hashes_hex(self) -> list:
        """Return path as a list of uppercase hex strings, one per hop.

        Examples::

            1-byte hashes: ["B5", "A3", "F2"]
            2-byte hashes: ["B5A3", "F2C1"]
            3-byte hashes: ["B5A3F2", "C1D4E7"]
        """
        return [entry.hex().upper() for entry in self.get_path_hashes()]

    def set_path(
        self,
        path_bytes: bytes,
        path_len_encoded: int = None,
    ) -> None:
        """Set the routing path with optional encoded path_len.

        Args:
            path_bytes: Raw path bytes to set.
            path_len_encoded: Pre-encoded path_len byte. If None, assumes
                1-byte hashes and encodes len(path_bytes) as the hop count.
        """
        self.path = bytearray(path_bytes)
        if path_len_encoded is not None:
            self.path_len = path_len_encoded
        else:
            hop_count = len(path_bytes)
            if hop_count > 63:
                raise ValueError(
                    f"path length {hop_count} exceeds maximum encodable hop count 63 "
                    "for 1-byte hashes; pass path_len_encoded explicitly or use a shorter path"
                )
            self.path_len = PathUtils.encode_path_len(1, hop_count)

    def get_payload(self) -> bytes:
        """
        Get the packet payload as immutable bytes, truncated to declared length.

        Returns:
            bytes: The actual payload data, limited to payload_len bytes.
                Returns empty bytes if payload_len is 0 or negative.

        Note:
            This method ensures only the declared payload length is returned,
            preventing access to any extra data that might be in the buffer.
        """
        return bytes(self.payload[: self.payload_len])

    def get_payload_app_data(self) -> bytes:
        """
        Extract application-specific data from the payload, skipping protocol headers.

        Returns:
            bytes: Application data portion of the payload, excluding the protocol
                overhead (public key, timestamp, and signature). Returns empty bytes
                if the payload is too short to contain the full protocol header.

        Note:
            The protocol header consists of:
            - Public key (PUB_KEY_SIZE bytes)
            - Timestamp (TIMESTAMP_SIZE bytes)
            - Signature (SIGNATURE_SIZE bytes)
        """
        offset = PUB_KEY_SIZE + TIMESTAMP_SIZE + SIGNATURE_SIZE
        return self.get_payload()[offset:] if self.payload_len >= offset else b""

    def _validate_lengths(self) -> None:
        """
        Validate that internal length values match actual buffer lengths.

        Ensures data integrity by checking that declared lengths (path_len, payload_len)
        match the actual buffer sizes. This prevents buffer overflow and underflow issues.

        Raises:
            ValueError: If any declared length doesn't match the actual buffer length.
        """
        PacketValidationUtils.validate_buffer_lengths(
            self.get_path_byte_len(),
            len(self.path),
            self.payload_len,
            len(self.payload),
        )

    def _validate_payload_size(self) -> None:
        """Validate that payload_len does not exceed MAX_PACKET_PAYLOAD."""
        PacketValidationUtils.validate_payload_size(self.payload_len)

    def _check_bounds(self, idx: int, required: int, data_len: int, error_msg: str) -> None:
        """
        Check if we have enough data remaining for the requested operation.

        Args:
            idx (int): Current position in the data buffer.
            required (int): Number of bytes required for the operation.
            data_len (int): Total length of the data buffer.
            error_msg (str): Error message to use if bounds check fails.

        Raises:
            ValueError: If there are insufficient bytes remaining in the buffer.
        """
        PacketValidationUtils.validate_packet_bounds(idx, required, data_len, error_msg)

    def write_to(self) -> bytes:
        """
        Serialize the packet to a byte sequence compatible with C++ Packet::writeTo().

        Creates a wire-format byte representation of the packet that can be transmitted
        over the mesh network. The format matches the C++ implementation exactly.

        Returns:
            bytes: Serialized packet data in the format:
                ``header(1) | [transport_codes(4)] | path_len(1) | path(N) | payload(M)``
                Transport codes are only included if has_transport_codes() is True.

        Raises:
            ValueError: If internal length values don't match actual buffer lengths,
                indicating data corruption or incorrect packet construction, or if
                the payload exceeds MAX_PACKET_PAYLOAD.
        """
        self._validate_lengths()
        self._validate_payload_size()

        out = bytearray([self.header])

        # Add transport codes if this packet type requires them
        if self.has_transport_codes():
            # Pack two 16-bit transport codes (4 bytes total) in little-endian format
            out.extend(self.transport_codes[0].to_bytes(2, "little"))
            out.extend(self.transport_codes[1].to_bytes(2, "little"))

        out.append(self.path_len)
        out += self.path[: self.get_path_byte_len()]
        out += self.payload[: self.payload_len]
        return bytes(out)

    def read_from(self, data: ByteString) -> bool:
        """
        Deserialize a C++ wire-format packet from bytes.

        Parses the binary packet data received over the network and populates
        the packet fields. The format must match the C++ Packet::readFrom() exactly.

        Args:
            data (ByteString): Raw packet data in wire format.

        Returns:
            bool: True if deserialization was successful.

        Raises:
            ValueError: If the packet format is invalid, truncated, or contains
                invalid values (e.g., path_len too large, invalid payload size).
        """
        idx, data_len = 0, len(data)
        self.header = data[idx]
        idx += 1

        # Validate packet version (must match C++ supported versions)
        version = self.get_payload_ver()
        if version > MAX_SUPPORTED_PAYLOAD_VERSION:
            raise ValueError(f"Unsupported packet version: {version}")

        # Read transport codes if present
        if self.has_transport_codes():
            self._check_bounds(idx, 4, data_len, "missing transport codes")
            # Unpack two 16-bit transport codes from little-endian format
            self.transport_codes[0] = int.from_bytes(data[idx : idx + 2], "little")
            self.transport_codes[1] = int.from_bytes(data[idx + 2 : idx + 4], "little")
            idx += 4
        else:
            self.transport_codes = [0, 0]

        self._check_bounds(idx, 1, data_len, "missing path_len")
        self.path_len = data[idx]
        idx += 1
        if not PathUtils.is_valid_path_len(self.path_len):
            hash_size = PathUtils.get_path_hash_size(self.path_len)
            if hash_size > 3:
                raise ValueError(f"invalid path_len encoding: 0x{self.path_len:02X}")
            raise ValueError("path_len too large")

        path_byte_len = self.get_path_byte_len()
        self._check_bounds(idx, path_byte_len, data_len, "truncated path")
        self.path = bytearray(data[idx : idx + path_byte_len])
        idx += path_byte_len

        self.payload = bytearray(data[idx:])
        self.payload_len = len(self.payload)
        PacketValidationUtils.validate_payload_size(self.payload_len)

        return True

    def calculate_packet_hash(self) -> bytes:
        """
        Compute SHA256-based hash for ACK, deduplication, and validation.

        Generates a cryptographic hash of the packet content for use in:
        - ACK packet generation and verification
        - Packet deduplication to prevent replay attacks
        - Message integrity validation

        Returns:
            bytes: First MAX_HASH_SIZE bytes of a SHA256 digest computed over
                the payload type and payload data. The path length (path_len) is
                included ONLY for TRACE packets; it is excluded for every other
                type.

        Note:
            path_len is deliberately NOT hashed for non-TRACE packets: echo and
            duplicate suppression depend on it, so a rebroadcast that arrives with
            a longer accumulated path must hash identically to the original. Only
            TRACE packets fold in path_len — per firmware's CAVEAT (Packet.cpp),
            a TRACE can revisit the same node on its return path, so its hash must
            differ by route. Matches PacketHashingUtils.calculate_packet_hash and
            MeshCore Packet::calculatePacketHash.
        """
        return PacketHashingUtils.calculate_packet_hash(
            self.get_payload_type(), self.path_len, self.payload[: self.payload_len]
        )

    def get_packet_hash_hex(self, length: Optional[int] = None) -> str:
        """
        Return upper-case hex string representation of this packet's hash.

        Args:
            length (Optional[int], optional): Maximum length of the returned hex string.
                Defaults to None (full hash string).

        Returns:
            str: Upper-case hex string of the packet hash.
        """
        return PacketHashingUtils.calculate_packet_hash_string(
            payload_type=self.get_payload_type(),
            path_len=self.path_len,
            payload=self.payload[: self.payload_len],
            length=length,
        )

    def get_crc(self) -> int:
        """
        Calculate a 4-byte CRC from SHA256 digest for ACK confirmation.

        Generates a compact checksum derived from the packet's SHA256 hash,
        used specifically for ACK packet confirmation to ensure the ACK
        corresponds to the correct original packet.

        Returns:
            int: 32-bit CRC value extracted from the SHA256 digest,
                used for lightweight packet identification in ACKs.

        Note:
            This CRC is more compact than the full hash but still provides
            sufficient uniqueness for ACK correlation in the mesh network.
        """
        return PacketHashingUtils.calculate_crc(
            self.get_payload_type(), self.path_len, self.payload[: self.payload_len]
        )

    def get_raw_length(self) -> int:
        """
        Calculate the total byte length of the packet on the wire.

        Computes the exact size of the serialized packet as it would appear
        on the network, matching the C++ Packet::getRawLength() implementation.

        Returns:
            int: Total packet size in bytes, calculated as:
                header(1) + [transport_codes(4)] + path_len(1) + path(N) + payload(M)
                Transport codes are only included if has_transport_codes() is True.

        Note:
            This matches the wire format used by write_to() and expected by read_from().
        """
        base_length = (
            2 + self.get_path_byte_len() + self.payload_len
        )  # header + path_len_byte + path + payload
        return base_length + (4 if self.has_transport_codes() else 0)

    def get_snr(self) -> float:
        """
        Calculate the signal-to-noise ratio in decibels.

        Converts the raw SNR value from firmware into a standardized
        decibel representation for signal quality assessment.

        Returns:
            float: SNR value in dB, where higher values indicate better
                signal quality relative to background noise.
        """
        return PacketDataUtils.calculate_snr_db(self._snr)

    @property
    def rssi(self) -> int:
        """
        Get the raw RSSI (Received Signal Strength Indicator) value.

        Returns the signal strength measurement from the radio firmware
        in its native scale, typically used for relative signal comparisons.

        Returns:
            int: Raw RSSI value from firmware. Higher values indicate
                stronger received signals.
        """
        return self._rssi

    @property
    def snr(self) -> float:
        """
        Get the signal-to-noise ratio in decibels.

        Provides convenient access to the calculated SNR value in dB,
        automatically converting from the raw firmware value.

        Returns:
            float: SNR in decibels, where positive values indicate
                signal power above noise floor, negative values indicate
                signal below noise floor.
        """
        return self.get_snr()

    def mark_do_not_retransmit(self) -> None:
        """
        Mark this packet to prevent retransmission.

        Sets a flag indicating this packet should not be forwarded by repeaters.
        This is typically set when a packet has been successfully delivered to
        its intended destination to prevent unnecessary network traffic.

        Used by destination nodes after successfully decrypting and processing
        a message intended for them.
        """
        self._do_not_retransmit = True

    def is_marked_do_not_retransmit(self) -> bool:
        """
        Check if this packet is marked to prevent retransmission.

        Returns:
            bool: True if the packet should not be retransmitted/forwarded.
                This indicates the packet has reached its destination or should
                remain local to the receiving node.
        """
        return self._do_not_retransmit
