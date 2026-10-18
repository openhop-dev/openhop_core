"""Protocol response handler for mesh network protocol requests.

Handles responses to protocol requests (like stats, config, etc.) that come
back as PATH packets with encrypted payloads.
"""

import asyncio
import struct
from typing import Any, Callable, Dict, Optional

from ...protocol import Packet
from ...protocol.constants import PAYLOAD_TYPE_PATH, PAYLOAD_TYPE_RESPONSE, ROUTE_TYPE_DIRECT
from ...protocol.crypto import CIPHER_BLOCK_SIZE, CIPHER_MAC_SIZE
from ...protocol.packet_builder import PacketBuilder
from ...protocol.packet_utils import PathUtils
from .crypto_helpers import iter_decrypt_by_src_hash
from .result import HandlerResult
from .return_path import ReturnPathTeacher

# ---------------------------------------------------------------------------
# Built-in CayenneLPP decoder (no external dependency)
# Spec: https://docs.mydevices.com/docs/lorawan/cayenne-lpp
# Each record: channel(1) + type_id(1) + value(N)
# ---------------------------------------------------------------------------

_LPP_TYPES: Dict[int, tuple] = {
    # type_id: (name, value_size_bytes, divisor, signed)
    # --- Original LPPv1 types ---
    0x00: ("Digital Input", 1, 1, False),
    0x01: ("Digital Output", 1, 1, False),
    0x02: ("Analog Input", 2, 100, True),
    0x03: ("Analog Output", 2, 100, True),
    # --- Extended types (from CayenneLPP.h) ---
    0x64: ("Generic Sensor", 4, 1, False),  # LPP_GENERIC_SENSOR  = 100
    0x65: ("Illuminance", 2, 1, False),  # LPP_LUMINOSITY      = 101
    0x66: ("Presence", 1, 1, False),  # LPP_PRESENCE        = 102
    0x67: ("Temperature", 2, 10, True),  # LPP_TEMPERATURE     = 103
    0x68: ("Humidity", 1, 2, False),  # LPP_RELATIVE_HUMIDITY = 104
    0x71: ("Accelerometer", 6, 1000, True),  # LPP_ACCELEROMETER   = 113, 3×int16
    0x73: ("Barometer", 2, 10, False),  # LPP_BAROMETRIC_PRESSURE = 115
    0x74: ("Voltage", 2, 100, False),  # LPP_VOLTAGE         = 116, 0.01V
    0x75: ("Current", 2, 1000, True),  # LPP_CURRENT         = 117, 0.001A signed
    0x76: ("Frequency", 4, 1, False),  # LPP_FREQUENCY       = 118, 1Hz
    0x78: ("Percentage", 1, 1, False),  # LPP_PERCENTAGE      = 120, 1-100%
    0x79: ("Altitude", 2, 1, True),  # LPP_ALTITUDE        = 121, 1m signed
    0x7D: ("Concentration", 2, 1, False),  # LPP_CONCENTRATION   = 125, 1ppm
    0x80: ("Power", 2, 1, False),  # LPP_POWER           = 128, 1W
    0x82: ("Distance", 4, 1000, False),  # LPP_DISTANCE        = 130, 0.001m
    0x83: ("Energy", 4, 1000, False),  # LPP_ENERGY          = 131, 0.001kWh
    0x84: ("Direction", 2, 1, False),  # LPP_DIRECTION       = 132, 1deg
    0x85: ("Unix Time", 4, 1, False),  # LPP_UNIXTIME        = 133
    0x86: ("Gyroscope", 6, 100, True),  # LPP_GYROMETER       = 134, 3×int16
    0x87: ("Colour", 3, 1, False),  # LPP_COLOUR          = 135, RGB
    0x88: ("GPS", 9, 1, True),  # LPP_GPS             = 136, lat(3)+lon(3)+alt(3), mult 10000/100
    0x8E: ("Switch", 1, 1, False),  # LPP_SWITCH          = 142, 0/1
    # LPP_POLYLINE 240: variable size; min 8 bytes (size+delta+lon+lat). Skip min to continue.
    0xF0: ("Polyline", 8, 1, False),  # LPP_POLYLINE       = 240
}


def _decode_cayenne_lpp(data: bytes) -> list:
    """Decode CayenneLPP binary payload into a list of sensor dicts."""
    sensors: list = []
    idx = 0
    while idx + 2 <= len(data):
        channel = data[idx]
        type_id = data[idx + 1]
        # Channel 0 is never used by MeshCore firmware (channels start at
        # TELEM_CHANNEL_SELF=1).  A channel=0 byte is AES zero-padding — stop.
        if channel == 0:
            break
        idx += 2
        spec = _LPP_TYPES.get(type_id)
        if spec is None:
            break  # unknown type → stop (remaining bytes may be padding)
        name, size, divisor, signed = spec
        if idx + size > len(data):
            break
        raw = data[idx : idx + size]
        idx += size

        if type_id == 0x88:
            # GPS: lat(3, signed, /10000) + lon(3, signed, /10000) + alt(3, signed, /100)
            lat = int.from_bytes(raw[0:3], "big", signed=True) / 10000
            lon = int.from_bytes(raw[3:6], "big", signed=True) / 10000
            alt = int.from_bytes(raw[6:9], "big", signed=True) / 100
            sensors.append(
                {
                    "channel": channel,
                    "type": name,
                    "type_id": type_id,
                    "value": {"latitude": lat, "longitude": lon, "altitude": alt},
                    "raw_value": raw.hex(),
                }
            )
        elif size == 6 and type_id in (0x71, 0x86):
            # 3-axis: x(2) + y(2) + z(2), all signed
            x = int.from_bytes(raw[0:2], "big", signed=True) / divisor
            y = int.from_bytes(raw[2:4], "big", signed=True) / divisor
            z = int.from_bytes(raw[4:6], "big", signed=True) / divisor
            sensors.append(
                {
                    "channel": channel,
                    "type": name,
                    "type_id": type_id,
                    "value": {"x": x, "y": y, "z": z},
                    "raw_value": raw.hex(),
                }
            )
        elif type_id == 0x87:
            # Colour: R(1) + G(1) + B(1)
            sensors.append(
                {
                    "channel": channel,
                    "type": name,
                    "type_id": type_id,
                    "value": {"r": raw[0], "g": raw[1], "b": raw[2]},
                    "raw_value": raw.hex(),
                }
            )
        elif type_id == 0xF0:
            # Polyline: variable size; we only consume minimum 8 bytes (MeshCore skipData).
            sensors.append(
                {
                    "channel": channel,
                    "type": name,
                    "type_id": type_id,
                    "value": raw.hex(),
                    "raw_value": raw.hex(),
                }
            )
        else:
            val = int.from_bytes(raw, "big", signed=signed)
            sensors.append(
                {
                    "channel": channel,
                    "type": name,
                    "type_id": type_id,
                    "value": val / divisor if divisor != 1 else val,
                    "raw_value": raw.hex(),
                }
            )
    return sensors


class ProtocolResponseHandler:
    """Handler for protocol responses that come back as encrypted PATH packets.

    This handler specifically deals with responses to protocol requests like:
    - Protocol 0x01: Get repeater stats
    - Protocol 0x02: Get configuration
    - etc.
    """

    def __init__(
        self,
        log_fn: Callable[[str], None],
        local_identity,
        contact_book,
        *,
        return_path_teacher: Optional["ReturnPathTeacher"] = None,
    ):
        self._log = log_fn
        self._local_identity = local_identity
        self._contact_book = contact_book
        # Re-teaches a peer its route back to us when a reply arrives flooded
        # despite us holding a direct out_path. Constructed here when the caller
        # supplies none so standalone use of this handler still works; the
        # factory passes a shared instance (see registry.create_core_handlers).
        self.return_path_teacher = return_path_teacher or ReturnPathTeacher(
            log_fn, local_identity, contact_book
        )

        # A response is correlated only after the MAC identifies the complete
        # contact and the peer reflects the request tag. The one-byte source
        # hash remains solely a hint for choosing decryption candidates.
        self._response_waiters: Dict[
            tuple[bytes, int], Callable[[bool, str, Dict[str, Any]], None]
        ] = {}
        # Optional: decrypted payloads with tag+data (and optional path) passed as binary response.
        # Signature: (tag_bytes, response_data, path_info=None).
        self._binary_response_callback: Optional[Callable[..., Any]] = None
        # Reference to LoginResponseHandler for state-based login detection
        self._login_response_handler: Optional[Any] = None
        # Packet injector for sending reciprocal PATH packets (mirrors C++ Mesh.cpp:168-169)
        self._packet_injector: Optional[Callable] = None
        # Reciprocal sends are queued so login/ACK delivery cannot block behind
        # radio TX, duty-cycle, or LBT waits. Keep strong references until done.
        self._pending_reciprocals: set[asyncio.Task] = set()
        # Optional: notify when contact out_path is updated from decrypted PATH
        # (e.g. companion persist).
        self._contact_path_updated_callback: Optional[Callable[..., Any]] = None

    def set_contact_path_updated_callback(self, callback: Optional[Callable[..., Any]]) -> None:
        """Set callback when contact out_path is updated from a decrypted PATH packet.

        Signature: (contact_pubkey: bytes, path_len: int, path_bytes: bytes)
        -> None | Awaitable[None].
        Called after _update_contact_path when the contact was found and updated.
        """
        self._contact_path_updated_callback = callback

    def set_login_response_handler(self, handler: Any) -> None:
        """Set login handler ref for checking active login state."""
        self._login_response_handler = handler

    def set_packet_injector(self, injector: Optional[Callable]) -> None:
        """Set packet injector for sending reciprocal PATH packets.

        When the companion receives a flooded PATH from a remote repeater,
        the C++ firmware sends a reciprocal PATH back so the remote repeater
        learns the route to us (Mesh.cpp:168-169).  Without this, the remote
        repeater has no out_path for us and must fall back to plain FLOOD for
        responses — which intermediate repeaters may drop due to transport-code
        region filtering.

        The same transmit path is handed to the return-path teacher, which
        covers the flood-RESPONSE case this handler's PATH-only reciprocal
        misses (see :mod:`.return_path`).
        """
        self._packet_injector = injector
        self.return_path_teacher.set_injector(injector)

    async def wait_for_pending_reciprocals(self) -> None:
        """Await queued reciprocal PATH transmissions (shutdown/tests)."""
        while self._pending_reciprocals:
            pending = tuple(self._pending_reciprocals)
            await asyncio.gather(*pending, return_exceptions=True)
            self._pending_reciprocals.difference_update(pending)

    def cancel_pending_reciprocals(self) -> None:
        """Cancel reciprocal PATH transmissions that have not completed."""
        for task in tuple(self._pending_reciprocals):
            task.cancel()

    @staticmethod
    def payload_type() -> int:
        return PAYLOAD_TYPE_PATH  # Protocol responses come as PATH packets

    def set_response_callback(
        self,
        contact_pubkey: bytes,
        request_tag: int,
        callback: Callable[[bool, str, Dict[str, Any]], None],
    ) -> None:
        """Set a callback for one contact's reflected request tag."""
        self._response_waiters[(bytes(contact_pubkey), request_tag & 0xFFFFFFFF)] = callback

    def clear_response_callback(self, contact_pubkey: bytes, request_tag: int) -> None:
        """Clear one contact-and-tag response waiter."""
        self._response_waiters.pop((bytes(contact_pubkey), request_tag & 0xFFFFFFFF), None)

    def set_binary_response_callback(self, callback: Callable[..., Any]) -> None:
        """Set callback for binary responses. (tag_bytes, response_data, path_info=None).
        path_info = (out_path, in_path, contact_pubkey) for path-return format."""
        self._binary_response_callback = callback

    async def __call__(self, pkt: Packet) -> HandlerResult:
        """Handle PATH/RESPONSE and report ownership after MAC verification."""
        authenticated = False
        try:
            # Check if this looks like an encrypted protocol response
            if len(pkt.payload) < 4:
                return HandlerResult.not_for_us()  # Too short for protocol response

            # Both PATH and RESPONSE packets share the same structure:
            # dest_hash(1) + src_hash(1) + encrypted_data(N)
            dest_hash = pkt.payload[0]
            src_hash = pkt.payload[1]
            pkt_type = pkt.get_payload_type()
            if dest_hash != self._local_identity.get_public_key()[0]:
                return HandlerResult.not_for_us()

            route_label = "FLOOD" if pkt.is_route_flood() else "DIRECT"
            if pkt_type == PAYLOAD_TYPE_RESPONSE:
                self._log(
                    f"[ProtocolResponse] Received RESPONSE (0x01) from 0x{src_hash:02X} "
                    f"({route_label}, {len(pkt.payload)}B)"
                )

            # Try to decrypt the response
            (
                success,
                decoded_text,
                parsed_data,
                raw_decrypted,
                matched_contact_pubkey,
                response_payload,
            ) = await self._decrypt_protocol_response(pkt, src_hash)
            if raw_decrypted is None:
                return HandlerResult.not_for_us()
            # A valid MAC establishes ownership even if higher-level parsing or
            # callback delivery later fails.
            authenticated = True

            # A valid MAC tells us which full contact sent the packet; the first
            # four response bytes are the firmware-reflected request tag. Pop
            # before invoking the callback so duplicate packets cannot complete
            # the same request twice.
            if (
                success
                and matched_contact_pubkey is not None
                and response_payload is not None
                and len(response_payload) >= 4
            ):
                response_tag = int.from_bytes(response_payload[:4], "little")
                callback = self._response_waiters.pop((matched_contact_pubkey, response_tag), None)
                if callback is not None:
                    if parsed_data.get("type") == "telemetry":
                        self._log(
                            f"[ProtocolResponse] Delivering telemetry to waiter "
                            f"(src=0x{src_hash:02X}, {parsed_data.get('sensor_count', 0)} sensors)"
                        )
                    callback(success, decoded_text, parsed_data)
                    return HandlerResult.consumed()

            # If binary response callback set, parse and invoke (tag+data or path-return)
            if (
                success
                and self._binary_response_callback is not None
                and response_payload is not None
                and len(response_payload) >= 4
            ):
                path_info = None
                pkt_type = pkt.get_payload_type()
                tag_bytes = response_payload[:4]
                response_data = response_payload[4:]

                if pkt_type == PAYLOAD_TYPE_PATH:
                    # PATH packet: decrypted is path_len(1)+path(N)+extra_type(1)+extra.
                    # _decrypt_protocol_response already verified this is a
                    # RESPONSE extra and returned that extra as response_payload.
                    path_len_byte = raw_decrypted[0]
                    path_byte_len = PathUtils.get_path_byte_len(path_len_byte)
                    if PathUtils.is_valid_path_len(path_len_byte):
                        out_path = bytes(raw_decrypted[1 : 1 + path_byte_len])
                        in_path = bytes(pkt.path) if pkt.path else b""
                        # Preserve the ENCODED path_len bytes (hash_count in
                        # bits 0-5, hash_size-1 in bits 6-7) so the push frame
                        # re-announces them verbatim like the firmware, which
                        # writes out_path_len / in_path_len directly
                        # (MyMesh.cpp:757-765). in_len_byte is pkt.path_len,
                        # the encoded byte the packet arrived with.
                        in_len_byte = pkt.path_len if pkt.path else 0
                        path_info = (
                            path_len_byte,
                            out_path,
                            in_len_byte,
                            in_path,
                            matched_contact_pubkey,
                        )

                # Do not deliver login responses to the binary callback; they are
                # handled by LoginResponseHandler. Login response format is
                # tag(4) + response_code(1) + keep_alive(1) + is_admin(1) + ...
                # = 13 bytes total, with response_code 0x00 or 0x01.
                if len(response_data) == 9 and response_data[0] in (0x00, 0x01):
                    return HandlerResult.consumed()

                try:
                    cb_result = self._binary_response_callback(tag_bytes, response_data, path_info)
                    if asyncio.iscoroutine(cb_result):
                        await cb_result
                except Exception as e:
                    self._log(f"[ProtocolResponse] Binary response callback error: {e}")
                return HandlerResult.consumed()

            return HandlerResult.consumed()

        except Exception as e:
            self._log(f"[ProtocolResponse] Error processing protocol response: {e}")
            return HandlerResult(authenticated=authenticated)

    def _update_contact_path(
        self,
        contact_pubkey: bytes,
        src_hash: int,
        path_len_byte: int,
        decrypted: bytes,
    ) -> bool:
        """Update contact out_path from decrypted PATH data (firmware onContactPathRecv pattern).

        When a PATH packet is successfully decrypted, store the return path
        on the contact so that subsequent requests use sendDirect() instead
        of sendFlood().  This mirrors C++ ``BaseChatMesh::onContactPathRecv``.

        Returns True if the contact was found and updated, False otherwise.
        """
        try:
            if not PathUtils.is_valid_path_len(path_len_byte):
                self._log(
                    f"[PATHDIAG] _update_contact_path REJECT src=0x{src_hash:02X}: "
                    f"invalid path_len_byte=0x{path_len_byte:02X}"
                )
                return False
            path_byte_len = PathUtils.get_path_byte_len(path_len_byte)
            out_path_bytes = bytes(decrypted[1 : 1 + path_byte_len])
            self._log(
                f"[PATHDIAG] _update_contact_path src=0x{src_hash:02X} "
                f"path_len_byte=0x{path_len_byte:02X} "
                f"hops={PathUtils.get_path_hash_count(path_len_byte)} "
                f"hash_size={PathUtils.get_path_hash_size(path_len_byte)} "
                f"byte_len={path_byte_len} out_path={out_path_bytes.hex() or '(empty)'}"
            )
            contact_obj = self._contact_book.get_by_key(contact_pubkey)
            if contact_obj is not None:
                prev_len = getattr(contact_obj, "out_path_len", None)
                contact_obj.out_path_len = path_len_byte
                contact_obj.out_path = out_path_bytes
                self._contact_book.update(contact_obj)
                self._log(
                    f"[ProtocolResponse] Updated out_path for 0x{src_hash:02X}: "
                    f"path_len={path_len_byte}"
                )
                self._log(
                    f"[PATHDIAG] contact 0x{src_hash:02X} out_path_len "
                    f"{prev_len} -> {path_len_byte} "
                    f"(hops {PathUtils.get_path_hash_count(path_len_byte)})"
                )
                return True
            else:
                self._log(
                    f"[ProtocolResponse] Cannot update out_path for 0x{src_hash:02X}: "
                    f"contact not found by key"
                )
                return False
        except Exception as e:
            self._log(f"[ProtocolResponse] Failed to update out_path: {e}")
            return False

    async def _send_reciprocal_path(
        self,
        src_hash: int,
        contact_pubkey: bytes,
        shared_secret: bytes,
        pkt: Packet,
        decrypted: bytes,
        path_len_byte: int,
    ) -> None:
        """Send a reciprocal PATH back to the sender so it learns the route to us.

        Mirrors C++ firmware behaviour (Mesh.cpp lines 166-169):

            mesh::Packet* rpath = createPathReturn(
                &src_hash, secret, pkt->path, pkt->path_len, 0, NULL, 0);
            if (rpath) sendDirect(rpath, path, path_len, 500);

        - ``pkt.path`` is the flood accumulation path on the received PATH
          (the inbound route, e.g. [hash_X, hash_B]).  This is placed inside
          the reciprocal's encrypted payload so the remote repeater stores it
          as *its* ``out_path`` — the route from itself back to us.
        - The reciprocal is sent **DIRECT** using the inner ``out_path``
          extracted from the decrypted data (e.g. [hash_B, hash_X]), which
          routes through the mesh to reach the remote repeater.
        - Transmission is queued rather than awaited inline. Firmware invokes
          ``onContactResponse`` before queueing this reciprocal; doing the same
          prevents a valid login reply from expiring behind the local TX path.
        """
        if self._packet_injector is None:
            return
        try:
            injector = self._packet_injector
            our_hash = self._local_identity.get_public_key()[0]
            # The inbound flood path (pkt.path) tells the remote repeater
            # "to reach me, go through these intermediate hops".
            in_path = list(pkt.path) if pkt.path else []
            # Key for the pre-dedup copy table, so the re-teach below can look up
            # the best-received copy of *this* reply. Path-independent, so every
            # copy hashes alike.
            reciprocal_hash_key = bytes(pkt.calculate_packet_hash())
            # The re-teach below replaces this copy only with a better one, so
            # the table must hold this copy too. A radio copy is there already
            # (pre-dedup feed); one delivered in-process by a multi-identity
            # host is not, and an over-the-air echo would otherwise win.
            self.return_path_teacher.seed_copy(pkt, reciprocal_hash_key)

            # Build the reciprocal PATH packet.  create_path_return produces a
            # FLOOD PATH by default; we convert it to DIRECT below.
            reciprocal = PacketBuilder.create_path_return(
                dest_hash=src_hash,
                src_hash=our_hash,
                secret=shared_secret,
                path=in_path,
                extra_type=0xFF,  # no extra payload (dummy, same as C++ NULL/0)
                extra=b"",
                path_len_encoded=pkt.path_len,
            )

            # Convert to DIRECT routing using the inner out_path (the route
            # from us to the remote repeater).
            path_byte_len = PathUtils.get_path_byte_len(path_len_byte)
            out_path_bytes = bytes(decrypted[1 : 1 + path_byte_len])
            reciprocal.header = (reciprocal.header & ~0x03) | ROUTE_TYPE_DIRECT
            reciprocal.set_path(out_path_bytes, path_len_byte)

            async def _dispatch_reciprocal() -> None:
                try:
                    sent = await injector(reciprocal)
                    if sent is False:
                        raise RuntimeError("packet injector rejected reciprocal PATH")
                    # Claims the teacher's cooldown so it does not immediately
                    # re-teach this contact the same route.
                    self.return_path_teacher.note_evidence_teach(contact_pubkey)
                    self._log(
                        f"[ProtocolResponse] Sending reciprocal PATH to 0x{src_hash:02X} "
                        f"via DIRECT (out_path_len={path_len_byte}, "
                        f"in_path_len={len(in_path)})"
                    )
                    self._log(
                        f"[PATHDIAG] reciprocal -> 0x{src_hash:02X} route=DIRECT "
                        f"routing_path={out_path_bytes.hex() or '(empty)'} "
                        f"embedded_in_path={bytes(in_path).hex() or '(empty)'} "
                        f"path_len_byte=0x{path_len_byte:02X}"
                    )
                    # The teach above had to go out now, on the first-arrived
                    # copy, so the peer has a usable route immediately. Copies of
                    # this same reply keep landing for a second or two, and the
                    # first is routinely the worst route; correct ourselves once
                    # the window closes. Scheduled, not awaited, so this send task
                    # ends with the wire write. Teaching twice is safe — see
                    # ReturnPathTeacher.maybe_reteach_better_copy.
                    self.return_path_teacher.schedule_reteach_better_copy(
                        contact_pubkey=contact_pubkey,
                        dest_hash=src_hash,
                        taught_path=bytes(in_path),
                        taught_len_byte=pkt.path_len,
                        out_path=out_path_bytes,
                        out_path_len=path_len_byte,
                        shared_secret=shared_secret,
                        hash_key=reciprocal_hash_key,
                        reason="reciprocal PATH",
                    )
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    self._log(f"[ProtocolResponse] Failed to send reciprocal PATH: {e}")

            task = asyncio.create_task(_dispatch_reciprocal())
            self._pending_reciprocals.add(task)
            task.add_done_callback(self._pending_reciprocals.discard)
        except Exception as e:
            self._log(f"[ProtocolResponse] Failed to queue reciprocal PATH: {e}")

    async def _decrypt_protocol_response(
        self, pkt: Packet, src_hash: int
    ) -> tuple[bool, str, Dict[str, Any], Optional[bytes], Optional[bytes], Optional[bytes]]:
        """Decrypt and parse a response with its authenticated sender and response bytes.

        Handles both packet types:
        - RESPONSE (0x01): direct → tag(4)+data
        - PATH (0x08): path_len+path(N)+extra_type+extra

        Both use same wire payload layout: dest_hash(1) + src_hash(1) + MAC(2) + ciphertext.
        """
        payload = pkt.get_payload()
        if len(payload) < 2 + 4:  # need dest+src + at least MAC(2)+min ciphertext
            return False, "Payload too short", {}, None, None, None
        encrypted_data = payload[2:]
        # MAC(2) + ciphertext. Ciphertext may be block-aligned or truncated (e.g. long PATH
        # packets lose one byte to header size; telemetry PATH 63 bytes). Allow MAC + 15 bytes
        # minimum so we can pad to one block and attempt decrypt.
        enc_len = len(encrypted_data)
        min_enc = CIPHER_MAC_SIZE + (CIPHER_BLOCK_SIZE - 1)  # 17: MAC(2) + 15 ciphertext
        if enc_len < min_enc:
            self._log(
                f"[ProtocolResponse] Payload too short for hash 0x{src_hash:02X}: "
                f"encrypted_data={enc_len}B (need MAC(2)+≥15 bytes ciphertext)"
            )
            return False, "Payload too short", {}, None, None, None
        pkt_type = pkt.get_payload_type()

        # Try every contact matching src_hash (same “try all hash matches” as TXT_MSG and PATH ACK).
        # Repeaters use the same ECDH shared secret as login (createPathReturn(..., secret, ...)).
        contacts_tried = list(self._contacts_by_hash(src_hash))
        for _contact, contact_pubkey, shared_secret, decrypted in iter_decrypt_by_src_hash(
            contacts_tried, src_hash, self._local_identity, encrypted_data
        ):
            # Determine the actual response data based on packet type. Only a
            # genuine RESPONSE payload is eligible for waiter correlation.
            response_data = decrypted
            response_payload = decrypted if pkt_type == PAYLOAD_TYPE_RESPONSE else None
            if pkt_type == PAYLOAD_TYPE_PATH:
                if len(decrypted) < 1 or not PathUtils.is_valid_path_len(decrypted[0]):
                    self._log(f"[ProtocolResponse] PATH format invalid for hash 0x{src_hash:02X}")
                    continue
                path_len_byte = decrypted[0]
                path_byte_len = PathUtils.get_path_byte_len(path_len_byte)
                inner_offset = 1 + path_byte_len + 1
                if len(decrypted) < inner_offset:
                    self._log(f"[ProtocolResponse] PATH data truncated for hash 0x{src_hash:02X}")
                    continue

                outer_path = bytes(pkt.path[: pkt.get_path_byte_len()]) if pkt.path_len else b""
                self._log(
                    f"[PATHDIAG] PATH rx src=0x{src_hash:02X} "
                    f"route={'FLOOD' if pkt.is_route_flood() else 'DIRECT'} "
                    f"outer_path_len=0x{pkt.path_len:02X} "
                    f"outer_hops={pkt.get_path_hash_count()} "
                    f"outer_path={outer_path.hex() or '(empty)'} "
                    f"inner_path_len_byte=0x{(decrypted[0] if decrypted else 0):02X}"
                )
                extra_type = decrypted[1 + path_byte_len] & 0x0F
                if extra_type == PAYLOAD_TYPE_RESPONSE and len(decrypted) > inner_offset:
                    response_data = decrypted[inner_offset:]
                    response_payload = response_data
                elif extra_type != PAYLOAD_TYPE_RESPONSE:
                    self._log(
                        f"[ProtocolResponse] PATH format: extra_type=0x{extra_type:02X}, "
                        f"not RESPONSE"
                    )

                # Firmware pattern (onContactPathRecv): update contact out_path
                # so subsequent requests use sendDirect() instead of sendFlood().
                out_path_bytes = bytes(decrypted[1 : 1 + path_byte_len])
                if self._update_contact_path(contact_pubkey, src_hash, path_len_byte, decrypted):
                    if self._contact_path_updated_callback is not None:
                        cb_result = self._contact_path_updated_callback(
                            contact_pubkey, path_len_byte, out_path_bytes
                        )
                        if asyncio.iscoroutine(cb_result):
                            await cb_result

                # Firmware pattern (Mesh.cpp:168-169): send reciprocal PATH back
                # to the sender so it learns the route to us.  Without this, the
                # remote repeater has no out_path for us and must fall back to
                # plain FLOOD for responses — which intermediate repeaters may
                # drop due to transport-code region filtering.
                if pkt.is_route_flood():
                    await self._send_reciprocal_path(
                        src_hash,
                        contact_pubkey,
                        shared_secret,
                        pkt,
                        decrypted,
                        path_len_byte,
                    )
            elif pkt_type == PAYLOAD_TYPE_RESPONSE:
                # Plain RESPONSE (0x01). Firmware parity with
                # BaseChatMesh::onPeerDataRecv's RESPONSE branch: a flood-routed
                # reply from a peer we already hold a direct out_path for means
                # the peer has no usable route back to us, so re-teach it. This
                # is the path a DIRECT (user-forced) login takes — the server
                # answers it with a flood RESPONSE, not the flood PATH that
                # carries the reciprocal above, so nothing else teaches it.
                await self.return_path_teacher.maybe_teach_from_flood_reply(
                    pkt,
                    contact_pubkey,
                    src_hash,
                    reason="flood RESPONSE",
                    shared_secret=shared_secret,
                )

            success, text, parsed = self._parse_protocol_response(response_data)
            return success, text, parsed, decrypted, contact_pubkey, response_payload

        # Log once per packet: no contact or HMAC failed for every matching contact
        if not contacts_tried:
            self._log(
                f"[ProtocolResponse] No contact for hash 0x{src_hash:02X}, "
                "cannot decrypt PATH/RESPONSE"
            )
        else:
            self._log(
                f"[ProtocolResponse] HMAC failed for hash 0x{src_hash:02X} "
                f"(tried {len(contacts_tried)} contact(s). Repeater PATH uses same ECDH as login)"
            )
        return False, "Decryption failed: Invalid HMAC", {}, None, None, None

    def _parse_protocol_response(self, data: bytes) -> tuple[bool, str, Dict[str, Any]]:
        """Parse decrypted protocol response data.

        Parse order:
        0. Login response (13 bytes, response_code at [4] 0x00/0x01) → binary,
          for LoginResponseHandler.
        1. Telemetry (reflected_timestamp + valid CayenneLPP signature byte check)
        2. Stats (RepeaterStats struct, ≥52 bytes, only when not telemetry)
        3. Text / status (UTF-8 printable after stripping tag + nulls)
        4. Binary fallback

        Telemetry is checked first because CayenneLPP data can be ≥56 bytes for
        sensors with many readings, which would otherwise be misidentified as stats.
        The telemetry signature check (channel=1, type=0x74) is cheap and reliable.
        """
        try:
            # 0. Login responses are 13 bytes (tag(4) + response_code(1) + keep_alive(1) + ...).
            #    Do not parse as telemetry/stats; LoginResponseHandler will handle them.
            if len(data) == 13 and data[4] in (0x00, 0x01):
                return (
                    True,
                    "Binary response: " + data.hex(),
                    {"type": "binary", "hex": data.hex()},
                )

            # 1. Check if this looks like a telemetry response (protocol 0x03).
            #    MeshCore always starts telemetry with addVoltage(TELEM_CHANNEL_SELF=1, ...)
            #    which produces LPP channel=0x01, type=0x74 (LPP_VOLTAGE) as first record.
            #    This signature reliably distinguishes telemetry from stats/text responses.
            if len(data) >= 8:  # tag(4) + at least one LPP record (ch+type+val = 3+)
                telemetry_result = self._parse_telemetry_response(data)
                if telemetry_result and telemetry_result.get("sensor_count", 0) > 0:
                    return True, telemetry_result["formatted"], telemetry_result

            # 2. Check if this looks like a stats response (protocol 0x01).
            #    RepeaterStats is 48-56 bytes + 4-byte tag.  Older firmware
            #    omits n_recv_errors (52 B struct → 56 total); PATH-wrapped
            #    responses may also lose trailing bytes to AES block alignment.
            #    Only reached if telemetry signature check above failed.
            if len(data) >= 56:
                stats_result = self._parse_stats_response(data)
                if stats_result:
                    # Include raw_bytes in the parsed dict so callers can
                    # forward the binary RepeaterStats to companion apps.
                    result_dict = stats_result["raw"]
                    result_dict["type"] = "stats"
                    result_dict["raw_bytes"] = stats_result["raw_bytes"]
                    self._log(
                        f"[ProtocolResponse] STATS: batt={result_dict['batt_milli_volts']}mV, "
                        f"rssi={result_dict['last_rssi']}, snr={result_dict['last_snr']}, "
                        f"raw={len(result_dict['raw_bytes'])}B"
                    )
                    return True, stats_result["formatted"], result_dict

            # 3. Try parsing as text/status response.
            #    Status responses are tag(4) + UTF-8 text.  Strip the 4-byte
            #    tag that prefixes every response, then check for printable text.
            if len(data) > 4:
                try:
                    text_candidate = data[4:].rstrip(b"\x00").decode("utf-8")
                    if text_candidate.strip() and text_candidate.strip().isprintable():
                        return (
                            True,
                            text_candidate.strip(),
                            {"type": "text", "content": text_candidate.strip()},
                        )
                except UnicodeDecodeError:
                    pass

            # 4. Fall back to hex representation
            hex_response = data.hex()
            return (
                True,
                f"Binary response: {hex_response}",
                {"type": "binary", "hex": hex_response},
            )

        except Exception as e:
            return False, f"Parse error: {e}", {}

    def _parse_stats_response(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse RepeaterStats struct response (protocol 0x01).

        RepeaterStats layout (from simple_repeater/MyMesh.h):
          uint16_t batt_milli_volts;        // offset 0
          uint16_t curr_tx_queue_len;       // offset 2
          int16_t  noise_floor;             // offset 4
          int16_t  last_rssi;               // offset 6
          uint32_t n_packets_recv;          // offset 8
          uint32_t n_packets_sent;          // offset 12
          uint32_t total_air_time_secs;     // offset 16
          uint32_t total_up_time_secs;      // offset 20
          uint32_t n_sent_flood;            // offset 24
          uint32_t n_sent_direct;           // offset 28
          uint32_t n_recv_flood;            // offset 32
          uint32_t n_recv_direct;           // offset 36
          uint16_t err_events;              // offset 40
          int16_t  last_snr;  // ×4         // offset 42
          uint16_t n_direct_dups;           // offset 44
          uint16_t n_flood_dups;            // offset 46
          uint32_t total_rx_air_time_secs;  // offset 48
          uint32_t n_recv_errors;           // offset 52
        Total: 56 bytes
        """
        try:
            # Skip 4-byte reflected timestamp/tag
            # memcpy(&reply_data[4], &stats, sizeof(stats))
            if len(data) < 56:  # 4 tag + 52 struct minimum (without n_recv_errors)
                return None

            stats_data = data[4:]  # Skip the 4-byte tag

            # Pad to 56 bytes so struct.unpack always succeeds.  Older firmware
            # or PATH-wrapped responses with AES block alignment may yield fewer
            # than 56 bytes; missing trailing fields default to zero.
            if len(stats_data) < 56:
                stats_data = stats_data + b"\x00" * (56 - len(stats_data))

            # Parse with correct field types matching C++ struct
            (
                batt_milli_volts,  # uint16  offset 0
                curr_tx_queue_len,  # uint16  offset 2
                noise_floor,  # int16   offset 4
                last_rssi,  # int16   offset 6
                n_packets_recv,  # uint32  offset 8
                n_packets_sent,  # uint32  offset 12
                total_air_time_secs,  # uint32  offset 16
                total_up_time_secs,  # uint32  offset 20
                n_sent_flood,  # uint32  offset 24
                n_sent_direct,  # uint32  offset 28
                n_recv_flood,  # uint32  offset 32
                n_recv_direct,  # uint32  offset 36
                err_events,  # uint16  offset 40
                last_snr_raw,  # int16   offset 42
                n_direct_dups,  # uint16  offset 44
                n_flood_dups,  # uint16  offset 46
                total_rx_air_time_secs,  # uint32  offset 48
                n_recv_errors,  # uint32  offset 52
            ) = struct.unpack("<HHhhIIIIIIIIHhHHII", stats_data[:56])

            # Sanity-check key fields to avoid misidentifying non-stats data
            # (e.g. neighbor list binary data parsed as RepeaterStats produces
            # batt=22mV, rssi=-27844, which are obviously invalid).
            if batt_milli_volts > 20000:  # > 20V is unreasonable
                return None
            if last_rssi < -200 or last_rssi > 0:  # RSSI always negative, > -200 dBm
                return None

            raw_stats = {
                "batt_milli_volts": batt_milli_volts,
                "curr_tx_queue_len": curr_tx_queue_len,
                "noise_floor": noise_floor,
                "last_rssi": last_rssi,
                "n_packets_recv": n_packets_recv,
                "n_packets_sent": n_packets_sent,
                "total_air_time_secs": total_air_time_secs,
                "total_up_time_secs": total_up_time_secs,
                "n_sent_flood": n_sent_flood,
                "n_sent_direct": n_sent_direct,
                "n_recv_flood": n_recv_flood,
                "n_recv_direct": n_recv_direct,
                "err_events": err_events,
                "last_snr": last_snr_raw / 4.0,  # firmware stores SNR × 4
                "n_direct_dups": n_direct_dups,
                "n_flood_dups": n_flood_dups,
                "total_rx_air_time_secs": total_rx_air_time_secs,
                "n_recv_errors": n_recv_errors,
            }

            # Format as human-readable string
            formatted = self._format_stats(raw_stats)

            # Include raw bytes after the 4-byte tag so callers can forward
            # the binary RepeaterStats struct to companion apps verbatim.
            # Pad to 56 bytes if shorter (companion app expects full struct).
            raw_bytes_after_tag = bytes(stats_data[:56])

            return {
                "raw": raw_stats,
                "formatted": formatted,
                "type": "stats",
                "raw_bytes": raw_bytes_after_tag,
            }

        except Exception as e:
            self._log(f"[ProtocolResponse] Stats parsing failed: {e}")
            return None

    def _parse_telemetry_response(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse telemetry response data (protocol 0x03) according to MeshCore packet structure.

        Expected format:
        - reflected_timestamp (4 bytes, little-endian)
        - CayenneLPP data (remaining bytes)

        Returns None if no valid CayenneLPP sensors can be decoded, allowing
        the caller to fall back to other response types.
        """
        try:
            if len(data) < 8:
                # Need at least tag(4) + one minimal LPP record (ch+type+val = 3)
                return None

            # First 4 bytes: reflected timestamp / tag (little-endian)
            reflected_timestamp = struct.unpack("<I", data[:4])[0]

            # Remaining bytes: CayenneLPP data
            lpp_data = data[4:]

            if len(lpp_data) < 3:
                # Not enough for even one LPP record (channel + type + 1-byte value)
                return None

            # Sanity check: MeshCore telemetry always starts with
            # addVoltage(TELEM_CHANNEL_SELF=1, battery_volts) which produces
            # channel=1, type=0x74 (LPP_VOLTAGE).  Require this signature to
            # distinguish telemetry from other response types that happen to
            # decrypt to >= 8 bytes.
            if lpp_data[0] != 0x01 or lpp_data[1] != 0x74:
                return None

            sensors = _decode_cayenne_lpp(lpp_data)
            if not sensors:
                return None

            self._log(
                f"[ProtocolResponse] CayenneLPP decoded {len(sensors)} sensor(s) "
                f"from {len(lpp_data)} bytes: {lpp_data.hex()}"
            )
            return {
                "type": "telemetry",
                "formatted": (f"Telemetry ({len(sensors)} sensors, " f"ts:{reflected_timestamp})"),
                "reflected_timestamp": reflected_timestamp,
                "sensor_count": len(sensors),
                "sensors": sensors,
                "raw_bytes": bytes(data[4:]),  # LPP data after tag for verbatim forwarding
            }

        except Exception as e:
            self._log(f"[ProtocolResponse] Telemetry parsing failed: {e}")
            return None

    def _format_stats(self, stats: Dict[str, Any]) -> str:
        """Format stats as human-readable string."""
        result = []

        # Battery voltage
        volts = stats["batt_milli_volts"] / 1000.0
        result.append(f"Batt: {volts:.2f}V")

        # TX Queue
        result.append(f"TxQ: {stats['curr_tx_queue_len']}")

        # Signal quality
        result.append(f"RSSI: {stats['last_rssi']}dBm")
        result.append(f"SNR: {stats['last_snr']:.1f}dB")
        result.append(f"NF: {stats['noise_floor']}dB")

        # Packet counts
        result.append(
            f"TX: {stats['n_packets_sent']} "
            f"(F:{stats['n_sent_flood']}/D:{stats['n_sent_direct']})"
        )
        result.append(
            f"RX: {stats['n_packets_recv']} "
            f"(F:{stats['n_recv_flood']}/D:{stats['n_recv_direct']})"
        )

        # Uptime formatting
        uptime = stats["total_up_time_secs"]
        if uptime < 3600:
            result.append(f"Up: {uptime}s")
        elif uptime < 86400:
            hours = uptime // 3600
            mins = (uptime % 3600) // 60
            result.append(f"Up: {hours}h{mins}m")
        else:
            days = uptime // 86400
            hours = (uptime % 86400) // 3600
            result.append(f"Up: {days}d{hours}h")

        # Air time
        result.append(f"TxAir: {stats['total_air_time_secs']}s")
        if stats.get("total_rx_air_time_secs"):
            result.append(f"RxAir: {stats['total_rx_air_time_secs']}s")

        # Error events (only if > 0)
        if stats["err_events"] > 0:
            result.append(f"Err: {stats['err_events']}")

        # RX errors (only if > 0)
        if stats.get("n_recv_errors", 0) > 0:
            result.append(f"RxErr: {stats['n_recv_errors']}")

        # Duplicates (only if > 0)
        if stats["n_direct_dups"] > 0 or stats["n_flood_dups"] > 0:
            result.append(f"Dups: D:{stats['n_direct_dups']}/F:{stats['n_flood_dups']}")

        return " | ".join(result)

    def _find_contact_by_hash(self, contact_hash: int):
        """Find first contact by hash value."""
        for contact in self._contacts_by_hash(contact_hash):
            return contact
        return None

    def _contacts_by_hash(self, contact_hash: int):
        """Yield all contacts whose public_key first byte matches contact_hash."""
        if not self._contact_book:
            return
        for contact in self._contact_book.list_contacts():
            try:
                contact_pubkey = bytes.fromhex(contact.public_key)
                if contact_pubkey[0] == contact_hash:
                    yield contact
            except (ValueError, IndexError):
                continue
