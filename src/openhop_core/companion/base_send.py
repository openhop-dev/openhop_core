"""Unified TX/send operations of CompanionBase (Radio and Bridge)."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import random
import struct
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional

from ..protocol import Packet, PacketBuilder
from ..protocol.constants import (
    ADVERT_FLAG_HAS_LOCATION,
    ADVERT_FLAG_HAS_NAME,
    MAX_PACKET_PAYLOAD,
    MAX_PATH_SIZE,
    PAYLOAD_TYPE_ADVERT,
    PAYLOAD_TYPE_CONTROL,
    PAYLOAD_TYPE_GRP_DATA,
    PH_ROUTE_MASK,
    PUB_KEY_SIZE,
    REQ_TYPE_GET_STATUS,
    REQ_TYPE_GET_TELEMETRY_DATA,
    ROUTE_TYPE_DIRECT,
    TELEM_PERM_BASE,
)
from ..protocol.packet_utils import PathUtils
from .base_support import ResponseWaiter, _fmt_path, _fmt_path_len, adv_type_to_flags
from .constants import (
    ADV_TYPE_NONE,
    ADVERT_LOC_SHARE,
    DEFAULT_RESPONSE_TIMEOUT_MS,
    MAX_GROUP_DATA_LENGTH,
    MAX_PENDING_ACK_CRCS,
    PROTOCOL_CODE_ANON_REQ,
    PROTOCOL_CODE_BINARY_REQ,
    PROTOCOL_CODE_RAW_DATA,
    PUSH_CODE_TELEMETRY_RESPONSE,
    TXT_TYPE_CLI_COMMAND,
    TXT_TYPE_CLI_DATA,
    TXT_TYPE_PLAIN,
)
from .models import Contact, QueuedMessage, SentResult
from .timing import (
    DEFAULT_MAX_ATTEMPTS,
    calc_direct_timeout_ms_for_hops,
    estimate_airtime_ms,
    response_timeout_ms,
)

logger = logging.getLogger("CompanionBase")

# Frame-server clients own login retry timing from the timeout in RESP_CODE_SENT.
# Keep one authenticated-response waiter alive across those retries so a slow
# flood reply can still complete login. This is deliberately longer than one
# adaptive send timeout; observed multi-hop replies can take over a minute.
FRAME_LOGIN_PENDING_TTL_S = 120.0


@dataclass
class _PendingFrameLogin:
    """One logical frame-server login session, reused across client retries."""

    target_key: bytes
    dest_hash: int
    contact_name: str
    event: asyncio.Event
    result: dict
    callback: Callable[[bool, dict], None]
    expires_at: float
    task: Optional[asyncio.Task] = None


class _SendOpsMixin:
    """Part of :class:`CompanionBase` (see companion_base.py)."""

    # -------------------------------------------------------------------------
    # Unified TX methods (shared between Radio and Bridge)
    # -------------------------------------------------------------------------

    async def advertise(self, flood: bool = True) -> bool:
        """Broadcast an advertisement packet."""
        flags = adv_type_to_flags(self.prefs.adv_type)
        flags |= ADVERT_FLAG_HAS_NAME
        lat, lon = 0.0, 0.0
        if self.prefs.advert_loc_policy == ADVERT_LOC_SHARE:
            # The location-sharing policy decides inclusion, not the coordinate
            # value: (0.0, 0.0) is a valid position and must be advertised when
            # sharing is enabled (matches MeshCore CommonCLI::buildAdvertData,
            # which serializes the coordinate for any non-NONE policy).
            lat, lon = self.prefs.latitude, self.prefs.longitude
            flags |= ADVERT_FLAG_HAS_LOCATION
        route = "flood" if flood else "direct"
        pkt = PacketBuilder.create_advert(
            local_identity=self._identity,
            name=self.prefs.node_name,
            lat=lat,
            lon=lon,
            flags=flags,
            route_type=route,
        )
        # Firmware CMD_SEND_SELF_ADVERT always scopes flood adverts with the
        # persisted default scope, never the transient send_scope override.
        self._apply_default_flood_scope(pkt)
        self._apply_path_hash_mode(pkt)
        success = await self._send_packet(pkt, wait_for_ack=False)
        if success:
            self.stats.record_tx(is_flood=flood)
        else:
            self.stats.record_tx_error()
        return success

    async def share_contact(self, pub_key: bytes) -> bool:
        """Share a contact's advert on zero hops (direct route, empty path).

        Matches firmware ``BaseChatMesh::shareContactZeroHop``: replay the last stored
        raw ADVERT wire bytes for this contact (see ``Contact.last_advert_packet``),
        with ``Mesh::sendZeroHop``-style header/path normalization. Does not re-sign with
        the companion identity. If no blob is stored (never heard an advert for this
        contact), returns ``False``.
        """
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return False
        blob = contact.last_advert_packet
        if not blob:
            return False
        try:
            pkt = Packet()
            if not pkt.read_from(bytes(blob)):
                return False
            if pkt.get_payload_type() != PAYLOAD_TYPE_ADVERT:
                return False
            if len(pkt.payload) >= PUB_KEY_SIZE:
                embedded = bytes(pkt.payload[:PUB_KEY_SIZE])
                if embedded != pub_key:
                    logger.warning(
                        "Cached advert pubkey does not match contact key; refusing share"
                    )
                    return False
            # Mesh::sendZeroHop (non-transport): direct route, path_len=0, empty path
            pkt.header = (pkt.header & ~PH_ROUTE_MASK) | ROUTE_TYPE_DIRECT
            pkt.transport_codes = [0, 0]
            pkt.path_len = 0
            pkt.path = bytearray()
            return await self._send_packet(pkt, wait_for_ack=False)
        except Exception as e:
            logger.error("Error sharing contact: %s", e)
            return False

    async def send_trace_path_raw(
        self,
        tag: int,
        auth_code: int,
        flags: int,
        path_bytes: bytes,
    ) -> SentResult:
        """Send a trace packet with an explicit path.

        Returns a :class:`SentResult` whose ``timeout_ms`` is the firmware
        est_timeout hint for the RESP_CODE_SENT frame. Firmware
        (MyMesh.cpp:1764-1765) sizes it from the packet's airtime and route:
        ``t = getEstAirtimeFor(payload_len + path_len + 2)`` fed through
        ``calcDirectTimeoutMillisFor(t, path_len >> path_sz)`` — i.e. the direct
        per-hop formula with a hop count of ``path_len // hash_width``. Here the
        whole trace (tag/auth/flags + path) lives in the payload, so
        ``pkt.get_raw_length()`` already equals firmware's
        ``payload_len + path_len + 2``.
        """
        try:
            path_list = list(path_bytes)
            pkt = PacketBuilder.create_trace(tag, auth_code, flags, path=path_list)
            self._apply_flood_scope(pkt)
            self._apply_path_hash_mode(pkt)
            success = await self._send_packet(pkt, wait_for_ack=False)
            if not success:
                return SentResult(success=False, error="send_failed")
            hash_width = PathUtils.trace_payload_hash_width(flags)
            hop_count = len(path_bytes) // hash_width if hash_width else 0
            airtime_ms = estimate_airtime_ms(
                pkt.get_raw_length(),
                int(getattr(self.prefs, "spreading_factor", 10)),
                int(getattr(self.prefs, "bandwidth_hz", 250000)),
                int(getattr(self.prefs, "coding_rate", 5)),
            )
            est_timeout_ms = calc_direct_timeout_ms_for_hops(airtime_ms, hop_count)
            # Firmware sends the trace via sendDirect and reports the SENT frame
            # with the flood byte cleared (MyMesh.cpp:1768).
            return SentResult(
                success=True,
                is_flood=False,
                expected_ack=tag,
                timeout_ms=est_timeout_ms,
            )
        except Exception as e:
            logger.error("Error sending trace (raw path): %s", e)
            return SentResult(success=False, error="send_failed")

    async def send_binary_req(
        self, pub_key: bytes, data: bytes, timeout_seconds: float = 15.0
    ) -> SentResult:
        """Send binary request (CMD_SEND_BINARY_REQ).

        data = request_type(1) + optional payload.
        Returns SentResult with expected_ack (4-byte tag as int) and timeout_ms.
        """
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return SentResult(success=False, error="not_found")
        # Resolve by exact public key, not name: two contacts can share a name
        # (e.g. a re-keyed node) and get_by_name returns the first match, which
        # would encrypt/route to the wrong key.
        proxy = self.contacts.get_proxy_by_key(pub_key)
        if not proxy:
            return SentResult(success=False, error="not_found")
        request_type = data[0] if len(data) >= 1 else 0
        # C++ companion pattern (BaseChatMesh::sendRequest):
        #   tag = getRTCClock()->getCurrentTimeUnique()
        #   memcpy(temp, &tag, 4);  memcpy(&temp[4], req_data, data_len);
        # create_protocol_request packs: timestamp(4) + protocol_code(1) + extra_data.
        # The repeater echoes sender_timestamp (bytes 0-3) in the response.
        # So the timestamp IS the tag — we capture it from create_protocol_request.
        protocol_code = request_type
        req_payload = data[1:]  # request params only; timestamp provides uniqueness
        self.cleanup_expired_binary_requests()
        try:
            pkt, timestamp = PacketBuilder.create_protocol_request(
                contact=proxy,
                local_identity=self._identity,
                protocol_code=protocol_code,
                data=req_payload,
            )
            # Use the timestamp as the tag — matches what the repeater echoes back
            tag_int = timestamp
            tag_bytes = tag_int.to_bytes(4, "little")
            tag_hex = tag_bytes.hex()
            self.register_binary_request(
                tag_hex,
                request_type=request_type,
                timeout_seconds=timeout_seconds,
                pubkey_prefix=pub_key[:6].hex(),
            )
            self._apply_flood_scope(pkt)
            self._apply_path_hash_mode(pkt)
            success = await self._send_packet(pkt, wait_for_ack=False)
        except Exception as e:
            logger.error("Binary request send error: %s", e)
            if "tag_hex" in locals():
                self._pending_binary_requests.pop(tag_hex, None)
            return SentResult(success=False, error="send_failed")
        if not success:
            self._pending_binary_requests.pop(tag_hex, None)
            return SentResult(success=False, error="send_failed")
        return SentResult(
            # Only OUT_PATH_UNKNOWN (-1) floods; out_path_len == 0 is a known
            # zero-hop direct route, matching the builder's route selection and
            # MeshCore sendRequest.
            success=True,
            is_flood=contact.out_path_len < 0,
            expected_ack=tag_int,
            timeout_ms=DEFAULT_RESPONSE_TIMEOUT_MS,
        )

    async def send_anon_req(
        self, pub_key: bytes, data: bytes, timeout_seconds: float = 15.0
    ) -> SentResult:
        """Send anonymous request (CMD_SEND_ANON_REQ), e.g. owner info.

        data = request payload (e.g. [0x07] for GET_OWNER_INFO). Response is
        delivered via on_binary_response (PUSH_CODE_BINARY_RESPONSE) like binary req.
        """
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            # FIRMWARE_VER_CODE 13+ (PR #2672): allow non-contact anon requests by
            # creating a transient zero-hop contact. Mirrors firmware sendAnonReq:
            # out_path_len=0 => direct zero-hop, type=ADV_TYPE_NONE (unknown).
            contact = Contact(
                public_key=pub_key,
                name="",
                adv_type=ADV_TYPE_NONE,
                out_path_len=0,
                out_path=b"",
                lastmod=int(time.time()),
            )
            if not self.contacts.add_transient(contact):
                return SentResult(success=False)
        # Resolve the proxy by key (anon contacts have an empty name, which
        # get_by_name would mis-match against any other empty-named contact).
        proxy = self.contacts.get_proxy_by_key(pub_key)
        if not proxy:
            return SentResult(success=False)
        request_type = PROTOCOL_CODE_ANON_REQ
        req_payload = data  # no random tag; timestamp provides uniqueness
        # The first byte is the ANON_REQ_TYPE_* sub-type (e.g. REGIONS/OWNER);
        # record it so the response can be parsed by sub-type rather than being
        # mistaken for a binary REQ_TYPE_GET_OWNER_INFO (both use code 0x07).
        anon_sub_type = req_payload[0] if len(req_payload) >= 1 else None
        self.cleanup_expired_binary_requests()
        try:
            pkt, timestamp = PacketBuilder.create_anon_request(
                contact=proxy,
                local_identity=self._identity,
                req_data=req_payload,
            )
            # Use the timestamp as the tag — matches what the repeater echoes back
            tag_int = timestamp
            tag_bytes = tag_int.to_bytes(4, "little")
            tag_hex = tag_bytes.hex()
            self._apply_flood_scope(pkt)
            self._apply_path_hash_mode(pkt)
            # Adaptive timeout (firmware calcFlood/DirectTimeoutMillisFor). This is
            # fire-and-forget: the response arrives async via the binary-response
            # push, and the client retries on this timeout hint — the same model
            # firmware uses for anon/discovery (it returns est_timeout and the host
            # app re-issues). A short adaptive hint => fast client-driven retry.
            timeout_s = self._response_timeout_s(pkt, proxy)
            self.register_binary_request(
                tag_hex,
                request_type=request_type,
                timeout_seconds=max(timeout_seconds, timeout_s * DEFAULT_MAX_ATTEMPTS),
                pubkey_prefix=pub_key[:6].hex(),
                context={"anon_sub_type": anon_sub_type},
            )
            success = await self._send_packet(pkt, wait_for_ack=False)
        except Exception as e:
            logger.error("Anon request send error: %s", e)
            if "tag_hex" in locals():
                self._pending_binary_requests.pop(tag_hex, None)
            return SentResult(success=False)
        if not success:
            self._pending_binary_requests.pop(tag_hex, None)
            return SentResult(success=False)
        return SentResult(
            success=True,
            # Direct (incl. zero-hop, out_path_len == 0) when the path is known;
            # flood only when the out_path is unknown (-1). Mirrors create_anon_request.
            is_flood=contact.out_path_len < 0,
            expected_ack=tag_int,
            timeout_ms=int(timeout_s * 1000),
        )

    async def send_path_discovery(self, pub_key: bytes) -> bool:
        """Legacy: send path discovery without returning tag. Prefer send_path_discovery_req."""
        result = await self.send_path_discovery_req(pub_key)
        return result.success

    async def send_path_discovery_req(self, pub_key: bytes) -> SentResult:
        """Send path discovery (flood telemetry request with tag).

        Returns SentResult for RESP_CODE_SENT. When path return arrives with
        matching tag, path_discovery_response is fired (PUSH 0x8D).
        """
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return SentResult(success=False, error="not_found")
        # Resolve by exact public key, not name: two contacts can share a name
        # (e.g. a re-keyed node) and get_by_name returns the first match, which
        # would encrypt/route to the wrong key.
        proxy = self.contacts.get_proxy_by_key(pub_key)
        if not proxy:
            return SentResult(success=False, error="not_found")
        inv_perm = 0xFF & ~TELEM_PERM_BASE
        req_data = bytes([REQ_TYPE_GET_TELEMETRY_DATA, inv_perm, 0, 0, 0]) + random.getrandbits(
            32
        ).to_bytes(4, "little")
        try:
            pkt, tag_int = PacketBuilder.create_protocol_request(
                contact=proxy,
                local_identity=self._identity,
                protocol_code=req_data[0],
                data=req_data[1:],
                route_type="flood",
            )
            self._apply_flood_scope(pkt)
            self._apply_path_hash_mode(pkt)
            success = await self._send_packet(pkt, wait_for_ack=False)
            if success:
                self._pending_discovery_tags.add(tag_int)
            return SentResult(
                success=success,
                is_flood=True,
                expected_ack=tag_int,
                timeout_ms=DEFAULT_RESPONSE_TIMEOUT_MS,
                error=None if success else "send_failed",
            )
        except Exception as e:
            logger.error("Error in path discovery: %s", e)
            return SentResult(success=False, error="send_failed")

    async def send_text_message(
        self,
        pub_key: bytes,
        text: str,
        txt_type: int = TXT_TYPE_PLAIN,
        attempt: int = 1,
        wait_for_ack: bool = True,
        timestamp: Optional[int] = None,
    ) -> SentResult:
        """Send a direct text message to a contact.

        When wait_for_ack is True (default), blocks until ACK or timeout.
        When wait_for_ack is False, returns as soon as the packet is handed off;
        ACK (if any) is still tracked and will trigger send_confirmed later.
        For the CLI types (``TXT_TYPE_CLI_DATA`` and ``TXT_TYPE_CLI_COMMAND``),
        delivery ACK is not used on MeshCore repeaters; ``wait_for_ack`` is
        treated as False and pending ACK is not tracked. Firmware routes both to
        ``sendCommandData`` with ``expected_ack = 0`` (MyMesh.cpp
        CMD_SEND_TXT_MSG).
        """
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            logger.warning("Contact not found for key %s...", pub_key.hex()[:12])
            return SentResult(success=False)
        # Resolve by exact public key, not name: two contacts can share a name
        # (e.g. a re-keyed node) and get_by_name returns the first match, which
        # would encrypt/route to the wrong key.
        proxy = self.contacts.get_proxy_by_key(pub_key)
        if not proxy:
            return SentResult(success=False)
        try:
            is_flood = proxy.out_path_len < 0
            msg_type = "flood" if is_flood else "direct"
            pkt, ack_crc = PacketBuilder.create_text_message(
                contact=proxy,
                local_identity=self._identity,
                message=text,
                attempt=attempt,
                message_type=msg_type,
                txt_type=txt_type,
                timestamp=timestamp,
            )
            self._apply_flood_scope(pkt)
            self._apply_path_hash_mode(pkt)
            is_cli = txt_type in (TXT_TYPE_CLI_DATA, TXT_TYPE_CLI_COMMAND)
            effective_wait_ack = wait_for_ack and not is_cli
            if not is_cli:
                self._track_pending_ack(ack_crc)
            if effective_wait_ack:
                success = await self._send_packet(pkt, wait_for_ack=True, expected_crc=ack_crc)
                if success:
                    self.stats.record_tx(is_flood=is_flood)
                else:
                    self.stats.record_tx_error()
                return SentResult(
                    success=success,
                    is_flood=is_flood,
                    expected_ack=ack_crc,
                    timeout_ms=None,
                )
            success = await self._send_packet(pkt, wait_for_ack=False)
            if success:
                self.stats.record_tx(is_flood=is_flood)
            else:
                self.stats.record_tx_error()
            return SentResult(
                success=success,
                is_flood=is_flood,
                expected_ack=ack_crc,
                timeout_ms=DEFAULT_RESPONSE_TIMEOUT_MS,
            )
        except Exception as e:
            logger.error("Error sending text message: %s", e)
            self.stats.record_tx_error()
            return SentResult(success=False)

    async def send_channel_message(
        self, channel_idx: int, text: str, timestamp: Optional[int] = None
    ) -> bool:
        """Send a message to a channel."""
        channel = self.channels.get(channel_idx)
        if not channel:
            logger.warning("Channel %s not found", channel_idx)
            return False
        try:
            pkt = PacketBuilder.create_group_datagram(
                group_name=channel.name,
                local_identity=self._identity,
                message=text,
                sender_name=self.prefs.node_name,
                channels_config=self.channels.get_channels(),
                timestamp=timestamp,
            )
            self._apply_flood_scope(pkt)
            self._apply_path_hash_mode(pkt)
            # Record before awaiting the transport because Repeater can queue
            # a local transmission back through its companion bridges first.
            self._check_and_track_group_packet(pkt)
            success = await self._send_packet(pkt, wait_for_ack=False)
            if success:
                self.stats.record_tx(is_flood=True)
            else:
                self.stats.record_tx_error()
            return success
        except Exception as e:
            logger.error("Error sending channel message: %s", e)
            self.stats.record_tx_error()
            return False

    async def send_channel_data(
        self,
        channel_idx: int,
        data_type: int,
        payload: bytes,
        *,
        path: Optional[bytes] = None,
        path_len_encoded: Optional[int] = None,
    ) -> bool:
        """Send a group binary datagram (PAYLOAD_TYPE_GRP_DATA)."""
        channel = self.channels.get(channel_idx)
        if not channel or data_type <= 0 or data_type > 0xFFFF:
            return False
        payload = bytes(payload or b"")
        if len(payload) > MAX_GROUP_DATA_LENGTH:
            return False
        try:
            secret_bytes = bytes(channel.secret or b"")
            if len(secret_bytes) < 32:
                secret_bytes = secret_bytes + b"\x00" * (32 - len(secret_bytes))
            else:
                secret_bytes = secret_bytes[:32]

            hash_input = (
                secret_bytes[:16]
                if len(secret_bytes) >= 32 and secret_bytes[16:32] == b"\x00" * 16
                else secret_bytes
            )
            channel_hash = hashlib.sha256(hash_input).digest()[0]
            plaintext = struct.pack("<HB", data_type & 0xFFFF, len(payload)) + payload
            pkt = PacketBuilder.create_group_data_packet(
                PAYLOAD_TYPE_GRP_DATA,
                channel_hash,
                secret_bytes,
                plaintext,
                secret_bytes,
            )

            is_flood = path_len_encoded in (None, 0xFF)
            if is_flood:
                self._apply_flood_scope(pkt)
            else:
                pkt.header = (pkt.header & ~PH_ROUTE_MASK) | ROUTE_TYPE_DIRECT
                pkt.set_path(path or b"", path_len_encoded=path_len_encoded)
            self._apply_path_hash_mode(pkt)

            self._check_and_track_group_packet(pkt)
            success = await self._send_packet(pkt, wait_for_ack=False)
            if success:
                self.stats.record_tx(is_flood=is_flood)
            else:
                self.stats.record_tx_error()
            return success
        except Exception as e:
            logger.error("Error sending channel data: %s", e)
            self.stats.record_tx_error()
            return False

    async def send_raw_data(
        self,
        dest_key: bytes,
        data: bytes,
        path: Optional[bytes] = None,
    ) -> SentResult:
        """Send raw data to a contact via a protocol request."""
        contact = self.contacts.get_by_key(dest_key)
        if not contact:
            return SentResult(success=False)
        # Resolve the proxy by the exact public key, not by name: two contacts can
        # share a name (e.g. a node that re-keyed) and get_by_name returns the first
        # match, which would encrypt/route to the wrong key.
        proxy = self.contacts.get_proxy_by_key(dest_key)
        if not proxy:
            return SentResult(success=False)
        try:
            pkt, _ = PacketBuilder.create_protocol_request(
                contact=proxy,
                local_identity=self._identity,
                protocol_code=PROTOCOL_CODE_RAW_DATA,
                data=data,
            )
            self._apply_path_hash_mode(pkt)
            success = await self._send_packet(pkt, wait_for_ack=False)
            return SentResult(success=success)
        except Exception as e:
            logger.error("Error sending raw data: %s", e)
            return SentResult(success=False)

    async def send_raw_data_direct(
        self, path: bytes, payload: bytes, *, path_len_encoded: int = None
    ) -> SentResult:
        """Send a raw custom packet (PAYLOAD_TYPE_RAW_CUSTOM) on the given direct path.

        No encryption or contact lookup; path and payload are supplied by the caller.
        Matches firmware CMD_SEND_RAW_DATA behaviour.

        Args:
            path_len_encoded: Encoded path_len byte. If None, assumes 1-byte hashes.
        """
        if len(payload) < 4:
            return SentResult(success=False)
        if len(path) > MAX_PATH_SIZE:
            return SentResult(success=False)
        if len(payload) > MAX_PACKET_PAYLOAD:
            return SentResult(success=False)
        try:
            pkt = PacketBuilder.create_raw_data(payload)
            pkt.set_path(path, path_len_encoded)
            success = await self._send_packet(pkt, wait_for_ack=False)
            if success:
                self.stats.record_tx(is_flood=False)
            else:
                self.stats.record_tx_error()
            return SentResult(success=success)
        except Exception as e:
            logger.error("Error sending raw data direct: %s", e)
            return SentResult(success=False)

    async def send_raw_packet(self, priority: int, packet_bytes: bytes) -> bool:
        """Inject a fully-formed on-air packet for transmission (CMD_SEND_RAW_PACKET).

        Mirrors firmware ``MyMesh.cpp`` ``CMD_SEND_RAW_PACKET``: parse the raw
        on-air bytes into a :class:`Packet` (``tryParsePacket``) and enqueue it
        for TX (``sendPacket``).  ``packet_bytes`` is the complete wire packet
        (header, optional transport codes, path, payload) as produced by
        :meth:`Packet.write_to`; it is sent verbatim, with no encryption,
        contact lookup, flood-scope, or path-hash-mode rewriting.

        The ``priority`` argument is accepted for protocol compatibility but is
        currently ignored: the bridge's low-level send path
        (:meth:`_send_packet`) does not expose a prioritized TX queue.

        Returns True if the packet parsed and was handed off for transmission,
        False on parse failure or send error (the frame_server handler maps
        False to ``ERR_CODE_TABLE_FULL``).
        """
        try:
            pkt = Packet()
            if not pkt.read_from(bytes(packet_bytes)):
                return False
        except Exception as e:
            logger.warning("send_raw_packet: failed to parse packet: %s", e)
            return False
        try:
            success = await self._send_packet(pkt, wait_for_ack=False)
            if success:
                self.stats.record_tx(is_flood=False)
            else:
                self.stats.record_tx_error()
            return success
        except Exception as e:
            logger.error("Error sending raw packet: %s", e)
            self.stats.record_tx_error()
            return False

    async def send_trace_path(
        self,
        pub_key: bytes,
        tag: int,
        auth_code: int,
        flags: int = 0,
    ) -> bool:
        """Send a trace path request to a contact."""
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return False
        path = list(contact.out_path) if contact.out_path else []
        if not path:
            path = [contact.public_key[0]]
        try:
            pkt = PacketBuilder.create_trace(tag, auth_code, flags, path=path)
            self._apply_path_hash_mode(pkt)
            return await self._send_packet(pkt, wait_for_ack=False)
        except Exception as e:
            logger.error("Error sending trace: %s", e)
            return False

    async def send_control_data(self, data: Any = None) -> bool:
        """Send a CONTROL packet (e.g. discovery request).

        If *data* is provided it must be 1-MAX_PACKET_PAYLOAD bytes with the first
        byte having the 0x80 bit set (e.g. ``DISCOVER_REQ``).  Returns ``False``
        for invalid payloads.

        When called with no *data* (or ``None``), a default discovery request
        is sent for backward compatibility.
        """
        try:
            if data and len(data) <= MAX_PACKET_PAYLOAD and (data[0] & 0x80) != 0:
                pkt = Packet()
                pkt.header = PacketBuilder._create_header(PAYLOAD_TYPE_CONTROL, route_type="direct")
                pkt.path_len = 0
                pkt.path = bytearray()
                pkt.payload = bytearray(data)
                pkt.payload_len = len(data)
                self._apply_path_hash_mode(pkt)
                return await self._send_packet(pkt, wait_for_ack=False)
            elif data is not None:
                # data was provided but invalid
                return False
            # No data: send default discovery request
            tag = random.randint(0, 0xFFFFFFFF)
            pkt = PacketBuilder.create_discovery_request(tag, filter_mask=0x04)
            self._apply_path_hash_mode(pkt)
            return await self._send_packet(pkt, wait_for_ack=False)
        except Exception as e:
            logger.error("Error sending control data: %s", e)
            return False

    async def _finish_started_request(
        self,
        build_packet: Callable[[], tuple[Packet, Optional[int]]],
        wait_for_response: Callable[[float], Awaitable[dict]],
        proxy: Any,
        *,
        first_timeout_s: float,
        deadline: Optional[float],
        log_label: str,
        cleanup: Optional[Callable[[], None]],
        response_tag_registered: Optional[Callable[[int], None]],
    ) -> dict:
        """Finish a request after its first packet has already been sent."""
        try:
            result = await wait_for_response(first_timeout_s)
            if not result.get("timeout"):
                return result

            for attempt in range(1, DEFAULT_MAX_ATTEMPTS):
                # Every retry floods, whatever route the contact holds; the first
                # attempt already went out before this method was called.
                pkt, packet_tag = self._build_retry_packet(build_packet, proxy, log_label)
                if response_tag_registered is not None and packet_tag is not None:
                    response_tag_registered(packet_tag)
                self._apply_flood_scope(pkt)
                self._apply_path_hash_mode(pkt)
                timeout_s = self._response_timeout_s(pkt, proxy)
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    timeout_s = min(timeout_s, remaining)
                logger.debug(
                    "[PATHDIAG] %s: route=%s attempt=%d/%d timeout=%.1fs out_path_len=%s",
                    log_label,
                    "FLOOD" if pkt.is_route_flood() else "DIRECT",
                    attempt + 1,
                    DEFAULT_MAX_ATTEMPTS,
                    timeout_s,
                    _fmt_path_len(getattr(proxy, "out_path_len", -1)),
                )
                if not await self._send_packet(pkt, wait_for_ack=False):
                    return {"success": False, "error": "send_failed", "reason": "Send failed"}
                result = await wait_for_response(timeout_s)
                if not result.get("timeout"):
                    break
            return result
        except Exception as e:
            logger.error("%s request error: %s", log_label, e)
            return {"success": False, "reason": str(e)}
        finally:
            if cleanup is not None:
                cleanup()

    async def _start_request(
        self,
        build_packet: Callable[[], tuple[Packet, Optional[int]]],
        wait_for_response: Callable[[float], Awaitable[dict]],
        proxy: Any,
        *,
        total_timeout_s: Optional[float],
        log_label: str,
        sent_tag: Optional[int] = None,
        cleanup: Optional[Callable[[], None]] = None,
        response_tag_registered: Optional[Callable[[int], None]] = None,
    ) -> dict:
        """Send the first packet and return its metadata plus a waiter task."""
        deadline = time.monotonic() + total_timeout_s if total_timeout_s is not None else None
        try:
            pkt, packet_tag = build_packet()
            if response_tag_registered is not None and packet_tag is not None:
                response_tag_registered(packet_tag)
            self._apply_flood_scope(pkt)
            self._apply_path_hash_mode(pkt)
            estimated_timeout_s = self._response_timeout_s(pkt, proxy)
            wait_timeout_s = estimated_timeout_s
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining > 0:
                    wait_timeout_s = min(wait_timeout_s, remaining)

            logger.debug(
                "[PATHDIAG] %s: route=%s attempt=1/%d timeout=%.1fs out_path_len=%s",
                log_label,
                "FLOOD" if pkt.is_route_flood() else "DIRECT",
                DEFAULT_MAX_ATTEMPTS,
                wait_timeout_s,
                _fmt_path_len(getattr(proxy, "out_path_len", -1)),
            )
            if not await self._send_packet(pkt, wait_for_ack=False):
                if cleanup is not None:
                    cleanup()
                return {"success": False, "error": "send_failed", "reason": "Send failed"}

            tag = sent_tag if sent_tag is not None else packet_tag
            task = self._spawn_background_task(
                self._finish_started_request(
                    build_packet,
                    wait_for_response,
                    proxy,
                    first_timeout_s=wait_timeout_s,
                    deadline=deadline,
                    log_label=log_label,
                    cleanup=cleanup,
                    response_tag_registered=response_tag_registered,
                ),
                f"{log_label} response",
            )
            return {
                "success": True,
                "sent": SentResult(
                    success=True,
                    is_flood=pkt.is_route_flood(),
                    expected_ack=tag,
                    timeout_ms=int(estimated_timeout_s * 1000),
                ),
                "task": task,
            }
        except Exception as e:
            if cleanup is not None:
                cleanup()
            logger.error("%s send error: %s", log_label, e)
            return {"success": False, "error": "send_failed", "reason": str(e)}

    async def _start_login_request(self, pub_key: bytes, password: str) -> dict:
        """Start a login request and return SENT metadata plus its result task."""
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return {"success": False, "error": "not_found", "reason": "Contact not found"}
        # Resolve by exact public key, not name: two contacts can share a name
        # (e.g. a re-keyed node) and get_by_name returns the first match, which
        # would encrypt/route to the wrong key.
        proxy = self.contacts.get_proxy_by_key(pub_key)
        if not proxy:
            return {"success": False, "error": "not_found", "reason": "Contact not found"}
        login_handler = self._get_login_response_handler()
        if not login_handler:
            return {
                "success": False,
                "error": "bad_state",
                "reason": "Login handler not available",
            }
        dest_hash = proxy.dest_hash
        login_handler.store_login_password(dest_hash, password)
        login_result: dict = {"success": False, "data": {}}
        login_event = asyncio.Event()

        def _login_cb(success: bool, data: dict) -> None:
            login_result["success"] = success
            login_result["data"] = data
            login_event.set()

        login_target_key = proxy.public_key_bytes
        login_handler.register_login_callback(login_target_key, _login_cb)

        async def _wait_login(timeout_s: float) -> dict:
            try:
                await asyncio.wait_for(login_event.wait(), timeout=timeout_s)
                return {"timeout": False}
            except asyncio.TimeoutError:
                return {"timeout": True}

        def _build_login_packet() -> tuple[Packet, Optional[int]]:
            return (
                PacketBuilder.create_login_packet(
                    contact=proxy, local_identity=self._identity, password=password
                ),
                None,
            )

        login_sent_tag = int.from_bytes(proxy.public_key_bytes[:4], "little")

        def _cleanup_login() -> None:
            login_handler.remove_login_callback(login_target_key, _login_cb)
            login_handler.clear_login_password(dest_hash)

        # MeshCore exposes the first four public-key bytes as the login SENT
        # tag, rather than the timestamp inside the login packet.
        login_log_label = f"login -> 0x{dest_hash:02X} ({contact.name})"
        started = await self._start_request(
            _build_login_packet,
            _wait_login,
            proxy,
            total_timeout_s=None,
            log_label=login_log_label,
            sent_tag=login_sent_tag,
            cleanup=_cleanup_login,
        )
        if not started.get("success"):
            return started

        raw_task = started["task"]

        async def _format_login_result() -> dict:
            await raw_task
            if not login_event.is_set():
                return {
                    "success": False,
                    "timeout": True,
                    "reason": "Login response timeout",
                }
            return self._build_login_result(
                pub_key,
                contact.name,
                login_result["success"],
                login_result["data"],
            )

        started["task"] = self._spawn_background_task(
            _format_login_result(), "login result formatting"
        )
        return started

    def _build_login_result(
        self,
        pub_key: bytes,
        contact_name: str,
        success: bool,
        data: dict,
    ) -> dict:
        """Build the common login result returned by API and frame-server paths."""
        if success:
            self.note_login_connection(pub_key, data.get("keep_alive_interval", 0))
        return {
            "success": success,
            "repeater": contact_name,
            "is_admin": data.get("is_admin", False),
            # Raw login-reply byte 6. Firmware's companion forwards it verbatim
            # (0/1/2), so a room server's "plain guest" 2 survives to the app.
            "admin_code": data.get("admin_code"),
            "keep_alive_interval": data.get("keep_alive_interval", 0),
            "tag": data.get("timestamp", 0),
            "acl_permissions": data.get("reserved", data.get("permissions", 0)),
            "firmware_ver_level": data.get("firmware_ver_level"),
            "reason": "Login successful" if success else "Login failed",
        }

    async def _start_frame_login_request(self, pub_key: bytes, password: str) -> dict:
        """Send one frame-server login attempt and reuse its pending response session.

        MeshCore companion clients own retries: each command gets one transmission
        and one per-send timeout hint. Repeated commands for the same full public
        key refresh this logical session instead of replacing its callback, so a
        late authenticated reply completes whichever retry is currently pending.

        The public :meth:`send_login` API intentionally keeps its existing
        three-attempt behaviour; this method is the frame-server compatibility
        boundary.
        """
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return {"success": False, "error": "not_found", "reason": "Contact not found"}
        proxy = self.contacts.get_proxy_by_key(pub_key)
        if not proxy:
            return {"success": False, "error": "not_found", "reason": "Contact not found"}
        login_handler = self._get_login_response_handler()
        if not login_handler:
            return {
                "success": False,
                "error": "bad_state",
                "reason": "Login handler not available",
            }

        target_key = proxy.public_key_bytes
        sessions = self._pending_frame_logins
        session = sessions.get(target_key)
        if session is not None and (
            session.event.is_set() or (session.task is not None and session.task.done())
        ):
            sessions.pop(target_key, None)
            login_handler.remove_login_callback(target_key, session.callback)
            session = None

        session_owner = session is None
        if session is None:
            event = asyncio.Event()
            result: dict = {"success": False, "data": {}}
            session_ref: Optional[_PendingFrameLogin] = None

            def _login_cb(success: bool, data: dict) -> None:
                current = session_ref
                if current is None or current.event.is_set():
                    return
                current.result["success"] = success
                current.result["data"] = data
                current.event.set()

            session = _PendingFrameLogin(
                target_key=target_key,
                dest_hash=proxy.dest_hash,
                contact_name=contact.name,
                event=event,
                result=result,
                callback=_login_cb,
                expires_at=time.monotonic() + FRAME_LOGIN_PENDING_TTL_S,
            )
            session_ref = session
            sessions[target_key] = session
            login_handler.register_login_callback(target_key, session.callback)

        login_handler.store_login_password(proxy.dest_hash, password)
        pkt = PacketBuilder.create_login_packet(
            contact=proxy, local_identity=self._identity, password=password
        )
        self._apply_flood_scope(pkt)
        self._apply_path_hash_mode(pkt)
        timeout_s = self._response_timeout_s(pkt, proxy)
        logger.debug(
            "[PATHDIAG] frame login -> 0x%02X (%s): route=%s attempt=1/1 "
            "timeout=%.1fs out_path_len=%s",
            proxy.dest_hash,
            contact.name,
            "FLOOD" if pkt.is_route_flood() else "DIRECT",
            timeout_s,
            _fmt_path_len(getattr(proxy, "out_path_len", -1)),
        )
        if not await self._send_packet(pkt, wait_for_ack=False):
            if session_owner and sessions.get(target_key) is session:
                sessions.pop(target_key, None)
                login_handler.remove_login_callback(target_key, session.callback)
                login_handler.clear_login_password(proxy.dest_hash)
            return {"success": False, "error": "send_failed", "reason": "Send failed"}

        session.expires_at = time.monotonic() + FRAME_LOGIN_PENDING_TTL_S

        if session.task is None:

            async def _wait_for_frame_login() -> dict:
                try:
                    while not session.event.is_set():
                        remaining = session.expires_at - time.monotonic()
                        if remaining <= 0:
                            return {
                                "success": False,
                                "timeout": True,
                                "reason": "Login response timeout",
                            }
                        try:
                            await asyncio.wait_for(session.event.wait(), timeout=remaining)
                        except asyncio.TimeoutError:
                            # A repeated command may have refreshed expires_at while
                            # this wait used the previous deadline.
                            continue
                    return self._build_login_result(
                        target_key,
                        session.contact_name,
                        session.result["success"],
                        session.result["data"],
                    )
                finally:
                    if sessions.get(target_key) is session:
                        sessions.pop(target_key, None)
                        login_handler.remove_login_callback(target_key, session.callback)
                        login_handler.clear_login_password(session.dest_hash)

            session.task = self._spawn_background_task(
                _wait_for_frame_login(), "frame login response"
            )

        return {
            "success": True,
            "sent": SentResult(
                success=True,
                is_flood=pkt.is_route_flood(),
                expected_ack=int.from_bytes(target_key[:4], "little"),
                timeout_ms=int(timeout_s * 1000),
            ),
            "task": session.task,
            "session_owner": session_owner,
        }

    def _clear_pending_frame_logins(self) -> None:
        """Cancel frame-login sessions and detach their response callbacks."""
        sessions = tuple(self._pending_frame_logins.values())
        self._pending_frame_logins.clear()
        login_handler = self._get_login_response_handler()
        for session in sessions:
            if login_handler is not None:
                login_handler.remove_login_callback(session.target_key, session.callback)
                login_handler.clear_login_password(session.dest_hash)
            if session.task is not None and not session.task.done():
                session.task.cancel()

    async def send_login(self, pub_key: bytes, password: str) -> dict:
        """Send a login request to a repeater and wait for the response."""
        started = await self._start_login_request(pub_key, password)
        if not started.get("success"):
            return {"success": False, "reason": started.get("reason", "Login failed")}
        return await started["task"]

    async def send_logout(self, pub_key: bytes) -> bool:
        """Send a logout / disconnect to a repeater contact."""
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return False
        try:
            pkt, _ = PacketBuilder.create_logout_packet(
                contact=contact, local_identity=self._identity
            )
            self._apply_path_hash_mode(pkt)
            await self._send_packet(pkt, wait_for_ack=False)
            return True
        except Exception as e:
            logger.error("Logout error: %s", e)
            return False

    # -------------------------------------------------------------------------
    # Login-session connection registry
    #
    # Mirrors firmware BaseChatMesh connections[] (src/helpers/BaseChatMesh.cpp).
    # A successful login response carrying a non-zero keep-alive interval opens a
    # connection (startConnection, BaseChatMesh.cpp:674-693); hasConnectionTo
    # (BaseChatMesh.cpp:707-712) reports it live until logout (stopConnection,
    # BaseChatMesh.cpp:695-705) or expiry. Firmware expires a slot 2.5x the
    # keep-alive interval after the last server activity (checkConnections,
    # BaseChatMesh.cpp:743-755), refreshing that deadline on every keep-alive ack
    # (checkConnectionsAck, :726-741). Core has no keep-alive traffic on this
    # path, so the window simply runs from login time — the closest faithful
    # equivalent without inventing keep-alive machinery.
    # -------------------------------------------------------------------------

    def note_login_connection(self, pub_key: bytes, keep_alive_interval: int) -> None:
        """Record a live login connection after a successful login response.

        ``keep_alive_interval`` is the raw keep-alive byte from the login
        response (login_response.py). Firmware onContactResponse
        (MyMesh.cpp:686-690) computes ``keep_alive_secs = data[5] * 16`` and only
        calls startConnection when that is > 0, so a zero interval records
        nothing.
        """
        keep_alive_secs = int(keep_alive_interval) * 16
        if keep_alive_secs <= 0:
            return
        # checkConnections (BaseChatMesh.cpp:749): expire_secs = keep_alive_secs * 5 / 2.
        self._login_connections[bytes(pub_key)] = time.monotonic() + keep_alive_secs * 2.5

    def has_login_connection(self, pub_key: bytes) -> bool:
        """Return whether a non-expired login connection exists for ``pub_key``.

        Mirrors hasConnectionTo (BaseChatMesh.cpp:707-712). Expired entries are
        pruned lazily on lookup, standing in for firmware's checkConnections
        sweep.
        """
        key = bytes(pub_key)
        expiry = self._login_connections.get(key)
        if expiry is None:
            return False
        if time.monotonic() >= expiry:
            del self._login_connections[key]
            return False
        return True

    def clear_login_connection(self, pub_key: bytes) -> None:
        """Drop any login connection for ``pub_key`` (mirrors stopConnection,
        BaseChatMesh.cpp:695-705)."""
        self._login_connections.pop(bytes(pub_key), None)

    def _response_timeout_s(self, pkt: Packet, proxy: Any) -> float:
        """Adaptive response timeout (seconds) for a request packet.

        Mirrors firmware calcFloodTimeoutMillisFor / calcDirectTimeoutMillisFor
        using the radio's SF/BW/CR and the packet's on-air length, so a lost
        round-trip is retried on a ~3s cadence instead of a fixed 10-15s wait.
        """
        try:
            out_path_len = getattr(proxy, "out_path_len", -1)
            ms = response_timeout_ms(
                raw_length=pkt.get_raw_length(),
                is_flood=pkt.is_route_flood(),
                out_path_len=out_path_len,
                sf=int(getattr(self.prefs, "spreading_factor", 10)),
                bw_hz=int(getattr(self.prefs, "bandwidth_hz", 250000)),
                cr=int(getattr(self.prefs, "coding_rate", 5)),
            )
            return ms / 1000.0
        except Exception:
            return 5.0  # safe fallback

    async def _request_with_retries(
        self,
        build_packet: Callable[[], tuple[Packet, Optional[int]]],
        wait_for_response: Callable[[float], Awaitable[dict]],
        proxy: Any,
        *,
        total_timeout_s: Optional[float] = None,
        log_label: str = "request",
        response_tag_registered: Optional[Callable[[int], None]] = None,
    ) -> dict:
        """Send a request up to DEFAULT_MAX_ATTEMPTS times until a response lands.

        A fresh packet is built per attempt (dodging repeater flood dedup) and
        each attempt waits one adaptive timeout (firmware cadence). A late reply
        that lands between attempts resolves the waiter immediately.

        ``total_timeout_s`` caps the cumulative wait across attempts: the final
        attempt's wait is clipped to the remaining budget and no new attempt
        starts once the budget is spent.

        Every attempt after the first floods, whatever route the contact holds;
        see :meth:`_build_retry_packet`.
        """
        result: dict = {"timeout": True}
        deadline = time.monotonic() + total_timeout_s if total_timeout_s else None
        for attempt in range(DEFAULT_MAX_ATTEMPTS):
            if attempt == 0:
                pkt, packet_tag = build_packet()
            else:
                pkt, packet_tag = self._build_retry_packet(build_packet, proxy, log_label)
            if response_tag_registered is not None and packet_tag is not None:
                response_tag_registered(packet_tag)
            self._apply_flood_scope(pkt)
            self._apply_path_hash_mode(pkt)
            timeout_s = self._response_timeout_s(pkt, proxy)
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                timeout_s = min(timeout_s, remaining)
            logger.debug(
                "[PATHDIAG] %s: route=%s attempt=%d/%d timeout=%.1fs out_path_len=%s",
                log_label,
                "FLOOD" if pkt.is_route_flood() else "DIRECT",
                attempt + 1,
                DEFAULT_MAX_ATTEMPTS,
                timeout_s,
                _fmt_path_len(getattr(proxy, "out_path_len", -1)),
            )
            await self._send_packet(pkt, wait_for_ack=False)
            result = await wait_for_response(timeout_s)
            if not result.get("timeout"):
                break
        return result

    def _build_retry_packet(
        self,
        build_packet: Callable[[], tuple[Packet, Optional[int]]],
        proxy: Any,
        log_label: str,
    ) -> tuple[Packet, Optional[int]]:
        """Build a retry attempt as a FLOOD request, whatever route the contact holds.

        A first attempt that timed out leaves the stored ``out_path`` suspect in
        both directions: either the request never reached the peer, or the peer
        answered DIRECT down a route back to us that no longer works. Flooding
        the retry addresses both — it reaches the peer without depending on the
        stored path, and a peer answers a *flood* REQ or ANON_REQ with a
        PATH-return (``simple_repeater`` ``onPeerDataRecv``/``onAnonDataRecv``,
        ``BaseChatMesh::onPeerDataRecv``), which is a real observed inbound path
        for the return-path teacher to teach from. The alternative — assuming the
        route is symmetric and teaching its reverse — is wrong whenever it is not,
        and a peer taught a wrong route answers into a void with no flood reply
        left to correct it.

        Mirrors how firmware forces a single request to flood
        (``companion_radio/MyMesh.cpp``)::

            auto save = recipient->out_path_len;  // temporarily force sendRequest() to flood
            recipient->out_path_len = OUT_PATH_UNKNOWN;
            int result = sendRequest(*recipient, req_data, sizeof(req_data), tag, est_timeout);
            recipient->out_path_len = save;

        The stored path is only masked, never cleared: a contact stays direct for
        every other caller, and a successful flood round-trip re-teaches the route
        rather than discarding it. ``build_packet`` is synchronous, so no other
        task can observe the mask, and it is restored on every exit path.

        The packet comes back un-scoped; the caller runs it through
        ``_apply_flood_scope`` like any other flood send. Masking ``out_path_len``
        is all firmware does too: ``sendRequest`` then takes its
        ``sendFloodScoped(recipient, pkt)`` branch, which resolves the region the
        same way as every other companion flood (send_unscoped, else the
        transient send_scope, else the persisted default). Marking the retry
        plain-flood instead would strand it at hop 0 on a mesh whose repeaters
        run ``flood.max.unscoped = 0`` — precisely the meshes that scope their
        traffic — so the recovery attempt would fail exactly where the first
        attempt already had.
        """
        saved = getattr(proxy, "out_path_len", None)
        if saved is None or saved < 0:
            return build_packet()  # already floods; nothing to force
        try:
            proxy.out_path_len = -1
        except Exception as e:  # not a settable proxy: fall back to its own route
            logger.debug("[PATHDIAG] %s: cannot force flood retry: %s", log_label, e)
            return build_packet()
        try:
            pkt, tag = build_packet()
        finally:
            proxy.out_path_len = saved
        if pkt is not None and pkt.is_route_flood():
            logger.debug("[PATHDIAG] %s: retry forced to FLOOD", log_label)
        return pkt, tag

    async def _wait_for_path_propagation(self, proxy: Any, request_type: str) -> None:
        """Log the pre-send path; no longer sleeps.

        Firmware sends the request immediately and relies on the peer already
        holding a route back to us. openHop teaches that route from the flood
        PATH a flood login returns, and — since a DIRECT (forced-path) login is
        answered with a plain flood RESPONSE instead — also from that RESPONSE;
        see :mod:`openhop_core.node.handlers.return_path`. The previous
        0.5s/hop sleep added up to ~1.5s+ of latency per request for multi-hop
        contacts with no reliability benefit and has been removed; the adaptive
        timeout + internal resend now handle a lost first attempt.
        """
        out_path_len = getattr(proxy, "out_path_len", -1)
        out_path = getattr(proxy, "out_path", b"") or b""
        logger.debug(
            "[PATHDIAG] %s pre-send: %s",
            request_type,
            _fmt_path(out_path_len, out_path),
        )

    async def _start_protocol_request(
        self,
        pub_key: bytes,
        protocol_code: int,
        data: bytes,
        *,
        timeout: float,
        log_label: str,
    ) -> dict:
        """Start a protocol request and return SENT metadata plus its result task."""
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return {"success": False, "error": "not_found", "reason": "Contact not found"}
        proxy = self.contacts.get_proxy_by_key(pub_key)
        if not proxy:
            return {"success": False, "error": "not_found", "reason": "Contact not found"}
        proto_handler = self._get_protocol_response_handler()
        if not proto_handler:
            return {
                "success": False,
                "error": "bad_state",
                "reason": "Protocol handler not available",
            }
        waiter = ResponseWaiter()
        request_tags: set[int] = set()

        def _register_response_tag(request_tag: int) -> None:
            request_tags.add(request_tag)
            proto_handler.set_response_callback(pub_key, request_tag, waiter.callback)

        def _clear_response_tags() -> None:
            for request_tag in request_tags:
                proto_handler.clear_response_callback(pub_key, request_tag)

        try:
            await self._wait_for_path_propagation(proxy, log_label)

            def _build_packet() -> tuple[Packet, Optional[int]]:
                return PacketBuilder.create_protocol_request(
                    contact=proxy,
                    local_identity=self._identity,
                    protocol_code=protocol_code,
                    data=data,
                )

            started = await self._start_request(
                _build_packet,
                waiter.wait,
                proxy,
                total_timeout_s=timeout,
                log_label=log_label,
                cleanup=_clear_response_tags,
                response_tag_registered=_register_response_tag,
            )
            if not started.get("success"):
                return started

            raw_task = started["task"]
            if protocol_code == REQ_TYPE_GET_STATUS:

                async def _format_status_result() -> dict:
                    result = await raw_task
                    return {
                        "success": result.get("success", False),
                        "repeater": contact.name,
                        "stats": result.get("parsed", {}),
                        "response_text": result.get("text"),
                        "reason": (
                            "Stats received" if result.get("success") else "Stats request failed"
                        ),
                    }

                started["task"] = self._spawn_background_task(
                    _format_status_result(), "stats response formatting"
                )
            else:

                async def _format_telemetry_result() -> dict:
                    result = await raw_task
                    telemetry_data = dict(result.get("parsed", {}))
                    raw_bytes = telemetry_data.get("raw_bytes", b"")
                    if raw_bytes and len(pub_key) >= 6:
                        telemetry_data["frame_bytes"] = (
                            bytes([PUSH_CODE_TELEMETRY_RESPONSE, 0]) + pub_key[:6] + raw_bytes
                        )
                    return {
                        "success": result.get("success", False),
                        "contact": contact.name,
                        "telemetry_data": telemetry_data,
                        "response_text": result.get("text"),
                        "reason": (
                            "Telemetry received" if result.get("success") else "Telemetry failed"
                        ),
                    }

                started["task"] = self._spawn_background_task(
                    _format_telemetry_result(), "telemetry response formatting"
                )
            return started
        except Exception as e:
            _clear_response_tags()
            logger.error("%s request error: %s", log_label, e)
            return {"success": False, "error": "bad_state", "reason": str(e)}

    async def _start_status_request(self, pub_key: bytes, timeout: float = 15.0) -> dict:
        return await self._start_protocol_request(
            pub_key,
            REQ_TYPE_GET_STATUS,
            b"",
            timeout=timeout,
            log_label="stats REQ",
        )

    async def send_status_request(self, pub_key: bytes, timeout: float = 15.0) -> dict:
        """Send a protocol request for repeater status/stats and wait for its response."""
        started = await self._start_status_request(pub_key, timeout=timeout)
        if not started.get("success"):
            return {"success": False, "reason": started.get("reason", "Stats request failed")}
        return await started["task"]

    async def _start_telemetry_request(
        self,
        pub_key: bytes,
        want_base: bool = True,
        want_location: bool = True,
        want_environment: bool = True,
        timeout: float = 10.0,
    ) -> dict:
        inv = PacketBuilder._compute_inverse_perm_mask(want_base, want_location, want_environment)
        return await self._start_protocol_request(
            pub_key,
            REQ_TYPE_GET_TELEMETRY_DATA,
            bytes([inv]),
            timeout=timeout,
            log_label="telemetry REQ",
        )

    async def send_telemetry_request(
        self,
        pub_key: bytes,
        want_base: bool = True,
        want_location: bool = True,
        want_environment: bool = True,
        timeout: float = 10.0,
    ) -> dict:
        """Send a telemetry request and wait for its response."""
        started = await self._start_telemetry_request(
            pub_key,
            want_base=want_base,
            want_location=want_location,
            want_environment=want_environment,
            timeout=timeout,
        )
        if not started.get("success"):
            return {"success": False, "reason": started.get("reason", "Telemetry failed")}
        return await started["task"]

    async def send_binary_request(self, pub_key: bytes, data: bytes) -> dict:
        """Legacy: send binary request and wait.

        Prefer ``send_binary_req`` + ``on_binary_response``.
        """
        return await self._send_protocol_request(pub_key, PROTOCOL_CODE_BINARY_REQ, data)

    async def send_anon_request(self, pub_key: bytes, data: bytes) -> dict:
        """Send an anonymous request to a contact and wait for the response."""
        return await self._send_protocol_request(pub_key, PROTOCOL_CODE_ANON_REQ, data)

    async def _send_protocol_request(self, pub_key: bytes, protocol_code: int, data: bytes) -> dict:
        """Build and send a protocol request, waiting for the response."""
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return {"success": False, "reason": "Contact not found"}
        # Resolve by exact public key, not name: two contacts can share a name
        # (e.g. a re-keyed node) and get_by_name returns the first match, which
        # would encrypt/route to the wrong key.
        proxy = self.contacts.get_proxy_by_key(pub_key)
        if not proxy:
            return {"success": False, "reason": "Contact not found"}
        proto_handler = self._get_protocol_response_handler()
        if not proto_handler:
            return {"success": False, "reason": "Protocol handler not available"}
        waiter = ResponseWaiter()
        request_tags: set[int] = set()

        def _register_response_tag(request_tag: int) -> None:
            request_tags.add(request_tag)
            proto_handler.set_response_callback(pub_key, request_tag, waiter.callback)

        try:
            result = await self._request_with_retries(
                lambda: PacketBuilder.create_protocol_request(
                    contact=proxy,
                    local_identity=self._identity,
                    protocol_code=protocol_code,
                    data=data,
                ),
                waiter.wait,
                proxy,
                log_label=f"protocol REQ 0x{protocol_code:02X}",
                response_tag_registered=_register_response_tag,
            )
            return {
                "success": result.get("success", False),
                "response": result.get("text"),
                "parsed_data": result.get("parsed", {}),
                "reason": "Success" if result.get("success") else "Failed",
            }
        except Exception as e:
            logger.error("Protocol request error: %s", e)
            return {"success": False, "reason": str(e)}
        finally:
            for request_tag in request_tags:
                proto_handler.clear_response_callback(pub_key, request_tag)

    async def send_repeater_command(
        self,
        pub_key: bytes,
        command: str,
        parameters: Optional[str] = None,
        txt_type: int = TXT_TYPE_CLI_DATA,
    ) -> dict:
        """Send a text-based command to a repeater and wait for the response.

        ``txt_type`` selects how the command is labelled on the wire.
        ``TXT_TYPE_CLI_DATA`` is the default because it is the only form every
        released firmware executes: before ``TXT_TYPE_CLI_COMMAND`` existed,
        CLI_DATA meant "a CLI command" and the receiver ran it. Newer firmware
        splits the two — a command is CLI_COMMAND, its reply is CLI_DATA — but
        still accepts CLI_DATA as a command (``simple_repeater``
        ``onPeerDataRecv`` takes PLAIN, CLI_DATA or CLI_COMMAND; the companion
        ``BaseChatMesh`` runs only CLI_COMMAND). Pass ``TXT_TYPE_CLI_COMMAND``
        to address a companion, which no longer executes CLI_DATA.

        Either way the reply comes back as CLI_DATA, which is what the pending
        command-response waiter matches on.
        """
        if txt_type not in (TXT_TYPE_CLI_DATA, TXT_TYPE_CLI_COMMAND):
            return {"success": False, "reason": f"Unsupported CLI txt_type {txt_type}"}
        contact = self.contacts.get_by_key(pub_key)
        if not contact:
            return {"success": False, "reason": "Contact not found"}
        # Resolve by exact public key, not name: two contacts can share a name
        # (e.g. a re-keyed node) and get_by_name returns the first match, which
        # would encrypt/route to the wrong key.
        proxy = self.contacts.get_proxy_by_key(pub_key)
        if not proxy:
            return {"success": False, "reason": "Contact not found"}
        text_handler = self._get_text_handler()
        if not text_handler:
            return {"success": False, "reason": "Text handler not available"}
        full_command = command
        if parameters:
            full_command += f" {parameters}"
        response_data: dict = {"text": None, "success": False}
        response_event = asyncio.Event()

        def _response_cb(message_text: str, sender_contact: Any) -> None:
            response_data["text"] = message_text
            response_data["success"] = True
            response_event.set()

        target_key = proxy.public_key_bytes
        text_handler.register_command_response(target_key, _response_cb)
        try:
            msg_type = "flood" if proxy.out_path_len < 0 else "direct"
            pkt, _ = PacketBuilder.create_text_message(
                contact=proxy,
                local_identity=self._identity,
                message=full_command,
                attempt=1,
                message_type=msg_type,
                txt_type=txt_type,
            )
            self._apply_flood_scope(pkt)
            self._apply_path_hash_mode(pkt)
            await self._send_packet(pkt, wait_for_ack=False)
            try:
                await asyncio.wait_for(response_event.wait(), timeout=15.0)
            except asyncio.TimeoutError:
                pass
            return {
                "success": response_data["success"],
                "repeater": contact.name,
                "command": command,
                "response": response_data["text"],
                "reason": ("Command successful" if response_data["success"] else "No response"),
            }
        except Exception as e:
            logger.error("Repeater command error: %s", e)
            return {"success": False, "reason": str(e)}
        finally:
            text_handler.unregister_command_response(target_key, _response_cb)

    def _track_pending_ack(self, ack_crc: int) -> None:
        """Record a pending expected ACK with its send time (send_confirmed).

        Bounded circular table (firmware expected_ack_table): when full, the
        oldest entry is evicted rather than dropping the newest, so a current
        send is never silently untracked in favour of a stale one.
        """
        # Re-inserting refreshes both position and send time for a resend.
        self._pending_ack_crcs.pop(ack_crc, None)
        self._pending_ack_crcs[ack_crc] = time.monotonic()
        while len(self._pending_ack_crcs) > MAX_PENDING_ACK_CRCS:
            self._pending_ack_crcs.popitem(last=False)  # evict oldest

    async def _try_confirm_send(self, crc: int) -> bool:
        """If CRC is pending, discard it and fire send_confirmed. Returns True if fired.

        Passes the round-trip time in milliseconds (now - send time), mirroring
        firmware processAck (trip_time = getMillis() - expected_ack_table[i].msg_sent).
        """
        sent_at = self._pending_ack_crcs.pop(crc, None)
        if sent_at is None:
            return False
        trip_ms = max(0, int(round((time.monotonic() - sent_at) * 1000)))
        await self._fire_callbacks("send_confirmed", crc, trip_ms)
        return True

    def sync_next_message(self) -> Optional[QueuedMessage]:
        """Pop and return the next queued message, or None."""
        return self.message_queue.pop()
