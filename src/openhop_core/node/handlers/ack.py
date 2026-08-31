from __future__ import annotations

from typing import Optional

from ...protocol import Packet
from ...protocol.constants import PAYLOAD_TYPE_ACK
from ...protocol.packet_utils import PathUtils
from ...util.callbacks import AckReceivedCallback, invoke_maybe_awaitable
from .base import BaseHandler
from .crypto_helpers import iter_decrypt_by_src_hash


class AckHandler(BaseHandler):
    """
    ACK handler that processes all ACK variants:
    1. Discrete ACK packets (payload type 1)
    2. Bundled ACKs in PATH packets
    3. Encrypted ACK responses carried by PATH packets
    """

    @staticmethod
    def payload_type() -> int:
        return PAYLOAD_TYPE_ACK

    def __init__(self, log_fn, dispatcher=None):
        self.log = log_fn
        self.dispatcher = dispatcher
        self._ack_received_callback: Optional[AckReceivedCallback] = None

    def set_ack_received_callback(self, callback: Optional[AckReceivedCallback]):
        """Set the ACK-received callback (the dispatcher's _register_ack_received).

        See :data:`AckReceivedCallback`: it returns whether the CRC matched one of this node's
        own pending sends (truthy = consumed -> do-not-retransmit; False/None = not mine).
        """
        self._ack_received_callback = callback

    def set_dispatcher(self, dispatcher):
        """Set dispatcher reference for contact lookup and waiting ACKs."""
        self.dispatcher = dispatcher

    async def __call__(self, packet: Packet) -> None:
        """Handle discrete ACK packets (payload type 1)."""
        ack_crc = await self.process_discrete_ack(packet)
        if ack_crc is not None:
            # Firmware BaseChatMesh::onAckRecv marks the packet do-not-retransmit
            # when the ACK matches a message this node sent (processAck != NULL),
            # so a client repeater does not re-flood an ACK addressed to itself.
            # Two places can be awaiting it: dispatcher-level waiters
            # (_waiting_acks) and an application listener (a companion tracks
            # expected ACK CRCs app-side). Mark for a dispatcher waiter BEFORE
            # notifying — the notify callback resolves and pops that waiter, and
            # marking first also keeps the packet marked when a listener raises
            # (the pre-existing guarantee). A listener-consumed ACK can only be
            # marked after the listener reports it.
            if self.dispatcher is not None and ack_crc in self.dispatcher._waiting_acks:
                packet.mark_do_not_retransmit()
            consumed = await self._notify_ack_received(ack_crc)
            if consumed:
                packet.mark_do_not_retransmit()

    async def process_discrete_ack(self, packet: Packet) -> Optional[int]:
        """Process a discrete ACK packet and return the CRC if valid."""
        self.log(f"Processing discrete ACK: payload_len={len(packet.payload)}")
        self.log(f"ACK payload (hex): {packet.payload.hex().upper()}")

        if len(packet.payload) < 4:
            self.log(f"Invalid ACK length: {len(packet.payload)} bytes (expected >= 4)")
            return None

        # Extract CRC checksum from the first 4 bytes (little endian per protocol spec).
        # Firmware emits 6-byte ACKs for plain DMs (4-byte hash + ext-attempt + random byte);
        # only the first 4 bytes are matched against the expected ACK.
        crc = int.from_bytes(packet.payload[:4], "little")
        self.log(f"Discrete ACK received: CRC={crc:08X}")
        return crc

    async def process_path_ack_variants(self, packet: Packet) -> Optional[int]:
        """
        Process PATH packets that may contain ACKs in different forms.
        Returns CRC if ACK found, None otherwise.
        """
        if not self.dispatcher:
            return None

        payload = packet.payload
        if len(payload) < 1:
            return None

        self.log(f"Processing PATH packet for ACKs: payload_len={len(payload)}")
        self.log(f"PATH payload (hex): {payload.hex().upper()}")

        # PATH returns are encrypted as dest_hash + src_hash + MAC + ciphertext.
        # Their outer length varies with the returned path, so do not restrict this
        # to the 20-byte (single AES-block) form.
        #
        # Deliberately NOT gated on dispatcher._waiting_acks: firmware
        # Mesh::onRecvPacket processes every PATH addressed to this node
        # unconditionally (Mesh.cpp PAYLOAD_TYPE_PATH case: decrypt, then
        # onPeerPathRecv with extra_type/extra). A companion never populates
        # _waiting_acks — it tracks expected ACK CRCs app-side and relies on the
        # ack-received listener — so gating here made the delivery confirmation
        # for a flood text message (whose ACK rides the PATH return) invisible
        # to companion clients.
        if (
            self.dispatcher.local_identity
            and self.dispatcher.contact_book
            and len(payload) >= 2
            and payload[0] == self.dispatcher.local_identity.get_public_key()[0]
        ):
            self.log("Checking encrypted PATH packet for ACK response")
            ack_crc = await self._try_decrypt_encrypted_ack(payload)
            if ack_crc is not None:
                self.log(f"Found encrypted ACK response: CRC={ack_crc:08X}")
                return ack_crc

        return None

    async def _try_decrypt_encrypted_ack(self, payload: bytes) -> Optional[int]:
        """Decrypt an addressed PATH return and extract its ACK extra, if any.

        A PATH source hash is only one byte, so it identifies a candidate set rather
        than a unique contact.  A valid MAC identifies the actual sender.  After a
        successful decrypt, decode the inner PATH layout instead of searching its
        path or non-ACK extra bytes for a value that happens to match a pending CRC.
        """
        if len(payload) < 2:
            return None

        src_hash = payload[1]
        encrypted = bytes(payload[2:])
        contacts = getattr(self.dispatcher.contact_book, "contacts", ())

        for _contact, _pubkey, _secret, decrypted in iter_decrypt_by_src_hash(
            contacts, src_hash, self.dispatcher.local_identity, encrypted
        ):
            # MeshCore treats a successfully authenticated PATH as belonging to
            # that matched contact.  Reject a malformed inner PATH rather than
            # interpreting arbitrary bytes as an ACK.
            if not decrypted or not PathUtils.is_valid_path_len(decrypted[0]):
                self.log("Encrypted PATH ACK has an invalid path length")
                return None

            path_byte_len = PathUtils.get_path_byte_len(decrypted[0])
            extra_start = 1 + path_byte_len
            if len(decrypted) < extra_start + 1:
                self.log("Encrypted PATH ACK is truncated before its extra type")
                return None

            extra_type = decrypted[extra_start] & 0x0F
            if extra_type != PAYLOAD_TYPE_ACK:
                return None

            if len(decrypted) < extra_start + 5:
                self.log("Encrypted PATH ACK extra is shorter than its CRC")
                return None

            # Return the CRC of any authenticated embedded ACK. Matching it
            # against a waiter is the notify path's job: dispatcher-level
            # waiters resolve through _waiting_acks, and a companion matches it
            # against its app-side expected-ACK table (firmware processAck
            # ignores CRCs it does not know, so an unknown CRC is harmless).
            return int.from_bytes(decrypted[extra_start + 1 : extra_start + 5], "little")

        return None

    async def _notify_ack_received(self, crc: int) -> Optional[bool]:
        """Notify the registered ACK callback; return its result (truthy when the ACK was
        consumed/matched app-side, so the caller marks the packet do-not-retransmit)."""
        if self._ack_received_callback:
            return await invoke_maybe_awaitable(self._ack_received_callback, crc)
        return None
