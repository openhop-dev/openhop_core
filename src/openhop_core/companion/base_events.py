"""Mesh-event RX handling and dedup of CompanionBase."""

from __future__ import annotations

import asyncio
import logging
import struct
import time
from typing import Optional

from ..node.events import MeshEvents
from ..protocol import Packet, PacketBuilder
from ..protocol.constants import (
    MAX_TEXT_LEN,
    ROUTE_TYPE_FLOOD,
    ROUTE_TYPE_TRANSPORT_FLOOD,
    TXT_TYPE_CLI_COMMAND,
    TXT_TYPE_CLI_DATA,
)
from ..protocol.crypto import CryptoUtils
from ..protocol.utils import derive_channel_hash, normalize_channel_secret
from .constants import CLI_REPLY_DELAY_MS
from .models import (
    Channel,
    ChannelDataEvent,
    ChannelMessageEvent,
    Contact,
    MessageEvent,
    QueuedMessage,
)

logger = logging.getLogger("CompanionBase")


class _RxEventsMixin:
    """Part of :class:`CompanionBase` (see companion_base.py)."""

    # -------------------------------------------------------------------------
    # Event Handling (shared)
    # -------------------------------------------------------------------------

    async def _handle_mesh_event(self, event_type: str, data: dict) -> None:
        try:
            if event_type == MeshEvents.NEW_MESSAGE:
                await self._handle_new_message(data)
            elif event_type == MeshEvents.NEW_CHANNEL_MESSAGE:
                await self._handle_new_channel_message(data)
            elif event_type == MeshEvents.NEW_CONTACT:
                await self._fire_callbacks("node_discovered", data)
            elif event_type == MeshEvents.CONTACT_UPDATED:
                pass
            elif event_type == MeshEvents.NODE_DISCOVERED:
                async with self._node_discovered_lock:
                    await self._handle_node_discovered(data)
            elif event_type == MeshEvents.TELEMETRY_UPDATED:
                await self._fire_callbacks("telemetry_response", data)
        except Exception as e:
            logger.error("Error handling mesh event %s: %s", event_type, e)

    async def _handle_node_discovered(self, data: dict) -> None:
        """Apply one advert to the stores and fire its callbacks.

        Callers hold ``_node_discovered_lock`` so the whole transition, callbacks
        included, completes before the next advert touches the contact store.
        The lock is not reentrant: a callback may schedule further advert
        handling but must not await it, or this companion's advert pipeline
        deadlocks.
        """
        # Advert pipeline (single path): all adverts applied here; one event
        # -> one store update and at most one advert_received (Bridge and Radio).
        now = int(time.time())
        contact = Contact.from_dict(data, now=now)
        if contact.public_key == self.get_public_key():
            # Backstop: the ADVERT handler already drops a self advert the way
            # Mesh::onRecvPacket does (Mesh.cpp:263).  This event is a public
            # seam, and a node must never contact-book or path-cache itself
            # however the event was produced.
            return
        # Wire advert flags (ADVERT_FLAG_IS_CHAT_NODE=0x01, etc.) must not
        # be stored as local contact flags (bit 0 = favourite).  For new
        # contacts the flags start at 0; for existing contacts
        # _apply_advert_to_stores restores the persisted value (line 708).
        contact.flags = 0
        raw_blob = data.get("raw_advert_packet")
        if isinstance(raw_blob, (bytes, bytearray)) and len(raw_blob) > 0:
            contact.last_advert_packet = bytes(raw_blob)
        if len(contact.public_key) < 7 or not contact.name:
            return
        # Replay protection (BaseChatMesh::onAdvertRecv): for a contact we
        # already know, ignore any advert whose timestamp is not strictly
        # newer than the stored one. This prevents a delayed or replayed
        # advert from overwriting newer name/location/type/app data (and
        # from downgrading the cached path). Matches the firmware's early
        # return, so no store update and no client notification fire.
        existing = self.contacts.get_by_key(contact.public_key)
        if existing is not None and contact.last_advert_timestamp <= existing.last_advert_timestamp:
            return
        inbound_path = data.get("inbound_path")
        path_len_encoded = data.get("path_len_encoded")
        applied = await self._apply_advert_to_stores(
            contact, inbound_path, path_len_encoded=path_len_encoded
        )
        if applied is not None:
            # Stored (existing or newly auto-added): persist + app contact update.
            await self._fire_callbacks("advert_received", applied)
        # Firmware parity (BaseChatMesh::onAdvertRecv -> onDiscoveredContact):
        # notify the client for *every* valid advert (stored or not). The frame
        # layer decides full NEW_ADVERT vs short ADVERT by whether the contact
        # ended up in the store.
        disc_contact = applied if applied is not None else contact
        await self._fire_callbacks("node_discovered", disc_contact)

    async def _handle_new_message(self, data: dict) -> None:
        # Deduplicate by packet hash so reconnects don't queue the same packet multiple times.
        pkt_hash = data.get("packet_hash")
        if pkt_hash and self._seen_txt.check_and_add(pkt_hash):
            return

        sender_key_hex = data.get("contact_pubkey", "")
        sender_key = bytes.fromhex(sender_key_hex) if sender_key_hex else b""
        # Handler publishes "message_text"; accept "text" for compatibility
        message_text = (data.get("message_text") or data.get("text") or "").rstrip("\x00")

        # A CLI command from a contact the app has allowed to use the remote CLI
        # runs here and is answered, not queued (BaseChatMesh::onPeerDataRecv ->
        # MyMesh::onCLICommandRecv). Anyone else's is queued as txt_type 3.
        if data.get("txt_type") == TXT_TYPE_CLI_COMMAND:
            contact = self.contacts.get_by_key(sender_key) if sender_key else None
            if contact is not None and contact.is_remote_cli_allowed:
                if self._remote_cli_closed:
                    return  # stopped: run nothing, transmit nothing
                sender_timestamp = int(data.get("timestamp") or 0)
                reply = self.run_cli_command(message_text, sender_timestamp)
                if reply:
                    task = self._spawn_background_task(
                        self._send_remote_cli_reply(sender_key, reply, sender_timestamp),
                        "remote CLI reply",
                    )
                    self._remote_cli_replies.add(task)
                    task.add_done_callback(self._remote_cli_replies.discard)
                return
        # Extract SNR/RSSI from network info if available (same as channel path)
        network_info = data.get("network_info", {})
        snr = network_info.get("snr")
        rssi = network_info.get("rssi")
        # 4-byte author pubkey prefix (TXT_TYPE_SIGNED_PLAIN room server posts)
        sender_prefix_hex = data.get("sender_prefix", "") or ""
        try:
            sender_prefix = bytes.fromhex(sender_prefix_hex)
        except ValueError:
            sender_prefix = b""
        # MeshCore queueMessage() writes the packet's encoded path length for
        # floods and 0xFF for direct routes.  TextMessageHandler supplies that
        # byte; retain the old zero default for third-party event producers
        # that have not supplied route metadata.
        path_len = data.get("path_len", 0)
        msg = QueuedMessage(
            sender_key=sender_key,
            txt_type=data.get("txt_type", data.get("flags", 0)),
            timestamp=data.get("timestamp", int(time.time())),
            text=message_text,
            is_channel=False,
            path_len=path_len,
            snr=snr if snr is not None else 0.0,
            rssi=rssi if rssi is not None else 0,
            sender_prefix=sender_prefix,
        )
        was_queued = self.message_queue.push(msg)
        await self._fire_callbacks(
            "message_event",
            MessageEvent(
                sender_key=sender_key,
                text=message_text,
                timestamp=msg.timestamp,
                txt_type=msg.txt_type,
                packet_hash=pkt_hash,
                snr=snr if snr is not None else 0.0,
                rssi=rssi if rssi is not None else 0,
                sender_prefix=sender_prefix,
                path_len=path_len,
                queued=was_queued,
                queue_entry=msg if was_queued else None,
            ),
        )

    async def _send_remote_cli_reply(
        self, sender_key: bytes, reply: str, sender_timestamp: int
    ) -> None:
        """Answer a remote CLI command the way firmware does: a CLI_DATA text
        with attempt 0 and no ACK, after CLI_REPLY_DELAY_MS, direct on the
        contact's path when known and flooded in this companion's scope
        otherwise (``send_text_message`` picks the route)."""
        await asyncio.sleep(CLI_REPLY_DELAY_MS / 1000.0)
        timestamp = PacketBuilder._get_timestamp()
        if timestamp == sender_timestamp:
            # Firmware: the two timestamps must differ in the app's CLI view.
            # The unique clock is strictly increasing, so asking again gives the
            # next second and keeps it from being handed out twice.
            timestamp = PacketBuilder._get_timestamp()
        text = reply.encode("utf-8")[:MAX_TEXT_LEN].decode("utf-8", errors="ignore")
        await self.send_text_message(
            sender_key,
            text,
            txt_type=TXT_TYPE_CLI_DATA,
            attempt=0,
            wait_for_ack=False,
            timestamp=timestamp,
        )

    def _cancel_remote_cli_replies(self) -> None:
        """Drop remote CLI replies still waiting out their delay, so a stopped
        companion transmits nothing further."""
        self._remote_cli_closed = True
        for task in list(self._remote_cli_replies):
            task.cancel()
        self._remote_cli_replies.clear()

    async def _handle_new_channel_message(self, data: dict) -> None:
        # Do not push our own (outgoing) channel messages to the client as incoming.
        if data.get("is_outgoing"):
            return

        # Deduplicate by packet hash so we queue one frame per logical message, matching
        # firmware: Mesh.cpp only calls onChannelMessageRecv when !_tables->hasSeen(pkt).
        pkt_hash = data.get("packet_hash")
        if pkt_hash and self._seen_grp_txt.check_and_add(pkt_hash):
            return

        path_len = data.get("path_len", 0)
        channel_name = data.get("channel_name", "")
        # Resolve channel index so sync_next_message returns correct channel_idx in the frame
        channel_idx = 0
        if getattr(self, "channels", None) and hasattr(self.channels, "find_by_name"):
            idx = self.channels.find_by_name(channel_name)
            if idx is not None:
                channel_idx = idx
        # MeshCore client expects "SenderName: Message" format in text field; it parses to show
        # sender and message separately. Use full_content (not message_text) so client can split.
        # Strip trailing nulls so frame matches firmware (exact string length, no padding).
        display_text = (data.get("full_content", data.get("message_text", "")) or "").rstrip("\x00")
        # Extract SNR/RSSI from network info if available
        network_info = data.get("network_info", {})
        snr = network_info.get("snr")
        rssi = network_info.get("rssi")

        msg = QueuedMessage(
            sender_key=b"",
            txt_type=0,
            timestamp=data.get("timestamp", int(time.time())),
            text=display_text,
            is_channel=True,
            channel_idx=channel_idx,
            path_len=path_len,
            snr=snr if snr is not None else 0.0,
            rssi=rssi if rssi is not None else 0,
        )
        was_queued = self.message_queue.push(msg)

        await self._fire_callbacks(
            "channel_message_event",
            ChannelMessageEvent(
                channel_name=data.get("channel_name", ""),
                sender_name=data.get("sender_name", ""),
                text=display_text,
                timestamp=msg.timestamp,
                path_len=path_len,
                channel_idx=channel_idx,
                packet_hash=pkt_hash,
                snr=snr,
                rssi=rssi,
                queued=was_queued,
                queue_entry=msg if was_queued else None,
            ),
        )

    def _get_channel_candidates_by_hash(self, channel_hash: int) -> list[tuple[int, Channel]]:
        """Return channel candidates that match the 1-byte channel hash."""
        matches: list[tuple[int, Channel]] = []
        max_channels = getattr(self.channels, "max_channels", 40)
        for idx in range(max_channels):
            channel = self.channels.get(idx)
            if channel is None:
                continue
            if derive_channel_hash(channel.secret) == channel_hash:
                matches.append((idx, channel))
        return matches

    async def _handle_group_data_packet(self, packet: Packet) -> None:
        """Parse and queue incoming PAYLOAD_TYPE_GRP_DATA for sync_next_message."""
        payload = packet.get_payload()
        if len(payload) < 4:
            return
        packet_hash = packet.calculate_packet_hash().hex().upper()

        channel_hash = payload[0]
        cipher_mac = payload[1:3]
        ciphertext = payload[3:]
        selected_idx: Optional[int] = None
        plaintext: Optional[bytes] = None

        for idx, channel in self._get_channel_candidates_by_hash(channel_hash):
            secret = normalize_channel_secret(channel.secret)
            try:
                plaintext = CryptoUtils.mac_then_decrypt(
                    secret[:16], secret, cipher_mac + ciphertext
                )
            except Exception:
                plaintext = None
            if plaintext is not None:
                selected_idx = idx
                break

        if selected_idx is None or plaintext is None or len(plaintext) < 3:
            return
        data_type = struct.unpack_from("<H", plaintext, 0)[0]
        data_len = plaintext[2]
        if data_type == 0 or len(plaintext) < 3 + data_len:
            return
        blob = bytes(plaintext[3 : 3 + data_len])

        # Cache only validated group data. Outbound packets are recorded
        # before injection, so a locally looped-back packet stops here.
        if self._check_and_track_group_packet(packet):
            return

        route_type = packet.get_route_type()
        path_len = (
            packet.path_len
            if route_type in (ROUTE_TYPE_FLOOD, ROUTE_TYPE_TRANSPORT_FLOOD)
            else 0xFF
        )
        snr = packet.get_snr() if hasattr(packet, "get_snr") else getattr(packet, "_snr", 0.0)
        rssi = packet.rssi if hasattr(packet, "rssi") else getattr(packet, "_rssi", 0)
        queued_message = QueuedMessage(
            sender_key=b"",
            txt_type=0,
            timestamp=0,
            text="",
            is_channel=True,
            channel_idx=selected_idx,
            path_len=path_len,
            snr=snr if snr is not None else 0.0,
            rssi=rssi if rssi is not None else 0,
            channel_data_type=data_type,
            channel_data_payload=blob,
        )
        was_queued = self.message_queue.push(queued_message)
        await self._fire_callbacks(
            "channel_data_event",
            ChannelDataEvent(
                channel_idx=selected_idx,
                path_len=path_len,
                data_type=data_type,
                payload=blob,
                packet_hash=packet_hash,
                snr=snr,
                rssi=rssi,
                queued=was_queued,
                queue_entry=queued_message if was_queued else None,
            ),
        )
