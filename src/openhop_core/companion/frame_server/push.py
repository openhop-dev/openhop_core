"""Push frames (radio -> app, unsolicited): bridge event subscriptions and
the public push_* methods called directly by the host application."""

import asyncio
import logging
import struct
import time

from ...protocol.packet_utils import PathUtils
from ..constants import (
    OUT_PATH_UNKNOWN,
    PUB_KEY_SIZE,
    PUSH_CODE_BINARY_RESPONSE,
    PUSH_CODE_CONTACT_DELETED,
    PUSH_CODE_CONTACTS_FULL,
    PUSH_CODE_CONTROL_DATA,
    PUSH_CODE_LOG_RX_DATA,
    PUSH_CODE_MSG_WAITING,
    PUSH_CODE_PATH_DISCOVERY_RESPONSE,
    PUSH_CODE_PATH_UPDATED,
    PUSH_CODE_RAW_DATA,
    PUSH_CODE_SEND_CONFIRMED,
    PUSH_CODE_TRACE_DATA,
)
from ..models import ChannelDataEvent, ChannelMessageEvent, Contact, MessageEvent
from .frames import _build_advert_push_frames

logger = logging.getLogger("CompanionFrameServer")

# (push event, handler attribute) for every bridge event this frame server
# subscribes to.  Declared once so setup and teardown cannot drift: teardown
# retracting less than setup registered is exactly how a stale closure survives
# a reconnect, which is what the clear-everything approach used to prevent.
_PUSH_SUBSCRIPTIONS = (
    ("message_event", "_on_message_event"),
    ("channel_message_event", "_on_channel_message_event"),
    ("channel_data_event", "_on_channel_data_event"),
    ("send_confirmed", "_on_send_confirmed"),
    ("advert_received", "_on_advert_received"),
    ("node_discovered", "_on_node_discovered"),
    ("contact_path_updated", "_on_contact_path_updated"),
    ("binary_response", "_on_binary_response"),
    ("path_discovery_response", "_on_path_discovery_response"),
    ("contact_deleted", "_on_contact_deleted"),
    ("contacts_full", "_on_contacts_full"),
    ("raw_data_received", "_on_raw_data_received"),
    ("trace_received", "_on_trace_received"),
)


class _PushMixin:
    """Bridge-event push callbacks and public push_* methods of
    :class:`CompanionFrameServer`."""

    def _setup_push_callbacks(self) -> None:
        """Subscribe to bridge events and send PUSH frames to connected client.

        Only this frame server's own subscriptions are retracted first.  The
        bridge is shared — a host repeater exposes the same events to an SSE
        stream and to plug-ins — and clearing every callback here silently
        unsubscribed those the moment a companion app connected, with no way for
        them to notice.  The registrations are bound methods of ``self``, so
        they are stable across calls and drop out cleanly by name.
        """
        self._teardown_push_callbacks()
        for event_name, handler_name in _PUSH_SUBSCRIPTIONS:
            self.bridge.add_push_callback(event_name, getattr(self, handler_name))

    def _teardown_push_callbacks(self) -> None:
        """Retract this frame server's bridge subscriptions, leaving others alone."""
        for event_name, handler_name in _PUSH_SUBSCRIPTIONS:
            self.bridge.remove_push_callback(event_name, getattr(self, handler_name))

    # -------------------------------------------------------------------------
    # Bridge event callbacks (registered by _setup_push_callbacks)
    # -------------------------------------------------------------------------

    async def _on_message_event(self, event: MessageEvent):
        msg_dict = {
            "sender_key": event.sender_key,
            "text": event.text,
            "timestamp": event.timestamp,
            "txt_type": event.txt_type,
            "is_channel": False,
            "channel_idx": 0,
            "path_len": event.path_len,
            "packet_hash": event.packet_hash,
            "snr": event.snr,
            "rssi": event.rssi,
            "sender_prefix": event.sender_prefix,
        }
        if event.queued:
            await self._persist_companion_message(msg_dict, event.queue_entry)
        self._enqueue_frame(bytes([PUSH_CODE_MSG_WAITING]))

    async def _on_channel_message_event(self, event: ChannelMessageEvent):
        msg_dict = {
            "sender_key": b"",
            "text": event.text,
            "timestamp": event.timestamp,
            "txt_type": 0,
            "is_channel": True,
            "channel_idx": event.channel_idx,
            "path_len": event.path_len,
            "packet_hash": event.packet_hash,
            "snr": event.snr,
            "rssi": event.rssi,
        }
        if event.queued:
            await self._persist_companion_message(msg_dict, event.queue_entry)
        self._enqueue_frame(bytes([PUSH_CODE_MSG_WAITING]))

    async def _on_channel_data_event(self, event: ChannelDataEvent):
        msg_dict = {
            "sender_key": b"",
            "text": "",
            "timestamp": 0,
            "txt_type": 0,
            "is_channel": True,
            "channel_idx": event.channel_idx,
            "path_len": event.path_len,
            "packet_hash": event.packet_hash,
            "snr": event.snr,
            "rssi": event.rssi,
            "channel_data_type": event.data_type,
            "channel_data_payload": bytes(event.payload or b""),
        }
        if event.queued:
            await self._persist_companion_message(msg_dict, event.queue_entry)
        self._enqueue_frame(bytes([PUSH_CODE_MSG_WAITING]))

    def _on_send_confirmed(self, crc, trip_ms=0):
        # Final 4 bytes are the elapsed milliseconds from send to ACK (firmware
        # processAck writes trip_time here); 0 only when the send time is unknown.
        data = struct.pack(
            "<B4sI",
            PUSH_CODE_SEND_CONFIRMED,
            struct.pack("<I", crc)[:4],
            int(trip_ms) & 0xFFFFFFFF,
        )
        self._enqueue_frame(data)

    async def _push_advert_frames(self, contact: Contact, *, is_new: bool) -> None:
        """Push the advert frame for a contact, mirroring firmware onDiscoveredContact:
        the full NEW_ADVERT when the contact was not stored (``is_new``), otherwise the
        short ADVERT (pubkey only) for a stored contact.
        """
        pubkey = contact.public_key
        if not isinstance(pubkey, bytes) or len(pubkey) < PUB_KEY_SIZE:
            return
        short, full = await asyncio.to_thread(_build_advert_push_frames, contact)
        if is_new:
            if full is not None:
                self._enqueue_frame(full)
        else:
            self._enqueue_frame(short)

    async def _on_advert_received(self, contact):
        """Stored advert: persist the contact. The client frame push is handled by
        _on_node_discovered (firmware onDiscoveredContact)."""
        try:
            if not isinstance(contact, Contact):
                logger.warning(
                    "advert_received: expected Contact, got %s — converting",
                    type(contact).__name__,
                )
                contact = Contact.from_dict(contact) if isinstance(contact, dict) else contact
            await self._maybe_persist_contact(contact)
        except Exception as e:
            logger.exception("advert_received callback error: %s", e)

    async def _on_node_discovered(self, contact_or_data):
        """Firmware onDiscoveredContact: fires for every valid advert. Pushes the full
        NEW_ADVERT when the contact was not stored, else the short ADVERT for a stored
        contact. "Stored" is determined by whether the contact is in the contact book
        (the advert pipeline has already applied any auto-add by this point)."""
        try:
            if isinstance(contact_or_data, Contact):
                contact = contact_or_data
            elif isinstance(contact_or_data, dict):
                contact = Contact.from_dict(contact_or_data, now=int(time.time()))
            else:
                return
            if not contact.name:
                return
            is_new = self.bridge.contacts.get_by_key(contact.public_key) is None
            await self._push_advert_frames(contact, is_new=is_new)
        except Exception as e:
            logger.exception("node_discovered callback error: %s", e)

    async def _on_contact_path_updated(self, contact):
        # Defense-in-depth: only push PATH and persist for known contacts
        # (mirrors firmware which does not send PATH for non-contacts).
        if not (
            hasattr(contact, "public_key")
            and isinstance(contact.public_key, bytes)
            and len(contact.public_key) >= PUB_KEY_SIZE
        ):
            return
        if not self.bridge.contacts.get_by_key(contact.public_key):
            return
        self._enqueue_frame(bytes([PUSH_CODE_PATH_UPDATED]) + contact.public_key[:PUB_KEY_SIZE])
        try:
            await self._maybe_persist_contact(contact)
        except Exception as e:
            logger.warning("Persist contact after path update failed: %s", e)

    def _on_binary_response(self, tag_bytes, response_data, parsed=None, request_type=None):
        if isinstance(tag_bytes, bytes):
            if len(tag_bytes) < 4:
                return
            tag_int = struct.unpack("<I", tag_bytes[:4])[0]
        else:
            try:
                tag_int = int(tag_bytes)
            except (TypeError, ValueError):
                return
        if tag_int not in self._companion_binary_tags:
            # Region discovery replies can be generated outside this
            # frame-server request path; allow those through for parity
            # with pre-owner-tag behavior while keeping other responses
            # isolated to the requesting virtual companion.
            if not (isinstance(parsed, dict) and parsed.get("type") == "regions"):
                return
        else:
            self._companion_binary_tags.discard(tag_int)
        frame = (
            bytes([PUSH_CODE_BINARY_RESPONSE, 0])
            + (tag_bytes if isinstance(tag_bytes, bytes) else struct.pack("<I", tag_bytes))
            + response_data
        )
        self._enqueue_frame(frame)

    def _on_path_discovery_response(
        self, tag_bytes, contact_pubkey, out_len_byte, out_path, in_len_byte, in_path
    ):
        pub_key_prefix = (
            contact_pubkey if isinstance(contact_pubkey, bytes) else bytes.fromhex(contact_pubkey)
        )[:6]
        out_path = out_path if isinstance(out_path, bytes) else bytes(out_path)
        in_path = in_path if isinstance(in_path, bytes) else bytes(in_path)
        # Re-announce the ENCODED path_len bytes verbatim, matching the firmware
        # (MyMesh.cpp:757-765). Drop the whole frame if either encoded byte is
        # invalid, mirroring the isValidPathLen guard at MyMesh.cpp:754-755.
        if not (
            PathUtils.is_valid_path_len(out_len_byte) and PathUtils.is_valid_path_len(in_len_byte)
        ):
            logger.debug(
                "[PUSH] dropping path_discovery frame: invalid encoded path_len "
                "(out=0x%02X, in=0x%02X)",
                out_len_byte,
                in_len_byte,
            )
            return
        frame = (
            bytes([PUSH_CODE_PATH_DISCOVERY_RESPONSE, 0])
            + pub_key_prefix
            + bytes([out_len_byte])
            + out_path
            + bytes([in_len_byte])
            + in_path
        )
        self._enqueue_frame(frame)

    def _on_contact_deleted(self, pub_key):
        if isinstance(pub_key, bytes) and len(pub_key) >= PUB_KEY_SIZE:
            self._enqueue_frame(bytes([PUSH_CODE_CONTACT_DELETED]) + pub_key[:PUB_KEY_SIZE])

    def _on_contacts_full(self):
        self._enqueue_frame(bytes([PUSH_CODE_CONTACTS_FULL]))

    def _on_raw_data_received(self, payload_bytes: bytes, snr: float, rssi: int) -> None:
        """Push PUSH_CODE_RAW_DATA (0x84): code, SNR byte, RSSI byte,
        path-len byte (unknown), payload.

        Never clipped: an over-long frame is dropped by _enqueue_frame, as
        firmware onRawDataRecv() drops it.
        """
        snr_byte = max(-128, min(127, int(round(snr * 4))))
        rssi_byte = max(-128, min(127, int(rssi)))
        data = (
            bytes([PUSH_CODE_RAW_DATA])
            + struct.pack("<bb", snr_byte, rssi_byte)
            + bytes([OUT_PATH_UNKNOWN])
            + payload_bytes
        )
        self._enqueue_frame(data)

    def _on_trace_received(self, info: dict) -> None:
        """Push PUSH_CODE_TRACE_DATA (0x89) when a trace completes at this node."""
        self.push_trace_data(
            path_len=info["path_len"],
            flags=info["flags"],
            tag=info["tag"],
            auth_code=info["auth_code"],
            path_hashes=info["path_hashes"],
            path_snrs=info["path_snrs"],
            final_snr_byte=info["final_snr_byte"],
        )

    # -------------------------------------------------------------------------
    # Public push methods (called directly by host application)
    # -------------------------------------------------------------------------

    def push_trace_data(
        self,
        path_len: int,
        flags: int,
        tag: int,
        auth_code: int,
        path_hashes: bytes,
        path_snrs: bytes,
        final_snr_byte: int,
    ) -> None:
        """Push PUSH_CODE_TRACE_DATA (0x89) to client.  Matches firmware
        ``onTraceRecv()`` frame format.

        Sync, non-blocking.  Safe to call from any context (async or sync),
        like :pymethod:`push_rx_raw`.
        """
        if self._write_queue is None:
            return
        hash_width = PathUtils.trace_payload_hash_width(flags)
        expected_snr_len = path_len // hash_width
        if len(path_snrs) != expected_snr_len:
            logger.debug(
                "push_trace_data: path_snrs len %s != expected %s",
                len(path_snrs),
                expected_snr_len,
            )
            return
        data = (
            bytes([PUSH_CODE_TRACE_DATA, 0, path_len, flags])
            + struct.pack("<II", tag & 0xFFFFFFFF, auth_code & 0xFFFFFFFF)
            + path_hashes
            + path_snrs
            + bytes([final_snr_byte & 0xFF])
        )
        self._enqueue_frame(data)

    async def push_trace_data_async(
        self,
        path_len: int,
        flags: int,
        tag: int,
        auth_code: int,
        path_hashes: bytes,
        path_snrs: bytes,
        final_snr_byte: int,
    ) -> None:
        """Async wrapper for code that must ``await`` a coroutine (same as
        :pymethod:`push_trace_data`).
        """
        self.push_trace_data(
            path_len,
            flags,
            tag,
            auth_code,
            path_hashes,
            path_snrs,
            final_snr_byte,
        )

    def push_rx_raw(self, snr: float, rssi: int, raw: bytes) -> None:
        """Push raw RX packet to client (PUSH_CODE_LOG_RX_DATA 0x88).

        Sync, non-blocking.  Safe to call from any context (async or sync).
        """
        if self._write_queue is None:
            return
        snr_byte = max(-128, min(127, int(round(snr * 4))))
        rssi_byte = max(-128, min(127, int(rssi)))
        if snr_byte < 0:
            snr_byte += 256
        if rssi_byte < 0:
            rssi_byte += 256
        # Never clipped: a clipped frame still parses but its MAC fails. An
        # over-long one is dropped by _enqueue_frame, as firmware logRxRaw() does.
        data = bytes([PUSH_CODE_LOG_RX_DATA, snr_byte & 0xFF, rssi_byte & 0xFF]) + raw
        self._enqueue_frame(data)

    async def push_rx_raw_async(self, snr: float, rssi: int, raw: bytes) -> None:
        """Push raw RX packet to client.  Async wrapper for backward compatibility."""
        self.push_rx_raw(snr, rssi, raw)

    async def push_control_data(
        self,
        snr: float,
        rssi: int,
        path_len: int,
        path_bytes: bytes,
        payload: bytes,
    ) -> None:
        """Push CONTROL packet to client (PUSH_CODE_CONTROL_DATA 0x8E).

        Kept as ``async def`` for backward-compatible call sites that
        ``await`` it, but the body is synchronous (just enqueues).
        """
        if self._write_queue is None:
            logger.warning("Push control data skipped: no client connection")
            return
        # Discovery response (0x90): clear only no-op callbacks owned by this
        # frame server (created by CMD_SEND_CONTROL_DATA discovery requests).
        if self._control_handler and len(payload) >= 6 and (payload[0] & 0xF0) == 0x90:
            tag = struct.unpack("<I", payload[2:6])[0]
            if tag in self._companion_discovery_tags:
                self._control_handler.clear_response_callback(tag)
                self._companion_discovery_tags.discard(tag)
        snr_val = snr if isinstance(snr, (int, float)) else 0.0
        rssi_val = rssi if isinstance(rssi, (int, float)) else 0
        snr_byte = max(-128, min(127, int(round(float(snr_val) * 4))))
        rssi_byte = max(-128, min(127, int(rssi_val)))
        if snr_byte < 0:
            snr_byte += 256
        if rssi_byte < 0:
            rssi_byte += 256
        path_len_byte = max(0, min(255, int(path_len) if path_len is not None else 0))
        # Never clipped; see _on_raw_data_received (firmware onControlDataRecv()).
        payload_slice = bytes(payload) if payload else b""
        data = (
            bytes(
                [
                    PUSH_CODE_CONTROL_DATA,
                    snr_byte & 0xFF,
                    rssi_byte & 0xFF,
                    path_len_byte,
                ]
            )
            + payload_slice
        )
        self._enqueue_frame(data)
        logger.debug("Pushed control data 0x8E to client: payload_len=%s", len(payload_slice))
