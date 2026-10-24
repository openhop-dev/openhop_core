"""Push-callback registration and response routing of CompanionBase."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Callable, Optional

from ..util.callbacks import invoke_maybe_awaitable
from .base_support import _fmt_path

logger = logging.getLogger("CompanionBase")


class _CallbackMixin:
    """Part of :class:`CompanionBase` (see companion_base.py)."""

    # -------------------------------------------------------------------------
    # Push Callbacks
    # -------------------------------------------------------------------------

    def add_push_callback(self, event_name: str, callback: Callable) -> bool:
        """Subscribe ``callback`` to ``event_name``; return whether it was added.

        Registration is idempotent: subscribing the same callable twice leaves
        one subscription, so two code paths that both want an event (a frame
        server and its host, say) cannot double-fire it.  Bound methods compare
        equal per instance, so this holds for ``self._on_x`` style callbacks.

        Raises:
            KeyError: ``event_name`` is not a known push event.
        """
        callbacks = self._push_callbacks.get(event_name)
        if callbacks is None:
            raise KeyError(f"Unknown push event: {event_name!r}")
        if callback in callbacks:
            return False
        callbacks.append(callback)
        return True

    def remove_push_callback(self, event_name: str, callback: Callable) -> bool:
        """Unsubscribe one callback; return whether it was registered.

        Lets a subsystem retract exactly its own subscriptions.  Anything that
        cannot name what it registered has to fall back to
        :meth:`clear_push_callbacks`, which takes every other subsystem's
        callbacks with it.
        """
        callbacks = self._push_callbacks.get(event_name)
        if not callbacks or callback not in callbacks:
            return False
        callbacks.remove(callback)
        return True

    def clear_push_callbacks(self) -> None:
        """Remove *every* registered push callback, whoever registered it.

        This is a full reset across subsystems, not a per-owner teardown: an
        app-facing subscriber (an SSE stream, a plugin) loses its callbacks here
        with no way to notice.  Prefer :meth:`remove_push_callback` for the
        callbacks you own; reach for this only when tearing the companion down.
        """
        for key in self._push_callbacks:
            self._push_callbacks[key].clear()
        self._legacy_push_adapters.clear()

    def _add_legacy_push_callback(
        self, event_name: str, callback: Callable, build_adapter: Callable[[], Callable]
    ) -> None:
        """Subscribe a legacy positional ``callback`` through a memoized adapter.

        The adapter is a closure, so a fresh one per call would defeat
        :meth:`add_push_callback`'s identity check and let a re-registering
        caller stack duplicates.  Caching it per ``(event, callback)`` keeps
        legacy registration idempotent too.
        """
        key = (event_name, callback)
        adapter = self._legacy_push_adapters.get(key)
        if adapter is None:
            adapter = build_adapter()
            self._legacy_push_adapters[key] = adapter
        self.add_push_callback(event_name, adapter)

    def on_message_event(self, callback: Callable) -> None:
        """Register a direct-message callback receiving one ``MessageEvent``."""
        self.add_push_callback("message_event", callback)

    def on_channel_message_event(self, callback: Callable) -> None:
        """Register a channel-text callback receiving one ``ChannelMessageEvent``."""
        self.add_push_callback("channel_message_event", callback)

    def on_channel_data_event(self, callback: Callable) -> None:
        """Register a channel-data callback receiving one ``ChannelDataEvent``."""
        self.add_push_callback("channel_data_event", callback)

    def on_message_sent(self, callback: Callable) -> None:
        """Register a sent-text callback receiving one ``SentMessageEvent``."""
        self.add_push_callback("message_sent", callback)

    @staticmethod
    async def _call_legacy(callback: Callable, *args: Any) -> None:
        """Invoke a legacy positional callback, awaiting it when async."""
        await invoke_maybe_awaitable(callback, *args)

    def on_message_received(self, callback: Callable) -> None:
        """Deprecated: prefer :meth:`on_message_event`.

        The legacy callback receives the ``MessageEvent`` fields exploded
        positionally: ``(sender_key, text, timestamp, txt_type, packet_hash,
        snr, rssi, sender_prefix, path_len, queued)``. The final ``queued``
        flag is false when the protected offline queue could not retain the
        message.
        """

        async def _legacy_adapter(event: Any) -> None:
            await self._call_legacy(
                callback,
                event.sender_key,
                event.text,
                event.timestamp,
                event.txt_type,
                event.packet_hash,
                event.snr,
                event.rssi,
                event.sender_prefix,
                event.path_len,
                event.queued,
            )

        self._add_legacy_push_callback("message_event", callback, lambda: _legacy_adapter)

    def on_channel_message_received(self, callback: Callable) -> None:
        """Deprecated: prefer :meth:`on_channel_message_event`.

        The legacy callback receives ``(channel_name, sender_name, text,
        timestamp, path_len, channel_idx, packet_hash, snr, rssi, queued)``.
        """

        async def _legacy_adapter(event: Any) -> None:
            await self._call_legacy(
                callback,
                event.channel_name,
                event.sender_name,
                event.text,
                event.timestamp,
                event.path_len,
                event.channel_idx,
                event.packet_hash,
                event.snr,
                event.rssi,
                event.queued,
            )

        self._add_legacy_push_callback("channel_message_event", callback, lambda: _legacy_adapter)

    def on_channel_data_received(self, callback: Callable) -> None:
        """Deprecated: prefer :meth:`on_channel_data_event`.

        The legacy callback receives ``(channel_idx, path_len, data_type,
        payload, packet_hash, snr, rssi, queued)``.
        """

        async def _legacy_adapter(event: Any) -> None:
            await self._call_legacy(
                callback,
                event.channel_idx,
                event.path_len,
                event.data_type,
                event.payload,
                event.packet_hash,
                event.snr,
                event.rssi,
                event.queued,
            )

        self._add_legacy_push_callback("channel_data_event", callback, lambda: _legacy_adapter)

    def on_advert_received(self, callback: Callable) -> None:
        self.add_push_callback("advert_received", callback)

    def on_contact_path_updated(self, callback: Callable) -> None:
        self.add_push_callback("contact_path_updated", callback)

    async def _on_contact_path_updated(self, pub: bytes, path_len: int, path_bytes: bytes) -> None:
        """Called by ProtocolResponseHandler when contact's out_path is updated from a PATH packet.

        Matches companion firmware behaviour: PATH updates are only applied
        (and pushed to the client) for contacts that already exist in the
        store.  Unknown public keys are silently ignored.
        """
        contact = self.get_contact_by_key(pub)
        if contact is None:
            logger.debug(
                "[PATHDIAG] _on_contact_path_updated: no contact for pub=%s (ignored)",
                pub[:4].hex(),
            )
            return  # Firmware does not send PATH for non-contacts
        logger.debug(
            "[PATHDIAG] _on_contact_path_updated pub=%s name=%s %s",
            pub[:4].hex(),
            getattr(contact, "name", "?"),
            _fmt_path(path_len, path_bytes),
        )
        contact.out_path_len = path_len
        contact.out_path = path_bytes
        self.contacts.update(contact)
        await self._fire_callbacks("contact_path_updated", contact)

    def on_send_confirmed(self, callback: Callable) -> None:
        self.add_push_callback("send_confirmed", callback)

    def on_trace_received(self, callback: Callable) -> None:
        self.add_push_callback("trace_received", callback)

    def on_node_discovered(self, callback: Callable) -> None:
        self.add_push_callback("node_discovered", callback)

    def on_login_result(self, callback: Callable) -> None:
        self.add_push_callback("login_result", callback)

    def on_telemetry_response(self, callback: Callable) -> None:
        self.add_push_callback("telemetry_response", callback)

    def on_status_response(self, callback: Callable) -> None:
        self.add_push_callback("status_response", callback)

    def on_raw_data_received(self, callback: Callable) -> None:
        self.add_push_callback("raw_data_received", callback)

    def on_rx_log_data(self, callback: Callable) -> None:
        """Register callback for raw RX with SNR/RSSI (CompanionRadio only).

        Callback(snr: float, rssi: int, raw_bytes: bytes). Same data as
        PUSH_CODE_LOG_RX_DATA (0x88). Only fired when using CompanionRadio;
        CompanionBridge does not own the radio.
        """
        self.add_push_callback("rx_log_data", callback)

    def on_binary_response(self, callback: Callable) -> None:
        """Register callback for PUSH 0x8C. Callback(tag_bytes, response_data)."""
        self.add_push_callback("binary_response", callback)

    def on_path_discovery_response(self, callback: Callable) -> None:
        """Register callback for path discovery 0x8D. (tag_bytes, pubkey, out_path, in_path)."""
        self.add_push_callback("path_discovery_response", callback)

    def on_contact_deleted(self, callback: Callable) -> None:
        """Register callback for PUSH 0x8F (contact overwritten). Callback(pub_key_bytes)."""
        self.add_push_callback("contact_deleted", callback)

    def on_contacts_full(self, callback: Callable) -> None:
        """Register callback for PUSH 0x90 (contacts store full). Callback()."""
        self.add_push_callback("contacts_full", callback)

    def on_channel_updated(self, callback: Callable) -> None:
        """Register callback for channel set/remove. Callback(idx: int, channel_or_none)."""
        self.add_push_callback("channel_updated", callback)

    def register_binary_request(
        self,
        tag_hex: str,
        request_type: int,
        timeout_seconds: float,
        pubkey_prefix: str = "",
        context: Optional[dict] = None,
    ) -> None:
        """Register a pending binary request. Call cleanup_expired_requests first."""
        self._pending_binary_requests[tag_hex] = {
            "request_type": request_type,
            "pubkey_prefix": pubkey_prefix,
            "expires_at": time.time() + timeout_seconds,
            "context": context or {},
        }

    def has_pending_request_tag(self, tag: int, contact_pubkey: bytes) -> bool:
        """True when ``tag`` is the reflected tag of a request we are waiting on.

        Wired into :meth:`LoginResponseHandler.set_foreign_request_probe` so a
        status/telemetry/neighbours reply is never mistaken for a login reply
        while a login to the same contact is still pending. Covers both places a
        pending tag can live:

        * ``_pending_binary_requests`` — ``send_binary_req`` (neighbours, owner
          info, ACL, MMA), keyed by the little-endian tag hex;
        * the protocol handler's per-(contact, tag) waiters — ``send_status`` /
          ``send_telemetry`` via ``_start_protocol_request``.

        Expired entries are pruned first, so a long-dead request cannot keep
        diverting replies away from a genuine login.
        """
        try:
            self.cleanup_expired_binary_requests()
            if (int(tag) & 0xFFFFFFFF).to_bytes(4, "little").hex() in self._pending_binary_requests:
                return True
            handler = self._get_protocol_response_handler()
            waiters = getattr(handler, "_response_waiters", None)
            if waiters and (bytes(contact_pubkey), int(tag) & 0xFFFFFFFF) in waiters:
                return True
        except Exception as e:
            logger.debug("has_pending_request_tag failed: %s", e)
        return False

    def cleanup_expired_binary_requests(self) -> None:
        """Remove expired entries from _pending_binary_requests."""
        now = time.time()
        expired = [
            tag for tag, info in self._pending_binary_requests.items() if now > info["expires_at"]
        ]
        for tag in expired:
            del self._pending_binary_requests[tag]

    async def _on_binary_response(
        self,
        tag_bytes: bytes,
        response_data: bytes,
        path_info: Optional[tuple] = None,
    ) -> bool:
        """Deliver a binary response; return whether a pending request claimed it."""
        if path_info is not None:
            if await self._try_handle_path_discovery(tag_bytes, path_info):
                return True
        self.cleanup_expired_binary_requests()
        tag_hex = tag_bytes.hex()
        info = self._pending_binary_requests.pop(tag_hex, None)
        if not info:
            # A decryptable response arrived but no request is waiting for this tag.
            # This is the signature of "response arrived but we already timed out"
            # (or a tag mismatch); distinct from "no response arrived at all".
            logger.debug(
                "[PATHDIAG] anon/binary response UNMATCHED tag=%s (%dB) — no pending "
                "request (arrived after timeout, or tag mismatch). pending=%s",
                tag_hex,
                len(response_data),
                list(self._pending_binary_requests.keys()),
            )
            await self._fire_callbacks("binary_response", tag_bytes, response_data)
            return False
        request_type = info["request_type"]
        logger.debug(
            "[PATHDIAG] anon/binary response MATCHED tag=%s type=%s (%dB)",
            tag_hex,
            request_type,
            len(response_data),
        )
        pubkey_prefix = info.get("pubkey_prefix", "")
        context = info.get("context", {})
        parsed = None
        try:
            from . import binary_parsing

            parsed = binary_parsing.parse_binary_response(
                request_type,
                response_data,
                pubkey_prefix=pubkey_prefix,
                context=context,
            )
        except Exception as e:
            logger.debug("Binary response parse for type %s: %s", request_type, e)
        await self._fire_callbacks(
            "binary_response", tag_bytes, response_data, parsed, request_type
        )
        return True

    async def _try_handle_path_discovery(self, tag_bytes: bytes, path_info: tuple) -> bool:
        """If tag is pending path discovery, fire path_discovery_response and return True."""
        out_len_byte, out_path, in_len_byte, in_path, contact_pubkey = path_info
        tag_int = int.from_bytes(tag_bytes, "little")
        if tag_int not in self._pending_discovery_tags:
            return False
        self._pending_discovery_tags.discard(tag_int)
        await self._fire_callbacks(
            "path_discovery_response",
            tag_bytes,
            contact_pubkey,
            out_len_byte,
            out_path,
            in_len_byte,
            in_path,
        )
        return True

    async def _fire_callbacks(self, event_name: str, *args: Any) -> None:
        # Iterate a snapshot: dispatch awaits, and a handler may subscribe or
        # unsubscribe (a frame server reconnecting, an SSE client leaving) while
        # this loop is suspended.
        for callback in list(self._push_callbacks.get(event_name, ())):
            try:
                await invoke_maybe_awaitable(callback, *args)
            except Exception as e:
                logger.error("Error in %s callback: %s", event_name, e)

    def _spawn_background_task(self, coro: Any, label: str) -> asyncio.Task:
        """Create a fire-and-forget task that is tracked until done.

        Holding a reference prevents premature garbage collection (see the
        asyncio.create_task docs) and the done callback surfaces exceptions
        that would otherwise be silently dropped.
        """
        task = asyncio.get_running_loop().create_task(coro)
        self._background_tasks.add(task)

        def _on_done(t: asyncio.Task) -> None:
            self._background_tasks.discard(t)
            if not t.cancelled() and t.exception() is not None:
                logger.error("Background task %s failed: %s", label, t.exception())

        task.add_done_callback(_on_done)
        return task

    def _schedule_fire_callbacks(self, event_name: str, *args: Any) -> None:
        """Schedule _fire_callbacks from sync code (e.g. set_channel). No-op if no running loop."""
        try:
            self._spawn_background_task(
                self._fire_callbacks(event_name, *args), f"fire_callbacks({event_name})"
            )
        except RuntimeError:
            pass
