"""TCP transport for the companion frame protocol: server lifecycle, frame
framing, the single writer task, and per-client read loop."""

import asyncio
import logging
import socket
import struct
import sys
from typing import Optional

from ..constants import (
    BINARY_REQ_TIMEOUT_HINT_MS,
    FRAME_INBOUND_PREFIX,
    FRAME_OUTBOUND_PREFIX,
    MAX_FRAME_SIZE,
    MAX_PAYLOAD_SIZE,
    RESP_CODE_CURR_TIME,
    RESP_CODE_ERR,
    RESP_CODE_OK,
    RESP_CODE_SENT,
)
from ..models import SentResult

logger = logging.getLogger("CompanionFrameServer")


class _FrameTransportMixin:
    """TCP lifecycle and frame I/O methods of :class:`CompanionFrameServer`."""

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

    async def start(self) -> None:
        """Start the TCP server."""
        self._server = await asyncio.start_server(
            self._handle_client,
            self.bind_address,
            self.port,
        )
        addr = (
            self._server.sockets[0].getsockname()
            if self._server.sockets
            else (self.bind_address, self.port)
        )
        # Repeater passes hash as hex (first byte of pubkey, e.g. "f5"); accept decimal or hex.
        try:
            hash_int = int(self.companion_hash)
        except ValueError:
            hash_int = int(self.companion_hash, 16)
        logger.info(
            "Companion frame server listening on %s:%s (hash=0x%02x)",
            addr[0],
            addr[1],
            hash_int,
        )

    async def attach(self, sock: socket.socket) -> None:
        """Serve one client over an already-connected socket.

        The TCP acceptor is not the only way in: a host that already holds the
        client's bytes (a WebSocket proxy in the same process) can hand one end
        of a ``socket.socketpair()`` here and skip the listener entirely, so a
        client that reaches the host is never turned away because the TCP
        listener failed to bind. The client takes the same path, and the same
        single slot, as one that arrived over TCP; the call returns when that
        client disconnects.
        """
        reader, writer = await asyncio.open_connection(sock=sock)
        await self._handle_client(reader, writer)

    async def stop(self) -> None:
        """Stop the TCP server and disconnect any client."""
        # Signal writer task to stop and wait for it
        if self._write_queue is not None:
            try:
                self._write_queue.put_nowait(None)  # Sentinel
            except asyncio.QueueFull:
                pass
        if self._writer_task is not None:
            self._writer_task.cancel()
            try:
                await self._writer_task
            except asyncio.CancelledError:
                pass
            self._writer_task = None
        self._write_queue = None
        if self._client_writer:
            try:
                self._client_writer.close()
                await self._client_writer.wait_closed()
            except Exception:
                pass
            self._client_writer = None
            self._client_reader = None
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        # The bridge outlives this server, so a stopped server must stop
        # receiving its events — otherwise it keeps pushing at a closed writer,
        # and a replacement server built on the same bridge doubles every event.
        self._teardown_push_callbacks()
        logger.info("Companion frame server stopped (port=%s)", self.port)

    def _enqueue_frame(self, data: bytes) -> None:
        """Build an outbound frame and enqueue it for the writer task.

        Sync, non-blocking.  On ``QueueFull`` the frame is dropped with a
        warning — this provides natural backpressure shedding.
        """
        if self._write_queue is None:
            return
        if len(data) > MAX_PAYLOAD_SIZE:
            # Firmware writeFrame() refuses (returns 0) rather than truncating; a
            # truncated frame would corrupt the response. Drop it instead.
            logger.warning(
                "Outbound frame payload too large (%s > %s); dropping frame",
                len(data),
                MAX_PAYLOAD_SIZE,
            )
            return
        frame = bytes([FRAME_OUTBOUND_PREFIX]) + struct.pack("<H", len(data)) + data
        try:
            self._write_queue.put_nowait(frame)
        except asyncio.QueueFull:
            logger.warning("Write queue full (%s); dropping frame", self._write_queue.maxsize)

    def _write_frame(self, data: bytes) -> None:
        """Alias for ``_enqueue_frame``; retained for subclass compatibility."""
        self._enqueue_frame(data)

    def _write_ok(self) -> None:
        self._write_frame(bytes([RESP_CODE_OK]))

    def _write_err(self, err_code: int) -> None:
        self._write_frame(bytes([RESP_CODE_ERR, err_code]))

    def _write_sent_response(self, is_flood: bool, tag: int, timeout_ms: int) -> None:
        """Write a RESP_CODE_SENT frame: [code][flood][tag u32][timeout_ms u32]."""
        self._write_frame(
            bytes([RESP_CODE_SENT, 1 if is_flood else 0]) + struct.pack("<II", tag, timeout_ms)
        )

    def _write_sent_result(
        self,
        result: SentResult,
        *,
        default_timeout_ms: int = BINARY_REQ_TIMEOUT_HINT_MS,
        own_binary_tag: bool = False,
    ) -> None:
        """Write RESP_CODE_SENT from a SentResult, defaulting a missing tag/timeout.

        When ``own_binary_tag`` is set, the response tag is recorded so that only
        this virtual companion consumes the matching PUSH_CODE_BINARY_RESPONSE.
        """
        tag = result.expected_ack if result.expected_ack is not None else 0
        timeout_ms = result.timeout_ms if result.timeout_ms is not None else default_timeout_ms
        if own_binary_tag and result.expected_ack is not None:
            self._companion_binary_tags.add(tag)
        self._write_sent_response(result.is_flood, tag, timeout_ms)

    # -------------------------------------------------------------------------
    # Writer task
    # -------------------------------------------------------------------------

    # Must exceed DEFAULT_MAX_CONTACTS (+2 for START/END) so that
    # _cmd_get_contacts can enqueue the full contact dump without drops.
    _WRITE_QUEUE_MAXSIZE = 2048
    # Drain after every frame so clients that count one TCP receive per response
    # (e.g. _receive_count per data_received()) stay in sync with sends.
    _DRAIN_BATCH = 1

    async def _writer_loop(self, writer: asyncio.StreamWriter) -> None:
        """Single writer task: pull frames from the queue, write to the
        ``StreamWriter``, and drain periodically.

        Integrates heartbeat via timeout on :pymethod:`asyncio.Queue.get` —
        when no frames arrive within ``_heartbeat_interval`` seconds a
        ``RESP_CODE_CURR_TIME`` heartbeat frame is generated automatically,
        eliminating the need for a separate heartbeat task.

        On any write/drain error the writer is closed, which causes the read
        loop in :pymethod:`_handle_client` to receive EOF → clean disconnect.
        """
        frames_since_drain = 0
        try:
            while True:
                # Wait for a frame, or timeout for heartbeat ---------
                try:
                    frame = await asyncio.wait_for(
                        self._write_queue.get(),
                        timeout=self._heartbeat_interval,
                    )
                except asyncio.TimeoutError:
                    # Heartbeat: send RESP_CODE_CURR_TIME
                    now = self.bridge.get_time()
                    hb_data = bytes([RESP_CODE_CURR_TIME]) + struct.pack("<I", now)
                    frame = (
                        bytes([FRAME_OUTBOUND_PREFIX]) + struct.pack("<H", len(hb_data)) + hb_data
                    )

                if frame is None:  # Sentinel → orderly shutdown
                    break

                # Write the frame ------------------------------------
                writer.write(frame)
                frames_since_drain += 1

                # Drain when queue empties (natural batching) or every N frames
                if self._write_queue.empty() or frames_since_drain >= self._DRAIN_BATCH:
                    await writer.drain()
                    frames_since_drain = 0
        except asyncio.CancelledError:
            pass
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            logger.warning("Writer loop connection lost: %s", e)
        except Exception as e:
            logger.error("Writer loop error: %s", e, exc_info=True)
        finally:
            try:
                if not writer.is_closing():
                    writer.close()
            except Exception:
                pass

    # -------------------------------------------------------------------------
    # Client handling
    # -------------------------------------------------------------------------

    @staticmethod
    def _configure_socket(writer: asyncio.StreamWriter) -> None:
        """Configure TCP keepalive and low-latency options on the underlying socket."""
        sock = writer.get_extra_info("socket")
        if sock is None:
            return
        try:
            # Disable Nagle's algorithm for real-time frame delivery (important
            # over VPN/Tailscale where latency is higher and small-write
            # coalescing can compound delays).
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError as e:
            logger.debug("Could not set TCP_NODELAY: %s", e)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            if sys.platform == "linux":
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 15)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 5)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
            elif sys.platform == "darwin":
                # TCP_KEEPALIVE is the macOS equivalent of TCP_KEEPIDLE
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPALIVE, 15)
                try:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 5)
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
                except (AttributeError, OSError):
                    pass  # older macOS may lack KEEPINTVL/KEEPCNT
        except (AttributeError, OSError) as e:
            # Some Python/macOS builds don't expose socket.TCP_KEEPALIVE.
            logger.debug("Could not set TCP keepalive: %s", e)

    async def _evict_existing_client(self) -> None:
        """Close the current client connection to make room for a new one."""
        logger.info(
            "Companion already has a client; evicting previous connection (port=%s)",
            self.port,
        )
        old_writer = self._client_writer
        old_writer_task = self._writer_task
        # Cancel and await the old writer task so it's fully gone before we replace
        # the queue and create a new task (avoids the new task being mistaken for
        # a failed writer when the old task had already exited).
        if old_writer_task is not None:
            old_writer_task.cancel()
            try:
                await old_writer_task
            except asyncio.CancelledError:
                pass
            if self._writer_task is old_writer_task:
                self._writer_task = None
        try:
            old_writer.close()
            await old_writer.wait_closed()
        except Exception:
            pass

    async def _read_client_frames(
        self, reader: asyncio.StreamReader, writer_task: asyncio.Task
    ) -> str:
        """Read and dispatch inbound frames until disconnect; return the reason."""
        while True:
            try:
                prefix = await asyncio.wait_for(
                    reader.read(1), timeout=self._client_idle_timeout_sec
                )
            except asyncio.TimeoutError:
                return "idle_timeout"
            if not prefix:
                return "empty_read"
            if prefix[0] != FRAME_INBOUND_PREFIX:
                logger.warning("Invalid frame prefix: 0x%02x", prefix[0])
                continue
            len_bytes = await reader.readexactly(2)
            frame_len = struct.unpack("<H", len_bytes)[0]
            if frame_len > MAX_FRAME_SIZE:
                logger.warning("Frame too long: %s", frame_len)
                return "frame_too_long"
            payload = await reader.readexactly(frame_len)
            await self._handle_cmd(payload)
            if writer_task.done():
                if not writer_task.cancelled():
                    exc = writer_task.exception()
                    if exc is not None:
                        logger.error(
                            "Writer task failed (port=%s): %s",
                            self.port,
                            exc,
                            exc_info=True,
                        )
                return "writer_failed"

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle a new client connection.  One client at a time.
        If a client is already connected, the existing connection is closed
        and the new one is accepted (eviction). An idle read timeout also
        frees the slot when no data is received for client_idle_timeout_sec.
        """
        if self._client_writer:
            await self._evict_existing_client()

        self._client_reader = reader
        self._client_writer = writer
        self._configure_socket(writer)
        local_write_queue: asyncio.Queue = asyncio.Queue(maxsize=self._WRITE_QUEUE_MAXSIZE)
        self._write_queue = local_write_queue
        self._setup_push_callbacks()
        logger.info("Companion client connected (port=%s)", self.port)

        local_writer_task = asyncio.create_task(self._writer_loop(writer))
        self._writer_task = local_writer_task
        disconnect_reason: Optional[str] = None
        try:
            disconnect_reason = await self._read_client_frames(reader, local_writer_task)
        except asyncio.IncompleteReadError:
            disconnect_reason = "incomplete_read"
        except (ConnectionResetError, BrokenPipeError) as e:
            disconnect_reason = type(e).__name__
        except Exception as e:
            disconnect_reason = f"other: {type(e).__name__}: {e}"
            logger.error("Client handler error: %s", e, exc_info=True)
        finally:
            await self._cleanup_client(
                writer, local_write_queue, local_writer_task, disconnect_reason
            )

    async def _cleanup_client(
        self,
        writer: asyncio.StreamWriter,
        write_queue: asyncio.Queue,
        writer_task: asyncio.Task,
        disconnect_reason: Optional[str],
    ) -> None:
        """Tear down per-client state, skipping parts a new client already replaced."""
        if self._write_queue is write_queue:
            try:
                write_queue.put_nowait(None)  # Sentinel
            except asyncio.QueueFull:
                pass
        else:
            logger.debug(
                "Skipping stale queue cleanup for disconnected client (port=%s)",
                self.port,
            )
        if self._writer_task is writer_task:
            writer_task.cancel()
            try:
                await writer_task
            except asyncio.CancelledError:
                pass
            self._writer_task = None
        else:
            logger.debug(
                "Skipping stale writer cleanup for disconnected client (port=%s)",
                self.port,
            )
        if self._write_queue is write_queue:
            self._write_queue = None
        if self._client_writer is writer:
            self._client_writer = None
            self._client_reader = None
            logger.info(
                "Companion client disconnected (port=%s): %s",
                self.port,
                disconnect_reason or "unknown",
            )
