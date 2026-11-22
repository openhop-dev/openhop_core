"""Companion sessions over message-oriented links (one frame per message).

The TCP transport speaks the companion protocol as a byte stream: every frame
carries a ``<``/``>`` prefix and a 2-byte length. Links such as BLE GATT (the
Nordic UART service that MeshCore firmware exposes) carry exactly one frame
payload per write or notification and no stream framing at all.

:class:`MessageFrameSession` adapts such a link to
:meth:`CompanionFrameServer._handle_client`, so the link shares everything the
TCP path has: command dispatch, push callbacks, the heartbeat, the write queue,
and the single client slot with its eviction rule (a new client, on any link,
replaces the current one).

The session needs only two things from the link:

* ``send(payload)`` -- deliver one outbound frame payload (sync or async);
* ``on_close()`` -- called once when the server drops the session (eviction or
  server stop), so the link can disconnect its peer.

The link calls :meth:`MessageFrameSession.feed` with each inbound payload and
:meth:`MessageFrameSession.end` when its peer goes away.
"""

import asyncio
import inspect
import logging
import struct
from typing import Any, Awaitable, Callable, Optional, Union

from ..constants import FRAME_INBOUND_PREFIX, FRAME_OUTBOUND_PREFIX, MAX_FRAME_SIZE

logger = logging.getLogger("CompanionFrameServer")

SendFn = Callable[[bytes], Union[None, Awaitable[None]]]


class _MessageWriter:
    """The ``StreamWriter`` side of a session: unframes outbound frames.

    ``CompanionFrameServer`` writes complete ``>``-framed frames and drains after
    each one; :meth:`drain` hands every complete payload to the link in order.
    """

    def __init__(self, session: "MessageFrameSession") -> None:
        self._session = session
        self._buf = bytearray()
        self._pending: list = []
        self._closed = False
        self._closed_event = asyncio.Event()

    # StreamWriter surface used by the frame server --------------------------

    def get_extra_info(self, _name: str, default: Any = None) -> Any:
        return default  # no socket: the server's TCP tuning is skipped

    def write(self, data: bytes) -> None:
        if self._closed:
            return
        self._buf += data
        while len(self._buf) >= 3:
            if self._buf[0] != FRAME_OUTBOUND_PREFIX:
                logger.warning("message session: bad outbound prefix 0x%02x", self._buf[0])
                self._buf.clear()
                return
            size = struct.unpack_from("<H", self._buf, 1)[0]
            if len(self._buf) < 3 + size:
                return
            self._pending.append(bytes(self._buf[3 : 3 + size]))
            del self._buf[: 3 + size]

    async def drain(self) -> None:
        while self._pending and not self._closed:
            payload = self._pending.pop(0)
            await self._session._send_one(payload)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._pending.clear()
        self._closed_event.set()
        self._session._on_writer_closed()

    def is_closing(self) -> bool:
        return self._closed

    async def wait_closed(self) -> None:
        await self._closed_event.wait()


class MessageFrameSession:
    """One companion client on a message-oriented link.

    Args:
        server: the :class:`CompanionFrameServer` to attach to.
        send: delivers one outbound frame payload to the peer. May be a coroutine
            function. An ``OSError`` from it ends the session.
        on_close: called once when the server closes the session (eviction,
            server stop, or a failed send). Not called for :meth:`end`.
        label: name used in log lines.
    """

    def __init__(
        self,
        server: Any,
        send: SendFn,
        on_close: Optional[Callable[[], None]] = None,
        *,
        label: str = "message",
    ) -> None:
        self._server = server
        self._send = send
        self._on_close = on_close
        self._label = label
        self._ended = False
        self.reader = asyncio.StreamReader()
        self.writer = _MessageWriter(self)
        self.task: Optional[asyncio.Task] = None

    def start(self) -> asyncio.Task:
        """Hand the session to the server (evicting any current client)."""
        if self.task is None:
            logger.info("Companion %s session starting", self._label)
            self.task = asyncio.create_task(self._server._handle_client(self.reader, self.writer))
        return self.task

    @property
    def active(self) -> bool:
        """True while the server still treats this session as its client."""
        return self.task is not None and not self.task.done() and not self.writer.is_closing()

    def feed(self, payload: bytes) -> bool:
        """Pass one inbound frame payload from the peer. Returns False if dropped."""
        if self._ended or self.writer.is_closing():
            return False
        if not payload or len(payload) > MAX_FRAME_SIZE:
            logger.warning(
                "Companion %s session: dropped inbound frame of %d bytes", self._label, len(payload)
            )
            return False
        self.reader.feed_data(
            bytes([FRAME_INBOUND_PREFIX]) + struct.pack("<H", len(payload)) + bytes(payload)
        )
        return True

    def end(self) -> None:
        """The peer went away: let the server finish the session normally."""
        if not self._ended:
            self._ended = True
            self.reader.feed_eof()

    async def wait(self) -> None:
        if self.task is not None:
            await self.task

    # Called by the writer ----------------------------------------------------

    async def _send_one(self, payload: bytes) -> None:
        result = self._send(payload)
        if inspect.isawaitable(result):
            await result

    def _on_writer_closed(self) -> None:
        # The frame server closed our writer: eviction, stop, or a failed send.
        # Make the read loop return as well, then tell the link once.
        if not self._ended:
            self._ended = True
            self.reader.feed_eof()
            if self._on_close is not None:
                try:
                    self._on_close()
                except Exception as exc:  # noqa: BLE001 - the link's problem, not ours
                    logger.warning("Companion %s session: on_close failed: %s", self._label, exc)
