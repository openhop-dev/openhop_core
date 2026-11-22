"""Tests for MessageFrameSession (companion frames over message-oriented links)."""

import asyncio
import struct
from unittest.mock import Mock

from openhop_core.companion.constants import (
    CMD_GET_DEVICE_TIME,
    FRAME_OUTBOUND_PREFIX,
    MAX_FRAME_SIZE,
    RESP_CODE_CURR_TIME,
)
from openhop_core.companion.frame_server import CompanionFrameServer
from openhop_core.companion.frame_server.message_session import MessageFrameSession


def _server():
    bridge = Mock()
    bridge.get_time = Mock(return_value=1234)
    bridge.prefs = Mock(node_name="CZ-test")
    bridge.contacts = Mock(max_contacts=100)
    return CompanionFrameServer(bridge, "ab", port=0, client_idle_timeout_sec=None)


async def _until(cond, steps=200):
    for _ in range(steps):
        if cond():
            return True
        await asyncio.sleep(0.001)
    return cond()


class _BlockingReader:
    def __init__(self):
        self.release = asyncio.Event()

    async def read(self, _n):
        await self.release.wait()
        return b""

    async def readexactly(self, n):
        raise asyncio.IncompleteReadError(partial=b"", expected=n)


class _DummyWriter:
    def __init__(self):
        self.closed = False

    def get_extra_info(self, _name, default=None):
        return default

    def write(self, _data):
        pass

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass

    def is_closing(self):
        return self.closed


# ---------------------------------------------------------------------------
# MessageFrameSession
# ---------------------------------------------------------------------------


async def test_session_round_trip_command_and_response():
    server = _server()
    sent = []
    session = MessageFrameSession(server, sent.append)
    session.start()
    assert session.feed(bytes([CMD_GET_DEVICE_TIME]))
    assert await _until(lambda: sent)
    assert sent[0] == bytes([RESP_CODE_CURR_TIME]) + struct.pack("<I", 1234)
    session.end()
    await asyncio.wait_for(session.wait(), 1)
    assert server._client_writer is None


async def test_session_accepts_async_send():
    server = _server()
    sent = []

    async def send(payload):
        await asyncio.sleep(0)
        sent.append(payload)

    session = MessageFrameSession(server, send)
    session.start()
    session.feed(bytes([CMD_GET_DEVICE_TIME]))
    assert await _until(lambda: sent)
    session.end()
    await asyncio.wait_for(session.wait(), 1)


async def test_session_drops_oversize_and_empty_inbound():
    session = MessageFrameSession(_server(), lambda _p: None)
    assert not session.feed(b"")
    assert not session.feed(b"\x01" * (MAX_FRAME_SIZE + 1))


async def test_writer_unframes_partial_and_batched_writes():
    sent = []
    session = MessageFrameSession(_server(), sent.append)
    w = session.writer
    f1 = bytes([FRAME_OUTBOUND_PREFIX]) + struct.pack("<H", 3) + b"abc"
    f2 = bytes([FRAME_OUTBOUND_PREFIX]) + struct.pack("<H", 1) + b"z"
    w.write(f1[:2])
    w.write(f1[2:] + f2)
    await w.drain()
    assert sent == [b"abc", b"z"]


async def test_tcp_client_evicts_message_session_and_calls_on_close():
    server = _server()
    closed = []
    session = MessageFrameSession(server, lambda _p: None, lambda: closed.append(True))
    session.start()
    assert await _until(lambda: server._client_writer is session.writer)

    reader = _BlockingReader()
    tcp_task = asyncio.create_task(server._handle_client(reader, _DummyWriter()))
    assert await _until(lambda: closed)
    await asyncio.wait_for(session.wait(), 1)
    assert not session.active
    assert not session.feed(bytes([CMD_GET_DEVICE_TIME]))  # dead session takes nothing

    reader.release.set()
    await asyncio.wait_for(tcp_task, 1)


async def test_message_session_evicts_tcp_client():
    server = _server()
    reader = _BlockingReader()
    tcp_writer = _DummyWriter()
    tcp_task = asyncio.create_task(server._handle_client(reader, tcp_writer))
    assert await _until(lambda: server._client_writer is tcp_writer)

    session = MessageFrameSession(server, lambda _p: None)
    session.start()
    assert await _until(lambda: tcp_writer.closed)
    assert await _until(lambda: server._client_writer is session.writer)
    reader.release.set()
    await asyncio.wait_for(tcp_task, 1)
    session.end()
    await asyncio.wait_for(session.wait(), 1)
