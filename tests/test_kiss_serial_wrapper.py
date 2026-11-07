"""
Tests for KissSerialWrapper (generic KISS TNC over serial).

Decoder and queue behavior is exercised without a real serial port.
"""

import asyncio
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from openhop_core.hardware.kiss_serial_wrapper import (
    KISS_CMD_DATA,
    KISS_CMD_TXDELAY,
    KISS_FEND,
    KISS_FESC,
    KISS_TFEND,
    KISS_TFESC,
    MAX_FRAME_SIZE,
    TX_BUFFER_SIZE,
    KissSerialWrapper,
)


def _make_wrapper(**kwargs) -> KissSerialWrapper:
    defaults = {
        "port": "/dev/null",
        "auto_configure": False,
    }
    defaults.update(kwargs)
    return KissSerialWrapper(**defaults)


def _kiss_encode(cmd: int, data: bytes, kiss_port: int = 0) -> bytes:
    frame = bytearray([KISS_FEND, ((kiss_port & 0x0F) << 4) | (cmd & 0x0F)])
    for byte in data:
        if byte == KISS_FEND:
            frame.extend([KISS_FESC, KISS_TFEND])
        elif byte == KISS_FESC:
            frame.extend([KISS_FESC, KISS_TFESC])
        else:
            frame.append(byte)
    frame.append(KISS_FEND)
    return bytes(frame)


def _feed_bytewise(wrapper: KissSerialWrapper, data: bytes) -> None:
    for b in data:
        wrapper._decode_kiss_byte(b)


def _feed_chunks(wrapper: KissSerialWrapper, data: bytes, chunk_sizes) -> None:
    i = 0
    for size in chunk_sizes:
        wrapper._decode_kiss(data[i : i + size])
        i += size
    if i < len(data):
        wrapper._decode_kiss(data[i:])


class TestOversizeFrameResync:
    """Unterminated RX frames must resync at MAX_FRAME_SIZE, not grow unbounded."""

    def test_bytewise_oversize_then_valid(self):
        received = []
        wrapper = _make_wrapper(on_frame_received=received.append)
        runaway = bytes([KISS_FEND, KISS_CMD_DATA]) + bytes(MAX_FRAME_SIZE + 50)
        valid = _kiss_encode(KISS_CMD_DATA, b"\x01\x02")
        _feed_bytewise(wrapper, runaway + valid)

        assert len(received) == 1
        assert received[0] == b"\x01\x02"
        assert wrapper.stats["frame_errors"] >= 1
        assert len(wrapper.rx_frame_buffer) <= MAX_FRAME_SIZE
        assert not wrapper.in_frame or len(wrapper.rx_frame_buffer) <= MAX_FRAME_SIZE

    def test_bulk_oversize_whole_stream(self):
        received = []
        wrapper = _make_wrapper(on_frame_received=received.append)
        runaway = bytes([KISS_FEND, KISS_CMD_DATA]) + bytes(MAX_FRAME_SIZE + 50)
        valid = _kiss_encode(KISS_CMD_DATA, b"\xaa\xbb")
        wrapper._decode_kiss(runaway + valid)

        assert len(received) == 1
        assert received[0] == b"\xaa\xbb"
        assert wrapper.stats["frame_errors"] >= 1
        assert len(wrapper.rx_frame_buffer) <= MAX_FRAME_SIZE

    def test_bulk_oversize_chunked(self):
        received = []
        wrapper = _make_wrapper(on_frame_received=received.append)
        runaway = bytes([KISS_FEND, KISS_CMD_DATA]) + bytes(MAX_FRAME_SIZE + 50)
        valid = _kiss_encode(KISS_CMD_DATA, b"\x03\x04")
        stream = runaway + valid
        _feed_chunks(wrapper, stream, [7, 600, 50])

        assert len(received) == 1
        assert received[0] == b"\x03\x04"
        assert wrapper.stats["frame_errors"] >= 1
        assert len(wrapper.rx_frame_buffer) <= MAX_FRAME_SIZE

    def test_buffer_never_exceeds_max_during_runaway(self):
        wrapper = _make_wrapper()
        wrapper._decode_kiss_byte(KISS_FEND)
        for _ in range(MAX_FRAME_SIZE + 200):
            wrapper._decode_kiss_byte(0x55)
            assert len(wrapper.rx_frame_buffer) <= MAX_FRAME_SIZE

        assert wrapper.stats["frame_errors"] >= 1
        assert not wrapper.in_frame

    def test_invalid_escape_resync_then_valid(self):
        received = []
        wrapper = _make_wrapper(on_frame_received=received.append)
        bad = bytes([KISS_FEND, KISS_CMD_DATA, KISS_FESC, 0x42, 0x99, KISS_FEND])
        valid = _kiss_encode(KISS_CMD_DATA, b"\x07")
        wrapper._decode_kiss(bad + valid)

        assert len(received) == 1
        assert received[0] == b"\x07"
        assert wrapper.stats["frame_errors"] >= 1

    def test_bytewise_escaped_oversize_then_valid(self):
        """FESC/TFEND floods must hit the same cap as plain-byte runaways."""
        received = []
        wrapper = _make_wrapper(on_frame_received=received.append)
        runaway = bytearray([KISS_FEND, KISS_CMD_DATA])
        for _ in range(MAX_FRAME_SIZE + 200):
            runaway.extend([KISS_FESC, KISS_TFEND])
        valid = _kiss_encode(KISS_CMD_DATA, b"\x11\x22")
        _feed_bytewise(wrapper, bytes(runaway) + valid)

        assert len(received) == 1
        assert received[0] == b"\x11\x22"
        assert wrapper.stats["frame_errors"] >= 1
        assert len(wrapper.rx_frame_buffer) <= MAX_FRAME_SIZE
        assert not wrapper.in_frame or len(wrapper.rx_frame_buffer) <= MAX_FRAME_SIZE

    def test_bulk_escaped_oversize_then_valid(self):
        received = []
        wrapper = _make_wrapper(on_frame_received=received.append)
        runaway = bytes([KISS_FEND, KISS_CMD_DATA]) + bytes([KISS_FESC, KISS_TFEND]) * (
            MAX_FRAME_SIZE + 200
        )
        valid = _kiss_encode(KISS_CMD_DATA, b"\x33")
        wrapper._decode_kiss(runaway + valid)

        assert len(received) == 1
        assert received[0] == b"\x33"
        assert wrapper.stats["frame_errors"] >= 1
        assert len(wrapper.rx_frame_buffer) <= MAX_FRAME_SIZE

    def test_buffer_never_exceeds_max_during_escaped_runaway(self):
        wrapper = _make_wrapper()
        wrapper._decode_kiss_byte(KISS_FEND)
        wrapper._decode_kiss_byte(KISS_CMD_DATA)
        for _ in range(MAX_FRAME_SIZE + 200):
            wrapper._decode_kiss_byte(KISS_FESC)
            wrapper._decode_kiss_byte(KISS_TFEND)
            assert len(wrapper.rx_frame_buffer) <= MAX_FRAME_SIZE

        assert wrapper.stats["frame_errors"] >= 1
        assert not wrapper.in_frame


class TestWaitForRxThreadSafety:
    """wait_for_rx must complete its Future on the event loop, not the RX thread."""

    @pytest.mark.asyncio
    async def test_wait_for_rx_schedules_set_result_on_loop(self):
        wrapper = _make_wrapper()
        payload = b"\x10\x20"

        async def deliver_from_worker():
            # Allow wait_for_rx to install its temp callback first.
            await asyncio.sleep(0)
            # Simulate RX worker thread invoking the callback.
            thread = threading.Thread(
                target=wrapper.on_frame_received,
                args=(payload,),
            )
            thread.start()
            thread.join(timeout=2.0)
            assert not thread.is_alive()

        deliver_task = asyncio.create_task(deliver_from_worker())
        result = await asyncio.wait_for(wrapper.wait_for_rx(), timeout=2.0)
        await deliver_task
        assert result == payload

    @pytest.mark.asyncio
    async def test_wait_for_rx_uses_call_soon_threadsafe(self):
        wrapper = _make_wrapper()
        real_loop = asyncio.get_running_loop()
        mock_loop = MagicMock(wraps=real_loop)
        mock_loop.call_soon_threadsafe = MagicMock(side_effect=real_loop.call_soon_threadsafe)

        with patch("asyncio.get_running_loop", return_value=mock_loop):

            async def deliver():
                await asyncio.sleep(0)
                wrapper.on_frame_received(b"\x01")

            deliver_task = asyncio.create_task(deliver())
            result = await asyncio.wait_for(wrapper.wait_for_rx(), timeout=2.0)
            await deliver_task

        assert result == b"\x01"
        mock_loop.call_soon_threadsafe.assert_called()
        args, _kwargs = mock_loop.call_soon_threadsafe.call_args
        assert args[1] == b"\x01"

    @pytest.mark.asyncio
    async def test_wait_for_rx_fans_out_to_original_callback(self):
        seen = []
        wrapper = _make_wrapper(on_frame_received=seen.append)

        async def deliver():
            await asyncio.sleep(0)
            wrapper.on_frame_received(b"\x55")

        deliver_task = asyncio.create_task(deliver())
        result = await asyncio.wait_for(wrapper.wait_for_rx(), timeout=2.0)
        await deliver_task

        assert result == b"\x55"
        assert seen == [b"\x55"]
        # Callback restored after wait completes
        assert wrapper.on_frame_received == seen.append


class TestSendMetadataContract:
    """Successful queueing must return a metadata mapping (Dispatcher rejects None)."""

    @pytest.mark.asyncio
    async def test_send_returns_empty_dict_on_success(self):
        wrapper = _make_wrapper()
        wrapper.is_connected = True
        result = await wrapper.send(b"\x01\x02\x03")
        assert result == {}
        assert isinstance(result, dict)
        assert len(wrapper.tx_buffer) == 1

    @pytest.mark.asyncio
    async def test_send_raises_when_not_connected(self):
        wrapper = _make_wrapper()
        wrapper.is_connected = False
        with pytest.raises(Exception, match="Failed to send frame"):
            await wrapper.send(b"\x01")


class TestConnectionHealth:
    """connect()/workers/__enter__ must not leave a false-healthy transport."""

    def test_autoconfig_failure_disconnects(self):
        wrapper = _make_wrapper(auto_configure=True)
        mock_serial = MagicMock()
        mock_serial.is_open = True
        mock_serial.read.return_value = b""
        mock_serial.in_waiting = 0

        with (
            patch(
                "openhop_core.hardware.kiss_serial_wrapper.serial.Serial",
                return_value=mock_serial,
            ),
            patch.object(wrapper, "configure_radio_and_enter_kiss", return_value=False),
        ):
            assert wrapper.connect() is False

        assert wrapper.is_connected is False
        assert wrapper.stop_event.is_set()
        mock_serial.close.assert_called()

    def test_tx_worker_fatal_clears_connected(self):
        wrapper = _make_wrapper()
        wrapper.is_connected = True
        wrapper.stop_event.clear()
        conn = MagicMock(is_open=True)
        wrapper.serial_conn = conn
        wrapper.serial_conn.write.side_effect = OSError("broken pipe")
        wrapper.tx_buffer.append(b"\xc0\x00\xc0")

        wrapper._tx_worker()

        assert wrapper.is_connected is False
        assert wrapper.stop_event.is_set()
        conn.close.assert_called()
        assert wrapper.serial_conn is None
        # Further queueing must be rejected once unhealthy
        assert wrapper.send_frame(b"\x01") is False

    def test_rx_worker_fatal_clears_connected(self):
        wrapper = _make_wrapper()
        wrapper.is_connected = True
        wrapper.stop_event.clear()
        conn = MagicMock(is_open=True)
        wrapper.serial_conn = conn
        wrapper.serial_conn.read.side_effect = OSError("device gone")

        wrapper._rx_worker()

        assert wrapper.is_connected is False
        assert wrapper.stop_event.is_set()
        conn.close.assert_called()
        assert wrapper.serial_conn is None

    def test_tx_worker_fatal_closes_port_for_reconnect(self):
        """Worker death must release the fd so a later connect() can reopen the port."""
        wrapper = _make_wrapper()
        wrapper.is_connected = True
        wrapper.stop_event.clear()
        old_serial = MagicMock()
        old_serial.is_open = True
        old_serial.write.side_effect = OSError("broken pipe")
        wrapper.serial_conn = old_serial
        wrapper.tx_buffer.append(b"\xc0\x00\xc0")

        wrapper._tx_worker()

        old_serial.close.assert_called_once()
        # Simulate pyserial after close: is_open becomes False
        old_serial.is_open = False

        new_serial = MagicMock()
        new_serial.is_open = True
        new_serial.read.return_value = b""
        new_serial.in_waiting = 0
        with patch(
            "openhop_core.hardware.kiss_serial_wrapper.serial.Serial",
            return_value=new_serial,
        ):
            assert wrapper.connect() is True

        assert wrapper.is_connected is True
        assert wrapper.serial_conn is new_serial
        assert not wrapper.stop_event.is_set()
        wrapper.disconnect()

    def test_enter_raises_when_connect_fails(self):
        wrapper = _make_wrapper()
        with patch.object(wrapper, "connect", return_value=False):
            with pytest.raises(RuntimeError, match="Failed to connect"):
                wrapper.__enter__()


class TestConfigQueueOrdering:
    """Local config must not change when the TX queue rejects a command."""

    def test_full_queue_leaves_config_unchanged(self):
        wrapper = _make_wrapper()
        wrapper.is_connected = True
        original = wrapper.get_config()["txdelay"]
        # Fill the TX buffer to capacity
        for _ in range(TX_BUFFER_SIZE):
            wrapper.tx_buffer.append(b"\xc0\x00\xc0")

        assert wrapper.send_config_command(KISS_CMD_TXDELAY, original + 10) is False
        assert wrapper.get_config()["txdelay"] == original
        assert wrapper.stats["buffer_overruns"] == 1
        assert len(wrapper.tx_buffer) == TX_BUFFER_SIZE

    def test_successful_queue_updates_config(self):
        wrapper = _make_wrapper()
        wrapper.is_connected = True
        original = wrapper.get_config()["txdelay"]
        new_value = original + 5

        assert wrapper.send_config_command(KISS_CMD_TXDELAY, new_value) is True
        assert wrapper.get_config()["txdelay"] == new_value
        assert len(wrapper.tx_buffer) == 1


class TestStalledSerial:
    def test_connect_write_timeout_is_bounded_and_logged(self, monkeypatch, caplog, stalled_serial):
        wrapper = _make_wrapper(port="/dev/ttyACM0", auto_configure=True)
        handles = []
        open_kwargs = []

        def open_serial(**kwargs):
            open_kwargs.append(kwargs)
            conn = stalled_serial(**kwargs)
            handles.append(conn)
            return conn

        monkeypatch.setattr("openhop_core.hardware.kiss_serial_wrapper.serial.Serial", open_serial)
        result = []
        worker = threading.Thread(target=lambda: result.append(wrapper.connect()), daemon=True)
        started = time.monotonic()
        worker.start()
        try:
            worker.join(timeout=2.8)
            assert not worker.is_alive(), "connect() hung on serial output"
            assert time.monotonic() - started < 2.8
            assert result == [False]
            assert open_kwargs[0]["write_timeout"] == 2.0
            assert not wrapper.is_connected
            assert wrapper.serial_conn is None
            assert not handles[0].is_open
            assert not handles[0].flush_started.is_set()
            warnings = [r.message for r in caplog.records if "modem is not reading" in r.message]
            assert len(warnings) == 1
            assert warnings[0].startswith("Serial write timed out on /dev/ttyACM0")
            assert "boot-looping" in warnings[0]
        finally:
            handles[0].close()
            wrapper.disconnect()
            worker.join(timeout=1)

    @pytest.mark.parametrize("operation", ["configure", "enter", "exit", "cli", "tx", "parameter"])
    def test_every_write_path_marks_transport_failed(
        self,
        monkeypatch,
        caplog,
        stalled_serial,
        operation,
    ):
        monkeypatch.setattr(
            "openhop_core.hardware.kiss_serial_wrapper.SERIAL_WRITE_TIMEOUT_S", 0.03
        )
        wrapper = _make_wrapper(port="/dev/ttyACM0")
        conn = stalled_serial()
        wrapper.serial_conn = conn
        wrapper.is_connected = True
        wrapper.kiss_mode_active = operation == "exit"
        calls = {
            "configure": wrapper._configure_radio,
            "enter": wrapper._enter_kiss_mode,
            "exit": wrapper.exit_kiss_mode,
            "cli": lambda: wrapper.send_cli_command("version"),
            "tx": wrapper._tx_worker,
            "parameter": wrapper._tx_worker,
        }
        if operation == "tx":
            assert wrapper.send_frame(b"payload")
        elif operation == "parameter":
            assert wrapper.send_config_command(KISS_CMD_TXDELAY, 5)
        started = time.monotonic()
        calls[operation]()
        assert time.monotonic() - started < 0.5
        assert not wrapper.is_connected
        assert wrapper.stop_event.is_set()
        assert wrapper.serial_conn is None
        assert not conn.is_open
        assert wrapper.stats["frames_sent"] == 0
        assert not conn.flush_started.is_set()
        warnings = [r.message for r in caplog.records if r.levelname == "WARNING"]
        assert len(warnings) == 1
        assert "modem is not reading" in warnings[0]

    def test_connect_recovers_when_device_reads_again(self, monkeypatch, stalled_serial):
        monkeypatch.setattr(
            "openhop_core.hardware.kiss_serial_wrapper.SERIAL_WRITE_TIMEOUT_S", 0.03
        )
        wrapper = _make_wrapper(auto_configure=True, radio_config={"frequency": 916750000})
        old = stalled_serial()
        new = stalled_serial(stalled=False)
        handles = iter([old, new])
        monkeypatch.setattr(
            "openhop_core.hardware.kiss_serial_wrapper.serial.Serial",
            lambda **kwargs: next(handles),
        )
        try:
            assert wrapper.connect() is False
            assert not old.is_open
            with patch.object(wrapper.stop_event, "wait", return_value=False):
                assert wrapper.connect() is True
            assert wrapper.is_connected
            assert wrapper.is_configured
            assert wrapper.kiss_mode_active
            assert wrapper.serial_conn is new
            assert len(new.writes) == 2
            assert not new.flush_started.is_set()
        finally:
            wrapper.disconnect()

    @pytest.mark.parametrize("during_startup", [False, True])
    def test_disconnect_cancels_stalled_writer_and_reader(
        self,
        monkeypatch,
        stalled_serial,
        during_startup,
    ):
        wrapper = _make_wrapper(auto_configure=during_startup)
        conn = stalled_serial(write_timeout=2)
        monkeypatch.setattr(
            "openhop_core.hardware.kiss_serial_wrapper.serial.Serial",
            lambda **kwargs: conn,
        )
        startup = None
        if during_startup:
            startup = threading.Thread(target=wrapper.connect, daemon=True)
            startup.start()
        else:
            assert wrapper.connect()
            assert wrapper.send_frame(b"payload")
        try:
            assert conn.write_started.wait(1)
            started = time.monotonic()
            wrapper.disconnect()
            if startup:
                startup.join(timeout=0.5)
                assert not startup.is_alive()
            assert time.monotonic() - started < 0.5
            assert not wrapper.rx_thread.is_alive()
            assert not wrapper.tx_thread.is_alive()
            assert not conn.is_open
        finally:
            conn.close()
            wrapper.disconnect()

    def test_partial_writes_share_one_budget(self, monkeypatch, stalled_serial):
        monkeypatch.setattr(
            "openhop_core.hardware.kiss_serial_wrapper.SERIAL_WRITE_TIMEOUT_S", 0.05
        )
        wrapper = _make_wrapper()
        conn = stalled_serial(stalled=False)
        wrapper.serial_conn = conn
        wrapper.is_connected = True
        timeouts = []

        def partial_write(data):
            timeouts.append(conn.write_timeout)
            time.sleep(min(0.015, conn.write_timeout))
            return 1

        conn.write = partial_write
        started = time.monotonic()
        assert wrapper._write_bytes(b"0123456789") is False
        assert time.monotonic() - started < 0.2
        assert len(timeouts) > 1
        assert timeouts[-1] < timeouts[0]
        assert not wrapper.is_connected
