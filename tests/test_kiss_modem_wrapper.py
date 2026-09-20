"""
Tests for MeshCore KISS Modem Wrapper

Tests the KISS frame encoding/decoding, command/response handling,
and LoRaRadio interface implementation.
"""

import gc
import struct
import threading
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from openhop_core.hardware import kiss_modem_wrapper
from openhop_core.hardware.kiss_modem_wrapper import (
    CMD_DATA,
    CMD_GET_BATTERY,
    CMD_GET_NOISE_FLOOR,
    CMD_GET_RADIO,
    CMD_GET_STATS,
    CMD_GET_VERSION,
    CMD_PING,
    CMD_SET_RADIO,
    CMD_SET_TX_POWER,
    CMD_SIGN_DATA,
    HW_CMD_GET_DEVICE_NAME,
    HW_CMD_GET_MCU_TEMP,
    HW_CMD_GET_SIGNAL_REPORT,
    HW_CMD_GET_VERSION,
    HW_CMD_REBOOT,
    HW_CMD_SET_SIGNAL_REPORT,
    HW_ERR_TX_BUSY,
    HW_RESP_DEVICE_NAME,
    HW_RESP_MCU_TEMP,
    HW_RESP_OK,
    HW_RESP_RX_META,
    HW_RESP_SIGNAL_REPORT,
    KISS_CMD_FULLDUPLEX,
    KISS_CMD_PERSISTENCE,
    KISS_CMD_SETHARDWARE,
    KISS_CMD_SLOTTIME,
    KISS_CMD_TXTAIL,
    KISS_FEND,
    KISS_FESC,
    KISS_TFEND,
    KISS_TFESC,
    RESP_BATTERY,
    RESP_ERROR,
    RESP_IDENTITY,
    RESP_NOISE_FLOOR,
    RESP_OK,
    RESP_PONG,
    RESP_RADIO,
    RESP_SIGNATURE,
    RESP_STATS,
    RESP_TX_DONE,
    RESP_VERSION,
    RESPONSE_TIMEOUT,
    RX_META_WAIT_SECONDS,
    KissModemWrapper,
)


class TestKissFrameEncoding:
    """Test KISS frame encoding/decoding"""

    def test_encode_simple_frame(self):
        """Test encoding a simple frame without special characters"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        frame = modem._encode_kiss_frame(CMD_DATA, b"\x01\x02\x03")

        # Should be: FEND + CMD + data + FEND
        assert frame[0] == KISS_FEND
        assert frame[1] == CMD_DATA
        assert frame[2:5] == b"\x01\x02\x03"
        assert frame[5] == KISS_FEND

    def test_encode_frame_with_fend_escape(self):
        """Test encoding a frame containing FEND byte"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        frame = modem._encode_kiss_frame(CMD_DATA, bytes([0xC0]))  # FEND

        # FEND in data should be escaped as FESC + TFEND
        assert frame[0] == KISS_FEND
        assert frame[1] == CMD_DATA
        assert frame[2] == KISS_FESC
        assert frame[3] == KISS_TFEND
        assert frame[4] == KISS_FEND

    def test_encode_frame_with_fesc_escape(self):
        """Test encoding a frame containing FESC byte"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        frame = modem._encode_kiss_frame(CMD_DATA, bytes([0xDB]))  # FESC

        # FESC in data should be escaped as FESC + TFESC
        assert frame[0] == KISS_FEND
        assert frame[1] == CMD_DATA
        assert frame[2] == KISS_FESC
        assert frame[3] == KISS_TFESC
        assert frame[4] == KISS_FEND

    def test_encode_frame_with_multiple_escapes(self):
        """Test encoding a frame with multiple special characters"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        frame = modem._encode_kiss_frame(CMD_DATA, bytes([0xC0, 0xDB, 0xC0]))

        expected = bytes(
            [
                KISS_FEND,
                CMD_DATA,
                KISS_FESC,
                KISS_TFEND,  # escaped 0xC0
                KISS_FESC,
                KISS_TFESC,  # escaped 0xDB
                KISS_FESC,
                KISS_TFEND,  # escaped 0xC0
                KISS_FEND,
            ]
        )
        assert frame == expected

    def test_decode_simple_frame(self):
        """Test decoding Data frame then RxMeta (spec: data and metadata separate)"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        received_frames = []
        modem.on_frame_received = lambda data: received_frames.append(data)

        # Data frame: FEND + 0x00 + raw_packet + FEND (no in-frame metadata)
        data_frame = bytes([KISS_FEND, CMD_DATA, 0x01, 0x02, 0x03, KISS_FEND])
        # RxMeta: FEND + 0x06 + 0xF9 + SNR + RSSI + FEND (sent immediately after Data)
        rx_meta_frame = bytes(
            [KISS_FEND, KISS_CMD_SETHARDWARE, HW_RESP_RX_META, 0x10, 0xB0, KISS_FEND]
        )

        for byte in data_frame:
            modem._decode_kiss_byte(byte)
        for byte in rx_meta_frame:
            modem._decode_kiss_byte(byte)

        assert len(received_frames) == 1
        assert received_frames[0] == b"\x01\x02\x03"

    def test_decode_frame_with_escapes(self):
        """Test decoding Data frame with escaped FEND, then RxMeta"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        received_frames = []
        modem.on_frame_received = lambda data: received_frames.append(data)

        # Data frame: payload is escaped 0xC0 (FESC + TFEND)
        data_frame = bytes([KISS_FEND, CMD_DATA, KISS_FESC, KISS_TFEND, KISS_FEND])
        rx_meta_frame = bytes(
            [KISS_FEND, KISS_CMD_SETHARDWARE, HW_RESP_RX_META, 0x10, 0xB0, KISS_FEND]
        )

        for byte in data_frame:
            modem._decode_kiss_byte(byte)
        for byte in rx_meta_frame:
            modem._decode_kiss_byte(byte)

        assert len(received_frames) == 1
        assert received_frames[0] == bytes([0xC0])

    def test_decode_extracts_rssi_snr(self):
        """Test that RSSI and SNR are extracted from RxMeta frame"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        data_frame = bytes([KISS_FEND, CMD_DATA, 0xAA, 0xBB, KISS_FEND])
        # RxMeta: SNR=0x10 (4.0 dB), RSSI=0xB0 (-80)
        rx_meta_frame = bytes(
            [KISS_FEND, KISS_CMD_SETHARDWARE, HW_RESP_RX_META, 0x10, 0xB0, KISS_FEND]
        )

        for byte in data_frame:
            modem._decode_kiss_byte(byte)
        for byte in rx_meta_frame:
            modem._decode_kiss_byte(byte)

        assert modem.stats["last_snr"] == pytest.approx(4.0)
        assert modem.stats["last_rssi"] == -80

    def test_rx_callback_receives_per_packet_rssi_snr(self):
        """Test that a 3-arg callback receives (data, rssi, snr) per Data+RxMeta pair"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        received = []

        def capture(data, rssi, snr):
            received.append((data, rssi, snr))

        modem.on_frame_received = capture

        # First packet: Data then RxMeta (SNR=4.0 dB, RSSI=-80)
        data1 = bytes([KISS_FEND, CMD_DATA, 0x01, 0x02, KISS_FEND])
        meta1 = bytes([KISS_FEND, KISS_CMD_SETHARDWARE, HW_RESP_RX_META, 0x10, 0xB0, KISS_FEND])
        for byte in data1:
            modem._decode_kiss_byte(byte)
        for byte in meta1:
            modem._decode_kiss_byte(byte)

        # Second packet: Data then RxMeta (SNR=2.0 dB, RSSI=-100)
        data2 = bytes([KISS_FEND, CMD_DATA, 0x03, 0x04, KISS_FEND])
        meta2 = bytes([KISS_FEND, KISS_CMD_SETHARDWARE, HW_RESP_RX_META, 0x08, 0x9C, KISS_FEND])
        for byte in data2:
            modem._decode_kiss_byte(byte)
        for byte in meta2:
            modem._decode_kiss_byte(byte)

        assert len(received) == 2
        assert received[0] == (b"\x01\x02", -80, 4.0)
        assert received[1] == (b"\x03\x04", -100, 2.0)

    def test_data_frame_without_rx_meta_does_not_call_callback(self):
        """Spec: Data frame queues payload; callback only on following RxMeta"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        received = []
        modem.on_frame_received = lambda data: received.append(data)

        # Only Data frame, no RxMeta
        data_frame = bytes([KISS_FEND, CMD_DATA, 0x01, 0x02, 0x03, KISS_FEND])
        for byte in data_frame:
            modem._decode_kiss_byte(byte)

        assert len(received) == 0
        assert len(modem._pending_rx_queue) == 1
        assert modem._pending_rx_queue[0][0] == b"\x01\x02\x03"

    def test_port_one_data_is_queued_as_secondary_profile(self):
        """KISS v2 uses type 0x10 for raw Data received on radio2."""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        received = []
        modem.on_frame_received = lambda data: received.append(data)

        # Type 0x10: port=1, cmd=0 (Data on the secondary profile).
        frame = bytes([KISS_FEND, 0x10, 0x01, 0x02, 0x03, KISS_FEND])
        for byte in frame:
            modem._decode_kiss_byte(byte)

        assert len(received) == 0
        assert len(modem._pending_rx_queue) == 1
        assert modem._pending_rx_queue[0][0] == b"\x01\x02\x03"
        assert modem._pending_rx_queue[0][2] == 1


class TestRxMetaBoundedWait:
    """Data frames must be delivered even when RxMeta never arrives.

    Firmware emits Data unconditionally and RxMeta only when signal reporting is
    enabled, so reception must not be gated on RxMeta. A queued Data frame waits at
    most RX_META_WAIT_SECONDS for its RxMeta, then is flushed with sentinel metrics.
    """

    @staticmethod
    def _feed(modem, frame):
        for byte in frame:
            modem._decode_kiss_byte(byte)

    @staticmethod
    def _expire_pending(modem):
        """Force every queued Data frame's deadline into the past."""
        q = modem._pending_rx_queue
        for i in range(len(q)):
            q[i] = (q[i][0], time.monotonic() - 1.0, q[i][2])

    def test_data_with_prompt_rx_meta_uses_real_metrics(self):
        """Data followed promptly by RxMeta is dispatched with real metrics."""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        received = []
        modem.on_frame_received = lambda d, r, s: received.append((d, r, s))

        self._feed(modem, bytes([KISS_FEND, CMD_DATA, 0x01, 0x02, KISS_FEND]))
        # SNR=0x10 (4.0 dB), RSSI=0xB0 (-80)
        self._feed(
            modem,
            bytes([KISS_FEND, KISS_CMD_SETHARDWARE, HW_RESP_RX_META, 0x10, 0xB0, KISS_FEND]),
        )

        assert received == [(b"\x01\x02", -80, 4.0)]
        assert modem.stats["last_snr"] == pytest.approx(4.0)
        assert modem.stats["last_rssi"] == -80
        assert len(modem._pending_rx_queue) == 0

    def test_flush_does_not_fire_before_deadline(self):
        """A freshly queued Data frame is not flushed while its deadline is in future."""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        received = []
        modem.on_frame_received = lambda d, r, s: received.append((d, r, s))

        self._feed(modem, bytes([KISS_FEND, CMD_DATA, 0x09, KISS_FEND]))
        modem._flush_expired_rx_frames()

        assert received == []
        assert len(modem._pending_rx_queue) == 1

    def test_data_without_rx_meta_flushed_with_sentinel(self):
        """Data with no RxMeta is dispatched after the wait with sentinel metrics.

        rx_packets is counted, but last_snr / last_rssi keep their real values.
        """
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        received = []
        modem.on_frame_received = lambda d, r, s: received.append((d, r, s))

        # Seed known real metrics so we can prove sentinels don't overwrite them.
        modem.stats["last_snr"] = 7.0
        modem.stats["last_rssi"] = -50
        rx_before = modem.stats["rx_packets"]

        self._feed(modem, bytes([KISS_FEND, CMD_DATA, 0x01, 0x02, 0x03, KISS_FEND]))
        self._expire_pending(modem)
        modem._flush_expired_rx_frames()

        assert received == [(b"\x01\x02\x03", -999, -999.0)]
        assert modem.stats["rx_packets"] == rx_before + 1
        assert modem.stats["last_snr"] == 7.0
        assert modem.stats["last_rssi"] == -50
        assert len(modem._pending_rx_queue) == 0

    def test_flush_preserves_arrival_order(self):
        """A timed-out head is delivered before a later Data whose RxMeta is prompt."""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        received = []
        modem.on_frame_received = lambda d, r, s: received.append((d, r, s))

        # DATA1 arrives with no RxMeta and times out.
        self._feed(modem, bytes([KISS_FEND, CMD_DATA, 0x01, KISS_FEND]))
        self._expire_pending(modem)
        modem._flush_expired_rx_frames()

        # DATA2 arrives later with a prompt RxMeta (SNR=2.0 dB, RSSI=-100).
        self._feed(modem, bytes([KISS_FEND, CMD_DATA, 0x02, KISS_FEND]))
        self._feed(
            modem,
            bytes([KISS_FEND, KISS_CMD_SETHARDWARE, HW_RESP_RX_META, 0x08, 0x9C, KISS_FEND]),
        )

        assert [entry[0] for entry in received] == [b"\x01", b"\x02"]
        assert received[0] == (b"\x01", -999, -999.0)
        assert received[1] == (b"\x02", -100, 2.0)

    def test_lost_rx_meta_costs_only_one_packets_metrics(self):
        """One lost RxMeta must not permanently shift metric attribution.

        DATA1's RxMeta is lost; after DATA1 times out, DATA2's RxMeta pairs with
        DATA2 (the new head), so DATA2 gets its own metrics rather than inheriting
        DATA1's leftover.
        """
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        received = []
        modem.on_frame_received = lambda d, r, s: received.append((d, r, s))

        # DATA1 with its RxMeta lost -> flushed sentinel on timeout.
        self._feed(modem, bytes([KISS_FEND, CMD_DATA, 0xAA, KISS_FEND]))
        self._expire_pending(modem)
        modem._flush_expired_rx_frames()

        # DATA2 with its own RxMeta (SNR=4.0 dB, RSSI=-80).
        self._feed(modem, bytes([KISS_FEND, CMD_DATA, 0xBB, KISS_FEND]))
        self._feed(
            modem,
            bytes([KISS_FEND, KISS_CMD_SETHARDWARE, HW_RESP_RX_META, 0x10, 0xB0, KISS_FEND]),
        )

        assert received[0] == (b"\xaa", -999, -999.0)
        assert received[1] == (b"\xbb", -80, 4.0)  # its own metrics, not leftover
        assert len(modem._pending_rx_queue) == 0

    def test_rx_meta_with_empty_queue_is_ignored(self):
        """A leftover RxMeta with nothing pending updates stats but dispatches nothing."""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        received = []
        modem.on_frame_received = lambda d, r, s: received.append((d, r, s))

        self._feed(
            modem,
            bytes([KISS_FEND, KISS_CMD_SETHARDWARE, HW_RESP_RX_META, 0x10, 0xB0, KISS_FEND]),
        )

        assert received == []
        assert len(modem._pending_rx_queue) == 0

    def test_disconnect_clears_pending_rx_queue(self):
        """Reconnect/disconnect must drop stale Data frames so they cannot pair with
        an RxMeta from a later link session."""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        self._feed(modem, bytes([KISS_FEND, CMD_DATA, 0x01, 0x02, KISS_FEND]))
        assert len(modem._pending_rx_queue) == 1

        modem.disconnect()

        assert len(modem._pending_rx_queue) == 0

    def test_bounded_wait_constant_is_subsecond(self):
        """Sanity guard: the RxMeta wait stays short so reception is not stalled."""
        assert 0 < RX_META_WAIT_SECONDS <= 0.5


class TestCommandResponses:
    """Test command sending and response parsing"""

    def test_send_command_encodes_correctly(self):
        """Test that _send_command sends SetHardware frame (FEND + 0x06 + sub_cmd + data + FEND)"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        mock_serial = MagicMock()
        mock_serial.is_open = True
        modem.serial_conn = mock_serial
        modem.is_connected = True

        modem._send_command(CMD_GET_VERSION, timeout=0.1)

        assert mock_serial.write.called
        written_frame = mock_serial.write.call_args[0][0]

        assert written_frame[0] == KISS_FEND
        assert written_frame[1] == KISS_CMD_SETHARDWARE  # type SetHardware
        assert written_frame[2] == HW_CMD_GET_VERSION  # sub_cmd GetVersion
        assert written_frame[-1] == KISS_FEND

    def test_response_parsing_identity(self):
        """Test parsing SetHardware Identity response (FEND + 0x06 + 0x21 + pubkey + FEND)"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        pubkey = bytes(range(32))
        raw_bytes = (
            bytes([KISS_FEND, KISS_CMD_SETHARDWARE, RESP_IDENTITY]) + pubkey + bytes([KISS_FEND])
        )

        for byte in raw_bytes:
            modem._decode_kiss_byte(byte)

        # Without an active waiter, SetHardware responses are queued for later consumption.
        assert len(modem._response_queue) == 1
        assert modem._response_queue[0][0] == RESP_IDENTITY
        assert modem._response_queue[0][1] == pubkey

    def test_response_parsing_error(self):
        """Test parsing SetHardware Error response (FEND + 0x06 + 0x2A + code + FEND)"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        raw_bytes = bytes([KISS_FEND, KISS_CMD_SETHARDWARE, RESP_ERROR, 0x05, KISS_FEND])

        for byte in raw_bytes:
            modem._decode_kiss_byte(byte)

        assert len(modem._response_queue) == 1
        assert modem._response_queue[0][0] == RESP_ERROR
        assert modem._response_queue[0][1][0] == 0x05

    def test_send_command_uses_queued_late_response(self):
        """If a matching response is already queued, _send_command returns it without writing."""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        # Queue a late PONG from a previous ping.
        modem._response_queue.append((RESP_PONG, b""))

        modem._write_frame = MagicMock(return_value=True)

        resp = modem._send_command(CMD_PING, timeout=0.1)
        assert resp == (RESP_PONG, b"")
        assert modem._write_frame.call_count == 0

    def test_send_command_correlates_expected_response(self):
        """Non-matching responses are queued; waiter completes only on expected sub_cmd."""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        # Set up a serial conn so _send_command can write.
        mock_serial = MagicMock()
        mock_serial.is_open = True
        mock_serial.write.side_effect = lambda b: len(b)
        modem.serial_conn = mock_serial

        result_holder: dict[str, object] = {}

        def caller():
            result_holder["resp"] = modem._send_command(CMD_PING, timeout=0.5)

        t = threading.Thread(target=caller)
        t.start()

        # Feed an unrelated identity response first; should be queued, not delivered.
        pubkey = bytes(range(32))
        identity_bytes = (
            bytes([KISS_FEND, KISS_CMD_SETHARDWARE, RESP_IDENTITY]) + pubkey + bytes([KISS_FEND])
        )
        for b in identity_bytes:
            modem._decode_kiss_byte(b)

        # Now feed the expected PONG.
        pong_bytes = bytes([KISS_FEND, KISS_CMD_SETHARDWARE, RESP_PONG, KISS_FEND])
        for b in pong_bytes:
            modem._decode_kiss_byte(b)

        t.join(timeout=1.0)
        assert result_holder.get("resp") == (RESP_PONG, b"")

        # The unrelated identity response should remain queued.
        assert len(modem._response_queue) == 1
        assert modem._response_queue[0][0] == RESP_IDENTITY

    def test_send_command_is_single_flight(self):
        """Concurrent _send_command calls must not interleave shared waiter state."""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        wrote_first = threading.Event()
        allow_first_write = threading.Event()
        wrote_second = threading.Event()

        def mock_write_frame(frame: bytes) -> bool:
            # sub_cmd is the first payload byte (frame[2]) in SetHardware frames.
            if frame[2] == CMD_GET_VERSION:
                wrote_first.set()
                allow_first_write.wait(timeout=1.0)
            elif frame[2] == CMD_PING:
                wrote_second.set()
            return True

        modem._write_frame = mock_write_frame

        results: dict[str, object] = {}

        def call_version():
            results["v"] = modem._send_command(CMD_GET_VERSION, timeout=0.5)

        def call_ping():
            results["p"] = modem._send_command(CMD_PING, timeout=0.5)

        t1 = threading.Thread(target=call_version)
        t2 = threading.Thread(target=call_ping)

        t1.start()
        assert wrote_first.wait(timeout=1.0)

        # Start second call while first is still holding the command lock in _write_frame.
        t2.start()
        assert not wrote_second.wait(timeout=0.1)

        # Let the first command proceed and respond.
        allow_first_write.set()
        version_bytes = bytes([KISS_FEND, KISS_CMD_SETHARDWARE, RESP_VERSION, 0x01, KISS_FEND])
        for b in version_bytes:
            modem._decode_kiss_byte(b)

        # Now second command can write and receive response.
        assert wrote_second.wait(timeout=1.0)
        pong_bytes = bytes([KISS_FEND, KISS_CMD_SETHARDWARE, RESP_PONG, KISS_FEND])
        for b in pong_bytes:
            modem._decode_kiss_byte(b)

        t1.join(timeout=1.0)
        t2.join(timeout=1.0)

        assert results.get("v") is not None
        assert results.get("p") == (RESP_PONG, b"")

    def test_send_command_timeout_clears_waiter_state(self):
        """Timeout path must clear active waiter metadata for later commands."""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True
        modem._write_frame = MagicMock(return_value=True)

        resp = modem._send_command(CMD_GET_VERSION, timeout=0.05)
        assert resp is None
        assert modem._expected_response_subcmds is None
        assert modem._active_request_subcmd is None

        # Ensure no lock leak by issuing another command.
        resp2 = modem._send_command(CMD_PING, timeout=0.05)
        assert resp2 is None
        assert modem._expected_response_subcmds is None
        assert modem._active_request_subcmd is None

    def test_send_command_write_failure_clears_waiter_state(self):
        """Write-failure path must clear active waiter metadata."""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True
        modem._write_frame = MagicMock(return_value=False)

        resp = modem._send_command(CMD_GET_VERSION, timeout=0.1)
        assert resp is None
        assert modem._expected_response_subcmds is None
        assert modem._active_request_subcmd is None

    def test_response_queue_drop_oldest_when_full(self):
        """Unmatched SetHardware responses should drop oldest when queue is full."""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        maxlen = modem._response_queue.maxlen or 0
        for i in range(maxlen):
            modem._response_queue.append((0xA0 + (i % 10), bytes([i % 256])))
        oldest = modem._response_queue[0]

        # No active waiter; incoming response should be enqueued as unmatched.
        frame = bytes([KISS_FEND, KISS_CMD_SETHARDWARE, RESP_IDENTITY, 0x42, KISS_FEND])
        for b in frame:
            modem._decode_kiss_byte(b)

        assert len(modem._response_queue) == maxlen
        assert modem._response_queue[0] != oldest
        assert modem._response_queue[-1] == (RESP_IDENTITY, b"\x42")

    def test_send_command_ok_policy_allowlisted_command(self):
        """Allowlisted SetHardware commands may resolve with HW_RESP_OK."""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True
        mock_serial = MagicMock()
        mock_serial.is_open = True
        mock_serial.write.side_effect = lambda b: len(b)
        modem.serial_conn = mock_serial

        result_holder: dict[str, object] = {}

        def caller():
            result_holder["resp"] = modem._send_command(CMD_SET_TX_POWER, b"\x16", timeout=0.5)

        t = threading.Thread(target=caller)
        t.start()

        ok_frame = bytes([KISS_FEND, KISS_CMD_SETHARDWARE, HW_RESP_OK, KISS_FEND])
        for b in ok_frame:
            modem._decode_kiss_byte(b)

        t.join(timeout=1.0)
        assert result_holder.get("resp") == (HW_RESP_OK, b"")

    def test_send_command_ok_policy_non_allowlisted_command(self):
        """Non-allowlisted commands should not complete on HW_RESP_OK."""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True
        mock_serial = MagicMock()
        mock_serial.is_open = True
        mock_serial.write.side_effect = lambda b: len(b)
        modem.serial_conn = mock_serial

        result_holder: dict[str, object] = {}

        def caller():
            result_holder["resp"] = modem._send_command(CMD_PING, timeout=0.5)

        t = threading.Thread(target=caller)
        t.start()

        ok_frame = bytes([KISS_FEND, KISS_CMD_SETHARDWARE, HW_RESP_OK, KISS_FEND])
        for b in ok_frame:
            modem._decode_kiss_byte(b)

        pong_frame = bytes([KISS_FEND, KISS_CMD_SETHARDWARE, RESP_PONG, KISS_FEND])
        for b in pong_frame:
            modem._decode_kiss_byte(b)

        t.join(timeout=1.0)
        assert result_holder.get("resp") == (RESP_PONG, b"")
        assert len(modem._response_queue) == 1
        assert modem._response_queue[0] == (HW_RESP_OK, b"")

    def test_send_command_preserves_unrelated_response_order(self):
        """Multiple unrelated responses remain queued in arrival order."""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True
        mock_serial = MagicMock()
        mock_serial.is_open = True
        mock_serial.write.side_effect = lambda b: len(b)
        modem.serial_conn = mock_serial

        result_holder: dict[str, object] = {}

        def caller():
            result_holder["resp"] = modem._send_command(CMD_PING, timeout=0.5)

        t = threading.Thread(target=caller)
        t.start()

        identity = bytes([KISS_FEND, KISS_CMD_SETHARDWARE, RESP_IDENTITY, 0xAA, KISS_FEND])
        version = bytes([KISS_FEND, KISS_CMD_SETHARDWARE, RESP_VERSION, 0x01, KISS_FEND])
        stats = bytes([KISS_FEND, KISS_CMD_SETHARDWARE, RESP_STATS, 0x02, KISS_FEND])
        for frame in (identity, version, stats):
            for b in frame:
                modem._decode_kiss_byte(b)

        pong = bytes([KISS_FEND, KISS_CMD_SETHARDWARE, RESP_PONG, KISS_FEND])
        for b in pong:
            modem._decode_kiss_byte(b)

        t.join(timeout=1.0)
        assert result_holder.get("resp") == (RESP_PONG, b"")
        assert [entry[0] for entry in modem._response_queue] == [
            RESP_IDENTITY,
            RESP_VERSION,
            RESP_STATS,
        ]
        assert [entry[1] for entry in modem._response_queue] == [b"\xaa", b"\x01", b"\x02"]

    def test_tx_done_response(self):
        """Test SetHardware TxDone (0xF8) response sets event"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True
        modem._tx_done_event = threading.Event()

        raw_bytes = bytes([KISS_FEND, KISS_CMD_SETHARDWARE, RESP_TX_DONE, 0x01, KISS_FEND])

        for byte in raw_bytes:
            modem._decode_kiss_byte(byte)

        assert modem._tx_done_event.is_set()
        assert modem._tx_done_result is True

    @pytest.mark.asyncio
    async def test_send_offloads_get_airtime_to_thread(self):
        """send() must not call blocking get_airtime on the asyncio event loop."""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True
        modem.send_frame_and_wait = MagicMock(return_value=True)

        async def to_thread_side_effect(fn, *args, **kwargs):
            if to_thread_side_effect.calls == 0:
                to_thread_side_effect.calls += 1
                return True
            to_thread_side_effect.calls += 1
            return 42

        to_thread_side_effect.calls = 0

        to_thread_mock = AsyncMock(side_effect=to_thread_side_effect)
        with patch("openhop_core.hardware.kiss_modem_wrapper.asyncio.to_thread", to_thread_mock):
            result = await modem.send(b"payload")

        assert result is not None
        assert result["airtime_ms"] == 42
        assert to_thread_mock.await_count == 2
        to_thread_mock.assert_any_await(
            modem.send_frame_and_wait, b"payload", RESPONSE_TIMEOUT, verdict=[]
        )
        to_thread_mock.assert_any_await(modem.get_airtime, len(b"payload"), 1.0)


class TestKissAsyncTelemetry:
    """Async-safe telemetry entrypoints delegate blocking work via asyncio.to_thread."""

    @pytest.mark.asyncio
    async def test_get_status_async_delegates_to_thread(self):
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        to_thread_mock = AsyncMock(return_value={"ok": True})
        with patch("openhop_core.hardware.kiss_modem_wrapper.asyncio.to_thread", to_thread_mock):
            result = await modem.get_status_async(1.25)
        assert result == {"ok": True}
        to_thread_mock.assert_awaited_once_with(modem._sync_get_status, 1.25)

    @pytest.mark.asyncio
    async def test_get_noise_floor_async_delegates_to_thread(self):
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        to_thread_mock = AsyncMock(return_value=-95)
        with patch("openhop_core.hardware.kiss_modem_wrapper.asyncio.to_thread", to_thread_mock):
            result = await modem.get_noise_floor_async(0.75)
        assert result == -95
        to_thread_mock.assert_awaited_once_with(modem.get_noise_floor, 0.75)

    @pytest.mark.asyncio
    async def test_get_modem_stats_async_delegates_to_thread(self):
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        stats = {"rx": 1, "tx": 2, "errors": 0}
        to_thread_mock = AsyncMock(return_value=stats)
        with patch("openhop_core.hardware.kiss_modem_wrapper.asyncio.to_thread", to_thread_mock):
            result = await modem.get_modem_stats_async(None)
        assert result == stats
        to_thread_mock.assert_awaited_once_with(modem.get_modem_stats, None)

    def test_get_noise_floor_forwards_timeout_to_send_command(self):
        """Optional timeout on sync getter must reach _send_command."""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True
        calls: list[tuple] = []

        def mock_send_command(cmd, data=b"", timeout=5.0):
            calls.append((cmd, data, timeout))
            if cmd == CMD_GET_NOISE_FLOOR:
                return (RESP_NOISE_FLOOR, struct.pack("<h", -88))
            return None

        modem._send_command = mock_send_command
        assert modem.get_noise_floor(timeout=0.42) == -88
        assert len(calls) == 1
        assert calls[0][0] == CMD_GET_NOISE_FLOOR
        assert calls[0][2] == 0.42


class TestRadioConfiguration:
    """Test radio configuration encoding"""

    def test_radio_config_struct_format(self):
        """Test that radio config is packed correctly"""
        KissModemWrapper(port="/dev/null", auto_configure=False)

        freq_hz = 869618000
        bw_hz = 62500
        sf = 8
        cr = 8

        # This is what configure_radio should pack
        expected = struct.pack("<IIBB", freq_hz, bw_hz, sf, cr)

        assert len(expected) == 10
        # Verify unpacking
        unpacked = struct.unpack("<IIBB", expected)
        assert unpacked == (freq_hz, bw_hz, sf, cr)

    def test_configure_radio_sends_correct_commands(self):
        """Test that configure_radio sends SET_RADIO and SET_TX_POWER"""
        modem = KissModemWrapper(
            port="/dev/null",
            auto_configure=False,
            radio_config={
                "frequency": 869618000,
                "bandwidth": 62500,
                "spreading_factor": 8,
                "coding_rate": 8,
                "power": 22,
            },
        )

        # Track sent commands
        sent_commands = []

        def mock_send_command(cmd, data=b"", timeout=5.0):
            sent_commands.append((cmd, data))
            return (RESP_OK, b"")

        modem._send_command = mock_send_command
        modem.is_connected = True
        modem.serial_conn = MagicMock(is_open=True)

        result = modem.configure_radio()

        assert result is True
        assert len(sent_commands) == 2

        # First command: SET_RADIO
        assert sent_commands[0][0] == CMD_SET_RADIO
        assert len(sent_commands[0][1]) == 10  # 4 + 4 + 1 + 1

        # Second command: SET_TX_POWER
        assert sent_commands[1][0] == CMD_SET_TX_POWER
        assert sent_commands[1][1] == bytes([22])


class TestCryptoOperations:
    """Test cryptographic operation methods"""

    def test_get_random_validates_length(self):
        """Test get_random validates length parameter"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        # Length too small
        assert modem.get_random(0) is None

        # Length too large
        assert modem.get_random(65) is None

    def test_sign_data_sends_correct_command(self):
        """Test sign_data sends correct command"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        signature = bytes(range(64))

        def mock_send_command(cmd, data=b"", timeout=5.0):
            if cmd == CMD_SIGN_DATA:
                return (RESP_SIGNATURE, signature)
            return None

        modem._send_command = mock_send_command
        modem.is_connected = True

        result = modem.sign_data(b"test data")
        assert result == signature

    def test_verify_signature_validates_lengths(self):
        """Test verify_signature validates input lengths"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        # Invalid pubkey length
        assert modem.verify_signature(b"short", bytes(64), b"data") is None

        # Invalid signature length
        assert modem.verify_signature(bytes(32), b"short", b"data") is None

    def test_encrypt_data_validates_key_length(self):
        """Test encrypt_data validates key length"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        # Invalid key length
        assert modem.encrypt_data(b"short_key", b"plaintext") is None

    def test_decrypt_data_validates_lengths(self):
        """Test decrypt_data validates input lengths"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        # Invalid key length
        assert modem.decrypt_data(b"short", bytes(2), b"ciphertext") is None

        # Invalid MAC length
        assert modem.decrypt_data(bytes(32), b"x", b"ciphertext") is None

    def test_key_exchange_validates_pubkey_length(self):
        """Test key_exchange validates pubkey length"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        assert modem.key_exchange(b"short_pubkey") is None


class TestLoRaRadioInterface:
    """Test LoRaRadio interface implementation"""

    def test_set_rx_callback(self):
        """Test setting RX callback"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        callback = MagicMock()
        modem.set_rx_callback(callback)

        assert modem.on_frame_received == callback

    def test_get_last_rssi(self):
        """Test get_last_rssi returns stats value"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.stats["last_rssi"] = -85

        assert modem.get_last_rssi() == -85

    def test_get_last_snr(self):
        """Test get_last_snr returns stats value"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.stats["last_snr"] = 7.5

        assert modem.get_last_snr() == 7.5

    def test_get_stats_returns_copy(self):
        """Test get_stats returns a copy of stats dict"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.stats["frames_sent"] = 100

        stats = modem.get_stats()
        stats["frames_sent"] = 999

        # Original should be unchanged
        assert modem.stats["frames_sent"] == 100


class TestSendFrame:
    """Test send_frame functionality"""

    def test_send_frame_validates_size(self):
        """Test send_frame validates packet size"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        # Too small (< 2 bytes)
        assert modem.send_frame(b"\x00") is False

        # Too large (> 255 bytes)
        assert modem.send_frame(bytes(256)) is False

    def test_send_frame_requires_connection(self):
        """Test send_frame requires connection"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = False

        assert modem.send_frame(b"\x00\x01") is False

    def test_send_frame_queues_to_buffer(self):
        """Test send_frame adds to TX buffer"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        assert len(modem.tx_buffer) == 0

        result = modem.send_frame(b"\x01\x02\x03")

        assert result is True
        assert len(modem.tx_buffer) == 1

        # Verify frame is properly encoded
        frame = modem.tx_buffer[0]
        assert frame[0] == KISS_FEND
        assert frame[1] == CMD_DATA
        assert frame[-1] == KISS_FEND


class TestSerialWriteSerialization:
    """Test UART write serialization across concurrent callers."""

    def test_write_frame_serializes_data_and_sethardware_callers(self):
        """Data TX and SetHardware writes must not interleave at the UART layer."""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        class BlockingSerial:
            def __init__(self):
                self.is_open = True
                self._active = 0
                self.max_active = 0
                self._state_lock = threading.Lock()
                self.first_write_entered = threading.Event()
                self.release_first_write = threading.Event()
                self.first_seen = False
                self.writes = []
                self.flush_count = 0

            def write(self, data):
                with self._state_lock:
                    self._active += 1
                    self.max_active = max(self.max_active, self._active)

                if not self.first_seen:
                    self.first_seen = True
                    self.first_write_entered.set()
                    self.release_first_write.wait(timeout=1.0)

                self.writes.append(bytes(data))

                with self._state_lock:
                    self._active -= 1
                return len(data)

            def flush(self):
                self.flush_count += 1

        serial_conn = BlockingSerial()
        modem.serial_conn = serial_conn
        modem.is_connected = True

        data_frame = modem._encode_kiss_frame(CMD_DATA, b"\x01\x02\x03")
        sethw_frame = modem._encode_kiss_frame(KISS_CMD_SETHARDWARE, bytes([CMD_PING]))

        results: dict[str, bool] = {}
        second_started = threading.Event()
        second_done = threading.Event()

        def write_data():
            results["data"] = modem._write_frame(data_frame)

        def write_sethw():
            second_started.set()
            results["sethw"] = modem._write_frame(sethw_frame)
            second_done.set()

        t1 = threading.Thread(target=write_data)
        t1.start()
        assert serial_conn.first_write_entered.wait(timeout=1.0)

        t2 = threading.Thread(target=write_sethw)
        t2.start()
        assert second_started.wait(timeout=1.0)

        # While the first writer is blocked inside serial.write, a second caller
        # should not enter serial.write concurrently.
        assert not second_done.wait(timeout=0.05)
        assert serial_conn.max_active == 1

        serial_conn.release_first_write.set()

        t1.join(timeout=1.0)
        t2.join(timeout=1.0)

        assert results.get("data") is True
        assert results.get("sethw") is True
        assert serial_conn.max_active == 1
        assert serial_conn.flush_count == 2
        assert serial_conn.writes == [data_frame, sethw_frame]

    def test_ping_and_noise_floor_under_concurrent_data_load(self):
        """Concurrent data TX should not cause ping/noise-floor command timeouts."""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        class RespondingSerial:
            def __init__(self):
                self.is_open = True
                self._modem: KissModemWrapper | None = None
                self.flush_count = 0

            def set_modem(self, m: KissModemWrapper) -> None:
                self._modem = m

            def write(self, data):
                frame = bytes(data)
                if (
                    self._modem is not None
                    and len(frame) >= 4
                    and frame[0] == KISS_FEND
                    and frame[-1] == KISS_FEND
                    and frame[1] == KISS_CMD_SETHARDWARE
                ):
                    sub_cmd = frame[2]
                    if sub_cmd == CMD_PING:
                        response_sub = RESP_PONG
                        response_payload = b""
                    elif sub_cmd == CMD_GET_NOISE_FLOOR:
                        response_sub = RESP_NOISE_FLOOR
                        response_payload = struct.pack("<h", -95)
                    else:
                        response_sub = None
                        response_payload = b""

                    if response_sub is not None:

                        def emit() -> None:
                            resp = (
                                bytes([KISS_FEND, KISS_CMD_SETHARDWARE, response_sub])
                                + response_payload
                                + bytes([KISS_FEND])
                            )
                            for b in resp:
                                self._modem._decode_kiss_byte(b)

                        threading.Thread(target=emit, daemon=True).start()
                return len(frame)

            def flush(self):
                self.flush_count += 1

        serial_conn = RespondingSerial()
        serial_conn.set_modem(modem)
        modem.serial_conn = serial_conn

        stop_event = threading.Event()
        data_frame = modem._encode_kiss_frame(CMD_DATA, b"\xaa\xbb\xcc")

        def data_tx_worker() -> None:
            for _ in range(200):
                if stop_event.is_set():
                    return
                modem._write_frame(data_frame)

        tx_thread = threading.Thread(target=data_tx_worker)
        tx_thread.start()

        try:
            for _ in range(40):
                ping_resp = modem._send_command(CMD_PING, timeout=0.2)
                assert ping_resp is not None
                assert ping_resp[0] == RESP_PONG

                noise = modem.get_noise_floor(timeout=0.2)
                assert noise == -95
        finally:
            stop_event.set()
            tx_thread.join(timeout=1.0)

    def test_tx_worker_and_sethardware_queries_make_progress_together(self):
        """Queued data TX should still make progress while periodic SetHardware queries run."""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        class RespondingSerial:
            def __init__(self):
                self.is_open = True
                self._modem: KissModemWrapper | None = None
                self.flush_count = 0
                self.data_writes = 0

            def set_modem(self, m: KissModemWrapper) -> None:
                self._modem = m

            def write(self, data):
                frame = bytes(data)
                if (
                    self._modem is not None
                    and len(frame) >= 4
                    and frame[0] == KISS_FEND
                    and frame[-1] == KISS_FEND
                    and frame[1] == KISS_CMD_SETHARDWARE
                ):
                    sub_cmd = frame[2]
                    if sub_cmd == CMD_PING:
                        response_sub = RESP_PONG
                        response_payload = b""
                    elif sub_cmd == CMD_GET_NOISE_FLOOR:
                        response_sub = RESP_NOISE_FLOOR
                        response_payload = struct.pack("<h", -92)
                    else:
                        response_sub = None
                        response_payload = b""

                    if response_sub is not None:

                        def emit() -> None:
                            resp = (
                                bytes([KISS_FEND, KISS_CMD_SETHARDWARE, response_sub])
                                + response_payload
                                + bytes([KISS_FEND])
                            )
                            for b in resp:
                                self._modem._decode_kiss_byte(b)

                        threading.Thread(target=emit, daemon=True).start()
                elif len(frame) >= 2 and frame[0] == KISS_FEND and frame[1] == CMD_DATA:
                    self.data_writes += 1

                return len(frame)

            def flush(self):
                self.flush_count += 1

        serial_conn = RespondingSerial()
        serial_conn.set_modem(modem)
        modem.serial_conn = serial_conn

        for _ in range(120):
            assert modem.send_frame(b"\x01\x02\x03")

        modem.stop_event.clear()
        tx_thread = threading.Thread(target=modem._tx_worker, daemon=True)
        tx_thread.start()

        try:
            for _ in range(25):
                ping_resp = modem._send_command(CMD_PING, timeout=0.3)
                assert ping_resp is not None
                assert ping_resp[0] == RESP_PONG

                noise = modem.get_noise_floor(timeout=0.3)
                assert noise == -92

            deadline = time.time() + 2.0
            while modem.tx_buffer and time.time() < deadline:
                time.sleep(0.01)
            assert len(modem.tx_buffer) == 0
            assert serial_conn.data_writes > 0
        finally:
            modem.stop_event.set()
            tx_thread.join(timeout=1.0)

    def test_write_error_does_not_poison_future_writes(self):
        """A serial write error should fail fast and transition to degraded mode."""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        class FlakySerial:
            def __init__(self):
                self.is_open = True
                self.calls = 0
                self.flush_count = 0

            def write(self, data):
                self.calls += 1
                if self.calls == 1:
                    raise OSError("simulated serial failure")
                return len(data)

            def flush(self):
                self.flush_count += 1

        serial_conn = FlakySerial()
        modem.serial_conn = serial_conn
        modem._start_reconnect_worker = MagicMock()

        frame = modem._encode_kiss_frame(CMD_DATA, b"\xaa\xbb")
        assert modem._write_frame(frame) is False
        assert modem._degraded is True
        assert modem.is_connected is False
        modem._start_reconnect_worker.assert_called_once()


class TestQueryMethods:
    """Test modem query methods"""

    def test_get_radio_config_parses_response(self):
        """Test get_radio_config parses response correctly"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        freq = 869618000
        bw = 62500
        sf = 8
        cr = 8
        response_data = struct.pack("<IIBB", freq, bw, sf, cr)

        def mock_send_command(cmd, data=b"", timeout=5.0):
            if cmd == CMD_GET_RADIO:
                return (RESP_RADIO, response_data)
            return None

        modem._send_command = mock_send_command
        modem.is_connected = True

        config = modem.get_radio_config()

        assert config["frequency"] == freq
        assert config["bandwidth"] == bw
        assert config["spreading_factor"] == sf
        assert config["coding_rate"] == cr

    def test_get_modem_stats_parses_response(self):
        """Test get_modem_stats parses response correctly"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        rx = 100
        tx = 50
        errors = 5
        response_data = struct.pack("<III", rx, tx, errors)

        def mock_send_command(cmd, data=b"", timeout=5.0):
            if cmd == CMD_GET_STATS:
                return (RESP_STATS, response_data)
            return None

        modem._send_command = mock_send_command
        modem.is_connected = True

        stats = modem.get_modem_stats()

        assert stats["rx"] == rx
        assert stats["tx"] == tx
        assert stats["errors"] == errors

    def test_get_battery_parses_response(self):
        """Test get_battery parses millivolt response"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        millivolts = 3700
        response_data = struct.pack("<H", millivolts)

        def mock_send_command(cmd, data=b"", timeout=5.0):
            if cmd == CMD_GET_BATTERY:
                return (RESP_BATTERY, response_data)
            return None

        modem._send_command = mock_send_command
        modem.is_connected = True

        result = modem.get_battery()
        assert result == millivolts

    def test_ping_returns_true_on_pong(self):
        """Test ping returns True when modem responds with PONG"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        def mock_send_command(cmd, data=b"", timeout=5.0):
            if cmd == CMD_PING:
                return (RESP_PONG, b"")
            return None

        modem._send_command = mock_send_command
        modem.is_connected = True

        assert modem.ping() is True

    def test_ping_returns_false_on_timeout(self):
        """Test ping returns False on timeout"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        def mock_send_command(cmd, data=b"", timeout=5.0):
            return None  # Simulate timeout

        modem._send_command = mock_send_command
        modem.is_connected = True

        assert modem.ping() is False

    def test_get_mcu_temp_parses_response(self):
        """Test get_mcu_temp parses signed int16 tenths of °C"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        # 253 tenths = 25.3 °C
        response_data = struct.pack("<h", 253)

        def mock_send_command(cmd, data=b"", timeout=5.0):
            if cmd == HW_CMD_GET_MCU_TEMP:
                return (HW_RESP_MCU_TEMP, response_data)
            return None

        modem._send_command = mock_send_command
        modem.is_connected = True

        assert modem.get_mcu_temp() == pytest.approx(25.3)

    def test_get_mcu_temp_returns_none_on_no_callback_error(self):
        """Test get_mcu_temp returns None when modem returns NoCallback error"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        def mock_send_command(cmd, data=b"", timeout=5.0):
            if cmd == HW_CMD_GET_MCU_TEMP:
                return (RESP_ERROR, bytes([0x03]))  # HW_ERR_NO_CALLBACK
            return None

        modem._send_command = mock_send_command
        modem.is_connected = True

        assert modem.get_mcu_temp() is None

    def test_get_device_name_parses_utf8(self):
        """Test get_device_name returns UTF-8 decoded string"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        name = "TestDevice"
        response_data = name.encode("utf-8")

        def mock_send_command(cmd, data=b"", timeout=5.0):
            if cmd == HW_CMD_GET_DEVICE_NAME:
                return (HW_RESP_DEVICE_NAME, response_data)
            return None

        modem._send_command = mock_send_command
        modem.is_connected = True

        assert modem.get_device_name() == "TestDevice"

    def test_reboot_sends_command(self):
        """Test reboot sends HW_CMD_REBOOT SetHardware command"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        sent = []

        def mock_send_command(cmd, data=b"", timeout=5.0):
            sent.append((cmd, data))
            return (HW_RESP_OK, b"")

        modem._send_command = mock_send_command
        modem.is_connected = True

        modem.reboot()

        assert len(sent) == 1
        assert sent[0][0] == HW_CMD_REBOOT
        assert sent[0][1] == b""


class TestEventLoop:
    """Test event loop integration for thread-safe async"""

    def test_set_event_loop(self):
        """Test setting event loop"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        loop = MagicMock()

        modem.set_event_loop(loop)

        assert modem._event_loop is loop

    def test_dispatch_uses_event_loop_when_set(self):
        """Test that dispatch uses call_soon_threadsafe when loop is set"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        loop = MagicMock()
        modem.set_event_loop(loop)

        callback = MagicMock()
        modem.on_frame_received = callback

        modem._dispatch_rx_callback(b"test", -80, 4.0)

        # Should have called call_soon_threadsafe
        loop.call_soon_threadsafe.assert_called_once()

    def test_dispatch_direct_when_no_event_loop(self):
        """Test that dispatch invokes callback directly when no loop set"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        received = []

        def callback(data, rssi, snr):
            received.append((data, rssi, snr))

        modem.on_frame_received = callback

        modem._dispatch_rx_callback(b"test", -80, 4.0)

        assert len(received) == 1
        assert received[0] == (b"test", -80, 4.0)


class TestRadioConfigCompatibility:
    """Test radio config key compatibility"""

    def test_power_key(self):
        """Test that 'power' key is used"""
        modem = KissModemWrapper(
            port="/dev/null",
            auto_configure=False,
            radio_config={"power": 15},
        )

        sent_commands = []

        def mock_send_command(cmd, data=b"", timeout=5.0):
            sent_commands.append((cmd, data))
            return (RESP_OK, b"")

        modem._send_command = mock_send_command
        modem.is_connected = True
        modem.serial_conn = MagicMock(is_open=True)

        modem.configure_radio()

        # Find SET_TX_POWER command
        tx_power_cmd = next((c for c in sent_commands if c[0] == CMD_SET_TX_POWER), None)
        assert tx_power_cmd is not None
        assert tx_power_cmd[1] == bytes([15])

    def test_tx_power_key_fallback(self):
        """Test that 'tx_power' key is used when 'power' is not present"""
        modem = KissModemWrapper(
            port="/dev/null",
            auto_configure=False,
            radio_config={"tx_power": 20},
        )

        sent_commands = []

        def mock_send_command(cmd, data=b"", timeout=5.0):
            sent_commands.append((cmd, data))
            return (RESP_OK, b"")

        modem._send_command = mock_send_command
        modem.is_connected = True
        modem.serial_conn = MagicMock(is_open=True)

        modem.configure_radio()

        # Find SET_TX_POWER command
        tx_power_cmd = next((c for c in sent_commands if c[0] == CMD_SET_TX_POWER), None)
        assert tx_power_cmd is not None
        assert tx_power_cmd[1] == bytes([20])

    def test_power_takes_precedence_over_tx_power(self):
        """Test that 'power' takes precedence over 'tx_power'"""
        modem = KissModemWrapper(
            port="/dev/null",
            auto_configure=False,
            radio_config={"power": 10, "tx_power": 20},
        )

        sent_commands = []

        def mock_send_command(cmd, data=b"", timeout=5.0):
            sent_commands.append((cmd, data))
            return (RESP_OK, b"")

        modem._send_command = mock_send_command
        modem.is_connected = True
        modem.serial_conn = MagicMock(is_open=True)

        modem.configure_radio()

        # Find SET_TX_POWER command - should use 'power' value
        tx_power_cmd = next((c for c in sent_commands if c[0] == CMD_SET_TX_POWER), None)
        assert tx_power_cmd is not None
        assert tx_power_cmd[1] == bytes([10])


class TestKissTuningMethods:
    """Test KISS config commands: persistence, slottime, txtail, full_duplex, signal report"""

    def test_set_kiss_persistence_sends_correct_frame(self):
        """Test set_kiss_persistence sends KISS_CMD_PERSISTENCE with value 0-255"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        written = []

        def capture_write(frame):
            written.append(bytes(frame))
            return True

        modem._write_frame = capture_write
        modem.is_connected = True

        result = modem.set_kiss_persistence(63)
        assert result is True
        assert len(written) == 1
        # FEND + 0x02 + 0x3F + FEND
        assert written[0][0] == KISS_FEND
        assert written[0][1] == KISS_CMD_PERSISTENCE
        assert written[0][2] == 63
        assert written[0][3] == KISS_FEND

    def test_set_kiss_persistence_clamps_value(self):
        """Test set_kiss_persistence clamps to 0-255"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        written = []

        def capture_write(frame):
            written.append(bytes(frame))
            return True

        modem._write_frame = capture_write
        modem.is_connected = True

        modem.set_kiss_persistence(300)
        assert written[0][2] == 255
        written.clear()
        modem.set_kiss_persistence(-1)
        assert written[0][2] == 0

    def test_set_kiss_slottime_sends_correct_frame(self):
        """Test set_kiss_slottime sends KISS_CMD_SLOTTIME with value in 10ms units"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        written = []

        def capture_write(frame):
            written.append(bytes(frame))
            return True

        modem._write_frame = capture_write
        modem.is_connected = True

        result = modem.set_kiss_slottime(100)
        assert result is True
        assert len(written) == 1
        assert written[0][0] == KISS_FEND
        assert written[0][1] == KISS_CMD_SLOTTIME
        assert written[0][2] == 10  # 100ms / 10
        assert written[0][3] == KISS_FEND

    def test_set_kiss_txtail_sends_correct_frame(self):
        """Test set_kiss_txtail sends KISS_CMD_TXTAIL with value in 10ms units"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        written = []

        def capture_write(frame):
            written.append(bytes(frame))
            return True

        modem._write_frame = capture_write
        modem.is_connected = True

        result = modem.set_kiss_txtail(50)
        assert result is True
        assert written[0][1] == KISS_CMD_TXTAIL
        assert written[0][2] == 5  # 50ms / 10

    def test_set_kiss_full_duplex_sends_correct_frame(self):
        """Test set_kiss_full_duplex sends KISS_CMD_FULLDUPLEX 0x01 or 0x00"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        written = []

        def capture_write(frame):
            written.append(bytes(frame))
            return True

        modem._write_frame = capture_write
        modem.is_connected = True

        modem.set_kiss_full_duplex(True)
        assert written[0][1] == KISS_CMD_FULLDUPLEX
        assert written[0][2] == 0x01
        written.clear()
        modem.set_kiss_full_duplex(False)
        assert written[0][2] == 0x00

    def test_set_signal_report_round_trip_via_real_send_command(self):
        """Firmware answers SET_SIGNAL_REPORT (0x19) with HW_RESP_SIGNAL_REPORT (0x9A).

        Drive the real _send_command so the acceptable-response set is exercised:
        the 0x9A reply must complete the waiter (no 5s timeout), set_signal_report
        must return True, and nothing may be left stranded in _response_queue.
        """
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        mock_serial = MagicMock()
        mock_serial.is_open = True
        mock_serial.write.side_effect = lambda b: len(b)
        modem.serial_conn = mock_serial

        result_holder: dict[str, object] = {}

        def caller():
            result_holder["resp"] = modem.set_signal_report(True)

        t = threading.Thread(target=caller)
        started = time.monotonic()
        t.start()

        # Synthetic 0x9A reply carrying the enabled flag, fed through real parsing.
        reply = bytes([KISS_FEND, KISS_CMD_SETHARDWARE, HW_RESP_SIGNAL_REPORT, 0x01, KISS_FEND])
        for b in reply:
            modem._decode_kiss_byte(b)

        t.join(timeout=2.0)
        elapsed = time.monotonic() - started

        assert result_holder.get("resp") is True
        assert elapsed < RESPONSE_TIMEOUT  # completed on the reply, not a timeout
        assert len(modem._response_queue) == 0  # 0x9A consumed, nothing stray left

    def test_set_signal_report_returns_true_on_ok(self):
        """Test set_signal_report returns True when modem responds HW_RESP_OK"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        def mock_send_command(cmd, data=b"", timeout=5.0):
            if cmd == HW_CMD_SET_SIGNAL_REPORT:
                return (HW_RESP_OK, b"")
            return None

        modem._send_command = mock_send_command
        modem.is_connected = True

        assert modem.set_signal_report(True) is True

    def test_set_signal_report_returns_false_on_error_or_timeout(self):
        """Test set_signal_report returns False on error or timeout"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        def mock_send_command(cmd, data=b"", timeout=5.0):
            return None

        modem._send_command = mock_send_command
        modem.is_connected = True

        assert modem.set_signal_report(True) is False

    def test_get_signal_report_returns_true_when_enabled(self):
        """Test get_signal_report returns True when modem reports enabled"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        def mock_send_command(cmd, data=b"", timeout=5.0):
            if cmd == HW_CMD_GET_SIGNAL_REPORT:
                return (HW_RESP_SIGNAL_REPORT, bytes([0x01]))
            return None

        modem._send_command = mock_send_command
        modem.is_connected = True

        assert modem.get_signal_report() is True

    def test_get_signal_report_returns_false_when_disabled(self):
        """Test get_signal_report returns False when modem reports disabled"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        def mock_send_command(cmd, data=b"", timeout=5.0):
            if cmd == HW_CMD_GET_SIGNAL_REPORT:
                return (HW_RESP_SIGNAL_REPORT, bytes([0x00]))
            return None

        modem._send_command = mock_send_command
        modem.is_connected = True

        assert modem.get_signal_report() is False

    def test_get_signal_report_returns_none_on_timeout(self):
        """Test get_signal_report returns None on timeout or error"""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        def mock_send_command(cmd, data=b"", timeout=5.0):
            return None

        modem._send_command = mock_send_command
        modem.is_connected = True

        assert modem.get_signal_report() is None


class TestContextManager:
    """Test context manager functionality"""

    def test_context_manager_calls_connect_disconnect(self):
        """Test context manager calls connect and disconnect"""
        # Drain finalizers from GC-collectable modems left by earlier tests so their
        # __del__ -> cleanup -> disconnect does not land inside the patch window below
        # and inflate the call count.
        gc.collect()
        with patch.object(KissModemWrapper, "connect", return_value=True) as mock_connect:
            with patch.object(KissModemWrapper, "disconnect") as mock_disconnect:
                with KissModemWrapper(port="/dev/null", auto_configure=False) as modem:
                    pass  # keep reference so __del__ doesn't run before assert

                mock_connect.assert_called_once()
                mock_disconnect.assert_called_once()
                _ = modem  # hold ref so __del__ runs after assert, not before


class TestAsyncSendTxDone:
    """Test async send() TX_DONE confirmation behavior."""

    @pytest.mark.asyncio
    async def test_send_returns_metadata_after_tx_done(self):
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True
        modem.lbt_enabled = False
        modem.send_frame_and_wait = MagicMock(return_value=True)
        modem.get_airtime = MagicMock(return_value=123)

        result = await modem.send(b"\x01\x02\x03\x04")

        assert result["airtime_ms"] == 123
        assert result["lbt_attempts"] == 0
        modem.send_frame_and_wait.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_raises_when_tx_done_not_received(self):
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True
        modem.lbt_enabled = False
        modem.send_frame_and_wait = MagicMock(return_value=False)

        with pytest.raises(Exception, match="TX_DONE"):
            await modem.send(b"\x01\x02\x03\x04")


class TestShutdownAndConnectResilience:
    def test_cleanup_sets_abort_flags_and_disconnects(self):
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem._response_event.clear()
        modem._tx_done_event.clear()

        with patch.object(modem, "disconnect") as mock_disconnect:
            modem.cleanup()

        assert modem._shutting_down is True
        assert modem._response_event.is_set() is True
        assert modem._tx_done_event.is_set() is True
        mock_disconnect.assert_called_once()

    def test_send_command_returns_none_while_shutting_down(self):
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem._shutting_down = True
        assert modem._send_command(CMD_GET_VERSION, timeout=0.1) is None

    def test_wait_for_modem_ready_retries_until_pong(self):
        modem = KissModemWrapper(
            port="/dev/serial/by-id/test",
            auto_configure=False,
            connect_retries=3,
            post_open_delay_ms=0,
            startup_retry_budget_sec=30.0,
        )
        serial_conn = MagicMock()
        serial_conn.is_open = True
        modem.serial_conn = serial_conn

        responses = [None, None, (RESP_PONG, b"")]

        def _fake_send_command(_cmd, data=b"", timeout=1.0):
            return responses.pop(0)

        modem._send_command = _fake_send_command

        with patch("threading.Event.wait", return_value=None):
            assert modem._wait_for_modem_ready() is True

        assert modem.serial_conn.write.called
        assert modem.serial_conn.flush.called

    def test_configure_radio_with_retries_eventually_succeeds(self):
        modem = KissModemWrapper(
            port="/dev/null",
            auto_configure=False,
            connect_retries=3,
            startup_retry_budget_sec=30.0,
        )

        with (
            patch.object(modem, "configure_radio", side_effect=[False, False, True]) as mock_cfg,
            patch("threading.Event.wait", return_value=None),
        ):
            assert modem._configure_radio_with_retries() is True

        assert mock_cfg.call_count == 3


class TestSerialRecovery:
    """Test serial degraded-state and reconnect behavior."""

    def test_write_frame_marks_degraded_and_triggers_reconnect(self):
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        class _FailingSerial:
            is_open = True

            def write(self, _data):
                raise OSError(5, "Input/output error")

        modem.serial_conn = _FailingSerial()
        modem._start_reconnect_worker = MagicMock()

        frame = modem._encode_kiss_frame(CMD_DATA, b"\x01\x02")
        assert modem._write_frame(frame) is False
        assert modem._degraded is True
        assert modem.is_connected is False
        assert modem.serial_conn is None
        modem._start_reconnect_worker.assert_called_once()

    def test_send_command_fails_fast_while_reconnecting(self):
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True
        modem._reconnecting_event.set()
        modem._write_frame = MagicMock(return_value=True)

        assert modem._send_command(CMD_PING, timeout=0.1) is None
        modem._write_frame.assert_not_called()

    def test_send_command_allowed_from_reconnect_thread_during_reconnect(self):
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True
        modem._reconnecting_event.set()
        modem.reconnect_thread = threading.current_thread()
        modem._response_queue.append((RESP_PONG, b""))

        assert modem._send_command(CMD_PING, timeout=0.1) == (RESP_PONG, b"")

    def test_send_command_allowed_from_reconnect_thread_while_degraded(self):
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True
        modem._degraded = True
        modem.reconnect_thread = threading.current_thread()
        modem._response_queue.append((RESP_PONG, b""))

        assert modem._send_command(CMD_PING, timeout=0.1) == (RESP_PONG, b"")

    def test_reconnect_worker_recovers_after_open_failure(self):
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem._reconnecting_event.set()
        modem._degraded = True
        modem._degraded_reason = "test failure"
        modem._reconnect_base_delay_s = 0.0
        modem._reconnect_max_delay_s = 0.0

        modem._open_serial_and_start_threads = MagicMock(side_effect=[False, True])
        modem._run_post_connect_handshake = MagicMock(return_value=True)
        modem._stop_io_threads = MagicMock()

        with patch("openhop_core.hardware.kiss_modem_wrapper.time.sleep", return_value=None):
            modem._reconnect_worker()

        assert modem._open_serial_and_start_threads.call_count == 2
        assert modem._run_post_connect_handshake.call_count == 1
        assert modem._degraded is False
        assert modem._reconnecting_event.is_set() is False

    def test_start_reconnect_worker_guard_prevents_duplicate_thread(self):
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem._reconnecting_event.set()
        modem._start_reconnect_worker()
        assert modem.reconnect_thread is None

    def test_mark_serial_failure_does_not_deadlock_with_reconnect_lock_order(self):
        """A failed command must not wait for a reconnect handshake's lock.

        An ordinary SetHardware caller holds _command_lock when its UART write
        fails. A reconnect worker holds _connection_lock while it starts its
        handshake and then needs _command_lock. Blocking failure handling creates
        an ABBA deadlock; the failure transition must return promptly instead.
        """
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        # Prevent the failure path from starting a real background reconnect.
        modem._reconnecting_event.set()

        command_held = threading.Event()
        connection_held = threading.Event()
        reconnect_waiting_on_command = threading.Event()
        failure_returned = threading.Event()
        reconnect_acquired_command = threading.Event()

        def failed_command():
            with modem._command_lock:
                command_held.set()
                assert connection_held.wait(1.0)
                modem._mark_serial_failure("simulated overlapping write failure")
                failure_returned.set()

        def reconnect_handshake():
            assert command_held.wait(1.0)
            with modem._connection_lock:
                connection_held.set()
                reconnect_waiting_on_command.set()
                with modem._command_lock:
                    reconnect_acquired_command.set()

        command_thread = threading.Thread(target=failed_command, daemon=True)
        reconnect_thread = threading.Thread(target=reconnect_handshake, daemon=True)
        command_thread.start()
        reconnect_thread.start()

        assert reconnect_waiting_on_command.wait(1.0)
        assert failure_returned.wait(0.5)
        assert reconnect_acquired_command.wait(0.5)
        command_thread.join(timeout=0.5)
        reconnect_thread.join(timeout=0.5)
        assert not command_thread.is_alive()
        assert not reconnect_thread.is_alive()

    def test_mark_serial_failure_does_not_deadlock_with_reconnect_write(self):
        """A failed UART write must not wait for a reconnect UART write.

        _write_frame holds _serial_write_lock while it invokes failure handling.
        A reconnect handshake holds _connection_lock while it waits to write its
        PING. Waiting for _connection_lock in the failure path would deadlock the
        two workers just as it does for SetHardware's _command_lock.
        """
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem._reconnecting_event.set()
        serial_conn = MagicMock()
        serial_conn.is_open = True
        serial_conn.write.side_effect = lambda data: len(data)
        modem.serial_conn = serial_conn

        connection_held = threading.Event()
        serial_write_held = threading.Event()
        failure_returned = threading.Event()
        reconnect_wrote = threading.Event()

        def failed_write():
            with modem._serial_write_lock:
                serial_write_held.set()
                assert connection_held.wait(1.0)
                modem._mark_serial_failure("simulated overlapping write failure")
                failure_returned.set()

        def reconnect_handshake():
            with modem._connection_lock:
                connection_held.set()
                assert serial_write_held.wait(1.0)
                assert modem._write_frame(b"reconnect ping") is True
                reconnect_wrote.set()

        failed_thread = threading.Thread(target=failed_write, daemon=True)
        reconnect_thread = threading.Thread(target=reconnect_handshake, daemon=True)
        failed_thread.start()
        reconnect_thread.start()

        assert failure_returned.wait(0.5)
        assert reconnect_wrote.wait(0.5)
        failed_thread.join(timeout=0.5)
        reconnect_thread.join(timeout=0.5)
        assert not failed_thread.is_alive()
        assert not reconnect_thread.is_alive()

    def test_reconnect_worker_clears_gate_after_unexpected_exception(self):
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem._reconnecting_event.set()
        modem._reconnect_loop = MagicMock(side_effect=RuntimeError("simulated reconnect error"))

        modem._reconnect_worker()

        assert modem._reconnecting_event.is_set() is False

    def test_connect_clears_reconnecting_gate_after_success(self):
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem._reconnecting_event.set()
        modem._open_serial_and_start_threads = MagicMock(return_value=True)
        modem._run_post_connect_handshake = MagicMock(return_value=True)

        assert modem.connect() is True
        assert modem.is_connected is True
        assert modem._reconnecting_event.is_set() is False

    def test_connect_sets_connected_only_after_handshake_success(self):
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem._open_serial_and_start_threads = MagicMock(return_value=True)

        def handshake() -> bool:
            # is_connected should stay false until handshake fully succeeds.
            assert modem.is_connected is False
            return True

        modem._run_post_connect_handshake = MagicMock(side_effect=handshake)

        assert modem.connect() is True
        assert modem.is_connected is True

    def test_connect_handshake_failure_leaves_disconnected(self):
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem._open_serial_and_start_threads = MagicMock(return_value=True)
        modem._run_post_connect_handshake = MagicMock(return_value=False)
        modem._close_serial_connection = MagicMock()

        assert modem.connect() is False
        assert modem.is_connected is False
        modem._close_serial_connection.assert_called_once()

    def test_connect_retries_transient_configure_failure_then_succeeds(self):
        modem = KissModemWrapper(
            port="/dev/null",
            auto_configure=True,
            radio_config={"frequency": 869618000},
        )
        modem._open_serial_and_start_threads = MagicMock(return_value=True)
        modem._close_serial_connection = MagicMock()
        modem._query_modem_info = MagicMock()
        modem._set_kiss_tx_delay = MagicMock()

        connected_states = []

        def transient_configure_failure() -> bool:
            connected_states.append(modem.is_connected)
            return len(connected_states) > 1

        modem.configure_radio = MagicMock(side_effect=transient_configure_failure)

        with (
            patch(
                "openhop_core.hardware.kiss_modem_wrapper.time.sleep", return_value=None
            ) as sleep_mock,
            patch("threading.Event.wait", return_value=None),
        ):
            assert modem.connect() is True

        assert modem.configure_radio.call_count == 2
        assert connected_states == [False, False]
        assert modem.is_connected is True
        assert modem._close_serial_connection.call_count == 0
        assert len(sleep_mock.call_args_list) == 1  # post-connect settle only

    def test_connect_persistent_configure_failures_still_fail(self):
        modem = KissModemWrapper(
            port="/dev/null",
            auto_configure=True,
            radio_config={"frequency": 869618000},
        )
        modem._open_serial_and_start_threads = MagicMock(return_value=True)
        modem._close_serial_connection = MagicMock()
        modem._query_modem_info = MagicMock()
        modem._set_kiss_tx_delay = MagicMock()
        modem.configure_radio = MagicMock(return_value=False)

        with (
            patch("openhop_core.hardware.kiss_modem_wrapper.time.sleep", return_value=None),
            patch("threading.Event.wait", return_value=None),
        ):
            assert modem.connect() is False

        assert modem.is_connected is False
        assert modem.configure_radio.call_count == modem.connect_retries
        modem._close_serial_connection.assert_called_once()

    def test_connect_sets_connected_only_after_retrying_handshake(self):
        modem = KissModemWrapper(
            port="/dev/null",
            auto_configure=True,
            radio_config={"frequency": 869618000},
        )
        modem._open_serial_and_start_threads = MagicMock(return_value=True)
        modem._close_serial_connection = MagicMock()
        modem._query_modem_info = MagicMock()
        modem._set_kiss_tx_delay = MagicMock()

        observed_states = []

        def configure_with_one_retry() -> bool:
            observed_states.append(modem.is_connected)
            return len(observed_states) >= 2

        modem.configure_radio = MagicMock(side_effect=configure_with_one_retry)

        with patch("openhop_core.hardware.kiss_modem_wrapper.time.sleep", return_value=None):
            assert modem.connect() is True

        assert observed_states == [False, False]
        assert modem.is_connected is True

    def test_reconnect_sets_connected_only_after_handshake_success(self):
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem._reconnecting_event.set()
        modem._degraded = True
        modem._degraded_reason = "test failure"
        modem._reconnect_base_delay_s = 0.0
        modem._reconnect_max_delay_s = 0.0
        modem._open_serial_and_start_threads = MagicMock(return_value=True)

        def reconnect_handshake() -> bool:
            assert modem.is_connected is False
            return True

        modem._run_post_connect_handshake = MagicMock(side_effect=reconnect_handshake)
        modem._stop_io_threads = MagicMock()

        with patch("openhop_core.hardware.kiss_modem_wrapper.time.sleep", return_value=None):
            modem._reconnect_worker()

        assert modem.is_connected is True
        assert modem._degraded is False
        assert modem._reconnecting_event.is_set() is False


class TestKissDataTxSingleFlight:
    """DATA transmits are single-flight; only TX_DONE decides the outcome."""

    def test_send_frame_and_wait_is_single_flight(self):
        """A second DATA frame must not be written while the first is in flight."""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        first_sent = threading.Event()
        second_sent = threading.Event()
        order: list[str] = []

        def mock_send_frame(data: bytes) -> bool:
            if data == b"AA":
                order.append("A")
                first_sent.set()
            elif data == b"BB":
                order.append("B")
                second_sent.set()
            return True

        modem.send_frame = mock_send_frame

        results: dict[str, object] = {}
        t1 = threading.Thread(
            target=lambda: results.__setitem__("a", modem.send_frame_and_wait(b"AA", timeout=2.0))
        )
        t1.start()
        assert first_sent.wait(timeout=1.0)

        # B must block on the in-flight lock while A awaits TX_DONE.
        t2 = threading.Thread(
            target=lambda: results.__setitem__("b", modem.send_frame_and_wait(b"BB", timeout=2.0))
        )
        t2.start()
        assert not second_sent.wait(timeout=0.2)

        tx_done = bytes([KISS_FEND, KISS_CMD_SETHARDWARE, RESP_TX_DONE, 0x01, KISS_FEND])
        for byte in tx_done:  # complete A -> releases the lock
            modem._decode_kiss_byte(byte)

        assert second_sent.wait(timeout=1.0)
        for byte in tx_done:  # complete B
            modem._decode_kiss_byte(byte)

        t1.join(timeout=1.0)
        t2.join(timeout=1.0)
        assert results.get("a") is True
        assert results.get("b") is True
        assert order == ["A", "B"]

    def test_tx_busy_does_not_fail_a_transmit_the_modem_confirms(self):
        """A TX_DONE arriving behind a TX_BUSY still confirms the send.

        Firmware emits the same 0x07 when its 2-slot host-output queue overflows -- a
        receive-side condition. Failing the send on it reported failure for frames that
        went out fine whenever inbound traffic backed the modem up.
        """
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        sent = threading.Event()
        modem.send_frame = lambda data: sent.set() or True

        result: dict[str, object] = {}
        t = threading.Thread(
            target=lambda: result.__setitem__("r", modem.send_frame_and_wait(b"AA", timeout=5.0))
        )
        t.start()
        assert sent.wait(timeout=1.0)

        err = bytes([KISS_FEND, KISS_CMD_SETHARDWARE, RESP_ERROR, HW_ERR_TX_BUSY, KISS_FEND])
        for byte in err:
            modem._decode_kiss_byte(byte)

        time.sleep(0.15)  # outlast a poll slice: TX_BUSY must not end the wait
        assert not result

        tx_done = bytes([KISS_FEND, KISS_CMD_SETHARDWARE, RESP_TX_DONE, 0x01, KISS_FEND])
        for byte in tx_done:
            modem._decode_kiss_byte(byte)

        t.join(timeout=1.0)
        assert result.get("r") is True
        assert modem.stats["tx_busy"] == 1  # counted, so backpressure stays visible
        assert len(modem._response_queue) == 0  # not consumed by the SetHardware waiter

    def test_tx_busy_without_tx_done_leaves_the_send_unconfirmed(self):
        """With no TX_DONE behind it, TX_BUSY still fails the send -- and says why."""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        sent = threading.Event()
        modem.send_frame = lambda data: sent.set() or True

        result: dict[str, object] = {}
        t = threading.Thread(
            target=lambda: result.__setitem__("r", modem.send_frame_and_wait(b"AA", timeout=0.2))
        )
        t.start()
        assert sent.wait(timeout=1.0)

        err = bytes([KISS_FEND, KISS_CMD_SETHARDWARE, RESP_ERROR, HW_ERR_TX_BUSY, KISS_FEND])
        for byte in err:
            modem._decode_kiss_byte(byte)

        t.join(timeout=5.0)
        assert result.get("r") is False
        assert "TX_BUSY" in (modem._tx_last_verdict or "")
        assert len(modem._response_queue) == 0

    def test_tx_done_failure_status_is_reported_as_the_modems_verdict(self):
        """A TX_DONE carrying 0x00 fails the send, named as the modem's own status."""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        sent = threading.Event()
        modem.send_frame = lambda data: sent.set() or True

        result: dict[str, object] = {}
        t = threading.Thread(
            target=lambda: result.__setitem__("r", modem.send_frame_and_wait(b"AA", timeout=5.0))
        )
        t.start()
        assert sent.wait(timeout=1.0)

        tx_fail = bytes([KISS_FEND, KISS_CMD_SETHARDWARE, RESP_TX_DONE, 0x00, KISS_FEND])
        for byte in tx_fail:
            modem._decode_kiss_byte(byte)

        t.join(timeout=1.0)
        assert result.get("r") is False
        assert "status=0x00" in (modem._tx_last_verdict or "")

    def test_serial_failure_wakes_in_flight_sender(self):
        """A serial failure mid-transmit wakes the waiter instead of stalling."""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True
        modem._start_reconnect_worker = MagicMock()  # don't spawn a reconnect thread

        sent = threading.Event()
        modem.send_frame = lambda data: sent.set() or True

        result: dict[str, object] = {}
        start = time.monotonic()
        t = threading.Thread(
            target=lambda: result.__setitem__("r", modem.send_frame_and_wait(b"AA", timeout=5.0))
        )
        t.start()
        assert sent.wait(timeout=1.0)

        modem._mark_serial_failure("link lost")

        t.join(timeout=1.0)
        assert result.get("r") is False
        assert time.monotonic() - start < 2.0

    def test_send_frame_and_wait_skips_when_degraded(self):
        """Don't enqueue DATA while the link is degraded."""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True
        modem._degraded = True
        modem.send_frame = MagicMock(return_value=True)

        assert modem.send_frame_and_wait(b"AA", timeout=2.0) is False
        modem.send_frame.assert_not_called()


class TestBulkDecodeEquivalence:
    """The bulk _decode_kiss() must be byte-for-byte equivalent to _decode_kiss_byte(),
    including across arbitrary read-chunk boundaries (escape/frame state spans chunks)."""

    @staticmethod
    def _kiss_encode(type_byte, payload):
        out = bytearray([KISS_FEND, type_byte])
        for b in payload:
            if b == KISS_FEND:
                out += bytes([KISS_FESC, KISS_TFEND])
            elif b == KISS_FESC:
                out += bytes([KISS_FESC, KISS_TFESC])
            else:
                out.append(b)
        out.append(KISS_FEND)
        return bytes(out)

    @staticmethod
    def _new_modem():
        m = KissModemWrapper(port="/dev/null", auto_configure=False)
        m.is_connected = True
        frames = []
        m.on_frame_received = lambda data: frames.append(data)
        return m, frames

    def _run_single(self, stream):
        m, frames = self._new_modem()
        for byte in stream:
            m._decode_kiss_byte(byte)
        return frames, m.stats["frame_errors"]

    def _run_bulk(self, stream, chunk_sizes):
        m, frames = self._new_modem()
        idx = 0
        for size in chunk_sizes:
            m._decode_kiss(stream[idx : idx + size])
            idx += size
        if idx < len(stream):
            m._decode_kiss(stream[idx:])
        return frames, m.stats["frame_errors"]

    def _assert_equiv(self, stream, chunk_sizes):
        exp_frames, exp_errors = self._run_single(stream)
        got_frames, got_errors = self._run_bulk(stream, chunk_sizes)
        assert got_frames == exp_frames
        assert got_errors == exp_errors

    def test_escape_split_across_chunk_boundary(self):
        # DATA payload = escaped FEND; split the stream right between FESC and TFEND
        stream = self._kiss_encode(CMD_DATA, bytes([0xC0])) + self._kiss_encode(
            KISS_CMD_SETHARDWARE, bytes([HW_RESP_RX_META, 0x10, 0xB0])
        )
        fesc_pos = stream.index(KISS_FESC)
        self._assert_equiv(stream, [fesc_pos + 1])  # chunk ends just after FESC

    def test_oversize_frame_resync(self):
        # A frame with a lost FEND exceeds MAX_FRAME_SIZE, then a valid pair follows.
        from openhop_core.hardware.kiss_modem_wrapper import MAX_FRAME_SIZE

        runaway = bytes([KISS_FEND, CMD_DATA]) + bytes(MAX_FRAME_SIZE + 50)  # no closing FEND
        valid = self._kiss_encode(CMD_DATA, b"\x01\x02") + self._kiss_encode(
            KISS_CMD_SETHARDWARE, bytes([HW_RESP_RX_META, 0x10, 0xB0])
        )
        stream = runaway + valid
        self._assert_equiv(stream, [1] * len(stream))  # byte-at-a-time chunks
        self._assert_equiv(stream, [len(stream)])  # whole thing at once
        self._assert_equiv(stream, [7, 600, 50])  # split through the oversize region

    def test_invalid_escape_sequence(self):
        # FESC followed by a non-transpose byte -> frame error + resync, then a valid pair.
        bad = bytes([KISS_FEND, CMD_DATA, KISS_FESC, 0x42, 0x99, KISS_FEND])
        valid = self._kiss_encode(CMD_DATA, b"\x07") + self._kiss_encode(
            KISS_CMD_SETHARDWARE, bytes([HW_RESP_RX_META, 0x10, 0xB0])
        )
        stream = bad + valid
        self._assert_equiv(stream, [len(stream)])
        self._assert_equiv(stream, [3, 1, 2, len(stream)])

    def test_fuzz_random_streams_and_chunkings(self):
        import random

        for seed in range(60):
            rng = random.Random(seed)
            stream = bytearray()
            for _ in range(rng.randint(1, 8)):
                payload_len = rng.randint(1, 40)
                payload = bytes(rng.randint(0, 255) for _ in range(payload_len))
                stream += self._kiss_encode(CMD_DATA, payload)
                snr = rng.randint(0, 255)
                rssi = rng.randint(0, 255)
                stream += self._kiss_encode(
                    KISS_CMD_SETHARDWARE, bytes([HW_RESP_RX_META, snr, rssi])
                )
            # Inject occasional stray delimiters / leading noise between frames
            if seed % 3 == 0:
                stream = bytes([KISS_FEND, KISS_FEND]) + bytes(stream)
            stream = bytes(stream)

            # Random chunk boundaries
            chunks = []
            remaining = len(stream)
            while remaining > 0:
                size = rng.randint(1, max(1, remaining // 2 or 1))
                chunks.append(size)
                remaining -= size
            self._assert_equiv(stream, chunks)


class TestWorkerFailureDuringReconnectWindow:
    """A worker failure must never be silent just because a reconnect is underway.

    ``_reconnect_loop`` starts the RX/TX workers with ``is_connected`` still
    False and only sets it True after readiness plus the SetHardware handshake.
    Gating the workers' error handler on ``is_connected`` therefore silenced
    exactly the window in which a freshly reopened USB device is most likely to
    fail: the thread died with no log and no failure marked, nothing re-armed a
    reconnect, and the node went permanently deaf while the log read "KISS modem
    serial reconnect successful". Seen in the field after two processes briefly
    contended for the port, and reproduced here.
    """

    class _FailingSerial:
        """An open port whose first read raises, as a just-reopened device can."""

        def __init__(self):
            self.is_open = True
            self._failed = False
            self.raised = threading.Event()

        def read(self, n=1):
            if not self._failed:
                self._failed = True
                self.raised.set()
                raise OSError("device reports readiness to read but returned no data")
            time.sleep(0.01)
            return b""

        @property
        def in_waiting(self):
            return 0

        def close(self):
            self.is_open = False

    def _run_worker_until_failure(self, is_connected: bool):
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        fake = self._FailingSerial()
        modem.serial_conn = fake
        modem.is_connected = is_connected
        failures = []
        modem._mark_serial_failure = lambda reason: failures.append(reason)

        worker = threading.Thread(target=modem._rx_worker, daemon=True)
        worker.start()
        assert fake.raised.wait(timeout=2.0)
        worker.join(timeout=2.0)
        assert not worker.is_alive()
        return failures

    def test_rx_failure_is_marked_inside_the_reconnect_window(self):
        """is_connected is False there; the failure must still arm a reconnect."""
        failures = self._run_worker_until_failure(is_connected=False)
        assert failures, "RX died silently: nothing will ever reconnect"

    def test_rx_failure_is_marked_in_steady_state_too(self):
        failures = self._run_worker_until_failure(is_connected=True)
        assert failures

    def test_rx_failure_is_silent_only_while_deliberately_stopping(self):
        """Teardown must stay quiet — that is what the old gate was protecting."""
        for attr, value in (("_shutting_down", True), ("stop_event", None)):
            modem = KissModemWrapper(port="/dev/null", auto_configure=False)
            fake = self._FailingSerial()
            modem.serial_conn = fake
            modem.is_connected = True
            failures = []
            modem._mark_serial_failure = lambda reason: failures.append(reason)
            if attr == "stop_event":
                modem.stop_event.set()
            else:
                setattr(modem, attr, value)

            worker = threading.Thread(target=modem._rx_worker, daemon=True)
            worker.start()
            worker.join(timeout=2.0)
            assert not worker.is_alive()
            assert failures == [], f"teardown via {attr} should not report a failure"


class TestReconnectRequiresLiveReader:
    """A (re)connect must not be reported as successful with a dead reader.

    The workers are started before readiness and the SetHardware handshake run,
    so an RX failure inside that window used to leave a dead reader behind while
    the caller logged "reconnect successful" — is_connected True, no error, no
    retry, and no further packet ever delivered.
    """

    class _ReadFailsSerial:
        def __init__(self):
            self.is_open = True
            self.raised = threading.Event()

        def read(self, n=1):
            self.raised.set()
            raise OSError("device reports readiness to read but returned no data")

        @property
        def in_waiting(self):
            return 0

        def close(self):
            self.is_open = False

    def test_open_reports_failure_when_the_reader_dies_during_startup(self):
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        fake = self._ReadFailsSerial()
        modem._mark_serial_failure = lambda reason: None

        def _ready():
            assert fake.raised.wait(timeout=2.0)  # let the reader die first
            modem.rx_thread.join(timeout=2.0)
            return True

        with (
            patch("openhop_core.hardware.kiss_modem_wrapper.serial.Serial", return_value=fake),
            patch.object(modem, "_wait_for_modem_ready", side_effect=_ready),
        ):
            assert modem._open_serial_and_start_threads() is False

    def test_open_reports_success_when_the_reader_survives(self):
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        class QuietSerial:
            is_open = True

            def read(self, n=1):
                time.sleep(0.01)
                return b""

            @property
            def in_waiting(self):
                return 0

            def close(self):
                type(self).is_open = False

        fake = QuietSerial()
        try:
            with (
                patch("openhop_core.hardware.kiss_modem_wrapper.serial.Serial", return_value=fake),
                patch.object(modem, "_wait_for_modem_ready", return_value=True),
            ):
                assert modem._open_serial_and_start_threads() is True
                assert modem.rx_thread.is_alive()
        finally:
            modem.stop_event.set()
            fake.close()
            if modem.rx_thread:
                modem.rx_thread.join(timeout=2)


class TestStopIoThreadsEndsThePreviousGeneration:
    def test_stop_io_threads_closes_the_port_so_a_blocked_reader_exits(self):
        """Joining alone let a reader blocked in read() outlive the join.

        _mark_serial_failure defers closing the port when the connection lock is
        busy, so the reconnect path could reach _stop_io_threads with the old
        port still open and a worker parked in read(). It survived the 0.5s join
        and kept decoding into the same KISS buffer as the new generation.
        """
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)

        class BlockingSerial:
            def __init__(self):
                self.is_open = True
                self.entered = threading.Event()

            def read(self, n=1):
                self.entered.set()
                while self.is_open:
                    time.sleep(0.005)
                raise OSError("port closed")

            @property
            def in_waiting(self):
                return 0

            def close(self):
                self.is_open = False

        fake = BlockingSerial()
        modem.serial_conn = fake
        modem.is_connected = True
        modem._mark_serial_failure = lambda reason: None

        reader = threading.Thread(target=modem._rx_worker, daemon=True)
        modem.rx_thread = reader
        reader.start()
        assert fake.entered.wait(timeout=2.0)

        modem._stop_io_threads(join_timeout=2.0)

        assert fake.is_open is False, "the port was left open, so the reader kept running"
        assert not reader.is_alive(), "the previous generation reader outlived the stop"


class TestRxCallbackDisarmRace:
    """RX dispatch must tolerate the callback being cleared concurrently.

    The dispatcher's RX disarm (and wait_for_rx's callback swap) can null
    on_frame_received between the dispatch-time guard and the deferred
    invoke, so dispatch must act on a snapshot, never a re-read.
    """

    def test_invoke_rx_callback_tolerates_none(self):
        from openhop_core.hardware.kiss_modem_wrapper import _invoke_rx_callback

        _invoke_rx_callback(None, b"data", -50, 7.5)  # must not raise

    def test_event_loop_dispatch_uses_snapshotted_callback(self):
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        scheduled = []
        fake_loop = MagicMock()
        fake_loop.call_soon_threadsafe.side_effect = lambda fn, *a: scheduled.append((fn, a))
        modem.set_event_loop(fake_loop)
        received = []
        modem.on_frame_received = lambda data: received.append(data)

        modem._dispatch_rx_callback(b"payload", -50, 7.5)
        # Callback cleared (e.g. dispatcher RX disarm) before the loop drains.
        modem.on_frame_received = None

        assert len(scheduled) == 1
        fn, args = scheduled[0]
        fn(*args)  # must invoke the snapshot, not re-read the cleared attribute
        assert received == [b"payload"]

    def test_dispatch_returns_quietly_when_callback_already_none(self):
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        fake_loop = MagicMock()
        modem.set_event_loop(fake_loop)
        modem.on_frame_received = None

        modem._dispatch_rx_callback(b"payload", -50, 7.5)  # must not raise

        fake_loop.call_soon_threadsafe.assert_not_called()


class TestSerialPortOpen:
    """Opening the port must not let pyserial drive the modem's control lines."""

    def _connect_with_fake_serial(self):
        """Run connect() against a fake pyserial, return the Serial() kwargs."""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem._post_connect_settle_s = 0
        with (
            patch("openhop_core.hardware.kiss_modem_wrapper.serial") as fake_serial,
            patch.object(kiss_modem_wrapper.threading, "Thread"),
            patch.object(KissModemWrapper, "_wait_for_modem_ready", return_value=True),
            patch.object(KissModemWrapper, "_query_modem_info"),
            patch.object(KissModemWrapper, "_set_kiss_tx_delay"),
        ):
            modem.connect()
        assert fake_serial.Serial.call_count == 1
        return fake_serial.Serial.call_args.kwargs

    def test_connect_leaves_dtr_alone(self):
        """dsrdtr=True stops pyserial asserting DTR on open, which resets the modem."""
        assert self._connect_with_fake_serial().get("dsrdtr") is True

    def test_connect_does_not_enable_hardware_flow_control(self):
        """The firmware implements no RTS/CTS flow control on the RX pipe."""
        assert self._connect_with_fake_serial().get("rtscts") is False


class TestKissPortRecovery:
    """Reconnect follows a renamed node, and says when a port is not coming back."""

    def test_reconnect_follows_a_renamed_node(self):
        """A device that re-enumerates under a new name is still reconnected to.

        macOS renamed this very modem from cu.usbmodem1101 to cu.usbmodem12301
        across a replug; pinned to the old path, the loop would retry forever.
        """
        modem = KissModemWrapper(port="/dev/old-node", auto_configure=False)
        modem._stop_io_threads = MagicMock()
        modem._alternate_port_paths = lambda: ["/dev/new-node"]
        # Only the new path opens; the configured one is gone.
        modem._open_serial_and_start_threads = lambda: modem.port == "/dev/new-node"
        modem._run_post_connect_handshake = MagicMock(return_value=True)

        with patch.object(kiss_modem_wrapper.time, "sleep", return_value=None):
            modem._reconnect_loop()

        assert modem.port == "/dev/new-node"
        assert modem.is_connected is True
        assert modem._degraded is False

    def test_reconnect_keeps_the_configured_path_when_nothing_opens(self):
        """A failed sweep must not leave the wrapper pointed at a candidate."""
        modem = KissModemWrapper(port="/dev/old-node", auto_configure=False)
        modem._stop_io_threads = MagicMock()
        modem._alternate_port_paths = lambda: ["/dev/new-node"]
        modem._open_serial_and_start_threads = lambda: False
        modem._reconnect_max_attempts = 2

        with patch.object(kiss_modem_wrapper.time, "sleep", return_value=None):
            modem._reconnect_loop()

        assert modem.port == "/dev/old-node"
        assert modem.is_connected is False

    def test_alternate_paths_match_on_usb_identity(self):
        """Only a port with the same vid/pid/serial is a candidate."""
        modem = KissModemWrapper(port="/dev/old-node", auto_configure=False)
        modem._port_identity_ref = (0x10C4, 0xEA60, "0001")

        same = MagicMock(device="/dev/new-node", vid=0x10C4, pid=0xEA60, serial_number="0001")
        other = MagicMock(device="/dev/other-radio", vid=0x239A, pid=0x8029, serial_number="ZZ")
        fake_list_ports = MagicMock(comports=MagicMock(return_value=[same, other]))
        with (
            patch.dict("sys.modules", {"serial.tools.list_ports": fake_list_ports}),
            patch("serial.tools.list_ports", fake_list_ports, create=True),
        ):
            assert modem._alternate_port_paths() == ["/dev/new-node"]

    def test_alternate_paths_needs_a_known_identity(self):
        """With no recorded identity, never adopt some other serial port."""
        modem = KissModemWrapper(port="/dev/old-node", auto_configure=False)
        assert modem._port_identity_ref is None
        assert modem._alternate_port_paths() == []

    def test_repeated_identical_open_failure_escalates_once(self, caplog):
        """The same errno every attempt gets one actionable line, not one per retry."""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        err = OSError(22, "Invalid argument")

        with caplog.at_level("ERROR"):
            for _ in range(modem._WEDGED_PORT_FAILURES + 3):
                modem._note_open_failure(err)

        wedged = [r for r in caplog.records if "failed to open" in r.getMessage()]
        assert len(wedged) == 1  # escalated once, then rate-limited
        assert "wedged" in wedged[0].getMessage()  # /dev/null exists, so: not a rename
        assert modem._degraded_reason is not None
        assert "Invalid argument" in modem._degraded_reason

    def test_a_different_error_restarts_the_count(self):
        """A changing failure is still churn, not a stuck port."""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem._note_open_failure(OSError(22, "Invalid argument"))
        modem._note_open_failure(OSError(22, "Invalid argument"))
        assert modem._open_failure_count == 2
        modem._note_open_failure(OSError(2, "No such file or directory"))
        assert modem._open_failure_count == 1


def _port_info(device, vid=0x10C4, pid=0xEA60, serial_number="0001"):
    """Stand-in for a pyserial ListPortInfo entry."""
    return MagicMock(device=device, vid=vid, pid=pid, serial_number=serial_number)


class TestKissPortIdentityEdges:
    """Identity matching must not guess, and must cope with aliased device paths."""

    def test_serial_less_twins_are_not_guessed_between(self):
        """Two of the same model with no serial number: any pick would be a coin toss."""
        modem = KissModemWrapper(port="/dev/old-node", auto_configure=False)
        modem._port_identity_ref = (0x10C4, 0xEA60, None)

        ports = [
            _port_info("/dev/twin-a", serial_number=None),
            _port_info("/dev/twin-b", serial_number=None),
        ]
        with patch("serial.tools.list_ports.comports", return_value=ports):
            assert modem._alternate_port_paths() == []

    def test_a_lone_serial_less_candidate_is_still_followed(self):
        """The no-serial guard must not disable recovery when there is no ambiguity."""
        modem = KissModemWrapper(port="/dev/old-node", auto_configure=False)
        modem._port_identity_ref = (0x10C4, 0xEA60, None)

        ports = [_port_info("/dev/new-node", serial_number=None)]
        with patch("serial.tools.list_ports.comports", return_value=ports):
            assert modem._alternate_port_paths() == ["/dev/new-node"]

    def test_identity_is_learned_through_an_aliased_path(self, tmp_path):
        """A by-id symlink never appears verbatim in comports(); resolve it."""
        alias = tmp_path / "openhop-modem"
        alias.symlink_to("/dev/null")
        modem = KissModemWrapper(port=str(alias), auto_configure=False)

        with patch("serial.tools.list_ports.comports", return_value=[_port_info("/dev/null")]):
            modem._remember_port_identity()

        assert modem._port_identity_ref == (0x10C4, 0xEA60, "0001")

    def test_an_alias_is_not_offered_as_its_own_alternate(self, tmp_path):
        """The configured alias and its target are one device, not two."""
        alias = tmp_path / "openhop-modem"
        alias.symlink_to("/dev/null")
        modem = KissModemWrapper(port=str(alias), auto_configure=False)
        modem._port_identity_ref = (0x10C4, 0xEA60, "0001")

        with patch("serial.tools.list_ports.comports", return_value=[_port_info("/dev/null")]):
            assert modem._alternate_port_paths() == []

    def test_a_different_radio_on_a_matching_path_is_refused(self):
        """Same make and model is not the same radio; the modem's own key decides."""
        modem = KissModemWrapper(port="/dev/old-node", auto_configure=False)
        modem._stop_io_threads = MagicMock()
        modem._alternate_port_paths = lambda: ["/dev/new-node"]
        modem._open_serial_and_start_threads = lambda: modem.port == "/dev/new-node"
        modem._modem_identity_ref = b"\x01" * 32
        modem._reconnect_max_attempts = 1

        def handshake():
            modem.modem_identity = b"\x02" * 32  # somebody else's modem
            return True

        modem._run_post_connect_handshake = handshake
        modem._close_serial_connection = MagicMock()

        with patch.object(kiss_modem_wrapper.time, "sleep", return_value=None):
            modem._reconnect_loop()

        assert modem.is_connected is False
        assert modem.port == "/dev/old-node"  # not adopted

    def test_wedged_port_escalates_within_a_minute_of_boot(self, caplog):
        """A low monotonic clock must not swallow the first escalation."""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        err = OSError(22, "Invalid argument")

        with patch.object(kiss_modem_wrapper.time, "monotonic", return_value=5.0):
            with caplog.at_level("ERROR"):
                for _ in range(modem._WEDGED_PORT_FAILURES):
                    modem._note_open_failure(err)

        assert any("failed to open" in r.getMessage() for r in caplog.records)


class TestKissSendVerdictOwnership:
    """A send's failure reason must belong to that send, not to whoever ran last."""

    def test_verdict_sink_carries_this_calls_reason(self):
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True
        modem.send_frame = lambda data: True

        sink: list = []
        assert modem.send_frame_and_wait(b"AA", timeout=0.2, verdict=sink) is False
        assert sink and "no TX_DONE" in sink[0]

    @pytest.mark.asyncio
    async def test_send_raises_with_its_own_reason_not_the_shared_field(self):
        """The shared field can be replaced by a concurrent send; the sink cannot."""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True
        modem.lbt_enabled = False

        def fake_send(data, timeout=None, *, verdict=None):
            if verdict is not None:
                verdict.append("mine: TX_DONE status=0x00")
            modem._tx_last_verdict = "theirs: some other send"
            return False

        modem.send_frame_and_wait = fake_send

        with pytest.raises(Exception, match="mine: TX_DONE status=0x00"):
            await modem.send(b"\x01\x02\x03\x04")
