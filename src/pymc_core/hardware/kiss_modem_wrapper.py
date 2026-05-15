"""
MeshCore KISS Modem Protocol Wrapper

Implements the MeshCore KISS modem protocol for sending/receiving
MeshCore packets over LoRa and cryptographic operations.

Protocol spec (frame format, SetHardware sub-commands, Data + RxMeta ordering):
  https://github.com/meshcore-dev/MeshCore/blob/dev/docs/kiss_modem_protocol.md
"""

import asyncio
import inspect
import logging
import random
import struct
import threading
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, Optional, Union

import serial

from ..protocol.packet_utils import PacketTimingUtils
from .base import LoRaRadio

# RX callback: (data) for backward compat, or (data, rssi, snr) for per-packet metrics
RxCallback = Union[
    Callable[[bytes], None],
    Callable[[bytes, Optional[int], Optional[float]], None],
]


def _invoke_rx_callback(
    callback: RxCallback,
    data: bytes,
    rssi: int,
    snr: float,
) -> None:
    """Invoke RX callback with 1 or 3 args depending on what it accepts."""
    try:
        sig = inspect.signature(callback)
        nparams = len([p for p in sig.parameters if p != "self"])
    except (ValueError, TypeError):
        nparams = 1
    if nparams >= 3:
        callback(data, rssi, snr)
    else:
        callback(data)


# KISS Protocol Constants (shared with standard KISS)
KISS_FEND = 0xC0  # Frame End
KISS_FESC = 0xDB  # Frame Escape
KISS_TFEND = 0xDC  # Transposed Frame End
KISS_TFESC = 0xDD  # Transposed Frame Escape

# Standard KISS type bytes (port in bits 7-4, command in bits 3-0)
CMD_DATA = 0x00  # Data frame (raw packet)
KISS_CMD_TXDELAY = 0x01  # Transmitter keyup delay in 10ms units (firmware default 50 = 500ms)
KISS_CMD_PERSISTENCE = 0x02  # CSMA persistence 0-255 (firmware default 63)
KISS_CMD_SLOTTIME = 0x03  # CSMA slot interval in 10ms units (firmware default 10 = 100ms)
KISS_CMD_TXTAIL = 0x04  # Post-TX hold time in 10ms units (default: 0)
KISS_CMD_FULLDUPLEX = 0x05  # 0 = half duplex, nonzero = full duplex (default: 0)
KISS_CMD_SETHARDWARE = 0x06  # SetHardware: first payload byte is sub-command
KISS_CMD_RETURN = 0xFF  # Exit KISS mode (no-op)

# SetHardware request sub-commands (Host -> TNC, first data byte inside 0x06)
HW_CMD_GET_IDENTITY = 0x01
HW_CMD_GET_RANDOM = 0x02
HW_CMD_VERIFY_SIGNATURE = 0x03
HW_CMD_SIGN_DATA = 0x04
HW_CMD_ENCRYPT_DATA = 0x05
HW_CMD_DECRYPT_DATA = 0x06
HW_CMD_KEY_EXCHANGE = 0x07
HW_CMD_HASH = 0x08
HW_CMD_SET_RADIO = 0x09
HW_CMD_SET_TX_POWER = 0x0A
HW_CMD_GET_RADIO = 0x0B
HW_CMD_GET_TX_POWER = 0x0C
HW_CMD_GET_CURRENT_RSSI = 0x0D
HW_CMD_IS_CHANNEL_BUSY = 0x0E
HW_CMD_GET_AIRTIME = 0x0F
HW_CMD_GET_NOISE_FLOOR = 0x10
HW_CMD_GET_VERSION = 0x11
HW_CMD_GET_STATS = 0x12
HW_CMD_GET_BATTERY = 0x13
HW_CMD_GET_MCU_TEMP = 0x14
HW_CMD_GET_SENSORS = 0x15
HW_CMD_GET_DEVICE_NAME = 0x16
HW_CMD_PING = 0x17
HW_CMD_REBOOT = 0x18
HW_CMD_SET_SIGNAL_REPORT = 0x19
HW_CMD_GET_SIGNAL_REPORT = 0x1A

# SetHardware response sub-commands (TNC -> Host)
# Spec: response = command | 0x80 for command responses; 0xF0+ for generic/unsolicited
HW_RESP_IDENTITY = 0x81  # HW_CMD_GET_IDENTITY | 0x80
HW_RESP_RANDOM = 0x82
HW_RESP_VERIFY = 0x83
HW_RESP_SIGNATURE = 0x84
HW_RESP_ENCRYPTED = 0x85
HW_RESP_DECRYPTED = 0x86
HW_RESP_SHARED_SECRET = 0x87
HW_RESP_HASH = 0x88
HW_RESP_RADIO = 0x8B  # HW_CMD_GET_RADIO | 0x80
HW_RESP_TX_POWER = 0x8C
HW_RESP_CURRENT_RSSI = 0x8D
HW_RESP_CHANNEL_BUSY = 0x8E
HW_RESP_AIRTIME = 0x8F
HW_RESP_NOISE_FLOOR = 0x90
HW_RESP_VERSION = 0x91
HW_RESP_STATS = 0x92
HW_RESP_BATTERY = 0x93
HW_RESP_MCU_TEMP = 0x94
HW_RESP_SENSORS = 0x95
HW_RESP_DEVICE_NAME = 0x96
HW_RESP_PONG = 0x97  # HW_CMD_PING | 0x80
HW_RESP_OK = 0xF0
HW_RESP_ERROR = 0xF1
HW_RESP_TX_DONE = 0xF8  # Unsolicited
HW_RESP_RX_META = 0xF9  # Unsolicited
HW_RESP_SIGNAL_REPORT = 0x9A  # HW_CMD_GET_SIGNAL_REPORT | 0x80

# Backward-compatible aliases (same values as HW_*)
CMD_GET_IDENTITY = HW_CMD_GET_IDENTITY
CMD_GET_RANDOM = HW_CMD_GET_RANDOM
CMD_VERIFY_SIGNATURE = HW_CMD_VERIFY_SIGNATURE
CMD_SIGN_DATA = HW_CMD_SIGN_DATA
CMD_ENCRYPT_DATA = HW_CMD_ENCRYPT_DATA
CMD_DECRYPT_DATA = HW_CMD_DECRYPT_DATA
CMD_KEY_EXCHANGE = HW_CMD_KEY_EXCHANGE
CMD_HASH = HW_CMD_HASH
CMD_SET_RADIO = HW_CMD_SET_RADIO
CMD_SET_TX_POWER = HW_CMD_SET_TX_POWER
CMD_GET_RADIO = HW_CMD_GET_RADIO
CMD_GET_TX_POWER = HW_CMD_GET_TX_POWER
CMD_GET_CURRENT_RSSI = HW_CMD_GET_CURRENT_RSSI
CMD_IS_CHANNEL_BUSY = HW_CMD_IS_CHANNEL_BUSY
CMD_GET_AIRTIME = HW_CMD_GET_AIRTIME
CMD_GET_NOISE_FLOOR = HW_CMD_GET_NOISE_FLOOR
CMD_GET_VERSION = HW_CMD_GET_VERSION
CMD_GET_STATS = HW_CMD_GET_STATS
CMD_GET_BATTERY = HW_CMD_GET_BATTERY
CMD_GET_SENSORS = HW_CMD_GET_SENSORS
CMD_PING = HW_CMD_PING

RESP_IDENTITY = HW_RESP_IDENTITY
RESP_RANDOM = HW_RESP_RANDOM
RESP_VERIFY = HW_RESP_VERIFY
RESP_SIGNATURE = HW_RESP_SIGNATURE
RESP_ENCRYPTED = HW_RESP_ENCRYPTED
RESP_DECRYPTED = HW_RESP_DECRYPTED
RESP_SHARED_SECRET = HW_RESP_SHARED_SECRET
RESP_HASH = HW_RESP_HASH
RESP_OK = HW_RESP_OK
RESP_RADIO = HW_RESP_RADIO
RESP_TX_POWER = HW_RESP_TX_POWER
RESP_VERSION = HW_RESP_VERSION
RESP_ERROR = HW_RESP_ERROR
RESP_TX_DONE = HW_RESP_TX_DONE
RESP_CURRENT_RSSI = HW_RESP_CURRENT_RSSI
RESP_CHANNEL_BUSY = HW_RESP_CHANNEL_BUSY
RESP_AIRTIME = HW_RESP_AIRTIME
RESP_NOISE_FLOOR = HW_RESP_NOISE_FLOOR
RESP_STATS = HW_RESP_STATS
RESP_BATTERY = HW_RESP_BATTERY
RESP_PONG = HW_RESP_PONG
RESP_SENSORS = HW_RESP_SENSORS

# Error codes (SetHardware Error response payload)
HW_ERR_INVALID_LENGTH = 0x01
HW_ERR_INVALID_PARAM = 0x02
HW_ERR_NO_CALLBACK = 0x03
HW_ERR_MAC_FAILED = 0x04
HW_ERR_UNKNOWN_CMD = 0x05
HW_ERR_ENCRYPT_FAILED = 0x06

ERR_INVALID_LENGTH = HW_ERR_INVALID_LENGTH
ERR_INVALID_PARAM = HW_ERR_INVALID_PARAM
ERR_NO_CALLBACK = HW_ERR_NO_CALLBACK
ERR_MAC_FAILED = HW_ERR_MAC_FAILED
ERR_UNKNOWN_CMD = HW_ERR_UNKNOWN_CMD
ERR_ENCRYPT_FAILED = HW_ERR_ENCRYPT_FAILED

# Buffer and timing constants
MAX_FRAME_SIZE = 512
# Data payload ≤255 bytes (MeshCore MAX_TRANS_UNIT); queue bounds unpaired Data frames
KISS_MAX_PACKET_SIZE = 255
MAX_PENDING_RX_FRAMES = 64  # max Data frames queued awaiting RxMeta; each payload ≤255 bytes
RX_BUFFER_SIZE = 1024
TX_BUFFER_SIZE = 1024
DEFAULT_BAUDRATE = 115200
DEFAULT_TIMEOUT = 1.0
RESPONSE_TIMEOUT = 5.0  # Timeout for command responses

logger = logging.getLogger("KissModemWrapper")


class KissModemWrapper(LoRaRadio):
    """
    MeshCore KISS Modem Protocol Interface

    Provides full-duplex KISS protocol communication with MeshCore modem firmware.
    Supports packet transmission/reception, radio configuration, and cryptographic
    operations via the modem's identity.

    Implements the LoRaRadio interface for PyMC Core compatibility.

    Threading Model:
        This wrapper uses background threads for serial RX/TX. The RX callback
        (on_frame_received) is invoked from the RX thread by default. For async
        applications, call set_event_loop() to have callbacks scheduled onto
        the event loop via call_soon_threadsafe().

    RX Callback Signature:
        The callback may accept either:
        - (data: bytes) - backward compatible, single argument
        - (data: bytes, rssi: int, snr: float) - per-packet signal metrics

        When using the 3-argument form, rssi and snr are the values for that
        specific packet, avoiding race conditions with get_last_rssi/get_last_snr.
    """

    def __init__(
        self,
        port: str,
        baudrate: int = DEFAULT_BAUDRATE,
        timeout: float = DEFAULT_TIMEOUT,
        on_frame_received: Optional[RxCallback] = None,
        radio_config: Optional[Dict[str, Any]] = None,
        auto_configure: bool = True,
        lbt_enabled: bool = False,
    ):
        """
        Initialize MeshCore KISS Modem Wrapper

        Args:
            port: Serial port device path (e.g., '/dev/ttyUSB0', '/dev/ttyACM0')
            baudrate: Serial communication baud rate (default: 115200)
            timeout: Serial read timeout in seconds (default: 1.0)
            on_frame_received: Callback for received data packets. May be invoked
                              from a background thread unless set_event_loop() is used.
            radio_config: Optional radio configuration dict with keys:
                         frequency, bandwidth, spreading_factor, coding_rate,
                         power (or tx_power), tx_delay_ms (KISS key-up delay in ms;
                         default 50), kiss_persistence (0-255), kiss_slottime_ms,
                         kiss_txtail_ms (post-TX hold), kiss_full_duplex (bool),
                         and SetHardware options as needed
            auto_configure: If True, automatically configure radio on connect
            lbt_enabled: If True, run Listen-Before-Talk before each send (default False).
                         For standard half-duplex the modem firmware performs p-persistent
                         CSMA; host-side LBT is redundant. Only enable for the marginal case
                         of full-duplex modem on a physically half-duplex link, where a
                         host "is channel busy?" check can delay submitting the next frame
                         to avoid collisions.
        """
        self.port = port
        self.baudrate = baudrate
        self.timeout = timeout
        self.auto_configure = auto_configure
        self.lbt_enabled = lbt_enabled

        self.radio_config = radio_config or {}
        self.is_configured = False

        # Radio configuration — instance attributes matching SX1262Wrapper
        # convention.  Seeded from the config dict; updated by configure_radio().
        self.frequency = self.radio_config.get("frequency", int(869.618 * 1000000))
        self.tx_power = self.radio_config.get("power", self.radio_config.get("tx_power", 22))
        self.spreading_factor = self.radio_config.get("spreading_factor", 8)
        self.bandwidth = self.radio_config.get("bandwidth", int(62500))
        self.coding_rate = self.radio_config.get("coding_rate", 8)
        self.preamble_length = self.radio_config.get("preamble_length", 17)

        self.serial_conn: Optional[serial.Serial] = None

        self.rx_buffer = deque(maxlen=RX_BUFFER_SIZE)
        self.tx_buffer = deque(maxlen=TX_BUFFER_SIZE)

        self.rx_frame_buffer = bytearray()
        self.in_frame = False
        self.escaped = False

        self.rx_thread: Optional[threading.Thread] = None
        self.tx_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()

        # Callbacks
        self.on_frame_received = on_frame_received

        # Event loop for thread-safe async callback invocation
        self._event_loop: Optional[asyncio.AbstractEventLoop] = None

        # When no event loop is set, run callback in a worker so RX thread never blocks
        self._callback_executor: Optional[ThreadPoolExecutor] = None

        # Response handling
        self._response_event = threading.Event()
        self._pending_response: Optional[tuple[int, bytes]] = None
        self._response_lock = threading.Lock()

        # TX completion tracking
        self._tx_done_event = threading.Event()
        self._tx_done_result: Optional[bool] = None

        # Pending RX data payloads (Data frame) waiting for RxMeta frame
        self._pending_rx_queue: deque = deque()

        self.stats = {
            "frames_sent": 0,
            "frames_received": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
            "frame_errors": 0,
            "buffer_overruns": 0,
            "rx_packets": 0,
            "tx_packets": 0,
            "errors": 0,
            "last_rssi": -999,
            "last_snr": -999.0,
            "noise_floor": None,
        }

        # Modem info
        self.modem_version: Optional[int] = None
        self.modem_identity: Optional[bytes] = None

    def set_event_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """
        Set the event loop for thread-safe async callback invocation.

        When set, RX callbacks are scheduled onto the event loop via
        call_soon_threadsafe() instead of being invoked directly from
        the RX thread. This is required for proper async integration.

        Args:
            loop: The asyncio event loop to use for callbacks
        """
        self._event_loop = loop
        logger.debug("Event loop set for thread-safe callbacks")

    @property
    def is_connected(self) -> bool:
        return (
            self.rx_thread is not None and self.rx_thread.is_alive()
            and self.tx_thread is not None and self.tx_thread.is_alive()
        )

    def set_lbt_enabled(self, enabled: bool) -> None:
        """
        Enable or disable host-side Listen-Before-Talk before each send.

        When enabled, send() checks is_channel_busy() and backs off (120/240/360 ms)
        until clear or 4 s. For standard half-duplex the modem already does CSMA;
        enable only for full-duplex modem on a physically half-duplex link.
        """
        self.lbt_enabled = enabled
        logger.debug("Software LBT %s", "enabled" if enabled else "disabled")

    def get_lbt_enabled(self) -> bool:
        """Return whether host-side Listen-Before-Talk is enabled."""
        return self.lbt_enabled

    def connect(self) -> bool:
        """
        Connect to serial port and start communication threads

        Returns:
            True if connection successful, False otherwise
        """
        try:
            self.serial_conn = serial.Serial(
                port=self.port,
                baudrate=self.baudrate,
                timeout=self.timeout,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
            )

            self.stop_event.clear()

            # Start communication threads
            self.rx_thread = threading.Thread(target=self._rx_worker, daemon=True)
            self.tx_thread = threading.Thread(target=self._tx_worker, daemon=True)

            self.rx_thread.start()
            self.tx_thread.start()

            logger.info(f"KISS modem connected to {self.port} at {self.baudrate} baud")

            # Auto-configure if requested
            if self.auto_configure and self.radio_config:
                if not self.configure_radio():
                    logger.warning("Auto-configuration failed")
                    return False

            # Query modem info
            self._query_modem_info()

            # Set KISS TXDELAY so key-up delay is not the firmware default 500ms (reduces
            # round-trip latency for repeaters). Value in 10ms units; default 50ms.
            tx_delay_ms = self.radio_config.get("tx_delay_ms", 50)
            self._set_kiss_tx_delay(tx_delay_ms)
            if "kiss_persistence" in self.radio_config:
                self.set_kiss_persistence(self.radio_config["kiss_persistence"])
            if "kiss_slottime_ms" in self.radio_config:
                self.set_kiss_slottime(self.radio_config["kiss_slottime_ms"])
            if "kiss_txtail_ms" in self.radio_config:
                self.set_kiss_txtail(self.radio_config["kiss_txtail_ms"])
            if "kiss_full_duplex" in self.radio_config:
                self.set_kiss_full_duplex(bool(self.radio_config["kiss_full_duplex"]))

            return True

        except Exception as e:
            logger.error(f"Failed to connect to {self.port}: {e}")
            return False

    def disconnect(self):
        """Disconnect from serial port and stop threads"""
        self.stop_event.set()

        # Wait for threads to finish
        if self.rx_thread and self.rx_thread.is_alive():
            self.rx_thread.join(timeout=2.0)
        if self.tx_thread and self.tx_thread.is_alive():
            self.tx_thread.join(timeout=2.0)

        if self._callback_executor is not None:
            self._callback_executor.shutdown(wait=False)
            self._callback_executor = None

        # Close serial connection
        if self.serial_conn and self.serial_conn.is_open:
            self.serial_conn.close()

        logger.info(f"KISS modem disconnected from {self.port}")

    def cleanup(self) -> None:
        self.disconnect()

    def _write_frame(self, frame: bytes) -> bool:
        """
        Write a complete KISS frame to the serial port.

        Ensures the entire frame (including trailing FEND) is written; retries
        on partial write so we never send a truncated frame.

        Returns:
            True if all bytes written, False on error or incomplete write.
        """
        if not self.serial_conn or not self.serial_conn.is_open:
            return False
        offset = 0
        while offset < len(frame):
            try:
                n = self.serial_conn.write(frame[offset:])
                if n is None or n <= 0:
                    logger.error("Serial write returned %s", n)
                    return False
                offset += n
            except Exception as e:
                logger.error("Serial write error: %s", e)
                return False
        try:
            self.serial_conn.flush()
        except Exception as e:
            logger.error("Serial flush error: %s", e)
            return False
        return True

    def _set_kiss_tx_delay(self, delay_ms: int) -> None:
        """
        Send KISS TXDELAY command so modem key-up delay is not the default 500ms.
        Value is in 10ms units; firmware default is 50 (= 500ms). Typical for
        repeaters: 50ms (value 5).
        """
        value = max(1, min(255, delay_ms // 10))
        frame = self._encode_kiss_frame(KISS_CMD_TXDELAY, bytes([value]))
        if self._write_frame(frame):
            logger.debug("KISS TXDELAY set to %dms (value %d)", value * 10, value)
        else:
            logger.warning("Failed to set KISS TXDELAY")

    def set_kiss_persistence(self, value: int) -> bool:
        """
        Set KISS CSMA persistence parameter (0-255). Lower values defer longer
        when channel is busy; firmware default is 63.

        Returns:
            True if the command was written successfully.
        """
        val = max(0, min(255, value))
        frame = self._encode_kiss_frame(KISS_CMD_PERSISTENCE, bytes([val]))
        ok = self._write_frame(frame)
        if ok:
            logger.debug("KISS PERSISTENCE set to %d", val)
        return ok

    def set_kiss_slottime(self, slottime_ms: int) -> bool:
        """
        Set KISS CSMA slot time in milliseconds (sent as 10ms units to modem).
        Firmware default is 100ms (value 10). Lower values reduce backoff delay
        when channel is busy at the cost of more collisions under load.

        Returns:
            True if the command was written successfully.
        """
        value = max(0, min(255, slottime_ms // 10))
        frame = self._encode_kiss_frame(KISS_CMD_SLOTTIME, bytes([value]))
        ok = self._write_frame(frame)
        if ok:
            logger.debug("KISS SLOTTIME set to %dms (value %d)", value * 10, value)
        return ok

    def set_kiss_txtail(self, txtail_ms: int) -> bool:
        """
        Set KISS post-TX hold time (TXtail) in milliseconds (sent as 10ms units).
        Firmware default is 0. Some radios need a short hold after TX.

        Returns:
            True if the command was written successfully.
        """
        value = max(0, min(255, txtail_ms // 10))
        frame = self._encode_kiss_frame(KISS_CMD_TXTAIL, bytes([value]))
        ok = self._write_frame(frame)
        if ok:
            logger.debug("KISS TXTAIL set to %dms (value %d)", value * 10, value)
        return ok

    def set_kiss_full_duplex(self, full_duplex: bool) -> bool:
        """
        Set KISS full-duplex mode. When False (default), modem uses p-persistent
        CSMA. When True, CSMA is bypassed and packets transmit after TXDELAY only.

        Returns:
            True if the command was written successfully.
        """
        value = 0x01 if full_duplex else 0x00
        frame = self._encode_kiss_frame(KISS_CMD_FULLDUPLEX, bytes([value]))
        ok = self._write_frame(frame)
        if ok:
            logger.debug("KISS FullDuplex set to %s", full_duplex)
        return ok

    def set_signal_report(self, enabled: bool) -> bool:
        """
        Enable or disable RxMeta frames (SNR + RSSI after each Data frame).
        Enabled by default. When disabled, the modem does not send SetHardware
        RxMeta (0xF9) after received packets.

        Returns:
            True if the command was sent and a valid response was received.
        """
        payload = bytes([0x01 if enabled else 0x00])
        resp = self._send_command(HW_CMD_SET_SIGNAL_REPORT, payload)
        if resp and resp[0] in (HW_RESP_SIGNAL_REPORT, HW_RESP_OK):
            return True
        return False

    def get_signal_report(self) -> Optional[bool]:
        """
        Query whether RxMeta (signal report) is enabled. When enabled, the modem
        sends an RxMeta frame after each received Data frame.

        Returns:
            True if enabled, False if disabled, None on error.
        """
        resp = self._send_command(HW_CMD_GET_SIGNAL_REPORT)
        if resp and resp[0] == HW_RESP_SIGNAL_REPORT and len(resp[1]) >= 1:
            return resp[1][0] != 0x00
        return None

    def _query_modem_info(self):
        """Query modem version and identity"""
        try:
            # Get version
            version_resp = self._send_command(CMD_GET_VERSION)
            if version_resp and version_resp[0] == RESP_VERSION and len(version_resp[1]) >= 1:
                self.modem_version = version_resp[1][0]
                logger.info(f"Modem version: {self.modem_version}")

            # Get identity (public key)
            identity_resp = self._send_command(CMD_GET_IDENTITY)
            if identity_resp and identity_resp[0] == RESP_IDENTITY and len(identity_resp[1]) == 32:
                self.modem_identity = identity_resp[1]
                logger.info(f"Modem identity: {self.modem_identity.hex()[:16]}...")

        except Exception as e:
            logger.warning(f"Failed to query modem info: {e}")

    def configure_radio(
        self,
        frequency: Optional[int] = None,
        bandwidth: Optional[int] = None,
        spreading_factor: Optional[int] = None,
        coding_rate: Optional[int] = None,
    ) -> bool:
        """Configure radio parameters.

        When called with keyword arguments (e.g. from CompanionRadio), those
        values take precedence.  When called with no arguments the values are
        read from ``self.radio_config`` (populated from config.yaml at init).

        Returns:
            True if configuration successful, False otherwise
        """
        if not self.is_connected:
            logger.error("Cannot configure radio: not connected")
            return False

        try:
            # Explicit kwargs take precedence, then radio_config dict, then defaults
            frequency_hz = (
                frequency
                if frequency is not None
                else self.radio_config.get("frequency", int(869.618 * 1000000))
            )
            bandwidth_hz = (
                bandwidth
                if bandwidth is not None
                else self.radio_config.get("bandwidth", int(62500))
            )
            sf = (
                spreading_factor
                if spreading_factor is not None
                else self.radio_config.get("spreading_factor", 8)
            )
            cr = coding_rate if coding_rate is not None else self.radio_config.get("coding_rate", 8)
            power = self.radio_config.get("power", self.radio_config.get("tx_power", 22))

            # Set radio parameters (frequency, bandwidth, SF, CR)
            # Format: Freq (4) + BW (4) + SF (1) + CR (1) - all little-endian
            radio_data = struct.pack("<IIBB", frequency_hz, bandwidth_hz, sf, cr)
            resp = self._send_command(CMD_SET_RADIO, radio_data)
            if not resp or resp[0] == RESP_ERROR:
                logger.error("Failed to set radio parameters")
                return False

            # Set TX power
            resp = self._send_command(CMD_SET_TX_POWER, bytes([power]))
            if not resp or resp[0] == RESP_ERROR:
                logger.error("Failed to set TX power")
                return False

            # Note: Sync word is configured at firmware build time, not at runtime

            # Sync instance attributes to match what was applied to hardware
            self.frequency = frequency_hz
            self.bandwidth = bandwidth_hz
            self.spreading_factor = sf
            self.coding_rate = cr
            self.tx_power = power

            self.is_configured = True
            logger.info(
                f"Radio configured: {frequency_hz / 1000000:.3f} MHz, "
                f"BW {bandwidth_hz / 1000:.1f} kHz, SF{sf}, CR4/{cr}, {power} dBm"
            )
            return True

        except Exception as e:
            logger.error(f"Radio configuration error: {e}")
            return False

    def send_frame(self, data: bytes) -> bool:
        """
        Send a data frame via KISS modem

        Args:
            data: Raw packet data to send (2-255 bytes)

        Returns:
            True if frame queued successfully, False otherwise
        """
        if not self.is_connected:
            logger.warning("Cannot send frame: not connected")
            return False

        if len(data) < 2 or len(data) > KISS_MAX_PACKET_SIZE:
            logger.warning(
                f"Invalid frame size: {len(data)} (must be 2-{KISS_MAX_PACKET_SIZE} bytes)"
            )
            return False

        try:
            # Create KISS frame with CMD_DATA command
            kiss_frame = self._encode_kiss_frame(CMD_DATA, data)

            # Add to TX buffer
            if len(self.tx_buffer) < TX_BUFFER_SIZE:
                self.tx_buffer.append(kiss_frame)
                return True
            else:
                self.stats["buffer_overruns"] += 1
                logger.warning("TX buffer overrun")
                return False

        except Exception as e:
            logger.error(f"Failed to send frame: {e}")
            return False

    def send_frame_and_wait(self, data: bytes, timeout: float = RESPONSE_TIMEOUT) -> bool:
        """
        Send a data frame and wait for TX_DONE response

        Args:
            data: Raw packet data to send
            timeout: Timeout in seconds to wait for TX_DONE

        Returns:
            True if transmission successful, False otherwise
        """
        self._tx_done_event.clear()
        self._tx_done_result = None

        if not self.send_frame(data):
            return False

        # Wait for TX_DONE response
        if self._tx_done_event.wait(timeout):
            return self._tx_done_result or False
        else:
            logger.warning("TX_DONE timeout")
            return False

    def _send_command(
        self, sub_cmd: int, data: bytes = b"", timeout: float = RESPONSE_TIMEOUT
    ) -> Optional[tuple[int, bytes]]:
        """
        Send a SetHardware command and wait for response.

        Encodes as KISS frame: FEND + 0x06 (SetHardware) + sub_cmd + data + FEND.

        Args:
            sub_cmd: SetHardware sub-command byte (e.g. HW_CMD_GET_IDENTITY)
            data: Sub-command payload
            timeout: Response timeout in seconds

        Returns:
            Tuple of (response_sub_cmd, response_data) or None on timeout
        """
        with self._response_lock:
            self._response_event.clear()
            self._pending_response = None

        # SetHardware frame: type 0x06, payload = sub_cmd (1 byte) + data
        kiss_frame = self._encode_kiss_frame(KISS_CMD_SETHARDWARE, bytes([sub_cmd]) + data)

        if not self._write_frame(kiss_frame):
            logger.warning("SetHardware frame write failed")
            return None

        # Wait for response
        if self._response_event.wait(timeout):
            with self._response_lock:
                return self._pending_response
        else:
            logger.warning(f"SetHardware sub_cmd 0x{sub_cmd:02X} timeout")
            return None

    def get_radio_config(self) -> Optional[Dict[str, Any]]:
        """
        Get current radio configuration from modem

        Returns:
            Dict with frequency, bandwidth, sf, cr, or None on error
        """
        resp = self._send_command(CMD_GET_RADIO)
        if resp and resp[0] == RESP_RADIO and len(resp[1]) >= 10:
            freq, bw, sf, cr = struct.unpack("<IIBB", resp[1][:10])
            return {
                "frequency": freq,
                "bandwidth": bw,
                "spreading_factor": sf,
                "coding_rate": cr,
            }
        return None

    def set_tx_power(self, power: int) -> bool:
        """Set TX power in dBm.

        Sends the command to the modem and updates the instance attribute
        on success, matching the SX1262Wrapper interface.
        """
        if not self.is_connected:
            logger.error("Cannot set TX power: not connected")
            return False
        try:
            resp = self._send_command(CMD_SET_TX_POWER, bytes([power]))
            if not resp or resp[0] == RESP_ERROR:
                logger.error("Failed to set TX power")
                return False
            self.tx_power = power
            logger.info(f"TX power set to {power} dBm")
            return True
        except Exception as e:
            logger.error(f"Error setting TX power: {e}")
            return False

    def get_tx_power(self) -> Optional[int]:
        """Get current TX power in dBm"""
        resp = self._send_command(CMD_GET_TX_POWER)
        if resp and resp[0] == RESP_TX_POWER and len(resp[1]) >= 1:
            return resp[1][0]
        return None

    def get_current_rssi(self) -> int:
        """Get current RSSI from modem"""
        resp = self._send_command(CMD_GET_CURRENT_RSSI)
        if resp and resp[0] == RESP_CURRENT_RSSI and len(resp[1]) >= 1:
            # RSSI is signed byte
            rssi = resp[1][0]
            if rssi > 127:
                rssi -= 256
            return rssi
        return -999

    def is_channel_busy(self) -> bool:
        """Check if channel is busy"""
        resp = self._send_command(CMD_IS_CHANNEL_BUSY)
        if resp and resp[0] == RESP_CHANNEL_BUSY and len(resp[1]) >= 1:
            return resp[1][0] == 0x01
        return False

    def get_airtime(self, packet_length: int, timeout: Optional[float] = None) -> Optional[int]:
        """
        Get estimated airtime for a packet from the modem.

        Args:
            packet_length: Length of packet in bytes
            timeout: Response timeout in seconds (default: RESPONSE_TIMEOUT).
                     Use a shorter value (e.g. 1.0) in the TX path to avoid
                     blocking when the modem is busy or unresponsive.

        Returns:
            Airtime in milliseconds or None on error/timeout
        """
        t = timeout if timeout is not None else RESPONSE_TIMEOUT
        resp = self._send_command(CMD_GET_AIRTIME, bytes([packet_length]), timeout=t)
        if resp and resp[0] == RESP_AIRTIME and len(resp[1]) >= 4:
            return struct.unpack("<I", resp[1][:4])[0]
        return None

    def get_noise_floor(self) -> Optional[int]:
        """Get noise floor in dBm"""
        resp = self._send_command(CMD_GET_NOISE_FLOOR)
        if resp and resp[0] == RESP_NOISE_FLOOR and len(resp[1]) >= 2:
            # Noise floor is signed 16-bit
            noise = struct.unpack("<h", resp[1][:2])[0]
            self.stats["noise_floor"] = noise
            return noise
        return None

    def get_modem_stats(self) -> Optional[Dict[str, int]]:
        """
        Get modem statistics

        Returns:
            Dict with rx, tx, errors counts or None on error
        """
        resp = self._send_command(CMD_GET_STATS)
        if resp and resp[0] == RESP_STATS and len(resp[1]) >= 12:
            rx, tx, errors = struct.unpack("<III", resp[1][:12])
            return {"rx": rx, "tx": tx, "errors": errors}
        return None

    def get_battery(self) -> Optional[int]:
        """Get battery voltage in millivolts"""
        resp = self._send_command(CMD_GET_BATTERY)
        if resp and resp[0] == RESP_BATTERY and len(resp[1]) >= 2:
            return struct.unpack("<H", resp[1][:2])[0]
        return None

    def ping(self) -> bool:
        """Ping the modem to check connectivity"""
        resp = self._send_command(CMD_PING)
        return resp is not None and resp[0] == RESP_PONG

    def get_sensors(self, permissions: int = 0x07) -> Optional[bytes]:
        """
        Get sensor data in CayenneLPP format

        Args:
            permissions: Bitmask of sensors to query
                        0x01 = battery, 0x02 = GPS, 0x04 = environment

        Returns:
            CayenneLPP encoded sensor data or None
        """
        resp = self._send_command(CMD_GET_SENSORS, bytes([permissions]))
        if resp and resp[0] == RESP_SENSORS:
            return resp[1]
        return None

    def get_mcu_temp(self) -> Optional[float]:
        """
        Get MCU temperature in degrees Celsius.

        Returns:
            Temperature in °C, or None if unsupported or error.
        """
        resp = self._send_command(HW_CMD_GET_MCU_TEMP)
        if resp and resp[0] == HW_RESP_MCU_TEMP and len(resp[1]) >= 2:
            temp_tenths = struct.unpack("<h", resp[1][:2])[0]
            return temp_tenths / 10.0
        if resp and resp[0] == HW_RESP_ERROR and len(resp[1]) >= 1:
            if resp[1][0] == HW_ERR_NO_CALLBACK:
                return None
        return None

    def get_device_name(self) -> Optional[str]:
        """
        Get device/manufacturer name (UTF-8 string).

        Returns:
            Device name string or None on error.
        """
        resp = self._send_command(HW_CMD_GET_DEVICE_NAME)
        if resp and resp[0] == HW_RESP_DEVICE_NAME:
            try:
                return resp[1].decode("utf-8")
            except UnicodeDecodeError:
                return None
        return None

    def reboot(self) -> None:
        """
        Request modem reboot. Sends Reboot (0x18), expects OK then connection drop.
        Does not wait for disconnect.
        """
        self._send_command(HW_CMD_REBOOT, timeout=1.0)

    # Cryptographic operations using modem's identity

    def get_identity(self) -> Optional[bytes]:
        """Get modem's public key (32 bytes)"""
        resp = self._send_command(CMD_GET_IDENTITY)
        if resp and resp[0] == RESP_IDENTITY and len(resp[1]) == 32:
            self.modem_identity = resp[1]
            return resp[1]
        return None

    def get_random(self, length: int) -> Optional[bytes]:
        """
        Get random bytes from modem

        Args:
            length: Number of random bytes (1-64)

        Returns:
            Random bytes or None on error
        """
        if length < 1 or length > 64:
            logger.error("Random length must be 1-64")
            return None
        resp = self._send_command(CMD_GET_RANDOM, bytes([length]))
        if resp and resp[0] == RESP_RANDOM:
            return resp[1]
        return None

    def sign_data(self, data: bytes) -> Optional[bytes]:
        """
        Sign data with modem's private key

        Args:
            data: Data to sign

        Returns:
            64-byte signature or None on error
        """
        resp = self._send_command(CMD_SIGN_DATA, data)
        if resp and resp[0] == RESP_SIGNATURE and len(resp[1]) == 64:
            return resp[1]
        return None

    def verify_signature(self, pubkey: bytes, signature: bytes, data: bytes) -> Optional[bool]:
        """
        Verify a signature

        Args:
            pubkey: 32-byte public key
            signature: 64-byte signature
            data: Original data

        Returns:
            True if valid, False if invalid, None on error
        """
        if len(pubkey) != 32 or len(signature) != 64:
            logger.error("Invalid pubkey or signature length")
            return None
        payload = pubkey + signature + data
        resp = self._send_command(CMD_VERIFY_SIGNATURE, payload)
        if resp and resp[0] == RESP_VERIFY and len(resp[1]) >= 1:
            return resp[1][0] == 0x01
        return None

    def encrypt_data(self, key: bytes, plaintext: bytes) -> Optional[tuple[bytes, bytes]]:
        """
        Encrypt data using a shared key

        Args:
            key: 32-byte encryption key
            plaintext: Data to encrypt

        Returns:
            Tuple of (mac, ciphertext) or None on error
        """
        if len(key) != 32:
            logger.error("Key must be 32 bytes")
            return None
        payload = key + plaintext
        resp = self._send_command(CMD_ENCRYPT_DATA, payload)
        if resp and resp[0] == RESP_ENCRYPTED and len(resp[1]) >= 2:
            mac = resp[1][:2]
            ciphertext = resp[1][2:]
            return (mac, ciphertext)
        return None

    def decrypt_data(self, key: bytes, mac: bytes, ciphertext: bytes) -> Optional[bytes]:
        """
        Decrypt data using a shared key

        Args:
            key: 32-byte decryption key
            mac: 2-byte MAC
            ciphertext: Encrypted data

        Returns:
            Plaintext or None on error (includes MAC failure)
        """
        if len(key) != 32 or len(mac) != 2:
            logger.error("Invalid key or MAC length")
            return None
        payload = key + mac + ciphertext
        resp = self._send_command(CMD_DECRYPT_DATA, payload)
        if resp and resp[0] == RESP_DECRYPTED:
            return resp[1]
        return None

    def key_exchange(self, remote_pubkey: bytes) -> Optional[bytes]:
        """
        Perform key exchange with remote public key

        Args:
            remote_pubkey: 32-byte remote public key

        Returns:
            32-byte shared secret or None on error
        """
        if len(remote_pubkey) != 32:
            logger.error("Remote public key must be 32 bytes")
            return None
        resp = self._send_command(CMD_KEY_EXCHANGE, remote_pubkey)
        if resp and resp[0] == RESP_SHARED_SECRET and len(resp[1]) == 32:
            return resp[1]
        return None

    def hash_data(self, data: bytes) -> Optional[bytes]:
        """
        Compute SHA-256 hash of data

        Args:
            data: Data to hash

        Returns:
            32-byte hash or None on error
        """
        resp = self._send_command(CMD_HASH, data)
        if resp and resp[0] == RESP_HASH and len(resp[1]) == 32:
            return resp[1]
        return None

    # LoRaRadio interface implementation

    def set_rx_callback(self, callback: RxCallback):
        """
        Set the RX callback function.

        The callback may be (data: bytes) or (data, rssi, snr). When invoked
        by this wrapper it is always called with (data, rssi, snr) so each
        packet gets correct per-packet metrics without race conditions.
        """
        self.on_frame_received = callback
        logger.debug("RX callback set")

    def begin(self):
        """Initialize the modem (LoRaRadio interface)"""
        success = self.connect()
        if not success:
            raise Exception("Failed to initialize KISS modem")

    def check_radio_health(self) -> bool:
        """Check modem connectivity. Returns True if connected and modem responds to ping."""
        if not self.is_connected:
            return False
        try:
            return self.ping()
        except Exception as e:
            logger.debug(f"KISS modem health check failed: {e}")
            return False

    # Optional host-side LBT (only when lbt_enabled, e.g. full-duplex on half-duplex link)
    LBT_RETRY_DELAYS_MS = (120, 240, 360)
    LBT_MAX_WAIT_MS = 4000

    async def _prepare_for_tx_lbt(self) -> tuple[bool, list[float]]:
        """
        Listen-Before-Talk: query modem channel busy until clear or max wait.
        Used only when lbt_enabled (marginal case: full-duplex modem on physically
        half-duplex link). Returns (success, lbt_backoff_delays_ms).
        """
        lbt_backoff_delays: list[float] = []
        total_wait_ms = 0.0

        while total_wait_ms < self.LBT_MAX_WAIT_MS:
            try:
                channel_busy = await asyncio.to_thread(self.is_channel_busy)
                if not channel_busy:
                    logger.debug(
                        "Channel busy check clear - channel available after "
                        f"{len(lbt_backoff_delays) + 1} check(s)"
                    )
                    break

                logger.debug("Channel busy check still busy - activity detected")
                remaining_ms = self.LBT_MAX_WAIT_MS - total_wait_ms
                retry_delay_ms = random.choice(self.LBT_RETRY_DELAYS_MS)
                backoff_ms = min(retry_delay_ms, remaining_ms)
                lbt_backoff_delays.append(float(backoff_ms))
                total_wait_ms += backoff_ms

                logger.debug(
                    f"LBT backoff - waiting {backoff_ms}ms before retry "
                    f"(total wait {total_wait_ms:.0f}ms / {self.LBT_MAX_WAIT_MS}ms)"
                )
                await asyncio.sleep(backoff_ms / 1000.0)

                if total_wait_ms >= self.LBT_MAX_WAIT_MS:
                    logger.warning(
                        f"LBT max duration reached ({self.LBT_MAX_WAIT_MS}ms) - "
                        "channel still busy, transmitting anyway"
                    )
            except Exception as e:
                logger.warning(f"Channel busy check failed: {e}, proceeding with transmission")
                break

        return True, lbt_backoff_delays

    async def send(self, data: bytes) -> Optional[Dict[str, Any]]:
        """
        Send data via KISS modem (LoRaRadio interface)

        For standard half-duplex, relies on the modem's p-persistent CSMA; no
        host-side LBT. When lbt_enabled is True (full-duplex on half-duplex link),
        runs a channel-busy check before submitting the frame.

        Args:
            data: Data to send

        Returns:
            Transmission metadata dict (airtime_ms, lbt_attempts,
            lbt_backoff_delays_ms, lbt_channel_busy)

        Raises:
            Exception: If send fails
        """
        lbt_backoff_delays: list[float] = []
        if self.lbt_enabled:
            _, lbt_backoff_delays = await self._prepare_for_tx_lbt()

        success = self.send_frame(data)
        if not success:
            raise Exception("Failed to send frame via KISS modem")

        # Use short timeout for GET_AIRTIME so TX path is not blocked if modem
        # is busy or unresponsive (avoids 5s stall and subsequent bad state).
        airtime = self.get_airtime(len(data), timeout=1.0)
        if airtime is None:
            airtime = int(PacketTimingUtils.estimate_airtime_ms(len(data), self.radio_config))
        return {
            "airtime_ms": airtime,
            "lbt_attempts": len(lbt_backoff_delays),
            "lbt_backoff_delays_ms": lbt_backoff_delays,
            "lbt_channel_busy": len(lbt_backoff_delays) > 0,
        }

    async def wait_for_rx(self) -> bytes:
        """
        Wait for a packet to be received asynchronously (LoRaRadio interface)

        Returns:
            Received packet data
        """
        future = asyncio.Future()

        original_callback = self.on_frame_received

        def temp_callback(data: bytes, rssi: Optional[int] = None, snr: Optional[float] = None):
            if not future.done():
                future.set_result(data)
            if original_callback:
                try:
                    rssi_val = rssi if rssi is not None else -999
                    snr_val = snr if snr is not None else -999.0
                    _invoke_rx_callback(original_callback, data, rssi_val, snr_val)
                except Exception as e:
                    logger.error(f"Error in original callback: {e}")

        self.on_frame_received = temp_callback

        try:
            data = await future
            return data
        finally:
            self.on_frame_received = original_callback

    def sleep(self):
        """Put the modem into low-power mode (LoRaRadio interface)"""
        logger.debug("Sleep mode not directly supported for KISS modem")
        pass

    def get_last_rssi(self) -> int:
        """Return last received RSSI in dBm (LoRaRadio interface)"""
        return self.stats.get("last_rssi", -999)

    def get_last_snr(self) -> float:
        """Return last received SNR in dB (LoRaRadio interface)"""
        return self.stats.get("last_snr", -999.0)

    def get_stats(self) -> Dict[str, Any]:
        """Get interface statistics"""
        return self.stats.copy()

    def get_status(self) -> Dict[str, Any]:
        """Get radio status. Uses cached config/stats where possible."""
        cfg = self.get_radio_config()
        tx_power = self.get_tx_power()
        status: Dict[str, Any] = {
            "initialized": self.is_connected,
            "frequency": cfg["frequency"] if cfg else self.radio_config.get("frequency", 0),
            "tx_power": tx_power
            if tx_power is not None
            else self.radio_config.get("tx_power", self.radio_config.get("power", 0)),
            "spreading_factor": cfg["spreading_factor"]
            if cfg
            else self.radio_config.get("spreading_factor", 0),
            "bandwidth": cfg["bandwidth"] if cfg else self.radio_config.get("bandwidth", 0),
            "coding_rate": cfg["coding_rate"] if cfg else self.radio_config.get("coding_rate", 0),
            "last_rssi": self.stats.get("last_rssi", -999),
            "last_snr": self.stats.get("last_snr", -999.0),
            "last_signal_rssi": self.stats.get("last_rssi", -999),
            "hardware_ready": self.is_connected,
        }
        return status

    # KISS frame encoding/decoding

    def _encode_kiss_frame(self, cmd: int, data: bytes) -> bytes:
        """
        Encode data into KISS frame format

        Args:
            cmd: Command byte
            data: Raw data to encode

        Returns:
            Encoded KISS frame
        """
        # Start with FEND and command
        frame = bytearray([KISS_FEND, cmd])

        # Escape and add data
        for byte in data:
            if byte == KISS_FEND:
                frame.extend([KISS_FESC, KISS_TFEND])
            elif byte == KISS_FESC:
                frame.extend([KISS_FESC, KISS_TFESC])
            else:
                frame.append(byte)

        # End with FEND
        frame.append(KISS_FEND)

        return bytes(frame)

    def _decode_kiss_byte(self, byte: int):
        """
        Process received byte for KISS frame decoding

        Args:
            byte: Received byte
        """
        if byte == KISS_FEND:
            if self.in_frame and len(self.rx_frame_buffer) > 0:
                # Complete frame received
                self._process_received_frame()
            # Start new frame
            self.rx_frame_buffer.clear()
            self.in_frame = True
            self.escaped = False

        elif byte == KISS_FESC:
            if self.in_frame:
                self.escaped = True

        elif self.escaped:
            if byte == KISS_TFEND:
                self.rx_frame_buffer.append(KISS_FEND)
            elif byte == KISS_TFESC:
                self.rx_frame_buffer.append(KISS_FESC)
            else:
                # Invalid escape sequence; reset so we resync at next FEND
                self.stats["frame_errors"] += 1
                logger.warning(f"Invalid KISS escape sequence: 0x{byte:02X}")
                self.rx_frame_buffer.clear()
                self.in_frame = False
            self.escaped = False

        else:
            if self.in_frame:
                if len(self.rx_frame_buffer) >= MAX_FRAME_SIZE:
                    # Frame too long (e.g. lost FEND); reset and resync at next FEND
                    self.stats["frame_errors"] += 1
                    logger.warning("KISS frame exceeded max size (%d), resyncing", MAX_FRAME_SIZE)
                    self.rx_frame_buffer.clear()
                    self.in_frame = False
                else:
                    self.rx_frame_buffer.append(byte)

    def _dispatch_rx_callback(self, data: bytes, rssi: int, snr: float) -> None:
        """
        Dispatch RX callback without blocking the RX thread.

        If an event loop is set via set_event_loop(), the callback is scheduled
        onto that loop. Otherwise, the callback is run in a single-worker thread
        pool so the RX thread can keep reading serial data (avoids dropped
        packets when the callback does I/O or heavy work).

        Args:
            data: Received packet data
            rssi: RSSI in dBm
            snr: SNR in dB
        """
        if self.on_frame_received is None:
            return

        if self._event_loop is not None:
            try:
                self._event_loop.call_soon_threadsafe(
                    lambda: _invoke_rx_callback(self.on_frame_received, data, rssi, snr)
                )
            except RuntimeError as e:
                logger.warning(f"Failed to schedule RX callback on event loop: {e}")
        elif self.rx_thread is not None and threading.current_thread() is self.rx_thread:
            # We're in the RX thread; run callback in executor so we don't block reading
            if self._callback_executor is None:
                self._callback_executor = ThreadPoolExecutor(max_workers=1)
            self._callback_executor.submit(
                _invoke_rx_callback, self.on_frame_received, data, rssi, snr
            )
        else:
            # Called from main thread (e.g. unit test); invoke directly
            _invoke_rx_callback(self.on_frame_received, data, rssi, snr)

    def _process_received_frame(self):
        """Process a complete received KISS frame (spec: type byte = port | cmd)."""
        if len(self.rx_frame_buffer) < 1:
            return

        type_byte = self.rx_frame_buffer[0]
        port = (type_byte >> 4) & 0x0F
        cmd = type_byte & 0x0F

        # Only process port 0 (single-port TNC)
        if port != 0:
            return

        self.stats["frames_received"] += 1
        self.stats["bytes_received"] += len(self.rx_frame_buffer) - 1

        if cmd == CMD_DATA:
            # Data frame: raw packet only (≤255 bytes per spec); queue until RxMeta arrives
            payload = bytes(self.rx_frame_buffer[1:])
            if len(self._pending_rx_queue) >= MAX_PENDING_RX_FRAMES:
                self.stats["frame_errors"] += 1
                logger.warning(
                    "Pending RX queue full (max %d), dropping Data frame",
                    MAX_PENDING_RX_FRAMES,
                )
            else:
                self._pending_rx_queue.append(payload)

        elif cmd == KISS_CMD_SETHARDWARE:
            # SetHardware: first byte is sub_cmd, rest is payload
            if len(self.rx_frame_buffer) < 2:
                return
            sub_cmd = self.rx_frame_buffer[1]
            payload = bytes(self.rx_frame_buffer[2:])

            if sub_cmd == HW_RESP_RX_META:
                # RxMeta follows a Data frame: SNR (1), RSSI (1); deliver queued data
                rssi_raw = -999
                snr_db = -999.0
                if len(payload) >= 2:
                    snr_raw = payload[0]
                    rssi_raw = payload[1]
                    if snr_raw > 127:
                        snr_raw -= 256
                    if rssi_raw > 127:
                        rssi_raw -= 256
                    snr_db = snr_raw / 4.0  # 0.25 dB steps
                    self.stats["last_snr"] = snr_db
                    self.stats["last_rssi"] = rssi_raw
                    self.stats["rx_packets"] += 1
                if self._pending_rx_queue:
                    packet_data = self._pending_rx_queue.popleft()
                    if self.on_frame_received:
                        try:
                            self._dispatch_rx_callback(packet_data, rssi_raw, snr_db)
                        except Exception as e:
                            logger.error(f"Error in frame received callback: {e}")
                else:
                    logger.warning("RxMeta received with no pending Data frame")

            elif sub_cmd == HW_RESP_TX_DONE:
                if len(payload) >= 1:
                    self._tx_done_result = payload[0] == 0x01
                    self.stats["tx_packets"] += 1
                self._tx_done_event.set()

            elif sub_cmd == HW_RESP_ERROR:
                if len(payload) >= 1:
                    self.stats["errors"] += 1
                    logger.warning(f"Modem error: 0x{payload[0]:02X}")
                with self._response_lock:
                    self._pending_response = (sub_cmd, payload)
                    self._response_event.set()

            else:
                # Other response sub-commands (Identity, Radio, OK, etc.)
                with self._response_lock:
                    self._pending_response = (sub_cmd, payload)
                    self._response_event.set()
        # cmd 0xFF (Return) has port=15 so is already discarded above

    def _rx_worker(self):
        """Background thread for receiving data"""
        while not self.stop_event.is_set():
            try:
                if self.serial_conn and self.serial_conn.in_waiting > 0:
                    data = self.serial_conn.read(self.serial_conn.in_waiting)

                    for byte in data:
                        self._decode_kiss_byte(byte)

                else:
                    threading.Event().wait(0.01)

            except Exception as e:
                logger.error(f"RX worker error: {e}")
                break

    def _tx_worker(self):
        """Background thread for sending data"""
        while not self.stop_event.is_set():
            try:
                if self.tx_buffer:
                    frame = self.tx_buffer.popleft()

                    if self.serial_conn and self.serial_conn.is_open:
                        if self._write_frame(frame):
                            self.stats["frames_sent"] += 1
                            self.stats["bytes_sent"] += len(frame)
                        else:
                            logger.warning("TX frame write failed, dropping frame")
                    else:
                        logger.warning("Serial connection not open")
                else:
                    threading.Event().wait(0.01)

            except Exception as e:
                logger.error(f"TX worker error: {e}")
                break

    def __enter__(self):
        """Context manager entry"""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.disconnect()

    def __del__(self):
        """Destructor to ensure cleanup"""
        try:
            self.disconnect()
        except Exception:
            pass
