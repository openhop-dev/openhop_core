"""
MeshCore KISS Modem Protocol Wrapper

Implements the MeshCore KISS modem protocol for sending/receiving
MeshCore packets over LoRa and cryptographic operations.

Protocol spec (frame format, SetHardware sub-commands, Data + RxMeta ordering):
  https://docs.openhop.dev/projects/openhop-core/kiss-modem-protocol/
"""

import asyncio
import inspect
import logging
import os
import random
import struct
import threading
import time
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
    callback: Optional[RxCallback],
    data: bytes,
    rssi: int,
    snr: float,
) -> None:
    """Invoke RX callback with 1 or 3 args depending on what it accepts.

    Tolerates ``None`` (a callback cleared between dispatch and invoke).
    """
    if callback is None:
        return
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

# Bytes forms of the delimiters, for C-level bytes.find() scanning in the bulk decoder.
_KISS_FEND_B = bytes([KISS_FEND])
_KISS_FESC_B = bytes([KISS_FESC])

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
# Protocol v2 (KISS_FIRMWARE_VERSION 2). Older firmware answers these with UNKNOWN_CMD.
HW_CMD_GET_CAPABILITIES = 0x1B
HW_CMD_SET_AGC_RESET_INTERVAL = 0x1C
HW_CMD_GET_AGC_RESET_INTERVAL = 0x1D
HW_CMD_SET_FEM_STATE = 0x1E
HW_CMD_GET_FEM_STATE = 0x1F
HW_CMD_SET_RX_BOOSTED_GAIN = 0x20
HW_CMD_GET_RX_BOOSTED_GAIN = 0x21

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
HW_RESP_CAPABILITIES = 0x9B  # HW_CMD_GET_CAPABILITIES | 0x80
# SET_AGC_RESET_INTERVAL, SET_FEM_STATE and SET_RX_BOOSTED_GAIN reply with GET-form
# codes; 0x9C, 0x9E and 0xA0 are never sent.
HW_RESP_AGC_RESET_INTERVAL = 0x9D  # HW_CMD_GET_AGC_RESET_INTERVAL | 0x80
HW_RESP_FEM_STATE = 0x9F  # HW_CMD_GET_FEM_STATE | 0x80
HW_RESP_RX_BOOSTED_GAIN = 0xA1  # HW_CMD_GET_RX_BOOSTED_GAIN | 0x80; also answers the Set

# GetCapabilities feature bits (uint32 LE). Probe these rather than inferring from the
# firmware version: boards on the same version expose different hardware controls.
HW_CAP_AGC_RESET = 1 << 0
HW_CAP_FEM_RX_GAIN = 1 << 1
HW_CAP_FEM_TX_GAIN = 1 << 2
# The radio chip's own boosted RX gain (MeshCore radio.rxgain), separate from FEM RX gain.
HW_CAP_RX_BOOSTED_GAIN = 1 << 3

# SetFemState / FemState bit masks
HW_FEM_RX_GAIN = 1 << 0  # external LNA enabled
HW_FEM_TX_GAIN = 1 << 1  # external PA high gain enabled

# AGC reset interval: 0 disables; firmware rounds down to a multiple of 4 s.
AGC_RESET_INTERVAL_MAX_SEC = 1020
AGC_RESET_INTERVAL_STEP_SEC = 4

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
# Two unrelated conditions share this code. The modem emits it on the DATA path when a
# transmit is already pending (single-slot modem TX), and -- since firmware moved its
# host-bound writes to a 2-slot queue -- whenever that queue overflows, which is a
# receive-side condition with no bearing on our transmit (kiss_modem_protocol.md:
# "Radio TX busy, or host output queue full"). The two are indistinguishable on the wire,
# so TX_BUSY is never a verdict on the in-flight frame; only TX_DONE is, and firmware
# retains a TX_DONE until it can be queued rather than dropping it.
HW_ERR_TX_BUSY = 0x07
# Command known, but this board cannot do it (e.g. FEM gain on a board without one).
HW_ERR_UNSUPPORTED = 0x08

ERR_INVALID_LENGTH = HW_ERR_INVALID_LENGTH
ERR_INVALID_PARAM = HW_ERR_INVALID_PARAM
ERR_NO_CALLBACK = HW_ERR_NO_CALLBACK
ERR_MAC_FAILED = HW_ERR_MAC_FAILED
ERR_UNKNOWN_CMD = HW_ERR_UNKNOWN_CMD
ERR_ENCRYPT_FAILED = HW_ERR_ENCRYPT_FAILED
ERR_TX_BUSY = HW_ERR_TX_BUSY
ERR_UNSUPPORTED = HW_ERR_UNSUPPORTED

# Buffer and timing constants
MAX_FRAME_SIZE = 512
# Data payload ≤255 bytes (MeshCore MAX_TRANS_UNIT); queue bounds unpaired Data frames
KISS_MAX_PACKET_SIZE = 255
MAX_PENDING_RX_FRAMES = 64  # max Data frames queued awaiting RxMeta; each payload ≤255 bytes
RX_BUFFER_SIZE = 1024
TX_BUFFER_SIZE = 1024
DEFAULT_BAUDRATE = 115200
DEFAULT_TIMEOUT = 1.0
# The RX worker uses a short blocking read so it sleeps in the kernel (releasing the GIL)
# instead of busy-polling, while still checking stop_event promptly on shutdown. The actual
# port timeout is min(this, self.timeout) so a caller-supplied lower timeout still wins.
RX_READ_TIMEOUT_S = 0.1
RESPONSE_TIMEOUT = 5.0  # Timeout for command responses
# Max time a received Data frame waits for its trailing RxMeta before being
# dispatched with sentinel metrics. RxMeta is only emitted when signal reporting
# is enabled, so a modem that never sends it must not stall reception.
RX_META_WAIT_SECONDS = 0.25
# Extra margin added to estimated airtime when waiting for a DATA TX_DONE, so a long
# transmit (e.g. a high-SF flood advert) is not cut short by the flat command timeout.
TX_DONE_TIMEOUT_MARGIN_S = 1.0
POST_CONNECT_SETTLE_SECONDS = 0.75
POST_CONNECT_CONFIGURE_RETRIES = 2
POST_CONNECT_CONFIGURE_RETRY_BACKOFF_SECONDS = 0.25

logger = logging.getLogger("KissModemWrapper")


class KissModemWrapper(LoRaRadio):
    """
    MeshCore KISS Modem Protocol Interface

    Provides full-duplex KISS protocol communication with MeshCore modem firmware.
    Supports packet transmission/reception, radio configuration, and cryptographic
    operations via the modem's identity.

    Implements the LoRaRadio interface for openHop Core compatibility.

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

    # Some SetHardware requests may legitimately respond with OK instead of the
    # command|0x80 specific response code.
    _SETHW_ALLOW_OK_FOR: set[int] = {
        HW_CMD_SET_RADIO,
        HW_CMD_SET_TX_POWER,
        HW_CMD_SET_SIGNAL_REPORT,
        HW_CMD_REBOOT,
    }

    # Some SetHardware setters answer with the GET-form response code rather than
    # the setter's own command|0x80. SET_SIGNAL_REPORT (0x19) replies with
    # HW_RESP(HW_CMD_GET_SIGNAL_REPORT) = 0x9A; the v2 setters follow suit.
    _SETHW_EXTRA_ACCEPT_RESP: dict[int, int] = {
        HW_CMD_SET_SIGNAL_REPORT: HW_RESP_SIGNAL_REPORT,
        HW_CMD_SET_AGC_RESET_INTERVAL: HW_RESP_AGC_RESET_INTERVAL,
        HW_CMD_SET_FEM_STATE: HW_RESP_FEM_STATE,
        HW_CMD_SET_RX_BOOSTED_GAIN: HW_RESP_RX_BOOSTED_GAIN,
    }

    # Commands whose reply is a snapshot of modem state that shares its code with
    # other requests (0x9D, 0x9F) and carries no request id. A queued reply for one
    # of these is a leftover from an earlier timed-out request -- a deferred
    # SetFemState answers only when the in-flight TX ends -- so it is discarded
    # rather than returned as this request's answer.
    _SETHW_FRESH_REPLY_ONLY: set[int] = {
        HW_CMD_SET_AGC_RESET_INTERVAL,
        HW_CMD_GET_AGC_RESET_INTERVAL,
        HW_CMD_SET_FEM_STATE,
        HW_CMD_GET_FEM_STATE,
        HW_CMD_SET_RX_BOOSTED_GAIN,
        HW_CMD_GET_RX_BOOSTED_GAIN,
    }

    def __init__(
        self,
        port: str,
        baudrate: int = DEFAULT_BAUDRATE,
        timeout: float = DEFAULT_TIMEOUT,
        on_frame_received: Optional[RxCallback] = None,
        radio_config: Optional[Dict[str, Any]] = None,
        auto_configure: bool = True,
        lbt_enabled: bool = False,
        connect_retries: int = 3,
        post_open_delay_ms: int = 500,
        usb_reset_on_connect: Optional[bool] = None,
        startup_retry_budget_sec: float = 5.0,
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
                         agc_reset_interval_seconds (0-1020, 0 disables),
                         fem_rx_gain (bool), fem_tx_gain (bool),
                         rx_boosted_gain (bool), and SetHardware
                         options as needed. The AGC/FEM keys are optional: when
                         absent the modem keeps its firmware/board default. They
                         are re-applied after every reconnect.
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
        self.connect_retries = max(1, int(connect_retries))
        self.post_open_delay_ms = max(0, int(post_open_delay_ms))
        self.startup_retry_budget_sec = max(1.0, float(startup_retry_budget_sec))
        if usb_reset_on_connect is None:
            self.usb_reset_on_connect = str(port).startswith("/dev/serial/by-id/")
        else:
            self.usb_reset_on_connect = bool(usb_reset_on_connect)
        self._shutting_down = False

        self.radio_config = radio_config or {}
        self.is_configured = False

        # Radio configuration — instance attributes matching SX1262Wrapper
        # convention.  Seeded from the config dict; updated by configure_radio().
        self.frequency = self.radio_config.get("frequency", int(869.618 * 1000000))
        self.tx_power = self.radio_config.get("power", self.radio_config.get("tx_power", 22))
        self.spreading_factor = self.radio_config.get("spreading_factor", 8)
        self.bandwidth = self.radio_config.get("bandwidth", int(62500))
        self.coding_rate = self.radio_config.get("coding_rate", 8)
        self.preamble_length = self.radio_config.get("preamble_length", 32)

        self.serial_conn: Optional[serial.Serial] = None
        self.is_connected = False
        self._degraded = False
        self._degraded_reason: Optional[str] = None

        self.rx_buffer = deque(maxlen=RX_BUFFER_SIZE)
        self.tx_buffer = deque(maxlen=TX_BUFFER_SIZE)

        self.rx_frame_buffer = bytearray()
        self.in_frame = False
        self.escaped = False

        self.rx_thread: Optional[threading.Thread] = None
        self.tx_thread: Optional[threading.Thread] = None
        self.reconnect_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self._reconnecting_event = threading.Event()
        self._connection_lock = threading.RLock()
        self._failure_log_lock = threading.Lock()
        self._last_failure_log_ts = 0.0
        self._failure_log_interval_s = float(
            self.radio_config.get("failure_log_interval_seconds", 10.0)
        )
        self._reconnect_base_delay_s = float(
            self.radio_config.get("reconnect_base_delay_seconds", 0.5)
        )
        self._reconnect_max_delay_s = float(
            self.radio_config.get("reconnect_max_delay_seconds", 15.0)
        )
        self._reconnect_max_attempts = int(self.radio_config.get("reconnect_max_attempts", 0))
        # USB identity (vid, pid, serial) of the configured port, learned on the first
        # successful open so a re-enumeration under a new node name can be followed.
        self._port_identity_ref: Optional[tuple] = None
        # Public key of the modem last handshaked, so a port that merely shares a
        # vid/pid is not mistaken for this radio.
        self._modem_identity_ref: Optional[bytes] = None
        # Consecutive open failures sharing one (path, errno), for the wedged-port line.
        self._open_failure_key: Optional[tuple] = None
        self._open_failure_count = 0
        self._open_failure_log_ts: Optional[float] = None
        self._post_connect_settle_s = max(
            0.0,
            float(
                self.radio_config.get(
                    "post_connect_settle_seconds",
                    POST_CONNECT_SETTLE_SECONDS,
                )
            ),
        )
        self._post_connect_configure_retries = max(
            0,
            int(
                self.radio_config.get(
                    "post_connect_configure_retries",
                    POST_CONNECT_CONFIGURE_RETRIES,
                )
            ),
        )
        self._post_connect_configure_retry_backoff_s = max(
            0.0,
            float(
                self.radio_config.get(
                    "post_connect_configure_retry_backoff_seconds",
                    POST_CONNECT_CONFIGURE_RETRY_BACKOFF_SECONDS,
                )
            ),
        )

        # Callbacks
        self.on_frame_received = on_frame_received

        # Event loop for thread-safe async callback invocation
        self._event_loop: Optional[asyncio.AbstractEventLoop] = None
        # When no event loop is set, run callback in a worker so RX thread never blocks
        self._callback_executor: Optional[ThreadPoolExecutor] = None

        # Response handling
        # Single-flight SetHardware command execution (send -> wait -> return)
        self._command_lock = threading.Lock()
        # Serialize all UART writes so frame bytes from different callers/threads
        # (TX worker vs SetHardware/control paths) cannot interleave.
        self._serial_write_lock = threading.Lock()
        self._response_event = threading.Event()
        self._pending_response: Optional[tuple[int, bytes]] = None
        self._response_lock = threading.Lock()
        self._expected_response_subcmds: Optional[set[int]] = None
        self._active_request_subcmd: Optional[int] = None
        self._response_queue: deque[tuple[int, bytes]] = deque(maxlen=32)

        # TX completion tracking
        # Single-flight DATA transmit: the modem holds one pending TX, so only one
        # frame may be in flight at a time. Serializing here prevents a second frame
        # being written mid-transmit and rejected with TX_BUSY (0x07).
        self._tx_inflight_lock = threading.Lock()
        self._tx_done_event = threading.Event()
        self._tx_done_result: Optional[bool] = None
        # TX_BUSY seen while the current frame was in flight. Recorded for the log line
        # and stats only -- see HW_ERR_TX_BUSY for why it cannot decide the send.
        self._tx_busy_seen = False
        # Why the last DATA send returned False, for the caller's error message.
        self._tx_last_verdict: Optional[str] = None

        # Pending RX data payloads (Data frame) awaiting their RxMeta frame.
        # Each entry is (payload, deadline_monotonic); a frame is dispatched with
        # sentinel metrics once its deadline passes if no RxMeta has arrived.
        self._pending_rx_queue: deque[tuple[bytes, float]] = deque()
        self._pending_rx_lock = threading.Lock()

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
            "tx_busy": 0,
            "last_rssi": -999,
            "last_snr": -999.0,
            "noise_floor": None,
        }

        # Modem info
        self.modem_version: Optional[int] = None
        self.modem_identity: Optional[bytes] = None
        # GetCapabilities feature bits; None until probed, 0 on pre-v2 firmware.
        self.modem_capabilities: Optional[int] = None
        # AGC/FEM values the modem has confirmed on this link, keyed like radio_config.
        # radio_config holds what should be applied (and is re-sent on reconnect);
        # this holds only what a modem reply reported, and is cleared on reconnect.
        self.applied_hardware_config: Dict[str, Any] = {}
        # Receive errors the modem counted since this wrapper first connected,
        # accumulated across modem resets and reconnects so it only ever rises,
        # like SX1262Wrapper's counter. The modem's GetStats "errors" field is
        # MeshCore's n_recv_errors: a failed readData(), which on its radios is a
        # CRC mismatch. Refresh with refresh_crc_error_count().
        self.crc_error_count = 0
        self._modem_errors_seen: Optional[int] = None

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
        with self._connection_lock:
            self.stop_event.clear()
            self.is_connected = False
            if not self._open_serial_and_start_threads():
                return False
            if not self._run_post_connect_handshake():
                self._close_serial_connection()
                self.is_connected = False
                return False
            self.is_connected = True
            self._reconnecting_event.clear()
            self._degraded = False
            self._degraded_reason = None
            self._remember_modem_identity()
            return True

    def disconnect(self):
        """Disconnect from serial port and stop threads"""
        with self._connection_lock:
            self.stop_event.set()
            self.is_connected = False
            self._degraded = False
            self._degraded_reason = None
            self._reconnecting_event.clear()
            self._close_serial_connection()

        self._stop_io_threads(join_timeout=2.0)
        self._stop_reconnect_thread(join_timeout=2.0)
        self._clear_pending_rx()

        if self._callback_executor is not None:
            self._callback_executor.shutdown(wait=False)
            self._callback_executor = None

        logger.info(f"KISS modem disconnected from {self.port}")

    def _open_serial_and_start_threads(self) -> bool:
        """Open serial device and start RX/TX workers."""
        try:
            self._shutting_down = False
            # Drop any Data frames left over from a prior session so a stale payload
            # cannot pair with an RxMeta from the freshly opened link.
            self._clear_pending_rx()
            self.serial_conn = serial.Serial(
                port=self.port,
                baudrate=self.baudrate,
                # Sole reader is _rx_worker, which does a short blocking read; cap the port
                # timeout so it releases the GIL while idle yet stays shutdown-responsive.
                timeout=min(self.timeout, RX_READ_TIMEOUT_S),
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                # dsrdtr=True tells pyserial to leave DTR alone on open rather than
                # asserting it, the same guard usb_radio.py already applies. On a
                # CP2102 board DTR pulls EN low and reboots the ESP32; on an
                # ESP32-S3 using the native USB-Serial-JTAG peripheral the host's
                # DTR/RTS state feeds the on-chip reset logic directly. Either way
                # the modem restarts every time we (re-)open the port. rtscts stays
                # off because the firmware has no hardware flow control.
                dsrdtr=True,
                rtscts=False,
            )
            self.is_connected = False

            self.rx_thread = threading.Thread(target=self._rx_worker, daemon=True)
            self.tx_thread = threading.Thread(target=self._tx_worker, daemon=True)
            self.rx_thread.start()
            self.tx_thread.start()
            logger.info("KISS modem connected to %s at %s baud", self.port, self.baudrate)

            if not self._wait_for_modem_ready():
                logger.warning("KISS modem did not become ready after reconnect")
                return False

            # Postcondition: this function's whole job is a live link, and the
            # workers were started before readiness ran. An RX failure in that
            # window used to leave a dead reader behind while the caller reported
            # a successful (re)connect, so the node went permanently deaf with
            # nothing left to re-arm a reconnect.
            if self.rx_thread is None or not self.rx_thread.is_alive():
                logger.warning("RX worker did not survive startup on %s", self.port)
                return False

            self._remember_port_identity()
            self._open_failure_key = None
            self._open_failure_count = 0
            return True
        except Exception as e:
            self._note_open_failure(e)
            self.is_connected = False
            return False

    # Consecutive identical open failures before the port is called wedged, and how
    # often that line may repeat afterwards.
    _WEDGED_PORT_FAILURES = 5
    _WEDGED_PORT_LOG_INTERVAL_S = 60.0

    def _port_identity(self, device: str) -> Optional[tuple]:
        """Return (vid, pid, serial_number) for *device*, or None if unavailable.

        Matches on the resolved path, not the configured string: a port is often
        given as an alias (/dev/serial/by-id/..., or a udev-named /dev/openhop-modem
        -- the constructor already treats the former specially) which never appears
        verbatim in comports(), and a literal comparison would leave exactly those
        setups with no identity to recover by.
        """
        target = os.path.realpath(device)
        try:
            from serial.tools import list_ports

            for info in list_ports.comports():
                if info.device == device or os.path.realpath(info.device) == target:
                    return (info.vid, info.pid, info.serial_number)
        except Exception as e:
            logger.debug("Could not enumerate serial ports: %s", e)
        return None

    def _remember_port_identity(self) -> None:
        """Record the open port's USB identity, if the OS exposes one."""
        identity = self._port_identity(self.port)
        if identity is not None and identity[0] is not None:
            self._port_identity_ref = identity

    def _alternate_port_paths(self) -> list[str]:
        """Device paths other than the configured one carrying the same USB identity.

        Node names are not stable across a re-enumeration -- this very modem moved
        from cu.usbmodem1101 to cu.usbmodem12301 across a replug -- so a reconnect
        loop pinned to the configured path can retry a name that will never open
        again. Matching on vid/pid/serial is what keeps this from adopting some
        other radio that happens to be plugged in.
        """
        reference = self._port_identity_ref
        if not reference:
            return []
        try:
            from serial.tools import list_ports

            ports = list_ports.comports()
        except Exception as e:
            logger.debug("Could not enumerate serial ports: %s", e)
            return []
        current = os.path.realpath(self.port)
        candidates = [
            info.device
            for info in ports
            if os.path.realpath(info.device) != current
            and (info.vid, info.pid, info.serial_number) == reference
        ]
        if reference[2] is None and len(candidates) > 1:
            # Same vendor, same model, no serial number to tell them apart: two of
            # these plugged in at once makes any pick a coin toss, and adopting the
            # wrong radio is worse than staying degraded until the node comes back.
            logger.warning(
                "%d ports share this modem's USB identity and none report a serial "
                "number; not guessing which one is the modem",
                len(candidates),
            )
            return []
        return candidates

    def _remember_modem_identity(self) -> None:
        """Record the handshaked modem's public key as the identity to expect."""
        if self.modem_identity is not None:
            self._modem_identity_ref = bytes(self.modem_identity)

    def _modem_identity_matches(self) -> bool:
        """True when the modem just handshaked is the one we were talking to.

        The USB identity only says "same make and model"; a CP2102's serial is
        often a batch constant like "0001". This compares the radio's own public
        key, which is what actually distinguishes two modems. Unknown on either
        side (no handshake info) means there is nothing to contradict, so the USB
        identity stands as the only filter.
        """
        expected = self._modem_identity_ref
        actual = self.modem_identity
        if expected is None or actual is None:
            return True
        return bytes(actual) == bytes(expected)

    def _note_open_failure(self, exc: BaseException) -> None:
        """Log an open failure, escalating once the port stops opening at all.

        A port that answers with the same error on every attempt is not coming back
        by itself. Whether the node is gone (a rename, which _alternate_port_paths
        covers) or present but unconfigurable (a wedged USB bridge, which nothing
        here can clear) the operator needs telling once -- not an identical line
        every retry for the life of the process.
        """
        errno_val = getattr(exc, "errno", None)
        if errno_val is None and exc.args and isinstance(exc.args[0], int):
            errno_val = exc.args[0]  # termios.error carries (errno, message)
        key = (self.port, errno_val)
        if key == self._open_failure_key:
            self._open_failure_count += 1
        else:
            self._open_failure_key = key
            self._open_failure_count = 1
            self._open_failure_log_ts = None
        self._degraded_reason = f"cannot open {self.port}: {exc}"

        if self._open_failure_count < self._WEDGED_PORT_FAILURES:
            logger.error("Failed to connect to %s: %s", self.port, exc)
            return
        now = time.monotonic()
        if (
            self._open_failure_log_ts is not None
            and now - self._open_failure_log_ts < self._WEDGED_PORT_LOG_INTERVAL_S
        ):
            return
        self._open_failure_log_ts = now
        if os.path.exists(self.port):
            detail = (
                "the device is still enumerated but will not configure, so its USB "
                "bridge or driver is wedged and retrying cannot clear it"
            )
        else:
            detail = "the device node is gone and no port with a matching USB identity was found"
        logger.error(
            "%s has failed to open %d times with the same error (%s): %s. "
            "Reconnect the modem physically to recover.",
            self.port,
            self._open_failure_count,
            exc,
            detail,
        )

    def _run_post_connect_handshake(self) -> bool:
        """Run modem setup steps after serial open."""
        if self._post_connect_settle_s > 0:
            logger.debug(
                "Post-connect settle delay %.2fs before SetHardware handshake",
                self._post_connect_settle_s,
            )
            time.sleep(self._post_connect_settle_s)

        # Auto-configure if requested
        if self.auto_configure and self.radio_config:
            if not self._configure_radio_with_retries():
                logger.warning("Auto-configuration failed after retries")
                return False

        # Query modem info
        self._query_modem_info()

        # Set KISS TXDELAY so key-up delay is not the firmware default 500ms.
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
        self._apply_optional_hardware_config()
        return True

    def _apply_optional_hardware_config(self) -> None:
        """Push configured AGC/FEM settings to the modem.

        Only keys present in radio_config are sent. A setting the modem cannot apply
        is logged, never fatal: front-end tuning must not take a working link down.
        """
        cfg = self.radio_config
        agc = cfg.get("agc_reset_interval_seconds")
        if agc is not None:
            if not self.supports_agc_reset_control():
                logger.warning(
                    "Configured AGC reset interval (%ss) cannot be applied: "
                    "modem firmware does not support it",
                    agc,
                )
            else:
                try:
                    effective = self.set_agc_reset_interval(int(agc))
                except (TypeError, ValueError) as e:
                    logger.warning("Invalid agc_reset_interval_seconds %r: %s", agc, e)
                else:
                    if effective is None:
                        logger.warning("Failed to apply AGC reset interval %ss", agc)
                    else:
                        logger.info("Modem AGC reset interval set to %ds", effective)

        rx_gain = cfg.get("fem_rx_gain")
        tx_gain = cfg.get("fem_tx_gain")
        # SetFemState is all-or-nothing, so drop unsupported bits rather than letting
        # one of them block the other.
        if rx_gain is not None and not self.supports_fem_rx_gain():
            logger.warning(
                "Configured FEM RX gain cannot be applied: modem reports feature unsupported"
            )
            rx_gain = None
        if tx_gain is not None and not self.supports_fem_tx_gain():
            logger.warning(
                "Configured FEM TX gain cannot be applied: modem reports feature unsupported"
            )
            tx_gain = None
        if rx_gain is not None or tx_gain is not None:
            state = self.set_fem_state(rx_gain=rx_gain, tx_gain=tx_gain)
            if state is None:
                logger.warning("Failed to apply FEM state (rx=%s, tx=%s)", rx_gain, tx_gain)
            else:
                logger.info(
                    "Modem FEM state: rx_gain=%s tx_gain=%s",
                    state["rx_gain"],
                    state["tx_gain"],
                )

        boosted = cfg.get("rx_boosted_gain")
        if boosted is not None:
            if not self.supports_rx_boosted_gain():
                logger.warning(
                    "Configured RX boosted gain cannot be applied: "
                    "modem reports feature unsupported"
                )
            elif self.set_rx_boosted_gain(bool(boosted)) != bool(boosted):
                logger.warning("Failed to apply RX boosted gain %s", bool(boosted))
            else:
                logger.info("Modem RX boosted gain set to %s", bool(boosted))

    def _close_serial_connection(self) -> None:
        """Close serial handle without waiting for worker threads."""
        conn = self.serial_conn
        self.serial_conn = None
        if conn and conn.is_open:
            try:
                conn.close()
            except Exception:
                pass

    def _is_stopping(self) -> bool:
        """True when the workers are meant to be winding down."""
        return self._shutting_down or self.stop_event.is_set()

    def _stop_io_threads(self, join_timeout: float = 2.0) -> None:
        """Stop RX/TX threads, skipping current thread to avoid deadlock.

        Closes the port first: the workers' loop conditions key off it being
        open, so that is what actually ends them. Joining alone — the previous
        behaviour — meant a worker blocked in ``read()`` on a port whose close
        had been deferred (see _mark_serial_failure) simply outlived the join
        timeout and kept running against the old handle, while the next
        generation started on the new one. Two RX threads then shared a single
        KISS decoder buffer.
        """
        conn = self.serial_conn
        if conn is not None:
            try:
                if getattr(conn, "is_open", False):
                    conn.close()
            except Exception as e:
                logger.debug("Closing serial port while stopping workers: %s", e)
        current = threading.current_thread()
        for label, thread in (("RX", self.rx_thread), ("TX", self.tx_thread)):
            if thread and thread.is_alive() and thread is not current:
                thread.join(timeout=join_timeout)
                if thread.is_alive():
                    logger.warning(
                        "%s worker still running after %.1fs; it will be replaced",
                        label,
                        join_timeout,
                    )

    def _stop_reconnect_thread(self, join_timeout: float = 2.0) -> None:
        """Join reconnect thread if it is running."""
        current = threading.current_thread()
        if (
            self.reconnect_thread
            and self.reconnect_thread.is_alive()
            and self.reconnect_thread is not current
        ):
            self.reconnect_thread.join(timeout=join_timeout)

    def cleanup(self) -> None:
        """Release resources and abort any in-flight blocking waits."""
        self._shutting_down = True
        self._response_event.set()
        self._tx_done_event.set()
        self.disconnect()

    def _wait_for_modem_ready(self) -> bool:
        """
        Perform serial resync and readiness probing after opening the port.
        """
        if not self.serial_conn:
            return False

        if self.post_open_delay_ms > 0:
            threading.Event().wait(self.post_open_delay_ms / 1000.0)

        try:
            self.serial_conn.reset_input_buffer()
            self.serial_conn.reset_output_buffer()
        except Exception as e:
            logger.debug("Serial buffer reset skipped/failed: %s", e)

        if self.usb_reset_on_connect and hasattr(self.serial_conn, "dtr"):
            try:
                self.serial_conn.dtr = False
                threading.Event().wait(0.1)
                self.serial_conn.dtr = True
            except Exception as e:
                logger.debug("USB DTR toggle skipped/failed: %s", e)

        try:
            self.serial_conn.write(bytes([KISS_FEND]))
            self.serial_conn.flush()
        except Exception as e:
            logger.debug("KISS parser resync write failed: %s", e)

        backoff_seconds = [0.5, 1.0, 2.0, 2.0, 2.0]
        deadline = time.monotonic() + self.startup_retry_budget_sec

        for attempt in range(self.connect_retries):
            if self._shutting_down:
                return False
            resp = self._send_command(CMD_PING, timeout=1.0)
            if resp and resp[0] == RESP_PONG:
                logger.debug("KISS modem responded to ping on attempt %d", attempt + 1)
                return True

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            delay = min(backoff_seconds[min(attempt, len(backoff_seconds) - 1)], remaining)
            threading.Event().wait(delay)

        return False

    def _configure_radio_with_retries(self) -> bool:
        """Attempt auto-configuration with bounded retries/backoff."""
        deadline = time.monotonic() + self.startup_retry_budget_sec
        backoff_seconds = [0.5, 1.0, 2.0, 2.0, 2.0]
        for attempt in range(self.connect_retries):
            if self._shutting_down:
                return False
            if self.configure_radio():
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            delay = min(backoff_seconds[min(attempt, len(backoff_seconds) - 1)], remaining)
            threading.Event().wait(delay)
        return False

    def _write_frame(self, frame: bytes) -> bool:
        """
        Write a complete KISS frame to the serial port.

        Ensures the entire frame (including trailing FEND) is written; retries
        on partial write so we never send a truncated frame.
        This method is atomic across threads so frame bytes cannot interleave
        on the UART when multiple callers write concurrently.

        Returns:
            True if all bytes written, False on error or incomplete write.
        """
        with self._serial_write_lock:
            if not self.serial_conn or not self.serial_conn.is_open:
                self._mark_serial_failure("Serial connection closed during write")
                return False
            offset = 0
            while offset < len(frame):
                try:
                    n = self.serial_conn.write(frame[offset:])
                    if n is None or n <= 0:
                        logger.error("Serial write returned %s", n)
                        self._mark_serial_failure(f"Serial write returned {n}")
                        return False
                    offset += n
                except Exception as e:
                    logger.error("Serial write error: %s", e)
                    self._mark_serial_failure(f"Serial write failed: {e}")
                    return False
            try:
                self.serial_conn.flush()
            except Exception as e:
                logger.error("Serial flush error: %s", e)
                self._mark_serial_failure(f"Serial flush failed: {e}")
                return False
            return True

    def _mark_serial_failure(self, reason: str) -> None:
        """Transition to degraded mode and trigger reconnect loop once."""
        if self.stop_event.is_set():
            return

        now = time.time()
        with self._failure_log_lock:
            should_log = (now - self._last_failure_log_ts) >= self._failure_log_interval_s
            if should_log:
                self._last_failure_log_ts = now
                logger.warning("Marking KISS serial link degraded: %s", reason)

        # Do not wait for the connection lock here. A failed SetHardware write can
        # hold _command_lock (or _serial_write_lock), while the reconnect worker
        # holds _connection_lock and needs that lock for its handshake. Waiting
        # would form an ABBA deadlock and leave the wrapper permanently degraded.
        # Defer closing the port while that lifecycle transition is in progress.
        self._degraded = True
        self._degraded_reason = reason
        self.is_connected = False
        if self._connection_lock.acquire(blocking=False):
            try:
                self._close_serial_connection()
            finally:
                self._connection_lock.release()
        else:
            logger.debug("Connection lock busy; deferring serial close to its owner")

        # Wake any in-flight DATA sender so it fails fast instead of waiting out the
        # full TX_DONE timeout on a link that is already gone (cleanup() does the same).
        self._tx_done_event.set()

        self._start_reconnect_worker()

    def _start_reconnect_worker(self) -> None:
        """Start reconnect thread once."""
        if self.stop_event.is_set() or self._reconnecting_event.is_set():
            return
        self._reconnecting_event.set()
        self.reconnect_thread = threading.Thread(target=self._reconnect_worker, daemon=True)
        self.reconnect_thread.start()

    def _reconnect_worker(self) -> None:
        """Run the reconnect loop and release its gate when the worker exits."""
        try:
            self._reconnect_loop()
        except Exception:
            logger.exception("KISS modem reconnect worker died unexpectedly")
        finally:
            self._reconnecting_event.clear()

    def _reconnect_loop(self) -> None:
        """Reconnect with exponential backoff and re-run modem handshake."""
        attempts = 0
        while not self.stop_event.is_set():
            attempts += 1
            if self._reconnect_max_attempts > 0 and attempts > self._reconnect_max_attempts:
                logger.error(
                    "KISS modem reconnect exhausted after %s attempts (last reason: %s)",
                    self._reconnect_max_attempts,
                    self._degraded_reason or "unknown",
                )
                break

            delay = min(
                self._reconnect_base_delay_s * (2 ** max(0, attempts - 1)),
                self._reconnect_max_delay_s,
            )
            jitter = random.uniform(0.0, min(0.25, delay * 0.2))
            if attempts > 1:
                time.sleep(delay + jitter)

            with self._connection_lock:
                if self.stop_event.is_set():
                    break
                self.is_connected = False
                configured_port = self.port
                # The configured path first; then any node carrying the same USB
                # identity, so a device that came back renamed is still found.
                for candidate in [configured_port] + self._alternate_port_paths():
                    self._stop_io_threads(join_timeout=0.5)
                    self.port = candidate
                    if not self._open_serial_and_start_threads():
                        continue
                    if not self._run_post_connect_handshake():
                        self._close_serial_connection()
                        self.is_connected = False
                        continue
                    if candidate != configured_port and not self._modem_identity_matches():
                        # Same make and model, different radio: adopting it would
                        # silently transmit this node's traffic from someone else's
                        # modem. Leave it alone and keep looking.
                        logger.warning(
                            "%s shares the USB identity but reports modem %s, not %s; "
                            "not adopting it",
                            candidate,
                            (self.modem_identity or b"").hex()[:16] or "unknown",
                            (self._modem_identity_ref or b"").hex()[:16] or "unknown",
                        )
                        self._close_serial_connection()
                        self.is_connected = False
                        continue
                    self.is_connected = True
                    self._degraded = False
                    self._degraded_reason = None
                    self._remember_modem_identity()
                    if candidate != configured_port:
                        logger.warning(
                            "KISS modem reappeared as %s (was %s, same USB identity); "
                            "continuing on the new path",
                            candidate,
                            configured_port,
                        )
                    logger.info("KISS modem serial reconnect successful on attempt %s", attempts)
                    return
                self.port = configured_port

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

    def get_hardware_capabilities(self, refresh: bool = False) -> int:
        """Return the modem's GetCapabilities feature bits (HW_CAP_*).

        Cached from the connect handshake; ``refresh`` re-probes. Firmware that
        predates the command answers UNKNOWN_CMD and reports 0. A probe that gets no
        answer also reports 0 but leaves the cache unset so a later call retries.
        """
        if self.modem_capabilities is not None and not refresh:
            return self.modem_capabilities
        resp = self._send_command(HW_CMD_GET_CAPABILITIES)
        if resp and resp[0] == HW_RESP_CAPABILITIES and len(resp[1]) >= 4:
            self.modem_capabilities = struct.unpack("<I", resp[1][:4])[0]
        elif resp and resp[0] == HW_RESP_ERROR:
            self.modem_capabilities = 0
        else:
            return 0
        return self.modem_capabilities

    def supports_agc_reset_control(self) -> bool:
        return bool(self.get_hardware_capabilities() & HW_CAP_AGC_RESET)

    def supports_fem_rx_gain(self) -> bool:
        return bool(self.get_hardware_capabilities() & HW_CAP_FEM_RX_GAIN)

    def supports_fem_tx_gain(self) -> bool:
        return bool(self.get_hardware_capabilities() & HW_CAP_FEM_TX_GAIN)

    def set_agc_reset_interval(self, seconds: int) -> Optional[int]:
        """Set the modem's periodic AGC reset interval.

        Args:
            seconds: 0-1020; 0 disables. The modem rounds down to a multiple of 4,
                so 1-3 also disable.

        Returns:
            The effective interval the modem is now running, or None on failure.
            On success it is remembered so a reconnect restores it.

        Raises:
            ValueError: seconds outside 0-1020.
        """
        seconds = int(seconds)
        if not 0 <= seconds <= AGC_RESET_INTERVAL_MAX_SEC:
            raise ValueError(f"AGC reset interval must be 0-{AGC_RESET_INTERVAL_MAX_SEC} seconds")
        resp = self._send_command(HW_CMD_SET_AGC_RESET_INTERVAL, struct.pack("<H", seconds))
        if resp and resp[0] == HW_RESP_AGC_RESET_INTERVAL and len(resp[1]) >= 2:
            effective = struct.unpack("<H", resp[1][:2])[0]
            self.radio_config["agc_reset_interval_seconds"] = effective
            self.applied_hardware_config["agc_reset_interval_seconds"] = effective
            return effective
        return None

    def get_agc_reset_interval(self) -> Optional[int]:
        """Return the modem's effective AGC reset interval in seconds (0 = disabled)."""
        resp = self._send_command(HW_CMD_GET_AGC_RESET_INTERVAL)
        if resp and resp[0] == HW_RESP_AGC_RESET_INTERVAL and len(resp[1]) >= 2:
            interval = struct.unpack("<H", resp[1][:2])[0]
            self.applied_hardware_config["agc_reset_interval_seconds"] = interval
            return interval
        return None

    def _record_fem_state(self, payload: bytes) -> Dict[str, Optional[bool]]:
        state = self._decode_fem_state(payload)
        for key, value in state.items():
            if value is not None:
                self.applied_hardware_config[f"fem_{key}"] = value
        return state

    @staticmethod
    def _decode_fem_state(payload: bytes) -> Dict[str, Optional[bool]]:
        cap_mask, value_mask = payload[0], payload[1]

        def bit(mask: int) -> Optional[bool]:
            return bool(value_mask & mask) if cap_mask & mask else None

        return {"rx_gain": bit(HW_FEM_RX_GAIN), "tx_gain": bit(HW_FEM_TX_GAIN)}

    def get_fem_state(self) -> Optional[Dict[str, Optional[bool]]]:
        """Return the board's external FEM gain state.

        Returns:
            ``{"rx_gain": ..., "tx_gain": ...}`` where each value is True/False, or
            None when this board cannot control it. None overall on failure or on
            firmware without FEM support.
        """
        resp = self._send_command(HW_CMD_GET_FEM_STATE)
        if resp and resp[0] == HW_RESP_FEM_STATE and len(resp[1]) >= 2:
            return self._record_fem_state(resp[1])
        return None

    def set_fem_state(
        self, rx_gain: Optional[bool] = None, tx_gain: Optional[bool] = None
    ) -> Optional[Dict[str, Optional[bool]]]:
        """Change external FEM gain; None leaves that control untouched.

        The modem applies the request all-or-nothing and replies UNSUPPORTED if any
        requested control is not available on this board. A request that arrives
        mid-transmit is applied (and answered) when the packet ends.

        Returns:
            The state the modem reported (as get_fem_state), or None on failure.
            Requested values the reply confirms are remembered so a reconnect
            restores them; callers should check the state, not just non-None.
        """
        apply_mask = 0
        value_mask = 0
        for enabled, mask in ((rx_gain, HW_FEM_RX_GAIN), (tx_gain, HW_FEM_TX_GAIN)):
            if enabled is not None:
                apply_mask |= mask
                if enabled:
                    value_mask |= mask
        if not apply_mask:
            return self.get_fem_state()
        # Allow for the reply being held until an in-flight transmit finishes.
        resp = self._send_command(
            HW_CMD_SET_FEM_STATE, bytes([apply_mask, value_mask]), timeout=2 * RESPONSE_TIMEOUT
        )
        if not (resp and resp[0] == HW_RESP_FEM_STATE and len(resp[1]) >= 2):
            return None
        # Trust the reported state, not the request: without a request id the reply
        # could still belong to an earlier request that timed out mid-TX.
        state = self._record_fem_state(resp[1])
        for key, requested in (("rx_gain", rx_gain), ("tx_gain", tx_gain)):
            if requested is not None and state[key] == bool(requested):
                self.radio_config[f"fem_{key}"] = bool(requested)
        return state

    def set_fem_rx_gain(self, enabled: bool) -> bool:
        """Enable/disable the external LNA. False if unsupported or on failure."""
        state = self.set_fem_state(rx_gain=enabled)
        return state is not None and state["rx_gain"] == bool(enabled)

    def set_fem_tx_gain(self, enabled: bool) -> bool:
        """Enable/disable external PA high gain. False if unsupported or on failure."""
        state = self.set_fem_state(tx_gain=enabled)
        return state is not None and state["tx_gain"] == bool(enabled)

    def supports_rx_boosted_gain(self) -> bool:
        return bool(self.get_hardware_capabilities() & HW_CAP_RX_BOOSTED_GAIN)

    def get_rx_boosted_gain(self) -> Optional[bool]:
        """Return whether the radio chip's boosted RX gain is on; None on failure/unsupported."""
        resp = self._send_command(HW_CMD_GET_RX_BOOSTED_GAIN)
        if resp and resp[0] == HW_RESP_RX_BOOSTED_GAIN and len(resp[1]) >= 1:
            enabled = resp[1][0] != 0x00
            self.applied_hardware_config["rx_boosted_gain"] = enabled
            return enabled
        return None

    def set_rx_boosted_gain(self, enabled: bool) -> Optional[bool]:
        """Set the radio chip's boosted RX gain (MeshCore ``radio.rxgain``).

        The modem refuses while a packet is on air or host output is backed up, and
        says so with TxBusy -- which never reaches the command path (see
        HW_ERR_TX_BUSY) -- so a refused request shows up as a timeout. A reply comes
        back at once otherwise, so use a short wait and try once more.

        Returns:
            The state the radio reports after the request, or None on failure. The
            requested value is remembered for reconnects only if the radio confirms it.
        """
        payload = bytes([0x01 if enabled else 0x00])
        for _ in range(2):
            resp = self._send_command(HW_CMD_SET_RX_BOOSTED_GAIN, payload, timeout=2.0)
            if resp and resp[0] == HW_RESP_ERROR:
                return None
            if resp and resp[0] == HW_RESP_RX_BOOSTED_GAIN and len(resp[1]) >= 1:
                state = resp[1][0] != 0x00
                self.applied_hardware_config["rx_boosted_gain"] = state
                if state == bool(enabled):
                    self.radio_config["rx_boosted_gain"] = bool(enabled)
                return state
        return None

    def _query_modem_info(self):
        """Query modem version, identity, device name and capabilities"""
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

            # Get device name. Diagnostic firmwares append crash info here (e.g. the
            # F103 KISS modem reports "HF#n pc=... cfsr=..." after a HardFault reboot),
            # so logging it on every (re)connect surfaces those records automatically.
            device_name = self.get_device_name()
            if device_name:
                logger.info(f"Modem device: {device_name}")

            # Soft probe: pre-v2 firmware answers UNKNOWN_CMD, which reads as 0. Drop the
            # cached value first; the modem may have been reflashed while disconnected.
            self.modem_capabilities = None
            self.applied_hardware_config = {}
            caps = self.get_hardware_capabilities()
            logger.info(f"Modem capabilities: 0x{caps:08X}")

            # Baseline the error counter for this link, so errors the modem counted
            # before openHop connected (or while it was unplugged) are not reported
            # as new ones.
            self._modem_errors_seen = None
            self.get_modem_stats()

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
        if not self.serial_conn or not self.serial_conn.is_open:
            logger.error("Cannot configure radio: serial link not ready")
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

    def send_frame_and_wait(
        self,
        data: bytes,
        timeout: float = RESPONSE_TIMEOUT,
        *,
        verdict: Optional[list] = None,
    ) -> bool:
        """
        Send a data frame and wait for the modem's TX_DONE.

        DATA transmits are single-flight: the modem holds only one pending TX, so
        only one frame may be in flight at a time. Concurrent callers serialize on
        ``_tx_inflight_lock`` so a second frame is never written mid-transmit and
        rejected with TX_BUSY (0x07).

        Args:
            data: Raw packet data to send
            timeout: Base timeout in seconds to wait for TX_DONE; extended to cover
                the estimated airtime of long frames.

        Returns:
            True only when the modem confirms the transmit with TX_DONE status 0x01.
            On False, the reason is appended to *verdict* when one is supplied, and
            also left in ``_tx_last_verdict``.

        Args:
            verdict: optional one-element sink for this call's failure reason.
                ``_tx_last_verdict`` is shared: senders serialise only inside
                ``_tx_inflight_lock``, so by the time a caller reads that field the
                next send may already have replaced it. Pass a list to be given the
                reason belonging to *this* call.
        """
        ok, reason = self._send_frame_and_wait_verdict(data, timeout)
        if verdict is not None:
            verdict.append(reason)
        return ok

    def _verdict(self, reason: str) -> tuple[bool, str]:
        """Record *reason* as the latest failure and return it to this caller."""
        self._tx_last_verdict = reason
        return (False, reason)

    def _send_frame_and_wait_verdict(
        self, data: bytes, timeout: float = RESPONSE_TIMEOUT
    ) -> tuple[bool, Optional[str]]:
        """:meth:`send_frame_and_wait`, returning (ok, reason) to the calling send.

        ``_tx_last_verdict`` is shared state: senders serialise only inside
        ``_tx_inflight_lock``, so by the time a caller reads the field its send has
        released the lock and the next one may already have cleared it. The reason
        travels back with the result instead.
        """
        if self._shutting_down:
            return self._verdict("shutting down")

        # Don't enqueue DATA while the link is down/reconnecting (mirror _send_command).
        in_reconnect_thread = threading.current_thread() is self.reconnect_thread
        if (self._reconnecting_event.is_set() or self._degraded) and not in_reconnect_thread:
            return self._verdict("serial link down or reconnecting")

        # Extend the wait to cover real airtime; a high-SF flood advert can exceed the
        # flat command timeout, which would otherwise look like a spurious TX_DONE timeout.
        try:
            airtime_s = PacketTimingUtils.estimate_airtime_ms(len(data), self.radio_config) / 1000.0
        except Exception:
            airtime_s = 0.0
        effective_timeout = max(timeout, airtime_s + TX_DONE_TIMEOUT_MARGIN_S)

        with self._tx_inflight_lock:
            self._tx_done_event.clear()
            self._tx_done_result = None
            self._tx_busy_seen = False
            self._tx_last_verdict = None

            if not self.send_frame(data):
                return self._verdict("frame not written to the modem")

            # Poll in short slices so a shutdown or mid-flight link failure returns
            # promptly instead of stalling the full timeout. TX_DONE (success or
            # failure) sets the event; a link drop sets it via _mark_serial_failure /
            # cleanup, leaving the result None. TX_BUSY deliberately does not set it.
            deadline = time.monotonic() + effective_timeout
            while not self._shutting_down:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                if self._tx_done_event.wait(min(0.1, remaining)):
                    return self._resolve_tx_done()
                if self._degraded or self.stop_event.is_set():
                    logger.warning("DATA send unconfirmed: serial link lost mid-transmit")
                    return self._verdict("serial link lost mid-transmit")

            if self._shutting_down:
                return self._verdict("shutting down")

            if self._tx_busy_seen:
                # Either the modem discarded this frame (a transmit was already
                # pending) or its host-bound queue overflowed and the TX_DONE never
                # got back to us. Both leave the transmit unconfirmed; neither proves
                # the frame stayed off the air.
                reason = "TX_BUSY and no TX_DONE (modem busy, or host output queue full)"
            else:
                reason = f"no TX_DONE within {effective_timeout:.1f}s"
            logger.warning("DATA send unconfirmed: %s", reason)
            return self._verdict(reason)

    def _resolve_tx_done(self) -> tuple[bool, Optional[str]]:
        """Turn a set ``_tx_done_event`` into (ok, reason), recording the reason."""
        result = self._tx_done_result
        if result is True:
            return (True, None)
        if result is False:
            # The modem completed a transmit cycle and reported failure. Its TX_SENDING
            # watchdog reports 0x00 when the radio's TX-done interrupt is missed, so the
            # frame may well have gone out -- but only 0x01 confirms a clean send, and
            # nothing else here can tell the two apart.
            reason = "modem reported TX_DONE status=0x00"
        else:
            reason = "transmit aborted (link lost or shutting down)"
        logger.warning("DATA send failed: %s", reason)
        return self._verdict(reason)

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
        if self._shutting_down:
            return None

        # Ensure SetHardware requests are single-flight. This prevents concurrent
        # callers from clearing the shared waiter state or stealing responses.
        in_reconnect_thread = threading.current_thread() is self.reconnect_thread
        reconnecting_from_non_reconnect_thread = (
            self._reconnecting_event.is_set() and not in_reconnect_thread
        )
        degraded_from_non_reconnect_thread = self._degraded and not in_reconnect_thread
        if reconnecting_from_non_reconnect_thread or degraded_from_non_reconnect_thread:
            return None

        with self._command_lock:
            expected = sub_cmd | 0x80
            acceptable: set[int] = {expected, HW_RESP_ERROR}
            if sub_cmd in self._SETHW_ALLOW_OK_FOR:
                acceptable.add(HW_RESP_OK)
            extra_resp = self._SETHW_EXTRA_ACCEPT_RESP.get(sub_cmd)
            if extra_resp is not None:
                acceptable.add(extra_resp)

            # Check queued responses first (late/out-of-order arrivals).
            with self._response_lock:
                if sub_cmd in self._SETHW_FRESH_REPLY_ONLY and self._response_queue:
                    stale = [r for r in self._response_queue if r[0] in acceptable]
                    if stale:
                        logger.debug(
                            "Discarding %d stale reply(s) before sub_cmd 0x%02X",
                            len(stale),
                            sub_cmd,
                        )
                        kept = [r for r in self._response_queue if r[0] not in acceptable]
                        self._response_queue.clear()
                        self._response_queue.extend(kept)
                if self._response_queue:
                    n = len(self._response_queue)
                    matched: Optional[tuple[int, bytes]] = None
                    for _ in range(n):
                        resp_sub, resp_payload = self._response_queue.popleft()
                        if matched is None and resp_sub in acceptable:
                            matched = (resp_sub, resp_payload)
                        else:
                            self._response_queue.append((resp_sub, resp_payload))
                    if matched is not None:
                        return matched

                self._response_event.clear()
                self._pending_response = None
                self._expected_response_subcmds = acceptable
                self._active_request_subcmd = sub_cmd

            try:
                # SetHardware frame: type 0x06, payload = sub_cmd (1 byte) + data
                kiss_frame = self._encode_kiss_frame(KISS_CMD_SETHARDWARE, bytes([sub_cmd]) + data)

                if not self._write_frame(kiss_frame):
                    logger.warning("SetHardware frame write failed")
                    return None

                # Wait for response with shutdown-aware polling.
                deadline = time.monotonic() + timeout
                while not self._shutting_down:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    if self._response_event.wait(min(0.1, remaining)):
                        with self._response_lock:
                            return self._pending_response

                if self._shutting_down:
                    return None

                logger.warning(f"SetHardware sub_cmd 0x{sub_cmd:02X} timeout")
                return None
            finally:
                with self._response_lock:
                    self._expected_response_subcmds = None
                    self._active_request_subcmd = None

    def get_radio_config(self, timeout: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """
        Get current radio configuration from modem.

        Blocks the caller thread for up to ``timeout`` seconds (default RESPONSE_TIMEOUT).

        Args:
            timeout: SetHardware response wait in seconds, or None for RESPONSE_TIMEOUT.

        Returns:
            Dict with frequency, bandwidth, sf, cr, or None on error
        """
        t = timeout if timeout is not None else RESPONSE_TIMEOUT
        resp = self._send_command(CMD_GET_RADIO, timeout=t)
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

    def get_tx_power(self, timeout: Optional[float] = None) -> Optional[int]:
        """Get current TX power in dBm.

        Blocks the caller thread for up to ``timeout`` seconds (default RESPONSE_TIMEOUT).

        Args:
            timeout: SetHardware response wait in seconds, or None for RESPONSE_TIMEOUT.
        """
        t = timeout if timeout is not None else RESPONSE_TIMEOUT
        resp = self._send_command(CMD_GET_TX_POWER, timeout=t)
        if resp and resp[0] == RESP_TX_POWER and len(resp[1]) >= 1:
            return resp[1][0]
        return None

    def get_current_rssi(self, timeout: Optional[float] = None) -> int:
        """Get current RSSI from modem.

        Blocks the caller thread for up to ``timeout`` seconds (default RESPONSE_TIMEOUT).

        Args:
            timeout: SetHardware response wait in seconds, or None for RESPONSE_TIMEOUT.
        """
        t = timeout if timeout is not None else RESPONSE_TIMEOUT
        resp = self._send_command(CMD_GET_CURRENT_RSSI, timeout=t)
        if resp and resp[0] == RESP_CURRENT_RSSI and len(resp[1]) >= 1:
            # RSSI is signed byte
            rssi = resp[1][0]
            if rssi > 127:
                rssi -= 256
            return rssi
        return -999

    def is_channel_busy(self, timeout: Optional[float] = None) -> bool:
        """Check if channel is busy.

        Blocks the caller thread for up to ``timeout`` seconds (default RESPONSE_TIMEOUT).

        Args:
            timeout: SetHardware response wait in seconds, or None for RESPONSE_TIMEOUT.
        """
        t = timeout if timeout is not None else RESPONSE_TIMEOUT
        resp = self._send_command(CMD_IS_CHANNEL_BUSY, timeout=t)
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

    def get_noise_floor(self, timeout: Optional[float] = None) -> Optional[int]:
        """Get noise floor in dBm.

        Blocks the caller thread for up to ``timeout`` seconds (default RESPONSE_TIMEOUT).

        Args:
            timeout: SetHardware response wait in seconds, or None for RESPONSE_TIMEOUT.
        """
        t = timeout if timeout is not None else RESPONSE_TIMEOUT
        resp = self._send_command(CMD_GET_NOISE_FLOOR, timeout=t)
        if resp and resp[0] == RESP_NOISE_FLOOR and len(resp[1]) >= 2:
            # Noise floor is signed 16-bit
            noise = struct.unpack("<h", resp[1][:2])[0]
            self.stats["noise_floor"] = noise
            return noise
        return None

    def get_modem_stats(self, timeout: Optional[float] = None) -> Optional[Dict[str, int]]:
        """
        Get modem statistics.

        Blocks the caller thread for up to ``timeout`` seconds (default RESPONSE_TIMEOUT).

        Args:
            timeout: SetHardware response wait in seconds, or None for RESPONSE_TIMEOUT.

        Returns:
            Dict with rx, tx, errors counts or None on error
        """
        t = timeout if timeout is not None else RESPONSE_TIMEOUT
        resp = self._send_command(CMD_GET_STATS, timeout=t)
        if resp and resp[0] == RESP_STATS and len(resp[1]) >= 12:
            rx, tx, errors = struct.unpack("<III", resp[1][:12])
            self._account_modem_errors(errors)
            return {"rx": rx, "tx": tx, "errors": errors}
        return None

    def _account_modem_errors(self, errors: int) -> None:
        """Fold the modem's cumulative error counter into crc_error_count."""
        seen = self._modem_errors_seen
        self._modem_errors_seen = errors
        if seen is None:
            return  # first reading on this link: a baseline, not new errors
        # A counter that went down means the modem restarted and began again from
        # zero, so everything it holds now is new.
        self.crc_error_count += errors - seen if errors >= seen else errors

    def refresh_crc_error_count(self, timeout: Optional[float] = None) -> Optional[int]:
        """Poll the modem's receive-error counter; returns crc_error_count, or None.

        Blocking (one SetHardware round trip); run it off the event loop.
        """
        if self.get_modem_stats(timeout=timeout) is None:
            return None
        return self.crc_error_count

    def get_battery(self, timeout: Optional[float] = None) -> Optional[int]:
        """Get battery voltage in millivolts.

        Blocks the caller thread for up to ``timeout`` seconds (default RESPONSE_TIMEOUT).

        Args:
            timeout: SetHardware response wait in seconds, or None for RESPONSE_TIMEOUT.
        """
        t = timeout if timeout is not None else RESPONSE_TIMEOUT
        resp = self._send_command(CMD_GET_BATTERY, timeout=t)
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

    @property
    def is_degraded(self) -> bool:
        """True while the serial link is known-bad and the reconnect loop owns it.

        ``is_connected`` on its own cannot be read as "usable": it is also False for
        the moments between opening the port and finishing the handshake. A caller
        deciding whether to wait rather than fail -- a local transmit weighing
        whether its retry has any chance -- wants this instead.
        """
        return self._degraded

    @property
    def degraded_reason(self) -> Optional[str]:
        """Why the link was last marked degraded, or None while it is healthy."""
        return self._degraded_reason

    def check_radio_health(self) -> bool:
        """Check modem connectivity. Returns True if connected and modem responds to ping."""
        if not self.is_connected:
            return False
        try:
            healthy = self.ping()
            if not healthy:
                self._mark_serial_failure("Health check ping failed")
            return healthy
        except Exception as e:
            logger.debug(f"KISS modem health check failed: {e}")
            self._mark_serial_failure(f"Health check exception: {e}")
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

        # Wait for modem-level TX_DONE instead of treating queueing as success.
        # Run the blocking wait off the event loop.
        # Dispatch through the public method (subclasses and tests override it),
        # collecting this send's own reason rather than reading shared state after
        # the in-flight lock has been handed to the next sender.
        verdict: list = []
        success = await asyncio.to_thread(
            self.send_frame_and_wait, data, RESPONSE_TIMEOUT, verdict=verdict
        )
        if not success:
            reason = (verdict[0] if verdict else None) or self._tx_last_verdict or "no TX_DONE"
            raise Exception(f"Failed to send frame via KISS modem: {reason}")

        # Use short timeout for GET_AIRTIME so TX path is not blocked if modem
        # is busy or unresponsive (avoids 5s stall and subsequent bad state).
        # Run off the event loop: get_airtime uses blocking SetHardware wait.
        airtime = await asyncio.to_thread(self.get_airtime, len(data), 1.0)
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

    def _sync_get_status(self, timeout: Optional[float] = None) -> Dict[str, Any]:
        """Build radio status dict (blocking SetHardware reads for config and TX power)."""
        cfg = self.get_radio_config(timeout=timeout)
        tx_power = self.get_tx_power(timeout=timeout)
        status: Dict[str, Any] = {
            "initialized": self.is_connected,
            "frequency": cfg["frequency"] if cfg else self.radio_config.get("frequency", 0),
            "tx_power": (
                tx_power
                if tx_power is not None
                else self.radio_config.get("tx_power", self.radio_config.get("power", 0))
            ),
            "spreading_factor": (
                cfg["spreading_factor"] if cfg else self.radio_config.get("spreading_factor", 0)
            ),
            "bandwidth": cfg["bandwidth"] if cfg else self.radio_config.get("bandwidth", 0),
            "coding_rate": cfg["coding_rate"] if cfg else self.radio_config.get("coding_rate", 0),
            "last_rssi": self.stats.get("last_rssi", -999),
            "last_snr": self.stats.get("last_snr", -999.0),
            "last_signal_rssi": self.stats.get("last_rssi", -999),
            "hardware_ready": self.is_connected,
            "crc_error_count": self.crc_error_count,
        }
        return status

    def get_status(self, timeout: Optional[float] = None) -> Dict[str, Any]:
        """Get radio status. Queries modem for config and TX power; blocks the caller thread.

        Args:
            timeout: Per-query SetHardware timeout in seconds for each modem read
                (default RESPONSE_TIMEOUT).
        """
        return self._sync_get_status(timeout)

    async def get_status_async(self, timeout: Optional[float] = None) -> Dict[str, Any]:
        """Get radio status without blocking the asyncio event loop.

        Runs blocking modem I/O in ``asyncio``'s default thread pool executor.
        """
        return await asyncio.to_thread(self._sync_get_status, timeout)

    async def get_radio_config_async(
        self, timeout: Optional[float] = None
    ) -> Optional[Dict[str, Any]]:
        """Async-safe :meth:`get_radio_config`; runs blocking modem I/O in a worker thread."""
        return await asyncio.to_thread(self.get_radio_config, timeout)

    async def get_tx_power_async(self, timeout: Optional[float] = None) -> Optional[int]:
        """Async-safe :meth:`get_tx_power`; runs blocking modem I/O in a worker thread."""
        return await asyncio.to_thread(self.get_tx_power, timeout)

    async def get_current_rssi_async(self, timeout: Optional[float] = None) -> int:
        """Async-safe :meth:`get_current_rssi`; runs blocking modem I/O in a worker thread."""
        return await asyncio.to_thread(self.get_current_rssi, timeout)

    async def is_channel_busy_async(self, timeout: Optional[float] = None) -> bool:
        """Async-safe :meth:`is_channel_busy`; runs blocking modem I/O in a worker thread."""
        return await asyncio.to_thread(self.is_channel_busy, timeout)

    async def get_noise_floor_async(self, timeout: Optional[float] = None) -> Optional[int]:
        """Async-safe :meth:`get_noise_floor`; runs blocking modem I/O in a worker thread."""
        return await asyncio.to_thread(self.get_noise_floor, timeout)

    async def get_modem_stats_async(
        self, timeout: Optional[float] = None
    ) -> Optional[Dict[str, int]]:
        """Async-safe :meth:`get_modem_stats`; runs blocking modem I/O in a worker thread."""
        return await asyncio.to_thread(self.get_modem_stats, timeout)

    async def get_battery_async(self, timeout: Optional[float] = None) -> Optional[int]:
        """Async-safe :meth:`get_battery`; runs blocking modem I/O in a worker thread."""
        return await asyncio.to_thread(self.get_battery, timeout)

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

    def _decode_kiss(self, data: bytes) -> None:
        """Bulk KISS decoder used by the RX worker.

        Behaviorally identical to feeding each byte through ``_decode_kiss_byte`` (which
        the unit tests still exercise), but copies runs of plain bytes with C-level
        ``bytes.find``/slicing and only does per-byte work at FEND/FESC delimiters. This
        slashes Python-level work — and therefore GIL hold time — under bursty traffic, so
        the reader keeps draining the port instead of letting backpressure reach the modem.

        Frame state (in_frame / escaped / rx_frame_buffer) persists on self across calls,
        so frames that span multiple read chunks decode correctly.
        """
        n = len(data)
        if n == 0:
            return

        buf = self.rx_frame_buffer  # bytearray, mutated in place
        in_frame = self.in_frame
        escaped = self.escaped
        i = 0

        while i < n:
            if escaped:
                b = data[i]
                i += 1
                escaped = False
                # Mirrors _decode_kiss_byte: escaped bytes are appended without a size check
                if b == KISS_TFEND:
                    buf.append(KISS_FEND)
                elif b == KISS_TFESC:
                    buf.append(KISS_FESC)
                else:
                    self.stats["frame_errors"] += 1
                    logger.warning(f"Invalid KISS escape sequence: 0x{b:02X}")
                    buf.clear()
                    in_frame = False
                continue

            # Scan to the next delimiter; everything in between is plain frame data.
            fend = data.find(_KISS_FEND_B, i)
            fesc = data.find(_KISS_FESC_B, i)
            if fend == -1:
                nxt = fesc
            elif fesc == -1:
                nxt = fend
            else:
                nxt = fend if fend < fesc else fesc

            run_end = n if nxt == -1 else nxt
            if run_end > i and in_frame:
                run = data[i:run_end]
                # Honor the MAX_FRAME_SIZE resync rule from _decode_kiss_byte: fill to the
                # cap, then the next plain byte triggers a resync (lost-FEND protection).
                space = MAX_FRAME_SIZE - len(buf)
                if len(run) <= space:
                    buf += run
                else:
                    if space > 0:
                        buf += run[:space]
                    self.stats["frame_errors"] += 1
                    logger.warning("KISS frame exceeded max size (%d), resyncing", MAX_FRAME_SIZE)
                    buf.clear()
                    in_frame = False

            if nxt == -1:
                break

            i = run_end
            b = data[i]
            i += 1
            if b == KISS_FEND:
                if in_frame and len(buf) > 0:
                    self._process_received_frame()
                buf.clear()
                in_frame = True
                escaped = False
            else:  # KISS_FESC
                if in_frame:
                    escaped = True

        self.in_frame = in_frame
        self.escaped = escaped

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
        # Snapshot once: the callback can be cleared concurrently (dispatcher
        # RX disarm, wait_for_rx swap), so re-reading the attribute at invoke
        # time could hand _invoke_rx_callback a None mid-race.
        callback = self.on_frame_received
        if callback is None:
            return

        if self._event_loop is not None:
            try:
                self._event_loop.call_soon_threadsafe(
                    lambda: _invoke_rx_callback(callback, data, rssi, snr)
                )
            except RuntimeError as e:
                logger.warning(f"Failed to schedule RX callback on event loop: {e}")
        elif self.rx_thread is not None and threading.current_thread() is self.rx_thread:
            # We're in the RX thread; run callback in executor so we don't block reading
            if self._callback_executor is None:
                self._callback_executor = ThreadPoolExecutor(max_workers=1)
            self._callback_executor.submit(_invoke_rx_callback, callback, data, rssi, snr)
        else:
            # Called from main thread (e.g. unit test); invoke directly
            _invoke_rx_callback(callback, data, rssi, snr)

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
            # Data frame: raw packet only (≤255 bytes per spec). Queue it with a
            # deadline; RxMeta (only sent when signal reporting is on) pairs metrics,
            # otherwise the frame is flushed with sentinel metrics once it times out.
            payload = bytes(self.rx_frame_buffer[1:])
            with self._pending_rx_lock:
                if len(self._pending_rx_queue) >= MAX_PENDING_RX_FRAMES:
                    self.stats["frame_errors"] += 1
                    logger.warning(
                        "Pending RX queue full (max %d), dropping Data frame",
                        MAX_PENDING_RX_FRAMES,
                    )
                else:
                    deadline = time.monotonic() + RX_META_WAIT_SECONDS
                    self._pending_rx_queue.append((payload, deadline))

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
                with self._pending_rx_lock:
                    packet_data = (
                        self._pending_rx_queue.popleft()[0] if self._pending_rx_queue else None
                    )
                if packet_data is not None:
                    if self.on_frame_received:
                        try:
                            self._dispatch_rx_callback(packet_data, rssi_raw, snr_db)
                        except Exception as e:
                            logger.error(f"Error in frame received callback: {e}")
                else:
                    # Leftover RxMeta from a desynced/flushed head: nothing to pair.
                    logger.warning("RxMeta received with no pending Data frame")

            elif sub_cmd == HW_RESP_TX_DONE:
                if len(payload) >= 1:
                    self._tx_done_result = payload[0] == 0x01
                    self.stats["tx_packets"] += 1
                self._tx_done_event.set()

            elif sub_cmd == HW_RESP_ERROR:
                err_code = payload[0] if len(payload) >= 1 else None
                if err_code is not None:
                    self.stats["errors"] += 1
                    logger.warning(f"Modem error: 0x{err_code:02X}")
                if err_code == HW_ERR_TX_BUSY:
                    # Not a verdict on the in-flight DATA frame: the same code covers a
                    # host-output-queue overflow, which says nothing about our transmit
                    # (see HW_ERR_TX_BUSY). Record it and let TX_DONE decide -- failing
                    # the send here reported failure for frames that went out fine
                    # whenever inbound traffic backed the modem's queue up. It still
                    # must not reach the SetHardware response path, where it would be
                    # mis-consumed as the in-flight command's error reply.
                    self.stats["tx_busy"] += 1
                    self._tx_busy_seen = True
                else:
                    with self._response_lock:
                        expected = self._expected_response_subcmds
                        if expected is not None and sub_cmd in expected:
                            self._pending_response = (sub_cmd, payload)
                            self._response_event.set()
                        else:
                            if len(self._response_queue) == self._response_queue.maxlen:
                                logger.debug(
                                    "Dropping oldest SetHardware response (queue full); "
                                    "sub_cmd=0x%02X",
                                    sub_cmd,
                                )
                            self._response_queue.append((sub_cmd, payload))

            else:
                # Other response sub-commands (Identity, Radio, OK, etc.)
                with self._response_lock:
                    expected = self._expected_response_subcmds
                    if expected is not None and sub_cmd in expected:
                        self._pending_response = (sub_cmd, payload)
                        self._response_event.set()
                    else:
                        if len(self._response_queue) == self._response_queue.maxlen:
                            logger.debug(
                                "Dropping oldest SetHardware response (queue full); sub_cmd=0x%02X",
                                sub_cmd,
                            )
                        self._response_queue.append((sub_cmd, payload))
        # cmd 0xFF (Return) has port=15 so is already discarded above

    def _flush_expired_rx_frames(self) -> None:
        """
        Dispatch Data frames whose RxMeta never arrived within RX_META_WAIT_SECONDS.

        Only the head is inspected: deadlines are monotonically increasing, so once
        the head has time remaining the rest do too. Flushing strictly from the head
        preserves arrival order even when a later frame's RxMeta arrives promptly.
        Sentinel metrics (-999) are used; rx_packets is still counted but last_snr /
        last_rssi are left untouched so no fake signal reading is recorded.
        """
        now = time.monotonic()
        while True:
            with self._pending_rx_lock:
                if not self._pending_rx_queue or self._pending_rx_queue[0][1] > now:
                    break
                payload = self._pending_rx_queue.popleft()[0]
                self.stats["rx_packets"] += 1
            if self.on_frame_received:
                try:
                    self._dispatch_rx_callback(payload, -999, -999.0)
                except Exception as e:
                    logger.error(f"Error in frame received callback: {e}")

    def _clear_pending_rx(self) -> None:
        """Drop any queued Data frames (e.g. on disconnect/reconnect) so a stale
        payload never pairs with an RxMeta from a different link session."""
        with self._pending_rx_lock:
            self._pending_rx_queue.clear()

    def _rx_worker(self):
        """Background thread for receiving data"""
        while (
            not self.stop_event.is_set()
            and self.serial_conn is not None
            and self.serial_conn.is_open
        ):
            try:
                conn = self.serial_conn
                if conn is None:
                    break
                # Flush Data frames whose RxMeta timed out. Runs every loop, including
                # idle wakeups (the read below caps at RX_READ_TIMEOUT_S), so a stalled
                # head is released within roughly RX_META_WAIT_SECONDS.
                self._flush_expired_rx_frames()
                # Blocking read of >=1 byte: sleeps in the kernel (releasing the GIL) until
                # data or the port timeout, instead of busy-polling. On wake, drain whatever
                # else has arrived and bulk-decode it in one pass.
                chunk = conn.read(1)
                if not chunk:
                    continue  # timeout with no data; loop re-checks stop_event
                pending = conn.in_waiting
                if pending:
                    chunk += conn.read(pending)
                self._decode_kiss(chunk)

            except Exception as e:
                # Gate on deliberate shutdown, NOT on is_connected. The reconnect
                # path starts these workers with is_connected still False and only
                # sets it True after readiness plus the SetHardware handshake, so
                # the old gate silenced exactly the window a freshly reopened
                # device is most likely to fail in: the thread died with no log
                # and no failure marked, nothing re-armed a reconnect, and the
                # node went permanently deaf while the log read "reconnect
                # successful". Observed in the field, and reproduced.
                if not self._is_stopping():
                    logger.error(f"RX worker error: {e}")
                    self._mark_serial_failure(f"RX worker error: {e}")
                break

    def _tx_worker(self):
        """Background thread for sending data"""
        while (
            not self.stop_event.is_set()
            and self.serial_conn is not None
            and self.serial_conn.is_open
        ):
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
                        self._mark_serial_failure("Serial connection not open in TX worker")
                else:
                    threading.Event().wait(0.01)

            except Exception as e:
                # See _rx_worker: gated on deliberate shutdown, not is_connected.
                if not self._is_stopping():
                    logger.error(f"TX worker error: {e}")
                    self._mark_serial_failure(f"TX worker error: {e}")
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
            self.cleanup()
        except Exception:
            pass
