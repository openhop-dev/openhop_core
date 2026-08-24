"""
TCP LoRa Radio Driver for openhop_core

Implements the LoRaRadio interface using an openHop Modem in Wi-Fi/TCP
mode. Same binary protocol as USBLoRaRadio — only
the transport differs.

Drop-in replacement for SX1262Radio in openhop_core's hardware layer.

Default sync word is 0x12 (MeshCore private syncword), matching the
firmware default — change only if the deployment uses a custom value.

Usage:
    from openhop_core.hardware.tcp_radio import TCPLoRaRadio

    radio = TCPLoRaRadio(
        host="192.168.1.50",
        port=5055,
        token="",                # empty = no auth (matches firmware NVS)
        frequency=869618000,
        bandwidth=62500,
        spreading_factor=8,
        coding_rate=8,
        tx_power=22,
        sync_word=0x12,
        preamble_length=16,
    )
    radio.begin()
    radio.set_rx_callback(my_callback)
    await radio.send(packet_bytes)
"""

import asyncio
import logging
import random
import socket
import struct
import threading
import time
from typing import Callable, Optional

from ..async_primitives import LazyAsyncLock
from .protocol_constants import (
    CMD_AUTH,
    CMD_AUTH_OK,
    CMD_CAD_PARAMS_RESP,
    CMD_CAD_REQUEST,
    CMD_CAD_RESP,
    CMD_CONFIG_RESP,
    CMD_ERROR,
    CMD_NOISE_REQ,
    CMD_NOISE_RESP,
    CMD_PING,
    CMD_PONG,
    CMD_RX_PACKET,
    CMD_RX_START,
    CMD_RX_STARTED,
    CMD_SET_CAD_PARAMS,
    CMD_SET_CONFIG,
    CMD_STATUS_REQ,
    CMD_STATUS_RESP,
    CMD_TX_DONE,
    CMD_TX_FAIL,
    CMD_TX_REQUEST,
    ERR_UNAUTHORIZED,
    MAX_LORA_PAYLOAD,
    PROTO_SYNC,
    RADIO_CONFIG_FMT,
    STATUS_RESP_FMT,
    STATUS_RESP_SIZE,
    build_cad_params_payload,
    build_frame,
    crc16_ccitt,
)

logger = logging.getLogger("TCPLoRaRadio")


# Import LoRaRadio base conditionally — allows standalone testing
try:
    from openhop_core.hardware.base import LoRaRadio

    _HAS_BASE = True
except ImportError:
    _HAS_BASE = False

if _HAS_BASE:

    class _RadioBase(LoRaRadio):
        pass

else:

    class _RadioBase:
        pass


class TCPLoRaRadio(_RadioBase):
    """TCP LoRa Radio — openhop_core LoRaRadio interface over Wi-Fi/TCP.

    Communicates with an openHop Modem in Wi-Fi STA mode. Provides the
    same interface as SX1262Radio and USBLoRaRadio
    for transparent integration with openhop_core.
    """

    def __init__(
        self,
        host: str,
        port: int = 5055,
        token: str = "",
        frequency: int = 869618000,
        bandwidth: int = 62500,
        spreading_factor: int = 8,
        coding_rate: int = 8,
        tx_power: int = 22,
        sync_word: int = 0x12,
        preamble_length: int = 16,
        lbt_enabled: bool = True,
        lbt_max_attempts: int = 5,
        connect_timeout: float = 5.0,
    ):
        self.host = host
        self.port = port
        self.token = token or ""
        self.connect_timeout = connect_timeout

        # Radio config — matches SX1262Radio/USBLoRaRadio constructor params
        self.frequency = frequency
        self.bandwidth = bandwidth
        self.spreading_factor = spreading_factor
        self.coding_rate = coding_rate
        self.tx_power = tx_power
        self.sync_word = sync_word
        self.preamble_length = preamble_length

        # LBT (Listen Before Talk) via CAD
        self.lbt_enabled = lbt_enabled
        self.lbt_max_attempts = lbt_max_attempts

        # State
        self._sock: Optional[socket.socket] = None
        self._sock_lock = threading.Lock()  # guards socket writes
        self._initialized = False
        self._rx_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._event_loop: Optional[asyncio.AbstractEventLoop] = None

        # Custom CAD thresholds. Set lazily by set_custom_cad_thresholds()
        # or perform_cad(det_peak=..., det_min=...); read by _reopen_socket
        # to re-push to the firmware after a reconnect, so they must exist
        # from construction time even when never customised.
        self._custom_cad_peak: Optional[int] = None
        self._custom_cad_min: Optional[int] = None
        self._custom_cad_symbol_num: Optional[int] = None

        # Signal metrics
        self.last_rssi: int = -99
        self.last_snr: float = 0.0
        self.last_signal_rssi: int = -99
        self._noise_floor: float = -99.0

        # RX callback
        self.rx_callback: Optional[Callable[[bytes], None]] = None

        # Response synchronization
        self._response_events: dict[int, asyncio.Event] = {}
        self._response_data: dict[int, Optional[bytes]] = {}
        self._response_lock = threading.Lock()

        # TX lock
        self._tx_lock = LazyAsyncLock()

        # Stats
        self._tx_count = 0
        self._rx_count = 0
        self._crc_errors = 0
        self.crc_error_count = 0

        logger.info(
            f"TCPLoRaRadio configured: {host}:{port} "
            f"(auth={'token' if self.token else 'open'}), "
            f"freq={frequency / 1e6:.1f}MHz, sf={spreading_factor}, "
            f"bw={bandwidth / 1000:.0f}kHz, power={tx_power}dBm, "
            f"syncword=0x{sync_word:04X}"
        )

    # ══════════════════════════════════════════════════════════
    # LoRaRadio interface
    # ══════════════════════════════════════════════════════════

    def begin(self) -> bool:
        """Open TCP connection, authenticate (if token set), push config.

        If the initial connect/handshake fails, the radio is still marked
        initialised and the RX worker is started in deferred-connect mode —
        it will keep retrying the connection with exponential backoff until
        the modem appears. This lets the repeater's HTTP server / setup
        wizard come up even when the modem is offline or its host has not
        been set yet (e.g. placeholder hostname after a fresh install).
        """
        if self._initialized:
            return True

        connected = False
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.settimeout(self.connect_timeout)
            self._sock.connect((self.host, self.port))
            # TCP_NODELAY mirrors the firmware side and avoids Nagle delay
            self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            logger.info(f"TCP connected to {self.host}:{self.port}")
            connected = True

            if self.token and not self._auth_sync(timeout=3.0):
                logger.error("Modem rejected AUTH token — entering deferred mode")
                self._close_sock()
                connected = False
            elif not self._ping_sync(timeout=3.0):
                logger.error("Modem not responding to PING — entering deferred mode")
                self._close_sock()
                connected = False
            elif not self._apply_config_sync():
                logger.error("Failed to configure radio — entering deferred mode")
                self._close_sock()
                connected = False
        except Exception as e:
            logger.warning(
                f"Could not reach modem at {self.host}:{self.port} ({e}); "
                f"starting in deferred-connect mode — RX worker will keep retrying"
            )
            self._close_sock()
            connected = False

        # Always start the RX worker. When connected it processes traffic
        # immediately; otherwise _reconnect_with_backoff drives reconnection
        # so the repeater UI can stay up while the user sets modem_tcp.host
        # via /api/setup_wizard or /api/update_radio_config.
        self._stop_event.clear()
        self._rx_thread = threading.Thread(target=self._rx_worker, daemon=True, name="tcp-lora-rx")
        self._rx_thread.start()

        self._initialized = True
        if connected:
            logger.info("TCPLoRaRadio initialized successfully")
        else:
            logger.info(
                "TCPLoRaRadio initialised in deferred-connect mode "
                "(no modem yet — radio commands will return None until reachable)"
            )
        return True

    async def send(self, data: bytes) -> Optional[dict]:
        """Send a LoRa packet asynchronously with LBT (CAD)."""
        if not self._initialized:
            logger.error("Radio not initialized")
            return None

        async with self._tx_lock:
            lbt_backoff_delays: list[float] = []

            if self.lbt_enabled:
                for attempt in range(self.lbt_max_attempts):
                    try:
                        channel_busy = await self._perform_cad(timeout=1.0)
                        if not channel_busy:
                            logger.debug(f"CAD clear after {attempt + 1} attempt(s)")
                            break
                        else:
                            logger.debug("CAD busy — channel activity detected")
                            if attempt < self.lbt_max_attempts - 1:
                                base_delay = random.randint(50, 200)
                                backoff_ms = min(base_delay * (2**attempt), 5000)
                                lbt_backoff_delays.append(float(backoff_ms))
                                logger.debug(
                                    f"CAD backoff {backoff_ms}ms "
                                    f"(attempt {attempt + 1}/{self.lbt_max_attempts})"
                                )
                                await asyncio.sleep(backoff_ms / 1000.0)
                            else:
                                logger.warning("CAD max attempts — transmitting anyway")
                    except Exception as e:
                        logger.warning(f"CAD failed: {e}, proceeding with TX")
                        break

            try:
                resp = await self._send_command(
                    CMD_TX_REQUEST,
                    data,
                    expect_cmd=CMD_TX_DONE,
                    timeout=10.0,
                )

                if resp is not None:
                    self._tx_count += 1
                    airtime_us = 0
                    if len(resp) >= 4:
                        airtime_us = struct.unpack("<I", resp[:4])[0]
                    airtime_ms = airtime_us / 1000.0

                    logger.debug(f"TX done: {len(data)}B, airtime={airtime_ms:.1f}ms")

                    await self._send_command(
                        CMD_RX_START,
                        b"",
                        expect_cmd=CMD_RX_STARTED,
                        timeout=2.0,
                    )

                    return {
                        "airtime_ms": airtime_ms,
                        "lbt_attempts": len(lbt_backoff_delays),
                        "lbt_backoff_delays_ms": lbt_backoff_delays,
                        "lbt_channel_busy": len(lbt_backoff_delays) > 0,
                    }
                else:
                    logger.error("TX failed — no TX_DONE response")
                    await self._send_command(
                        CMD_RX_START,
                        b"",
                        expect_cmd=CMD_RX_STARTED,
                        timeout=2.0,
                    )
                    return None

            except Exception as e:
                logger.error(f"TX error: {e}")
                return None

    async def wait_for_rx(self) -> bytes:
        """Not used — packets arrive via set_rx_callback()."""
        raise NotImplementedError(
            "Use set_rx_callback(callback) to receive packets asynchronously."
        )

    def set_event_loop(self, loop) -> None:
        # Called by repeater.main so radio can schedule live config pushes.
        self._event_loop = loop

    def set_rx_callback(self, callback: Callable[[bytes], None]):
        """Set RX callback — called by Dispatcher."""
        self.rx_callback = callback
        logger.info("RX callback registered")
        try:
            self._event_loop = asyncio.get_running_loop()
        except RuntimeError:
            pass

    def sleep(self):
        logger.debug("Sleep not applicable for TCP modem")

    def get_last_rssi(self) -> int:
        return self.last_rssi

    def get_last_snr(self) -> float:
        return self.last_snr

    def get_last_signal_rssi(self) -> int:
        return self.last_signal_rssi

    # ══════════════════════════════════════════════════════════
    # Extended interface
    # ══════════════════════════════════════════════════════════

    def check_radio_health(self) -> bool:
        if not self._initialized:
            return False

        if self._rx_thread is None or not self._rx_thread.is_alive():
            logger.warning("RX thread dead — restarting")
            self._stop_event.clear()
            self._rx_thread = threading.Thread(
                target=self._rx_worker, daemon=True, name="tcp-lora-rx"
            )
            self._rx_thread.start()
            return False

        if self._event_loop:
            self._event_loop.call_soon_threadsafe(
                lambda: self._event_loop.create_task(self._refresh_background_metrics())
            )
        return True

    def get_status(self) -> dict:
        return {
            "initialized": self._initialized,
            "frequency": self.frequency,
            "tx_power": self.tx_power,
            "spreading_factor": self.spreading_factor,
            "bandwidth": self.bandwidth,
            "coding_rate": self.coding_rate,
            "last_rssi": self.last_rssi,
            "last_snr": self.last_snr,
            "last_signal_rssi": self.last_signal_rssi,
            "hardware_ready": self._initialized,
            "driver": "modem_tcp",
            "host": self.host,
            "port": self.port,
            "tx_count": self._tx_count,
            "rx_count": self._rx_count,
            "crc_errors": self._crc_errors,
            "crc_error_count": self.crc_error_count,
        }

    async def get_modem_status(self) -> Optional[dict]:
        resp = await self._send_command(
            CMD_STATUS_REQ,
            b"",
            expect_cmd=CMD_STATUS_RESP,
            timeout=2.0,
        )
        if resp and len(resp) >= STATUS_RESP_SIZE:
            fields = struct.unpack(STATUS_RESP_FMT, resp[:STATUS_RESP_SIZE])
            status = {
                "uptime_sec": fields[0],
                "rx_count": fields[1],
                "tx_count": fields[2],
                "crc_errors": fields[3],
                "last_rssi": fields[4],
                "last_snr": fields[5] / 10.0,
                "noise_floor": fields[6] / 10.0,
                "temp_c": fields[7],
                "radio_state": ["idle/rx", "tx", "error"][min(fields[8], 2)],
            }
            self._crc_errors = status["crc_errors"]
            self.crc_error_count = status["crc_errors"]
            return status
        return None

    async def _refresh_background_metrics(self) -> None:
        try:
            await self.refresh_noise_floor()
        except Exception as e:
            logger.debug(f"Noise-floor refresh failed: {e}")
        try:
            await self.get_modem_status()
        except Exception as e:
            logger.debug(f"Status refresh failed: {e}")

    def get_noise_floor(self) -> Optional[float]:
        if not self._initialized:
            return None
        if self._tx_lock.locked():
            return None
        return self._noise_floor

    async def refresh_noise_floor(self) -> Optional[float]:
        resp = await self._send_command(
            CMD_NOISE_REQ,
            b"",
            expect_cmd=CMD_NOISE_RESP,
            timeout=2.0,
        )
        if resp and len(resp) >= 2:
            nf_x10 = struct.unpack("<h", resp[:2])[0]
            self._noise_floor = nf_x10 / 10.0
            logger.debug(f"Noise floor: {self._noise_floor:.1f} dBm")
            return self._noise_floor
        return None

    async def perform_cad(
        self,
        det_peak: Optional[int] = None,
        det_min: Optional[int] = None,
        timeout: float = 1.0,
        calibration: bool = False,
        cad_symbol_num: Optional[int] = None,
    ) -> bool:
        """Public CAD interface compatible with sx1262_wrapper.perform_cad().

        When det_peak/det_min are supplied (e.g. by the repeater's CAD
        calibration tool), program the chip with those thresholds and the
        requested symbol count via CMD_SET_CAD_PARAMS before running the scan.
        """
        if cad_symbol_num is None:
            cad_symbol_num = self._custom_cad_symbol_num or 2
        cad_symbol_num = int(cad_symbol_num)

        if det_peak is not None and det_min is not None:
            new_peak = int(det_peak)
            new_min = int(det_min)
            # Skip the firmware roundtrip when all CAD parameters match the
            # previous call. Changing only symbol count must still be pushed.
            if (
                new_peak != self._custom_cad_peak
                or new_min != self._custom_cad_min
                or cad_symbol_num != self._custom_cad_symbol_num
            ):
                payload = build_cad_params_payload(cad_symbol_num, new_peak, new_min)
                await self._send_command(
                    CMD_SET_CAD_PARAMS,
                    payload,
                    expect_cmd=CMD_CAD_PARAMS_RESP,
                    timeout=2.0,
                )
                self._custom_cad_peak = new_peak
                self._custom_cad_min = new_min
                self._custom_cad_symbol_num = cad_symbol_num

        # Calibration engine passes 0.3s, which is tight for TCP transport
        # with the firmware's CAD-prime delay; floor it so the sweep gets
        # real samples instead of "no response → assumed clear".
        effective = max(timeout, 0.6)
        return await self._perform_cad(effective)

    def cleanup(self):
        self._initialized = False
        self._stop_event.set()

        if self._rx_thread and self._rx_thread.is_alive():
            self._rx_thread.join(timeout=2.0)

        self._close_sock()
        logger.info("TCPLoRaRadio cleanup complete")

    # ══════════════════════════════════════════════════════════
    # Private — socket I/O
    # ══════════════════════════════════════════════════════════

    def _close_sock(self):
        if self._sock is not None:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def _sock_write(self, data: bytes):
        """Thread-safe write to the TCP socket."""
        if self._sock is None:
            raise ConnectionError("socket not open")
        with self._sock_lock:
            self._sock.sendall(data)

    def _auth_sync(self, timeout: float = 3.0) -> bool:
        """Send CMD_AUTH with token payload, expect CMD_AUTH_OK."""
        frame = build_frame(CMD_AUTH, self.token.encode("utf-8"))
        self._sock_write(frame)

        deadline = time.time() + timeout
        while time.time() < deadline:
            resp = self._read_frame_sync(timeout=max(0.1, deadline - time.time()))
            if resp is None:
                continue
            cmd, payload = resp
            if cmd == CMD_AUTH_OK:
                logger.info("Modem accepted AUTH token")
                return True
            if cmd == CMD_ERROR:
                err = payload[0] if payload else 0xFF
                if err == ERR_UNAUTHORIZED:
                    logger.error("AUTH rejected: ERR_UNAUTHORIZED")
                    return False
                logger.warning(f"Unexpected error during AUTH: 0x{err:02X}")
            # Ignore other frames (e.g. broadcast RX) during auth handshake
        return False

    def _ping_sync(self, timeout: float = 3.0) -> bool:
        frame = build_frame(CMD_PING)
        self._sock_write(frame)

        deadline = time.time() + timeout
        while time.time() < deadline:
            resp = self._read_frame_sync(timeout=max(0.1, deadline - time.time()))
            if resp and resp[0] == CMD_PONG:
                logger.info("Modem PONG received — alive")
                return True
        return False

    def _apply_config_sync(self) -> bool:
        payload = struct.pack(
            RADIO_CONFIG_FMT,
            self.frequency,
            self.bandwidth,
            self.spreading_factor,
            self.coding_rate,
            self.tx_power,
            self.sync_word,
            self.preamble_length,
        )
        frame = build_frame(CMD_SET_CONFIG, payload)
        self._sock_write(frame)

        # The firmware may emit RX_PACKET broadcasts concurrently; filter by cmd.
        deadline = time.time() + 3.0
        while time.time() < deadline:
            resp = self._read_frame_sync(timeout=max(0.1, deadline - time.time()))
            if resp is None:
                continue
            cmd, payload = resp
            if cmd == CMD_CONFIG_RESP:
                logger.info(
                    f"Radio configured: {self.frequency / 1e6:.1f}MHz "
                    f"SF{self.spreading_factor} BW{self.bandwidth / 1000:.0f}kHz "
                    f"{self.tx_power}dBm sync=0x{self.sync_word:04X} "
                    f"pre={self.preamble_length}"
                )
                return True
            if cmd == CMD_ERROR:
                err = payload[0] if payload else 0xFF
                logger.error(f"Config rejected by modem: error 0x{err:02X}")
                return False
            # Ignore RX_PACKET or other unrelated frames during config
        logger.error("No config response from modem")
        return False

    def _read_frame_sync(self, timeout: float = 2.0) -> Optional[tuple]:
        """Read one frame synchronously with a single timeout budget."""
        if self._sock is None:
            return None
        try:
            self._sock.settimeout(timeout)

            # Look for SYNC byte
            sync_found = False
            deadline = time.time() + timeout
            while time.time() < deadline:
                b = self._sock.recv(1)
                if not b:
                    return None
                if b[0] == PROTO_SYNC:
                    sync_found = True
                    break
            if not sync_found:
                return None

            # Header (cmd + len)
            hdr = b""
            while len(hdr) < 3:
                chunk = self._sock.recv(3 - len(hdr))
                if not chunk:
                    return None
                hdr += chunk

            cmd = hdr[0]
            length = struct.unpack("<H", hdr[1:3])[0]

            payload = b""
            while len(payload) < length:
                chunk = self._sock.recv(length - len(payload))
                if not chunk:
                    return None
                payload += chunk

            crc_bytes = b""
            while len(crc_bytes) < 2:
                chunk = self._sock.recv(2 - len(crc_bytes))
                if not chunk:
                    return None
                crc_bytes += chunk

            received_crc = struct.unpack("<H", crc_bytes)[0]
            computed_crc = crc16_ccitt(hdr + payload)
            if received_crc != computed_crc:
                logger.warning(f"CRC mismatch: recv=0x{received_crc:04X} comp=0x{computed_crc:04X}")
                return None
            return (cmd, payload)
        except socket.timeout:
            return None
        except (OSError, ConnectionError) as e:
            logger.warning(f"Socket read error: {e}")
            return None

    # ── RX background thread ─────────────────────────────────

    def _reopen_socket(self) -> bool:
        """Open a fresh TCP socket + auth + push config. Returns True on success.
        Does NOT start a new RX worker (we are already in one); does NOT flip
        self._initialized (the radio is still the same instance from the host's
        point of view). Used by _reconnect_with_backoff after a dropped link."""
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.settimeout(self.connect_timeout)
            self._sock.connect((self.host, self.port))
            self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            logger.info(f"TCP re-connected to {self.host}:{self.port}")
            if self.token and not self._auth_sync(timeout=3.0):
                logger.error("Reconnect: AUTH rejected")
                self._close_sock()
                return False
            if not self._ping_sync(timeout=3.0):
                logger.error("Reconnect: PING failed")
                self._close_sock()
                return False
            if not self._apply_config_sync():
                logger.error("Reconnect: SET_CONFIG failed")
                self._close_sock()
                return False
            # Re-apply custom CAD if host had programmed any.
            if self._custom_cad_peak is not None and self._custom_cad_min is not None:
                try:
                    self.set_custom_cad_thresholds(
                        peak=self._custom_cad_peak, min_val=self._custom_cad_min
                    )
                except Exception as e:
                    logger.warning(f"Reconnect: re-push CAD failed: {e}")
            return True
        except Exception as e:
            logger.error(f"Reconnect socket open failed: {e}")
            self._close_sock()
            return False

    def _reconnect_with_backoff(self) -> bool:
        """Exponential backoff (1, 2, 5, 10, 30 s) until socket is up or stop_event fires."""
        for delay in (1.0, 2.0, 5.0, 10.0, 30.0):
            if self._stop_event.is_set():
                return False
            logger.info(f"Reconnect attempt in {delay:.0f}s…")
            if self._stop_event.wait(delay):
                return False
            if self._reopen_socket():
                return True
        # Last resort: keep trying at 30 s intervals forever.
        while not self._stop_event.is_set():
            if self._stop_event.wait(30.0):
                return False
            if self._reopen_socket():
                return True
        return False

    def _rx_worker(self):
        """Background thread: reads socket, dispatches RX packets and responses."""
        logger.debug("RX worker thread started")
        buf = bytearray()

        while not self._stop_event.is_set():
            try:
                if self._sock is None:
                    # Deferred-connect mode: begin() couldn't reach the
                    # modem, so we drive the reconnect ourselves with the
                    # same exponential backoff used after a runtime drop.
                    # Returns False if stop_event fires while waiting.
                    if not self._reconnect_with_backoff():
                        return
                    buf.clear()
                    continue

                # Short recv timeout so stop_event is honoured promptly
                self._sock.settimeout(0.1)
                try:
                    chunk = self._sock.recv(4096)
                except socket.timeout:
                    continue
                except (OSError, ConnectionError) as e:
                    logger.error(f"Socket read error in RX worker: {e} — reconnecting")
                    self._close_sock()
                    buf.clear()
                    if not self._reconnect_with_backoff():
                        return
                    continue

                if not chunk:
                    # Remote closed — try to reopen instead of dying; the
                    # previous behaviour left tcp_radio permanently offline
                    # until systemctl restart (known_issue_tcp_no_reconnect).
                    logger.warning("TCP connection closed by peer — attempting reconnect")
                    self._close_sock()
                    buf.clear()
                    if self._reconnect_with_backoff():
                        continue
                    return

                buf.extend(chunk)

                # Parse complete frames from buffer
                while len(buf) >= 6:
                    sync_idx = buf.find(PROTO_SYNC)
                    if sync_idx < 0:
                        buf.clear()
                        break
                    if sync_idx > 0:
                        buf = buf[sync_idx:]

                    if len(buf) < 4:
                        break

                    cmd = buf[1]
                    length = buf[2] | (buf[3] << 8)
                    # Sanity-cap the LEN field. The largest legitimate frame
                    # is RX_PACKET (6 B header + MAX_LORA_PAYLOAD); anything
                    # bigger means we're parsing garbage from a desync.
                    # Drop the SYNC byte we just consumed and resync rather
                    # than waiting indefinitely for a phantom 64 KB frame.
                    if length > MAX_LORA_PAYLOAD + 32:
                        logger.warning(
                            f"RX frame LEN={length} exceeds sanity bound — "
                            f"dropping SYNC byte and resyncing"
                        )
                        buf = buf[1:]
                        continue
                    frame_size = 1 + 1 + 2 + length + 2

                    if len(buf) < frame_size:
                        break

                    hdr = bytes(buf[1:4])
                    payload = bytes(buf[4 : 4 + length])
                    crc_recv = buf[4 + length] | (buf[5 + length] << 8)
                    crc_comp = crc16_ccitt(hdr + payload)

                    buf = buf[frame_size:]

                    if crc_recv != crc_comp:
                        logger.warning(f"RX CRC mismatch, cmd=0x{cmd:02X}, dropping")
                        continue

                    self._dispatch_frame(cmd, payload)

            except Exception as e:
                logger.error(f"RX worker error: {e}")
                time.sleep(0.1)

        logger.debug("RX worker thread exiting")

    def _dispatch_frame(self, cmd: int, payload: bytes):
        """Route a received frame."""

        if cmd == CMD_RX_PACKET:
            if len(payload) < 6:
                logger.warning(f"RX_PACKET too short: {len(payload)}B")
                return

            rssi = struct.unpack("<h", payload[0:2])[0]
            snr_x10 = struct.unpack("<h", payload[2:4])[0]
            signal_rssi = struct.unpack("<h", payload[4:6])[0]
            lora_data = payload[6:]

            self.last_rssi = rssi
            self.last_snr = snr_x10 / 10.0
            self.last_signal_rssi = signal_rssi
            self._rx_count += 1

            logger.debug(f"RX: {len(lora_data)}B RSSI={rssi}dBm SNR={snr_x10 / 10:.1f}dB")

            if self.rx_callback:
                if self._event_loop is None:
                    try:
                        self._event_loop = asyncio.get_event_loop()
                    except RuntimeError:
                        pass

                if self._event_loop and self._event_loop.is_running():
                    self._event_loop.call_soon_threadsafe(self.rx_callback, lora_data)
                else:
                    try:
                        self.rx_callback(lora_data)
                    except Exception as e:
                        logger.error(f"RX callback error: {e}")
            else:
                logger.warning("RX packet but no callback registered")

        elif cmd == CMD_ERROR:
            err_code = payload[0] if payload else 0xFF
            logger.warning(f"Modem error: 0x{err_code:02X}")
            with self._response_lock:
                for evt_cmd, evt in list(self._response_events.items()):
                    self._response_data[evt_cmd] = None
                    if self._event_loop:
                        self._event_loop.call_soon_threadsafe(evt.set)

        elif cmd == CMD_TX_FAIL:
            # The TX request reached the radio but the chip never asserted
            # TX_DONE before the firmware's own timeout. Wake up whoever is
            # blocked on CMD_TX_DONE so the caller doesn't have to wait out
            # the full 10 s driver timeout.
            logger.warning("Modem TX_FAIL — radio did not assert TX_DONE")
            with self._response_lock:
                evt = self._response_events.get(CMD_TX_DONE)
                if evt is not None:
                    self._response_data[CMD_TX_DONE] = None
                    if self._event_loop:
                        self._event_loop.call_soon_threadsafe(evt.set)

        else:
            with self._response_lock:
                if cmd in self._response_events:
                    self._response_data[cmd] = payload
                    evt = self._response_events[cmd]
                    if self._event_loop:
                        self._event_loop.call_soon_threadsafe(evt.set)

    # ── Async command/response ────────────────────────────────

    async def _send_command(
        self,
        cmd: int,
        payload: bytes,
        expect_cmd: int,
        timeout: float = 5.0,
    ) -> Optional[bytes]:
        if self._sock is None:
            return None

        if self._event_loop is None:
            try:
                self._event_loop = asyncio.get_running_loop()
            except RuntimeError:
                pass

        evt = asyncio.Event()
        with self._response_lock:
            self._response_events[expect_cmd] = evt
            self._response_data.pop(expect_cmd, None)

        try:
            frame = build_frame(cmd, payload)
            try:
                self._sock_write(frame)
            except (OSError, ConnectionError) as e:
                logger.error(f"TCP write failed: {e}")
                return None

            try:
                await asyncio.wait_for(evt.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                logger.warning(f"Timeout: cmd=0x{cmd:02X} → expected 0x{expect_cmd:02X}")
                return None

            return self._response_data.get(expect_cmd)

        finally:
            with self._response_lock:
                self._response_events.pop(expect_cmd, None)
                self._response_data.pop(expect_cmd, None)

    async def _perform_cad(self, timeout: float = 1.0) -> bool:
        resp = await self._send_command(
            CMD_CAD_REQUEST,
            b"",
            expect_cmd=CMD_CAD_RESP,
            timeout=timeout,
        )
        if resp and len(resp) >= 1:
            busy = resp[0] != 0
            logger.debug(f"CAD: {'BUSY' if busy else 'CLEAR'}")
            return busy
        logger.warning("CAD no response — assuming clear")
        return False

    # ── Config setters — live push to firmware ───────────────
    #
    # Callers (repeater HTTP UI) invoke these from threads that are not
    # the asyncio loop, so we bridge with run_coroutine_threadsafe().
    # Local state is always updated first; firmware ack is best-effort —
    # a timeout downgrades to False but keeps the in-memory state current
    # so the next begin()/_apply_config_sync will flush it.
    def _run_async_safe(self, coro, wait_timeout: float = 6.0):
        """Run *coro* on self._event_loop, whether we're on that loop or not.
        On-loop caller: schedule with ensure_future (fire-and-forget, logs in bg).
        Off-loop caller: block with run_coroutine_threadsafe and return its result.
        Returns True on success/scheduled, False on timeout/exception."""
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is self._event_loop:
            # Same thread/loop — can't block; schedule and log outcome asynchronously.
            async def _bg():
                try:
                    res = await coro
                    logger.info(f"Async config push result: ok={res is not None}")
                except Exception as e:
                    logger.error(f"Async config push error: {e}", exc_info=True)

            asyncio.ensure_future(_bg())
            return True
        # Different thread — blocking wait is fine.
        try:
            fut = asyncio.run_coroutine_threadsafe(coro, self._event_loop)
            resp = fut.result(timeout=wait_timeout)
            return resp is not None
        except Exception as e:
            logger.error(f"Cross-thread config push error: {e}", exc_info=True)
            return False

    def _push_config_live(self, changed: str) -> bool:
        if not self._initialized:
            return True
        if self._event_loop is None or not self._event_loop.is_running():
            return True
        payload = struct.pack(
            RADIO_CONFIG_FMT,
            self.frequency,
            self.bandwidth,
            self.spreading_factor,
            self.coding_rate,
            self.tx_power,
            self.sync_word,
            self.preamble_length,
        )
        ok = self._run_async_safe(
            self._send_command(CMD_SET_CONFIG, payload, expect_cmd=CMD_CONFIG_RESP, timeout=5.0),
            wait_timeout=6.0,
        )
        logger.info(f"Live config push ({changed}): {'OK' if ok else 'TIMEOUT'}")
        return ok

    def set_frequency(self, frequency: int) -> bool:
        self.frequency = frequency
        return self._push_config_live(f"freq={frequency}")

    def set_tx_power(self, power: int) -> bool:
        self.tx_power = power
        return self._push_config_live(f"power={power}")

    def set_spreading_factor(self, sf: int) -> bool:
        self.spreading_factor = sf
        return self._push_config_live(f"sf={sf}")

    def set_bandwidth(self, bw: int) -> bool:
        self.bandwidth = bw
        return self._push_config_live(f"bw={bw}")

    def set_coding_rate(self, cr: int) -> bool:
        self.coding_rate = cr
        return self._push_config_live(f"cr={cr}")

    def set_preamble_length(self, preamble: int) -> bool:
        self.preamble_length = preamble
        return self._push_config_live(f"preamble={preamble}")

    def set_sync_word(self, sync_word: int) -> bool:
        self.sync_word = sync_word
        return self._push_config_live(f"syncword=0x{sync_word:04X}")

    # CAD thresholds — v0.5.4 firmware exposes them via CMD_SET_CAD_PARAMS.
    # symNum=0x01 (2 symbols) and exitMode=0x00 (STDBY) match pymc_core SX1262 defaults.
    def set_tcp_target(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        token: Optional[str] = None,
    ) -> bool:
        """Change the modem TCP endpoint at runtime.

        Updates self.host/port/token in place, closes the current socket,
        and lets _rx_worker re-establish the connection via the existing
        backoff path. Returns True if any field actually changed.

        Use case: a fresh repeater install starts in deferred-connect mode
        with a placeholder host; the user supplies the real one later
        through a dedicated config panel, and we apply it without a
        service restart.
        """
        changed = []
        if host is not None and host != self.host:
            self.host = host
            changed.append(f"host={host}")
        if port is not None:
            try:
                p = int(port)
            except (TypeError, ValueError):
                p = self.port
            if p != self.port and 1 <= p <= 65535:
                self.port = p
                changed.append(f"port={p}")
        if token is not None and token != self.token:
            self.token = token
            changed.append("token=***")

        if not changed:
            return False

        logger.info(f"TCP target changed: {', '.join(changed)} — forcing reconnect")
        # Drop the socket; _rx_worker sees self._sock is None and runs
        # _reconnect_with_backoff against the new host/port.
        self._close_sock()
        return True

    def set_custom_cad_thresholds(self, peak: int, min_val: int) -> bool:
        self._custom_cad_peak = int(peak)
        self._custom_cad_min = int(min_val)
        if not self._initialized:
            return True
        if self._event_loop is None or not self._event_loop.is_running():
            return True
        payload = build_cad_params_payload(self._custom_cad_symbol_num or 2, peak, min_val)
        ok = self._run_async_safe(
            self._send_command(
                CMD_SET_CAD_PARAMS, payload, expect_cmd=CMD_CAD_PARAMS_RESP, timeout=3.0
            ),
            wait_timeout=4.0,
        )
        logger.info(f"CAD thresholds pushed peak={peak} min={min_val}: {'OK' if ok else 'TIMEOUT'}")
        return ok

    def set_custom_cad_symbol_num(self, cad_symbol_num: int) -> bool:
        """Store a validated CAD symbol count for calls that omit an override."""
        build_cad_params_payload(cad_symbol_num, 0, 0)
        self._custom_cad_symbol_num = int(cad_symbol_num)
        return True

    def clear_custom_cad_thresholds(self) -> None:
        self._custom_cad_peak = None
        self._custom_cad_min = None
        # Firmware retains last programmed values until reboot; explicit
        # reset would need a dedicated command — out of scope for v0.5.4.

    def __del__(self):
        try:
            self.cleanup()
        except Exception:
            pass
