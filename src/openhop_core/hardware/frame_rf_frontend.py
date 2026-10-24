"""Host control of an OpenHop modem's AGC reset, FEM gain, and RX boost.

The v0.8 frame commands are not stored on the modem. ``radio_config`` is what
a reconnect must send again; ``applied_hardware_config`` is only what a reply
has confirmed on this link.

FEM and RX-boost replies, including a bare ``CMD_ERROR``, carry no request id
and can be held until the current reception ends. A timed-out exchange must
drain its reply before another command is sent on that link.
"""

import asyncio
import logging
import struct
import threading
import time
from typing import Dict, Optional

from .protocol_constants import (
    AGC_INTERVAL_MAX_SEC,
    CMD_AGC_INTERVAL_RESP,
    CMD_ERROR,
    CMD_FEM_STATE_RESP,
    CMD_GET_AGC_INTERVAL,
    CMD_GET_FEM_STATE,
    CMD_GET_RF_CAPS,
    CMD_GET_RX_BOOST,
    CMD_RF_CAPS_RESP,
    CMD_RX_BOOST_RESP,
    CMD_SET_AGC_INTERVAL,
    CMD_SET_FEM_STATE,
    CMD_SET_RX_BOOST,
    FEM_STATE_RX_LNA,
    FEM_STATE_TX_PA,
    RF_CAP_AGC,
    RF_CAP_FEM_RX_LNA,
    RF_CAP_FEM_TX_PA,
    RF_CAP_RX_BOOSTED_GAIN,
    build_frame,
)

logger = logging.getLogger("FrameRfControls")

FRONTEND_KEYS = (
    "agc_reset_interval_seconds",
    "fem_rx_gain",
    "fem_tx_gain",
    "rx_boosted_gain",
)

# A SET can wait out the packet already on air. Gets and AGC are answered
# in the command handler, so they do not need that budget.
_RF_SET_TIMEOUT_S = 8.0
_RF_GET_TIMEOUT_S = 3.0

_RF_REPLY_CMDS = {
    CMD_RF_CAPS_RESP,
    CMD_AGC_INTERVAL_RESP,
    CMD_FEM_STATE_RESP,
    CMD_RX_BOOST_RESP,
}


def _as_int(value) -> Optional[int]:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


class FrameRfControls:
    """Methods mixed into ``TCPLoRaRadio`` and ``USBLoRaRadio``."""

    def _init_rf_controls(self, radio_config: Optional[dict] = None) -> None:
        source = radio_config if isinstance(radio_config, dict) else {}
        self.radio_config: Dict[str, object] = {}
        for key in FRONTEND_KEYS:
            if key in source and source[key] is not None:
                self.radio_config[key] = source[key]
        self.applied_hardware_config: Dict[str, object] = {}
        self._rf_caps: Optional[int] = None
        self._rf_expect_stale: set[int] = set()
        self._rf_lock = threading.Lock()
        if not hasattr(self, "_response_lock"):
            self._response_lock = threading.Lock()

    @staticmethod
    def effective_agc_reset_interval(seconds: int) -> Optional[int]:
        """The interval a frame modem will run, or None if it will reject it.

        Unlike KISS, the frame path does not round down to a multiple of 4.
        """
        value = _as_int(seconds)
        if value is None or not 0 <= value <= AGC_INTERVAL_MAX_SEC:
            return None
        return value

    def _rf_link_open(self) -> bool:
        sock = getattr(self, "_sock", None)
        if sock is not None:
            return True
        serial = getattr(self, "_serial", None)
        return bool(serial is not None and getattr(serial, "is_open", False))

    def _rf_write_frame(self, frame: bytes) -> None:
        if getattr(self, "_sock", None) is not None:
            self._sock_write(frame)
            return
        self._serial.write(frame)
        self._serial.flush()

    def _rf_use_sync(self) -> bool:
        """True while the RX worker is not the reader, so a direct read is safe."""
        loop = getattr(self, "_event_loop", None)
        if loop is None or not loop.is_running():
            return True
        rx = getattr(self, "_rx_thread", None)
        return rx is not None and threading.current_thread() is rx

    def _deliver_waiting_frame(self, cmd: int, payload: bytes) -> bool:
        """Wake the command waiting for ``cmd``. Caller holds ``_response_lock``."""
        if self._rf_discard_late(cmd):
            return True
        evt = self._response_events.get(cmd)
        if evt is None:
            return False
        self._response_data[cmd] = payload
        loop = getattr(self, "_event_loop", None)
        if loop is not None and loop.is_running():
            loop.call_soon_threadsafe(evt.set)
        else:
            evt.set()
        return True

    def _rf_note_unsolicited(self, cmd: int, payload: bytes) -> bool:
        """Discard an unclaimed RF reply. Caller holds ``_response_lock``."""
        return self._rf_discard_late(cmd) or cmd in _RF_REPLY_CMDS

    def _rf_discard_late(self, cmd: int) -> bool:
        """Consume either terminal reply, never leave an orphan CMD_ERROR marker."""
        if cmd in self._rf_expect_stale:
            self._rf_expect_stale.clear()
            logger.debug("Discarding late RF reply 0x%02X", cmd)
            return True
        return False

    async def _rf_wait_clean_async(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while True:
            with self._response_lock:
                if not self._rf_expect_stale:
                    return True
            if time.monotonic() >= deadline:
                logger.warning("Previous RF reply still pending; command not sent")
                return False
            await asyncio.sleep(min(0.01, max(0, deadline - time.monotonic())))

    def _rf_transact(
        self, cmd: int, payload: bytes, expect: int, timeout: float
    ) -> Optional[tuple[int, bytes]]:
        try:
            if asyncio.get_running_loop() is getattr(self, "_event_loop", None):
                logger.error("RF control was called on the radio event loop")
                return None
        except RuntimeError:
            pass
        with self._rf_lock:
            return self._rf_transact_fresh(cmd, payload, expect, timeout)

    def _rf_transact_fresh(
        self, cmd: int, payload: bytes, expect: int, timeout: float
    ) -> Optional[tuple[int, bytes]]:
        if not self._rf_link_open():
            return None
        if self._rf_use_sync():
            return self._rf_transact_sync(cmd, payload, expect, timeout)
        finished = threading.Event()
        cancelled = threading.Event()

        async def exchange():
            try:
                # Include command-lock contention and draining in the same budget.
                return await asyncio.wait_for(
                    self._rf_transact_async(cmd, payload, expect, timeout, cancelled), timeout
                )
            except asyncio.TimeoutError:
                logger.warning("RF command timed out: 0x%02X", cmd)
                return None
            finally:
                finished.set()

        fut = asyncio.run_coroutine_threadsafe(exchange(), self._event_loop)
        try:
            return fut.result(timeout=timeout + 1.0)
        except Exception as exc:
            cancelled.set()
            fut.cancel()
            finished.wait(timeout=1.0)
            logger.warning("RF exchange failed: %s", exc)
            return None

    def _rf_transact_sync(
        self, cmd: int, payload: bytes, expect: int, timeout: float
    ) -> Optional[tuple[int, bytes]]:
        deadline = time.monotonic() + timeout
        while True:
            with self._response_lock:
                if not self._rf_expect_stale:
                    break
            if time.monotonic() >= deadline:
                logger.warning("Previous RF reply still pending; command not sent")
                return None
            resp = self._read_frame_sync(timeout=max(0.01, deadline - time.monotonic()))
            if resp:
                with self._response_lock:
                    self._rf_discard_late(resp[0])
        try:
            self._rf_write_frame(build_frame(cmd, payload))
        except Exception as exc:
            logger.warning("RF write failed: %s", exc)
            return None
        accept = {expect, CMD_ERROR}
        while time.monotonic() < deadline:
            remaining = max(0.05, deadline - time.monotonic())
            resp = self._read_frame_sync(timeout=remaining)
            if resp and resp[0] in accept:
                return resp
        with self._response_lock:
            self._rf_expect_stale = {expect, CMD_ERROR}
        return None

    async def _rf_transact_async(
        self,
        cmd: int,
        payload: bytes,
        expect: int,
        timeout: float,
        cancelled: Optional[threading.Event] = None,
    ) -> Optional[tuple[int, bytes]]:
        async with self._command_lock:
            if not self._rf_link_open():
                return None
            if not await self._rf_wait_clean_async(timeout):
                return None
            if self._event_loop is None:
                try:
                    self._event_loop = asyncio.get_running_loop()
                except RuntimeError:
                    pass
            ok_evt = asyncio.Event()
            err_evt = asyncio.Event()
            with self._response_lock:
                if cancelled is not None and cancelled.is_set():
                    return None
                self._response_events[expect] = ok_evt
                self._response_data.pop(expect, None)
                self._response_events[CMD_ERROR] = err_evt
                self._response_data.pop(CMD_ERROR, None)
            sent = False
            waiters = set()
            try:
                try:
                    self._rf_write_frame(build_frame(cmd, payload))
                    sent = True
                except Exception as exc:
                    logger.warning("RF write failed: %s", exc)
                    return None
                waiters = {
                    asyncio.create_task(ok_evt.wait()),
                    asyncio.create_task(err_evt.wait()),
                }
                done, pending = await asyncio.wait(
                    waiters,
                    timeout=timeout,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for task in pending:
                    task.cancel()
                if not done:
                    logger.warning("Timeout: cmd=0x%02X → expected 0x%02X", cmd, expect)
                    return None
                with self._response_lock:
                    if err_evt.is_set() and self._response_data.get(CMD_ERROR) is not None:
                        return (CMD_ERROR, self._response_data[CMD_ERROR])
                    data = self._response_data.get(expect)
                    if data is None:
                        return None
                    return (expect, data)
            finally:
                with self._response_lock:
                    if (
                        sent
                        and expect not in self._response_data
                        and CMD_ERROR not in self._response_data
                    ):
                        self._rf_expect_stale = {expect, CMD_ERROR}
                    self._response_events.pop(expect, None)
                    self._response_data.pop(expect, None)
                    self._response_events.pop(CMD_ERROR, None)
                    self._response_data.pop(CMD_ERROR, None)
                for task in waiters:
                    task.cancel()
                await asyncio.gather(*waiters, return_exceptions=True)

    def _rf_error_code(self, reply: Optional[tuple[int, bytes]]) -> Optional[int]:
        if not reply or reply[0] != CMD_ERROR or not reply[1]:
            return None
        return reply[1][0]

    def get_rf_caps(self) -> int:
        if self._rf_caps is not None:
            return self._rf_caps
        reply = self._rf_transact(CMD_GET_RF_CAPS, b"", CMD_RF_CAPS_RESP, _RF_GET_TIMEOUT_S)
        if reply and reply[0] == CMD_RF_CAPS_RESP and len(reply[1]) >= 4:
            self._rf_caps = struct.unpack("<I", reply[1][:4])[0]
            return self._rf_caps
        if self._rf_error_code(reply) is not None:
            # The firmware knows the command and refused it. Don't probe again
            # until the next connect.
            self._rf_caps = 0
        return 0

    def supports_agc_reset_control(self) -> bool:
        return bool(self.get_rf_caps() & RF_CAP_AGC)

    def supports_fem_rx_gain(self) -> bool:
        return bool(self.get_rf_caps() & RF_CAP_FEM_RX_LNA)

    def supports_fem_tx_gain(self) -> bool:
        return bool(self.get_rf_caps() & RF_CAP_FEM_TX_PA)

    def supports_rx_boosted_gain(self) -> bool:
        return bool(self.get_rf_caps() & RF_CAP_RX_BOOSTED_GAIN)

    def set_agc_reset_interval(self, seconds: int) -> Optional[int]:
        """Set the modem's AGC reset interval. 0 disables. Returns the effective
        value, or None if the modem rejected it or did not answer.
        """
        effective = self.effective_agc_reset_interval(seconds)
        if effective is None:
            return None
        reply = self._rf_transact(
            CMD_SET_AGC_INTERVAL,
            struct.pack("<H", effective),
            CMD_AGC_INTERVAL_RESP,
            _RF_GET_TIMEOUT_S,
        )
        if not reply or reply[0] != CMD_AGC_INTERVAL_RESP or len(reply[1]) < 2:
            return None
        applied = struct.unpack("<H", reply[1][:2])[0]
        self.radio_config["agc_reset_interval_seconds"] = applied
        self.applied_hardware_config["agc_reset_interval_seconds"] = applied
        return applied

    def get_agc_reset_interval(self) -> Optional[int]:
        reply = self._rf_transact(
            CMD_GET_AGC_INTERVAL, b"", CMD_AGC_INTERVAL_RESP, _RF_GET_TIMEOUT_S
        )
        if not reply or reply[0] != CMD_AGC_INTERVAL_RESP or len(reply[1]) < 2:
            return None
        interval = struct.unpack("<H", reply[1][:2])[0]
        self.applied_hardware_config["agc_reset_interval_seconds"] = interval
        return interval

    @staticmethod
    def _decode_fem_state(payload: bytes) -> Optional[Dict[str, Optional[bool]]]:
        if len(payload) < 2:
            return None
        cap_mask, value_mask = payload[0], payload[1]

        def bit(mask: int) -> Optional[bool]:
            return bool(value_mask & mask) if cap_mask & mask else None

        return {"rx_gain": bit(FEM_STATE_RX_LNA), "tx_gain": bit(FEM_STATE_TX_PA)}

    def _record_fem_state(self, payload: bytes) -> Optional[Dict[str, Optional[bool]]]:
        state = self._decode_fem_state(payload)
        if state is None:
            return None
        for key, value in state.items():
            if value is not None:
                self.applied_hardware_config[f"fem_{key}"] = value
        return state

    def get_fem_state(self) -> Optional[Dict[str, Optional[bool]]]:
        reply = self._rf_transact(CMD_GET_FEM_STATE, b"", CMD_FEM_STATE_RESP, _RF_SET_TIMEOUT_S)
        if not reply or reply[0] != CMD_FEM_STATE_RESP:
            return None
        return self._record_fem_state(reply[1])

    def set_fem_state(
        self, rx_gain: Optional[bool] = None, tx_gain: Optional[bool] = None
    ) -> Optional[Dict[str, Optional[bool]]]:
        """Change external FEM gain. None leaves that bit alone.

        The modem rejects the whole request if any apply bit is one it cannot
        control. A SET that arrives during reception is answered when it ends.
        """
        apply_mask = 0
        value_mask = 0
        for enabled, mask in ((rx_gain, FEM_STATE_RX_LNA), (tx_gain, FEM_STATE_TX_PA)):
            if enabled is not None:
                apply_mask |= mask
                if enabled:
                    value_mask |= mask
        if not apply_mask:
            return self.get_fem_state()
        reply = self._rf_transact(
            CMD_SET_FEM_STATE,
            bytes([apply_mask, value_mask]),
            CMD_FEM_STATE_RESP,
            _RF_SET_TIMEOUT_S,
        )
        if not reply or reply[0] != CMD_FEM_STATE_RESP:
            return None
        state = self._record_fem_state(reply[1])
        if state is None:
            return None
        for key, requested in (("rx_gain", rx_gain), ("tx_gain", tx_gain)):
            if requested is not None and state.get(key) == bool(requested):
                self.radio_config[f"fem_{key}"] = bool(requested)
        return state

    def set_fem_rx_gain(self, enabled: bool) -> bool:
        state = self.set_fem_state(rx_gain=enabled)
        return state is not None and state.get("rx_gain") == bool(enabled)

    def set_fem_tx_gain(self, enabled: bool) -> bool:
        state = self.set_fem_state(tx_gain=enabled)
        return state is not None and state.get("tx_gain") == bool(enabled)

    def get_rx_boosted_gain(self) -> Optional[bool]:
        reply = self._rf_transact(CMD_GET_RX_BOOST, b"", CMD_RX_BOOST_RESP, _RF_SET_TIMEOUT_S)
        if not reply or reply[0] != CMD_RX_BOOST_RESP or not reply[1]:
            return None
        enabled = reply[1][0] != 0
        self.applied_hardware_config["rx_boosted_gain"] = enabled
        return enabled

    def set_rx_boosted_gain(self, enabled: bool) -> Optional[bool]:
        """Set the radio chip's boosted RX gain.

        A failed write comes back as ``ERR_RADIO_INIT`` (previous mode kept) or
        ``ERR_RADIO_FAULT`` (state unknown). The requested value is remembered
        for reconnects only when the reply confirms it.
        """
        reply = self._rf_transact(
            CMD_SET_RX_BOOST,
            bytes([0x01 if enabled else 0x00]),
            CMD_RX_BOOST_RESP,
            _RF_SET_TIMEOUT_S,
        )
        if not reply or reply[0] != CMD_RX_BOOST_RESP or not reply[1]:
            return None
        state = reply[1][0] != 0
        self.applied_hardware_config["rx_boosted_gain"] = state
        if state == bool(enabled):
            self.radio_config["rx_boosted_gain"] = bool(enabled)
        return state

    def apply_saved_rf_controls(self) -> None:
        """Push configured front-end settings after connect. Never fatal."""
        self._rf_caps = None
        self.applied_hardware_config.clear()
        with self._response_lock:
            self._rf_expect_stale.clear()
        if not any(key in self.radio_config for key in FRONTEND_KEYS):
            return

        agc = self.radio_config.get("agc_reset_interval_seconds")
        if agc is not None:
            if not self.supports_agc_reset_control():
                logger.warning(
                    "Configured AGC reset interval (%ss) cannot be applied: "
                    "modem does not support it",
                    agc,
                )
            else:
                applied = self.set_agc_reset_interval(agc)
                if applied is None:
                    logger.warning("Failed to apply AGC reset interval %ss", agc)
                else:
                    logger.info("Modem AGC reset interval set to %ds", applied)

        rx_gain = self.radio_config.get("fem_rx_gain")
        tx_gain = self.radio_config.get("fem_tx_gain")
        if rx_gain is not None and not self.supports_fem_rx_gain():
            logger.warning("Configured FEM RX gain cannot be applied on this modem")
            rx_gain = None
        if tx_gain is not None and not self.supports_fem_tx_gain():
            logger.warning("Configured FEM TX gain cannot be applied on this modem")
            tx_gain = None
        if rx_gain is not None or tx_gain is not None:
            state = self.set_fem_state(
                rx_gain=None if rx_gain is None else bool(rx_gain),
                tx_gain=None if tx_gain is None else bool(tx_gain),
            )
            if state is None:
                logger.warning("Failed to apply FEM state rx=%s tx=%s", rx_gain, tx_gain)

        boosted = self.radio_config.get("rx_boosted_gain")
        if boosted is not None:
            if not self.supports_rx_boosted_gain():
                logger.warning("Configured RX boosted gain cannot be applied on this modem")
            elif self.set_rx_boosted_gain(bool(boosted)) != bool(boosted):
                logger.warning("Failed to apply RX boosted gain %s", boosted)
