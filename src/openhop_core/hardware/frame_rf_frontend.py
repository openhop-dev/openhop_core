"""Host control of an OpenHop modem's AGC reset, FEM gain, and RX boost.

The v0.8 frame commands are not stored on the modem. ``radio_config`` is what
a reconnect must send again; ``applied_hardware_config`` is only what a reply
has confirmed on this link.

FEM and RX-boost replies, including a bare ``CMD_ERROR``, carry no request id
and can be held until the current reception ends. A timed-out exchange drains
its reply within a bounded grace before another command is sent on that link.
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
    CMD_STATUS_RESP,
    ERR_RADIO_FAULT,
    FEM_STATE_RX_LNA,
    FEM_STATE_TX_PA,
    RF_CAP_AGC,
    RF_CAP_FEM_RX_LNA,
    RF_CAP_FEM_TX_PA,
    RF_CAP_RX_BOOSTED_GAIN,
    STATUS_RESP_SIZE,
    build_frame,
)

logger = logging.getLogger("FrameRfControls")

FRONTEND_KEYS = (
    "agc_reset_interval_seconds",
    "fem_rx_gain",
    "fem_tx_gain",
    "rx_boosted_gain",
)

# FEM/boost GETs can queue behind a SET waiting for reception to end.
# AGC and capability requests are answered directly in the command handler.
_RF_SET_TIMEOUT_S = 8.0
_RF_GET_TIMEOUT_S = 3.0
# Reception has no fixed deferral limit; allow three SET budgets before recovery.
_RF_QUARANTINE_GRACE_S = 3 * _RF_SET_TIMEOUT_S

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
        self._rf_stale_deadline: Optional[float] = None
        self._rf_last_uptime: Optional[tuple[int, float]] = None
        self._rf_inflight_reply: Optional[int] = None
        self._rf_generation = 0
        self._rf_restoring = False
        self._rf_reconnecting = False
        self._rf_restore_thread = None
        self._rf_lock = threading.RLock()
        self._rf_write_lock = threading.Lock()
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
        if self._rf_reconnecting and self._rf_restore_thread is not threading.current_thread():
            return False
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

    def _rf_use_sync(self) -> bool:
        """True while the RX worker is not the reader, so a direct read is safe."""
        rx = getattr(self, "_rx_thread", None)
        if rx is not None:
            if threading.current_thread() is rx:
                return True
            if rx.is_alive():
                return False
        loop = getattr(self, "_event_loop", None)
        return loop is None or not loop.is_running()

    def _rf_note_state(self, cmd: int, payload: bytes) -> None:
        if cmd == CMD_STATUS_RESP and len(payload) >= STATUS_RESP_SIZE:
            uptime = struct.unpack_from("<I", payload)[0]
            now = time.monotonic()
            previous = self._rf_last_uptime
            if previous is not None:
                old_uptime, observed = previous
                # millis() wraps at 2**32 ms; an ambiguous wrap is not a reboot.
                if uptime < old_uptime and old_uptime + now - observed + 1 < 2**32 / 1000:
                    if self._rf_expect_stale:
                        self._rf_expect_stale.clear()
                        self._rf_stale_deadline = None
                        logger.info("Modem uptime decreased; clearing RF quarantine after reboot")
            self._rf_last_uptime = (uptime, now)
        if (cmd == CMD_ERROR and payload and payload[0] == ERR_RADIO_FAULT) or (
            cmd == CMD_STATUS_RESP
            and len(payload) >= STATUS_RESP_SIZE
            and payload[STATUS_RESP_SIZE - 1] == 2
        ):
            self.applied_hardware_config.pop("rx_boosted_gain", None)

    def _deliver_waiting_frame(self, cmd: int, payload: bytes) -> bool:
        """Wake the command waiting for ``cmd``. Caller holds ``_response_lock``."""
        self._rf_note_state(cmd, payload)
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
            self._rf_stale_deadline = None
            logger.debug("Discarding late RF reply 0x%02X", cmd)
            return True
        return False

    def _rf_quarantine(self, expect: int) -> None:
        """Retain terminal-reply ownership for a bounded grace under _response_lock."""
        self._rf_expect_stale = {expect, CMD_ERROR}
        self._rf_stale_deadline = time.monotonic() + _RF_QUARANTINE_GRACE_S

    def _rf_expire_stale(self) -> bool:
        """Release lost replies once, under _response_lock."""
        if self._rf_expect_stale:
            if self._rf_stale_deadline is None:
                self._rf_stale_deadline = time.monotonic() + _RF_QUARANTINE_GRACE_S
            if time.monotonic() >= self._rf_stale_deadline:
                self._rf_expect_stale.clear()
                self._rf_stale_deadline = None
                logger.warning(
                    "RF reply quarantine expired after %.0fs; resuming commands "
                    "with possible stale untagged replies",
                    _RF_QUARANTINE_GRACE_S,
                )
                return True
        return False

    def _rf_serial_reopened(self) -> None:
        """Allow deferred USB work a fresh grace measured from the reopen."""
        with self._response_lock:
            if self._rf_expect_stale:
                self._rf_stale_deadline = time.monotonic() + _RF_QUARANTINE_GRACE_S

    async def _rf_wait_clean_async(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while True:
            with self._response_lock:
                if self._stop_event.is_set():
                    return False
                self._rf_expire_stale()
                if not (self._rf_restoring or self._rf_reconnecting or self._rf_expect_stale):
                    return True
            if time.monotonic() >= deadline:
                logger.warning("RF restore, reconnect or reply still pending; command not sent")
                return False
            await asyncio.sleep(min(0.01, max(0, deadline - time.monotonic())))

    def _rf_transact(
        self, cmd: int, payload: bytes, expect: int, timeout: float
    ) -> Optional[tuple[int, bytes]]:
        try:
            if asyncio.get_running_loop():
                logger.error("RF control was called on an event loop")
                return None
        except RuntimeError:
            pass
        with self._rf_lock:
            if self._rf_restoring and self._rf_restore_thread is not threading.current_thread():
                return None
            reply = self._rf_transact_fresh(cmd, payload, expect, timeout)
            if reply:
                self._rf_note_state(*reply)
            return reply

    def _rf_transact_fresh(
        self, cmd: int, payload: bytes, expect: int, timeout: float
    ) -> Optional[tuple[int, bytes]]:
        if not self._rf_link_open():
            return None
        if self._rf_use_sync():
            return self._rf_transact_sync(cmd, payload, expect, timeout)
        loop = getattr(self, "_event_loop", None)
        if loop is None or not loop.is_running():
            logger.warning("RF control requires the radio event loop while RX is running")
            return None
        generation = self._rf_generation
        finished = threading.Event()
        cancelled = threading.Event()

        async def exchange():
            try:
                # Include command-lock contention and draining in the same budget.
                return await asyncio.wait_for(
                    self._rf_transact_async(cmd, payload, expect, timeout, cancelled, generation),
                    timeout,
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
                self._rf_expire_stale()
                if not self._rf_expect_stale:
                    break
                drain_deadline = min(deadline, self._rf_stale_deadline)
            if time.monotonic() >= deadline:
                logger.warning("Previous RF reply still pending; command not sent")
                return None
            resp = self._read_frame_sync(timeout=max(0.001, drain_deadline - time.monotonic()))
            if resp:
                with self._response_lock:
                    discarded = self._rf_discard_late(resp[0])
                if not discarded:
                    self._dispatch_frame(*resp)
        if time.monotonic() >= deadline:
            return None
        try:
            with self._rf_write_lock:
                self._rf_write_frame(build_frame(cmd, payload))
        except Exception as exc:
            with self._response_lock:
                self._rf_quarantine(expect)
            logger.warning("RF write failed: %s", exc)
            return None
        accept = {expect, CMD_ERROR}
        while time.monotonic() < deadline:
            remaining = max(0.05, deadline - time.monotonic())
            resp = self._read_frame_sync(timeout=remaining)
            if resp and resp[0] in accept:
                return resp
            if resp:
                self._dispatch_frame(*resp)
        with self._response_lock:
            self._rf_quarantine(expect)
        return None

    async def _rf_transact_async(
        self,
        cmd: int,
        payload: bytes,
        expect: int,
        timeout: float,
        cancelled: Optional[threading.Event] = None,
        generation: Optional[int] = None,
    ) -> Optional[tuple[int, bytes]]:
        async with self._command_lock:
            if generation is None:
                generation = self._rf_generation
            if generation != self._rf_generation:
                return None
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
            aborted = threading.Event()
            write_task = None
            waiters = set()
            try:
                try:

                    def write():
                        nonlocal sent
                        with self._rf_write_lock:
                            with self._response_lock:
                                if (
                                    generation != self._rf_generation
                                    or aborted.is_set()
                                    or (cancelled is not None and cancelled.is_set())
                                ):
                                    return
                                # Partial writes can still produce a reply.
                                sent = True
                                self._rf_inflight_reply = expect
                            self._rf_write_frame(build_frame(cmd, payload))

                    write_task = asyncio.create_task(asyncio.to_thread(write))
                    await asyncio.shield(write_task)
                    if not sent or generation != self._rf_generation:
                        return None
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
                    if generation != self._rf_generation:
                        return None
                    if err_evt.is_set() and self._response_data.get(CMD_ERROR) is not None:
                        return (CMD_ERROR, self._response_data[CMD_ERROR])
                    data = self._response_data.get(expect)
                    if data is None:
                        return None
                    return (expect, data)
            finally:
                aborted.set()
                while write_task is not None and not write_task.done():
                    # Cancellation cannot stop a worker already writing to the modem.
                    try:
                        await asyncio.shield(write_task)
                    except asyncio.CancelledError:
                        continue
                    except Exception:
                        break
                with self._response_lock:
                    self._rf_inflight_reply = None
                    if (
                        sent
                        and generation == self._rf_generation
                        and expect not in self._response_data
                        and CMD_ERROR not in self._response_data
                    ):
                        self._rf_quarantine(expect)
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
        self._rf_restoring = True
        self._rf_restore_thread = threading.current_thread()
        try:
            # Serial reopen does not cancel deferred requests on the modem.
            self._rf_retire_link(preserve_pending=getattr(self, "_serial", None) is not None)
            with self._rf_lock:
                self._restore_rf_controls()
        finally:
            self._rf_restoring = False
            self._rf_reconnecting = False
            self._rf_restore_thread = None

    def _rf_retire_link(self, preserve_pending: bool = False) -> None:
        """Release old waiters before the RX worker starts a new handshake."""
        # A started write must finish on its original handle before replacement.
        with self._rf_write_lock:
            self._rf_retire_waiters(preserve_pending)

    def _rf_retire_waiters(self, preserve_pending: bool) -> None:
        with self._response_lock:
            self._rf_generation += 1
            if preserve_pending:
                cmd = self._rf_inflight_reply
                if (
                    cmd is not None
                    and cmd not in self._response_data
                    and CMD_ERROR not in self._response_data
                ):
                    if not self._rf_expect_stale:
                        self._rf_quarantine(cmd)
            else:
                self._rf_expect_stale.clear()
                self._rf_stale_deadline = None
            self._rf_inflight_reply = None
            for cmd, evt in self._response_events.items():
                self._response_data[cmd] = None
                loop = getattr(self, "_event_loop", None)
                if loop is not None and loop.is_running():
                    loop.call_soon_threadsafe(evt.set)
                else:
                    evt.set()

    def _restore_rf_controls(self) -> None:
        self._rf_caps = None
        self.applied_hardware_config.clear()
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
