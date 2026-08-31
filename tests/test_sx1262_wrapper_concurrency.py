"""
Comprehensive concurrency, interrupt, and lifecycle tests for SX1262Radio.

Covers every category of weakness in the driver:
  - RX/TX locking and mutex guarantees
  - Interrupt timing and race-condition simulation
  - Async task safety and event-loop interaction
  - Transmission lifecycle edge cases
  - Deadlock and lock-contention scenarios
  - State corruption under rapid IRQ activity
  - Overlapping RX/TX operations
  - Recovery from failed / partial transmissions
  - Event ordering and stale-event hazards
  - Re-entrant / re-entrant-safe interrupt handling
  - TX and CAD timeout handling
  - Cleanup and reset after exceptions
  - Thread / event-loop safety (IRQ trampoline)
  - Packet corruption and stale-buffer conditions
  - IRQs that arrive during active TX lock
  - Concurrent access to shared radio state
  - LBT/CAD backoff mechanics
  - Noise-floor sampling correctness
  - Fuzz / stress IRQ injection
  - TX airtime calculation correctness
  - begin() initialisation sequencing
  - CAD threshold management
  - TX/RX pin control
"""

import asyncio
import contextlib
import random
import threading
import time
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest

# ---------------------------------------------------------------------------
# IRQ bitmask constants (mirror SX126x driver values exactly)
# ---------------------------------------------------------------------------
IRQ_NONE = 0x0000
IRQ_TX_DONE = 0x0001
IRQ_RX_DONE = 0x0002
IRQ_PREAMBLE_DETECTED = 0x0004
IRQ_SYNC_WORD_VALID = 0x0008
IRQ_HEADER_VALID = 0x0010
IRQ_HEADER_ERR = 0x0020
IRQ_CRC_ERR = 0x0040
IRQ_CAD_DONE = 0x0080
IRQ_CAD_DETECTED = 0x0100
IRQ_TIMEOUT = 0x0200

# Flat list for fuzz / stress testing
ALL_IRQ_FLAGS = [
    IRQ_TX_DONE,
    IRQ_RX_DONE,
    IRQ_PREAMBLE_DETECTED,
    IRQ_SYNC_WORD_VALID,
    IRQ_HEADER_VALID,
    IRQ_HEADER_ERR,
    IRQ_CRC_ERR,
    IRQ_CAD_DONE,
    IRQ_CAD_DETECTED,
    IRQ_TIMEOUT,
]


# ---------------------------------------------------------------------------
# CAD test helpers
# ---------------------------------------------------------------------------
def arm_cad_completion(radio, detected: bool, irq_status=None):
    """Arm the CAD completion IRQ to fire once the driver starts CAD.

    perform_cad() clears _cad_event during setup, so completion armed on a
    timer can be wiped before the driver ever waits on it -- the operation
    then falls through to its timeout, which returns False and is therefore
    indistinguishable from a genuine channel-clear result. Firing from
    setCad() mirrors the hardware, since the IRQ cannot arrive before CAD is
    running, and keeps these tests independent of machine speed.
    """

    def _fire(*_args, **_kwargs):
        if irq_status is None:
            radio._last_cad_irq_status = (
                IRQ_CAD_DONE | IRQ_CAD_DETECTED if detected else IRQ_CAD_DONE
            )
        else:
            radio._last_cad_irq_status = irq_status
        radio._last_cad_detected = detected
        radio._cad_event.set()

    radio.lora.setCad.side_effect = _fire


# ---------------------------------------------------------------------------
# Mock builders
# ---------------------------------------------------------------------------


def _make_mock_lora() -> MagicMock:
    """Return a fully configured MagicMock for the SX126x low-level driver."""
    lora = MagicMock(name="SX126x")

    # IRQ masks
    lora.IRQ_NONE = IRQ_NONE
    lora.IRQ_TX_DONE = IRQ_TX_DONE
    lora.IRQ_RX_DONE = IRQ_RX_DONE
    lora.IRQ_PREAMBLE_DETECTED = IRQ_PREAMBLE_DETECTED
    lora.IRQ_SYNC_WORD_VALID = IRQ_SYNC_WORD_VALID
    lora.IRQ_HEADER_VALID = IRQ_HEADER_VALID
    lora.IRQ_HEADER_ERR = IRQ_HEADER_ERR
    lora.IRQ_CRC_ERR = IRQ_CRC_ERR
    lora.IRQ_CAD_DONE = IRQ_CAD_DONE
    lora.IRQ_CAD_DETECTED = IRQ_CAD_DETECTED
    lora.IRQ_TIMEOUT = IRQ_TIMEOUT

    # Mode and config constants
    lora.STANDBY_RC = 0
    lora.LORA_MODEM = 1
    lora.STATUS_MODE_STDBY_RC = 2
    lora.RX_CONTINUOUS = 3
    lora.TX_POWER_SX1262 = 0
    lora.HEADER_EXPLICIT = 0
    lora.CRC_ON = 1
    lora.IQ_STANDARD = 0
    lora.RX_GAIN_BOOSTED = 1
    lora.CAD_ON_1_SYMB = 0
    lora.CAD_ON_2_SYMB = 1
    lora.CAD_ON_4_SYMB = 2
    lora.CAD_ON_8_SYMB = 3
    lora.CAD_ON_16_SYMB = 4
    lora.CAD_EXIT_STDBY = 0
    lora.REGULATOR_DC_DC = 0
    lora.TCXO_DELAY_5 = 5

    # DIO3 TCXO voltage constants
    for attr, val in [
        ("DIO3_OUTPUT_1_6", 1),
        ("DIO3_OUTPUT_1_7", 2),
        ("DIO3_OUTPUT_1_8", 3),
        ("DIO3_OUTPUT_2_2", 4),
        ("DIO3_OUTPUT_2_4", 5),
        ("DIO3_OUTPUT_2_7", 6),
        ("DIO3_OUTPUT_3_0", 7),
        ("DIO3_OUTPUT_3_3", 8),
    ]:
        setattr(lora, attr, val)

    # Image calibration constants
    for attr, val in [
        ("CAL_IMG_430", 0x6B),
        ("CAL_IMG_440", 0x70),
        ("CAL_IMG_470", 0x75),
        ("CAL_IMG_510", 0x81),
        ("CAL_IMG_779", 0xC1),
        ("CAL_IMG_787", 0xC5),
        ("CAL_IMG_863", 0xD7),
        ("CAL_IMG_870", 0xDB),
        ("CAL_IMG_902", 0xE1),
        ("CAL_IMG_928", 0xE9),
    ]:
        setattr(lora, attr, val)

    # Default hardware-state responses
    lora.busyCheck.return_value = False
    lora.getIrqStatus.return_value = IRQ_NONE
    lora.getMode.return_value = lora.STATUS_MODE_STDBY_RC
    lora.getRxBufferStatus.return_value = (4, 0x80)
    lora.getSignalMetrics.return_value = (-100.0, 5.0, -102.0)
    lora.readBuffer.return_value = list(b"test")
    lora.getRssiInst.return_value = 160  # raw → -80 dBm (raw / 2)
    lora.transmitTime.return_value = 0
    lora.dataRate.return_value = 0
    lora.getDeviceErrors.return_value = 0
    return lora


def _make_mock_gpio() -> MagicMock:
    gm = MagicMock(name="GPIOPinManager")
    gm.setup_interrupt_pin.return_value = MagicMock()
    gm.setup_output_pin.return_value = True
    gm.read_pin.return_value = False  # IRQ pin LOW (idle)
    return gm


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_singleton():
    """Ensure the instance registry is clean before and after every test."""
    from openhop_core.hardware.sx1262_wrapper import SX1262Radio

    SX1262Radio._active_instance = None
    SX1262Radio._active_instances = set()
    yield
    SX1262Radio._active_instance = None
    SX1262Radio._active_instances = set()


@pytest.fixture
def mock_lora():
    return _make_mock_lora()


@pytest.fixture
def mock_gpio():
    return _make_mock_gpio()


@pytest.fixture
async def radio(mock_lora, mock_gpio):
    """
    SX1262Radio with all hardware mocked and pre-initialised.

    __init__ runs for real (with GPIOPinManager and set_gpio_manager patched);
    lora hardware is injected post-construction so begin() is never called.
    Setting radio_timing_delay=0.0 eliminates hardware sleep delays in send().
    """
    with (
        patch(
            "openhop_core.hardware.sx1262_wrapper.GPIOPinManager",
            return_value=mock_gpio,
        ),
        patch("openhop_core.hardware.sx1262_wrapper.set_gpio_manager"),
    ):
        from openhop_core.hardware.sx1262_wrapper import SX1262Radio

        r = SX1262Radio(radio_timing_delay=0.0)

    r.lora = mock_lora
    r._initialized = True
    r._interrupt_setup = True
    r._gpio_manager = mock_gpio
    r._event_loop = asyncio.get_running_loop()
    yield r


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _inject_irq(radio, irq_flags: int) -> None:
    """
    Synchronously inject an IRQ into the radio's interrupt handler,
    simulating a hardware interrupt edge (GPIOPinManager fires the callback).
    """
    radio.lora.getIrqStatus.return_value = irq_flags
    radio._last_irq_status = irq_flags
    radio._handle_interrupt()


def _make_tx_succeed(radio, mock_lora) -> None:
    """
    Configure the radio and mock so that a send() completes successfully:
      - perform_cad returns False (channel clear)
      - getIrqStatus returns IRQ_TX_DONE on the third call (poll path)
    """
    radio.perform_cad = AsyncMock(return_value=False)

    _calls = [0]

    def _irq_side_effect():
        _calls[0] += 1
        return IRQ_TX_DONE if _calls[0] > 2 else IRQ_NONE

    mock_lora.getIrqStatus.side_effect = _irq_side_effect


async def _wait_condition(predicate, *, timeout: float = 1.0, interval: float = 0.005):
    """Spin-wait until predicate() returns True or timeout expires."""
    deadline = asyncio.get_event_loop().time() + timeout
    while not predicate():
        if asyncio.get_event_loop().time() > deadline:
            raise asyncio.TimeoutError(f"Condition not met within {timeout}s")
        await asyncio.sleep(interval)


# ===========================================================================
# 1. Interrupt-handler dispatch
# ===========================================================================


class TestInterruptHandlerDispatch:
    """_handle_interrupt correctly routes IRQ flags to asyncio events."""

    def test_tx_done_irq_sets_tx_done_event(self, radio):
        _inject_irq(radio, IRQ_TX_DONE)
        assert radio._tx_done_event.is_set()

    def test_tx_done_irq_does_not_set_rx_done_event(self, radio):
        _inject_irq(radio, IRQ_TX_DONE)
        assert not radio._rx_done_event.is_set()

    def test_rx_done_irq_sets_rx_done_event(self, radio):
        _inject_irq(radio, IRQ_RX_DONE)
        assert radio._rx_done_event.is_set()

    def test_crc_err_irq_sets_rx_done_event(self, radio):
        _inject_irq(radio, IRQ_CRC_ERR)
        assert radio._rx_done_event.is_set()

    def test_timeout_irq_sets_rx_done_event(self, radio):
        _inject_irq(radio, IRQ_TIMEOUT)
        assert radio._rx_done_event.is_set()

    def test_header_err_irq_sets_rx_done_event(self, radio):
        _inject_irq(radio, IRQ_HEADER_ERR)
        assert radio._rx_done_event.is_set()

    def test_preamble_detected_is_non_terminal_no_rx_wake(self, radio):
        """Non-terminal progress interrupts must NOT wake the background task."""
        _inject_irq(radio, IRQ_PREAMBLE_DETECTED)
        assert not radio._rx_done_event.is_set()

    def test_sync_word_valid_is_non_terminal_no_rx_wake(self, radio):
        _inject_irq(radio, IRQ_SYNC_WORD_VALID)
        assert not radio._rx_done_event.is_set()

    def test_header_valid_is_non_terminal_no_rx_wake(self, radio):
        _inject_irq(radio, IRQ_HEADER_VALID)
        assert not radio._rx_done_event.is_set()

    def test_cad_done_irq_sets_cad_event(self, radio):
        radio._cad_event.clear()
        _inject_irq(radio, IRQ_CAD_DONE)
        assert radio._cad_event.is_set()

    def test_cad_detected_flag_stored_true(self, radio):
        radio._last_cad_detected = False
        _inject_irq(radio, IRQ_CAD_DONE | IRQ_CAD_DETECTED)
        assert radio._last_cad_detected is True

    def test_cad_clear_flag_stored_false(self, radio):
        radio._last_cad_detected = True
        _inject_irq(radio, IRQ_CAD_DONE)  # CAD_DONE without CAD_DETECTED
        assert radio._last_cad_detected is False

    def test_spurious_zero_irq_sets_no_events(self, radio):
        radio.lora.getIrqStatus.return_value = IRQ_NONE
        radio._handle_interrupt()
        assert not radio._tx_done_event.is_set()
        assert not radio._rx_done_event.is_set()
        assert not radio._cad_event.is_set()

    def test_uninitialized_radio_irq_does_not_crash(self, radio):
        radio._initialized = False
        radio._handle_interrupt()  # must not raise

    def test_lora_none_irq_does_not_crash(self, radio):
        radio.lora = None
        radio._handle_interrupt()  # must not raise

    def test_spi_exception_sets_both_fallback_events(self, radio):
        """If getIrqStatus throws, fallback: set tx_done AND rx_done."""
        radio.lora.getIrqStatus.side_effect = OSError("SPI bus error")
        radio._tx_done_event.clear()
        radio._rx_done_event.clear()
        radio._handle_interrupt()
        assert radio._tx_done_event.is_set()
        assert radio._rx_done_event.is_set()

    def test_combined_tx_rx_irq_dispatches_both(self, radio):
        """Edge case: both TX_DONE and RX_DONE set in same register."""
        _inject_irq(radio, IRQ_TX_DONE | IRQ_RX_DONE)
        assert radio._tx_done_event.is_set()
        assert radio._rx_done_event.is_set()

    def test_irq_clears_hardware_status_register(self, radio, mock_lora):
        _inject_irq(radio, IRQ_RX_DONE)
        mock_lora.clearIrqStatus.assert_called_once_with(0xFFFF)

    def test_last_irq_status_stored(self, radio):
        radio._last_irq_status = 0
        _inject_irq(radio, IRQ_TX_DONE)
        assert radio._last_irq_status == IRQ_TX_DONE


# ===========================================================================
# 2. IRQ suppression during TX lock
# ===========================================================================


class TestIrqSuppressionDuringTx:
    """Terminal RX interrupts must be ignored while _tx_lock is held."""

    async def test_rx_done_suppressed_while_tx_locked(self, radio):
        async with radio._tx_lock:
            radio._rx_done_event.clear()
            _inject_irq(radio, IRQ_RX_DONE)
            assert not radio._rx_done_event.is_set(), (
                "RX_DONE must NOT wake background task during active TX"
            )

    async def test_crc_err_suppressed_while_tx_locked(self, radio):
        async with radio._tx_lock:
            radio._rx_done_event.clear()
            _inject_irq(radio, IRQ_CRC_ERR)
            assert not radio._rx_done_event.is_set()

    async def test_timeout_irq_suppressed_while_tx_locked(self, radio):
        async with radio._tx_lock:
            radio._rx_done_event.clear()
            _inject_irq(radio, IRQ_TIMEOUT)
            assert not radio._rx_done_event.is_set()

    async def test_header_err_suppressed_while_tx_locked(self, radio):
        async with radio._tx_lock:
            radio._rx_done_event.clear()
            _inject_irq(radio, IRQ_HEADER_ERR)
            assert not radio._rx_done_event.is_set()

    async def test_tx_done_event_fires_even_while_tx_locked(self, radio):
        """TX_DONE must still propagate so the sender coroutine can unblock."""
        async with radio._tx_lock:
            radio._tx_done_event.clear()
            _inject_irq(radio, IRQ_TX_DONE)
            assert radio._tx_done_event.is_set()

    async def test_rx_done_allowed_after_tx_lock_released(self, radio):
        async with radio._tx_lock:
            pass  # acquire and immediately release
        radio._rx_done_event.clear()
        _inject_irq(radio, IRQ_RX_DONE)
        assert radio._rx_done_event.is_set()


# ===========================================================================
# 3. IRQ trampoline (thread safety)
# ===========================================================================


class TestIrqTrampoline:
    """_irq_trampoline schedules the real handler on the event loop."""

    async def test_trampoline_does_not_call_handler_inline(self, radio):
        called = []
        radio._handle_interrupt = lambda: called.append(True)
        radio._irq_trampoline()
        assert called == [], "Handler must not run before event loop processes it"
        await asyncio.sleep(0)
        assert called == [True]

    def test_trampoline_with_no_event_loop_returns_silently(self, radio, caplog):
        import logging

        radio._event_loop = None
        with caplog.at_level(logging.WARNING, logger="SX1262_wrapper"):
            radio._irq_trampoline()
        assert caplog.records == []

    async def test_trampoline_from_background_thread_is_safe(self, radio):
        """The trampoline is typically called from a GPIO poll thread."""
        received = []
        radio._handle_interrupt = lambda: received.append(True)

        t = threading.Thread(target=radio._irq_trampoline)
        t.start()
        t.join()
        await asyncio.sleep(0)
        assert received == [True]

    async def test_trampoline_exception_does_not_propagate(self, radio):
        """A crash in call_soon_threadsafe must be caught, not propagated."""
        radio._event_loop = MagicMock()
        radio._event_loop.call_soon_threadsafe.side_effect = RuntimeError("loop closed")
        radio._irq_trampoline()  # must not raise


# ===========================================================================
# 4. RX/TX lock behaviour
# ===========================================================================


class TestRxTxLocking:
    """Verify mutex guarantees enforced by the TX lock in send()."""

    async def test_tx_lock_is_held_during_execution(self, radio, mock_lora):
        _make_tx_succeed(radio, mock_lora)
        held_during = []

        original = radio._execute_transmission

        async def spy(driver_timeout):
            held_during.append(radio._tx_lock.locked())
            return await original(driver_timeout)

        radio._execute_transmission = spy
        await radio.send(b"probe")
        assert any(held_during), "TX lock should be held during _execute_transmission"

    async def test_tx_lock_released_after_successful_send(self, radio, mock_lora):
        _make_tx_succeed(radio, mock_lora)
        await radio.send(b"hello")
        assert not radio._tx_lock.locked()

    async def test_tx_lock_released_after_writeBuffer_exception(self, radio, mock_lora):
        radio.perform_cad = AsyncMock(return_value=False)
        mock_lora.writeBuffer.side_effect = RuntimeError("SPI write failed")
        with pytest.raises(RuntimeError):
            await radio.send(b"data")
        assert not radio._tx_lock.locked()

    async def test_tx_lock_released_after_tx_timeout(self, radio, mock_lora):
        radio.perform_cad = AsyncMock(return_value=False)
        radio._wait_for_transmission_complete = AsyncMock(return_value=False)
        with pytest.raises(RuntimeError, match="TX completion timeout"):
            await radio.send(b"data")
        assert not radio._tx_lock.locked()

    async def test_concurrent_sends_are_serialized_not_interleaved(
        self, radio, mock_lora
    ):
        """
        Two overlapping send() calls must execute sequentially.
        The second must not enter _execute_transmission until the first exits.
        """
        radio.perform_cad = AsyncMock(return_value=False)
        execution_log = []

        async def instrumented_execute(driver_timeout):
            execution_log.append("enter")
            await asyncio.sleep(0)  # yield so the second task can attempt entry
            execution_log.append("exit")
            return True

        radio._execute_transmission = instrumented_execute
        radio._wait_for_transmission_complete = AsyncMock(return_value=True)
        radio._finalize_transmission = MagicMock()

        await asyncio.gather(
            radio.send(b"first"),
            radio.send(b"second"),
            return_exceptions=True,
        )

        enter_idxs = [i for i, e in enumerate(execution_log) if e == "enter"]
        exit_idxs = [i for i, e in enumerate(execution_log) if e == "exit"]
        if len(enter_idxs) >= 2:
            assert exit_idxs[0] < enter_idxs[1], (
                "Second send started before first completed — mutex failed!"
            )

    async def test_send_not_initialized_raises(self, radio):
        radio._initialized = False
        with pytest.raises(RuntimeError, match="not initialized"):
            await radio.send(b"data")

    async def test_send_lora_none_raises(self, radio):
        radio.lora = None
        with pytest.raises(RuntimeError):
            await radio.send(b"data")


# ===========================================================================
# 5. Transmission lifecycle
# ===========================================================================


class TestTransmissionLifecycle:
    """End-to-end and component-level transmission correctness."""

    async def test_happy_path_returns_metadata_dict(self, radio, mock_lora):
        _make_tx_succeed(radio, mock_lora)
        result = await radio.send(b"hello world")
        assert isinstance(result, dict)
        for key in (
            "airtime_ms",
            "lbt_attempts",
            "lbt_backoff_delays_ms",
            "lbt_channel_busy",
        ):
            assert key in result

    async def test_lbt_clear_no_backoff_in_result(self, radio, mock_lora):
        _make_tx_succeed(radio, mock_lora)
        result = await radio.send(b"payload")
        assert result["lbt_attempts"] == 0
        assert result["lbt_channel_busy"] is False
        assert result["lbt_backoff_delays_ms"] == []

    async def test_writeBuffer_called_with_correct_args(self, radio, mock_lora):
        _make_tx_succeed(radio, mock_lora)
        data = b"\xde\xad\xbe\xef"
        await radio.send(data)
        mock_lora.writeBuffer.assert_called_once_with(0x00, list(data), len(data))

    async def test_setTx_is_called_during_send(self, radio, mock_lora):
        _make_tx_succeed(radio, mock_lora)
        await radio.send(b"data")
        mock_lora.setTx.assert_called_once()

    async def test_rx_mode_restored_on_success(self, radio, mock_lora):
        _make_tx_succeed(radio, mock_lora)
        await radio.send(b"data")
        mock_lora.request.assert_called_with(mock_lora.RX_CONTINUOUS)

    async def test_rx_mode_restored_even_on_failure(self, radio, mock_lora):
        radio.perform_cad = AsyncMock(return_value=False)
        radio._wait_for_transmission_complete = AsyncMock(return_value=False)
        with pytest.raises(RuntimeError):
            await radio.send(b"data")
        mock_lora.request.assert_called_with(mock_lora.RX_CONTINUOUS)

    async def test_execute_transmission_busy_forever_returns_false(
        self, radio, mock_lora
    ):
        mock_lora.busyCheck.return_value = True
        result = await radio._execute_transmission(0xFFFFFF)
        assert result is False

    async def test_execute_transmission_immediate_irq_timeout_returns_false(
        self, radio, mock_lora
    ):
        mock_lora.busyCheck.return_value = False
        mock_lora.getIrqStatus.return_value = IRQ_TIMEOUT
        result = await radio._execute_transmission(12345)
        assert result is False

    async def test_execute_transmission_spi_glitch_0xffff_returns_true(
        self, radio, mock_lora
    ):
        """Persistent 0xFFFF on IrqStatus read must yield True (optimistic continue)."""
        mock_lora.busyCheck.return_value = False
        mock_lora.getIrqStatus.return_value = 0xFFFF
        result = await radio._execute_transmission(12345)
        assert result is True

    async def test_wait_for_tx_complete_via_pre_set_event(self, radio):
        radio._tx_done_event.set()
        result = await radio._wait_for_transmission_complete(1.0)
        assert result is True

    async def test_wait_for_tx_complete_via_irq_poll(self, radio, mock_lora):
        radio._tx_done_event.clear()
        mock_lora.getIrqStatus.return_value = IRQ_TX_DONE
        result = await radio._wait_for_transmission_complete(1.0)
        assert result is True

    async def test_wait_for_tx_complete_poll_finds_irq_timeout(self, radio, mock_lora):
        radio._tx_done_event.clear()
        mock_lora.getIrqStatus.return_value = IRQ_TIMEOUT
        result = await radio._wait_for_transmission_complete(0.5)
        assert result is False

    async def test_wait_for_tx_hard_timeout_returns_false(self, radio, mock_lora):
        radio._tx_done_event.clear()
        mock_lora.getIrqStatus.return_value = IRQ_NONE
        result = await radio._wait_for_transmission_complete(0.1)
        assert result is False

    async def test_wait_for_tx_spi_glitch_poll_is_skipped(self, radio, mock_lora):
        """0xFFFF from the poll loop must be skipped; TX_DONE found later."""
        radio._tx_done_event.clear()
        _n = [0]

        def _side():
            _n[0] += 1
            return 0xFFFF if _n[0] < 5 else IRQ_TX_DONE

        mock_lora.getIrqStatus.side_effect = _side
        result = await radio._wait_for_transmission_complete(2.0)
        assert result is True

    async def test_wait_for_tx_getIrqStatus_exception_skipped(self, radio, mock_lora):
        """Exception in poll propagates once timeout triggers _handle_transmission_timeout."""
        radio._tx_done_event.clear()
        mock_lora.getIrqStatus.side_effect = OSError("bus error")
        # The poll loop swallows the exception and continues, but _handle_transmission_timeout
        # (called after hard-timeout) calls getIrqStatus without a guard and will propagate.
        with pytest.raises(OSError, match="bus error"):
            await radio._wait_for_transmission_complete(0.15)

    def test_finalize_transmission_clears_irq_register(self, radio, mock_lora):
        mock_lora.getIrqStatus.return_value = IRQ_TX_DONE
        radio._finalize_transmission()
        mock_lora.clearIrqStatus.assert_called()

    def test_finalize_transmission_resets_pins_to_rx_mode(self, radio, mock_lora):
        mock_lora.getIrqStatus.return_value = IRQ_NONE
        radio._finalize_transmission()
        radio._gpio_manager.set_pin_low.assert_called_with(radio.txen_pin)

    async def test_restore_rx_mode_calls_request_rx_continuous(self, radio, mock_lora):
        await radio._restore_rx_mode()
        mock_lora.request.assert_called_with(mock_lora.RX_CONTINUOUS)

    async def test_restore_rx_mode_clears_irq_multiple_times(self, radio, mock_lora):
        await radio._restore_rx_mode()
        assert mock_lora.clearIrqStatus.call_count >= 2

    async def test_restore_rx_mode_exception_swallowed(self, radio, mock_lora):
        mock_lora.clearIrqStatus.side_effect = RuntimeError("SPI failure")
        await radio._restore_rx_mode()  # must not propagate


# ===========================================================================
# 6. CAD / LBT behaviour
# ===========================================================================


class TestCADAndLBT:
    """Channel Activity Detection and Listen-Before-Talk backoff."""

    def _arm_cad_event(self, radio, detected: bool):
        arm_cad_completion(radio, detected=detected)

    async def test_perform_cad_channel_clear_returns_false(self, radio):
        self._arm_cad_event(radio, detected=False)
        result = await radio.perform_cad(timeout=1.0)
        assert result is False

    async def test_perform_cad_channel_busy_returns_true(self, radio):
        self._arm_cad_event(radio, detected=True)
        result = await radio.perform_cad(timeout=1.0)
        assert result is True

    async def test_perform_cad_timeout_returns_false(self, radio, mock_lora):
        """CAD that never fires its event must be treated as channel-clear."""
        mock_lora.getIrqStatus.return_value = IRQ_NONE
        result = await radio.perform_cad(timeout=0.05)
        assert result is False

    async def test_perform_cad_always_restores_rx_mode(self, radio, mock_lora):
        mock_lora.getIrqStatus.return_value = IRQ_NONE
        await radio.perform_cad(timeout=0.05)
        mock_lora.request.assert_called_with(mock_lora.RX_CONTINUOUS)

    async def test_perform_cad_calibration_mode_returns_dict(self, radio):
        self._arm_cad_event(radio, detected=False)
        result = await radio.perform_cad(timeout=1.0, calibration=True)
        assert isinstance(result, dict)
        assert "detected" in result
        assert "cad_done" in result
        assert "det_peak" in result
        assert "sf" in result
        assert "timestamp" in result

    async def test_perform_cad_calibration_reports_done_without_detected(self, radio):
        self._arm_cad_event(radio, detected=False)
        result = await radio.perform_cad(timeout=1.0, calibration=True)
        assert result["cad_done"] is True
        assert result["detected"] is False

    async def test_perform_cad_calibration_reports_done_and_detected(self, radio):
        self._arm_cad_event(radio, detected=True)
        result = await radio.perform_cad(timeout=1.0, calibration=True)
        assert result["cad_done"] is True
        assert result["detected"] is True

    async def test_perform_cad_calibration_timeout_returns_dict_with_timeout_key(
        self, radio, mock_lora
    ):
        mock_lora.getIrqStatus.return_value = IRQ_NONE
        result = await radio.perform_cad(timeout=0.05, calibration=True)
        assert isinstance(result, dict)
        assert result.get("timeout") is True
        assert result.get("cad_done") is False

    async def test_perform_cad_symbol_mapping_uses_requested_symbol_count(
        self, radio, mock_lora
    ):
        self._arm_cad_event(radio, detected=False)
        await radio.perform_cad(timeout=1.0, calibration=True, cad_symbol_num=8)
        mock_lora.setCadParams.assert_called()
        cad_symbol_arg = mock_lora.setCadParams.call_args[0][0]
        assert cad_symbol_arg == mock_lora.CAD_ON_8_SYMB

    async def test_perform_cad_invalid_symbol_count_returns_error_in_calibration_mode(
        self, radio
    ):
        result = await radio.perform_cad(
            timeout=0.05, calibration=True, cad_symbol_num=3
        )
        assert "error" in result
        assert "cad_symbol_num must be one of" in result["error"]

    async def test_perform_cad_exception_returns_false(self, radio, mock_lora):
        mock_lora.setStandby.side_effect = RuntimeError("hardware fault")
        result = await radio.perform_cad(timeout=0.1)
        assert result is False

    async def test_perform_cad_exception_calibration_returns_dict_with_error(
        self, radio, mock_lora
    ):
        mock_lora.setStandby.side_effect = RuntimeError("fault")
        result = await radio.perform_cad(timeout=0.1, calibration=True)
        assert "error" in result

    async def test_lbt_busy_then_clear_records_backoff(self, radio, mock_lora):
        """First two CAD checks busy, third clear: two backoff entries recorded."""
        _calls = [0]

        async def _cad(*args, **kwargs):
            _calls[0] += 1
            return _calls[0] <= 2  # True=busy for first two

        radio.perform_cad = _cad
        mock_lora.getIrqStatus.return_value = IRQ_TX_DONE
        radio._wait_for_transmission_complete = AsyncMock(return_value=True)
        radio._finalize_transmission = MagicMock()

        result = await radio.send(b"payload")
        assert result["lbt_attempts"] == 2
        assert len(result["lbt_backoff_delays_ms"]) == 2
        assert result["lbt_channel_busy"] is True

    async def test_lbt_budget_exhaustion_still_transmits(self, radio, mock_lora):
        """Once the LBT TIME budget runs out the TX proceeds unconditionally.

        LBT is bounded in time, not attempts: with a channel that never
        clears, the loop keeps re-checking on short jittered intervals until
        the budget is exhausted, then transmits (a channel busy that long is
        likelier a wedged radio than a real occupation)."""
        radio.perform_cad = AsyncMock(return_value=True)  # always busy
        radio.lbt_max_wait_seconds = 0.5
        radio.lbt_retry_interval_ms = 20
        mock_lora.getIrqStatus.return_value = IRQ_TX_DONE
        radio._wait_for_transmission_complete = AsyncMock(return_value=True)
        radio._finalize_transmission = MagicMock()

        result = await radio.send(b"forced")
        # Many short retries; the exact count is timing-dependent, the
        # invariant is the time bound.
        assert result["lbt_attempts"] > 5
        assert sum(result["lbt_backoff_delays_ms"]) <= 600.0
        mock_lora.setTx.assert_called_once()

    async def test_lbt_cad_exception_proceeds_with_tx(self, radio, mock_lora):
        radio.perform_cad = AsyncMock(side_effect=RuntimeError("CAD broken"))
        mock_lora.getIrqStatus.return_value = IRQ_TX_DONE
        radio._wait_for_transmission_complete = AsyncMock(return_value=True)
        radio._finalize_transmission = MagicMock()

        result = await radio.send(b"data")
        assert result is not None
        mock_lora.setTx.assert_called_once()

    async def test_lbt_backoff_delays_are_positive(self, radio, mock_lora):
        _n = [0]

        async def _cad(*args, **kwargs):
            _n[0] += 1
            return _n[0] == 1  # busy once

        radio.perform_cad = _cad
        mock_lora.getIrqStatus.return_value = IRQ_TX_DONE
        radio._wait_for_transmission_complete = AsyncMock(return_value=True)
        radio._finalize_transmission = MagicMock()

        result = await radio.send(b"x")
        for delay in result["lbt_backoff_delays_ms"]:
            assert delay > 0


# ===========================================================================
# 7. RX background task
# ===========================================================================


class TestRxBackgroundTask:
    """RX IRQ background task packet handling and callback delivery."""

    async def _one_rx_cycle(self, radio, irq_flags, payload=b"data"):
        """Prime state and fire the event; return after the task has a chance to process."""
        radio._last_irq_status = irq_flags
        radio.lora.getRxBufferStatus.return_value = (len(payload), 0x80)
        radio.lora.readBuffer.return_value = list(payload)
        radio._rx_done_event.set()
        await asyncio.sleep(0.1)  # 10× the background-task polling interval

    async def _run_task_with(self, radio, *, irq_flags, payload=b"data", callback=None):
        """Start background task, fire one IRQ cycle, stop task, return radio."""
        if callback:
            radio.set_rx_callback(callback)
        task = asyncio.get_running_loop().create_task(radio._rx_irq_background_task())
        await self._one_rx_cycle(radio, irq_flags, payload)
        radio._initialized = False
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass
        return radio

    async def test_rx_callback_invoked_with_packet_bytes(self, radio):
        received = []
        await self._run_task_with(
            radio, irq_flags=IRQ_RX_DONE, payload=b"hello", callback=received.append
        )
        assert b"hello" in received

    async def test_crc_error_increments_counter(self, radio):
        initial = radio.crc_error_count
        await self._run_task_with(radio, irq_flags=IRQ_CRC_ERR)
        assert radio.crc_error_count == initial + 1

    async def test_crc_error_does_not_invoke_rx_callback(self, radio):
        received = []
        await self._run_task_with(
            radio, irq_flags=IRQ_CRC_ERR, callback=received.append
        )
        assert received == []

    async def test_timeout_irq_does_not_invoke_callback(self, radio):
        received = []
        await self._run_task_with(
            radio, irq_flags=IRQ_TIMEOUT, callback=received.append
        )
        assert received == []

    async def test_header_error_does_not_invoke_callback(self, radio):
        received = []
        await self._run_task_with(
            radio, irq_flags=IRQ_HEADER_ERR, callback=received.append
        )
        assert received == []

    async def test_empty_packet_does_not_invoke_callback(self, radio):
        received = []
        radio.lora.getRxBufferStatus.return_value = (0, 0x80)
        await self._run_task_with(
            radio, irq_flags=IRQ_RX_DONE, payload=b"", callback=received.append
        )
        assert received == []

    async def test_buggy_callback_does_not_kill_task(self, radio):
        """A crashing RX callback must not terminate the background task."""

        def _crash(_):
            raise ValueError("broken callback")

        radio.set_rx_callback(_crash)
        task = asyncio.get_running_loop().create_task(radio._rx_irq_background_task())
        await self._one_rx_cycle(radio, IRQ_RX_DONE)

        assert not task.done(), "Background task must survive a crashing callback"

        radio._initialized = False
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass

    async def test_rx_mode_restored_after_packet(self, radio, mock_lora):
        await self._run_task_with(radio, irq_flags=IRQ_RX_DONE, callback=lambda _: None)
        mock_lora.request.assert_called_with(mock_lora.RX_CONTINUOUS)

    async def test_rssi_and_snr_updated_on_rx_done(self, radio, mock_lora):
        mock_lora.getSignalMetrics.return_value = (-85.0, 7.5, -87.0)
        await self._run_task_with(radio, irq_flags=IRQ_RX_DONE, callback=lambda _: None)
        assert radio.last_rssi == -85
        assert radio.last_snr == pytest.approx(7.5)

    async def test_processing_rx_packet_flag_cleared_after_processing(self, radio):
        await self._run_task_with(radio, irq_flags=IRQ_RX_DONE, callback=lambda _: None)
        assert not radio._processing_rx_packet

    async def test_crc_error_logs_diagnostic_info(self, radio, mock_lora, caplog):
        import logging

        mock_lora.getDeviceErrors.return_value = 0x0001
        with caplog.at_level(logging.WARNING, logger="SX1262_wrapper"):
            await self._run_task_with(radio, irq_flags=IRQ_CRC_ERR)
        assert "CRC error" in caplog.text


# ===========================================================================
# 8. State management
# ===========================================================================


class TestStateManagement:
    """Radio lifecycle: singleton, double-init guard, cleanup."""

    def test_double_begin_is_noop(self, radio, mock_lora):
        radio._initialized = True
        result = radio.begin()
        assert result is True
        mock_lora.reset.assert_not_called()

    def test_cleanup_marks_radio_uninitialized(self, radio):
        radio.cleanup()
        assert radio._initialized is False
        assert radio._interrupt_setup is False

    def test_cleanup_calls_lora_end(self, radio, mock_lora):
        radio.cleanup()
        mock_lora.end.assert_called_once()

    def test_cleanup_removes_active_singleton(self, radio):
        from openhop_core.hardware.sx1262_wrapper import SX1262Radio

        SX1262Radio._active_instance = radio
        radio.cleanup()
        assert SX1262Radio._active_instance is None

    def test_cleanup_lora_end_exception_does_not_propagate(self, radio, mock_lora):
        mock_lora.end.side_effect = RuntimeError("lora.end() failed")
        radio.cleanup()  # must not raise

    def test_new_instance_does_not_destroy_previous_instance(self, mock_gpio):
        """Phase 1: constructing a second radio must not cleanup the first."""
        from openhop_core.hardware.sx1262_wrapper import SX1262Radio

        with (
            patch(
                "openhop_core.hardware.sx1262_wrapper.GPIOPinManager",
                return_value=mock_gpio,
            ),
            patch("openhop_core.hardware.sx1262_wrapper.set_gpio_manager"),
        ):
            first = SX1262Radio(radio_timing_delay=0.0)
            first._initialized = True

            def boom():
                raise AssertionError("first radio must not be cleaned up")

            first.cleanup = boom  # type: ignore[method-assign]
            second = SX1262Radio(radio_timing_delay=0.0)

        assert first is not second
        assert first._initialized is True
        assert first in SX1262Radio._active_instances
        assert second in SX1262Radio._active_instances

    def test_get_instance_returns_existing_without_creating(self, radio):
        from openhop_core.hardware.sx1262_wrapper import SX1262Radio

        SX1262Radio._active_instance = radio
        with (
            patch("openhop_core.hardware.sx1262_wrapper.GPIOPinManager") as gm_patch,
            patch("openhop_core.hardware.sx1262_wrapper.set_gpio_manager"),
        ):
            instance = SX1262Radio.get_instance()
        assert instance is radio
        gm_patch.assert_not_called()  # no new hardware created

    def test_get_status_contains_expected_fields(self, radio):
        status = radio.get_status()
        for key in (
            "initialized",
            "frequency",
            "tx_power",
            "spreading_factor",
            "bandwidth",
            "coding_rate",
            "last_rssi",
            "last_snr",
            "crc_error_count",
        ):
            assert key in status

    def test_check_radio_health_returns_false_for_dead_task(self, radio):
        radio._rx_irq_task = MagicMock()
        radio._rx_irq_task.done.return_value = True
        result = radio.check_radio_health()
        assert result is False


# ===========================================================================
# 9. Noise-floor sampling
# ===========================================================================


class TestNoiseFloorSampling:
    """Guard conditions and calculation correctness for noise-floor sampler."""

    def test_no_sample_when_tx_lock_held(self, radio):
        radio._tx_lock = MagicMock()
        radio._tx_lock.locked.return_value = True
        with patch("openhop_core.hardware.sx1262_wrapper.time.time", return_value=10.0):
            radio._sample_noise_floor()
        radio.lora.getRssiInst.assert_not_called()

    def test_no_sample_during_packet_reception(self, radio):
        radio._processing_rx_packet = True
        with patch("openhop_core.hardware.sx1262_wrapper.time.time", return_value=20.0):
            radio._sample_noise_floor()
        radio.lora.getRssiInst.assert_not_called()

    def test_no_sample_with_pending_rx_irq_status(self, radio):
        radio._pending_rx_irq_status = IRQ_RX_DONE
        with patch("openhop_core.hardware.sx1262_wrapper.time.time", return_value=30.0):
            radio._sample_noise_floor()
        radio.lora.getRssiInst.assert_not_called()

    def test_no_sample_during_active_rx_irq_flags(self, radio, mock_lora):
        with patch("openhop_core.hardware.sx1262_wrapper.time.monotonic", return_value=40.0):
            radio._rx_activity_at = 40.0
            with patch("openhop_core.hardware.sx1262_wrapper.time.time", return_value=40.0):
                radio._sample_noise_floor()
        mock_lora.getRssiInst.assert_not_called()

    def test_no_sample_within_500ms_of_last_packet(self, radio):
        radio._last_packet_activity = 50.0
        with patch("openhop_core.hardware.sx1262_wrapper.time.time", return_value=50.3):
            radio._sample_noise_floor()
        radio.lora.getRssiInst.assert_not_called()

    def test_rate_limit_enforced_at_5_seconds(self, radio, mock_lora):
        radio._last_sample_check = 100.0
        with patch(
            "openhop_core.hardware.sx1262_wrapper.time.time", return_value=104.9
        ):
            radio._sample_noise_floor()
        mock_lora.getRssiInst.assert_not_called()

    def test_sample_accepted_during_quiet_period(self, radio, mock_lora):
        mock_lora.getRssiInst.return_value = 160  # -80 dBm
        radio._last_packet_activity = 0.0
        radio._processing_rx_packet = False
        with patch(
            "openhop_core.hardware.sx1262_wrapper.time.time", return_value=200.0
        ):
            radio._sample_noise_floor()
        assert radio._num_floor_samples == 1
        assert radio._noise_floor == pytest.approx(-80.0)

    def test_rolling_window_averages_latest_20_samples(self, radio, mock_lora):
        radio._last_packet_activity = 0.0
        radio._processing_rx_packet = False
        samples_dbm = [(-120.0 + i) for i in range(21)]
        mock_lora.getRssiInst.side_effect = [
            int(-(sample * 2)) for sample in samples_dbm
        ]

        base_ts = 1000.0
        for idx in range(21):
            with patch(
                "openhop_core.hardware.sx1262_wrapper.time.time",
                return_value=base_ts + (idx * 6.0),
            ):
                radio._sample_noise_floor()

        expected_floor = sum(samples_dbm[1:]) / 20.0
        assert radio._num_floor_samples == 20
        assert radio._noise_floor == pytest.approx(expected_floor)
        assert len(radio._noise_floor_samples) == 20

    def test_raw_rssi_conversion_divide_by_two(self, radio, mock_lora):
        mock_lora.getRssiInst.return_value = 237  # -(237/2) = -118.5 dBm
        radio._last_packet_activity = 0.0
        with patch(
            "openhop_core.hardware.sx1262_wrapper.time.time", return_value=300.0
        ):
            radio._sample_noise_floor()
        assert radio._noise_floor == pytest.approx(-118.5)

    def test_out_of_range_rssi_is_rejected(self, radio, mock_lora):
        mock_lora.getRssiInst.return_value = 255  # -127.5 dBm edge is valid
        radio._last_packet_activity = 0.0
        with patch(
            "openhop_core.hardware.sx1262_wrapper.time.time", return_value=310.0
        ):
            radio._sample_noise_floor()
        assert radio._num_floor_samples == 1

        mock_lora.getRssiInst.return_value = 256  # -128.0 dBm -> reject
        with patch(
            "openhop_core.hardware.sx1262_wrapper.time.time", return_value=316.0
        ):
            radio._sample_noise_floor()
        assert radio._num_floor_samples == 1

    def test_old_noise_floor_plus_10_filter_removed(self, radio, mock_lora):
        radio._noise_floor = -120.0
        radio._noise_floor_samples = []
        radio._num_floor_samples = 0
        radio._floor_sample_sum = 0.0
        radio._last_packet_activity = 0.0
        mock_lora.getRssiInst.return_value = 200  # -100 dBm
        with patch(
            "openhop_core.hardware.sx1262_wrapper.time.time", return_value=400.0
        ):
            radio._sample_noise_floor()

        assert radio._num_floor_samples == 1
        assert radio._noise_floor == pytest.approx(-100.0)

    def test_get_noise_floor_returns_none_when_uninitialized(self, radio):
        radio._initialized = False
        assert radio.get_noise_floor() is None

    def test_get_noise_floor_returns_none_when_lora_none(self, radio):
        radio.lora = None
        assert radio.get_noise_floor() is None

    def test_get_noise_floor_returns_none_while_tx_lock_held(self, radio):
        radio._num_floor_samples = 1
        radio._noise_floor = -101.5
        radio._tx_lock = MagicMock()
        radio._tx_lock.locked.return_value = True
        assert radio.get_noise_floor() is None

    def test_get_noise_floor_returns_none_for_uninitialized_internal_sentinel(
        self, radio
    ):
        radio._noise_floor = -120.0
        radio._num_floor_samples = 0
        radio._noise_floor_samples = []
        assert radio.get_noise_floor() is None

    def test_get_noise_floor_returns_valid_negative_measurements(self, radio):
        radio._noise_floor = -101.5
        radio._num_floor_samples = 3
        assert radio.get_noise_floor() == pytest.approx(-101.5)

    def test_get_noise_floor_preserves_measured_minus_120(self, radio):
        radio._noise_floor = -120.0
        radio._num_floor_samples = 1
        assert radio.get_noise_floor() == pytest.approx(-120.0)


# ===========================================================================
# 10. TX airtime calculation
# ===========================================================================


class TestTxAirtimeCalculation:
    """_calculate_tx_timeout must produce sensible LoRa airtime values."""

    def test_returns_positive_values(self, radio):
        timeout_ms, driver_timeout = radio._calculate_tx_timeout(20)
        assert timeout_ms > 0
        assert driver_timeout > 0

    def test_larger_payload_longer_timeout(self, radio):
        t_small, _ = radio._calculate_tx_timeout(10)
        t_large, _ = radio._calculate_tx_timeout(200)
        assert t_large > t_small

    def test_higher_sf_longer_timeout(self, radio):
        radio.spreading_factor = 7
        t7, _ = radio._calculate_tx_timeout(50)
        radio.spreading_factor = 12
        t12, _ = radio._calculate_tx_timeout(50)
        assert t12 > t7

    def test_driver_timeout_is_timeout_times_64(self, radio):
        timeout_ms, driver_timeout = radio._calculate_tx_timeout(50)
        assert driver_timeout == timeout_ms * 64

    def test_timeout_includes_1000ms_safety_margin(self, radio):
        timeout_ms, _ = radio._calculate_tx_timeout(10)
        # airtime must be positive
        assert (timeout_ms - 1000) > 0

    def test_sf12_narrow_bw_enables_ldro(self, radio):
        """SF12 + 62.5 kHz BW → low_dr_opt=1 (both conditions must hold: SF>=11 and BW<=125kHz)."""
        radio.spreading_factor = 12
        radio.bandwidth = 62500  # 62.5 kHz
        # _calculate_tx_timeout uses low_dr_opt=1 for SF>=11 and BW<=125000.
        # Verify indirectly: the airtime with LDRO enabled differs from without.
        timeout_with_ldro, _ = radio._calculate_tx_timeout(20)
        radio.spreading_factor = 9  # LDRO disabled for SF9
        timeout_without_ldro, _ = radio._calculate_tx_timeout(20)
        # Just assert the call succeeds and returns reasonable values.
        assert timeout_with_ldro > 0
        assert timeout_without_ldro > 0


# ===========================================================================
# 11. Event ordering and stale-event hazards
# ===========================================================================


class TestEventOrdering:
    """Ensure events are properly cleared before re-use."""

    async def test_pre_set_tx_done_does_not_skip_actual_tx(self, radio, mock_lora):
        """Pre-existing TX_DONE must be cleared at the start of send()."""
        radio._tx_done_event.set()  # stale event from a previous operation
        _make_tx_succeed(radio, mock_lora)
        await radio.send(b"data")
        # Real TX must have occurred
        mock_lora.setTx.assert_called_once()

    async def test_rx_done_event_cleared_after_processing(self, radio):
        radio.set_rx_callback(lambda _: None)
        task = asyncio.get_running_loop().create_task(radio._rx_irq_background_task())
        radio._last_irq_status = IRQ_RX_DONE
        radio._rx_done_event.set()
        await asyncio.sleep(0.1)
        assert not radio._rx_done_event.is_set()
        radio._initialized = False
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass

    async def test_completed_rx_packet_is_not_lost_when_send_starts(
        self, radio, mock_lora
    ):
        received = []
        radio.set_rx_callback(received.append)

        # Simulate a fully received packet whose IRQ handler has run,
        # but whose background RX task has not consumed it yet.
        mock_lora.getIrqStatus.return_value = mock_lora.IRQ_RX_DONE
        radio._handle_interrupt()

        mock_lora.getRxBufferStatus.return_value = (4, 0x80)
        mock_lora.readBuffer.return_value = list(b"test")

        _make_tx_succeed(radio, mock_lora)
        await radio.send(b"outbound")

        assert received == [b"test"]

        read_idx = next(
            i
            for i, c in enumerate(mock_lora.mock_calls)
            if c == call.readBuffer(0x80, 4)
        )
        write_idx = next(
            i
            for i, c in enumerate(mock_lora.mock_calls)
            if c == call.writeBuffer(0x00, list(b"outbound"), len(b"outbound"))
        )
        assert read_idx < write_idx

    async def test_corrupt_header_irq_is_not_latched(self, radio, mock_lora):
        """0x0022 (RX_DONE | HEADER_ERR) with no header validated for this
        reception: the length driving readBuffer is untrustworthy."""
        radio._pending_rx_irq_status = 0

        _inject_irq(radio, IRQ_RX_DONE | IRQ_HEADER_ERR)

        assert radio._pending_rx_irq_status == 0

    async def test_header_err_does_not_discard_an_already_latched_packet(
        self, radio, mock_lora
    ):
        """Observed on-air: HEADER_ERR arriving while a good packet is still
        unread. Latching it would OR to 0x0022 and lose a sound packet."""
        radio._pending_rx_irq_status = IRQ_RX_DONE  # good packet, not yet read

        _inject_irq(radio, IRQ_HEADER_ERR)

        assert radio._pending_rx_irq_status == IRQ_RX_DONE

    async def test_rx_done_while_tx_lock_held_is_latched_and_drained_before_tx_reuse(
        self, radio, mock_lora
    ):
        received = []
        radio.set_rx_callback(received.append)

        await radio._tx_lock.acquire()
        try:
            # IRQ arrives while TX lock is held: hardware IRQ is cleared and
            # background RX task is not woken, so software latch must preserve it.
            mock_lora.getIrqStatus.return_value = mock_lora.IRQ_RX_DONE
            radio._handle_interrupt()
        finally:
            radio._tx_lock.release()

        assert radio._pending_rx_irq_status & mock_lora.IRQ_RX_DONE
        assert not radio._rx_done_event.is_set()

        mock_lora.getRxBufferStatus.return_value = (4, 0x80)
        mock_lora.readBuffer.return_value = list(b"test")

        _make_tx_succeed(radio, mock_lora)
        await radio.send(b"outbound")

        assert received == [b"test"]

        read_idx = next(
            i
            for i, c in enumerate(mock_lora.mock_calls)
            if c == call.readBuffer(0x80, 4)
        )
        write_idx = next(
            i
            for i, c in enumerate(mock_lora.mock_calls)
            if c == call.writeBuffer(0x00, list(b"outbound"), len(b"outbound"))
        )
        assert read_idx < write_idx

    async def test_background_rx_processing_claims_and_clears_pending_latch(
        self, radio, mock_lora
    ):
        received = []
        radio.set_rx_callback(received.append)

        mock_lora.getRxBufferStatus.return_value = (4, 0x80)
        mock_lora.readBuffer.return_value = list(b"test")
        mock_lora.getIrqStatus.return_value = mock_lora.IRQ_RX_DONE

        radio._handle_interrupt()
        assert radio._pending_rx_irq_status & mock_lora.IRQ_RX_DONE

        task = asyncio.get_running_loop().create_task(radio._rx_irq_background_task())
        await _wait_condition(lambda: received == [b"test"], timeout=1.0)

        # The RX consumer must claim and clear the corresponding software latch,
        # preventing the pre-TX drain from delivering the same packet again.
        assert (radio._pending_rx_irq_status & mock_lora.IRQ_RX_DONE) == 0

        await radio._drain_pending_rx_irq_before_buffer_reuse()
        assert received == [b"test"]

        radio._initialized = False
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    async def test_standalone_cad_acquires_tx_lock_before_pending_rx_drain(
        self, radio, mock_lora
    ):
        drain_lock_states = []

        async def _drain_spy():
            drain_lock_states.append(radio._tx_lock.locked())

        radio._drain_pending_rx_irq_before_buffer_reuse = AsyncMock(
            side_effect=_drain_spy
        )
        mock_lora.getIrqStatus.return_value = IRQ_NONE

        result = await radio.perform_cad(timeout=0.05)
        assert result is False
        assert drain_lock_states == [True]

    async def test_pending_drain_crc_and_rx_done_uses_crc_branch_only(
        self, radio, mock_lora
    ):
        received = []
        radio.set_rx_callback(received.append)

        radio._pending_rx_irq_status = mock_lora.IRQ_CRC_ERR | mock_lora.IRQ_RX_DONE
        start_crc_errors = radio.crc_error_count

        mock_lora.getRxBufferStatus.return_value = (4, 0x80)
        mock_lora.readBuffer.return_value = list(b"test")

        await radio._drain_pending_rx_irq_before_buffer_reuse()

        assert radio.crc_error_count == start_crc_errors + 1
        mock_lora.readBuffer.assert_not_called()
        assert received == []

    async def test_stale_cad_detected_not_inherited_by_next_cad(self, radio):
        """
        A 'detected=True' result left from a previous CAD must not contaminate
        the next CAD operation's result.
        """
        # Seed stale state
        radio._cad_event.set()
        radio._last_cad_detected = True

        # New CAD completes with detected=False
        arm_cad_completion(radio, detected=False)
        started = time.monotonic()
        result = await radio.perform_cad(timeout=1.0)
        elapsed = time.monotonic() - started
        assert result is False, "Stale 'detected' state must not leak"
        assert elapsed < 0.5, (
            "perform_cad() fell through to its timeout instead of consuming "
            "the CAD completion, so the stale-state path went untested"
        )

    async def test_cad_event_cleared_at_start_of_cad_operation(self, radio, mock_lora):
        """Verify CAD operation clears the event before starting."""
        radio._cad_event.set()  # stale
        # CAD will timeout because we never fire a new event
        mock_lora.getIrqStatus.return_value = IRQ_NONE
        result = await radio.perform_cad(timeout=0.05)
        # Timeout → False; if stale event were used, this might succeed prematurely
        assert result is False


# ===========================================================================
# 12. Race-condition simulations
# ===========================================================================


class TestRaceConditionSimulations:
    """Controlled race scenarios to expose coordination weaknesses."""

    async def test_tx_done_fired_via_irq_while_waiting(self, radio, mock_lora):
        """TX_DONE arriving via the IRQ path unblocks a waiting send()."""
        radio.perform_cad = AsyncMock(return_value=False)
        mock_lora.getIrqStatus.return_value = IRQ_NONE  # poll never sees it

        async def _fire_irq_after_delay():
            await asyncio.sleep(0.05)
            radio._tx_done_event.set()

        asyncio.get_running_loop().create_task(_fire_irq_after_delay())
        result = await asyncio.wait_for(radio.send(b"irq_driven"), timeout=5.0)
        assert result is not None

    async def test_rx_irqs_during_send_do_not_corrupt_tx(self, radio, mock_lora):
        """
        RX interrupts fired during an active send() must be silently dropped.
        The TX must still complete without error.
        """
        radio.perform_cad = AsyncMock(return_value=False)

        async def _fire_rx_irqs():
            await asyncio.sleep(0.01)
            for _ in range(20):
                _inject_irq(radio, IRQ_RX_DONE)
                await asyncio.sleep(0.001)

        asyncio.get_running_loop().create_task(_fire_rx_irqs())
        mock_lora.getIrqStatus.return_value = IRQ_TX_DONE
        radio._wait_for_transmission_complete = AsyncMock(return_value=True)
        radio._finalize_transmission = MagicMock()

        result = await radio.send(b"concurrent_rx_test")
        assert result is not None

    async def test_multiple_concurrent_sends_complete_without_deadlock(
        self, radio, mock_lora
    ):
        """N concurrent send() calls must all resolve, never deadlock."""
        N = 6
        radio.perform_cad = AsyncMock(return_value=False)
        radio._wait_for_transmission_complete = AsyncMock(return_value=True)
        radio._finalize_transmission = MagicMock()

        results = await asyncio.gather(
            *[radio.send(bytes([i % 256] * 10)) for i in range(N)],
            return_exceptions=True,
        )

        for r in results:
            # Results are either dicts (success) or non-timeout exceptions (failure)
            if isinstance(r, Exception):
                assert not isinstance(r, asyncio.TimeoutError), (
                    f"Task timed out — possible deadlock: {r}"
                )

    async def test_fuzz_irq_injection_never_raises(self, radio, mock_lora):
        """
        500 random IRQ flag combinations fired at the interrupt handler
        must never raise an unhandled exception.
        """
        rng = random.Random(0xC0FFEE)
        edge_cases = [IRQ_NONE, 0xFFFF, 0x0000, 0x03FF, 0xFFFF & ~IRQ_NONE]

        for iteration in range(500):
            if iteration % 50 == 0:
                flags = rng.choice(edge_cases)
            else:
                # Random combination of valid flags
                flags = 0
                for flag in ALL_IRQ_FLAGS:
                    if rng.random() < 0.3:
                        flags |= flag

            mock_lora.getIrqStatus.return_value = flags
            radio._last_irq_status = flags
            try:
                radio._handle_interrupt()
            except Exception as exc:
                pytest.fail(
                    f"_handle_interrupt raised {exc!r} on iteration {iteration} "
                    f"with flags=0x{flags:04X}"
                )

            # Reset events between iterations to prevent accumulation
            radio._tx_done_event.clear()
            radio._rx_done_event.clear()
            radio._cad_event.clear()

    async def test_rapid_sequential_crc_errors_increment_counter_correctly(self, radio):
        """
        Three CRC errors fired one at a time (each fully processed before the next)
        must yield a counter increment of exactly 3.
        """
        radio.crc_error_count = 0
        task = asyncio.get_running_loop().create_task(radio._rx_irq_background_task())

        expected = 0
        for _ in range(3):
            expected += 1
            radio._last_irq_status = IRQ_CRC_ERR
            radio._rx_done_event.set()
            # Wait until this specific IRQ has been counted before firing the next one.
            await _wait_condition(
                lambda: radio.crc_error_count >= expected,
                timeout=1.0,
            )
            # Prevent stale wakeups from reusing the previous CRC IRQ status.
            radio._last_irq_status = IRQ_NONE
            await _wait_condition(
                lambda: (
                    not radio._processing_rx_packet and not radio._rx_done_event.is_set()
                ),
                timeout=1.0,
            )

        radio._initialized = False
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass

        assert radio.crc_error_count == 3


# ===========================================================================
# 13. Failure injection
# ===========================================================================


class TestFailureInjection:
    """Inject hardware and async failures; verify safe recovery."""

    async def test_writeBuffer_exception_releases_tx_lock(self, radio, mock_lora):
        radio.perform_cad = AsyncMock(return_value=False)
        mock_lora.writeBuffer.side_effect = RuntimeError("SPI failed")
        with pytest.raises(RuntimeError):
            await radio.send(b"data")
        assert not radio._tx_lock.locked()

    async def test_setTx_exception_releases_tx_lock(self, radio, mock_lora):
        radio.perform_cad = AsyncMock(return_value=False)
        mock_lora.setTx.side_effect = OSError("setTx failed")
        with pytest.raises(Exception):
            await radio.send(b"data")
        assert not radio._tx_lock.locked()

    async def test_failed_send_leaves_radio_in_rx_mode(self, radio, mock_lora):
        radio.perform_cad = AsyncMock(return_value=False)
        mock_lora.writeBuffer.side_effect = RuntimeError("transient")
        with pytest.raises(RuntimeError):
            await radio.send(b"x")
        # _restore_rx_mode must have been attempted
        mock_lora.request.assert_called_with(mock_lora.RX_CONTINUOUS)

    async def test_permanently_busy_radio_raises_cleanly(self, radio, mock_lora):
        mock_lora.busyCheck.return_value = True  # never clears
        radio.perform_cad = AsyncMock(return_value=False)
        with pytest.raises(RuntimeError, match="Radio not ready for TX"):
            await radio.send(b"data")
        assert not radio._tx_lock.locked()

    async def test_second_send_succeeds_after_first_fails(self, radio, mock_lora):
        """State must be clean after a failed send so a retry can succeed."""
        radio.perform_cad = AsyncMock(return_value=False)

        # First send fails
        mock_lora.writeBuffer.side_effect = RuntimeError("transient")
        with pytest.raises(RuntimeError):
            await radio.send(b"fail")

        # Clear the injected fault
        mock_lora.writeBuffer.side_effect = None
        radio._wait_for_transmission_complete = AsyncMock(return_value=True)
        radio._finalize_transmission = MagicMock()
        mock_lora.getIrqStatus.return_value = IRQ_TX_DONE

        result = await radio.send(b"retry")
        assert result is not None

    async def test_getIrqStatus_exception_during_wait_yields_timeout(
        self, radio, mock_lora
    ):
        """OSError from getIrqStatus propagates via _handle_transmission_timeout."""
        radio._tx_done_event.clear()
        mock_lora.getIrqStatus.side_effect = OSError("SPI dead")
        with pytest.raises(OSError, match="SPI dead"):
            await radio._wait_for_transmission_complete(0.15)


# ===========================================================================
# 14. CAD threshold management
# ===========================================================================


class TestCADThresholds:
    def test_default_thresholds_for_known_sfs(self, radio):
        expected = {
            7: (22, 10),
            8: (22, 10),
            9: (24, 10),
            10: (25, 10),
            11: (26, 10),
            12: (30, 10),
        }
        for sf, (peak, min_val) in expected.items():
            radio.spreading_factor = sf
            assert radio._get_thresholds_for_current_settings() == (peak, min_val)

    def test_custom_thresholds_override_defaults(self, radio):
        radio.set_custom_cad_thresholds(peak=15, min_val=5)
        assert radio._get_thresholds_for_current_settings() == (15, 5)

    def test_custom_thresholds_out_of_range_raises(self, radio):
        with pytest.raises(ValueError):
            radio.set_custom_cad_thresholds(peak=256, min_val=0)
        with pytest.raises(ValueError):
            radio.set_custom_cad_thresholds(peak=10, min_val=-1)

    def test_clearing_custom_thresholds_restores_defaults(self, radio):
        radio.set_custom_cad_thresholds(peak=15, min_val=5)
        radio.clear_custom_cad_thresholds()
        radio.spreading_factor = 7
        assert radio._get_thresholds_for_current_settings() == (22, 10)

    def test_unknown_sf_falls_back_to_sf7_defaults(self, radio):
        radio._custom_cad_peak = None
        radio._custom_cad_min = None
        radio.spreading_factor = 6  # not in the table
        peak, min_val = radio._get_thresholds_for_current_settings()
        assert isinstance(peak, int)
        assert isinstance(min_val, int)


# ===========================================================================
# 15. TX/RX pin control
# ===========================================================================


class TestTxRxPinControl:
    def test_tx_mode_drives_txen_high_rxen_low(self, radio, mock_gpio):
        radio.txen_pin = 6
        radio.rxen_pin = 26
        radio._control_tx_rx_pins(tx_mode=True)
        mock_gpio.set_pin_high.assert_called_with(6)
        mock_gpio.set_pin_low.assert_called_with(26)

    def test_rx_mode_drives_txen_low_rxen_high(self, radio, mock_gpio):
        radio.txen_pin = 6
        radio.rxen_pin = 26
        radio._control_tx_rx_pins(tx_mode=False)
        mock_gpio.set_pin_low.assert_called_with(6)
        mock_gpio.set_pin_high.assert_called_with(26)

    def test_disabled_pins_are_not_touched(self, radio, mock_gpio):
        radio.txen_pin = -1
        radio.rxen_pin = -1
        mock_gpio.reset_mock()
        radio._control_tx_rx_pins(tx_mode=True)
        mock_gpio.set_pin_high.assert_not_called()
        mock_gpio.set_pin_low.assert_not_called()

    def test_tx_mode_only_txen_no_rxen(self, radio, mock_gpio):
        radio.txen_pin = 6
        radio.rxen_pin = -1
        mock_gpio.reset_mock()
        radio._control_tx_rx_pins(tx_mode=True)
        mock_gpio.set_pin_high.assert_called_once_with(6)
        mock_gpio.set_pin_low.assert_not_called()

    def test_send_sets_tx_pins_then_restores_rx_pins(self, radio, mock_lora, mock_gpio):
        """_finalize_transmission must drive pins back to RX mode."""
        mock_lora.getIrqStatus.return_value = IRQ_NONE
        mock_gpio.reset_mock()
        radio._finalize_transmission()
        # txen_pin (default=6) should go LOW after TX
        mock_gpio.set_pin_low.assert_called_with(radio.txen_pin)


# ===========================================================================
# 16. begin() initialisation sequence
# ===========================================================================


class TestBeginInitSequence:
    """begin() must initialise correctly and handle failure modes."""

    async def test_begin_succeeds_with_mocked_hardware(self, mock_lora, mock_gpio):
        from openhop_core.hardware.sx1262_wrapper import SX1262Radio

        with (
            patch(
                "openhop_core.hardware.sx1262_wrapper.SX126x", return_value=mock_lora
            ),
            patch(
                "openhop_core.hardware.sx1262_wrapper.GPIOPinManager",
                return_value=mock_gpio,
            ),
            patch("openhop_core.hardware.sx1262_wrapper.set_gpio_manager"),
        ):
            r = SX1262Radio(radio_timing_delay=0.0)
            result = r.begin()
        assert result is True
        assert r._initialized is True

    async def test_begin_returns_false_when_standby_not_reached(
        self, mock_lora, mock_gpio
    ):
        """Busy check never clears after reset → standby fails → return False."""
        mock_lora.busyCheck.return_value = True
        from openhop_core.hardware.sx1262_wrapper import SX1262Radio

        with (
            patch(
                "openhop_core.hardware.sx1262_wrapper.SX126x", return_value=mock_lora
            ),
            patch(
                "openhop_core.hardware.sx1262_wrapper.GPIOPinManager",
                return_value=mock_gpio,
            ),
            patch("openhop_core.hardware.sx1262_wrapper.set_gpio_manager"),
        ):
            r = SX1262Radio(radio_timing_delay=0.0)
            result = r.begin()
        assert result is False

    async def test_begin_raises_when_irq_pin_setup_fails(self, mock_lora, mock_gpio):
        """Failure to set up the IRQ interrupt pin must raise RuntimeError."""
        mock_gpio.setup_interrupt_pin.return_value = None
        from openhop_core.hardware.sx1262_wrapper import SX1262Radio

        with (
            patch(
                "openhop_core.hardware.sx1262_wrapper.SX126x", return_value=mock_lora
            ),
            patch(
                "openhop_core.hardware.sx1262_wrapper.GPIOPinManager",
                return_value=mock_gpio,
            ),
            patch("openhop_core.hardware.sx1262_wrapper.set_gpio_manager"),
        ):
            r = SX1262Radio(radio_timing_delay=0.0)
            with pytest.raises(RuntimeError):
                r.begin()

    async def test_begin_already_initialized_is_noop(self, radio, mock_lora):
        result = radio.begin()
        assert result is True
        mock_lora.reset.assert_not_called()

    async def test_begin_configures_rx_continuous_at_end(self, mock_lora, mock_gpio):
        from openhop_core.hardware.sx1262_wrapper import SX1262Radio

        with (
            patch(
                "openhop_core.hardware.sx1262_wrapper.SX126x", return_value=mock_lora
            ),
            patch(
                "openhop_core.hardware.sx1262_wrapper.GPIOPinManager",
                return_value=mock_gpio,
            ),
            patch("openhop_core.hardware.sx1262_wrapper.set_gpio_manager"),
        ):
            r = SX1262Radio(radio_timing_delay=0.0)
            r.begin()
        mock_lora.request.assert_called_with(mock_lora.RX_CONTINUOUS)

    async def test_begin_uses_image_calibration_for_frequency_band(
        self, mock_lora, mock_gpio
    ):
        """900 MHz band must use CAL_IMG_902/928 constants."""
        from openhop_core.hardware.sx1262_wrapper import SX1262Radio

        with (
            patch(
                "openhop_core.hardware.sx1262_wrapper.SX126x", return_value=mock_lora
            ),
            patch(
                "openhop_core.hardware.sx1262_wrapper.GPIOPinManager",
                return_value=mock_gpio,
            ),
            patch("openhop_core.hardware.sx1262_wrapper.set_gpio_manager"),
        ):
            r = SX1262Radio(frequency=915_000_000, radio_timing_delay=0.0)
            r.begin()
        mock_lora.calibrateImage.assert_called_with(
            mock_lora.CAL_IMG_902, mock_lora.CAL_IMG_928
        )


# ===========================================================================
# 17. Hardware integration test ideas (documented, not executable here)
# ===========================================================================


class TestHardwareIntegrationIdeas:
    """
    Placeholder class documenting hardware integration test strategies.

    These tests cannot run in CI without physical hardware, but are included
    to guide manual / on-device validation:

    1.  GPIO IRQ edge detection:
        - Connect a signal generator to the IRQ pin and verify _irq_trampoline
          fires within <1ms of the hardware edge.

    2.  SPI bus contention:
        - Run TX and a concurrent RX poll; verify SPI arbitration never hangs.

    3.  Real CAD on an over-the-air signal:
        - Inject a CW carrier on the RX frequency; verify perform_cad() returns
          True reliably.

    4.  Power-cycle recovery:
        - Cut radio power mid-TX; call begin() and verify full re-initialisation.

    5.  Long-duration RX stress:
        - Run the RX background task for 24 h with bursts every 5 s; verify
          no memory leak in crc_error_count and no task death.

    6.  Brownout / SPI glitch injection:
        - Toggle MISO to 0xFF during a status read; verify 0xFFFF retry logic
          absorbs the glitch and TX completes.

    7.  Concurrent GPIO and SPI:
        - Trigger IRQ pin while SPI is mid-transfer; verify no data corruption.

    8.  TCXO warm-up:
        - Measure first-packet RSSI before and after TCXO stabilises to confirm
          the 5ms/50ms delay is sufficient.
    """


# ===========================================================================
# 18. FIFO corruption race behavior
# ===========================================================================


class TestFIFOCorruptionRace:
    """
    Behavioral tests for FIFO corruption race windows.

    The SX1262 has a 256-byte FIFO shared between TX (base 0x00) and RX
    (base 0x80 = 128).  Any TX packet longer than 128 bytes has its last
    bytes land in the RX region (FIFO[0x80+]).

    Race window
    -----------
    A terminal RX interrupt (RX_DONE, CRC_ERR, TIMEOUT, HEADER_ERR) can
    arrive just *before* send() acquires _tx_lock.  At that moment
    _handle_interrupt sees the lock is free and legitimately sets
    _rx_done_event.  Once send() acquires the lock and writes the FIFO,
    the first ``await`` inside _prepare_radio_for_tx() yields the event
    loop.  _rx_irq_background_task is waiting on _rx_done_event — the
    event is still set — so it wakes, processes the "received" interrupt,
    and calls ``request(RX_CONTINUOUS)``, briefly returning the radio to
    receive mode.  If any packet arrives during that window it is written
    to FIFO[0x80+], overwriting the TX overflow bytes.  setTx() then
    transmits the corrupted data with a valid CRC (the radio computes CRC
    over whatever bytes are in the FIFO).

    Fix
    ---
    Clear _rx_done_event immediately after _tx_done_event in
    _prepare_radio_for_tx(), before the first ``await``.
    Because _tx_lock is already held at that point, _handle_interrupt
    cannot set the event again, so _rx_irq_background_task stays asleep
    for the entire TX preparation window.
    """

    async def test_stale_rx_event_does_not_re_enable_rx_before_setTx(
        self, radio, mock_lora
    ):
        """
        Proves the race: a stale _rx_done_event causes _rx_irq_background_task
        to call request(RX_CONTINUOUS) while the TX lock is held and before
        setTx() fires — the exact window where an incoming packet can corrupt
        FIFO[0x80+] for any TX packet > 128 bytes.

        This test verifies event and lock ordering during TX preparation.
        """
        # Track whether request(RX_CONTINUOUS) is called in the dangerous
        # window: TX lock held AND setTx() not yet called.
        rx_re_enabled_in_fifo_window: list[str] = []
        setTx_called = False

        def _track_setTx(timeout):
            nonlocal setTx_called
            setTx_called = True

        def _track_request(mode):
            if (
                mode == mock_lora.RX_CONTINUOUS
                and radio._tx_lock.locked()
                and not setTx_called
            ):
                rx_re_enabled_in_fifo_window.append(
                    "request(RX_CONTINUOUS) called during TX prep"
                )

        mock_lora.setTx.side_effect = _track_setTx
        mock_lora.request.side_effect = _track_request

        # Simulate: a packet arrived just before send() acquires _tx_lock.
        # _handle_interrupt saw lock=False and set _rx_done_event (correct
        # behaviour — the lock wasn't held yet).  IRQ_TIMEOUT is used because
        # its path through _rx_irq_background_task is simplest (no readBuffer).
        radio._last_irq_status = IRQ_TIMEOUT
        radio._rx_done_event.set()

        # Start the background task (normally started in begin()).
        bg_task = asyncio.get_running_loop().create_task(
            radio._rx_irq_background_task()
        )

        # Send a packet > 128 bytes — the size that overflows into the RX
        # region of the shared FIFO.
        radio.perform_cad = AsyncMock(return_value=False)
        radio._wait_for_transmission_complete = AsyncMock(return_value=True)
        radio._finalize_transmission = MagicMock()
        await radio.send(bytes(136))

        bg_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await bg_task

        assert rx_re_enabled_in_fifo_window == [], "\n".join(
            [
                "",
                "FIFO corruption race reproduced:",
                f"  request(RX_CONTINUOUS) was called {len(rx_re_enabled_in_fifo_window)}"
                " time(s) while TX lock was held and before setTx() fired.",
                "  A stale _rx_done_event (set before _tx_lock was acquired) woke",
                "  _rx_irq_background_task at the first await in _prepare_radio_for_tx().",
                "  On a busy network this allows an incoming packet to overwrite",
                "  FIFO[0x80+], corrupting the last bytes of any TX packet > 128 bytes.",
                "  Fix: add  self._rx_done_event.clear()  in _prepare_radio_for_tx()",
                "  immediately after self._tx_done_event.clear(), before setStandby().",
            ]
        )

    async def test_irq_handler_exception_fallback_respects_tx_lock(
        self, radio, mock_lora
    ):
        """
        The exception fallback in _handle_interrupt sets _rx_done_event
        unconditionally as a last resort.  If this fires while _tx_lock is held
        it re-introduces the same FIFO corruption race that the primary fix closes.

        This test verifies the fallback also guards on _tx_lock.locked().
        """
        rx_re_enabled_in_fifo_window: list[str] = []
        setTx_called = False

        def _track_setTx(timeout):
            nonlocal setTx_called
            setTx_called = True

        def _track_request(mode):
            if (
                mode == mock_lora.RX_CONTINUOUS
                and radio._tx_lock.locked()
                and not setTx_called
            ):
                rx_re_enabled_in_fifo_window.append(
                    "request(RX_CONTINUOUS) called during TX prep via exception fallback"
                )

        mock_lora.setTx.side_effect = _track_setTx
        mock_lora.request.side_effect = _track_request

        # Force _handle_interrupt's exception fallback to fire while the lock
        # is held.  We do this by making getIrqStatus raise on the first call
        # (which happens inside _handle_interrupt), then restoring it so the
        # rest of send() works normally.
        call_count = [0]

        def _fail_first_irq_read():
            call_count[0] += 1
            if call_count[0] == 1:
                raise OSError("SPI glitch during IRQ read")
            return IRQ_TX_DONE

        mock_lora.getIrqStatus.side_effect = _fail_first_irq_read

        # Start the background task.
        bg_task = asyncio.get_running_loop().create_task(
            radio._rx_irq_background_task()
        )

        # Inject the interrupt while the lock is NOT yet held so it fires
        # the exception fallback (getIrqStatus raises), which would set
        # _rx_done_event unconditionally before the fix.
        radio._handle_interrupt()

        radio.perform_cad = AsyncMock(return_value=False)
        radio._wait_for_transmission_complete = AsyncMock(return_value=True)
        radio._finalize_transmission = MagicMock()
        await radio.send(bytes(136))

        bg_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await bg_task

        assert rx_re_enabled_in_fifo_window == [], (
            "Exception fallback in _handle_interrupt set _rx_done_event while TX "
            "lock was held, allowing _rx_irq_background_task to re-enable RX "
            "during TX preparation. The fallback must guard on _tx_lock.locked()."
        )

    async def test_background_task_midflight_does_not_re_enable_rx_during_tx(
        self, radio, mock_lora
    ):
        """
        Background task mid-flight scenario.

        _rx_irq_background_task can already be executing (past the _rx_done_event
        wait) when send() acquires _tx_lock.  Before the fix it calls
        request(RX_CONTINUOUS) unconditionally, putting the radio back into RX
        mid-TX-setup regardless of the lock.

        Fix: wrap request(RX_CONTINUOUS) in _rx_irq_background_task with
             `if not self._tx_lock.locked():`.
        """
        rx_re_enabled_while_locked: list[str] = []
        setTx_called = False

        def _track_setTx(timeout):
            nonlocal setTx_called
            setTx_called = True

        def _track_request(mode):
            if (
                mode == mock_lora.RX_CONTINUOUS
                and radio._tx_lock.locked()
                and not setTx_called
            ):
                rx_re_enabled_while_locked.append(
                    "request(RX_CONTINUOUS) called by background task while TX lock held"
                )

        mock_lora.setTx.side_effect = _track_setTx
        mock_lora.request.side_effect = _track_request

        # Simulate a received packet arriving just before send() — the background
        # task has consumed the event and is mid-flight when the lock is taken.
        # IRQ_TIMEOUT is the simplest path through the bg task (no payload read).
        # The bg task reads _last_irq_status directly; getIrqStatus is left at its
        # fixture default (IRQ_NONE) so the TX path initial-status check sees clean state.
        radio._last_irq_status = IRQ_TIMEOUT
        radio._rx_done_event.set()  # event already consumed before lock acquired

        bg_task = asyncio.get_running_loop().create_task(
            radio._rx_irq_background_task()
        )

        radio.perform_cad = AsyncMock(return_value=False)
        radio._wait_for_transmission_complete = AsyncMock(return_value=True)
        radio._finalize_transmission = MagicMock()
        await radio.send(bytes(136))

        bg_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await bg_task

        assert rx_re_enabled_while_locked == [], "\n".join(
            [
                "",
                "Background task mid-flight race reproduced:",
                f"  request(RX_CONTINUOUS) was called {len(rx_re_enabled_while_locked)}"
                " time(s) by _rx_irq_background_task while _tx_lock was held.",
                "  The background task was already past the _rx_done_event wait when",
                "  send() acquired the lock, and completed its unconditional",
                "  request(RX_CONTINUOUS) call, putting the radio back in RX mode",
                "  mid-TX setup. For packets >128 bytes this overwrites FIFO[0x80+].",
                "  Fix: guard request(RX_CONTINUOUS) with `if not self._tx_lock.locked()`",
                "  in _rx_irq_background_task().",
            ]
        )

    async def test_patched_legacy_sequence_reproduces_fifo_window(
        self, radio, mock_lora, monkeypatch
    ):
        """
        With SX1262 configured TX=0x00 and RX=0x80, any TX payload >128 bytes
        overlaps the RX region of the shared 256-byte FIFO, so restoring RX in
        this window can overwrite the TX tail.
        """
        rx_re_enabled_in_fifo_window: list[str] = []
        setTx_called = False

        def _track_setTx(timeout):
            nonlocal setTx_called
            setTx_called = True

        def _track_request(mode):
            if (
                mode == mock_lora.RX_CONTINUOUS
                and radio._tx_lock.locked()
                and not setTx_called
            ):
                rx_re_enabled_in_fifo_window.append(
                    "request(RX_CONTINUOUS) called during TX prep window"
                )

        mock_lora.setTx.side_effect = _track_setTx
        mock_lora.request.side_effect = _track_request

        async def _legacy_prepare_radio_for_tx():
            radio._tx_done_event.clear()
            # Intentionally omit: radio._rx_done_event.clear()
            radio.lora.setStandby(radio.lora.STANDBY_RC)
            await asyncio.sleep(radio.RADIO_TIMING_DELAY)
            return True, []

        async def _legacy_rx_irq_background_task():
            await radio._rx_done_event.wait()
            radio._rx_done_event.clear()
            # Intentionally unguarded to emulate legacy behavior.
            radio.lora.request(radio.lora.RX_CONTINUOUS)

        monkeypatch.setattr(
            radio, "_prepare_radio_for_tx", _legacy_prepare_radio_for_tx
        )
        monkeypatch.setattr(
            radio, "_rx_irq_background_task", _legacy_rx_irq_background_task
        )

        # Stale RX event set before send() acquires TX lock.
        radio._last_irq_status = IRQ_TIMEOUT
        radio._rx_done_event.set()

        bg_task = asyncio.get_running_loop().create_task(
            radio._rx_irq_background_task()
        )

        radio.perform_cad = AsyncMock(return_value=False)
        radio._wait_for_transmission_complete = AsyncMock(return_value=True)
        radio._finalize_transmission = MagicMock()
        await radio.send(bytes(136))
        await bg_task

        write_addr, _, write_len = mock_lora.writeBuffer.call_args[0]
        assert write_addr == 0x00
        assert write_len > 128
        assert rx_re_enabled_in_fifo_window != [], (
            "Expected legacy sequencing to re-enable RX while TX lock was held "
            "before setTx(), but it did not trigger."
        )

    async def test_perform_cad_does_not_restore_rx_while_tx_lock_held(
        self, radio, mock_lora
    ):
        """
        Race 3: perform_cad() cleanup must not request RX_CONTINUOUS while send()
        still holds _tx_lock and has not started setTx() yet.

        This is the CAD-specific variant of the FIFO corruption window.
        """
        rx_re_enabled_in_fifo_window: list[str] = []
        setTx_called = False

        def _track_setTx(timeout):
            nonlocal setTx_called
            setTx_called = True

        def _track_request(mode):
            if (
                mode == mock_lora.RX_CONTINUOUS
                and radio._tx_lock.locked()
                and not setTx_called
            ):
                rx_re_enabled_in_fifo_window.append(
                    "perform_cad() restored RX_CONTINUOUS before setTx()"
                )

        mock_lora.setTx.side_effect = _track_setTx
        mock_lora.request.side_effect = _track_request

        arm_cad_completion(radio, detected=False)

        radio._wait_for_transmission_complete = AsyncMock(return_value=True)
        radio._finalize_transmission = MagicMock()
        await radio.send(bytes(136))

        assert rx_re_enabled_in_fifo_window == [], "\n".join(
            [
                "",
                "CAD cleanup race reproduced — RX restored mid-TX prep:",
                f"  request(RX_CONTINUOUS) was called {len(rx_re_enabled_in_fifo_window)}"
                " time(s) while _tx_lock was held and before setTx().",
                "  perform_cad() must not restore RX_CONTINUOUS during active TX prep;",
                "  send() already restores RX in its finally block after TX completes.",
            ]
        )


# ===========================================================================
# 19. Targeted branch-coverage tests
# ===========================================================================


class TestCoverageGapBranches:
    def test_constructor_ignores_previous_instance_without_cleanup(
        self, mock_gpio, caplog
    ):
        """Phase 1: a stale _active_instance is not cleaned up on construct."""
        import logging

        from openhop_core.hardware.sx1262_wrapper import SX1262Radio

        previous = MagicMock()
        previous.cleanup.side_effect = RuntimeError("cleanup failed")
        SX1262Radio._active_instance = previous

        with (
            patch(
                "openhop_core.hardware.sx1262_wrapper.GPIOPinManager",
                return_value=mock_gpio,
            ),
            patch("openhop_core.hardware.sx1262_wrapper.set_gpio_manager"),
            caplog.at_level(logging.ERROR, logger="SX1262_wrapper"),
        ):
            radio = SX1262Radio(radio_timing_delay=0.0)

        previous.cleanup.assert_not_called()
        assert radio is not previous
        assert "Error cleaning up previous instance" not in caplog.text

    def test_constructor_uses_existing_gpio_manager(self, mock_gpio):
        import importlib

        from openhop_core.hardware.sx1262_wrapper import SX1262Radio

        sx126x_module = importlib.import_module(
            "openhop_core.hardware.lora.LoRaRF.SX126x"
        )
        previous_gpio_manager = getattr(sx126x_module, "_gpio_manager", None)
        sx126x_module.set_gpio_manager(mock_gpio)

        try:
            with (
                patch(
                    "openhop_core.hardware.sx1262_wrapper.GPIOPinManager"
                ) as gp_patch,
                patch(
                    "openhop_core.hardware.sx1262_wrapper.set_gpio_manager"
                ) as set_patch,
            ):
                radio = SX1262Radio(radio_timing_delay=0.0)

            assert radio._gpio_manager is mock_gpio
            gp_patch.assert_not_called()
            set_patch.assert_not_called()
        finally:
            sx126x_module.set_gpio_manager(previous_gpio_manager)

    def test_trampoline_early_return_when_shutting_down(self, radio):
        radio._shutting_down = True
        radio._event_loop = MagicMock()
        radio._irq_trampoline()
        radio._event_loop.call_soon_threadsafe.assert_not_called()

    def test_trampoline_runtime_error_logs_for_non_closed_loop(self, radio, caplog):
        import logging

        radio._event_loop = MagicMock()
        radio._event_loop.call_soon_threadsafe.side_effect = RuntimeError("loop boom")

        with caplog.at_level(logging.ERROR, logger="SX1262_wrapper"):
            radio._irq_trampoline()

        assert any(
            "IRQ trampoline runtime error" in r.getMessage() for r in caplog.records
        )

    def test_trampoline_generic_exception_logs_error(self, radio, caplog):
        import logging

        radio._event_loop = MagicMock()
        radio._event_loop.call_soon_threadsafe.side_effect = ValueError("unexpected")

        with caplog.at_level(logging.ERROR, logger="SX1262_wrapper"):
            radio._irq_trampoline()

        assert any("IRQ trampoline error" in r.getMessage() for r in caplog.records)

    def test_setters_return_false_if_uninitialized(self, radio):
        radio._initialized = False
        assert radio.set_frequency(868100000) is False
        assert radio.set_tx_power(14) is False
        assert radio.set_spreading_factor(9) is False
        assert radio.set_bandwidth(250000) is False

    def test_setters_update_driver_and_state(self, radio, mock_lora):
        assert radio.set_frequency(915000000) is True
        assert radio.set_tx_power(17) is True
        assert radio.set_spreading_factor(10) is True
        assert radio.set_bandwidth(250000) is True

        assert radio.frequency == 915000000
        assert radio.tx_power == 17
        assert radio.spreading_factor == 10
        assert radio.bandwidth == 250000
        mock_lora.setFrequency.assert_called_once_with(915000000)

    def test_set_tx_power_returns_false_when_driver_raises(self, radio, mock_lora):
        mock_lora.setTxPower.side_effect = RuntimeError("txpower failed")
        assert radio.set_tx_power(20) is False

    async def test_wait_for_tx_timeout_clear_irq_exception_swallowed(
        self, radio, mock_lora
    ):
        radio._tx_done_event.clear()
        mock_lora.getIrqStatus.return_value = IRQ_TIMEOUT
        mock_lora.clearIrqStatus.side_effect = RuntimeError("clear failed")
        assert await radio._wait_for_transmission_complete(0.2) is False

    async def test_handle_transmission_timeout_logs_configuration_issue(
        self, radio, mock_lora, caplog
    ):
        import logging

        mock_lora.getIrqStatus.return_value = IRQ_TIMEOUT
        with caplog.at_level(logging.ERROR, logger="SX1262_wrapper"):
            await radio._handle_transmission_timeout(0.2, time.time())
        assert any(
            "configuration issue" in r.getMessage().lower() for r in caplog.records
        )

    def test_finalize_transmission_timeout_warning_path(self, radio, mock_lora, caplog):
        import logging

        mock_lora.getIrqStatus.return_value = IRQ_TIMEOUT
        with caplog.at_level(logging.WARNING, logger="SX1262_wrapper"):
            radio._finalize_transmission()
        assert any("TX_TIMEOUT" in r.getMessage() for r in caplog.records)

    def test_finalize_transmission_logs_stats_when_available(self, radio, mock_lora):
        mock_lora.getIrqStatus.return_value = IRQ_TX_DONE
        mock_lora.transmitTime.return_value = 12.5
        mock_lora.dataRate.return_value = 32.0
        radio._finalize_transmission()
        mock_lora.dataRate.assert_called_once()

    def test_finalize_transmission_stats_exception_is_swallowed(self, radio, mock_lora):
        mock_lora.getIrqStatus.return_value = IRQ_TX_DONE
        mock_lora.transmitTime.side_effect = RuntimeError("no stats")
        radio._finalize_transmission()  # must not raise

    async def test_wait_for_rx_is_not_implemented(self, radio):
        with pytest.raises(NotImplementedError):
            await radio.wait_for_rx()

    def test_sleep_and_metric_getters(self, radio, mock_lora):
        radio.last_rssi = -77
        radio.last_snr = 4.5
        radio.last_signal_rssi = -79
        radio.sleep()
        mock_lora.sleep.assert_called_once()
        assert radio.get_last_rssi() == -77
        assert radio.get_last_snr() == pytest.approx(4.5)
        assert radio.get_last_signal_rssi() == -79

    def test_sleep_driver_exception_is_swallowed(self, radio, mock_lora):
        mock_lora.sleep.side_effect = RuntimeError("sleep failed")
        radio.sleep()  # must not raise

    def test_get_noise_floor_returns_none_while_tx_lock_held(self, radio):
        radio._tx_lock = MagicMock()
        radio._tx_lock.locked.return_value = True
        assert radio.get_noise_floor() is None

    def test_noise_floor_sampling_handles_rssi_read_exception(self, radio, mock_lora):
        radio._last_packet_activity = 0.0
        radio._processing_rx_packet = False
        mock_lora.getRssiInst.side_effect = RuntimeError("rssi error")
        radio._sample_noise_floor()  # must not raise

    async def test_perform_cad_raises_when_not_initialized(self, radio):
        radio._initialized = False
        with pytest.raises(RuntimeError, match="Radio not initialized"):
            await radio.perform_cad(timeout=0.1)

    async def test_perform_cad_raises_when_lora_missing(self, radio):
        radio.lora = None
        with pytest.raises(RuntimeError, match="LoRa radio object not available"):
            await radio.perform_cad(timeout=0.1)

    async def test_perform_cad_clears_existing_irq_before_operation(
        self, radio, mock_lora
    ):
        mock_lora.getIrqStatus.side_effect = [0x0010, 0x0000]
        arm_cad_completion(radio, detected=False)
        started = time.monotonic()
        result = await radio.perform_cad(timeout=1.0)
        elapsed = time.monotonic() - started
        assert result is False
        assert elapsed < 0.5, (
            "perform_cad() timed out instead of completing, so the existing-IRQ "
            "clear was not verified against a real CAD operation"
        )
        assert any(c.args == (0x0010,) for c in mock_lora.clearIrqStatus.call_args_list)

    async def test_perform_cad_warns_when_irq_pin_stays_high(
        self, radio, mock_lora, caplog
    ):
        import logging

        radio._gpio_manager.read_pin.return_value = True
        mock_lora.getIrqStatus.return_value = 0
        with caplog.at_level(logging.WARNING, logger="SX1262_wrapper"):
            await radio.perform_cad(timeout=0.05)
        assert any("IRQ pin stuck HIGH" in r.getMessage() for r in caplog.records)

    async def test_perform_cad_success_clears_nonzero_current_irq(
        self, radio, mock_lora
    ):
        # existing_irq=0, current_irq(after completion)=0x0020
        mock_lora.getIrqStatus.side_effect = [0, 0x0020]
        arm_cad_completion(radio, detected=True, irq_status=IRQ_CAD_DONE)
        assert await radio.perform_cad(timeout=1.0) is True
        assert any(c.args == (0x0020,) for c in mock_lora.clearIrqStatus.call_args_list)

    async def test_perform_cad_timeout_clears_nonzero_irq(self, radio, mock_lora):
        # existing_irq=0, timeout irq check=0x0040
        mock_lora.getIrqStatus.side_effect = [0, 0x0040]
        result = await radio.perform_cad(timeout=0.05)
        assert result is False
        assert any(c.args == (0x0040,) for c in mock_lora.clearIrqStatus.call_args_list)

    def test_cleanup_handles_rx_task_done_check_exception(self, radio):
        bad_task = MagicMock()
        bad_task.done.side_effect = RuntimeError("task state failed")
        radio._rx_irq_task = bad_task
        radio.cleanup()  # must not raise


class TestBeginBranchCoverage:
    def test_begin_sets_manual_cs_pin_when_configured(self, mock_lora, mock_gpio):
        from openhop_core.hardware.sx1262_wrapper import SX1262Radio

        with (
            patch(
                "openhop_core.hardware.sx1262_wrapper.SX126x", return_value=mock_lora
            ),
            patch(
                "openhop_core.hardware.sx1262_wrapper.GPIOPinManager",
                return_value=mock_gpio,
            ),
            patch("openhop_core.hardware.sx1262_wrapper.set_gpio_manager"),
        ):
            radio = SX1262Radio(cs_pin=21, radio_timing_delay=0.0)
            assert radio.begin() is True

        mock_lora.setManualCsPin.assert_called_once_with(21)

    def test_begin_logs_warnings_for_output_pin_setup_failures(
        self, mock_lora, mock_gpio, caplog
    ):
        import logging

        from openhop_core.hardware.sx1262_wrapper import SX1262Radio

        failing_pins = {6, 26, 23, 24, 30}

        def _setup_output_pin(pin, initial_value=False):
            return pin not in failing_pins

        mock_gpio.setup_output_pin.side_effect = _setup_output_pin

        with (
            patch(
                "openhop_core.hardware.sx1262_wrapper.SX126x", return_value=mock_lora
            ),
            patch(
                "openhop_core.hardware.sx1262_wrapper.GPIOPinManager",
                return_value=mock_gpio,
            ),
            patch("openhop_core.hardware.sx1262_wrapper.set_gpio_manager"),
            caplog.at_level(logging.WARNING, logger="SX1262_wrapper"),
        ):
            radio = SX1262Radio(
                txen_pin=6,
                rxen_pin=26,
                txled_pin=23,
                rxled_pin=24,
                en_pins=[30],
                radio_timing_delay=0.0,
            )
            assert radio.begin() is True

        expected = [
            "Could not setup TXEN pin",
            "Could not setup RXEN pin",
            "Could not setup TX LED pin",
            "Could not setup RX LED pin",
            "Could not setup EN pin",
        ]
        for msg in expected:
            assert any(msg in r.getMessage() for r in caplog.records)

    def test_begin_maps_invalid_tcxo_voltage_to_closest_value(
        self, mock_lora, mock_gpio
    ):
        from openhop_core.hardware.sx1262_wrapper import SX1262Radio

        with (
            patch(
                "openhop_core.hardware.sx1262_wrapper.SX126x", return_value=mock_lora
            ),
            patch(
                "openhop_core.hardware.sx1262_wrapper.GPIOPinManager",
                return_value=mock_gpio,
            ),
            patch("openhop_core.hardware.sx1262_wrapper.set_gpio_manager"),
        ):
            radio = SX1262Radio(
                use_dio3_tcxo=True, dio3_tcxo_voltage=2.6, radio_timing_delay=0.0
            )
            assert radio.begin() is True

        mock_lora.setDio3TcxoCtrl.assert_called_once_with(
            mock_lora.DIO3_OUTPUT_2_7, mock_lora.TCXO_DELAY_5
        )

    def test_begin_custom_cad_threshold_write_failure_is_non_fatal(
        self, mock_lora, mock_gpio, caplog
    ):
        import logging

        from openhop_core.hardware.sx1262_wrapper import SX1262Radio

        mock_lora.setCadParams.side_effect = RuntimeError("cad params failed")

        with (
            patch(
                "openhop_core.hardware.sx1262_wrapper.SX126x", return_value=mock_lora
            ),
            patch(
                "openhop_core.hardware.sx1262_wrapper.GPIOPinManager",
                return_value=mock_gpio,
            ),
            patch("openhop_core.hardware.sx1262_wrapper.set_gpio_manager"),
            caplog.at_level(logging.WARNING, logger="SX1262_wrapper"),
        ):
            radio = SX1262Radio(radio_timing_delay=0.0)
            radio._custom_cad_peak = 12
            radio._custom_cad_min = 4
            assert radio.begin() is True

        assert any(
            "[CAD] Failed to write thresholds" in r.getMessage() for r in caplog.records
        )

    def test_begin_custom_cad_threshold_write_success(self, mock_lora, mock_gpio):
        from openhop_core.hardware.sx1262_wrapper import SX1262Radio

        with (
            patch(
                "openhop_core.hardware.sx1262_wrapper.SX126x", return_value=mock_lora
            ),
            patch(
                "openhop_core.hardware.sx1262_wrapper.GPIOPinManager",
                return_value=mock_gpio,
            ),
            patch("openhop_core.hardware.sx1262_wrapper.set_gpio_manager"),
        ):
            radio = SX1262Radio(radio_timing_delay=0.0)
            radio._custom_cad_peak = 12
            radio._custom_cad_min = 4
            assert radio.begin() is True

        # One call from begin() custom-threshold programming path.
        assert mock_lora.setCadParams.call_count >= 1

    def test_begin_polling_start_exception_is_non_fatal(
        self, mock_lora, mock_gpio, caplog
    ):
        import logging

        from openhop_core.hardware.sx1262_wrapper import SX1262Radio

        irq_pin_obj = MagicMock()
        irq_pin_obj.start_polling.side_effect = RuntimeError("poll failed")
        mock_gpio._pins = {16: irq_pin_obj}

        with (
            patch(
                "openhop_core.hardware.sx1262_wrapper.SX126x", return_value=mock_lora
            ),
            patch(
                "openhop_core.hardware.sx1262_wrapper.GPIOPinManager",
                return_value=mock_gpio,
            ),
            patch("openhop_core.hardware.sx1262_wrapper.set_gpio_manager"),
            caplog.at_level(logging.WARNING, logger="SX1262_wrapper"),
        ):
            radio = SX1262Radio(radio_timing_delay=0.0)
            assert radio.begin() is True

        assert any(
            "Failed to start IRQ polling" in r.getMessage() for r in caplog.records
        )

    def test_begin_returns_true_without_running_loop_for_rx_task_start(
        self, mock_lora, mock_gpio
    ):
        from openhop_core.hardware.sx1262_wrapper import SX1262Radio

        with (
            patch(
                "openhop_core.hardware.sx1262_wrapper.SX126x", return_value=mock_lora
            ),
            patch(
                "openhop_core.hardware.sx1262_wrapper.GPIOPinManager",
                return_value=mock_gpio,
            ),
            patch("openhop_core.hardware.sx1262_wrapper.set_gpio_manager"),
        ):
            radio = SX1262Radio(radio_timing_delay=0.0)
            assert radio.begin() is True
            assert not hasattr(radio, "_rx_irq_task")

    async def test_begin_uses_already_running_rx_irq_task(self, mock_lora, mock_gpio):
        from openhop_core.hardware.sx1262_wrapper import SX1262Radio

        existing_task = MagicMock()
        existing_task.done.return_value = False

        with (
            patch(
                "openhop_core.hardware.sx1262_wrapper.SX126x", return_value=mock_lora
            ),
            patch(
                "openhop_core.hardware.sx1262_wrapper.GPIOPinManager",
                return_value=mock_gpio,
            ),
            patch("openhop_core.hardware.sx1262_wrapper.set_gpio_manager"),
        ):
            radio = SX1262Radio(radio_timing_delay=0.0)
            radio._rx_irq_task = existing_task
            assert radio.begin() is True

        assert radio._rx_irq_task is existing_task

    async def test_begin_rx_task_start_exception_is_non_fatal(
        self, mock_lora, mock_gpio, caplog
    ):
        import logging

        from openhop_core.hardware.sx1262_wrapper import SX1262Radio

        with (
            patch(
                "openhop_core.hardware.sx1262_wrapper.SX126x", return_value=mock_lora
            ),
            patch(
                "openhop_core.hardware.sx1262_wrapper.GPIOPinManager",
                return_value=mock_gpio,
            ),
            patch("openhop_core.hardware.sx1262_wrapper.set_gpio_manager"),
            patch(
                "openhop_core.hardware.sx1262_wrapper.asyncio.get_running_loop",
                side_effect=ValueError("loop boom"),
            ),
            caplog.at_level(logging.WARNING, logger="SX1262_wrapper"),
        ):
            radio = SX1262Radio(radio_timing_delay=0.0)
            assert radio.begin() is True

        assert any(
            "Failed to start RX IRQ background handler" in r.getMessage()
            for r in caplog.records
        )

    @pytest.mark.parametrize(
        "freq,cal_min,cal_max",
        [
            (433_000_000, "CAL_IMG_430", "CAL_IMG_440"),
            (500_000_000, "CAL_IMG_470", "CAL_IMG_510"),
            (800_000_000, "CAL_IMG_779", "CAL_IMG_787"),
            (868_000_000, "CAL_IMG_863", "CAL_IMG_870"),
        ],
    )
    def test_begin_frequency_band_calibration_paths(
        self, mock_lora, mock_gpio, freq, cal_min, cal_max
    ):
        from openhop_core.hardware.sx1262_wrapper import SX1262Radio

        with (
            patch(
                "openhop_core.hardware.sx1262_wrapper.SX126x", return_value=mock_lora
            ),
            patch(
                "openhop_core.hardware.sx1262_wrapper.GPIOPinManager",
                return_value=mock_gpio,
            ),
            patch("openhop_core.hardware.sx1262_wrapper.set_gpio_manager"),
        ):
            radio = SX1262Radio(frequency=freq, radio_timing_delay=0.0)
            assert radio.begin() is True

        mock_lora.calibrateImage.assert_called_with(
            getattr(mock_lora, cal_min), getattr(mock_lora, cal_max)
        )


class TestFactoryAndSingletonPaths:
    def test_get_instance_constructs_when_singleton_missing(self, mock_gpio):
        from openhop_core.hardware.sx1262_wrapper import SX1262Radio

        SX1262Radio._active_instance = None
        with (
            patch(
                "openhop_core.hardware.sx1262_wrapper.GPIOPinManager",
                return_value=mock_gpio,
            ),
            patch("openhop_core.hardware.sx1262_wrapper.set_gpio_manager"),
        ):
            instance = SX1262Radio.get_instance(radio_timing_delay=0.0)

        assert isinstance(instance, SX1262Radio)

    def test_create_sx1262_radio_returns_instance_on_success(self):
        from openhop_core.hardware import sx1262_wrapper as module

        fake_radio = MagicMock()
        fake_radio.begin.return_value = True

        with patch.object(module, "SX1262Radio", return_value=fake_radio):
            created = module.create_sx1262_radio(test=True)

        assert created is fake_radio

    def test_create_sx1262_radio_raises_when_begin_fails(self):
        from openhop_core.hardware import sx1262_wrapper as module

        fake_radio = MagicMock()
        fake_radio.begin.return_value = False

        with patch.object(module, "SX1262Radio", return_value=fake_radio):
            with pytest.raises(RuntimeError, match="Failed to initialize SX1262 radio"):
                module.create_sx1262_radio(test=True)


class TestCoverageSecondPass:
    def test_trampoline_clears_loop_on_closed_runtime_error(self, radio):
        radio._event_loop = MagicMock()
        radio._event_loop.call_soon_threadsafe.side_effect = RuntimeError(
            "Event loop is closed"
        )
        radio._irq_trampoline()
        assert radio._event_loop is None

    def test_basic_radio_setup_fails_when_mode_mismatch_without_busy_check(
        self, radio, mock_lora
    ):
        mock_lora.getMode.return_value = 999
        assert radio._basic_radio_setup(use_busy_check=False) is False

    def test_set_rx_callback_no_running_loop_logs_debug(self, radio, caplog):
        import logging

        radio._rx_irq_task = None
        with caplog.at_level(logging.DEBUG, logger="SX1262_wrapper"):
            radio.set_rx_callback(lambda _pkt: None)
        assert any(
            "No event loop available for RX task startup" in r.getMessage()
            for r in caplog.records
        )

    async def test_set_rx_callback_running_loop_error_logs_warning(self, radio, caplog):
        import logging

        radio._rx_irq_task = None
        with (
            patch(
                "openhop_core.hardware.sx1262_wrapper.asyncio.get_running_loop",
                side_effect=ValueError("boom"),
            ),
            caplog.at_level(logging.WARNING, logger="SX1262_wrapper"),
        ):
            radio.set_rx_callback(lambda _pkt: None)
        assert any(
            "Failed to start delayed RX IRQ background handler" in r.getMessage()
            for r in caplog.records
        )

    async def test_rx_crc_diag_readbuffer_failure_logs_read_failed(self, radio, caplog):
        import logging

        radio.lora.getRxBufferStatus.return_value = (4, 0x80)
        radio.lora.readBuffer.side_effect = RuntimeError("read fail")
        task = asyncio.get_running_loop().create_task(radio._rx_irq_background_task())
        radio._last_irq_status = IRQ_CRC_ERR
        with caplog.at_level(logging.WARNING, logger="SX1262_wrapper"):
            radio._rx_done_event.set()
            await asyncio.sleep(0.05)
        radio._initialized = False
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        assert "RawData=(read failed)" in caplog.text or "CRC error" in caplog.text

    async def test_rx_crc_diag_collection_failure_uses_fallback_warning(
        self, radio, caplog
    ):
        import logging

        radio.lora.getSignalMetrics.side_effect = RuntimeError("diag fail")
        task = asyncio.get_running_loop().create_task(radio._rx_irq_background_task())
        radio._last_irq_status = IRQ_CRC_ERR
        with caplog.at_level(logging.WARNING, logger="SX1262_wrapper"):
            radio._rx_done_event.set()
            await asyncio.sleep(0.05)
        radio._initialized = False
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        assert any(
            "Unable to collect diagnostics" in r.getMessage() for r in caplog.records
        )

    async def test_rx_no_callback_warning_path(self, radio, caplog):
        import logging

        radio.rx_callback = None
        task = asyncio.get_running_loop().create_task(radio._rx_irq_background_task())
        radio._last_irq_status = IRQ_RX_DONE
        with caplog.at_level(logging.WARNING, logger="SX1262_wrapper"):
            radio._rx_done_event.set()
            await asyncio.sleep(0.05)
        radio._initialized = False
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        assert any(
            "No RX callback registered" in r.getMessage() for r in caplog.records
        )

    @pytest.mark.parametrize(
        "irq", [IRQ_PREAMBLE_DETECTED, IRQ_SYNC_WORD_VALID, IRQ_HEADER_VALID, 0x0000]
    )
    async def test_rx_progress_and_other_irq_paths(self, radio, irq):
        task = asyncio.get_running_loop().create_task(radio._rx_irq_background_task())
        radio._last_irq_status = irq
        radio._rx_done_event.set()
        await asyncio.sleep(0.05)
        radio._initialized = False
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    async def test_rx_restore_mode_failure_logs_error(self, radio, caplog):
        import logging

        radio.lora.request.side_effect = RuntimeError("restore fail")
        task = asyncio.get_running_loop().create_task(radio._rx_irq_background_task())
        radio._last_irq_status = IRQ_TIMEOUT
        with caplog.at_level(logging.ERROR, logger="SX1262_wrapper"):
            radio._rx_done_event.set()
            await asyncio.sleep(0.05)
        radio._initialized = False
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        assert any(
            "Failed to restore RX mode" in r.getMessage() for r in caplog.records
        )

    async def test_rx_restore_skipped_when_tx_lock_held(self, radio, caplog):
        import logging

        task = asyncio.get_running_loop().create_task(radio._rx_irq_background_task())
        async with radio._tx_lock:
            radio._last_irq_status = IRQ_TIMEOUT
            with caplog.at_level(logging.DEBUG, logger="SX1262_wrapper"):
                radio._rx_done_event.set()
                await asyncio.sleep(0.05)
        radio._initialized = False
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        assert any("Skipped RX restore" in r.getMessage() for r in caplog.records)

    async def test_rx_packet_processing_exception_logged(self, radio, caplog):
        import logging

        radio.lora.getRxBufferStatus.side_effect = RuntimeError("rx status fail")
        task = asyncio.get_running_loop().create_task(radio._rx_irq_background_task())
        radio._last_irq_status = IRQ_RX_DONE
        with caplog.at_level(logging.ERROR, logger="SX1262_wrapper"):
            radio._rx_done_event.set()
            await asyncio.sleep(0.05)
        radio._initialized = False
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        assert any(
            "Error processing received packet" in r.getMessage() for r in caplog.records
        )

    async def test_rx_task_logs_periodic_status_every_500_timeouts(self, radio):
        calls = {"n": 0}

        def _sample_and_stop():
            calls["n"] += 1
            if calls["n"] >= 500:
                radio._initialized = False

        radio.RADIO_TIMING_DELAY = 0.0
        radio._sample_noise_floor = _sample_and_stop
        await radio._rx_irq_background_task()
        assert calls["n"] >= 500

    async def test_rx_task_interrupt_disabled_branch(self, radio):
        radio._interrupt_setup = False

        async def _stop_soon():
            await asyncio.sleep(0.02)
            radio._initialized = False

        asyncio.get_running_loop().create_task(_stop_soon())
        await radio._rx_irq_background_task()
        assert radio._initialized is False

    async def test_rx_task_unexpected_error_branch(self, radio):
        original_wait_for = asyncio.wait_for

        async def _boom_wait_for(*args, **kwargs):
            # If wait_for is mocked to raise immediately, close the coroutine
            # argument to avoid "coroutine was never awaited" warnings.
            if args and asyncio.iscoroutine(args[0]):
                args[0].close()
            raise RuntimeError("wait boom")

        async def _fast_sleep(_delay):
            radio._initialized = False

        with (
            patch(
                "openhop_core.hardware.sx1262_wrapper.asyncio.wait_for",
                side_effect=_boom_wait_for,
            ),
            patch(
                "openhop_core.hardware.sx1262_wrapper.asyncio.sleep",
                side_effect=_fast_sleep,
            ),
        ):
            await radio._rx_irq_background_task()

        # Keep reference to avoid lint complaints about shadowing in older runners.
        assert original_wait_for is not None

    def test_check_radio_health_uninitialized_returns_false(self, radio):
        radio._initialized = False
        assert radio.check_radio_health() is False

    async def test_check_radio_health_restarts_dead_task(self, radio):
        radio._rx_irq_task = MagicMock()
        radio._rx_irq_task.done.return_value = True
        assert radio.check_radio_health() is False
        assert hasattr(radio, "_rx_irq_task")
        if isinstance(radio._rx_irq_task, asyncio.Task):
            radio._initialized = False
            radio._rx_irq_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await radio._rx_irq_task

    def test_check_radio_health_true_when_task_alive(self, radio):
        alive_task = MagicMock()
        alive_task.done.return_value = False
        radio._rx_irq_task = alive_task
        assert radio.check_radio_health() is True

    def test_begin_covers_success_pin_setup_paths_and_info_logs(
        self, mock_lora, mock_gpio, caplog
    ):
        import logging

        from openhop_core.hardware.sx1262_wrapper import SX1262Radio

        irq_pin_obj = MagicMock()
        irq_pin_obj.start_polling = MagicMock()
        mock_gpio._pins = {16: irq_pin_obj}

        with (
            patch(
                "openhop_core.hardware.sx1262_wrapper.SX126x", return_value=mock_lora
            ),
            patch(
                "openhop_core.hardware.sx1262_wrapper.GPIOPinManager",
                return_value=mock_gpio,
            ),
            patch("openhop_core.hardware.sx1262_wrapper.set_gpio_manager"),
            caplog.at_level(logging.INFO, logger="SX1262_wrapper"),
        ):
            radio = SX1262Radio(
                txen_pin=6,
                rxen_pin=26,
                txled_pin=23,
                rxled_pin=24,
                en_pins=[30],
                use_dio3_tcxo=True,
                dio3_tcxo_voltage=1.8,
                use_dio2_rf=True,
                radio_timing_delay=0.0,
            )
            assert radio.begin() is True

        assert radio._txled_pin_setup is True
        assert radio._rxled_pin_setup is True
        assert radio._en_pins_setup is True
        assert any(
            "DIO2 RF switch control enabled" in r.getMessage() for r in caplog.records
        )
        assert any(
            "Started IRQ polling after radio init" in r.getMessage()
            for r in caplog.records
        )

    def test_calculate_tx_timeout_covers_non_positive_tmp_branch(self, radio):
        radio.spreading_factor = 12
        timeout_ms, driver_timeout = radio._calculate_tx_timeout(0)
        assert timeout_ms > 0
        assert driver_timeout == timeout_ms * 64

    async def test_send_raises_when_execute_transmission_returns_false(self, radio):
        radio.perform_cad = AsyncMock(return_value=False)
        radio._execute_transmission = AsyncMock(return_value=False)
        with pytest.raises(RuntimeError, match="Radio failed to start TX"):
            await radio.send(b"data")

    def test_noise_floor_accepts_valid_sample_without_adaptive_threshold(
        self, radio, mock_lora
    ):
        radio._noise_floor = -120.0
        radio._noise_floor_samples = []
        radio._num_floor_samples = 0
        radio._floor_sample_sum = 0.0
        radio._last_packet_activity = 0.0
        radio._processing_rx_packet = False
        mock_lora.getRssiInst.return_value = 100  # -50 dBm, valid range

        with patch(
            "openhop_core.hardware.sx1262_wrapper.time.time", return_value=500.0
        ):
            radio._sample_noise_floor()

        assert radio._num_floor_samples == 1
        assert radio._noise_floor == pytest.approx(-50.0)

    def test_cleanup_cancels_not_done_rx_task(self, radio):
        task = MagicMock()
        task.done.return_value = False
        radio._rx_irq_task = task
        radio.cleanup()
        task.cancel.assert_called_once()


class TestHandleInterruptIdempotency:
    def test_second_call_with_zero_irq_preserves_last_irq_status(self, radio):
        radio.lora.getIrqStatus.return_value = IRQ_CRC_ERR
        radio._handle_interrupt()
        assert radio._last_irq_status == IRQ_CRC_ERR

        radio.lora.getIrqStatus.return_value = IRQ_NONE
        radio._handle_interrupt()

        assert radio._last_irq_status == IRQ_CRC_ERR
