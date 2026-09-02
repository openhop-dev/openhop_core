"""Tests for the SX1262 Listen-Before-Talk path.

Two properties are under test:

* LBT is bounded in TIME, not in attempts: short jittered retries run for the
  whole budget, so an occupation longer than it cannot leave two co-located
  repeaters forcing their TX together (MeshCore parity: 200 ms retry, time
  cap);
* a reception in progress defers TX without being aborted. Each check
  consults a passive software latch (is_receiving_packet, fed by the
  preamble / sync word / header IRQs) BEFORE any standby/CAD, and the radio
  is staged for TX only once the channel is deemed clear.
"""

import asyncio
import time
from unittest.mock import AsyncMock, patch

import pytest

from openhop_core.hardware.sx1262_wrapper import SX1262Radio

from .test_sx1262_wrapper_concurrency import (
    IRQ_HEADER_VALID,
    IRQ_PREAMBLE_DETECTED,
    IRQ_RX_DONE,
    _make_mock_gpio,
    _make_mock_lora,
)


@pytest.fixture(autouse=True)
def _reset_singleton():
    SX1262Radio._active_instance = None
    SX1262Radio._active_instances = set()
    yield
    SX1262Radio._active_instance = None
    SX1262Radio._active_instances = set()


@pytest.fixture
async def radio():
    """SX1262Radio with all hardware mocked, fast LBT timings for tests."""
    mock_gpio = _make_mock_gpio()
    with (
        patch(
            "openhop_core.hardware.sx1262_wrapper.GPIOPinManager",
            return_value=mock_gpio,
        ),
        patch("openhop_core.hardware.sx1262_wrapper.set_gpio_manager"),
    ):
        r = SX1262Radio(
            radio_timing_delay=0.0,
            lbt_max_wait_seconds=0.5,
            lbt_retry_interval_ms=20,
        )

    r.lora = _make_mock_lora()
    r._initialized = True
    r._interrupt_setup = True
    r._gpio_manager = mock_gpio
    r._event_loop = asyncio.get_running_loop()
    yield r


def _inject_irq(radio, irq_flags: int) -> None:
    radio.lora.getIrqStatus.return_value = irq_flags
    radio._last_irq_status = irq_flags
    radio._handle_interrupt()


# ─── is_receiving_packet: software latch lifecycle ───────────────────


async def test_preamble_irq_latches_reception_in_progress(radio):
    assert radio.is_receiving_packet() is False

    _inject_irq(radio, IRQ_PREAMBLE_DETECTED)

    assert radio.is_receiving_packet() is True


async def test_header_valid_irq_latches_too(radio):
    _inject_irq(radio, IRQ_HEADER_VALID)

    assert radio.is_receiving_packet() is True
    assert radio._rx_header_at > 0


async def test_terminal_irq_clears_the_latch(radio):
    _inject_irq(radio, IRQ_PREAMBLE_DETECTED)
    assert radio.is_receiving_packet() is True

    _inject_irq(radio, IRQ_RX_DONE)

    assert radio.is_receiving_packet() is False
    assert radio._rx_activity_at == 0.0


async def test_stale_latch_expires_instead_of_wedging_tx(radio):
    """A lost terminal IRQ must not report "receiving" forever: the latch
    expires after a worst-case packet airtime (MeshCore bounds its equivalent
    the same way)."""
    radio._rx_activity_at = time.monotonic() - (radio._max_reception_seconds() + 1.0)

    assert radio.is_receiving_packet() is False
    assert radio._rx_activity_at == 0.0  # expired latch is cleared


async def test_max_reception_seconds_tracks_radio_params(radio):
    """Slower params → longer worst-case packet → longer expiry bound."""
    fast = radio._max_reception_seconds()
    radio.spreading_factor = 11
    radio.bandwidth = 62500
    slow = radio._max_reception_seconds()

    assert slow > fast


# ─── two-stage expiry: preamble-only vs header-seen ───────────────────


async def test_max_preamble_seconds_is_much_shorter_than_max_reception(radio):
    """A preamble that never reaches a header should time out fast, not wait
    out a full packet's worth of airtime."""
    assert radio._max_preamble_seconds() < radio._max_reception_seconds() / 4


async def test_preamble_only_latch_expires_on_the_short_bound(radio):
    """No header ever arrived: expiry uses _max_preamble_seconds(), not the
    much longer _max_reception_seconds() — a false preamble trigger (noise)
    must not defer TX for a full packet's worth of time."""
    _inject_irq(radio, IRQ_PREAMBLE_DETECTED)
    radio._rx_activity_at = time.monotonic() - (radio._max_preamble_seconds() + 0.01)

    assert radio.is_receiving_packet() is False
    assert radio._rx_activity_at == 0.0


async def test_header_valid_restarts_the_clock(radio):
    """A preamble latch about to expire must not expire once a header
    arrives: the clock restarts and the longer bound applies from here."""
    _inject_irq(radio, IRQ_PREAMBLE_DETECTED)
    radio._rx_activity_at = time.monotonic() - (radio._max_preamble_seconds() - 0.005)

    _inject_irq(radio, IRQ_HEADER_VALID)

    assert radio.is_receiving_packet() is True
    assert time.monotonic() - radio._rx_activity_at < 0.005


# ─── LBT: passive check first, no standby/CAD during a reception ─────


async def test_lbt_defers_to_in_progress_reception_without_cad(radio):
    """While a reception is latched, the LBT loop must wait on the passive
    check alone: running CAD would drop to standby and abort the reception it
    is probing for. The CAD scan happens only once the latch clears."""
    radio._max_preamble_seconds = lambda: 10.0  # keep expiry out of the picture
    _inject_irq(radio, IRQ_PREAMBLE_DETECTED)
    radio.perform_cad = AsyncMock(return_value=False)
    radio._restore_rx_for_cad_backoff = AsyncMock()

    async def _finish_reception():
        await asyncio.sleep(0.05)
        _inject_irq(radio, IRQ_RX_DONE)

    finisher = asyncio.create_task(_finish_reception())
    success, delays = await radio._prepare_radio_for_tx()
    await finisher

    assert success is True
    assert len(delays) >= 1  # waited at least one retry interval
    # No CAD (hence no standby) while the reception was in progress: the
    # single scan ran after the terminal IRQ cleared the latch.
    assert radio.perform_cad.await_count == 1


async def test_lbt_does_not_touch_the_radio_while_a_reception_is_latched(radio):
    """Deferring on the passive latch must leave the radio alone.

    Re-arming RX between retries clears the IRQ flags and drops to standby,
    which aborts the reception the latch is protecting — and with no terminal
    IRQ left to clear it, the latch would then block TX until it goes stale.
    Only a CAD scan leaves standby behind, so only a scan needs the re-arm.
    """
    radio._max_preamble_seconds = lambda: 10.0  # keep expiry out of the picture
    _inject_irq(radio, IRQ_PREAMBLE_DETECTED)
    radio.perform_cad = AsyncMock(return_value=False)
    radio._restore_rx_for_cad_backoff = AsyncMock()

    async def _finish_reception():
        await asyncio.sleep(0.05)
        _inject_irq(radio, IRQ_RX_DONE)

    finisher = asyncio.create_task(_finish_reception())
    success, delays = await radio._prepare_radio_for_tx()
    await finisher

    assert success is True
    assert delays  # at least one deferral happened on the latch alone
    radio._restore_rx_for_cad_backoff.assert_not_awaited()
    # The only standby is the post-LBT TX staging: none during the deferral.
    assert radio.lora.setStandby.call_count == 1


async def test_lbt_standby_only_after_channel_clear(radio):
    """The staging standby must happen only once the channel is deemed
    clear, never before the first channel check."""
    radio.perform_cad = AsyncMock(return_value=False)

    await radio._prepare_radio_for_tx()

    # perform_cad is mocked (no internal standby) and no busy wait occurred,
    # so every setStandby call is the post-LBT TX staging.
    assert radio.lora.setStandby.called
    assert radio.perform_cad.await_count == 1


# ─── LBT: time budget, not attempt count ─────────────────────────────


async def test_lbt_budget_is_time_bounded_with_short_retries(radio):
    """A busy channel is re-checked on short jittered intervals for the
    whole TIME budget, however long the occupation lasts."""
    radio.perform_cad = AsyncMock(return_value=True)
    radio._restore_rx_for_cad_backoff = AsyncMock()

    started = time.monotonic()
    success, delays = await radio._prepare_radio_for_tx()
    elapsed = time.monotonic() - started

    assert success is True  # forced TX at budget exhaustion, loudly logged
    # Many checks across the window; the exact count is timing-dependent.
    assert radio.perform_cad.await_count > 5
    # The loop honored the budget: it neither gave up early nor overshot much.
    assert 0.4 <= elapsed <= 2.0
    assert sum(delays) <= radio.lbt_max_wait_seconds * 1000.0 + 100.0
    # Every retry is short and jittered around lbt_retry_interval_ms.
    assert all(10.0 <= d <= radio.lbt_retry_interval_ms * 1.5 for d in delays)


async def test_lbt_clear_channel_transmits_without_waiting(radio):
    radio.perform_cad = AsyncMock(return_value=False)

    success, delays = await radio._prepare_radio_for_tx()

    assert success is True
    assert delays == []


# ─── TX commit clears the reception latch ────────────────────────────


async def test_forced_tx_clears_the_reception_latch(radio):
    """Transmitting kills the reception the latch is tracking, so its
    terminal IRQ never arrives. The TX commit must clear the markers itself:
    left armed, they would make the next send defer on a reception that no
    longer exists — without a single CAD — until the staleness bound expired.
    """
    radio._max_reception_seconds = lambda: 10.0  # keep expiry out of the picture
    _inject_irq(radio, IRQ_PREAMBLE_DETECTED)  # a reception that never finishes
    radio.perform_cad = AsyncMock(return_value=False)

    success, delays = await radio._prepare_radio_for_tx()  # deadline -> forced TX

    assert success is True
    assert delays  # it did defer on the latch until the budget ran out
    assert radio._rx_activity_at == 0.0 and radio._rx_header_at == 0.0
    assert radio.is_receiving_packet() is False


async def test_send_after_forced_tx_probes_the_channel_again(radio):
    """The send following a forced TX must sense the channel, not sit out a
    ghost of the reception that TX destroyed."""
    radio._max_reception_seconds = lambda: 10.0
    _inject_irq(radio, IRQ_PREAMBLE_DETECTED)
    radio.perform_cad = AsyncMock(return_value=False)
    await radio._prepare_radio_for_tx()  # forced TX; must clear the latch

    radio.perform_cad.reset_mock()
    success, delays = await radio._prepare_radio_for_tx()

    assert success is True
    assert delays == []  # no ghost deferral
    assert radio.perform_cad.await_count == 1  # the channel was actually probed


# ─── LBT/CAD decision logging ─────────────────────────────────────────


async def test_lbt_summary_reports_cad_clear(radio, caplog):
    radio.perform_cad = AsyncMock(return_value=False)

    with caplog.at_level("DEBUG", logger="SX1262_wrapper"):
        await radio._prepare_radio_for_tx()

    (summary,) = [r.message for r in caplog.records if "[LBT] Summary:" in r.message]
    assert "outcome=clear" in summary
    assert "latch_defers=0" in summary
    assert "cad_checks=1" in summary


async def test_lbt_summary_counts_latch_defers_separately_from_cad(radio, caplog):
    radio._max_preamble_seconds = lambda: 10.0  # keep expiry out of the picture
    _inject_irq(radio, IRQ_PREAMBLE_DETECTED)
    radio.perform_cad = AsyncMock(return_value=False)
    radio._restore_rx_for_cad_backoff = AsyncMock()

    async def _finish_reception():
        await asyncio.sleep(0.05)
        _inject_irq(radio, IRQ_RX_DONE)

    finisher = asyncio.create_task(_finish_reception())
    with caplog.at_level("DEBUG", logger="SX1262_wrapper"):
        await radio._prepare_radio_for_tx()
    await finisher

    (summary,) = [r.message for r in caplog.records if "[LBT] Summary:" in r.message]
    assert "latch_defers=0" not in summary  # the reception was polled at least once
    assert "cad_checks=1" in summary  # the single scan after the latch cleared


# ─── Constructor knobs ───────────────────────────────────────────────


async def test_lbt_knob_clamps():
    mock_gpio = _make_mock_gpio()
    with (
        patch(
            "openhop_core.hardware.sx1262_wrapper.GPIOPinManager",
            return_value=mock_gpio,
        ),
        patch("openhop_core.hardware.sx1262_wrapper.set_gpio_manager"),
    ):
        r = SX1262Radio(
            radio_timing_delay=0.0,
            lbt_max_wait_seconds=0.0,
            lbt_retry_interval_ms=5,
        )

    assert r.lbt_max_wait_seconds == 0.5
    assert r.lbt_retry_interval_ms == 20


async def test_lbt_defaults():
    mock_gpio = _make_mock_gpio()
    with (
        patch(
            "openhop_core.hardware.sx1262_wrapper.GPIOPinManager",
            return_value=mock_gpio,
        ),
        patch("openhop_core.hardware.sx1262_wrapper.set_gpio_manager"),
    ):
        r = SX1262Radio(radio_timing_delay=0.0)

    # Matches MeshCore: getCADFailMaxDuration() 4 s, 200 ms retry.
    assert r.lbt_max_wait_seconds == 4.0
    assert r.lbt_retry_interval_ms == 200
