"""Radio reconfiguration must never stall the event loop.

``_tx_lock`` is an asyncio lock held for the whole of a TX. A reconfigure that
waited for it with a blocking sleep froze the loop, so the TX holding the lock
could never finish: every caller (CompanionRadio, the frame server, a repeater
web handler) stalled for the full timeout and the change was then dropped.
"""

import asyncio
import contextlib
import struct
import threading
import time
from unittest.mock import patch

import pytest

from openhop_core.companion import CompanionRadio
from openhop_core.companion.constants import CMD_SET_RADIO_PARAMS, RESP_CODE_OK
from openhop_core.companion.frame_server import CompanionFrameServer
from openhop_core.hardware.sx1262_wrapper import SX1262Radio
from openhop_core.protocol import LocalIdentity

from .test_sx1262_wrapper_concurrency import _make_mock_gpio, _make_mock_lora


@pytest.fixture(autouse=True)
def _reset_singleton():
    SX1262Radio._active_instance = None
    SX1262Radio._active_instances = set()
    yield
    SX1262Radio._active_instance = None
    SX1262Radio._active_instances = set()


def _build_radio(**kwargs) -> SX1262Radio:
    mock_gpio = _make_mock_gpio()
    params = {"radio_timing_delay": 0.0, "frequency": 915000000, "bandwidth": 250000, **kwargs}
    with (
        patch("openhop_core.hardware.sx1262_wrapper.GPIOPinManager", return_value=mock_gpio),
        patch("openhop_core.hardware.sx1262_wrapper.set_gpio_manager"),
    ):
        r = SX1262Radio(**params)
    r.lora = _make_mock_lora()
    r._initialized = True
    r._interrupt_setup = True
    r._gpio_manager = mock_gpio
    return r


@pytest.fixture
async def radio():
    r = _build_radio()
    r._event_loop = asyncio.get_running_loop()
    yield r


async def _ticks_during(awaitable, seconds: float) -> tuple:
    """How many 10 ms ticks another task gets while ``awaitable`` runs."""
    ticks = 0
    stop = asyncio.Event()

    async def ticker():
        nonlocal ticks
        while not stop.is_set():
            await asyncio.sleep(0.01)
            ticks += 1

    task = asyncio.create_task(ticker())
    try:
        return_value = await asyncio.wait_for(awaitable, timeout=seconds)
    finally:
        stop.set()
        await task
    return ticks, return_value


def _retuned_to(radio: SX1262Radio) -> list[int]:
    return [c.args[0] for c in radio.lora.setFrequency.call_args_list]


# ─── configure_radio_async ─────────────────────────────────────────────


async def test_async_reconfigure_waits_for_the_tx_without_blocking_the_loop(radio):
    await radio._tx_lock.acquire()  # a TX in flight
    task = asyncio.create_task(radio.configure_radio_async(frequency=869618000))

    ticks, _ = await _ticks_during(asyncio.sleep(0.1), 1.0)
    assert ticks >= 3  # the loop kept running
    assert _retuned_to(radio) == []  # not while the TX holds the radio

    radio._tx_lock.release()
    assert await task is True
    assert _retuned_to(radio) == [869618000]
    assert radio.frequency == 869618000


async def test_async_reconfigure_holds_the_tx_lock_while_it_retunes(radio):
    held = []
    radio.lora.setFrequency.side_effect = lambda f: held.append(radio._tx_lock.locked())
    assert await radio.configure_radio_async(frequency=869618000) is True
    assert held == [True]
    assert radio._tx_lock.locked() is False


async def test_async_reconfigure_gives_up_on_a_tx_that_never_ends(radio):
    radio.CONFIGURE_TX_WAIT_SECONDS = 0.1
    await radio._tx_lock.acquire()
    try:
        assert await radio.configure_radio_async(frequency=869618000) is False
    finally:
        radio._tx_lock.release()
    assert _retuned_to(radio) == []
    assert radio._tx_lock.locked() is False


async def test_omitted_params_keep_their_values(radio):
    assert await radio.configure_radio_async(spreading_factor=9) is True
    assert radio.frequency == 915000000
    assert radio.spreading_factor == 9


async def test_uninitialised_radio_is_refused(radio):
    radio._initialized = False
    assert await radio.configure_radio_async(frequency=869618000) is False
    assert radio.configure_radio(frequency=869618000) is False


# ─── configure_radio (sync) ────────────────────────────────────────────


async def test_sync_on_the_loop_with_the_radio_idle_applies_at_once(radio):
    assert radio.configure_radio(frequency=869618000) is True
    assert _retuned_to(radio) == [869618000]


async def test_sync_on_the_loop_during_a_tx_queues_instead_of_blocking(radio):
    await radio._tx_lock.acquire()
    started = time.monotonic()
    assert radio.configure_radio(frequency=869618000) is True
    assert time.monotonic() - started < 0.1  # returned immediately
    assert _retuned_to(radio) == []

    radio._tx_lock.release()
    await radio._pending_configure
    assert _retuned_to(radio) == [869618000]


async def test_a_newer_reconfigure_supersedes_one_still_waiting(radio):
    await radio._tx_lock.acquire()
    radio.configure_radio(frequency=868000000)
    first = radio._pending_configure
    radio.configure_radio(frequency=869618000)
    radio._tx_lock.release()
    await radio._pending_configure
    assert first.cancelled()
    assert _retuned_to(radio) == [869618000]


async def test_applying_at_once_cancels_a_stale_queued_reconfigure(radio):
    await radio._tx_lock.acquire()
    radio.configure_radio(frequency=868000000)
    stale = radio._pending_configure
    radio._tx_lock.release()
    radio.configure_radio(frequency=869618000)  # idle now: applies at once
    await asyncio.sleep(0)
    assert stale.cancelled()
    assert _retuned_to(radio) == [869618000]


async def test_sync_from_another_thread_runs_on_the_radio_loop(radio):
    """A repeater web handler calls configure_radio from a worker thread: the
    retune must run on the radio's loop, after the TX, with the caller waiting
    for the real result."""
    loop_thread = threading.get_ident()
    threads = []
    radio.lora.setFrequency.side_effect = lambda f: threads.append(threading.get_ident())
    await radio._tx_lock.acquire()

    worker = asyncio.get_running_loop().run_in_executor(
        None, lambda: radio.configure_radio(frequency=869618000)
    )
    ticks, _ = await _ticks_during(asyncio.sleep(0.1), 1.0)
    assert ticks >= 3
    assert not worker.done()  # waiting for the TX, not given up

    radio._tx_lock.release()
    assert await worker is True
    assert threads == [loop_thread]


def test_sync_with_no_loop_anywhere_applies_directly():
    radio = _build_radio()
    assert radio.configure_radio(frequency=869618000) is True
    assert _retuned_to(radio) == [869618000]


async def test_cleanup_cancels_a_queued_reconfigure(radio):
    await radio._tx_lock.acquire()
    radio.configure_radio(frequency=869618000)
    pending = radio.pending_configure
    radio.cleanup()
    await asyncio.sleep(0)
    assert pending.cancelled()
    radio._tx_lock.release()
    radio.lora.end.assert_called_once()


def test_cleanup_survives_a_queued_reconfigure_whose_loop_is_closed():
    """The repeater runs cleanup() on a worker thread after its loop stops: the
    queued retune can no longer be cancelled, but the hardware must still be
    released."""
    radio = _build_radio()
    loop = asyncio.new_event_loop()
    try:

        async def queue_one():
            radio._event_loop = asyncio.get_running_loop()
            await radio._tx_lock.acquire()
            radio.configure_radio(frequency=869618000)

        loop.run_until_complete(queue_one())
    finally:
        loop.close()
    pending = radio.pending_configure
    assert pending is not None

    radio.cleanup()  # must not raise

    radio.lora.end.assert_called_once()
    assert pending.get_coro().cr_frame is None  # closed, not left unawaited


async def test_a_failed_queued_reconfigure_is_logged_and_cleared(radio, caplog):
    radio.CONFIGURE_TX_WAIT_SECONDS = 0.05
    await radio._tx_lock.acquire()
    assert radio.configure_radio(frequency=869618000) is True
    pending = radio.pending_configure
    await asyncio.sleep(0.2)
    radio._tx_lock.release()

    assert pending.done()
    assert radio.pending_configure is None
    assert "Queued radio reconfigure was not applied" in caplog.text
    assert _retuned_to(radio) == []


async def test_a_coroutine_on_another_loop_is_marshalled_to_the_radio_loop():
    """Only the radio's own loop may retune without the TX lock. A coroutine on
    a different loop must go through the radio's loop like a worker thread."""
    radio = _build_radio()
    radio_loop = asyncio.new_event_loop()
    ready = threading.Event()
    radio_thread = threading.Thread(
        target=lambda: (asyncio.set_event_loop(radio_loop), ready.set(), radio_loop.run_forever()),
        daemon=True,
    )
    radio_thread.start()
    ready.wait()
    radio._event_loop = radio_loop
    threads = []
    radio.lora.setFrequency.side_effect = lambda f: threads.append(threading.get_ident())
    try:
        result = await asyncio.get_running_loop().run_in_executor(
            None, lambda: asyncio.run(_configure_from_a_foreign_loop(radio))
        )
    finally:
        radio_loop.call_soon_threadsafe(radio_loop.stop)
        radio_thread.join()
        radio_loop.close()
    assert result is True
    assert threads == [radio_thread.ident]


async def _configure_from_a_foreign_loop(radio):
    return radio.configure_radio(frequency=869618000)


def test_a_loop_that_closes_under_the_call_is_reported_not_raised():
    radio = _build_radio()
    closed = asyncio.new_event_loop()
    closed.close()
    radio._event_loop = closed
    with patch.object(type(closed), "is_running", return_value=True):
        assert radio.configure_radio(frequency=869618000) is False


# ─── callers ───────────────────────────────────────────────────────────


async def test_companion_reboot_during_a_tx_does_not_stall_and_still_retunes(radio):
    comp = CompanionRadio(radio, LocalIdentity())
    comp.cli.handle("set radio 869.618,62.5,8,5")
    await radio._tx_lock.acquire()

    started = time.monotonic()
    comp.cli.handle("reboot")
    assert time.monotonic() - started < 0.1

    radio._tx_lock.release()
    await radio._pending_configure
    assert (radio.frequency, radio.bandwidth, radio.spreading_factor, radio.coding_rate) == (
        869618000,
        62500,
        8,
        5,
    )


async def test_frame_set_radio_params_waits_for_the_tx_and_reports_the_result(radio):
    comp = CompanionRadio(radio, LocalIdentity())
    server = CompanionFrameServer(comp, "hash", port=0)
    frames = []
    server._write_frame = frames.append
    await radio._tx_lock.acquire()

    handling = asyncio.create_task(
        server._handle_cmd(
            bytes([CMD_SET_RADIO_PARAMS]) + struct.pack("<IIBB", 869618, 62500, 8, 5)
        )
    )
    ticks, _ = await _ticks_during(asyncio.sleep(0.1), 1.0)
    assert ticks >= 3
    assert frames == []  # no OK until the radio has actually retuned

    radio._tx_lock.release()
    await handling
    assert frames == [bytes([RESP_CODE_OK])]
    assert radio.frequency == 869618000
    assert comp.get_self_info().frequency_hz == 869618000


async def test_frame_set_radio_params_reports_failure_when_the_tx_never_ends(radio):
    radio.CONFIGURE_TX_WAIT_SECONDS = 0.1
    comp = CompanionRadio(radio, LocalIdentity())
    server = CompanionFrameServer(comp, "hash", port=0)
    frames = []
    server._write_frame = frames.append
    await radio._tx_lock.acquire()
    try:
        await server._handle_cmd(
            bytes([CMD_SET_RADIO_PARAMS]) + struct.pack("<IIBB", 869618, 62500, 8, 5)
        )
    finally:
        radio._tx_lock.release()
    assert frames[0][0] != RESP_CODE_OK
    assert comp.get_self_info().frequency_hz == 915000000  # not persisted


async def test_companion_retries_params_whose_queued_retune_failed(radio):
    """A queued retune that fails must not leave CompanionRadio believing the
    new params are live, or the next start/reboot would never retry them."""
    radio.CONFIGURE_TX_WAIT_SECONDS = 0.05
    comp = CompanionRadio(radio, LocalIdentity())
    await radio._tx_lock.acquire()
    assert comp.set_radio_params(869618000, 62500, 8, 5) is True  # queued
    await asyncio.sleep(0.2)  # the TX outlives the wait: the retune fails
    radio._tx_lock.release()
    assert _retuned_to(radio) == []
    assert comp.get_self_info().frequency_hz == 869618000  # still the wanted value

    comp._apply_staged_radio_params()  # e.g. the next reboot

    assert _retuned_to(radio) == [869618000]


async def test_a_reboot_retune_that_failed_is_retried_on_the_next_reboot(radio):
    radio.CONFIGURE_TX_WAIT_SECONDS = 0.05
    comp = CompanionRadio(radio, LocalIdentity())
    comp.cli.handle("set radio 869.618,62.5,8,5")
    await radio._tx_lock.acquire()
    comp.cli.handle("reboot")  # queued behind the TX, which outlives the wait
    await asyncio.sleep(0.2)
    radio._tx_lock.release()
    assert _retuned_to(radio) == []

    comp.cli.handle("reboot")

    assert _retuned_to(radio) == [869618000]


async def test_an_awaited_reconfigure_supersedes_a_queued_one(radio):
    """The frame command awaits configure_radio_async; a retune queued earlier
    by a sync caller must not land after it and undo it."""
    await radio._tx_lock.acquire()
    radio.configure_radio(frequency=868000000)  # queued behind the TX
    queued = radio.pending_configure
    newer = asyncio.create_task(radio.configure_radio_async(frequency=869618000))
    await asyncio.sleep(0)
    radio._tx_lock.release()

    assert await newer is True
    with contextlib.suppress(asyncio.CancelledError):
        await queued  # however late the cancel lands (Python < 3.12's wait_for)
    assert queued.cancelled()
    assert _retuned_to(radio) == [869618000]
    assert radio.frequency == 869618000


async def test_a_failed_superseding_retune_leaves_the_last_confirmed_params_live(radio):
    """915 running; 868 queued, superseded by 869, and the TX outlasts the wait.
    Neither was applied, so neither may count as live: staging 868 and
    rebooting must still retune."""
    radio.CONFIGURE_TX_WAIT_SECONDS = 0.05
    comp = CompanionRadio(radio, LocalIdentity())
    await radio._tx_lock.acquire()
    comp.set_radio_params(868000000, 250000, 7, 5)
    comp.set_radio_params(869000000, 250000, 7, 5)
    await asyncio.sleep(0.2)
    radio._tx_lock.release()
    assert _retuned_to(radio) == []
    assert comp._running_radio_params()["frequency_hz"] == 915000000

    comp.cli.handle("set radio 868.0,250,7,5")
    comp.cli.handle("reboot")

    assert _retuned_to(radio) == [868000000]


async def test_rebooting_back_to_the_live_params_cancels_a_queued_retune():
    """915 live, 868 queued behind a TX, then the stored params go back to 915
    and the companion reboots before the TX ends: 868 must not land later."""
    radio = _build_radio(spreading_factor=10, coding_rate=5)
    radio._event_loop = asyncio.get_running_loop()
    comp = CompanionRadio(radio, LocalIdentity())
    await radio._tx_lock.acquire()
    radio.configure_radio(frequency=868000000)  # queued
    queued = radio.pending_configure

    comp.cli.handle("set radio 915.0,250,10,5")  # what the radio already runs
    comp.cli.handle("reboot")
    radio._tx_lock.release()
    await asyncio.sleep(0.05)

    assert queued.cancelled()
    assert radio.frequency == 915000000
    assert 868000000 not in _retuned_to(radio)


async def test_live_params_follow_the_radio_not_the_order_retunes_complete(radio):
    """A queued 868 finishes, then a newer 869 is applied. Staging 868 and
    rebooting must retune: the radio is on 869, whatever finished first."""
    comp = CompanionRadio(radio, LocalIdentity())
    await radio._tx_lock.acquire()
    comp.set_radio_params(868000000, 250000, 7, 5)  # queued
    radio._tx_lock.release()
    await radio.pending_configure
    comp.set_radio_params(869000000, 250000, 7, 5)  # idle: applied at once
    assert radio.frequency == 869000000

    comp.cli.handle("set radio 868.0,250,7,5")
    comp.cli.handle("reboot")

    assert radio.frequency == 868000000


def test_a_companion_without_radio_config_reports_and_keeps_the_radios_params():
    """Built from the radio's own kwargs (radio_config omitted), the companion
    must report the radio's real params and start() must not retune it."""
    radio = _build_radio()
    comp = CompanionRadio(radio, LocalIdentity())
    prefs = comp.get_self_info()
    assert (prefs.frequency_hz, prefs.bandwidth_hz) == (915000000, 250000)
    assert (prefs.spreading_factor, prefs.coding_rate) == (
        radio.spreading_factor,
        radio.coding_rate,
    )

    comp._apply_staged_radio_params()

    assert _retuned_to(radio) == []


async def test_a_half_applied_retune_is_retried_on_the_next_reboot(radio):
    """If re-arming RX fails after the chip took the new params, the radio must
    not report them as running, or the next reboot would skip the retry."""
    comp = CompanionRadio(radio, LocalIdentity())
    comp.cli.handle("set radio 868.0,250,7,5")
    radio.lora.request.side_effect = RuntimeError("SPI error")
    comp.cli.handle("reboot")
    assert radio.frequency == 915000000  # not applied as far as anyone can tell

    radio.lora.request.side_effect = None
    comp.cli.handle("reboot")

    assert radio.frequency == 868000000
    assert _retuned_to(radio) == [868000000, 868000000]
