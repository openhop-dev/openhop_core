"""TX airtime duty-cycle budget in the Core dispatcher (client-repeat only).

Reproduces MeshCore Dispatcher.cpp budget mechanics: a leaky bucket that
refills at duty_cycle = 1/(1+airtime_factor) over a 1-hour window, is spent on
each transmit's estimated airtime, gates sends below est_airtime(255)/2, and
DELAYS (never drops) when short. The bucket is consulted only while
client-repeat is enabled; when disabled the send path is untouched.
"""

import asyncio
import time

import pytest

from openhop_core.node import dispatcher as disp_mod
from openhop_core.node.dispatcher import DUTY_CYCLE_WINDOW_MS, MIN_TX_BUDGET_RESERVE_MS, Dispatcher
from openhop_core.protocol import Packet
from openhop_core.protocol.constants import PAYLOAD_TYPE_TXT_MSG, ROUTE_TYPE_FLOOD

SELF_KEY = b"0123456789abcdef0123456789abcdef"


class Radio:
    def __init__(self):
        self.rx_callback = None
        self.send_count = 0
        self.tx_data = None

    def set_rx_callback(self, cb):
        self.rx_callback = cb

    async def send(self, data):
        self.send_count += 1
        self.tx_data = data
        return {"ok": 1}

    def get_last_rssi(self):
        return -70

    def get_last_snr(self):
        return 8.0


class Identity:
    def get_public_key(self):
        return SELF_KEY


class Clock:
    """Virtual monotonic clock; its sleep advances time instead of blocking."""

    def __init__(self, start=1000.0):
        self.t = start
        self.slept = []

    def monotonic(self):
        return self.t

    async def sleep(self, secs):
        self.slept.append(secs)
        if secs > 0:
            self.t += secs


def _make(factor=1.0, enabled=True):
    d = Dispatcher(Radio(), dedupe_enabled=True)
    d.local_identity = Identity()
    d.airtime_budget_factor = factor
    if enabled:
        d.set_client_repeat_enabled(True)
    return d, d.radio


def _flood_txt():
    p = Packet()
    p.header = (PAYLOAD_TYPE_TXT_MSG << 2) | ROUTE_TYPE_FLOOD
    p.payload = bytearray([0x77, 0x99]) + bytearray(b"\xAA" * 12)
    p.payload_len = len(p.payload)
    return p


@pytest.fixture
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(disp_mod.time, "monotonic", c.monotonic)
    return c


# --------------------------------------------------------------------------- #
# Budget arithmetic (independently computed firmware values)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "factor,duty",
    [(0.0, 1.0), (1.0, 0.5), (3.0, 0.25), (9.0, 0.1)],
)
def test_duty_cycle_from_airtime_factor(factor, duty):
    d, _ = _make(factor=factor, enabled=False)
    assert d._duty_cycle() == pytest.approx(duty)


def test_reset_starts_full(clock):
    # Dispatcher::begin: tx_budget_ms = window * duty_cycle. factor 1.0 -> 50%.
    d, _ = _make(factor=1.0)
    assert d._tx_budget_ms == pytest.approx(DUTY_CYCLE_WINDOW_MS * 0.5)  # 1_800_000


def test_refill_accrues_at_duty_and_caps(clock):
    d, _ = _make(factor=1.0)  # duty 0.5, max 1_800_000
    d._tx_budget_ms = 0.0
    d._tx_budget_last_update = clock.t
    # Advance 1000 s: refill = elapsed_ms * duty = 1_000_000 * 0.5 = 500_000.
    clock.t += 1000.0
    d._refill_tx_budget(clock.t)
    assert d._tx_budget_ms == pytest.approx(500_000.0)
    # Advance far beyond the window: budget caps at window * duty.
    clock.t += 100_000.0
    d._refill_tx_budget(clock.t)
    assert d._tx_budget_ms == pytest.approx(DUTY_CYCLE_WINDOW_MS * 0.5)


def test_debit_uses_actual_airtime(clock):
    d, _ = _make(factor=1.0)
    d._tx_est_airtime_ms = lambda n: 123.0  # controlled per-packet airtime
    d._tx_budget_ms = 1000.0
    d._tx_budget_last_update = clock.t  # no refill (elapsed 0)
    d._debit_tx_budget(_flood_txt())
    assert d._tx_budget_ms == pytest.approx(877.0)  # 1000 - 123


def test_debit_clamps_at_zero_and_sets_pacing(clock):
    d, _ = _make(factor=1.0)
    d._tx_est_airtime_ms = lambda n: 500.0
    d._tx_budget_ms = 200.0  # less than the airtime to spend
    d._tx_budget_last_update = clock.t
    d._debit_tx_budget(_flood_txt())
    assert d._tx_budget_ms == 0.0
    # budget < MIN_TX_BUDGET_RESERVE_MS -> next_tx_time = now + needed/duty.
    needed = MIN_TX_BUDGET_RESERVE_MS - 0.0
    assert d._tx_next_time == pytest.approx(clock.t + (needed / 0.5) / 1000.0)


# --------------------------------------------------------------------------- #
# TX gate: delay-not-drop, boundary
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_gate_no_wait_when_budget_at_reserve(clock, monkeypatch):
    monkeypatch.setattr(disp_mod.asyncio, "sleep", clock.sleep)
    d, _ = _make(factor=1.0)
    d._tx_est_airtime_ms = lambda n: 200.0  # reserve = 200/2 = 100
    d._tx_budget_ms = 100.0  # exactly at reserve -> not below -> no wait
    d._tx_next_time = clock.t
    await d._await_tx_budget(_flood_txt())
    assert clock.slept == []  # returned immediately


@pytest.mark.asyncio
async def test_gate_waits_computed_amount_when_short(clock, monkeypatch):
    monkeypatch.setattr(disp_mod.asyncio, "sleep", clock.sleep)
    d, _ = _make(factor=1.0)  # duty 0.5
    d._tx_est_airtime_ms = lambda n: 200.0  # reserve = 100
    d._tx_budget_ms = 60.0  # 40 ms short of reserve
    d._tx_next_time = clock.t
    await d._await_tx_budget(_flood_txt())
    # needed 40 ms / duty 0.5 = 80 ms = 0.08 s; after that refill reaches reserve.
    assert clock.slept == [pytest.approx(0.08)]
    assert d._tx_budget_ms == pytest.approx(100.0)


@pytest.mark.asyncio
async def test_burst_delayed_not_dropped(clock, monkeypatch):
    monkeypatch.setattr(disp_mod.asyncio, "sleep", clock.sleep)
    d, radio = _make(factor=1.0)
    d._tx_est_airtime_ms = lambda n: 200.0  # reserve 100, spend 200 each
    d._tx_budget_ms = 300.0  # only enough for the first without waiting
    d._tx_next_time = clock.t
    for _ in range(4):
        assert await d.send_packet(_flood_txt(), wait_for_ack=False) is True
    # All four eventually transmit (never dropped); the short budget forced waits.
    assert radio.send_count == 4
    assert len(clock.slept) >= 1
    assert sum(s for s in clock.slept if s > 0) > 0


# --------------------------------------------------------------------------- #
# Repeat-off: send path untouched
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_repeat_off_send_does_not_gate_or_debit(monkeypatch):
    d, radio = _make(enabled=False)
    called = {"await": 0, "debit": 0}

    async def _spy_await(pkt):
        called["await"] += 1

    # Budget entry points are the only send-path callers of time.monotonic;
    # proving they are not entered proves the hot path adds no time syscalls.
    monkeypatch.setattr(d, "_await_tx_budget", _spy_await)
    monkeypatch.setattr(d, "_debit_tx_budget", lambda pkt: called.__setitem__("debit", 1))

    assert await d.send_packet(_flood_txt(), wait_for_ack=False) is True
    assert radio.send_count == 1
    assert called == {"await": 0, "debit": 0}  # hot path untouched


# --------------------------------------------------------------------------- #
# Cancellation safety
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_cancellation_during_wait_leaves_bucket_consistent(clock):
    # Real asyncio.sleep here so the wait actually suspends and can be cancelled.
    d, radio = _make(factor=1.0)
    d._tx_est_airtime_ms = lambda n: 200.0  # reserve 100
    d._tx_budget_ms = 0.0  # far short -> long wait
    d._tx_budget_last_update = clock.t
    d._tx_next_time = clock.t

    task = asyncio.create_task(d._await_tx_budget(_flood_txt()))
    await asyncio.sleep(0)  # let it reach the real sleep
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # No transmit happened and the bucket is unchanged/consistent: budget stayed
    # at the last synchronous refill value (0.0, elapsed was 0) and last_update
    # equals the refill time. No partial debit.
    assert radio.send_count == 0
    assert d._tx_budget_ms == 0.0
    assert d._tx_budget_last_update == clock.t


# --------------------------------------------------------------------------- #
# Concurrency: admission is re-decided under the TX lock (real time, no clock)
# --------------------------------------------------------------------------- #


class GatedRadio:
    """Radio that records real send-start times and can block its first send.

    ``gate`` (an asyncio.Event) parks the first ``send`` so a caller can hold the
    TX lock in flight while another caller is examined. Non-first sends yield
    once so concurrent callers get to evaluate the pre-gate before the first
    debit lands.
    """

    def __init__(self):
        self.rx_callback = None
        self.send_count = 0
        self.send_starts = []
        self.gate = None
        self._first = True

    def set_rx_callback(self, cb):
        self.rx_callback = cb

    async def send(self, data):
        self.send_starts.append(time.monotonic())
        self.send_count += 1
        if self.gate is not None and self._first:
            self._first = False
            await self.gate.wait()
        else:
            await asyncio.sleep(0)
        return {"ok": 1}

    def get_last_rssi(self):
        return -70

    def get_last_snr(self):
        return 8.0


def _make_gated(factor=0.0):
    d = Dispatcher(GatedRadio(), dedupe_enabled=True)
    d.local_identity = Identity()
    d.airtime_budget_factor = factor
    d.set_client_repeat_enabled(True)
    return d, d.radio


@pytest.mark.asyncio
async def test_concurrent_second_send_waits_for_pacing():
    # Budget seeded for exactly one send. Task A holds the lock in radio.send;
    # task B passes the pre-gate against the undebited bucket and queues on the
    # lock. B must not transmit until A's debit-derived pacing has elapsed.
    d, radio = _make_gated(factor=0.0)  # duty 1.0
    d._tx_est_airtime_ms = lambda n: 200.0  # reserve 100, spend 200 each
    now = time.monotonic()
    d._tx_budget_ms = 200.0
    d._tx_budget_last_update = now
    d._tx_next_time = now
    radio.gate = asyncio.Event()

    task_a = asyncio.create_task(d.send_packet(_flood_txt(), wait_for_ack=False))
    await asyncio.sleep(0.02)  # A reaches radio.send and blocks holding the lock
    assert radio.send_count == 1
    assert d._tx_lock.locked()

    task_b = asyncio.create_task(d.send_packet(_flood_txt(), wait_for_ack=False))
    await asyncio.sleep(0.02)  # B passes the pre-gate snapshot, queues on the lock
    assert radio.send_count == 1  # B has NOT transmitted yet

    radio.gate.set()  # A finishes -> debits, sets next_tx_time pacing, frees lock
    assert await task_a is True
    pacing_deadline = d._tx_next_time  # A's debit put next_tx_time in the future
    assert pacing_deadline > now  # a real pacing window exists

    assert await task_b is True
    assert radio.send_count == 2
    # On pre-fix code B reuses the pre-lock snapshot and transmits immediately,
    # i.e. before pacing_deadline. The under-lock recheck holds it back.
    assert radio.send_starts[1] >= pacing_deadline


@pytest.mark.asyncio
async def test_burst_serialized_by_pacing():
    # Four tasks against a one-send bucket. Every send yields once, so all four
    # evaluate the pre-gate before the first debit; the under-lock recheck then
    # serializes them one per next_tx_time pacing window.
    d, radio = _make_gated(factor=0.0)  # duty 1.0
    d._tx_est_airtime_ms = lambda n: 200.0  # reserve 100, spend 200 each
    now = time.monotonic()
    d._tx_budget_ms = 200.0  # only the first admits without waiting
    d._tx_budget_last_update = now
    d._tx_next_time = now

    tasks = [asyncio.create_task(d.send_packet(_flood_txt(), wait_for_ack=False)) for _ in range(4)]
    assert all(await asyncio.gather(*tasks))
    assert radio.send_count == 4
    # Each debit sets ~0.1 s (needed 100 / duty 1.0) of pacing every later
    # admission honours. On pre-fix code all four share the pre-lock snapshot
    # and fire back-to-back (gaps ~0).
    starts = radio.send_starts
    for i in range(1, 4):
        assert starts[i] - starts[i - 1] >= 0.08


@pytest.mark.asyncio
async def test_cancel_while_queued_on_lock_no_debit():
    # Cancel B while it is queued on the TX lock behind A. B must leave the
    # bucket untouched (no debit), and the lock must stay usable afterwards.
    d, radio = _make_gated(factor=0.0)
    d._tx_est_airtime_ms = lambda n: 200.0
    now = time.monotonic()
    d._tx_budget_ms = 200.0
    d._tx_budget_last_update = now
    d._tx_next_time = now
    radio.gate = asyncio.Event()

    task_a = asyncio.create_task(d.send_packet(_flood_txt(), wait_for_ack=False))
    await asyncio.sleep(0.02)
    assert radio.send_count == 1
    assert d._tx_lock.locked()

    task_b = asyncio.create_task(d.send_packet(_flood_txt(), wait_for_ack=False))
    await asyncio.sleep(0.02)  # B passes the pre-gate, blocks acquiring the lock
    budget_before = d._tx_budget_ms
    task_b.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task_b
    assert d._tx_budget_ms == budget_before  # B took no debit
    assert radio.send_count == 1  # B never transmitted

    radio.gate.set()
    assert await task_a is True
    assert not d._tx_lock.locked()  # lock released and usable

    d._tx_budget_ms = 200.0
    d._tx_next_time = time.monotonic()
    assert await d.send_packet(_flood_txt(), wait_for_ack=False) is True
    assert radio.send_count == 2  # a fresh send still goes through after B's cancel


class _ResultRadio(Radio):
    """Radio whose send fails deterministically: raises, or returns None."""

    def __init__(self, mode):
        super().__init__()
        self.mode = mode

    async def send(self, data):
        self.send_count += 1
        if self.mode == "raise":
            raise RuntimeError("tx fail")
        return None  # missing confirmation metadata


@pytest.mark.asyncio
async def test_failed_send_takes_no_debit(clock, monkeypatch):
    # A raising or None-returning send returns False before the debit path, so
    # neither the budget nor the pacing clock moves (pinned: true pre- and post-fix).
    monkeypatch.setattr(disp_mod.asyncio, "sleep", clock.sleep)
    for mode in ("raise", "none"):
        radio = _ResultRadio(mode)
        d = Dispatcher(radio, dedupe_enabled=True)
        d.local_identity = Identity()
        d.airtime_budget_factor = 1.0
        d.set_client_repeat_enabled(True)
        d._tx_est_airtime_ms = lambda n: 200.0  # reserve 100
        d._tx_budget_ms = 200.0
        d._tx_budget_last_update = clock.t
        d._tx_next_time = clock.t

        assert await d.send_packet(_flood_txt(), wait_for_ack=False) is False
        assert radio.send_count == 1
        assert d._tx_budget_ms == pytest.approx(200.0)  # no debit
        assert d._tx_next_time == pytest.approx(clock.t)  # pacing untouched


@pytest.mark.asyncio
async def test_lock_free_while_throttled_waiting():
    # A task throttled in its budget wait does not hold the TX lock (sleeps
    # happen off the lock).
    d, radio = _make_gated(factor=0.0)
    d._tx_est_airtime_ms = lambda n: 200.0
    now = time.monotonic()
    d._tx_budget_ms = 0.0
    d._tx_budget_last_update = now
    d._tx_next_time = now + 3600.0  # long pacing -> stays parked in the wait

    task = asyncio.create_task(d.send_packet(_flood_txt(), wait_for_ack=False))
    await asyncio.sleep(0.02)  # let it reach the budget sleep
    assert radio.send_count == 0
    assert d._tx_lock is None or not d._tx_lock.locked()  # lock-free while sleeping

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_toggle_off_releases_waiter_ungated(monkeypatch):
    # Disabling client-repeat while a task is parked in its budget wait releases
    # it after the current sleep and lets it send ungated (no debit, no pacing).
    d, radio = _make_gated(factor=0.0)
    d._tx_est_airtime_ms = lambda n: 200.0
    now = time.monotonic()
    d._tx_budget_ms = 10_000.0  # budget is not the constraint
    d._tx_budget_last_update = now
    d._tx_next_time = now + 3600.0  # pacing far out -> never admits on its own

    real_sleep = asyncio.sleep
    release = asyncio.Event()

    async def gated_sleep(secs):
        if secs and secs > 0:
            await release.wait()  # park the budget wait until the test releases it
        # Always yield, so a pre-fix loop that ignores the flag cannot tight-spin
        # (the wait_for timeout below can still fire) -- it fails cleanly instead.
        await real_sleep(0)

    monkeypatch.setattr(disp_mod.asyncio, "sleep", gated_sleep)

    task = asyncio.create_task(d.send_packet(_flood_txt(), wait_for_ack=False))
    for _ in range(5):
        await real_sleep(0)
    assert radio.send_count == 0  # parked in the budget wait
    assert d._tx_lock is None or not d._tx_lock.locked()

    d.set_client_repeat_enabled(False)  # disable does not reset the bucket
    release.set()  # let the current sleep return; the loop re-reads the flag
    # On pre-fix code the wait loop ignores the flag and never admits (huge
    # pacing), so this times out; the flag check releases it post-fix.
    assert await asyncio.wait_for(task, 2.0) is True
    assert radio.send_count == 1  # proceeded on the next iteration, ungated
    # No debit (a debit subtracts airtime); refill only ever adds to the bucket.
    assert d._tx_budget_ms >= 10_000.0
    assert d._tx_next_time == pytest.approx(now + 3600.0)  # pacing untouched
