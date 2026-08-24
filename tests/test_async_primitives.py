import asyncio

import pytest

from openhop_core.async_primitives import LazyAsyncEvent, LazyAsyncLock


def test_lazy_async_primitives_construct_without_current_event_loop():
    lock = LazyAsyncLock()
    event = LazyAsyncEvent()

    assert lock.locked() is False
    assert event.is_set() is False


@pytest.mark.asyncio
async def test_lazy_async_lock_serializes_waiters():
    lock = LazyAsyncLock()
    entered = []

    async def worker(value):
        async with lock:
            entered.append(value)
            await asyncio.sleep(0)

    await asyncio.gather(worker(1), worker(2))

    assert entered == [1, 2]
    assert lock.locked() is False


@pytest.mark.asyncio
async def test_lazy_async_event_preserves_pre_loop_state_and_wakes_waiter():
    event = LazyAsyncEvent()
    event.set()

    assert await asyncio.wait_for(event.wait(), timeout=0.1) is True

    event.clear()
    waiter = asyncio.create_task(event.wait())
    await asyncio.sleep(0)
    assert not waiter.done()

    event.set()

    assert await asyncio.wait_for(waiter, timeout=0.1) is True
