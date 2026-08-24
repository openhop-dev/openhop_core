"""Async primitives that can be constructed before an event loop exists.

Python 3.9 binds ``asyncio`` locks and events during construction. Core objects
are often assembled synchronously and used later by an application event loop,
so these wrappers defer creation of the real primitive until first async use.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Optional, Type


class LazyAsyncLock:
    """An ``asyncio.Lock`` compatible wrapper with deferred loop binding."""

    def __init__(self) -> None:
        self._lock: Optional[asyncio.Lock] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._guard = threading.Lock()

    def _get_lock(self) -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        with self._guard:
            if self._lock is None:
                self._lock = asyncio.Lock()
                self._loop = loop
            elif self._loop is not loop:
                if self._lock.locked():
                    raise RuntimeError("async lock is active on a different event loop")
                self._lock = asyncio.Lock()
                self._loop = loop
            return self._lock

    async def acquire(self) -> bool:
        return await self._get_lock().acquire()

    def release(self) -> None:
        with self._guard:
            lock = self._lock
        if lock is None:
            raise RuntimeError("Lock is not acquired")
        lock.release()

    def locked(self) -> bool:
        with self._guard:
            return self._lock is not None and self._lock.locked()

    async def __aenter__(self) -> "LazyAsyncLock":
        await self.acquire()
        return self

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc: Optional[BaseException],
        traceback,
    ) -> None:
        del exc_type, exc, traceback
        self.release()


class LazyAsyncEvent:
    """An ``asyncio.Event`` compatible wrapper with deferred loop binding."""

    def __init__(self) -> None:
        self._event: Optional[asyncio.Event] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._flag = False
        self._guard = threading.Lock()

    def _get_event(self) -> asyncio.Event:
        loop = asyncio.get_running_loop()
        with self._guard:
            if self._event is None or self._loop is not loop:
                self._event = asyncio.Event()
                self._loop = loop
            if self._flag:
                self._event.set()
            else:
                self._event.clear()
            return self._event

    def set(self) -> None:
        with self._guard:
            self._flag = True
            event = self._event
        if event is not None:
            event.set()

    def clear(self) -> None:
        with self._guard:
            self._flag = False
            event = self._event
        if event is not None:
            event.clear()

    def is_set(self) -> bool:
        with self._guard:
            return self._flag

    async def wait(self) -> bool:
        await self._get_event().wait()
        return True
