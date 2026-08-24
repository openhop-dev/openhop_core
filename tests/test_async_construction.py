import asyncio

import pytest

from openhop_core.companion.base_support import ResponseWaiter
from openhop_core.hardware.tcp_radio import TCPLoRaRadio
from openhop_core.hardware.usb_radio import USBLoRaRadio
from openhop_core.node.dispatcher import Dispatcher


class _Radio:
    def set_rx_callback(self, callback):
        self.callback = callback

    async def send(self, data):
        del data
        return {"airtime_ms": 0.0}


def test_async_owners_construct_without_creating_loop_bound_primitives():
    dispatcher = Dispatcher(_Radio())
    tcp = TCPLoRaRadio("127.0.0.1")
    usb = USBLoRaRadio("/dev/null")
    waiter = ResponseWaiter()

    assert dispatcher._tx_lock is None
    assert tcp._tx_lock is None
    assert tcp._command_lock is None
    assert usb._tx_lock is None
    assert usb._command_lock is None
    assert waiter.event.is_set() is False


@pytest.mark.asyncio
async def test_async_owners_create_standard_primitives_on_running_loop():
    dispatcher = Dispatcher(_Radio())
    tcp = TCPLoRaRadio("127.0.0.1")
    usb = USBLoRaRadio("/dev/null")

    assert isinstance(dispatcher._get_tx_lock(), asyncio.Lock)
    assert isinstance(tcp._get_tx_lock(), asyncio.Lock)
    assert isinstance(tcp._get_command_lock(), asyncio.Lock)
    assert isinstance(usb._get_tx_lock(), asyncio.Lock)
    assert isinstance(usb._get_command_lock(), asyncio.Lock)


@pytest.mark.asyncio
async def test_response_waiter_uses_thread_event_without_blocking_loop():
    waiter = ResponseWaiter()
    waiter.callback(True, "done", {"value": 1})

    result = await waiter.wait(timeout=0.1)

    assert result == {"success": True, "text": "done", "parsed": {"value": 1}}
