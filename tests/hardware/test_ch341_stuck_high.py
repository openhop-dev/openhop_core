"""CH341 IRQ polling: recovery when DIO1 stays HIGH (missed rising edge)."""

import sys
import threading
import time
from types import ModuleType
from unittest.mock import MagicMock

# Provide a minimal fake pyusb so this module imports without hardware deps
# (same stub as tests/test_ch341_multi_device.py).
if "usb" not in sys.modules:
    usb_mod = ModuleType("usb")
    usb_core = ModuleType("usb.core")
    usb_util = ModuleType("usb.util")

    class _USBError(Exception):
        def __init__(self, *args, errno=None, **kwargs):
            super().__init__(*args)
            self.errno = errno

    usb_core.USBError = _USBError
    usb_core.find = MagicMock(return_value=[])
    usb_util.get_string = MagicMock(return_value=None)
    usb_util.claim_interface = MagicMock()
    usb_util.release_interface = MagicMock()
    usb_util.dispose_resources = MagicMock()
    usb_util.find_descriptor = MagicMock(return_value=None)
    usb_mod.core = usb_core
    usb_mod.util = usb_util
    sys.modules["usb"] = usb_mod
    sys.modules["usb.core"] = usb_core
    sys.modules["usb.util"] = usb_util

from openhop_core.hardware.ch341.ch341_gpio_manager import CH341GPIOPin  # noqa: E402


def _run_polling(levels, refire_s=0.01, timeout=2.0):
    """Run the CH341 poller over a scripted sequence of (level, duration_s) phases."""
    phases = list(levels)
    start = [None]

    def gpio_get(_pin):
        now = time.monotonic()
        if start[0] is None:
            start[0] = now
        elapsed = now - start[0]
        for level, duration in phases:
            if elapsed < duration:
                return level
            elapsed -= duration
        pin._stop_polling = True
        return False

    device = MagicMock()
    device.gpio_get.side_effect = gpio_get

    pin = CH341GPIOPin(device, 6, is_output=False)
    pin.stuck_high_refire_s = refire_s
    pin._cached_state = False

    calls = []
    pin._interrupt_callback = lambda: calls.append(time.monotonic())
    pin._interrupt_edge = "rising"
    pin._stop_polling = False

    thread = threading.Thread(target=pin._poll_for_interrupt, daemon=True)
    thread.start()
    thread.join(timeout=timeout)
    assert not thread.is_alive(), "Polling thread did not terminate"
    return calls


def test_stuck_high_refires_callback():
    """LOW then HIGH for much longer than the threshold fires again after the edge."""
    calls = _run_polling([(False, 0.02), (True, 0.2)], refire_s=0.02)

    assert len(calls) >= 2, f"Expected edge + recovery callbacks, got {len(calls)}"


def test_refire_is_rate_limited():
    """While stuck HIGH, re-fires happen at most once per threshold, not every poll."""
    calls = _run_polling([(False, 0.02), (True, 0.3)], refire_s=0.05)

    # 1 edge + roughly 0.3 / 0.05 re-fires; never one per 1 ms poll.
    assert 2 <= len(calls) <= 8, f"Unexpected callback count {len(calls)}"


def test_short_pulses_fire_once_per_edge():
    """HIGH pulses shorter than the threshold only fire on their rising edge."""
    phases = []
    for _ in range(3):
        phases += [(False, 0.02), (True, 0.02)]
    calls = _run_polling(phases + [(False, 0.02)], refire_s=0.5)

    assert len(calls) == 3, f"Expected one callback per rising edge, got {len(calls)}"
