"""CH341 multi-adapter USB selection tests."""

from __future__ import annotations

import ctypes
import struct
import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

# Provide a minimal fake pyusb so this module imports without hardware deps.
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

from openhop_core.hardware.ch341.ch341_async import CH341Async, CH341Error, CH341SPIError


def _fake_dev(bus, address, serial=None, vid=0x1A86, pid=0x5512):
    return SimpleNamespace(
        idVendor=vid,
        idProduct=pid,
        bus=bus,
        address=address,
        iSerialNumber=1 if serial else 0,
    )


@pytest.fixture(autouse=True)
def _reset_ch341():
    CH341Async._instances = {}
    CH341Async._instance = None
    yield
    CH341Async._instances = {}
    CH341Async._instance = None


def test_find_device_by_bus_address():
    d1 = _fake_dev(1, 5, "AAA")
    d2 = _fake_dev(1, 8, "BBB")
    with patch("openhop_core.hardware.ch341.ch341_async.usb.core.find", return_value=[d1, d2]):
        with patch.object(
            CH341Async, "_device_serial", side_effect=lambda d: {d1: "AAA", d2: "BBB"}[d]
        ):
            got = CH341Async._find_device(0x1A86, 0x5512, bus=1, address=8)
    assert got is d2


def test_find_device_by_serial():
    d1 = _fake_dev(1, 5)
    d2 = _fake_dev(2, 3)
    with patch("openhop_core.hardware.ch341.ch341_async.usb.core.find", return_value=[d1, d2]):
        with patch.object(
            CH341Async,
            "_device_serial",
            side_effect=lambda d: "SER-B" if d is d2 else "SER-A",
        ):
            got = CH341Async._find_device(0x1A86, 0x5512, serial_number="SER-B")
    assert got is d2


def test_find_device_ambiguous_without_filter_raises():
    d1 = _fake_dev(1, 5)
    d2 = _fake_dev(1, 8)
    with patch("openhop_core.hardware.ch341.ch341_async.usb.core.find", return_value=[d1, d2]):
        with patch.object(CH341Async, "_device_serial", return_value=None):
            with pytest.raises(CH341Error, match="Multiple CH341 devices"):
                CH341Async._find_device(0x1A86, 0x5512)


def test_find_device_single_unfiltered_ok():
    d1 = _fake_dev(1, 5)
    with patch("openhop_core.hardware.ch341.ch341_async.usb.core.find", return_value=[d1]):
        with patch.object(CH341Async, "_device_serial", return_value=None):
            got = CH341Async._find_device(0x1A86, 0x5512)
    assert got is d1


def test_get_instance_reuses_same_bus_address():
    d1 = _fake_dev(1, 5, "AAA")

    def fake_open(self):
        self.dev = d1
        self.bus = 1
        self.address = 5
        self.serial_number = "AAA"

    with patch.object(CH341Async, "_open_device", fake_open):
        a = CH341Async.get_instance(bus=1, address=5)
        b = CH341Async.get_instance(bus=1, address=5)
    assert a is b


def test_get_instance_two_locations_are_distinct():
    d1 = _fake_dev(1, 5)
    d2 = _fake_dev(1, 8)

    def fake_open(self):
        self.dev = d1 if self.address == 5 else d2
        self.bus = 1
        self.serial_number = None

    with patch.object(CH341Async, "_open_device", fake_open):
        a = CH341Async.get_instance(bus=1, address=5)
        b = CH341Async.get_instance(bus=1, address=8)
    assert a is not b
    assert a.address == 5
    assert b.address == 8


def test_list_devices_returns_locations():
    d1 = _fake_dev(1, 5)
    d2 = _fake_dev(2, 9)
    with patch("openhop_core.hardware.ch341.ch341_async.usb.core.find", return_value=[d1, d2]):
        with patch.object(
            CH341Async, "_device_serial", side_effect=lambda d: "A" if d is d1 else "B"
        ):
            listed = CH341Async.list_devices()
    assert listed == [
        {"vid": 0x1A86, "pid": 0x5512, "bus": 1, "address": 5, "serial_number": "A"},
        {"vid": 0x1A86, "pid": 0x5512, "bus": 2, "address": 9, "serial_number": "B"},
    ]


# --- bulk transfers through usbfs (Linux) ------------------------------------

_NODE = "/dev/bus/usb/001/005"
_PINS = bytes([0x40, 0xEF, 0xEF, 0x94, 0x13, 0xFF])  # GPIO 6 high, GPIO 4 low
_MISO = bytes([0x01, 0x80, 0x48])  # as the CH341 hands SPI data back, LSB first


class _FakeAdapter:
    """Records bulk traffic and answers pin status reads and SPI like the CH341."""

    def __init__(self):
        self.traffic = []
        self.ioctls = 0

    def write(self, data, timeout=None):
        self.traffic.append(("out", bytes(data), timeout))
        return len(data)

    def read(self, length, timeout=None):
        self.traffic.append(("in", length, timeout))
        if timeout == 200:  # pin status read
            return _PINS[:length]
        return _MISO[:length] if timeout == CH341Async.USB_TIMEOUT else b""

    def ioctl(self, fd, request, arg, mutate_flag):
        # _IOWR('U', 2, struct usbdevfs_bulktransfer) for 4- and 8-byte pointers.
        assert request == {4: 0xC0105502, 8: 0xC0185502}[ctypes.sizeof(ctypes.c_void_p)]
        assert (fd, mutate_flag) == (7, True)
        self.ioctls += 1
        endpoint, length, timeout, address = struct.unpack("IIIP", arg)
        if endpoint == CH341Async.EP_OUT:
            return self.write(ctypes.string_at(address, length), timeout)
        reply = self.read(length, timeout)
        ctypes.memmove(address, reply, len(reply))
        return len(reply)


def _open_ch341(adapter, platform, links):
    """Run the real _open_device against a fake adapter and a fake /proc/self/fd."""
    dev = MagicMock(bus=1, address=5)
    dev.is_kernel_driver_active.return_value = False
    mod = "openhop_core.hardware.ch341.ch341_async"
    with (
        patch.object(CH341Async, "_find_device", return_value=dev),
        patch.object(CH341Async, "_device_serial", return_value="S"),
        patch(f"{mod}.usb.util.claim_interface"),
        patch(f"{mod}.usb.util.find_descriptor", return_value=adapter),
        patch("sys.platform", platform),
        patch("os.listdir", return_value=list(links)),
        patch("os.readlink", side_effect=lambda path: links[path.rsplit("/", 1)[1]]),
    ):
        ch = CH341Async(bus=1, address=5)
    adapter.traffic.clear()  # drop the pinmux init and the drain
    return ch


@pytest.mark.parametrize(
    "platform, links, ioctls",
    [
        ("linux", {"3": "/dev/null", "7": _NODE}, 9),  # one usbfs descriptor: every transfer
        ("linux", {"7": _NODE, "9": _NODE}, 0),  # ambiguous: pyusb
        ("darwin", {"7": _NODE}, 0),  # not Linux: pyusb
    ],
)
def test_bulk_transfers_are_the_same_through_usbfs_and_pyusb(platform, links, ioctls):
    adapter = _FakeAdapter()
    ch = _open_ch341(adapter, platform, links)
    with patch("fcntl.ioctl", adapter.ioctl):
        assert (ch.gpio_get(6), ch.gpio_get(4), ch.gpio_get(15)) == (True, False, True)
        ch.gpio_set(0, False)
        assert ch.spi_transfer_async(b"\x12\x00\x00") == b"\x80\x01\x12"
    assert adapter.traffic == [
        ("out", b"\xa0", 200),
        ("in", 6, 200),
        ("out", b"\xa0", 200),
        ("in", 6, 200),
        ("out", b"\xa0", 200),
        ("in", 6, 200),
        ("out", b"\xab\xa8\x69\x20", 5000),
        ("out", b"\xa8\x48\x00\x00", 5000),
        ("in", 3, 5000),
    ]
    assert adapter.ioctls == ioctls


def test_usbfs_transfer_failure_keeps_the_ch341_errors():
    ch = _open_ch341(_FakeAdapter(), "linux", {"7": _NODE})
    gone = OSError(19, "No such device")
    with patch("fcntl.ioctl", side_effect=gone):
        with pytest.raises(CH341SPIError, match="SPI OUT bulk transfer failed"):
            ch.spi_transfer_async(b"\x12")
        with pytest.raises(CH341Error, match="GPIO read write failed"):
            ch.gpio_get(6)
    with patch("fcntl.ioctl", side_effect=[2, gone]):
        with pytest.raises(CH341SPIError, match="SPI IN bulk transfer failed"):
            ch.spi_transfer_async(b"\x12")
    with patch("fcntl.ioctl", side_effect=[1, 5]):  # five of the six status bytes
        with pytest.raises(CH341Error, match="GPIO read IN failed: short read"):
            ch.gpio_get(6)


def test_close_forgets_the_usbfs_descriptor():
    ch = _open_ch341(_FakeAdapter(), "linux", {"7": _NODE})
    with patch("usb.util.release_interface"), patch("usb.util.dispose_resources"):
        ch.close()
    assert ch._usbfs_fd is None
