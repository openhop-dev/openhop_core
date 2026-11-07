import threading

import pytest
import serial


@pytest.fixture
def stalled_serial():
    """Model a USB device with cancellable reads and a timeout-aware write."""
    handles = []

    class StalledSerial:
        def __init__(self, *, stalled=True, stall_after=0, on_write=None, **kwargs):
            self.is_open = True
            self.timeout = kwargs.get("timeout", 0.1)
            self.write_timeout = kwargs.get("write_timeout")
            self.stalled = stalled
            self.stall_after = stall_after
            self.on_write = on_write
            self.writes = []
            self.write_started = threading.Event()
            self.cancelled = threading.Event()
            self.flush_started = threading.Event()
            self.in_waiting = 0
            handles.append(self)

        def write(self, data):
            self.write_started.set()
            if self.stalled and len(self.writes) >= self.stall_after:
                if self.cancelled.wait(self.write_timeout):
                    raise serial.SerialException("Write cancelled")
                raise serial.SerialTimeoutException("Device is not reading")
            self.writes.append(bytes(data))
            if self.on_write:
                self.on_write(bytes(data))
            return len(data)

        def flush(self):
            self.flush_started.set()
            self.cancelled.wait()

        def read(self, _size):
            self.cancelled.wait(self.timeout)
            return b""

        def reset_input_buffer(self):
            pass

        def reset_output_buffer(self):
            pass

        def cancel_read(self):
            self.cancelled.set()

        def cancel_write(self):
            self.cancelled.set()

        def close(self):
            self.is_open = False
            self.cancelled.set()

    yield StalledSerial
    for handle in handles:
        handle.close()
