"""SX126x wake(): the NSS edge comes before the first BUSY wait."""

from unittest.mock import MagicMock

import pytest
from openhop_core.hardware.lora.LoRaRF.SX126x import SX126x


@pytest.mark.parametrize("manual_cs", [True, False])
def test_wake_clocks_nop_before_waiting_on_busy(manual_cs):
    events = []
    radio = SX126x()
    radio.busyCheck = lambda timeout=5000: events.append("busy") or False
    bus = MagicMock(spec=["transfer"])  # SPIDevTransport's shape: no xfer2
    bus.transfer.side_effect = lambda buf: events.append(buf[0]) or [0] * len(buf)
    radio.set_spi_transport(bus)
    if manual_cs:
        nss = MagicMock()
        nss.write.side_effect = lambda high: events.append("NSS high" if high else "NSS low")
        radio.set_gpio_manager(MagicMock(_pins={24: nss}))
        radio.setManualCsPin(24)

    radio.wake()

    # NOP, SetStandby, then the TX clamp fix's register read and write.
    spi = [e for e in events if "NSS" not in str(e)]
    assert spi == [0x00, "busy", 0x80, "busy", 0x1D, "busy", 0x0D]
    if manual_cs:
        assert events[:3] == ["NSS low", 0x00, "NSS high"]
