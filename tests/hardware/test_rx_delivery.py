"""Each received frame reaches the RX callback with its own RSSI/SNR."""

import asyncio
import struct

import pytest

from openhop_core.hardware.protocol_constants import CMD_RX_PACKET
from openhop_core.hardware.rx_delivery import deliver_rx_packet
from openhop_core.hardware.tcp_radio import TCPLoRaRadio
from openhop_core.hardware.usb_radio import USBLoRaRadio


def _rx_frame(rssi: int, snr: float, data: bytes) -> bytes:
    return struct.pack("<hhh", rssi, int(snr * 10), rssi - 1) + data


@pytest.mark.asyncio
@pytest.mark.parametrize("cls", [TCPLoRaRadio, USBLoRaRadio])
async def test_back_to_back_frames_keep_their_own_signal(cls):
    radio = cls("unused")
    radio._event_loop = asyncio.get_running_loop()
    received = []
    radio.rx_callback = lambda data, rssi=None, snr=None: received.append((data, rssi, snr))

    # The reader thread can store the next frame's metrics before the loop runs
    # the first callback; each callback must still see its own frame's values.
    radio._dispatch_frame(CMD_RX_PACKET, _rx_frame(-60, 9.5, b"near"))
    radio._dispatch_frame(CMD_RX_PACKET, _rx_frame(-118, -12.0, b"far"))
    await asyncio.sleep(0)

    assert received == [(b"near", -60, 9.5), (b"far", -118, -12.0)]
    assert (radio.last_rssi, radio.last_snr) == (-118, -12.0)


@pytest.mark.asyncio
@pytest.mark.parametrize("cls", [TCPLoRaRadio, USBLoRaRadio])
async def test_data_only_callbacks_still_work(cls):
    radio = cls("unused")
    radio._event_loop = asyncio.get_running_loop()
    received = []
    radio.rx_callback = lambda data: received.append(data)

    radio._dispatch_frame(CMD_RX_PACKET, _rx_frame(-80, 1.0, b"legacy"))
    await asyncio.sleep(0)

    assert received == [b"legacy"]


def test_a_typeerror_inside_the_callback_is_not_a_second_delivery():
    calls = []

    def callback(data, rssi, snr):
        calls.append(data)
        raise TypeError("bug inside the callback")

    with pytest.raises(TypeError, match="inside the callback"):
        deliver_rx_packet(callback, b"x", -90, 2.0)
    assert calls == [b"x"]
