"""Tests for the LR11xx driver and SX1262Radio(chip="lr1121")."""

from unittest.mock import MagicMock

from openhop_core.hardware.lora.LoRaRF.LR11xx import LR11xx
from openhop_core.hardware.sx1262_wrapper import SX1262Radio


class FakeSpi:
    """Records each SPI transaction and answers from a queue of replies."""

    def __init__(self, *replies):
        self.sent = []
        self.replies = list(replies)

    def open(self, bus, cs):
        pass

    def xfer2(self, buf):
        self.sent.append(list(buf))
        reply = list(self.replies.pop(0)) if self.replies else []
        return reply + [0] * (len(buf) - len(reply))


def _make_chip(*replies):
    chip = LR11xx()
    chip._busy = -1  # no BUSY pin, so busyCheck() reports ready
    spi = FakeSpi(*replies)
    chip.set_spi_transport(spi)
    return chip, spi


def test_reads_send_the_command_then_clock_out_the_response():
    # the second transaction answers Stat1, then the payload length and offset
    chip, spi = _make_chip([], [0x04, 20, 0x80])

    assert chip.getRxBufferStatus() == (20, 0x80)
    assert spi.sent == [[0x02, 0x03], [0x00, 0x00, 0x00]]


def test_irq_status_comes_from_get_status():
    chip, spi = _make_chip([0x05, 0x02, 0x00, 0x00, 0x04, 0x08])

    assert chip.getIrqStatus() == chip.IRQ_TIMEOUT | chip.IRQ_RX_DONE
    assert spi.sent == [[0x01, 0x00, 0x00, 0x00, 0x00, 0x00]]


def test_request_lifts_the_tx_payload_length_before_listening():
    chip, spi = _make_chip()
    chip.setPacketParamsLoRa(32, chip.HEADER_EXPLICIT, 20, chip.CRC_ON, chip.IQ_STANDARD)
    spi.sent.clear()

    chip.request(chip.RX_CONTINUOUS)

    # an explicit header over PayloadLen would be rejected, so go back to 255
    assert spi.sent[0] == [0x01, 0x1C, 0x00]
    assert spi.sent[1] == [0x02, 0x10, 0x00, 0x20, 0x00, 0xFF, 0x01, 0x00]
    assert spi.sent[-1] == [0x02, 0x09, 0xFF, 0xFF, 0xFF]


def test_begin_brings_up_an_lr1121():
    spi = FakeSpi()
    radio = SX1262Radio(
        chip="lr1121",
        rf_switch=[0x03, 0x00, 0x02, 0x03, 0x01, 0x00, 0x00, 0x00],
        frequency=869_618_000,
        use_dio3_tcxo=True,
        reset_pin=-1,
        busy_pin=-1,
        txen_pin=-1,
        radio_timing_delay=0.0,
        spi_transport=spi,
        gpio_manager=MagicMock(),
    )

    assert radio.begin() is True
    sent = list(spi.sent)
    radio.cleanup()

    assert isinstance(radio.lora, LR11xx)
    # an inherited SX126x command would go out with a 0x00 high byte
    assert all(command[0] in (0x01, 0x02) for command in sent)
    assert [0x01, 0x17, 0x02, 0x00, 0x00, 0xA4] in sent  # TCXO at 1.8 V
    assert [0x01, 0x12, 0x03, 0x00, 0x02, 0x03, 0x01, 0x00, 0x00, 0x00] in sent
    assert [0x02, 0x0B, 0x33, 0xD5, 0x51, 0x50] in sent  # 869.618 MHz in Hz
    assert [0x02, 0x15, 0x01, 0x01, 0x04, 0x07] in sent  # high power PA on VBAT
    assert sent[-1] == [0x02, 0x09, 0xFF, 0xFF, 0xFF]  # continuous RX
