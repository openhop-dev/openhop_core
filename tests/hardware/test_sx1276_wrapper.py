"""SX1276Radio against a register-level fake of the chip (no hardware needed)."""

import asyncio

import pytest

from openhop_core.hardware import sx1276_wrapper as sx
from openhop_core.hardware.sx1276_wrapper import SX1276Radio


class FakeSX1276:
    """Register file + FIFO + IRQ behaviour of an SX1276 in LoRa mode."""

    def __init__(self, version=0x12):
        self.regs = [0] * 0x80
        self.regs[sx.REG_VERSION] = version
        self.fifo = bytearray(256)
        self.irq_cb = None
        self.transmitted = []
        self.cad_busy = False

    # --- SPI side
    @property
    def is_open(self):
        return True

    def transfer(self, data):
        addr = data[0] & 0x7F
        write = bool(data[0] & 0x80)
        out = [0]
        for value in data[1:]:
            if write:
                self._write(addr, value)
                out.append(0)
            else:
                out.append(self._read(addr))
            if addr != sx.REG_FIFO:
                addr += 1
        return out

    def _read(self, addr):
        if addr == sx.REG_FIFO:
            ptr = self.regs[sx.REG_FIFO_ADDR_PTR]
            self.regs[sx.REG_FIFO_ADDR_PTR] = (ptr + 1) & 0xFF
            return self.fifo[ptr]
        return self.regs[addr]

    def _write(self, addr, value):
        if addr == sx.REG_FIFO:
            ptr = self.regs[sx.REG_FIFO_ADDR_PTR]
            self.fifo[ptr] = value
            self.regs[sx.REG_FIFO_ADDR_PTR] = (ptr + 1) & 0xFF
            return
        if addr == sx.REG_IRQ_FLAGS:  # write-1-to-clear
            self.regs[addr] &= ~value & 0xFF
            return
        self.regs[addr] = value
        if addr == sx.REG_OP_MODE:
            mode = value & 0x07
            if mode == sx.MODE_TX:
                length = self.regs[sx.REG_PAYLOAD_LENGTH]
                base = self.regs[sx.REG_FIFO_TX_BASE_ADDR]
                self.transmitted.append(bytes(self.fifo[base : base + length]))
                self.regs[sx.REG_OP_MODE] = (value & 0xF8) | sx.MODE_STDBY
                self._raise(sx.IRQ_TX_DONE)
            elif mode == sx.MODE_CAD:
                flags = sx.IRQ_CAD_DONE | (sx.IRQ_CAD_DETECTED if self.cad_busy else 0)
                self._raise(flags)

    def _raise(self, flags):
        self.regs[sx.REG_IRQ_FLAGS] |= flags
        wanted = {
            sx.DIO0_RX_DONE: sx.IRQ_RX_DONE,
            sx.DIO0_TX_DONE: sx.IRQ_TX_DONE,
            sx.DIO0_CAD_DONE: sx.IRQ_CAD_DONE,
        }[self.regs[sx.REG_DIO_MAPPING_1] & 0xC0]
        if flags & wanted and self.irq_cb:
            self.irq_cb()  # like the GPIO edge thread

    # --- test helper
    def receive(self, payload: bytes, snr_q=24, rssi=100, crc_error=False):
        start = 0x40
        self.fifo[start : start + len(payload)] = payload
        self.regs[sx.REG_FIFO_RX_CURRENT_ADDR] = start
        self.regs[sx.REG_RX_NB_BYTES] = len(payload)
        self.regs[sx.REG_PKT_SNR_VALUE] = snr_q & 0xFF
        self.regs[sx.REG_PKT_RSSI_VALUE] = rssi
        flags = sx.IRQ_RX_DONE | sx.IRQ_VALID_HEADER
        if crc_error:
            flags |= sx.IRQ_PAYLOAD_CRC_ERROR
        self._raise(flags)


class FakeGPIO:
    def __init__(self, chip):
        self.chip = chip
        self.levels = {}

    def setup_output_pin(self, pin, initial_value=False):
        self.levels[pin] = initial_value
        return True

    def setup_interrupt_pin(self, pin, pull_up=False, callback=None):
        self.chip.irq_cb = callback
        return object()

    def set_pin_high(self, pin):
        self.levels[pin] = True
        return True

    def set_pin_low(self, pin):
        self.levels[pin] = False
        return True

    def read_pin(self, pin):
        return self.levels.get(pin, False)

    def blink_led(self, pin, duration=0.2):
        pass

    def cleanup_pin(self, pin):
        self.levels.pop(pin, None)

    def cleanup_all(self):
        self.levels.clear()


def make_radio(chip=None, **kwargs):
    chip = chip or FakeSX1276()
    gpio = FakeGPIO(chip)
    params = dict(
        frequency=869_618_000,
        bandwidth=62_500,
        spreading_factor=8,
        coding_rate=5,
        tx_power=20,
        preamble_length=32,
        sync_word=0x12,
    )
    params.update(kwargs)
    radio = SX1276Radio(spi_transport=chip, gpio_manager=gpio, radio_timing_delay=0, **params)
    return radio, chip, gpio


async def wait_until(predicate, timeout=1.0):
    deadline = asyncio.get_running_loop().time() + timeout
    while not predicate():
        if asyncio.get_running_loop().time() > deadline:
            return False
        await asyncio.sleep(0.01)
    return True


# ----------------------------------------------------------------- pure helpers
def test_frequency_registers_match_datasheet():
    # 868.0 MHz -> 0xD90000 (Frf = f * 2^19 / 32 MHz)
    assert sx.frf_bytes(868_000_000) == (0xD9, 0x00, 0x00)
    msb, mid, lsb = sx.frf_bytes(869_618_000)
    assert ((msb << 16) | (mid << 8) | lsb) == (869_618_000 << 19) // 32_000_000


def test_sync_word_folds_sx126x_values():
    assert sx.sx127x_sync_word(0x12) == 0x12
    assert sx.sx127x_sync_word(0x1424) == 0x12
    assert sx.sx127x_sync_word(0x3444) == 0x34


def test_pa_boost_power_mapping():
    assert sx.pa_settings(20) == (0xFF, 0x87, 20)
    assert sx.pa_settings(17) == (0xFF, 0x84, 17)
    assert sx.pa_settings(22)[2] == 20  # clamped to the PA_BOOST maximum
    assert sx.pa_settings(0)[2] == 2


def test_bandwidth_and_ocp_codes():
    assert sx.bandwidth_code(62_500) == 6
    assert sx.bandwidth_code(125_000) == 7
    assert sx.bandwidth_code(250_000) == 8
    assert sx.ocp_register(120) == 0x2F  # MeshCore SX127X_CURRENT_LIMIT=120
    assert sx.ocp_register(240) == 0x3B


def test_snr_and_rssi_conversion():
    assert sx.snr_from_register(24) == 6.0
    assert sx.snr_from_register(0xF8) == -2.0
    assert sx.packet_rssi_dbm(60, -2.0, 869_000_000) == -157 + 60 - 2.0


# ----------------------------------------------------------------- with fake chip
def test_begin_programs_meshcore_settings():
    radio, chip, gpio = make_radio()
    assert radio.begin() is True
    r = chip.regs
    assert r[sx.REG_OP_MODE] == sx.LONG_RANGE_MODE | sx.MODE_RX_CONTINUOUS
    assert r[sx.REG_MODEM_CONFIG_1] == (6 << 4) | (1 << 1)  # BW 62.5k, CR 4/5, explicit header
    assert r[sx.REG_MODEM_CONFIG_2] == (8 << 4) | 0x04  # SF8, CRC on
    assert r[sx.REG_MODEM_CONFIG_3] == 0x04  # AGC on; SF8/62.5k symbol is 4.1 ms, no LDRO
    assert r[sx.REG_SYNC_WORD] == 0x12
    assert (r[sx.REG_PREAMBLE_MSB] << 8 | r[sx.REG_PREAMBLE_LSB]) == 32
    assert r[sx.REG_PA_CONFIG] == 0xFF and r[sx.REG_PA_DAC] == 0x87
    assert r[sx.REG_OCP] == 0x2F
    assert r[sx.REG_DIO_MAPPING_1] & 0xC0 == sx.DIO0_RX_DONE
    assert gpio.levels[25] is True  # NSS idles high
    radio.cleanup()


def test_begin_rejects_missing_chip():
    radio, _, _ = make_radio(FakeSX1276(version=0x00))
    with pytest.raises(RuntimeError, match="SX1276 not found"):
        radio.begin()


def test_sx1262_power_request_is_clamped():
    radio, chip, _ = make_radio(tx_power=22)
    radio.begin()
    assert radio.tx_power == 20
    radio.cleanup()


async def test_receive_delivers_packet_and_metrics():
    radio, chip, _ = make_radio()
    radio.begin()
    got = []
    radio.set_rx_callback(got.append)
    chip.receive(b"\x01\x02hello", snr_q=24, rssi=90)
    assert await wait_until(lambda: got)
    assert got == [b"\x01\x02hello"]
    assert radio.get_last_snr() == 6.0
    assert radio.get_last_rssi() == round(-157 + 90 * 16 / 15)
    assert chip.regs[sx.REG_OP_MODE] & 0x07 == sx.MODE_RX_CONTINUOUS
    radio.cleanup()


async def test_crc_error_is_counted_not_delivered():
    radio, chip, _ = make_radio()
    radio.begin()
    got = []
    radio.set_rx_callback(got.append)
    chip.receive(b"bad", crc_error=True)
    assert await wait_until(lambda: radio.crc_error_count == 1)
    await asyncio.sleep(0.05)
    assert got == []
    radio.cleanup()


async def test_missed_edge_is_recovered_by_polling():
    radio, chip, _ = make_radio()
    radio.begin()
    got = []
    radio.set_rx_callback(got.append)
    radio.IRQ_SAFETY_POLL_S = 0.05
    chip.irq_cb = None  # simulate a lost DIO0 edge
    chip.receive(b"late")
    assert await wait_until(lambda: got, timeout=2.0)
    assert got == [b"late"]
    radio.cleanup()


async def test_send_writes_fifo_and_returns_to_rx():
    radio, chip, _ = make_radio()
    radio.begin()
    radio.set_rx_callback(lambda _p: None)
    meta = await radio.send(b"\xaa\xbb\xcc")
    assert chip.transmitted == [b"\xaa\xbb\xcc"]
    assert meta["lbt_attempts"] == 0 and meta["airtime_ms"] > 0
    assert chip.regs[sx.REG_DIO_MAPPING_1] & 0xC0 == sx.DIO0_RX_DONE
    assert chip.regs[sx.REG_OP_MODE] & 0x07 == sx.MODE_RX_CONTINUOUS
    radio.cleanup()


async def test_busy_channel_defers_then_transmits():
    radio, chip, _ = make_radio(lbt_max_wait_seconds=0.5, lbt_retry_interval_ms=20)
    radio.begin()
    chip.cad_busy = True
    meta = await radio.send(b"x")
    assert meta["lbt_channel_busy"] is True
    assert chip.transmitted == [b"x"]  # forced once the LBT budget ran out
    radio.cleanup()


async def test_cad_reports_activity():
    radio, chip, _ = make_radio()
    radio.begin()
    assert await radio.perform_cad() is False
    chip.cad_busy = True
    assert await radio.perform_cad() is True
    info = await radio.perform_cad(calibration=True)
    assert info["detected"] is True and info["cad_done"] is True
    assert chip.regs[sx.REG_OP_MODE] & 0x07 == sx.MODE_RX_CONTINUOUS
    radio.cleanup()


async def test_health_check_from_worker_thread_restarts_rx_task():
    radio, chip, _ = make_radio()
    radio.begin()
    radio.set_rx_callback(lambda _p: None)
    radio._rx_irq_task.cancel()
    await asyncio.sleep(0.05)
    # The dispatcher calls this through asyncio.to_thread
    assert await asyncio.to_thread(radio.check_radio_health) is False
    assert await wait_until(
        lambda: radio._rx_irq_task is not None and not radio._rx_irq_task.done()
    )
    got = []
    radio.set_rx_callback(got.append)
    chip.receive(b"again")
    assert await wait_until(lambda: got)
    radio.cleanup()


def test_configure_radio_rewrites_modulation():
    radio, chip, _ = make_radio()
    radio.begin()
    assert radio.configure_radio(frequency=868_000_000, bandwidth=125_000, spreading_factor=11)
    assert chip.regs[sx.REG_FRF_MSB] == 0xD9
    assert chip.regs[sx.REG_MODEM_CONFIG_1] >> 4 == 7
    assert chip.regs[sx.REG_MODEM_CONFIG_2] >> 4 == 11
    assert chip.regs[sx.REG_MODEM_CONFIG_3] & 0x08  # LDRO for SF11/125k (16.4 ms symbol)
    assert chip.regs[sx.REG_OP_MODE] & 0x07 == sx.MODE_RX_CONTINUOUS
    radio.cleanup()
