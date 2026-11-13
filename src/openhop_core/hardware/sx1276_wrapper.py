"""
SX1276 / SX1278 (RFM95/96/98) LoRa radio for Linux SPI, e.g. the Dragino LoRa/GPS HAT.

Same public surface as SX1262Radio, so the repeater, dispatcher and web UI drive it
unchanged. Registers are accessed directly over spidev; there is no BUSY line on this
chip family, and a single interrupt line (DIO0) is remapped per mode:

    RX      DIO0 = RxDone      (00)
    TX      DIO0 = TxDone      (01)
    CAD     DIO0 = CadDone     (10)

Every edge is resolved by reading RegIrqFlags, so the mapping only decides which event
wakes us. Radio settings mirror MeshCore's CustomSX1276 (RadioLib) defaults: explicit
header, CRC on, AGC on, PA_BOOST output, automatic LDRO above a 16 ms symbol time.
"""

import asyncio
import logging
import math
import random
import threading
import time
from typing import Optional, Union

from ..protocol.packet_utils import calculate_lora_airtime_ms, coding_rate_denominator
from .base import LoRaRadio
from .gpio_manager import GPIOPinManager

logger = logging.getLogger("SX1276_wrapper")

# --- Register map (LoRa mode) -------------------------------------------------
REG_FIFO = 0x00
REG_OP_MODE = 0x01
REG_FRF_MSB = 0x06
REG_FRF_MID = 0x07
REG_FRF_LSB = 0x08
REG_PA_CONFIG = 0x09
REG_OCP = 0x0B
REG_LNA = 0x0C
REG_FIFO_ADDR_PTR = 0x0D
REG_FIFO_TX_BASE_ADDR = 0x0E
REG_FIFO_RX_BASE_ADDR = 0x0F
REG_FIFO_RX_CURRENT_ADDR = 0x10
REG_IRQ_FLAGS_MASK = 0x11
REG_IRQ_FLAGS = 0x12
REG_RX_NB_BYTES = 0x13
REG_MODEM_STAT = 0x18
REG_PKT_SNR_VALUE = 0x19
REG_PKT_RSSI_VALUE = 0x1A
REG_RSSI_VALUE = 0x1B
REG_MODEM_CONFIG_1 = 0x1D
REG_MODEM_CONFIG_2 = 0x1E
REG_SYMB_TIMEOUT_LSB = 0x1F
REG_PREAMBLE_MSB = 0x20
REG_PREAMBLE_LSB = 0x21
REG_PAYLOAD_LENGTH = 0x22
REG_MAX_PAYLOAD_LENGTH = 0x23
REG_MODEM_CONFIG_3 = 0x26
REG_DETECT_OPTIMIZE = 0x31
REG_HIGH_BW_OPTIMIZE_1 = 0x36
REG_DETECTION_THRESHOLD = 0x37
REG_SYNC_WORD = 0x39
REG_HIGH_BW_OPTIMIZE_2 = 0x3A
REG_DIO_MAPPING_1 = 0x40
REG_VERSION = 0x42
REG_PA_DAC = 0x4D

# RegOpMode
LONG_RANGE_MODE = 0x80
MODE_SLEEP = 0x00
MODE_STDBY = 0x01
MODE_TX = 0x03
MODE_RX_CONTINUOUS = 0x05
MODE_CAD = 0x07

# RegIrqFlags
IRQ_RX_TIMEOUT = 0x80
IRQ_RX_DONE = 0x40
IRQ_PAYLOAD_CRC_ERROR = 0x20
IRQ_VALID_HEADER = 0x10
IRQ_TX_DONE = 0x08
IRQ_CAD_DONE = 0x04
IRQ_FHSS_CHANGE = 0x02
IRQ_CAD_DETECTED = 0x01

# RegDioMapping1, DIO0 field (bits 7..6)
DIO0_RX_DONE = 0x00
DIO0_TX_DONE = 0x40
DIO0_CAD_DONE = 0x80

# RegModemStat
MODEM_STAT_SIGNAL_DETECTED = 0x01
MODEM_STAT_SIGNAL_SYNCHRONIZED = 0x02
MODEM_STAT_RX_ONGOING = 0x04
MODEM_STAT_HEADER_INFO_VALID = 0x08

# Accepted silicon versions: SX1276/77/78/79 report 0x12, early SX1272-era parts 0x22.
SUPPORTED_VERSIONS = (0x12, 0x22)

FXOSC = 32_000_000
FSTEP_SHIFT = 19  # Frf = f * 2^19 / FXOSC

# Bandwidth in Hz -> RegModemConfig1 code
BANDWIDTHS = {
    7800: 0,
    10400: 1,
    15600: 2,
    20800: 3,
    31250: 4,
    41700: 5,
    62500: 6,
    125000: 7,
    250000: 8,
    500000: 9,
}

# MeshCore uses the LoRa "private" sync word 0x12. SX126x configs store it as a
# 16-bit value (0x1424, 0x3444 ...); fold those back to the SX127x single byte.
DEFAULT_SYNC_WORD = 0x12


def sx127x_sync_word(sync_word: int) -> int:
    """Return the one-byte SX127x sync word for an SX127x or SX126x-style value."""
    sync_word = int(sync_word)
    if sync_word <= 0xFF:
        return sync_word
    return ((sync_word >> 8) & 0xF0) | ((sync_word >> 4) & 0x0F)


def bandwidth_code(bandwidth_hz: int) -> int:
    """Return the RegModemConfig1 code of the closest supported bandwidth."""
    nearest = min(BANDWIDTHS, key=lambda bw: abs(bw - int(bandwidth_hz)))
    return BANDWIDTHS[nearest]


def frf_bytes(frequency_hz: int) -> tuple[int, int, int]:
    """Return RegFrf MSB/MID/LSB for a carrier frequency in Hz."""
    frf = (int(frequency_hz) << FSTEP_SHIFT) // FXOSC
    return (frf >> 16) & 0xFF, (frf >> 8) & 0xFF, frf & 0xFF


def pa_settings(power_dbm: int) -> tuple[int, int, int]:
    """Return (RegPaConfig, RegPaDac, effective dBm) for PA_BOOST output.

    PA_BOOST gives 2..17 dBm in normal mode; +20 dBm needs the high-power DAC,
    which RadioLib enables only for exactly 20 dBm. 18-19 dBm requests use the
    same high-power path with a lower output setting.
    """
    power = int(power_dbm)
    if power >= 18:
        power = min(power, 20)
        return 0x80 | 0x70 | (power - 5), 0x87, power
    power = max(power, 2)
    return 0x80 | 0x70 | (power - 2), 0x84, power


def ocp_register(current_ma: int) -> int:
    """Return RegOcp enabling over-current protection at the closest trim."""
    current_ma = int(current_ma)
    if current_ma <= 120:
        trim = max(0, (current_ma - 45) // 5)
    else:
        trim = min(27, (current_ma + 30) // 10)
    return 0x20 | trim


def packet_rssi_dbm(raw_rssi: int, snr_db: float, frequency_hz: int) -> float:
    """Packet RSSI per the SX1276 datasheet (section 5.5.5)."""
    offset = -157 if frequency_hz >= 779_000_000 else -164
    if snr_db < 0:
        return offset + raw_rssi + snr_db
    return offset + raw_rssi * 16.0 / 15.0


def snr_from_register(raw_snr: int) -> float:
    """RegPktSnrValue is a signed byte in quarter-dB steps."""
    if raw_snr > 127:
        raw_snr -= 256
    return raw_snr / 4.0


class _SpiRegisters:
    """Register access over spidev with an optional GPIO-driven chip select.

    The Dragino HAT wires NSS to GPIO25 rather than to a hardware CE line, so the
    spidev device only supplies the clock and data lines in that case.
    """

    def __init__(self, transport, gpio_manager, cs_pin: int):
        self._spi = transport
        self._gpio = gpio_manager
        self._cs_pin = cs_pin
        self._lock = threading.RLock()

    @property
    def lock(self) -> threading.RLock:
        return self._lock

    def _xfer(self, data: list[int]) -> list[int]:
        with self._lock:
            if self._cs_pin != -1:
                self._gpio.set_pin_low(self._cs_pin)
            try:
                return self._spi.transfer(data)
            finally:
                if self._cs_pin != -1:
                    self._gpio.set_pin_high(self._cs_pin)

    def read(self, address: int) -> int:
        return self._xfer([address & 0x7F, 0x00])[1]

    def write(self, address: int, value: int) -> None:
        self._xfer([address | 0x80, value & 0xFF])

    def read_burst(self, address: int, length: int) -> bytes:
        if length <= 0:
            return b""
        return bytes(self._xfer([address & 0x7F] + [0x00] * length)[1:])

    def write_burst(self, address: int, data: bytes) -> None:
        if data:
            self._xfer([address | 0x80] + list(data))


class SX1276Radio(LoRaRadio):
    """SX1276 LoRa radio on a Linux SBC, e.g. Raspberry Pi + Dragino LoRa/GPS HAT."""

    _active_instances: set = set()
    _active_instance = None

    # PA_BOOST limit with the high-power DAC
    max_tx_power_dbm = 20

    RADIO_TIMING_DELAY = 0.01
    # RX task wake-up period. Longer than the SX1262 wrapper's 10 ms: a Pi Zero has
    # a single core, and every packet still wakes the task at once through DIO0.
    RX_POLL_INTERVAL = 0.05
    # How often the RX task re-reads RegIrqFlags in case a DIO0 edge was missed.
    IRQ_SAFETY_POLL_S = 1.0

    def __init__(
        self,
        bus_id: int = 0,
        cs_id: int = 0,
        cs_pin: int = 25,
        gpio_chip: int = 0,
        use_gpiod_backend: bool = False,
        reset_pin: int = 17,
        busy_pin: int = -1,
        irq_pin: int = 4,
        txen_pin: int = -1,
        rxen_pin: int = -1,
        txled_pin: int = -1,
        rxled_pin: int = -1,
        en_pin: int = -1,
        en_pins: Optional[list[int]] = None,
        frequency: int = 869618000,
        tx_power: int = 20,
        spreading_factor: int = 8,
        bandwidth: int = 62500,
        coding_rate: int = 5,
        preamble_length: int = 32,  # MeshCore: 32 for SF<=8, 16 above
        sync_word: int = DEFAULT_SYNC_WORD,
        current_limit_ma: int = 120,
        lbt_max_wait_seconds: float = 4.0,
        lbt_retry_interval_ms: int = 200,
        radio_timing_delay: float = RADIO_TIMING_DELAY,
        spi_speed_hz: int = 2_000_000,
        spi_transport=None,
        gpio_manager=None,
        **_ignored,
    ):
        """
        Args mirror SX1262Radio. SX1262-only options (busy_pin, TCXO, DIO2 RF switch,
        Waveshare mode) are accepted and ignored so the same config section works.

        Dragino LoRa/GPS HAT defaults (BCM): NSS 25, RESET 17, DIO0 4.
        """
        if _ignored:
            logger.debug("SX1276: ignoring SX1262-only options %s", sorted(_ignored))

        self.bus_id = bus_id
        self.cs_id = cs_id
        self.cs_pin = cs_pin
        self.gpio_chip = gpio_chip
        self.use_gpiod_backend = use_gpiod_backend
        self.reset_pin = reset_pin
        self.busy_pin = busy_pin
        self.irq_pin_number = irq_pin
        self.txen_pin = txen_pin
        self.rxen_pin = rxen_pin
        self.txled_pin = txled_pin
        self.rxled_pin = rxled_pin
        pins = [p for p in (en_pins or ([] if en_pin in (None, -1) else [en_pin])) if p != -1]
        self.en_pins = pins
        self.en_pin = pins[0] if pins else -1
        self._RADIO_TIMING_DELAY = radio_timing_delay
        self.spi_speed_hz = spi_speed_hz

        self.frequency = int(frequency)
        self.tx_power = int(tx_power)
        self.spreading_factor = int(spreading_factor)
        self.bandwidth = int(bandwidth)
        self.coding_rate = int(coding_rate)
        self.preamble_length = int(preamble_length)
        self.sync_word = int(sync_word)
        self.current_limit_ma = int(current_limit_ma)

        self.lora: Optional[_SpiRegisters] = None  # truthy once the chip answers
        self.last_rssi: int = -99
        self.last_snr: float = 0.0
        self.last_signal_rssi: int = -99
        self._initialized = False
        self._rx_lock = asyncio.Lock()
        self._tx_lock = asyncio.Lock()
        self._tx_buffer_busy = False

        self._spi_transport = spi_transport
        self._owns_spi_transport = spi_transport is None
        if gpio_manager is not None:
            self._gpio_manager = gpio_manager
            self._owns_gpio_manager = False
        else:
            backend = "gpiod" if use_gpiod_backend else "auto"
            self._gpio_manager = GPIOPinManager(
                backend=backend, gpio_chip=f"/dev/gpiochip{gpio_chip}"
            )
            self._owns_gpio_manager = True

        self._interrupt_setup = False
        self._tx_done_event = asyncio.Event()
        self._rx_done_event = asyncio.Event()
        self._cad_event = asyncio.Event()
        self._last_irq_status = 0
        self._last_cad_detected = False
        self._last_cad_irq_status = 0
        self._event_loop = None
        self._shutting_down = False
        self._rx_irq_task = None
        self._last_safety_poll = 0.0

        self.lbt_max_wait_seconds = max(0.5, float(lbt_max_wait_seconds))
        self.lbt_retry_interval_ms = max(20, int(lbt_retry_interval_ms))

        # The SX127x CAD has no tunable thresholds; these are kept so the web UI's
        # calibration endpoints keep working, and reported back unchanged.
        self._custom_cad_peak = None
        self._custom_cad_min = None
        self._custom_cad_symbol_num = None

        self._noise_floor = -120.0
        self._num_floor_samples = 0
        self._floor_sample_sum = 0.0
        self._noise_floor_samples: list[float] = []
        self._last_packet_activity = 0.0
        self._is_receiving_packet = False
        self._last_sample_check = 0.0
        self.NUM_NOISE_FLOOR_SAMPLES = 20
        self.NOISE_FLOOR_UPDATE_INTERVAL = 5.0

        self.crc_error_count = 0
        self.rx_callback = None

        logger.info(
            f"SX1276Radio configured: freq={self.frequency / 1e6:.3f}MHz, "
            f"power={self.tx_power}dBm, sf={self.spreading_factor}, "
            f"bw={self.bandwidth / 1000:.1f}kHz, pre={self.preamble_length}"
        )
        SX1276Radio._active_instances.add(self)
        SX1276Radio._active_instance = self

    # ------------------------------------------------------------------ helpers
    def _set_mode(self, mode: int) -> None:
        self.lora.write(REG_OP_MODE, LONG_RANGE_MODE | mode)

    def _ldro(self, sf: Optional[int] = None, bw: Optional[int] = None) -> bool:
        sf = self.spreading_factor if sf is None else sf
        bw = self.bandwidth if bw is None else bw
        return (2**sf) / (bw / 1000.0) >= 16.0

    def _write_modulation(self, sf: int, bw: int, cr: int) -> None:
        """Write SF/BW/CR plus the registers that depend on them. Radio must be idle."""
        cr_code = min(max(int(cr), 5), 8) - 4
        self.lora.write(REG_MODEM_CONFIG_1, (bandwidth_code(bw) << 4) | (cr_code << 1))
        # Explicit header (bit0 of ModemConfig1 = 0), RX payload CRC on
        self.lora.write(REG_MODEM_CONFIG_2, ((int(sf) & 0x0F) << 4) | 0x04)
        self.lora.write(REG_MODEM_CONFIG_3, (0x08 if self._ldro(sf, bw) else 0x00) | 0x04)

        detect = self.lora.read(REG_DETECT_OPTIMIZE) & 0xF8
        if sf == 6:
            self.lora.write(REG_DETECT_OPTIMIZE, detect | 0x05)
            self.lora.write(REG_DETECTION_THRESHOLD, 0x0C)
        else:
            self.lora.write(REG_DETECT_OPTIMIZE, detect | 0x03)
            self.lora.write(REG_DETECTION_THRESHOLD, 0x0A)

        # Errata 2.1: sensitivity optimisation for 500 kHz bandwidth
        if bandwidth_code(bw) == 9 and self.frequency >= 779_000_000:
            self.lora.write(REG_HIGH_BW_OPTIMIZE_1, 0x02)
            self.lora.write(REG_HIGH_BW_OPTIMIZE_2, 0x64)
        else:
            self.lora.write(REG_HIGH_BW_OPTIMIZE_1, 0x03)

    def _write_frequency(self, frequency: int) -> None:
        msb, mid, lsb = frf_bytes(frequency)
        self.lora.write(REG_FRF_MSB, msb)
        self.lora.write(REG_FRF_MID, mid)
        self.lora.write(REG_FRF_LSB, lsb)

    def _write_tx_power(self, power: int) -> int:
        pa_config, pa_dac, effective = pa_settings(power)
        self.lora.write(REG_PA_CONFIG, pa_config)
        self.lora.write(REG_PA_DAC, pa_dac)
        self.lora.write(REG_OCP, ocp_register(self.current_limit_ma))
        return effective

    def _write_preamble(self, preamble: int) -> None:
        self.lora.write(REG_PREAMBLE_MSB, (preamble >> 8) & 0xFF)
        self.lora.write(REG_PREAMBLE_LSB, preamble & 0xFF)

    def _clear_irq(self) -> None:
        self.lora.write(REG_IRQ_FLAGS, 0xFF)

    def _start_rx_continuous(self) -> None:
        """Standby, map DIO0 to RxDone, reset the FIFO and listen."""
        with self.lora.lock:
            self._control_tx_rx_pins(tx_mode=False)
            self._set_mode(MODE_STDBY)
            self.lora.write(REG_DIO_MAPPING_1, DIO0_RX_DONE)
            self.lora.write(REG_FIFO_RX_BASE_ADDR, 0x00)
            self.lora.write(REG_FIFO_ADDR_PTR, 0x00)
            self._clear_irq()
            self._set_mode(MODE_RX_CONTINUOUS)

    def _control_tx_rx_pins(self, tx_mode: bool) -> None:
        if self.txen_pin != -1:
            (self._gpio_manager.set_pin_high if tx_mode else self._gpio_manager.set_pin_low)(
                self.txen_pin
            )
        if self.rxen_pin != -1:
            (self._gpio_manager.set_pin_low if tx_mode else self._gpio_manager.set_pin_high)(
                self.rxen_pin
            )

    def _reset_noise_floor(self) -> None:
        self._noise_floor = -120.0
        self._num_floor_samples = 0
        self._floor_sample_sum = 0.0
        self._noise_floor_samples = []

    def _ensure_event_loop(self) -> None:
        if self._event_loop is None:
            try:
                self._event_loop = asyncio.get_running_loop()
            except RuntimeError:
                pass

    def _start_rx_task(self) -> None:
        if self._rx_irq_task is not None and not self._rx_irq_task.done():
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # Called from a worker thread (the dispatcher runs check_radio_health via
            # asyncio.to_thread): hop onto the radio's loop instead.
            loop = self._event_loop
            if loop is not None and not loop.is_closed():
                loop.call_soon_threadsafe(self._start_rx_task)
            else:
                logger.debug("No event loop yet; RX task starts with set_rx_callback()")
            return
        self._event_loop = loop
        self._rx_irq_task = loop.create_task(self._rx_irq_background_task())
        logger.debug("[RX] RX IRQ background task started")

    # --------------------------------------------------------------- lifecycle
    def begin(self) -> bool:
        if self._initialized:
            return True
        self._shutting_down = False

        try:
            if self._spi_transport is None:
                from .transports.spidev_transport import SPIDevTransport

                self._spi_transport = SPIDevTransport()
            if not self._spi_transport.is_open and not self._spi_transport.open(
                self.bus_id, self.cs_id, self.spi_speed_hz
            ):
                raise RuntimeError(f"cannot open /dev/spidev{self.bus_id}.{self.cs_id}")

            if self.cs_pin != -1 and not self._gpio_manager.setup_output_pin(
                self.cs_pin, initial_value=True
            ):
                raise RuntimeError(f"cannot drive NSS pin {self.cs_pin}")
            regs = _SpiRegisters(self._spi_transport, self._gpio_manager, self.cs_pin)

            for pin in self.en_pins:
                self._gpio_manager.setup_output_pin(pin, initial_value=True)
            for pin in (self.txen_pin, self.rxen_pin, self.txled_pin, self.rxled_pin):
                if pin != -1:
                    self._gpio_manager.setup_output_pin(pin, initial_value=False)
            if self.en_pins:
                time.sleep(0.1)

            # Hardware reset: RESET is active low; the chip is ready 5 ms after release
            if self.reset_pin != -1:
                self._gpio_manager.setup_output_pin(self.reset_pin, initial_value=True)
                self._gpio_manager.set_pin_low(self.reset_pin)
                time.sleep(0.002)
                self._gpio_manager.set_pin_high(self.reset_pin)
                time.sleep(0.01)

            version = regs.read(REG_VERSION)
            if version not in SUPPORTED_VERSIONS:
                raise RuntimeError(
                    f"SX1276 not found (RegVersion=0x{version:02X}); "
                    "check that SPI is enabled, the HAT is seated and the pins are right"
                )
            logger.info(f"SX1276 detected (RegVersion=0x{version:02X})")
            self.lora = regs

            with regs.lock:
                # LongRangeMode can only change in sleep
                regs.write(REG_OP_MODE, MODE_SLEEP)
                time.sleep(self._RADIO_TIMING_DELAY)
                self._set_mode(MODE_SLEEP)
                time.sleep(self._RADIO_TIMING_DELAY)
                self._set_mode(MODE_STDBY)
                time.sleep(self._RADIO_TIMING_DELAY)

                self._write_frequency(self.frequency)
                effective = self._write_tx_power(self.tx_power)
                if effective != self.tx_power:
                    logger.warning(
                        f"TX power {self.tx_power} dBm not available on PA_BOOST, using "
                        f"{effective} dBm"
                    )
                    self.tx_power = effective
                regs.write(REG_LNA, 0x23)  # max gain, HF LNA boost (AGC overrides gain)
                self._write_modulation(self.spreading_factor, self.bandwidth, self.coding_rate)
                self._write_preamble(self.preamble_length)
                regs.write(REG_SYNC_WORD, sx127x_sync_word(self.sync_word))
                regs.write(REG_SYMB_TIMEOUT_LSB, 0x64)
                regs.write(REG_MAX_PAYLOAD_LENGTH, 0xFF)
                regs.write(REG_FIFO_TX_BASE_ADDR, 0x00)
                regs.write(REG_FIFO_RX_BASE_ADDR, 0x00)
                regs.write(REG_IRQ_FLAGS_MASK, 0x00)
                self._clear_irq()

            logger.info(
                f"LDRO {'enabled' if self._ldro() else 'disabled'}, "
                f"sync word 0x{sx127x_sync_word(self.sync_word):02X}"
            )

            irq = self._gpio_manager.setup_interrupt_pin(
                self.irq_pin_number, pull_up=False, callback=self._irq_trampoline
            )
            if irq is None:
                raise RuntimeError(f"could not set up DIO0 interrupt on GPIO{self.irq_pin_number}")
            self._interrupt_setup = True

            self._start_rx_continuous()
            time.sleep(self._RADIO_TIMING_DELAY)
            self._initialized = True
            logger.info("SX1276 radio initialized successfully")
            self._start_rx_task()
            return True
        except Exception as e:
            logger.error(f"Failed to initialize SX1276 radio: '{e}'")
            self._initialized = False
            raise RuntimeError(f"Failed to initialize SX1276 radio: {e}") from e

    def cleanup(self) -> None:
        self._shutting_down = True
        self._event_loop = None
        self._interrupt_setup = False
        if self._rx_irq_task is not None and not self._rx_irq_task.done():
            self._rx_irq_task.cancel()
        if self.lora is not None:
            try:
                self._set_mode(MODE_SLEEP)
            except Exception as e:
                logger.debug(f"Could not put SX1276 to sleep during cleanup: {e}")
        if self._owns_spi_transport and self._spi_transport is not None:
            try:
                self._spi_transport.close()
            except Exception:
                pass
        if self._gpio_manager is not None:
            if self._owns_gpio_manager:
                self._gpio_manager.cleanup_all()
            else:
                for pin in {
                    self.irq_pin_number,
                    self.reset_pin,
                    self.cs_pin,
                    self.txen_pin,
                    self.rxen_pin,
                    self.txled_pin,
                    self.rxled_pin,
                    *self.en_pins,
                }:
                    if pin not in (None, -1):
                        try:
                            self._gpio_manager.cleanup_pin(pin)
                        except Exception:
                            pass
        self._initialized = False
        SX1276Radio._active_instances.discard(self)
        if SX1276Radio._active_instance is self:
            SX1276Radio._active_instance = next(iter(SX1276Radio._active_instances), None)

    # --------------------------------------------------------------- interrupts
    def _irq_trampoline(self):
        """Called from the GPIO thread: hop onto the event loop."""
        if self._shutting_down:
            return
        loop = self._event_loop
        if loop is None:
            return
        try:
            loop.call_soon_threadsafe(self._handle_interrupt)
        except RuntimeError as e:
            if "Event loop is closed" in str(e):
                self._event_loop = None
            else:
                logger.error(f"IRQ trampoline runtime error: {e}")

    def _handle_interrupt(self):
        """Read and clear RegIrqFlags, then wake whichever path is waiting."""
        try:
            if not self._initialized or self.lora is None:
                return
            with self.lora.lock:
                flags = self.lora.read(REG_IRQ_FLAGS)
                if not flags:
                    return
                self._clear_irq()
            self._dispatch_irq(flags)
        except Exception as e:
            logger.error(f"IRQ handler error: {e}")
            self._tx_done_event.set()
            if not self._tx_buffer_busy:
                self._rx_done_event.set()

    def _dispatch_irq(self, flags: int) -> None:
        if flags & IRQ_TX_DONE:
            self._tx_done_event.set()
        if flags & IRQ_CAD_DONE:
            self._last_cad_detected = bool(flags & IRQ_CAD_DETECTED)
            self._last_cad_irq_status = flags
            self._cad_event.set()
        if flags & (IRQ_RX_DONE | IRQ_RX_TIMEOUT):
            self._last_irq_status = flags
            if not self._tx_buffer_busy:
                self._rx_done_event.set()
            else:
                logger.debug(f"[RX] Ignoring RX IRQ 0x{flags:02X} during TX")

    def set_rx_callback(self, callback):
        self.rx_callback = callback
        if self._interrupt_setup and self._initialized:
            self._start_rx_task()

    def check_radio_health(self) -> bool:
        if not self._initialized:
            return False
        if self._rx_irq_task is None or self._rx_irq_task.done():
            self._start_rx_task()
            logger.warning("[RX] RX task was not running; restart requested")
            return False
        return True

    # ----------------------------------------------------------------------- RX
    def _read_packet(self) -> Optional[bytes]:
        """Read the packet that raised RxDone and refresh RSSI/SNR."""
        with self.lora.lock:
            length = self.lora.read(REG_RX_NB_BYTES)
            start = self.lora.read(REG_FIFO_RX_CURRENT_ADDR)
            snr = snr_from_register(self.lora.read(REG_PKT_SNR_VALUE))
            raw_rssi = self.lora.read(REG_PKT_RSSI_VALUE)
            self.lora.write(REG_FIFO_ADDR_PTR, start)
            payload = self.lora.read_burst(REG_FIFO, length)
        rssi = packet_rssi_dbm(raw_rssi, snr, self.frequency)
        self.last_snr = snr
        self.last_rssi = int(round(rssi))
        self.last_signal_rssi = self.last_rssi
        return payload if length > 0 else None

    async def _rx_irq_background_task(self):
        logger.debug("[RX] Starting RX IRQ background task")
        while self._initialized:
            try:
                try:
                    await asyncio.wait_for(
                        self._rx_done_event.wait(), timeout=self.RX_POLL_INTERVAL
                    )
                except asyncio.TimeoutError:
                    self._safety_poll_irq()
                    self._sample_noise_floor()
                    continue
                self._rx_done_event.clear()

                self._is_receiving_packet = True
                self._last_packet_activity = time.time()
                packet = None
                try:
                    async with self._rx_lock:
                        flags = self._last_irq_status
                        if flags & IRQ_RX_DONE and flags & IRQ_PAYLOAD_CRC_ERROR:
                            self.crc_error_count += 1
                            logger.warning(
                                f"[RX] CRC error #{self.crc_error_count} (IRQ 0x{flags:02X})"
                            )
                        elif flags & IRQ_RX_DONE:
                            packet = self._read_packet()
                            if packet is None:
                                logger.warning("[RX] Empty packet received")
                            else:
                                logger.debug(
                                    "[RX] Packet received: length=%d, RSSI=%ddBm, SNR=%.1fdB",
                                    len(packet),
                                    self.last_rssi,
                                    self.last_snr,
                                )
                                self._gpio_manager.blink_led(self.rxled_pin)
                        elif flags & IRQ_RX_TIMEOUT:
                            logger.debug("[RX] RX timeout")

                        if not self._tx_lock.locked():
                            self._start_rx_continuous()
                    if packet is not None:
                        if self.rx_callback:
                            try:
                                self.rx_callback(packet)
                            except Exception as cb_exc:
                                logger.error(f"RX callback error: {cb_exc}")
                        else:
                            logger.warning("[RX] No RX callback registered!")
                except Exception as e:
                    logger.error(f"[IRQ RX] Error processing received packet: {e}")
                finally:
                    self._is_receiving_packet = False
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[RX Task] Unexpected error: {e}")
                await asyncio.sleep(1.0)
        logger.debug("[RX] RX IRQ background task exiting")

    def _safety_poll_irq(self) -> None:
        """Catch an RxDone whose DIO0 edge was missed (e.g. GPIO thread hiccup)."""
        now = time.monotonic()
        if now - self._last_safety_poll < self.IRQ_SAFETY_POLL_S:
            return
        self._last_safety_poll = now
        if self._tx_lock.locked() or self.lora is None:
            return
        try:
            with self.lora.lock:
                flags = self.lora.read(REG_IRQ_FLAGS)
                if not flags & (IRQ_RX_DONE | IRQ_RX_TIMEOUT):
                    return
                self._clear_irq()
            logger.debug(f"[RX] Picked up missed IRQ 0x{flags:02X} by polling")
            self._dispatch_irq(flags)
        except Exception as e:
            logger.debug(f"[RX] Safety poll failed: {e}")

    def is_receiving_packet(self) -> bool:
        """MeshCore CustomSX1276::isReceiving(): signal detected, synced or header seen."""
        if not self._initialized or self.lora is None:
            return False
        try:
            stat = self.lora.read(REG_MODEM_STAT)
        except Exception:
            return False
        return bool(
            stat
            & (
                MODEM_STAT_SIGNAL_DETECTED
                | MODEM_STAT_SIGNAL_SYNCHRONIZED
                | MODEM_STAT_HEADER_INFO_VALID
            )
        )

    async def wait_for_rx(self) -> bytes:
        raise NotImplementedError(
            "Use set_rx_callback(callback) to receive packets asynchronously."
        )

    # ----------------------------------------------------------------------- TX
    def _calculate_tx_timeout(self, packet_length: int) -> tuple[int, int]:
        air_time_ms = calculate_lora_airtime_ms(
            packet_length,
            self.spreading_factor,
            int(self.bandwidth),
            coding_rate_denominator(self.coding_rate),
            self.preamble_length,
        )
        timeout_ms = math.ceil(air_time_ms) + 1000
        return timeout_ms, timeout_ms

    async def _listen_before_talk(self) -> list[int]:
        """Same time-bounded LBT as the SX1262 wrapper (MeshCore: 200 ms retry, 4 s cap)."""
        delays: list[int] = []
        deadline = time.monotonic() + self.lbt_max_wait_seconds
        while True:
            try:
                if self.is_receiving_packet():
                    busy = True
                    logger.debug("[LBT] Reception in progress - deferring TX")
                else:
                    busy = await self.perform_cad(timeout=0.5, respect_tx_lock=False)
            except Exception as e:
                logger.warning(f"[LBT] Channel check failed: {e}, proceeding with transmission")
                break
            if not busy:
                break
            if time.monotonic() >= deadline:
                logger.warning(
                    f"[LBT] Budget exhausted ({self.lbt_max_wait_seconds:.1f}s) - "
                    "channel still busy, transmitting anyway"
                )
                break
            delay_ms = self.lbt_retry_interval_ms * random.uniform(0.5, 1.5)
            delay_ms = max(10.0, min(delay_ms, (deadline - time.monotonic()) * 1000.0))
            delays.append(round(delay_ms))
            await asyncio.sleep(delay_ms / 1000.0)
        if delays:
            logger.debug(f"[LBT] Summary: {len(delays)} deferral(s) {delays}")
        return delays

    async def send(self, data: bytes) -> dict:
        if not self._initialized or self.lora is None:
            raise RuntimeError("Radio not initialized")
        if len(data) > 255:
            raise ValueError(f"Packet too long for SX1276: {len(data)} bytes")
        self._ensure_event_loop()

        async with self._tx_lock:
            try:
                final_timeout_ms, _ = self._calculate_tx_timeout(len(data))
                airtime_ms = final_timeout_ms - 1000
                lbt_delays = await self._listen_before_talk()

                self._tx_buffer_busy = True
                self._tx_done_event.clear()
                with self.lora.lock:
                    self._set_mode(MODE_STDBY)
                    self.lora.write(REG_DIO_MAPPING_1, DIO0_TX_DONE)
                    self._clear_irq()
                    self.lora.write(REG_FIFO_TX_BASE_ADDR, 0x00)
                    self.lora.write(REG_FIFO_ADDR_PTR, 0x00)
                    self.lora.write_burst(REG_FIFO, bytes(data))
                    self.lora.write(REG_PAYLOAD_LENGTH, len(data))
                    self._control_tx_rx_pins(tx_mode=True)
                    self._set_mode(MODE_TX)

                try:
                    await asyncio.wait_for(
                        self._tx_done_event.wait(), timeout=final_timeout_ms / 1000.0 + 0.5
                    )
                except asyncio.TimeoutError:
                    # Last chance: the flag may be set with the edge lost
                    if not self.lora.read(REG_IRQ_FLAGS) & IRQ_TX_DONE:
                        raise RuntimeError("TX completion timeout")
                self._tx_done_event.clear()
                self._gpio_manager.blink_led(self.txled_pin)
                logger.debug(f"[TX] Done {len(data)}B airtime={airtime_ms:.0f}ms")
                return {
                    "airtime_ms": airtime_ms,
                    "lbt_attempts": len(lbt_delays),
                    "lbt_backoff_delays_ms": lbt_delays,
                    "lbt_channel_busy": len(lbt_delays) > 0,
                }
            except Exception as e:
                logger.error(f"[TX] Send failed: {e}")
                raise
            finally:
                self._tx_buffer_busy = False
                try:
                    self._start_rx_continuous()
                except Exception as e:
                    logger.warning(f"[RX] Failed to restore RX mode: {e}")

    # ---------------------------------------------------------------------- CAD
    async def perform_cad(
        self,
        det_peak: Optional[int] = None,
        det_min: Optional[int] = None,
        timeout: float = 1.0,
        calibration: bool = False,
        cad_symbol_num: Optional[int] = None,
        respect_tx_lock: bool = True,
    ) -> Union[bool, dict]:
        """Channel Activity Detection. Threshold arguments are accepted for API parity;
        the SX127x CAD detector is not tunable."""
        if not self._initialized or self.lora is None:
            raise RuntimeError("Radio not initialized")
        self._ensure_event_loop()
        if det_peak is None or det_min is None:
            det_peak, det_min = self._get_thresholds_for_current_settings()

        def result(detected: bool, cad_done: bool, **extra):
            if not calibration:
                return detected
            return {
                "frequency": self.frequency,
                "sf": self.spreading_factor,
                "bw": self.bandwidth,
                "det_peak": det_peak,
                "det_min": det_min,
                "cad_symbol_num": cad_symbol_num or 2,
                "detected": detected,
                "cad_done": cad_done,
                "timestamp": time.time(),
                **extra,
            }

        acquired = False
        try:
            if respect_tx_lock:
                try:
                    await asyncio.wait_for(
                        self._tx_lock.acquire(), timeout=max(0.1, timeout + 0.25)
                    )
                    acquired = True
                except asyncio.TimeoutError:
                    return result(False, False, error="cad_waited_for_tx_lock_timeout")

            self._cad_event.clear()
            with self.lora.lock:
                self._set_mode(MODE_STDBY)
                self.lora.write(REG_DIO_MAPPING_1, DIO0_CAD_DONE)
                self._clear_irq()
                self._set_mode(MODE_CAD)

            try:
                await asyncio.wait_for(self._cad_event.wait(), timeout=timeout)
                self._cad_event.clear()
                return result(self._last_cad_detected, True, irq_status=self._last_cad_irq_status)
            except asyncio.TimeoutError:
                flags = self.lora.read(REG_IRQ_FLAGS)
                if flags & IRQ_CAD_DONE:
                    self._clear_irq()
                    return result(bool(flags & IRQ_CAD_DETECTED), True, irq_status=flags)
                logger.debug("[CAD] Timed out - assuming clear")
                return result(False, False, irq_status=flags, timeout=True)
        except Exception as e:
            logger.error(f"[CAD] Scan failed: {e}")
            return result(False, False, error=str(e))
        finally:
            try:
                if acquired or not self._tx_lock.locked():
                    self._start_rx_continuous()
                if acquired:
                    self._reset_noise_floor()
            except Exception as e:
                logger.warning(f"[CAD] Failed to restore RX mode: {e}")
            if acquired and self._tx_lock.locked():
                self._tx_lock.release()

    def set_custom_cad_thresholds(self, peak: int, min_val: int) -> None:
        if not (0 <= peak <= 255) or not (0 <= min_val <= 255):
            raise ValueError("CAD thresholds must be between 0 and 255")
        self._custom_cad_peak = peak
        self._custom_cad_min = min_val
        logger.info("[CAD] SX1276 CAD thresholds are fixed in silicon; values stored only")

    def clear_custom_cad_thresholds(self) -> None:
        self._custom_cad_peak = None
        self._custom_cad_min = None

    def set_custom_cad_symbol_num(self, cad_symbol_num: int) -> None:
        if cad_symbol_num not in {1, 2, 4, 8, 16}:
            raise ValueError("cad_symbol_num must be one of: 1, 2, 4, 8, 16")
        self._custom_cad_symbol_num = int(cad_symbol_num)

    def _get_thresholds_for_current_settings(self) -> tuple[int, int]:
        if self._custom_cad_peak is not None and self._custom_cad_min is not None:
            return (self._custom_cad_peak, self._custom_cad_min)
        return (22, 10)

    # ------------------------------------------------------------- noise floor
    def _sample_noise_floor(self) -> None:
        if not self._initialized or self.lora is None:
            return
        now = time.time()
        if now - self._last_sample_check < self.NOISE_FLOOR_UPDATE_INTERVAL:
            return
        if self._tx_lock.locked() or self._is_receiving_packet:
            return
        if now - self._last_packet_activity < 0.5:
            return
        self._last_sample_check = now
        try:
            with self.lora.lock:
                if self.lora.read(REG_MODEM_STAT) & (
                    MODEM_STAT_SIGNAL_DETECTED | MODEM_STAT_HEADER_INFO_VALID
                ):
                    return
                raw = self.lora.read(REG_RSSI_VALUE)
            offset = -157 if self.frequency >= 779_000_000 else -164
            rssi = float(offset + raw)
            if not (-164.0 <= rssi < 0.0):
                return
            self._noise_floor_samples.append(rssi)
            if len(self._noise_floor_samples) > self.NUM_NOISE_FLOOR_SAMPLES:
                self._noise_floor_samples.pop(0)
            self._num_floor_samples = len(self._noise_floor_samples)
            self._floor_sample_sum = sum(self._noise_floor_samples)
            self._noise_floor = self._floor_sample_sum / self._num_floor_samples
        except Exception as e:
            logger.debug(f"Failed to sample noise floor: {e}")

    def get_noise_floor(self) -> Optional[float]:
        if not self._initialized or self.lora is None or self._tx_lock.locked():
            return None
        if self._num_floor_samples <= 0:
            return None
        return self._noise_floor

    # ------------------------------------------------------------- settings
    def _safe_radio_operation(self, name: str, func, success_msg: Optional[str] = None) -> bool:
        if not self._initialized or self.lora is None:
            return False
        try:
            with self.lora.lock:
                func()
            if success_msg:
                logger.debug(success_msg)
            return True
        except Exception as e:
            logger.error(f"Failed to {name}: {e}")
            return False

    def _reconfigure(self, apply) -> None:
        """Run a register change from standby, then go back to RX."""
        self._set_mode(MODE_STDBY)
        apply()
        if not self._tx_lock.locked():
            self._start_rx_continuous()

    def set_frequency(self, frequency: int) -> bool:
        def op():
            self.frequency = int(frequency)
            self._reconfigure(lambda: self._write_frequency(self.frequency))

        return self._safe_radio_operation(
            "set frequency", op, f"Frequency set to {frequency / 1e6:.3f} MHz"
        )

    def set_tx_power(self, power: int) -> bool:
        def op():
            self.tx_power = self._write_tx_power(power)

        return self._safe_radio_operation("set TX power", op, f"TX power set to {power} dBm")

    def set_spreading_factor(self, sf: int) -> bool:
        def op():
            self.spreading_factor = int(sf)
            self._reconfigure(
                lambda: self._write_modulation(
                    self.spreading_factor, self.bandwidth, self.coding_rate
                )
            )

        return self._safe_radio_operation("set spreading factor", op, f"SF set to {sf}")

    def set_bandwidth(self, bw: int) -> bool:
        def op():
            self.bandwidth = int(bw)
            self._reconfigure(
                lambda: self._write_modulation(
                    self.spreading_factor, self.bandwidth, self.coding_rate
                )
            )

        return self._safe_radio_operation(
            "set bandwidth", op, f"Bandwidth set to {bw / 1000:.1f} kHz"
        )

    def set_coding_rate(self, cr: int) -> bool:
        def op():
            self.coding_rate = int(cr)
            self._reconfigure(
                lambda: self._write_modulation(
                    self.spreading_factor, self.bandwidth, self.coding_rate
                )
            )

        return self._safe_radio_operation("set coding rate", op, f"Coding rate set to 4/{cr}")

    def set_preamble_length(self, preamble: int) -> bool:
        def op():
            self.preamble_length = int(preamble)
            self._reconfigure(lambda: self._write_preamble(self.preamble_length))

        return self._safe_radio_operation("set preamble", op, f"Preamble set to {preamble}")

    def set_sync_word(self, sync_word: int) -> bool:
        def op():
            self.sync_word = int(sync_word)
            self._reconfigure(
                lambda: self.lora.write(REG_SYNC_WORD, sx127x_sync_word(self.sync_word))
            )

        return self._safe_radio_operation("set sync word", op, f"Sync word set to {sync_word:#x}")

    def configure_radio(
        self,
        frequency: Optional[int] = None,
        bandwidth: Optional[int] = None,
        spreading_factor: Optional[int] = None,
        coding_rate: Optional[int] = None,
    ) -> bool:
        if not self._initialized or self.lora is None:
            logger.error("Cannot configure radio: not initialised")
            return False
        deadline = time.monotonic() + 10.0
        while self._tx_lock.locked():
            if time.monotonic() > deadline:
                logger.error("configure_radio: TX did not complete within 10s")
                return False
            time.sleep(0.05)

        freq = int(frequency if frequency is not None else self.frequency)
        bw = int(bandwidth if bandwidth is not None else self.bandwidth)
        sf = int(spreading_factor if spreading_factor is not None else self.spreading_factor)
        cr = int(coding_rate if coding_rate is not None else self.coding_rate)
        try:
            with self.lora.lock:
                self._set_mode(MODE_STDBY)
                time.sleep(self._RADIO_TIMING_DELAY)
                self.frequency = freq
                self._write_frequency(freq)
                self._write_modulation(sf, bw, cr)
                self.bandwidth, self.spreading_factor, self.coding_rate = bw, sf, cr
                self._reset_noise_floor()
                self._start_rx_continuous()
            logger.info(
                "Radio reconfigured: %.3f MHz BW=%.1f kHz SF%d CR4/%d",
                freq / 1e6,
                bw / 1000,
                sf,
                cr,
            )
            return True
        except Exception as e:
            logger.error("Failed to configure radio: %s", e)
            return False

    # ---------------------------------------------------------------- getters
    def sleep(self) -> None:
        if self._initialized and self.lora:
            try:
                self._set_mode(MODE_SLEEP)
            except Exception as e:
                logger.error(f"Failed to put radio to sleep: {e}")

    def get_last_rssi(self) -> int:
        return self.last_rssi

    def get_last_snr(self) -> float:
        return self.last_snr

    def get_last_signal_rssi(self) -> int:
        return self.last_signal_rssi

    def get_frequency(self) -> int:
        return self.frequency

    def get_tx_power(self) -> int:
        return self.tx_power

    def get_spreading_factor(self) -> int:
        return self.spreading_factor

    def get_bandwidth(self) -> int:
        return self.bandwidth

    def get_coding_rate(self) -> int:
        return self.coding_rate

    def get_status(self) -> dict:
        return {
            "initialized": self._initialized,
            "chip": "SX1276",
            "frequency": self.frequency,
            "tx_power": self.tx_power,
            "spreading_factor": self.spreading_factor,
            "bandwidth": self.bandwidth,
            "coding_rate": self.coding_rate,
            "last_rssi": self.last_rssi,
            "last_snr": self.last_snr,
            "last_signal_rssi": self.last_signal_rssi,
            "crc_error_count": self.crc_error_count,
            "hardware_ready": bool(self._initialized and self.lora),
        }

    @classmethod
    def get_instance(cls, **kwargs):
        if cls._active_instance is not None:
            return cls._active_instance
        return cls(**kwargs)


def create_sx1276_radio(**kwargs) -> SX1276Radio:
    radio = SX1276Radio(**kwargs)
    radio.begin()
    return radio
