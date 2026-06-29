"""
SX1262 LoRa Radio Driver for Raspberry Pi
Implements the LoRaRadio interface using the SX126x library
"""

import asyncio
import logging
import math
import random
import time
from typing import Optional, Union

from .base import LoRaRadio
from .gpio_manager import GPIOPinManager
from .lora.LoRaRF.SX126x import SX126x, set_gpio_manager

logger = logging.getLogger("SX1262_wrapper")


class SX1262Radio(LoRaRadio):
    """SX1262 LoRa Radio implementation for Raspberry Pi"""

    # Class variable to track the active instance (singleton-like behavior)
    _active_instance = None

    # Common timing constants to avoid magic numbers
    RADIO_TIMING_DELAY = 0.01  # 10ms delay for standard radio operations

    def __init__(
        self,
        bus_id: int = 0,
        cs_id: int = 0,
        cs_pin: int = -1,
        gpio_chip: int = 0,
        use_gpiod_backend: bool = False,
        reset_pin: int = 18,
        busy_pin: int = 20,
        irq_pin: int = 16,
        txen_pin: int = 6,
        rxen_pin: int = -1,
        txled_pin: int = -1,
        rxled_pin: int = -1,
        en_pin: int = -1,
        en_pins: Optional[list[int]] = None,
        frequency: int = 868000000,
        tx_power: int = 22,
        spreading_factor: int = 7,
        bandwidth: int = 125000,
        coding_rate: int = 5,
        preamble_length: int = 12,
        sync_word: int = 0x3444,
        is_waveshare: bool = False,
        use_dio3_tcxo: bool = False,
        dio3_tcxo_voltage: float = 1.8,
        use_dio2_rf: bool = False,
        radio_timing_delay: float = RADIO_TIMING_DELAY,
    ):
        """
        Initialize SX1262 radio

        Args:
            bus_id: SPI bus ID (default: 0)
            cs_id: SPI chip select ID (default: 0)
            cs_pin: Manual CS GPIO pin (-1 = use hardware CS, e.g. 21 for Waveshare HAT)
            gpio_chip: GPIO chip select ID (default: 0)
            use_gpiod_backend: Use alternative backend for GPIO support (default: False)
            reset_pin: GPIO pin for reset (default: 18)
            busy_pin: GPIO pin for busy signal (default: 20)
            irq_pin: GPIO pin for interrupt (default: 16)
            txen_pin: GPIO pin for TX enable (default: 6)
            rxen_pin: GPIO pin for RX enable (default: -1 if not used)
            txled_pin: GPIO pin for TX LED (default: -1 if not used)
            rxled_pin: GPIO pin for RX LED (default: -1 if not used)
            en_pin: GPIO pin for powering up the radio goes high on init
            en_pins: GPIO pins for powering up the radio that go high on init
            frequency: Operating frequency in Hz (default: 868MHz)
            tx_power: TX power in dBm (default: 22)
            spreading_factor: LoRa spreading factor (default: 7)
            bandwidth: Bandwidth in Hz (default: 125kHz)
            coding_rate: Coding rate (default: 5 for 4/5)
            preamble_length: Preamble length (default: 12)
            sync_word: Sync word (default: 0x3444 for public network)
            is_waveshare: Use alternate initialization needed for Waveshare HAT
            use_dio3_tcxo: Enable DIO3 TCXO control (default: False)
            dio3_tcxo_voltage: TCXO reference voltage in volts (default: 1.8)
            use_dio2_rf: Enable DIO2 as RF switch control (default: False)
            radio_timing_delay: Delay used for radio state transitions (default: 10ms)
        """
        # Check if there's already an active instance and clean it up
        if SX1262Radio._active_instance is not None:
            logger.warning("Another SX1262Radio instance is already active - cleaning it up first")
            try:
                SX1262Radio._active_instance.cleanup()
            except Exception as e:
                logger.error(f"Error cleaning up previous instance: {e}")
            SX1262Radio._active_instance = None

        self.en_pins = self._normalize_en_pins(en_pin=en_pin, en_pins=en_pins)

        self.bus_id = bus_id
        self.cs_id = cs_id
        self.cs_pin = cs_pin
        self.gpio_chip = gpio_chip
        self.use_gpiod_backend = use_gpiod_backend
        self.reset_pin = reset_pin
        self.busy_pin = busy_pin
        self.irq_pin_number = irq_pin  # Store pin number
        self.txen_pin = txen_pin
        self.rxen_pin = rxen_pin
        self.txled_pin = txled_pin
        self.rxled_pin = rxled_pin
        self.en_pin = self.en_pins[0] if self.en_pins else -1
        self._RADIO_TIMING_DELAY = radio_timing_delay

        # Radio configuration
        self.frequency = frequency
        self.tx_power = tx_power
        self.spreading_factor = spreading_factor
        self.bandwidth = bandwidth
        self.coding_rate = coding_rate
        self.preamble_length = preamble_length
        self.sync_word = sync_word
        self.is_waveshare = is_waveshare
        self.use_dio3_tcxo = use_dio3_tcxo
        self.dio3_tcxo_voltage = dio3_tcxo_voltage
        self.use_dio2_rf = use_dio2_rf

        # State variables
        self.lora: Optional[SX126x] = None
        self.last_rssi: int = -99
        self.last_snr: float = 0.0
        self.last_signal_rssi: int = -99
        self._initialized = False
        self._rx_lock = asyncio.Lock()
        self._tx_lock = asyncio.Lock()

        # GPIO management - check if external GPIO manager is already set (e.g. CH341)
        from .lora.LoRaRF.SX126x import _gpio_manager as existing_gpio_manager

        if existing_gpio_manager is not None:
            # Use externally configured GPIO manager (e.g. CH341GPIOManager)
            self._gpio_manager = existing_gpio_manager
            logger.info("Using externally configured GPIO manager")
        else:
            backend = "gpiod" if self.use_gpiod_backend else "auto"
            self._gpio_manager = GPIOPinManager(
                backend=backend, gpio_chip=f"/dev/gpiochip{self.gpio_chip}"
            )
            # Share GPIO manager instance with SX126x low-level driver
            set_gpio_manager(self._gpio_manager)
        self._interrupt_setup = False
        self._txen_pin_setup = False
        self._txled_pin_setup = False
        self._rxled_pin_setup = False
        self._en_pins_setup = False

        self._tx_done_event = asyncio.Event()
        self._rx_done_event = asyncio.Event()
        self._cad_event = asyncio.Event()

        # Store last IRQ status for background task
        self._last_irq_status = 0

        # Track event loop for thread-safe interrupt handling
        self._event_loop = None
        self._shutting_down = False

        # Store CAD results from interrupt handler
        self._last_cad_detected = False
        self._last_cad_irq_status = 0

        # Custom CAD thresholds (None means use defaults)
        self._custom_cad_peak = None
        self._custom_cad_min = None

        # Noise floor sampling
        self._noise_floor = -99.0
        self._num_floor_samples = 0
        self._floor_sample_sum = 0.0
        self._last_packet_activity = 0.0
        self._is_receiving_packet = False
        self.NUM_NOISE_FLOOR_SAMPLES = 20
        self.SAMPLING_THRESHOLD = 10  # Only sample if RSSI < noise_floor + threshold

        # Radio metrics
        self.crc_error_count = 0

        logger.info(
            f"SX1262Radio configured: freq={frequency/1e6:.1f}MHz, "
            f"power={tx_power}dBm, sf={spreading_factor}, "
            f"bw={bandwidth/1000:.1f}kHz, pre={preamble_length}"
        )
        # Register this instance as the active radio for IRQ callback access
        SX1262Radio._active_instance = self

        # RX callback for received packets
        self.rx_callback = None

    @staticmethod
    def _normalize_en_pins(en_pin: int = -1, en_pins: Optional[list[int]] = None) -> list[int]:
        normalized_pins = []

        if en_pins:
            normalized_pins.extend(en_pins)
        elif en_pin != -1:
            normalized_pins.append(en_pin)

        deduped_pins = []
        for pin in normalized_pins:
            if pin == -1 or pin in deduped_pins:
                continue
            deduped_pins.append(pin)

        return deduped_pins

    def _get_rx_irq_mask(self) -> int:
        """Get the standard RX interrupt mask"""
        return (
            self.lora.IRQ_RX_DONE
            | self.lora.IRQ_CRC_ERR
            | self.lora.IRQ_TIMEOUT
            | self.lora.IRQ_PREAMBLE_DETECTED
            | self.lora.IRQ_SYNC_WORD_VALID
            | self.lora.IRQ_HEADER_VALID
            | self.lora.IRQ_HEADER_ERR
        )

    def _get_tx_irq_mask(self) -> int:
        """Get the standard TX interrupt mask"""
        return self.lora.IRQ_TX_DONE | self.lora.IRQ_TIMEOUT

    def _irq_trampoline(self):
        """Lightweight trampoline called by GPIO thread - schedules real handler on event loop."""
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
                return
            logger.error(f"IRQ trampoline runtime error: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"IRQ trampoline error: {e}", exc_info=True)

    def _safe_radio_operation(
        self, operation_name: str, operation_func, success_msg: str = None
    ) -> bool:
        """Helper method for safe radio operations with consistent error handling (DRY)"""
        if not self._initialized or self.lora is None:
            return False

        try:
            operation_func()
            if success_msg:
                logger.debug(success_msg)
            return True
        except Exception as e:
            logger.error(f"Failed to {operation_name}: {e}")
            return False

    def _basic_radio_setup(self, use_busy_check: bool = False) -> bool:
        """Common radio setup: reset, standby, and LoRa packet type"""
        self.lora.reset()
        time.sleep(self._RADIO_TIMING_DELAY)  # Give hardware time to complete reset
        self.lora.setStandby(self.lora.STANDBY_RC)
        time.sleep(self._RADIO_TIMING_DELAY)  # Give hardware time to enter standby mode

        # Check if standby mode was set correctly (different methods for different boards)
        if use_busy_check:
            if self.lora.busyCheck():
                logger.error("Something wrong, can't set to standby mode")
                return False
        else:
            if self.lora.getMode() != self.lora.STATUS_MODE_STDBY_RC:
                logger.error("Something wrong, can't set to standby mode")
                return False

        self.lora.setPacketType(self.lora.LORA_MODEM)
        return True

    def _handle_interrupt(self):
        """instance method interrupt handler"""

        try:
            if not self._initialized or not self.lora:
                logger.warning("Interrupt called but radio not initialized")
                return

            irqStat = self.lora.getIrqStatus()

            if irqStat != 0:
                self.lora.clearIrqStatus(0xFFFF)

            self._last_irq_status = irqStat
            if irqStat & self.lora.IRQ_TX_DONE:
                logger.debug("[TX] TX_DONE interrupt (0x{:04X})".format(self.lora.IRQ_TX_DONE))
                self._tx_done_event.set()

            if irqStat & (self.lora.IRQ_CAD_DETECTED | self.lora.IRQ_CAD_DONE):
                cad_detected = bool(irqStat & self.lora.IRQ_CAD_DETECTED)
                if cad_detected:
                    logger.debug(f"[CAD] Channel activity detected (0x{irqStat:04X})")
                else:
                    logger.debug(f"[CAD] Channel clear detected (0x{irqStat:04X})")

                self._last_cad_detected = cad_detected
                self._last_cad_irq_status = irqStat
                if hasattr(self, "_cad_event"):
                    self._cad_event.set()

            rx_interrupts = self._get_rx_irq_mask()
            if irqStat & rx_interrupts:
                # Define terminal interrupts (packet complete or failed - need action)
                terminal_interrupts = (
                    self.lora.IRQ_RX_DONE
                    | self.lora.IRQ_CRC_ERR
                    | self.lora.IRQ_TIMEOUT
                    | self.lora.IRQ_HEADER_ERR
                )

                # Log all interrupt types for debugging
                if irqStat & self.lora.IRQ_RX_DONE:
                    logger.debug("[RX] RX_DONE interrupt (0x{:04X})".format(self.lora.IRQ_RX_DONE))
                if irqStat & self.lora.IRQ_CRC_ERR:
                    logger.debug("[RX] CRC_ERR interrupt (0x{:04X})".format(self.lora.IRQ_CRC_ERR))
                if irqStat & self.lora.IRQ_TIMEOUT:
                    logger.debug("[RX] TIMEOUT interrupt (0x{:04X})".format(self.lora.IRQ_TIMEOUT))
                if irqStat & self.lora.IRQ_HEADER_ERR:
                    logger.debug(
                        "[RX] HEADER_ERR interrupt (0x{:04X})".format(self.lora.IRQ_HEADER_ERR)
                    )
                if irqStat & self.lora.IRQ_PREAMBLE_DETECTED:
                    logger.debug(
                        "[RX] PREAMBLE_DETECTED interrupt (0x{:04X})".format(
                            self.lora.IRQ_PREAMBLE_DETECTED
                        )
                    )
                if irqStat & self.lora.IRQ_SYNC_WORD_VALID:
                    logger.debug(
                        "[RX] SYNC_WORD_VALID interrupt (0x{:04X})".format(
                            self.lora.IRQ_SYNC_WORD_VALID
                        )
                    )
                if irqStat & self.lora.IRQ_HEADER_VALID:
                    logger.debug(
                        "[RX] HEADER_VALID interrupt (0x{:04X})".format(self.lora.IRQ_HEADER_VALID)
                    )

                # Only wake the background task for TERMINAL interrupts
                # Intermediate interrupts (preamble, sync, header valid) are just progress updates
                if irqStat & terminal_interrupts:
                    if not self._tx_lock.locked():
                        self._rx_done_event.set()
                        logger.debug(
                            f"[RX] Terminal interrupt 0x{irqStat:04X} - waking background task"
                        )
                    else:
                        logger.debug(
                            f"[RX] Ignoring terminal interrupt 0x{irqStat:04X} during TX operation"
                        )
                else:
                    # Non-terminal interrupt - just log it, don't wake background task
                    logger.debug(f"[RX] Progress interrupt 0x{irqStat:04X} - packet still incoming")

        except Exception as e:
            logger.error(f"IRQ handler error: {e}")
            self._tx_done_event.set()
            if not self._tx_lock.locked():
                self._rx_done_event.set()

    def set_rx_callback(self, callback):
        """Set a callback to be called with each received packet (bytes)."""
        self.rx_callback = callback

        # If we have interrupts but no background task yet, start it now
        if (
            self._interrupt_setup
            and self._initialized
            and (
                not hasattr(self, "_rx_irq_task")
                or self._rx_irq_task is None
                or self._rx_irq_task.done()
            )
        ):
            try:
                loop = asyncio.get_running_loop()
                # Capture event loop for thread-safe interrupt handling
                self._event_loop = loop
                self._rx_irq_task = loop.create_task(self._rx_irq_background_task())
            except RuntimeError:
                logger.debug("No event loop available for RX task startup")
            except Exception as e:
                logger.warning(f"Failed to start delayed RX IRQ background handler: {e}")

    async def _rx_irq_background_task(self):
        """Background task: waits for RX_DONE IRQ and processes received packets automatically."""
        logger.debug("[RX] Starting RX IRQ background task")
        rx_check_count = 0

        while self._initialized:
            try:
                if self._interrupt_setup:
                    # Wait for RX_DONE event
                    try:
                        await asyncio.wait_for(
                            self._rx_done_event.wait(), timeout=self.RADIO_TIMING_DELAY
                        )
                        self._rx_done_event.clear()
                        logger.debug("[RX] RX_DONE event triggered!")

                        # Mark that we're processing a packet (prevents noise floor sampling)
                        self._is_receiving_packet = True
                        self._last_packet_activity = time.time()

                        try:
                            # Use the IRQ status stored by the interrupt handler
                            irqStat = self._last_irq_status

                            if irqStat & self.lora.IRQ_CRC_ERR:
                                self.crc_error_count += 1
                                
                                try:

                                    packet_rssi_dbm, snr_db, signal_rssi_dbm = self.lora.getSignalMetrics()
                                    payloadLengthRx, rxStartBufferPointer = self.lora.getRxBufferStatus()
                                    device_errors = self.lora.getDeviceErrors()
                                    noise_floor = self.get_noise_floor()
                                    raw_packet_hex = ""
                                    if payloadLengthRx > 0 and payloadLengthRx < 256:
                                        try:
                                            buffer = self.lora.readBuffer(rxStartBufferPointer, payloadLengthRx)
                                            raw_packet_hex = bytes(buffer).hex()
                                        except Exception:
                                            raw_packet_hex = "(read failed)"
                                    
                                    logger.warning(
                                        "[RX] CRC error #%d - RSSI=%ddBm, SNR=%.1fdB, SignalRSSI=%ddBm, "
                                        "Length=%d, NoiseFloor=%.1fdBm, DeviceErrors=0x%04X, IRQ=0x%04X, "
                                        "RawData=%s",
                                        self.crc_error_count,
                                        int(packet_rssi_dbm), snr_db, int(signal_rssi_dbm),
                                        payloadLengthRx, noise_floor, device_errors, irqStat,
                                        raw_packet_hex
                                    )
                                except Exception as diag_err:
                                    # Fallback if diagnostic collection fails
                                    logger.warning(
                                        "[RX] CRC error #%d - Unable to collect diagnostics: %s", 
                                        self.crc_error_count, diag_err
                                    )
                            elif irqStat & self.lora.IRQ_RX_DONE:
                                (
                                    payloadLengthRx,
                                    rxStartBufferPointer,
                                ) = self.lora.getRxBufferStatus()
                                (
                                    packet_rssi_dbm,
                                    snr_db,
                                    signal_rssi_dbm,
                                ) = self.lora.getSignalMetrics()
                                self.last_rssi = int(packet_rssi_dbm)
                                self.last_snr = snr_db
                                self.last_signal_rssi = int(signal_rssi_dbm)

                                logger.debug(
                                    f"[RX] Packet received: length={payloadLengthRx}, "
                                    f"RSSI={self.last_rssi}dBm, SNR={self.last_snr}dB"
                                )

                                # Trigger RX LED
                                self._gpio_manager.blink_led(self.rxled_pin)

                                if payloadLengthRx > 0:
                                    buffer = self.lora.readBuffer(
                                        rxStartBufferPointer, payloadLengthRx
                                    )
                                    packet_data = bytes(buffer)
                                    logger.debug(
                                        f"[RX] Packet data: {packet_data.hex()[:32]}... "
                                        f"({len(packet_data)} bytes)"
                                    )

                                    # Call user RX callback if set
                                    if self.rx_callback:
                                        try:
                                            self.rx_callback(packet_data)
                                        except Exception as cb_exc:
                                            logger.error(f"RX callback error: {cb_exc}")
                                    else:
                                        logger.warning("[RX] No RX callback registered!")
                                else:
                                    logger.warning("[RX] Empty packet received")
                            elif irqStat & self.lora.IRQ_TIMEOUT:
                                logger.warning("[RX] RX timeout detected")
                            elif irqStat & self.lora.IRQ_HEADER_ERR:
                                logger.warning(
                                    f"[RX] Header error detected (0x{irqStat:04X}) - "
                                    "corrupted header, restoring RX mode"
                                )
                            elif irqStat & self.lora.IRQ_PREAMBLE_DETECTED:
                                logger.debug("[RX] Preamble detected - packet incoming")
                            elif irqStat & self.lora.IRQ_SYNC_WORD_VALID:
                                logger.debug("[RX] Sync word valid - receiving packet data")
                            elif irqStat & self.lora.IRQ_HEADER_VALID:
                                logger.debug(
                                    "[RX] Header valid - packet header received, payload coming"
                                )
                            else:
                                logger.debug(f"[RX] Other interrupt: 0x{irqStat:04X}")

                            if not self._tx_lock.locked():
                                try:
                                    self.lora.request(self.lora.RX_CONTINUOUS)
                                    # Read before clearing to catch back-to-back packets that arrived during processing.
                                    pending_irq = self.lora.getIrqStatus()
                                    self.lora.clearIrqStatus(0xFFFF)
                                    terminal_irqs = (
                                        self.lora.IRQ_RX_DONE
                                        | self.lora.IRQ_CRC_ERR
                                        | self.lora.IRQ_TIMEOUT
                                        | self.lora.IRQ_HEADER_ERR
                                    )
                                    if pending_irq & terminal_irqs:
                                        logger.debug(f"[RX] Back-to-back packet queued (IRQ 0x{pending_irq:04X})")
                                        self._last_irq_status = pending_irq
                                        self._rx_done_event.set()
                                    await asyncio.sleep(self.RADIO_TIMING_DELAY)
                                    logger.debug(
                                        f"[RX] Restored RX continuous mode after IRQ 0x{irqStat:04X}"
                                    )
                                except Exception as e:
                                    logger.error(f"Failed to restore RX mode: {e}")
                            else:
                                logger.debug(
                                    f"[RX] Skipped RX restore after IRQ 0x{irqStat:04X}"
                                    " — TX lock held, send() will restore RX on completion"
                                )
                        except Exception as e:
                            logger.error(f"[IRQ RX] Error processing received packet: {e}")
                        finally:
                            # Clear packet processing flag
                            self._is_receiving_packet = False

                    except asyncio.TimeoutError:
                        # No RX event within timeout - normal operation
                        rx_check_count += 1

                        # Sample noise floor during quiet periods
                        self._sample_noise_floor()

                        # Watchdog: gpiod polling can miss an edge if IRQ goes HIGH then LOW within
                        # the 20ms poll window. Recover by driving _handle_interrupt directly.
                        if (
                            self.use_gpiod_backend
                            and not self._tx_lock.locked()
                            and not self._is_receiving_packet
                        ):
                            try:
                                pin_state = self._gpio_manager.read_pin(self.irq_pin_number)
                                if pin_state:
                                    logger.warning("[RX] IRQ pin stuck HIGH (gpiod polling gap) — recovering")
                                    self._handle_interrupt()
                            except Exception as e:
                                logger.debug(f"[RX] IRQ watchdog read failed: {e}")

                        # Log every 500 checks (roughly every 5 seconds) to show RX task is alive
                        if rx_check_count % 500 == 0:
                            logger.debug(
                                f"[RX Task] Status check #{rx_check_count}, "
                                f"noise_floor={self._noise_floor:.1f}dBm"
                            )

                else:
                    await asyncio.sleep(0.1)

            except Exception as e:
                logger.error(f"[RX Task] Unexpected error: {e}")
                await asyncio.sleep(1.0)  # Wait and continue

        logger.warning("[RX] RX IRQ background task exiting")

    def check_radio_health(self) -> bool:
        """Simple health check - restart RX task if it's dead."""
        if not self._initialized:
            return False

        # Check if RX task is dead and restart it
        if (
            not hasattr(self, "_rx_irq_task")
            or self._rx_irq_task is None
            or self._rx_irq_task.done()
        ):
            try:
                loop = asyncio.get_running_loop()
                self._rx_irq_task = loop.create_task(self._rx_irq_background_task())
                logger.warning("[RX] Restarted dead RX task")
                return False  # Was dead, now restarted
            except Exception:
                return False  # Failed to restart

        return True  # Task is alive

    def begin(self) -> bool:
        """Initialize the SX1262 radio module. Returns True if successful, False otherwise."""
        # Prevent double initialization
        if self._initialized:
            logger.debug("SX1262 radio already initialized, skipping")
            return True

        self._shutting_down = False

        try:
            logger.debug("Initializing SX1262 radio...")
            self.lora = SX126x()

            # Register GPIO interrupt using lightweight trampoline
            self.irq_pin = self._gpio_manager.setup_interrupt_pin(
                self.irq_pin_number, pull_up=False, callback=self._irq_trampoline
            )

            if self.irq_pin is not None:
                self._interrupt_setup = True
            else:
                logger.error(f"Failed to setup interrupt pin {self.irq_pin_number}")
                raise RuntimeError(f"Could not setup IRQ pin {self.irq_pin_number}")

            # SPI and GPIO Pins setting
            self.lora.setSpi(self.bus_id, self.cs_id)
            if self.cs_pin != -1:
                # Override CS pin
                self.lora.setManualCsPin(self.cs_pin)

            self.lora._reset = self.reset_pin
            self.lora._busy = self.busy_pin
            self.lora._irq = self.irq_pin_number
            # Pass -1 for TXEN/RXEN to prevent SX126x driver from controlling them
            # The wrapper handles these pins correctly via _control_tx_rx_pins()
            self.lora._txen = -1  # Managed by wrapper, not low-level driver
            self.lora._rxen = -1  # Managed by wrapper, not low-level driver
            self.lora._wake = -1  # Not used

            # Setup TXEN pin if needed
            if self.txen_pin != -1 and not self._txen_pin_setup:
                if self._gpio_manager.setup_output_pin(self.txen_pin, initial_value=False):
                    logger.debug(f"TXEN pin {self.txen_pin} configured")
                    self._txen_pin_setup = True
                else:
                    logger.warning(f"Could not setup TXEN pin {self.txen_pin}")

            # Setup RXEN pin if needed
            if self.rxen_pin != -1:
                if self._gpio_manager.setup_output_pin(self.rxen_pin, initial_value=False):
                    logger.debug(f"RXEN pin {self.rxen_pin} configured")
                else:
                    logger.warning(f"Could not setup RXEN pin {self.rxen_pin}")

            # Ensure TX/RX pins are in default state (RX mode)
            if self.txen_pin != -1 or self.rxen_pin != -1:
                self._control_tx_rx_pins(tx_mode=False)
                logger.debug("TX/RX control pins set to RX mode")

            # Setup LED pins if specified
            if self.txled_pin != -1 and not self._txled_pin_setup:
                if self._gpio_manager.setup_output_pin(self.txled_pin, initial_value=False):
                    self._txled_pin_setup = True
                    logger.debug(f"TX LED pin {self.txled_pin} configured")
                else:
                    logger.warning(f"Could not setup TX LED pin {self.txled_pin}")

            if self.rxled_pin != -1 and not self._rxled_pin_setup:
                if self._gpio_manager.setup_output_pin(self.rxled_pin, initial_value=False):
                    self._rxled_pin_setup = True
                    logger.debug(f"RX LED pin {self.rxled_pin} configured")
                else:
                    logger.warning(f"Could not setup RX LED pin {self.rxled_pin}")

            # Setup EN pin(s) if specified (powers up the radio when set HIGH)
            if self.en_pins and not self._en_pins_setup:
                all_en_pins_configured = True
                for en_pin in self.en_pins:
                    if self._gpio_manager.setup_output_pin(en_pin, initial_value=True):
                        logger.debug(f"EN pin {en_pin} configured and set HIGH")
                    else:
                        all_en_pins_configured = False
                        logger.warning(f"Could not setup EN pin {en_pin}")
                self._en_pins_setup = all_en_pins_configured

            # Basic radio setup
            if not self._basic_radio_setup(use_busy_check=True):
                return False

            # Configure TCXO if enabled
            if self.use_dio3_tcxo:
                # Map voltage to DIO3 constants following Meshtastic pattern
                voltage_map = {
                    1.6: self.lora.DIO3_OUTPUT_1_6,
                    1.7: self.lora.DIO3_OUTPUT_1_7,
                    1.8: self.lora.DIO3_OUTPUT_1_8,
                    2.2: self.lora.DIO3_OUTPUT_2_2,
                    2.4: self.lora.DIO3_OUTPUT_2_4,
                    2.7: self.lora.DIO3_OUTPUT_2_7,
                    3.0: self.lora.DIO3_OUTPUT_3_0,
                    3.3: self.lora.DIO3_OUTPUT_3_3,
                }

                voltage_constant = voltage_map.get(self.dio3_tcxo_voltage)
                if voltage_constant is None:
                    closest_voltage = min(
                        voltage_map.keys(), key=lambda x: abs(x - self.dio3_tcxo_voltage)
                    )
                    voltage_constant = voltage_map[closest_voltage]
                    logger.debug(
                        f"DIO3 TCXO voltage {self.dio3_tcxo_voltage}V "
                        f"mapped to closest {closest_voltage}V"
                    )
                else:
                    logger.debug(f"DIO3 TCXO voltage {self.dio3_tcxo_voltage}V mapped exactly")

                # Set TCXO with 5ms delay (standard value)
                self.lora.setDio3TcxoCtrl(voltage_constant, self.lora.TCXO_DELAY_5)
                logger.info(f"DIO3 TCXO enabled: {self.dio3_tcxo_voltage}V, 5ms delay")
                time.sleep(0.05)  # Allow TCXO to stabilize
            else:
                logger.debug("DIO3 TCXO is not enabled")

            # Regulator, calibration and RF switch configuration (required for all boards)
            self.lora.setRegulatorMode(self.lora.REGULATOR_DC_DC)
            self.lora.calibrate(0x7F)

            # Image calibration based on frequency band
            if self.frequency < 446000000:
                calFreqMin = self.lora.CAL_IMG_430
                calFreqMax = self.lora.CAL_IMG_440
                logger.debug("Image calibration for 430-440MHz band")
            elif self.frequency < 734000000:
                calFreqMin = self.lora.CAL_IMG_470
                calFreqMax = self.lora.CAL_IMG_510
                logger.debug("Image calibration for 470-510MHz band")
            elif self.frequency < 828000000:
                calFreqMin = self.lora.CAL_IMG_779
                calFreqMax = self.lora.CAL_IMG_787
                logger.debug("Image calibration for 779-787MHz band")
            elif self.frequency < 877000000:
                calFreqMin = self.lora.CAL_IMG_863
                calFreqMax = self.lora.CAL_IMG_870
                logger.debug("Image calibration for 863-870MHz band")
            else:
                calFreqMin = self.lora.CAL_IMG_902
                calFreqMax = self.lora.CAL_IMG_928
                logger.debug("Image calibration for 902-928MHz band")

            self.lora.calibrateImage(calFreqMin, calFreqMax)

            self.lora.setDio2RfSwitch(self.use_dio2_rf)
            time.sleep(self._RADIO_TIMING_DELAY)
            if self.use_dio2_rf:
                logger.info("DIO2 RF switch control enabled")

            # Common configuration for all board types
            # self.lora._fixResistanceAntenna()

            # Set frequency
            rfFreq = int(self.frequency * 33554432 / 32000000)
            self.lora.setRfFrequency(rfFreq)

            # Set buffer base addresses
            self.lora.setBufferBaseAddress(0x00, 0x80)  # TX=0x00, RX=0x80

            # Set TX power
            logger.info(f"Setting TX power to {self.tx_power} dBm during initialization")
            self.lora.setTxPower(self.tx_power, self.lora.TX_POWER_SX1262)

            # Configure modulation parameters
            # Enable LDRO if symbol duration > 16ms (SF11/62.5kHz = 32.768ms)
            symbol_duration_ms = (2**self.spreading_factor) / (self.bandwidth / 1000)
            ldro = symbol_duration_ms > 16.0
            logger.info(
                f"LDRO {'enabled' if ldro else 'disabled'} "
                f"(symbol duration: {symbol_duration_ms:.3f}ms)"
            )
            self.lora.setLoRaModulation(
                self.spreading_factor, self.bandwidth, self.coding_rate, ldro
            )

            # Configure packet parameters
            self.lora.setPacketParamsLoRa(
                self.preamble_length,
                self.lora.HEADER_EXPLICIT,
                64,  # Initial payload length
                self.lora.CRC_ON,
                self.lora.IQ_STANDARD,
            )

            # Configure RX interrupts and gain
            rx_mask = self._get_rx_irq_mask()
            self.lora.clearIrqStatus(0xFFFF)
            self.lora.setDioIrqParams(rx_mask, rx_mask, self.lora.IRQ_NONE, self.lora.IRQ_NONE)
            self.lora.setRxGain(self.lora.RX_GAIN_BOOSTED)

            # Program custom CAD thresholds to chip hardware if available
            if self._custom_cad_peak is not None and self._custom_cad_min is not None:
                logger.info(
                    f"Setting CAD thresholds to chip: peak={self._custom_cad_peak},",
                    f"min={self._custom_cad_min}",
                )
                try:
                    self.lora.setCadParams(
                        self.lora.CAD_ON_2_SYMB,  # 2 symbols for detection
                        self._custom_cad_peak,
                        self._custom_cad_min,
                        self.lora.CAD_EXIT_STDBY,  # exit to standby
                        0,  # no timeout
                    )
                    logger.debug("Custom CAD thresholds written")
                except Exception as e:
                    logger.warning(f"Failed to write CAD thresholds: {e}")

            self.lora.request(self.lora.RX_CONTINUOUS)
            time.sleep(self._RADIO_TIMING_DELAY)

            self._initialized = True
            logger.info("SX1262 radio initialized successfully")

            # Start GPIO interrupt polling now that init is complete
            # (Polling interferes with SPI during init, so we delayed it)
            if self._gpio_manager:
                try:
                    # Start polling on the IRQ pin if it exists
                    irq_pin_num = getattr(self, "irq_pin_number", None)
                    if (
                        irq_pin_num is not None
                        and hasattr(self._gpio_manager, "_pins")
                        and irq_pin_num in self._gpio_manager._pins
                    ):
                        irq_pin_obj = self._gpio_manager._pins[irq_pin_num]
                        if hasattr(irq_pin_obj, "start_polling"):
                            irq_pin_obj.start_polling()
                            logger.info("Started IRQ polling after radio init")
                except Exception as e:
                    logger.warning(f"Failed to start IRQ polling: {e}")

            # Start RX IRQ background handler if using interrupts (only once)
            try:
                if self._interrupt_setup:
                    # Check if task is already running to prevent duplicates
                    if (
                        not hasattr(self, "_rx_irq_task")
                        or self._rx_irq_task is None
                        or self._rx_irq_task.done()
                    ):
                        try:
                            loop = asyncio.get_running_loop()
                            # Capture event loop for thread-safe interrupt handling
                            self._event_loop = loop
                        except RuntimeError:
                            # No event loop running, we'll start the task later
                            # when one is available
                            return True

                        self._rx_irq_task = loop.create_task(self._rx_irq_background_task())
                        logger.debug("[RX] RX IRQ background task started")
                    else:
                        logger.debug("[RX] RX IRQ background task already running")
            except Exception as e:
                logger.warning(f"Failed to start RX IRQ background handler: {e}")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize SX1262 radio: '{e}'")
            self._initialized = False
            # Hard fail immediately - no retries
            raise RuntimeError(f"Failed to initialize SX1262 radio: {e}") from e

    def _calculate_tx_timeout(self, packet_length: int) -> tuple[int, int]:
        """
        Calculate the LoRa packet airtime and transmission timeout using the standard
        Semtech formula.

        This method implements the LoRa airtime calculation as described in the Semtech
        LoRa Modem Designer's Guide (AN1200.13, section 4.1), taking into account the
        following parameters:
            - Spreading Factor (SF)
            - Bandwidth (BW)
            - Coding Rate (CR)
            - Preamble length
            - Explicit/implicit header mode (always explicit here)
            - CRC enabled (always enabled here)
            - Low Data Rate Optimization (enabled if SF >= 11 and BW <= 125 kHz)
            - Payload length (packet_length)

        Returns:
            timeout_ms (int): Calculated packet transmission timeout in milliseconds
                (airtime + margin).
            driver_timeout (int): Timeout value in units required by the radio driver
                (typically ms * 64).
        """
        sf = self.spreading_factor
        bw_hz = int(self.bandwidth)  # your class already stores Hz
        cr = self.coding_rate  # 1→4/5, 2→4/6, 3→4/7, 4→4/8
        preamble = self.preamble_length
        crc_on = True  # you always enable CRC
        explicit_header = True  # you always use explicit header
        low_dr_opt = 1 if (sf >= 11 and bw_hz <= 125000) else 0
        symbol_time = (1 << sf) / float(bw_hz)
        preamble_time = (preamble + 4.25) * symbol_time
        ih = 0 if explicit_header else 1
        crc = 1 if crc_on else 0

        tmp = 8 * packet_length - 4 * sf + 28 + 16 * crc - 20 * ih

        denom = 4 * (sf - 2 * low_dr_opt)

        if tmp > 0:
            payload_symbols = 8 + max(math.ceil(tmp / denom) * (cr + 4), 0)
        else:
            payload_symbols = 8

        payload_time = payload_symbols * symbol_time
        air_time_ms = (preamble_time + payload_time) * 1000.0
        timeout_ms = math.ceil(air_time_ms) + 1000
        driver_timeout = timeout_ms * 64

        logger.debug(
            f"TX timing SF{sf}/{bw_hz/1000:.1f}kHz "
            f"CR4/{cr} {packet_length}B: "
            f"symbol={symbol_time*1000:.3f}ms, "
            f"preamble={preamble_time*1000:.1f}ms, "
            f"tmp={tmp}, "
            f"payload_syms={payload_symbols:.1f}, "
            f"payload={payload_time*1000:.1f}ms, "
            f"air_time={air_time_ms:.1f}ms, "
            f"timeout={timeout_ms}ms, "
            f"driver_timeout={driver_timeout}"
        )

        return timeout_ms, driver_timeout

    def _prepare_packet_transmission(self, data_list: list, length: int) -> None:
        """Prepare radio for packet transmission"""
        self.lora.writeBuffer(0x00, data_list, length)
        headerType = self.lora.HEADER_EXPLICIT
        preambleLength = self.preamble_length
        crcType = self.lora.CRC_ON
        invertIq = self.lora.IQ_STANDARD

        self.lora.setPacketParamsLoRa(preambleLength, headerType, length, crcType, invertIq)

    def _setup_tx_interrupts(self) -> None:
        """Configure interrupts for transmission - TX and CAD only, disable RX interrupts"""
        mask = self._get_tx_irq_mask() | self.lora.IRQ_CAD_DONE | self.lora.IRQ_CAD_DETECTED
        self.lora.setDioIrqParams(mask, mask, self.lora.IRQ_NONE, self.lora.IRQ_NONE)

        existing_irq = self.lora.getIrqStatus()
        if existing_irq != 0:
            self.lora.clearIrqStatus(existing_irq)

    async def _prepare_radio_for_tx(self) -> tuple[bool, list[float]]:
        """Prepare radio hardware for transmission. Returns (success, lbt_backoff_delays_ms)."""
        self._tx_done_event.clear()
        self._rx_done_event.clear()
        self.lora.setStandby(self.lora.STANDBY_RC)
        await asyncio.sleep(self.RADIO_TIMING_DELAY)  # Give hardware time to enter standby
        if self.lora.busyCheck():
            busy_wait = 0
            while self.lora.busyCheck() and busy_wait < 20:
                await asyncio.sleep(self.RADIO_TIMING_DELAY)
                busy_wait += 1

        # Listen Before Talk (LBT) - Check for channel activity using CAD
        lbt_backoff_delays = []  # Track each backoff delay in ms
        lbt_attempts = 0
        max_lbt_attempts = 5

        while lbt_attempts < max_lbt_attempts:
            try:
                channel_busy = await self.perform_cad(timeout=0.5)
                if not channel_busy:
                    logger.debug(
                        f"CAD check clear - channel available after {lbt_attempts + 1} attempts"
                    )
                    break

                logger.debug("CAD check still busy - channel activity detected")
                lbt_attempts += 1
                if lbt_attempts < max_lbt_attempts:
                    # Jitter (50-200ms)
                    base_delay = random.randint(50, 200)
                    # Exponential backoff: base * 2^attempts
                    backoff_ms = base_delay * (2 ** (lbt_attempts - 1))
                    # Cap at 5 seconds maximum
                    backoff_ms = min(backoff_ms, 5000)

                    lbt_backoff_delays.append(float(backoff_ms))

                    logger.debug(
                        f"CAD backoff - waiting {backoff_ms}ms before retry "
                        f"(attempt {lbt_attempts}/{max_lbt_attempts})"
                    )
                    await asyncio.sleep(backoff_ms / 1000.0)
                else:
                    logger.warning(
                        f"CAD max attempts reached - channel still busy after "
                        f"{max_lbt_attempts} attempts, transmitting anyway"
                    )
            except Exception as e:
                logger.warning(f"CAD check failed: {e}, proceeding with transmission")
                break

        self._control_tx_rx_pins(tx_mode=True)

        if self.lora.busyCheck():
            logger.warning("Radio is busy before starting transmission")
            # Wait for radio to become ready
            busy_timeout = 0
            while self.lora.busyCheck() and busy_timeout < 100:
                await asyncio.sleep(self.RADIO_TIMING_DELAY)
                busy_timeout += 1
            if self.lora.busyCheck():
                logger.error("Radio stayed busy - cannot start transmission")
                return False, lbt_backoff_delays

        return True, lbt_backoff_delays

    def _control_tx_rx_pins(self, tx_mode: bool) -> None:
        """Control TXEN/RXEN pins for the E22 module (simple and deterministic)."""

        # TX: TXEN=HIGH, RXEN=LOW
        if tx_mode:
            if self.txen_pin != -1:
                self._gpio_manager.set_pin_high(self.txen_pin)
            if self.rxen_pin != -1:
                self._gpio_manager.set_pin_low(self.rxen_pin)

        # RX or idle: TXEN=LOW, RXEN=HIGH
        else:
            if self.txen_pin != -1:
                self._gpio_manager.set_pin_low(self.txen_pin)
            if self.rxen_pin != -1:
                self._gpio_manager.set_pin_high(self.rxen_pin)

    async def _execute_transmission(self, driver_timeout: int) -> bool:
        """Execute the actual transmission. Returns True if successful."""
        # Start transmission
        self.lora.setTx(driver_timeout)

        # Check if radio accepted the TX command (wait for busy to clear)
        busy_timeout = 0
        while self.lora.busyCheck() and busy_timeout < 50:  # 500ms max wait
            await asyncio.sleep(self.RADIO_TIMING_DELAY)
            busy_timeout += 1

        if self.lora.busyCheck():
            logger.error("Radio stayed busy after TX command - transmission may not have started")
            return False

        # Check initial interrupt status immediately after TX command
        # NOTE: On some USB-SPI backends, a very early read can occasionally return 0xFFFF
        # (SPI read glitch / radio still transitioning). Retry briefly before treating it as fatal.
        initial_status = 0xFFFF
        for attempt in range(3):
            initial_status = self.lora.getIrqStatus()
            if initial_status != 0xFFFF:
                break
            await asyncio.sleep(0.002)

        # Check for critical errors
        if initial_status == 0xFFFF:
            logger.warning(
                "IRQ status read returned 0xFFFF after TX command (possible SPI read glitch); "
                "continuing and relying on TX_DONE interrupt"
            )
            return True

        if initial_status & self.lora.IRQ_TIMEOUT:
            logger.error(
                "TX_TIMEOUT detected immediately after TX command - radio configuration issue"
            )
            self.lora.clearIrqStatus(initial_status)
            return False
        elif initial_status != 0:
            logger.warning(f"Unexpected initial interrupt status: 0x{initial_status:04X}")
            # Clear any unexpected flags but continue
            self.lora.clearIrqStatus(initial_status)

        return True

    async def _wait_for_transmission_complete(self, timeout_seconds: float) -> bool:
        """Wait for transmission to complete.

        Primary path: IRQ edge -> _tx_done_event.
        Fallback path: periodic polling of IRQ status (useful if an IRQ edge is missed).
        """
        logger.debug(f"[TX] Waiting for TX completion (timeout: {timeout_seconds}s)")
        start_time = time.time()

        poll_interval = 0.05  # 50ms polling fallback
        next_poll = start_time

        while True:
            elapsed = time.time() - start_time
            remaining = timeout_seconds - elapsed
            if remaining <= 0:
                logger.error("[TX] TX completion timeout - no interrupt received!")
                await self._handle_transmission_timeout(timeout_seconds, start_time)
                return False

            # Wait for either an interrupt event or the next polling tick
            wait_for = min(remaining, max(0.0, next_poll - time.time()))
            if wait_for <= 0:
                wait_for = 0.0

            try:
                await asyncio.wait_for(self._tx_done_event.wait(), timeout=wait_for)
                logger.debug("[TX] TX completion interrupt received!")
                return True
            except asyncio.TimeoutError:
                pass

            # Poll IRQ status periodically as a fallback
            now = time.time()
            if now >= next_poll:
                next_poll = now + poll_interval
                try:
                    irq = self.lora.getIrqStatus()
                except Exception as e:
                    logger.debug(f"[TX] IRQ status poll failed: {e}")
                    continue

                # 0xFFFF is usually a read glitch / bus not responding
                if irq == 0xFFFF:
                    continue

                if irq & self.lora.IRQ_TX_DONE:
                    logger.debug("[TX] TX_DONE detected via IRQ status poll")
                    return True

                if irq & self.lora.IRQ_TIMEOUT:
                    logger.error("[TX] TX_TIMEOUT detected via IRQ status poll")
                    # Clear and fail
                    try:
                        self.lora.clearIrqStatus(irq)
                    except Exception:
                        pass
                    return False

    async def _handle_transmission_timeout(self, timeout_seconds: float, start_time: float) -> None:
        """Handle transmission timeout and provide diagnostic information"""
        logger.error(
            f"Transmission wait timed out after {timeout_seconds:.1f} seconds - "
            f"radio may not be transmitting"
        )

        # Check interrupt status to see what happened
        irqStat = self.lora.getIrqStatus()
        logger.error(f"Interrupt status at timeout: 0x{irqStat:04X}")

        # Check if this is a configuration issue
        if irqStat == 0x0200:  # Only timeout bit set
            logger.error("Radio configuration issue: TX operation timed out without starting")

        self.lora.clearIrqStatus(irqStat)

    def _finalize_transmission(self) -> None:
        """Finalize transmission by checking status and logging results"""
        # Get final interrupt status
        irqStat = self.lora.getIrqStatus()

        # Check what actually happened
        logger.debug(f"Final interrupt status: 0x{irqStat:04X}")

        if irqStat & self.lora.IRQ_TX_DONE:
            pass  # Success
        elif irqStat & self.lora.IRQ_TIMEOUT:
            logger.warning("TX_TIMEOUT interrupt received - transmission failed")
        else:
            # No warning for 0x0000 - interrupt already cleared by handler
            pass

        # Get transmission stats if available
        try:
            tx_time = self.lora.transmitTime()
            if tx_time > 0:
                data_rate = self.lora.dataRate()
                logger.debug(f"Packet transmitted: {tx_time:.2f}ms, {data_rate:.2f} bytes/s")
        except Exception as e:
            logger.debug(f"Transmission stats not available: {e}")

        # Clear interrupt status
        self.lora.clearIrqStatus(irqStat)

        # Reset TX/RX enable pins after transmission
        self._control_tx_rx_pins(tx_mode=False)

    async def _restore_rx_mode(self) -> None:
        """Restore radio to RX continuous mode after transmission"""
        logger.debug("[TX->RX] Starting RX mode restoration after transmission")
        try:
            if self.lora:
                # Critical sequence to prevent interrupt race conditions

                # Step 1: Clear all interrupts first
                self.lora.clearIrqStatus(0xFFFF)

                # Step 2: Put radio in standby
                self.lora.setStandby(self.lora.STANDBY_RC)
                await asyncio.sleep(self.RADIO_TIMING_DELAY)

                # Step 3: Disable all interrupts temporarily during reconfiguration
                self.lora.setDioIrqParams(
                    self.lora.IRQ_NONE, self.lora.IRQ_NONE, self.lora.IRQ_NONE, self.lora.IRQ_NONE
                )
                await asyncio.sleep(0.001)

                # Step 4: Clear any interrupts that may have fired
                self.lora.clearIrqStatus(0xFFFF)

                # Step 5: Restore RX interrupt configuration
                rx_mask = self._get_rx_irq_mask()
                self.lora.setDioIrqParams(rx_mask, rx_mask, self.lora.IRQ_NONE, self.lora.IRQ_NONE)
                await asyncio.sleep(0.001)

                # Step 6: Start RX mode
                self.lora.request(self.lora.RX_CONTINUOUS)
                await asyncio.sleep(self.RADIO_TIMING_DELAY)

                # Step 7: Final interrupt clear to start fresh
                self.lora.clearIrqStatus(0xFFFF)

                # Always restore external RF switch control pins to RX mode
                self._control_tx_rx_pins(tx_mode=False)

                logger.debug("[TX->RX] RX mode restoration completed")

        except Exception as e:
            logger.warning(f"[TX->RX] Failed to restore RX mode after TX: {e}")

    async def send(self, data: bytes) -> dict:
        """Send a packet asynchronously. Returns transmission metadata including LBT metrics."""
        if not self._initialized or self.lora is None:
            raise RuntimeError("Radio not initialized")

        async with self._tx_lock:
            try:
                data_list = list(data)
                length = len(data_list)

                # Calculate transmission timeout and airtime
                final_timeout_ms, driver_timeout = self._calculate_tx_timeout(length)
                timeout_seconds = (final_timeout_ms / 1000.0) + 0.5  # Add margin
                # Airtime is the timeout minus the 1000ms margin we add
                airtime_ms = final_timeout_ms - 1000

                self._prepare_packet_transmission(data_list, length)

                logger.debug(
                    f"Setting TX timeout: {final_timeout_ms}ms "
                    f"(tOut={driver_timeout}) for {length} bytes"
                )

                # Prepare for TX and capture LBT metrics
                tx_ready, lbt_backoff_delays = await self._prepare_radio_for_tx()
                if not tx_ready:
                    raise RuntimeError("Radio not ready for TX")

                # Setup TX interrupts AFTER CAD checks (CAD changes interrupt config)
                self._setup_tx_interrupts()
                await asyncio.sleep(self.RADIO_TIMING_DELAY)
                self.lora.setTxPower(self.tx_power, self.lora.TX_POWER_SX1262)

                if not await self._execute_transmission(driver_timeout):
                    raise RuntimeError("Radio failed to start TX")

                tx_ok = await self._wait_for_transmission_complete(timeout_seconds)
                if not tx_ok:
                    raise RuntimeError("TX completion timeout")

                self._finalize_transmission()

                # Trigger TX LED
                self._gpio_manager.blink_led(self.txled_pin)

                # Build and return transmission metadata
                return {
                    "airtime_ms": airtime_ms,
                    "lbt_attempts": len(lbt_backoff_delays),
                    "lbt_backoff_delays_ms": lbt_backoff_delays,
                    "lbt_channel_busy": len(lbt_backoff_delays) > 0,
                }

            except Exception as e:
                logger.error(f"Failed to send packet: {e}")
                raise
            finally:
                # Always leave radio in RX continuous mode after TX
                await self._restore_rx_mode()

    async def wait_for_rx(self) -> bytes:
        """Not implemented: use set_rx_callback instead."""
        raise NotImplementedError(
            "Use set_rx_callback(callback) to receive packets asynchronously."
        )

    def sleep(self) -> None:
        """Put the radio into low-power sleep mode"""
        if self._initialized and self.lora:
            try:
                self.lora.sleep()
                logger.debug("Radio in sleep mode")
            except Exception as e:
                logger.error(f"Failed to put radio to sleep: {e}")

    def get_last_rssi(self) -> int:
        """Return last received RSSI in dBm"""
        return self.last_rssi

    def get_last_snr(self) -> float:
        """Return last received SNR in dB"""
        return self.last_snr

    def get_last_signal_rssi(self) -> int:
        """Return last received signal RSSI in dBm"""
        return self.last_signal_rssi

    def _sample_noise_floor(self) -> None:
        """Sample noise floor"""
        if not self._initialized or self.lora is None:
            return

        # Don't sample during TX operations or if recently received packet
        if self._tx_lock.locked():
            return

        # Give 500ms quiet time after any packet activity
        if time.time() - self._last_packet_activity < 0.5:
            return

        # Don't sample if currently receiving a packet
        if self._is_receiving_packet:
            return

        # Sample RSSI during quiet periods only
        if self._num_floor_samples < self.NUM_NOISE_FLOOR_SAMPLES:
            try:
                raw_rssi = self.lora.getRssiInst()
                if raw_rssi is not None:
                    current_rssi = -(float(raw_rssi) / 2)

                    # For initial sampling (bootstrap), accept any reasonable RSSI
                    # After that, only accept values near current noise floor
                    if self._noise_floor == -99.0:
                        # Bootstrap: accept any RSSI in valid range (-150 to -30 dBm)
                        accept_sample = -150 < current_rssi < -30
                    else:
                        # Normal: only accept samples near current noise floor
                        accept_sample = current_rssi < (self._noise_floor + self.SAMPLING_THRESHOLD)

                    if accept_sample:
                        self._num_floor_samples += 1
                        self._floor_sample_sum += current_rssi

            except Exception as e:
                logger.debug(f"Failed to sample noise floor: {e}")

        elif (
            self._num_floor_samples >= self.NUM_NOISE_FLOOR_SAMPLES and self._floor_sample_sum != 0
        ):
            # Calculate new noise floor average
            new_noise_floor = self._floor_sample_sum / self.NUM_NOISE_FLOOR_SAMPLES

            # Clamp to reasonable bounds (-150 to -50 dBm)
            if new_noise_floor < -150:
                new_noise_floor = -150
            elif new_noise_floor > -50:
                new_noise_floor = -50

            self._noise_floor = new_noise_floor
            self._floor_sample_sum = 0.0
            self._num_floor_samples = 0

    def get_noise_floor(self) -> Optional[float]:
        """
        Get current noise floor in dBm.
        Returns properly sampled noise floor from background measurements.
        """
        if not self._initialized or self.lora is None:
            return 0.0

        # If currently transmitting, return 0 (clear indicator)
        if hasattr(self, "_tx_lock") and self._tx_lock.locked():
            return 0.0

        # Return the properly sampled and averaged noise floor
        return self._noise_floor

    def set_frequency(self, frequency: int) -> bool:
        """Set operating frequency"""

        def set_freq():
            self.frequency = frequency
            self.lora.setFrequency(frequency)

        return self._safe_radio_operation(
            "set frequency", set_freq, f"Frequency set to {frequency/1e6:.1f} MHz"
        )

    def set_tx_power(self, power: int) -> bool:
        """Set TX power in dBm"""

        def set_power():
            self.tx_power = power
            self.lora.setTxPower(power, self.lora.TX_POWER_SX1262)

        return self._safe_radio_operation("set TX power", set_power, f"TX power set to {power} dBm")

    def set_spreading_factor(self, sf: int) -> bool:
        """Set spreading factor (6-12)"""

        def set_sf():
            self.spreading_factor = sf
            self.lora.setLoRaModulation(sf, self.bandwidth, self.coding_rate)

        return self._safe_radio_operation(
            "set spreading factor", set_sf, f"Spreading factor set to {sf}"
        )

    def set_bandwidth(self, bw: int) -> bool:
        """Set bandwidth in Hz"""

        def set_bw():
            self.bandwidth = bw
            self.lora.setLoRaModulation(self.spreading_factor, bw, self.coding_rate)

        return self._safe_radio_operation(
            "set bandwidth", set_bw, f"Bandwidth set to {bw/1000:.0f} kHz"
        )

    def configure_radio(
        self,
        frequency: Optional[int] = None,
        bandwidth: Optional[int] = None,
        spreading_factor: Optional[int] = None,
        coding_rate: Optional[int] = None,
    ) -> bool:
        """Reconfigure LoRa parameters inline without restarting the radio.

        Any omitted parameter retains its current value. Waits for any
        in-flight TX to complete before touching the hardware, then restores
        RX_CONTINUOUS so the caller does not need to restart.
        """
        if not self._initialized or self.lora is None:
            logger.error("Cannot configure radio: not initialised")
            return False

        freq = frequency        if frequency        is not None else self.frequency
        bw   = bandwidth        if bandwidth        is not None else self.bandwidth
        sf   = spreading_factor if spreading_factor is not None else self.spreading_factor
        cr   = coding_rate      if coding_rate      is not None else self.coding_rate
        ldro = sf >= 11 and bw <= 125000

        deadline = time.monotonic() + 10.0
        while self._tx_lock.locked():
            if time.monotonic() > deadline:
                logger.error("configure_radio: TX did not complete within 10s")
                return False
            time.sleep(0.05)

        try:
            self.lora.clearIrqStatus(0xFFFF)
            self.lora.setStandby(self.lora.STANDBY_RC)
            time.sleep(self._RADIO_TIMING_DELAY)
            self.lora.setFrequency(freq)
            self.lora.setLoRaModulation(sf, bw, cr, ldro)
            self.frequency        = freq
            self.bandwidth        = bw
            self.spreading_factor = sf
            self.coding_rate      = cr
            self._noise_floor         = -99.0
            self._num_floor_samples   = 0
            self._floor_sample_sum    = 0.0
            rx_mask = self._get_rx_irq_mask()
            self.lora.clearIrqStatus(0xFFFF)
            self.lora.setDioIrqParams(rx_mask, rx_mask, self.lora.IRQ_NONE, self.lora.IRQ_NONE)
            self.lora.request(self.lora.RX_CONTINUOUS)
            time.sleep(self._RADIO_TIMING_DELAY)
            self.lora.clearIrqStatus(0xFFFF)
            self._control_tx_rx_pins(tx_mode=False)
            logger.info(
                "Radio reconfigured: %.3f MHz BW=%.1f kHz SF%d CR4/%d",
                freq / 1e6, bw / 1000, sf, cr,
            )
            return True
        except Exception as e:
            logger.error("Failed to configure radio: %s", e)
            return False

    def get_status(self) -> dict:
        """Get radio status information"""
        status = {
            "initialized": self._initialized,
            "frequency": self.frequency,
            "tx_power": self.tx_power,
            "spreading_factor": self.spreading_factor,
            "bandwidth": self.bandwidth,
            "coding_rate": self.coding_rate,
            "last_rssi": self.last_rssi,
            "last_snr": self.last_snr,
            "last_signal_rssi": self.last_signal_rssi,
            "crc_error_count": self.crc_error_count,
        }

        if self._initialized and self.lora:
            try:
                # Add hardware-specific status if available
                status["hardware_ready"] = True
            except Exception as e:
                logger.debug(f"Could not get hardware status: {e}")
                status["hardware_ready"] = False

        return status

    def set_custom_cad_thresholds(self, peak: int, min_val: int) -> None:
        """Set custom CAD thresholds that override the defaults.

        Args:
            peak: CAD detection peak threshold (0-31)
            min_val: CAD detection minimum threshold (0-31)
        """
        if not (0 <= peak <= 31) or not (0 <= min_val <= 31):
            raise ValueError("CAD thresholds must be between 0 and 31")

        self._custom_cad_peak = peak
        self._custom_cad_min = min_val
        logger.info(f"Custom CAD thresholds set: peak={peak}, min={min_val}")

    def clear_custom_cad_thresholds(self) -> None:
        """Clear custom CAD thresholds and revert to defaults."""
        self._custom_cad_peak = None
        self._custom_cad_min = None
        logger.info("Custom CAD thresholds cleared, reverting to defaults")

    def _get_thresholds_for_current_settings(self) -> tuple[int, int]:
        """Fetch CAD thresholds for the current spreading factor.
        Returns (cadDetPeak, cadDetMin).
        """
        # Use custom thresholds if set
        if self._custom_cad_peak is not None and self._custom_cad_min is not None:
            return (self._custom_cad_peak, self._custom_cad_min)

        # Default CAD thresholds by SF (based on Semtech TR013 recommendations)
        DEFAULT_CAD_THRESHOLDS = {
            7: (22, 10),
            8: (22, 10),
            9: (24, 10),
            10: (25, 10),
            11: (26, 10),
            12: (30, 10),
        }

        # Fall back to SF7 values if unknown
        return DEFAULT_CAD_THRESHOLDS.get(self.spreading_factor, (22, 10))

    async def perform_cad(
        self,
        det_peak: Optional[int] = None,
        det_min: Optional[int] = None,
        timeout: float = 1.0,
        calibration: bool = False,
    ) -> Union[bool, dict]:
        """
        Perform Channel Activity Detection (CAD).
        If calibration=True, uses provided thresholds and returns info.
        If calibration=False, uses pre-calibrated/default thresholds.

        Returns:
            bool: Channel activity detected (when calibration=False)
            dict: Calibration data (when calibration=True)
        """
        if not self._initialized:
            raise RuntimeError("Radio not initialized")

        if not self.lora:
            raise RuntimeError("LoRa radio object not available")

        # Choose thresholds
        if det_peak is None or det_min is None:
            det_peak, det_min = self._get_thresholds_for_current_settings()

        try:
            # Critical sequence to prevent interrupt race conditions during CAD

            # Step 1: Put radio in standby mode before CAD configuration
            self.lora.setStandby(self.lora.STANDBY_RC)
            await asyncio.sleep(self.RADIO_TIMING_DELAY)  # Give hardware time to enter standby

            # Step 2: Clear any existing interrupt flags
            existing_irq = self.lora.getIrqStatus()
            if existing_irq != 0:
                self.lora.clearIrqStatus(existing_irq)
                await asyncio.sleep(0.01)  # Wait for IRQ pin to go LOW after clearing

            # Step 2.5: Verify IRQ pin is LOW after clearing interrupts
            # If it's HIGH, we need to clear again
            for retry in range(3):
                irq_pin_state = self._gpio_manager.read_pin(self.irq_pin_number)
                if not irq_pin_state:  # LOW is good
                    logger.debug(f"[CAD] IRQ pin is LOW after clear (retry {retry})")
                    break
                else:
                    logger.warning(
                        f"[CAD] IRQ pin still HIGH after clear, retrying (attempt {retry+1}/3)"
                    )
                    self.lora.clearIrqStatus(0xFFFF)
                    await asyncio.sleep(0.01)
            else:
                logger.warning("[CAD] IRQ pin stuck HIGH, proceeding anyway")

            # Step 3: Clear the CAD event before configuring
            self._cad_event.clear()

            # Step 4: Configure CAD interrupts
            cad_mask = self.lora.IRQ_CAD_DONE | self.lora.IRQ_CAD_DETECTED
            self.lora.setDioIrqParams(cad_mask, cad_mask, self.lora.IRQ_NONE, self.lora.IRQ_NONE)
            await asyncio.sleep(0.001)  # Let interrupt config settle

            # Step 5: Configure CAD parameters
            self.lora.setCadParams(
                self.lora.CAD_ON_2_SYMB,  # 2 symbols
                det_peak,
                det_min,
                self.lora.CAD_EXIT_STDBY,  # exit to standby
                0,  # no timeout
            )

            # Step 6: Prime the IRQ pin state before starting CAD.
            # This helps edge-detection/polling GPIO backends establish a baseline.
            _ = self._gpio_manager.read_pin(self.irq_pin_number)

            # Give polling backends one more cycle to observe the baseline state.
            await asyncio.sleep(0.02)  # one poll cycle

            # Step 7: Start CAD operation
            self.lora.setCad()

            # Give hardware time to start CAD and GPIO polling to detect state changes
            # Don't call getMode() or busyCheck() here - they hold the lock and prevent
            # GPIO polling from detecting the CAD completion interrupt
            await asyncio.sleep(
                0.01
            )  # 10ms should be enough for CAD to complete (~8ms for 2 symbols)

            logger.debug(
                f"[CAD] Operation started - checking channel with peak={det_peak}, min={det_min}"
            )

            try:
                await asyncio.wait_for(self._cad_event.wait(), timeout=timeout)
                self._cad_event.clear()

                # Use CAD results stored by interrupt handler (avoids race condition)
                irq = self._last_cad_irq_status
                detected = self._last_cad_detected
                cad_done = bool(irq & self.lora.IRQ_CAD_DONE)

                logger.debug(f"CAD operation completed - IRQ status: 0x{irq:04X}")

                if detected:
                    logger.debug("CAD result: BUSY - channel activity detected")
                else:
                    logger.debug("CAD result: CLEAR - no channel activity detected")

                # Clear hardware IRQ status
                current_irq = self.lora.getIrqStatus()
                if current_irq != 0:
                    self.lora.clearIrqStatus(current_irq)

                if calibration:
                    return {
                        "sf": self.spreading_factor,
                        "bw": self.bandwidth,
                        "det_peak": det_peak,
                        "det_min": det_min,
                        "detected": detected,
                        "cad_done": cad_done,
                        "timestamp": time.time(),
                        "irq_status": irq,
                    }
                else:
                    return detected

            except asyncio.TimeoutError:
                logger.debug("CAD operation timed out - assuming channel clear")
                irq = self.lora.getIrqStatus()
                if irq != 0:
                    logger.debug(f"CAD timeout but IRQ status: 0x{irq:04X}")
                    self.lora.clearIrqStatus(irq)

                if calibration:
                    return {
                        "sf": self.spreading_factor,
                        "bw": self.bandwidth,
                        "det_peak": det_peak,
                        "det_min": det_min,
                        "detected": False,
                        "timestamp": time.time(),
                        "timeout": True,
                    }
                else:
                    return False

        except Exception as e:
            logger.error(f"CAD operation failed: {e}")
            if calibration:
                return {
                    "sf": self.spreading_factor,
                    "bw": self.bandwidth,
                    "det_peak": det_peak,
                    "det_min": det_min,
                    "detected": False,
                    "timestamp": time.time(),
                    "error": str(e),
                }
            else:
                return False
        finally:
            try:
                self.lora.clearIrqStatus(0xFFFF)

                self.lora.setStandby(self.lora.STANDBY_RC)
                await asyncio.sleep(self.RADIO_TIMING_DELAY)  # Give hardware time to enter standby

                self.lora.setDioIrqParams(
                    self.lora.IRQ_NONE, self.lora.IRQ_NONE, self.lora.IRQ_NONE, self.lora.IRQ_NONE
                )
                await asyncio.sleep(0.001)  # Let interrupt config settle

                self.lora.clearIrqStatus(0xFFFF)
                rx_mask = self._get_rx_irq_mask()
                self.lora.setDioIrqParams(rx_mask, rx_mask, self.lora.IRQ_NONE, self.lora.IRQ_NONE)
                await asyncio.sleep(0.001)
                if not self._tx_lock.locked():
                    self.lora.request(self.lora.RX_CONTINUOUS)
                    await asyncio.sleep(
                        self.RADIO_TIMING_DELAY
                    )  # Give hardware time to enter RX mode

                # Step 7: Final interrupt clear to start fresh
                self.lora.clearIrqStatus(0xFFFF)
            except Exception as e:
                logger.warning(f"Failed to restore RX mode after CAD: {e}")

    def cleanup(self) -> None:
        """Clean up radio resources"""
        self._shutting_down = True
        self._event_loop = None
        self._interrupt_setup = False

        if hasattr(self, "_rx_irq_task") and self._rx_irq_task is not None:
            try:
                if not self._rx_irq_task.done():
                    self._rx_irq_task.cancel()
            except Exception as e:
                logger.debug(f"Could not cancel RX IRQ task during cleanup: {e}")

        if hasattr(self, "lora") and self.lora:
            try:
                self.lora.end()
            except Exception as e:
                logger.error(f"Error during cleanup: {e}")

        if hasattr(self, "_gpio_manager"):
            self._gpio_manager.cleanup_all()

        self._initialized = False

        if SX1262Radio._active_instance is self:
            SX1262Radio._active_instance = None

    @classmethod
    def get_instance(cls, **kwargs):
        """Get the active instance or create a new one (singleton-like behavior)"""
        if cls._active_instance is not None:
            return cls._active_instance
        else:
            return cls(**kwargs)


# Factory function for easy instantiation
def create_sx1262_radio(**kwargs) -> SX1262Radio:
    """Create and initialize an SX1262 radio instance"""
    radio = SX1262Radio(**kwargs)
    if radio.begin():
        return radio
    else:
        raise RuntimeError("Failed to initialize SX1262 radio")
