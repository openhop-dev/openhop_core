"""
Mock GPIO Manager for CH341
Provides GPIO interface using CH341's built-in GPIO pins instead of system GPIO
Includes software interrupt polling to emulate hardware interrupts
"""

import logging
import threading
import time
from typing import Callable, Optional

from .ch341_async import CH341Error

logger = logging.getLogger(__name__)


class CH341GPIOPin:
    """Mock GPIO pin that uses CH341 GPIO

    GPIO pin mapping for CH341B/A/F in synchronous serial communication
    mode (device id = 0x5512) based on the information at
    https://github.com/frank-zago/ch341-i2c-spi-gpio:

    CH341A/B/F     GPIO  Names                    Mode
      pin          bit

     15             0     CS0                      input/output
     16             1     CS1                      input/output
     17             2     CS2                      input/output
     18             3     SCK                      input/output
     19             4     DOUT2                    input/output
     20             5     MOSI                     input/output
     21             6     DIN2                     input
     22             7     MISO                     input
      5             8     General purpose          input
      6             9     General purpose          input
      7            10     INT#                     input
      8            11     General purpose          input
      ?            12     ?                        input
     27            13     WT (WAIT)                input
      4            14     DS (Data Select?)        input
      3            15     AS (Address Select?)     input
    """

    def __init__(self, ch341_device, pin_number: int, is_output: bool = True, gpio_manager=None):
        self.ch341 = ch341_device
        self.pin = pin_number
        self.is_output = is_output
        self._value = True if is_output else False
        self._interrupt_callback = None
        self._polling_thread = None
        self._stop_polling = False

        # For INPUT pins we keep a cached last-read state so callers can get a value
        # even when the CH341 is busy with SPI.
        self._cached_state = None

        self._direction_configured = False
        self._gpio_manager = gpio_manager  # Reference to manager for CS state checking

        # Re-fire the interrupt callback if the pin stays HIGH this long (missed edge).
        self.stuck_high_refire_s = 0.2

    def read(self) -> bool:
        """Read pin value"""
        # Lazy configure: set direction on first access
        if not self._direction_configured:
            try:
                self.ch341.gpio_set_direction(self.pin, self.is_output)
                self._direction_configured = True
                direction = "output" if self.is_output else "input"
                logger.debug(f"[CH341] GPIO pin {self.pin} configured as {direction}")
            except Exception as e:
                logger.debug(f"Failed to set CH341 GPIO {self.pin} direction on first read: {e}")

        if self.is_output:
            return self._value
        try:
            val = self.ch341.gpio_get(self.pin)
            # Cache last known state for any input pin (BUSY/IRQ/etc.).
            # IMPORTANT: do not reuse this for edge detection state in the poller.
            self._cached_state = bool(val)
            return self._cached_state
        except CH341Error:
            # If we can't acquire lock (e.g., SPI transfer in progress),
            # return last known state
            if self._cached_state is not None:
                return self._cached_state
            return False  # Default to LOW if no cached value

    def read_cached(self) -> bool:
        """Read cached pin value without acquiring locks (non-blocking)"""
        if self.is_output:
            return self._value
        if self._cached_state is not None:
            return self._cached_state
        # No cached value, do a blocking read as fallback
        return self.read()

    def write(self, value: bool) -> None:
        """Write pin value"""
        # Lazy configure: set direction on first access
        if not self._direction_configured:
            try:
                self.ch341.gpio_set_direction(self.pin, self.is_output)
                self._direction_configured = True
            except Exception as e:
                logger.debug(f"Failed to set CH341 GPIO {self.pin} direction on first write: {e}")

        if not self.is_output:
            logger.warning(f"Attempting to write to input pin {self.pin}")
            return

        self._value = value
        try:
            self.ch341.gpio_set(self.pin, value)
        except Exception as e:
            logger.warning(f"Failed to write CH341 GPIO pin {self.pin}: {e}")

    def enable_interrupt(self, callback: Callable, edge: str = "rising"):
        """
        Enable software interrupt polling on this pin.

        Args:
            callback: Function to call when interrupt triggers
            edge: 'rising', 'falling', or 'both'
        """
        if self.is_output:
            logger.error(f"Cannot enable interrupt on output pin {self.pin}")
            return False

        self._interrupt_callback = callback
        self._interrupt_edge = edge
        self._stop_polling = False

        # Prime cached state
        try:
            self._cached_state = bool(self.read())
        except Exception:
            self._cached_state = False

        # Delay starting the polling thread - it interferes with radio init
        # The radio doesn't need IRQ monitoring until after initialization completes
        logger.info(f"IRQ callback registered for pin {self.pin} - polling will start after init")
        return True

    def start_polling(self):
        """Start the interrupt polling thread (call after radio init completes)"""
        if self._polling_thread is not None:
            return True  # Already started

        # Start polling thread
        self._polling_thread = threading.Thread(
            target=self._poll_for_interrupt, daemon=True, name=f"CH341-IRQ-Poll-{self.pin}"
        )
        self._polling_thread.start()
        edge = getattr(self, "_interrupt_edge", "rising")
        logger.info(f"Started interrupt polling on CH341 GPIO {self.pin} (edge={edge})")
        return True

    def _poll_for_interrupt(self):
        """Polling thread that checks pin state and triggers callback on configured edge."""
        poll_interval = 0.001  # 1ms polling interval
        iteration_count = 0
        interrupt_count = 0
        last_debug_time = time.time()

        interval_ms = poll_interval * 1000
        logger.info(
            f"Interrupt polling thread started for pin {self.pin} with {interval_ms}ms interval"
        )

        # Local edge state for polling (do NOT reuse _cached_state; that is for non-blocking reads)
        try:
            self._poll_last_state = bool(self.read_cached())
        except Exception:
            self._poll_last_state = False

        # Stuck-HIGH recovery (same idea as GPIOPinManager._monitor_polling for gpiod).
        # Edges are inferred by sampling, and read() returns the cached state while an
        # SPI transfer holds the CH341 lock. A short LOW between two IRQs (typically
        # IRQ cleared in _restore_rx_mode() after TX, then PREAMBLE/HEADER of an
        # incoming packet) can therefore be missed: the pin reads HIGH -> HIGH, no
        # callback fires, nothing clears the IRQ and DIO1 stays HIGH forever (RX deaf).
        # Treat a pin that stays HIGH as still pending and re-fire the callback.
        # Time-based rather than every other poll: at 1 ms polling that would schedule
        # hundreds of handler calls per second while the event loop is busy.
        high_since = None
        last_refire = 0.0

        while not self._stop_polling:
            iteration_count += 1

            try:
                current_state = bool(self.read())

                now = time.monotonic()
                if current_state and self._poll_last_state:
                    if high_since is None:
                        high_since = now
                    elif (
                        now - high_since >= self.stuck_high_refire_s
                        and now - last_refire >= self.stuck_high_refire_s
                        and self._interrupt_callback
                    ):
                        last_refire = now
                        interrupt_count += 1
                        logger.debug(
                            f"[POLL] pin={self.pin} stuck HIGH for "
                            f"{now - high_since:.2f}s, re-firing callback"
                        )
                        try:
                            self._interrupt_callback()
                        except Exception as e:
                            logger.error(f"Error in interrupt callback: {e}")
                elif not current_state:
                    high_since = None

                # Periodic debug (very low rate)
                current_time = time.time()
                if current_time - last_debug_time > 5.0:
                    logger.debug(
                        f"[POLL] pin={self.pin} state={current_state} "
                        f"last={self._poll_last_state} callbacks={interrupt_count}"
                    )
                    last_debug_time = current_time

                # Detect edges. IMPORTANT: keep edge-detection state local to this thread.
                edge = getattr(self, "_interrupt_edge", "rising")

                if edge in ("rising", "both") and (
                    self._poll_last_state is False and current_state is True
                ):
                    interrupt_count += 1
                    if self._interrupt_callback:
                        try:
                            self._interrupt_callback()
                        except Exception as e:
                            logger.error(f"Error in interrupt callback: {e}")

                if edge in ("falling", "both") and (
                    self._poll_last_state is True and current_state is False
                ):
                    interrupt_count += 1
                    if self._interrupt_callback:
                        try:
                            self._interrupt_callback()
                        except Exception as e:
                            logger.error(f"Error in interrupt callback: {e}")

                # Update last state for next iteration
                self._poll_last_state = current_state

            except Exception as e:
                # Suppress expected BUSY errors during heavy SPI activity
                msg = str(e)
                if "GPIO read IN failed: -6" not in msg and "GPIO read write failed: -6" not in msg:
                    logger.warning(
                        f"Error polling pin {self.pin} (iteration {iteration_count}): {e}"
                    )
                time.sleep(0.001)

            time.sleep(poll_interval)

        logger.info(
            f"Interrupt polling thread stopped for pin {self.pin} after "
            f"{iteration_count} iterations, {interrupt_count} interrupts detected"
        )

    def disable_interrupt(self):
        """Stop interrupt polling."""
        self._stop_polling = True
        if self._polling_thread and self._polling_thread.is_alive():
            self._polling_thread.join(timeout=0.5)
        self._interrupt_callback = None
        logger.debug(f"Disabled interrupt polling on CH341 GPIO {self.pin}")


class CH341GPIOManager:
    """GPIO manager that uses CH341's GPIO pins (0-15) directly.

    Only pins 0-5 are output-capable. Pins 6-15 are input-only.
    Pin mapping for CH341F sync-serial mode (PID 0x5512):
      GPIO 0 = pin 15 (CS0)
      GPIO 1 = pin 16 (CS1)
      GPIO 2 = pin 17 (CS2)
      GPIO 3 = pin 18 (SCK)
      GPIO 4 = pin 19 (DOUT2/CS3)
      GPIO 5 = pin 20 (MOSI)
      GPIO 6 = pin 21 (DIN2)
      GPIO 7 = pin 22 (MISO)
      GPIO 10 = pin 7  (INT#)
      GPIO 11 = pin 8  (BUSY/SLCT)
    """

    def __init__(
        self,
        vid: int = 0x1A86,
        pid: int = 0x5512,
        bus: Optional[int] = None,
        address: Optional[int] = None,
        serial_number: Optional[str] = None,
        ch341_device=None,
    ):
        """
        Initialize CH341 GPIO manager

        Args:
            vid: USB Vendor ID (default: 0x1a86 for CH341)
            pid: USB Product ID (default: 0x5512 for CH341)
            bus: Optional USB bus number for multi-adapter selection
            address: Optional USB device address on that bus
            serial_number: Optional USB serial string
            ch341_device: Optional already-open CH341Async instance to share
        """
        from .ch341_async import CH341Async

        if ch341_device is not None:
            self.ch341 = ch341_device
        else:
            self.ch341 = CH341Async.get_instance(
                vid=vid,
                pid=pid,
                bus=bus,
                address=address,
                serial_number=serial_number,
            )
        self._pins = {}  # pin_number -> CH341GPIOPin
        self._cs_pin_number = None  # Track CS pin for SPI state detection

        # LED blink support (same semantics as GPIOPinManager)
        self._led_threads = {}  # pin_number -> Thread
        self._led_stop_events = {}  # pin_number -> Event

        logger.info(
            "Using CH341 GPIO manager - pins 0-15 (0-5 out) bus=%s addr=%s serial=%r",
            getattr(self.ch341, "bus", None),
            getattr(self.ch341, "address", None),
            getattr(self.ch341, "serial_number", None),
        )

    def setup_output_pin(self, pin: int, initial_value: bool = True) -> bool:
        """
        Setup output pin using CH341 GPIO

        Args:
            pin: CH341 GPIO pin number (0-5, output-capable). -1 means unused.
            initial_value: Initial pin state

        Returns:
            True if successful
        """
        try:
            # -1 = not connected (e.g. PineDio reset_pin). Not an error.
            if pin is None or pin == -1:
                return False
            if not (0 <= pin <= 5):
                logger.error(f"CH341 output pin {pin} out of range (must be 0-5)")
                return False

            if pin in self._pins:
                logger.debug(f"CH341 GPIO {pin} already set up")
                return True

            gpio_pin = CH341GPIOPin(self.ch341, pin, is_output=True, gpio_manager=self)
            gpio_pin.write(initial_value)
            self._pins[pin] = gpio_pin

            # Track CS pin (pin 0 for CS)
            if pin == 0:
                self._cs_pin_number = pin
                logger.debug(f"Registered CS pin {pin} for SPI state tracking")

            logger.debug(f"CH341 GPIO output pin {pin} configured")
            return True
        except Exception as e:
            logger.error(f"Failed to setup CH341 output pin {pin}: {e}")
            return False

    def setup_input_pin(self, pin: int) -> bool:
        """
        Setup input pin using CH341 GPIO

        Args:
            pin: CH341 GPIO pin number (0-15). -1 means unused.

        Returns:
            True if successful
        """
        try:
            if pin is None or pin == -1:
                return False
            if not (0 <= pin <= 15):
                logger.error(f"CH341 input pin {pin} out of range (must be 0-15)")
                return False

            if pin in self._pins:
                logger.debug(f"CH341 GPIO {pin} already set up")
                return True

            gpio_pin = CH341GPIOPin(self.ch341, pin, is_output=False, gpio_manager=self)
            self._pins[pin] = gpio_pin
            logger.debug(f"CH341 GPIO input pin {pin} configured")
            return True
        except Exception as e:
            logger.error(f"Failed to setup CH341 input pin {pin}: {e}")
            return False

    def setup_interrupt_pin(
        self, pin: int, pull_up: bool = False, callback: Optional[Callable] = None
    ):
        """
        Setup interrupt pin with software polling to emulate hardware interrupts.

        CH341 doesn't support hardware interrupts, so this uses a polling thread
        to detect pin state changes and call the callback function.

        Args:
            pin: CH341 GPIO pin number (0-15)
            pull_up: Pull-up resistor (ignored, CH341 has internal config)
            callback: Interrupt callback function

        Returns:
            Pin object with interrupt polling enabled, or None on failure
        """
        if pin is None or pin == -1:
            logger.debug("CH341 interrupt pin not configured (pin=%r)", pin)
            return None
        if not (0 <= pin <= 15):
            logger.error(f"CH341 interrupt pin {pin} out of range (must be 0-15)")
            return None

        # Create input pin
        if not self.setup_input_pin(pin):
            logger.error(f"Failed to setup input pin {pin} for interrupt")
            return None

        gpio_pin = self._pins[pin]

        # Enable software interrupt polling if callback provided
        if callback:
            if gpio_pin.enable_interrupt(callback, edge="rising"):
                logger.info(f"Interrupt polling enabled on CH341 GPIO {pin}")
            else:
                logger.error(f"Failed to enable interrupt polling on pin {pin}")
                return None
        else:
            logger.warning("No callback provided for interrupt pin - polling not started")

        return gpio_pin

    def cleanup_all(self) -> None:
        """Cleanup all GPIO pins and stop interrupt polling threads"""
        logger.debug("Cleaning up CH341 GPIO pins")

        # Stop all LED threads
        for stop_event in self._led_stop_events.values():
            stop_event.set()
        for thread in self._led_threads.values():
            thread.join(timeout=0.2)
        self._led_threads.clear()
        self._led_stop_events.clear()

        # Stop all interrupt polling threads
        for pin in self._pins.values():
            if hasattr(pin, "disable_interrupt"):
                pin.disable_interrupt()
        self._pins.clear()

    def get_pin(self, pin: int):
        """Get pin object"""
        return self._pins.get(pin)

    def set_pin_high(self, pin_number: int) -> bool:
        """Set output pin to HIGH"""
        if pin_number in self._pins:
            try:
                gpio = self._pins[pin_number]
                if gpio.is_output:
                    gpio.write(True)
                    return True
                else:
                    logger.warning(f"Pin {pin_number} is not configured as output")
            except Exception as e:
                logger.warning(f"Failed to set pin {pin_number} HIGH: {e}")
        else:
            logger.debug(f"Pin {pin_number} not configured")
        return False

    def set_pin_low(self, pin_number: int) -> bool:
        """Set output pin to LOW"""
        if pin_number in self._pins:
            try:
                gpio = self._pins[pin_number]
                if gpio.is_output:
                    gpio.write(False)
                    return True
                else:
                    logger.warning(f"Pin {pin_number} is not configured as output")
            except Exception as e:
                logger.warning(f"Failed to set pin {pin_number} LOW: {e}")
        else:
            logger.debug(f"Pin {pin_number} not configured")
        return False

    def write_pin(self, pin_number: int, value: bool) -> bool:
        """
        Write value to output pin

        Args:
            pin_number: Pin number to write to
            value: True for HIGH, False for LOW

        Returns:
            True if successful
        """
        if value:
            return self.set_pin_high(pin_number)
        else:
            return self.set_pin_low(pin_number)

    def read_pin(self, pin_number: int) -> Optional[bool]:
        """
        Read current state of a pin

        Returns:
            True for HIGH, False for LOW, None if pin not configured or error
        """
        if pin_number in self._pins:
            try:
                return self._pins[pin_number].read()
            except Exception as e:
                logger.warning(f"Failed to read pin {pin_number}: {e}")
        else:
            logger.debug(f"Pin {pin_number} not configured")
        return None

    def _led_blink_thread(
        self, pin_number: int, duration: float, stop_event: threading.Event
    ) -> None:
        try:
            self.set_pin_high(pin_number)
            stop_event.wait(timeout=duration)
        finally:
            try:
                self.set_pin_low(pin_number)
            except Exception:
                pass
            self._led_threads.pop(pin_number, None)
            self._led_stop_events.pop(pin_number, None)

    def blink_led(self, pin_number: int, duration: float = 0.2) -> None:
        """Blink a CH341-controlled LED pin (non-blocking)."""
        if pin_number == -1:
            return

        gpio = self._pins.get(pin_number)
        if gpio is None or not getattr(gpio, "is_output", False):
            return

        # Stop any existing blink
        if pin_number in self._led_stop_events:
            self._led_stop_events[pin_number].set()
        if pin_number in self._led_threads:
            self._led_threads[pin_number].join(timeout=0.05)

        stop_event = threading.Event()
        self._led_stop_events[pin_number] = stop_event

        thread = threading.Thread(
            target=self._led_blink_thread,
            args=(pin_number, duration, stop_event),
            daemon=True,
            name=f"CH341-LED-{pin_number}",
        )
        thread.start()
        self._led_threads[pin_number] = thread

    def is_spi_active(self) -> bool:
        """Check if SPI is active by reading CS pin state.

        Returns:
            True if SPI is active (CS is LOW), False otherwise
        """
        if self._cs_pin_number is None:
            return False  # CS not configured, assume SPI inactive

        cs_pin = self._pins.get(self._cs_pin_number)
        if cs_pin is None:
            return False

        # CS LOW = SPI active, CS HIGH = SPI idle
        try:
            cs_state = cs_pin._value  # Read cached value to avoid USB round-trip
            return not cs_state  # LOW = active
        except Exception:
            return False  # On error, assume inactive
