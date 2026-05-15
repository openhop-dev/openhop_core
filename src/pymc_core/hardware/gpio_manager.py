"""
GPIO Pin Manager for Linux SBCs
Manages GPIO pins abstraction using python-periphery or gpiod
Works on Raspberry Pi, Orange Pi, Luckfox, and other Linux SBCs
"""

import glob
import logging
import sys
import threading
import time
import os
from typing import Callable, Dict, Optional

try:
    from periphery import GPIO, EdgeEvent
    try:
        # python-periphery's cdev2 backend asks for realtime event timestamps
        # by default. Linux 5.10 Rockchip kernels reject that flag during edge
        # requests, and pyMC does not need IRQ timestamps.
        # Resolve the module via the already-imported GPIO class to avoid
        # hardcoding the internal submodule path.
        import sys as _sys
        _cdev_mod = _sys.modules.get(GPIO.__module__, None)
        if _cdev_mod is not None and hasattr(_cdev_mod, "_GPIO_V2_LINE_FLAG_EVENT_CLOCK_REALTIME"):
            _cdev_mod._GPIO_V2_LINE_FLAG_EVENT_CLOCK_REALTIME = 0
        elif hasattr(GPIO, "_GPIO_V2_LINE_FLAG_EVENT_CLOCK_REALTIME"):
            GPIO._GPIO_V2_LINE_FLAG_EVENT_CLOCK_REALTIME = 0
    except (ImportError, AttributeError):
        pass
    PERIPHERY_AVAILABLE = True
except ImportError:
    # Mock GPIO classes for testing/non-hardware environments
    PERIPHERY_AVAILABLE = False
    GPIO = None
    EdgeEvent = None

# Optional libgpiod support
try:
    import gpiod
    GPIOD_AVAILABLE = True
except Exception:
    GPIOD_AVAILABLE = False
    gpiod = None


class GPIOImportError(ImportError):
    """Raised when GPIO functionality is used without python-periphery or gpiod"""

    def __init__(self):
        super().__init__(
            "\n\nError: python-periphery or gpiod library is required for GPIO management.\n"
            "━" * 60 + "\n"
            "This application requires GPIO hardware access which is only\n"
            "available on Linux-based systems (Raspberry Pi, Orange Pi, etc.)\n\n"
            "Reason: python-periphery uses Linux kernel interfaces that\n"
            "        don't exist on macOS or Windows.\n\n"
            "Solutions:\n"
            "   • Run this application on a Linux SBC\n"
            "━" * 60
        )


logger = logging.getLogger("GPIOPinManager")


class GPIOPinManager:
    """Manages GPIO pins abstraction using Linux GPIO character device interface"""

    def __init__(self, gpio_chip: str = "/dev/gpiochip0", backend: str = "auto"):
        """
        Initialize GPIO Pin Manager

        Args:
            gpio_chip: Path to GPIO chip device (default: /dev/gpiochip0)
                      Set to "auto" to auto-detect first available chip
            backend: 'periphery', 'gpiod', or 'auto' to select backend

        Raises:
            GPIOImportError: If python-periphery is not available
        """
        # Determine backend to use
        self._backend = backend
        if backend == "auto":
            if PERIPHERY_AVAILABLE:
                self._backend = "periphery"
            elif GPIOD_AVAILABLE:
                self._backend = "gpiod"

                class GpiodGPIO:
                    def __init__(self, chip_path, lineoffset, direction, bias=None, edge=None):
                        # chip_path is like '/dev/gpiochip0' — use it directly
                        try:
                            self._chip = gpiod.Chip(chip_path)
                        except Exception as e:
                            raise FileNotFoundError(
                                f"gpiod Chip '{chip_path}' not found: {e}"
                            ) from e

                        self._line = self._chip.get_line(lineoffset)
                        self.direction = direction
                        self._consumer = "pymc_core"

                        # Request line for input or output using libgpiod v2 LineRequest,
                        # if available.
                        requested = False
                        try:
                            LineRequest = getattr(gpiod, "LineRequest", None)
                            if LineRequest is not None:
                                req = LineRequest()
                                if hasattr(req, "consumer"):
                                    req.consumer = self._consumer
                                if hasattr(req, "request_type"):
                                    req.request_type = (
                                        getattr(gpiod, "LINE_REQ_DIR_OUT", None)
                                        if direction == "out"
                                        else getattr(gpiod, "LINE_REQ_DIR_IN", None)
                                    )
                                try:
                                    self._line.request(req)
                                    requested = True
                                except Exception:
                                    pass
                        except Exception:
                            pass

                        if not requested:
                            try:
                                req_type = (
                                    getattr(gpiod, "LINE_REQ_DIR_OUT", None)
                                    if direction == "out"
                                    else getattr(gpiod, "LINE_REQ_DIR_IN", None)
                                )
                                if req_type is None:
                                    req_type = 1 if direction == "out" else 0
                                try:
                                    self._line.request(consumer=self._consumer, type=req_type)
                                    requested = True
                                except Exception:
                                    # try request with older API
                                    try:
                                        self._line.request(req_type)
                                        requested = True
                                    except Exception:
                                        requested = False
                            except Exception:
                                requested = False

                        if not requested:
                            raise RuntimeError(
                                "Unsupported gpiod Python API on this system. "
                                "Please install a compatible python-libgpiod (v2.4) "
                                "or adjust the wrapper."
                            )

                    def write(self, value: bool):
                        self._line.set_value(1 if value else 0)

                    def read(self) -> bool:
                        return bool(self._line.get_value())

                    def close(self):
                        try:
                            self._line.release()
                        except Exception:
                            pass

                    def poll(self, timeout):
                        return False

                    def read_event(self):
                        return None

                # Make the module-level GPIO name point to the wrapper so the rest of the
                # code can instantiate it.
                globals()["GPIO"] = GpiodGPIO
            else:
                raise GPIOImportError()

        self._gpio_chip = self._resolve_gpio_chip(gpio_chip)
        self._pins: Dict[int, GPIO] = {}
        self._led_threads: Dict[int, threading.Thread] = {}  # Track active LED threads
        self._led_stop_events: Dict[int, threading.Event] = {}  # Stop events for LED threads
        self._input_callbacks: Dict[int, Callable] = {}  # Track input pin callbacks
        self._edge_threads: Dict[int, threading.Thread] = {}  # Track edge detection threads
        self._edge_stop_events: Dict[int, threading.Event] = {}  # Stop events for edge threads

        logger.debug(
            f"GPIO Manager initialized with chip: {self._gpio_chip} using backend: {self._backend}"
        )

    def _resolve_gpio_chip(self, gpio_chip: str) -> str:
        """Resolve GPIO chip path, auto-detecting if needed"""
        if gpio_chip == "auto":
            chips = sorted(glob.glob("/dev/gpiochip*"))
            if chips:
                logger.info(f"Auto-detected GPIO chips: {chips}, using {chips[0]}")
                return chips[0]
            else:
                logger.warning("No GPIO chips found, defaulting to /dev/gpiochip0")
                return "/dev/gpiochip0"
        return gpio_chip

    def _gpio_ref_for_pin(self, pin_number: int):
        """
        Resolve a configured pin number to a gpiochip path and line offset.

        Raspberry Pi style BCM numbers are line offsets on /dev/gpiochip0 and
        continue to work as before. Luckfox/Rockchip documentation often uses
        global GPIO numbers (bank * 32 + offset). When a configured pin is 32
        or higher and the matching /dev/gpiochip<bank> exists, split it into
        the banked character device expected by python-periphery/libgpiod.
        """
        if pin_number >= 32:
            bank = pin_number // 32
            line = pin_number % 32
            chip = f"/dev/gpiochip{bank}"
            if os.path.exists(chip):
                logger.debug("Mapped global GPIO %s to %s line %s", pin_number, chip, line)
                return chip, line
        return self._gpio_chip, pin_number

    def setup_output_pin(self, pin_number: int, initial_value: bool = False) -> bool:
        """
        Setup an output pin with initial value

        Args:
            pin_number: GPIO line number
            initial_value: Initial state (True=HIGH, False=LOW)
        """
        if pin_number == -1:
            return False

        try:
            # Close existing pin if already configured
            if pin_number in self._pins:
                self._pins[pin_number].close()
                del self._pins[pin_number]

            chip, line = self._gpio_ref_for_pin(pin_number)
            gpio = GPIO(chip, line, "out")
            gpio.write(initial_value)
            self._pins[pin_number] = gpio

            logger.debug(f"Output pin {pin_number} configured (initial={initial_value})")
            return True
        except Exception as e:
            error_msg = str(e).lower()
            if "busy" in error_msg or "device or resource busy" in error_msg:
                logger.error(f"GPIO pin {pin_number} is already in use by another process: {e}")
                print(f"\nFATAL: GPIO Pin {pin_number} is already in use")
                print("━" * 60)
                print("The pin is being used by another process.")
                print(f"\nDebug: sudo lsof /dev/gpiochip* | grep {pin_number}")
                print("\nThe system cannot function without GPIO access.")
                print("━" * 60)
                raise RuntimeError(f"GPIO pin {pin_number} is already in use by another process") from e
            elif "permission denied" in error_msg:
                logger.error(f"Permission denied for GPIO pin {pin_number}: {e}")
                print(f"\nFATAL: Permission denied for GPIO pin {pin_number}")
                print("━" * 60)
                print("Solutions:")
                print("  • Add user to gpio group: sudo usermod -a -G gpio $USER")
                print("  • Then logout and login again")
                print("━" * 60)
                raise RuntimeError(f"Permission denied for GPIO pin {pin_number}") from e
            else:
                logger.error(
                    f"Failed to setup output pin {pin_number} on {self._gpio_chip} "
                    f"(backend={self._backend}): {e}"
                )
                print(
                    f"\nFATAL: Cannot setup GPIO pin {pin_number} on {self._gpio_chip} "
                    f"(backend={self._backend})"
                )
                print("━" * 60)
                print(f"Error: {e}")
                print("\nThe system cannot function without GPIO access.")
                print("━" * 60)
                raise RuntimeError(f"Cannot setup GPIO output pin {pin_number}: {e}") from e

    def setup_input_pin(
        self,
        pin_number: int,
        pull_up: bool = False,
        callback: Optional[Callable] = None,
    ) -> bool:
        """
        Setup an input pin with optional callback using hardware edge detection

        Args:
            pin_number: GPIO line number
            pull_up: Enable pull-up resistor (not all chips support this)
            callback: Function to call on rising edge (hardware interrupt)
        """
        if pin_number == -1:
            return False

        try:
            # Close existing pin if already configured
            if pin_number in self._pins:
                self._pins[pin_number].close()
                del self._pins[pin_number]

            # Determine bias setting
            bias = "pull_up" if pull_up else "default"

            # Open GPIO pin as input with edge detection if callback provided
            if callback:
                # For gpiod backend, libgpiod does not provide the same edge API here
                # so we open a plain input and use a polling thread to detect edges.
                chip, line = self._gpio_ref_for_pin(pin_number)
                if self._backend == "gpiod":
                    gpio = GPIO(chip, line, "in", bias=bias)
                    self._input_callbacks[pin_number] = callback
                    # start polling-based detection
                    self._start_polling_detection(pin_number)
                else:
                    gpio = GPIO(chip, line, "in", bias=bias, edge="rising")
                    self._input_callbacks[pin_number] = callback
                    self._start_edge_detection(pin_number)
            else:
                chip, line = self._gpio_ref_for_pin(pin_number)
                gpio = GPIO(chip, line, "in", bias=bias)

            self._pins[pin_number] = gpio

            logger.debug(
                f"Input pin {pin_number} configured "
                f"(pull_up={pull_up}, callback={callback is not None})"
            )
            return True
        except Exception as e:
            error_msg = str(e).lower()
            if "busy" in error_msg or "device or resource busy" in error_msg:
                logger.error(f"GPIO pin {pin_number} is already in use by another process: {e}")
                print(f"\nFATAL: GPIO Pin {pin_number} is already in use")
                print("━" * 60)
                print("The pin is being used by another process.")
                print(f"\nDebug: sudo lsof /dev/gpiochip* | grep {pin_number}")
                print("\nThe system cannot function without GPIO access.")
                print("━" * 60)
                raise RuntimeError(f"GPIO pin {pin_number} is already in use by another process") from e
            elif "permission denied" in error_msg:
                logger.error(f"Permission denied for GPIO pin {pin_number}: {e}")
                print(f"\nFATAL: Permission denied for GPIO pin {pin_number}")
                print("━" * 60)
                print("Solutions:")
                print("  • Add user to gpio group: sudo usermod -a -G gpio $USER")
                print("  • Then logout and login again")
                print("━" * 60)
                raise RuntimeError(f"Permission denied for GPIO pin {pin_number}") from e
            else:
                logger.error(
                    f"Failed to setup input pin {pin_number} on {self._gpio_chip} "
                    f"(backend={self._backend}): {e}"
                )
                print(
                    f"\nFATAL: Cannot setup GPIO pin {pin_number} on {self._gpio_chip} "
                    f"(backend={self._backend})"
                )
                print("━" * 60)
                print(f"Error: {e}")
                print("\nThe system cannot function without GPIO access.")
                print("━" * 60)
                raise RuntimeError(f"Cannot setup GPIO input pin {pin_number}: {e}") from e

    def setup_interrupt_pin(
        self,
        pin_number: int,
        pull_up: bool = False,
        callback: Optional[Callable] = None,
    ) -> Optional[GPIO]:
        """
        Setup an interrupt pin with edge detection (alias for setup_input_pin)

        Args:
            pin_number: GPIO line number
            pull_up: Enable pull-up resistor
            callback: Function to call on rising edge (hardware interrupt)

        Returns:
            GPIO object for direct access, or None on failure
        """
        if pin_number == -1:
            return None

        try:
            # Close existing pin if already configured
            if pin_number in self._pins:
                self._pins[pin_number].close()
                del self._pins[pin_number]

            # Determine bias setting
            bias = "pull_up" if pull_up else "default"

            # Open GPIO pin as input with edge detection on rising edge or polling for gpiod
            chip, line = self._gpio_ref_for_pin(pin_number)
            if self._backend == "gpiod":
                gpio = GPIO(chip, line, "in", bias=bias)
                self._pins[pin_number] = gpio
                if callback:
                    self._input_callbacks[pin_number] = callback
                    self._start_polling_detection(pin_number)
            else:
                gpio = GPIO(chip, line, "in", bias=bias, edge="rising")
                self._pins[pin_number] = gpio
                if callback:
                    self._input_callbacks[pin_number] = callback
                    self._start_edge_detection(pin_number)

            logger.debug(
                f"Interrupt pin {pin_number} configured "
                f"(pull_up={pull_up}, callback={callback is not None})"
            )
            return gpio
        except Exception as e:
            error_msg = str(e).lower()
            if "busy" in error_msg or "device or resource busy" in error_msg:
                print(f"\nFATAL: GPIO Pin {pin_number} is already in use")
                print("━" * 60)
                print("The pin is being used by another process.")
                print(f"\nDebug: sudo lsof /dev/gpiochip* | grep {pin_number}")
                print("\nThe system cannot function without GPIO access.")
                print("━" * 60)
                raise RuntimeError(f"GPIO pin {pin_number} is already in use by another process") from e
            elif "permission denied" in error_msg:
                print(f"\nFATAL: Permission denied for GPIO pin {pin_number}")
                print("━" * 60)
                print("Solutions:")
                print("  • Add user to gpio group: sudo usermod -a -G gpio $USER")
                print("  • Then logout and login again")
                print("━" * 60)
                raise RuntimeError(f"Permission denied for GPIO pin {pin_number}") from e
            else:
                logger.error(
                    f"Failed to setup interrupt pin {pin_number} on {self._gpio_chip} "
                    f"(backend={self._backend}): {e}"
                )
                print(
                    f"\nFATAL: Cannot setup GPIO pin {pin_number} on {self._gpio_chip} "
                    f"(backend={self._backend})"
                )
                print("━" * 60)
                print(f"Error: {e}")
                print("\nThe system cannot function without GPIO access.")
                print("━" * 60)
                raise RuntimeError(f"Cannot setup GPIO interrupt pin {pin_number}: {e}") from e

    def _start_edge_detection(self, pin_number: int) -> None:
        """Start hardware edge detection thread"""
        stop_event = threading.Event()
        self._edge_stop_events[pin_number] = stop_event

        thread = threading.Thread(
            target=self._monitor_edge_events,
            args=(pin_number, stop_event),
            daemon=True,
            name=f"GPIO-Edge-{pin_number}",
        )
        thread.start()
        self._edge_threads[pin_number] = thread
        logger.debug(f"Edge detection thread started for pin {pin_number}")

    def _start_polling_detection(self, pin_number: int, interval: float = 0.02) -> None:
        """Start a polling thread to detect rising edges for GPIO lines.

        This is used with the gpiod backend.
        """
        stop_event = threading.Event()
        self._edge_stop_events[pin_number] = stop_event

        thread = threading.Thread(
            target=self._monitor_polling,
            args=(pin_number, stop_event, interval),
            daemon=True,
            name=f"GPIO-Poll-{pin_number}",
        )
        thread.start()
        self._edge_threads[pin_number] = thread
        logger.debug(
            f"Polling detection thread started for pin {pin_number} (interval={interval}s)"
        )

    def _monitor_polling(
        self, pin_number: int, stop_event: threading.Event, interval: float
    ) -> None:
        """Poll input state and invoke callback on rising edge (low->high)."""
        try:
            gpio = self._pins.get(pin_number)
            if not gpio:
                return

            # initialize last_state
            try:
                last_state = bool(gpio.read())
            except Exception:
                last_state = False

            while not stop_event.is_set() and pin_number in self._pins:
                try:
                    current = bool(self._pins[pin_number].read())
                    if current and not last_state:
                        callback = self._input_callbacks.get(pin_number)
                        if callback:
                            try:
                                callback()
                            except Exception:
                                pass
                    last_state = current
                    time.sleep(interval)
                except Exception:
                    if not stop_event.is_set():
                        time.sleep(0.1)

        except Exception as e:
            logger.error(f"Polling detection error for pin {pin_number}: {e}")

    def _monitor_edge_events(self, pin_number: int, stop_event: threading.Event) -> None:
        """Monitor hardware edge events using poll() for interrupts"""
        try:
            gpio = self._pins.get(pin_number)
            if not gpio:
                return

            while not stop_event.is_set() and pin_number in self._pins:
                try:
                    # Wait for edge event (kernel blocks until interrupt)
                    if gpio.poll(30.0) and not stop_event.is_set():
                        # Consume event from kernel queue to prevent repeated triggers
                        event: EdgeEvent = gpio.read_event()

                        # Only process rising edges (kernel filters, but verify)
                        if event.edge == "rising":
                            callback = self._input_callbacks.get(pin_number)
                            if callback:
                                callback()

                except Exception:
                    if not stop_event.is_set():
                        time.sleep(0.1)  # Brief pause on errors

        except Exception as e:
            logger.error(f"Edge detection error for pin {pin_number}: {e}")

    def set_pin_high(self, pin_number: int) -> bool:
        """Set output pin to HIGH"""
        if pin_number in self._pins:
            try:
                gpio = self._pins[pin_number]
                if gpio.direction == "out":
                    gpio.write(True)
                    return True
                else:
                    logger.warning(f"Pin {pin_number} is not configured as output")
            except Exception as e:
                logger.warning(f"Failed to set pin {pin_number} HIGH: {e}")
        return False

    def set_pin_low(self, pin_number: int) -> bool:
        """Set output pin to LOW"""
        if pin_number in self._pins:
            try:
                gpio = self._pins[pin_number]
                if gpio.direction == "out":
                    gpio.write(False)
                    return True
                else:
                    logger.warning(f"Pin {pin_number} is not configured as output")
            except Exception as e:
                logger.warning(f"Failed to set pin {pin_number} LOW: {e}")
        return False

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
        return None

    def cleanup_pin(self, pin_number: int) -> None:
        """Clean up a specific pin"""
        # Stop any LED thread for this pin
        if pin_number in self._led_stop_events:
            self._led_stop_events[pin_number].set()
        if pin_number in self._led_threads:
            self._led_threads[pin_number].join(timeout=2.0)
            del self._led_threads[pin_number]
        if pin_number in self._led_stop_events:
            del self._led_stop_events[pin_number]

        # Stop any edge detection thread for this pin
        if pin_number in self._edge_stop_events:
            self._edge_stop_events[pin_number].set()
        if pin_number in self._edge_threads:
            self._edge_threads[pin_number].join(timeout=2.0)
            del self._edge_threads[pin_number]
        if pin_number in self._edge_stop_events:
            del self._edge_stop_events[pin_number]

        # Remove callback
        if pin_number in self._input_callbacks:
            del self._input_callbacks[pin_number]

        # Close GPIO pin
        if pin_number in self._pins:
            try:
                self._pins[pin_number].close()
                del self._pins[pin_number]
                logger.debug(f"Pin {pin_number} cleaned up")
            except Exception as e:
                logger.warning(f"Failed to cleanup pin {pin_number}: {e}")

    def cleanup_all(self) -> None:
        """Clean up all managed pins"""
        # Stop all LED threads
        for stop_event in self._led_stop_events.values():
            stop_event.set()
        for thread in self._led_threads.values():
            thread.join(timeout=2.0)
        self._led_threads.clear()
        self._led_stop_events.clear()

        # Stop all edge detection threads
        for stop_event in self._edge_stop_events.values():
            stop_event.set()
        for thread in self._edge_threads.values():
            thread.join(timeout=2.0)
        self._edge_threads.clear()
        self._edge_stop_events.clear()

        # Clear callbacks
        self._input_callbacks.clear()

        # Clean up all pins
        for pin_number in list(self._pins.keys()):
            try:
                self._pins[pin_number].close()
                del self._pins[pin_number]
            except Exception as e:
                logger.warning(f"Failed to cleanup pin {pin_number}: {e}")

        logger.debug("All GPIO pins cleaned up")

    def _led_blink_thread(
        self, pin_number: int, duration: float, stop_event: threading.Event
    ) -> None:
        """Internal thread function to blink LED for specified duration"""
        try:
            # Turn LED on
            self.set_pin_high(pin_number)
            logger.debug(f"LED {pin_number} turned ON for {duration}s")

            # Wait for duration or stop event
            stop_event.wait(timeout=duration)

            # Turn LED off
            self.set_pin_low(pin_number)
            logger.debug(f"LED {pin_number} turned OFF")

        except Exception as e:
            logger.warning(f"LED {pin_number} thread error: {e}")
            # Ensure LED is off on error
            try:
                self.set_pin_low(pin_number)
            except Exception:
                pass
        finally:
            # Remove from active threads
            if pin_number in self._led_threads:
                del self._led_threads[pin_number]
            if pin_number in self._led_stop_events:
                del self._led_stop_events[pin_number]

    def blink_led(self, pin_number: int, duration: float = 0.2) -> None:
        """
        Blink LED for specified duration (non-blocking)

        Args:
            pin_number: GPIO pin number for LED
            duration: How long to keep LED on (seconds, default: 0.2)
        """
        if pin_number == -1:
            return  # LED disabled

        if pin_number not in self._pins:
            logger.debug(f"LED pin {pin_number} not configured, skipping")
            return

        try:
            # Stop any existing LED thread for this pin
            if pin_number in self._led_stop_events:
                self._led_stop_events[pin_number].set()
            if pin_number in self._led_threads:
                self._led_threads[pin_number].join(timeout=0.1)

            # Start new LED thread
            stop_event = threading.Event()
            self._led_stop_events[pin_number] = stop_event

            thread = threading.Thread(
                target=self._led_blink_thread,
                args=(pin_number, duration, stop_event),
                daemon=True,
                name=f"GPIO-LED-{pin_number}",
            )
            thread.start()
            self._led_threads[pin_number] = thread

        except Exception as e:
            logger.warning(f"Failed to start LED thread for pin {pin_number}: {e}")
