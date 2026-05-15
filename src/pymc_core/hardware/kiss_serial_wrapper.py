"""
KISS Serial Protocol Wrapper

"""

import asyncio
import logging
import threading
from collections import deque
from typing import Any, Callable, Dict, Optional

import serial

from .base import LoRaRadio

# KISS Protocol Constants
KISS_FEND = 0xC0  # Frame End
KISS_FESC = 0xDB  # Frame Escape
KISS_TFEND = 0xDC  # Transposed Frame End
KISS_TFESC = 0xDD  # Transposed Frame Escape

# KISS Command Masks
KISS_MASK_PORT = 0xF0
KISS_MASK_CMD = 0x0F

# KISS Commands
KISS_CMD_DATA = 0x00
KISS_CMD_TXDELAY = 0x01
KISS_CMD_PERSIST = 0x02
KISS_CMD_SLOTTIME = 0x03
KISS_CMD_TXTAIL = 0x04
KISS_CMD_FULLDUP = 0x05
KISS_CMD_VENDOR = 0x06
KISS_CMD_RETURN = 0xFF

# Buffer and timing constants
MAX_FRAME_SIZE = 512
RX_BUFFER_SIZE = 1024
TX_BUFFER_SIZE = 1024
DEFAULT_BAUDRATE = 115200
DEFAULT_TIMEOUT = 1.0

logger = logging.getLogger("KissSerialWrapper")


class KissSerialWrapper(LoRaRadio):
    """
    KISS Serial Protocol Interface

    Provides full-duplex KISS protocol communication over serial port.
    Handles frame encoding/decoding, buffering, and configuration commands.
    Implements the LoRaRadio interface for PyMC Core compatibility.
    """

    def __init__(
        self,
        port: str,
        baudrate: int = DEFAULT_BAUDRATE,
        timeout: float = DEFAULT_TIMEOUT,
        kiss_port: int = 0,
        on_frame_received: Optional[Callable[[bytes], None]] = None,
        radio_config: Optional[Dict[str, Any]] = None,
        auto_configure: bool = True,
    ):
        """
        Initialize KISS Serial Wrapper

        Args:
            port: Serial port device path (e.g., '/dev/ttyUSB0',
            '/dev/cu.usbserial-0001', 'comm1', etc.)
            baudrate: Serial communication baud rate (default: 115200)
            timeout: Serial read timeout in seconds (default: 1.0)
            kiss_port: KISS port number (0-15, default: 0)
            on_frame_received: Callback for received HDLC frames
            radio_config: Optional radio configuration dict with keys:
                         frequency, bandwidth, sf, cr, sync_word, power, etc.
            auto_configure: If True, automatically configure radio and enter KISS mode
        """
        self.port = port
        self.baudrate = baudrate
        self.timeout = timeout
        self.kiss_port = kiss_port & 0x0F  # Ensure 4-bit port number
        self.auto_configure = auto_configure

        self.radio_config = radio_config or {}
        self.is_configured = False
        self.kiss_mode_active = False

        self.serial_conn: Optional[serial.Serial] = None

        self.rx_buffer = deque(maxlen=RX_BUFFER_SIZE)
        self.tx_buffer = deque(maxlen=TX_BUFFER_SIZE)

        self.rx_frame_buffer = bytearray()
        self.in_frame = False
        self.escaped = False

        self.rx_thread: Optional[threading.Thread] = None
        self.tx_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()

        # Callbacks
        self.on_frame_received = on_frame_received


        # KISS Configuration
        self.config = {
            "txdelay": 30,  # TX delay (units of 10ms)
            "persist": 64,  # P parameter (0-255)
            "slottime": 10,  # Slot time (units of 10ms)
            "txtail": 1,  # TX tail time (units of 10ms)
            "fulldup": False,  # Full duplex mode
        }

        self.stats = {
            "frames_sent": 0,
            "frames_received": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
            "frame_errors": 0,
            "buffer_overruns": 0,
            "last_rssi": None,
            "last_snr": None,
            "noise_floor": None,
        }

    @property
    def is_connected(self) -> bool:
        return (
            self.rx_thread is not None and self.rx_thread.is_alive()
            and self.tx_thread is not None and self.tx_thread.is_alive()
        )

    def connect(self) -> bool:
        """
        Connect to serial port and start communication threads

        Returns:
            True if connection successful, False otherwise
        """
        try:
            self.serial_conn = serial.Serial(
                port=self.port,
                baudrate=self.baudrate,
                timeout=self.timeout,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
            )

            self.stop_event.clear()

            # Start communication threads
            self.rx_thread = threading.Thread(target=self._rx_worker, daemon=True)
            self.tx_thread = threading.Thread(target=self._tx_worker, daemon=True)

            self.rx_thread.start()
            self.tx_thread.start()

            logger.info(f"KISS serial connected to {self.port} at {self.baudrate} baud")

            # Auto-configure if requested
            if self.auto_configure:
                if not self.configure_radio_and_enter_kiss():
                    logger.warning("Auto-configuration failed, KISS mode not active")
                    return False

            return True

        except Exception as e:
            logger.error(f"Failed to connect to {self.port}: {e}")
            return False

    def disconnect(self):
        """Disconnect from serial port and stop threads"""
        self.stop_event.set()

        # Wait for threads to finish
        if self.rx_thread and self.rx_thread.is_alive():
            self.rx_thread.join(timeout=2.0)
        if self.tx_thread and self.tx_thread.is_alive():
            self.tx_thread.join(timeout=2.0)

        # Close serial connection
        if self.serial_conn and self.serial_conn.is_open:
            self.serial_conn.close()

        logger.info(f"KISS serial disconnected from {self.port}")

    def cleanup(self) -> None:
        self.disconnect()

    def send_frame(self, data: bytes) -> bool:
        """
        Send a data frame via KISS protocol

        Args:
            data: Raw frame data to send

        Returns:
            True if frame queued successfully, False otherwise
        """
        if not self.is_connected or len(data) > MAX_FRAME_SIZE:
            logger.warning(
                f"Cannot send frame - connected: {self.is_connected}, "
                f"size: {len(data)}/{MAX_FRAME_SIZE}"
            )
            return False

        try:
            # Create KISS frame
            kiss_frame = self._encode_kiss_frame(KISS_CMD_DATA, data)

            # Add to TX buffer
            if len(self.tx_buffer) < TX_BUFFER_SIZE:
                self.tx_buffer.append(kiss_frame)
                return True
            else:
                self.stats["buffer_overruns"] += 1
                logger.warning("TX buffer overrun")
                return False

        except Exception as e:
            logger.error(f"Failed to send frame: {e}")
            return False

    def send_config_command(self, cmd: int, value: int) -> bool:
        """
        Send KISS configuration command

        Args:
            cmd: KISS command type (KISS_CMD_*)
            value: Command parameter value

        Returns:
            True if command sent successfully, False otherwise
        """
        if not self.is_connected:
            return False

        try:
            # Update local config
            if cmd == KISS_CMD_TXDELAY:
                self.config["txdelay"] = value
            elif cmd == KISS_CMD_PERSIST:
                self.config["persist"] = value
            elif cmd == KISS_CMD_SLOTTIME:
                self.config["slottime"] = value
            elif cmd == KISS_CMD_TXTAIL:
                self.config["txtail"] = value
            elif cmd == KISS_CMD_FULLDUP:
                self.config["fulldup"] = bool(value)

            # Create and send KISS command frame
            kiss_frame = self._encode_kiss_frame(cmd, bytes([value]))

            if len(self.tx_buffer) < TX_BUFFER_SIZE:
                self.tx_buffer.append(kiss_frame)
                return True
            else:
                self.stats["buffer_overruns"] += 1
                return False

        except Exception as e:
            logger.error(f"Failed to send config command: {e}")
            return False

    def get_stats(self) -> Dict[str, Any]:
        """Get interface statistics"""
        return self.stats.copy()

    def get_config(self) -> Dict[str, Any]:
        """Get current KISS configuration"""
        return self.config.copy()

    def configure_radio_and_enter_kiss(self) -> bool:
        """
        Configure radio settings and enter KISS mode

        Returns:
            True if configuration successful, False otherwise
        """
        if not self.is_connected:
            logger.error("Cannot configure radio: not connected")
            return False

        try:
            if self.radio_config:
                if not self._configure_radio():
                    logger.error("Radio configuration failed")
                    return False

            if not self._enter_kiss_mode():
                logger.error("Failed to enter KISS mode")
                return False

            self.kiss_mode_active = True
            logger.info("Successfully configured radio and entered KISS mode")
            return True

        except Exception as e:
            logger.error(f"Configuration failed: {e}")
            return False

    def _configure_radio(self) -> bool:
        """
        Send radio configuration commands

        Returns:
            True if configuration successful, False otherwise
        """
        if not self.serial_conn or not self.serial_conn.is_open:
            return False

        try:
            # Extract configuration parameters with defaults
            frequency_hz = self.radio_config.get("frequency", int(916.75 * 1000000))
            bandwidth_hz = self.radio_config.get("bandwidth", int(500.0 * 1000))
            sf = self.radio_config.get("spreading_factor", 5)
            cr = self.radio_config.get("coding_rate", 5)
            sync_word = self.radio_config.get("sync_word", 0x12)
            power = self.radio_config.get("power", 20)  # noqa: F841 - kept for future use

            # Convert Hz values to MHz/kHz for KISS command
            frequency = frequency_hz / 1000000.0  # Convert Hz to MHz
            bandwidth = bandwidth_hz / 1000.0  # Convert Hz to kHz

            # Format sync_word as hex if it's an integer
            if isinstance(sync_word, int):
                sync_word_str = f"0x{sync_word:02X}"
            else:
                sync_word_str = str(sync_word)

            # Build command string: set radio <freq>,<bw>,<sf>,<coding-rate>,<syncword>
            # Note: power parameter kept in config but not used in current command format
            radio_cmd = f"set radio {frequency},{bandwidth},{sf},{cr},{sync_word_str}\r\n"
            logger.info(radio_cmd)

            # Send command
            self.serial_conn.write(radio_cmd.encode("ascii"))
            self.serial_conn.flush()

            # Wait for response
            threading.Event().wait(0.5)

            # Read any response
            response = ""
            if self.serial_conn.in_waiting > 0:
                response = self.serial_conn.read(self.serial_conn.in_waiting).decode(
                    "ascii", errors="ignore"
                )

            logger.info(f"Radio config sent: {radio_cmd.strip()}")
            if response:
                logger.debug(f"Radio config response: {response.strip()}")

            self.is_configured = True
            return True

        except Exception as e:
            logger.error(f"Radio configuration error: {e}")
            return False

    def _enter_kiss_mode(self) -> bool:
        """
        Enter KISS serial mode

        Returns:
            True if KISS mode entered successfully, False otherwise
        """
        if not self.serial_conn or not self.serial_conn.is_open:
            return False

        try:
            # Send command to enter KISS mode
            kiss_cmd = "serial mode kiss\r\n"
            self.serial_conn.write(kiss_cmd.encode("ascii"))
            self.serial_conn.flush()

            # Wait for mode switch
            threading.Event().wait(1.0)

            # Read any response
            response = ""
            if self.serial_conn.in_waiting > 0:
                response = self.serial_conn.read(self.serial_conn.in_waiting).decode(
                    "ascii", errors="ignore"
                )

            logger.info("Entered KISS mode")
            if response:
                logger.debug(f"KISS mode response: {response.strip()}")

            return True

        except Exception as e:
            logger.error(f"KISS mode entry error: {e}")
            return False

    def exit_kiss_mode(self) -> bool:
        """
        Exit KISS mode and return to CLI mode

        Returns:
            True if successfully exited KISS mode, False otherwise
        """
        if not self.is_connected or not self.kiss_mode_active:
            return False

        try:
            # Send KISS return command to exit mode
            return_frame = self._encode_kiss_frame(KISS_CMD_RETURN, b"")

            if self.serial_conn and self.serial_conn.is_open:
                self.serial_conn.write(return_frame)
                self.serial_conn.flush()

                # Wait for mode switch
                threading.Event().wait(1.0)

                self.kiss_mode_active = False
                logger.info("Exited KISS mode")
                return True

        except Exception as e:
            logger.error(f"Failed to exit KISS mode: {e}")

        return False

    def send_cli_command(self, command: str) -> Optional[str]:
        """
        Send a CLI command (only works when not in KISS mode)

        Args:
            command: CLI command to send

        Returns:
            Response string if available, None otherwise
        """
        if not self.is_connected or self.kiss_mode_active or not self.serial_conn:
            logger.error("Cannot send CLI command: not connected or in KISS mode")
            return None

        try:
            # Send command
            cmd_line = f"{command}\r\n"
            self.serial_conn.write(cmd_line.encode("ascii"))
            self.serial_conn.flush()

            # Wait for response
            threading.Event().wait(0.5)

            # Read response
            response = ""
            if self.serial_conn.in_waiting > 0:
                response = self.serial_conn.read(self.serial_conn.in_waiting).decode(
                    "ascii", errors="ignore"
                )

            logger.debug(f"CLI command: {command.strip()} -> {response.strip()}")
            return response.strip() if response else None

        except Exception as e:
            logger.error(f"CLI command error: {e}")
            return None

    def set_rx_callback(self, callback: Callable[[bytes], None]):
        """
        Set the RX callback function

        Args:
            callback: Function to call when a frame is received
        """
        self.on_frame_received = callback
        logger.debug("RX callback set")

    def begin(self):
        """
        Initialize the radio
        """
        success = self.connect()
        if not success:
            raise Exception("Failed to initialize KISS radio")

    async def send(self, data: bytes) -> None:
        """
        Send data via KISS TNC. Returns None (no metadata available).

        Args:
            data: Data to send

        Raises:
            Exception: If send fails
        """
        success = self.send_frame(data)
        if not success:
            raise Exception("Failed to send frame via KISS TNC")
        return None

    async def wait_for_rx(self) -> bytes:
        """
        Wait for a packet to be received asynchronously

        Returns:
            Received packet data
        """
        # Create a future to wait for the next received frame
        future = asyncio.Future()

        # Store the original callback
        original_callback = self.on_frame_received

        # Set a temporary callback that completes the future
        def temp_callback(data: bytes):
            if not future.done():
                future.set_result(data)
            # Restore original callback if it exists
            if original_callback:
                try:
                    original_callback(data)
                except Exception as e:
                    logger.error(f"Error in original callback: {e}")

        self.on_frame_received = temp_callback

        try:
            # Wait for the next frame
            data = await future
            return data
        finally:
            # Restore original callback
            self.on_frame_received = original_callback

    def sleep(self):
        """
        Put the radio into low-power mode

        Note: KISS TNCs typically don't have software sleep control
        """
        logger.debug("Sleep mode not supported for KISS TNC")
        pass

    def get_last_rssi(self) -> int:
        """
        Return last received RSSI in dBm

        Returns:
            Last RSSI value or -999 if not available
        """
        return self.stats.get("last_rssi", -999)

    def get_last_snr(self) -> float:
        """
        Return last received SNR in dB

        Returns:
            Last SNR value or -999.0 if not available
        """
        return self.stats.get("last_snr", -999.0)

    def _encode_kiss_frame(self, cmd: int, data: bytes) -> bytes:
        """
        Encode data into KISS frame format

        Args:
            cmd: KISS command byte
            data: Raw data to encode

        Returns:
            Encoded KISS frame
        """
        # Create command byte with port number
        cmd_byte = ((self.kiss_port << 4) & KISS_MASK_PORT) | (cmd & KISS_MASK_CMD)

        # Start with FEND and command
        frame = bytearray([KISS_FEND, cmd_byte])

        # Escape and add data
        for byte in data:
            if byte == KISS_FEND:
                frame.extend([KISS_FESC, KISS_TFEND])
            elif byte == KISS_FESC:
                frame.extend([KISS_FESC, KISS_TFESC])
            else:
                frame.append(byte)

        # End with FEND
        frame.append(KISS_FEND)

        return bytes(frame)

    def _decode_kiss_byte(self, byte: int):
        """
        Process received byte for KISS frame decoding

        Args:
            byte: Received byte
        """
        if byte == KISS_FEND:
            if self.in_frame and len(self.rx_frame_buffer) > 1:
                # Complete frame received
                self._process_received_frame()
            # Start new frame
            self.rx_frame_buffer.clear()
            self.in_frame = True
            self.escaped = False

        elif byte == KISS_FESC:
            if self.in_frame:
                self.escaped = True

        elif self.escaped:
            if byte == KISS_TFEND:
                self.rx_frame_buffer.append(KISS_FEND)
            elif byte == KISS_TFESC:
                self.rx_frame_buffer.append(KISS_FESC)
            else:
                # Invalid escape sequence
                self.stats["frame_errors"] += 1
                logger.warning(f"Invalid KISS escape sequence: 0x{byte:02X}")
            self.escaped = False

        else:
            if self.in_frame:
                self.rx_frame_buffer.append(byte)

    def _process_received_frame(self):
        """Process a complete received KISS frame"""
        if len(self.rx_frame_buffer) < 1:
            return

        # Extract command byte
        cmd_byte = self.rx_frame_buffer[0]
        port = (cmd_byte & KISS_MASK_PORT) >> 4
        cmd = cmd_byte & KISS_MASK_CMD

        # Check if frame is for our port
        if port != self.kiss_port:
            return

        # Extract data payload
        data = bytes(self.rx_frame_buffer[1:])

        if cmd == KISS_CMD_DATA:
            # Data frame - emit to callback
            if self.on_frame_received and len(data) > 0:
                self.stats["frames_received"] += 1
                self.stats["bytes_received"] += len(data)
                try:
                    self.on_frame_received(data)
                except Exception as e:
                    logger.error(f"Error in frame received callback: {e}")
        else:
            # Configuration command response
            logger.debug(f"Received KISS config command: cmd=0x{cmd:02X}, data={data.hex()}")

    def _rx_worker(self):
        """Background thread for receiving data"""
        while not self.stop_event.is_set():
            try:
                if self.serial_conn and self.serial_conn.in_waiting > 0:
                    # Read available bytes
                    data = self.serial_conn.read(self.serial_conn.in_waiting)

                    # Process each byte through KISS decoder
                    for byte in data:
                        self._decode_kiss_byte(byte)

                else:
                    # Short sleep when no data available
                    threading.Event().wait(0.01)

            except Exception as e:
                logger.error(f"RX worker error: {e}")
                break

    def _tx_worker(self):
        """Background thread for sending data"""
        while not self.stop_event.is_set():
            try:
                if self.tx_buffer:
                    # Get frame from buffer
                    frame = self.tx_buffer.popleft()

                    # Send via serial
                    if self.serial_conn and self.serial_conn.is_open:
                        self.serial_conn.write(frame)
                        self.serial_conn.flush()

                        self.stats["frames_sent"] += 1
                        self.stats["bytes_sent"] += len(frame)
                    else:
                        logger.warning("Serial connection not open or not available")
                else:
                    # Short sleep when no data to send
                    threading.Event().wait(0.01)

            except Exception as e:
                logger.error(f"TX worker error: {e}")
                break

    def __enter__(self):
        """Context manager entry"""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.disconnect()

    def __del__(self):
        """Destructor to ensure cleanup"""
        try:
            self.disconnect()
        except Exception:
            pass  # Ignore errors during destruction


if __name__ == "__main__":
    # Example usage
    import time

    def on_frame_received(data):
        print(f"Received frame: {data.hex()}")

    # Radio configuration example
    radio_config = {
        "frequency": int(916.75 * 1000000),  # US: 916.75 MHz
        "bandwidth": int(500.0 * 1000),  # 500 kHz
        "spreading_factor": 5,  # LoRa SF5
        "coding_rate": 5,  # LoRa CR 4/5
        "sync_word": 0x16,  # Sync word
        "power": 20,  # TX power
    }

    # Initialize with auto-configuration
    kiss = KissSerialWrapper(
        port="/dev/ttyUSB0",
        baudrate=115200,
        radio_config=radio_config,
        on_frame_received=on_frame_received,
    )

    try:
        if kiss.connect():
            print("Connected and configured successfully")
            print(f"Configuration: {kiss.get_config()}")
            print(f"Statistics: {kiss.get_stats()}")

            # Send a test frame
            kiss.send_frame(b"Hello KISS World!")

            # Keep running for a bit
            time.sleep(5)
        else:
            print("Failed to connect")

    except KeyboardInterrupt:
        print("Interrupted by user")
    finally:
        kiss.disconnect()
