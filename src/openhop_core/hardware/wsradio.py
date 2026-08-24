import asyncio
import json
import logging
import time

import websockets
from websockets.exceptions import ConnectionClosed

from .base import LoRaRadio

logger = logging.getLogger("WsRadio")


class WsRadio(LoRaRadio):
    def __init__(self, ip_address="192.168.0.33", port=81, timeout=30, radio_config=None):
        self.url = f"ws://{ip_address}:{port}"
        self.ws = None
        self.last_rssi = -99
        self.last_snr = 0.0
        self._connected = False
        self._last_tx_data = None  # Stores last transmitted packet
        self._last_tx_time = 0.0
        self._connection_lock = None  # Created on the running loop when first used
        self._recv_lock = None  # Created on the running loop when first used
        self._reconnect_delay = 1.0  # Start with 1 second
        self._max_reconnect_delay = 30.0  # Max 30 seconds
        self._timeout = timeout

        # Store radio configuration
        self.radio_config = radio_config
        if radio_config:
            logger.info(
                f"Radio config: freq={radio_config.frequency}MHz, "
                f"power={radio_config.tx_power}dBm, bw={radio_config.bandwidth}kHz, "
                f"sf={radio_config.spreading_factor}, cr={radio_config.coding_rate}, "
                f"preamble={radio_config.preamble_length}"
            )

    def _get_connection_lock(self) -> asyncio.Lock:
        if self._connection_lock is None:
            self._connection_lock = asyncio.Lock()
        return self._connection_lock

    def _get_recv_lock(self) -> asyncio.Lock:
        if self._recv_lock is None:
            self._recv_lock = asyncio.Lock()
        return self._recv_lock

    async def _send_radio_config(self):
        """Send radio configuration to the WebSocket radio."""
        if not self.radio_config or not self.ws:
            return

        try:
            config_msg = {
                "cmd": "SET_CONFIG",
                "frequency": self.radio_config.frequency,
                "tx_power": self.radio_config.tx_power,
                "bandwidth": self.radio_config.bandwidth,
                "spreading_factor": self.radio_config.spreading_factor,
                "coding_rate": self.radio_config.coding_rate,
                "preamble_length": self.radio_config.preamble_length,
                "sync_word": self.radio_config.sync_word,
                "crc_enabled": self.radio_config.crc_enabled,
            }

            await self.ws.send(json.dumps(config_msg))
            logger.info(f"Sent radio configuration: {config_msg}")

            # Wait for acknowledgment
            try:
                ack = await asyncio.wait_for(self.ws.recv(), timeout=self._timeout)
                logger.debug(f"Config ACK: {ack}")
            except asyncio.TimeoutError:
                logger.warning("No response to radio config (continuing anyway)")

        except Exception as e:
            logger.error(f"Failed to send radio config: {e}")

    async def _connect(self):
        async with self._get_connection_lock():  # Prevent concurrent connection attempts
            if self._connected and self.ws is not None:
                return  # Already connected

            try:
                if self.ws is not None:
                    try:
                        await self.ws.close()
                    except Exception as e:
                        logger.debug(f"Error closing existing connection: {e}")

                self.ws = await websockets.connect(self.url)
                self._connected = True
                self._reconnect_delay = 1.0  # Reset delay on successful connection
                logger.info(f"Connected to {self.url}")

                # Send radio configuration first
                await self._send_radio_config()

                # Then start RX mode
                await self.ws.send("START_RX")

                try:
                    ack = await asyncio.wait_for(self.ws.recv(), timeout=self._timeout)
                    logger.debug(f"RX: {ack}")
                except asyncio.TimeoutError:
                    logger.warning("No response to START_RX (continuing anyway)")

            except Exception as e:
                self._connected = False
                self.ws = None
                logger.error(f"Connection failed: {e}")
                # Exponential backoff with jitter
                await asyncio.sleep(self._reconnect_delay)
                self._reconnect_delay = min(self._reconnect_delay * 1.5, self._max_reconnect_delay)

    async def _ensure(self):
        if not self._connected:
            await self._connect()

    def begin(self):
        """Initialize the websocket radio (connection happens on first use)"""
        logger.info(f"WebSocket radio initialized for {self.url}")
        # Connection will be established when needed

    async def send(self, data: bytes):
        """Send packet via WebSocket. Returns None (no metadata available)."""
        await self._ensure()
        try:
            if self.ws is not None and self._connected:
                await self.ws.send(f"TX:{data.hex().upper()}")
                self._last_tx_data = data
                self._last_tx_time = time.time()

                logger.debug(f"TX: {data.hex().upper()}")
            else:
                logger.warning("WebSocket connection is not established (ws is None)")
                self._connected = False
                await asyncio.sleep(1)
        except Exception as e:
            logger.warning(f"Send failed: {e}")
            self._connected = False
            self.ws = None
            await asyncio.sleep(1)

    async def wait_for_rx(self) -> bytes:
        await self._ensure()
        async with self._get_recv_lock():  # Prevent concurrent recv calls
            while True:
                try:
                    if self.ws is None:
                        logger.warning("WebSocket connection is not established (ws is None)")
                        self._connected = False
                        await asyncio.sleep(1)
                        await self._ensure()
                        continue

                    msg = await self.ws.recv()
                    pkt = json.loads(msg)

                    hex_str = pkt.get("data") or pkt.get("hex")
                    if hex_str:
                        data = bytes.fromhex(hex_str.replace(" ", ""))

                        # Echo filter: skip exact match within short delay
                        if (
                            self._last_tx_data
                            and data == self._last_tx_data
                            and (time.time() - self._last_tx_time) < 0.5
                        ):
                            logger.warning("Ignored echo of own TX (exact match)")
                            continue

                        self.last_rssi = pkt.get("rssi", -99)
                        self.last_snr = pkt.get("snr", 0.0)
                        logger.debug(
                            f"RX: {data.hex()} (RSSI={self.last_rssi} SNR={self.last_snr})"
                        )
                        return data
                    else:
                        logger.warning(f"Unhandled RX format: {pkt}")

                except ConnectionClosed:
                    logger.info("Connection closed. Reconnecting...")
                    self._connected = False
                    self.ws = None
                    await asyncio.sleep(1)
                    await self._ensure()

                except json.JSONDecodeError as e:
                    logger.warning(
                        f"JSON error: {e} — Raw message: {msg if 'msg' in locals() else 'unknown'}"
                    )

                except Exception as e:
                    logger.warning(f"Unexpected error: {e}")
                    self._connected = False
                    self.ws = None
                    await asyncio.sleep(1)
                    await self._ensure()

    def get_last_rssi(self):
        return self.last_rssi

    def get_last_snr(self):
        return self.last_snr

    def sleep(self):
        print("Sleep (noop)")
