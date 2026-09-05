from abc import ABC, abstractmethod
from typing import Optional


class LoRaRadio(ABC):
    @abstractmethod
    def begin(self):
        """Initialise the radio module."""
        pass

    @abstractmethod
    async def send(self, data: bytes):
        """Send a packet asynchronously.

        On success return a transmission metadata mapping (possibly empty).
        Return None only on failure; Dispatcher treats None as a failed send.
        """
        pass

    @abstractmethod
    async def wait_for_rx(self) -> bytes:
        """Wait for a packet to be received asynchronously."""
        pass

    @abstractmethod
    def sleep(self):
        """Put the radio into low-power mode."""
        pass

    @abstractmethod
    def get_last_rssi(self) -> int:
        """Return last received RSSI in dBm."""
        pass

    @abstractmethod
    def get_last_snr(self) -> float:
        """Return last received SNR in dB."""
        pass

    def get_cached_noise_floor(self) -> Optional[float]:
        """Return the last measured channel noise floor in dBm, or None.

        Optional capability with a strict contract: an override MUST be
        nonblocking and MUST return only an already-taken measurement — never
        trigger modem I/O or return an initialisation placeholder. Backends
        without such a cached value (including ones whose synchronous getter
        would block on the modem) keep this default; callers treat None as
        "no measurement available" and fall back to their existing behaviour.
        """
        return None
