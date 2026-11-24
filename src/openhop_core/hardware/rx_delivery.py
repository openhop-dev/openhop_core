"""Hand a received frame to an RX callback together with its own signal metrics."""

import inspect
from typing import Callable


def deliver_rx_packet(callback: Callable[..., None], data: bytes, rssi: int, snr: float) -> None:
    """Call ``callback(data, rssi, snr)``, or ``callback(data)`` if it takes only data.

    The Dispatcher and RFFabric accept per-packet ``rssi``/``snr``. Without them
    they read the radio's ``last_rssi``/``last_snr`` later, from the event loop,
    by which time the reader thread may have stored the next frame's values.

    Binding is checked before the call, so a TypeError raised inside the
    callback is not mistaken for a data-only signature and delivered twice.
    """
    try:
        inspect.signature(callback).bind(data, rssi, snr)
    except (TypeError, ValueError):
        callback(data)
    else:
        callback(data, rssi, snr)
