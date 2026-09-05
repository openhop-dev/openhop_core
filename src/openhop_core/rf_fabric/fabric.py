"""RFFabric: multi-endpoint RF container.

Registers N radios, stamps each RX with ``radio_id``, and selects a default or
explicit radio for TX. Each physical callback yields one ``RFIngress`` with one
``RadioReception``. Dispatcher-level dedup collapses duplicate mesh handling.
"""

from __future__ import annotations

import logging
from collections import OrderedDict
from typing import Any, Awaitable, Callable, Optional

from .models import RadioReception, RFIngress

logger = logging.getLogger("RFFabric")

LegacyRxCallback = Callable[..., Any]
TxSelector = Callable[[bytes], Optional[str]]


class RFFabric:
    """Multi-radio fabric with per-edge ingress delivery and selectable TX."""

    def __init__(self) -> None:
        # Stable insertion order for default TX / attribute pass-through.
        self._radios: "OrderedDict[str, Any]" = OrderedDict()
        self._default_radio_id: Optional[str] = None
        self._ingress_callback: Optional[Callable[[RFIngress], Any]] = None
        self._legacy_rx_callback: Optional[LegacyRxCallback] = None
        self._tx_selector: Optional[TxSelector] = None
        self._origin_tx: str = "default"
        self._armed = False
        # Latest delivered reception metrics (for FabricRadio get_last_*).
        self._last_rssi: int = 0
        self._last_snr: float = 0.0
        self._last_rx_radio_id: Optional[str] = None

    # ------------------------------------------------------------------
    # Registry
    # ------------------------------------------------------------------

    @property
    def radio(self) -> Any:
        """Default / first registered radio."""
        rid = self.default_radio_id
        if rid is None:
            return None
        return self._radios.get(rid)

    @property
    def radio_id(self) -> Optional[str]:
        """Default radio id."""
        return self.default_radio_id

    @property
    def last_rx_radio_id(self) -> Optional[str]:
        """Radio id that delivered the most recent RX, if any."""
        return self._last_rx_radio_id

    @property
    def default_radio_id(self) -> Optional[str]:
        if self._default_radio_id and self._default_radio_id in self._radios:
            return self._default_radio_id
        if self._radios:
            return next(iter(self._radios.keys()))
        return None

    @property
    def radios(self) -> "OrderedDict[str, Any]":
        """Copy-like view of registered radios (insertion order)."""
        return OrderedDict(self._radios)

    def get_radio(self, radio_id: str) -> Any:
        try:
            return self._radios[radio_id]
        except KeyError as exc:
            raise KeyError(f"Unknown radio_id={radio_id!r}") from exc

    def register_radio(self, radio: Any, *, radio_id: str = "radio0") -> None:
        """Register a radio endpoint under a unique ``radio_id``."""
        if not radio_id:
            raise ValueError("radio_id must be a non-empty string")
        if radio_id in self._radios:
            raise RuntimeError(f"radio_id={radio_id!r} is already registered")
        # Prevent the same object under two ids (ambiguous TX/RX ownership).
        for existing_id, existing in self._radios.items():
            if existing is radio:
                raise RuntimeError(f"Radio object already registered as radio_id={existing_id!r}")
        self._radios[radio_id] = radio
        if self._default_radio_id is None:
            self._default_radio_id = radio_id
        if self._armed:
            self._bind_one(radio_id, radio)
        logger.debug(
            "RFFabric registered radio_id=%s (%s); count=%d",
            radio_id,
            type(radio).__name__,
            len(self._radios),
        )

    def unregister_radio(self, radio_id: Optional[str] = None) -> None:
        """Detach one radio (by id) or all radios when ``radio_id`` is None."""
        if radio_id is None:
            for rid in list(self._radios.keys()):
                self._unbind_one(rid)
            self._radios.clear()
            self._default_radio_id = None
            return

        radio = self._radios.pop(radio_id, None)
        if radio is None:
            return
        self._unbind_one(radio_id, radio)
        if self._default_radio_id == radio_id:
            self._default_radio_id = next(iter(self._radios.keys()), None)

    def set_default_radio(self, radio_id: str) -> None:
        if radio_id not in self._radios:
            raise KeyError(f"Unknown radio_id={radio_id!r}")
        self._default_radio_id = radio_id

    def set_tx_selector(self, selector: Optional[TxSelector]) -> None:
        """Optional policy: ``selector(data) -> radio_id | None`` for default TX."""
        self._tx_selector = selector

    @property
    def origin_tx(self) -> str:
        """Egress policy for locally originated packets: "default" or "all"."""
        return self._origin_tx

    def set_origin_tx(self, mode: str) -> None:
        """Set the egress policy for locally originated packets.

        - "default": origins TX on the default/selector radio (current
          behaviour, and the default).
        - "all": origins fan out to every registered radio via
          :meth:`send_all`. Bridge topologies need this: ``tx_mode=bridge``
          only steers *forwards* (RX radio -> the other radio); an origin
          packet has no RX side, so without fan-out it leaves on a single
          radio and never crosses the link.
        """
        mode_l = (mode or "default").strip().lower()
        if mode_l not in ("default", "all"):
            raise ValueError(f"Unknown origin_tx mode={mode!r}. Supported: default, all")
        self._origin_tx = mode_l

    # ------------------------------------------------------------------
    # Callbacks / arming
    # ------------------------------------------------------------------

    def set_ingress_callback(self, callback: Optional[Callable[[RFIngress], Any]]) -> None:
        """Receive each fabric ingress (typically one RadioReception)."""
        self._ingress_callback = callback

    def set_legacy_rx_callback(self, callback: Optional[LegacyRxCallback]) -> None:
        """Receive each reception with legacy ``(data, rssi, snr)`` signature."""
        self._legacy_rx_callback = callback

    def arm(self) -> None:
        """Bind fabric RX callbacks on every registered radio."""
        self._armed = True
        for radio_id, radio in self._radios.items():
            self._bind_one(radio_id, radio)

    def disarm(self) -> None:
        """Unbind fabric RX callbacks from every registered radio."""
        self._armed = False
        for radio_id in list(self._radios.keys()):
            self._unbind_one(radio_id)

    def _bind_one(self, radio_id: str, radio: Any) -> None:
        if not hasattr(radio, "set_rx_callback"):
            logger.warning(
                "Radio %s (%s) has no set_rx_callback; fabric will not receive",
                radio_id,
                type(radio).__name__,
            )
            return
        radio.set_rx_callback(self._make_rx_handler(radio_id))
        logger.debug(
            "RFFabric armed on radio_id=%s (%s)",
            radio_id,
            type(radio).__name__,
        )

    def _unbind_one(self, radio_id: str, radio: Any = None) -> None:
        target = radio if radio is not None else self._radios.get(radio_id)
        if target is None or not hasattr(target, "set_rx_callback"):
            return
        try:
            target.set_rx_callback(None)
        except Exception:
            logger.debug(
                "Clearing fabric radio RX callback failed for %s",
                radio_id,
                exc_info=True,
            )

    def _make_rx_handler(self, radio_id: str):
        def _handler(
            data: bytes,
            rssi: Optional[int] = None,
            snr: Optional[float] = None,
        ) -> None:
            self._on_radio_rx(radio_id, data, rssi, snr)

        return _handler

    def _on_radio_rx(
        self,
        radio_id: str,
        data: bytes,
        rssi: Optional[int] = None,
        snr: Optional[float] = None,
    ) -> None:
        """Convert one radio callback into one RFIngress + one legacy fire."""
        reception = RadioReception(
            data=data,
            rssi=rssi,
            snr=snr,
            radio_id=radio_id,
        )
        ingress = RFIngress.from_reception(reception)

        if rssi is not None:
            self._last_rssi = int(rssi)
        elif radio_id in self._radios and hasattr(self._radios[radio_id], "get_last_rssi"):
            try:
                self._last_rssi = int(self._radios[radio_id].get_last_rssi())
            except Exception:
                pass
        if snr is not None:
            self._last_snr = float(snr)
        elif radio_id in self._radios and hasattr(self._radios[radio_id], "get_last_snr"):
            try:
                self._last_snr = float(self._radios[radio_id].get_last_snr())
            except Exception:
                pass
        self._last_rx_radio_id = radio_id

        if self._ingress_callback is not None:
            try:
                result = self._ingress_callback(ingress)
                if isinstance(result, Awaitable):
                    # Sync radio edge; async consumers schedule themselves.
                    pass
            except Exception:
                logger.exception("RFFabric ingress callback failed")

        if self._legacy_rx_callback is not None:
            try:
                self._legacy_rx_callback(data, rssi, snr)
            except TypeError:
                try:
                    self._legacy_rx_callback(data)  # type: ignore[misc,call-arg]
                except Exception:
                    logger.exception("RFFabric legacy RX callback failed")
            except Exception:
                logger.exception("RFFabric legacy RX callback failed")

    # ------------------------------------------------------------------
    # TX
    # ------------------------------------------------------------------

    def resolve_tx_radio_id(self, data: bytes, radio_id: Optional[str] = None) -> str:
        """Choose which registered radio should transmit ``data``."""
        if radio_id is not None:
            if radio_id not in self._radios:
                raise KeyError(f"Unknown radio_id={radio_id!r}")
            return radio_id
        if self._tx_selector is not None:
            selected = self._tx_selector(data)
            if selected is not None:
                if selected not in self._radios:
                    raise KeyError(f"TX selector returned unknown radio_id={selected!r}")
                return selected
        default = self.default_radio_id
        if default is None:
            raise RuntimeError("RFFabric has no registered radio")
        return default

    async def send(self, data: bytes, *, radio_id: Optional[str] = None) -> Any:
        """Transmit via default, selector, or explicit ``radio_id``.

        When the physical radio returns a dict metadata blob, attach
        ``radio_id`` so callers (Dispatcher TX logs) know which endpoint TX'd.
        Non-dict results are returned unchanged for legacy radios.
        """
        rid = self.resolve_tx_radio_id(data, radio_id)
        radio = self._radios[rid]
        if not hasattr(radio, "send"):
            raise RuntimeError(f"Radio {rid!r} ({type(radio).__name__}) does not support send()")
        result = await radio.send(data)
        if isinstance(result, dict):
            # Do not overwrite if the radio already stamped a more specific id.
            result.setdefault("radio_id", rid)
            return result
        if result is False or result is None:
            # Preserve failure semantics used by Dispatcher (None/False = TX fail).
            return result
        if result is True:
            return {"ok": True, "radio_id": rid}
        # Unknown non-dict success payload: leave unchanged.
        return result

    async def send_all(self, data: bytes) -> Any:
        """Transmit ``data`` on every registered radio, sequentially.

        Radios TX in registration order and each ``send()`` is awaited to
        completion before the next starts, so transmissions are serialised —
        a driver that returns on TX-done naturally staggers the next radio by
        its own airtime. Register the real RF radio first so a slow or hung
        link radio never delays RF egress.

        Per-radio failures are logged and skipped; the call fails (returns
        ``None``) only when every radio failed. On success returns the first
        successful radio's metadata dict with ``radio_id`` set to ``"all"``
        and the successful ids listed under ``radio_ids`` (non-dict legacy
        results are wrapped).
        """
        if not self._radios:
            raise RuntimeError("RFFabric has no registered radio")
        first_meta: Optional[dict] = None
        ok_ids = []
        for rid in list(self._radios.keys()):
            try:
                result = await self.send(data, radio_id=rid)
            except Exception as exc:
                logger.warning("send_all: TX failed on radio_id=%s: %s", rid, exc)
                continue
            if result is None or result is False:
                logger.warning("send_all: no TX confirmation from radio_id=%s", rid)
                continue
            ok_ids.append(rid)
            if first_meta is None:
                first_meta = dict(result) if isinstance(result, dict) else {"ok": True}
        if first_meta is None:
            return None
        first_meta["radio_id"] = "all"
        first_meta["radio_ids"] = ok_ids
        return first_meta

    def get_last_rssi(self) -> int:
        if self._last_rx_radio_id and self._last_rx_radio_id in self._radios:
            radio = self._radios[self._last_rx_radio_id]
            if hasattr(radio, "get_last_rssi"):
                try:
                    return int(radio.get_last_rssi())
                except Exception:
                    pass
        default = self.radio
        if default is not None and hasattr(default, "get_last_rssi"):
            try:
                return int(default.get_last_rssi())
            except Exception:
                pass
        return int(self._last_rssi)

    def get_last_snr(self) -> float:
        if self._last_rx_radio_id and self._last_rx_radio_id in self._radios:
            radio = self._radios[self._last_rx_radio_id]
            if hasattr(radio, "get_last_snr"):
                try:
                    return float(radio.get_last_snr())
                except Exception:
                    pass
        default = self.radio
        if default is not None and hasattr(default, "get_last_snr"):
            try:
                return float(default.get_last_snr())
            except Exception:
                pass
        return float(self._last_snr)

    def __getattr__(self, name: str) -> Any:
        """Attribute pass-through for radio settings used by Dispatcher."""
        if name.startswith("_"):
            raise AttributeError(name)
        radio = self.radio
        if radio is None:
            raise AttributeError(name)
        return getattr(radio, name)
