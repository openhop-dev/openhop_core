"""BLE (Bluetooth LE) transport for the companion frame protocol, on Linux/BlueZ.

MeshCore companion firmware exposes the Nordic UART service: the phone writes
command frames to the RX characteristic and receives response and push frames as
notifications on the TX characteristic, one frame per GATT operation.
:class:`CompanionBleTransport` serves the same service through BlueZ, so the
MeshCore apps can pair with a node that drives its radio from a Linux host.

It attaches to an existing :class:`CompanionFrameServer` and shares its single
client slot with TCP: a phone connecting over BLE evicts a TCP client, and a TCP
client evicts the phone, which is then disconnected.

Requires Linux, BlueZ 5.62 or newer on the system D-Bus (for the
``encrypt-notify`` characteristic flags), a powered adapter, the ``dbus-fast``
package (``pip install openhop_core[ble]``) and permission to register GATT
services and a pairing agent with BlueZ.

Usage::

    server = CompanionFrameServer(bridge, companion_hash, port=5000)
    await server.start()
    ble = CompanionBleTransport(server, security="encrypt")
    await ble.start()                 # advertises "MeshCore-<node name>"
    ...
    await ble.stop()                  # before the server, so no phone can reopen it
    await server.stop()

Security modes (``security=``, required):

* ``"encrypt"``: an encrypted link, paired "Just Works" (the phone shows a Pair
  button, no code). Anyone in radio range can pair while the transport runs.
* ``"authenticated"``: encrypted and MITM-protected, as firmware does. BlueZ
  picks a random 6-digit passkey per pairing; ``passkey_callback(device_path,
  passkey)`` receives it so a screen can show it, then ``passkey_callback(
  device_path, None)`` when that pairing ends. BlueZ has no fixed PIN, so the
  protocol's device PIN has no effect here.
* ``"none"``: no pairing, no encryption. For testing only.

Limits:

* While the transport runs, its pairing agent is BlueZ's default agent for the
  host (``register_agent=False`` leaves pairing to another agent).
* BlueZ notifies every subscribed central: two paired phones connected at once
  both receive all outbound frames, and both can write.
* A frame is one notification. One that does not fit the client's ATT MTU is
  dropped with a warning, because BlueZ would truncate it.
* If ``bluetoothd`` restarts, call :meth:`stop` and :meth:`start` again.

D-Bus objects are served from one raw message handler rather than
``dbus_fast.service.ServiceInterface`` classes, to keep memory low on small hosts.
"""

import asyncio
import logging
from typing import Any, Callable, Dict, List, Optional, Set

from ..constants import CMD_APP_START, CMD_DEVICE_QUERY
from .message_session import MessageFrameSession

try:  # optional dependency, see the ``ble`` extra
    from dbus_fast import BusType, Message, MessageType, Variant
    from dbus_fast.aio import MessageBus
except ImportError as exc:  # pragma: no cover - exercised only without the extra
    raise ImportError(
        "CompanionBleTransport needs dbus-fast (pip install 'openhop_core[ble]'); "
        "it runs on Linux with BlueZ only"
    ) from exc

logger = logging.getLogger("CompanionBleTransport")

NUS_SERVICE_UUID = "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
NUS_RX_UUID = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"  # phone -> node (write)
NUS_TX_UUID = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"  # node -> phone (notify)
BLE_NAME_PREFIX = "MeshCore-"  # as MeshCore companion firmware advertises
# Seconds after which a displayed passkey is withdrawn if BlueZ reports no outcome.
PASSKEY_TIMEOUT = 60.0
# Commands an app sends first on (re)connect; they may take the slot back after eviction.
_SESSION_OPENERS = (CMD_DEVICE_QUERY, CMD_APP_START)
_ATT_NOTIFY_OVERHEAD = 3  # opcode + handle

_OBJECT_PATH = "/org/openhop/companion/ble0"  # where our D-Bus objects are exported
_BLUEZ = "org.bluez"
_DBUS = "org.freedesktop.DBus"
_PROPS = "org.freedesktop.DBus.Properties"
_OBJMGR = "org.freedesktop.DBus.ObjectManager"
_INTROSPECT = "org.freedesktop.DBus.Introspectable"
_GATT_SERVICE = "org.bluez.GattService1"
_GATT_CHRC = "org.bluez.GattCharacteristic1"
_ADVERT = "org.bluez.LEAdvertisement1"
_AGENT = "org.bluez.Agent1"
_DEVICE = "org.bluez.Device1"

_SECURITY = {
    # mode: (RX flags, TX flags, agent IO capability)
    "none": (["write", "write-without-response"], ["notify"], "NoInputNoOutput"),
    "encrypt": (
        ["write", "write-without-response", "encrypt-write"],
        ["notify", "encrypt-notify"],
        "NoInputNoOutput",
    ),
    "authenticated": (
        ["write", "write-without-response", "encrypt-authenticated-write"],
        ["notify", "encrypt-authenticated-notify"],
        "DisplayOnly",
    ),
}

PasskeyCallback = Callable[[str, Optional[int]], None]


class BleTransportError(RuntimeError):
    """BlueZ refused a registration (missing adapter, permission, ...)."""


def advert_name_for(server: Any) -> str:
    """``MeshCore-<node name>`` from the server's bridge, as firmware does."""
    prefs = getattr(getattr(server, "bridge", None), "prefs", None)
    node_name = getattr(prefs, "node_name", "") or "openHop"
    return BLE_NAME_PREFIX + node_name


class CompanionBleTransport:
    """Serve a :class:`CompanionFrameServer` over BLE (Nordic UART service).

    Args:
        server: the frame server to attach to (it need not listen on TCP).
        security: ``"encrypt"``, ``"authenticated"`` or ``"none"`` (see module doc).
            Required: who may pair with the node is the caller's decision.
        name: advertised local name; default ``MeshCore-<node name>``.
        adapter: BlueZ adapter, e.g. ``"hci0"``.
        passkey_callback: receives the passkey in ``"authenticated"`` mode.
        register_agent: register a pairing agent and make it BlueZ's default, so a
            phone-initiated pairing reaches it. Disable if another agent should
            answer (the security flags still apply). Ignored in ``"none"`` mode.
        bus: an already connected system ``MessageBus`` to use (not closed on stop).
    """

    def __init__(
        self,
        server: Any,
        *,
        security: str,
        name: Optional[str] = None,
        adapter: str = "hci0",
        passkey_callback: Optional[PasskeyCallback] = None,
        register_agent: bool = True,
        bus: Optional["MessageBus"] = None,
    ) -> None:
        if security not in _SECURITY:
            raise ValueError(f"security must be one of {sorted(_SECURITY)}")
        self.server = server
        self.name = name or advert_name_for(server)
        self.adapter_path = f"/org/bluez/{adapter}"
        self.security = security
        self.passkey_callback = passkey_callback
        self.register_agent = register_agent and security != "none"
        self._bus = bus
        self._own_bus = bus is None
        self._rx_flags, self._tx_flags, self._io_capability = _SECURITY[security]

        self._app = _OBJECT_PATH
        self._service = f"{_OBJECT_PATH}/service0"
        self._rx = f"{self._service}/char0"
        self._tx = f"{self._service}/char1"
        self._advert = f"{_OBJECT_PATH}/advertisement0"
        self._agent = f"{_OBJECT_PATH}/agent"
        self._match = (
            f"type='signal',sender='{_BLUEZ}',interface='{_PROPS}',"
            f"member='PropertiesChanged',path_namespace='{self.adapter_path}',arg0='{_DEVICE}'"
        )

        self._started = False
        # Unique bus name of bluetoothd. Only it may call our objects or report devices.
        self._bluez_owner: Optional[str] = None
        self._session: Optional[MessageFrameSession] = None
        # BlueZ device objects that are connected, kept current from Device1 signals.
        self._connected: Set[str] = set()
        # The device BlueZ named in the latest write, and the connected device that
        # holds the session's link. They differ for an iPhone: it writes through the
        # object of its resolvable private address while the link belongs to the
        # object of its identity address, so the named device may not be "connected".
        # ``_links`` is that one device when it can be told apart, else None: then the
        # session ends when every device has disconnected and nobody is disconnected
        # on eviction.
        self._device: Optional[str] = None
        self._links: Optional[Set[str]] = None
        self._notifying = False
        # The server closed our session (a TCP client took the slot). Late writes from
        # the old app session are ignored; a new app session starts with DEVICE_QUERY or
        # APP_START, or after the phone's link dropped.
        self._evicted = False
        self._mtu: Optional[int] = None
        self._mtu_warned = False
        self._pairing: Optional[str] = None  # device a passkey is being shown for
        self._pairing_timer: Optional[asyncio.TimerHandle] = None
        self._registered: List[str] = []
        self._tasks: set = set()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @property
    def connected(self) -> bool:
        """True while a phone holds the companion session."""
        return self._session is not None and self._session.active

    async def start(self) -> None:
        """Register the GATT service, the advertisement and (optionally) the agent."""
        if self._started:
            raise RuntimeError("CompanionBleTransport is already started")
        if self._bus is None:
            self._bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
        self._bus.add_message_handler(self._on_message)
        try:
            dbus = ("/org/freedesktop/DBus", _DBUS)
            self._bluez_owner = (
                await self._call(*dbus, "GetNameOwner", "s", [_BLUEZ], destination=_DBUS)
            )[0]
            await self._call(*dbus, "AddMatch", "s", [self._match], destination=_DBUS)
            self._registered.append("match")
            objects = (await self._call("/", _OBJMGR, "GetManagedObjects", "", []))[0]
            self._connected = {
                path
                for path, ifaces in objects.items()
                if path.startswith(self.adapter_path + "/")
                and getattr(ifaces.get(_DEVICE, {}).get("Connected"), "value", False)
            }
            if self.register_agent:
                agents = ("/org/bluez", "org.bluez.AgentManager1")
                await self._call(*agents, "RegisterAgent", "os", [self._agent, self._io_capability])
                self._registered.append("agent")
                await self._call(*agents, "RequestDefaultAgent", "o", [self._agent])
            try:
                await self._call(
                    self.adapter_path,
                    "org.bluez.GattManager1",
                    "RegisterApplication",
                    "oa{sv}",
                    [self._app, {}],
                )
            except BleTransportError as exc:
                if self.security == "none":
                    raise
                raise BleTransportError(
                    f"{exc} (security={self.security!r} needs BlueZ 5.62 or newer)"
                ) from exc
            self._registered.append("app")
            await self._register_advert()
        except Exception:
            await self.stop()
            raise
        self._started = True
        logger.info("BLE companion advertising as %r (security=%s)", self.name, self.security)

    async def stop(self) -> None:
        """End any session and unregister everything from BlueZ."""
        self._started = False
        session, self._session = self._session, None
        if session is not None:
            session.end()
            try:  # let the server finish the session before the bus goes away
                await asyncio.wait_for(session.wait(), 2)
            except Exception as exc:  # noqa: BLE001 - best effort on the way out
                logger.debug("BLE session did not finish cleanly: %s", exc)
        self._end_pairing()
        if self._bus is not None:
            for what in reversed(self._registered):
                try:
                    if what == "advert":
                        await self._call(
                            self.adapter_path,
                            "org.bluez.LEAdvertisingManager1",
                            "UnregisterAdvertisement",
                            "o",
                            [self._advert],
                        )
                    elif what == "app":
                        await self._call(
                            self.adapter_path,
                            "org.bluez.GattManager1",
                            "UnregisterApplication",
                            "o",
                            [self._app],
                        )
                    elif what == "agent":
                        await self._call(
                            "/org/bluez",
                            "org.bluez.AgentManager1",
                            "UnregisterAgent",
                            "o",
                            [self._agent],
                        )
                    elif what == "match":
                        await self._call(
                            "/org/freedesktop/DBus",
                            _DBUS,
                            "RemoveMatch",
                            "s",
                            [self._match],
                            destination=_DBUS,
                        )
                except Exception as exc:  # noqa: BLE001 - best effort on the way out
                    logger.debug("BLE unregister %s: %s", what, exc)
            self._registered.clear()
            self._bus.remove_message_handler(self._on_message)
            if self._own_bus:
                self._bus.disconnect()
                self._bus = None
        for task in list(self._tasks):
            task.cancel()
        self._connected = set()
        self._device = self._links = self._mtu = None
        self._notifying = self._evicted = False

    async def _register_advert(self) -> None:
        await self._call(
            self.adapter_path,
            "org.bluez.LEAdvertisingManager1",
            "RegisterAdvertisement",
            "oa{sv}",
            [self._advert, {}],
        )
        self._registered.append("advert")

    async def _call(
        self,
        path: str,
        interface: str,
        member: str,
        signature: str,
        body: list,
        *,
        destination: str = _BLUEZ,
    ) -> Any:
        reply = await self._bus.call(
            Message(
                destination=destination,
                path=path,
                interface=interface,
                member=member,
                signature=signature,
                body=body,
            )
        )
        if reply.message_type == MessageType.ERROR:
            raise BleTransportError(
                f"{interface}.{member}: {reply.error_name}: "
                f"{reply.body[0] if reply.body else ''}"
            )
        return reply.body

    def _spawn(self, coro) -> None:
        task = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    # ------------------------------------------------------------------
    # Companion session
    # ------------------------------------------------------------------

    def _ensure_session(self) -> MessageFrameSession:
        if self._session is None or not self._session.active:
            self._mtu_warned = False
            if self._device in self._connected:
                self._links = {self._device}
            elif len(self._connected) == 1:
                self._links = set(self._connected)
            else:  # cannot tell the phone from other connected devices
                self._links = None
            self._session = MessageFrameSession(
                self.server,
                self._notify,
                self._on_session_closed,
                label="BLE",
            )
            self._session.start()
        return self._session

    def _on_rx(self, value: bytes, options: Dict[str, Any]) -> None:
        device = options.get("device")
        if device is not None:
            self._device = getattr(device, "value", device)
            if self._device in self._connected:
                self._links = {self._device}
        mtu = options.get("mtu")
        if mtu is not None:
            self._mtu = getattr(mtu, "value", mtu)
        if self._evicted:
            if not value or value[0] not in _SESSION_OPENERS:
                return  # late write from the evicted session: don't take the slot back
            self._evicted = False
            logger.info("BLE client opened a new session")
        self._ensure_session().feed(value)

    def _start_notify(self) -> None:
        self._notifying = True
        self._evicted = False
        logger.info("BLE client subscribed")
        self._ensure_session()

    def _stop_notify(self) -> None:
        # BlueZ calls StopNotify when the last subscriber unsubscribes, or disconnects
        # without a bond. A bonded phone keeps its subscription across disconnects and
        # reconnects, with no StopNotify or StartNotify: _link_lost covers that.
        self._notifying = False
        self._evicted = False
        logger.info("BLE client unsubscribed")
        self._end_session()

    def _end_session(self) -> None:
        if self._session is not None:
            self._session.end()
            self._session = None

    def _on_device_changed(self, path: str, changed: Dict[str, Any]) -> None:
        """A BlueZ device under our adapter changed (PropertiesChanged on Device1)."""
        connected = getattr(changed.get("Connected"), "value", None)
        if connected:
            self._connected.add(path)
        elif connected is not None:
            self._connected.discard(path)
            self._link_lost(path)
        if self._pairing == path and (
            connected is False or getattr(changed.get("Paired"), "value", False)
        ):
            self._end_pairing()

    def _link_lost(self, path: str) -> None:
        if self._links is not None:
            self._links.discard(path)
            gone = not self._links
        else:
            gone = not self._connected
        if not (gone or path == self._device):
            return
        # The phone's link is down. Whatever connects next starts a new session.
        self._device = self._links = self._mtu = None
        self._evicted = False
        if self._session is not None:
            logger.info("BLE client disconnected")
            self._end_session()

    async def _notify(self, payload: bytes) -> None:
        if self._bus is None:
            raise ConnectionResetError("BLE transport stopped")
        if self._mtu is not None and len(payload) > self._mtu - _ATT_NOTIFY_OVERHEAD:
            if not self._mtu_warned:  # once per session, not once per frame
                self._mtu_warned = True
                logger.warning(
                    "BLE frame of %d bytes does not fit the client's ATT MTU of %d; "
                    "dropping frames of that size",
                    len(payload),
                    self._mtu,
                )
            return
        # Addressed to bluetoothd, so the frame is not broadcast to the system bus.
        await self._bus.send(
            Message(
                message_type=MessageType.SIGNAL,
                destination=_BLUEZ,
                path=self._tx,
                interface=_PROPS,
                member="PropertiesChanged",
                signature="sa{sv}as",
                body=[_GATT_CHRC, {"Value": Variant("ay", payload)}, []],
            )
        )

    def _on_session_closed(self) -> None:
        # The server dropped the BLE session (a TCP client evicted it, or the server
        # stopped): disconnect the phone so it does not sit on a dead link.
        self._session = None
        self._evicted = True
        target = self._peer_to_disconnect()
        if target is None:
            logger.warning("BLE session closed by the server; no single device to disconnect")
        elif self._bus is not None:
            self._spawn(self._disconnect(target))

    def _peer_to_disconnect(self) -> Optional[str]:
        """The connected device that held the session, if it can be told apart.

        The device BlueZ names with a write if it is connected; otherwise the only
        device that was connected when the session began, if it still is (an
        iPhone, see ``_device``). Never a device that connected for something else.
        """
        if self._device in self._connected:
            return self._device
        live = (self._links or set()) & self._connected
        return next(iter(live)) if live else None

    async def _disconnect(self, target: str) -> None:
        try:
            await self._call(target, _DEVICE, "Disconnect", "", [])
            logger.info("BLE session closed by the server; disconnected %s", target)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - nothing to do but say so
            logger.warning("BLE disconnect of %s failed: %s", target, exc)

    # ------------------------------------------------------------------
    # D-Bus objects (one raw handler)
    # ------------------------------------------------------------------

    def _properties(self) -> Dict[str, Dict[str, Dict[str, Variant]]]:
        return {
            self._service: {
                _GATT_SERVICE: {
                    "UUID": Variant("s", NUS_SERVICE_UUID),
                    "Primary": Variant("b", True),
                }
            },
            self._rx: {
                _GATT_CHRC: {
                    "UUID": Variant("s", NUS_RX_UUID),
                    "Service": Variant("o", self._service),
                    "Flags": Variant("as", self._rx_flags),
                }
            },
            self._tx: {
                _GATT_CHRC: {
                    "UUID": Variant("s", NUS_TX_UUID),
                    "Service": Variant("o", self._service),
                    "Flags": Variant("as", self._tx_flags),
                    "Notifying": Variant("b", self._notifying),
                }
            },
            self._advert: {
                _ADVERT: {
                    "Type": Variant("s", "peripheral"),
                    "ServiceUUIDs": Variant("as", [NUS_SERVICE_UUID]),
                    "LocalName": Variant("s", self.name),
                    "Discoverable": Variant("b", True),
                }
            },
        }

    def _on_message(self, msg: "Message") -> Any:
        if msg.sender != self._bluez_owner or not msg.path:
            return None  # not bluetoothd: frames, pairing and link state are its to give
        if msg.message_type == MessageType.SIGNAL:
            if (
                msg.member == "PropertiesChanged"
                and msg.path.startswith(self.adapter_path + "/")
                and len(msg.body) > 1
                and msg.body[0] == _DEVICE
            ):
                self._on_device_changed(msg.path, msg.body[1])
            return None
        if msg.message_type != MessageType.METHOD_CALL:
            return None
        if not (msg.path == self._app or msg.path.startswith(self._app + "/")):
            return None
        try:
            return self._dispatch(msg)
        except _Rejected as exc:
            return Message.new_error(msg, exc.name, str(exc))
        except Exception as exc:  # noqa: BLE001 - answer BlueZ instead of hanging it
            logger.warning("BLE D-Bus %s.%s failed: %s", msg.interface, msg.member, exc)
            return Message.new_error(msg, "org.bluez.Error.Failed", str(exc))

    def _dispatch(self, msg: "Message") -> Any:
        path, iface, member = msg.path, msg.interface, msg.member

        # The hot path first: one WriteValue per frame from the phone.
        if iface == _GATT_CHRC:
            if member == "WriteValue" and path == self._rx:
                self._on_rx(bytes(msg.body[0]), msg.body[1])
                return Message.new_method_return(msg)
            if member == "StartNotify" and path == self._tx:
                self._start_notify()
                return Message.new_method_return(msg)
            if member == "StopNotify" and path == self._tx:
                self._stop_notify()
                return Message.new_method_return(msg)
            raise _Rejected("org.bluez.Error.NotSupported", member)

        if iface == _OBJMGR and member == "GetManagedObjects" and path == self._app:
            gatt = {p: v for p, v in self._properties().items() if p != self._advert}
            return Message.new_method_return(msg, "a{oa{sa{sv}}}", [gatt])
        if iface == _PROPS and member == "GetAll":
            return Message.new_method_return(
                msg, "a{sv}", [self._properties().get(path, {}).get(msg.body[0], {})]
            )
        if iface == _PROPS and member == "Get":
            value = self._properties().get(path, {}).get(msg.body[0], {}).get(msg.body[1])
            if value is None:
                raise _Rejected("org.freedesktop.DBus.Error.InvalidArgs", "no such property")
            return Message.new_method_return(msg, "v", [value])
        if iface == _INTROSPECT and member == "Introspect":
            return Message.new_method_return(
                msg, "s", [_introspect(self._properties().get(path, {}))]
            )

        if iface == _ADVERT and member == "Release":
            logger.warning("BLE advertisement released by BlueZ; the node is no longer visible")
            if "advert" in self._registered:
                self._registered.remove("advert")
            return Message.new_method_return(msg)

        if iface == _AGENT and path == self._agent:
            return self._agent_method(msg)

        raise _Rejected("org.freedesktop.DBus.Error.UnknownMethod", f"{iface}.{member}")

    def _agent_method(self, msg: "Message") -> Any:
        member = msg.member
        if member == "DisplayPasskey":
            device, passkey, entered = msg.body
            if entered == 0:
                logger.info("BLE pairing passkey issued for %s", device)
                logger.debug("BLE pairing passkey: %06d", passkey)
                self._end_pairing()
                self._pairing = device
                self._pairing_timer = asyncio.get_running_loop().call_later(
                    PASSKEY_TIMEOUT, self._end_pairing
                )
                if self.passkey_callback is not None:
                    self.passkey_callback(device, passkey)
            return Message.new_method_return(msg)
        if member == "Cancel":
            logger.info("BLE pairing cancelled")
            self._end_pairing()
            return Message.new_method_return(msg)
        if member in ("RequestAuthorization", "RequestConfirmation"):
            # An incoming pairing without a code ("Just Works"): the Pair button.
            if self.security != "encrypt":
                raise _Rejected("org.bluez.Error.Rejected", "pairing needs the passkey")
            logger.info("BLE pairing accepted for %s", msg.body[0] if msg.body else "?")
            return Message.new_method_return(msg)
        if member == "Release":
            if "agent" in self._registered:
                self._registered.remove("agent")
            return Message.new_method_return(msg)
        if member in ("RequestPinCode", "RequestPasskey", "DisplayPinCode", "AuthorizeService"):
            # No keys to type a code on, and no business authorising other services.
            raise _Rejected("org.bluez.Error.Rejected", "not supported by this agent")
        raise _Rejected("org.freedesktop.DBus.Error.UnknownMethod", member)

    def _end_pairing(self) -> None:
        """Withdraw a displayed passkey: paired, failed, cancelled or timed out."""
        device, self._pairing = self._pairing, None
        if self._pairing_timer is not None:
            self._pairing_timer.cancel()
            self._pairing_timer = None
        if device is not None and self.passkey_callback is not None:
            self.passkey_callback(device, None)


class _Rejected(Exception):
    def __init__(self, name: str, text: str) -> None:
        super().__init__(text)
        self.name = name


def _introspect(interfaces: Dict[str, Any]) -> str:
    body = "".join(f'<interface name="{name}"/>' for name in interfaces)
    return (
        '<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN" '
        '"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">'
        f"<node>{body}</node>"
    )
