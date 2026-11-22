"""Tests for CompanionBleTransport: D-Bus dispatch without a bus or a Bluetooth adapter."""

import asyncio
from unittest.mock import Mock

import pytest

pytest.importorskip("dbus_fast")  # the ``ble`` extra; also in the ``test`` extra

from dbus_fast import Message, MessageType, Variant  # noqa: E402

from openhop_core.companion.constants import (  # noqa: E402
    CMD_DEVICE_QUERY,
    CMD_GET_DEVICE_TIME,
    RESP_CODE_CURR_TIME,
)
from openhop_core.companion.frame_server import CompanionFrameServer  # noqa: E402
from openhop_core.companion.frame_server import ble_transport  # noqa: E402
from openhop_core.companion.frame_server.ble_transport import (  # noqa: E402
    NUS_RX_UUID,
    NUS_SERVICE_UUID,
    NUS_TX_UUID,
    BleTransportError,
    CompanionBleTransport,
)

BLUEZ = ":1.5"  # bluetoothd's unique bus name in these tests
PHONE = "/org/bluez/hci0/dev_AA"
CHRC = "org.bluez.GattCharacteristic1"
AGENT = "org.bluez.Agent1"
WRITE = (CHRC, "WriteValue", "aya{sv}")


def _server():
    bridge = Mock()
    bridge.get_time = Mock(return_value=1234)
    bridge.prefs = Mock(node_name="CZ-test")
    bridge.contacts = Mock(max_contacts=100)
    return CompanionFrameServer(bridge, "ab", port=0, client_idle_timeout_sec=None)


async def _until(cond, steps=200):
    for _ in range(steps):
        if cond():
            return True
        await asyncio.sleep(0.001)
    return cond()


class _BlockingReader:
    def __init__(self):
        self.release = asyncio.Event()

    async def read(self, _n):
        await self.release.wait()
        return b""

    async def readexactly(self, n):
        raise asyncio.IncompleteReadError(partial=b"", expected=n)


class _DummyWriter:
    def __init__(self):
        self.closed = False

    def get_extra_info(self, _name, default=None):
        return default

    def write(self, _data):
        pass

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass

    def is_closing(self):
        return self.closed


def _connected(path, yes=True):
    return {path: {"org.bluez.Device1": {"Connected": Variant("b", yes)}}}


class _FakeBus:
    """Records what the transport sends; answers as bluetoothd and the bus daemon would."""

    def __init__(self):
        self.signals = []
        self.calls = []
        self.fail = set()  # members that answer with an error
        self.objects = {}  # GetManagedObjects reply
        self.handlers = []
        self.disconnected = False

    def add_message_handler(self, handler):
        self.handlers.append(handler)

    def remove_message_handler(self, handler):
        self.handlers.remove(handler)

    def disconnect(self):
        self.disconnected = True

    def send(self, msg):
        self.signals.append(msg)
        fut = asyncio.get_running_loop().create_future()
        fut.set_result(None)
        return fut

    async def call(self, msg):
        self.calls.append(msg)
        if msg.member in self.fail:
            return Message(
                message_type=MessageType.ERROR,
                reply_serial=1,
                error_name="org.bluez.Error.Failed",
                signature="s",
                body=["no"],
            )
        if msg.member == "GetNameOwner":
            return Message(
                message_type=MessageType.METHOD_RETURN,
                reply_serial=1,
                signature="s",
                body=[BLUEZ],
            )
        if msg.member == "GetManagedObjects":
            return Message(
                message_type=MessageType.METHOD_RETURN,
                reply_serial=1,
                signature="a{oa{sa{sv}}}",
                body=[self.objects],
            )
        return Message(message_type=MessageType.METHOD_RETURN, reply_serial=1)

    def members(self):
        return [c.member for c in self.calls]


def _transport(security="encrypt", connected=(PHONE,), **kw):
    """A transport as it is after start(): bluetoothd known, one phone connected."""
    t = CompanionBleTransport(_server(), security=security, **kw)
    t._bus = _FakeBus()
    t._bus.add_message_handler(t._on_message)
    t._bluez_owner = BLUEZ
    t._connected = set(connected)
    return t


def _call(t, path, iface, member, signature="", body=None, sender=BLUEZ):
    return t._on_message(
        Message(
            destination=":1.1",
            path=path,
            interface=iface,
            member=member,
            signature=signature,
            body=body or [],
            serial=7,
            sender=sender,
        )
    )


def _write(t, payload, device=PHONE, mtu=185):
    options = {"mtu": Variant("q", mtu)}
    if device:
        options["device"] = Variant("o", device)
    return _call(t, t._rx, *WRITE, [bytes(payload), options])


def _device_signal(t, path, sender=BLUEZ, **props):
    changed = {name: Variant("b", value) for name, value in props.items()}
    return t._on_message(
        Message(
            message_type=MessageType.SIGNAL,
            path=path,
            interface="org.freedesktop.DBus.Properties",
            member="PropertiesChanged",
            signature="sa{sv}as",
            body=["org.bluez.Device1", changed, []],
            sender=sender,
        )
    )


async def _tcp_client_takes_slot(t):
    reader, writer = _BlockingReader(), _DummyWriter()
    task = asyncio.create_task(t.server._handle_client(reader, writer))
    assert await _until(lambda: t.server._client_writer is writer)
    return reader, writer, task


# ---------------------------------------------------------------------------
# Construction and the D-Bus objects BlueZ reads
# ---------------------------------------------------------------------------


def test_default_name_comes_from_node_name():
    assert _transport().name == "MeshCore-CZ-test"


def test_security_mode_is_required_and_checked():
    with pytest.raises(TypeError):
        CompanionBleTransport(_server())
    with pytest.raises(ValueError):
        CompanionBleTransport(_server(), security="pin")


@pytest.mark.parametrize(
    "security,rx_flag,tx_flag",
    [
        ("encrypt", "encrypt-write", "encrypt-notify"),
        ("authenticated", "encrypt-authenticated-write", "encrypt-authenticated-notify"),
    ],
)
def test_managed_objects_describe_nus_with_security_flags(security, rx_flag, tx_flag):
    t = _transport(security=security)
    reply = _call(t, t._app, "org.freedesktop.DBus.ObjectManager", "GetManagedObjects")
    objs = reply.body[0]
    assert set(objs) == {t._service, t._rx, t._tx}  # the advertisement is not a GATT object
    assert objs[t._service]["org.bluez.GattService1"]["UUID"].value == NUS_SERVICE_UUID
    rx = objs[t._rx][CHRC]
    tx = objs[t._tx][CHRC]
    assert rx["UUID"].value == NUS_RX_UUID and rx_flag in rx["Flags"].value
    assert tx["UUID"].value == NUS_TX_UUID and tx_flag in tx["Flags"].value
    assert not any("read" in flag for flag in tx["Flags"].value)  # frames are never readable


def test_advertisement_properties():
    t = _transport()
    reply = _call(
        t,
        t._advert,
        "org.freedesktop.DBus.Properties",
        "GetAll",
        "s",
        ["org.bluez.LEAdvertisement1"],
    )
    props = reply.body[0]
    assert props["LocalName"].value == "MeshCore-CZ-test"
    assert props["ServiceUUIDs"].value == [NUS_SERVICE_UUID]


def test_foreign_paths_are_ignored_and_unknown_methods_error():
    t = _transport()
    assert _call(t, "/somewhere/else", "x.y", "Z") is None
    for member in ("AcquireWrite", "ReadValue"):
        reply = _call(t, t._tx, CHRC, member, "a{sv}", [{}])
        assert reply.message_type == MessageType.ERROR


async def test_only_bluetoothd_is_listened_to():
    """Another process on the system bus can neither inject frames nor fake a disconnect."""
    t = _transport()
    _call(t, t._tx, CHRC, "StartNotify")
    assert await _until(lambda: t.connected)
    stranger = ":1.99"
    assert _call(t, t._rx, *WRITE, [bytes([CMD_GET_DEVICE_TIME]), {}], sender=stranger) is None
    assert _device_signal(t, PHONE, sender=stranger, Connected=False) is None
    await asyncio.sleep(0.01)
    assert t.connected and not t._bus.signals
    await t.stop()


# ---------------------------------------------------------------------------
# start() and stop()
# ---------------------------------------------------------------------------


async def test_start_registers_and_stop_unregisters_in_reverse():
    bus = _FakeBus()
    bus.objects = {**_connected(PHONE), **_connected("/org/bluez/hci0/dev_OFF", False)}
    t = CompanionBleTransport(_server(), security="encrypt", bus=bus)
    await t.start()
    assert bus.members() == [
        "GetNameOwner",
        "AddMatch",
        "GetManagedObjects",
        "RegisterAgent",
        "RequestDefaultAgent",
        "RegisterApplication",
        "RegisterAdvertisement",
    ]
    assert t._connected == {PHONE} and t._bluez_owner == BLUEZ
    with pytest.raises(RuntimeError):
        await t.start()  # a second start must not tear down the first

    bus.calls.clear()
    await t.stop()
    assert bus.members() == [
        "UnregisterAdvertisement",
        "UnregisterApplication",
        "UnregisterAgent",
        "RemoveMatch",
    ]
    assert not bus.handlers and not bus.disconnected  # a bus we were given stays open


async def test_start_failure_rolls_back_and_names_the_bluez_version():
    bus = _FakeBus()
    bus.fail = {"RegisterApplication"}
    t = CompanionBleTransport(_server(), security="encrypt", bus=bus)
    with pytest.raises(BleTransportError, match="5.62"):
        await t.start()
    assert bus.members()[-2:] == ["UnregisterAgent", "RemoveMatch"]
    assert not bus.handlers


async def test_no_agent_without_pairing():
    bus = _FakeBus()
    t = CompanionBleTransport(_server(), security="none", bus=bus)
    await t.start()
    assert "RegisterAgent" not in bus.members()
    await t.stop()


async def test_stop_ends_the_session_and_forgets_the_phone():
    t = _transport()
    _call(t, t._tx, CHRC, "StartNotify")
    _write(t, [CMD_GET_DEVICE_TIME])
    assert await _until(lambda: t.connected)
    session = t._session
    await t.stop()
    assert session.task.done() and t.server._client_writer is None
    assert not t.connected and not t._notifying and t._device is None and not t._connected


# ---------------------------------------------------------------------------
# Frames
# ---------------------------------------------------------------------------


async def test_write_and_notify_round_trip_through_server():
    t = _transport()
    _call(t, t._tx, CHRC, "StartNotify")
    reply = _write(t, [CMD_GET_DEVICE_TIME])
    assert reply.message_type == MessageType.METHOD_RETURN
    assert await _until(lambda: t._bus.signals)
    sig = t._bus.signals[0]
    assert sig.member == "PropertiesChanged" and sig.path == t._tx
    assert sig.destination == "org.bluez"  # to bluetoothd only, not broadcast on the bus
    assert sig.body[1]["Value"].value[0] == RESP_CODE_CURR_TIME
    assert t.connected

    _call(t, t._tx, CHRC, "StopNotify")
    assert await _until(lambda: not t.connected)
    assert await _until(lambda: t.server._client_writer is None)


async def test_write_before_subscribing_does_not_drop_the_phone():
    t = _transport()
    _write(t, [CMD_GET_DEVICE_TIME])
    assert await _until(lambda: t._bus.signals)
    assert t.connected and not t._evicted
    assert "Disconnect" not in t._bus.members()
    await t.stop()


async def test_frame_larger_than_the_mtu_is_dropped_with_one_warning(caplog):
    """BlueZ would truncate it, and a small-MTU client must not fill the log."""
    t = _transport()
    _call(t, t._tx, CHRC, "StartNotify")
    t._mtu = 23
    with caplog.at_level("WARNING", logger="CompanionBleTransport"):
        for _ in range(3):
            await t._notify(bytes(40))
        await t._notify(bytes(20))
    assert [len(s.body[1]["Value"].value) for s in t._bus.signals] == [20]
    assert len(caplog.records) == 1
    await t.stop()


# ---------------------------------------------------------------------------
# The phone leaves
# ---------------------------------------------------------------------------


async def test_bonded_phone_walking_away_frees_the_slot():
    """BlueZ sends no StopNotify for a bonded device; its Connected property says it."""
    t = _transport()
    _call(t, t._tx, CHRC, "StartNotify")
    _write(t, [CMD_GET_DEVICE_TIME])
    assert await _until(lambda: t.connected)

    _device_signal(t, PHONE, Connected=False)
    assert await _until(lambda: not t.connected)
    assert await _until(lambda: t.server._client_writer is None)
    assert "Disconnect" not in t._bus.members()  # it is already gone
    assert t._notifying  # BlueZ still counts the subscription

    # It comes back without subscribing again, and its first write opens a session.
    _device_signal(t, PHONE, Connected=True)
    _write(t, [CMD_GET_DEVICE_TIME])
    assert await _until(lambda: t.connected)
    await t.stop()


async def test_iphone_link_is_followed_through_its_identity_object():
    """An iPhone writes through one device object and is connected through another."""
    identity, rpa = "/org/bluez/hci0/dev_ID", "/org/bluez/hci0/dev_RPA"
    t = _transport(connected=(identity,))
    _call(t, t._tx, CHRC, "StartNotify")
    _write(t, [CMD_GET_DEVICE_TIME], device=rpa)
    assert await _until(lambda: t.connected)
    _device_signal(t, identity, Connected=False)
    assert await _until(lambda: not t.connected)


async def test_another_device_disconnecting_does_not_end_the_session():
    headset = "/org/bluez/hci0/dev_HEADSET"
    t = _transport(connected=(PHONE, headset))
    _call(t, t._tx, CHRC, "StartNotify")
    _write(t, [CMD_GET_DEVICE_TIME])
    assert await _until(lambda: t.connected)
    _device_signal(t, headset, Connected=False)
    await asyncio.sleep(0.01)
    assert t.connected
    await t.stop()


# ---------------------------------------------------------------------------
# A TCP client takes the slot
# ---------------------------------------------------------------------------


async def test_tcp_eviction_disconnects_phone_and_ignores_its_late_writes():
    t = _transport()
    _call(t, t._tx, CHRC, "StartNotify")
    _write(t, [CMD_GET_DEVICE_TIME])
    assert await _until(lambda: t.connected)

    reader, tcp_writer, tcp_task = await _tcp_client_takes_slot(t)
    assert await _until(lambda: "Disconnect" in t._bus.members())
    disconnect = next(c for c in t._bus.calls if c.member == "Disconnect")
    assert disconnect.path == PHONE

    # A write that races the disconnect must not evict the TCP client back.
    _write(t, [CMD_GET_DEVICE_TIME], device=None)
    for _ in range(20):
        await asyncio.sleep(0)
    assert t.server._client_writer is tcp_writer and not t.connected
    reader.release.set()
    await asyncio.wait_for(tcp_task, 1)


@pytest.mark.parametrize(
    "named,connected,expect",
    [
        # iPhone: writes name an RPA object; the link is on the identity object
        ("/org/bluez/hci0/dev_RPA", ["/org/bluez/hci0/dev_ID"], "/org/bluez/hci0/dev_ID"),
        # the named device is connected among others: that one
        (PHONE, [PHONE, "/org/bluez/hci0/dev_HEADSET"], PHONE),
        # the named device is not connected and two others are: touch none
        ("/org/bluez/hci0/dev_RPA", ["/org/bluez/hci0/dev_A", "/org/bluez/hci0/dev_B"], None),
    ],
)
async def test_eviction_disconnects_only_the_session_phone(named, connected, expect):
    t = _transport(connected=connected)
    _call(t, t._tx, CHRC, "StartNotify")
    _write(t, [CMD_GET_DEVICE_TIME], device=named)
    assert await _until(lambda: t.connected)
    reader, _writer, tcp_task = await _tcp_client_takes_slot(t)
    assert await _until(lambda: not t.connected)
    for _ in range(20):
        await asyncio.sleep(0)
    targets = [c.path for c in t._bus.calls if c.member == "Disconnect"]
    assert targets == ([expect] if expect else [])
    reader.release.set()
    await asyncio.wait_for(tcp_task, 1)


async def test_a_device_that_connected_later_is_never_disconnected():
    """The phone left unnoticed among other devices; a keyboard must not pay for it."""
    rpa, identity, keyboard = (f"/org/bluez/hci0/dev_{n}" for n in ("RPA", "ID", "KBD"))
    t = _transport(connected=(identity, "/org/bluez/hci0/dev_HEADSET"))
    _call(t, t._tx, CHRC, "StartNotify")
    _write(t, [CMD_GET_DEVICE_TIME], device=rpa)
    assert await _until(lambda: t.connected)
    _device_signal(t, identity, Connected=False)
    _device_signal(t, "/org/bluez/hci0/dev_HEADSET", Connected=False)
    _device_signal(t, keyboard, Connected=True)
    reader, _writer, tcp_task = await _tcp_client_takes_slot(t)
    for _ in range(20):
        await asyncio.sleep(0)
    assert "Disconnect" not in t._bus.members()
    reader.release.set()
    await asyncio.wait_for(tcp_task, 1)


async def test_evicted_phone_takes_slot_back_with_a_new_app_session():
    """A bonded phone may return without StartNotify; DEVICE_QUERY reopens the session."""
    t = _transport()
    _call(t, t._tx, CHRC, "StartNotify")
    _write(t, [CMD_GET_DEVICE_TIME])
    assert await _until(lambda: t.connected)

    reader, tcp_writer, tcp_task = await _tcp_client_takes_slot(t)
    assert await _until(lambda: not t.connected)

    _write(t, [CMD_GET_DEVICE_TIME])  # late write: ignored
    for _ in range(20):
        await asyncio.sleep(0)
    assert t.server._client_writer is tcp_writer

    _write(t, [CMD_DEVICE_QUERY, 3])  # new app session
    assert await _until(lambda: t.connected)
    assert await _until(lambda: tcp_writer.closed)
    reader.release.set()
    await asyncio.wait_for(tcp_task, 1)
    assert t._notifying  # BlueZ's subscription state is untouched by eviction
    await t.stop()


async def test_evicted_phone_starts_fresh_after_its_link_dropped():
    t = _transport()
    _call(t, t._tx, CHRC, "StartNotify")
    _write(t, [CMD_GET_DEVICE_TIME])
    assert await _until(lambda: t.connected)
    reader, tcp_writer, tcp_task = await _tcp_client_takes_slot(t)
    assert await _until(lambda: t._evicted)

    _device_signal(t, PHONE, Connected=False)  # our Disconnect took effect
    _device_signal(t, PHONE, Connected=True)
    _write(t, [CMD_GET_DEVICE_TIME])  # any command now opens a session
    assert await _until(lambda: t.connected)
    reader.release.set()
    await asyncio.wait_for(tcp_task, 1)
    await t.stop()


# ---------------------------------------------------------------------------
# Pairing agent
# ---------------------------------------------------------------------------


async def test_passkey_is_shown_then_withdrawn_when_pairing_completes():
    seen = []
    t = _transport(security="authenticated", passkey_callback=lambda d, k: seen.append((d, k)))
    _call(t, t._agent, AGENT, "DisplayPasskey", "ouq", [PHONE, 123456, 0])
    _call(t, t._agent, AGENT, "DisplayPasskey", "ouq", [PHONE, 123456, 3])  # typing progress
    assert seen == [(PHONE, 123456)]
    _device_signal(t, "/org/bluez/hci0/dev_OTHER", Paired=True)  # someone else: ignored
    assert seen == [(PHONE, 123456)]
    _device_signal(t, PHONE, Paired=True)  # BlueZ sends no Cancel after a passkey display
    assert seen == [(PHONE, 123456), (PHONE, None)]
    assert t._pairing_timer is None


@pytest.mark.parametrize("ending", ["cancel", "disconnect", "timeout"])
async def test_passkey_is_withdrawn_when_pairing_fails(ending, monkeypatch):
    monkeypatch.setattr(ble_transport, "PASSKEY_TIMEOUT", 0.01)
    seen = []
    t = _transport(security="authenticated", passkey_callback=lambda d, k: seen.append((d, k)))
    _call(t, t._agent, AGENT, "DisplayPasskey", "ouq", [PHONE, 4242, 0])
    if ending == "cancel":
        _call(t, t._agent, AGENT, "Cancel")
    elif ending == "disconnect":
        _device_signal(t, PHONE, Connected=False)
    assert await _until(lambda: len(seen) == 2)
    assert seen == [(PHONE, 4242), (PHONE, None)]
    await asyncio.sleep(0.02)
    assert len(seen) == 2  # withdrawn once


@pytest.mark.parametrize(
    "security,accepted",
    [("encrypt", True), ("authenticated", False)],
)
def test_pair_button_is_accepted_only_in_encrypt_mode(security, accepted):
    t = _transport(security=security)
    for member, signature, body in (
        ("RequestAuthorization", "o", [PHONE]),
        ("RequestConfirmation", "ou", [PHONE, 0]),
    ):
        reply = _call(t, t._agent, AGENT, member, signature, body)
        assert (reply.message_type == MessageType.METHOD_RETURN) is accepted


@pytest.mark.parametrize("security", ["encrypt", "authenticated"])
def test_agent_never_enters_codes_or_authorises_other_services(security):
    t = _transport(security=security)
    for member, signature, body in (
        ("RequestPasskey", "o", [PHONE]),
        ("RequestPinCode", "o", [PHONE]),
        ("AuthorizeService", "os", [PHONE, "0000110b-0000-1000-8000-00805f9b34fb"]),
    ):
        reply = _call(t, t._agent, AGENT, member, signature, body)
        assert reply.message_type == MessageType.ERROR
