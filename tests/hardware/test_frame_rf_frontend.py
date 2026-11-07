"""Frame-protocol AGC/FEM/RX-boost client, with a scripted modem."""

import asyncio
import struct
import threading
import time
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from openhop_core.hardware.frame_rf_frontend import FrameRfControls
from openhop_core.hardware.kiss_modem_wrapper import KissModemWrapper
from openhop_core.hardware.protocol_constants import (
    AGC_INTERVAL_MAX_SEC,
    CMD_AGC_INTERVAL_RESP,
    CMD_CONFIG_RESP,
    CMD_ERROR,
    CMD_FEM_STATE_RESP,
    CMD_GET_AGC_INTERVAL,
    CMD_GET_RF_CAPS,
    CMD_RF_CAPS_RESP,
    CMD_RX_BOOST_RESP,
    CMD_RX_PACKET,
    CMD_SET_AGC_INTERVAL,
    CMD_SET_FEM_STATE,
    CMD_SET_RX_BOOST,
    CMD_STATUS_REQ,
    CMD_STATUS_RESP,
    CMD_TX_DONE,
    CMD_TX_REQUEST,
    ERR_RADIO_FAULT,
    ERR_RADIO_INIT,
    ERR_UNSUPPORTED,
    FEM_STATE_RX_LNA,
    FEM_STATE_TX_PA,
    RF_CAP_AGC,
    RF_CAP_FEM_RX_LNA,
    RF_CAP_FEM_TX_PA,
    RF_CAP_RX_BOOSTED_GAIN,
    STATUS_RESP_FMT,
    build_frame,
)
from openhop_core.hardware.tcp_radio import TCPLoRaRadio
from openhop_core.hardware.usb_radio import USBLoRaRadio


def _u16(value: int) -> bytes:
    return struct.pack("<H", value)


def _u32(value: int) -> bytes:
    return struct.pack("<I", value)


class FakeModem(FrameRfControls):
    def __init__(self, radio_config=None):
        self._init_rf_controls(radio_config)
        self.sent = []
        self.script = []
        self._response_events = {}
        self._response_data = {}

    def _rf_transact_fresh(self, cmd, payload, expect, timeout):
        self.sent.append((cmd, bytes(payload), expect))
        if not self.script:
            return None
        reply = self.script.pop(0)
        if reply is None:
            return None
        return reply


def _caps(*bits: int) -> tuple[int, bytes]:
    mask = 0
    for bit in bits:
        mask |= bit
    return (CMD_RF_CAPS_RESP, _u32(mask))


def test_agc_interval_is_one_second_steps_up_to_an_hour():
    assert FrameRfControls.effective_agc_reset_interval(30) == 30
    assert FrameRfControls.effective_agc_reset_interval(1024) == 1024
    assert FrameRfControls.effective_agc_reset_interval(0) == 0
    assert FrameRfControls.effective_agc_reset_interval(AGC_INTERVAL_MAX_SEC) == 3600
    assert FrameRfControls.effective_agc_reset_interval(3601) is None
    assert FrameRfControls.effective_agc_reset_interval(True) is None

    # KISS firmware still rounds down to a multiple of 4 and stops at 1020.
    assert KissModemWrapper.effective_agc_reset_interval(30) == 28
    assert KissModemWrapper.effective_agc_reset_interval(10) == 8
    assert KissModemWrapper.effective_agc_reset_interval(1) == 0
    assert KissModemWrapper.effective_agc_reset_interval(1020) == 1020
    assert KissModemWrapper.effective_agc_reset_interval(1024) is None


def test_set_agc_sends_the_requested_second_and_keeps_the_reply():
    modem = FakeModem()
    modem.script.append((CMD_AGC_INTERVAL_RESP, _u16(30)))

    assert modem.set_agc_reset_interval(30) == 30
    assert modem.sent == [(CMD_SET_AGC_INTERVAL, _u16(30), CMD_AGC_INTERVAL_RESP)]
    assert modem.radio_config["agc_reset_interval_seconds"] == 30
    assert modem.applied_hardware_config["agc_reset_interval_seconds"] == 30


def test_agc_outside_range_is_not_sent():
    modem = FakeModem()
    assert modem.set_agc_reset_interval(3601) is None
    assert modem.set_agc_reset_interval(-1) is None
    assert modem.sent == []


def test_agc_error_does_not_update_saved_state():
    modem = FakeModem()
    modem.script.append((CMD_ERROR, bytes([0x06])))
    assert modem.set_agc_reset_interval(30) is None
    assert "agc_reset_interval_seconds" not in modem.radio_config


def test_capabilities_select_which_controls_answer():
    modem = FakeModem()
    modem.script.append(_caps(RF_CAP_AGC, RF_CAP_FEM_RX_LNA))

    assert modem.supports_agc_reset_control() is True
    assert modem.supports_fem_rx_gain() is True
    assert modem.supports_fem_tx_gain() is False
    assert modem.supports_rx_boosted_gain() is False
    assert modem.sent == [(CMD_GET_RF_CAPS, b"", CMD_RF_CAPS_RESP)]
    # The probe is cached.
    assert modem.supports_agc_reset_control() is True
    assert len(modem.sent) == 1


def test_fem_unsupported_bit_fails_the_whole_request():
    modem = FakeModem()
    modem.script.append((CMD_ERROR, bytes([ERR_UNSUPPORTED])))

    assert modem.set_fem_state(rx_gain=True, tx_gain=True) is None
    assert modem.set_fem_rx_gain(True) is False
    assert "fem_rx_gain" not in modem.radio_config
    assert "fem_tx_gain" not in modem.radio_config
    assert modem.sent[0] == (CMD_SET_FEM_STATE, bytes([0x03, 0x03]), CMD_FEM_STATE_RESP)


def test_fem_reply_is_remembered_only_for_bits_it_confirms():
    modem = FakeModem()
    modem.script.append((CMD_FEM_STATE_RESP, bytes([FEM_STATE_RX_LNA, FEM_STATE_RX_LNA])))

    state = modem.set_fem_state(rx_gain=True, tx_gain=False)
    assert state == {"rx_gain": True, "tx_gain": None}
    assert modem.radio_config["fem_rx_gain"] is True
    assert "fem_tx_gain" not in modem.radio_config


def test_rx_boost_fault_does_not_claim_the_requested_state():
    modem = FakeModem()
    modem.script.append((CMD_ERROR, bytes([ERR_RADIO_FAULT])))
    assert modem.set_rx_boosted_gain(True) is None
    assert "rx_boosted_gain" not in modem.radio_config

    modem.script.append((CMD_RX_BOOST_RESP, bytes([0x00])))
    assert modem.set_rx_boosted_gain(True) is False
    assert "rx_boosted_gain" not in modem.radio_config

    modem.script.append((CMD_RX_BOOST_RESP, bytes([0x01])))
    assert modem.set_rx_boosted_gain(True) is True
    assert modem.radio_config["rx_boosted_gain"] is True


def test_a_queued_reply_cannot_confirm_the_next_request():
    modem = FakeModem()
    with modem._response_lock:
        assert modem._rf_note_unsolicited(CMD_AGC_INTERVAL_RESP, _u16(4))
    modem.script.append((CMD_AGC_INTERVAL_RESP, _u16(30)))

    assert modem.set_agc_reset_interval(30) == 30
    assert modem.script == []
    assert modem.sent == [(CMD_SET_AGC_INTERVAL, _u16(30), CMD_AGC_INTERVAL_RESP)]


def test_a_reply_after_timeout_is_discarded():
    modem = FakeModem()
    modem._rf_expect_stale = {CMD_AGC_INTERVAL_RESP, CMD_ERROR}

    with modem._response_lock:
        assert modem._rf_note_unsolicited(CMD_AGC_INTERVAL_RESP, _u16(30)) is True
    assert modem._rf_expect_stale == set()

    modem.script.append((CMD_AGC_INTERVAL_RESP, _u16(12)))
    assert modem.set_agc_reset_interval(12) == 12


def test_saved_controls_are_sent_again_after_reconnect():
    modem = FakeModem(
        {
            "agc_reset_interval_seconds": 30,
            "fem_rx_gain": True,
            "rx_boosted_gain": False,
        }
    )
    caps = _caps(RF_CAP_AGC, RF_CAP_FEM_RX_LNA, RF_CAP_FEM_TX_PA, RF_CAP_RX_BOOSTED_GAIN)
    cycle = [
        caps,
        (CMD_AGC_INTERVAL_RESP, _u16(30)),
        (CMD_FEM_STATE_RESP, bytes([FEM_STATE_RX_LNA | FEM_STATE_TX_PA, FEM_STATE_RX_LNA])),
        (CMD_RX_BOOST_RESP, bytes([0x00])),
    ]
    modem.script.extend(cycle)
    modem.apply_saved_rf_controls()
    first = [item[0] for item in modem.sent]
    assert first == [
        CMD_GET_RF_CAPS,
        CMD_SET_AGC_INTERVAL,
        CMD_SET_FEM_STATE,
        CMD_SET_RX_BOOST,
    ]
    assert modem.applied_hardware_config["agc_reset_interval_seconds"] == 30
    assert modem.applied_hardware_config["fem_rx_gain"] is True
    assert modem.applied_hardware_config["rx_boosted_gain"] is False

    modem.script.extend(cycle)
    modem.apply_saved_rf_controls()
    assert modem.sent[len(first)][0] == CMD_GET_RF_CAPS
    assert modem.sent[len(first) + 1] == (CMD_SET_AGC_INTERVAL, _u16(30), CMD_AGC_INTERVAL_RESP)


def test_get_agc_reports_the_running_interval():
    modem = FakeModem()
    modem.script.append((CMD_AGC_INTERVAL_RESP, _u16(12)))
    assert modem.get_agc_reset_interval() == 12
    assert modem.sent == [(CMD_GET_AGC_INTERVAL, b"", CMD_AGC_INTERVAL_RESP)]


def _live_radio(cls):
    radio = cls("unused")
    if cls is TCPLoRaRadio:
        radio._sock = object()
    else:
        radio._serial = SimpleNamespace(is_open=True)
        radio._connected_event.set()
    radio._event_loop = asyncio.get_running_loop()
    radio._rf_write_frame = Mock()
    return radio


@pytest.mark.asyncio
@pytest.mark.parametrize("cls", [TCPLoRaRadio, USBLoRaRadio])
@pytest.mark.parametrize("late_error", [False, True])
@pytest.mark.parametrize(
    "cmd,reply_cmd,old_reply,new_reply,setter,expected",
    [
        (
            CMD_SET_RX_BOOST,
            CMD_RX_BOOST_RESP,
            b"\x00",
            b"\x01",
            lambda r: r.set_rx_boosted_gain(True),
            True,
        ),
        (
            CMD_SET_FEM_STATE,
            CMD_FEM_STATE_RESP,
            b"\x03\x00",
            b"\x03\x01",
            lambda r: r.set_fem_state(rx_gain=True),
            {"rx_gain": True, "tx_gain": False},
        ),
        (
            CMD_SET_AGC_INTERVAL,
            CMD_AGC_INTERVAL_RESP,
            _u16(30),
            _u16(12),
            lambda r: r.set_agc_reset_interval(12),
            12,
        ),
    ],
)
async def test_next_request_waits_for_old_reply(
    cls, late_error, cmd, reply_cmd, old_reply, new_reply, setter, expected
):
    radio = _live_radio(cls)
    assert await asyncio.to_thread(radio._rf_transact, cmd, b"", reply_cmd, 0.01) is None
    writes = radio._rf_write_frame.call_count
    request = asyncio.create_task(asyncio.to_thread(setter, radio))
    await asyncio.sleep(0.02)
    assert radio._rf_write_frame.call_count == writes
    if late_error:
        radio._dispatch_frame(CMD_ERROR, bytes([ERR_UNSUPPORTED]))
    else:
        radio._dispatch_frame(reply_cmd, old_reply)

    async def answer():
        while radio._rf_write_frame.call_count == writes:
            await asyncio.sleep(0.001)
        radio._dispatch_frame(reply_cmd, new_reply)

    await asyncio.wait_for(answer(), 0.5)
    assert await asyncio.wait_for(request, 0.5) == expected
    assert radio._rf_expect_stale == set()
    assert radio._response_events == {}


@pytest.mark.asyncio
@pytest.mark.parametrize("cls", [TCPLoRaRadio, USBLoRaRadio])
async def test_missing_late_reply_prevents_another_write(cls):
    radio = _live_radio(cls)
    for _ in range(2):
        result = await asyncio.to_thread(
            radio._rf_transact, CMD_SET_RX_BOOST, b"\x01", CMD_RX_BOOST_RESP, 0.01
        )
        assert result is None
    assert radio._rf_write_frame.call_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("cls", [TCPLoRaRadio, USBLoRaRadio])
async def test_command_lock_timeout_cannot_send_later(cls):
    radio = _live_radio(cls)
    await radio._command_lock.acquire()
    result = await asyncio.to_thread(
        radio._rf_transact, CMD_SET_AGC_INTERVAL, _u16(30), CMD_AGC_INTERVAL_RESP, 0.01
    )
    assert result is None
    radio._command_lock.release()
    await asyncio.sleep(0.02)
    assert radio._rf_write_frame.call_count == 0
    assert radio._rf_expect_stale == set()
    assert radio._response_events == {}


@pytest.mark.asyncio
@pytest.mark.parametrize("cls", [TCPLoRaRadio, USBLoRaRadio])
async def test_timeout_cleans_event_waiters_and_preserves_late_reply(cls):
    radio = _live_radio(cls)
    tasks = asyncio.all_tasks()
    assert (
        await asyncio.to_thread(
            radio._rf_transact, CMD_SET_RX_BOOST, b"\x01", CMD_RX_BOOST_RESP, 0.01
        )
        is None
    )
    await asyncio.sleep(0)
    assert asyncio.all_tasks() == tasks
    assert radio._response_events == {}
    radio._dispatch_frame(CMD_RX_BOOST_RESP, b"\x01")
    assert radio._rf_expect_stale == set()


@pytest.mark.asyncio
@pytest.mark.parametrize("cls", [TCPLoRaRadio, USBLoRaRadio])
async def test_normal_command_waits_for_late_reply_and_keeps_its_own_error(cls):
    radio = _live_radio(cls)
    assert (
        await asyncio.to_thread(
            radio._rf_transact, CMD_SET_RX_BOOST, b"\x01", CMD_RX_BOOST_RESP, 0.01
        )
        is None
    )
    written = asyncio.Event()

    def write(frame):
        written.set()
        asyncio.get_running_loop().call_soon(
            radio._dispatch_frame, CMD_ERROR, bytes([ERR_UNSUPPORTED])
        )

    if cls is TCPLoRaRadio:
        radio._sock_write = write
    else:
        radio._serial.write = write
        radio._serial.flush = Mock()
    request = asyncio.create_task(
        radio._send_command(CMD_TX_REQUEST, b"data", CMD_TX_DONE, timeout=0.5)
    )
    await asyncio.sleep(0.02)
    assert not written.is_set()
    radio._dispatch_frame(CMD_RX_BOOST_RESP, b"\x01")
    assert await asyncio.wait_for(request, 0.2) is None
    assert written.is_set()
    assert radio._rf_expect_stale == set()


@pytest.mark.parametrize("cls", [TCPLoRaRadio, USBLoRaRadio])
def test_sync_exchange_drains_old_reply_before_writing(cls):
    radio = cls("unused")
    if cls is TCPLoRaRadio:
        radio._sock = object()
    else:
        radio._serial = SimpleNamespace(is_open=True)
    radio._rf_expect_stale = {CMD_RX_BOOST_RESP, CMD_ERROR}
    radio._rf_write_frame = Mock()

    def read(timeout):
        if radio._rf_expect_stale:
            radio._rf_write_frame.assert_not_called()
            return CMD_ERROR, bytes([ERR_UNSUPPORTED])
        radio._rf_write_frame.assert_called_once()
        return CMD_RX_BOOST_RESP, b"\x01"

    radio._read_frame_sync = read
    assert radio.set_rx_boosted_gain(True) is True
    assert radio._rf_expect_stale == set()


def test_reconnect_clears_pending_reply_even_without_saved_controls():
    radio = TCPLoRaRadio("unused")
    radio._rf_expect_stale = {CMD_RX_BOOST_RESP, CMD_ERROR}
    radio._rf_caps = 15
    radio.applied_hardware_config["rx_boosted_gain"] = False
    radio.apply_saved_rf_controls()
    assert radio._rf_expect_stale == set()
    assert radio._rf_caps is None
    assert radio.applied_hardware_config == {}


@pytest.mark.parametrize("setter", [False, True])
def test_rx_boost_fault_invalidates_previously_confirmed_state(setter):
    modem = FakeModem({"rx_boosted_gain": True})
    modem.applied_hardware_config["rx_boosted_gain"] = True
    modem.script.append((CMD_ERROR, bytes([ERR_RADIO_FAULT])))
    result = modem.set_rx_boosted_gain(True) if setter else modem.get_rx_boosted_gain()
    assert result is None
    assert "rx_boosted_gain" not in modem.applied_hardware_config
    assert modem.radio_config["rx_boosted_gain"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize("cls", [TCPLoRaRadio, USBLoRaRadio])
@pytest.mark.parametrize("draining", [False, True])
async def test_sync_rf_wait_preserves_received_packets(cls, draining):
    radio = cls("unused")
    if cls is TCPLoRaRadio:
        radio._sock = object()
    else:
        radio._serial = SimpleNamespace(is_open=True)
    radio._rf_write_frame = Mock()
    radio.rx_callback = Mock()
    radio._event_loop = asyncio.get_running_loop()
    packet = struct.pack("<hhh", -90, 25, -91) + b"packet"
    script = [(CMD_RX_PACKET, packet)]
    if draining:
        radio._rf_expect_stale = {CMD_RX_BOOST_RESP, CMD_ERROR}
        script.append((CMD_ERROR, bytes([ERR_UNSUPPORTED])))
    script.append((CMD_RX_BOOST_RESP, b"\x01"))
    replies = iter(script)
    radio._read_frame_sync = lambda timeout: next(replies)

    def restore():
        radio._rx_thread = threading.current_thread()
        return radio.set_rx_boosted_gain(True)

    assert await asyncio.to_thread(restore) is True
    radio.rx_callback.assert_called_once_with(b"packet")


@pytest.mark.asyncio
@pytest.mark.parametrize("cls", [TCPLoRaRadio, USBLoRaRadio])
async def test_rf_write_does_not_block_event_loop(cls):
    radio = _live_radio(cls)
    started = threading.Event()
    release = threading.Event()

    def write(frame):
        started.set()
        release.wait(0.3)
        radio._dispatch_frame(CMD_RX_BOOST_RESP, b"\x01")

    radio._rf_write_frame = write
    before = time.monotonic()
    request = asyncio.create_task(asyncio.to_thread(radio.set_rx_boosted_gain, True))
    try:
        while not started.is_set():
            await asyncio.sleep(0.001)
        assert time.monotonic() - before < 0.15
        assert not release.is_set()
        # The write remains blocked while the loop services this task.
        assert not request.done()
        assert radio.applied_hardware_config == {}
    finally:
        release.set()
    assert await request is True


@pytest.mark.asyncio
@pytest.mark.parametrize("cls", [TCPLoRaRadio, USBLoRaRadio])
async def test_old_exchange_cannot_quarantine_reconnected_link(cls):
    radio = _live_radio(cls)
    request = asyncio.create_task(
        asyncio.to_thread(radio._rf_transact, CMD_SET_RX_BOOST, b"\x01", CMD_RX_BOOST_RESP, 0.1)
    )
    while not radio._rf_write_frame.called:
        await asyncio.sleep(0.001)
    await asyncio.to_thread(radio.apply_saved_rf_controls)
    assert await request is None
    expected = {CMD_RX_BOOST_RESP, CMD_ERROR} if cls is USBLoRaRadio else set()
    assert radio._rf_expect_stale == expected


@pytest.mark.parametrize("cls", [TCPLoRaRadio, USBLoRaRadio])
def test_rf_call_does_not_read_alongside_rx_worker_without_event_loop(cls):
    radio = cls("unused")
    if cls is TCPLoRaRadio:
        radio._sock = object()
    else:
        radio._serial = SimpleNamespace(is_open=True)
    radio._rx_thread = SimpleNamespace(is_alive=lambda: True)
    radio._read_frame_sync = Mock(return_value=(CMD_RX_BOOST_RESP, b"\x01"))
    radio._rf_write_frame = Mock()
    assert radio.get_rx_boosted_gain() is None
    radio._read_frame_sync.assert_not_called()
    radio._rf_write_frame.assert_not_called()


@pytest.mark.parametrize("cls", [TCPLoRaRadio, USBLoRaRadio])
@pytest.mark.parametrize("status_reply", [False, True])
def test_radio_fault_from_dispatch_invalidates_boost_cache(cls, status_reply):
    radio = cls("unused", radio_config={"rx_boosted_gain": True})
    radio.applied_hardware_config["rx_boosted_gain"] = True
    if status_reply:
        radio._dispatch_frame(
            CMD_STATUS_RESP, struct.pack(STATUS_RESP_FMT, 10, 1, 2, 0, -90, 20, -1000, 25, 2)
        )
    else:
        radio._dispatch_frame(CMD_ERROR, bytes([ERR_RADIO_FAULT]))
    assert "rx_boosted_gain" not in radio.applied_hardware_config
    assert radio.radio_config["rx_boosted_gain"] is True


def test_clean_rx_boost_rollback_keeps_previous_confirmed_mode():
    modem = FakeModem({"rx_boosted_gain": False})
    modem.applied_hardware_config["rx_boosted_gain"] = False
    modem.script.append((CMD_ERROR, bytes([ERR_RADIO_INIT])))
    assert modem.set_rx_boosted_gain(True) is None
    assert modem.applied_hardware_config["rx_boosted_gain"] is False
    assert modem.radio_config["rx_boosted_gain"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("cls", [TCPLoRaRadio, USBLoRaRadio])
async def test_failed_rf_write_still_quarantines_a_possible_reply(cls):
    radio = _live_radio(cls)
    radio._rf_write_frame.side_effect = OSError("partial write")
    assert await asyncio.to_thread(radio.set_rx_boosted_gain, True) is None
    assert radio._rf_expect_stale == {CMD_RX_BOOST_RESP, CMD_ERROR}
    radio._dispatch_frame(CMD_RX_BOOST_RESP, b"\x01")
    assert radio._rf_expect_stale == set()


@pytest.mark.asyncio
@pytest.mark.parametrize("cls", [TCPLoRaRadio, USBLoRaRadio])
async def test_cancelling_inflight_write_keeps_command_ownership(cls):
    radio = _live_radio(cls)
    started = threading.Event()
    release = threading.Event()
    writes = []

    def write(frame):
        writes.append(frame)
        if len(writes) == 1:
            started.set()
            release.wait(1)
        radio._dispatch_frame(CMD_RX_BOOST_RESP, bytes([len(writes) == 1]))

    radio._rf_write_frame = write
    first = asyncio.create_task(
        radio._rf_transact_async(CMD_SET_RX_BOOST, b"\x01", CMD_RX_BOOST_RESP, 1)
    )
    while not started.is_set():
        await asyncio.sleep(0.001)
    first.cancel()
    second = asyncio.create_task(
        radio._rf_transact_async(CMD_SET_RX_BOOST, b"\x00", CMD_RX_BOOST_RESP, 1)
    )
    try:
        await asyncio.sleep(0.02)
        assert len(writes) == 1
        assert not first.done()
        first.cancel()
        await asyncio.sleep(0)
        assert not first.done()
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await first
    assert await second == (CMD_RX_BOOST_RESP, b"\x00")
    assert radio._rf_expect_stale == set()


@pytest.mark.asyncio
@pytest.mark.parametrize("cls", [TCPLoRaRadio, USBLoRaRadio])
async def test_cancelled_write_queued_for_worker_cannot_send(monkeypatch, cls):
    radio = _live_radio(cls)
    entered = asyncio.Event()
    release = asyncio.Event()
    to_thread = asyncio.to_thread

    async def delayed_worker(func, *args, **kwargs):
        entered.set()
        await release.wait()
        return await to_thread(func, *args, **kwargs)

    monkeypatch.setattr(asyncio, "to_thread", delayed_worker)
    request = asyncio.create_task(
        radio._rf_transact_async(CMD_SET_RX_BOOST, b"\x01", CMD_RX_BOOST_RESP, 1)
    )
    await entered.wait()
    request.cancel()
    await asyncio.sleep(0)
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await request
    radio._rf_write_frame.assert_not_called()
    assert radio._rf_expect_stale == set()


@pytest.mark.asyncio
async def test_serial_reopen_does_not_quarantine_an_unsent_write(monkeypatch):
    radio = _live_radio(USBLoRaRadio)
    entered = asyncio.Event()
    release = asyncio.Event()

    async def delayed_worker(func):
        entered.set()
        await release.wait()
        return func()

    monkeypatch.setattr(asyncio, "to_thread", delayed_worker)
    request = asyncio.create_task(
        radio._rf_transact_async(CMD_SET_RX_BOOST, b"\x01", CMD_RX_BOOST_RESP, 1)
    )
    await entered.wait()
    radio.apply_saved_rf_controls()
    release.set()
    assert await request is None
    radio._rf_write_frame.assert_not_called()
    assert radio._rf_expect_stale == set()


@pytest.mark.asyncio
@pytest.mark.parametrize("cls", [TCPLoRaRadio, USBLoRaRadio])
async def test_reconnect_handshake_excludes_runtime_commands(cls):
    radio = _live_radio(cls)
    radio._rf_reconnecting = True
    assert await asyncio.to_thread(radio.set_rx_boosted_gain, True) is None
    assert await radio._send_command(CMD_TX_REQUEST, b"data", CMD_TX_DONE, 0.01) is None
    radio._rf_write_frame.assert_not_called()


@pytest.mark.asyncio
async def test_socket_close_retires_inflight_rf_exchange():
    radio = _live_radio(TCPLoRaRadio)
    request = asyncio.create_task(
        asyncio.to_thread(radio._rf_transact, CMD_SET_RX_BOOST, b"\x01", CMD_RX_BOOST_RESP, 0.1)
    )
    while not radio._rf_write_frame.called:
        await asyncio.sleep(0.001)
    radio._close_sock()
    assert await request is None
    assert radio._rf_expect_stale == set()
    assert radio._rf_reconnecting


@pytest.mark.parametrize("cls", [TCPLoRaRadio, USBLoRaRadio])
def test_sync_drain_cannot_send_after_deadline(monkeypatch, cls):
    radio = cls("unused")
    radio._rf_expect_stale = {CMD_RX_BOOST_RESP, CMD_ERROR}
    radio._rf_write_frame = Mock()
    now = [0.0]
    monkeypatch.setattr(time, "monotonic", lambda: now[0])

    def read(timeout):
        now[0] = 1.0
        return CMD_RX_BOOST_RESP, b"\x00"

    radio._read_frame_sync = read
    assert radio._rf_transact_sync(CMD_SET_RX_BOOST, b"\x01", CMD_RX_BOOST_RESP, 0.1) is None
    radio._rf_write_frame.assert_not_called()
    assert radio._rf_expect_stale == set()


def test_serial_reopen_preserves_deferred_reply_ownership():
    radio = USBLoRaRadio("unused")
    radio._serial = SimpleNamespace(is_open=True)
    radio._rf_expect_stale = {CMD_RX_BOOST_RESP, CMD_ERROR}
    radio.apply_saved_rf_controls()
    assert radio._rf_expect_stale == {CMD_RX_BOOST_RESP, CMD_ERROR}


@pytest.mark.parametrize("late_cmd,payload", [(CMD_RX_BOOST_RESP, b"\x01"), (CMD_ERROR, b"\x10")])
def test_serial_handshake_consumes_deferred_terminal_reply(late_cmd, payload):
    radio = USBLoRaRadio("unused")
    radio._rf_expect_stale = {CMD_RX_BOOST_RESP, CMD_ERROR}
    frames = bytearray(build_frame(late_cmd, payload) + build_frame(CMD_CONFIG_RESP, b"config"))

    def read(size):
        part = bytes(frames[:size])
        del frames[:size]
        return part

    radio._serial = SimpleNamespace(timeout=0.1, read=read)
    assert radio._read_frame_sync(0.1, CMD_CONFIG_RESP) == (CMD_CONFIG_RESP, b"config")
    assert radio._rf_expect_stale == set()


@pytest.mark.asyncio
@pytest.mark.parametrize("cls", [TCPLoRaRadio, USBLoRaRadio])
async def test_link_retirement_waits_for_started_write(cls):
    radio = _live_radio(cls)
    started = threading.Event()
    release = threading.Event()

    def write(frame):
        started.set()
        release.wait(1)
        radio._dispatch_frame(CMD_RX_BOOST_RESP, b"\x01")

    radio._rf_write_frame = write
    request = asyncio.create_task(asyncio.to_thread(radio.set_rx_boosted_gain, True))
    while not started.is_set():
        await asyncio.sleep(0.001)
    generation = radio._rf_generation
    retiring = asyncio.create_task(asyncio.to_thread(radio._rf_retire_link, cls is USBLoRaRadio))
    try:
        await asyncio.sleep(0.02)
        assert not retiring.done()
        assert radio._rf_generation == generation
    finally:
        release.set()
    await retiring
    await request
    assert radio._rf_generation == generation + 1


def _tx_writer(radio):
    writer = Mock(side_effect=lambda frame: radio._dispatch_frame(CMD_TX_DONE, _u32(1000)))
    if isinstance(radio, TCPLoRaRadio):
        radio._sock_write = writer
    else:
        radio._serial = Mock(is_open=True)
        radio._serial.write = writer
    return writer


@pytest.mark.asyncio
async def test_usb_missing_reply_expires_from_reopen_and_commands_resume(monkeypatch, caplog):
    from openhop_core.hardware import frame_rf_frontend as frontend

    now = [0.0]
    monkeypatch.setattr(frontend, "time", SimpleNamespace(monotonic=lambda: now[0]))
    monkeypatch.setattr("openhop_core.hardware.usb_radio.time.sleep", lambda delay: None)
    radio = _live_radio(USBLoRaRadio)
    radio._serial = Mock(is_open=True)
    radio._rf_inflight_reply = CMD_RX_BOOST_RESP

    def reopen():
        now[0] = 100.0
        return Mock(is_open=True)

    radio._open_serial_sync = reopen
    radio._apply_config_sync = Mock(return_value=True)
    assert radio._reconnect_serial_sync()
    radio._serial.reset_input_buffer.assert_not_called()
    writer = _tx_writer(radio)
    grace = frontend._RF_QUARANTINE_GRACE_S
    assert grace == 3 * frontend._RF_SET_TIMEOUT_S
    now[0] = 100.0 + grace - 0.001
    with radio._response_lock:
        assert not radio._rf_expire_stale()
    assert radio._rf_expect_stale
    now[0] += 0.001
    with caplog.at_level("WARNING", logger="FrameRfControls"):
        assert await radio._send_command(CMD_TX_REQUEST, b"data", CMD_TX_DONE, 0.1) == _u32(1000)
        assert await radio._send_command(CMD_TX_REQUEST, b"more", CMD_TX_DONE, 0.1) == _u32(1000)
    assert writer.call_count == 2
    assert not radio._rf_expect_stale
    assert sum("quarantine expired" in record.message for record in caplog.records) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("cls", [TCPLoRaRadio, USBLoRaRadio])
async def test_missing_reply_expires_without_reconnect(monkeypatch, cls):
    from openhop_core.hardware import frame_rf_frontend as frontend

    radio = _live_radio(cls)
    assert (
        await radio._rf_transact_async(CMD_SET_RX_BOOST, b"\x01", CMD_RX_BOOST_RESP, 0.01) is None
    )
    assert radio._rf_expect_stale
    expires = radio._rf_stale_deadline
    monkeypatch.setattr(frontend, "time", SimpleNamespace(monotonic=lambda: expires))
    writer = _tx_writer(radio)
    assert await radio._send_command(CMD_TX_REQUEST, b"data", CMD_TX_DONE, 0.1) == _u32(1000)
    writer.assert_called_once()


@pytest.mark.parametrize("cls", [TCPLoRaRadio, USBLoRaRadio])
def test_sync_commands_resume_after_lost_reply_grace(monkeypatch, cls):
    from openhop_core.hardware import frame_rf_frontend as frontend

    radio = cls("unused")
    now = [0.0]
    monkeypatch.setattr(frontend, "time", SimpleNamespace(monotonic=lambda: now[0]))
    radio._rf_write_frame = Mock()

    def lose_reply(timeout):
        now[0] += timeout
        return None

    radio._read_frame_sync = lose_reply
    assert radio._rf_transact_sync(CMD_SET_RX_BOOST, b"\x01", CMD_RX_BOOST_RESP, 0.1) is None
    now[0] = radio._rf_stale_deadline - 0.01

    def read(timeout):
        if radio._rf_expect_stale:
            now[0] += timeout
            return None
        return CMD_RX_BOOST_RESP, b"\x01"

    radio._read_frame_sync = read
    assert radio._rf_transact_sync(CMD_SET_RX_BOOST, b"\x01", CMD_RX_BOOST_RESP, 0.1) == (
        CMD_RX_BOOST_RESP,
        b"\x01",
    )
    assert radio._rf_write_frame.call_count == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("late_cmd,payload", [(CMD_RX_BOOST_RESP, b"\x00"), (CMD_ERROR, b"\x10")])
async def test_late_usb_reply_inside_reopen_grace_is_discarded(monkeypatch, late_cmd, payload):
    monkeypatch.setattr("openhop_core.hardware.usb_radio.time.sleep", lambda delay: None)
    radio = _live_radio(USBLoRaRadio)
    radio._serial = Mock(is_open=True)
    radio._rf_inflight_reply = CMD_RX_BOOST_RESP
    radio._open_serial_sync = Mock(return_value=Mock(is_open=True))
    radio._apply_config_sync = Mock(return_value=True)
    assert radio._reconnect_serial_sync()
    request = asyncio.create_task(
        radio._rf_transact_async(CMD_SET_RX_BOOST, b"\x01", CMD_RX_BOOST_RESP, 0.5)
    )
    await asyncio.sleep(0.02)
    assert not request.done()
    radio._rf_write_frame.assert_not_called()
    radio._dispatch_frame(late_cmd, payload)
    while not radio._rf_write_frame.called:
        await asyncio.sleep(0.001)
    assert not request.done()
    radio._dispatch_frame(CMD_RX_BOOST_RESP, b"\x01")
    assert await request == (CMD_RX_BOOST_RESP, b"\x01")


@pytest.mark.asyncio
@pytest.mark.parametrize("cls", [TCPLoRaRadio, USBLoRaRadio])
@pytest.mark.parametrize("times_out", [False, True])
async def test_tx_waits_for_rf_restore_with_its_own_deadline(cls, times_out):
    radio = _live_radio(cls)
    writer = _tx_writer(radio)
    started = threading.Event()
    release = threading.Event()

    def restore():
        started.set()
        assert release.wait(1)

    radio._restore_rf_controls = restore
    restoring = asyncio.create_task(asyncio.to_thread(radio.apply_saved_rf_controls))
    while not started.is_set():
        await asyncio.sleep(0.001)
    tx = asyncio.create_task(radio._send_command(CMD_TX_REQUEST, b"data", CMD_TX_DONE, 0.08))
    try:
        await asyncio.sleep(0.02)
        assert not tx.done()
        writer.assert_not_called()
        if times_out:
            assert await tx is None
            writer.assert_not_called()
        else:
            release.set()
            assert await tx == _u32(1000)
            writer.assert_called_once()
    finally:
        release.set()
        await restoring
    assert not radio._response_events
    assert not radio._response_data


@pytest.mark.parametrize("failure", ["open", "config"])
@pytest.mark.parametrize("cls", [TCPLoRaRadio, USBLoRaRadio])
def test_failed_reconnect_clears_gate_and_later_success_can_restore(monkeypatch, cls, failure):
    radio = cls("unused")
    handle = Mock(is_open=True)
    radio._apply_config_sync = Mock(return_value=failure != "config")
    if cls is TCPLoRaRadio:
        monkeypatch.setattr(
            "openhop_core.hardware.tcp_radio.socket.socket", Mock(return_value=handle)
        )
        radio._ping_sync = Mock(return_value=True)
        if failure == "open":
            handle.connect.side_effect = OSError("missing modem")
        reconnect = radio._reopen_socket
    else:
        monkeypatch.setattr("openhop_core.hardware.usb_radio.time.sleep", lambda delay: None)
        radio._open_serial_sync = Mock(return_value=handle)
        if failure == "open":
            radio._open_serial_sync.side_effect = OSError("missing modem")
        radio._stop_event.wait = Mock(side_effect=lambda delay: radio._stop_event.set())
        reconnect = radio._reconnect_serial_sync
    assert not reconnect()
    assert not radio._rf_reconnecting
    radio._stop_event.clear()
    handle.connect.side_effect = None
    if cls is USBLoRaRadio:
        radio._open_serial_sync.side_effect = None
    radio._apply_config_sync.return_value = True
    assert reconnect()
    assert not radio._rf_reconnecting


@pytest.mark.parametrize("cls", [TCPLoRaRadio, USBLoRaRadio])
def test_stopped_reconnect_clears_gate(cls):
    radio = cls("unused")
    radio._rf_reconnecting = True
    radio._stop_event.set()
    reconnect = (
        radio._reconnect_with_backoff if cls is TCPLoRaRadio else radio._reconnect_serial_sync
    )
    assert not reconnect()
    assert not radio._rf_reconnecting
    radio._rf_reconnecting = True
    radio.cleanup()
    assert not radio._rf_reconnecting


@pytest.mark.parametrize(
    "before,after,elapsed,cleared",
    [
        (120, 2, 2, True),
        (120, 122, 2, False),
        (None, 2, 2, False),
        (4294966, 1, 3, False),
        (120, None, 2, False),
    ],
)
def test_usb_reopen_status_detects_reboot_before_rf_restore(
    monkeypatch, before, after, elapsed, cleared
):
    from openhop_core.hardware import frame_rf_frontend as frontend

    now = [0.0]
    monkeypatch.setattr(frontend, "time", SimpleNamespace(monotonic=lambda: now[0]))
    monkeypatch.setattr("openhop_core.hardware.usb_radio.time.sleep", lambda delay: None)
    radio = USBLoRaRadio("unused")
    radio._serial = Mock(is_open=True)

    def status(uptime):
        return struct.pack(STATUS_RESP_FMT, uptime, 0, 0, 0, -100, 0, -1100, 20, 0)

    if before is not None:
        radio._dispatch_frame(CMD_STATUS_RESP, status(before))
    radio._rf_inflight_reply = CMD_RX_BOOST_RESP
    frames = bytearray(build_frame(CMD_CONFIG_RESP, b"config"))
    frames.extend(build_frame(CMD_STATUS_RESP, status(after) if after is not None else b"short"))

    def read(size):
        part = bytes(frames[:size])
        del frames[:size]
        return part

    handle = Mock(is_open=True, timeout=0.1)
    handle.read.side_effect = read

    def reopen():
        now[0] += elapsed
        return handle

    radio._open_serial_sync = reopen
    quarantined_at_restore = []
    radio._restore_rf_controls = Mock(
        side_effect=lambda: quarantined_at_restore.append(bool(radio._rf_expect_stale))
    )
    assert radio._reconnect_serial_sync()
    assert bool(radio._rf_expect_stale) is not cleared
    assert handle.write.call_args_list[1].args[0] == build_frame(CMD_STATUS_REQ)
    radio._restore_rf_controls.assert_called_once()
    assert quarantined_at_restore == [not cleared]
    handle.reset_input_buffer.assert_not_called()
    assert not radio._rf_reconnecting


@pytest.mark.asyncio
@pytest.mark.parametrize("cls", [TCPLoRaRadio, USBLoRaRadio])
async def test_tx_waits_for_missing_transport_during_reconnect(cls):
    radio = _live_radio(cls)
    radio._rf_reconnecting = True
    if cls is TCPLoRaRadio:
        radio._sock = None
    else:
        radio._connected_event.clear()
    tx = asyncio.create_task(radio._send_command(CMD_TX_REQUEST, b"data", CMD_TX_DONE, 0.2))
    try:
        await asyncio.sleep(0.02)
        assert not tx.done()
        writer = _tx_writer(radio)
        if cls is TCPLoRaRadio:
            radio._sock = Mock()
        else:
            radio._connected_event.set()
        radio._rf_reconnecting = False
        assert await tx == _u32(1000)
        writer.assert_called_once()
    finally:
        tx.cancel()
        await asyncio.gather(tx, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("cls", [TCPLoRaRadio, USBLoRaRadio])
async def test_restore_and_reply_share_one_command_timeout(cls):
    radio = _live_radio(cls)
    radio._rf_restoring = True
    writer = Mock()
    if cls is TCPLoRaRadio:
        radio._sock_write = writer
    else:
        radio._serial = Mock(is_open=True)
        radio._serial.write = writer
    loop = asyncio.get_running_loop()
    restore_done = loop.call_later(0.04, setattr, radio, "_rf_restoring", False)
    late_reply = loop.call_later(0.12, radio._dispatch_frame, CMD_TX_DONE, _u32(1000))
    try:
        assert await radio._send_command(CMD_TX_REQUEST, b"data", CMD_TX_DONE, 0.1) is None
        writer.assert_called_once()
        assert not radio._response_events
        assert not radio._response_data
    finally:
        restore_done.cancel()
        late_reply.cancel()
