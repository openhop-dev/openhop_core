"""Frame-protocol AGC/FEM/RX-boost client, with a scripted modem."""

import asyncio
import struct
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from openhop_core.hardware.frame_rf_frontend import FrameRfControls
from openhop_core.hardware.kiss_modem_wrapper import KissModemWrapper
from openhop_core.hardware.tcp_radio import TCPLoRaRadio
from openhop_core.hardware.usb_radio import USBLoRaRadio
from openhop_core.hardware.protocol_constants import (
    AGC_INTERVAL_MAX_SEC,
    CMD_AGC_INTERVAL_RESP,
    CMD_ERROR,
    CMD_FEM_STATE_RESP,
    CMD_GET_AGC_INTERVAL,
    CMD_GET_RF_CAPS,
    CMD_RF_CAPS_RESP,
    CMD_RX_BOOST_RESP,
    CMD_SET_AGC_INTERVAL,
    CMD_SET_FEM_STATE,
    CMD_SET_RX_BOOST,
    CMD_TX_DONE,
    CMD_TX_REQUEST,
    ERR_RADIO_FAULT,
    ERR_UNSUPPORTED,
    FEM_STATE_RX_LNA,
    FEM_STATE_TX_PA,
    RF_CAP_AGC,
    RF_CAP_FEM_RX_LNA,
    RF_CAP_FEM_TX_PA,
    RF_CAP_RX_BOOSTED_GAIN,
)


def _u16(value: int) -> bytes:
    return struct.pack("<H", value)


def _u32(value: int) -> bytes:
    return struct.pack("<I", value)


class FakeModem(FrameRfControls):
    def __init__(self, radio_config=None):
        self._init_rf_controls(radio_config)
        self.sent = []
        self.script = []

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
