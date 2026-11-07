import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, call

import pytest

from openhop_core.hardware.protocol_constants import (
    CMD_CAD_PARAMS_RESP,
    CMD_SET_CAD_PARAMS,
)
from openhop_core.hardware.tcp_radio import TCPLoRaRadio
from openhop_core.hardware.usb_radio import USBLoRaRadio


def _make_radio(radio_cls):
    if radio_cls is TCPLoRaRadio:
        return radio_cls("127.0.0.1")
    return radio_cls("/dev/null")


@pytest.mark.asyncio
@pytest.mark.parametrize("radio_cls", [TCPLoRaRadio, USBLoRaRadio])
async def test_modem_cad_accepts_symbol_count_and_programs_firmware(radio_cls):
    radio = _make_radio(radio_cls)
    radio._send_command = AsyncMock(return_value=b"\x01")
    radio._perform_cad = AsyncMock(return_value=False)

    result = await radio.perform_cad(
        det_peak=23,
        det_min=11,
        timeout=0.5,
        calibration=True,
        cad_symbol_num=8,
    )

    assert result is False
    radio._send_command.assert_awaited_once_with(
        CMD_SET_CAD_PARAMS,
        bytes([0x03, 23, 11, 0x00]),
        expect_cmd=CMD_CAD_PARAMS_RESP,
        timeout=2.0,
    )
    radio._perform_cad.assert_awaited_once_with(0.6)


@pytest.mark.asyncio
@pytest.mark.parametrize("radio_cls", [TCPLoRaRadio, USBLoRaRadio])
async def test_modem_cad_reprograms_firmware_when_only_symbol_count_changes(radio_cls):
    radio = _make_radio(radio_cls)
    radio._send_command = AsyncMock(return_value=b"\x01")
    radio._perform_cad = AsyncMock(return_value=False)

    await radio.perform_cad(det_peak=23, det_min=11, cad_symbol_num=2)
    await radio.perform_cad(det_peak=23, det_min=11, cad_symbol_num=8)

    payloads = [call.args[1] for call in radio._send_command.await_args_list]
    assert payloads == [bytes([0x01, 23, 11, 0x00]), bytes([0x03, 23, 11, 0x00])]


@pytest.mark.parametrize("radio_cls", [TCPLoRaRadio, USBLoRaRadio])
def test_modem_cad_symbol_setter_tracks_valid_symbol_count_before_start(radio_cls):
    radio = _make_radio(radio_cls)

    assert radio.set_custom_cad_symbol_num(16) is True
    assert radio._custom_cad_symbol_num == 16


@pytest.mark.parametrize("radio_cls", [TCPLoRaRadio, USBLoRaRadio])
def test_modem_cad_symbol_setter_rejects_unsupported_count(radio_cls):
    radio = _make_radio(radio_cls)

    with pytest.raises(ValueError, match="cad_symbol_num must be one of"):
        radio.set_custom_cad_symbol_num(3)


@pytest.mark.parametrize("radio_cls", [TCPLoRaRadio, USBLoRaRadio])
def test_modem_cad_setters_push_complete_config_in_either_order(radio_cls):
    radio = _make_radio(radio_cls)
    radio._initialized = True
    radio._push_cad_config_live = Mock(return_value=True)

    assert radio.set_custom_cad_thresholds(peak=23, min_val=11) is True
    assert radio.set_custom_cad_symbol_num(8) is True

    assert radio._push_cad_config_live.call_args_list == [
        call(),
        call(),
    ]
    assert radio._custom_cad_peak == 23
    assert radio._custom_cad_min == 11
    assert radio._custom_cad_symbol_num == 8

    radio = _make_radio(radio_cls)
    radio._initialized = True
    radio._push_cad_config_live = Mock(return_value=True)

    assert radio.set_custom_cad_symbol_num(8) is True
    assert radio.set_custom_cad_thresholds(peak=23, min_val=11) is True

    assert radio._push_cad_config_live.call_args_list == [call(), call()]
    assert radio._custom_cad_peak == 23
    assert radio._custom_cad_min == 11
    assert radio._custom_cad_symbol_num == 8


@pytest.mark.parametrize("radio_cls", [TCPLoRaRadio, USBLoRaRadio])
def test_modem_cad_sync_apply_restores_complete_cached_config(radio_cls):
    radio = _make_radio(radio_cls)
    radio.set_custom_cad_symbol_num(8)
    radio.set_custom_cad_thresholds(peak=23, min_val=11)
    radio._write_cad_frame_sync = Mock(return_value=True)

    assert radio._apply_cad_config_sync() is True

    radio._write_cad_frame_sync.assert_called_once_with(bytes([0x03, 23, 11, 0x00]))


@pytest.mark.parametrize("radio_cls", [TCPLoRaRadio, USBLoRaRadio])
def test_modem_cad_sync_apply_is_noop_without_thresholds(radio_cls):
    radio = _make_radio(radio_cls)
    radio.set_custom_cad_symbol_num(8)
    radio._write_cad_frame_sync = Mock(return_value=True)

    assert radio._apply_cad_config_sync() is True

    radio._write_cad_frame_sync.assert_not_called()


@pytest.mark.parametrize("radio_cls", [TCPLoRaRadio, USBLoRaRadio])
@pytest.mark.parametrize(
    ("symbol_count", "symbol_code"),
    [(1, 0x00), (2, 0x01), (4, 0x02), (8, 0x03), (16, 0x04)],
)
def test_modem_cad_live_setters_push_complete_encoded_tuple(
    radio_cls, symbol_count, symbol_code
):
    radio = _make_radio(radio_cls)
    radio._initialized = True
    radio._event_loop = Mock()
    radio._event_loop.is_running.return_value = True
    radio._send_command = Mock(return_value="cad-command")
    radio._run_async_safe = Mock(return_value=True)

    radio.set_custom_cad_thresholds(peak=23, min_val=11)
    radio.set_custom_cad_symbol_num(symbol_count)

    assert radio._send_command.call_args_list[-1] == call(
        CMD_SET_CAD_PARAMS,
        bytes([symbol_code, 23, 11, 0x00]),
        expect_cmd=CMD_CAD_PARAMS_RESP,
        timeout=3.0,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("radio_cls", [TCPLoRaRadio, USBLoRaRadio])
async def test_modem_commands_with_same_response_are_serialized(radio_cls):
    radio = _make_radio(radio_cls)
    radio._event_loop = asyncio.get_running_loop()
    active = 0
    max_active = 0

    if radio_cls is TCPLoRaRadio:
        radio._sock = Mock()
        radio._sock_write = Mock()
    else:
        radio._serial = Mock()
        radio._serial.is_open = True
        radio._connected_event.set()

    async def dispatch_response(payload):
        nonlocal active, max_active
        active += 1
        max_active = max(max_active, active)
        await asyncio.sleep(0)
        radio._dispatch_frame(CMD_CAD_PARAMS_RESP, payload)
        active -= 1

    original_write = radio._sock_write if radio_cls is TCPLoRaRadio else radio._serial.write

    def write_and_respond(_frame):
        result = original_write(_frame) if radio_cls is TCPLoRaRadio else None
        asyncio.create_task(dispatch_response(b"\x01"))
        return result

    if radio_cls is TCPLoRaRadio:
        radio._sock_write = Mock(side_effect=write_and_respond)
    else:
        radio._serial.write = Mock(side_effect=write_and_respond)

    responses = await asyncio.gather(
        radio._send_command(
            CMD_SET_CAD_PARAMS,
            b"first",
            expect_cmd=CMD_CAD_PARAMS_RESP,
        ),
        radio._send_command(
            CMD_SET_CAD_PARAMS,
            b"second",
            expect_cmd=CMD_CAD_PARAMS_RESP,
        ),
    )

    assert responses == [b"\x01", b"\x01"]
    assert max_active == 1


def test_usb_reconnect_resolves_reenumerated_port(monkeypatch):
    radio = USBLoRaRadio("/dev/ttyACM0")
    radio._port_identity = (0x1A86, 0x55D3, "5B5F091637")
    monkeypatch.setattr(
        "openhop_core.hardware.usb_radio.list_ports.comports",
        lambda: [
            SimpleNamespace(
                device="/dev/ttyACM1",
                vid=0x1A86,
                pid=0x55D3,
                serial_number="5B5F091637",
            )
        ],
    )

    assert radio._resolve_serial_port() == "/dev/ttyACM1"


def test_usb_status_reports_disconnected_transport_unavailable():
    radio = USBLoRaRadio("/dev/ttyACM0")
    radio._initialized = True

    status = radio.get_status()

    assert status["initialized"] is False
    assert status["hardware_ready"] is False


def test_usb_reconnect_reopens_transport_and_restores_cached_configuration():
    radio = USBLoRaRadio("/dev/ttyACM0")
    old_serial = Mock()
    new_serial = Mock()
    radio._serial = old_serial
    radio._open_serial_sync = Mock(return_value=new_serial)
    radio._apply_config_sync = Mock(return_value=True)

    assert radio._reconnect_serial_sync() is True

    old_serial.close.assert_called_once_with()
    new_serial.reset_input_buffer.assert_not_called()
    radio._apply_config_sync.assert_called_once_with()
    assert radio._serial is new_serial
    assert radio._connected_event.is_set()


def test_usb_rx_worker_reconnects_after_device_io_error():
    radio = USBLoRaRadio("/dev/ttyACM0")
    broken_serial = Mock()
    type(broken_serial).in_waiting = property(
        lambda _self: (_ for _ in ()).throw(OSError(5, "Input/output error"))
    )
    radio._serial = broken_serial

    def reconnect_then_stop():
        radio._stop_event.set()
        return True

    radio._reconnect_serial_sync = Mock(side_effect=reconnect_then_stop)
    radio._rx_worker()

    radio._reconnect_serial_sync.assert_called_once_with()
