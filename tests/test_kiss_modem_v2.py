"""Wire-level tests for MeshCore KISS v2 logical radio profiles.

These tests deliberately use only the host wrapper's byte decoder and mocked
serial connection.  They exercise the exact traffic a MeshCore KISS v2 modem
expects without requiring a radio or transmitting anything.
"""

import struct
import threading
import time
from unittest.mock import MagicMock

from openhop_core.hardware.kiss_modem_wrapper import (
    HW_CMD_GET_RADIO2,
    HW_CMD_SET_RADIO2,
    HW_CMD_SET_TEMPRADIO2,
    HW_RESP_OK,
    HW_RESP_RADIO2,
    HW_RESP_RX_META,
    HW_RESP_TEMPRADIO2,
    HW_RESP_TX_DONE,
    KISS_CMD_SETHARDWARE,
    KISS_FEND,
    KISS_RADIO2_PORT,
    KissModemWrapper,
)


def _feed(modem: KissModemWrapper, frame: bytes) -> None:
    for byte in frame:
        modem._decode_kiss_byte(byte)


def _wait_for_request(modem: KissModemWrapper, command: int) -> None:
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        if modem._active_request_subcmd == command:
            return
        time.sleep(0.001)
    raise AssertionError(f"KISS request 0x{command:02X} was not active")


class TestKissModemV2RadioConfig:
    def test_set_radio2_uses_fixed_little_endian_tuple(self):
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        calls = []

        def send(command, data=b"", timeout=5.0):
            calls.append((command, data, timeout))
            return (HW_RESP_OK, b"")

        modem._send_command = send

        assert modem.set_radio2_config(
            909_500_000,
            62_500,
            7,
            5,
            mode=2,
            preamble_length=96,
        )
        assert calls == [
            (
                HW_CMD_SET_RADIO2,
                struct.pack("<IIBBBH", 909_500_000, 62_500, 7, 5, 2, 96),
                5.0,
            )
        ]
        assert modem.radio2_config == {
            "frequency": 909_500_000,
            "bandwidth": 62_500,
            "spreading_factor": 7,
            "coding_rate": 5,
            "mode": 2,
            "preamble_length": 96,
        }

    def test_get_radio2_parses_saved_profile(self):
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        payload = struct.pack("<IIBBBH", 909_500_000, 62_500, 7, 5, 1, 0)
        modem._send_command = MagicMock(return_value=(HW_RESP_RADIO2, payload))

        assert modem.get_radio2_config() == {
            "frequency": 909_500_000,
            "bandwidth": 62_500,
            "spreading_factor": 7,
            "coding_rate": 5,
            "mode": 1,
            "preamble_length": 0,
        }
        modem._send_command.assert_called_once_with(HW_CMD_GET_RADIO2, timeout=5.0)

    def test_temporary_radio2_adds_minutes_and_preserves_saved_profile_cache(self):
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        saved = {"frequency": 910_525_000}
        modem.radio2_config = saved
        calls = []

        def send(command, data=b"", timeout=5.0):
            calls.append((command, data, timeout))
            return (HW_RESP_OK, b"")

        modem._send_command = send

        assert modem.set_temporary_radio2_config(
            909_500_000,
            62_500,
            7,
            5,
            3,
            mode=2,
            preamble_length=88,
        )
        assert calls == [
            (
                HW_CMD_SET_TEMPRADIO2,
                struct.pack("<IIBBBHH", 909_500_000, 62_500, 7, 5, 2, 88, 3),
                5.0,
            )
        ]
        assert modem.radio2_config is saved
        assert modem.temporary_radio2_config["remaining_minutes"] == 3

    def test_get_temporary_radio2_marks_zero_tuple_inactive(self):
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        active = struct.pack("<IIBBBHH", 909_500_000, 62_500, 7, 5, 2, 88, 2)
        modem._send_command = MagicMock(return_value=(HW_RESP_TEMPRADIO2, active))

        response = modem.get_temporary_radio2_config()
        assert response["frequency"] == 909_500_000
        assert response["remaining_minutes"] == 2
        assert response["active"] is True

        modem._send_command = MagicMock(
            return_value=(HW_RESP_TEMPRADIO2, bytes(struct.calcsize("<IIBBBHH")))
        )
        response = modem.get_temporary_radio2_config()
        assert response["mode"] == 0
        assert response["remaining_minutes"] == 0
        assert response["active"] is False
        assert modem.temporary_radio2_config is None

    def test_temporary_radio2_cancel_is_off_for_zero_minutes(self):
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.temporary_radio2_config = {"frequency": 909_500_000}
        modem._send_command = MagicMock(return_value=(HW_RESP_OK, b""))

        assert modem.set_temporary_radio2_config(0, 0, 0, 0, 0, mode=0)
        modem._send_command.assert_called_once_with(
            HW_CMD_SET_TEMPRADIO2,
            struct.pack("<IIBBBHH", 0, 0, 0, 0, 0, 0, 0),
            timeout=5.0,
        )
        assert modem.temporary_radio2_config is None

    def test_port_one_airtime_uses_active_then_saved_radio2_tuple(self):
        modem = KissModemWrapper(
            port="/dev/null",
            auto_configure=False,
            radio_config={"spreading_factor": 7, "bandwidth": 62_500, "coding_rate": 5},
        )
        saved = {"spreading_factor": 12, "bandwidth": 7_800, "coding_rate": 8, "mode": 2}
        temporary = {
            "spreading_factor": 11,
            "bandwidth": 15_600,
            "coding_rate": 8,
            "mode": 2,
            "active": True,
        }
        modem.radio2_config = saved
        modem.temporary_radio2_config = temporary

        assert modem._airtime_config_for_port(KISS_RADIO2_PORT) is temporary
        modem.temporary_radio2_config["active"] = False
        assert modem._airtime_config_for_port(KISS_RADIO2_PORT) is saved
        modem.radio2_config["mode"] = 1
        assert modem._airtime_config_for_port(KISS_RADIO2_PORT) is modem.radio_config


class TestKissModemV2Ports:
    def test_send_radio2_frame_uses_port_one_without_mutating_packet(self):
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True

        assert modem.send_radio2_frame(b"\x01\x02")
        assert modem.tx_buffer.pop() == bytes([KISS_FEND, 0x10, 0x01, 0x02, KISS_FEND])
        assert not modem.send_frame(b"\x01\x02", radio_port=2)

    def test_radio2_rx_port_reaches_four_argument_callback_with_legacy_rxmeta(self):
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True
        received = []
        modem.on_frame_received = lambda data, rssi, snr, port: received.append(
            (data, rssi, snr, port)
        )

        _feed(modem, bytes([KISS_FEND, 0x10, 0xA1, 0xB2, KISS_FEND]))
        _feed(
            modem,
            bytes(
                [
                    KISS_FEND,
                    KISS_CMD_SETHARDWARE,
                    HW_RESP_RX_META,
                    0x10,
                    0xB0,
                    KISS_FEND,
                ]
            ),
        )

        assert received == [(b"\xA1\xB2", -80, 4.0, KISS_RADIO2_PORT)]

    def test_radio2_query_response_correlates_with_real_command_waiter(self):
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        serial_conn = MagicMock()
        serial_conn.is_open = True
        serial_conn.write.side_effect = lambda frame: len(frame)
        modem.serial_conn = serial_conn
        modem.is_connected = True
        result = {}
        payload = struct.pack("<IIBBBH", 909_500_000, 62_500, 7, 5, 2, 88)

        thread = threading.Thread(
            target=lambda: result.setdefault("response", modem._send_command(HW_CMD_GET_RADIO2))
        )
        thread.start()
        _wait_for_request(modem, HW_CMD_GET_RADIO2)
        _feed(
            modem,
            bytes([KISS_FEND, KISS_CMD_SETHARDWARE, HW_RESP_RADIO2]) + payload + bytes([KISS_FEND]),
        )
        thread.join(timeout=1.0)

        assert not thread.is_alive()
        assert result["response"] == (HW_RESP_RADIO2, payload)
        assert serial_conn.write.call_args[0][0][1:3] == bytes(
            [KISS_CMD_SETHARDWARE, HW_CMD_GET_RADIO2]
        )

    def test_set_radio2_accepts_generic_ok_from_real_command_waiter(self):
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        serial_conn = MagicMock()
        serial_conn.is_open = True
        serial_conn.write.side_effect = lambda frame: len(frame)
        modem.serial_conn = serial_conn
        modem.is_connected = True
        result = {}

        thread = threading.Thread(
            target=lambda: result.setdefault(
                "response",
                modem._send_command(HW_CMD_SET_RADIO2, b"\x00" * 13),
            )
        )
        thread.start()
        _wait_for_request(modem, HW_CMD_SET_RADIO2)
        _feed(modem, bytes([KISS_FEND, KISS_CMD_SETHARDWARE, HW_RESP_OK, KISS_FEND]))
        thread.join(timeout=1.0)

        assert not thread.is_alive()
        assert result["response"] == (HW_RESP_OK, b"")

    def test_radio2_rejected_transmit_uses_normal_failed_txdone(self):
        """An RX-only/off radio2 does not need ambiguous generic Error handling."""
        modem = KissModemWrapper(port="/dev/null", auto_configure=False)
        modem.is_connected = True
        sent = threading.Event()
        requested_ports = []

        def send(data, *, radio_port=0):
            requested_ports.append(radio_port)
            sent.set()
            return True

        modem.send_frame = send
        verdict = []
        result = {}
        thread = threading.Thread(
            target=lambda: result.setdefault(
                "ok",
                modem.send_radio2_frame_and_wait(b"\xA1\xB2", timeout=0.5, verdict=verdict),
            )
        )
        thread.start()
        assert sent.wait(timeout=1.0)
        _feed(
            modem,
            bytes([KISS_FEND, KISS_CMD_SETHARDWARE, HW_RESP_TX_DONE, 0x00, KISS_FEND]),
        )
        thread.join(timeout=1.0)

        assert not thread.is_alive()
        assert requested_ports == [KISS_RADIO2_PORT]
        assert result["ok"] is False
        assert verdict == ["modem reported TX_DONE status=0x00"]
