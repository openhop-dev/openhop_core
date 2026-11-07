"""Tests for the companion's local CLI (firmware ``MyMesh::handleCommand``).

Covers ``openhop_core.companion.cli`` driven through a real companion, the
``CMD_RUN_CLI_COMMAND`` / ``CMD_SET_DEVICE_PIN`` frame handlers, and the remote
CLI path taken by a ``TXT_TYPE_CLI_COMMAND`` message from a contact flagged
``CONTACT_FLAG_REMOTE_CLI`` (firmware ``BaseChatMesh::onPeerDataRecv``).
"""

import asyncio
import dataclasses
import struct
from typing import Optional
from unittest.mock import AsyncMock, Mock, patch

import pytest

import openhop_core

from openhop_core.companion import CompanionBridge, CompanionRadio
from openhop_core.companion.cli import (
    MAX_CLI_REPLY_LEN,
    UNKNOWN_COMMAND,
    UNSUPPORTED,
    CompanionCLI,
    ftoa,
    ftoa3,
    is_valid_node_name,
)
from openhop_core.companion.constants import (
    CMD_DEVICE_QUERY,
    CMD_REBOOT,
    CMD_RUN_CLI_COMMAND,
    CMD_SEND_CHANNEL_DATA,
    CMD_SET_DEVICE_PIN,
    CMD_SET_RADIO_PARAMS,
    CMD_SET_RADIO_TX_POWER,
    CONTACT_FLAG_FAVOURITE,
    CONTACT_FLAG_REMOTE_CLI,
    CONTACT_FLAG_TELEM_BASE,
    CONTACT_FLAG_TELEM_ENV,
    CONTACT_FLAG_TELEM_LOC,
    ERR_CODE_ILLEGAL_ARG,
    ERR_CODE_UNSUPPORTED_CMD,
    FIRMWARE_VER_CODE,
    MAX_GROUP_DATA_LENGTH,
    RESP_CODE_CLI_REPLY,
    RESP_CODE_DEVICE_INFO,
    RESP_CODE_ERR,
    RESP_CODE_OK,
)
from openhop_core.companion.contact_store import ContactStore
from openhop_core.companion.frame_server import CompanionFrameServer
from openhop_core.companion.models import Contact, QueuedMessage
from openhop_core.node.events import MeshEvents
from openhop_core.protocol import CryptoUtils, Identity, LocalIdentity, Packet, PacketBuilder
from openhop_core.protocol.constants import TXT_TYPE_CLI_COMMAND, TXT_TYPE_CLI_DATA, TXT_TYPE_PLAIN

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class MockPacketInjector:
    """Records injected packets and returns True by default."""

    def __init__(self):
        self.calls: list[tuple] = []

    async def __call__(self, pkt, wait_for_ack: bool = False, expected_crc=None) -> bool:
        self.calls.append((pkt, wait_for_ack))
        return True


class MockRadio:
    """Radio backend for CompanionRadio that records what the CLI applied."""

    def __init__(self):
        self.rx_callback = None
        self.sent: list[bytes] = []
        self.radio_params: Optional[dict] = None
        self.tx_power: Optional[int] = None

    def set_rx_callback(self, callback):
        self.rx_callback = callback

    async def send(self, data: bytes) -> bool:
        self.sent.append(data)
        return True

    def configure_radio(self, **kwargs) -> bool:
        self.radio_params = kwargs
        return True

    def set_tx_power(self, power: int) -> bool:
        self.tx_power = power
        return True


def _make_bridge(node_name: str = "BridgeNode", radio_settings=None) -> CompanionBridge:
    """A real CompanionBridge, optionally reading its radio state from a host."""
    return CompanionBridge(
        LocalIdentity(),
        MockPacketInjector(),
        node_name=node_name,
        radio_settings_getter=(lambda: radio_settings) if radio_settings is not None else None,
    )


def _capture_server(bridge, **kwargs):
    """Frame server whose outbound frames (responses and errors) land in a list."""
    server = CompanionFrameServer(bridge, "hash", port=0, **kwargs)
    frames: list[bytes] = []
    server._write_frame = lambda f: frames.append(f)
    return server, frames


class _BridgeWithoutCli:
    """Bridge that predates the CLI: nothing for CMD_RUN_CLI_COMMAND to call."""

    def get_self_info(self):
        return None


def _firmware_ftoa(value: float) -> str:
    """Oracle for :func:`ftoa`, transcribed from ``StrHelper::ftoa``.

    MeshCore ``src/helpers/TxtDataHelpers.cpp:57-134``: float32 bits printed as
    up to 7 decimal digits, truncated (never rounded), trailing zeros dropped
    with at least one decimal kept.
    """
    raw = struct.unpack("<I", struct.pack("<f", value))[0]
    if (raw << 1) == 0:
        return "0.0"
    exp2 = ((raw >> 23) & 0xFF) - 127
    mantissa = (raw & 0xFFFFFF) | 0x800000
    if exp2 >= 23:
        int_part, frac_part = mantissa << (exp2 - 23), 0
    elif exp2 >= 0:
        int_part = mantissa >> (23 - exp2)
        frac_part = (mantissa << (exp2 + 1)) & 0xFFFFFF
    else:
        int_part, frac_part = 0, (mantissa & 0xFFFFFF) >> -(exp2 + 1)
    text = ("-" if raw & 0x80000000 else "") + (str(int_part) if int_part else "0") + "."
    if frac_part == 0:
        return text + "0"
    digits = []
    for _ in range(7):
        frac_part = (frac_part << 3) + (frac_part << 1)
        digits.append(chr((frac_part >> 24) + 0x30))
        frac_part &= 0xFFFFFF
    text += "".join(digits)
    while text[-1] == "0" and text[-2] != ".":
        text = text[:-1]
    return text


# ---------------------------------------------------------------------------
# Node name
# ---------------------------------------------------------------------------


class TestCompanionCLIName:
    def test_get_name_returns_advertised_name(self):
        assert _make_bridge(node_name="BridgeNode").cli.handle("get name") == "> BridgeNode"

    def test_set_name_stores_and_persists(self):
        bridge = _make_bridge()
        with patch.object(bridge, "_save_prefs") as save:
            assert bridge.cli.handle("set name Foo") == "OK"
        assert bridge.prefs.node_name == "Foo"
        assert bridge.get_self_info().node_name == "Foo"
        save.assert_called_once()

    @pytest.mark.parametrize("bad", ["[", "]", "\\", ":", ",", "?", "*"])
    def test_set_name_rejects_every_forbidden_char_and_keeps_the_old_name(self, bad):
        """Firmware ``AdvertDataParser::isValidName`` (AdvertDataHelpers.cpp:31)."""
        bridge = _make_bridge(node_name="Keep")
        assert bridge.cli.handle(f"set name a{bad}b") == "Error, bad chars"
        assert bridge.prefs.node_name == "Keep"
        assert is_valid_node_name(f"a{bad}b") is False
        assert is_valid_node_name("plain name 42-_.~") is True


# ---------------------------------------------------------------------------
# PIN
# ---------------------------------------------------------------------------


class TestCompanionCLIPin:
    def test_set_pin_six_digits_is_stored_and_persisted(self):
        bridge = _make_bridge()
        with patch.object(bridge, "_save_prefs") as save:
            assert bridge.cli.handle("set pin 123456") == "> pin is now 123456"
        assert bridge.prefs.ble_pin == 123456
        save.assert_called_once()

    def test_set_pin_zero_pads_to_six_digits(self):
        bridge = _make_bridge()
        assert bridge.cli.handle("set pin 42") == "> pin is now 000042"
        assert bridge.prefs.ble_pin == 42


# ---------------------------------------------------------------------------
# Time zone offset
# ---------------------------------------------------------------------------


class TestCompanionCLITimezone:
    def test_get_and_set_tz_offset(self):
        bridge = _make_bridge()
        assert bridge.cli.handle("get tz.offset") == "> 0"
        with patch.object(bridge, "_save_prefs") as save:
            assert bridge.cli.handle("set tz.offset -5") == "OK"
        assert bridge.prefs.tz_offset == -5
        assert bridge.cli.handle("get tz.offset") == "> -5"
        save.assert_called_once()

    @pytest.mark.parametrize("tz", ["15", "-13", "24"])
    def test_set_tz_offset_outside_minus_12_to_14_is_refused(self, tz):
        bridge = _make_bridge()
        assert bridge.cli.handle(f"set tz.offset {tz}") == "Error, must be from -12 to +14"
        assert bridge.prefs.tz_offset == 0


# ---------------------------------------------------------------------------
# board / ver
# ---------------------------------------------------------------------------


class TestCompanionCLIDeviceInfo:
    def test_board_reflects_set_device_info(self):
        cli = CompanionCLI(_make_bridge())
        cli.set_device_info("pyMC-Radio")
        assert cli.handle("board") == "pyMC-Radio"

    def test_ver_reports_the_openhop_core_version(self):
        """A companion is openHop software: `ver` names its versions, not the
        protocol level or a firmware build date."""
        assert _make_bridge().cli.handle("ver") == f"openHop core v{openhop_core.__version__}"

    def test_a_host_adds_its_own_version_ahead_of_the_core(self):
        cli = _make_bridge().cli
        cli.add_software_version("repeater", "1.0.11")
        assert cli.handle("ver") == f"openHop repeater v1.0.11, core v{openhop_core.__version__}"
        cli.add_software_version("repeater", "1.0.12")  # replaced, not duplicated
        assert cli.handle("ver") == f"openHop repeater v1.0.12, core v{openhop_core.__version__}"
        assert cli.handle("ab|ver").startswith("ab|openHop repeater v1.0.12")


# ---------------------------------------------------------------------------
# Tuning: airtime factor, duty cycle, rx delay, hash mode, multi-acks
# ---------------------------------------------------------------------------


class TestCompanionCLITuning:
    def test_get_af_reports_airtime_factor(self):
        assert _make_bridge().cli.handle("get af") == "> 1.0"

    def test_set_af_stores_the_factor(self):
        bridge = _make_bridge()
        with patch.object(bridge, "_save_prefs") as save:
            assert bridge.cli.handle("set af 2") == "OK"
        assert bridge.prefs.airtime_factor == 2.0
        assert bridge.cli.handle("get af") == "> 2.0"
        save.assert_called_once()

    @pytest.mark.parametrize("value", ["10", "9.5", "x"])
    def test_set_af_outside_0_to_9_is_refused(self, value):
        bridge = _make_bridge()
        assert bridge.cli.handle(f"set af {value}") == "ERROR: af must be 0-9"
        assert bridge.prefs.airtime_factor == 1.0

    def test_get_dutycycle_derives_from_airtime_factor(self):
        """Firmware: 100 / (airtime_factor + 1), one decimal (CommonRadioPrefs.cpp:81)."""
        assert _make_bridge().cli.handle("get dutycycle") == "> 50.0%"

    def test_set_dutycycle_rewrites_airtime_factor_and_echoes_the_actual(self):
        bridge = _make_bridge()
        with patch.object(bridge, "_save_prefs") as save:
            assert bridge.cli.handle("set dutycycle 25") == "OK - 25.0%"
        assert bridge.prefs.airtime_factor == 3.0
        assert bridge.cli.handle("get dutycycle") == "> 25.0%"
        save.assert_called_once()

    @pytest.mark.parametrize("value", ["0", "0.5", "101"])
    def test_set_dutycycle_outside_1_to_100_is_refused(self, value):
        bridge = _make_bridge()
        assert bridge.cli.handle(f"set dutycycle {value}") == "ERROR: dutycycle must be 1-100"
        assert bridge.prefs.airtime_factor == 1.0

    def test_get_and_set_rxdelay(self):
        bridge = _make_bridge()
        assert bridge.cli.handle("get rxdelay") == "> 0.0"
        with patch.object(bridge, "_save_prefs") as save:
            assert bridge.cli.handle("set rxdelay 5") == "OK"
        assert bridge.prefs.rx_delay_base == 5.0
        assert bridge.cli.handle("get rxdelay") == "> 5.0"
        save.assert_called_once()

    def test_set_rxdelay_outside_0_to_20_is_refused(self):
        bridge = _make_bridge()
        assert bridge.cli.handle("set rxdelay 21") == "Error, must be 0-20"
        assert bridge.prefs.rx_delay_base == 0.0

    def test_get_and_set_path_hash_mode(self):
        bridge = _make_bridge()
        assert bridge.cli.handle("get path.hash.mode") == "> 0"
        with patch.object(bridge, "_save_prefs") as save:
            assert bridge.cli.handle("set path.hash.mode 1") == "OK"
        assert bridge.prefs.path_hash_mode == 1
        assert bridge.cli.handle("get path.hash.mode") == "> 1"
        save.assert_called_once()

    def test_set_path_hash_mode_3_is_refused(self):
        bridge = _make_bridge()
        assert bridge.cli.handle("set path.hash.mode 3") == "Error, must be 0,1, or 2"
        assert bridge.prefs.path_hash_mode == 0

    def test_set_multi_acks_keeps_the_rest_of_other_params(self):
        """Firmware stores every other-param byte, so the CLI must not zero them."""
        bridge = _make_bridge()
        bridge.set_other_params(
            manual_add=1,
            telemetry_modes=1 | (2 << 2) | (3 << 4),
            advert_loc_policy=1,
            multi_acks=0,
        )
        with patch.object(bridge, "_save_prefs") as save:
            assert bridge.cli.handle("get multi.acks") == "> 0"
            assert bridge.cli.handle("set multi.acks 1") == "OK"
        assert bridge.prefs.multi_acks == 1
        assert bridge.prefs.manual_add_contacts == 1
        assert bridge.prefs.telemetry_mode_base == 1
        assert bridge.prefs.telemetry_mode_location == 2
        assert bridge.prefs.telemetry_mode_environment == 3
        assert bridge.prefs.advert_loc_policy == 1
        assert bridge.cli.handle("get multi.acks") == "> 1"
        save.assert_called_once()


# ---------------------------------------------------------------------------
# Radio settings
# ---------------------------------------------------------------------------

_HOST_RADIO = {
    "frequency": 869618000,
    "bandwidth": 62500,
    "spreading_factor": 8,
    "coding_rate": 5,
}


class TestCompanionCLIRadio:
    def test_get_radio_prints_freq_mhz_bandwidth_khz_sf_cr(self):
        """``> freq,bw,sf,cr``, MHz and kHz via firmware's ftoa / ftoa3."""
        bridge = _make_bridge(radio_settings=_HOST_RADIO)
        assert bridge.cli.handle("get radio") == "> 869.6179809,62.5,8,5"
        assert bridge.cli.handle("get freq") == "> 869.6179809"

    def test_get_radio_frequency_uses_ftoa_truncation(self):
        """869.618 MHz as float32 is 869.6179809570312, truncated at 7 decimals."""
        assert _firmware_ftoa(869618000 / 1e6) == "869.6179809"
        bridge = _make_bridge(radio_settings=_HOST_RADIO)
        assert bridge.cli.handle("get radio") == f"> {_firmware_ftoa(869.618)},62.5,8,5"

    def test_get_tx_reports_current_tx_power(self):
        assert _make_bridge().cli.handle("get tx") == "> 20"

    def test_set_radio_is_refused_by_a_bridge_that_does_not_own_the_radio(self):
        bridge = _make_bridge()
        with patch.object(bridge, "set_radio_params") as apply:
            assert bridge.cli.handle("set radio 869.618,62.5,8,5") == UNSUPPORTED
        apply.assert_not_called()

    def test_set_tx_is_refused_by_a_bridge_that_does_not_own_the_radio(self):
        bridge = _make_bridge()
        with patch.object(bridge, "set_tx_power") as apply:
            assert bridge.cli.handle("set tx 10") == UNSUPPORTED
        apply.assert_not_called()

    def test_invalid_radio_params_are_reported_before_the_ownership_check(self):
        """Firmware validates the ranges first, so the reply is never "unsupported"."""
        bridge = _make_bridge()
        with patch.object(bridge, "supports_radio_params_mutation", return_value=False):
            assert bridge.cli.handle("set radio 100,62.5,8,5") == "Error, invalid radio params"

    @pytest.mark.parametrize(
        "key",
        ["int.thresh", "cad", "radio.rxgain", "agc.reset.interval", "txdelay", "direct.txdelay"],
    )
    def test_radio_keys_openhop_cannot_apply_answer_unsupported(self, key):
        """Firmware's own wording for an unsupported rxgain (CommonRadioPrefs.cpp:132)."""
        cli = _make_bridge().cli
        assert cli.handle(f"get {key}") == UNSUPPORTED
        assert cli.handle(f"set {key} 1") == UNSUPPORTED


class TestCompanionRadioOwnedRadio:
    def test_set_radio_is_stored_but_not_applied_live(self):
        """Firmware's CLI only stores the values ("OK - reboot to apply",
        CommonRadioPrefs.cpp); retuning live could strand the remote peer that
        sent the command."""
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity(), node_name="RadioNode")
        before = getattr(radio, "radio_params", None)

        with patch.object(comp, "_save_prefs") as save:
            assert comp.cli.handle("set radio 869.618,62.5,8,5") == "OK - reboot to apply"
        save.assert_called()
        assert getattr(radio, "radio_params", None) == before
        prefs = comp.get_self_info()
        assert (prefs.frequency_hz, prefs.bandwidth_hz) == (869618000, 62500)
        assert (prefs.spreading_factor, prefs.coding_rate) == (8, 5)
        assert comp.cli.handle("get radio") == f"> {_firmware_ftoa(869.618)},62.5,8,5"

    def test_staged_radio_params_are_applied_when_the_companion_starts(self):
        """Firmware brings the radio up on its stored prefs at boot, which is
        what makes "reboot to apply" true."""
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        comp.cli.handle("set radio 869.618,62.5,8,5")
        assert radio.radio_params is None

        comp._apply_staged_radio_params()
        assert radio.radio_params == {
            "frequency": 869618000,
            "bandwidth": 62500,
            "spreading_factor": 8,
            "coding_rate": 5,
        }
        radio.radio_params = None
        comp._apply_staged_radio_params()  # already live: nothing to do
        assert radio.radio_params is None

    def test_start_without_staged_params_leaves_the_radio_alone(self):
        """No radio_config at all: the seed defaults must never be pushed."""
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        comp._apply_staged_radio_params()
        assert radio.radio_params is None

    def test_params_applied_live_are_not_reapplied_on_start(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        assert comp.set_radio_params(869618000, 62500, 8, 5)
        radio.radio_params = None
        comp._apply_staged_radio_params()
        assert radio.radio_params is None

    @pytest.mark.asyncio
    async def test_start_applies_staged_params(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        comp.cli.handle("set radio 869.618,62.5,8,5")
        with patch.object(comp, "_apply_staged_radio_params") as apply, patch.object(
            comp.node, "start", AsyncMock()
        ):
            try:
                await comp.start()
            finally:
                await comp.stop()
        apply.assert_called_once()

    def test_set_tx_is_applied_to_the_owned_backend(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())

        assert comp.cli.handle("set tx 10") == "OK"
        assert radio.tx_power == 10
        assert comp.get_self_info().tx_power_dbm == 10
        assert comp.cli.handle("get tx") == "> 10"


# ---------------------------------------------------------------------------
# Power commands, unknown commands, prefix reflection
# ---------------------------------------------------------------------------


class TestCompanionCLIMisc:
    @pytest.mark.parametrize("command", ["poweroff", "shutdown"])
    def test_power_commands_need_a_host_that_can_perform_them(self, command):
        assert _make_bridge().cli.handle(command) == UNSUPPORTED

    @pytest.mark.parametrize("command", ["bogus", "get nosuch", "set nosuch 1", ""])
    def test_unknown_commands(self, command):
        assert _make_bridge().cli.handle(command) == UNKNOWN_COMMAND

    def test_two_character_prefix_is_reflected_before_the_reply(self):
        cli = _make_bridge(node_name="N").cli
        assert cli.handle("ab|get name") == "ab|> N"
        assert cli.handle("ab|bogus") == "ab|Unknown command"
        assert cli.handle("ab|poweroff") == "ab|Error: unsupported"

    def test_leading_spaces_are_stripped(self):
        assert _make_bridge(node_name="N").cli.handle("   get name") == "> N"


# ---------------------------------------------------------------------------
# Host hook
# ---------------------------------------------------------------------------


class TestCompanionCLICommandHook:
    def test_hook_answers_a_built_in(self):
        """Firmware consults ``board.handleCommand`` before its own power commands."""
        bridge = _make_bridge()
        bridge.cli_command_hook = lambda command, sender_timestamp: "host rebooted"
        assert bridge.cli.handle("reboot") == "host rebooted"

    def test_hook_answers_an_unknown_command_and_receives_the_arguments(self):
        bridge = _make_bridge()
        seen = []

        def hook(command, sender_timestamp):
            seen.append((command, sender_timestamp))
            return "> host value" if command == "get host.thing" else None

        bridge.cli_command_hook = hook
        assert bridge.cli.handle("get host.thing", 1700000000) == "> host value"
        assert seen == [("get host.thing", 1700000000)]

    def test_hook_returning_none_falls_through_to_the_built_ins(self):
        bridge = _make_bridge(node_name="N")
        bridge.cli_command_hook = lambda command, sender_timestamp: None
        assert bridge.cli.handle("get name") == "> N"
        assert bridge.cli.handle("bogus") == UNKNOWN_COMMAND

    def test_radio_commands_are_answered_before_the_hook(self):
        bridge = _make_bridge()
        bridge.cli_command_hook = Mock(return_value="hook answer")
        assert bridge.cli.handle("get af") == "> 1.0"
        bridge.cli_command_hook.assert_not_called()

    def test_hook_reply_keeps_the_reflected_prefix(self):
        bridge = _make_bridge()
        bridge.cli_command_hook = lambda command, sender_timestamp: "> 42"
        assert bridge.cli.handle("xy|get host.thing") == "xy|> 42"

    def test_reply_is_capped_at_the_firmware_reply_buffer(self):
        """Firmware ``reply_buf[166]``: 165 reply bytes plus the terminator."""
        bridge = _make_bridge()
        bridge.cli_command_hook = lambda command, sender_timestamp: "A" * 400
        reply = bridge.cli.handle("get host.thing")
        assert reply == "A" * MAX_CLI_REPLY_LEN
        assert len(reply.encode("utf-8")) == MAX_CLI_REPLY_LEN

    def test_cap_never_splits_a_multi_byte_code_point(self):
        bridge = _make_bridge()
        bridge.cli_command_hook = lambda command, sender_timestamp: "é" * 200
        reply = bridge.cli.handle("get host.thing")
        assert reply == "é" * 82
        assert len(reply.encode("utf-8")) <= MAX_CLI_REPLY_LEN


# ---------------------------------------------------------------------------
# ftoa / ftoa3 (firmware StrHelper)
# ---------------------------------------------------------------------------


class TestCompanionCLIFloatFormatting:
    @pytest.mark.parametrize(
        ("value", "text"),
        [
            (0.0, "0.0"),
            (1.0, "1.0"),
            (2.0, "2.0"),
            (10.0, "10.0"),
            (20.0, "20.0"),
            (0.5, "0.5"),
            (0.25, "0.25"),
            (0.1, "0.0999999"),
            (0.3, "0.3"),
            (-3.25, "-3.25"),
            (915.0, "915.0"),
        ],
    )
    def test_ftoa(self, value, text):
        assert ftoa(value) == text

    @pytest.mark.parametrize(
        ("value", "text"),
        [(62.5, "62.5"), (125.0, "125"), (7.8, "7.8"), (250.0, "250"), (0.125, "0.125")],
    )
    def test_ftoa3(self, value, text):
        assert ftoa3(value) == text

    @pytest.mark.parametrize(
        "value",
        [869.618, 915.0, 62.5, 250.0, 1.0, 0.5, 0.25, 0.1, 0.2, 0.3, 0.75, 1.3, 9.0, -0.6],
    )
    def test_ftoa_matches_the_firmware_bit_algorithm(self, value):
        # Includes values below 1: firmware's exp2 < 0 branch shifts the
        # fraction right and drops low bits (TxtDataHelpers.cpp:90-92), so
        # ftoa(0.1) prints "0.0999999" there, and must here too.
        assert ftoa(value) == _firmware_ftoa(value)


# ---------------------------------------------------------------------------
# CMD_RUN_CLI_COMMAND
# ---------------------------------------------------------------------------


class TestFrameServerRunCLICommand:
    def test_handler_is_registered_for_cmd_66(self):
        server, _ = _capture_server(_make_bridge())
        assert server._cmd_handlers[CMD_RUN_CLI_COMMAND] == server._cmd_run_cli_command

    @pytest.mark.asyncio
    async def test_run_cli_command_answers_with_a_cli_reply_frame(self):
        bridge = _make_bridge(node_name="name")
        server, frames = _capture_server(bridge)

        await server._handle_cmd(bytes([CMD_RUN_CLI_COMMAND]) + b"get name")

        assert frames == [bytes([RESP_CODE_CLI_REPLY]) + b"> name"]

    @pytest.mark.asyncio
    async def test_unknown_command_is_a_reply_not_an_err_frame(self):
        server, frames = _capture_server(_make_bridge())

        await server._handle_cmd(bytes([CMD_RUN_CLI_COMMAND]) + b"bogus")

        assert frames == [bytes([RESP_CODE_CLI_REPLY]) + b"Unknown command"]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("data", [b"", b"x"])
    async def test_payload_shorter_than_two_bytes_is_unsupported(self, data):
        """Firmware needs frame len >= 3 (MyMesh.cpp:1105), so the branch is skipped."""
        server, frames = _capture_server(_make_bridge())

        await server._handle_cmd(bytes([CMD_RUN_CLI_COMMAND]) + data)

        assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_UNSUPPORTED_CMD])]

    @pytest.mark.asyncio
    async def test_command_ends_at_the_first_nul(self):
        """Firmware reads the text as a C string (MyMesh.cpp:1110)."""
        bridge = _make_bridge(node_name="name")
        server, frames = _capture_server(bridge)

        await server._handle_cmd(bytes([CMD_RUN_CLI_COMMAND]) + b"get name\x00junk")

        assert frames == [bytes([RESP_CODE_CLI_REPLY]) + b"> name"]

    @pytest.mark.asyncio
    async def test_bridge_without_a_cli_is_unsupported(self):
        server, frames = _capture_server(_BridgeWithoutCli())

        await server._handle_cmd(bytes([CMD_RUN_CLI_COMMAND]) + b"get name")

        assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_UNSUPPORTED_CMD])]

    @pytest.mark.asyncio
    async def test_prefix_is_reflected_by_the_frame_handler(self):
        bridge = _make_bridge(node_name="name")
        server, frames = _capture_server(bridge)

        await server._handle_cmd(bytes([CMD_RUN_CLI_COMMAND]) + b"ab|get name")

        assert frames == [bytes([RESP_CODE_CLI_REPLY]) + b"ab|> name"]

    @pytest.mark.asyncio
    async def test_constructor_feeds_its_device_info_to_the_cli(self):
        """`board` must answer what DEVICE_INFO reports; `ver` keeps naming the
        openHop versions, not DEVICE_INFO's protocol-level string."""
        bridge = _make_bridge()
        _capture_server(bridge, device_model="pyMC-Unit", build_date="2026-09-25")

        assert bridge.cli.handle("board") == "pyMC-Unit"
        assert bridge.cli.handle("ver") == f"openHop core v{openhop_core.__version__}"

    @pytest.mark.asyncio
    async def test_cli_device_info_is_truncated_like_device_info(self):
        """DEVICE_INFO carries a 40-byte model; the CLI must not report a
        longer name than the app was sent."""
        bridge = _make_bridge()
        _capture_server(bridge, device_model="M" * 50)

        assert bridge.cli.handle("board") == "M" * 40


# ---------------------------------------------------------------------------
# CMD_SET_DEVICE_PIN and DEVICE_INFO
# ---------------------------------------------------------------------------


class TestFrameServerDevicePin:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("pin", [0, 100000, 123456, 999999])
    async def test_zero_or_six_digit_pin_is_stored(self, pin):
        bridge = _make_bridge()
        server, frames = _capture_server(bridge)

        await server._handle_cmd(bytes([CMD_SET_DEVICE_PIN]) + struct.pack("<I", pin))

        assert frames == [bytes([RESP_CODE_OK])]
        assert bridge.prefs.ble_pin == pin

    @pytest.mark.asyncio
    @pytest.mark.parametrize("pin", [1, 99999, 1000000, 0xFFFFFFFF])
    async def test_any_other_pin_is_illegal(self, pin):
        bridge = _make_bridge()
        server, frames = _capture_server(bridge)

        await server._handle_cmd(bytes([CMD_SET_DEVICE_PIN]) + struct.pack("<I", pin))

        assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_ILLEGAL_ARG])]
        assert bridge.prefs.ble_pin == 0

    @pytest.mark.asyncio
    @pytest.mark.parametrize("data", [b"", b"\x01", b"\x01\x02\x03"])
    async def test_short_pin_frame_is_unsupported(self, data):
        """Firmware requires frame len >= 5 (MyMesh.cpp:1826)."""
        bridge = _make_bridge()
        server, frames = _capture_server(bridge)

        await server._handle_cmd(bytes([CMD_SET_DEVICE_PIN]) + data)

        assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_UNSUPPORTED_CMD])]
        assert bridge.prefs.ble_pin == 0

    @pytest.mark.asyncio
    async def test_device_info_reports_the_stored_pin_and_ver_code(self):
        """DEVICE_INFO bytes 4..7 are ``_prefs.ble_pin`` (MyMesh.cpp:1051)."""
        bridge = _make_bridge()
        server, frames = _capture_server(bridge)
        await server._handle_cmd(bytes([CMD_SET_DEVICE_PIN]) + struct.pack("<I", 123456))

        await server._handle_cmd(bytes([CMD_DEVICE_QUERY]) + bytes([0]))

        info = frames[-1]
        assert info[0] == RESP_CODE_DEVICE_INFO
        assert info[1] == FIRMWARE_VER_CODE == 14
        assert info[4:8] == struct.pack("<I", 123456)

    @pytest.mark.asyncio
    async def test_device_info_reports_zero_pin_when_none_is_set(self):
        server, frames = _capture_server(_make_bridge())

        await server._handle_cmd(bytes([CMD_DEVICE_QUERY]) + bytes([0]))

        assert frames[-1][4:8] == struct.pack("<I", 0)

    @pytest.mark.asyncio
    async def test_pin_set_through_the_cli_is_reported_by_device_info(self):
        bridge = _make_bridge()
        server, frames = _capture_server(bridge)
        assert bridge.cli.handle("set pin 654321") == "> pin is now 654321"

        await server._handle_cmd(bytes([CMD_DEVICE_QUERY]) + bytes([0]))

        assert frames[-1][4:8] == struct.pack("<I", 654321)


# ---------------------------------------------------------------------------
# Remote CLI (TXT_TYPE_CLI_COMMAND from a flagged contact)
# ---------------------------------------------------------------------------


def _cli_command_event(peer: LocalIdentity, text: str = "get name", **overrides) -> dict:
    data = {
        "contact_pubkey": peer.get_public_key().hex(),
        "message_text": text,
        "txt_type": TXT_TYPE_CLI_COMMAND,
        "timestamp": 1700000000,
        "packet_hash": "AABBCCDD",
        "path_len": 0xFF,
        "network_info": {"snr": 5.0, "rssi": -70},
    }
    data.update(overrides)
    return data


class _NoDelay:
    """Record the CLI reply delay without actually waiting for it."""

    def __init__(self):
        self.delays: list[float] = []
        self._real_sleep = asyncio.sleep

    async def sleep(self, delay, *args, **kwargs):
        self.delays.append(delay)
        await self._real_sleep(0)

    def __enter__(self):
        self._patcher = patch("openhop_core.companion.base_events.asyncio.sleep", self.sleep)
        self._patcher.start()
        return self

    def __exit__(self, *exc):
        self._patcher.stop()
        return False


async def _drain_background_tasks(bridge: CompanionBridge) -> None:
    for task in list(bridge._background_tasks):
        await task


def _decrypt_txt_msg(bridge: CompanionBridge, peer: LocalIdentity, packet: Packet) -> bytes:
    secret = Identity(peer.get_public_key()).calc_shared_secret(bridge._identity.get_private_key())
    return CryptoUtils.mac_then_decrypt(secret[:16], secret, bytes(packet.payload[2:]))


def _bridge_with_cli_contact(injector, flags: int) -> tuple:
    bridge = CompanionBridge(LocalIdentity(), injector, node_name="name")
    peer = LocalIdentity()
    bridge.contacts.add(Contact(public_key=peer.get_public_key(), flags=flags))
    return bridge, peer


class TestRemoteCLI:
    @pytest.mark.asyncio
    async def test_flagged_contact_command_is_answered_not_queued(self):
        injector = MockPacketInjector()
        bridge, peer = _bridge_with_cli_contact(injector, CONTACT_FLAG_REMOTE_CLI)
        events = []
        bridge.on_message_event(events.append)

        with _NoDelay() as delay:
            await bridge._handle_mesh_event(MeshEvents.NEW_MESSAGE, _cli_command_event(peer))
            assert bridge.message_queue.count == 0
            assert events == []
            await _drain_background_tasks(bridge)

        # Firmware CLI_REPLY_DELAY_MILLIS (BaseChatMesh.cpp:283).
        assert delay.delays == [0.6]
        assert len(injector.calls) == 1
        plaintext = _decrypt_txt_msg(bridge, peer, injector.calls[0][0])
        assert (plaintext[4] >> 2) & 0x3F == TXT_TYPE_CLI_DATA
        assert plaintext[5:].rstrip(b"\x00") == b"> name"

    @pytest.mark.asyncio
    async def test_reply_is_sent_with_the_firmware_send_parameters(self):
        bridge, peer = _bridge_with_cli_contact(MockPacketInjector(), CONTACT_FLAG_REMOTE_CLI)
        bridge.send_text_message = AsyncMock()

        with _NoDelay(), patch(
            "openhop_core.protocol.PacketBuilder._get_timestamp", return_value=1700000500
        ):
            await bridge._handle_mesh_event(
                MeshEvents.NEW_MESSAGE, _cli_command_event(peer, timestamp=1700000000)
            )
            await _drain_background_tasks(bridge)

        bridge.send_text_message.assert_awaited_once_with(
            peer.get_public_key(),
            "> name",
            txt_type=TXT_TYPE_CLI_DATA,
            attempt=0,
            wait_for_ack=False,
            timestamp=1700000500,
        )

    @pytest.mark.asyncio
    async def test_reply_timestamp_is_bumped_past_the_sender_timestamp(self):
        """Firmware: the two timestamps must differ in the app's CLI view."""
        bridge, peer = _bridge_with_cli_contact(MockPacketInjector(), CONTACT_FLAG_REMOTE_CLI)
        bridge.send_text_message = AsyncMock()

        # The real unique clock, pinned so its next second equals the sender's.
        saved = PacketBuilder._last_unique_timestamp
        PacketBuilder._last_unique_timestamp = 0
        try:
            with _NoDelay(), patch(
                "openhop_core.protocol.packet_builder.time.time", return_value=1700000000.0
            ):
                await bridge._handle_mesh_event(
                    MeshEvents.NEW_MESSAGE, _cli_command_event(peer, timestamp=1700000000)
                )
                await _drain_background_tasks(bridge)
                # The bumped second was taken from the clock, so it is not reissued.
                next_stamp = PacketBuilder._get_timestamp()
        finally:
            PacketBuilder._last_unique_timestamp = max(saved, PacketBuilder._last_unique_timestamp)

        assert bridge.send_text_message.await_args.kwargs["timestamp"] == 1700000001
        assert next_stamp == 1700000002

    @pytest.mark.asyncio
    async def test_a_command_handled_after_stop_is_neither_run_nor_answered(self):
        """A receive event already queued when stop() runs must not transmit."""
        injector = MockPacketInjector()
        bridge, peer = _bridge_with_cli_contact(injector, CONTACT_FLAG_REMOTE_CLI)
        await bridge.stop()

        with _NoDelay(), patch.object(bridge, "run_cli_command") as run:
            await bridge._handle_mesh_event(MeshEvents.NEW_MESSAGE, _cli_command_event(peer))
            await _drain_background_tasks(bridge)

        run.assert_not_called()
        assert injector.calls == []
        assert bridge.message_queue.count == 0

    @pytest.mark.asyncio
    async def test_start_after_stop_answers_again(self):
        injector = MockPacketInjector()
        bridge, peer = _bridge_with_cli_contact(injector, CONTACT_FLAG_REMOTE_CLI)
        await bridge.stop()
        await bridge.start()

        with _NoDelay():
            await bridge._handle_mesh_event(MeshEvents.NEW_MESSAGE, _cli_command_event(peer))
            await _drain_background_tasks(bridge)

        assert len(injector.calls) == 1

    @pytest.mark.asyncio
    async def test_stop_cancels_a_reply_still_waiting_out_its_delay(self):
        injector = MockPacketInjector()
        bridge, peer = _bridge_with_cli_contact(injector, CONTACT_FLAG_REMOTE_CLI)

        await bridge._handle_mesh_event(MeshEvents.NEW_MESSAGE, _cli_command_event(peer))
        (task,) = bridge._remote_cli_replies
        await bridge.stop()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert injector.calls == []
        assert bridge._remote_cli_replies == set()

    @pytest.mark.asyncio
    async def test_contact_without_the_flag_is_queued_and_unanswered(self):
        injector = MockPacketInjector()
        bridge, peer = _bridge_with_cli_contact(injector, CONTACT_FLAG_TELEM_BASE)

        with _NoDelay():
            await bridge._handle_mesh_event(MeshEvents.NEW_MESSAGE, _cli_command_event(peer))
            await _drain_background_tasks(bridge)

        assert bridge.message_queue.count == 1
        assert bridge.message_queue.peek().txt_type == TXT_TYPE_CLI_COMMAND
        assert injector.calls == []

    @pytest.mark.asyncio
    async def test_command_from_an_unknown_sender_is_queued_and_unanswered(self):
        injector = MockPacketInjector()
        bridge = CompanionBridge(LocalIdentity(), injector, node_name="name")
        peer = LocalIdentity()

        with _NoDelay():
            await bridge._handle_mesh_event(MeshEvents.NEW_MESSAGE, _cli_command_event(peer))
            await _drain_background_tasks(bridge)

        assert bridge.message_queue.count == 1
        assert injector.calls == []

    @pytest.mark.asyncio
    async def test_flag_does_not_change_plain_text_handling(self):
        injector = MockPacketInjector()
        bridge, peer = _bridge_with_cli_contact(injector, CONTACT_FLAG_REMOTE_CLI)

        with _NoDelay():
            await bridge._handle_mesh_event(
                MeshEvents.NEW_MESSAGE,
                _cli_command_event(peer, "hello", txt_type=TXT_TYPE_PLAIN),
            )
            await _drain_background_tasks(bridge)

        queued = bridge.message_queue.peek()
        assert queued.txt_type == TXT_TYPE_PLAIN
        assert queued.text == "hello"
        assert injector.calls == []

    @pytest.mark.asyncio
    async def test_duplicate_packet_hash_runs_the_cli_once(self):
        bridge, peer = _bridge_with_cli_contact(MockPacketInjector(), CONTACT_FLAG_REMOTE_CLI)
        runs: list[str] = []
        bridge.cli_command_hook = lambda command, sender_timestamp: runs.append(command) or "> ok"
        bridge.send_text_message = AsyncMock()

        with _NoDelay():
            for _ in range(3):
                await bridge._handle_mesh_event(MeshEvents.NEW_MESSAGE, _cli_command_event(peer))
            await _drain_background_tasks(bridge)

        assert runs == ["get name"]
        assert bridge.send_text_message.await_count == 1


# ---------------------------------------------------------------------------
# Contact flag accessors
# ---------------------------------------------------------------------------


class TestContactFlags:
    @pytest.mark.parametrize(
        ("bit", "attribute"),
        [
            (CONTACT_FLAG_FAVOURITE, "is_favourite"),
            (CONTACT_FLAG_TELEM_BASE, "is_telem_base_allowed"),
            (CONTACT_FLAG_TELEM_LOC, "is_telem_loc_allowed"),
            (CONTACT_FLAG_TELEM_ENV, "is_telem_env_allowed"),
            (CONTACT_FLAG_REMOTE_CLI, "is_remote_cli_allowed"),
        ],
    )
    def test_each_bit_drives_only_its_own_property(self, bit, attribute):
        contact = Contact(public_key=b"\x01" * 32, flags=0)
        assert getattr(contact, attribute) is False
        for other in (1, 2, 4, 8, 16):
            contact.flags = other
            assert getattr(contact, attribute) is (other == bit)
        contact.flags = 0xFF
        assert getattr(contact, attribute) is True

    def test_fresh_contact_is_not_a_favourite(self):
        assert Contact(public_key=b"\x01" * 32).is_favourite is False


class TestContactStoreEviction:
    def test_eviction_skips_favourites(self):
        store = ContactStore(max_contacts=2)
        store.add(
            Contact(public_key=b"\x01" * 32, name="Old", adv_type=1, flags=0x01, lastmod=1)
        )
        store.add(Contact(public_key=b"\x02" * 32, name="Newer", adv_type=1, lastmod=9))

        ok, overwritten = store.add_or_overwrite(
            Contact(public_key=b"\x03" * 32, name="C", adv_type=1, lastmod=50)
        )

        assert (ok, overwritten) == (True, b"\x02" * 32)
        assert store.get_by_name("Old") is not None

    def test_a_full_store_of_favourites_refuses_the_new_contact(self):
        store = ContactStore(max_contacts=2)
        store.add(Contact(public_key=b"\x01" * 32, name="A", adv_type=1, flags=0x01, lastmod=1))
        store.add(
            Contact(public_key=b"\x02" * 32, name="B", adv_type=1, flags=0x11, lastmod=2)
        )

        assert store.add_or_overwrite(
            Contact(public_key=b"\x03" * 32, name="C", adv_type=1, lastmod=50)
        ) == (False, None)


# ---------------------------------------------------------------------------
# Channel data bound (F5)
# ---------------------------------------------------------------------------


class _ChannelDataBridge:
    """Minimal bridge for CMD_SEND_CHANNEL_DATA."""

    def get_channel(self, idx: int):
        return object() if idx == 1 else None

    async def send_channel_data(
        self, channel_idx, data_type, payload, *, path=None, path_len_encoded=None
    ):
        return True


class TestChannelDataBound:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("length", "accepted"),
        [(MAX_GROUP_DATA_LENGTH, True), (MAX_GROUP_DATA_LENGTH + 1, False)],
    )
    async def test_payload_bound_is_165_bytes(self, length, accepted):
        """Firmware ``MAX_GROUP_DATA_LENGTH`` is 165, not the 167 the docs claim."""
        assert MAX_GROUP_DATA_LENGTH == 165
        server, frames = _capture_server(_ChannelDataBridge())
        # channel 1, 0xFF (unknown path -> flood), data type 1, then the payload.
        data = bytes([1, 0xFF]) + (1).to_bytes(2, "little") + b"\xaa" * length

        await server._handle_cmd(bytes([CMD_SEND_CHANNEL_DATA]) + data)

        accepted_frame = bytes([RESP_CODE_OK])
        rejected_frame = bytes([RESP_CODE_ERR, ERR_CODE_ILLEGAL_ARG])
        assert frames == [accepted_frame if accepted else rejected_frame]


# ===========================================================================
# Audit follow-up: the firmware rows the audit listed as UNTESTED, the float32
# duty-cycle chain, strtof/atoi coercion, radio staging, and remote-CLI routing.
#
# Every expectation below is derived from the MeshCore sources in
# /Users/adam/MeshCore -- CommonRadioPrefs.cpp, MyMesh.cpp, BaseChatMesh.cpp,
# TxtDataHelpers.cpp, Utils.cpp, NodePrefs.h -- and not from openhop's own
# output. Arithmetic that C performs in float32 is transcribed operation by
# operation with a binary32 round-trip after each step (``_f32``); the duty-cycle
# transcription was additionally cross-checked against a compiled transcription
# of CommonRadioPrefs.cpp:81-99. The C string conversions are cross-checked
# against the host libc (``_c_strtof`` / ``_c_atoi``), which import ctypes inside
# the function so this appended section need not touch the file's import block.
# ===========================================================================


def _f32(value: float) -> float:
    """One IEEE-754 binary32 round-trip: what an assignment to C ``float`` does."""
    return struct.unpack("<f", struct.pack("<f", value))[0]


def _load_libc():
    """The host C library, for the strtof/atoi oracles; None when unreachable."""
    import ctypes

    try:
        libc = ctypes.CDLL(None)
        libc.strtof.restype = ctypes.c_float
        libc.strtof.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        libc.atoi.restype = ctypes.c_int
        libc.atoi.argtypes = [ctypes.c_char_p]
    except (AttributeError, OSError):
        return None
    return libc


_LIBC = _load_libc()

requires_libc = pytest.mark.skipif(_LIBC is None, reason="host libc exposes no strtof/atoi")


def _c_strtof(text: str) -> float:
    """C ``strtof``: skip whitespace, take the longest valid float prefix.

    The return type is ``float``, so this is the binary32 result -- the same
    conversion the firmware's ``strtof`` performs before it stores a value in
    a ``float`` preference.
    """
    return _LIBC.strtof(text.encode(), None)


def _c_atoi(text: str) -> int:
    """C ``atoi``: ``strtol`` base 10 truncated to ``int``, 0 when nothing parses."""
    return _LIBC.atoi(text.encode())


def _firmware_dutycycle_text(airtime_factor: float) -> str:
    """``get dutycycle`` as firmware prints it (CommonRadioPrefs.cpp:81-86).

    ``float dc = 100.0f / (af + 1.0f)`` then ``> %d.%d%%`` with the fraction
    rounded by ``(int)((dc - dc_int) * 10.0f + 0.5f)``. Every step is float32,
    which is what makes 45 come back as "44.10%".
    """
    dc = _f32(100.0 / _f32(_f32(airtime_factor) + 1.0))
    whole = int(dc)
    tenths = int(_f32(_f32(_f32(dc - whole) * 10.0) + 0.5))
    return f"{whole}.{tenths}%"


def _firmware_set_dutycycle(dc: float) -> tuple:
    """``set dutycycle`` as firmware runs it (CommonRadioPrefs.cpp:88-99).

    Takes the ``atof`` result (a double) and returns ``(reply, stored airtime
    factor)``; the ``float dc`` assignment is the first ``_f32``. Note the gate
    is ``dc < 1 || dc > 100`` only -- a NaN passes it, which is exactly what
    openhop adds a check for.
    """
    dc = _f32(dc)
    if dc < 1 or dc > 100:
        return "ERROR: dutycycle must be 1-100", None
    airtime_factor = _f32(_f32(100.0 / dc) - 1.0)
    return f"OK - {_firmware_dutycycle_text(airtime_factor)}", airtime_factor


def _scope_transport_code(key: bytes, pkt) -> int:
    """``TransportKey::calcTransportCode(pkt)`` as openhop computes it.

    MyMesh::sendFloodScoped (MyMesh.cpp:496) sets ``codes[0]`` from the scope
    key and ``codes[1] = 0``; protocol/transport_keys.py is the single place
    openhop derives the code from the packet.
    """
    from openhop_core.protocol.transport_keys import calc_transport_code

    return calc_transport_code(key, pkt)


def _radio_owned_companion() -> CompanionRadio:
    """A companion that owns its radio, so ``set radio``/``set tx`` are allowed."""
    return CompanionRadio(MockRadio(), LocalIdentity(), node_name="RadioNode")


def _bridge_with_cli_path(injector, out_path: bytes, out_path_len: int) -> tuple:
    """Bridge plus a remote-CLI contact with an explicit stored out_path."""
    bridge = CompanionBridge(LocalIdentity(), injector, node_name="name")
    peer = LocalIdentity()
    bridge.contacts.add(
        Contact(
            public_key=peer.get_public_key(),
            flags=CONTACT_FLAG_REMOTE_CLI,
            out_path=out_path,
            out_path_len=out_path_len,
        )
    )
    return bridge, peer


# ---------------------------------------------------------------------------
# C string conversions (strtof / atoi)
# ---------------------------------------------------------------------------


class TestCompanionCLICStringConversions:
    @requires_libc
    @pytest.mark.parametrize(
        ("text", "value"),
        [
            ("0x1A2.8", 418.5),  # C99 hex float, no 'p' exponent: 0x1A2 + 8/16
            ("0x10", 16.0),
            ("0x5", 5.0),
            ("0x1A2", 418.0),
            ("0x1p4", 16.0),
            ("inf", float("inf")),
            ("infinity", float("inf")),
            ("nan", float("nan")),
            (".5", 0.5),
            ("5abc", 5.0),
            ("1e2", 100.0),
            ("1e-3", 0.001),
            ("  3.5", 3.5),  # strtof skips leading whitespace
            ("\t  0x10", 16.0),
            ("+5", 5.0),
            ("-0.5", -0.5),
            ("869.618", 869.618),
        ],
    )
    def test_atof_parses_what_strtof_parses(self, text, value):
        from openhop_core.companion.cli import _atof

        # The values are the decimal literals read as binary32, which is what a
        # ``float`` preference holds after strtof.
        libc_value = _c_strtof(text)
        if value != value:  # NaN never compares equal, including to itself
            assert libc_value != libc_value
            assert _atof(text) != _atof(text)
        else:
            assert libc_value == _f32(value)
            assert _atof(text) == _f32(value)

    @requires_libc
    @pytest.mark.parametrize("text", ["", "   ", "abc", "x10", "-", "+"])
    def test_atof_reports_no_number_parsed(self, text):
        """C has no way to say that: ``strtof`` gives 0.0 and leaves ``end`` at
        the start, so every caller substitutes 0.0 itself."""
        from openhop_core.companion.cli import _atof

        assert _atof(text) is None
        assert _c_strtof(text) == 0.0

    @requires_libc
    @pytest.mark.parametrize("text", ["0x", "0b101"])
    def test_atof_falls_back_to_the_leading_zero(self, text):
        """A hex prefix with no digits is not a hex float, so the leading "0" is
        the number and the rest is ignored -- as in C."""
        from openhop_core.companion.cli import _atof

        assert _c_strtof(text) == 0.0
        assert _atof(text) == 0.0

    @requires_libc
    @pytest.mark.parametrize(
        ("text", "value"),
        [
            ("20x", 20),  # trailing garbage is ignored
            ("+7", 7),  # explicit sign
            ("-1", -1),
            ("0x10", 0),  # atoi is base 10: the leading 0 ends the number
            ("0x1A2", 0),
            ("", 0),  # nothing to parse
            ("abc", 0),
            ("  -12xyz", -12),
            ("3.7", 3),  # stops at the point
            (" 42 ", 42),
        ],
    )
    def test_atoi_is_base_10_and_never_raises(self, text, value):
        from openhop_core.companion.cli import _atoi

        assert _atoi(text) == value
        assert _c_atoi(text) == value

    @pytest.mark.parametrize("text", ["3000000000", "12345678901", "2147483648"])
    def test_atoi_saturates_at_a_32_bit_long(self, text):
        """newlib's ``atoi`` is ``(int)strtol(...)`` and ``long`` is 32 bits on
        the firmware's MCUs, so anything past ``LONG_MAX`` saturates. (A 64-bit
        host libc would wrap instead; the firmware target decides.)"""
        from openhop_core.companion.cli import _atoi

        assert _atoi(text) == 2147483647
        assert _atoi("-" + text) == -2147483648


# ---------------------------------------------------------------------------
# Duty cycle: the whole 1..100 integer range, in float32
# ---------------------------------------------------------------------------


class TestCompanionCLIDutyCycleFloat32:
    @pytest.mark.parametrize(
        "argument", [str(n) for n in range(1, 101)] + ["12.5", "99.9", "6", "45"]
    )
    def test_set_dutycycle_follows_the_firmware_float32_chain(self, argument):
        """Every integer 1..100, plus the fractional cases.

        Firmware computes ``setAirtimeFactor((100.0f / dc) - 1.0f)`` and then
        reports ``100.0f / (af + 1.0f)``, both in float32 (CommonRadioPrefs.cpp:
        88-99). Rounding only at the end -- as the audit found openhop doing --
        answers 6.0% as "5.10%" and 45 as "45.0%" instead of "44.10%".
        """
        reply, airtime_factor = _firmware_set_dutycycle(float(argument))
        bridge = _make_bridge()

        assert bridge.cli.handle(f"set dutycycle {argument}") == reply

        assert bridge.prefs.airtime_factor == airtime_factor
        # The stored factor is what every later `get dutycycle` reports.
        assert bridge.cli.handle("get dutycycle") == f"> {_firmware_dutycycle_text(airtime_factor)}"

    @requires_libc
    @pytest.mark.parametrize(
        ("argument", "stored"),
        [
            ("0x10", 5.25),  # C99 hex float: 16.0
            ("0x64", 0.0),  # 100.0
            ("1e1", 9.0),  # 10.0
            ("+25", 3.0),
            (" 40 ", 1.5),
            ("12.5", 7.0),
            ("99.9", 0.0010010004043579102),
        ],
    )
    def test_dutycycle_accepts_everything_atof_does(self, argument, stored):
        """The reply must come from the same chain, whatever atof produced."""
        reply, airtime_factor = _firmware_set_dutycycle(_c_strtof(argument))
        bridge = _make_bridge()

        assert bridge.cli.handle(f"set dutycycle {argument}") == reply

        assert airtime_factor == stored
        assert bridge.prefs.airtime_factor == stored
        assert bridge.cli.handle("get dutycycle") == f"> {_firmware_dutycycle_text(stored)}"


# ---------------------------------------------------------------------------
# set tx: atoi coercion and the int8_t wrap
# ---------------------------------------------------------------------------


class TestCompanionCLITxPower:
    @pytest.mark.parametrize(
        ("argument", "atoi_value", "stored"),
        [
            ("-1", -1, -1),
            ("300", 300, 44),  # uint8_t 44 stored into the int8_t pref
            ("256", 256, 0),
            ("20x", 20, 20),
            ("+7", 7, 7),
            ("0x10", 0, 0),  # atoi is base 10
            ("", 0, 0),
        ],
    )
    def test_set_tx_coerces_with_atoi_and_wraps_into_int8(self, argument, atoi_value, stored):
        """``setTxPower(atoi(...))`` (CommonRadioPrefs.cpp:141-145) with a
        ``uint8_t`` argument feeding an ``int8_t`` pref (NodePrefs.h:25,105), so
        the stored value is ``(int8_t)atoi(arg)`` and the radio gets that too."""
        from openhop_core.companion.cli import _atoi

        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity(), node_name="RadioNode")

        assert comp.cli.handle(f"set tx {argument}") == "OK"

        assert _atoi(argument) == atoi_value
        assert comp.get_self_info().tx_power_dbm == stored
        assert radio.tx_power == stored
        assert comp.cli.handle("get tx") == f"> {stored}"

    def test_set_tx_minus_one_is_reported_signed_where_firmware_prints_255(self):
        """INTENTIONAL DIVERGENCE (openhop prints the signed pref value).

        Firmware reads the pref back through ``uint8_t getTxPower()`` and prints
        it as ``(int32_t)`` (CommonRadioPrefs.cpp:137-139 with
        examples/companion_radio/NodePrefs.h:105), so a stored -1 answers
        ``> 255`` on the next ``get tx``. openhop answers ``> -1``: an app that
        reads the signed number cannot tell a deliberately-set -1 from a wrapped
        255, and the SELF_INFO byte matches either way (it is masked with
        ``& 0xFF`` at pack time).
        """
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity(), node_name="RadioNode")

        assert comp.cli.handle("set tx -1") == "OK"

        assert comp.get_self_info().tx_power_dbm == -1  # int8_t
        assert comp.get_self_info().tx_power_dbm & 0xFF == 255  # what firmware prints
        assert comp.cli.handle("get tx") == "> -1"

    @pytest.mark.parametrize(
        ("argument", "expected_byte"), [("-1", 255), ("300", 44), ("256", 0), ("20x", 20)]
    )
    def test_the_tx_byte_in_self_info_matches_firmware_for_every_wrap(
        self, argument, expected_byte
    ):
        """The only place the two representations cannot disagree: SELF_INFO
        masks the pref to a byte (commands_device.py), so the app never sees the
        signed value either way."""
        comp = _radio_owned_companion()

        comp.cli.handle(f"set tx {argument}")

        assert comp.get_self_info().tx_power_dbm & 0xFF == expected_byte


# ---------------------------------------------------------------------------
# get tx boundaries
# ---------------------------------------------------------------------------


class TestCompanionCLIGetTxBoundaries:
    @pytest.mark.parametrize("command", ["get tx", "get tx ", "get tx 5", "get tx 20"])
    def test_get_tx_matches_the_memcmp_and_the_byte_after_it(self, command):
        """``memcmp(command, "get tx", 6) == 0 && (command[6] == 0 || ' ')``
        (CommonRadioPrefs.cpp:137-139): the sixth byte is all that is checked, so
        ``get tx 5`` answers the stored power and ignores the rest."""
        assert _make_bridge().cli.handle(command) == "> 20"

    @pytest.mark.parametrize("command", ["get tx5", "get txX", "get tx-1", "get tx5 "])
    def test_other_get_tx_spellings_fall_through_to_unknown(self, command):
        assert _make_bridge().cli.handle(command) == UNKNOWN_COMMAND

    def test_get_txdelay_keeps_its_own_branch(self):
        """``get txdelay`` has a branch of its own (CommonRadioPrefs.cpp:201), so
        it must not be swallowed by the ``get tx`` prefix match."""
        assert _make_bridge().cli.handle("get txdelay") == UNSUPPORTED


# ---------------------------------------------------------------------------
# Hex floats, NaN and inf through the commands that parse floats
# ---------------------------------------------------------------------------


class TestCompanionCLIAtOfThroughCommands:
    def test_hex_float_frequency_is_accepted(self):
        """``strtof`` reads C99 hex floats, so 0x1A2.8 is 418.5 MHz
        (CommonRadioPrefs.cpp:44)."""
        comp = _radio_owned_companion()

        assert comp.cli.handle("set radio 0x1A2.8,62.5,8,5") == "OK - reboot to apply"

        assert comp.get_self_info().frequency_hz == 418500000

    def test_hex_float_rx_delay_is_accepted(self):
        """``atof("0x10")`` is 16.0, inside the 0-20 window
        (CommonRadioPrefs.cpp:152-160)."""
        bridge = _make_bridge()

        assert bridge.cli.handle("set rxdelay 0x10") == "OK"

        assert bridge.prefs.rx_delay_base == 16.0
        assert bridge.cli.handle("get rxdelay") == "> 16.0"

    def test_hex_float_timezone_is_accepted(self):
        """``int8_t tz = atof(...)`` (MyMesh.cpp:2186) with atof("0x5") = 5.0."""
        bridge = _make_bridge()

        assert bridge.cli.handle("set tz.offset 0x5") == "OK"

        assert bridge.prefs.tz_offset == 5
        assert bridge.cli.handle("get tz.offset") == "> 5"

    @pytest.mark.parametrize("value", ["nan", "inf", "-inf"])
    def test_rx_delay_refuses_everything_outside_zero_to_twenty(self, value):
        """NaN fails ``db >= 0`` and inf fails ``db <= 20.0f``, so firmware
        answers "Error, must be 0-20" too (CommonRadioPrefs.cpp:153-159)."""
        bridge = _make_bridge()

        assert bridge.cli.handle(f"set rxdelay {value}") == "Error, must be 0-20"

        assert bridge.prefs.rx_delay_base == 0.0

    @pytest.mark.parametrize(
        ("command", "firmware_reply"),
        [
            ("set rxdelay 1e39", "Error, must be 0-20"),
            ("set rxdelay 0x1p1000000", "Error, must be 0-20"),
            ("set af 1e39", "ERROR: af must be 0-9"),
            ("set dutycycle 1e39", "ERROR: dutycycle must be 1-100"),
            ("set radio 1e39,62.5,8,5", "Error, invalid radio params"),
        ],
    )
    def test_a_value_too_large_for_float32_is_an_infinity_not_an_error(
        self, command, firmware_reply
    ):
        assert _make_bridge().cli.handle(command) == firmware_reply

    def test_airtime_factor_refuses_nan_although_firmware_stores_it(self):
        """INTENTIONAL DIVERGENCE. NaN fails neither ``af < 0`` nor ``af > 9`` in
        firmware, which then stores NaN and answers "OK" (CommonRadioPrefs.cpp:
        69-78); ``get af`` afterwards prints garbage and every duty cycle
        derived from it is NaN too. openhop refuses the value instead.
        """
        bridge = _make_bridge()

        assert bridge.cli.handle("set af nan") == "ERROR: af must be 0-9"

        assert bridge.prefs.airtime_factor == 1.0
        assert bridge.cli.handle("get af") == "> 1.0"
        assert bridge.cli.handle("get dutycycle") == "> 50.0%"

    def test_dutycycle_refuses_nan_although_firmware_passes_the_gate(self):
        """INTENTIONAL DIVERGENCE. Firmware's gate is ``dc < 1 || dc > 100``
        (CommonRadioPrefs.cpp:90), which NaN passes, so it stores a NaN airtime
        factor and formats the reply from a NaN conversion. openhop refuses.
        """
        bridge = _make_bridge()

        assert bridge.cli.handle("set dutycycle nan") == "ERROR: dutycycle must be 1-100"

        assert bridge.prefs.airtime_factor == 1.0
        assert bridge.cli.handle("get dutycycle") == "> 50.0%"

    @pytest.mark.parametrize("value", ["nan", "inf", "-inf"])
    def test_timezone_refuses_everything_not_finite(self, value):
        """``int8_t tz = atof(...)`` is undefined for a value that does not fit
        an int8_t (MyMesh.cpp:2186-2188), so openhop refuses rather than store
        whatever the conversion produced."""
        bridge = _make_bridge()

        assert bridge.cli.handle(f"set tz.offset {value}") == "Error, must be from -12 to +14"

        assert bridge.prefs.tz_offset == 0

    @pytest.mark.parametrize("value", ["15", "-13", "24", "1e9"])
    def test_timezone_range_gate_uses_the_stored_integer(self, value):
        bridge = _make_bridge()

        assert bridge.cli.handle(f"set tz.offset {value}") == "Error, must be from -12 to +14"

        assert bridge.prefs.tz_offset == 0


# ---------------------------------------------------------------------------
# set radio: part splitting, uint8 wraps, range gate, kHz staging
# ---------------------------------------------------------------------------


class TestCompanionCLISetRadio:
    def test_spaces_around_the_parts_are_skipped_by_strtof_and_atoi(self):
        """``parseTextParts`` splits on the separator and does not trim
        (Utils.cpp:228-243), but ``strtof``/``atoi`` skip leading blanks."""
        comp = _radio_owned_companion()

        assert comp.cli.handle("set radio 869.618, 62.5 ,8,5") == "OK - reboot to apply"

        prefs = comp.get_self_info()
        assert (prefs.frequency_hz, prefs.bandwidth_hz) == (869618000, 62500)
        assert (prefs.spreading_factor, prefs.coding_rate) == (8, 5)

    def test_a_fifth_part_is_ignored(self):
        """``parseTextParts(tmp, parts, 4)`` stops at four and nulls the
        separator after the last one (Utils.cpp:228-243)."""
        comp = _radio_owned_companion()

        assert comp.cli.handle("set radio 869.618,62.5,8,5,12,extra") == "OK - reboot to apply"

        prefs = comp.get_self_info()
        assert (prefs.spreading_factor, prefs.coding_rate) == (8, 5)

    @pytest.mark.parametrize(
        "args", ["", "869.618", "869.618,62.5", "869.618,62.5,8", "869.618,62.5,8,"]
    )
    def test_fewer_than_four_parts_leaves_the_rest_at_zero_and_is_refused(self, args):
        """The missing parts keep the 0.0/0 defaults of CommonRadioPrefs.cpp:44-47,
        so bw/sf/cr fall outside their windows and the reply is the range error."""
        comp = _radio_owned_companion()
        before = comp.get_self_info()

        assert comp.cli.handle(f"set radio {args}") == "Error, invalid radio params"

        after = comp.get_self_info()
        assert (after.frequency_hz, after.spreading_factor, after.coding_rate) == (
            before.frequency_hz,
            before.spreading_factor,
            before.coding_rate,
        )

    @pytest.mark.parametrize(
        ("args", "accepted", "expected"),
        [
            ("869.618,62.5,258,5", False, None),  # sf 2 -> below the window
            ("869.618,62.5,8,258", False, None),  # cr 2
            ("869.618,62.5,261,5", True, (5, 5)),  # 261 & 0xFF == 5
            ("869.618,62.5,8,261", True, (8, 5)),
            ("869.618,62.5,264,5", True, (8, 5)),
            ("869.618,62.5,268,5", True, (12, 5)),  # sf 12 is the top of the window
            ("869.618,62.5,269,5", False, None),  # sf 13
            ("869.618,62.5,8,260", False, None),  # cr 4 -> below the window
        ],
    )
    def test_spreading_factor_and_coding_rate_wrap_through_uint8(self, args, accepted, expected):
        """``uint8_t sf = atoi(parts[2])`` (CommonRadioPrefs.cpp:46-47) keeps the
        low byte, and the range gate then sees the wrapped value."""
        comp = _radio_owned_companion()

        reply = comp.cli.handle(f"set radio {args}")

        assert reply == ("OK - reboot to apply" if accepted else "Error, invalid radio params")
        prefs = comp.get_self_info()
        if expected is None:
            assert (prefs.spreading_factor, prefs.coding_rate) == (10, 5)  # untouched
        else:
            assert (prefs.spreading_factor, prefs.coding_rate) == expected

    @pytest.mark.parametrize(
        ("bandwidth", "accepted"), [("7.0", True), ("6.99", False), ("500", True), ("500.1", False)]
    )
    def test_bandwidth_range_is_7_to_500_inclusive(self, bandwidth, accepted):
        """``bw >= 7.0f && bw <= 500.0f`` (CommonRadioPrefs.cpp:48) -- the lower
        bound is included, which is where the 0.1 kHz step lives."""
        comp = _radio_owned_companion()

        reply = comp.cli.handle(f"set radio 869.618,{bandwidth},8,5")

        assert reply == ("OK - reboot to apply" if accepted else "Error, invalid radio params")

    @pytest.mark.parametrize(
        ("frequency", "accepted"),
        [("150", True), ("2500", True), ("149.9", False), ("2500.1", False)],
    )
    def test_frequency_range_is_150_to_2500_mhz_inclusive(self, frequency, accepted):
        """``freq >= 150.0f && freq <= 2500.0f`` (CommonRadioPrefs.cpp:48)."""
        comp = _radio_owned_companion()

        reply = comp.cli.handle(f"set radio {frequency},62.5,8,5")

        assert reply == ("OK - reboot to apply" if accepted else "Error, invalid radio params")

    def test_staged_frequency_is_a_whole_number_of_kilohertz(self):
        """DIVERGENCE (audit 7, deliberate): the frame protocol's radio params
        are whole kHz (CMD_SET_RADIO_PARAMS), so openhop stages
        ``round(freq_MHz * 1e3) * 1000``. Firmware keeps the ``float`` MHz and
        SELF_INFO derives ``uint32(freq * 1000)`` by truncation, which reports
        869617 kHz for 869.618 MHz (commands_device.py:111). The stored value
        differs by 1 kHz; both are the same frequency to the radio.
        """
        comp = _radio_owned_companion()

        assert comp.cli.handle("set radio 869.618,62.5,8,5") == "OK - reboot to apply"

        assert comp.get_self_info().frequency_hz == 869618000
        assert comp.get_self_info().frequency_hz % 1000 == 0

    def test_staged_bandwidth_is_a_whole_number_of_kilohertz(self):
        comp = _radio_owned_companion()

        assert comp.cli.handle("set radio 869.618,7.8,8,5") == "OK - reboot to apply"

        assert comp.get_self_info().bandwidth_hz == 7800

    def test_staging_never_touches_the_radio(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity(), node_name="RadioNode")

        assert comp.cli.handle("set radio 869.618,62.5,8,5") == "OK - reboot to apply"

        assert radio.radio_params is None


# ---------------------------------------------------------------------------
# Byte-sized tuning fields
# ---------------------------------------------------------------------------


class TestCompanionCLITuningByteFields:
    @pytest.mark.parametrize(
        ("argument", "reply", "mode"),
        [
            ("2", "OK", 2),
            ("258", "OK", 2),  # uint8_t 2
            ("256", "OK", 0),  # uint8_t 0
            ("300", "Error, must be 0,1, or 2", 0),  # uint8_t 44
            ("-1", "Error, must be 0,1, or 2", 0),  # uint8_t 255
        ],
    )
    def test_path_hash_mode_is_the_low_byte_of_atoi(self, argument, reply, mode):
        """``uint8_t mode = atoi(config)`` (CommonRadioPrefs.cpp:179-189): the
        wrap happens before the ``mode < 3`` test, so 258 is accepted as 2."""
        bridge = _make_bridge()

        assert bridge.cli.handle(f"set path.hash.mode {argument}") == reply

        assert bridge.prefs.path_hash_mode == mode
        assert bridge.cli.handle("get path.hash.mode") == f"> {mode}"

    @pytest.mark.parametrize(
        ("argument", "stored"),
        [("5", 5), ("300", 44), ("256", 0), ("-1", 255), ("0x10", 0), ("", 0)],
    )
    def test_multi_acks_is_the_low_byte_of_atoi(self, argument, stored):
        """``setMultiAcks(atoi(...))`` into a ``uint8_t`` (CommonRadioPrefs.cpp:
        195-199); every other other-param byte must survive."""
        bridge = _make_bridge()
        bridge.set_other_params(
            manual_add=1, telemetry_modes=1 | (2 << 2) | (3 << 4), advert_loc_policy=1, multi_acks=0
        )

        assert bridge.cli.handle(f"set multi.acks {argument}") == "OK"

        prefs = bridge.get_self_info()
        assert prefs.multi_acks == stored
        assert (prefs.manual_add_contacts, prefs.advert_loc_policy) == (1, 1)
        assert (prefs.telemetry_mode_base, prefs.telemetry_mode_location) == (1, 2)
        assert prefs.telemetry_mode_environment == 3


# ---------------------------------------------------------------------------
# set af / set rxdelay parsing
# ---------------------------------------------------------------------------


class TestCompanionCLIAtofTuningParsing:
    @pytest.mark.parametrize(
        ("value", "stored"), [("5abc", 5.0), (".5", 0.5), ("+5", 5.0), ("0", 0.0), ("9", 9.0)]
    )
    def test_airtime_factor_keeps_the_longest_prefix_strtof_parsed(self, value, stored):
        """``strtof(&command[7], &end)`` is only refused when ``end`` never moved
        or the value is out of 0-9 (CommonRadioPrefs.cpp:69-78), so trailing
        garbage is stored, not rejected."""
        bridge = _make_bridge()

        assert bridge.cli.handle(f"set af {value}") == "OK"

        assert bridge.prefs.airtime_factor == stored
        assert bridge.cli.handle("get af") == f"> {ftoa(stored)}"

    @pytest.mark.parametrize("value", ["1e2", "9.5", "10", "x", "", "0x1A2.8"])
    def test_airtime_factor_refuses_nothing_parsed_or_outside_zero_to_nine(self, value):
        bridge = _make_bridge()

        assert bridge.cli.handle(f"set af {value}") == "ERROR: af must be 0-9"

        assert bridge.prefs.airtime_factor == 1.0

    @pytest.mark.parametrize(
        ("value", "stored"),
        [("", 0.0), ("  3.5", 3.5), ("20", 20.0), ("0x10", 16.0), ("2.5abc", 2.5)],
    )
    def test_rx_delay_takes_the_atof_prefix(self, value, stored):
        """``atof`` of nothing is 0.0, which is inside the window, so an empty
        argument is accepted and stores zero (CommonRadioPrefs.cpp:152-160)."""
        bridge = _make_bridge()

        assert bridge.cli.handle(f"set rxdelay {value}") == "OK"

        assert bridge.prefs.rx_delay_base == stored
        assert bridge.cli.handle("get rxdelay") == f"> {ftoa(stored)}"

    @pytest.mark.parametrize("value", ["20.5", "21", "-0.5", "-1"])
    def test_rx_delay_refuses_values_outside_zero_to_twenty(self, value):
        bridge = _make_bridge()

        assert bridge.cli.handle(f"set rxdelay {value}") == "Error, must be 0-20"

        assert bridge.prefs.rx_delay_base == 0.0

    @pytest.mark.parametrize("value", ["1.9", "-0.5", "0", "14", "-12"])
    def test_timezone_truncates_towards_zero_before_the_range_gate(self, value):
        """``int8_t tz = atof(...)`` truncates first, so 1.9 stores 1 and -0.5
        stores 0 (MyMesh.cpp:2186-2188)."""
        bridge = _make_bridge()

        assert bridge.cli.handle(f"set tz.offset {value}") == "OK"

        assert bridge.prefs.tz_offset == int(float(value))

    @pytest.mark.parametrize("value", ["270", "244", "-244"])
    def test_timezone_wrap_window_is_refused_where_firmware_would_accept(self, value):
        """DOCUMENTED DIVERGENCE (the choice is spelled out at cli.py:338-339).
        Firmware's ``int8_t tz = atof(...)`` wraps first: ``(int8_t)270`` is 14,
        ``244`` is -12 and ``-244`` is 12, all inside the window, so firmware
        answers "OK" for values far outside it. openhop refuses anything whose
        truncated value is out of -12..+14.
        """
        bridge = _make_bridge()

        assert bridge.cli.handle(f"set tz.offset {value}") == "Error, must be from -12 to +14"

        assert bridge.prefs.tz_offset == 0


# ---------------------------------------------------------------------------
# set pin: the uint32_t field and %06d of a signed int
# ---------------------------------------------------------------------------


class TestCompanionCLIPinWrap:
    @pytest.mark.parametrize(
        ("argument", "stored", "reply"),
        [
            ("-1", 4294967295, "> pin is now -00001"),
            ("2147483647", 2147483647, "> pin is now 2147483647"),
            ("0x10", 0, "> pin is now 000000"),
            ("", 0, "> pin is now 000000"),
            ("-42", 4294967254, "> pin is now -00042"),
        ],
    )
    def test_pin_is_atoi_into_a_uint32_and_printed_as_a_signed_int(self, argument, stored, reply):
        """``_prefs.ble_pin = atoi(...)`` (MyMesh.cpp:2112-2116) then
        ``sprintf("> pin is now %06d", ble_pin)``: the field is 32 bits wide, so
        the printed int is negative whenever bit 31 is set. ``atoi`` itself
        saturates on the firmware's 32-bit ``long``: see the test below.
        """
        bridge = _make_bridge()

        assert bridge.cli.handle(f"set pin {argument}") == reply

        assert bridge.get_self_info().ble_pin == stored

    @pytest.mark.parametrize("argument", ["3000000000", "12345678901", "2147483648"])
    def test_a_pin_above_long_max_saturates_like_a_32_bit_atoi(self, argument):
        bridge = _make_bridge()

        assert bridge.cli.handle(f"set pin {argument}") == "> pin is now 2147483647"


# ---------------------------------------------------------------------------
# set name: the 32-byte field
# ---------------------------------------------------------------------------


class TestCompanionCLINameByteLimit:
    def test_name_is_stored_up_to_31_bytes(self):
        """``char node_name[32]`` (NodePrefs.h) and ``StrHelper::strncpy(dest,
        src, 32)`` copies 31 bytes and always writes the NUL
        (TxtDataHelpers.cpp:3-9)."""
        bridge = _make_bridge(node_name="old")

        assert bridge.cli.handle("set name " + "A" * 40) == "OK"

        assert bridge.get_self_info().node_name == "A" * 31

    def test_a_code_point_straddling_byte_31_is_dropped_whole(self):
        """DOCUMENTED DIVERGENCE (base_config.set_advert_name). Firmware copies 31
        *raw* bytes, so 15 two-byte code points plus a stray 0xC3 lead byte: 31
        bytes that are not valid UTF-8 and that ``get name`` would echo back. openhop
        drops the split code point, keeping 15 code points.
        """
        bridge = _make_bridge(node_name="old")

        assert bridge.cli.handle("set name " + "é" * 16) == "OK"

        assert bridge.get_self_info().node_name == "é" * 15

    def test_a_name_of_exactly_31_bytes_is_kept_whole(self):
        bridge = _make_bridge(node_name="old")

        assert bridge.cli.handle("set name " + "é" * 15 + "a") == "OK"

        assert bridge.get_self_info().node_name == "é" * 15 + "a"

    def test_a_32_byte_name_loses_only_its_last_byte(self):
        bridge = _make_bridge(node_name="old")

        assert bridge.cli.handle("set name " + "é" * 15 + "ab") == "OK"

        assert bridge.get_self_info().node_name == "é" * 15 + "a"


# ---------------------------------------------------------------------------
# Command prefix edge cases
# ---------------------------------------------------------------------------


class TestCompanionCLIPrefixEdges:
    @pytest.mark.parametrize(
        "command",
        [
            "ab|x",  # strlen == 4, so the prefix rule does not apply
            "abx|get name",  # command[2] is not '|'
            "ab||",
            "a|get name",  # strlen <= 4
            "a\u00e9|get name",  # command[2] is the second byte of the '\u00e9'
        ],
    )
    def test_a_command_without_a_recognised_prefix_is_dispatched_whole(self, command):
        """``strlen(command) > 4 && command[2] == '|'`` (MyMesh.cpp:2069) -- only
        then is the first three bytes echoed and stripped."""
        assert _make_bridge(node_name="N").cli.handle(command) == UNKNOWN_COMMAND

    @pytest.mark.parametrize(
        ("command", "reply"),
        [
            ("  ab|get name", "ab|> N"),
            ("   ab|bogus", "ab|" + UNKNOWN_COMMAND),
            ("    ab|poweroff", "ab|" + UNSUPPORTED),
        ],
    )
    def test_leading_spaces_are_stripped_before_the_prefix_is_read(self, command, reply):
        """``while (*command == ' ') command++;`` runs first
        (MyMesh.cpp:2067), so the prefix is found after the blanks."""
        cli = _make_bridge(node_name="N").cli

        assert cli.handle(command) == reply

    @pytest.mark.parametrize("command", ["", " ", "   ", "    "])
    def test_a_whitespace_only_command_is_unknown(self, command):
        """After the blanks go, the command is empty: no branch matches, so
        handleCommand returns false and the caller appends "Unknown command"
        (MyMesh.cpp:1113)."""
        assert _make_bridge().cli.handle(command) == UNKNOWN_COMMAND

    def test_only_spaces_are_stripped_not_tabs(self):
        """Firmware skips ``' '`` only, and a tab-prefixed command is not a match
        for any branch either -- so the answer is the same on both sides."""
        assert _make_bridge(node_name="N").cli.handle("\tget name") == UNKNOWN_COMMAND

    def test_the_prefix_is_found_by_byte_not_by_character(self):
        """'\u00e9' is two bytes, so its '|' is command[2] to firmware."""
        cli = _make_bridge(node_name="N").cli

        assert cli.handle("\u00e9|get name") == "\u00e9|> N"

    def test_a_prefix_on_a_command_that_does_not_exist_is_still_reflected(self):
        cli = _make_bridge(node_name="N").cli

        assert cli.handle("zz|nosuch") == "zz|" + UNKNOWN_COMMAND


# ---------------------------------------------------------------------------
# Remote CLI routing
# ---------------------------------------------------------------------------


class TestRemoteCLIRouting:
    @pytest.mark.asyncio
    async def test_a_known_contact_path_is_answered_direct(self):
        """``from.out_path_len == OUT_PATH_UNKNOWN ? sendFloodScoped : sendDirect
        (from.out_path, from.out_path_len)`` (BaseChatMesh.cpp:283-287)."""
        injector = MockPacketInjector()
        bridge, peer = _bridge_with_cli_path(injector, b"\xaa\xbb\xcc", 3)

        with _NoDelay():
            await bridge._handle_mesh_event(MeshEvents.NEW_MESSAGE, _cli_command_event(peer))
            await _drain_background_tasks(bridge)

        (pkt, _), = injector.calls
        assert pkt.is_route_direct() is True
        assert not pkt.has_transport_codes()
        assert bytes(pkt.path) == b"\xaa\xbb\xcc"
        assert pkt.get_path_hash_count() == 3

    @pytest.mark.asyncio
    async def test_an_unknown_path_is_answered_with_a_plain_flood(self):
        """The OUT_PATH_UNKNOWN branch with no scope configured is firmware's
        ``sendFlood(pkt, delay, path_hash_size)`` (MyMesh.cpp:492-494)."""
        injector = MockPacketInjector()
        bridge, peer = _bridge_with_cli_path(injector, b"", -1)

        with _NoDelay():
            await bridge._handle_mesh_event(MeshEvents.NEW_MESSAGE, _cli_command_event(peer))
            await _drain_background_tasks(bridge)

        (pkt, _), = injector.calls
        assert pkt.is_route_flood() is True
        assert pkt.has_transport_codes() is False
        assert pkt.transport_codes == [0, 0]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("path_hash_mode", [0, 1, 2])
    async def test_an_unknown_path_carries_the_default_scope_and_the_node_hash_width(
        self, path_hash_mode
    ):
        """MyMesh::sendFloodScoped(ContactInfo&) (MyMesh.cpp:502-513): the
        persisted default scope is turned into transport codes, and the flood is
        sent with ``_prefs.path_hash_mode + 1`` bytes per hop hash.
        """
        injector = MockPacketInjector()
        bridge, peer = _bridge_with_cli_path(injector, b"", -1)
        scope_key = bytes(range(1, 17))
        bridge.set_default_flood_scope("cli-test", scope_key)
        bridge.set_path_hash_mode(path_hash_mode)

        with _NoDelay():
            await bridge._handle_mesh_event(MeshEvents.NEW_MESSAGE, _cli_command_event(peer))
            await _drain_background_tasks(bridge)

        (pkt, _), = injector.calls
        assert pkt.is_route_flood() is True
        assert pkt.has_transport_codes() is True
        assert pkt.transport_codes[0] == _scope_transport_code(scope_key, pkt)
        assert pkt.transport_codes[1] == 0
        assert pkt.get_path_hash_size() == path_hash_mode + 1
        assert pkt.get_path_hash_count() == 0

    @pytest.mark.asyncio
    async def test_a_transient_send_scope_wins_over_the_persisted_default(self):
        """``auto scope = send_scope.isNull() ? &default_scope : &send_scope``
        (MyMesh.cpp:508-511)."""
        injector = MockPacketInjector()
        bridge, peer = _bridge_with_cli_path(injector, b"", -1)
        default_key = bytes(range(1, 17))
        send_key = bytes(range(21, 37))
        bridge.set_default_flood_scope("cli-test", default_key)
        bridge.set_flood_scope(send_key)

        with _NoDelay():
            await bridge._handle_mesh_event(MeshEvents.NEW_MESSAGE, _cli_command_event(peer))
            await _drain_background_tasks(bridge)

        (pkt, _), = injector.calls
        assert pkt.transport_codes[0] == _scope_transport_code(send_key, pkt)
        assert pkt.transport_codes[0] != _scope_transport_code(default_key, pkt)

    @pytest.mark.asyncio
    async def test_a_zero_length_reply_is_never_transmitted(self):
        """``int text_len = strlen(reply); if (text_len > 0)`` -- an empty reply
        means no datagram at all (BaseChatMesh.cpp:271-272)."""
        injector = MockPacketInjector()
        bridge, peer = _bridge_with_cli_path(injector, b"\xaa", 1)
        bridge.cli_command_hook = lambda command, sender_timestamp: ""

        with _NoDelay():
            await bridge._handle_mesh_event(MeshEvents.NEW_MESSAGE, _cli_command_event(peer))
            await _drain_background_tasks(bridge)

        assert injector.calls == []
        assert bridge.message_queue.count == 0
        assert bridge._remote_cli_replies == set()

    @pytest.mark.asyncio
    async def test_the_sender_timestamp_reaches_the_hook_on_the_remote_path(self):
        """``onCLICommandRecv(from, packet, sender_timestamp, text, reply)``
        passes it to handleCommand (MyMesh.cpp:540-542)."""
        injector = MockPacketInjector()
        bridge, peer = _bridge_with_cli_path(injector, b"\xaa", 1)
        seen: list = []
        bridge.cli_command_hook = lambda command, sender_timestamp: (
            seen.append((command, sender_timestamp)) or "> ok"
        )

        with _NoDelay():
            await bridge._handle_mesh_event(
                MeshEvents.NEW_MESSAGE,
                _cli_command_event(peer, "get host.thing", timestamp=1700000000),
            )
            await _drain_background_tasks(bridge)

        assert seen == [("get host.thing", 1700000000)]
        assert len(injector.calls) == 1

    @pytest.mark.asyncio
    async def test_the_remote_reply_is_capped_at_the_remote_text_buffer(self):
        """Firmware builds the reply in ``uint8_t temp[166]`` with the text at
        ``+5`` (BaseChatMesh.cpp:263-265), so at most 160 text bytes fit; the
        CLI's own 165-byte cap (MyMesh.h reply_buf) cannot be reached over the air."""
        injector = MockPacketInjector()
        bridge, peer = _bridge_with_cli_path(injector, b"", -1)
        bridge.cli_command_hook = lambda command, sender_timestamp: "A" * 300

        with _NoDelay():
            await bridge._handle_mesh_event(MeshEvents.NEW_MESSAGE, _cli_command_event(peer))
            await _drain_background_tasks(bridge)

        (pkt, _), = injector.calls
        plaintext = _decrypt_txt_msg(bridge, peer, pkt)
        assert plaintext[5:].rstrip(b"\x00") == b"A" * 160


# ---------------------------------------------------------------------------
# Hook failures
# ---------------------------------------------------------------------------


class TestCompanionCLIHookFailure:
    def test_an_exception_in_a_hook_becomes_an_error_reply(self):
        """openhop-only behaviour. Firmware's ``board.handleCommand`` returns a
        bool; a C++ exception there would not become a CLI reply, it would
        escape (MyMesh.cpp:2082-2085). openhop turns any exception from the
        dispatch into ``Error: <message>`` so one bad hook cannot take the
        companion's CLI down.
        """
        bridge = _make_bridge()

        def hook(command, sender_timestamp):
            raise RuntimeError("host is busy")

        bridge.cli_command_hook = hook

        assert bridge.cli.handle("get host.thing") == "Error: host is busy"
        # The reflected prefix is still applied to the error text.
        assert bridge.cli.handle("ab|get host.thing") == "ab|Error: host is busy"

    def test_an_exception_in_a_built_in_setter_also_becomes_an_error_reply(self):
        """The same guard covers the radio commands, which run before the hook."""
        bridge = _make_bridge()
        with patch.object(bridge, "set_tuning_params", side_effect=OSError("disk full")):
            reply = bridge.cli.handle("set af 2")

        assert reply == "Error: disk full"
        assert bridge.prefs.airtime_factor == 1.0

    def test_a_failing_hook_does_not_stop_the_next_command(self):
        bridge = _make_bridge(node_name="N")
        calls: list = []

        def hook(command, sender_timestamp):
            calls.append(command)
            if command == "get host.boom":
                raise ValueError("nope")
            return None

        bridge.cli_command_hook = hook

        assert bridge.cli.handle("get host.boom") == "Error: nope"
        assert bridge.cli.handle("get name") == "> N"
        assert calls == ["get host.boom", "get name"]


# ---------------------------------------------------------------------------
# board / ver with no frame server
# ---------------------------------------------------------------------------


class TestCompanionCLIDefaultDeviceInfo:
    def test_board_and_ver_answer_the_python_companion_defaults(self):
        """Firmware answers ``board.getManufacturerName()`` (MyMesh.cpp:2171).
        With no frame server there is no DEVICE_INFO to copy, so the CLI must
        still answer with its own default rather than an empty string.
        """
        bridge = _make_bridge()
        assert bridge.cli.manufacturer == "pyMC-Companion"
        assert bridge.cli.handle("board") == "pyMC-Companion"
        assert bridge.cli.handle("ver") == f"openHop core v{openhop_core.__version__}"

    def test_a_frame_server_still_overrides_the_defaults(self):
        bridge = _make_bridge()
        _capture_server(bridge, device_model="pyMC-Bridge", build_date="2026-09-25")

        assert bridge.cli.handle("board") == "pyMC-Bridge"


@pytest.mark.parametrize("value", [1e39, -1e39, float("inf"), float("nan")])
def test_ftoa_falls_back_to_zero_outside_its_range(value):
    """``_ftoa`` flags |value| > 2147483520 as too large and ftoa prints "0"
    (TxtDataHelpers.cpp:50, 76-79); inf, NaN and float32 overflow land there too."""
    assert ftoa(value) == "0"


# ---------------------------------------------------------------------------
# A bridge never controls the host's radio
# ---------------------------------------------------------------------------


_RADIO_PREF_FIELDS = ("frequency_hz", "bandwidth_hz", "spreading_factor", "coding_rate")


class TestBridgeHasNoRadioControl:
    """A CompanionBridge is a virtual companion on a repeater: the radio and its
    settings belong to the host. No CLI command, frame command, remote command
    or direct API call may change them, or the bridge's stored copy of them."""

    def _bridge(self):
        host = {**_HOST_RADIO, "power": 22}
        bridge = CompanionBridge(
            LocalIdentity(),
            MockPacketInjector(),
            node_name="Bridge",
            radio_settings_getter=lambda: host,
        )
        snapshot = dict(host)
        stored = {f: getattr(bridge.prefs, f) for f in _RADIO_PREF_FIELDS + ("tx_power_dbm",)}
        return bridge, host, snapshot, stored

    def _assert_untouched(self, bridge, host, snapshot, stored):
        assert host == snapshot
        assert {
            f: getattr(bridge.prefs, f) for f in _RADIO_PREF_FIELDS + ("tx_power_dbm",)
        } == stored
        assert bridge.cli.handle("get radio") == f"> {_firmware_ftoa(869.618)},62.5,8,5"
        assert bridge.cli.handle("get tx") == "> 22"

    @pytest.mark.parametrize(
        "command",
        [
            "set radio 915.0,250,10,5",
            "set tx 10",
            "set int.thresh 5",
            "set cad on",
            "set radio.rxgain on",
            "set agc.reset.interval 8",
            "set txdelay 1",
            "set direct.txdelay 1",
        ],
    )
    def test_cli_radio_commands_are_refused(self, command):
        bridge, host, snapshot, stored = self._bridge()
        with patch.object(bridge, "_save_prefs") as save:
            assert bridge.cli.handle(command) == UNSUPPORTED
        save.assert_not_called()
        self._assert_untouched(bridge, host, snapshot, stored)

    def test_direct_api_calls_are_refused(self):
        bridge, host, snapshot, stored = self._bridge()
        with patch.object(bridge, "_save_prefs") as save:
            assert bridge.set_radio_params(915000000, 250000, 10, 5) is False
            assert bridge.set_tx_power(10) is False
            assert bridge.stage_radio_params(915000000, 250000, 10, 5) is False
        save.assert_not_called()
        assert bridge.supports_radio_params_mutation() is False
        assert bridge.supports_tx_power_mutation() is False
        assert bridge.supports_client_repeat() is False
        self._assert_untouched(bridge, host, snapshot, stored)

    @pytest.mark.asyncio
    async def test_frame_radio_commands_are_acknowledged_but_not_applied(self):
        """CMD_SET_RADIO_PARAMS / CMD_SET_RADIO_TX_POWER answer OK so an app's
        settings save can continue, but change nothing (commands_device.py)."""
        bridge, host, snapshot, stored = self._bridge()
        server, frames = _capture_server(bridge)
        with patch.object(bridge, "set_radio_params") as set_radio, patch.object(
            bridge, "set_tx_power"
        ) as set_tx, patch.object(bridge, "set_client_repeat") as set_repeat:
            await server._handle_cmd(
                bytes([CMD_SET_RADIO_PARAMS])
                + struct.pack("<IIBB", 915000, 250000, 10, 5)
                + b"\x00"
            )
            await server._handle_cmd(bytes([CMD_SET_RADIO_TX_POWER]) + struct.pack("<b", 10))
        assert frames == [bytes([RESP_CODE_OK]), bytes([RESP_CODE_OK])]
        set_radio.assert_not_called()
        set_tx.assert_not_called()
        set_repeat.assert_not_called()
        self._assert_untouched(bridge, host, snapshot, stored)

    @pytest.mark.asyncio
    async def test_a_remote_cli_command_cannot_retune_the_host(self):
        bridge, host, snapshot, stored = self._bridge()
        peer = LocalIdentity()
        bridge.contacts.add(
            Contact(public_key=peer.get_public_key(), flags=CONTACT_FLAG_REMOTE_CLI)
        )
        replies = []

        async def capture(pub_key, text, **kwargs):
            replies.append(text)

        bridge.send_text_message = capture
        with _NoDelay():
            for command in ("set radio 915.0,250,10,5", "set tx 10"):
                await bridge._handle_mesh_event(
                    MeshEvents.NEW_MESSAGE,
                    _cli_command_event(peer, message_text=command, packet_hash=command),
                )
            await _drain_background_tasks(bridge)

        assert replies == [UNSUPPORTED, UNSUPPORTED]
        self._assert_untouched(bridge, host, snapshot, stored)

    def test_a_bridge_has_no_radio_to_apply_prefs_to(self):
        """Applying stored prefs at start is CompanionRadio's; a bridge has no
        radio handle for it to reach."""
        bridge, *_ = self._bridge()
        assert not hasattr(bridge, "_apply_staged_radio_params")
        assert not hasattr(bridge, "_radio")


# ---------------------------------------------------------------------------
# reboot: a settings reload (CompanionRadio also re-applies its radio)
# ---------------------------------------------------------------------------


class _FakeWriter:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class TestReboot:
    """Firmware reboots and never replies; the app sees the connection drop,
    reconnects and re-syncs. openHop reloads the settings instead and a frame
    server drops its client, so the app sees the same thing."""

    def test_cli_reboot_reloads_settings_and_answers_nothing(self):
        bridge = _make_bridge()
        with patch.object(bridge, "reload_settings") as reload:
            assert bridge.cli.handle("reboot") == ""
            assert bridge.cli.handle("ab|reboot") == ""  # not even the prefix
        assert reload.call_count == 2

    def test_a_host_hook_can_still_answer_reboot(self):
        bridge = _make_bridge()
        bridge.cli_command_hook = lambda command, ts: (
            "> host reboot" if command == "reboot" else None
        )
        with patch.object(bridge, "reload_settings") as reload:
            assert bridge.cli.handle("reboot") == "> host reboot"
        reload.assert_not_called()

    def test_reload_reads_prefs_back_and_clears_ram_only_state(self):
        bridge = _make_bridge()
        bridge.set_flood_scope(bytes(range(1, 17)))
        bridge.set_flood_unscoped()
        with patch.object(bridge, "_load_prefs") as load, patch.object(
            bridge, "_apply_prefs_to_runtime"
        ) as apply:
            bridge.reload_settings()
        load.assert_called_once()
        apply.assert_called_once()
        assert bridge._flood_transport_key is None
        assert bridge._flood_unscoped is False

    def test_reload_keeps_contacts_and_queued_messages(self):
        bridge = _make_bridge()
        bridge.contacts.add(Contact(public_key=LocalIdentity().get_public_key(), name="peer"))
        bridge.message_queue.push(
            QueuedMessage(sender_key=b"\x01" * 32, txt_type=0, timestamp=1, text="hi")
        )
        bridge.reload_settings()
        assert bridge.contacts.get_count() == 1
        assert bridge.message_queue.count == 1

    def test_bridge_reload_reapplies_only_its_own_prefs(self):
        bridge = _make_bridge()
        with patch.object(bridge, "_apply_multi_acks_pref") as multi_acks:
            bridge.reload_settings()
        multi_acks.assert_called_once()

    def test_companion_radio_reboot_applies_staged_radio_params(self):
        radio = MockRadio()
        comp = CompanionRadio(radio, LocalIdentity())
        comp.cli.handle("set radio 869.618,62.5,8,5")
        assert radio.radio_params is None

        comp.cli.handle("reboot")

        assert radio.radio_params == {
            "frequency": 869618000,
            "bandwidth": 62500,
            "spreading_factor": 8,
            "coding_rate": 5,
        }

    def test_companion_radio_reboot_resyncs_the_dispatcher(self):
        comp = CompanionRadio(MockRadio(), LocalIdentity())
        comp.set_flood_scope(bytes(range(1, 17)))
        comp.node.dispatcher.flood_transport_key = bytes(range(1, 17))
        comp.prefs.rx_delay_base = 7.0  # as a persistence layer would restore it

        comp.reload_settings()

        assert comp.node.dispatcher.flood_transport_key is None
        assert comp.node.dispatcher.rx_delay_base == 7.0

    def test_request_reboot_without_an_event_loop_just_reloads(self):
        bridge = _make_bridge()
        with patch.object(bridge, "reload_settings") as reload:
            assert bridge.request_reboot() is True
        reload.assert_called_once()

    @pytest.mark.asyncio
    async def test_reboot_push_reaches_sync_and_async_subscribers(self):
        bridge = _make_bridge()
        seen = []

        async def async_cb():
            seen.append("async")

        bridge.add_push_callback("reboot", lambda: seen.append("sync"))
        bridge.add_push_callback("reboot", async_cb)
        bridge.request_reboot()
        await _drain_background_tasks(bridge)
        assert seen == ["sync", "async"]

    @pytest.mark.asyncio
    async def test_a_failing_subscriber_does_not_stop_the_others(self):
        bridge = _make_bridge()
        seen = []

        async def boom():
            raise RuntimeError("subscriber failed")

        bridge.add_push_callback("reboot", boom)
        bridge.add_push_callback("reboot", lambda: seen.append("ran"))
        bridge.request_reboot()
        await _drain_background_tasks(bridge)
        assert seen == ["ran"]

    @pytest.mark.asyncio
    async def test_two_reboots_back_to_back_each_reload_and_notify(self):
        bridge = _make_bridge()
        seen = []
        bridge.add_push_callback("reboot", lambda: seen.append(1))
        with patch.object(bridge, "reload_settings") as reload:
            bridge.request_reboot()
            bridge.request_reboot()
            await _drain_background_tasks(bridge)
        assert reload.call_count == 2
        assert seen == [1, 1]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("hook", ["_load_prefs", "_apply_prefs_to_runtime"])
    async def test_a_failed_reload_still_drops_the_client_and_sends_nothing(self, hook):
        """Firmware's reboot always ends the session; a persistence error must
        not leave the app connected after being told nothing went wrong."""
        bridge = _make_bridge()
        server, frames = _capture_server(bridge)
        server._setup_push_callbacks()
        writer = _FakeWriter()
        server._client_writer = writer
        with patch.object(bridge, hook, side_effect=RuntimeError("sqlite is locked")), patch.object(
            server, "_save_contacts", AsyncMock()
        ):
            await server._handle_cmd(bytes([CMD_REBOOT]) + b"reboot")
            await server._handle_cmd(bytes([CMD_RUN_CLI_COMMAND]) + b"reboot")
            await _drain_background_tasks(bridge)
        assert frames == []
        assert writer.closed is True

    @pytest.mark.asyncio
    async def test_a_failed_contact_save_still_drops_the_client(self):
        bridge = _make_bridge()
        server, frames = _capture_server(bridge)
        server._setup_push_callbacks()
        writer = _FakeWriter()
        server._client_writer = writer
        with patch.object(
            server, "_save_contacts", AsyncMock(side_effect=RuntimeError("sqlite is locked"))
        ):
            await server._handle_cmd(bytes([CMD_REBOOT]) + b"reboot")
            await _drain_background_tasks(bridge)
        assert frames == []
        assert writer.closed is True

    @pytest.mark.asyncio
    async def test_reboot_drops_the_client_that_asked_not_one_that_connected_since(self):
        """An app that connects while contacts are saving is already a fresh
        session; only the rebooting one is dropped."""
        bridge = _make_bridge()
        server, _ = _capture_server(bridge)
        server._setup_push_callbacks()
        rebooting, newcomer = _FakeWriter(), _FakeWriter()
        server._client_writer = rebooting

        async def reconnect_during_save():
            server._client_writer = newcomer

        with patch.object(server, "_save_contacts", AsyncMock(side_effect=reconnect_during_save)):
            await server._handle_cmd(bytes([CMD_REBOOT]) + b"reboot")
            await _drain_background_tasks(bridge)
        assert rebooting.closed is True
        assert newcomer.closed is False

    @pytest.mark.asyncio
    async def test_a_command_queued_behind_reboot_still_gets_its_reply(self):
        """Only the reboot's own reply is suppressed, not whatever the app
        pipelined after it on the same connection."""
        bridge = _make_bridge(node_name="N")
        server, frames = _capture_server(bridge)
        server._setup_push_callbacks()
        server._client_writer = _FakeWriter()
        with patch.object(server, "_save_contacts", AsyncMock()):
            await server._handle_cmd(bytes([CMD_RUN_CLI_COMMAND]) + b"reboot")
            await server._handle_cmd(bytes([CMD_RUN_CLI_COMMAND]) + b"get name")
            await _drain_background_tasks(bridge)
        assert frames == [bytes([RESP_CODE_CLI_REPLY]) + b"> N"]

    def test_reboot_reads_back_what_a_persistence_layer_stored(self):
        """End to end, no mocks on the reload itself: prefs written to a store
        come back on reboot, and RAM-only scope state is gone."""
        store: dict = {}

        class PersistentBridge(CompanionBridge):
            def _save_prefs(self):
                store.update(dataclasses.asdict(self.prefs))

            def _load_prefs(self):
                for key, value in store.items():
                    setattr(self.prefs, key, value)

        bridge = PersistentBridge(LocalIdentity(), MockPacketInjector(), node_name="Old")
        bridge.cli.handle("set name New")
        bridge.cli.handle("set tz.offset -5")
        bridge.set_flood_scope(bytes(range(1, 17)))
        bridge.prefs.node_name = "unsaved edit"  # in memory only, never saved

        bridge.cli.handle("reboot")

        assert bridge.prefs.node_name == "New"
        assert bridge.prefs.tz_offset == -5
        assert bridge._flood_transport_key is None

    @pytest.mark.asyncio
    async def test_cmd_reboot_reloads_writes_nothing_saves_contacts_and_drops_the_client(self):
        bridge = _make_bridge()
        server, frames = _capture_server(bridge)
        server._setup_push_callbacks()
        writer = _FakeWriter()
        server._client_writer = writer
        with patch.object(bridge, "reload_settings") as reload, patch.object(
            server, "_save_contacts", AsyncMock()
        ) as save:
            await server._handle_cmd(bytes([CMD_REBOOT]) + b"reboot")
            await _drain_background_tasks(bridge)

        assert frames == []
        reload.assert_called_once()
        save.assert_awaited_once()
        assert writer.closed is True

    @pytest.mark.asyncio
    @pytest.mark.parametrize("payload", [b"", b"reboo", b"REBOOT", b"restart"])
    async def test_cmd_reboot_needs_the_magic(self, payload):
        bridge = _make_bridge()
        server, frames = _capture_server(bridge)
        with patch.object(bridge, "reload_settings") as reload:
            await server._handle_cmd(bytes([CMD_REBOOT]) + payload)
        assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_UNSUPPORTED_CMD])]
        reload.assert_not_called()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("payload", [b"reboot", b"reboot\x00", b"rebootX"])
    async def test_cmd_reboot_compares_only_the_six_magic_bytes(self, payload):
        """``memcmp(&cmd_frame[1], "reboot", 6)`` (MyMesh.cpp:1499): trailing
        bytes do not matter to firmware either."""
        bridge = _make_bridge()
        server, frames = _capture_server(bridge)
        with patch.object(bridge, "reload_settings") as reload:
            await server._handle_cmd(bytes([CMD_REBOOT]) + payload)
        assert frames == []
        reload.assert_called_once()

    @pytest.mark.asyncio
    async def test_cmd_reboot_on_a_bridge_without_reboot_is_unsupported(self):
        server, frames = _capture_server(_BridgeWithoutCli())
        await server._handle_cmd(bytes([CMD_REBOOT]) + b"reboot")
        assert frames == [bytes([RESP_CODE_ERR, ERR_CODE_UNSUPPORTED_CMD])]

    @pytest.mark.asyncio
    async def test_cli_reboot_over_cmd_66_writes_no_cli_reply(self):
        bridge = _make_bridge()
        server, frames = _capture_server(bridge)
        server._setup_push_callbacks()
        writer = _FakeWriter()
        server._client_writer = writer
        with patch.object(server, "_save_contacts", AsyncMock()):
            await server._handle_cmd(bytes([CMD_RUN_CLI_COMMAND]) + b"reboot")
            await _drain_background_tasks(bridge)
        assert frames == []
        assert writer.closed is True

    @pytest.mark.asyncio
    async def test_remote_cli_reboot_reloads_and_sends_no_reply(self):
        injector = MockPacketInjector()
        bridge, peer = _bridge_with_cli_contact(injector, CONTACT_FLAG_REMOTE_CLI)
        with _NoDelay(), patch.object(bridge, "reload_settings") as reload:
            await bridge._handle_mesh_event(
                MeshEvents.NEW_MESSAGE, _cli_command_event(peer, text="reboot")
            )
            await _drain_background_tasks(bridge)
        reload.assert_called_once()
        assert injector.calls == []
        assert bridge.message_queue.count == 0


# ---------------------------------------------------------------------------
# cad: listen-before-talk on a companion that owns its radio
# ---------------------------------------------------------------------------


class _LbtRadio(MockRadio):
    def __init__(self, lbt_enabled=True, with_setter=False):
        super().__init__()
        self.lbt_enabled = lbt_enabled
        self.setter_calls = []
        if with_setter:
            self.set_lbt_enabled = lambda enabled: (
                self.setter_calls.append(enabled),
                setattr(self, "lbt_enabled", enabled),
            )


class TestCad:
    def test_a_bridge_has_no_cad(self):
        cli = _make_bridge().cli
        assert cli.handle("get cad") == UNSUPPORTED
        assert cli.handle("set cad on") == UNSUPPORTED

    def test_a_radio_without_an_lbt_switch_has_no_cad(self):
        cli = CompanionRadio(MockRadio(), LocalIdentity()).cli
        assert cli.handle("get cad") == UNSUPPORTED
        assert cli.handle("set cad off") == UNSUPPORTED

    @pytest.mark.parametrize("lbt", [True, False])
    def test_an_unset_pref_reports_the_radios_own_mode(self, lbt):
        comp = CompanionRadio(_LbtRadio(lbt_enabled=lbt), LocalIdentity())
        assert comp.cli.handle("get cad") == ("> on" if lbt else "> off")
        assert comp.prefs.cad_enabled is None

    @pytest.mark.parametrize(
        ("value", "enabled"),
        [("on", True), ("off", False), ("onion", True), ("ON", False), ("1", False)],
    )
    def test_set_cad_follows_firmwares_two_byte_match(self, value, enabled):
        """``setCadEnabled(memcmp(&command[8], "on", 2) == 0)`` (CommonRadioPrefs.cpp)."""
        radio = _LbtRadio(lbt_enabled=not enabled)
        comp = CompanionRadio(radio, LocalIdentity())
        with patch.object(comp, "_save_prefs") as save:
            assert comp.cli.handle(f"set cad {value}") == "OK"
        save.assert_called_once()
        assert comp.prefs.cad_enabled is enabled
        assert radio.lbt_enabled is enabled
        assert comp.cli.handle("get cad") == ("> on" if enabled else "> off")

    def test_the_radios_setter_is_used_when_it_has_one(self):
        radio = _LbtRadio(lbt_enabled=True, with_setter=True)
        comp = CompanionRadio(radio, LocalIdentity())
        comp.cli.handle("set cad off")
        assert radio.setter_calls == [False]

    def test_an_unset_pref_leaves_the_radio_alone_on_reload(self):
        radio = _LbtRadio(lbt_enabled=True, with_setter=True)
        comp = CompanionRadio(radio, LocalIdentity())
        comp.reload_settings()
        assert radio.setter_calls == []
        assert radio.lbt_enabled is True

    def test_a_stored_pref_is_applied_on_reload(self):
        radio = _LbtRadio(lbt_enabled=True)
        comp = CompanionRadio(radio, LocalIdentity())
        comp.prefs.cad_enabled = False  # restored by a persistence layer
        comp.reload_settings()
        assert radio.lbt_enabled is False
