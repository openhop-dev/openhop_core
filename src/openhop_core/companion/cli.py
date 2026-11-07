"""The companion's local CLI (firmware ``MyMesh::handleCommand``).

MeshCore v14 gives a companion a text CLI, reached two ways: the app sends
``CMD_RUN_CLI_COMMAND`` over the frame protocol, or a contact the app has
flagged ``CONTACT_FLAG_REMOTE_CLI`` sends a ``TXT_TYPE_CLI_COMMAND`` message.
Both run the same command set and return the same reply text.

Reply strings, ranges and parsing mirror firmware
(``examples/companion_radio/MyMesh.cpp`` ``handleCommand`` and
``src/helpers/CommonRadioPrefs.cpp``) so an app written against a firmware
companion reads them the same way.
"""

from __future__ import annotations

import logging
import math
import re
import struct
from typing import TYPE_CHECKING, Callable, Optional

from .. import __version__ as core_version

if TYPE_CHECKING:
    from .companion_base import CompanionBase

logger = logging.getLogger("CompanionCLI")

# Firmware MyMesh::reply_buf[166]: at most 165 reply bytes plus the terminator.
MAX_CLI_REPLY_LEN = 165

UNKNOWN_COMMAND = "Unknown command"
UNSUPPORTED = "Error: unsupported"

# Characters AdvertDataParser::isValidName refuses in a node name.
_INVALID_NAME_CHARS = frozenset("[]\\:,?*")

# Radio settings firmware keeps in CommonRadioPrefs that no companion backend
# applies yet (`cad` is handled where the owned radio has an LBT switch).
# Answering "OK" would claim an effect that never happens.
_UNSUPPORTED_RADIO_KEYS = (
    "int.thresh",
    "radio.rxgain",
    "agc.reset.interval",
    "txdelay",
    "direct.txdelay",
)

# A host hook sees the command after the radio settings and before the
# built-ins (firmware ``board.handleCommand``). Return the reply, or None when
# the command is not the host's.
CliCommandHook = Callable[[str, int], Optional[str]]


def is_valid_node_name(name: str) -> bool:
    """Firmware ``AdvertDataParser::isValidName``."""
    return not any(c in _INVALID_NAME_CHARS for c in name)


_LONG_MIN, _LONG_MAX = -(1 << 31), (1 << 31) - 1


def _atoi(text: str) -> int:
    """C ``atoi``: optional leading whitespace and sign, then base-10 digits;
    else 0. Saturates like ``strtol`` on the firmware's 32-bit ``long``."""
    m = re.match(r"\s*([+-]?\d+)", text)
    return max(_LONG_MIN, min(_LONG_MAX, int(m.group(1)))) if m else 0


_STRTOF = re.compile(
    r"\s*(?P<num>[+-]?(?:"
    r"0[xX](?:[0-9a-fA-F]+\.?[0-9a-fA-F]*|\.[0-9a-fA-F]+)(?:[pP][+-]?\d+)?"
    r"|(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?"
    r"|inf(?:inity)?|nan"
    r"))",
    re.IGNORECASE,
)


def _atof(text: str) -> Optional[float]:
    """C ``strtof`` prefix parse, including hex floats, ``inf`` and ``nan``.
    Returns None when no number was consumed (C ``atof`` then gives 0)."""
    m = _STRTOF.match(text)
    if not m:
        return None
    num = m.group("num")
    body = num.lstrip("+-")
    if body[:2].lower() == "0x":
        if "p" not in body.lower():
            body += "p0"
        try:
            value = _float32(float.fromhex(body))
        except OverflowError:
            value = math.inf
        return -value if num.startswith("-") else value
    return _float32(float(num))


def _int8(value: int) -> int:
    return ((value & 0xFF) ^ 0x80) - 0x80


def _float32(value: float) -> float:
    """Round to binary32; out-of-range values become +/-inf as in C."""
    try:
        return struct.unpack("<f", struct.pack("<f", value))[0]
    except OverflowError:
        return math.copysign(math.inf, value)


def ftoa(value: float) -> str:
    """Firmware ``StrHelper::ftoa`` (``TxtDataHelpers.cpp`` ``_ftoa``), bit for bit.

    Works on the float32 bits: up to 7 decimals, truncated rather than rounded,
    trailing zeros dropped but one decimal kept. Below 1.0 firmware shifts the
    fraction right and loses its low bits, so 0.1 prints as ``0.0999999``.
    """
    raw = struct.unpack("<I", struct.pack("<f", _float32(value)))[0]
    if raw & 0x7FFFFFFF == 0:
        return "0.0"
    exp2 = ((raw >> 23) & 0xFF) - 127
    mantissa = (raw & 0xFFFFFF) | 0x800000
    if exp2 >= 31 or exp2 < -23:
        return "0"  # firmware's fallback for out-of-range values
    if exp2 >= 23:
        int_part, frac_part = mantissa << (exp2 - 23), 0
    elif exp2 >= 0:
        int_part = mantissa >> (23 - exp2)
        frac_part = (mantissa << (exp2 + 1)) & 0xFFFFFF
    else:
        int_part, frac_part = 0, mantissa >> -(exp2 + 1)
    text = ("-" if raw & 0x80000000 else "") + f"{int_part}."
    if frac_part == 0:
        return text + "0"
    digits = ""
    for _ in range(7):
        frac_part *= 10
        digits += str(frac_part >> 24)
        frac_part &= 0xFFFFFF
    return text + (digits.rstrip("0") or "0")


def ftoa3(value: float) -> str:
    """Firmware ``StrHelper::ftoa3``: rounded to 3 decimals, trailing zeros and
    a bare point dropped."""
    v = _float32(value)
    scaled = int(_float32(_float32(v * 1000.0) + (0.5 if v >= 0 else -0.5)))
    whole = int(scaled / 1000)
    frac = abs(scaled) % 1000
    text = f"{whole}.{frac:03d}".rstrip("0")
    return text[:-1] if text.endswith(".") else text


def _cut(text: str, limit: int) -> str:
    """Truncate to ``limit`` UTF-8 bytes without splitting a code point."""
    return text.encode("utf-8")[:limit].decode("utf-8", errors="ignore")


class CompanionCLI:
    """Runs one CLI command against a companion and returns the reply text."""

    def __init__(self, companion: "CompanionBase") -> None:
        self._companion = companion
        # Reported by `board` and `ver`. The frame server supplies its own
        # device info at construction so both answer what DEVICE_INFO says.
        self._rebooted = False
        self.manufacturer = "pyMC-Companion"
        # Reported by `ver`, host first, core last. A host (e.g. the repeater)
        # adds its own entry with add_software_version().
        self._software_versions: list[tuple[str, str]] = [("core", core_version)]

    @property
    def last_command_rebooted(self) -> bool:
        """Whether the last :meth:`handle` call ran the built-in ``reboot``,
        whose reply firmware never sends."""
        return self._rebooted

    def set_device_info(self, manufacturer: str) -> None:
        """`board` answers what DEVICE_INFO reports as the manufacturer."""
        self.manufacturer = manufacturer

    def add_software_version(self, name: str, version: str) -> None:
        """Report ``name`` (e.g. "repeater") in `ver`, ahead of the core."""
        self._software_versions = [(n, v) for n, v in self._software_versions if n != name]
        self._software_versions.insert(0, (name, version))

    @property
    def version_text(self) -> str:
        """`ver`: the openHop software running this companion, e.g.
        "openHop repeater v1.0.11, core v1.1.4". Firmware answers
        "<FIRMWARE_VERSION> (Build: <date>)"; a companion is openHop software,
        so it names those versions instead of the protocol level."""
        return "openHop " + ", ".join(f"{name} v{ver}" for name, ver in self._software_versions)

    def handle(self, command: str, sender_timestamp: int = 0) -> str:
        """Run ``command`` and return the reply (never empty for a known command)."""
        self._rebooted = False
        command = command.lstrip(" ")
        prefix = ""
        # Optional "XX|" prefix from the companion app, reflected back so the
        # app can match a reply to its command. Firmware indexes bytes.
        raw = command.encode("utf-8")
        if len(raw) > 4 and raw[2:3] == b"|":
            prefix, command = raw[:3].decode("utf-8"), raw[3:].decode("utf-8")

        try:
            reply = self._dispatch(command, sender_timestamp)
        except Exception as e:
            logger.error("CLI command %r failed: %s", command, e, exc_info=True)
            reply = f"Error: {e}"
        if reply is None:
            reply = UNKNOWN_COMMAND
        if self._rebooted:
            return ""  # not even the reflected prefix: firmware never answers
        return _cut(prefix + reply, MAX_CLI_REPLY_LEN)

    # ------------------------------------------------------------------
    # Dispatch, in firmware order: radio settings, host hook, built-ins
    # ------------------------------------------------------------------

    def _dispatch(self, command: str, sender_timestamp: int) -> Optional[str]:
        reply = self._radio_command(command)
        if reply is not None:
            return reply

        hook: Optional[CliCommandHook] = getattr(self._companion, "cli_command_hook", None)
        if hook is not None:
            reply = hook(command, sender_timestamp)
            if reply is not None:
                return reply

        return self._builtin_command(command)

    def _radio_command(self, command: str) -> Optional[str]:
        c = self._companion
        prefs = c.get_self_info()

        if command == "get radio":
            return (
                f"> {ftoa(prefs.frequency_hz / 1e6)},{ftoa3(prefs.bandwidth_hz / 1e3)},"
                f"{prefs.spreading_factor},{prefs.coding_rate}"
            )
        if command.startswith("set radio "):
            return self._set_radio(command[10:])

        if command == "get freq":
            return f"> {ftoa(prefs.frequency_hz / 1e6)}"

        if command == "get af":
            return f"> {ftoa(prefs.airtime_factor)}"
        if command.startswith("set af "):
            af = _atof(command[7:])
            # Firmware lets NaN through both comparisons and stores it; refusing
            # it here is deliberate.
            if af is None or math.isnan(af) or af < 0 or af > 9:
                return "ERROR: af must be 0-9"
            c.set_tuning_params(prefs.rx_delay_base, af)
            return "OK"

        if command == "get dutycycle":
            return f"> {self._duty_cycle_text(prefs.airtime_factor)}"
        if command.startswith("set dutycycle "):
            dc = _atof(command[14:]) or 0.0
            if math.isnan(dc) or dc < 1 or dc > 100:  # NaN: see `set af`
                return "ERROR: dutycycle must be 1-100"
            # Firmware computes in float32 at every step; the rounding decides
            # the reply (`set dutycycle 45` answers "OK - 44.10%").
            af = _float32(_float32(100.0 / dc) - 1.0)
            c.set_tuning_params(prefs.rx_delay_base, af)
            return f"OK - {self._duty_cycle_text(c.get_self_info().airtime_factor)}"

        if command.startswith("get tx") and command[6:7] in ("", " "):
            return f"> {prefs.tx_power_dbm}"
        if command.startswith("set tx "):
            # Firmware passes atoi() through a uint8_t into the int8_t pref.
            dbm = _int8(_atoi(command[7:]))
            if not c.supports_tx_power_mutation() or not c.set_tx_power(dbm):
                return UNSUPPORTED
            return "OK"

        if command == "get cad":
            cad = c.get_cad_enabled()
            if cad is None:
                return UNSUPPORTED
            return f"> {'on' if cad else 'off'}"
        if command.startswith("set cad "):
            # memcmp(value, "on", 2): "onion" is on, "ON" and anything else off.
            if not c.set_cad_enabled(command[8:10] == "on"):
                return UNSUPPORTED
            return "OK"

        if command == "get rxdelay":
            return f"> {ftoa(prefs.rx_delay_base)}"
        if command.startswith("set rxdelay "):
            delay = _atof(command[12:]) or 0.0
            if not 0 <= delay <= 20.0:
                return "Error, must be 0-20"
            c.set_tuning_params(delay, prefs.airtime_factor)
            return "OK"

        if command == "get path.hash.mode":
            return f"> {prefs.path_hash_mode}"
        if command.startswith("set path.hash.mode "):
            mode = _atoi(command[19:]) & 0xFF
            if mode >= 3:
                return "Error, must be 0,1, or 2"
            c.set_path_hash_mode(mode)
            return "OK"

        if command == "get multi.acks":
            return f"> {prefs.multi_acks}"
        if command.startswith("set multi.acks "):
            c.set_other_params(
                prefs.manual_add_contacts,
                prefs.telemetry_mode_base
                | (prefs.telemetry_mode_location << 2)
                | (prefs.telemetry_mode_environment << 4),
                prefs.advert_loc_policy,
                _atoi(command[15:]) & 0xFF,
            )
            return "OK"

        for key in _UNSUPPORTED_RADIO_KEYS:
            if command == f"get {key}" or command.startswith(f"set {key} "):
                return UNSUPPORTED

        return None

    def _set_radio(self, args: str) -> str:
        c = self._companion
        parts = args.split(",")[:4]
        freq = (_atof(parts[0]) if len(parts) > 0 else None) or 0.0
        bw = (_atof(parts[1]) if len(parts) > 1 else None) or 0.0
        sf = (_atoi(parts[2]) if len(parts) > 2 else 0) & 0xFF
        cr = (_atoi(parts[3]) if len(parts) > 3 else 0) & 0xFF
        if not (150.0 <= freq <= 2500.0 and 5 <= sf <= 12 and 5 <= cr <= 8 and 7.0 <= bw <= 500.0):
            return "Error, invalid radio params"
        if not c.supports_radio_params_mutation():
            return UNSUPPORTED
        # Stored, not applied: the firmware CLI never retunes live.
        # Whole kHz, the frame protocol's resolution (CMD_SET_RADIO_PARAMS), so
        # float32 noise in the parsed MHz never reaches the stored Hz.
        if not c.stage_radio_params(round(freq * 1e3) * 1000, round(bw * 1e3), sf, cr):
            return UNSUPPORTED
        return "OK - reboot to apply"

    @staticmethod
    def _duty_cycle_text(airtime_factor: float) -> str:
        # Float32 throughout, as firmware; the tenths can come out as "10".
        dc = _float32(100.0 / _float32(_float32(airtime_factor) + 1.0))
        whole = int(dc)
        tenths = int(_float32(_float32((dc - whole) * 10.0) + 0.5))
        return f"{whole}.{tenths}%"

    def _builtin_command(self, command: str) -> Optional[str]:
        c = self._companion

        # A Python companion cannot power itself off; a host that can answers
        # these through ``cli_command_hook``.
        if command in ("poweroff", "shutdown"):
            return UNSUPPORTED
        # Firmware reboots and never replies. Here a reboot reloads the settings
        # and a frame server drops its client; the reply stays empty.
        if command == "reboot":
            c.request_reboot()
            self._rebooted = True
            return ""

        if command.startswith("set name "):
            name = command[9:]
            if not is_valid_node_name(name):
                return "Error, bad chars"
            c.set_advert_name(name)
            return "OK"
        if command == "get name":
            return f"> {c.get_self_info().node_name}"

        if command.startswith("set pin "):
            pin = _atoi(command[8:]) & 0xFFFFFFFF
            c.set_device_pin(pin)
            signed = pin - (1 << 32) if pin & 0x80000000 else pin
            return f"> pin is now {signed:06d}"

        if command == "board":
            return self.manufacturer
        if command == "ver":
            return self.version_text

        if command == "get tz.offset":
            return f"> {c.get_self_info().tz_offset}"
        if command.startswith("set tz.offset "):
            value = _atof(command[14:]) or 0.0
            # Firmware converts to int8_t, which is undefined outside its range;
            # anything not finite or out of range is refused.
            tz = int(value) if math.isfinite(value) else 99
            if tz < -12 or tz > 14:
                return "Error, must be from -12 to +14"
            c.set_tz_offset(tz)
            return "OK"

        return None
