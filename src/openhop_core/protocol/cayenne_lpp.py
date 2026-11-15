"""CayenneLPP telemetry encoding, byte-compatible with MeshCore's vendored
CayenneLPP library (.pio/libdeps/.../CayenneLPP).

Firmware seeds telemetry with a battery-voltage entry and appends per-sensor
entries via ``CayenneLPP::addField`` (CayenneLPP.cpp). The value is scaled by a
per-type integer multiplier computed entirely in single-precision float and then
truncated toward zero, so a value like 4200 mV becomes ``4.2f * 100 = 419.99998
-> 419`` (0x01A3). That float rounding is reproduced here so the encoded bytes
match the firmware exactly.
"""

import struct

# LPP type codes, byte sizes and multipliers (CayenneLPP.h).
LPP_TEMPERATURE = 0x67  # 103: 2 bytes, 0.1 C/LSB, signed
LPP_RELATIVE_HUMIDITY = 0x68  # 104: 1 byte, 0.5 %/LSB, unsigned
LPP_BAROMETRIC_PRESSURE = 0x73  # 115: 2 bytes, 0.1 hPa/LSB, unsigned
LPP_VOLTAGE = 0x74  # 116: 2 bytes, 0.01 V/LSB, unsigned
LPP_CURRENT = 0x75  # 117: 2 bytes, 0.001 A/LSB, signed
LPP_POWER = 0x80  # 128: 2 bytes, 1 W/LSB, unsigned
LPP_PERCENTAGE = 0x78  # 120: 1 byte, 1 %/LSB, unsigned (max 100)
LPP_LUMINOSITY = 0x65  # 101: 2 bytes, 1 lux/LSB, unsigned
LPP_DIRECTION = 0x84  # 132: 2 bytes, 1 deg/LSB, unsigned
# LPP data channel for the 'self' device (SensorManager.h:10).
TELEM_CHANNEL_SELF = 1

# Back-compat aliases for existing importers.
LPP_VOLTAGE_TYPE = LPP_VOLTAGE
LPP_VOLTAGE_MULT = 100

# type -> (size_bytes, multiplier, is_signed)
_LPP_TYPES = {
    LPP_TEMPERATURE: (2, 10, True),
    LPP_RELATIVE_HUMIDITY: (1, 2, False),
    LPP_BAROMETRIC_PRESSURE: (2, 10, False),
    LPP_VOLTAGE: (2, 100, False),
    LPP_CURRENT: (2, 1000, True),
    LPP_POWER: (2, 1, False),
    LPP_PERCENTAGE: (1, 1, False),
    LPP_LUMINOSITY: (2, 1, False),
    LPP_DIRECTION: (2, 1, False),
}


def _f32(value: float) -> float:
    """Round a Python double to IEEE-754 single precision (C ``float``)."""
    return struct.unpack("<f", struct.pack("<f", value))[0]


def _add_field(channel: int, lpp_type: int, value: float) -> bytes:
    """Encode one CayenneLPP entry the way ``CayenneLPP::addField`` does.

    The multiplier is applied in single-precision float and truncated toward
    zero; signed types store the two's-complement of the magnitude (matching
    the firmware's ``mask - v + 1`` path). Bytes are MSB-first.
    """
    size, multiplier, is_signed = _LPP_TYPES[lpp_type]
    sign = value < 0
    if sign:
        value = -value
    v = int(_f32(_f32(value) * _f32(multiplier)))
    mask = (1 << (size * 8)) - 1
    if is_signed and sign:
        v = (mask - (v & mask) + 1) & mask
    else:
        v &= mask
    return bytes([channel & 0xFF, lpp_type & 0xFF]) + v.to_bytes(size, "big")


def encode_voltage(channel: int, volts: float) -> bytes:
    """Encode a voltage entry (LPP_VOLTAGE, 0.01 V/LSB, unsigned)."""
    return _add_field(channel, LPP_VOLTAGE, volts)


def encode_current(channel: int, amps: float) -> bytes:
    """Encode a current entry (LPP_CURRENT, 0.001 A/LSB, signed)."""
    return _add_field(channel, LPP_CURRENT, amps)


def encode_power(channel: int, watts: int) -> bytes:
    """Encode a power entry (LPP_POWER, 1 W/LSB, unsigned)."""
    return _add_field(channel, LPP_POWER, watts)


def encode_temperature(channel: int, celsius: float) -> bytes:
    """Encode a temperature entry (LPP_TEMPERATURE, 0.1 C/LSB, signed)."""
    return _add_field(channel, LPP_TEMPERATURE, celsius)


def encode_relative_humidity(channel: int, percent: float) -> bytes:
    """Encode a relative-humidity entry (LPP_RELATIVE_HUMIDITY, 0.5 %/LSB)."""
    return _add_field(channel, LPP_RELATIVE_HUMIDITY, percent)


def encode_barometric_pressure(channel: int, hpa: float) -> bytes:
    """Encode a barometric-pressure entry (LPP_BAROMETRIC_PRESSURE, 0.1 hPa/LSB)."""
    return _add_field(channel, LPP_BAROMETRIC_PRESSURE, hpa)


def encode_percentage(channel: int, percent: float) -> bytes:
    """Encode a percentage entry (LPP_PERCENTAGE, 1 %/LSB, unsigned).

    Clamped to 0-100: the field is one byte and an unclamped value would wrap
    through the mask rather than saturate.
    """
    return _add_field(channel, LPP_PERCENTAGE, max(0.0, min(100.0, float(percent))))


def encode_luminosity(channel: int, lux: float) -> bytes:
    """Encode an illuminance entry (LPP_LUMINOSITY, 1 lux/LSB, unsigned).

    Clamped to the 16-bit field so an out-of-range reading saturates instead of
    wrapping.
    """
    return _add_field(channel, LPP_LUMINOSITY, max(0.0, min(65535.0, float(lux))))


def encode_direction(channel: int, degrees: float) -> bytes:
    """Encode a bearing entry (LPP_DIRECTION, 1 deg/LSB, unsigned).

    Bearings are modular, so the value wraps into 0-360 rather than clamping.
    """
    return _add_field(channel, LPP_DIRECTION, float(degrees) % 360.0)

