"""Byte-pinning tests for the shared CayenneLPP encoder.

Values are pinned against MeshCore's vendored CayenneLPP library, which scales
by a per-type integer multiplier in single-precision float and truncates toward
zero, then stores the result MSB-first (signed types as two's complement).
"""

from openhop_core.protocol.cayenne_lpp import (
    LPP_BAROMETRIC_PRESSURE,
    LPP_DIRECTION,
    LPP_LUMINOSITY,
    LPP_PERCENTAGE,
    LPP_RELATIVE_HUMIDITY,
    LPP_TEMPERATURE,
    LPP_VOLTAGE,
    TELEM_CHANNEL_SELF,
    encode_barometric_pressure,
    encode_direction,
    encode_luminosity,
    encode_percentage,
    encode_relative_humidity,
    encode_temperature,
    encode_voltage,
)


def test_type_codes_match_firmware():
    assert LPP_VOLTAGE == 0x74
    assert LPP_TEMPERATURE == 0x67
    assert LPP_RELATIVE_HUMIDITY == 0x68
    assert LPP_BAROMETRIC_PRESSURE == 0x73
    assert LPP_LUMINOSITY == 0x65
    assert LPP_PERCENTAGE == 0x78
    assert LPP_DIRECTION == 0x84
    assert TELEM_CHANNEL_SELF == 1


def test_voltage_float32_truncation():
    # 4.2 V: 4.2f * 100 = 419.99998 -> 419 (0x01A3), not 420. This is the
    # single-precision truncation the firmware exhibits.
    assert encode_voltage(TELEM_CHANNEL_SELF, 4.2) == bytes([0x01, 0x74, 0x01, 0xA3])
    # 3.7 V -> 370 (0x0172).
    assert encode_voltage(TELEM_CHANNEL_SELF, 3.7) == bytes([0x01, 0x74, 0x01, 0x72])
    # 12.6 V -> 1260 (0x04EC).
    assert encode_voltage(TELEM_CHANNEL_SELF, 12.6) == bytes([0x01, 0x74, 0x04, 0xEC])


def test_voltage_zero_floor():
    assert encode_voltage(TELEM_CHANNEL_SELF, 0.0) == bytes([0x01, 0x74, 0x00, 0x00])


def test_temperature_signed_two_bytes():
    # 21.5 C -> 215 (0x00D7); 0.1 C/LSB, signed 2 bytes.
    assert encode_temperature(2, 21.5) == bytes([0x02, 0x67, 0x00, 0xD7])
    # -5.5 C -> abs 55, two's complement 0xFFC9.
    assert encode_temperature(2, -5.5) == bytes([0x02, 0x67, 0xFF, 0xC9])
    # 0 C -> 0x0000.
    assert encode_temperature(3, 0.0) == bytes([0x03, 0x67, 0x00, 0x00])


def test_relative_humidity_single_byte():
    # 55.0 % -> 110 (0x6E); 0.5 %/LSB, unsigned 1 byte.
    assert encode_relative_humidity(2, 55.0) == bytes([0x02, 0x68, 0x6E])
    # 48.5 % -> 97 (0x61).
    assert encode_relative_humidity(2, 48.5) == bytes([0x02, 0x68, 0x61])
    # 100 % -> 200 (0xC8), the unsigned byte max region.
    assert encode_relative_humidity(4, 100.0) == bytes([0x04, 0x68, 0xC8])


def test_barometric_pressure_unsigned_two_bytes():
    # 1013.25 hPa -> 10132 (0x2794); 0.1 hPa/LSB, unsigned 2 bytes.
    assert encode_barometric_pressure(2, 1013.25) == bytes([0x02, 0x73, 0x27, 0x94])
    # 1021.46 hPa: 1021.46f * 10f truncates to 10214 (0x27E6), not 10215.
    assert encode_barometric_pressure(2, 1021.46) == bytes([0x02, 0x73, 0x27, 0xE6])
    # 1025.94 hPa -> 10259 (0x2813).
    assert encode_barometric_pressure(1, 1025.94) == bytes([0x01, 0x73, 0x28, 0x13])


def test_luminosity_unsigned_two_bytes():
    # 1 lux/LSB, unsigned 2 bytes (firmware LPP_LUMINOSITY).
    assert encode_luminosity(3, 800) == bytes([0x03, 0x65, 0x03, 0x20])
    assert encode_luminosity(3, 0) == bytes([0x03, 0x65, 0x00, 0x00])
    # Truncation toward zero, matching the firmware float path.
    assert encode_luminosity(3, 0.9) == bytes([0x03, 0x65, 0x00, 0x00])
    assert encode_luminosity(3, 1234.7) == bytes([0x03, 0x65, 0x04, 0xD2])


def test_luminosity_saturates_instead_of_wrapping():
    # _add_field masks, so an unclamped 70000 would wrap to 4464 (0x1170).
    # The helper must clamp to the 16-bit field's maximum.
    assert encode_luminosity(3, 70000) == bytes([0x03, 0x65, 0xFF, 0xFF])
    assert encode_luminosity(3, -5) == bytes([0x03, 0x65, 0x00, 0x00])


def test_percentage_single_byte():
    # 1 %/LSB, unsigned 1 byte (firmware LPP_PERCENTAGE).
    assert encode_percentage(4, 55) == bytes([0x04, 0x78, 0x37])
    assert encode_percentage(4, 100) == bytes([0x04, 0x78, 0x64])
    assert encode_percentage(4, 0) == bytes([0x04, 0x78, 0x00])


def test_percentage_clamps_to_0_100():
    # One byte of room: 250 would encode as 0xFA, i.e. 250 %, which no client
    # can interpret. Clamp to 100 instead.
    assert encode_percentage(4, 250) == bytes([0x04, 0x78, 0x64])
    assert encode_percentage(4, -10) == bytes([0x04, 0x78, 0x00])


def test_direction_is_modular():
    # 1 deg/LSB, unsigned 2 bytes (firmware LPP_DIRECTION).
    assert encode_direction(5, 90) == bytes([0x05, 0x84, 0x00, 0x5A])
    assert encode_direction(5, 359) == bytes([0x05, 0x84, 0x01, 0x67])
    # Bearings wrap rather than clamp: 360 -> 0, 450 -> 90.
    assert encode_direction(5, 360) == bytes([0x05, 0x84, 0x00, 0x00])
    assert encode_direction(5, 450) == bytes([0x05, 0x84, 0x00, 0x5A])
    # Truncation, not rounding: 359.9 -> 359.
    assert encode_direction(5, 359.9) == bytes([0x05, 0x84, 0x01, 0x67])
