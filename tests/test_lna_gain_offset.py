"""External front-end LNA gain compensation.

Boards built around modules such as the Ebyte E22P, or front ends like the
SKY66122, put an LNA between the antenna and the SX1262. The chip has no way to
know it is there, so every RSSI it reports is inflated by that LNA's gain. These
tests pin the compensation down: RSSI figures move, SNR does not, and a board
that declares no front end behaves exactly as before.
"""

from unittest.mock import MagicMock

import pytest

from openhop_core.hardware.sx1262_wrapper import SX1262Radio

# raw register 190 -> -(190/2) = -95.0 dBm measured at the chip
RAW_RSSI_MINUS_95 = 190


def _prime_for_noise_sample(radio: SX1262Radio, raw_rssi: int) -> SX1262Radio:
    """Satisfy the idle-window guards so _sample_noise_floor() takes a sample."""
    lora = MagicMock()
    lora.getRssiInst.return_value = raw_rssi
    lora.getIrqStatus.return_value = 0
    for flag in (
        "IRQ_PREAMBLE_DETECTED",
        "IRQ_HEADER_VALID",
        "IRQ_RX_DONE",
        "IRQ_CRC_ERR",
        "IRQ_HEADER_ERR",
    ):
        setattr(lora, flag, 0)
    radio.lora = lora
    radio._initialized = True
    radio._is_receiving_packet = False
    radio._pending_rx_irq_status = None
    radio._last_sample_check = 0.0
    radio._last_packet_activity = 0.0
    return radio


def test_defaults_to_zero_so_existing_boards_are_unaffected():
    assert SX1262Radio().lna_gain_db == 0.0


def test_gain_is_coerced_to_float():
    assert isinstance(SX1262Radio(lna_gain_db=16).lna_gain_db, float)
    assert SX1262Radio(lna_gain_db=14.5).lna_gain_db == pytest.approx(14.5)


def test_noise_floor_is_referred_back_to_the_antenna():
    radio = _prime_for_noise_sample(SX1262Radio(lna_gain_db=14.5), RAW_RSSI_MINUS_95)
    radio._sample_noise_floor()
    assert radio.get_noise_floor() == pytest.approx(-109.5)


def test_noise_floor_unchanged_when_no_front_end_is_declared():
    radio = _prime_for_noise_sample(SX1262Radio(), RAW_RSSI_MINUS_95)
    radio._sample_noise_floor()
    assert radio.get_noise_floor() == pytest.approx(-95.0)


def test_negative_offset_is_allowed_for_known_feedline_loss():
    radio = _prime_for_noise_sample(SX1262Radio(lna_gain_db=-3.0), RAW_RSSI_MINUS_95)
    radio._sample_noise_floor()
    assert radio.get_noise_floor() == pytest.approx(-92.0)


def test_status_reports_the_declared_gain():
    assert SX1262Radio(lna_gain_db=14.5).get_status()["lna_gain_db"] == pytest.approx(14.5)


def test_snr_is_not_offset_because_gain_cancels_in_a_ratio():
    """A front-end LNA raises signal and noise together, so SNR is unchanged."""
    radio = SX1262Radio(lna_gain_db=14.5)
    radio.last_snr = 7.5
    assert radio.get_last_snr() == pytest.approx(7.5)
