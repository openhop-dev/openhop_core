"""
Wire-protocol constants and framing helpers shared by USBLoRaRadio and
TCPLoRaRadio.

Mirrors the on-the-wire format defined in the openHop Modem firmware
(`firmware/include/protocol.h`). Keep this file and the firmware header
in sync — every command code, struct layout, CRC vector and sync byte
must match bit-for-bit, otherwise both drivers will silently lose frames.

Frame format:

    SYNC (0xAA) | CMD (1B) | LEN (2B LE) | PAYLOAD (0..N B) | CRC-16/CCITT (2B LE)

CRC is computed over `CMD + LEN + PAYLOAD` (the SYNC byte is excluded);
polynomial 0x1021, initial 0xFFFF, no reflect, no xor-out (CRC-16/CCITT-FALSE).
"""

import struct

# ─── Framing ─────────────────────────────────────────────────────────
PROTO_SYNC = 0xAA

# Maximum LoRa payload size accepted by the firmware (single-byte LEN
# optimisation in the modem's RX buffer). The wire LEN field itself is
# u16, so the framing helpers below handle anything that fits in 65535 B.
MAX_LORA_PAYLOAD = 255

# ─── Host → Modem ────────────────────────────────────────────────────
CMD_TX_REQUEST = 0x01
CMD_SET_CONFIG = 0x10
CMD_GET_CONFIG = 0x11
CMD_STATUS_REQ = 0x20
CMD_NOISE_REQ = 0x22
CMD_CAD_REQUEST = 0x30
CMD_RX_START = 0x31
CMD_SET_CAD_PARAMS = 0x34  # v0.5.4
CMD_GET_RF_CAPS = 0x14  # v0.8
CMD_SET_AGC_INTERVAL = 0x16  # v0.8 — uint16 LE seconds; 0 disables
CMD_GET_AGC_INTERVAL = 0x17  # v0.8
CMD_SET_FEM_STATE = 0x19  # v0.8 — apply mask + value mask
CMD_GET_FEM_STATE = 0x1A  # v0.8
CMD_SET_RX_BOOST = 0x1C  # v0.8 — 0 power-saving, 1 boosted
CMD_GET_RX_BOOST = 0x1D  # v0.8
CMD_SET_WIFI = 0x41  # v0.5
CMD_AUTH = 0x50
CMD_WIFI_RESET = 0x60
CMD_GET_WIFI = 0x61  # v0.5
CMD_GET_VERSION = 0x70  # v0.5.3
CMD_PING = 0xFF

# ─── Modem → Host ────────────────────────────────────────────────────
CMD_TX_DONE = 0x02
CMD_TX_FAIL = 0x03
CMD_RX_PACKET = 0x04
CMD_CONFIG_RESP = 0x12
CMD_STATUS_RESP = 0x21
CMD_NOISE_RESP = 0x23
CMD_CAD_RESP = 0x32
CMD_RX_STARTED = 0x33
CMD_CAD_PARAMS_RESP = 0x35  # v0.5.4
CMD_RF_CAPS_RESP = 0x15  # v0.8 — uint32 LE capability bits
CMD_AGC_INTERVAL_RESP = 0x18  # v0.8 — uint16 LE effective seconds
CMD_FEM_STATE_RESP = 0x1B  # v0.8 — capability mask + value mask
CMD_RX_BOOST_RESP = 0x1E  # v0.8 — 0 power-saving, 1 boosted
CMD_AUTH_OK = 0x51
CMD_WIFI_STATUS = 0x62  # v0.5
CMD_VERSION_RESP = 0x71  # v0.5.3
CMD_ERROR = 0xFE
CMD_PONG = 0xFF

# ─── Error codes (CMD_ERROR payload[0]) ──────────────────────────────
ERR_CRC_MISMATCH = 0x01
ERR_INVALID_CMD = 0x02
ERR_RADIO_BUSY = 0x03
ERR_TX_TIMEOUT = 0x04
ERR_PAYLOAD_TOO_BIG = 0x05
ERR_INVALID_CONFIG = 0x06
ERR_CAD_FAILED = 0x07
ERR_RADIO_INIT = 0x08
ERR_UNAUTHORIZED = 0x09
# Firmware auto-CAD (CMD_SET_AUTO_CAD) refused a TX because the channel was
# busy after all its retries. LBT feedback, not a failure: the host retries
# within its own LBT time budget.
ERR_CHANNEL_BUSY = 0x0E
ERR_NO_RADIO = 0x0B
ERR_UNSUPPORTED = 0x0F  # v0.8 — command known, control absent on this board
ERR_RADIO_FAULT = 0x10  # v0.8 — RX boost rollback or RX restart failed

# RF capability bits in CMD_RF_CAPS_RESP (uint32 LE).
RF_CAP_AGC = 1 << 0
RF_CAP_FEM_RX_LNA = 1 << 1
RF_CAP_FEM_TX_PA = 1 << 2
RF_CAP_RX_BOOSTED_GAIN = 1 << 3

# FEM apply/value masks. Not the same bits as RF_CAP_*.
FEM_STATE_RX_LNA = 1 << 0
FEM_STATE_TX_PA = 1 << 1

# Frame AGC interval: 0 disables, 1-second steps. Above this is ERR_INVALID_CONFIG.
AGC_INTERVAL_MAX_SEC = 3600

# ─── WIFI_STATUS mode codes ──────────────────────────────────────────
# Matches firmware main.cpp::buildWifiStatusPayload
WIFI_MODE_OFFLINE = 0
WIFI_MODE_STA_CONNECTING = 1
WIFI_MODE_STA_CONNECTED = 2
WIFI_MODE_AP_CONFIG = 3

# ─── Packed struct layouts ───────────────────────────────────────────
# RadioConfig (14 B): freq_hz(u32) | bandwidth_hz(u32) | sf(u8) | cr(u8)
#                     | power_dbm(i8) | syncword(u16) | preamble_len(u8)
RADIO_CONFIG_FMT = "<IIBBbHB"
RADIO_CONFIG_SIZE = struct.calcsize(RADIO_CONFIG_FMT)

# StatusResp (24 B): uptime | rx_count | tx_count | crc_errors
#                    | last_rssi | snr×10 | noise×10 | temp_c | radio_state
STATUS_RESP_FMT = "<IIIIhhhbB"
STATUS_RESP_SIZE = struct.calcsize(STATUS_RESP_FMT)

# RadioLib CAD symbol-count encoding used by CMD_SET_CAD_PARAMS.
CAD_SYMBOL_CODES = {1: 0x00, 2: 0x01, 4: 0x02, 8: 0x03, 16: 0x04}


def build_cad_params_payload(cad_symbol_num: int, peak: int, min_val: int) -> bytes:
    """Build the firmware CAD-parameter payload for a supported symbol count."""
    try:
        symbol_code = CAD_SYMBOL_CODES[int(cad_symbol_num)]
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("cad_symbol_num must be one of: 1, 2, 4, 8, 16") from exc
    return bytes([symbol_code, int(peak) & 0xFF, int(min_val) & 0xFF, 0x00])


# ─── Framing helpers ─────────────────────────────────────────────────


def crc16_ccitt(data: bytes) -> int:
    """CRC-16/CCITT-FALSE. Matches the firmware reference implementation."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc <<= 1
            crc &= 0xFFFF
    return crc


def build_frame(cmd: int, payload: bytes = b"") -> bytes:
    """Build a wire frame: SYNC | CMD | LEN | PAYLOAD | CRC.

    Raises ValueError if the payload does not fit in the 16-bit LEN
    field. The firmware caps individual LoRa payloads at
    MAX_LORA_PAYLOAD, but the framing itself accepts anything up to
    0xFFFF — exceeding that is a programming error in the caller.
    """
    length = len(payload)
    if length > 0xFFFF:
        raise ValueError(
            f"payload length {length} exceeds 16-bit LEN field "
            f"(max 65535; firmware caps at MAX_LORA_PAYLOAD={MAX_LORA_PAYLOAD})"
        )
    hdr = struct.pack("<BH", cmd, length)
    crc = crc16_ccitt(hdr + payload)
    return bytes([PROTO_SYNC]) + hdr + payload + struct.pack("<H", crc)


__all__ = [
    "PROTO_SYNC",
    "MAX_LORA_PAYLOAD",
    # Host → Modem
    "CMD_TX_REQUEST",
    "CMD_SET_CONFIG",
    "CMD_GET_CONFIG",
    "CMD_STATUS_REQ",
    "CMD_NOISE_REQ",
    "CMD_CAD_REQUEST",
    "CMD_RX_START",
    "CMD_SET_CAD_PARAMS",
    "CMD_GET_RF_CAPS",
    "CMD_SET_AGC_INTERVAL",
    "CMD_GET_AGC_INTERVAL",
    "CMD_SET_FEM_STATE",
    "CMD_GET_FEM_STATE",
    "CMD_SET_RX_BOOST",
    "CMD_GET_RX_BOOST",
    "CMD_SET_WIFI",
    "CMD_AUTH",
    "CMD_WIFI_RESET",
    "CMD_GET_WIFI",
    "CMD_GET_VERSION",
    "CMD_PING",
    # Modem → Host
    "CMD_TX_DONE",
    "CMD_TX_FAIL",
    "CMD_RX_PACKET",
    "CMD_CONFIG_RESP",
    "CMD_STATUS_RESP",
    "CMD_NOISE_RESP",
    "CMD_CAD_RESP",
    "CMD_RX_STARTED",
    "CMD_CAD_PARAMS_RESP",
    "CMD_RF_CAPS_RESP",
    "CMD_AGC_INTERVAL_RESP",
    "CMD_FEM_STATE_RESP",
    "CMD_RX_BOOST_RESP",
    "CMD_AUTH_OK",
    "CMD_WIFI_STATUS",
    "CMD_VERSION_RESP",
    "CMD_ERROR",
    "CMD_PONG",
    # Errors
    "ERR_CRC_MISMATCH",
    "ERR_INVALID_CMD",
    "ERR_RADIO_BUSY",
    "ERR_TX_TIMEOUT",
    "ERR_PAYLOAD_TOO_BIG",
    "ERR_INVALID_CONFIG",
    "ERR_CAD_FAILED",
    "ERR_RADIO_INIT",
    "ERR_UNAUTHORIZED",
    "ERR_CHANNEL_BUSY",
    "ERR_NO_RADIO",
    "ERR_UNSUPPORTED",
    "ERR_RADIO_FAULT",
    "RF_CAP_AGC",
    "RF_CAP_FEM_RX_LNA",
    "RF_CAP_FEM_TX_PA",
    "RF_CAP_RX_BOOSTED_GAIN",
    "FEM_STATE_RX_LNA",
    "FEM_STATE_TX_PA",
    "AGC_INTERVAL_MAX_SEC",
    # WIFI_STATUS modes
    "WIFI_MODE_OFFLINE",
    "WIFI_MODE_STA_CONNECTING",
    "WIFI_MODE_STA_CONNECTED",
    "WIFI_MODE_AP_CONFIG",
    # Structs
    "RADIO_CONFIG_FMT",
    "RADIO_CONFIG_SIZE",
    "STATUS_RESP_FMT",
    "STATUS_RESP_SIZE",
    "CAD_SYMBOL_CODES",
    # Framing
    "crc16_ccitt",
    "build_frame",
    "build_cad_params_payload",
]
