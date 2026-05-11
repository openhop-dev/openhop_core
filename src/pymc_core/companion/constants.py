"""Companion radio constants for application-layer mesh networking features."""

from __future__ import annotations

import base64
from enum import IntEnum

# ---------------------------------------------------------------------------
# ADV Types (contact/node classification)
# ---------------------------------------------------------------------------
ADV_TYPE_CHAT = 1
ADV_TYPE_REPEATER = 2
ADV_TYPE_ROOM = 3
ADV_TYPE_SENSOR = 4

# ---------------------------------------------------------------------------
# Text Types
# ---------------------------------------------------------------------------
TXT_TYPE_PLAIN = 0
TXT_TYPE_CLI_DATA = 1
TXT_TYPE_SIGNED_PLAIN = 2

# ---------------------------------------------------------------------------
# Telemetry Modes
# ---------------------------------------------------------------------------
TELEM_MODE_DENY = 0
TELEM_MODE_ALLOW_FLAGS = 1
TELEM_MODE_ALLOW_ALL = 2

# ---------------------------------------------------------------------------
# Advert Location Policy
# ---------------------------------------------------------------------------
ADVERT_LOC_NONE = 0
ADVERT_LOC_SHARE = 1

# ---------------------------------------------------------------------------
# Auto-Add Config Bitmask
# ---------------------------------------------------------------------------
AUTOADD_OVERWRITE_OLDEST = 0x01
AUTOADD_CHAT = 0x02
AUTOADD_REPEATER = 0x04
AUTOADD_ROOM = 0x08
AUTOADD_SENSOR = 0x10

# ---------------------------------------------------------------------------
# Message Send Result
# ---------------------------------------------------------------------------
MSG_SEND_FAILED = 0
MSG_SEND_SENT_FLOOD = 1
MSG_SEND_SENT_DIRECT = 2

# ---------------------------------------------------------------------------
# Stats Types
# ---------------------------------------------------------------------------
STATS_TYPE_CORE = 0
STATS_TYPE_RADIO = 1
STATS_TYPE_PACKETS = 2


# ---------------------------------------------------------------------------
# Binary request types (CMD_SEND_BINARY_REQ / PUSH_CODE_BINARY_RESPONSE)
# ---------------------------------------------------------------------------
class BinaryReqType(IntEnum):
    """Binary request type codes (companion frame protocol)."""

    STATUS = 0x01
    KEEP_ALIVE = 0x02
    TELEMETRY = 0x03
    MMA = 0x04
    ACL = 0x05
    NEIGHBOURS = 0x06
    OWNER_INFO = 0x07  # REQ_TYPE_GET_OWNER_INFO: variable "version\nname\nowner"


# ---------------------------------------------------------------------------
# Protocol Codes (used in create_protocol_request / send_protocol_request)
# ---------------------------------------------------------------------------
PROTOCOL_CODE_RAW_DATA = 0x00
PROTOCOL_CODE_BINARY_REQ = 0x02
PROTOCOL_CODE_ANON_REQ = 0x07

# ---------------------------------------------------------------------------
# Default configuration
# ---------------------------------------------------------------------------
DEFAULT_RESPONSE_TIMEOUT_MS = 10000
DEFAULT_MAX_CONTACTS = 1000
DEFAULT_OFFLINE_QUEUE_SIZE = 512
DEFAULT_MAX_CHANNELS = 40
CONTACT_NAME_SIZE = 32
MAX_SIGN_DATA_SIZE = 8192  # 8KB signing buffer (matches firmware)
MAX_PENDING_ACK_CRCS = 64

# ===========================================================================
# Frame Protocol Constants (MeshCore Companion Radio Protocol)
# ===========================================================================

# Protocol version reported in RESP_CODE_DEVICE_INFO; phone uses 9+ to infer
# CMD_SEND_ANON_REQ (owner requests, etc.) is supported.
# 10+ provides support for multi-byte path lengths.
# 11+ adds channel binary datagrams and default flood scope commands.
FIRMWARE_VER_CODE = 10

# ---------------------------------------------------------------------------
# Commands (app -> radio)
# ---------------------------------------------------------------------------
CMD_APP_START = 1
CMD_SEND_TXT_MSG = 2
CMD_SEND_CHANNEL_TXT_MSG = 3
CMD_GET_CONTACTS = 4
CMD_GET_DEVICE_TIME = 5
CMD_SET_DEVICE_TIME = 6
CMD_SEND_SELF_ADVERT = 7
CMD_SET_ADVERT_NAME = 8
CMD_ADD_UPDATE_CONTACT = 9
CMD_SYNC_NEXT_MESSAGE = 10
CMD_SET_RADIO_PARAMS = 11
CMD_SET_RADIO_TX_POWER = 12
CMD_RESET_PATH = 13
CMD_SET_ADVERT_LATLON = 14
CMD_REMOVE_CONTACT = 15
CMD_SHARE_CONTACT = 16
CMD_EXPORT_CONTACT = 17
CMD_IMPORT_CONTACT = 18
CMD_REBOOT = 19
CMD_GET_BATT_AND_STORAGE = 20
CMD_SET_TUNING_PARAMS = 21
CMD_DEVICE_QUERY = 22
CMD_EXPORT_PRIVATE_KEY = 23
CMD_IMPORT_PRIVATE_KEY = 24
CMD_SEND_RAW_DATA = 25
CMD_SEND_LOGIN = 26
CMD_SEND_STATUS_REQ = 27
CMD_HAS_CONNECTION = 28
CMD_LOGOUT = 29
CMD_GET_CONTACT_BY_KEY = 30
CMD_GET_CHANNEL = 31
CMD_SET_CHANNEL = 32
CMD_SIGN_START = 33
CMD_SIGN_DATA = 34
CMD_SIGN_FINISH = 35
CMD_SEND_TRACE_PATH = 36
CMD_SET_DEVICE_PIN = 37
CMD_SET_OTHER_PARAMS = 38
CMD_SEND_TELEMETRY_REQ = 39
CMD_GET_CUSTOM_VARS = 40
CMD_SET_CUSTOM_VAR = 41
CMD_GET_ADVERT_PATH = 42
CMD_GET_TUNING_PARAMS = 43
CMD_SEND_BINARY_REQ = 50
CMD_FACTORY_RESET = 51
CMD_SEND_PATH_DISCOVERY_REQ = 52
CMD_SET_FLOOD_SCOPE = 54
CMD_SEND_CONTROL_DATA = 55
CMD_GET_STATS = 56
CMD_SEND_ANON_REQ = 57
CMD_SET_AUTOADD_CONFIG = 58
CMD_GET_AUTOADD_CONFIG = 59
CMD_SET_PATH_HASH_MODE = 61
CMD_SEND_CHANNEL_DATA = 62
CMD_SET_DEFAULT_FLOOD_SCOPE = 63
CMD_GET_DEFAULT_FLOOD_SCOPE = 64

# ---------------------------------------------------------------------------
# Response codes (radio -> app)
# ---------------------------------------------------------------------------
RESP_CODE_OK = 0
RESP_CODE_ERR = 1
RESP_CODE_CONTACTS_START = 2
RESP_CODE_CONTACT = 3
RESP_CODE_END_OF_CONTACTS = 4
RESP_CODE_SELF_INFO = 5
RESP_CODE_SENT = 6
RESP_CODE_CONTACT_MSG_RECV = 7
RESP_CODE_CHANNEL_MSG_RECV = 8
RESP_CODE_CURR_TIME = 9
RESP_CODE_NO_MORE_MESSAGES = 10
RESP_CODE_EXPORT_CONTACT = 11
RESP_CODE_BATT_AND_STORAGE = 12
RESP_CODE_DEVICE_INFO = 13
RESP_CODE_PRIVATE_KEY = 14
RESP_CODE_DISABLED = 15
RESP_CODE_CONTACT_MSG_RECV_V3 = 16
RESP_CODE_CHANNEL_MSG_RECV_V3 = 17
RESP_CODE_CHANNEL_INFO = 18
RESP_CODE_SIGN_START = 19
RESP_CODE_SIGNATURE = 20
RESP_CODE_CUSTOM_VARS = 21
RESP_CODE_ADVERT_PATH = 22
RESP_CODE_TUNING_PARAMS = 23
RESP_CODE_STATS = 24
RESP_CODE_AUTOADD_CONFIG = 25
RESP_CODE_CHANNEL_DATA_RECV = 27
RESP_CODE_DEFAULT_FLOOD_SCOPE = 28

# ---------------------------------------------------------------------------
# Push codes (radio -> app, unsolicited)
# ---------------------------------------------------------------------------
PUSH_CODE_ADVERT = 0x80
PUSH_CODE_PATH_UPDATED = 0x81
PUSH_CODE_SEND_CONFIRMED = 0x82
PUSH_CODE_MSG_WAITING = 0x83
PUSH_CODE_RAW_DATA = 0x84
PUSH_CODE_LOGIN_SUCCESS = 0x85
PUSH_CODE_LOGIN_FAIL = 0x86
PUSH_CODE_STATUS_RESPONSE = 0x87
PUSH_CODE_LOG_RX_DATA = 0x88
PUSH_CODE_TRACE_DATA = 0x89
PUSH_CODE_NEW_ADVERT = 0x8A
PUSH_CODE_TELEMETRY_RESPONSE = 0x8B
PUSH_CODE_BINARY_RESPONSE = 0x8C
PUSH_CODE_PATH_DISCOVERY_RESPONSE = 0x8D
PUSH_CODE_CONTROL_DATA = 0x8E
PUSH_CODE_CONTACT_DELETED = 0x8F
PUSH_CODE_CONTACTS_FULL = 0x90

# ---------------------------------------------------------------------------
# Error codes
# ---------------------------------------------------------------------------
ERR_CODE_UNSUPPORTED_CMD = 1
ERR_CODE_NOT_FOUND = 2
ERR_CODE_TABLE_FULL = 3
ERR_CODE_BAD_STATE = 4
ERR_CODE_FILE_IO_ERROR = 5
ERR_CODE_ILLEGAL_ARG = 6

# ---------------------------------------------------------------------------
# Frame delimiters (USB/TCP: > = outbound, < = inbound)
# ---------------------------------------------------------------------------
FRAME_OUTBOUND_PREFIX = 0x3E  # '>'
FRAME_INBOUND_PREFIX = 0x3C  # '<'
# Match firmware: writeFrame() refuses to send if len > MAX_FRAME_SIZE; BLE MTU
# is set to this (e.g. BLEDevice::setMTU(MAX_FRAME_SIZE)). Frame = prefix(1) + len(2) + payload.
MAX_FRAME_SIZE = 172
MAX_PAYLOAD_SIZE = MAX_FRAME_SIZE - 3  # max bytes after prefix + 2-byte length
# Firmware companion command parser uses MAX_FRAME_SIZE - 9 for channel binary payloads.
MAX_CHANNEL_DATA_LENGTH = MAX_FRAME_SIZE - 9
OUT_PATH_UNKNOWN = 0xFF
PUB_KEY_SIZE = 32
MAX_PATH_SIZE = 64

# ---------------------------------------------------------------------------
# Default public channel PSK (from firmware MeshCore companion_radio example)
# ---------------------------------------------------------------------------
PUBLIC_GROUP_PSK = b"izOH6cXN6mrJ5e26oRXNcg=="
DEFAULT_PUBLIC_CHANNEL_SECRET = base64.b64decode(PUBLIC_GROUP_PSK)
