"""Companion radio constants for application-layer mesh networking features."""

from __future__ import annotations

import base64
from enum import IntEnum

# Wire-level values shared with the node/protocol layers live in
# protocol.constants; they are re-exported here so existing
# ``openhop_core.companion.constants`` imports keep working.
from ..protocol.constants import ANON_REQ_TYPE_BASIC  # noqa: F401
from ..protocol.constants import ANON_REQ_TYPE_OWNER  # noqa: F401
from ..protocol.constants import ANON_REQ_TYPE_REGIONS  # noqa: F401
from ..protocol.constants import CIPHER_BLOCK_SIZE  # noqa: F401
from ..protocol.constants import MAX_PACKET_PAYLOAD  # noqa: F401
from ..protocol.constants import MAX_PATH_SIZE  # noqa: F401
from ..protocol.constants import PUB_KEY_SIZE  # noqa: F401
from ..protocol.constants import TXT_TYPE_CLI_COMMAND  # noqa: F401
from ..protocol.constants import TXT_TYPE_CLI_DATA  # noqa: F401
from ..protocol.constants import TXT_TYPE_PLAIN  # noqa: F401
from ..protocol.constants import TXT_TYPE_SIGNED_PLAIN  # noqa: F401

# ---------------------------------------------------------------------------
# ADV Types (contact/node classification)
# ---------------------------------------------------------------------------
# transient/anon contact (non-contact request), never persisted/synced
ADV_TYPE_NONE = 0
ADV_TYPE_CHAT = 1
ADV_TYPE_REPEATER = 2
ADV_TYPE_ROOM = 3
ADV_TYPE_SENSOR = 4

# Max number of transient (ADV_TYPE_NONE) anon-request contacts kept at once.
# Mirrors firmware MAX_ANON_CONTACTS (BaseChatMesh.h).
MAX_ANON_CONTACTS = 8

# ---------------------------------------------------------------------------
# Text Types: TXT_TYPE_PLAIN / _CLI_DATA / _SIGNED_PLAIN / _CLI_COMMAND are
# defined in protocol.constants (wire values shared with node.handlers.text)
# and re-exported at the top of this module.
# ---------------------------------------------------------------------------

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
# Anonymous request sub-types: ANON_REQ_TYPE_REGIONS / _OWNER / _BASIC are
# defined in protocol.constants (wire values shared with node.handlers) and
# re-exported at the top of this module. Note they collide numerically with
# BinaryReqType values, so anon responses must be disambiguated by sub-type.
# ---------------------------------------------------------------------------
# Feature flags in the ANON_REQ_TYPE_BASIC response (byte after the clock).
# The firmware writes these inline (simple_repeater/MyMesh.cpp
# handleAnonClockReq): bits 0-1 are a bridge-type field, bit 7 is set while
# the repeater has forwarding disabled.
# ---------------------------------------------------------------------------
ANON_BASIC_FEAT_BRIDGE_MASK = 0x03  # bridge-type field (0 = no bridge)
ANON_BASIC_FEAT_BRIDGE_UART = 0x01  # RS232/UART bridge
ANON_BASIC_FEAT_BRIDGE_ESPNOW = 0x03  # ESP-NOW bridge
ANON_BASIC_FEAT_DISABLED = 0x80  # repeater forwarding disabled

# ---------------------------------------------------------------------------
# Default configuration
# ---------------------------------------------------------------------------
DEFAULT_RESPONSE_TIMEOUT_MS = 10000
DEFAULT_MAX_CONTACTS = 1000
DEFAULT_OFFLINE_QUEUE_SIZE = 512
DEFAULT_MAX_CHANNELS = 40
# SELF_INFO always carries a maximum TX-power byte. Backends which own or
# represent a concrete radio should override this generic capability.
DEFAULT_MAX_TX_POWER_DBM = 22
CONTACT_NAME_SIZE = 32
CHANNEL_NAME_SIZE = 32  # channel name field width (CHANNEL_INFO / SET_CHANNEL)
# Firmware `char node_name[32]` (NodePrefs.h); usable bytes exclude the NUL terminator
# (see MyMesh.cpp CMD_SET_ADVERT_NAME: `nlen > sizeof(_prefs.node_name) - 1`).
NODE_NAME_MAX_BYTES = 31
MAX_SIGN_DATA_SIZE = 8192  # 8KB signing buffer (matches firmware)
MAX_PENDING_ACK_CRCS = 64
ZERO_FLOOD_SCOPE_KEY = b"\x00" * 16  # firmware's null scope override (send_scope.isNull())

# Frequencies (kHz) at which client-repeat may be enabled, as inclusive
# (lower, upper) ranges. Mirrors firmware's default ``repeat_freq_ranges``
# (MyMesh.cpp), single-frequency entries for the three default LoRa bands.
# A concrete companion may override this via the ``allowed_repeat_freq_ranges``
# key in its ``radio_config`` dict (list of (lower_khz, upper_khz) pairs).
DEFAULT_ALLOWED_REPEAT_FREQ_RANGES = ((433000, 433000), (869495, 869495), (918000, 918000))

# ---------------------------------------------------------------------------
# Response-timeout hints (ms) returned in RESP_CODE_SENT frames. The firmware
# computes est_timeout per packet (calcFlood/DirectTimeoutMillisFor); the
# virtual companion performs the wait internally and returns fixed hints.
# ---------------------------------------------------------------------------
TXT_MSG_TIMEOUT_HINT_MS = 5000
BINARY_REQ_TIMEOUT_HINT_MS = 10000
LOGIN_TIMEOUT_HINT_MS = 10000
STATUS_TIMEOUT_HINT_MS = 15000
TELEMETRY_TIMEOUT_HINT_MS = 15000
# CMD_SEND_TRACE_PATH returns a per-packet est_timeout computed from the trace
# packet's airtime and hop count (firmware calcDirectTimeoutMillisFor); see
# CompanionBase.send_trace_path_raw. No fixed hint constant is needed.

# ===========================================================================
# Frame Protocol Constants (MeshCore Companion Radio Protocol)
# ===========================================================================

# Protocol version reported in RESP_CODE_DEVICE_INFO; phone uses 9+ to infer
# CMD_SEND_ANON_REQ (owner requests, etc.) is supported.
# 10+ provides support for multi-byte path lengths.
# 11+ adds channel binary datagrams and default flood scope commands.
# 12+ matches the MeshCore dev-branch companion (v1.15.x/1.16.0 family): adds
#     CMD_GET_ALLOWED_REPEAT_FREQ and CMD_SEND_RAW_PACKET.
# 13+ (MeshCore PR #2672, v1.16.0): non-contact CMD_SEND_ANON_REQ — the device
#     creates a transient zero-hop contact for a pubkey not already in contacts.
FIRMWARE_VER_CODE = 13

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
CMD_GET_ALLOWED_REPEAT_FREQ = 60
CMD_SET_PATH_HASH_MODE = 61
CMD_SEND_CHANNEL_DATA = 62
CMD_SET_DEFAULT_FLOOD_SCOPE = 63
CMD_GET_DEFAULT_FLOOD_SCOPE = 64
CMD_SEND_RAW_PACKET = 65

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
RESP_CODE_ALLOWED_REPEAT_FREQ = 26
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
# Error codes (payload of RESP_CODE_ERR). Frame-server convention:
#   ERR_CODE_ILLEGAL_ARG      malformed/short command payload; also the
#                             dispatcher's catch-all for handler exceptions
#   ERR_CODE_NOT_FOUND        unknown contact/channel/resource
#   ERR_CODE_TABLE_FULL       store full or send failure (firmware maps
#                             MSG_SEND_FAILED here, e.g. anon/binary req)
#   ERR_CODE_BAD_STATE        valid request that cannot run right now
#   ERR_CODE_UNSUPPORTED_CMD  unknown command or feature not available
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
# 176 since MeshCore PR #2022 (+4 over the old 172 for region-scoping transport codes).
MAX_FRAME_SIZE = 176
# Firmware writeFrame() accepts up to MAX_FRAME_SIZE payload bytes and writes the
# 3-byte serial prefix (">", len_lsb, len_msb) *in addition*. So the framed
# payload maximum equals MAX_FRAME_SIZE, not MAX_FRAME_SIZE - 3.
MAX_PAYLOAD_SIZE = MAX_FRAME_SIZE
# Firmware companion command parser uses MAX_FRAME_SIZE - 9 for channel binary payloads.
MAX_CHANNEL_DATA_LENGTH = MAX_FRAME_SIZE - 9
# Firmware MeshCore.h: MAX_GROUP_DATA_LENGTH = MAX_PACKET_PAYLOAD - CIPHER_BLOCK_SIZE - 3.
# BaseChatMesh::sendGroupData rejects group application data longer than this.
MAX_GROUP_DATA_LENGTH = MAX_PACKET_PAYLOAD - CIPHER_BLOCK_SIZE - 3
OUT_PATH_UNKNOWN = 0xFF
# PUB_KEY_SIZE and MAX_PATH_SIZE are re-exported from protocol.constants at
# the top of this module.

# ---------------------------------------------------------------------------
# Default public channel PSK (from firmware MeshCore companion_radio example)
# ---------------------------------------------------------------------------
PUBLIC_GROUP_PSK = b"izOH6cXN6mrJ5e26oRXNcg=="
DEFAULT_PUBLIC_CHANNEL_SECRET = base64.b64decode(PUBLIC_GROUP_PSK)
