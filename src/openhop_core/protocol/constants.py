# protocol_consts.py
"""Mesh protocol constants extracted from the C++ firmware."""

# ---------------------------------------------------------------------------
# Header bit‑field layout
# ---------------------------------------------------------------------------
PH_ROUTE_MASK = 0x03  # bits 0‑1
PH_TYPE_SHIFT = 2
PH_TYPE_MASK = 0x0F  # bits 2‑5 (4 bits)
PH_VER_SHIFT = 6
PH_VER_MASK = 0x03  # bits 6‑7 (2 bits)

# ---------------------------------------------------------------------------
# Route‑type values (2 bits)
# ---------------------------------------------------------------------------
ROUTE_TYPE_TRANSPORT_FLOOD = 0x00
ROUTE_TYPE_FLOOD = 0x01
ROUTE_TYPE_DIRECT = 0x02
ROUTE_TYPE_TRANSPORT_DIRECT = 0x03

# ---------------------------------------------------------------------------
# Payload‑type values (4 bits)
# ---------------------------------------------------------------------------
PAYLOAD_TYPE_REQ = 0x00
PAYLOAD_TYPE_RESPONSE = 0x01
PAYLOAD_TYPE_TXT_MSG = 0x02
PAYLOAD_TYPE_ACK = 0x03
PAYLOAD_TYPE_ADVERT = 0x04
PAYLOAD_TYPE_GRP_TXT = 0x05
PAYLOAD_TYPE_GRP_DATA = 0x06
PAYLOAD_TYPE_ANON_REQ = 0x07
PAYLOAD_TYPE_PATH = 0x08
PAYLOAD_TYPE_TRACE = 0x09
PAYLOAD_TYPE_MULTIPART = 0x0A
PAYLOAD_TYPE_CONTROL = 0x0B
PAYLOAD_TYPE_RAW_CUSTOM = 0x0F

# ---------------------------------------------------------------------------
# Payload version values (2 bits)
# ---------------------------------------------------------------------------
PAYLOAD_VER_1 = 0x00  # Currently supported
PAYLOAD_VER_2 = 0x01  # Reserved for future use
PAYLOAD_VER_3 = 0x02  # Reserved for future use
PAYLOAD_VER_4 = 0x03  # Reserved for future use
# Firmware Dispatcher::tryParsePacket rejects any packet whose payload version
# is greater than PAYLOAD_VER_1 (the only defined layout: 1-byte hashes,
# 2-byte MAC). Versions 2-4 are reserved for future, possibly incompatible,
# wire layouts, so decoding them with the current layout would misparse.
MAX_SUPPORTED_PAYLOAD_VERSION = PAYLOAD_VER_1  # Accept version 0 only

# ---------------------------------------------------------------------------
# Misc sizes
# ---------------------------------------------------------------------------
MAX_ADVERT_DATA_SIZE = 32  # firmware MeshCore.h MAX_ADVERT_DATA_SIZE
PUB_KEY_SIZE = 32
SIGNATURE_SIZE = 64
PATH_HASH_SIZE = 1  # Legacy default; see PathUtils for multi-byte path support
PATH_HASH_COUNT_MASK = 0x3F  # bits 0-5 of encoded path_len (max encodable hop count)
PATH_HASH_SIZE_SHIFT = 6  # bits 6-7 of encoded path_len
CIPHER_MAC_SIZE = 2  # HMAC-SHA256 truncated to 2 bytes for the wire MAC
CIPHER_BLOCK_SIZE = 16
MAX_PACKET_PAYLOAD = 184  # firmware MeshCore.h packet payload cap
MAX_TEXT_LEN = 10 * CIPHER_BLOCK_SIZE  # firmware BaseChatMesh.h message text cap (160)

MAX_PATH_SIZE = 64
MAX_HASH_SIZE = 32  # SHA-256 truncated

NAME_MAX_LEN = 16  # Max length of a contact name

TIMESTAMP_SIZE = 4  # 4 bytes for a timestamp (32-bit unsigned int)
# ---------------------------------------------------------------------------

# Node Advert Flags (bitfield values)
ADVERT_FLAG_IS_CHAT_NODE = 0x01
ADVERT_FLAG_IS_REPEATER = 0x02
ADVERT_FLAG_IS_ROOM_SERVER = 0x03
ADVERT_FLAG_IS_SENSOR = 0x04
ADVERT_FLAG_HAS_LOCATION = 0x10
ADVERT_FLAG_HAS_FEATURE1 = 0x20
ADVERT_FLAG_HAS_FEATURE2 = 0x40
ADVERT_FLAG_HAS_NAME = 0x80


def describe_advert_flags(flags: int) -> str:
    labels = []

    # Extract node type from bits 0-3
    node_type = flags & 0x0F
    if node_type == ADVERT_FLAG_IS_CHAT_NODE:
        labels.append("is chat node")
    elif node_type == ADVERT_FLAG_IS_REPEATER:
        labels.append("is repeater")
    elif node_type == ADVERT_FLAG_IS_ROOM_SERVER:
        labels.append("is room server")
    elif node_type == 0x04:
        labels.append("is sensor")

    # Check feature flags (bits 4-7)
    if flags & ADVERT_FLAG_HAS_LOCATION:
        labels.append("has location")
    if flags & ADVERT_FLAG_HAS_FEATURE1:
        labels.append("has feature 1")
    if flags & ADVERT_FLAG_HAS_FEATURE2:
        labels.append("has feature 2")
    if flags & ADVERT_FLAG_HAS_NAME:
        labels.append("has name")

    return ", ".join(labels) or "none"


# Contact Types (derived from advert flags)
CONTACT_TYPE_UNKNOWN = 0
CONTACT_TYPE_CHAT_NODE = 1
CONTACT_TYPE_REPEATER = 2
CONTACT_TYPE_ROOM_SERVER = 3  # Equivalent to C++ ADV_TYPE_ROOM
CONTACT_TYPE_HYBRID = 4


# Protocol Request Types
REQ_TYPE_GET_STATUS = 0x01  # Get repeater stats (RepeaterStats struct)
REQ_TYPE_GET_TELEMETRY_DATA = 0x03  # Get telemetry data (CayenneLPP)
REQ_TYPE_GET_OWNER_INFO = 0x07  # Variable-length: tag(4) + "version\nname\nowner" (simple_repeater)
TELEM_PERM_BASE = 0x01
TELEM_PERM_LOCATION = 0x02
TELEM_PERM_ENVIRONMENT = 0x04

# ---------------------------------------------------------------------------
# ClientACL roles (firmware src/helpers/ClientACL.h). The role lives in the low
# two bits of the permissions byte; the upper bits are reserved for future
# per-feature flags. These are the *wire* values every stock-firmware client
# decodes, so servers must publish roles using exactly this numbering — note
# that ADMIN is 3, not "the 0x02 bit".
# ---------------------------------------------------------------------------
PERM_ACL_ROLE_MASK = 0x03
PERM_ACL_GUEST = 0
PERM_ACL_READ_ONLY = 1
PERM_ACL_READ_WRITE = 2
PERM_ACL_ADMIN = 3


def acl_role(permissions: int) -> int:
    """Return the ACL role in ``permissions`` (firmware ``perms & PERM_ACL_ROLE_MASK``)."""
    return permissions & PERM_ACL_ROLE_MASK


def acl_is_admin(permissions: int) -> bool:
    """Mirror of firmware ``ClientInfo::isAdmin()`` — role must equal ADMIN (3).

    Testing the 0x02 bit instead would also match READ_WRITE (2) and would let a
    read-write client be announced as an admin.
    """
    return acl_role(permissions) == PERM_ACL_ADMIN


# ---------------------------------------------------------------------------
# Anonymous request sub-types (first byte of an ANON_REQ payload, after the
# 4-byte timestamp). Wire values shared by the anon-request handler (node) and
# the companion protocol; see firmware simple_repeater/MyMesh.cpp.
# ---------------------------------------------------------------------------
ANON_REQ_TYPE_REGIONS = 0x01  # repeater replies with comma-separated region names
ANON_REQ_TYPE_OWNER = 0x02  # repeater replies with "name\nowner"
ANON_REQ_TYPE_BASIC = 0x03  # repeater replies with clock + feature flags

# ---------------------------------------------------------------------------
# Text message types (upper 6 bits of the TXT_MSG flags byte; firmware
# TxtDataHelpers.h). Wire values shared by node.handlers.text and companion.
# ---------------------------------------------------------------------------
TXT_TYPE_PLAIN = 0  # plain text message
TXT_TYPE_CLI_DATA = 1  # a CLI command -or- reply (no delivery ACK)
# Signed plain text (e.g. room server posts): a 4-byte author pubkey prefix
# precedes the text in the decrypted payload.
TXT_TYPE_SIGNED_PLAIN = 2
# A CLI command, explicitly (firmware 2c0ace25). Before it existed, CLI_DATA
# carried both directions and the receiver executed whatever arrived; now a
# command is CLI_COMMAND and only its reply is CLI_DATA. Receivers still accept
# CLI_DATA as a command for older senders (simple_repeater onPeerDataRecv).
TXT_TYPE_CLI_COMMAND = 3
