"""
MeshCore Companion Radio - Python-native implementation.

Provides contact management, messaging with offline queue, advertisement
broadcasting, channel management, path tracking, signing, telemetry,
statistics, and device configuration on top of MeshNode.
"""

from .channel_store import ChannelStore
from .companion_bridge import CompanionBridge
from .companion_radio import CompanionRadio
from .constants import (
    ADV_TYPE_CHAT,
    ADV_TYPE_REPEATER,
    ADV_TYPE_ROOM,
    ADV_TYPE_SENSOR,
    ADVERT_LOC_NONE,
    ADVERT_LOC_SHARE,
    AUTOADD_CHAT,
    AUTOADD_OVERWRITE_OLDEST,
    AUTOADD_REPEATER,
    AUTOADD_ROOM,
    AUTOADD_SENSOR,
    DEFAULT_MAX_CHANNELS,
    DEFAULT_MAX_CONTACTS,
    DEFAULT_OFFLINE_QUEUE_SIZE,
    MSG_SEND_FAILED,
    MSG_SEND_SENT_DIRECT,
    MSG_SEND_SENT_FLOOD,
    STATS_TYPE_CORE,
    STATS_TYPE_PACKETS,
    STATS_TYPE_RADIO,
    TELEM_MODE_ALLOW_ALL,
    TELEM_MODE_ALLOW_FLAGS,
    TELEM_MODE_DENY,
    TXT_TYPE_CLI_COMMAND,
    TXT_TYPE_CLI_DATA,
    TXT_TYPE_PLAIN,
    TXT_TYPE_SIGNED_PLAIN,
    BinaryReqType,
)
from .contact_store import ContactStore
from .frame_server import CompanionFrameServer
from .message_queue import MessageQueue
from .models import (
    AdvertPath,
    Channel,
    ChannelDataEvent,
    ChannelMessageEvent,
    Contact,
    MessageEvent,
    NodePrefs,
    PacketStats,
    QueuedMessage,
    SentResult,
)
from .path_cache import PathCache
from .stats_collector import StatsCollector

__all__ = [
    # Main classes
    "CompanionRadio",
    "CompanionBridge",
    "CompanionFrameServer",
    # Stores
    "ContactStore",
    "ChannelStore",
    "MessageQueue",
    "PathCache",
    "StatsCollector",
    # Models
    "Contact",
    "Channel",
    "NodePrefs",
    "SentResult",
    "PacketStats",
    "AdvertPath",
    "QueuedMessage",
    "MessageEvent",
    "ChannelMessageEvent",
    "ChannelDataEvent",
    # ADV Types
    "ADV_TYPE_CHAT",
    "ADV_TYPE_REPEATER",
    "ADV_TYPE_ROOM",
    "ADV_TYPE_SENSOR",
    # Text Types
    "TXT_TYPE_PLAIN",
    "TXT_TYPE_CLI_DATA",
    "TXT_TYPE_SIGNED_PLAIN",
    "TXT_TYPE_CLI_COMMAND",
    # Telemetry Modes
    "TELEM_MODE_DENY",
    "TELEM_MODE_ALLOW_FLAGS",
    "TELEM_MODE_ALLOW_ALL",
    # Location Policy
    "ADVERT_LOC_NONE",
    "ADVERT_LOC_SHARE",
    # Auto-Add Config
    "AUTOADD_OVERWRITE_OLDEST",
    "AUTOADD_CHAT",
    "AUTOADD_REPEATER",
    "AUTOADD_ROOM",
    "AUTOADD_SENSOR",
    # Message Send Result
    "MSG_SEND_FAILED",
    "MSG_SEND_SENT_FLOOD",
    "MSG_SEND_SENT_DIRECT",
    # Binary request types
    "BinaryReqType",
    # Stats Types
    "STATS_TYPE_CORE",
    "STATS_TYPE_RADIO",
    "STATS_TYPE_PACKETS",
    # Defaults
    "DEFAULT_MAX_CONTACTS",
    "DEFAULT_MAX_CHANNELS",
    "DEFAULT_OFFLINE_QUEUE_SIZE",
]
