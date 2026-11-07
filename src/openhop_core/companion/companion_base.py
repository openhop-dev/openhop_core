"""
CompanionBase - Shared logic for CompanionRadio and CompanionBridge.

Provides stores, event handling, contact management, device configuration,
and push callbacks. Subclasses implement TX via MeshNode or packet_injector.
The implementation is split across the base_* mixin modules.
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from collections import OrderedDict
from typing import Any, Callable, Iterable, Optional

from ..node.events import EventService, EventSubscriber
from ..protocol import LocalIdentity, Packet
from ..protocol.packet_filter import PacketHashCache
from .base_callbacks import _CallbackMixin
from .base_config import _DeviceConfigMixin
from .base_contacts import _ContactChannelMixin
from .base_events import _RxEventsMixin
from .base_send import _SendOpsMixin

# Re-exported for backwards compatibility (tests and callers import these here).
from .base_support import PUSH_CALLBACK_KEYS  # noqa: F401
from .base_support import ResponseWaiter  # noqa: F401
from .base_support import adv_type_to_flags  # noqa: F401
from .base_support import _SeenCache
from .channel_store import ChannelStore
from .cli import CliCommandHook, CompanionCLI
from .constants import (
    ADV_TYPE_CHAT,
    DEFAULT_MAX_CHANNELS,
    DEFAULT_MAX_CONTACTS,
    DEFAULT_OFFLINE_QUEUE_SIZE,
)
from .contact_store import ContactStore
from .message_queue import MessageQueue
from .models import Contact, NodePrefs
from .path_cache import PathCache
from .stats_collector import StatsCollector

logger = logging.getLogger("CompanionBase")


class _CompanionEventSubscriber(EventSubscriber):
    """Bridges event service to companion push callbacks."""

    def __init__(self, companion: CompanionBase) -> None:
        self._companion = companion

    async def handle_event(self, event_type: str, data: dict) -> None:
        await self._companion._handle_mesh_event(event_type, data)


class CompanionBase(
    _ContactChannelMixin,
    _DeviceConfigMixin,
    _CallbackMixin,
    _SendOpsMixin,
    _RxEventsMixin,
    ABC,
):
    """Abstract base class for companion implementations.

    Provides shared stores, event handling, contact management, device config,
    and push callbacks. Subclasses implement TX (via node or packet_injector).
    """

    def _init_companion_stores(
        self,
        identity: LocalIdentity,
        node_name: str = "pyMC",
        adv_type: int = ADV_TYPE_CHAT,
        max_contacts: int = DEFAULT_MAX_CONTACTS,
        max_channels: int = DEFAULT_MAX_CHANNELS,
        offline_queue_size: int = DEFAULT_OFFLINE_QUEUE_SIZE,
        radio_config: Optional[dict] = None,
        initial_contacts: Optional[Iterable[Contact]] = None,
    ) -> None:
        """Initialize shared stores, prefs, event service, and push callbacks."""
        self._identity = identity
        # Preserve a host-provided mapping by reference. A repeater can update
        # it after an administrative change, and bridges must not report a
        # stale startup snapshot.
        self._radio_config = radio_config if radio_config is not None else {}
        self._running = False

        self.contacts = ContactStore(max_contacts)
        self.channels = ChannelStore(max_channels)
        self.message_queue = MessageQueue(offline_queue_size)
        self.path_cache = PathCache()
        self.stats = StatsCollector()
        # NODE_DISCOVERED events may be published through EventService.publish_sync(),
        # which schedules each event in its own task. Serialize the complete advert
        # state transition, including callbacks, so concurrent adverts cannot
        # interleave mutations of the contact store. This orders adverts against
        # each other only; app commands and PATH updates still mutate contacts
        # outside it.
        self._node_discovered_lock = asyncio.Lock()

        self.prefs = NodePrefs(
            node_name=node_name,
            adv_type=adv_type,
            tx_power_dbm=self._radio_config.get("power", self._radio_config.get("tx_power", 20)),
            **self._configured_radio_prefs(),
        )

        self._custom_vars: dict[str, str] = {}
        # Login-session connection registry, mirroring firmware BaseChatMesh
        # connections[] (src/helpers/BaseChatMesh.cpp:74). Maps a full 32-byte
        # server public key to a monotonic expiry deadline. See the
        # note_login_connection / has_login_connection / clear_login_connection
        # methods in base_send.py for the lifecycle.
        self._login_connections: dict[bytes, float] = {}
        # Frame-server login commands expose a per-send timeout and are retried
        # by the companion app. Keep one logical response session per full
        # contact key so those retries do not replace each other's callbacks.
        self._pending_frame_logins: dict[bytes, Any] = {}
        self._sign_buffer: Optional[bytearray] = None
        self._flood_transport_key: Optional[bytes] = None
        # Sticky "force unscoped flood" flag (FW PR #2492 / FIRMWARE_VER_CODE 12+):
        # when set, floods ignore the default scope until a scope override/reset.
        self._flood_unscoped: bool = False
        self._time_offset: float = 0.0

        self._event_service = EventService()
        self._event_subscriber = _CompanionEventSubscriber(self)
        self._event_service.subscribe_all(self._event_subscriber)

        self._push_callbacks: dict[str, list[Callable]] = {k: [] for k in PUSH_CALLBACK_KEYS}
        # Adapters built by the legacy positional on_*_received registrars,
        # memoized by (event, original callable) so registering the same legacy
        # callback twice reuses one adapter instead of stacking a fresh closure.
        self._legacy_push_adapters: dict[tuple[str, Callable], Callable] = {}

        # Pending binary requests by tag (hex) for matching responses
        self._pending_binary_requests: dict[str, dict] = {}
        # Pending path discovery tags for matching responses
        self._pending_discovery_tags: set[int] = set()
        # Pending expected ACKs for send_confirmed (Bridge and Radio), mapping
        # ACK CRC -> monotonic send time. Bounded circular table mirroring the
        # firmware expected_ack_table (AckTableEntry.msg_sent + ack): when full,
        # the oldest entry is evicted so a current send is never dropped.
        self._pending_ack_crcs: "OrderedDict[int, float]" = OrderedDict()
        # Fire-and-forget tasks kept alive until done (see _spawn_background_task)
        self._background_tasks: set[asyncio.Task] = set()

        # The local CLI (CMD_RUN_CLI_COMMAND and the remote CLI). A host adds its
        # own commands through ``cli_command_hook`` (see companion/cli.py).
        self.cli = CompanionCLI(self)
        self.cli_command_hook: Optional[CliCommandHook] = None
        # Remote CLI replies waiting out CLI_REPLY_DELAY_MS; cancelled on stop().
        self._remote_cli_replies: set[asyncio.Task] = set()
        # Set by stop(), cleared by start(). Not ``_running``: a host may never
        # call start() (openhop_repeater does not for its bridges).
        self._remote_cli_closed = False

        # Event-level de-dup caches keep reconnects from re-queuing text.
        self._seen_grp_txt = _SeenCache(ttl=60.0, max_size=4096)
        self._seen_txt = _SeenCache()
        # Group packets have no sender identity, so local echoes are matched
        # by full packet hash marked at send time. MeshCore's seen table never
        # expires (cyclic displacement only); keep the window generous so
        # echoes via slow multi-hop or store-and-forward paths still match.
        # The capacity is a safety limit for untrusted RX.
        self._seen_group_packets = PacketHashCache(ttl_seconds=600.0, max_entries=4096)

        # Allow subclasses to restore persisted preferences on startup.
        self._load_prefs()

        # Optional bulk load of contacts (e.g. from persistence on boot).
        if initial_contacts is not None:
            self.contacts.load_from(initial_contacts)

    def _configured_radio_prefs(self) -> dict:
        """The radio prefs ``radio_config`` implies, with the defaults used
        when it is silent. Prefs start from these."""
        return {
            "frequency_hz": self._radio_config.get("frequency", 915000000),
            "bandwidth_hz": self._radio_config.get("bandwidth", 250000),
            "spreading_factor": self._radio_config.get("spreading_factor", 10),
            "coding_rate": self._radio_config.get("coding_rate", 5),
        }

    def _check_and_track_group_packet(self, packet: Packet) -> bool:
        """Record a group packet and report whether it was recently seen."""
        return self._seen_group_packets.check_and_add(packet.calculate_packet_hash().hex())

    # -------------------------------------------------------------------------
    # Preference Persistence Hooks
    # -------------------------------------------------------------------------

    def _save_prefs(self) -> None:
        """Hook: persist the current :attr:`prefs` to stable storage.

        The default implementation is a no-op — preferences live only in
        memory.  Subclasses that need persistence (e.g. backed by SQLite or
        a JSON file) should override this method.

        Called automatically after any preference-mutating method
        (``set_radio_params``, ``set_tx_power``, ``set_tuning_params``,
        ``set_autoadd_config``, ``set_other_params``,
        ``set_advert_name``, ``set_advert_latlon``).
        """

    def _load_prefs(self) -> None:
        """Hook: restore :attr:`prefs` from stable storage on startup.

        The default implementation is a no-op.  Subclasses should override
        to populate :attr:`self.prefs` fields from their persistence layer.

        Called once at the end of :meth:`_init_companion_stores`.
        """

    # -------------------------------------------------------------------------
    # Abstract methods (subclasses must implement)
    # -------------------------------------------------------------------------

    @abstractmethod
    async def _send_packet(
        self,
        pkt: Packet,
        wait_for_ack: bool = False,
        expected_crc: Optional[int] = None,
    ) -> bool:
        """Send a packet via the subclass transport (radio or packet_injector)."""

    @abstractmethod
    async def start(self) -> None:
        """Start the companion."""

    @abstractmethod
    async def stop(self) -> None:
        """Stop the companion."""

    @property
    @abstractmethod
    def is_running(self) -> bool:
        """Return whether the companion is currently running."""

    @abstractmethod
    def import_private_key(self, key: bytes) -> bool:
        """Import a private key and rebuild the identity."""

    def _get_protocol_response_handler(self) -> Any:
        """Return the protocol response handler, or ``None``.

        Subclasses that support request/response methods (telemetry, status,
        binary request, etc.) must override this to return their handler.
        """
        return None

    def _get_login_response_handler(self) -> Any:
        """Return the login response handler, or ``None``."""
        return None

    def _get_text_handler(self) -> Any:
        """Return the text message handler, or ``None``."""
        return None

    def _get_advert_handler(self) -> Any:
        """Return the normal ADVERT handler used for imported-contact loopback."""
        return None

    def _apply_multi_acks_pref(self) -> None:
        """Push the current ``multi_acks`` pref into the text handler (best-effort)."""
        th = self._get_text_handler()
        if th is not None and hasattr(th, "set_multi_acks"):
            th.set_multi_acks(getattr(self.prefs, "multi_acks", 0))
