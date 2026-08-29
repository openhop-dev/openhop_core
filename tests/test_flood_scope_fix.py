"""Regression tests for the OH-022 + OH-026 flood-scope fix.

OH-022: mirror the persisted default flood scope (and the explicit-unscoped
        flag) to the dispatcher, so sends that build a packet and rely on the
        dispatcher to scope it at TX time carry the default too.
OH-026: capture the region a request arrived under on the Packet, and scope a
        freshly-built flood reply to that region (or plain), never the node
        default.

Both parts share one ``scope_packet`` primitive and the ``_flood_scope_applied``
double-scope gate.

Upstream MeshCore PR #3106 ("Fix replies dropped when flood.max.unscoped is
low") later made the reply decision three-way rather than two-way: a reply whose
request scope is *unknowable* (a DIRECT request carries no transport codes, or
its code matched no Region) now falls back to the node's default scope instead
of going out un-scoped, where repeaters running ``flood.max.unscoped=0`` drop it
at hop 0. Un-scoped is only mirrored when the request itself arrived un-scoped.
See ``TestReplyScopeDecision`` below.
"""

from __future__ import annotations

import asyncio
import contextlib
import struct
import time

import pytest

from openhop_core.companion import CompanionBridge, CompanionRadio
from openhop_core.companion.models import Contact
from openhop_core.node.dispatcher import Dispatcher
from openhop_core.node.handlers.login_server import LoginServerHandler
from openhop_core.node.handlers.protocol_request import (
    REQ_TYPE_GET_STATUS,
    ProtocolRequestHandler,
)
from openhop_core.protocol import (
    CryptoUtils,
    Identity,
    LocalIdentity,
    Packet,
    PacketBuilder,
    PathUtils,
)
from openhop_core.protocol.constants import (
    PAYLOAD_TYPE_ANON_REQ,
    PAYLOAD_TYPE_PATH,
    PAYLOAD_TYPE_REQ,
    PAYLOAD_TYPE_TXT_MSG,
    ROUTE_TYPE_DIRECT,
    ROUTE_TYPE_FLOOD,
    ROUTE_TYPE_TRANSPORT_FLOOD,
    TXT_TYPE_PLAIN,
)
from openhop_core.protocol.region_map import (
    REGION_DENY_FLOOD,
    RegionEntry,
    RegionMap,
    apply_reply_scope,
    capture_recv_region,
)
from openhop_core.protocol.transport_keys import (
    calc_transport_code,
    get_auto_key_for,
    scope_packet,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class MockRadio:
    """Minimal mock radio that records transmitted frames."""

    def __init__(self):
        self.rx_callback = None
        self.sent: list[bytes] = []

    def set_rx_callback(self, callback):
        self.rx_callback = callback

    async def send(self, data: bytes) -> bool:
        self.sent.append(bytes(data))
        return True

    def get_last_rssi(self) -> int:
        return -50

    def get_last_snr(self) -> float:
        return 5.0


def _make_companion(node_name: str = "test") -> CompanionRadio:
    return CompanionRadio(radio=MockRadio(), identity=LocalIdentity(), node_name=node_name)


def _make_flood_packet() -> Packet:
    """A minimal flood-routed advert packet (for dispatcher-level unit tests)."""
    return PacketBuilder.create_advert(local_identity=LocalIdentity(), name="x", route_type="flood")


def _build_login_req(
    server: LocalIdentity,
    client: LocalIdentity,
    password: str = "pw",
    region_key: bytes = None,
    route_type: int = ROUTE_TYPE_FLOOD,
) -> Packet:
    """Build an ANON_REQ login packet from ``client`` to ``server``.

    When ``region_key`` is given the packet is scoped (TRANSPORT_FLOOD) with
    that key, exactly as a firmware repeater would have re-broadcast it.
    """
    server_pub = server.get_public_key()
    client_pub = client.get_public_key()
    shared = Identity(server_pub).calc_shared_secret(client.get_private_key())
    aes = shared[:16]
    plaintext = struct.pack("<I", int(time.time())) + password.encode("utf-8") + b"\x00"
    enc = CryptoUtils.encrypt_then_mac(aes, shared, plaintext)
    payload = bytes([server_pub[0]]) + client_pub + enc

    pkt = Packet()
    pkt.header = (PAYLOAD_TYPE_ANON_REQ << 2) | route_type
    pkt.payload = bytearray(payload)
    pkt.payload_len = len(payload)
    pkt.path = bytearray()
    pkt.path_len = 0
    if region_key is not None:
        scope_packet(pkt, region_key)  # -> TRANSPORT_FLOOD with region code
    return pkt


def _login_handler(server: LocalIdentity, get_client_fn=None):
    """A LoginServerHandler that always authenticates, capturing sent replies."""
    sent: list = []
    handler = LoginServerHandler(
        local_identity=server,
        log_fn=lambda *_: None,
        authenticate_callback=lambda *a, **k: (True, 0x03),
        is_room_server=False,
        get_client_fn=get_client_fn,
    )
    handler.set_send_packet_callback(lambda pkt, delay_ms: sent.append(pkt))
    return handler, sent


def _build_flood_dm(sender: LocalIdentity, receiver: LocalIdentity, text: str = "hi") -> Packet:
    """Build a real encrypted FLOOD DM from ``sender`` to ``receiver``."""

    class _SendContact:
        def __init__(self, pubkey_hex):
            self.public_key = pubkey_hex
            self.out_path = []
            self.out_path_len = -1

    pkt, _ = PacketBuilder.create_text_message(
        _SendContact(receiver.get_public_key().hex()),
        sender,
        text,
        attempt=0,
        message_type="flood",
        txt_type=TXT_TYPE_PLAIN,
    )
    return pkt


async def _drain_first_tx(companion: CompanionRadio, radio: MockRadio, coro) -> Packet:
    """Run ``coro`` until the first packet is transmitted, return it, then cancel.

    Several public send methods block on a response (login/status/telemetry/CLI).
    Only their first transmitted packet matters here, so poll ``radio.sent``,
    capture that packet, then cancel the call and any retry/waiter background
    tasks so they stop re-sending.
    """
    n0 = len(radio.sent)
    task = asyncio.ensure_future(coro)
    try:
        for _ in range(400):
            if len(radio.sent) > n0:
                break
            await asyncio.sleep(0.005)
    finally:
        task.cancel()
        with contextlib.suppress(BaseException):
            await task
        for bt in list(getattr(companion, "_background_tasks", ())):
            bt.cancel()
        for bt in list(getattr(companion, "_background_tasks", ())):
            with contextlib.suppress(BaseException):
                await bt
    assert len(radio.sent) > n0, "expected a transmitted packet"
    pkt = Packet()
    pkt.read_from(radio.sent[n0])
    return pkt


# ---------------------------------------------------------------------------
# Part 1 — OH-022: default / unscoped mirror on the dispatcher
# ---------------------------------------------------------------------------


class TestDefaultMirrorToDispatcher:
    def test_set_default_flood_scope_reaches_dispatcher(self):
        """(1) set_default_flood_scope mirrors the resolved key to the dispatcher."""
        companion = _make_companion()
        key = get_auto_key_for("#usa")
        companion.set_default_flood_scope("usa", key)
        assert companion.node.dispatcher.default_flood_transport_key == key

    def test_null_and_short_default_clear_dispatcher_mirror(self):
        """(1) A null (all-zero) or too-short default resolves to None on the mirror."""
        companion = _make_companion()
        companion.set_default_flood_scope("usa", get_auto_key_for("#usa"))
        assert companion.node.dispatcher.default_flood_transport_key is not None

        # All-zero key: firmware persists the name but treats the key as null at send.
        companion.set_default_flood_scope("usa", b"\x00" * 16)
        assert companion.node.dispatcher.default_flood_transport_key is None

        companion.set_default_flood_scope("usa", get_auto_key_for("#usa"))
        # Short key => base clears the default entirely.
        companion.set_default_flood_scope("usa", b"\x01" * 8)
        assert companion.node.dispatcher.default_flood_transport_key is None

        companion.set_default_flood_scope("usa", get_auto_key_for("#usa"))
        companion.set_default_flood_scope(None, None)
        assert companion.node.dispatcher.default_flood_transport_key is None

    @pytest.mark.asyncio
    async def test_start_seeds_all_three_mirrors_from_prefs(self):
        """(2) start() seeds default + override + unscoped flag from persisted prefs."""
        companion = _make_companion()
        default_key = get_auto_key_for("#usa")
        override_key = b"\x02" * 16
        # Simulate persisted prefs restored at boot, bypassing the live setters.
        companion.prefs.default_scope_name = "usa"
        companion.prefs.default_scope_key = default_key
        companion._flood_transport_key = override_key
        companion._flood_unscoped = True

        # Not yet started: mirrors are still at their __init__ defaults.
        assert companion.node.dispatcher.default_flood_transport_key is None
        assert companion.node.dispatcher.flood_transport_key is None
        assert companion.node.dispatcher.flood_unscoped is False

        await companion.start()
        try:
            assert companion.node.dispatcher.default_flood_transport_key == default_key
            assert companion.node.dispatcher.flood_transport_key == override_key
            assert companion.node.dispatcher.flood_unscoped is True
        finally:
            await companion.stop()


class TestSetASendsCarryDefault:
    """(3) With only a default set, sends that rely on the dispatcher carry it."""

    async def _companion_with_default(self):
        radio = MockRadio()
        companion = CompanionRadio(radio=radio, identity=LocalIdentity(), node_name="setA")
        peer = LocalIdentity()
        contact_key = peer.get_public_key()
        companion.contacts.add(Contact(public_key=contact_key, name="rpt"))  # out_path_len=-1
        default_key = get_auto_key_for("#usa")
        await companion.start()
        companion.set_default_flood_scope("usa", default_key)
        # Ensure NO transient override / unscoped is in play.
        assert companion.node.dispatcher.flood_transport_key is None
        assert companion.node.dispatcher.flood_unscoped is False
        return companion, radio, contact_key, default_key

    def _assert_scoped_with_default(self, pkt: Packet, default_key: bytes, label: str):
        assert pkt.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD, f"{label} not TRANSPORT_FLOOD"
        assert pkt.transport_codes[0] == calc_transport_code(
            default_key, pkt
        ), f"{label} transport code does not match the default key"

    @pytest.mark.asyncio
    async def test_flood_sends_carry_default(self):
        companion, radio, key, default_key = await self._companion_with_default()
        try:
            pkt = await _drain_first_tx(companion, radio, companion.send_login(key, "pw"))
            self._assert_scoped_with_default(pkt, default_key, "login")

            pkt = await _drain_first_tx(companion, radio, companion.send_status_request(key))
            self._assert_scoped_with_default(pkt, default_key, "status")

            pkt = await _drain_first_tx(companion, radio, companion.send_telemetry_request(key))
            self._assert_scoped_with_default(pkt, default_key, "telemetry")

            pkt = await _drain_first_tx(
                companion, radio, companion.send_repeater_command(key, "reboot")
            )
            self._assert_scoped_with_default(pkt, default_key, "cli/repeater_command")

            pkt = await _drain_first_tx(
                companion, radio, companion.send_raw_data(key, b"\x01\x02\x03\x04")
            )
            self._assert_scoped_with_default(pkt, default_key, "raw_data")
        finally:
            await companion.stop()


class TestUnscopedSuppressesDefault:
    def test_unscoped_suppresses_default_then_resumes(self):
        """(4) Unscoped suppresses (not nulls) the default; a later scope resumes."""
        companion = _make_companion()
        dispatcher = companion.node.dispatcher
        default_key = get_auto_key_for("#usa")
        companion.set_default_flood_scope("usa", default_key)

        companion.set_flood_unscoped()
        # The default mirror is preserved, only suppressed by the flag.
        assert dispatcher.default_flood_transport_key == default_key
        assert dispatcher.flood_unscoped is True

        pkt = _make_flood_packet()
        dispatcher._apply_flood_scope(pkt)
        assert pkt.get_route_type() == ROUTE_TYPE_FLOOD  # stayed plain
        assert pkt.transport_codes == [0, 0]

        # A transient override clears the flag and resumes scoping.
        override_key = get_auto_key_for("#europe")
        companion.set_flood_scope(override_key)
        assert dispatcher.flood_unscoped is False
        pkt2 = _make_flood_packet()
        dispatcher._apply_flood_scope(pkt2)
        assert pkt2.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD
        assert pkt2.transport_codes[0] == calc_transport_code(override_key, pkt2)

        # Clearing the override falls back to the (still-present) default.
        companion.set_flood_scope(None)
        assert dispatcher.flood_unscoped is False
        pkt3 = _make_flood_packet()
        dispatcher._apply_flood_scope(pkt3)
        assert pkt3.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD
        assert pkt3.transport_codes[0] == calc_transport_code(default_key, pkt3)


class TestOverrideBeatsDefault:
    def test_transient_override_beats_default(self):
        """(5) The transient override wins over the persisted default."""
        companion = _make_companion()
        dispatcher = companion.node.dispatcher
        default_key = get_auto_key_for("#usa")
        override_key = get_auto_key_for("#europe")
        companion.set_default_flood_scope("usa", default_key)
        companion.set_flood_region("europe")

        assert dispatcher.flood_transport_key == override_key
        assert dispatcher.default_flood_transport_key == default_key

        pkt = _make_flood_packet()
        dispatcher._apply_flood_scope(pkt)
        assert pkt.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD
        assert pkt.transport_codes[0] == calc_transport_code(override_key, pkt)
        assert pkt.transport_codes[0] != calc_transport_code(default_key, pkt)


class TestPreScopedPacketUntouched:
    def test_dispatcher_skips_marked_packet_even_with_default(self):
        """(6) A packet already marked _flood_scope_applied is never re-scoped,
        even when the dispatcher holds a default."""
        companion = _make_companion()
        dispatcher = companion.node.dispatcher
        dispatcher.default_flood_transport_key = get_auto_key_for("#usa")
        dispatcher.flood_transport_key = get_auto_key_for("#europe")

        pkt = _make_flood_packet()
        pkt._flood_scope_applied = True
        dispatcher._apply_flood_scope(pkt)

        assert pkt.get_route_type() == ROUTE_TYPE_FLOOD
        assert pkt.transport_codes == [0, 0]


# ---------------------------------------------------------------------------
# Part 2 — OH-026: reply-region capture + scoping
# ---------------------------------------------------------------------------


class TestStandaloneCompanionReplyCarriesDefault:
    @pytest.mark.asyncio
    async def test_standalone_txt_ack_carries_default(self):
        """(7) A standalone companion (region_map None) does not capture, so its
        flood TXT ACK falls through to the dispatcher default (OH-022)."""
        radio = MockRadio()
        server = LocalIdentity()
        companion = CompanionRadio(radio=radio, identity=server, node_name="standalone")
        sender = LocalIdentity()
        companion.contacts.add(Contact(public_key=sender.get_public_key(), name="peer"))
        default_key = get_auto_key_for("#usa")

        await companion.start()
        try:
            companion.set_default_flood_scope("usa", default_key)
            assert companion.node.dispatcher.region_map is None

            dm = _build_flood_dm(sender, server, "hello")
            await companion.node.dispatcher._process_received_packet(dm.write_to(), -50, 5.0)
            # The flood PATH-return ACK is scheduled after TXT_ACK_DELAY (~200ms).
            for _ in range(200):
                if radio.sent:
                    break
                await asyncio.sleep(0.005)

            assert radio.sent, "expected a flood ACK to be transmitted"
            ack = Packet()
            ack.read_from(radio.sent[-1])
            assert ack.get_payload_type() == PAYLOAD_TYPE_PATH
            assert ack.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD
            assert ack.transport_codes[0] == calc_transport_code(default_key, ack)
        finally:
            await companion.stop()


class TestRepeaterReplyCarriesRegion:
    def _region_map(self):
        rm = RegionMap([RegionEntry(id=1, name="#region-a"), RegionEntry(id=2, name="#region-b")])
        return rm, get_auto_key_for("#region-a"), get_auto_key_for("#region-b")

    @pytest.mark.asyncio
    async def test_reply_carries_incoming_region(self):
        """(8) A request scoped to region B yields a reply scoped to region B,
        with the code re-hashed over the reply payload, marked applied."""
        region_map, _a_key, b_key = self._region_map()
        server, client = LocalIdentity(), LocalIdentity()
        handler, sent = _login_handler(server)

        req = _build_login_req(server, client, region_key=b_key)
        capture_recv_region(region_map, req)  # what the RX path does
        assert req._recv_region_captured is True
        assert req._recv_region_key == b_key

        result = await handler(req)
        assert result.authenticated is True
        assert len(sent) == 1
        reply = sent[0]
        assert reply.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD
        assert reply.transport_codes[0] == calc_transport_code(b_key, reply)
        assert reply._flood_scope_applied is True

    @pytest.mark.asyncio
    async def test_plain_flood_request_reply_stays_plain(self):
        """(9) A plain-flood request => plain reply (not over-scoped, not
        default-scoped): marked applied so the dispatcher default cannot touch it."""
        region_map, _a_key, _b_key = self._region_map()
        server, client = LocalIdentity(), LocalIdentity()
        handler, sent = _login_handler(server)

        req = _build_login_req(server, client, region_key=None)  # plain FLOOD
        capture_recv_region(region_map, req)
        assert req._recv_region_captured is True
        assert req._recv_region_key is None

        await handler(req)
        reply = sent[0]
        assert reply.get_route_type() == ROUTE_TYPE_FLOOD
        assert reply.transport_codes == [0, 0]
        assert reply._flood_scope_applied is True

    @pytest.mark.asyncio
    async def test_unknown_region_reply_takes_the_node_default(self):
        """(10) A request scoped to a region absent from the map: the scope is
        unknowable, so PR #3106's REPLY_SCOPE_DEFAULT applies -- the reply defers
        to the node default rather than going out un-scoped (which a repeater
        running flood.max.unscoped=0 would drop at hop 0)."""
        region_map, _a_key, _b_key = self._region_map()
        server, client = LocalIdentity(), LocalIdentity()
        handler, sent = _login_handler(server)

        unknown_key = get_auto_key_for("#not-in-map")
        req = _build_login_req(server, client, region_key=unknown_key)
        capture_recv_region(region_map, req)
        assert req._recv_region_captured is True
        assert req._recv_region_key is None  # no region matched
        assert req._recv_region_unscoped is False  # unknowable, not un-scoped

        await handler(req)
        reply = sent[0]
        # Deferred, not decided: the build leaves it plain but unmarked.
        assert reply.get_route_type() == ROUTE_TYPE_FLOOD
        assert reply._flood_scope_applied is False

        # ...and the dispatcher resolves it to the default at TX time.
        default_key = get_auto_key_for("#default-region")
        dispatcher = Dispatcher(MockRadio())
        dispatcher.default_flood_transport_key = default_key
        dispatcher._apply_flood_scope(reply)
        assert reply.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD
        assert reply.transport_codes[0] == calc_transport_code(default_key, reply)

    @pytest.mark.asyncio
    async def test_interleaved_requests_each_reply_scoped_correctly(self):
        """(11) Region lives on each Packet, not a shared member: two interleaved
        requests (regions A, B) each yield a correctly-scoped reply."""
        region_map, a_key, b_key = self._region_map()
        server = LocalIdentity()
        client_a, client_b = LocalIdentity(), LocalIdentity()
        handler, sent = _login_handler(server)

        req_a = _build_login_req(server, client_a, region_key=a_key)
        req_b = _build_login_req(server, client_b, region_key=b_key)

        # Capture both BEFORE either reply is built (a shared member would be
        # overwritten by the second capture).
        capture_recv_region(region_map, req_a)
        capture_recv_region(region_map, req_b)
        assert req_a._recv_region_key == a_key
        assert req_b._recv_region_key == b_key

        await handler(req_a)
        await handler(req_b)
        assert len(sent) == 2
        reply_a, reply_b = sent
        assert reply_a.transport_codes[0] == calc_transport_code(a_key, reply_a)
        assert reply_b.transport_codes[0] == calc_transport_code(b_key, reply_b)
        # Cross-check: each reply matches only its own region.
        assert reply_a.transport_codes[0] != calc_transport_code(b_key, reply_a)
        assert reply_b.transport_codes[0] != calc_transport_code(a_key, reply_b)


class TestRepeaterReqReplyScope:
    """Both REQ reply shapes in ``ProtocolRequestHandler._build_response``.

    Firmware ``simple_repeater::onPeerDataRecv`` (PAYLOAD_TYPE_REQ) has two
    flood reply branches, and both go through ``sendFloodReply``::

        if (packet->isRouteFlood()) {
          path = createPathReturn(...);  sendFloodReply(path, ...);          // (a)
        } else {
          reply = createDatagram(PAYLOAD_TYPE_RESPONSE, ...);
          if (client->out_path_len != OUT_PATH_UNKNOWN) sendDirect(...);
          else                                          sendFloodReply(reply, ...);  // (b)
        }

    ``sendFloodReply`` scopes to ``recv_pkt_region`` — which is NULL for a DIRECT
    request — so branch (b) is a plain, unscoped flood. Branch (b) used to be the
    one reply builder that never marked its decision, so the dispatcher's node
    default/override stamped a region onto it that firmware would never use. It
    is the reply that carries a status/telemetry/neighbours response whenever the
    ACL holds no out_path for the client.
    """

    def _req_handler(self, server: LocalIdentity, client_info):
        handler = ProtocolRequestHandler(
            local_identity=server,
            contacts=None,
            get_clients_fn=lambda src_hash: [client_info],
            request_handlers={REQ_TYPE_GET_STATUS: lambda c, ts, data: b"\x01\x02\x03\x04"},
            log_fn=lambda *_: None,
        )
        return handler

    def _client_info(self, client: LocalIdentity, *, out_path_len: int = -1, out_path=b""):
        class _Client:
            def __init__(self):
                self.id = Identity(client.get_public_key())
                self.public_key = client.get_public_key()
                self.out_path = bytearray(out_path)
                self.out_path_len = out_path_len
                self.last_timestamp = 0

        return _Client()

    def _build_req(
        self,
        server: LocalIdentity,
        client: LocalIdentity,
        *,
        route_type: int,
        region_key: bytes = None,
    ) -> Packet:
        server_pub = server.get_public_key()
        client_pub = client.get_public_key()
        shared = Identity(server_pub).calc_shared_secret(client.get_private_key())
        plaintext = struct.pack("<I", int(time.time())) + bytes([REQ_TYPE_GET_STATUS])
        enc = CryptoUtils.encrypt_then_mac(shared[:16], shared, plaintext)
        payload = bytes([server_pub[0], client_pub[0]]) + enc

        pkt = Packet()
        pkt.header = (PAYLOAD_TYPE_REQ << 2) | route_type
        pkt.payload = bytearray(payload)
        pkt.payload_len = len(payload)
        pkt.path = bytearray()
        pkt.path_len = 0
        if region_key is not None:
            scope_packet(pkt, region_key)
        return pkt

    @pytest.mark.asyncio
    async def test_direct_req_without_out_path_takes_the_node_default(self):
        """Branch (b): a DIRECT request carries no transport codes, so firmware's
        ``recv_pkt_region`` is NULL and the reply scope is unknowable.

        Pre-#3106 this flooded un-scoped, which is exactly the reported bug: any
        repeater on the way back running ``flood.max.unscoped=0`` drops it at hop
        0. REPLY_SCOPE_DEFAULT now sends it under the node's default Region.
        """
        region_map = RegionMap([RegionEntry(id=1, name="#region-a")])
        server, client = LocalIdentity(), LocalIdentity()
        handler = self._req_handler(server, self._client_info(client))  # no out_path

        req = self._build_req(server, client, route_type=ROUTE_TYPE_DIRECT)
        capture_recv_region(region_map, req)
        assert req._recv_region_captured is True
        assert req._recv_region_key is None
        assert req._recv_region_unscoped is False

        result = await handler(req)
        assert result.authenticated is True
        reply = result.response
        assert reply is not None
        assert reply.get_route_type() == ROUTE_TYPE_FLOOD
        assert reply._flood_scope_applied is False

        default_key = get_auto_key_for("#region-a")
        dispatcher = Dispatcher(MockRadio())
        dispatcher.default_flood_transport_key = default_key
        dispatcher._apply_flood_scope(reply)
        assert reply.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD
        assert reply.transport_codes[0] == calc_transport_code(default_key, reply)

    @pytest.mark.asyncio
    async def test_flood_req_path_return_carries_request_region(self):
        """Branch (a) keeps carrying the region the REQ arrived under."""
        a_key = get_auto_key_for("#region-a")
        region_map = RegionMap([RegionEntry(id=1, name="#region-a")])
        server, client = LocalIdentity(), LocalIdentity()
        handler = self._req_handler(server, self._client_info(client))

        req = self._build_req(
            server, client, route_type=ROUTE_TYPE_TRANSPORT_FLOOD, region_key=a_key
        )
        capture_recv_region(region_map, req)
        assert req._recv_region_key == a_key

        result = await handler(req)
        reply = result.response
        assert reply is not None
        assert reply.get_payload_type() == PAYLOAD_TYPE_PATH
        assert reply.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD
        assert reply.transport_codes[0] == calc_transport_code(a_key, reply)
        assert reply._flood_scope_applied is True

    @pytest.mark.asyncio
    async def test_direct_req_with_out_path_replies_direct_unscoped(self):
        """A known out_path is a sendDirect: no flood scope decision at all."""
        region_map = RegionMap([RegionEntry(id=1, name="#region-a")])
        server, client = LocalIdentity(), LocalIdentity()
        client_info = self._client_info(client, out_path_len=1, out_path=b"\x5a")
        handler = self._req_handler(server, client_info)

        req = self._build_req(server, client, route_type=ROUTE_TYPE_DIRECT)
        capture_recv_region(region_map, req)

        result = await handler(req)
        reply = result.response
        assert reply is not None
        assert reply.get_route_type() == ROUTE_TYPE_DIRECT
        assert reply.transport_codes == [0, 0]

    @pytest.mark.asyncio
    async def test_standalone_node_flood_reply_still_takes_the_default(self):
        """Without a RegionMap the reply falls through to the node default.

        Companion parity: ``BaseChatMesh::onPeerDataRecv`` answers this branch
        with ``sendFloodScoped(from, ...)``, which does fall back to
        ``prefs.default_scope_key``. The mark must not be applied when nothing
        was captured, or that fallback would be suppressed.
        """
        server, client = LocalIdentity(), LocalIdentity()
        handler = self._req_handler(server, self._client_info(client))

        req = self._build_req(server, client, route_type=ROUTE_TYPE_DIRECT)
        # No capture_recv_region(): region_map is None on a standalone node.
        assert req._recv_region_captured is False

        result = await handler(req)
        reply = result.response
        assert reply is not None
        assert reply._flood_scope_applied is False

        default_key = get_auto_key_for("#default-region")
        dispatcher = Dispatcher(MockRadio())
        dispatcher.default_flood_transport_key = default_key
        dispatcher._apply_flood_scope(reply)
        assert reply.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD
        assert reply.transport_codes[0] == calc_transport_code(default_key, reply)


class TestRegionCaptureBothEntrypoints:
    def _region_map(self):
        return RegionMap([RegionEntry(id=2, name="#region-b")]), get_auto_key_for("#region-b")

    def _scoped_transport_flood_packet(self, key: bytes) -> Packet:
        pkt = Packet()
        pkt.header = (PAYLOAD_TYPE_TXT_MSG << 2) | ROUTE_TYPE_TRANSPORT_FLOOD
        pkt.payload = bytearray(b"\x11\x22hello-region-payload")
        pkt.payload_len = len(pkt.payload)
        pkt.path = bytearray()
        pkt.path_len = 0
        pkt.transport_codes[0] = calc_transport_code(key, pkt)
        pkt.transport_codes[1] = 0
        return pkt

    @pytest.mark.asyncio
    async def test_capture_via_dispatcher_entrypoint(self):
        """(12a) Dispatcher._process_received_packet captures the region."""
        region_map, b_key = self._region_map()
        dispatcher = Dispatcher(MockRadio())
        dispatcher.region_map = region_map

        seen: list[Packet] = []

        async def _record(pkt: Packet):
            seen.append(pkt)

        dispatcher.register_handler(PAYLOAD_TYPE_TXT_MSG, _record)

        raw = self._scoped_transport_flood_packet(b_key).write_to()
        await dispatcher._process_received_packet(raw, -50, 5.0)

        assert len(seen) == 1
        assert seen[0]._recv_region_captured is True
        assert seen[0]._recv_region_key == b_key

    @pytest.mark.asyncio
    async def test_capture_via_bridge_entrypoint(self):
        """(12b) CompanionBridge.process_received_packet captures the region."""
        region_map, b_key = self._region_map()

        async def _injector(pkt, wait_for_ack=False, expected_crc=None):
            return True

        bridge = CompanionBridge(LocalIdentity(), _injector, node_name="bridge")
        bridge.region_map = region_map

        pkt = self._scoped_transport_flood_packet(b_key)
        await bridge.process_received_packet(pkt)

        assert pkt._recv_region_captured is True
        assert pkt._recv_region_key == b_key

    @pytest.mark.asyncio
    async def test_bridge_without_region_map_does_not_capture(self):
        """A standalone bridge (region_map None) captures nothing."""

        async def _injector(pkt, wait_for_ack=False, expected_crc=None):
            return True

        bridge = CompanionBridge(LocalIdentity(), _injector, node_name="bridge")
        assert bridge.region_map is None

        _rm, b_key = self._region_map()
        pkt = self._scoped_transport_flood_packet(b_key)
        await bridge.process_received_packet(pkt)

        assert pkt._recv_region_captured is False
        assert pkt._recv_region_key is None


# ---------------------------------------------------------------------------
# Upstream MeshCore PR #3106 parity
# ---------------------------------------------------------------------------


class TestReplyScopeDecision:
    """The three-way ``chooseReplyScope`` truth table (RoutingPolicy.h).

    Exercised through ``capture_recv_region`` + ``apply_reply_scope`` + the
    dispatcher's TX-time resolution, which together are what firmware's
    ``sendFloodReply`` does in one call.
    """

    DEFAULT = get_auto_key_for("#default-region")

    def _reply(self):
        """A bare plain-FLOOD reply packet, as a handler would hand over."""
        pkt = Packet()
        pkt.header = (PAYLOAD_TYPE_PATH << 2) | ROUTE_TYPE_FLOOD
        pkt.payload = bytearray(b"reply-payload")
        pkt.payload_len = len(pkt.payload)
        return pkt

    def _request(self, route_type, region_key=None):
        pkt = Packet()
        pkt.header = (PAYLOAD_TYPE_ANON_REQ << 2) | route_type
        pkt.payload = bytearray(b"request-payload")
        pkt.payload_len = len(pkt.payload)
        if region_key is not None:
            scope_packet(pkt, region_key)
        return pkt

    def _tx(self, reply, default_key=DEFAULT, **dispatcher_state):
        dispatcher = Dispatcher(MockRadio())
        dispatcher.default_flood_transport_key = default_key
        for attr, value in dispatcher_state.items():
            setattr(dispatcher, attr, value)
        dispatcher._apply_flood_scope(reply)
        return reply

    def test_request_scope_known_is_mirrored(self):
        """REPLY_SCOPE_REQUEST wins over a configured default."""
        a_key = get_auto_key_for("#region-a")
        region_map = RegionMap([RegionEntry(id=1, name="#region-a")])
        req = self._request(ROUTE_TYPE_TRANSPORT_FLOOD, region_key=a_key)
        capture_recv_region(region_map, req)
        assert req._recv_region_key == a_key

        reply = self._reply()
        apply_reply_scope(reply, req)
        assert reply._flood_scope_applied is True
        self._tx(reply)
        assert reply.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD
        # Region A, not the default, and re-hashed over the *reply* payload.
        assert reply.transport_codes[0] == calc_transport_code(a_key, reply)
        assert reply.transport_codes[0] != calc_transport_code(self.DEFAULT, reply)

    def test_unscoped_flood_request_is_mirrored_even_when_a_default_exists(self):
        """REPLY_SCOPE_NONE: un-scoped is itself a known scope, so mirror it.

        Upstream's reasoning: replying scoped would change a return path that
        works today, and repeaters not holding our default Region would drop it.
        """
        region_map = RegionMap([RegionEntry(id=1, name="#region-a")])
        req = self._request(ROUTE_TYPE_FLOOD)
        capture_recv_region(region_map, req)
        assert req._recv_region_key is None
        assert req._recv_region_unscoped is True

        reply = self._reply()
        apply_reply_scope(reply, req)
        assert reply._flood_scope_applied is True
        self._tx(reply)
        assert reply.get_route_type() == ROUTE_TYPE_FLOOD
        assert reply.transport_codes == [0, 0]

    def test_wildcard_denying_flood_makes_the_scope_unknowable(self):
        """Firmware sets recv_pkt_region = NULL when the wildcard denies flood,
        which is the unknowable case, not the un-scoped one."""
        region_map = RegionMap([RegionEntry(id=1, name="#region-a")])
        region_map.wildcard.flags = REGION_DENY_FLOOD
        req = self._request(ROUTE_TYPE_FLOOD)
        capture_recv_region(region_map, req)
        assert req._recv_region_key is None
        assert req._recv_region_unscoped is False

        reply = self._reply()
        apply_reply_scope(reply, req)
        self._tx(reply)
        assert reply.transport_codes[0] == calc_transport_code(self.DEFAULT, reply)

    def test_direct_request_defers_to_the_default(self):
        """REPLY_SCOPE_DEFAULT: a DIRECT request carries no transport codes."""
        region_map = RegionMap([RegionEntry(id=1, name="#region-a")])
        req = self._request(ROUTE_TYPE_DIRECT)
        capture_recv_region(region_map, req)
        assert req._recv_region_unscoped is False

        reply = self._reply()
        apply_reply_scope(reply, req)
        assert reply._flood_scope_applied is False
        self._tx(reply)
        assert reply.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD
        assert reply.transport_codes[0] == calc_transport_code(self.DEFAULT, reply)

    def test_no_default_configured_falls_back_to_unscoped(self):
        """Firmware's final REPLY_SCOPE_NONE: no scope available at all."""
        region_map = RegionMap([RegionEntry(id=1, name="#region-a")])
        req = self._request(ROUTE_TYPE_DIRECT)
        capture_recv_region(region_map, req)

        reply = self._reply()
        apply_reply_scope(reply, req)
        self._tx(reply, default_key=None)
        assert reply.get_route_type() == ROUTE_TYPE_FLOOD
        assert reply.transport_codes == [0, 0]

    def test_default_branch_uses_the_ordinary_send_precedence(self):
        """The deferring branch resolves through the node's normal chain.

        On a repeater that is just the persisted default (no override, no
        send_unscoped), i.e. exactly sendFloodScoped(default_scope, ...). On a
        companion the transient override wins first, which is what firmware's
        sendFloodScoped(recipient) -- the overload BaseChatMesh answers this
        same case with -- does. One mechanism, correct in both roles.
        """
        region_map = RegionMap([RegionEntry(id=1, name="#region-a")])
        override = get_auto_key_for("#override-region")

        req = self._request(ROUTE_TYPE_DIRECT)
        capture_recv_region(region_map, req)
        reply = self._reply()
        apply_reply_scope(reply, req)
        self._tx(reply, flood_transport_key=override)

        assert reply.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD
        assert reply.transport_codes[0] == calc_transport_code(override, reply)

    def test_explicit_unscoped_still_suppresses_the_deferred_scope(self):
        """A node told to force un-scoped floods keeps doing so; the deferring
        branch never overrides a decision the operator made explicitly."""
        region_map = RegionMap([RegionEntry(id=1, name="#region-a")])
        req = self._request(ROUTE_TYPE_DIRECT)
        capture_recv_region(region_map, req)
        reply = self._reply()
        apply_reply_scope(reply, req)
        self._tx(reply, flood_unscoped=True)

        assert reply.get_route_type() == ROUTE_TYPE_FLOOD
        assert reply.transport_codes == [0, 0]

    def test_uncaptured_reply_is_left_to_the_ordinary_precedence(self):
        """A standalone node (no RegionMap) is untouched by any of this: the
        reply keeps falling through to the override-else-default chain."""
        override = get_auto_key_for("#override-region")
        reply = self._reply()
        apply_reply_scope(reply, self._request(ROUTE_TYPE_DIRECT))  # never captured
        assert reply._flood_scope_applied is False
        self._tx(reply, flood_transport_key=override)
        assert reply.transport_codes[0] == calc_transport_code(override, reply)


class _AclClient:
    """Stand-in for a repeater ACL entry (firmware ``ClientInfo``)."""

    def __init__(self, out_path: bytes = b"", out_path_len: int = -1):
        self.out_path = bytearray(out_path)
        self.out_path_len = out_path_len


class TestLoginReplyRoute:
    """``chooseReplyRoute`` parity for ANON_REQ logins (RoutingPolicy.h).

    A login never carries a supplied reply path -- firmware's ``handleLoginReq``
    never sets ``reply_path_len`` -- so REPLY_ROUTE_DIRECT_SUPPLIED cannot arise
    and the table reduces to: flood => PATH return, stored out_path => DIRECT,
    otherwise => flood.
    """

    @staticmethod
    def _two_hop_path():
        """A 2-hop, 2-byte-hash out_path: 4 bytes, path_len 0x42."""
        return bytes([0xA1, 0xA2, 0xB1, 0xB2]), PathUtils.encode_path_len(2, 2)

    @pytest.mark.asyncio
    async def test_direct_login_with_out_path_replies_direct(self):
        """The reported bug: this used to be flooded, and died at hop 0 on any
        repeater running flood.max.unscoped=0."""
        out_path, out_path_len = self._two_hop_path()
        client_info = _AclClient(out_path, out_path_len)
        server, client = LocalIdentity(), LocalIdentity()
        handler, sent = _login_handler(server, get_client_fn=lambda _pub: client_info)

        req = _build_login_req(server, client, route_type=ROUTE_TYPE_DIRECT)
        await handler(req)

        assert len(sent) == 1
        reply = sent[0]
        assert reply.get_route_type() == ROUTE_TYPE_DIRECT
        assert bytes(reply.path) == out_path
        assert reply.path_len == out_path_len
        # A sendDirect is never scoped and never routed through sendFloodReply.
        assert reply.transport_codes == [0, 0]
        assert reply._flood_scope_applied is False

    @pytest.mark.asyncio
    async def test_out_path_reply_keeps_its_own_hash_width(self):
        """The stored path's width must survive: the request's width is mirrored
        onto flood replies only, and would misdescribe these path bytes."""
        out_path, out_path_len = self._two_hop_path()  # 2-byte hashes
        server, client = LocalIdentity(), LocalIdentity()
        handler, sent = _login_handler(
            server, get_client_fn=lambda _pub: _AclClient(out_path, out_path_len)
        )

        req = _build_login_req(server, client, route_type=ROUTE_TYPE_DIRECT)
        assert PathUtils.get_path_hash_size(req.path_len) == 1  # request is 1-byte
        await handler(req)

        reply = sent[0]
        assert PathUtils.get_path_hash_size(reply.path_len) == 2
        assert PathUtils.get_path_hash_count(reply.path_len) == 2
        assert reply._path_hash_mode_applied is False

    @pytest.mark.asyncio
    async def test_direct_login_without_out_path_still_floods(self):
        """REPLY_ROUTE_FLOOD fallback, unchanged."""
        server, client = LocalIdentity(), LocalIdentity()
        handler, sent = _login_handler(server, get_client_fn=lambda _pub: _AclClient())

        req = _build_login_req(server, client, route_type=ROUTE_TYPE_DIRECT)
        await handler(req)
        assert sent[0].get_route_type() == ROUTE_TYPE_FLOOD

    @pytest.mark.asyncio
    async def test_direct_login_without_an_acl_lookup_still_floods(self):
        """No ``get_client_fn`` wired (e.g. CompanionBridge): behaviour is
        exactly what it was before this change."""
        server, client = LocalIdentity(), LocalIdentity()
        handler, sent = _login_handler(server)  # get_client_fn defaults to None

        req = _build_login_req(server, client, route_type=ROUTE_TYPE_DIRECT)
        await handler(req)
        assert sent[0].get_route_type() == ROUTE_TYPE_FLOOD

    @pytest.mark.asyncio
    async def test_flood_login_still_gets_a_path_return(self):
        """REPLY_ROUTE_PATH_RETURN outranks a stored out_path."""
        out_path, out_path_len = self._two_hop_path()
        server, client = LocalIdentity(), LocalIdentity()
        handler, sent = _login_handler(
            server, get_client_fn=lambda _pub: _AclClient(out_path, out_path_len)
        )

        req = _build_login_req(server, client, route_type=ROUTE_TYPE_FLOOD)
        await handler(req)
        assert sent[0].get_payload_type() == PAYLOAD_TYPE_PATH

    @pytest.mark.asyncio
    async def test_flood_login_clears_a_stored_out_path(self):
        """Firmware ``handleLoginReq``: a client that reached us by flooding has
        no trustworthy stored path any more. Without this the *next* DIRECT
        request would be answered down a dead route."""
        out_path, out_path_len = self._two_hop_path()
        client_info = _AclClient(out_path, out_path_len)
        server, client = LocalIdentity(), LocalIdentity()
        handler, _sent = _login_handler(server, get_client_fn=lambda _pub: client_info)

        await handler(_build_login_req(server, client, route_type=ROUTE_TYPE_FLOOD))
        assert client_info.out_path_len == -1

        # ...so a subsequent DIRECT login falls back to flooding, not the stale path.
        handler2, sent2 = _login_handler(server, get_client_fn=lambda _pub: client_info)
        await handler2(_build_login_req(server, client, route_type=ROUTE_TYPE_DIRECT))
        assert sent2[0].get_route_type() == ROUTE_TYPE_FLOOD

    @pytest.mark.asyncio
    async def test_short_out_path_buffer_is_rejected(self):
        """``set_path`` stores the buffer verbatim while ``path_len`` keeps the
        declared count, so a short path makes ``write_to`` raise ``path_len
        mismatch`` and the reply is never transmitted. Falling back to a flood
        costs the direct route but still delivers."""
        _out_path, out_path_len = self._two_hop_path()  # declares 4 bytes
        server, client = LocalIdentity(), LocalIdentity()
        handler, sent = _login_handler(
            server, get_client_fn=lambda _pub: _AclClient(b"\xa1", out_path_len)
        )

        await handler(_build_login_req(server, client, route_type=ROUTE_TYPE_DIRECT))
        assert sent[0].get_route_type() == ROUTE_TYPE_FLOOD

    @pytest.mark.asyncio
    async def test_unencodable_out_path_len_is_rejected(self):
        bad_len = PathUtils.encode_path_len(3, 63)  # 189 bytes > MAX_PATH_SIZE
        assert PathUtils.is_valid_path_len(bad_len) is False
        server, client = LocalIdentity(), LocalIdentity()
        handler, sent = _login_handler(
            server, get_client_fn=lambda _pub: _AclClient(bytes(189), bad_len)
        )

        await handler(_build_login_req(server, client, route_type=ROUTE_TYPE_DIRECT))
        assert sent[0].get_route_type() == ROUTE_TYPE_FLOOD

    @pytest.mark.asyncio
    async def test_acl_lookup_failure_falls_back_to_flood(self):
        """An application ACL must not be able to kill the login reply."""

        def _boom(_pub):
            raise RuntimeError("ACL exploded")

        server, client = LocalIdentity(), LocalIdentity()
        handler, sent = _login_handler(server, get_client_fn=_boom)

        await handler(_build_login_req(server, client, route_type=ROUTE_TYPE_DIRECT))
        assert len(sent) == 1
        assert sent[0].get_route_type() == ROUTE_TYPE_FLOOD

    @pytest.mark.asyncio
    async def test_acl_is_looked_up_by_full_public_key(self):
        """Firmware ``acl.getClient(sender.pub_key, PUB_KEY_SIZE)`` -- not the
        one-byte hash ProtocolRequestHandler's lookup takes."""
        seen: list = []
        server, client = LocalIdentity(), LocalIdentity()
        handler, _sent = _login_handler(
            server, get_client_fn=lambda pub: seen.append(pub) or _AclClient()
        )

        await handler(_build_login_req(server, client, route_type=ROUTE_TYPE_DIRECT))
        assert seen == [client.get_public_key()]

    @pytest.mark.asyncio
    async def test_scoped_direct_login_with_out_path_is_not_scoped_or_restamped(self):
        """The DIRECT branch's two guards, with a request that actually captured
        a region -- without this the guards are unreachable and deleting them
        leaves the suite green.

        A DIRECT request can still arrive TRANSPORT_FLOOD-scoped (a repeater
        re-broadcast it under a Region), so ``apply_reply_scope`` would have a
        real key to stamp. A sendDirect must carry neither that scope nor the
        request's path-hash width.
        """
        a_key = get_auto_key_for("#region-a")
        region_map = RegionMap([RegionEntry(id=1, name="#region-a")])
        out_path, out_path_len = self._two_hop_path()
        server, client = LocalIdentity(), LocalIdentity()
        handler, sent = _login_handler(
            server, get_client_fn=lambda _pub: _AclClient(out_path, out_path_len)
        )

        req = _build_login_req(server, client, region_key=a_key)
        req.header = (req.header & ~0x03) | ROUTE_TYPE_DIRECT  # scoped, then routed direct
        capture_recv_region(region_map, req)
        assert req._recv_region_key is None  # direct => no codes to match on

        await handler(req)
        reply = sent[0]
        assert reply.get_route_type() == ROUTE_TYPE_DIRECT
        assert reply.transport_codes == [0, 0]
        assert reply._flood_scope_applied is False
        # The stored path's own width survived; the request's was not stamped on.
        assert reply.path_len == out_path_len
        assert reply._path_hash_mode_applied is False

    @pytest.mark.asyncio
    async def test_a_scoped_flood_login_still_scopes_its_path_return(self):
        """Cross-check for the test above: on the flood branch both calls do run,
        so the same RegionMap does scope the reply."""
        a_key = get_auto_key_for("#region-a")
        region_map = RegionMap([RegionEntry(id=1, name="#region-a")])
        server, client = LocalIdentity(), LocalIdentity()
        handler, sent = _login_handler(server, get_client_fn=lambda _pub: _AclClient())

        req = _build_login_req(server, client, region_key=a_key)
        capture_recv_region(region_map, req)
        await handler(req)

        reply = sent[0]
        assert reply.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD
        assert reply.transport_codes[0] == calc_transport_code(a_key, reply)
        assert reply._flood_scope_applied is True

    @pytest.mark.asyncio
    async def test_a_malformed_out_path_never_costs_the_reply(self):
        """An application ACL must not be able to kill the login reply. The
        pre-change handler always sent one; every unusable shape must still.

        ``contact_store`` persists ``out_path`` as a hex *string*, so an ACL
        backed by that on-disk shape is not hypothetical.
        """
        _p, good_len = self._two_hop_path()

        class _HexStr:
            out_path = "a1a2b1b2"

        class _BadList:
            out_path = [0xA1, 999, 0xB1, 0xB2]

        class _RaisesOnRead:
            @property
            def out_path(self):
                raise RuntimeError("ACL exploded")

        class _LenExplodes:
            out_path = b"\xa1\xa2\xb1\xb2"

            @property
            def out_path_len(self):
                raise RuntimeError("ACL exploded")

        _HexStr.out_path_len = good_len
        _BadList.out_path_len = good_len
        _RaisesOnRead.out_path_len = good_len

        for shape in (_HexStr, _BadList, _RaisesOnRead, _LenExplodes):
            client_info = shape()
            server, client = LocalIdentity(), LocalIdentity()
            handler, sent = _login_handler(server, get_client_fn=lambda _pub: client_info)

            await handler(_build_login_req(server, client, route_type=ROUTE_TYPE_DIRECT))
            assert len(sent) == 1, f"{shape.__name__} produced no login reply"
            assert sent[0].get_route_type() == ROUTE_TYPE_FLOOD

    @pytest.mark.asyncio
    async def test_flood_login_leaves_a_pathless_client_object_alone(self):
        """An app ACL that models only permissions must not have routing fields
        grafted onto it by a flood login."""

        class _PermsOnly:
            permissions = 0x03

        client_info = _PermsOnly()
        server, client = LocalIdentity(), LocalIdentity()
        handler, sent = _login_handler(server, get_client_fn=lambda _pub: client_info)

        await handler(_build_login_req(server, client, route_type=ROUTE_TYPE_FLOOD))
        assert len(sent) == 1
        assert not hasattr(client_info, "out_path_len")

    @pytest.mark.asyncio
    async def test_a_raising_out_path_len_never_costs_a_flood_reply(self):
        """``hasattr`` only swallows AttributeError, so the invalidation probe
        has to sit inside the guard or an exploding ACL property kills the
        PATH return."""

        class _LenExplodes:
            @property
            def out_path_len(self):
                raise RuntimeError("ACL exploded")

        server, client = LocalIdentity(), LocalIdentity()
        handler, sent = _login_handler(server, get_client_fn=lambda _pub: _LenExplodes())

        await handler(_build_login_req(server, client, route_type=ROUTE_TYPE_FLOOD))
        assert len(sent) == 1
        assert sent[0].get_payload_type() == PAYLOAD_TYPE_PATH

    @pytest.mark.asyncio
    async def test_flood_login_clears_both_halves_of_the_stored_path(self):
        """Length and buffer are cleared together, so nothing reading the pair
        (the REQ handler, PacketBuilder) sees a half-cleared record."""
        out_path, out_path_len = self._two_hop_path()
        client_info = _AclClient(out_path, out_path_len)
        server, client = LocalIdentity(), LocalIdentity()
        handler, _sent = _login_handler(server, get_client_fn=lambda _pub: client_info)

        await handler(_build_login_req(server, client, route_type=ROUTE_TYPE_FLOOD))
        assert client_info.out_path_len == -1
        assert bytes(client_info.out_path) == b""

    @pytest.mark.asyncio
    async def test_zero_hop_out_path_keeps_its_declared_width(self):
        """A client that is a direct neighbour has a 0-hop out_path, and 0 hops
        is exactly where ``apply_path_hash_mode`` stops being a no-op -- so this
        is the case where mirroring the request's width onto a sendDirect would
        actually corrupt the reply's ``path_len``.
        """
        out_path_len = PathUtils.encode_path_len(2, 0)  # 2-byte hashes, no hops
        assert PathUtils.get_path_byte_len(out_path_len) == 0
        server, client = LocalIdentity(), LocalIdentity()
        handler, sent = _login_handler(
            server, get_client_fn=lambda _pub: _AclClient(b"", out_path_len)
        )

        req = _build_login_req(server, client, route_type=ROUTE_TYPE_DIRECT)
        assert PathUtils.get_path_hash_size(req.path_len) == 1  # would restamp to 1
        await handler(req)

        reply = sent[0]
        assert reply.get_route_type() == ROUTE_TYPE_DIRECT
        assert reply.path_len == out_path_len
        assert reply._path_hash_mode_applied is False
        reply.write_to()  # declared width and buffer agree
