"""Regression tests for the OH-022 + OH-026 flood-scope fix.

OH-022: mirror the persisted default flood scope (and the explicit-unscoped
        flag) to the dispatcher, so sends that build a packet and rely on the
        dispatcher to scope it at TX time carry the default too.
OH-026: capture the region a request arrived under on the Packet, and scope a
        freshly-built flood reply to that region (or plain), never the node
        default.

Both parts share one ``scope_packet`` primitive and the ``_flood_scope_applied``
double-scope gate.
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
    RegionEntry,
    RegionMap,
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


def _login_handler(server: LocalIdentity):
    """A LoginServerHandler that always authenticates, capturing sent replies."""
    sent: list = []
    handler = LoginServerHandler(
        local_identity=server,
        log_fn=lambda *_: None,
        authenticate_callback=lambda *a, **k: (True, 0x03),
        is_room_server=False,
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
    async def test_unknown_region_reply_stays_plain(self):
        """(10) A request scoped to a region absent from the map => plain reply."""
        region_map, _a_key, _b_key = self._region_map()
        server, client = LocalIdentity(), LocalIdentity()
        handler, sent = _login_handler(server)

        unknown_key = get_auto_key_for("#not-in-map")
        req = _build_login_req(server, client, region_key=unknown_key)
        capture_recv_region(region_map, req)
        assert req._recv_region_captured is True
        assert req._recv_region_key is None  # no region matched

        await handler(req)
        reply = sent[0]
        assert reply.get_route_type() == ROUTE_TYPE_FLOOD
        assert reply.transport_codes == [0, 0]
        assert reply._flood_scope_applied is True

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
    async def test_direct_req_without_out_path_replies_plain_flood(self):
        """Branch (b): the node default must not reach this reply.

        A DIRECT request captures no region (firmware ``recv_pkt_region`` is
        NULL), so the flood RESPONSE stays plain and is marked applied.
        """
        region_map = RegionMap([RegionEntry(id=1, name="#region-a")])
        server, client = LocalIdentity(), LocalIdentity()
        handler = self._req_handler(server, self._client_info(client))  # no out_path

        req = self._build_req(server, client, route_type=ROUTE_TYPE_DIRECT)
        capture_recv_region(region_map, req)
        assert req._recv_region_captured is True
        assert req._recv_region_key is None

        result = await handler(req)
        assert result.authenticated is True
        reply = result.response
        assert reply is not None
        assert reply.get_route_type() == ROUTE_TYPE_FLOOD
        assert reply._flood_scope_applied is True

        # The gate has to actually hold at TX time against a configured default.
        dispatcher = Dispatcher(MockRadio())
        dispatcher.default_flood_transport_key = get_auto_key_for("#region-a")
        dispatcher._apply_flood_scope(reply)
        assert reply.get_route_type() == ROUTE_TYPE_FLOOD
        assert reply.transport_codes == [0, 0]

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


class TestBridgeRequestsCarryTheirOwnScope:
    """A virtual companion's requests take *its* scope, not its host repeater's.

    ``CompanionBridge`` shares the repeater's dispatcher and, unlike
    ``CompanionRadio``, cannot mirror its scope onto it -- the dispatcher belongs
    to the repeater. So anything the bridge leaves for the send-time resolver
    comes out stamped with the repeater's region instead of the one the app set
    over the frame protocol. Firmware has no such split: sendLogin, sendAnonReq,
    sendRequest and sendCommandData all go through
    ``MyMesh::sendFloodScoped(const ContactInfo&)``, which reads the companion's
    own send_unscoped / send_scope / default_scope_key.
    """

    async def _bridge_over_a_scoped_repeater(self):
        """A bridge whose injector runs packets through a repeater's resolver."""
        sink = MockRadio()  # only its .sent list is used, as the injector's sink
        dispatcher = Dispatcher(MockRadio())
        dispatcher.flood_transport_key = get_auto_key_for("#repeater-region")

        async def _injector(pkt, wait_for_ack=False, expected_crc=None):
            # Mirrors the real path: PacketRouter.inject_packet eventually lands
            # in Dispatcher.send_packet, which calls _apply_flood_scope.
            dispatcher._apply_flood_scope(pkt)
            sink.sent.append(bytes(pkt.write_to()))
            return True

        bridge = CompanionBridge(LocalIdentity(), _injector, node_name="bridge")
        peer = LocalIdentity()
        key = peer.get_public_key()
        bridge.contacts.add(Contact(public_key=key, name="rpt"))  # out_path_len=-1
        await bridge.start()
        bridge_key = get_auto_key_for("#bridge-region")
        bridge.set_flood_scope(bridge_key)
        return bridge, sink, key, bridge_key

    def _assert_bridge_scoped(self, pkt: Packet, bridge_key: bytes, label: str):
        assert pkt.get_route_type() == ROUTE_TYPE_TRANSPORT_FLOOD, f"{label} not scoped"
        assert pkt.transport_codes[0] == calc_transport_code(
            bridge_key, pkt
        ), f"{label} carries the repeater's region, not the bridge's"

    @pytest.mark.asyncio
    async def test_bridge_requests_use_the_bridge_scope(self):
        """[fails pre-fix] Login/status/telemetry/CLI take the bridge's own region."""
        bridge, sink, key, bridge_key = await self._bridge_over_a_scoped_repeater()
        try:
            for label, coro in (
                ("login", bridge.send_login(key, "pw")),
                ("status", bridge.send_status_request(key)),
                ("telemetry", bridge.send_telemetry_request(key)),
                ("cli", bridge.send_repeater_command(key, "ver")),
            ):
                pkt = await _drain_first_tx(bridge, sink, coro)
                self._assert_bridge_scoped(pkt, bridge_key, label)
        finally:
            await bridge.stop()

    @pytest.mark.asyncio
    async def test_bridge_unscoped_request_is_not_given_the_repeater_region(self):
        """[fails pre-fix] An app that asked for un-scoped gets un-scoped.

        ``set_flood_unscoped`` is firmware's send_unscoped (FW #2492): the very
        first branch of sendFloodScoped, ahead of both the override and the
        default. Leaving the packet for the repeater's resolver instead silently
        overrides the app's explicit choice.
        """
        bridge, sink, key, _bridge_key = await self._bridge_over_a_scoped_repeater()
        try:
            bridge.set_flood_unscoped()
            pkt = await _drain_first_tx(bridge, sink, bridge.send_login(key, "pw"))
            assert pkt.get_route_type() == ROUTE_TYPE_FLOOD
            assert pkt.transport_codes == [0, 0]
        finally:
            await bridge.stop()


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
