"""Reciprocal return-path teaching for flood-routed replies.

MeshCore servers do **not** derive a reply route by reversing the path an
inbound request arrived on. ``simple_repeater``'s ``MyMesh::onPeerDataRecv``
answers a DIRECT ``PAYLOAD_TYPE_REQ`` out of the per-client ``out_path`` stored
in its ACL::

    if (client->out_path_len != OUT_PATH_UNKNOWN) {
      sendDirect(reply, client->out_path, client->out_path_len, ...);
    } else {
      sendFloodReply(reply, ...);
    }

That ``out_path`` has exactly one writer — ``onPeerPathRecv``, i.e. receiving a
``PAYLOAD_TYPE_PATH`` packet from the client. A client that never sends one
leaves the server replying down whatever route it last stored, which after a
direct login is either nothing (``OUT_PATH_UNKNOWN`` -> flood) or a stale route
from an earlier session (``MyMesh.cpp``: ``if (is_flood) client->out_path_len =
OUT_PATH_UNKNOWN;`` — a *direct* login deliberately does not reset it).

MeshCore's chat client covers this with a self-healing retry
(``BaseChatMesh::onPeerDataRecv`` RESPONSE branch and ``onAckRecv``)::

    if (packet->isRouteFlood() && from.out_path_len != OUT_PATH_UNKNOWN) {
      // we have direct path, but other node is still sending flood response,
      // so maybe they didn't receive reciprocal path properly(?)
      handleReturnPathRetry(from, packet->path, packet->path_len);
    }

A flood reply from a peer we *already* hold a direct ``out_path`` for is the
tell: the peer has no usable route back to us. The fix is to re-teach it with a
``createPathReturn`` sent DIRECT along our own ``out_path``.

openHop previously sent a reciprocal PATH in only one place — on receiving a
flood ``PAYLOAD_TYPE_PATH`` (:mod:`.protocol_response`). That covers a *flood*
login, whose response comes back wrapped in a PATH. It does not cover a login
sent DIRECT (the user-forced-path case), which the server answers with a plain
flood ``RESPONSE``. This module supplies the missing parity.

Deliberate deviations from firmware, each documented at its definition:

* ``RETURN_PATH_COOLDOWN_S`` throttles re-teaching per contact. Firmware has no
  such throttle; openHop adds one so a burst of flood replies cannot turn into a
  burst of transmits.
* Firmware paces its retry with ``sendDirect(..., 3000)`` — a *queued* send whose
  3 s delay is a settle window (``queueOutbound(..., futureMillis(3000))``), not a
  busy wait. openHop honours that window (``RETURN_PATH_SETTLE_S``) in a background
  task rather than inline on the RX path: the injector may block on a TX lock and
  an airtime budget, and awaiting it inline would delay delivery of the very reply
  that triggered the teach, potentially past its own response timeout.
* openHop chooses the teach source across every copy of the flood reply,
  collected pre-dedup via ``note_flood_copy``, and ranks them by **decodability
  rather than signal strength**: a copy's SNR margin over the demodulator limit
  decides whether its link is reliable, and among reliable copies the shortest
  route wins. Firmware embeds whichever copy it processed first, and only its
  (SNR-scored, ships-disabled) reception hold makes that the best one; neither
  firmware mode weighs hop count, so a strong nearby repeater can append itself
  as an extra hop. See ``SF_DEMOD_SNR_LIMIT_DB``,
  ``RETURN_PATH_RELIABLE_MARGIN_DB`` and ``_copy_rank`` for the model and the
  measurements behind it. There is deliberately no cross-reply downgrade guard:
  firmware has none, and a flood reply from a peer we hold an ``out_path`` for is
  by this module's own premise a broken return route, so refusing to re-teach it
  because a newer copy is weaker than a previous (non-working) one would prolong
  the failure.
* The reciprocal teach that follows a flood login cannot wait for that window —
  the peer needs a usable route immediately — so it goes out on the copy in hand
  and then corrects itself once the window closes
  (``maybe_reteach_better_copy``). Firmware never re-teaches, but it is safe
  against firmware: ``onPeerPathRecv`` stores the path with an unconditional
  ``copyPath``, touches no replay watermark, and returns ``false`` so no
  reciprocal bounces back. The correction only transmits when the better copy
  differs, so the common case costs nothing.

Every teach this module sends embeds a path it actually observed. It deliberately
does **not** guess one: an earlier revision, on a request timeout, taught the
reverse of our own ``out_path`` on the assumption that routes are symmetric.
Real routes frequently are not, and ``onPeerPathRecv`` overwrites
``client->out_path`` unconditionally (``BaseChatMesh.cpp``), so a wrong guess
replaced a working route with a dead one and the peer then answered DIRECT into a
void — leaving no flood reply to correct it. The timeout case is handled where the
evidence can actually be obtained instead: the request itself is re-sent as a
flood on retry (``_SendOpsMixin._build_retry_packet``), and the peer answers a
flood request with a PATH-return, which is a real inbound path to teach from.

Not yet covered: firmware also re-teaches from ``onAckRecv``. A discrete ACK on
the wire is a bare 4-byte CRC with no source hash, and openHop's dispatcher
tracks pending ACK CRCs in a plain set with no contact attribution, so there is
nothing to key the re-teach on. Wiring that up needs a CRC->contact map in the
send path; it is not required for the request/response flows this module fixes.
"""

from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from typing import Any, Callable, Optional, Set, Tuple

from ...protocol import Identity, Packet
from ...protocol.constants import (
    PAYLOAD_TYPE_PATH,
    PAYLOAD_TYPE_RESPONSE,
    PH_ROUTE_MASK,
    ROUTE_TYPE_DIRECT,
)
from ...protocol.packet_builder import PacketBuilder
from ...protocol.packet_utils import PathUtils

# Flood payload types whose arrival can trigger a return-path teach, and whose
# copies are therefore worth collecting: RESPONSE (a server answering a direct
# request by flood) and PATH (the path-return that answers a flood request or
# flood login). Both carry ``dest_hash | src_hash | encrypted``.
_TEACHABLE_COPY_TYPES = (PAYLOAD_TYPE_RESPONSE, PAYLOAD_TYPE_PATH)

# Minimum gap between two return-path teaches aimed at the same contact.
# Firmware has no equivalent throttle: it re-teaches on every qualifying flood
# reply. openHop adds one as a safety valve so a peer that keeps flooding (for
# example because our teach itself is not getting through) cannot drive an
# unbounded transmit rate.
#
# This is shorter than a typical request retry cadence but not uniformly so:
# measured adaptive response timeouts (SF10/250k/4:5, 40 B) run ~2.4 s zero-hop,
# ~4.2 s one-hop, ~4.8 s flood and ~6.1 s at two hops, so for near contacts the
# second and third retry-driven teaches are suppressed. That is intended — the
# first teach after a timeout still goes out immediately, because a contact with
# no prior teach has no cooldown entry, and re-teaching the same guess every two
# seconds buys nothing.
RETURN_PATH_COOLDOWN_S = 5.0

# How long to keep collecting copies of a flood reply before teaching from the
# best-received one. Firmware sends its retry with ``sendDirect(..., 3000)``;
# that 3 s is a queued-send "not before" schedule (``queueOutbound(...,
# futureMillis(3000))``) — a settle window, not just pacing.
#
# A flood reply reaches us by several routes, and openHop's dedup, like
# firmware's ``hasSeen``, is "first packet wins". The first copy to arrive is
# NOT the best route -- observed on a live SF7/62.5k mesh, four copies of one
# login reply landed over ~6 s at -102, -62, -41 and -24 dBm, weakest first.
# Teaching from the first copy tells the peer to answer down its most marginal
# link, and its replies then die there while flood replies still get through,
# which looks exactly like the bug this module was written to fix.
#
# Firmware avoids this only when its reception-quality hold is enabled: the hold
# reorders flood processing so the best-scored copy is seen (and marks-seen)
# first, making firmware's embedded ``packet->path`` the best copy. But the hold
# is scored on SNR alone and ships DISABLED (``rx_delay_base`` is memset-zeroed;
# the enabling line is commented "enable once new algo fixed"), so on a stock
# node firmware embeds the first-arrived copy -- and its 3 s delay only defers
# the transmit, it does not re-pick the copy. openHop therefore selects the
# teach source itself, by decodability margin and hop count (see
# ``_copy_rank`` and ``note_flood_copy``), during this window
# instead of leaning on the hold. Unchanged on the wire, strictly better than
# firmware when the hold is off and no worse when it is on.
RETURN_PATH_SETTLE_S = 3.0

# --- Copy selection: decodability, not raw signal strength -------------------
#
# LoRa demodulates below the noise floor, so what decides whether a copy's link
# works is its SNR margin over the demodulator limit for the spreading factor --
# not its absolute RSSI. Measured on this mesh (SF7/62.5 kHz): four copies of one
# reply arrived at -16, -21, -69 and -80 dBm and *every one* reported +11.25 to
# +12.5 dB SNR, i.e. ~19 dB of margin. RSSI spanned 86 dB while decodability was
# pinned at "certain" for all of them. Ranking those by RSSI ranks noise.
#
# The PER-vs-SNR curve is a waterfall: it goes from ~0 to ~1 across roughly 3-6 dB
# around the limit. Above ~6 dB of margin, loss is dominated by collisions rather
# than signal, so extra dB buy nothing and an extra hop can never be an RF
# improvement. Below the limit the link is dead. dB are only currency inside that
# narrow band, which is why selection is a threshold rule rather than the linear
# dB-per-hop trade this replaced (that trade was calibrated around -56 dBm, some
# 60 dB above where decodability actually changes).
#
# Semtech SX126x LoRa demodulator SNR limits, dB, by spreading factor.
SF_DEMOD_SNR_LIMIT_DB = {
    5: -2.5,
    6: -5.0,
    7: -7.5,
    8: -10.0,
    9: -12.5,
    10: -15.0,
    11: -17.5,
    12: -20.0,
}
RETURN_PATH_DEFAULT_SF = 7

# Fallback noise floor for turning an RSSI into a margin when SNR is unavailable.
# Measured floor on this mesh ran -100 to -114 dBm (typical -107/-108), i.e. ~18 dB
# above thermal for SF7/62.5 kHz -- these nodes are noise-limited, not
# sensitivity-limited (datasheet sensitivity would be ~-126 dBm).
RETURN_PATH_ASSUMED_NOISE_FLOOR_DBM = -108.0

# Hard floor: below this margin a copy is not a route at all, so it is never
# recorded as a teach candidate. Sits just above the demodulator limit, inside the
# waterfall, where PER is already climbing steeply.
RETURN_PATH_MIN_MARGIN_DB = 2.0

# Margin at which a link is "reliable enough": past the waterfall, into the region
# where loss is collision-driven and further dB are worthless. Copies at or above
# this are ranked by HOP COUNT alone -- the whole point of the policy.
RETURN_PATH_RELIABLE_MARGIN_DB = 6.0

# Why hops are penalised at all, given the signal says they are free:
#   1. We only ever measure the LAST hop. For a zero-hop copy that is the entire
#      path; for an N-hop copy it is 1 of N links, and the others are known only
#      to have worked once. Confidence is structurally lower.
#   2. Each hop adds airtime plus MeshCore's randomised getDirectRetransmitDelay,
#      and consumes shared channel capacity on a mesh where collisions dominate.
#   3. The relay has to be *willing* to forward routed traffic (disable_fwd, ACL,
#      region policy). No signal metric can see that -- observed here: the
#      strongest-RSSI relay on the mesh forwarded none of it.
# So a hop is only ever bought when the shorter alternative is genuinely marginal.

# Bounds for the best-copy table (``note_flood_copy``): entries older than the
# TTL are dropped and the table never holds more than ``_MAX`` hashes (oldest
# evicted). The TTL only has to outlive one settle window; it is clamped up to
# cover a custom ``settle_s`` in __init__.
RETURN_PATH_COPY_TTL_S = 8.0
RETURN_PATH_COPY_CACHE_MAX = 128


def _delivered_in_process(pkt: Packet) -> bool:
    """True when the host handed us this copy in-process rather than over RF.

    A host that runs several identities on one radio hands traffic between them
    to the co-hosted addressee directly; the repeater's inject path marks that
    very object ``_injected_for_tx`` before fanning it out. That copy is
    zero-hop and loss-free, so no route heard over the air can beat it -- yet
    its ``_rssi``/``_snr`` are 0, which would rank it as a weak radio copy. A
    packet parsed off the radio never carries the marker.
    """
    return bool(getattr(pkt, "_injected_for_tx", False))


def _hop_count(len_byte: int) -> int:
    """Hop count encoded in a path_len byte; 0 when the byte does not decode."""
    try:
        return PathUtils.get_path_hash_count(len_byte)
    except Exception:
        return 0


class _FloodCopy:
    """The best-received copy of one flood reply, keyed by its packet hash.

    ``path`` / ``len_byte`` are the flood accumulation path that copy arrived on —
    the route the peer should be taught to use back to us. ``rssi`` and ``margin``
    are the last-hop measurements kept for logging and tie-breaks; ``rank`` is the
    comparable tuple copies are ordered by (see
    :meth:`ReturnPathTeacher._copy_rank`). ``ts`` is the monotonic time the entry
    was last improved, for TTL pruning.
    """

    __slots__ = ("path", "len_byte", "rssi", "margin", "rank", "ts")

    def __init__(
        self,
        path: bytes,
        len_byte: int,
        rssi: int,
        margin: float,
        rank: tuple,
        ts: float,
    ) -> None:
        self.path = path
        self.len_byte = len_byte
        self.rssi = rssi
        self.margin = margin
        self.rank = rank
        self.ts = ts


class ReturnPathTeacher:
    """Sends ``PAYLOAD_TYPE_PATH`` teaches so a peer learns its route back to us.

    One instance is shared by the login and protocol-response handlers (see
    :func:`..registry.create_core_handlers`) so the cooldown is accounted per
    contact rather than per handler.
    """

    def __init__(
        self,
        log_fn: Callable[[str], None],
        local_identity: Any,
        contact_book: Any,
        *,
        cooldown_s: float = RETURN_PATH_COOLDOWN_S,
        settle_s: float = RETURN_PATH_SETTLE_S,
        sf_getter: Optional[Callable[[], int]] = None,
        noise_floor_dbm: float = RETURN_PATH_ASSUMED_NOISE_FLOOR_DBM,
        min_margin_db: float = RETURN_PATH_MIN_MARGIN_DB,
        reliable_margin_db: float = RETURN_PATH_RELIABLE_MARGIN_DB,
        time_fn: Callable[[], float] = time.monotonic,
    ) -> None:
        self._log = log_fn
        self._local_identity = local_identity
        self._contact_book = contact_book
        self._cooldown_s = cooldown_s
        self._settle_s = settle_s
        # Spreading factor decides the demodulator limit every margin is measured
        # against. A callable so a runtime radio reconfigure is picked up; falls
        # back to SF7 when the host does not supply one.
        self._sf_getter = sf_getter
        self._noise_floor_dbm = noise_floor_dbm
        self._min_margin_db = min_margin_db
        self._reliable_margin_db = reliable_margin_db
        self._time = time_fn
        self._injector: Optional[Callable] = None
        # contact pubkey -> monotonic timestamp of the last teach dispatched.
        # Bounded by the contact book: keys only come from resolved contacts.
        self._last_taught: dict[bytes, float] = {}
        # In-flight teach tasks, so callers (and tests) can await completion.
        self._pending_teaches: Set[asyncio.Task] = set()
        # packet hash -> best-received copy, populated pre-dedup by
        # note_flood_copy across the settle window. Bounded and TTL-pruned; the
        # TTL must outlive one settle window.
        self._recent_copies: "OrderedDict[bytes, _FloodCopy]" = OrderedDict()
        self._copy_ttl_s = max(RETURN_PATH_COPY_TTL_S, self._settle_s + 2.0)
        self._copy_cache_max = RETURN_PATH_COPY_CACHE_MAX
        # Cached destination hash (our own) used to filter recorded copies to
        # replies addressed to us. Resolved lazily so a late-bound identity still
        # works; None means "record regardless" rather than dropping everything.
        self._local_hash: Optional[int] = None

    def set_injector(self, injector: Optional[Callable]) -> None:
        """Set the async callable used to transmit a teach packet."""
        self._injector = injector

    def note_evidence_teach(self, contact_pubkey: bytes) -> None:
        """Record that a return path was taught to ``contact_pubkey`` elsewhere.

        :meth:`ProtocolResponseHandler._send_reciprocal_path` also teaches a
        return path (its flood-PATH reciprocal). Reporting it here claims the
        cooldown, so this teacher does not immediately re-teach the same contact
        the same route.
        """
        self._last_taught[bytes(contact_pubkey)] = self._time()

    def note_flood_copy(self, pkt: Packet, data: Any = None, analysis: Any = None) -> None:
        """Record a flood reply copy for best-route selection (raw RX subscriber).

        Wired via ``dispatcher.add_raw_packet_subscriber``, which fires for every
        received packet *before* dedup — the only place later copies of a flood
        reply are visible, since dedup drops them before any handler runs. Keeps,
        per packet hash, the best-ranked copy (decodability margin then hop count,
        see :meth:`_copy_rank`) so a teach triggered on the first-arrived copy
        can still embed the best route (see :meth:`maybe_teach_from_flood_reply`).

        Best-effort and cheap: only flood packets addressed to us whose type can
        trigger a teach are recorded (``RESPONSE`` and ``PATH``), and any error is
        swallowed — this runs on the hot RX path and must never disturb packet
        processing.

        ``PATH`` is included because a *flood login* is answered with a flood
        PATH-return, and the reciprocal teach that follows it
        (``ProtocolResponseHandler._send_reciprocal_path``) is the single most
        consequential teach we send: it decides the route the peer will use for
        every later direct reply. Both types share the
        ``dest_hash | src_hash | encrypted`` payload prefix, and the packet hash
        is path-independent, so copies of either key together.
        """
        if self._injector is None:
            return
        try:
            if not pkt.is_route_flood():
                return
            if pkt.get_payload_type() not in _TEACHABLE_COPY_TYPES:
                return
            payload = getattr(pkt, "payload", None)
            if payload is None or len(payload) < 2:
                return
            if not self._addressed_to_us(payload[0]):
                return
            self._record_packet(pkt)
        except Exception as e:  # never let a bad copy disturb RX
            self._log(f"[ReturnPath] note_flood_copy ignored a packet: {e}")

    async def wait_for_pending(self) -> None:
        """Await every in-flight teach. Intended for shutdown and for tests."""
        if self._pending_teaches:
            await asyncio.gather(*tuple(self._pending_teaches), return_exceptions=True)

    @property
    def enabled(self) -> bool:
        """True when a transmit path has been wired up."""
        return self._injector is not None

    # ------------------------------------------------------------------
    # Firmware parity: re-teach after a flood reply
    # ------------------------------------------------------------------

    async def maybe_teach_from_flood_reply(
        self,
        pkt: Packet,
        contact_pubkey: bytes,
        src_hash: int,
        *,
        reason: str,
        shared_secret: Optional[bytes] = None,
    ) -> bool:
        """Re-teach our return path when a flood reply arrives from a known route.

        Mirrors ``BaseChatMesh::onPeerDataRecv``'s RESPONSE branch: only fires
        when the reply is flood-routed *and* we already hold a direct
        ``out_path`` for the sender. The path embedded in the teach is the flood
        accumulation path the reply arrived on, which is precisely the route
        from the peer back to us.

        The triggering ``pkt`` is only the *first-arrived* copy (dedup drops the
        rest before this handler runs). This copy is used as a seed/fallback, but
        the teach is delayed by :data:`RETURN_PATH_SETTLE_S` and then embeds the
        best-RSSI copy collected pre-dedup by :meth:`note_flood_copy` — see the
        constant's docstring for why first-arrived is often the worst route.

        Returns True when a teach was transmitted.
        """
        if self._injector is None:
            return False
        if not pkt.is_route_flood():
            return False

        out_path, out_path_len = self._known_out_path(contact_pubkey)
        if out_path is None:
            # No stored route to the peer, so a flood reply is the expected
            # behaviour, not a symptom. Firmware's OUT_PATH_UNKNOWN guard.
            return False

        # Seed the best-copy table with this first-arrived copy so a teach still
        # has a source even when no raw subscriber is wired (standalone/tests);
        # note_flood_copy improves it with better copies during the settle window.
        recorded = self._record_packet(pkt)
        if recorded is None:
            self._log(
                f"[ReturnPath] Skip teach to 0x{src_hash:02X}: inbound path "
                f"(path_len 0x{int(getattr(pkt, 'path_len', 0) or 0):02X}) "
                f"is malformed or truncated"
            )
            return False
        embedded_path, in_len_byte, packet_hash = recorded

        return await self._teach(
            contact_pubkey=contact_pubkey,
            dest_hash=src_hash,
            embedded_path=embedded_path,
            embedded_len_byte=in_len_byte,
            out_path=out_path,
            out_path_len=out_path_len,
            shared_secret=shared_secret,
            reason=reason,
            hash_key=packet_hash,
            settle_s=self._settle_s,
        )

    def seed_copy(self, pkt: Packet, packet_hash: Optional[bytes] = None) -> None:
        """Record the copy a caller is teaching from, so only a better one replaces it.

        ``maybe_reteach_better_copy`` re-teaches whenever the best recorded copy
        differs from the route it taught. That is only a *better* route if the
        taught copy was itself in the table: the pre-dedup feed
        (``note_flood_copy``) records every radio copy, but a copy the host
        delivered in-process never passes the radio, so without this an echo of
        our own flood -- relayed back by a nearby repeater -- was the sole entry
        and re-taught a co-hosted peer a route through that repeater. Recording
        the same radio copy twice is harmless (an equal rank keeps the entry).

        Best-effort and never raises: the teach it refines has already gone out.
        Pass ``packet_hash`` when the caller has computed it already.
        """
        try:
            self._record_packet(pkt, packet_hash)
        except Exception as e:
            self._log(f"[ReturnPath] seed_copy ignored a packet: {e}")

    # ------------------------------------------------------------------
    # Refine a teach that was already sent from the first-arrived copy
    # ------------------------------------------------------------------

    def schedule_reteach_better_copy(self, **kwargs: Any) -> None:
        """Run :meth:`maybe_reteach_better_copy` as a tracked background task.

        The corrective teach waits out the settle window, so it must not be
        awaited by the caller: the reciprocal's own send task should complete as
        soon as the wire write does, or ``wait_for_pending_reciprocals`` (and
        shutdown behind it) would block for the whole window. The task is tracked
        in ``_pending_teaches``, so :meth:`wait_for_pending` still covers it.
        """
        if self._injector is None:
            return
        task = asyncio.ensure_future(self.maybe_reteach_better_copy(**kwargs))
        self._pending_teaches.add(task)
        task.add_done_callback(self._pending_teaches.discard)

    async def maybe_reteach_better_copy(
        self,
        *,
        contact_pubkey: bytes,
        dest_hash: int,
        taught_path: bytes,
        taught_len_byte: int,
        out_path: bytes,
        out_path_len: int,
        shared_secret: bytes,
        hash_key: bytes,
        reason: str,
    ) -> bool:
        """Re-teach once if the settle window found a better route than ``taught_path``.

        A flood reply arrives as several copies over a couple of seconds, but the
        teach it triggers must go out immediately — the peer needs *some* usable
        route, and delaying the reciprocal would delay the login that carries it.
        So the caller teaches from the first-arrived copy and then calls this to
        correct itself once the better copies have landed.

        Teaching twice is safe against firmware. ``simple_repeater``'s
        ``onPeerPathRecv`` (and ``simple_room_server``'s) stores the path with an
        unconditional ``copyPath`` — last write wins, no comparison — touches only
        ``last_activity`` so the REQ replay watermark is unaffected, and returns
        ``false`` with an explicit ``// NOTE: no reciprocal path send!!``, so there
        is no ping-pong. ``Mesh.cpp`` gates its own reciprocal on
        ``isRouteFlood()`` too, and this teach is DIRECT, so even a
        ``BaseChatMesh`` peer will not bounce one back.

        The residual risk is wire-order inversion: ``copyPath`` has no sequence
        number, so if the first (worse) teach somehow landed *after* this one the
        peer would keep the worse route. The settle window's seconds of separation
        make that far beyond normal relay jitter, and this only transmits when the
        route actually differs, so the common case sends nothing at all.

        Returns True when a corrective teach was transmitted.
        """
        if self._injector is None:
            return False
        if self._settle_s > 0.0:
            await self._settle(self._settle_s)

        best = self._recent_copies.pop(bytes(hash_key), None)
        if best is None:
            return False
        if best.path == taught_path and best.len_byte == taught_len_byte:
            return False  # first copy was already the best; nothing to correct

        key = bytes(contact_pubkey)
        try:
            teach = PacketBuilder.create_path_return(
                dest_hash=dest_hash,
                src_hash=self._local_identity.get_public_key()[0],
                secret=shared_secret,
                path=best.path,
                extra_type=0xFF,  # no extra payload (firmware passes NULL/0)
                extra=b"",
                path_len_encoded=best.len_byte,
            )
            teach.header = (teach.header & ~PH_ROUTE_MASK) | ROUTE_TYPE_DIRECT
            teach.set_path(out_path, out_path_len)
            await self._injector(teach)
        except Exception as e:
            self._log(f"[ReturnPath] Failed to re-teach 0x{dest_hash:02X}: {e}")
            return False

        # Deliberately does NOT consult the cooldown: this is a correction to a
        # teach just sent (which claimed it), not a new one. It does refresh the
        # claim so an unrelated trigger still gets throttled.
        self._last_taught[key] = self._time()
        try:
            hops = PathUtils.get_path_hash_count(best.len_byte)
        except Exception:
            hops = "?"
        self._log(
            f"[ReturnPath] Re-taught 0x{dest_hash:02X} its route back ({reason}): "
            f"better copy {best.path.hex() or '(zero-hop)'} "
            f"(path_len=0x{best.len_byte:02X}, {hops} hop(s), last-hop margin "
            f"{best.margin:.1f}dB, RSSI {best.rssi}) replaces "
            f"{taught_path.hex() or '(zero-hop)'}"
        )
        return True

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _known_out_path(self, contact_pubkey: bytes) -> tuple[Optional[bytes], int]:
        """Return ``(out_path, encoded_len)`` for a contact, or ``(None, -1)``.

        ``out_path_len`` is the encoded path_len byte, with -1 standing in for
        firmware's ``OUT_PATH_UNKNOWN``. Zero is a *known* route (zero-hop
        direct neighbour) and must not be confused with unknown, so the value is
        range-checked rather than truth-tested.
        """
        try:
            contact = self._contact_book.get_by_key(contact_pubkey)
        except Exception as e:
            self._log(f"[ReturnPath] Contact lookup failed: {e}")
            return None, -1
        if contact is None:
            return None, -1

        raw_len = getattr(contact, "out_path_len", -1)
        try:
            out_path_len = -1 if raw_len is None else int(raw_len)
        except (TypeError, ValueError):
            return None, -1
        if out_path_len < 0 or not PathUtils.is_valid_path_len(out_path_len):
            return None, -1

        out_path = bytes(getattr(contact, "out_path", b"") or b"")
        expected = PathUtils.get_path_byte_len(out_path_len)
        if len(out_path) < expected:
            self._log(
                f"[ReturnPath] Stored out_path is {len(out_path)}B but path_len "
                f"0x{out_path_len:02X} declares {expected}B — not teaching"
            )
            return None, -1
        return out_path[:expected], out_path_len

    def _shared_secret_for(self, contact_pubkey: bytes) -> Optional[bytes]:
        """Derive the X25519 shared secret with ``contact_pubkey``."""
        try:
            return Identity(bytes(contact_pubkey)).calc_shared_secret(
                self._local_identity.get_private_key()
            )
        except Exception as e:
            self._log(f"[ReturnPath] Failed to derive shared secret: {e}")
            return None

    def _cooldown_active(self, key: bytes) -> bool:
        """Whether ``key``'s cooldown blocks the teach about to be dispatched.

        Every teach now embeds an observed path, so there is one kind of claim
        and the window is a plain rate limit.
        """
        last = self._last_taught.get(key)
        return last is not None and (self._time() - last) < self._cooldown_s

    # ---- best-copy collection (decodability-threshold selection) ------------

    def _demod_limit_db(self) -> float:
        """SNR limit of the demodulator at the current spreading factor."""
        sf = RETURN_PATH_DEFAULT_SF
        if self._sf_getter is not None:
            try:
                sf = int(self._sf_getter())
            except Exception:
                sf = RETURN_PATH_DEFAULT_SF
        return SF_DEMOD_SNR_LIMIT_DB.get(sf, SF_DEMOD_SNR_LIMIT_DB[RETURN_PATH_DEFAULT_SF])

    def _copy_margin_db(self, rssi: int, snr: float) -> float:
        """How many dB of margin this copy's last hop had over the demod limit.

        Two independent estimates, and the **pessimistic** one is used:

        * from SNR directly — ``snr - demod_limit`` — which self-normalises for
          whatever the noise floor happens to be;
        * from RSSI against an assumed noise floor, for radios or paths that
          report no SNR.

        Taking the minimum means a copy counts as reliable only when neither
        estimate calls it marginal, and it removes any need to guess whether a
        reported ``0`` means "0 dB" or "not measured": at a genuine 0 dB SNR the
        RSSI sits at about the noise floor, so the two estimates agree anyway.
        """
        limit = self._demod_limit_db()
        from_snr = float(snr) - limit
        from_rssi = float(rssi) - (self._noise_floor_dbm + limit)
        return min(from_snr, from_rssi)

    def _copy_rank(self, margin: float, len_byte: int, rssi: int) -> tuple:
        """Comparable rank for a copy; larger is better.

        Lexicographic, because dB only matter inside the waterfall:

        * A copy at or above ``reliable_margin_db`` outranks every copy below it,
          however strong the weaker one's signal looks. Within that reliable tier
          the order is **fewest hops**, then margin, then RSSI — extra dB above
          the waterfall buy nothing, so hop count decides.
        * Below the threshold the copy is in the steep region, where each dB does
          change delivery odds: order by margin, then fewest hops, then RSSI.

        The two tiers never compare their later elements against each other (the
        leading tier flag decides first), so an extra hop is only ever bought when
        every shorter copy is genuinely marginal and the longer one clears the
        threshold.
        """
        hops = _hop_count(len_byte)
        if margin >= self._reliable_margin_db:
            return (1, -hops, margin, rssi)
        return (0, margin, -hops, rssi)

    def _addressed_to_us(self, dest_hash: int) -> bool:
        """True when ``dest_hash`` is our own hash (or our hash is unknown).

        Filters the pre-dedup firehose down to replies actually meant for us.
        If our hash cannot be resolved we record regardless rather than drop
        everything — a slightly larger table is safer than a silent no-op.
        """
        if self._local_hash is None:
            try:
                self._local_hash = self._local_identity.get_public_key()[0]
            except Exception:
                return True
        return dest_hash == self._local_hash

    def _record_packet(
        self, pkt: Packet, packet_hash: Optional[bytes] = None
    ) -> Optional[Tuple[bytes, int, bytes]]:
        """Validate a copy's inbound path and record it; the one way copies get in.

        Every entry point (:meth:`note_flood_copy`, :meth:`seed_copy`,
        :meth:`maybe_teach_from_flood_reply`) goes through here, so a copy is
        always ranked the same way -- in-process detection included. Callers
        keep their own pre-filters. ``packet_hash`` saves the SHA-256 when the
        caller already has it.

        Returns ``(path, len_byte, packet_hash)``, or None when the path is
        malformed or truncated. A copy whose margin is too low is still
        returned (the caller may teach from it) even though it is not recorded.
        """
        len_byte = int(getattr(pkt, "path_len", 0) or 0)
        path = self._validated_inbound_path(pkt, len_byte)
        if path is None:
            return None
        if packet_hash is None:
            packet_hash = bytes(pkt.calculate_packet_hash())
        self._record_copy(
            packet_hash,
            path,
            len_byte,
            int(getattr(pkt, "_rssi", 0) or 0),
            float(getattr(pkt, "_snr", 0) or 0),
            in_process=_delivered_in_process(pkt),
        )
        return path, len_byte, packet_hash

    def _validated_inbound_path(self, pkt: Packet, len_byte: int) -> Optional[bytes]:
        """The inbound flood path trimmed to its declared length, or None."""
        if not PathUtils.is_valid_path_len(len_byte):
            return None
        byte_len = PathUtils.get_path_byte_len(len_byte)
        raw = bytes(getattr(pkt, "path", b"") or b"")
        if len(raw) < byte_len:
            return None
        return raw[:byte_len]

    def _record_copy(
        self,
        packet_hash: bytes,
        path: bytes,
        len_byte: int,
        rssi: int,
        snr: float = 0.0,
        *,
        in_process: bool = False,
    ) -> None:
        """Keep the best-ranked copy of a flood reply, keyed by packet hash.

        Copies are ordered by :meth:`_copy_rank`. A copy whose margin is below
        ``min_margin_db`` is discarded outright rather than recorded: below the
        waterfall it is not a route, and teaching it would hand the peer a link
        that cannot carry its replies. Discarding leaves whatever the caller
        seeded (the first-arrived copy) as the fallback, so a teach is never lost.

        ``in_process`` marks a copy the host delivered without RF (see
        :func:`_delivered_in_process`). It has no last-hop measurement to rank by
        and needs none: it gets a tier above every radio copy, so no relayed echo
        of it can displace it.
        """
        if in_process:
            margin = float("inf")
            rank: tuple = (2, -_hop_count(len_byte), margin, rssi)
        else:
            margin = self._copy_margin_db(rssi, snr)
            if margin < self._min_margin_db:
                return
            rank = self._copy_rank(margin, len_byte, rssi)
        now = self._time()
        self._prune_copies(now)
        existing = self._recent_copies.get(packet_hash)
        if existing is not None and rank <= existing.rank:
            existing.ts = now  # refresh so the winning copy outlives the window
            self._recent_copies.move_to_end(packet_hash)
            return
        self._recent_copies[packet_hash] = _FloodCopy(path, len_byte, rssi, margin, rank, now)
        self._recent_copies.move_to_end(packet_hash)
        if len(self._recent_copies) > self._copy_cache_max:
            self._recent_copies.popitem(last=False)  # evict least-recently-touched

    def _prune_copies(self, now: float) -> None:
        """Drop copies older than the TTL. Front entries are the oldest-touched."""
        ttl = self._copy_ttl_s
        while self._recent_copies:
            oldest = next(iter(self._recent_copies))
            if (now - self._recent_copies[oldest].ts) <= ttl:
                break
            self._recent_copies.popitem(last=False)

    async def _settle(self, seconds: float) -> None:
        """Wait out the teach settle window (overridable by tests/subclasses)."""
        await asyncio.sleep(seconds)

    # ---- teach dispatch ---------------------------------------------------

    async def _teach(
        self,
        *,
        contact_pubkey: bytes,
        dest_hash: int,
        embedded_path: bytes,
        embedded_len_byte: int,
        out_path: bytes,
        out_path_len: int,
        shared_secret: Optional[bytes],
        reason: str,
        hash_key: Optional[bytes] = None,
        settle_s: float = 0.0,
    ) -> bool:
        """Schedule one return-path teach. True when a teach was scheduled.

        The cooldown is claimed *synchronously*, before anything is awaited, so
        two concurrent triggers for the same contact cannot both pass the check
        and both transmit. It is released again if the packet never reaches the
        injector, so a failed teach is retried on the next trigger instead of
        being muted for the whole cooldown window.

        The packet is *not* built here: with a ``settle_s`` window the best copy
        is not known until the window closes, so build and transmit both happen
        in :meth:`_dispatch_teach`. The shared secret is derived up front so a
        contact that cannot be resolved fails synchronously (returns False)
        rather than after the settle delay.
        """
        key = bytes(contact_pubkey)
        if self._cooldown_active(key):
            self._log(
                f"[ReturnPath] Skip teach to 0x{dest_hash:02X} ({reason}): "
                f"within {self._cooldown_s:.0f}s cooldown"
            )
            return False

        secret = shared_secret if shared_secret is not None else self._shared_secret_for(key)
        if not secret:
            return False

        # Claim the cooldown now: everything past this point is asynchronous.
        previous = self._last_taught.get(key)
        self._last_taught[key] = self._time()

        # Firmware queues this send (sendDirect with a 3s delay) rather than
        # blocking. Awaiting it here would stall the RX path — the injector can
        # wait on a TX lock and an airtime budget — and delay delivery of the
        # reply that triggered the teach.
        task = asyncio.ensure_future(
            self._dispatch_teach(
                key=key,
                previous_cooldown=previous,
                dest_hash=dest_hash,
                secret=secret,
                embedded_path=embedded_path,
                embedded_len_byte=embedded_len_byte,
                out_path=out_path,
                out_path_len=out_path_len,
                reason=reason,
                hash_key=hash_key,
                settle_s=settle_s,
            )
        )
        self._pending_teaches.add(task)
        task.add_done_callback(self._pending_teaches.discard)
        return True

    async def _dispatch_teach(
        self,
        *,
        key: bytes,
        previous_cooldown: Optional[float],
        dest_hash: int,
        secret: bytes,
        embedded_path: bytes,
        embedded_len_byte: int,
        out_path: bytes,
        out_path_len: int,
        reason: str,
        hash_key: Optional[bytes],
        settle_s: float,
    ) -> None:
        """Wait out the settle window, then build and transmit the best teach.

        Rolls the cooldown back on any failure so the next trigger can retry.
        """
        if settle_s > 0.0:
            await self._settle(settle_s)

        # Pick the best-received copy collected during the window. Falls back to
        # the seed passed in (the first-arrived copy) when nothing better was
        # recorded, when the entry was evicted, or for a reverse-of-out_path
        # guess (which has no hash_key and no inbound copies to collect).
        chosen_rssi: Optional[int] = None
        if hash_key is not None:
            best = self._recent_copies.pop(hash_key, None)
            if best is not None:
                embedded_path = best.path
                embedded_len_byte = best.len_byte
                chosen_rssi = best.rssi

        try:
            teach = PacketBuilder.create_path_return(
                dest_hash=dest_hash,
                src_hash=self._local_identity.get_public_key()[0],
                secret=secret,
                path=embedded_path,
                extra_type=0xFF,  # no extra payload (firmware passes NULL/0)
                extra=b"",
                path_len_encoded=embedded_len_byte,
            )
            # createPathReturn yields a FLOOD PATH; firmware's handleReturnPathRetry
            # sends it DIRECT along the out_path we already hold for the peer.
            teach.header = (teach.header & ~PH_ROUTE_MASK) | ROUTE_TYPE_DIRECT
            teach.set_path(out_path, out_path_len)
            await self._injector(teach)
        except Exception as e:
            if previous_cooldown is None:
                self._last_taught.pop(key, None)
            else:
                self._last_taught[key] = previous_cooldown
            self._log(f"[ReturnPath] Failed to send teach to 0x{dest_hash:02X}: {e}")
            return

        if chosen_rssi is not None:
            try:
                hops = PathUtils.get_path_hash_count(embedded_len_byte)
            except Exception:
                hops = "?"
            rssi_note = f", best last-hop RSSI {chosen_rssi} over {hops} hop(s)"
        else:
            rssi_note = ""
        self._log(
            f"[ReturnPath] Taught 0x{dest_hash:02X} its route back ({reason}): "
            f"embedded={embedded_path.hex() or '(zero-hop)'} "
            f"(path_len=0x{embedded_len_byte:02X}){rssi_note}, "
            f"sent DIRECT via {out_path.hex() or '(zero-hop)'}"
        )
