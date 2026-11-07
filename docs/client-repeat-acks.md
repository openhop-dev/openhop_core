# Client-repeat ACK regeneration

This forwarding behavior follows MeshCore 1.18.0 (`81dbae59`), specifically
`Mesh::forwardMultipartDirect`, `Mesh::routeDirectRecvAcks`, and
`Packet::calculatePacketHash`.

When client-repeat is enabled and this node is the next hop of a routed-direct
ACK or multipart ACK, Core removes its own path hash and generates a new sequence
using its local `multi_acks` preference. A value of N produces N multipart ACKs,
with remaining counts N down to 1, followed by an ordinary ACK. The whole ACK
payload is preserved, including bytes after the four-byte CRC. Output packets
use plain DIRECT, matching firmware even when the input has transport codes.

Direct jitter uses the received packet before removing this node's path hash.
For a multipart input, the first output is additionally delayed by
`(incoming_remaining + 1) * 300ms`. Outputs have queue deadlines 300ms apart;
transmission time and airtime-budget waits do not add another 300ms to each
deadline. The send funnel still serializes and budgets every actual transmission.

For example, with incoming remaining count 2, local `multi_acks=2`, and jitter J:

| Output | Earliest queue deadline |
| --- | --- |
| Multipart, remaining 2 | J + 900ms |
| Multipart, remaining 1 | J + 1200ms |
| Ordinary ACK | J + 1500ms |

Multipart forwarding claims hash the unwrapped ACK payload with the original
MULTIPART payload type, just as firmware does. Different remaining-count wrappers
therefore share one claim. An overheard packet whose next hop is another node
cannot claim that hash before the routed copy reaches this node. Ordinary ACKs
have a separate hash; this change does not coalesce them with multipart claims.
Regenerated packets do not make additional seen-table claims: only their
incoming packets do, matching firmware's relay queue. This lets a later inbound
ordinary ACK retain its own forwarding decision. Normally originated packets
still register loopback protection, using the same fingerprint on RX and TX.
The firmware-style canonical hash is used only when Core client-repeat is on,
preserving the deduplication contract for applications with their own routers.

Malformed or unsupported multipart packets and flood multipart packets are not
repeated. Zero-hop multipart ACKs are delivered locally without regeneration.
Ordinary ACKs shorter than the four-byte CRC are dropped rather than relaying
malformed data, a deliberate stricter check than firmware's direct relay branch.
An ordinary ACK consumed by a local waiter is not repeated. Existing early
multipart CRC notification remains unchanged.

`CompanionRadio` synchronizes `multi_acks` to both its text handler and dispatcher
when preferences are applied or changed. Bridge hosts continue to own routing.
Disabling client-repeat cancels its pending forwarding tasks, including an ACK
sequence waiting for its first deadline or for airtime budget admission.

Tests cover both direct route forms, one/two/three-byte hashes, zero/one remaining
path hops, multiple incoming and local counts, complete payload preservation,
ingress-radio attribution, malformed inputs, duplicate claims, consumed ACKs,
preference wiring, budget debits, and cancellation. A process-only restoration
of the old forwarding method fails all 96 sequence cases.

These are Python and wire-format checks. Live multi-hop RF reliability,
interoperability, and on-air spacing remain unverified; radio airtime and other
queued traffic can postpone actual transmission beyond a queue deadline.

At the packet-size boundary, an ordinary ACK whose payload is already the
maximum size cannot fit a multipart wrapper. Core skips the unrepresentable
extra copies and forwards the intact ordinary ACK.

The existing runtime command accepts a raw uint8 `multi_acks`, as firmware's
`CMD_SET_OTHER_PARAMS` does. Large values therefore multiply relay traffic;
every frame still passes through the airtime budget. Counts above 15 wrap the
wire wrapper's four-bit remaining field, matching firmware. Firmware additionally
clamps persisted values to 0/1 on load; this branch does not change Core's
pre-existing preference load or command contract.
