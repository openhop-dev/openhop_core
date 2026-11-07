# MeshCore 1.18.0 compatibility

Compared on 2026-10-17:

- Core base: `upstream/dev` at `bef7021` (1.1.4.dev6).
- Previous compatibility work: `c3bf35c` (companion CLI/v14), compared with
  MeshCore `618b2ef4` on 2026-09-25.
- Release: MeshCore `81dbae592ffad40b4212bc0b37e82b38da08f4bc`, shared by
  `companion-v1.18.0`, `repeater-v1.18.0`, and `room-server-v1.18.0`.

Sources: [release notes](https://blog.meshcore.io/2026/10/15/release-1-18-0),
[firmware comparison](https://github.com/meshcore-dev/MeshCore/compare/618b2ef4...81dbae592ffad40b4212bc0b37e82b38da08f4bc).
The source comparison covers `src/`, `examples/companion_radio/`,
`examples/simple_repeater/`, and `examples/simple_room_server/`.

## Changes in Core

| Firmware change or compatibility concern | Core behavior |
| --- | --- |
| Unhandled contact responses now reach the app (`b204f9a11`, `MyMesh::onContactResponse`). | Forward unsolicited responses as `PUSH_CODE_BINARY_RESPONSE`: reserved byte, original four-byte tag, and remaining decrypted bytes, including timestamp, LPP records, and AES padding. Both RESPONSE and PATH-wrapped responses work. |
| Sensor pushes have no pending request tag. | A pending request in another frame server still cannot consume its matched reply here. Unmatched responses pass through; the existing region-reply exception remains. Authentication and contact lookup happen before delivery. |
| Sensor push bytes can resemble the old login-response heuristic. | Use pending-login state for the authenticated full public key, excluding tags owned by pending requests. This works for every padded response length; a timestamp starting with 0 or 1 alone cannot hide a push. |
| PATH replies pass through both request and login handlers. | A claimed response carries `HandlerResult.response_claimed` after its request tag is consumed. PATH dispatch skips login parsing for that response, preventing a false login success or failure. The claim survives a request consumer error; unsolicited responses remain unclaimed. |
| Transport code zero means wildcard (`01f9293be`, `RegionMap::findMatch`). | Return the wildcard for a transport-routed packet with first code zero. Reply-scope capture mirrors it as unscoped, overriding any default region. Like firmware, this early return does not consult the wildcard deny flag. Plain FLOOD handling is unchanged. |
| Reject ciphertext that is not a whole number of AES blocks (`9c9a2ba2d`, `b74ba5453`, `Utils::MACThenDecrypt`). | Reject before HMAC or decryption instead of padding malformed ciphertext. Valid encrypted packets retain their existing zero padding. |
| Direct ACK jitter uses the received path length (`6df5aaed4`, `Mesh::onRecvPacket`). | Compute direct-forward jitter before removing this node's path hash. Flood forwards continue using the path after appending this node. |
| Contact shares use TRANSPORT_DIRECT with zero transport codes (`BaseChatMesh::shareContactZeroHop`, predating `618b2ef4`). | Replay the cached signed advert with that marker and an empty path, preserving the payload and cached bytes. |

The companion protocol version stays **14**: the release does not change it.
Core keeps its own product/version metadata.

## Other release changes

| Firmware change | Assessment |
| --- | --- |
| Companion CLI, remote CLI permission, PIN/time-zone preferences, reboot, encoded raw paths, and channel-data bounds | Already covered by the previous compatibility work and existing tests. |
| `MAX_SEARCH_RESULTS` increases from 8 to 24 (`f9e70426a`) | Core already tries all matching contacts; it has no eight-contact search cap. |
| Ordinary direct ACK forwarding uses retransmit jitter (`6df5aaed4`) | Core already delayed client-repeat ACK forwards; the new change aligns the path length used to calculate that delay. |
| Multipart ACK forwarding and regenerated multi-ACK timing | Client-repeat regenerates the local configured ACK sequence, using unwrapped multipart duplicate claims and the firmware's remaining-count delay. See [client-repeat ACKs](client-repeat-acks.md) for timing and validation limits. |
| Hidden repeaters stop answering discovery (`f19733e47`) | Advertisement scheduling and discovery response policy belong to the Repeater application. Core's control handler parses and dispatches requests; it does not decide whether a repeater advertises. |
| Room `set repeat on` deprecated | Room CLI policy belongs to the Repeater application; no matching Core command. |
| CommonCLI `power` and GPS diagnostics, board/driver fixes, Wi-Fi/BLE, retained MCU clock | Hardware/firmware or Repeater command surfaces, outside this Python Core change. |
| Sensor subscribe/unsubscribe server | Core has no sensor-server role. Opaque binary requests can already carry these requests; this change enables receiving their unsolicited responses. |

## Known existing divergences

These were present before the compatibility changes; they remain separate from
this release delta:

- As in firmware, a pending login takes priority for an authenticated response
  from that same contact when no known request tag disambiguates it. An
  unsolicited telemetry push can therefore be interpreted as a login outcome.
  This pre-existing ambiguity remains; tests pin the firmware priority for
  RESPONSE and PATH packets. Known request replies are now protected by the
  response-claim handoff described above. A genuine login reply with a tag
  identical to a pending request can still be claimed as that request; the
  wire format does not distinguish this collision.

## Validation boundary

Regression coverage exercises encrypted RESPONSE and PATH pushes through a real
`CompanionBridge` and frame-server subscription, login-shaped timestamp bytes,
pending login delivery, malformed/unauthenticated input, request ownership
across PATH dispatch, two simultaneous frame-server request tags, consumer
errors, same-contact login/push ambiguity,
wildcard reply scope, and complete/incomplete AES blocks.

Validation on Python 3.12:

- ACK branch before integrating the contact-share follow-up: **2,761 passed**.
- ACK regeneration: **124 new tests**, plus **26 existing forwarding tests**,
  cover sequence deadlines, both direct route forms, path widths, canonical
  claims, late plain ACKs, payload bounds, preference wiring, and cancellation.
- Compatibility branch including the contact-share follow-up: **2,640 passed**.
- Contact sharing: four cached-route variants preserve the signed payload and
  cached bytes, emit zero transport codes and path length, and round-trip through
  the wire parser. All four fail with the old DIRECT marker.
- Focused release-delta files contain **581 passing tests** within the full suite.
- Downstream Repeater bridge/preferences/callback/policy tests: **44 passed**
  against Repeater `3c4bf3a`, with this Core source on `PYTHONPATH`.
- Source Black/isort checks, changed-file flake8, and `git diff --check` passed.
- Restoring the old push filter, login-shape filter, AES behavior, wildcard
  handling, direct-delay input, and PATH dispatch in separate test processes
  made the new regressions fail in all six cases. Restoring the old PATH
  dispatch alone produces 16 failures. No working-tree source was changed
  for these checks.

Independent reviews checked the release deltas and ran the focused tests and
full suite. Additional adversarial review exposed a false-login-success variant
of the old PATH ownership bug; the response-claim fix and behavioral regressions
are included here. The untouched vendored LoRaRF
files fail a whole-`src` Black check; formatting checks on changed sources pass.

This is source and Python test validation. It does not establish live firmware,
app interoperability, RF behavior, or hardware persistence.
