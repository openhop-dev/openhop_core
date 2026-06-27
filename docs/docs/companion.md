# Companion Module

The companion module provides a high-level Python interface to the MeshCore companion radio protocol. It manages contacts, messaging, channels, advertisements, path routing, telemetry, cryptographic signing, and device configuration on top of openhop-core's `MeshNode`.

Three main classes are provided:

| Class | Owns Radio | Use Case |
|---|---|---|
| `CompanionRadio` | Yes | Standalone companion — wraps a hardware radio and `MeshNode` |
| `CompanionBridge` | No | Repeater-integrated companion — shares an existing dispatcher via a packet injector callback |
| `CompanionFrameServer` | No | TCP server implementing the MeshCore companion frame protocol (the binary wire format used by companion apps) |

`CompanionRadio` and `CompanionBridge` both inherit from `CompanionBase` (an abstract base class), which holds all shared stores, event handling, device configuration logic, and unified TX methods. Subclasses implement transport via the abstract `_send_packet` method.

`CompanionFrameServer` wraps a `CompanionBridge` (or any `CompanionBase` subclass) and exposes it over TCP using the same binary frame protocol as the MeshCore firmware companion radio.

---

## Architecture

```
CompanionBase (ABC)
├── ContactStore          (in-memory contacts, max 1000)
├── ChannelStore          (group channels, max 40)
├── MessageQueue          (offline FIFO, max 512)
├── PathCache             (recent advert paths, max 16)
├── StatsCollector        (TX/RX counters, uptime)
├── NodePrefs             (radio params, name, location)
│
│   Persistence hooks (no-op by default, override for SQLite/JSON):
│   _save_prefs, _load_prefs
│
│   Unified methods (use abstract _send_packet):
│   advertise, share_contact, send_text_message,
│   send_channel_message, send_binary_req,
│   send_path_discovery_req, send_trace_path,
│   send_login, send_logout, sync_next_message
│
├─► CompanionRadio        (owns MeshNode + hardware radio)
└─► CompanionBridge       (packet_injector callback, no radio)
        │
        └─► CompanionFrameServer  (TCP binary frame protocol server)
                │
                │   Persistence hooks (no-op by default):
                │   _persist_companion_message, _sync_next_from_persistence,
                │   _save_contacts, _save_channels, _get_batt_and_storage
                │
                └─► (your subclass, e.g. SQLite-backed repeater)
```

---

## Installation

```bash
pip install openhop-core            # core only
pip install openhop-core[hardware]  # SX1262 direct radio support
pip install openhop-core[all]       # everything
```

---

## CompanionRadio

`CompanionRadio` is a standalone companion that owns a hardware radio and a `MeshNode`. It is the typical entry point for building a chat application, sensor gateway, or automation tool that participates in a MeshCore network.

### Quick Start

```python
import asyncio
from openhop_core import LocalIdentity
from openhop_core.companion import (
    CompanionRadio,
    ADV_TYPE_CHAT,
    STATS_TYPE_PACKETS,
)

async def main():
    # --- Setup ---
    from openhop_core.hardware import KissModemWrapper

    radio = KissModemWrapper("/dev/ttyUSB0")
    radio.connect()

    identity = LocalIdentity()  # generates a new Ed25519 keypair
    companion = CompanionRadio(
        radio=radio,
        identity=identity,
        node_name="myNode",
        adv_type=ADV_TYPE_CHAT,
    )

    # --- Register callbacks before starting ---
    companion.on_message_received(on_msg)
    companion.on_advert_received(on_advert)
    companion.on_channel_message_received(on_chan_msg)
    companion.on_send_confirmed(on_ack)

    await companion.start()

    # --- Advertise presence ---
    await companion.advertise(flood=True)

    # --- Send a direct message ---
    dest = bytes.fromhex("ab" * 32)  # 32-byte public key
    result = await companion.send_text_message(dest, "Hello mesh!")
    print(f"Sent: success={result.success}, flood={result.is_flood}")

    # --- Keep running ---
    try:
        while True:
            await asyncio.sleep(1)
    finally:
        await companion.stop()


# --- Callbacks ---
def on_msg(sender_key, text, timestamp, txt_type, *args):
    print(f"DM from {sender_key[:8].hex()}: {text}")

def on_advert(contact):
    print(f"Discovered: {contact.name} (type={contact.adv_type})")

def on_chan_msg(channel_name, sender_name, text, timestamp, path_len, channel_idx, *args):
    print(f"[{channel_name}] {sender_name}: {text}")

def on_ack(ack_crc):
    print(f"ACK confirmed: {ack_crc:#x}")


asyncio.run(main())
```

### Constructor

```python
CompanionRadio(
    radio,                              # hardware radio wrapper
    identity: LocalIdentity,            # Ed25519 identity
    node_name: str = "pyMC",
    adv_type: int = ADV_TYPE_CHAT,      # 1=chat, 2=repeater, 3=room, 4=sensor
    max_contacts: int = 1000,
    max_channels: int = 40,
    offline_queue_size: int = 512,
    radio_config: dict | None = None,
    initial_contacts: iterable of Contact | None = None,  # optional bulk load on boot
)
```

### Lifecycle

```python
await companion.start()      # start dispatcher task
await companion.stop()       # cancel dispatcher
companion.is_running         # bool property
```

### Messaging

```python
# Direct text message
result = await companion.send_text_message(pub_key, "hello", txt_type=0, attempt=1)
# result: SentResult(success, is_flood, expected_ack, timeout_ms)

# Group channel message
ok = await companion.send_channel_message(channel_idx=0, text="hello group")

# Pop oldest queued offline message
msg = companion.sync_next_message()  # -> QueuedMessage | None

# Raw binary data (direct path only)
result = await companion.send_raw_data(dest_key, data=b"\x01\x02", path=None)
```

### Advertisements

```python
await companion.advertise(flood=True)       # broadcast presence
await companion.share_contact(pub_key)      # share a contact via direct advert
```

**Share contact (firmware parity):** MeshCore replays the **last received raw ADVERT** for that contact (`getBlobByKey` + `sendZeroHop`), not a newly signed advert from the companion identity. openhop-core stores the wire bytes on each contact when an advert is heard (`Contact.last_advert_packet`) and `share_contact()` returns `False` if no blob exists (e.g. contact was only added manually and never advertised on-air).

### Contact Management

```python
from openhop_core.companion import Contact

# List / lookup
contacts = companion.get_contacts(since=0)
contact  = companion.get_contact_by_key(pub_key_bytes)
contact  = companion.get_contact_by_name("Alice")

# Add / update / remove
companion.add_update_contact(Contact(public_key=key, name="Bob"))
companion.remove_contact(pub_key_bytes)

# Populate on boot: pass initial_contacts into the constructor (CompanionRadio or CompanionBridge).
# Replaces the need to call the store after construction.
contacts_from_prefs = [Contact(public_key=k, name=name) for ...]  # e.g. from _load_prefs or a file
companion = CompanionRadio(radio, identity, node_name="myNode", initial_contacts=contacts_from_prefs)
await companion.start()

# If your data is dicts (e.g. JSON/DB), load after construction:
companion.contacts.load_from_dicts([{"public_key": key_hex, "name": "Bob"}, ...])

# Reset routing path (force re-discovery)
companion.reset_path(pub_key_bytes)

# Serialise for sharing
blob   = companion.export_contact(pub_key)   # bytes (73-byte binary packet)
ok     = companion.import_contact(blob)      # bool
```

### Channel Management

```python
from openhop_core.companion import Channel

companion.set_channel(0, name="General", secret=b"shared_secret_key_here__________")
ch = companion.get_channel(0)   # -> Channel | None
```

### Path Discovery & Tracing

```python
# Path discovery (returns SentResult, fires on_path_discovery_response callback)
result = await companion.send_path_discovery_req(pub_key)

# Trace path through the network
ok = await companion.send_trace_path(pub_key, tag=42, auth_code=0, flags=0)

# Get recently heard advert path
advert_path = companion.get_advert_path(pub_key_prefix_7bytes)
```

### Repeater Interaction

```python
# Login to a repeater
resp = await companion.send_login(repeater_key, password="secret")

# Logout from a repeater
ok = await companion.send_logout(repeater_key)

# Request repeater status
resp = await companion.send_status_request(repeater_key)

# Request telemetry
resp = await companion.send_telemetry_request(
    repeater_key,
    want_base=True,
    want_location=True,
    want_environment=False,
    timeout=10.0,
)

# Send a text command to a repeater
resp = await companion.send_repeater_command(repeater_key, command="status")
```

### Binary Requests

The generic binary request/response mechanism uses random 4-byte tags for matching.

```python
# Send and wait for response
result = await companion.send_binary_req(pub_key, data=b"\x01", timeout_seconds=10)

# Register a callback for responses
companion.on_binary_response(
    lambda tag, data, parsed, req_type: print(f"Response: {parsed}")
)
```

### Device Configuration

All preference-mutating methods automatically call `_save_prefs()` (a no-op by default; override in subclasses for persistence).

```python
companion.set_advert_name("NewName")                     # max 31 chars
companion.set_advert_latlon(37.7749, -122.4194)          # GPS coordinates
companion.set_radio_params(915_000_000, 250_000, 10, 5)  # freq, bw, SF, CR
companion.set_tx_power(22)                                # dBm
companion.set_tuning_params(rx_delay=0.0, airtime_factor=0.0)

# Path hash mode for flood packets: 0=1-byte, 1=2-byte, 2=3-byte per hop (repeaters
# use this to decide how many bytes to append when forwarding). Applied to all
# companion-originated flood packets with 0 hops. Set via CMD_SET_PATH_HASH_MODE on
# the frame server.
companion.set_path_hash_mode(1)   # use 2-byte path hashes

# Fetch current radio configuration (frequency, bandwidth, SF, CR, TX power, tuning)
radio_params = companion.get_radio_params()
# {'frequency_hz': 915000000, 'bandwidth_hz': 250000, 'spreading_factor': 10, ...}

# Time management (transient, not persisted)
device_time = companion.get_time()                        # Unix timestamp
ok = companion.set_time(1700000000)                       # returns False if in the past

# Custom variables (key:value string pairs, max 140 chars total)
custom_vars = companion.get_custom_vars()                 # -> dict[str, str]
ok = companion.set_custom_var("key", "value")             # -> bool

# Auto-add configuration
config = companion.get_autoadd_config()                   # -> int bitmask
companion.set_autoadd_config(AUTOADD_CHAT | AUTOADD_REPEATER)

# Location sharing in adverts
from openhop_core.companion import ADVERT_LOC_SHARE
companion.set_other_params(
    manual_add=0,
    telemetry_modes=0,
    advert_loc_policy=ADVERT_LOC_SHARE,
    multi_acks=0,
)

prefs = companion.get_self_info()   # -> NodePrefs (copy)
```

Originated flood packets (including adverts) set the high bits of the packet's
``path_len`` byte so repeaters know how many bytes to append when forwarding
(1-, 2-, or 3-byte path hashes). The companion applies its ``path_hash_mode``
preference to all such packets with zero hops via ``set_path_hash_mode()``;
the frame server exposes this as CMD_SET_PATH_HASH_MODE and reports it in
device info (byte 81).

### Flood Scope (Regions)

Constrain flood packets to a specific region using transport key scoping.
Nodes outside the region will ignore scoped flood packets.

```python
from openhop_core.protocol.transport_keys import get_auto_key_for

# Set region by name (auto-derives transport key via SHA-256)
companion.set_flood_region("usa")       # '#' prefix added automatically
companion.set_flood_region("#europe")   # explicit '#' also works

# Or set directly with a raw 16-byte transport key
key = get_auto_key_for("#usa")
companion.set_flood_scope(key)

# Clear scope (flood to all nodes)
companion.set_flood_region(None)
```

For MeshCore v1.15 parity, the frame protocol also supports a persisted default flood scope:

- `CMD_SET_DEFAULT_FLOOD_SCOPE` (`63`) stores `name(31)` + `key(16)`
- `CMD_GET_DEFAULT_FLOOD_SCOPE` (`64`) returns the stored value (or empty if unset)

openhop-core resolves effective flood scope as:

1. explicit unscoped mode (`CMD_SET_FLOOD_SCOPE` mode 1) until mode 0 sets/resets scope
2. transient key set by `CMD_SET_FLOOD_SCOPE` mode 0 / `set_flood_scope()`
3. otherwise persisted default key (if configured)
4. otherwise unscoped flood

When a flood scope is active, all flood packets are tagged with a 16-bit transport code
(HMAC-SHA256 derived) and sent as `ROUTE_TYPE_TRANSPORT_FLOOD`. Direct-routed packets
are unaffected.

### Firmware v1.15 Note (nRF BLE DFU)

MeshCore v1.15 may expose Nordic DFU service on the normal nRF companion BLE stack.
This does not change openhop-core TCP frame protocol behavior, but BLE clients should not
assume only UART service is present on companion devices.

### Cryptographic Signing

```python
buf_size = companion.sign_start()          # returns max buffer size (8192)
companion.sign_data(b"data to sign...")
signature = companion.sign_finish()        # -> 64-byte Ed25519 signature
```

### Statistics

```python
from openhop_core.companion import STATS_TYPE_CORE, STATS_TYPE_RADIO, STATS_TYPE_PACKETS

stats = companion.get_stats(STATS_TYPE_CORE)
# {'uptime': 3600, 'queue_len': 2, 'contacts_count': 15, 'channels_count': 3}

stats = companion.get_stats(STATS_TYPE_PACKETS)
# {'flood_tx': 42, 'flood_rx': 108, 'direct_tx': 5, 'direct_rx': 12, ...}
```

### CompanionRadio-Specific Overrides

`CompanionRadio` overrides several `CompanionBase` methods to also configure the physical radio hardware:

| Method | Base Behavior | Radio Override |
|---|---|---|
| `set_radio_params()` | Updates `prefs` fields | Also calls `radio.configure_radio()` |
| `set_tx_power()` | Updates `prefs.tx_power_dbm` | Also calls `radio.set_tx_power()` |
| `set_advert_name()` | Updates `prefs.node_name` | Also syncs `node.node_name` |
| `set_flood_scope()` | Stores transport key | Also syncs to `node.dispatcher` |
| `set_flood_region()` | Derives key from name | Also syncs to `node.dispatcher` |
| `set_path_hash_mode()` | Updates `prefs.path_hash_mode` | Also syncs to `node.dispatcher.set_default_path_hash_mode()` |

---

## CompanionBridge

`CompanionBridge` is designed for repeater integration. It does not own a radio or `MeshNode` — instead, the repeater host feeds received packets in via `process_received_packet()`, and all outbound packets go through a `packet_injector` callback you provide. This lets a companion identity coexist alongside a repeater on the same radio.

### Quick Start

```python
import asyncio
from openhop_core import LocalIdentity
from openhop_core.companion import CompanionBridge, ADV_TYPE_CHAT

async def main():
    identity = LocalIdentity()

    async def packet_injector(pkt, wait_for_ack=False):
        """Forward packet to the repeater's radio."""
        return await my_repeater.send_packet(pkt)

    def authenticate(user_hash, password):
        """Validate login attempts. Return (success, acl_bits)."""
        if user_hash == expected_hash:
            return (True, 0x01)
        return (False, 0)

    bridge = CompanionBridge(
        identity=identity,
        packet_injector=packet_injector,
        node_name="myBridge",
        adv_type=ADV_TYPE_CHAT,
        authenticate_callback=authenticate,
    )

    bridge.on_message_received(
        lambda key, text, ts, tt, *args: print(f"Bridge msg: {text}")
    )

    await bridge.start()

    # Feed packets from the repeater's dispatcher
    async def on_repeater_rx(packet):
        await bridge.process_received_packet(packet)

    # ... register on_repeater_rx with your repeater ...

asyncio.run(main())
```

### Constructor

```python
CompanionBridge(
    identity: LocalIdentity,
    packet_injector: Callable,          # async (pkt, wait_for_ack=False) -> bool
    node_name: str = "pyMC",
    adv_type: int = ADV_TYPE_CHAT,
    max_contacts: int = 1000,
    max_channels: int = 40,
    offline_queue_size: int = 512,
    radio_config: dict | None = None,
    authenticate_callback: Callable | None = None,  # (hash, pw) -> (bool, int)
    initial_contacts: iterable of Contact | None = None,  # optional bulk load on boot
)
```

### RX Entry Point

```python
# Called by the repeater host for every received packet
await bridge.process_received_packet(packet)
```

The bridge registers internal handlers for these payload types:

| Payload Type | Handler |
|---|---|
| ACK | Bridge ACK handler (matches pending CRCs) |
| TXT_MSG | TextMessageHandler |
| ADVERT | AdvertHandler |
| PATH | PathHandler |
| ANON_REQ | LoginServerHandler |
| GRP_TXT | GroupTextHandler |
| RESPONSE | LoginResponseHandler |

### All Other APIs

`CompanionBridge` exposes the same messaging, contact, channel, path, signing, stats, and configuration APIs as `CompanionRadio` (inherited from `CompanionBase`). The only behavioral difference is that all TX goes through the `packet_injector` instead of an owned radio.

Note that **CompanionBridge does not own the radio**. `set_radio_params()` and `set_tx_power()` update in-memory prefs only; there is no physical radio to configure. `get_radio_params()` and `get_self_info()` return those in-memory prefs, not the repeater's actual hardware configuration.

### Avoiding doubled messages

When you have **multiple bridges** on the same repeater, the other bridge can receive the same logical message twice: once from local fan-out when one bridge injects a packet, and again when the repeater's radio receives that packet over the air. Deduplication uses a packet hash; if the data used for local delivery differs from the bytes sent over the air, the hashes differ and both copies appear.

**Use one canonical byte representation** for both TX and local delivery:

1. When your `packet_injector` is called with `pkt`, apply any in-place changes (e.g. flood scope) **before** serializing.
2. Serialize once: `raw = pkt.write_to()`.
3. Send `raw` on the radio.
4. For local delivery to the other bridge, build a new packet from those **same** bytes and pass it:
   `pkt2 = Packet(); pkt2.read_from(raw); await other_bridge.process_received_packet(pkt2)`.

Then both local and OTA deliveries share the same packet hash and companion-side dedup collapses the duplicate.

**Optional:** Feed the same `raw` bytes into the repeater's dispatcher RX path (the same entry the radio uses) instead of calling `other_bridge.process_received_packet(pkt)` directly. The dispatcher will track the packet hash; when the same bytes arrive over the air they are dropped as duplicates, and you deliver to bridges only from the dispatcher (single path, no double delivery).

Example injector with serialize-once local delivery to another bridge:

```python
from openhop_core.protocol import Packet

async def packet_injector(pkt, wait_for_ack=False):
    raw = pkt.write_to()  # after any in-place changes (e.g. flood scope)
    ok = await repeater.send_raw(raw)  # or dispatcher.send_packet with pre-serialized bytes
    if ok and other_bridge:
        pkt2 = Packet()
        pkt2.read_from(raw)
        await other_bridge.process_received_packet(pkt2)
    return ok
```

---

## CompanionFrameServer

`CompanionFrameServer` implements the MeshCore companion radio TCP frame protocol — the same binary wire format used by the C++ firmware (`examples/companion_radio/`). It wraps a `CompanionBase` subclass (typically a `CompanionBridge`) and exposes it to companion apps (e.g. MeshCore Android/iOS) over a TCP socket.

### Frame Format

All frames use a simple length-prefixed format:

| Direction | Prefix | Length | Data |
|---|---|---|---|
| App → Radio | `<` (0x3C) | 2-byte LE | Command byte + payload |
| Radio → App | `>` (0x3E) | 2-byte LE | Response/push byte + payload |

Maximum frame size: 172 bytes (matches firmware; BLE MTU).

### Quick Start

```python
from openhop_core import LocalIdentity
from openhop_core.companion import CompanionBridge, CompanionFrameServer

identity = LocalIdentity()
bridge = CompanionBridge(identity=identity, packet_injector=my_injector)

server = CompanionFrameServer(
    bridge=bridge,
    companion_hash="abcd1234",   # identifier for this companion
    port=5000,
    device_model="pyMC-Companion",
    device_version="1.0.0",
)

await server.start()   # starts listening on TCP port
# ... companion app connects and sends commands ...
await server.stop()
```

### Constructor

```python
CompanionFrameServer(
    bridge: CompanionBase,              # the companion to wrap
    companion_hash: str,                # unique identifier
    port: int = 5000,
    bind_address: str = "0.0.0.0",
    *,
    device_model: str = "pyMC-Companion",
    device_version: str = "1.0.0",
    build_date: str = "",
    local_hash: int | None = None,
    stats_getter: Callable | None = None,
    control_handler: Any | None = None,
    heartbeat_interval: int = 15,      # seconds between keepalive frames
    client_idle_timeout_sec: int | None = 120,  # no data from client → disconnect; None = no timeout (firmware behaviour)
)
```

**Connection management:** Only one client is allowed at a time. If a new connection arrives while one is already active, the server closes the existing connection and accepts the new one (same as firmware). If the client disappears without closing (e.g. kill, network drop), the slot is freed after no data is received for `client_idle_timeout_sec` seconds (default 120). Pass `None` to disable the idle timeout (no disconnect on idle, matching firmware). Operators can tune this timeout to avoid dropping slow but live clients.

### Supported Commands

The frame server handles the following companion radio protocol commands:

| CMD | Code | Description |
|---|---|---|
| `CMD_APP_START` | 1 | Initialize connection, return device info |
| `CMD_SEND_TXT_MSG` | 2 | Send a direct text message |
| `CMD_SEND_CHANNEL_TXT_MSG` | 3 | Send a channel message |
| `CMD_GET_CONTACTS` | 4 | Retrieve contact list (paginated) |
| `CMD_GET_DEVICE_TIME` | 5 | Get current device time |
| `CMD_SET_DEVICE_TIME` | 6 | Set device time |
| `CMD_SEND_SELF_ADVERT` | 7 | Broadcast self advertisement |
| `CMD_SET_ADVERT_NAME` | 8 | Set advertised node name |
| `CMD_ADD_UPDATE_CONTACT` | 9 | Add or update a contact |
| `CMD_SYNC_NEXT_MESSAGE` | 10 | Pop next queued message |
| `CMD_SET_RADIO_PARAMS` | 11 | Set frequency, bandwidth, SF, CR |
| `CMD_SET_RADIO_TX_POWER` | 12 | Set transmit power |
| `CMD_RESET_PATH` | 13 | Reset routing path for a contact |
| `CMD_SET_ADVERT_LATLON` | 14 | Set GPS coordinates |
| `CMD_REMOVE_CONTACT` | 15 | Remove a contact |
| `CMD_SHARE_CONTACT` | 16 | Share a contact to the mesh |
| `CMD_EXPORT_CONTACT` | 17 | Export contact as 73-byte blob |
| `CMD_IMPORT_CONTACT` | 18 | Import contact from blob |
| `CMD_EXPORT_PRIVATE_KEY` | 23 | Export private/signing key (64-byte MeshCore format) |
| `CMD_IMPORT_PRIVATE_KEY` | 24 | Import private key (stub/no-op; key set from config) |
| `CMD_SEND_RAW_DATA` | 25 | Send raw payload on given direct path |
| `CMD_GET_BATT_AND_STORAGE` | 20 | Get battery/storage info |
| `CMD_SET_TUNING_PARAMS` | 21 | Set RX delay and airtime factor |
| `CMD_DEVICE_QUERY` | 22 | Return device model/version |
| `CMD_SEND_LOGIN` | 26 | Login to a repeater |
| `CMD_SEND_STATUS_REQ` | 27 | Request repeater status |
| `CMD_LOGOUT` | 29 | Logout from a repeater |
| `CMD_GET_CONTACT_BY_KEY` | 30 | Look up contact by public key |
| `CMD_GET_CHANNEL` | 31 | Get a channel by index |
| `CMD_SET_CHANNEL` | 32 | Set a channel |
| `CMD_SEND_TRACE_PATH` | 36 | Send trace path request |
| `CMD_SEND_TELEMETRY_REQ` | 39 | Request telemetry data |
| `CMD_GET_CUSTOM_VARS` | 40 | Get custom variables |
| `CMD_SET_CUSTOM_VAR` | 41 | Set a custom variable |
| `CMD_GET_ADVERT_PATH` | 42 | Get cached advert path |
| `CMD_SEND_BINARY_REQ` | 50 | Send binary request |
| `CMD_SEND_PATH_DISCOVERY_REQ` | 52 | Send path discovery |
| `CMD_SET_FLOOD_SCOPE` | 54 | Set flood scope transport key |
| `CMD_SEND_CONTROL_DATA` | 55 | Send control data |
| `CMD_GET_STATS` | 56 | Get statistics |
| `CMD_SET_AUTOADD_CONFIG` | 58 | Set auto-add configuration |
| `CMD_GET_AUTOADD_CONFIG` | 59 | Get auto-add configuration |
| `CMD_SEND_CHANNEL_DATA` | 62 | Send binary channel datagram (`data_type + payload`) |
| `CMD_SET_DEFAULT_FLOOD_SCOPE` | 63 | Persist default flood scope (`name(31) + key(16)`) |
| `CMD_GET_DEFAULT_FLOOD_SCOPE` | 64 | Get persisted default flood scope |

`CMD_SEND_CHANNEL_DATA` payload after command byte matches firmware (`MyMesh.cpp`):

`[channel_idx][path_len][path...][data_type_le16][payload...]`

- `path_len=0xFF` means flood (no path bytes present)
- otherwise `path_len` uses normal encoded path-length semantics (1/2/3-byte path hashes)
- `data_type=0` is reserved and rejected

### Push Notifications

The frame server sends unsolicited push frames to the companion app when events occur:

| Push Code | Value | Description |
|---|---|---|
| `PUSH_CODE_ADVERT` | 0x80 | Contact advertisement received |
| `PUSH_CODE_MSG_WAITING` | 0x83 | New message queued |
| `PUSH_CODE_SEND_CONFIRMED` | 0x82 | ACK received for a sent message |
| `PUSH_CODE_RAW_DATA` | 0x84 | Raw custom payload received (SNR, RSSI, 0xFF, payload) |
| `PUSH_CODE_PATH_UPDATED` | 0x81 | Contact path updated |
| `PUSH_CODE_LOG_RX_DATA` | 0x88 | Raw RX packet (diagnostics) |
| `PUSH_CODE_TRACE_DATA` | 0x89 | Trace path response |
| `PUSH_CODE_NEW_ADVERT` | 0x8A | New (previously unknown) contact discovered |
| `PUSH_CODE_CONTROL_DATA` | 0x8E | Control data received |
| `PUSH_CODE_LOGIN_SUCCESS` | 0x91 | Repeater login succeeded |
| `PUSH_CODE_LOGIN_FAIL` | 0x92 | Repeater login failed |
| `PUSH_CODE_STATUS_RESPONSE` | 0x93 | Repeater status response |
| `PUSH_CODE_TELEMETRY_RESPONSE` | 0x8B | Telemetry response |
| `PUSH_CODE_BINARY_RESPONSE` | 0x95 | Binary request response |
| `PUSH_CODE_PATH_DISCOVERY_RESPONSE` | 0x96 | Path discovery response |

### Sync Message Responses

`CMD_SYNC_NEXT_MESSAGE` can return:

- `RESP_CODE_CONTACT_MSG_RECV` / `RESP_CODE_CONTACT_MSG_RECV_V3` for direct text messages
- `RESP_CODE_CHANNEL_MSG_RECV` / `RESP_CODE_CHANNEL_MSG_RECV_V3` for channel text messages
- `RESP_CODE_CHANNEL_DATA_RECV` (`27`) for channel binary datagrams
- `RESP_CODE_NO_MORE_MESSAGES` when the queue is empty

`RESP_CODE_CHANNEL_DATA_RECV` payload layout:

`[code=27][snr][0][0][channel_idx][path_len][data_type_le16][data_len][data...]`

### Host-Callable Push Methods

The frame server exposes methods for the host application to push data to the connected companion app:

```python
# Push trace data from the repeater (sync; enqueues like push_rx_raw)
server.push_trace_data(
    path_len=3, flags=0, tag=42, auth_code=0,
    path_hashes=b"...", path_snrs=b"...", final_snr_byte=0
)
# Optional async wrapper if you must await a coroutine:
await server.push_trace_data_async(
    path_len=3, flags=0, tag=42, auth_code=0,
    path_hashes=b"...", path_snrs=b"...", final_snr_byte=0
)

# Push raw RX packet for diagnostics logging (sync: schedules send, works without await)
server.push_rx_raw(snr=-5.0, rssi=-100, raw=b"...")
# Or from async code with backpressure:
await server.push_rx_raw_async(snr=-5.0, rssi=-100, raw=b"...")

# Push control data
await server.push_control_data(
    snr=-5.0, rssi=-100, path_len=2,
    path_bytes=b"...", payload=b"..."
)
```

### Persistence Hooks

`CompanionFrameServer` provides no-op hooks that subclasses override for persistent storage (e.g. SQLite):

```python
class MyFrameServer(CompanionFrameServer):
    async def _persist_companion_message(self, msg_dict: dict) -> None:
        """Called when a message is received. Save to database."""
        await self.db.save_message(msg_dict)

    def _sync_next_from_persistence(self) -> QueuedMessage | None:
        """Called when the in-memory queue is empty. Pop from database."""
        return self.db.pop_oldest_message()

    def _save_contacts(self) -> None:
        """Called after contact list changes. Sync to database."""
        self.db.save_contacts(self.bridge.contacts.to_dicts())

    def _save_channels(self) -> None:
        """Called after channel changes. Sync to database."""
        self.db.save_channels(...)

    def _get_batt_and_storage(self) -> tuple[int, int, int]:
        """Return (millivolts, used_kb, total_kb) for CMD_GET_BATT_AND_STORAGE."""
        return (4200, 128, 1024)
```

---

## Persistence Hooks

The companion module uses a "no-op hook" pattern for persistence: base classes define empty methods that subclasses override to save/load state from their storage backend.

### CompanionBase Hooks (Preferences)

```python
class CompanionBase:
    def _save_prefs(self) -> None:
        """Persist self.prefs. Called after any pref-mutating method."""

    def _load_prefs(self) -> None:
        """Restore self.prefs on startup. Called at end of _init_companion_stores()."""
```

`_save_prefs()` is called automatically by: `set_radio_params`, `set_tx_power`, `set_tuning_params`, `set_autoadd_config`, `set_other_params`, `set_advert_name`, `set_advert_latlon`.

Note: `set_time()` does **not** call `_save_prefs()` — the time offset is a transient runtime correction, not a persistent preference.

### CompanionFrameServer Hooks (Messages, Contacts, Channels)

```python
class CompanionFrameServer:
    async def _persist_companion_message(self, msg_dict: dict) -> None: ...
    def _sync_next_from_persistence(self) -> QueuedMessage | None: ...
    def _save_contacts(self) -> None: ...
    def _save_channels(self) -> None: ...
    def _get_batt_and_storage(self) -> tuple[int, int, int]: ...
```

---

## Use Cases

### 1. Chat Application

Build a terminal or GUI chat client that discovers peers and exchanges messages.

```python
companion = CompanionRadio(radio, identity, node_name="ChatApp")

companion.on_message_received(display_message)
companion.on_advert_received(add_to_contact_list)

await companion.start()
await companion.advertise()

# User picks a contact and sends
contact = companion.get_contact_by_name("Alice")
await companion.send_text_message(contact.public_key, user_input)
```

### 2. Sensor Gateway

Collect telemetry from sensor nodes in the mesh, forward to a database or MQTT.

```python
companion = CompanionRadio(radio, identity, node_name="Gateway", adv_type=ADV_TYPE_CHAT)

async def on_telemetry(event_data):
    # event_data contains parsed CayenneLPP sensor readings
    publish_to_mqtt(event_data)

companion.on_telemetry_response(on_telemetry)

await companion.start()

# Periodically poll known sensors
for sensor in companion.get_contacts():
    if sensor.adv_type == ADV_TYPE_SENSOR:
        await companion.send_telemetry_request(
            sensor.public_key, want_base=True,
            want_location=True, want_environment=True, timeout=15,
        )
```

### 3. Repeater Companion (Bridge Mode)

Add a companion identity to an existing repeater without a second radio.

```python
bridge = CompanionBridge(
    identity=identity,
    packet_injector=repeater.inject_packet,
    node_name="RepeaterBot",
    authenticate_callback=auth_check,
)

bridge.on_message_received(handle_bot_command)
await bridge.start()

# In the repeater's RX loop:
async def repeater_on_rx(pkt):
    await bridge.process_received_packet(pkt)
    # ... also handle repeater logic ...
```

### 4. Companion Frame Server (TCP Protocol)

Expose a companion over TCP so standard companion apps can connect.

```python
bridge = CompanionBridge(
    identity=identity,
    packet_injector=repeater.inject_packet,
    node_name="pyMC-Server",
)

server = CompanionFrameServer(
    bridge=bridge,
    companion_hash="abcd1234",
    port=5000,
    device_model="pyMC-Companion",
    device_version="1.0.0",
)

await bridge.start()
await server.start()
# Companion apps (Android/iOS) can now connect on port 5000
```

### 5. Network Diagnostics Tool

Trace paths and discover topology.

```python
companion.on_trace_received(lambda data: print(f"Trace: {data}"))
companion.on_path_discovery_response(
    lambda tag, key, out_path, in_path: print(f"Path to {key.hex()[:8]}: out={out_path}, in={in_path}")
)

# Trace route to a node
await companion.send_trace_path(target_key, tag=1, auth_code=0)

# Discover paths
await companion.send_path_discovery_req(target_key)
```

### 6. Group Chat / Channels

```python
companion.set_channel(0, name="Emergency", secret=b"shared_channel_secret___________")
companion.set_channel(1, name="General",   secret=b"another_shared_secret___________")

companion.on_channel_message_received(
    lambda ch_name, sender, text, ts, path_len, idx, *args:
        print(f"[{ch_name}] {sender}: {text}")
)

await companion.send_channel_message(0, "Emergency broadcast")
```

---

## Push Callbacks Reference

Register callbacks to receive asynchronous events. Both sync and async functions are supported.
Callbacks for `on_message_received` and `on_channel_message_received` receive optional trailing args
`(packet_hash, snr, rssi)` when available; use `*args` to ignore them.

| Registration Method | Callback Signature |
|---|---|
| `on_message_received` | `(sender_key: bytes, text: str, timestamp: int, txt_type: int [, packet_hash, snr, rssi])` |
| `on_channel_message_received` | `(channel_name: str, sender_name: str, text: str, timestamp: int, path_len: int, channel_idx: int [, packet_hash, snr, rssi])` |
| `on_advert_received` | `(contact: Contact)` |
| `on_contact_path_updated` | `(contact: Contact)` |
| `on_send_confirmed` | `(ack_crc: int)` |
| `on_trace_received` | `(trace_data)` |
| `on_node_discovered` | `(event_data)` |
| `on_login_result` | `(result_data)` |
| `on_telemetry_response` | `(event_data)` |
| `on_status_response` | `(status_data)` |
| `on_raw_data_received` | `(payload: bytes, snr: float, rssi: int)` — raw custom packet received |
| `on_rx_log_data` | `(snr: float, rssi: int, raw_bytes: bytes)` — **CompanionRadio only**; same data as PUSH 0x88 LOG_RX_DATA |
| `on_binary_response` | `(tag: bytes, data: bytes, parsed: dict\|None, request_type: int\|None)` |
| `on_path_discovery_response` | `(tag: bytes, contact_pubkey: bytes, out_path: bytes, in_path: bytes)` |

---

## Models Reference

### Contact

```python
@dataclass
class Contact:
    public_key: bytes           # 32-byte Ed25519 public key
    name: str = ""              # up to 32 characters
    adv_type: int = 0           # ADV_TYPE_CHAT / REPEATER / ROOM / SENSOR
    flags: int = 0
    out_path_len: int = -1      # -1=unknown, 0=direct, >0=multi-hop
    out_path: bytes = b""
    last_advert_timestamp: int = 0
    lastmod: int = 0
    gps_lat: float = 0.0
    gps_lon: float = 0.0
    sync_since: int = 0
```

### Channel

```python
@dataclass
class Channel:
    name: str           # up to 32 characters
    secret: bytes       # 16-byte pre-shared key
```

### NodePrefs

```python
@dataclass
class NodePrefs:
    node_name: str = "pyMC"
    adv_type: int = 1               # ADV_TYPE_CHAT
    tx_power_dbm: int = 20
    frequency_hz: int = 915000000
    bandwidth_hz: int = 250000
    spreading_factor: int = 10
    coding_rate: int = 5
    latitude: float = 0.0
    longitude: float = 0.0
    advert_loc_policy: int = 0      # ADVERT_LOC_NONE
    multi_acks: int = 0
    telemetry_mode_base: int = 0    # TELEM_MODE_DENY
    telemetry_mode_location: int = 0
    telemetry_mode_environment: int = 0
    manual_add_contacts: int = 0
    autoadd_config: int = 0
    rx_delay_base: float = 0.0
    airtime_factor: float = 0.0
    client_repeat: int = 0   # reported in CMD_DEVICE_QUERY device info frame (byte 80)
    path_hash_mode: int = 0   # 0=1-byte, 1=2-byte, 2=3-byte path hashes for flood packets (byte 81)
    default_scope_name: str = ""   # persisted default scope label (v1.15)
    default_scope_key: bytes = b"" # persisted default scope key (16 bytes)
```

---

### SentResult

```python
@dataclass
class SentResult:
    success: bool
    is_flood: bool = False
    expected_ack: int | None = None
    timeout_ms: int | None = None
```

### QueuedMessage

```python
@dataclass
class QueuedMessage:
    sender_key: bytes
    txt_type: int = 0           # TXT_TYPE_PLAIN / CLI_DATA / SIGNED_PLAIN
    timestamp: int = 0
    text: str = ""
    is_channel: bool = False
    channel_idx: int = 0
    path_len: int = 0
```

### AdvertPath

```python
@dataclass
class AdvertPath:
    public_key_prefix: bytes    # 7-byte prefix
    name: str = ""
    path_len: int = 0
    path: bytes = b""
    recv_timestamp: int = 0
```

### PacketStats

```python
@dataclass
class PacketStats:
    flood_tx: int = 0
    flood_rx: int = 0
    direct_tx: int = 0
    direct_rx: int = 0
    tx_errors: int = 0
```

---

## Constants

```python
# Advertisement types
ADV_TYPE_CHAT      = 1
ADV_TYPE_REPEATER  = 2
ADV_TYPE_ROOM      = 3
ADV_TYPE_SENSOR    = 4

# Text message types
TXT_TYPE_PLAIN         = 0
TXT_TYPE_CLI_DATA      = 1
TXT_TYPE_SIGNED_PLAIN  = 2

# Telemetry modes
TELEM_MODE_DENY        = 0
TELEM_MODE_ALLOW_FLAGS = 1
TELEM_MODE_ALLOW_ALL   = 2

# Location policy
ADVERT_LOC_NONE  = 0
ADVERT_LOC_SHARE = 1

# Auto-add config bitmask
AUTOADD_OVERWRITE_OLDEST = 0x01
AUTOADD_CHAT             = 0x02
AUTOADD_REPEATER         = 0x04
AUTOADD_ROOM             = 0x08
AUTOADD_SENSOR           = 0x10

# Stats types
STATS_TYPE_CORE    = 0
STATS_TYPE_RADIO   = 1
STATS_TYPE_PACKETS = 2

# Binary request types (IntEnum)
BinaryReqType.STATUS     # 0x01
BinaryReqType.KEEP_ALIVE # 0x02
BinaryReqType.TELEMETRY  # 0x03
BinaryReqType.MMA        # 0x04
BinaryReqType.ACL        # 0x05
BinaryReqType.NEIGHBOURS # 0x06

# Protocol codes
PROTOCOL_CODE_RAW_DATA    = 0x00
PROTOCOL_CODE_BINARY_REQ  = 0x02
PROTOCOL_CODE_ANON_REQ    = 0x07

# Frame format
FRAME_OUTBOUND_PREFIX = 0x3E  # '>' (radio → app)
FRAME_INBOUND_PREFIX  = 0x3C  # '<' (app → radio)
MAX_FRAME_SIZE        = 172
MAX_PAYLOAD_SIZE      = 169   # MAX_FRAME_SIZE - 3 (prefix + 2-byte length)

# Error codes (returned by frame server)
ERR_CODE_UNSUPPORTED_CMD = 1
ERR_CODE_NOT_FOUND       = 2
ERR_CODE_TABLE_FULL      = 3
ERR_CODE_BAD_STATE       = 4
ERR_CODE_FILE_IO_ERROR   = 5
ERR_CODE_ILLEGAL_ARG     = 6

# Defaults
DEFAULT_RESPONSE_TIMEOUT_MS = 10000
DEFAULT_MAX_CONTACTS        = 1000
DEFAULT_MAX_CHANNELS        = 40
DEFAULT_OFFLINE_QUEUE_SIZE  = 512
PUB_KEY_SIZE                = 32
MAX_PATH_SIZE               = 64
```

---

## Unimplemented MeshCore Companion Features

The following protocol-level features from the MeshCore companion radio firmware (`examples/companion_radio/`) are **not yet implemented** in openhop-core. CMD_SEND_RAW_DATA (25) and PUSH_CODE_RAW_DATA (0x84) for raw custom packets are implemented.

| Feature | Firmware Reference | Description |
|---|---|---|
| Has connection | `CMD_HAS_CONNECTION` (0x1C) | Check if active connection exists to a contact |
| Push: contact deleted | `PUSH_CODE_CONTACT_DELETED` (0x8F) | Notification when a contact is overwritten by auto-add |
| Push: contacts full | `PUSH_CODE_CONTACTS_FULL` (0x90) | Notification when contact storage is full |
| Keep-alive mechanism | Server-driven keep-alive | Periodic keep-alive packets for active server connections |
