# hdht

HyperDHT client and server in C: the networking core of hyperdht-esp32. It speaks the [hyperdht](https://github.com/holepunchto/hyperdht) 6.x wire protocol byte for byte. The protocol notes it was written from are in [`docs/protocol.md`](../../docs/protocol.md).

The same sources build in two ways:
- **ESP-IDF component**, on top of `uv_esp` (a libuv subset for lwIP), `libudx` and `espressif/libsodium`.
- **Desktop library** (macOS/Linux) on real libuv, for fast tests against the JS reference.

## Features

| Area | Status |
|---|---|
| dht-rpc: requests, retries, relaying, small routing table, iterative queries | Done. The device is an ephemeral, firewalled node, not a routing node |
| Noise IK and XX (`Noise_*_Ed25519_ChaChaPoly_BLAKE2b`) | Done; byte-exact against vectors from the JS |
| SecretStream over UDX: framing, `crypto_secretstream`, keepalive, graceful end | Done; unordered `send` messages not supported |
| SecretStream over any byte stream (`secret_stream.h`): in-band handshake | Done; used for BLE |
| `hdht_connect`: FIND_PEER, relayed handshake, direct/OPEN, LAN shortcut, holepunch | Done |
| `hdht_listen`: announce to the 3 closest nodes, relay keepalive pings every 3 s, re-announce every ~5 min, relayed handshakes, holepunch, unannounce on close | Done |
| Mutable records (`hdht_mutable_put` / `hdht_mutable_get`): signed values up to 1000 bytes stored under a public key | Done; interoperates with hyperdht's `mutablePut` / `mutableGet` |
| Topic lookup (`hdht_lookup`): the public keys announced under a topic | Done; finds peers announced by hyperdht's `announce` and Hyperswarm servers |
| Holepunching | Consistent ↔ consistent NATs, and local consistent ↔ remote random (random-port probing). A **random NAT on the device's side** is not supported, because hyperdht opens up to 256 sockets for that |
| Not implemented | blind-relay fallback (`relayThrough`), immutable put/get, announcing under a topic from the device, reusable sockets, IPv6 |

## API

Everything runs on one event loop: libuv on desktop, `uv_esp` on the device. **Call `hdht_*` functions only from the task running that loop.** To hand work over from other tasks, use `uv_async_send`, as [`examples/minimal`](../../examples/minimal) does.

```c
#include "hdht.h"

hdht_t dht;
hdht_opts_t opts = {0};                      // .bootstrap = NULL: public HyperDHT nodes
hdht_init(&dht, &loop, &opts);
hdht_add_local_address(&dht, lan_ip);        // lets peers behind the same router connect over the LAN
hdht_bootstrap(&dht, on_ready);              // on_ready(dht, status)

// server: reachable by public key
hdht_server_t server;
hdht_listen(&dht, &server, public_key, secret_key, on_connection, on_listening, user_data);
// on_connection(server, stream): set stream->on_data / on_close / data.
// The library owns server streams and frees them after on_close returns.

// client: connect by public key
hdht_stream_t stream;                        // caller-owned
hdht_connect(&dht, &stream, server_public_key, on_open, on_data, on_close, user_data);

hdht_stream_write(&stream, data, len);       // one encrypted message
hdht_stream_end(&stream);                    // graceful close
hdht_stream_destroy(&stream, 0);             // immediate close
// on_close(stream, error) always runs last; error < 0 if the connection failed

// mutable records: a signed value stored under a public key
hdht_mutable_put(&dht, public_key, secret_key, seq, value, len, on_put, user_data);
hdht_mutable_get(&dht, public_key, min_seq, on_get, user_data);

// topic lookup: who announced under a topic (for example a Hyperswarm topic)
hdht_lookup(&dht, topic, on_peers, user_data);
// on_put(dht, status, stored_nodes, data); on_get(dht, status, seq, value, len, data)

hdht_server_close(&server, on_closed);
hdht_destroy(&dht, on_destroyed);
```

- **Keys**: Ed25519 key pairs (`hdht_keypair(pk, sk, seed)`). The public key is the device's address. Generate a random seed once and keep it, for example in NVS.
- **Peers**: `stream->remote_public_key` is authenticated by the Noise handshake. Check it against an allow list if only known peers may connect.
- **Mutable records**: stored on the ~20 nodes closest to `BLAKE2b(public key)`, which keep them for up to 48 hours, so republish periodically. A higher `seq` replaces a lower one; putting the same `seq` with a different value fails with `HDHT_MUTABLE_ESEQ_REUSED`, and a lower one with `HDHT_MUTABLE_ESEQ_TOO_LOW`. `get` returns only values whose signature matches the key, and the highest `seq` it finds. Anyone holding a signed record can republish it unchanged.
- **Topic lookup**: returns up to `HDHT_LOOKUP_MAX_PEERS` (16) distinct public keys from the nodes closest to the topic. The replies are not signed, so treat each key as a hint: connecting to it is what authenticates it, and anything the peer claims should be checked, for example against its mutable record.
- **Errors**: connection failures are reported through `on_close` with a `HDHT_CONNECT_E*` or `HDHT_STREAM_E*` code.

### SecretStream over other transports

`secret_stream.h` runs the official SecretStream protocol, including its in-band Noise XX/IK handshake, over any reliable byte stream: feed it received bytes and it hands back bytes to send. `components/hdht_ble` uses it over BLE GATT, and `test/test_ss.c` uses it over TCP. The other end can be the unmodified `@hyperswarm/secret-stream`.

```c
hdht_ss_t ss;
hdht_ss_init(&ss, false, HDHT_NOISE_XX, public_key, secret_key, NULL);
ss.on_send = transmit;     // bytes for the transport
ss.on_open = on_open;      // ss.remote_public_key is authenticated now
ss.on_data = on_message;
hdht_ss_feed(&ss, received, len);
hdht_ss_write(&ss, msg, len);
```

## ESP-IDF requirements

- Components: `hdht`, `libudx`, `uv_esp`. `espressif/libsodium` is fetched automatically through `idf_component.yml`.
- `CONFIG_FREERTOS_HZ=1000`: libudx paces with 1 ms timers.
- `CONFIG_LWIP_UDP_RECVMBOX_SIZE=32`: the default of 6 drops packets while the loop is busy, which halves throughput.
- A large enough app partition: WiFi + hdht is ~1.06 MB, so for example `CONFIG_PARTITION_TABLE_SINGLE_APP_LARGE=y`.
- The loop task needs **at least 16 KB of stack** (20 KB recommended): libudx's `_send_packet` alone uses 11.6 KB.

## Memory on the ESP32-C3

| Item | Value |
|---|---|
| Node (`hdht_t`, socket, timers) | ~0.5 KB plus the 32-entry routing table inside `hdht_t` |
| One connection, peak | ~25 KB of heap (query, Noise, puncher socket, UDX stream) |
| Loop task stack | 12.5–13.5 KB used |
| Free heap with WiFi up, during a connection | ~165 KB |

Measurements and logs are in [`examples/hyperdht_demo/README.md`](../../examples/hyperdht_demo/README.md).

## Desktop build and tests

Needs CMake, Ninja, libuv and libsodium (`brew install libuv libsodium`, or your distro's packages).

```bash
cmake -S components/hdht -B components/hdht/build -G Ninja && ninja -C components/hdht/build
```

```bash
components/hdht/build/test_vectors
```

`test_vectors` checks Noise, key derivation, every message encoding and the announce signature against vectors generated from the JS reference (`tools/host/gen-vectors.js`).

Interop tests run against a private testnet with a JS peer:

```bash
cd tools/host && npm install
```

```bash
node tools/host/testnet.js --server --firewalled
```

Then:
- `components/hdht/build/test_connect 127.0.0.1:49800 <key>` connects from C to the JS server over the holepunch path.
- `components/hdht/build/test_server 127.0.0.1:49800` announces a C server; then `node tools/host/connect-board.js 127.0.0.1:49800 5 0x22` connects to it from JS.
- `components/hdht/build/test_mutable 127.0.0.1:49800 put <hex seed> <seq> <value>` stores a mutable record and `test_mutable 127.0.0.1:49800 get <hex public key>` reads one; either side can be hyperdht's `mutablePut` / `mutableGet`. Both also work with `public`.
- `components/hdht/build/test_lookup <host:port | public> <hex topic>` lists the keys announced under a topic, for example by a Hyperswarm server that joined it.
- `components/hdht/build/test_ss 7777 xx` is a SecretStream responder over TCP; `node tools/host/ss-client.js 7777 xx` runs the official module against it.

## Source map

| File | Contents |
|---|---|
| `include/hdht.h` | Public API |
| `src/cenc.h` | compact-encoding primitives |
| `src/dht.c` | dht-rpc: transport, routing table, iterative queries |
| `src/messages.c` | HyperDHT message encodings |
| `src/noise.c` | Noise IK/XX with Ed25519 DH and BLAKE2b |
| `src/crypto.c` | Namespaces, node ids, tokens |
| `src/stream.c` | SecretStream over UDX |
| `src/secret_stream.c` | SecretStream over any byte stream |
| `src/holepunch.c` | NAT analysis and probing |
| `src/connect.c` | Client connect state machine |
| `src/server.c` | Announcer and server handshakes |
| `src/hdht.c` | Node setup, bootstrap, request routing |
