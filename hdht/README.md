# hdht: HyperDHT in C for the ESP32-C3

A from-scratch C implementation of the [HyperDHT](https://github.com/holepunchto/hyperdht) client and server, so a device can connect to (and be connected to by) Holepunch peers by public key, through NATs, end-to-end encrypted. It speaks the hyperdht 6.x wire protocol byte for byte. The wire format is documented in [`docs/PROTOCOL.md`](../docs/PROTOCOL.md).

The same code builds two ways:
- **ESP-IDF component**, using the PoC's libuv shim (`poc/components/uv_esp`), libudx (`poc/components/libudx`, with two upstream bug fixes) and `espressif/libsodium`. The demo app is in `firmware/`.
- **Desktop library** (macOS/Linux) using libuv, for fast interop tests against the JS reference.

## What it does

| Area | Status |
|---|---|
| dht-rpc (requests, retries, relaying, routing table, iterative queries) | Done. Ephemeral, firewalled node only |
| Noise IK (`Noise_IK_Ed25519_ChaChaPoly_BLAKE2b`) | Done, byte-exact against the JS vectors |
| SecretStream over UDX (framing, secretstream, keepalive, graceful end) | Done. Unordered `send` messages not supported |
| Client `connect(publicKey)`: FIND_PEER, relayed handshake, direct, OPEN, LAN shortcut, holepunch | Done |
| Server `listen(keyPair)`: announce to the 3 closest nodes, 3 s relay pings, ~5 min re-announce, relayed handshakes, holepunch, unannounce on close | Done |
| Holepunching | Consistent ↔ consistent, and local consistent ↔ remote random (random-port probing). A local **random** NAT is not supported: the JS uses up to 256 sockets for that |
| Not implemented | blind-relay fallback (`relayThrough`), mutable/immutable put/get, LOOKUP, Hyperswarm topics, reusable sockets, IPv6 |

## API

```c
#include "hdht.h"

hdht_t dht;
hdht_opts_t opts = {.bootstrap = NULL}; // NULL = public HyperDHT bootstrap nodes
hdht_init(&dht, loop, &opts);
hdht_add_local_address(&dht, my_lan_ip); // lets peers on the same LAN connect directly
hdht_bootstrap(&dht, on_ready);

// client
hdht_stream_t stream;
hdht_connect(&dht, &stream, server_public_key, on_open, on_data, on_close, user_data);
hdht_stream_write(&stream, buf, len);
hdht_stream_end(&stream);

// server
hdht_server_t server;
hdht_listen(&dht, &server, public_key, secret_key, on_connection, on_listening, user_data);
// in on_connection: set stream->on_data / on_close; the library frees server streams after on_close
hdht_server_close(&server, on_closed);
```

Everything runs on one event loop (libuv on desktop, uv_esp on the device). There are no threads and no locks.

## Building and testing on a desktop

```bash
cmake -S hdht -B hdht/build -G Ninja && ninja -C hdht/build
```

```bash
hdht/build/test_vectors
```

`test_vectors` checks Noise, key derivation, all message encodings and the announce signature against vectors generated from the JS (`poc/host/gen-vectors.js`).

Interop tests need a private testnet from `poc/host/testnet.js` (`npm install` there first):

```bash
node poc/host/testnet.js --server --firewalled
```

Then, against it:

- `hdht/build/test_connect 127.0.0.1:49800 <key>` connects from C to the JS server (holepunch path).
- `hdht/build/test_server 127.0.0.1:49800` announces a C server; `node poc/host/connect-board.js 127.0.0.1:49800 5 0x22` connects to it from JS.

## Memory on the ESP32-C3

See `firmware/README.md` for measured numbers. In short: the node itself is a few KB, one client connection peaks at about 25 KB of heap, and the event loop task needs about 13 KB of stack (20 KB configured).
