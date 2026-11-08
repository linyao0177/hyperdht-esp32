# hyperdht-esp32

**[HyperDHT](https://github.com/holepunchto/hyperdht) for microcontrollers.** A C implementation of the Holepunch peer-to-peer networking core for the ESP32-C3. It lets a device reach, and be reached by, any HyperDHT peer by **public key**, through NATs, **end-to-end encrypted**, with no server of your own.

It speaks the hyperdht 6.x wire protocol byte for byte, so the other end can be an unmodified Node.js `hyperdht` app. Hyperswarm apps dial the device with `swarm.joinPeer(publicKey)`, and the device finds and connects to Hyperswarm servers by topic (tested with Hyperswarm on Node.js, and with a Pear app on Bare). A device can also open the same encrypted channel over **Bluetooth LE** with the same key, when there is no internet.

> **Status: experimental.** Both the client and the server work on real hardware: on the public DHT, through home routers, and across a carrier NAT. The API may still change, and some hyperdht features are missing (see [Limitations](#limitations)).

```
   ESP32-C3                          the internet                           your laptop / phone
 ┌────────────┐   find, handshake    ┌──────────────────┐   find, handshake   ┌───────────────────┐
 │ hyperdht-  │ ───────────────────▶ │  public HyperDHT │ ◀────────────────── │ hyperdht (Node),  │
 │ esp32      │                      │  nodes           │                     │ Pear, Hyperswarm  │
 └─────┬──────┘                      └──────────────────┘                     └─────────┬─────────┘
       │            direct UDP after holepunching, Noise + secretstream encrypted       │
       └────────────────────────────────────────────────────────────────────────────────┘
```

## Contents

- [Features](#features)
- [Quick start](#quick-start)
- [Using it in your project](#using-it-in-your-project)
- [Performance and footprint](#performance-and-footprint)
- [How it works](#how-it-works)
- [Same key over BLE](#same-key-over-ble)
- [Repository layout](#repository-layout)
- [Testing](#testing)
- [Limitations](#limitations)
- [Contributing](#contributing)
- [Acknowledgements and license](#acknowledgements-and-license)

## Features

- **Client**: `hdht_connect(public_key)`. Finds the peer on the DHT, runs the Noise IK handshake through a relay node, then connects directly, over the LAN, or by UDP holepunching.
- **Server**: `hdht_listen(key_pair)`. Announces the device to the closest DHT nodes, keeps the relay paths alive, answers relayed handshakes, holepunches, and re-announces every ~5 min.
- **Encrypted streams**: wire-compatible with [`@hyperswarm/secret-stream`](https://github.com/holepunchto/hyperswarm-secret-stream), carried over [libudx](https://github.com/holepunchto/libudx) (reliable UDP with BBR).
- **SecretStream over any transport**: an in-band Noise XX/IK handshake over BLE, TCP or a UART, talking to the official JS module.
- **Small footprint**: ~25 KB of heap per connection, one event-loop task, no threads, no PSRAM. ESP-IDF 5.3+.
- **Tested against the reference**: byte-exact test vectors from the JS implementation, plus interop tests against `hyperdht` on a private testnet, the public DHT, and real NATs.

## Quick start

You need an ESP32-C3 board with 4 MB flash, [ESP-IDF](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c3/get-started/) 5.3 or newer, a 2.4 GHz WiFi network, and Node.js on a computer.

1. Clone the repo and add your WiFi credentials:

   ```bash
   git clone https://github.com/linyao0177/hyperdht-esp32 && cd hyperdht-esp32
   ```

   ```bash
   cp sdkconfig.wifi.example sdkconfig.wifi    # then edit SSID and password
   ```

2. Build and flash the minimal example:

   ```bash
   cd examples/minimal && idf.py set-target esp32c3 && idf.py build flash monitor
   ```

3. Wait for the device to print its public key:

   ```
   bootstrapped (status 0, 32 nodes)
   listening (status 0), public key:
   b30a4d32cc55008d3ccac0c31852b6bf074dcd5764a4a3ae98defbaa919d0f17
   ```

4. Connect to it from anywhere:

   ```bash
   npm install hyperdht
   ```

   ```js
   const DHT = require('hyperdht')
   const socket = new DHT().connect(Buffer.from('<device public key>', 'hex'))
   socket.on('open', () => socket.write('hello'))
   socket.on('data', (data) => console.log(data.toString()))
   ```

You get `hello` back, then a reading every 5 s pushed from another task on the device. See [`examples/minimal`](examples/minimal) for what the firmware does.

## Using it in your project

**1. Add the components.** Add this repo as a git submodule (or copy it), and list the components in your `main/idf_component.yml`, pointing at the copy until they are on the ESP Component Registry:

```yaml
dependencies:
  tlay/hdht:
    version: "0.1.0"
    override_path: "../third_party/hyperdht-esp32/components/hdht"
  tlay/libudx:
    version: "0.1.0"
    override_path: "../third_party/hyperdht-esp32/components/libudx"
  tlay/uv_esp:
    version: "0.1.0"
    override_path: "../third_party/hyperdht-esp32/components/uv_esp"
```

In your component's `CMakeLists.txt`, add `REQUIRES hdht`, plus `hdht_ble` for BLE or `hdht_cred` for credential checks (add them to the manifest the same way). libsodium comes from the ESP Component Registry. The examples in this repo are set up this way. A project that lists only `tlay/hdht` this way also builds, the rest resolving through the components' own manifests; that was tried with the components packed by `compote` into registry-style folders, and short names in `REQUIRES` still work (ESP-IDF 5.5).

**2. Set the required options** in `sdkconfig.defaults`:

```
CONFIG_FREERTOS_HZ=1000                     # libudx paces with 1 ms timers
CONFIG_LWIP_UDP_RECVMBOX_SIZE=32            # the default of 6 drops packets and halves throughput
CONFIG_PARTITION_TABLE_SINGLE_APP_LARGE=y   # WiFi + hdht is ~1.06 MB
```

**3. Run hdht on its own task** with at least 16 KB of stack (20 KB recommended):

```c
static void hdht_task(void *arg) {
  uv_loop_init(&loop);
  uv_async_init(&loop, &wake, on_wake);     // lets other tasks hand data to this loop
  hdht_init(&dht, &loop, &(hdht_opts_t){0}); // public bootstrap nodes
  hdht_bootstrap(&dht, on_ready);           // then hdht_listen() and/or hdht_connect()
  uv_run(&loop, UV_RUN_DEFAULT);
}
```

**4. Follow the threading rule.** hdht is single-threaded: call `hdht_*` only from that task. Other tasks put data in a FreeRTOS queue and call `uv_async_send()`, which is safe from any task, to wake the loop.

**5. Keep a real identity.** Generate a random seed once, store it (NVS, ideally encrypted), and derive the key pair with `hdht_keypair()`. The public key is the device's address. On the server side, check `stream->remote_public_key` if only known peers may connect.

The full API is in [`components/hdht/README.md`](components/hdht/README.md).

## Performance and footprint

Measured on an ESP32-C3 (rev v0.4, 160 MHz, 2.4 GHz WiFi). Details and logs are in [`examples/hyperdht_demo`](examples/hyperdht_demo/README.md).

| Scenario | Result |
|---|---|
| Bootstrap on the public DHT | ~3 s (routing table full) |
| Connect by key on a LAN testnet, holepunched | ~0.5 s, 9/9 as client; 0.34–0.47 s, 10/10 as server |
| Public DHT, same router (hairpin NAT) | Client 3/3, 1.4–1.9 s; server 10/10 |
| Across a home router and a carrier NAT (random-port punching) | Client 3/3 in 12–32 s; server 3/4 in 9–20 s |
| 30-minute server run, a connection every 30 s | 52/52, 6 re-announces, flat heap |
| UDX echo throughput on a LAN | 313–365 KiB/s (CPU bound) |
| Heap per connection | ~25 KB peak |
| Free heap with WiFi + DHT, during a connection | ~165 KB |
| Free heap with WiFi + DHT + BLE, all busy | ~50 KB |
| Firmware size (WiFi + libsodium + hdht) | ~1.06 MB; +0.22 MB with BLE |

Crypto runs in software (the C3 has no Ed25519 or BLAKE2b acceleration). An Ed25519 DH takes ~40 ms, and a full Noise handshake ~0.2 s per side.

## How it works

The Holepunch stack, and what this project implements:

| Layer | Holepunch (JS) | hyperdht-esp32 |
|---|---|---|
| Apps, storage | Pear, Hypercore, Autobase | out of scope |
| Discovery by topic | Hyperswarm | **reimplemented in C**: lookup and announce, so the device finds Hyperswarm servers and they find it |
| Peer connections | hyperdht | **reimplemented in C** (`components/hdht`) |
| DHT RPC | dht-rpc | **reimplemented in C** |
| Encryption | Noise IK/XX, SecretStream | **reimplemented in C** on libsodium |
| Transport | libudx + libuv | official **libudx**, on **uv_esp** (a libuv subset for lwIP) |

A connection goes like this:
1. The client looks up `BLAKE2b(server public key)` on the DHT.
2. The nodes holding the server's announcement relay a Noise IK handshake between the two sides.
3. Both sides sample their NAT mappings from a fresh socket and exchange addresses through encrypted, relayed holepunch messages.
4. Each side sends UDP probes until one gets through.
5. The UDX stream is connected on that socket and the SecretStream starts.

How the pieces fit together as a base layer for products (identity, reachability, encrypted channels, signed records, trust model, roadmap) is in [`docs/architecture.md`](docs/architecture.md). The byte-level details are in [`docs/protocol.md`](docs/protocol.md). To run an open anchor node on the public testnet, see [`docs/anchor-node.md`](docs/anchor-node.md). Manufacturer credentials, which tell a genuine device from any other key, are in [`docs/credentials.md`](docs/credentials.md), and protecting device keys in hardware is in [`docs/key-protection.md`](docs/key-protection.md). The design study that led here, including memory estimates and the alternatives considered, is in [`docs/feasibility.md`](docs/feasibility.md).

## Same key over BLE

[`components/hdht_ble`](components/hdht_ble) runs the same SecretStream over a BLE GATT service, keyed by the device's HyperDHT identity. A phone or laptop next to the device can open an end-to-end encrypted session without any network. The device advertises the first bytes of its HyperDHT target, so the client can verify it is talking to the right key. On a Mac with the official JS module: Noise XX in ~190 ms, ~60 ms round trips, ~10 KiB/s each way. See [`examples/ble_echo`](examples/ble_echo/README.md).

WiFi + HyperDHT + BLE also run together on one C3, with ~50 KB of heap to spare.

## Repository layout

| Path | What |
|---|---|
| [`components/hdht`](components/hdht) | The HyperDHT library (ESP-IDF component, also builds on desktop) |
| [`components/libudx`](components/libudx) | Vendored [libudx](https://github.com/holepunchto/libudx) with two bug fixes, plus ESP-IDF glue |
| [`components/uv_esp`](components/uv_esp) | The libuv subset libudx and hdht need, on lwIP |
| [`components/hdht_ble`](components/hdht_ble) | SecretStream over BLE GATT (NimBLE) |
| [`components/hdht_cred`](components/hdht_cred) | Manufacturer credentials checked on the device: a peer's record, its credential, the issuer's revocations |
| [`components/hdht_ota`](components/hdht_ota) | Firmware updates from a Hypercore over HyperDHT, every block checked on the device against the publisher's signed tree |
| [`components/zk`](components/zk) | Groth16 verification on alt_bn128 (circom/snarkjs proofs) with vendored [mcl](https://github.com/herumi/mcl), and the camera event format that uses it |
| [`examples/minimal`](examples/minimal) | Start here: a device reachable by key, NVS identity, cross-task data |
| [`examples/uart_module`](examples/uart_module) | The C3 as a network module: a host MCU drives it with AT-style commands over a serial line ([command reference](docs/module-uart.md)) |
| [`examples/app_template`](examples/app_template) | Template for a product with no server: signed record, claim with a setup code, owner-signed grants, revocation, signed readings kept by any peer |
| [`examples/hyperdht_demo`](examples/hyperdht_demo) | Test firmware: client rounds, then server; optional BLE |
| [`examples/ble_echo`](examples/ble_echo) | BLE-only SecretStream echo |
| [`examples/boat_mer`](examples/boat_mer) | With [BoAT MER](https://github.com/TLAY-IO/boat-mer): DID as the HyperDHT address, DID records in the DHT, open anchor nodes found by topic lookup (public testnet), nanopayments over HyperDHT |
| [`packages/boat-peer`](packages/boat-peer) | The app side of BoAT MER for Node.js, Bare and Pear: DID records, signed readings, and a seller that checks every payment |
| [`packages/wdk-protocol-boat-evm`](packages/wdk-protocol-boat-evm) | BoAT MER devices for Tether's WDK: a WDK EVM account sells to devices and settles their EIP-3009 payments, one by one or in batches, also from an ERC-4337 account whose gas an operator sponsors; an x402 facilitator, for devices that sell with x402 too |
| [`packages/wdk-protocol-boat-solana`](packages/wdk-protocol-boat-solana) | The device as a Solana signer for WDK: it signs its own SPL token (USD₮) transfers with a key derived from its DID, a WDK account pays the fee |
| [`packages/boat-ota`](packages/boat-ota) | Firmware releases in a Hypercore: publish, seed from any peer, fetch and check the way a device does |
| [`apps/pear-seller`](apps/pear-seller) | A Pear app that sells to `examples/boat_mer` devices, settles their payments with a WDK account, and keeps the receipts in a Hypercore |
| [`tools/host`](tools/host) | Node.js peers: private testnet, test clients, vector generator, BLE client, BoAT MER seller, anchor node, discovery and verifier, app template peer, module test peers, credential issuer |
| [`docs`](docs) | Architecture, protocol notes and the feasibility study |
| [`research/phase0`](research/phase0) | The original feasibility PoC (libsodium and libudx measurements) |
| [`patches/libudx`](patches/libudx) | The libudx fixes, prepared for upstream |

## Testing

- **Desktop** (fast): `components/hdht` builds with libuv and libsodium. `test_vectors` checks Noise, key derivation, every message encoding and the announce signature byte for byte against vectors generated from the JS. Interop programs connect to and accept connections from `hyperdht` on a private testnet. See [`components/hdht/README.md`](components/hdht/README.md#desktop-build-and-tests).
- **On the device**: `examples/hyperdht_demo` plus `tools/host/testnet.js` and `tools/host/connect-board.js` reproduce the measurements above. `tools/capture.py` resets the board and collects its output.

## Limitations

- **Random NAT on the device side**: no holepunching. hyperdht handles this case with up to 256 sockets ("birthday" punching), which a C3 cannot afford. Such a device connects through a blind relay instead (`hdht_set_relay`), which needs a relay node with a public address. Devices can find public relay nodes by topic (`hdht_relay_find`, [docs/relay-node.md](docs/relay-node.md)), and one runs on a cloud VM; more operators are needed. A device behind a consistent NAT can still reach peers behind random NATs directly.
- **Relayed connections move to direct paths only by holepunching**: as in hyperdht, holepunching runs alongside the relay and a stream moves when it gets through. The LAN shortcut is not tried alongside a relay, and a relayed connection to a peer with a public address stays relayed.
- **Not implemented**: immutable records, general Protomux (only the blind-relay channel), IPv6, reusable sockets, unordered UDX messages.
- **The device is never a DHT routing node**: it is always an ephemeral, firewalled node, by design.
- **ESP32-C3 only** for now. Other ESP32 variants should work but are untested.
- **Power**: a server keeps WiFi on and pings its relay nodes every 3 s. Battery devices fit the client role, or BLE.
- **Throughput** is CPU bound at a few hundred KiB/s on a LAN, which is fine for control and telemetry and not meant for bulk transfer.

## Contributing

Issues and pull requests are welcome, especially:
- running public relay nodes ([docs/relay-node.md](docs/relay-node.md)) and anchor nodes ([docs/anchor-node.md](docs/anchor-node.md)); [`deploy/`](deploy) has Docker and systemd files
- other ESP32 targets
- smaller and faster crypto paths (an IRAM BLAKE2b, fixed-point BBR)
- a phone app over BLE

Please run `test_vectors` and the desktop interop tests before sending protocol changes. If a change touches wire formats, regenerate the vectors with `tools/host/gen-vectors.js`.

## Acknowledgements and license

Built on the work of [Holepunch](https://holepunch.to): the protocols implemented here are theirs, and [libudx](https://github.com/holepunchto/libudx) is used as is (Apache-2.0, see [NOTICE](NOTICE)). Cryptography by [libsodium](https://libsodium.org) (ISC).

hyperdht-esp32 is released under the [MIT License](LICENSE). Copyright (c) 2026 Leo Lin.
