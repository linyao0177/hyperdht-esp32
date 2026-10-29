# Architecture

English | [中文](architecture.zh-CN.md)

hyperdht-esp32 turns an ESP32-C3 module into a peer on the Holepunch network. A device that integrates the module gets the base layer of a distributed application with no backend of its own:

- an **identity** it creates and holds itself;
- an **address** derived from that identity, reachable from anywhere through NATs;
- **end-to-end encrypted channels** to any peer that knows its key, over the internet or over BLE;
- **records** it can publish under its key and that anyone can verify, such as a DID document.

This document describes how those pieces fit together, what each one guarantees, and how a product builds on them. The byte-level protocol is in [`protocol.md`](protocol.md); the API is in [`components/hdht/README.md`](../components/hdht/README.md).

## Contents

- [Principles](#principles)
- [Layers](#layers)
- [Primitives](#primitives)
- [Identity](#identity)
- [Flows](#flows)
- [Trust model](#trust-model)
- [What runs where](#what-runs-where)
- [Building a product on it](#building-a-product-on-it)
- [Reference integration: BoAT MER](#reference-integration-boat-mer)
- [Footprint](#footprint)
- [Gaps and roadmap](#gaps-and-roadmap)

## Principles

1. **The key is the identity, and the identity is the address.** A device is reached by its Ed25519 public key, not by an IP address, a hostname or a cloud account. Nothing has to be registered for that to work.
2. **No server of your own on the data path.** The device finds peers through the public HyperDHT and then talks to them directly. DHT nodes help peers find each other and relay the handshake, but never see the content.
3. **Encrypted and authenticated end to end.** Every channel runs a Noise handshake that proves both public keys. A device knows exactly which key it is talking to, and so does the peer.
4. **Self-certifying data.** A record published under a key is signed by that key. Readers check it themselves and do not have to trust the nodes that store it or the party that served it.
5. **Wire compatible with the reference.** The C implementation speaks the hyperdht 6.x protocol byte for byte, so the other end can be an unmodified Node.js `hyperdht` app.
6. **The device is a light client.** It joins the DHT as an ephemeral, firewalled node: it uses the network but does not route for others, which keeps memory, power and traffic low.
7. **Same identity, online or offline.** The same key opens the same kind of encrypted channel over BLE when there is no internet.

## Layers

```
 ┌──────────────────────────────────────────────────────────────────────────────────┐
 │ Product application                                                                │
 │   telemetry, control, configuration, payments (e.g. BoAT MER 0xEE00), ...          │
 ├──────────────────────────────────────────────────────────────────────────────────┤
 │ Application protocol (yours): message framing on top of an encrypted stream        │
 ├────────────────────────────┬───────────────────────────┬─────────────────────────┤
 │ Identity                    │ Reachability & channels   │ Records                  │
 │  Ed25519 key pair in NVS    │  hdht_listen (server)     │  hdht_mutable_put / get  │
 │  DID = did:mw:<public key>  │  hdht_connect (client)    │  e.g. the DID record     │
 │                             │  hdht_ble (local)         │                          │
 ├────────────────────────────┴───────────────────────────┴─────────────────────────┤
 │ hdht core (components/hdht)                                                        │
 │  dht-rpc queries · announce · relayed Noise IK/XX · holepunching · SecretStream    │
 ├──────────────────────────────────────────────┬───────────────────────────────────┤
 │ libudx: reliable UDP streams with BBR         │ NimBLE GATT (components/hdht_ble)  │
 │ uv_esp: libuv subset on lwIP                  │                                    │
 ├──────────────────────────────────────────────┴───────────────────────────────────┤
 │ ESP-IDF · FreeRTOS · WiFi · BLE · libsodium · NVS                                  │
 └──────────────────────────────────────────────────────────────────────────────────┘
```

Everything from `uv_esp` up runs on **one event-loop task**. Other tasks hand work to it with `uv_async_send`.

How it maps to the Holepunch stack:

| Layer | Holepunch (JS) | On the module |
|---|---|---|
| Apps, storage | Pear, Hypercore, Autobase | Out of scope on the device; peers can run them |
| Discovery by topic | Hyperswarm | Lookup: the device finds peers announced under a topic (`hdht_lookup`). It does not announce itself under one; peers dial it by key |
| Peer connections | hyperdht | `components/hdht` (C) |
| Records | hyperdht `mutablePut` / `mutableGet` | `hdht_mutable_put` / `hdht_mutable_get` |
| DHT RPC | dht-rpc | `components/hdht` (C) |
| Encryption | Noise, SecretStream | `components/hdht` on libsodium |
| Transport | libudx, libuv | libudx (vendored), `uv_esp` |

## Primitives

These are the building blocks a product gets. Each is usable on its own.

| Primitive | API | What it gives you | Status |
|---|---|---|---|
| Key pair | `hdht_keypair(pk, sk, seed)` | An Ed25519 identity from a 32-byte seed kept in NVS | Done |
| Listen | `hdht_listen(key pair, ...)` | The device is reachable by its public key from anywhere. Re-announces every ~5 min and keeps relay paths alive | Done |
| Connect | `hdht_connect(public key, ...)` | An encrypted stream to any HyperDHT server by key: direct, over the LAN, or holepunched | Done |
| Stream | `hdht_stream_write / end / destroy` | Ordered, reliable, encrypted messages, wire compatible with `@hyperswarm/secret-stream` | Done |
| Records | `hdht_mutable_put / get` | A signed value of up to 1000 bytes stored on the ~20 DHT nodes closest to the key; anyone can read and verify it | Done |
| Local channel | `components/hdht_ble`, `secret_stream.h` | The same SecretStream over BLE GATT (or any byte stream), keyed by the same identity | Done |
| Topic lookup | `hdht_lookup` | Finding peers announced under a topic, such as Hyperswarm servers; the replies are hints, authenticated by connecting | Done |
| Topic announce | Hyperswarm | Being found by topic instead of by key | Not yet |
| Relay fallback | blind-relay | Connections that cannot be holepunched | Not yet |

## Identity

One Ed25519 key pair is the device's identity:

- **Created on the device** on first boot from a random seed, and stored in NVS (use NVS encryption in production). It never leaves the device.
- **Public key = address.** Peers connect to `BLAKE2b(public key)` on the DHT; `hdht_listen` announces exactly that.
- **Public key = DID.** As in BoAT MER, `did:mw:<hex public key>` names the same key, so a DID can be dialed directly. No resolver is needed to go from a DID to a key, because the DID is the key.
- **Authenticated on every connection.** The Noise handshake proves the server holds the key it was dialed by, and gives the server the client's key (`stream->remote_public_key`). Set `hdht_opts_t.seed` so outgoing connections use the device's identity too.

**Other keys hang off this one through records.** A product often has keys for other systems, such as a secp256k1 wallet for payments. The device publishes a record, signed by its identity key, that names them, and each other key signs the DID back. The [DID record](#the-did-record) below does this for a wallet.

**Key reuse.** The identity key does Noise DH, DHT announce signatures and record signatures. All of these are domain separated: each signs a 32-byte namespace plus a hash, so a signature for one purpose cannot be replayed for another. A product that wants strict separation can derive several keys from one seed and link them with a record.

**Rotation** is not built in: a new key is a new address and a new DID. The old key can publish a record pointing to the new one; a fuller scheme with controller keys is listed under [gaps](#gaps-and-roadmap).

### The DID record

[`examples/boat_mer`](../examples/boat_mer) defines a small DID document that works without a registry:

```json
{"v":1,"did":"did:mw:<ed25519 public key>","eth":"0x<wallet>","eth_sig":"0x<EIP-191 signature of the did>"}
```

- It is stored with `hdht_mutable_put` under the DID key, so DHT nodes only accept it, and readers only return it, if the DID key signed it. The DID claims the wallet.
- `eth_sig` is the wallet's signature of the DID. The wallet claims the DID back, so nobody can claim someone else's wallet.
- Anyone who knows the DID can look the record up and check both signatures, with no other input.
- Nodes keep records for up to 48 hours. The device republishes every 30 minutes. Because the record is signed, anyone else can republish it too, but nobody can change it.
- A higher `seq` replaces a lower one. A deterministic record (MER signs with RFC 6979) can be republished at the same `seq` after every boot.

The same pattern carries other claims: firmware version, capabilities, service endpoints, a manufacturer credential.

## Flows

### A peer reaches the device

```
 device                         HyperDHT nodes                         peer (Node / Pear / phone)
   │ ANNOUNCE BLAKE2b(pk)  ─────────▶ │                                       │
   │                                  │ ◀──────────── FIND_PEER BLAKE2b(pk)    │
   │ ◀────── relayed Noise IK handshake (both keys proven) ──────────────────▶ │
   │ ◀────── relayed holepunch messages: addresses, NAT type ────────────────▶ │
   │ ◀════════════ direct UDP (libudx) + SecretStream, end to end ══════════▶ │
```

1. `hdht_listen` announces the device to the 3 closest nodes and pings them every 3 s, so they can relay to it.
2. The peer looks up the key, and the nodes relay a Noise IK handshake. After it, both sides have proven their keys.
3. Both sides exchange their addresses and NAT types inside encrypted, relayed messages, then punch UDP towards each other. On the same LAN they connect directly.
4. The stream runs directly between the two. The DHT nodes are no longer involved.

### The device reaches a peer

The same flow in the other direction: `hdht_connect(public key)` looks the peer up, runs the handshake as the initiator, and holepunches. This is how the device calls a service, another device, or a seller.

### Publishing and resolving a record

```
 device: hdht_mutable_put(pk, sk, seq, value)    any reader: mutableGet(pk) / hdht_mutable_get(pk)
   │ MUTABLE_GET query towards BLAKE2b(pk), collect tokens        │
   │ MUTABLE_PUT {pk, seq, value, signature} to ~20 nodes ──▶ nodes ◀── MUTABLE_GET ── │
   │                                                              │ verify signature, keep highest seq
```

A lookup costs one DHT query, typically 2–7 s on the public network. Callers that need the answer often should cache it and refresh it in the background.

### Local, without internet

A phone or laptop next to the device connects over BLE and runs the same SecretStream handshake against the same key. The device advertises the first bytes of its DHT target, so the client can check it found the right device before connecting. The product's application protocol can be identical over both transports, as MER's 0xEE00 protocol is in the reference integration.

## Trust model

What each party can rely on, and why:

| Claim | Established by | Trusts |
|---|---|---|
| "I am talking to the holder of key K" | Noise IK/XX handshake | Only the key |
| "Nobody on the path can read or change the stream" | SecretStream (XChaCha20-Poly1305) keyed by the handshake | Only the keys |
| "This record was published by K" | Ed25519 signature checked by the reader | Only the key |
| "This is K's latest record" | Highest `seq` among the nodes asked | The DHT returning it; a node can withhold a record but not forge one |
| "K's wallet is W" | DID record signed by K, plus W's signature of K's DID | Only the two keys |
| "K is a genuine product of manufacturer M" | Not yet: a credential signed by M, in the record | M's public key |
| "K is reachable" | Announce on the DHT | The DHT nodes to relay the handshake honestly enough to connect; they cannot impersonate K |

What the DHT can do to you: refuse to store or return records, or fail to relay a handshake. That is denial of service. It cannot impersonate a key, read a stream or forge a record.

What the DHT does not give you: admission control. Any key can join, announce and publish. "Is this a real device of ours?" has to be answered by a credential from an issuer you trust, which a record can carry.

## What runs where

| Component | Who runs it | Needed? |
|---|---|---|
| The device firmware | You, on the module | Yes |
| HyperDHT bootstrap and routing nodes | Public nodes (Holepunch runs the bootstrap nodes); anyone can add more | Yes, but not yours. A private network can run its own with `hyperdht` and point devices at it (`hdht_opts_t.bootstrap`) |
| Peers that talk to devices | Your apps: Node.js, Pear, desktop, phone | Your product |
| Record republishers and indexers | Optional: any process holding the signed records | Only to keep records alive for offline devices, or to list devices (the DHT is lookup by key, not a search index) |
| Settlement, issuer, revocation list | Optional: a chain or an append-only log | Only for payments and admission |

There is no central server on the data path. Optional services sit beside it and are untrusted for content: a republisher cannot change a record, and an indexer can only point to records that readers verify themselves.

## Building a product on it

A product whose own MCU runs the application can keep its firmware and drive the C3 as a module over a serial line instead: [`examples/uart_module`](../examples/uart_module), commands in [`module-uart.md`](module-uart.md).

[`examples/app_template`](../examples/app_template) puts the steps below together: identity, record, claim, grants, revocation and signed readings that any peer can keep. Copy it and replace `app.c`.

**1. Hardware budget.** An ESP32-C3 with 4 MB flash. WiFi plus hdht is ~1.06 MB of firmware, +0.22 MB with BLE. Plan for one 20 KB task and ~25 KB of heap per active connection.

**2. Identity at first boot.** Generate a seed, store it in encrypted NVS, derive the key pair. Print or label the public key (or DID) at manufacturing if users need to pair with it. Publish a record describing the device.

**3. Pick roles.**
- *Server* (always reachable): `hdht_listen`. Keeps WiFi on and pings relays every 3 s. Fits mains-powered devices.
- *Client* (calls out): `hdht_connect`. Can sleep between sessions. Fits battery devices.
- *Local*: `hdht_ble` for setup, offline control, or phone pairing.

**4. Define your application protocol** as messages on the stream. Keep it transport-neutral so the same code runs over HyperDHT and BLE. The reference integration uses `op | id | value` frames, one per message.

**5. Decide who may connect.** The stream tells you the peer's key. Check it against an allow list, a record, or a credential before acting on commands. The DHT does not do this for you.

**6. Keep the loop responsive.** All hdht work runs on one task. Slow work, such as a 0.5 s secp256k1 signature, blocks networking while it runs. Move it to another task and hand back the result with `uv_async_send` when it happens often.

**7. Configuration.** `CONFIG_FREERTOS_HZ=1000`, `CONFIG_LWIP_UDP_RECVMBOX_SIZE=32`, a large app partition. Details in [`components/hdht/README.md`](../components/hdht/README.md#esp-idf-requirements).

## Reference integration: BoAT MER

[`examples/boat_mer`](../examples/boat_mer) combines the module with [BoAT MER](https://github.com/TLAY-IO/boat-mer), a C runtime for device identity, signed data and EIP-3009 nanopayments. It exercises every primitive:

| Primitive | Use |
|---|---|
| Identity | MER's Ed25519 key is the HyperDHT key, so the device's DID is its network address |
| Listen | Anyone can dial the device by DID and get a reading attested by MER |
| Connect | The device, as a buyer, connects to a remote seller by its key |
| Stream | MER's BLE payment protocol (0xEE00) runs unchanged over the HyperDHT stream |
| Records | Buyer and seller each publish a DID record binding their wallet. The buyer pays only the wallet in the seller's record; the seller accepts only payments signed by the wallet in the buyer's record |
| Anchoring | Signed readings go to several open anchor nodes, found by topic lookup, instead of one HashAnchor server ([operator guide](anchor-node.md)). Each node batches, anchors on a permissionless contract and keeps a replicable log; receipts stay compatible with HashAnchor's verifier |

Measured on the public HyperDHT: 53 + 24 payment authorizations verified with none rejected, a seller billing the wrong wallet refused 4 of 4 times, records stored on 20 of 20 nodes. Details in its [README](../examples/boat_mer/README.md).

## Footprint

ESP32-C3 at 160 MHz, from [`examples/hyperdht_demo`](../examples/hyperdht_demo/README.md) and [`examples/boat_mer`](../examples/boat_mer/README.md):

| | Value |
|---|---|
| Firmware, WiFi + libsodium + hdht | ~1.06 MB; +0.22 MB with BLE |
| Heap per connection, peak | ~25 KB |
| Free heap, WiFi + DHT, during a connection | ~165 KB |
| Free heap, WiFi + DHT + BLE, all busy | ~50 KB |
| Loop task stack | 12.5–14.4 KB used; 20 KB recommended |
| Bootstrap on the public DHT | ~3 s |
| Connect by key on a LAN | ~0.5 s |
| Connect across a home router and a carrier NAT | 9–32 s |
| Record publish / lookup, public DHT | ~6–11 s / 2–7 s |
| Noise handshake | ~0.2 s per side (software crypto) |
| Throughput on a LAN | 313–365 KiB/s, CPU bound |

## Gaps and roadmap

Known limits today, roughly in order of impact for products:

| Gap | Effect | Direction |
|---|---|---|
| No relay fallback | Peer pairs that cannot holepunch cannot connect | Implement blind-relay (`relayThrough`) |
| Random NAT on the device side | Holepunching fails; hyperdht's 256-socket approach does not fit a C3 | Relay fallback covers it |
| No topic announce from the device | Peers must already know the device's key (the device can look topics up) | Announce under a topic hash, as hyperdht's announcer |
| No admission | Any key can claim to be a device | Manufacturer credentials in the DID record, with a revocation list on a chain or an append-only log |
| No key rotation | A new key is a new DID | A signed "moved to" record, or controller keys in the DID record |
| No listing | The DHT looks up by key only | An indexer over records, e.g. a Hypercore/Hyperbee log written by the issuer |
| Untested with Pear/Hyperswarm apps | Expected to work through `swarm.joinPeer(publicKey)`, which uses the same connect path | Test and document |
| Server power | Relay pings every 3 s keep WiFi on | Client role for battery devices, or longer intervals with slower failover |
| ESP32-C3 only | Other chips untested | Port to other ESP32 variants |
| No Protomux, IPv6, immutable records | Fewer protocol features than hyperdht | Add as products need them |
