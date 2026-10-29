# BoAT MER over HyperDHT

A proof of concept that combines [BoAT MER](https://github.com/TLAY-IO/boat-mer) with hyperdht-esp32 on one ESP32-C3. BoAT MER (Machine Economy Runtime) is an Apache-2.0 C runtime that handles device identity, signed machine data and EIP-3009 nanopayments. hyperdht-esp32 makes the device reachable by public key from anywhere.

The firmware does five things:

1. **One identity.** MER generates and keeps the device keys. Its Ed25519 key pair is used unchanged as the HyperDHT key pair, for listening and for outgoing connections. So the device's DID, `did:mw:<ed25519 public key>`, is also its HyperDHT address.
2. **Reachable by DID.** Anyone who knows the DID can connect to the device, through NATs and end to end encrypted. The Noise handshake proves the device holds the DID's key. The device answers with a reading attested by MER (SHA-256 + Ed25519) and ends the stream.
3. **A DID record without a registry.** The device publishes a small record that binds its DID to its wallet as a HyperDHT mutable record, stored under its own key. Anyone can look it up by DID and check it without trusting the nodes that store it.
4. **Anchoring without a central server.** Signed readings go to several open anchor nodes that anyone can run, instead of one HashAnchor server. See [Distributed anchoring](#distributed-anchoring).
5. **Nanopayments across the internet.** MER's buyer engine is written against a small transport vtable, and normally runs over BLE GATT to a seller a few metres away. Here it runs over a HyperDHT stream. The board reads the remote seller's power, opens a paying stream, validates every slice and signs an EIP-3009 authorization for each one on the device. It pays only the wallet named in the seller's DID record.

Nothing is settled on-chain. The seller (`tools/host/mer-seller.js`) verifies each authorization the way a settlement service would, and the amounts are synthetic.

## DID record

MER's own registration (`boat_identity_register`) posts the device's public key and wallet address to a relay, authenticated by an API key, and the relay is the only place that knows the mapping. Here each party publishes its own record instead:

```json
{"v":1,"did":"did:mw:<ed25519 public key>","eth":"0x<wallet>","eth_sig":"0x<65 bytes>"}
```

- It is stored with `hdht_mutable_put` under the DID's Ed25519 key, so the DHT nodes only accept it, and readers only return it, if the DID key signed it. That proves the DID claims the wallet.
- `eth_sig` is an EIP-191 `personal_sign` of the DID string by the wallet's secp256k1 key. That proves the wallet claims the DID, so nobody can publish someone else's wallet as their own.
- Checking a record needs the DID and nothing else: look it up by key, check `did`, recover the `eth_sig` signer and compare it with `eth`.
- MER signs deterministically (RFC 6979), so the board builds the same 283 bytes on every boot. At boot it reads its current record: if the bytes match, it republishes the same `seq`, otherwise it publishes `seq + 1`. It republishes every 30 minutes, because nodes drop records after 48 hours. Anyone holding the record can republish it, but nobody can change it.

How the two sides use it:

| Who | Checks |
|---|---|
| Board (buyer) | Before each connection, reads the seller's record. It does not connect if the record is missing or invalid. Every `0xEE03` slice whose `to_address` is not the record's wallet is dropped before MER's engine sees it, and the board disconnects without signing |
| Seller | Reads the buyer's record when the buyer connects. It accepts a payment only if its EIP-712 signer is the wallet in the buyer's DID record |
| `mer-dial.js` | Resolves the record before dialing and checks that the wallet in the attested reading matches it |

The record does not say who made the device. Admission, such as a manufacturer's signed credential in the record and a revocation list, is not part of this example.

## Wire

Each HyperDHT message carries one GATT operation of MER's `0xEE00` protocol, with the characteristic values unchanged:

```
op (1 byte) | characteristic uuid16 (little-endian) | value
```

| op | Direction | Meaning |
|---|---|---|
| 1 | buyer → seller | write (`0xEE01` open/close, `0xEE04` signed proof) |
| 2 | buyer → seller | read (`0xEE05` status: liveness and power) |
| 3 | seller → buyer | read result: status byte, then the value |
| 4 | seller → buyer | notify (`0xEE02` offer, `0xEE03` slice request) |

Because the stream is authenticated by key, the buyer knows which seller it is paying before it signs anything. Over plain BLE, any device can advertise as a seller.

## Running it

MER is fetched at build time from its `v1.0.1` tag (`main/idf_component.yml`) and built with `BOAT_PROFILE=buyer`.

1. Start the seller on the Mac. It listens on the public HyperDHT with a fixed test key and prints that key as a DID:

   ```bash
   cd tools/host && npm install && node mer-seller.js public 170
   ```

2. Set `CONFIG_MER_SELLER_KEY` to the seller's key (the hex after `did:mw:`), then build and flash. `sdkconfig.wifi` at the repo root supplies the WiFi credentials, as for the other examples:

   ```bash
   cd examples/boat_mer && idf.py set-target esp32c3 && idf.py menuconfig && idf.py build flash monitor
   ```

   The board prints `MER|identity did=did:mw:...` on boot.

3. Resolve the board's DID record and connect to it by its DID:

   ```bash
   node tools/host/mer-dial.js did:mw:<hex> public 3
   ```

4. Optionally, restart the seller with `--wrong-payee`. It still publishes its real wallet in its record but bills a different one, and the board refuses to sign.

The seller simulates 12 W for 40 s, then 0 W for 20 s. The buyer opens a paying stream once the output reaches 5 W and closes it after 3 s below 3 W.

## Results (2026-10-29, ESP32-C3 on the public HyperDHT)

The board and the seller were on the same LAN, so they connected over the LAN shortcut. Two runs:

| | Result |
|---|---|
| Key check | MER's Ed25519 key pair and the HyperDHT key pair derived from MER's seed are byte-identical (`same_keypair=yes`) |
| Payments | 53 of 53 authorizations verified by the seller over two runs (32 + 21), 0 rejected. The recovered signer is always the board's EVM address |
| Buyer identity | With `hdht_opts_t.seed` set to MER's seed, the seller sees the board's own DID as the connecting buyer |
| Power self-drive | 6 complete sessions, each opened at power-on and closed after power-off, slice ids restarting per session. A seventh was cut off when the seller exited |
| DID dial | 3 of 3. Each round checked that the Noise peer is the DID, the hash matches the payload, and the Ed25519 signature is valid. ~1.0–1.7 s to open |
| Slice round trip | 566–592 ms on average from slice request to verified proof, nearly all of it signing |
| secp256k1 EIP-712 signature (micro-ecc) | 395–651 ms, 467–534 ms on average |
| Ed25519 attestation (TweetNaCl) | ~481 ms. libsodium does the same signature in ~15 ms on this chip |
| Free heap | ~152 KB steady; lowest 80.2 KB, during bootstrap |
| Loop task stack | 14.4 KB of 20 KB used at peak |
| Static RAM (DRAM) | 158.8 KB, 35.3 KB more than `examples/minimal`. Most of the difference is MER's 33 KB buyer context (its replay-guard set) |
| Image | 1.09 MB, 28 KB more than `examples/minimal` |

## Results: DID records (2026-10-29, same board, public HyperDHT)

Three runs: a normal one, a dial from the Mac, and one against a seller billing the wrong wallet.

| | Result |
|---|---|
| Publishing | The board's record (283 bytes) was stored on 20 of 20 nodes each boot. Lookup of its own record 3.2–6.7 s, lookup plus put 8.8–11.5 s. A stale `seq` 1 was replaced by `seq` 2, and the next boot republished `seq` 2 unchanged |
| Building the record | One secp256k1 signature at boot, 392–394 ms |
| Seller record on the board | Found and valid before every connection. Lookup 3.3–4.8 s, verification (ecrecover) 257–259 ms |
| Payments | 24 of 24 verified, 0 rejected, 93 µUSDC over 3 sessions. The seller found the buyer's record in 1.8–2.5 s, and every signer matched the wallet in it. Slice round trip 662 ms on average |
| Wrong payee | 4 of 4 sessions refused at the first slice: the board logged the mismatch, disconnected and signed nothing. The seller received 0 proofs |
| DID dial | Record resolved from the Mac in 2.9 s and valid. 3 of 3 dials passed, and the wallet in each attested reading matched the record |
| Interop | C put → Node `mutableGet`, Node `mutablePut` → C get, `SEQ_TOO_LOW`, `SEQ_REUSED`, same-value republish and a 1000-byte value, on a private testnet and on the public network |
| Free heap | ~147 KB steady; lowest 104 KB |
| Loop task stack | 14.4 KB of 20 KB at peak, unchanged |
| Image | 1.09 MB, 7.6 KB more than without DID records |

## Distributed anchoring

[HashAnchor](https://github.com/TLAY-IO/hashanchor) batches data hashes into Merkle trees, anchors each root on a chain and hands out receipts that anyone can verify offline. A receipt's validity does not depend on who built the tree or who anchored the root, so that role does not have to be one company's server. This proof of concept splits it into open nodes:

| Piece | What it does |
|---|---|
| [`tools/host/contracts/OpenAnchor.sol`](../../tools/host/contracts/OpenAnchor.sol) | Anyone can anchor a root; the first anchor is kept with who did it and when. No operator role and no upgrade path |
| [`tools/host/anchor-node.js`](../../tools/host/anchor-node.js) | An anchor node. Devices reach it over HyperDHT by its key. It checks each submission, batches every 20 s into a tree that HashAnchor's public verifier accepts (keccak256, sorted pairs), anchors from its own wallet, appends the batch to a Hypercore anyone can replicate, and sends receipts back. It publishes a DID record with its wallet, fee, contract and log key |
| [`main/anchor.c`](main/anchor.c) | The device side: reads each node's DID record, attests a reading every 30 s (MER: SHA-256 + Ed25519), sends it to every node with an EIP-3009 payment of the node's fee, checks each receipt's Merkle proof, and flags receipts that do not arrive |
| [`tools/host/anchor-verify.js`](../../tools/host/anchor-verify.js) | An independent verifier. From two DIDs only, it replicates the node's batch log, rebuilds every receipt for the device, checks it with HashAnchor's own `verifyReceiptProof`, and reads the contract |

What changes compared with the hosted service:

- **No API key.** The HyperDHT stream authenticates the device's DID, and a payment signed by the wallet in the device's DID record pays for each submission.
- **The leaf binds the device.** A leaf is `keccak256(data hash || device public key || Ed25519 signature)`, not the bare hash, so a receipt proves which device signed the data. The verifier recomputes the leaf from its parts.
- **Several nodes per reading.** The device sends each reading to every node, so one node that drops it cannot censor it. Identical single-leaf batches on two nodes give the same root, which the second node reuses instead of anchoring again.
- **Receipts can be rebuilt without the node.** Every batch, with all its leaves, is in the node's Hypercore. Anyone who replicates it can serve or rebuild receipts after the node is gone.
- **The device checks what it can.** It recomputes the leaf and walks the proof to the root, but it has no chain access, so it cannot see the anchor itself. The verifier, or any phone or server, does that.

### Running it

1. Start a local chain and deploy the contract (needs [Foundry](https://getfoundry.sh)):

   ```bash
   anvil
   ```

   ```bash
   cd tools/host && node anchor-deploy.js
   ```

2. Start nodes, each in its own terminal, with the printed contract address. Index 1–3 selects the node's key and an anvil dev wallet. `--drop` makes a node that accepts and never anchors:

   ```bash
   node anchor-node.js public 1 <contract>
   ```

3. Set `CONFIG_MER_ANCHOR_NODES` to the nodes' keys (the hex after `did:mw:` in each node's first line), comma-separated, then build and flash. `CONFIG_MER_SELLER_KEY` can stay empty.

4. Verify a node's work for the board:

   ```bash
   node anchor-verify.js public did:mw:<node> did:mw:<board>
   ```

### Results (2026-10-29, same board, public HyperDHT, local anvil chain)

Three nodes: two honest, one started with `--drop`. The board ran for 4 minutes.

| | Result |
|---|---|
| Node discovery | All 3 node records found and valid; each node's quote named the wallet in its record |
| Submissions | 8 readings, each to all 3 nodes: 24 submissions, 24 payments signed on the device (394–659 ms each), 0 rejected |
| Honest nodes | 8 of 8 receipts from each, every Merkle proof valid on the device. Node 2's 8 batches had the same roots as node 1's and reused node 1's transactions, so node 2 paid no gas |
| Censoring node | Accepted all 8 and anchored none. The board flagged each receipt overdue after 120 s (4 within the run); the same readings were anchored through the other two nodes |
| Submit to receipt | 2.7–20.8 s, median 9.3 s, with a 20 s batch interval |
| Independent verification | Node 1: 9 of 9 leaves pass, node 2: 10 of 10 (the board kept submitting after the capture). Each: device signature, leaf, tree root, HashAnchor `verifyReceiptProof`, root on chain, anchorer as logged. Replicating each log took ~10 s |
| Restart | Nodes restarted on their stored logs kept the same log key, and the logs replicated from them afterwards |
| Wrong payer (JS test device) | A payment signed by a wallet other than the one in the device's DID record was rejected |
| Free heap | ~141 KB steady; lowest 59 KB, with three node connections open |
| Loop task stack | 12.5 KB of 20 KB at peak |
| Image | 4 KB more than without anchoring |

A first run found two node bugs, both fixed before these results: the second node to build an identical root failed with "already anchored" and lost the batch, and a failed transaction left the node's nonce manager stuck so it never anchored again.

What this does not cover yet:

- **Settlement.** Payments are verified, not settled.
- **A real chain and real gas economics.** With many nodes, batches get smaller and gas per hash rises. A shared root of roots, or a cheap chain, would offset that.
- **Discovery.** Nodes are configured by key. Open discovery needs Hyperswarm topics on the device, which hdht does not have yet.
- **Mirrors.** Only the node itself serves its log. Independent mirrors that keep replicating are needed so receipts outlive nodes.
- **Node-signed receipts.** HashAnchor receipts have an optional `signature` field; here the authenticated stream stands in for it, which helps only the device.

## Integration notes

- **Duplicate `randombytes`.** MER defines a global `randombytes()` to feed TweetNaCl, and libsodium defines one too, so linking both fails with `multiple definition of 'randombytes'`. `CMakeLists.txt` renames MER's copy inside its own component (`randombytes=boat_mer_randombytes`) without changing MER's sources. A weak symbol upstream, or building MER's Ed25519 on libsodium, would remove the need for this.
- **Signing blocks the loop.** MER signs on the hdht task, which is single-threaded, so each signature pauses networking for 0.4–0.65 s. That is fine at one slice every 5 s. For faster slices, sign on another task and hand the result back with `uv_async_send`. Switching MER's Ed25519 to libsodium would bring attestations from ~480 ms to ~15 ms.
- **Memory.** The buyer context is 33 KB of static RAM at MER's default `BOAT_BUYER_NONCE_CAP` of 4096. MER allows a smaller cap, which has to be defined globally. Adding BLE on top (see `examples/hyperdht_demo`'s coexistence numbers) would leave little headroom on a C3.
- **Key reuse.** One Ed25519 key now serves Noise (as a DH key), HyperDHT announce signatures and MER attestations. HyperDHT already uses one key for both DH and signing. MER attestations sign a 32-byte SHA-256 digest, while HyperDHT signs a namespaced 64-byte message, so neither signature can stand in for the other. Products that want strict separation can derive two keys from one seed and have the DID key sign the HyperDHT key.
- **Payee binding.** MER's buyer engine trusts the `to_address` in each slice request. This example checks it outside the engine, against the seller's DID record, before passing the slice on. A hook in the engine, or an expected-payee field in `boat_buyer_config_t`, would be cleaner.
- **Lookups take seconds.** Reading a record costs a DHT query of 2–5 s, on top of the connection. A buyer that pays the same seller often can cache the payee and look it up again in the background.
