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
| [`tools/host/anchor-node.js`](../../tools/host/anchor-node.js) | An anchor node ([operator guide](../../docs/anchor-node.md)). It announces itself under the deployment's topic and devices reach it over HyperDHT by its key. It checks each submission, batches every 20 s into a tree that HashAnchor's public verifier accepts (keccak256, sorted pairs), anchors from its own wallet, appends the batch to a Hypercore anyone can replicate, and sends receipts back. It publishes a DID record with its wallet, fee, contract and log key |
| [`main/anchor.c`](main/anchor.c) | The device side: finds nodes by looking up the deployment's topic, reads each node's DID record, attests a reading every 30 s (MER: SHA-256 + Ed25519), sends it to every node with an EIP-3009 payment of the node's fee, checks each receipt's Merkle proof, and flags receipts that do not arrive |
| [`tools/host/anchor-discover.js`](../../tools/host/anchor-discover.js) | Lists a deployment's nodes and checks their records, as the device does |
| [`tools/host/anchor-verify.js`](../../tools/host/anchor-verify.js) | An independent verifier. From two DIDs only, it replicates the node's batch log, rebuilds every receipt for the device, checks it with HashAnchor's own `verifyReceiptProof`, and reads the contract |

What changes compared with the hosted service:

- **No API key.** The HyperDHT stream authenticates the device's DID, and a payment signed by the wallet in the device's DID record pays for each submission.
- **The leaf binds the device.** A leaf is `keccak256(data hash || device public key || Ed25519 signature)`, not the bare hash, so a receipt proves which device signed the data. The verifier recomputes the leaf from its parts.
- **Several nodes per reading.** The device sends each reading to every node, so one node that drops it cannot censor it. Identical single-leaf batches on two nodes give the same root, which the second node reuses instead of anchoring again.
- **Receipts can be rebuilt without the node.** Every batch, with all its leaves, is in the node's Hypercore. Anyone who replicates it can serve or rebuild receipts after the node is gone.
- **The device checks what it can.** It recomputes the leaf and walks the proof to the root, but it has no chain access, so it cannot see the anchor itself. The verifier, or any phone or server, does that.

### Running it

On the public testnet, set `CONFIG_MER_ANCHOR_CONTRACT` to the Arc testnet contract in [docs/anchor-node.md](../../docs/anchor-node.md#the-network). Leave `CONFIG_MER_ANCHOR_CHAIN_ID` at 5042002 and `CONFIG_MER_SELLER_KEY` empty. Then build and flash. The board finds whatever nodes are running. To run nodes of your own, follow the operator guide.

On a local chain (needs [Foundry](https://getfoundry.sh)):

1. Start a chain and deploy the contract:

   ```bash
   anvil
   ```

   ```bash
   cd tools/host && node anchor-deploy.js
   ```

2. Start nodes, each in its own terminal. `--dev 1`–`3` selects an anvil dev wallet and a fixed identity. `--drop` makes a node that accepts and never anchors:

   ```bash
   node anchor-node.js public --dev 1
   ```

3. Set `CONFIG_MER_ANCHOR_CONTRACT` to the printed contract address and `CONFIG_MER_ANCHOR_CHAIN_ID` to 31337, then build and flash. `CONFIG_MER_ANCHOR_NODES` can add fixed node keys alongside discovery.

4. List the nodes, or verify a node's work for the board:

   ```bash
   node anchor-discover.js public --network local
   ```

   ```bash
   node anchor-verify.js public did:mw:<node> did:mw:<board> --network local
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

Discovery was added after this run; see the testnet results below.

### Results: public testnet (2026-10-29, same board, public HyperDHT, Arc testnet)

OpenAnchor is deployed at [`0xd7d651a6fecE5C9ed96796678ED995Fb12dAbeCA`](https://explorer.testnet.arc.io/address/0xd7d651a6fecE5C9ed96796678ED995Fb12dAbeCA) on Arc testnet (chain 5042002). Two nodes ran with their own identities and wallets ([operator guide](../../docs/anchor-node.md)). A third key announced itself on the topic without a DID record, standing in for a bogus node. The board was configured with the contract address only and no node keys. It ran across two boots, with about 25 minutes of output captured.

| | Result |
|---|---|
| Discovery | One lookup, about 5 s after the board's own record was published, found all 3 announced keys. Both real nodes' records were valid. The bogus key had no record, so the board dropped it and later lookups skipped it. `anchor-discover.js` found the same 3 keys, 2 of them valid, in 1.3–2.1 s |
| Receipts | 69 receipts on the board in the captured output, every Merkle proof valid, 0 rejected submissions |
| Submit to receipt | 8.5–29 s, median 18 s, in the last run, with 20 s batches and Arc block times |
| On chain | 66 roots anchored: 37 by node 1, 29 by node 2. When both nodes built the same single-leaf root, the second reused the first's transaction |
| Gas | about 47,000 gas per anchor, 0.0012 USDC on testnet, whatever the batch size. Deploying cost 0.0085 USDC |
| Independent verification | From the two DIDs only: node 1 54 of 54 leaves pass, node 2 38 of 38. Logs of 46 and 38 batches replicated in 13–18 s |
| Node restart | The board saw both streams close, re-read the records and reconnected within 10 s |
| Node stopped with work pending | It anchored the pending submission, delivered the receipt and closed the stream before exiting. The board dropped it after 3 failed reconnects. It had unannounced, so the next lookup no longer listed it |
| Free heap | ~141 KB steady, lowest 60 KB |
| Loop task stack | 13.3 KB of 20 KB at peak |
| Image | 0x10c8a0 bytes, 2 KB more than with fixed node keys |

The testnet runs found three problems in the nodes. All are fixed, and the last run above was clean:

- **Two nodes building the same root at the same moment.** One of them lost the race: its check showed the root missing, then its own transaction failed with "already anchored". The node put the batch back in its queue for a later round, which delayed its receipts. It now re-checks the chain after a failure and reuses the other node's transaction.
- **A node that stopped dropped what it had accepted.** Accepted submissions were held only in memory. It now anchors them before exiting.
- **A stopped node sent its last receipts too late.** The process exited before they left the socket. It now ends its streams and waits for them to close.

What this does not cover yet:

- **Settlement.** Payments are verified, not settled.
- **Gas at scale.** Each node pays one anchor per batch, whatever its size. With many nodes and few devices each, batches get small and gas per hash rises. A shared root of roots, or longer batches, would offset that.
- **Mirrors.** Only the node itself serves its log. To verify node 2 after it stopped, it had to be restarted. Independent mirrors that keep replicating are needed so receipts outlive nodes.
- **Node-signed receipts.** HashAnchor receipts have an optional `signature` field; here the authenticated stream stands in for it, which helps only the device.
- **Spam on the topic.** Lookup replies are unsigned, and anyone can announce under the topic. The board checks each key's record and keeps at most 3 nodes, so many bogus keys can delay discovery. Ranking nodes by record age or stake would help.

### Results: a node on a cloud VM (2026-10-31, same board)

One anchor node runs on a Google Cloud e2-small in Taiwan as a systemd service from [`deploy/`](../../deploy), with its own wallet. It was the only node on the topic. The board again had the contract address only.

| | Result |
|---|---|
| Discovery | The first lookup found the node; its record was valid, and the board connected to the VM's public address |
| Receipts | 5 of 5 in 3 minutes of output, every Merkle proof valid, 0 rejected, 0 overdue |
| Submit to receipt | 9.2–19.6 s with 20 s batches |
| Gas | 18 anchors cost 0.0198 USDC, about 0.0011 each |
| Independent verification | `anchor-verify.js` from the two DIDs only: 6 of 6 leaves pass (the board kept submitting), log replicated in 3.3 s |
| Free heap | ~140.5 KB steady |

## With a Pear app as the seller (2026-11-07)

[`apps/pear-seller`](../../apps/pear-seller) is a Pear app that plays `mer-seller.js`'s part, on Bare, with [`packages/boat-peer`](../../packages/boat-peer). Set `CONFIG_MER_SELLER_KEY` to the DID it prints. In 18 paying sessions the board signed 122 authorizations and the app accepted all 122, each kept in a Hypercore of receipts that an independent script replicated and checked again. Results are in its [README](../../apps/pear-seller/README.md#results-2026-11-07-esp32-c3-and-a-mac-public-hyperdht).

## Settled on-chain by a WDK account (2026-11-07)

By default the board signs its payments under Circle Gateway's batched domain. With `CONFIG_MER_BUYER_DOMAIN_NAME`, `_VERSION` and `_VERIFYING_CONTRACT` set to a token's own EIP-712 domain (USDC on the Arc testnet: `USDC`, `2`, `0x3600000000000000000000000000000000000000`), each authorization can be submitted straight to the token's `transferWithAuthorization`. Payments to anchor nodes keep the Gateway domain. `apps/pear-seller --settle` did that with a WDK account: 41 of 41 settled ([results](../../apps/pear-seller/README.md#results-settled-with-wdk-2026-11-07-arc-testnet)).

## The device as a signer for its owner's wallet (2026-11-07)

With `CONFIG_MER_OWNER_KEY` set to the owner's HyperDHT public key, a stream from that key to the device's DID carries signing requests instead of an attested reading ([`main/signer.c`](main/signer.c)). The device signs EIP-191 messages and EIP-3009 authorizations from its own address, up to `CONFIG_MER_SIGNER_MAX_VALUE` each; its secp256k1 key never leaves it. [`packages/wdk-protocol-boat-evm`](../../packages/wdk-protocol-boat-evm#the-device-as-a-wdk-signer) wraps this as a WDK signer, so the owner's WDK app holds a WDK account for the device: it read the device's balance, had it sign, and swept 0.05 USDC from it on the Arc testnet, 8 of 8 checks passed.

## The device pays an x402 API (2026-11-07)

With `CONFIG_MER_X402_URL` set, a task of its own ([`main/x402.c`](main/x402.c)) waits for the clock (SNTP, started at boot) and calls the URL every `CONFIG_MER_X402_INTERVAL_S` with MER's x402 client, paying at most `CONFIG_MER_X402_MAX` per call. Against [the WDK-facilitated x402 server](../../packages/wdk-protocol-boat-evm/examples/x402) on the Arc testnet, 4 of 4 calls were paid and settled, 10.4–15.0 s each. The image grows to 1.26 MB (14% of the app partition free) with the HTTP client.

MER v1.0.1 signs through a global EIP-712 domain, so two tasks signing at once can sign under each other's domain. [`patches/boat-mer`](../../patches/boat-mer) makes it sign under a per-call domain. With the patch (built with `override_path` to a patched checkout), the buyer, anchoring, x402 and the signer ran together on the board for 5 minutes: 41 slices accepted, 7 of 8 anchor submissions accepted with valid receipts and none rejected, 6 of 6 x402 calls settled, the signer's 8 checks passed. Without the patch, turn the buyer and anchoring off when x402 is on.

## Paying a smart account (2026-11-08)

A seller paid to a smart account (an ERC-4337 Safe from WDK) publishes a record with a `pay` field, `{"v":1,"did","eth":"<owner>","pay":"<Safe>","eth_sig"}`, `eth_sig` signing `"<did>\npay:<Safe>"` with the owner key ([boat-peer](../../packages/boat-peer)). `verify_record` accepts it and makes the `pay` address the payee every slice is checked against. Firmware without this refuses such a record, so it never pays the owner key by mistake.

## A Solana wallet on the device (2026-11-08)

With `CONFIG_MER_SOL_MINT` set (and `CONFIG_MER_OWNER_KEY`), the owner channel also takes `sol_address` and `sol_transfer`. The device derives an Ed25519 key for Solana from its DID key (`BLAKE2b(key = DID seed, "boat-solana/1")`, [`main/solana.h`](main/solana.h)) and signs a transaction message only when it is a Token `transferChecked` of that mint out of its own account, within `CONFIG_MER_SIGNER_MAX_VALUE`, whose fee someone else pays and in which the device is a read-only signer. [`packages/wdk-protocol-boat-solana`](../../packages/wdk-protocol-boat-solana) makes it a signer for a WDK Solana account; its tests run this C code against a local validator, 13 of 13.

## Selling readings with x402 (2026-11-08)

With `CONFIG_MER_X402_SELL_PORT` and `CONFIG_MER_X402_SELL_FACILITATOR`, the device runs an HTTP server ([`main/x402_sell.c`](main/x402_sell.c)): `GET /reading` costs `CONFIG_MER_X402_SELL_PRICE` units of `CONFIG_MER_X402_SELL_TOKEN` (EIP-3009, with its domain name and version), paid to the device's own address. The device checks each payment itself with MER's crypto ([`main/x402_check.c`](main/x402_check.c): payee, price, validity window, the signature recovered under the token's EIP-712 domain, a nonce not seen before), has the facilitator settle it, and only then answers with an attested reading and a `PAYMENT-RESPONSE`. The request header limit goes up to 3 KB (`CONFIG_HTTPD_MAX_REQ_HDR_LEN`) for the payment. [`packages/wdk-protocol-boat-evm`](../../packages/wdk-protocol-boat-evm#a-device-that-sells-with-x402) has the facilitator, a buyer, and a test that runs `x402_check.c` against payments from the standard x402 client, 8 of 8.

## Firmware updates from a Hypercore (2026-11-08)

With `CONFIG_MER_OTA_CORE`, `_SIGNER` and `_SERVER`, the device checks for a newer release every `CONFIG_MER_OTA_INTERVAL_S` ([`components/hdht_ota`](../../components/hdht_ota), [`packages/boat-ota`](../../packages/boat-ota)) and updates itself, every block checked against the publisher's signed Hypercore tree. The firmware version is `PROJECT_VER` in `CMakeLists.txt`. This example now uses a partition table with two OTA slots, [`partitions_ota.csv`](partitions_ota.csv) (1.9 MB each; `nvs` stays at 0x9000, so a board keeps its keys when flashed with it). The image, with the x402 server and the Solana signer, is 1.36 MB.

## On the board, every feature at once (2026-11-08)

One 0.7.0 image with the buyer, anchoring, the owner's signer (EVM and Solana), x402 selling and OTA, on the ESP32-C3 over the public HyperDHT. Chains were local: an anvil fork of the Stable testnet (USD₮0, chain 2201) and a `solana-test-validator`; anchoring stayed on the Arc testnet through the cloud anchor node.

| | Result |
|---|---|
| EVM wallet (`wdk-protocol-boat-evm/examples/device-wallet.js`) | 8 of 8: the device signed a 0.05 USD₮0 sweep, the owner's WDK account submitted it and paid the gas |
| Solana wallet (`wdk-protocol-boat-solana/examples/device-wallet.js`) | 4 of 4: the device signed a 0.1-token transfer, the owner's WDK account paid the 10,000-lamport fee; over-limit and other-owner requests refused |
| x402 selling (`buy-from-device.js`, `facilitator.js`) | 3 of 3 readings bought by a standard x402 client and settled by the facilitator, 1.4–2.1 s each, every reading's signature valid |
| Batched settlement (`apps/pear-seller --settle --batch 20`) | 4 batches, 12 of 12 slices settled, 0 failures (one transaction per batch, Multicall3) |
| A seller record with `pay` | Same seller DID, wallet switched to a WDK Safe: the board, still holding the old record, refused the first slice to the Safe ("payee mismatch") and disconnected, looked the record up again, then paid the Safe; settled as user operations (`wdk-protocol-boat-evm/examples/smart-seller.js`), 10 of 10 with `--batch 20` |
| OTA 0.7.0 → 0.7.1 | 1,366,240 bytes in 334 blocks from a Mac seeding the core, 65.7 s, every block checked; rebooted into `ota_1`, then "up to date" |

Found and fixed on the way: the clock was set by SNTP only when `CONFIG_MER_X402_URL` was on, so without it the signer and the x402 seller compared validity windows with the seconds since boot and refused every authorization. SNTP now starts in `app_main` for every feature, and both say "device clock not set yet" until it has synced. Not fixed: about 24 s after boot the task watchdog warned twice that the hdht task had kept the CPU for 5 s (BLAKE2b, then TweetNaCl, as records are verified and signed back to back); the board did not reset.

## MQTT, paid per message (2026-11-08)

With `CONFIG_MER_MQTT_NODE` (a network name, or a node's key), the device joins an MQTT network of nodes anyone can run ([`packages/boat-mqtt-node`](../../packages/boat-mqtt-node)) over HyperDHT ([`components/hdht_mqtt`](../../components/hdht_mqtt)) and publishes an attested reading every `CONFIG_MER_MQTT_INTERVAL_S` to `d/<its key>/telemetry` ([`main/mqtt.c`](main/mqtt.c)). Its DID record gains `"mqtt":"<node key>"`, so apps and other nodes find the node it is on.

A node that charges puts its terms (payee, token, price per message and per KB, credit) in its own DHT record and sends invoices to the device's inbox. The device pays each with an EIP-3009 authorization signed by MER and published to `d/<its key>/to/<node>/pay`. It pays:

- only the payee and token in the node's signed terms, and only in its buyer's token and EIP-712 domain (`CONFIG_MER_BUYER_*`). That also leaves MER's single global domain as the buyer set it, and the payment is signed on the hdht task like the buyer's;
- at most what it counted itself plus the node's stated credit, and at most `CONFIG_MER_MQTT_MAX_PAY` at once.

The node checks each payment against the device's DID record and stops taking its messages while more than the credit is unpaid. `packages/wdk-protocol-boat-evm/examples/mqtt-node.js` runs such a node and settles the payments from a WDK account in Multicall3 batches.

On the board, with an anvil fork of the Stable testnet (USD₮0), two runs of 5 minutes, at 100 µUSD₮0 per message plus 1000 per KB:

| | Run 1 | Run 2 |
|---|---|---|
| Readings published (about 430 bytes each) | 55 | 51 |
| Invoices paid / settled on chain | 29 / 29, in 10 batches | 26 / 26, in 9 batches |
| What the device counted vs what the node charged | equal (28,638) | equal (26,570) |
| Paid | 0.028117 USD₮0 | 0.026048 USD₮0 |
| Signing a payment on the C3 | 0.40–0.65 s | 0.40–0.65 s |
| Gas per payment, batches of 3 | ~58,000 | ~58,000 |

In run 1 the task watchdog warned once more, 4 minutes in: the hdht task had signed four times back to back (anchoring and an MQTT reading, each an attestation and a payment). The readings are now attested on the MQTT task instead, and run 2 had only the boot-time warnings noted above.

## Integration notes

- **Duplicate `randombytes`.** MER defines a global `randombytes()` to feed TweetNaCl, and libsodium defines one too, so linking both fails with `multiple definition of 'randombytes'`. `CMakeLists.txt` renames MER's copy inside its own component (`randombytes=boat_mer_randombytes`) without changing MER's sources. A weak symbol upstream, or building MER's Ed25519 on libsodium, would remove the need for this.
- **Signing blocks the loop.** MER signs on the hdht task, which is single-threaded, so each signature pauses networking for 0.4–0.65 s. That is fine at one slice every 5 s. For faster slices, sign on another task and hand the result back with `uv_async_send`. Switching MER's Ed25519 to libsodium would bring attestations from ~480 ms to ~15 ms.
- **Memory.** The buyer context is 33 KB of static RAM at MER's default `BOAT_BUYER_NONCE_CAP` of 4096. MER allows a smaller cap, which has to be defined globally. Adding BLE on top (see `examples/hyperdht_demo`'s coexistence numbers) would leave little headroom on a C3.
- **Key reuse.** One Ed25519 key now serves Noise (as a DH key), HyperDHT announce signatures and MER attestations. HyperDHT already uses one key for both DH and signing. MER attestations sign a 32-byte SHA-256 digest, while HyperDHT signs a namespaced 64-byte message, so neither signature can stand in for the other. Products that want strict separation can derive two keys from one seed and have the DID key sign the HyperDHT key.
- **Payee binding.** MER's buyer engine trusts the `to_address` in each slice request. This example checks it outside the engine, against the seller's DID record, before passing the slice on. A hook in the engine, or an expected-payee field in `boat_buyer_config_t`, would be cleaner.
- **Lookups take seconds.** Reading a record costs a DHT query of 2–5 s, on top of the connection. A buyer that pays the same seller often can cache the payee and look it up again in the background.
