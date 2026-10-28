# BoAT MER over HyperDHT

A proof of concept that combines [BoAT MER](https://github.com/TLAY-IO/boat-mer) with hyperdht-esp32 on one ESP32-C3. BoAT MER (Machine Economy Runtime) is an Apache-2.0 C runtime that handles device identity, signed machine data and EIP-3009 nanopayments. hyperdht-esp32 makes the device reachable by public key from anywhere.

The firmware does three things:

1. **One identity.** MER generates and keeps the device keys. Its Ed25519 key pair is used unchanged as the HyperDHT key pair, for listening and for outgoing connections. So the device's DID, `did:mw:<ed25519 public key>`, is also its HyperDHT address.
2. **Reachable by DID.** Anyone who knows the DID can connect to the device, through NATs and end to end encrypted. The Noise handshake proves the device holds the DID's key. The device answers with a reading attested by MER (SHA-256 + Ed25519) and ends the stream.
3. **Nanopayments across the internet.** MER's buyer engine is written against a small transport vtable, and normally runs over BLE GATT to a seller a few metres away. Here it runs over a HyperDHT stream. The board reads the remote seller's power, opens a paying stream, validates every slice and signs an EIP-3009 authorization for each one on the device.

Nothing is settled on-chain. The seller (`tools/host/mer-seller.js`) verifies each authorization the way a settlement service would, and the amounts are synthetic.

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

3. Connect to the board by its DID:

   ```bash
   node tools/host/mer-dial.js did:mw:<hex> public 3
   ```

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

## Integration notes

- **Duplicate `randombytes`.** MER defines a global `randombytes()` to feed TweetNaCl, and libsodium defines one too, so linking both fails with `multiple definition of 'randombytes'`. `CMakeLists.txt` renames MER's copy inside its own component (`randombytes=boat_mer_randombytes`) without changing MER's sources. A weak symbol upstream, or building MER's Ed25519 on libsodium, would remove the need for this.
- **Signing blocks the loop.** MER signs on the hdht task, which is single-threaded, so each signature pauses networking for 0.4–0.65 s. That is fine at one slice every 5 s. For faster slices, sign on another task and hand the result back with `uv_async_send`. Switching MER's Ed25519 to libsodium would bring attestations from ~480 ms to ~15 ms.
- **Memory.** The buyer context is 33 KB of static RAM at MER's default `BOAT_BUYER_NONCE_CAP` of 4096. MER allows a smaller cap, which has to be defined globally. Adding BLE on top (see `examples/hyperdht_demo`'s coexistence numbers) would leave little headroom on a C3.
- **Key reuse.** One Ed25519 key now serves Noise (as a DH key), HyperDHT announce signatures and MER attestations. HyperDHT already uses one key for both DH and signing. MER attestations sign a 32-byte SHA-256 digest, while HyperDHT signs a namespaced 64-byte message, so neither signature can stand in for the other. Products that want strict separation can derive two keys from one seed and have the DID key sign the HyperDHT key.
- **Payee binding.** The buyer engine trusts the `to_address` in each slice request. This example authenticates the seller by key, but does not yet check that the payee address belongs to that seller. A real product should pin or look up the seller's payee address for its DID before signing.
