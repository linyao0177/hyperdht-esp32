# boat-ota

Firmware for BoAT MER devices over Holepunch. A publisher appends releases to a Hypercore; any peer that holds the core serves it to devices over HyperDHT; each device checks every block against the publisher's signature before it writes it, and boots a newer release only when the whole image matches the release's SHA-256. The peers in between are not trusted: a changed block stops the update at that block.

The core is the product's firmware channel. It is append-only, so every release ever offered to devices stays in it and is replicated with it, like a transparency log.

```bash
boat-ota publish build/hdht_boat_mer.bin --storage ./firmware     # name and version from the image's app description
boat-ota seed --storage ./firmware                                # serve it; prints the key devices dial
boat-ota seed --storage ./mirror --key <core key>                 # another peer, replicating it over Hyperswarm
boat-ota list --storage ./firmware
```

`publish` prints `CONFIG_MER_OTA_CORE` (the core key) and `CONFIG_MER_OTA_SIGNER` (the publisher's key); `seed` prints `CONFIG_MER_OTA_SERVER`. A device built with them ([`components/hdht_ota`](../../components/hdht_ota), wired into `examples/boat_mer`) checks for updates every `CONFIG_MER_OTA_INTERVAL_S`.

## How a device checks it

A Hypercore is a Merkle tree over its blocks whose roots the writer signs. The device gets a signed tree head (roots, length, fork, signature) and checks the signature over `TREE ‖ key ‖ BLAKE2b(0x02 ‖ roots) ‖ length ‖ fork`, hypercore 11's own signable, with the publisher's key. Then each block comes with its sibling nodes up to a root, which the device hashes up (hypercore-crypto's leaf and parent hashes) and compares with the signed root. It checks this in C ([`hc_proof.c`](../../components/hdht_ota/hc_proof.c)), against proofs Hypercore made: the tests write them out and the C code checks them too.

A release is a manifest block, `{"type":"boat-ota/1","name","version","size","sha256","chunk","first","blocks","t"}`, followed by the image in 4 KB blocks. The device takes the latest release of its product (`esp_app_desc_t.project_name`), and updates when its version is newer than the running one. The protocol on the HyperDHT stream is in [`lib/wire.js`](lib/wire.js).

## API

| | |
|---|---|
| `publish(core, { name, version, image })` | Appends a release |
| `latest(core, name)` | The index of the latest release of `name` |
| `serve(dht, keyPair, core)` | Serves the core to devices |
| `fetchLatest(dht, { server, key, signer, name })` | Fetches and checks the latest release the way a device does |
| `verifyHead`, `verifyBlock` | The device's checks, in JS |

## Tests

```bash
npm install && npm test
```

12 of 12 (2026-11-08): two releases published; a seeder with no key of the publisher replicates the core; its head and block proofs verify, and the device's C code agrees on 12 proofs and forgeries; a device fetches the 70 KB release over a local HyperDHT testnet in 20 requests; a device that trusts another publisher refuses it; a bridge that changes block 25 is caught at block 25; a new release replicates to the seeder and reaches devices.

On the board (2026-11-08): `examples/boat_mer` 0.7.0 found 0.7.1 in a core seeded from a Mac over the public HyperDHT and fetched 1,366,240 bytes in 334 blocks in 65.7 s (about 20 KB/s), each block checked against the signed head, then booted it from `ota_1` and reported itself up to date. A storage is locked by the process that has it open: stop `seed` before `publish` into the same storage, and start it again after.
