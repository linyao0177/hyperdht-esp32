# hdht_ota

Firmware updates for hyperdht-esp32 devices from a Hypercore ([`packages/boat-ota`](../../packages/boat-ota) publishes and serves it).

```c
hdht_ota_config_t ota = {
  .server = { /* a peer serving the core */ },
  .key = { /* the core's key */ },
  .signer = { /* the publisher's Ed25519 public key */ },
  .name = esp_app_get_description()->project_name,
  .interval_s = 3600,
};
hdht_ota_start(&dht, &ota);   // once bootstrapped
hdht_ota_tick();              // once a second, on the hdht task
hdht_ota_confirm();           // once the new image works (with bootloader rollback)
```

The device dials the server, checks the signed tree head against `key` and `signer`, reads the latest release's manifest, and downloads the image block by block into the other OTA partition, each block checked against the head before it is written (`OTA_WITH_SEQUENTIAL_WRITES`, so the loop is not stalled erasing). When the image matches the manifest's SHA-256 and `esp_ota_end` accepts it, it boots it. A head shorter than one seen before is refused.

`hc_proof.c` is the Hypercore part, plain C over libsodium: flat-tree, hypercore-crypto's leaf, parent and tree hashes, and hypercore 11's tree signable. It builds on the desktop too (`test/test_hc_proof.c`), and `packages/boat-ota`'s tests check it against proofs made by Hypercore itself.

Needs a partition table with two OTA slots (`examples/boat_mer/partitions_ota.csv`: 1.9 MB each on 4 MB of flash, `nvs` where the single-app layout has it).
