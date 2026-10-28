# hdht_ble

SecretStream over a BLE GATT service (NimBLE), using the device's hdht key pair: the same Ed25519 identity reaches the device locally over BLE, without internet, or remotely over HyperDHT.

```c
hdht_ble_start(public_key, secret_key); // after nvs_flash_init() and sodium_init()
```

- **Advertising**: a custom service UUID. The scan response carries `hdht-<4 hex>` and manufacturer data `0xffff` followed by the first 8 bytes of `BLAKE2b(public key)`, which is also the device's HyperDHT target.
- **GATT**: service `1d9e0001-3c2a-4b8e-9f5e-6864687462ee`, RX `…0002…` (write, write without response) and TX `…0003…` (notify). Both carry raw SecretStream bytes.
- **Security**: in-band Noise XX (`hdht/src/secret_stream.c`). Clients check the device's public key after the handshake; BLE pairing is not used.
- **Behaviour**: one connection at a time; every message is echoed. Adapt `on_ss_data` in `hdht_ble.c` for your protocol.
- **Config**: `CONFIG_BT_NIMBLE_ENABLED=y` (the component compiles to nothing otherwise), NimBLE host task stack of at least 12 KB (the handshake runs there), ATT MTU 512. See `examples/hyperdht_demo/sdkconfig.ble`.

Cost: ~56 KB of heap for NimBLE, plus ~38 KB the BT controller reserves at boot. Measurements are in [`examples/ble_echo`](../../examples/ble_echo/README.md).
