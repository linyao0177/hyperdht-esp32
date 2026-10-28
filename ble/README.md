# SecretStream over BLE on the ESP32-C3

A PoC for "same key, two paths": the device's Holepunch identity (the Ed25519 key pair it announces on HyperDHT in `firmware/`) is reused for a local connection over Bluetooth LE, with no internet involved. BLE carries a plain [@hyperswarm/secret-stream](https://github.com/holepunchto/hyperswarm-secret-stream) byte stream, so the official JS module works on the other end unchanged.

## How it works

- **Discovery**: the device advertises a custom service UUID. Its scan response carries the name `hdht-<first 4 hex of the key>` and manufacturer data `0xffff` followed by the first 8 bytes of `BLAKE2b-256(public key)`, which is also its HyperDHT target. A client can pick out the device it wants before connecting.
- **Transport**: GATT service `1d9e0001-3c2a-4b8e-9f5e-6864687462ee`, with two characteristics: RX `…0002…` (write / write without response) and TX `…0003…` (notify). Both carry raw stream bytes, chunked to the ATT MTU. Outgoing bytes are queued in an 8 KB ring when the notification buffers are full.
- **Security**: SecretStream with an in-band Noise **XX** handshake (`hdht/src/secret_stream.c`, also supports IK), then `crypto_secretstream` messages. The client checks that the handshake's remote key is the expected device key. BLE pairing/bonding is not used, since Noise already authenticates and encrypts.
- **Key pair**: seed = 32 × `HDHT_BLE_SEED_BYTE` (default 0x33, the same key as the `firmware/` server).
- The device echoes every message.

## Running

```bash
idf.py build flash
```

On the Mac, Bluetooth needs an app bundle that declares `NSBluetoothAlwaysUsageDescription`. Without it, macOS kills the process (TCC). Build the bundle once:

```bash
sh ../poc/host/make-ble-app.sh /tmp/bleapp
```

Then run the client:

```bash
open -W -n /tmp/bleapp/hdht-ble-client.app --args 0x33 32768 norsp
```

Its output goes to `/tmp/bleapp/ble-client.log`. The first run asks for Bluetooth permission.

## Measured (2026-10-28, ESP32-C3 rev v0.4, MacBook as central, ~1 m apart, RSSI −47 to −57)

| Item | Result |
|---|---|
| Scan to device found (key hash checked) | 75–350 ms |
| Connect + GATT discovery | 0.9–1.1 s |
| Link | 2M PHY both ways, ATT MTU 512, connection interval 30 ms (macOS declined 15 ms) |
| Noise XX handshake + headers | 184–220 ms on the client (device side 266–333 ms incl. waiting), device key verified |
| Echo round trip, small message | min 58 ms, median 60 ms |
| Echo throughput, acknowledged writes (`rsp`) | 1.5 KiB/s each way: each write waits for the next connection event |
| Echo throughput, write without response (`norsp`) | **10.1 KiB/s each way** (~20 KiB/s total), all 164 × 200 B messages verified |
| NimBLE host + controller heap | 56 KB |
| Free heap while connected (no WiFi) | ~205 KB, back to the same value after each disconnect |

## Lessons

- The NimBLE host task runs the Noise handshake (three Ed25519 DHs) inside the GATT write callback. It needs 12 KB of stack, and large buffers should not live on that stack.
- `ble_gatts_notify_custom` raises `BLE_GAP_EVENT_NOTIFY_TX` synchronously. Draining the queue from that event recursed until the stack overflowed, so it is now deferred through a callout.
- Throughput is bound by the central: one 182-byte write per connection event with responses, more without. Phones that grant 7.5–15 ms intervals or L2CAP CoC (not available through noble on macOS) should do better.

## Not done

- **Phone client**: iOS/Android could reuse the same JS SecretStream (e.g. in a React Native or Bare app) or a native Noise implementation.
- **L2CAP connection-oriented channels** instead of GATT.
- **Running BLE and WiFi + HyperDHT at the same time** on one C3: they share the radio, and NimBLE's 56 KB comes on top of the ~25 KB per DHT connection. This needs measuring.
- A **BLE ↔ HyperDHT bridge** (a mains-powered C3 forwarding a BLE device's stream to a remote peer, end-to-end encrypted).
