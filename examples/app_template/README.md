# app_template: a device app with no server

The starting point for a product built on this module. The device does everything a cloud backend usually does for it: identity, reachability, ownership, access control, configuration and keeping its data. It does this together with peers, with no server in between. Copy this directory, replace [`main/app.c`](main/app.c), and keep the rest.

| Usually a server's job | Here |
|---|---|
| Device registry, accounts | The device's key is its identity, `did:mw:<public key>`. It signs its own record (service, name, owner, grant epoch), which anyone can read from the DHT |
| Cloud relay, MQTT broker | Peers connect to the device by its key, from anywhere and through NATs, over an encrypted stream that authenticates both sides |
| Pairing and ownership | The first peer to send the device's setup code becomes its owner. The owner can release it again |
| Sharing access | The owner signs a grant for another peer's key. The device checks grants from their signature alone and stores none. Grants expire, and the owner can revoke them all at once |
| Remote configuration | The owner sets values, which are checked by `app_set` and kept in NVS |
| Data storage | Every reading is signed by the device. Any peer with access can keep copies in a Hypercore and share them. Anyone can check a copy against the device's key, whoever served it |

## Roles

- **Device**: this firmware. It holds no data history and trusts nothing but signatures.
- **Owner**: the peer that claimed the device. It can read the device, change settings, and grant, revoke or release access.
- **Reader**: a peer holding a grant from the owner. It can read state and subscribe to readings.
- **Replica**: an owner or reader that keeps the signed readings and shares them. The device does not need to be online for others to get its data.
- **Anyone**: can read the record and check a replica's copies. Neither needs the device's permission.

All peers here use [`tools/host/app-peer.js`](../../tools/host/app-peer.js). A phone app, a gateway or another device would speak the same messages, which are listed at the top of [`main/main.c`](main/main.c).

## Run it

1. Copy `sdkconfig.wifi.example` to `sdkconfig.wifi` at the repo root and fill in a 2.4 GHz network.

2. Build and flash, then watch for the device's DID and setup code:

   ```bash
   cd examples/app_template && idf.py set-target esp32c3 && idf.py build flash monitor
   ```

   ```
   APP|device did:mw:2ced4bb7...
   APP|unclaimed; setup code: DUYK-NL6U
   ```

   A product would print the setup code on a label or a QR code instead.

3. Install the host tools:

   ```bash
   cd tools/host && npm ci
   ```

4. Claim the device and use it. Each command connects, does its job and exits. `--id` keeps several identities on one machine. Each identity's key is kept in `~/.app-peer/<id>`.

   ```bash
   node app-peer.js claim did:mw:<device> <setup code>
   ```

   ```bash
   node app-peer.js state did:mw:<device>
   ```

   ```bash
   node app-peer.js set did:mw:<device> interval_s=10
   ```

5. Share read access with another peer. The grant is a signature, so you can send it any way you like:

   ```bash
   node app-peer.js whoami --id guest
   ```

   ```bash
   node app-peer.js grant did:mw:<device> did:mw:<guest> --hours 24 > guest.grant
   ```

   ```bash
   node app-peer.js state did:mw:<device> --id guest --grant guest.grant
   ```

6. Keep copies of the data. Each replica prints its log key and serves the log while it runs:

   ```bash
   node app-peer.js replica did:mw:<device> --id guest --grant guest.grant
   ```

   Anyone with that key can fetch the copies and check them. They need no grant, and they need neither the device nor the guest's identity:

   ```bash
   node app-peer.js check did:mw:<device> <log key> --id someone-else
   ```

7. End access:

   ```bash
   node app-peer.js revoke did:mw:<device>
   ```

   ```bash
   node app-peer.js release did:mw:<device>
   ```

## Make it yours

- **[`main/app.c`](main/app.c)** is the application. `app_reading` writes one reading, here the C3's internal temperature. `app_settings` and `app_set` expose what the owner may change, here `interval_s`. `APP_SERVICE` in [`main/app.h`](main/app.h) names your protocol in the record.
- **New commands** go in `on_session_data` in [`main/main.c`](main/main.c). Check `s->role` first.
- **More roles**: grants carry a role in the text the owner signs, so adding one is a new word in that text and a new `role_t`.
- **Commands from the owner that must reach the device while it sleeps or is offline**: publish them as a record under the owner's key and let the device read it on wake. The device can already read any record.
- **Tamper-evident history**: send the readings' hashes to open anchor nodes as [`examples/boat_mer`](../boat_mer/README.md#distributed-anchoring) does. Each receipt then proves on chain when the device signed the reading.
- **Payments**: [`examples/boat_mer`](../boat_mer) shows the device signing EIP-3009 payments with the same key.

## Security notes

- **Setup code**: 8 characters from a 32-letter alphabet, which is 40 bits. Only 5 wrong attempts are allowed per boot, and the comparison is constant-time. The code is kept in NVS until the device is claimed.
- **Grants**: a grant is the owner's Ed25519 signature over `app-template/grant/1 <device key> <grantee key> read <epoch> <exp>`. The device fills in its own key and the connecting peer's key, so a grant works only for that device and that peer. A stolen grant file is useless to anyone else. In the test run, a stranger presenting a guest's grant was refused.
- **Expiry and revocation**:
  - Expiry needs the time. The device gets it over SNTP, and refuses grants until its clock is set.
  - Revocation is all at once. It raises the epoch in NVS and in the record, and closes open reader sessions.
  - To revoke one reader only, add a revocation list to the owner's record.
- **The record is public**: anyone can read it. Never put secrets in it.
- **Replicas are readable by anyone who has the log key.** The key works as a capability, not as access control. For private data, encrypt the readings to the readers' keys, or use Hypercore's encryption.
- **Keys at rest**: NVS is not encrypted here. A product should turn on flash encryption and NVS encryption, or keep the key in a secure element.

## Results (2026-10-29, ESP32-C3 on the public HyperDHT)

| | Result |
|---|---|
| Record | Published to 20 DHT nodes 4 s after start. It changed on claim, revoke and release (seq 1 → 6), and every peer saw the current version |
| Commands | `claim`, `state`, `set`, `grant`, `revoke` and `release` each took 3–5 s from a laptop, mostly finding and connecting to the device |
| Claim | A wrong code was refused. Once the device was claimed, the right code from another peer was refused too |
| Access | The guest read with its grant. The guest's `set` was refused. A stranger presenting the guest's grant was refused. A stranger without a grant could not read |
| Replicas | Owner and guest each kept every reading (`subscribers=2`). A third peer with no grant fetched the guest's copy and checked 11 of 11 signatures. Later it fetched the owner's copy, 30 readings over two boots and one firmware update, and checked 30 of 30 |
| Revoke | The guest's session closed at once. Its replica's reconnect was refused with "grant revoked". The owner's replica kept running |
| Release and claim again | The record showed no owner. The new setup code worked, and the old owner's grants were void because release raises the epoch |
| Persistence | Owner, epoch, settings and record seq survived a reflash |
| Free heap | ~181 KB with two subscribed peers |
| Image | 1.03 MB (0x107830); 30% of the app partition free |

The test run found one bug, fixed before the second round. A reader whose session the device ended never closed its side of the stream, which would have kept one of the device's 4 session slots. Now the device closes revoked sessions outright, and `app-peer.js` closes its side when the device ends.

## Limits

- **4 sessions at a time** (`MAX_SESSIONS`). Each costs ~25 KB of heap while connected.
- **One owner.** To transfer ownership, release the device and let the new owner claim it.
- **Peers must know the device's DID.** The device does not announce under a topic yet. Share the DID with the setup code or through the owner.
- **No relay fallback**: a device behind a random NAT cannot be reached; see the main README.
