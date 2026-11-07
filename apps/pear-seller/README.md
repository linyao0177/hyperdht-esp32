# pear-seller: a Pear app that sells to BoAT MER devices

A Pear terminal app that sells power to ESP32-C3 devices running [`examples/boat_mer`](../../examples/boat_mer), over Holepunch, with no server in between:

1. The app has a DID, which is its Hyperswarm key, and publishes a DID record that names the wallet it is paid to.
2. A device connects to that DID. It reads the app's record first, and pays only that wallet.
3. The app bills the device every 5 s for the power it delivered. The device signs an EIP-3009 authorization for each slice.
4. The app checks each one with [`boat-peer`](../../packages/boat-peer): the signer must be the wallet in the device's DID record, and the payee, amount and slice must match the bill.
5. Each accepted authorization is appended to a Hypercore, the receipts log. Anyone with its key can replicate it and check every receipt again with `verify-receipts.js`.
6. With `--dial <did>`, the app also reads the device's signed reading by its DID every minute.

The power is simulated: 12 W for 40 s, then 0 W for 20 s, so the device opens and closes paying sessions on its own. Nothing is settled on-chain.

The app is built from Holepunch's [hello-pear-bare](https://github.com/holepunchto/hello-pear-bare) template (Pear 3, Apache-2.0). The host (`bin.mjs`, `app.js`) starts the worker (`workers/main.js`) with `pear-runtime` and keeps its updater. All the peer-to-peer work runs in the worker, on Bare.

## Run it

```bash
cd packages/boat-peer && npm install && cd ../../apps/pear-seller && npm install
```

```bash
npm start
```

The app prints its DID. Set `CONFIG_MER_SELLER_KEY` in `examples/boat_mer` to the hex after `did:mw:`, then build and flash the board. To also read the board's signed reading, add `-- --dial did:mw:<board>` to `npm start`.

To check the receipts from another computer, using only the key the app prints:

```bash
node verify-receipts.js <receipts hypercore key>
```

`npm run make` builds a standalone binary that needs no Node.js, Bare or Pear (see the template's notes on `upgrade` links and signing).

## Results (2026-11-07, ESP32-C3 and a Mac, public HyperDHT)

The app ran on Bare 1.36 on a Mac, and the board ran `examples/boat_mer`, on the same LAN. The board also sent its readings to the public anchor node on the testnet, as usual.

| | Result |
|---|---|
| App start | Seller DID record stored on 20 nodes |
| Device to app | The board found the app's record (valid, lookup 5.1 s, check 259 ms) and connected to its DID, through the router's public address |
| App reads the device's record | Valid, 2.4–2.6 s |
| Payments | 18 paying sessions over 4 runs of the app, each opened when the power came on and closed after it went off. 122 authorizations checked, 122 accepted, 0 refused. Bill to checked payment: 424–1835 ms, median 686 ms. The board's signature took 396–658 ms of that |
| Restart | After the app was stopped and started again, the board reconnected within seconds and the receipts log went on from where it was |
| Receipts | `verify-receipts.js` on the same Mac, with a store of its own, replicated the log from the app over Hyperswarm (114 receipts in 21 s) and found 114 of 114 valid, 441 micro-USDC, against both DID records read from the DHT |
| Signed reading by DID | 3 of 3, opened in 0.87–1.55 s, every check passed |

One problem is not understood yet. Dialed from the swarm's own DHT in this app, the reading timed out 6 times out of 6 (`connection timed out`). The same dial passed from a script in every set-up tried: Node.js and Bare, a plain HyperDHT and a Hyperswarm's, with a seller swarm on the same DHT that the board was paying, after joining a topic as a server, and inside a `bare-worker` thread. The app now dials readings from a HyperDHT of its own, which passed 3 of 3.

## Files

| File | |
|---|---|
| [`workers/main.js`](workers/main.js) | The worker: seller identity, DID record, seller swarm, receipts Hypercore, reading dials, and the template's updater |
| [`bin.mjs`](bin.mjs), [`app.js`](app.js) | The template's host, with a `--dial` flag added |
| [`verify-receipts.js`](verify-receipts.js) | Replicates a receipts log by key and checks every receipt |
| [`scripts/make.js`](scripts/make.js) | The template's standalone build |
