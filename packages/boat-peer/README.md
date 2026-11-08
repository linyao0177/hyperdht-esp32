# boat-peer

The app side of [BoAT MER](https://github.com/TLAY-IO/boat-mer) over Holepunch. A Node.js, Bare or Pear app uses it to work with BoAT MER devices running [`examples/boat_mer`](../../examples/boat_mer):

- look up a device's DID record and check it;
- dial a device by its DID and check the reading it signed;
- sell to a device over MER's streaming nanopayment protocol, and check every EIP-3009 authorization it signs.

It runs the same in Node.js and in Bare, so it also works in Pear apps and in Bare Kit mobile apps. The Ethereum signatures use [noble](https://paulmillr.com/noble/) in plain JavaScript, with no Node.js `crypto` and no ethers. [`apps/pear-seller`](../../apps/pear-seller) is a Pear app built on it.

```js
const { resolveDid, dialReading, Seller, publishRecord } = require('boat-peer')

const { record } = await resolveDid(dht, 'did:mw:7dc9...')   // {v, did, eth, eth_sig}, checked
const r = await dialReading(dht, 'did:mw:7dc9...', { record })
if (r.ok) console.log(r.reading.payload)                       // signed by the DID key

const seller = new Seller({ payee, domain, token, rate: 250000, power: () => watts })
seller.on('payment', (p) => p.ok && settle(p.authorization))  // checked against the buyer's DID record
swarm.on('connection', (conn) => seller.serve(conn, swarm.dht))
```

`dht` is a [HyperDHT](https://github.com/holepunchto/hyperdht), or a Hyperswarm's `swarm.dht`.

## API

| | |
|---|---|
| `didOf(publicKey)`, `keyOf(did)` | A DID is `did:mw:<Ed25519 public key hex>`, which is also the device's HyperDHT address |
| `resolveDid(dht, did)` | Reads the DID record from the DHT. Returns `{ record, seq }`, with `record` null when it is not valid, or null when there is none |
| `verifyRecord(publicKey, value)` | A record is valid when its `did` is the key it is stored under (the DHT checks that the key signed it) and its `eth_sig`, an EIP-191 signature of the DID, recovers to its `eth` |
| `signRecordVersion(keyPair, record, seq)`, `verifyRecordVersion(did, version)` | A record version signed by the DID key, for logs that must outlive the DHT's latest record: a receipt can be checked against the record that was current when it was paid |
| `makeRecord(publicKey, ethPrivateKey, { pay })`, `publishRecord(dht, keyPair, ethPrivateKey, { pay })` | Make and publish a record for your own DID, so devices can check who they pay. With `pay`, the record names a payee other than the signing key, a smart account for example: `eth_sig` then signs `"<did>\npay:<payee>"`, so the owner key vouches for it, and a verifier that does not know `pay` refuses the record |
| `payeeOf(record)` | The address a DID is paid at: `pay` if the record has one, else `eth` |
| `new OwnerChannel({ dht, did, keyPair })` | A device's owner channel (`CONFIG_MER_OWNER_KEY`): `open()`, then `request({ op, ... })` for JSON answers. The device signers in [wdk-protocol-boat-evm](../wdk-protocol-boat-evm) and [wdk-protocol-boat-solana](../wdk-protocol-boat-solana) use it |
| `dialReading(dht, did, { record })` | Connects to the device, reads its one message, and returns `{ ok, checks, reading, openMs }`. Checks: the stream's peer is the DID, the hash matches the payload, the Ed25519 signature is the DID's, and the wallet matches the record |
| `verifyReading(did, message, { remotePublicKey, record })` | The same checks on a reading you already hold |
| `new Seller({ payee, domain, token, rate, sliceMs, maxSession, powerRange, power, settle })` | A seller for MER's 0xEE00 protocol. `seller.serve(conn, dht)` serves one buyer on a stream. `settle: 'session'` asks for session settlement (a BoAT MER buyer with [patches/boat-mer](../../patches/boat-mer) 0002): one nonce per session, the buyer signs the running total, and the `session` event hands over the one authorization to settle |
| `eth` | `signMessage`, `verifyMessage` (EIP-191), `signTransfer`, `verifyTransfer` (EIP-712 TransferWithAuthorization), `addressOf`, `checksum` |

The seller's events: `buyer`, `record` (the buyer's DID record, once read), `open` and `end` (a paying session), `slice` (a bill sent), `payment`, `session` (session settlement: `{ authorization, total, slices }` when a session ends), `close`. A `payment` carries `ok`, and when it is false a `reason`:

| Reason | |
|---|---|
| `not billed` | The nonce is not one the seller billed, or was already paid |
| `signer is not from` | The signature does not recover to the `from` address |
| `buyer has no valid DID record` | The buyer's record was missing or invalid when the payment came |
| `signer is not the wallet in the buyer DID record` | Someone else's wallet signed |
| `wrong payee`, `wrong amount`, `wrong slice` | The authorization does not match the bill |

A `payment` that is `ok` holds the signed `authorization` (`from`, `to`, `value`, `validAfter`, `validBefore`, `nonce`, `signature`), ready to submit to the token's `transferWithAuthorization`. Settling it is the app's job; [`wdk-protocol-boat-evm`](../wdk-protocol-boat-evm) does it from a WDK account.

## Wire

Each stream message carries one GATT operation of MER's 0xEE00 service, with the characteristic values unchanged: `op (1) | uuid16 (little-endian) | value`. See [examples/boat_mer](../../examples/boat_mer/README.md#wire).

## Tests

```bash
npm install && npm test
```

`npm test` runs `test/run.js` in Node.js and then in Bare: 47 checks each. The signatures must match ethers byte for byte (`test/vectors.json`, made by `test/gen-vectors.js`). A buyer on an in-memory stream signs the way MER's buyer does, and the seller must accept three slices, and refuse another wallet and another payee.

## Bare

Bare has no global `TextEncoder`, which `@noble/curves` needs as it loads. `lib/encoding.js` defines one from b4a, only where it is missing. noble 2.x is ES modules only; Node.js 22 and Bare both `require` them.
