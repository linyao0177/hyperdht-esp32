# wdk-protocol-boat-evm

BoAT MER devices for [WDK](https://docs.wdk.tether.io), Tether's Wallet Development Kit. A WDK EVM account can sell to ESP32-class devices running BoAT MER over Holepunch, settle their EIP-3009 payments on-chain, and act as an x402 facilitator.

WDK runs where Bare runs: phones, desktops, servers and Linux-class devices. BoAT MER runs on microcontrollers. Each device signs an EIP-3009 `TransferWithAuthorization` for every slice it pays for; this module lets a WDK account take the other side. It works in Node.js and in Bare, so in Pear apps too ([`apps/pear-seller`](../../apps/pear-seller)).

```js
import WDK from '@tetherto/wdk'
import WalletManagerEvm from '@tetherto/wdk-wallet-evm'
import { registerBoat } from 'wdk-protocol-boat-evm'

const wdk = new WDK(seedPhrase).registerWallet('arc', WalletManagerEvm, { provider: rpc, chainId: 5042002 })
registerBoat(wdk, 'arc', { token: '0x3600000000000000000000000000000000000000', chainId: 5042002, tokenName: 'USDC', tokenVersion: '2' })

const account = await wdk.getAccount('arc', 0)
const boat = account.getBoatProtocol()

await boat.publishDidRecord(swarm.dht, keyPair)       // the seller's DID record, signed by the WDK account
const seller = boat.seller({ rate: 250000, power: () => watts })
seller.on('payment', async (p) => {
  if (!p.ok) return
  const { hash } = await boat.settle(p.authorization)   // transferWithAuthorization, gas paid by the account
  await boat.waitForSettlement(hash)
})
swarmForTheSellerDid.on('connection', (conn) => seller.serve(conn, swarm.dht))
```

WDK's protocol types are swap, bridge, lending, fiat, swidge and sda, and `wdk.registerProtocol` ignores a class that is none of them. So `registerBoat` adds `account.getBoatProtocol()` with `wdk.registerMiddleware` instead. Without WDK core, `new BoatProtocolEvm(account, config)` takes any `@tetherto/wdk-wallet-evm` account.

## API

| | |
|---|---|
| `registerBoat(wdk, blockchain, { token, chainId, tokenName, tokenVersion })` | Adds `getBoatProtocol()` to that blockchain's accounts. `tokenName` and `tokenVersion` are the token's own EIP-712 domain, which differs per chain: `USDC`/`2` on Circle's testnets, `USD₮0`/`1` on Stable |
| `boat.domain` | The domain devices must sign under (configure `examples/boat_mer` with `CONFIG_MER_BUYER_DOMAIN_NAME`, `_VERSION` and `_VERIFYING_CONTRACT`) |
| `boat.didRecord(publicKey)`, `boat.publishDidRecord(dht, keyPair)` | The seller's DID record `{v, did, eth, eth_sig}`, with the account as its wallet and its EIP-191 signature |
| `boat.seller(options)` | A [boat-peer](../boat-peer) `Seller` that bills devices to the account under the token's domain |
| `boat.settle(authorization)` | Calls the token's `transferWithAuthorization` from the account. Settlements are queued one at a time, so payments that arrive together don't race for the account's nonce |
| `boat.waitForSettlement(hash)`, `boat.isSettled(from, nonce)` | The receipt, and the token's `authorizationState` |
| `boat.x402FacilitatorSigner()` | An `@x402/evm` `FacilitatorEvmSigner` backed by the account (Node.js; it uses ethers for ABI encoding). Overloaded functions such as USDC's two `transferWithAuthorization` are picked by argument count |

## The device as a WDK signer

`BoatDeviceSignerEvm` is a WDK EVM signer whose key stays on the device, the way a Ledger signer's key stays on the Ledger. The owner's app reaches the device by its DID over HyperDHT, authenticated with the owner's Ed25519 key, which the device trusts through `CONFIG_MER_OWNER_KEY` ([`examples/boat_mer/main/signer.c`](../../examples/boat_mer/main/signer.c)).

```js
import HyperDHT from 'hyperdht'
import { WalletAccountEvm } from '@tetherto/wdk-wallet-evm'
import { BoatDeviceSignerEvm } from 'wdk-protocol-boat-evm'

const signer = await BoatDeviceSignerEvm.connect({ dht: new HyperDHT(), did: deviceDid, keyPair: ownerKeyPair })
const device = new WalletAccountEvm(signer, { provider, chainId })
await device.getTokenBalance(token)                        // read from the chain as usual
const sig = await device.signTypedData({ domain, types, message: transferWithAuthorization })   // signed on the device
await ownerAccount.getBoatProtocol().settle({ ...transferWithAuthorization, signature: sig })   // the owner pays the gas
```

The device signs EIP-191 messages and one kind of typed data: EIP-3009 `TransferWithAuthorization` from its own address, up to `CONFIG_MER_SIGNER_MAX_VALUE` per authorization and valid for at most 7 days. It signs no transactions, so it never needs gas. `keyPair` is `{ privateKey: null, publicKey: null }`, and every signature the device returns is checked against its address before WDK gets it.

[`examples/device-wallet.js`](examples/device-wallet.js) on the board (Arc testnet, 2026-11-07), 8 of 8:

| | Result |
|---|---|
| WDK account with the device as its signer | Address `0x6fA1…2308`, the board's wallet; connected by DID in 4.1 s |
| Message (EIP-191) | Signed on the device in 0.39 s, 0.5 s round trip |
| Sweep 0.05 USDC to the owner's WDK account | Signed on the device in 0.39 s; the owner's account submitted it, and the device's balance went from 99,841 to 49,841 units |
| Over the device's limit (`CONFIG_MER_SIGNER_MAX_VALUE`) | Refused by the device |
| Other typed data, a transaction | Refused by the signer before reaching the device |
| Another key connecting as owner | The device sends it an attested reading instead, and the signer reports it is not the owner |

## Tests

```bash
npm install && npm test
```

10 checks. With Foundry installed, the test starts anvil and deploys a minimal EIP-3009 token (`tests/fixtures/TestToken3009.sol`) under a `USD₮0`/`1` domain. A WDK account then settles three authorizations signed the way MER signs them. A second settlement of the same authorization and a changed amount must both be refused by the token.

## x402 example

[`examples/x402/server.js`](examples/x402/server.js) is an x402 v2 resource server. Its facilitator (`@x402/core` and `@x402/evm` 2.30) verifies and settles payments with a WDK account through `x402FacilitatorSigner()`. It answers 402 with the requirements in the `PAYMENT-REQUIRED` header and in the body, because BoAT MER's x402 client reads the body. The requirements' `extra` carries `verifyingContract`, which MER needs to pick the token domain.

[`examples/x402/mer-client`](examples/x402/mer-client) is BoAT MER's own x402 client (`boat_x402_pay`), built on a computer against a BoAT MER checkout:

```bash
cmake -S examples/x402/mer-client -B build -DBOAT_MER_DIR=<boat-mer> -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)
cmake --build build --target mer_x402_client
node examples/x402/server.js <seed phrase file> --rpc <url> &
HOME=<test dir> build/mer_x402_client http://127.0.0.1:4021/reading
```

## Results (2026-11-07, Arc testnet, USDC)

USDC on the Arc testnet (`0x3600…0000`) implements EIP-3009 under the domain `USDC`/`2`; this was checked with `eth_call` and by settling. The demo addresses were funded with 1.7 test USDC from one of the anchor nodes' test wallets.

| | Result |
|---|---|
| Device payments settled by a WDK account in a Pear app | 41 of 41 settled from `apps/pear-seller` (Bare) over two runs, 0 failed. In the first run (32, across 5 paying sessions of the board) bill to settled took 6.2–15.1 s, median 8.1 s, including the queue |
| Checked again from the log | `verify-receipts.js --rpc`, run between the two, found all 32 settlements logged so far used on-chain (`authorizationState`) |
| x402: BoAT MER's C client to the WDK facilitator | 3 of 3 paid and settled, 8–15 s each. A price over the client's limit was refused by MER before signing |
| Balances | The board paid 159 micro-USDC; the x402 client paid 3 × 1000. Gas came to about 2,180 micro-USDC per settlement for the seller's account and 2,290 for the facilitator's |

The board itself, too: with `CONFIG_MER_X402_URL` set, `examples/boat_mer` calls the server every 30 s from a task of its own, after SNTP has set its clock. 4 of 4 calls were paid and settled, 10.4–15.0 s each, most of it waiting for the facilitator's transaction; the task's 12 KB stack peaked at about 4 KB, with 115–121 KB of heap free.

MER keeps the EIP-712 domain in one global (`boat_pay_set_domain_ext`, then `boat_pay_authorize`), so two tasks signing at once can sign under each other's domain. The x402 run had the buyer and anchoring off for that reason. MER should take the domain per call.

**Gas is the catch.** On Arc a settlement cost about 2,200 micro-USDC of gas, and the board's slices are 3–4 micro-USDC each. Settling every slice on its own costs some 500 times the payment, so it only makes sense as a demo. A product settles in batches (Circle Gateway, which `examples/boat_mer` supports with its default domain), or has the device sign larger authorizations, for example one per session.
