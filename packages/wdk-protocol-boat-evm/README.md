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

**Gas is the catch.** On Arc a settlement cost about 2,200 micro-USDC of gas, and the board's slices are 3–4 micro-USDC each. Settling every slice on its own costs some 500 times the payment, so it only makes sense as a demo. A product settles in batches (Circle Gateway, which `examples/boat_mer` supports with its default domain), or has the device sign larger authorizations, for example one per session.
