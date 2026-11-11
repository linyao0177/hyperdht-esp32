# wdk-protocol-boat-evm

BoAT MER devices for [WDK](https://docs.wdk.tether.io), Tether's Wallet Development Kit. A WDK EVM account can sell to ESP32-class devices running BoAT MER over Holepunch, settle their EIP-3009 payments on-chain one at a time or in batches, do so from an ERC-4337 smart account whose gas an operator sponsors, and act as an x402 facilitator, including for devices that sell with x402 themselves.

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

WDK's protocol types are swap, bridge, lending, fiat, swidge and sda, and `wdk.registerProtocol` ignores a class that is none of them. So `registerBoat` adds `account.getBoatProtocol()` with `wdk.registerMiddleware` instead. Without WDK core, `new BoatProtocolEvm(account, config)` takes any `@tetherto/wdk-wallet-evm` account, and `await BoatProtocolEvm.create(account, config)` an `@tetherto/wdk-wallet-evm-erc-4337` one too (a smart account knows its address only asynchronously).

**With WDK transaction policies**, build the protocol on the governed account, `new BoatProtocolEvm(await wdk.getAccount(...), config)`: its settlements (`sendTransaction`) and DID records (`sign`) are then policy-checked, and reads go through `toReadOnlyAccount()`, which the policy proxy allows. `getBoatProtocol()` is denied by the policy proxy unless listed (`new WDK(seed, { policyExclusions: ['getBoatProtocol'] })`), and the protocol it returns runs on the raw account, so its writes are not policy-checked, as with WDK's own `wdk.registerProtocol`. The tests cover all three on anvil.

## API

| | |
|---|---|
| `registerBoat(wdk, blockchain, { token, chainId, tokenName, tokenVersion })` | Adds `getBoatProtocol()` to that blockchain's accounts. `tokenName` and `tokenVersion` are the token's own EIP-712 domain, which differs per chain: `USDC`/`2` on Circle's testnets, `USD₮0`/`1` on Stable |
| `boat.domain` | The domain devices must sign under (configure `examples/boat_mer` with `CONFIG_MER_BUYER_DOMAIN_NAME`, `_VERSION` and `_VERIFYING_CONTRACT`) |
| `boat.didRecord(publicKey)`, `boat.publishDidRecord(dht, keyPair)` | The seller's DID record `{v, did, eth, eth_sig}`, with the account as its wallet and its EIP-191 signature |
| `boat.seller(options)` | A [boat-peer](../boat-peer) `Seller` that bills devices to the account under the token's domain |
| `boat.settle(authorization)` | Calls the token's `transferWithAuthorization` from the account. Settlements are queued one at a time, so payments that arrive together don't race for the account's nonce |
| `boat.settleBatch(authorizations)`, `boat.waitForBatch(batch)` | Many authorizations in one transaction, through Multicall3 (one user operation for a smart account). Simulated first: authorizations the token would refuse are left out and returned in `skipped`. `waitForBatch` tells which were settled, by the token's `authorizationState` |
| `boat.waitForSettlement(hash)`, `boat.isSettled(from, nonce)` | `{ ok, block, gasUsed, fee }` (a smart account's own share), and the token's `authorizationState` |
| `createSponsor({ operator, paymaster, chainId, token, sellers })` from `wdk-protocol-boat-evm/paymaster` | An ERC-7677 paymaster service that pays smart-account sellers' settlement gas from an operator's deposit (below) |
| `x402FacilitatorSigner(account)` from `wdk-protocol-boat-evm/x402` | An `@x402/evm` `FacilitatorEvmSigner` backed by the account. Node.js only (it uses ethers for ABI encoding), so it is a separate entry and Bare apps that bundle the main module do not pull in ethers. Overloaded functions such as USDC's two `transferWithAuthorization` are picked by argument count |

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

## Batch settlement

`settleBatch` submits many authorizations, from many devices, in one transaction: Multicall3's `aggregate3` calls the token's `transferWithAuthorization` for each, so the 21,000 gas every transaction costs is paid once. Anyone may call `transferWithAuthorization`, so the token does not mind who submits them. Each call may fail on its own inside the batch; the batch is simulated first and authorizations that would fail are left out. Its gas is estimated with failures disallowed: estimated as sent, the lowest gas that does not revert is one at which the transfers run out of gas inside a batch that itself succeeds (seen on the fork before the fix: a batch of one "succeeded" and settled nothing). A batch of one is sent as a plain settlement, which is cheaper.

On a fork of the Stable testnet, with the real USD₮0 contract, 2026-11-08:

| Authorizations | Gas each, alone | Gas each, in a batch | USD₮0 each at 11.25 gwei |
|---|---|---|---|
| 5 | 87,506 | 50,985 (42% less) | 984 → 574 µ |
| 10 | 87,510 | 45,636 (48% less) | 984 → 513 µ |
| 20 | 87,502 | 42,973 (51% less) | 984 → 483 µ |
| 50 | 87,504 | 41,374 (53% less) | 984 → 465 µ |

With session settlement (one authorization per paying session, boat-peer `settle: 'session'`) and batches, a seller pays roughly 0.0005 USD₮0 of gas per session. `apps/pear-seller --settle --batch <seconds>` settles this way.

## An MQTT node paid per message

[`examples/mqtt-node.js`](examples/mqtt-node.js) runs an MQTT node of [`boat-mqtt-node`](https://github.com/linyao0177/xid-network/tree/main/packages/boat-mqtt-node) (in xid-network; check it out next to this repository) that charges per message. Devices (`examples/boat_mer` with `CONFIG_MER_MQTT_NODE`) pay its invoices with EIP-3009 authorizations, and the node checks each one against the device's DID record. This script settles them from WDK account 0, which is also the payee, with `settleBatch` every `--batch` seconds. On a Stable testnet fork with the board (2026-11-08), 29 of 29 payments were settled in 10 batches, with the device's count equal to the node's ([results](../../examples/boat_mer/README.md#mqtt-paid-per-message-2026-11-08)).

```bash
node examples/mqtt-node.js --rpc http://127.0.0.1:8550 --mnemonic-file wdk.txt --network boat-mqtt-paid --batch 30 --fund
```

## ERC-4337 smart accounts and sponsored gas

A seller can be paid to, and settle from, a WDK ERC-4337 account (`@tetherto/wdk-wallet-evm-erc-4337`, a Safe with the 4337 module). Settlements are then user operations, and a batch is one user operation of several calls (the Safe's MultiSend, all or none).

A contract cannot sign as itself, so the seller's DID record names it apart, vouched for by the Safe's owner key: `{"v":1,"did","eth":"<owner>","pay":"<Safe>","eth_sig"}`, with `eth_sig` over `"<did>\npay:<Safe>"`. Devices pay the `pay` address ([boat-peer](../boat-peer), and `verify_record` in `examples/boat_mer`). A verifier that does not know `pay` refuses such a record rather than pay the owner key.

The seller's account then needs no gas if an operator sponsors it: [`paymaster.js`](paymaster.js) is an ERC-7677 paymaster service (`pm_getPaymasterStubData`, `pm_getPaymasterData`, what WDK asks for with `isSponsored` and `paymasterUrl`) in front of eth-infinitism's `VerifyingPaymaster` for EntryPoint v0.7. It signs only user operations from the operator's sellers that do nothing but settle the token to the sender itself, so its deposit pays for nothing else. Its signer is the operator's WDK account.

```js
import { createSponsor } from 'wdk-protocol-boat-evm/paymaster'
const sponsor = createSponsor({ operator, paymaster, chainId, token, sellers: [sellerSafe] })
await sponsor.listen(4338)   // the sellers' WDK config: { isSponsored: true, paymasterUrl: 'http://…:4338', bundlerUrl, … }
```

`npm run test:aa` forks the Stable testnet (EntryPoint v0.7, the Safe 4337 modules and USD₮0 are all deployed there), runs Pimlico's alto bundler against the fork, and checks it, 14 of 14 (2026-11-08):

| | Result |
|---|---|
| Settling from a WDK Safe | First user operation 510,177 gas (it deploys the Safe), then 177,825; 5 in one user operation 76,246 each |
| A seller Safe with no gas, sponsored | Settled, its balance still 0; a sponsored batch of 3 too, paid from the operator's deposit |
| Refused by the sponsor | A user operation moving the token out; a Safe that is not one of its sellers |
| The service's paymaster hash | Equal to the contract's `getHash` |

On the board (2026-11-08, `examples/boat_mer` and the fork): [`examples/smart-seller.js`](examples/smart-seller.js) took over the Pear seller's DID with a Safe as its wallet. The board paid the Safe once it had read the new record, and the seller settled every payment as a user operation, 10 of 10 batched every 20 s (4 payments in one user operation: 336,350 gas). Two things it showed, now fixed: a smart account's user operations went out back to back, so the second one (built while the first was still deploying the Safe) was refused by the bundler; `settle` now sends the next only once the last is included. And one at a time they cannot keep up with a slice every 5 s, which is what `--batch` is for.

A smart account costs about twice an EOA's gas per settlement, so it is for sellers who should hold no gas, not for saving it. On Stable the native coin is USD₮0, so even unsponsored a Safe pays its gas from the USD₮0 it is paid.

## A device that sells with x402

With `CONFIG_MER_X402_SELL_PORT`, `examples/boat_mer` sells its attested readings over HTTP: `GET /reading` answers 402 with x402 v2 requirements, paid to the device's own address. The device checks a payment itself (payee, price, validity, and the EIP-712 signature recovered with MER's secp256k1, `main/x402_check.c`) and has a facilitator settle it before it answers, so it needs no gas. [`examples/x402/facilitator.js`](examples/x402/facilitator.js) is such a facilitator (`/verify`, `/settle`, `/supported`), a WDK account paying the gas; [`examples/x402/buy-from-device.js`](examples/x402/buy-from-device.js) buys with a standard x402 client (`@x402/fetch`) whose signer is a WDK account.

`npm run test:x402-device` runs it end to end on anvil, the device emulated over HTTP but its payment checks done by its C code (`X402_HOST`, `examples/boat_mer/test/x402_host.c` built for the desktop against MER), 8 of 8: 3 readings bought, the facilitator's account paying the gas and the device none; a replayed payment, less than the price, a payment to someone else and one not signed by its payer refused. Settling payments back to back also showed that `x402FacilitatorSigner` reused a stale nonce; it now sends one transaction at a time and retries, as `settle` does.

## Tests

```bash
npm install && npm test        # anvil: 19 checks
npm run test:aa                # a Stable testnet fork and a local bundler: 14
npm run test:x402-device       # anvil: 8
```

`npm test` has 19 checks. With Foundry installed, the test starts anvil and deploys a minimal EIP-3009 token (`tests/fixtures/TestToken3009.sol`) under a `USD₮0`/`1` domain. A WDK account then settles three authorizations signed the way MER signs them. A second settlement of the same authorization and a changed amount must both be refused by the token. Three more check WDK policies: a governed protocol settles under a policy that allows the token, is blocked by one that denies transactions, and the middleware's protocol is not policy-checked. Six check batches: the call data against ethers, 10 in one transaction (37% less gas than one by one on this token), used and forged authorizations left out, a batch of one, and a chain without Multicall3.

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

MER v1.0.1 keeps the EIP-712 domain in one global (`boat_pay_set_domain_ext`, then `boat_pay_authorize`), so two tasks signing at once can sign under each other's domain. The first x402 run had the buyer and anchoring off for that reason; [`patches/boat-mer`](../../patches/boat-mer) fixes it, and with it all of them ran together ([results](../../examples/boat_mer/README.md#the-device-pays-an-x402-api-2026-11-07)).

**Gas is the catch.** On Arc a settlement cost about 2,200 micro-USDC of gas, and the board's slices are 3–4 micro-USDC each. Settling every slice on its own costs some 500 times the payment, so it only makes sense as a demo. A product settles in batches (`settleBatch` above, or Circle Gateway, which `examples/boat_mer` supports with its default domain), or has the device sign larger authorizations, for example one per session; both together bring it to a few hundred micro-units per session.
