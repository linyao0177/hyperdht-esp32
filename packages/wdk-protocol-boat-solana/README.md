# wdk-protocol-boat-solana

A BoAT MER device as a Solana signer for [WDK](https://docs.wdk.tether.io). The device holds USD₮ (or any SPL token) on Solana and no SOL; it signs transfers out of its own token account with a key that never leaves it, and a WDK Solana account pays the fee. On EVM chains the same device signs EIP-3009 authorizations ([wdk-protocol-boat-evm](../wdk-protocol-boat-evm)); this is the Solana side of it.

```js
import HyperDHT from 'hyperdht'
import WalletManagerSolana from '@tetherto/wdk-wallet-solana'
import BoatDeviceSignerSolana, { deviceTransferMessage } from 'wdk-protocol-boat-solana'

const device = await BoatDeviceSignerSolana.connect({ dht: new HyperDHT(), did: deviceDid, keyPair: ownerKeyPair })
const account = await new WalletManagerSolana(seed, { provider: rpc }).getAccount(0)
const message = await deviceTransferMessage({ device, mint: USDT, to: await account.getAddress(), amount: 1_500_000n, decimals: 6 })
const { hash } = await account.sendTransaction(message)   // signed by the device and by the account, which pays the fee
```

## The device's key

The device's Solana key is derived from its DID key, not the DID key itself, so a signature for one can never be taken for the other: `seed = BLAKE2b-256(key = DID seed, "boat-solana/1")`, an Ed25519 key pair ([`examples/boat_mer/main/solana.h`](../../examples/boat_mer/main/solana.h)). `deriveSolanaKeyPair(didSecretKey)` computes the same in JS; the tests check that both agree.

## What the device signs

`BoatDeviceSignerSolana` is a Solana Kit `TransactionPartialSigner`: `deviceTransferInstruction` puts it on a Token `transferChecked` instruction as the authority, and the WDK account that sends the message (which makes itself the fee payer) gets the device's signature with its own. The device answers over its owner channel (`sol_address`, `sol_transfer` in `examples/boat_mer/main/signer.c`, owner key `CONFIG_MER_OWNER_KEY`) and signs a message only when, checked on the device:

- the fee payer is someone else, and the device is a read-only signer (no SOL can leave it);
- the instructions are Token `transferChecked` with the device as authority, of the mint in `CONFIG_MER_SOL_MINT`, all to one destination, plus ComputeBudget ones;
- the total is at most `CONFIG_MER_SIGNER_MAX_VALUE` base units;
- legacy or v0 messages without address tables.

Every signature the device returns is checked against its key before it goes to the transaction.

## Tests

```bash
npm install && npm test
```

The device is emulated on a local HyperDHT testnet, its policy and signing done by the device's own C code (`examples/boat_mer/main/solana.c`, built for the desktop as `test/sol_host.c`); the chain is a local `solana-test-validator` with a 6-decimal SPL token standing in for USD₮; the fee payer is a WDK Solana account. Needs clang, libsodium and the Solana CLI. 13 of 13 (2026-11-08):

| | Result |
|---|---|
| The key derived in JS | The device's (C) |
| A 1.5 USD₮ transfer from the device | Signed on the device, the fee (10,000 lamports) paid by the WDK account; the device still has no SOL |
| Refused by the device | Over its limit; another mint; another program's instruction; paying the fee itself; its account writable |
| Another key as owner | Refused: the device sends it an attested reading instead |

[`examples/device-wallet.js`](examples/device-wallet.js) does it with a board (`CONFIG_MER_SOL_MINT`): 4 of 4 on the ESP32-C3 with a local validator (2026-11-08), a 0.1-token transfer signed on the device and its 10,000-lamport fee paid by the owner's WDK account, an over-limit transfer and another owner key refused. The transfer must fit `CONFIG_MER_SIGNER_MAX_VALUE` (100,000 base units by default).
