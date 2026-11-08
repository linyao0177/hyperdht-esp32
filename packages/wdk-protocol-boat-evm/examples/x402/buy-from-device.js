// Buys a device's attested readings with x402, paying from a WDK account.
//
// A standard x402 client (@x402/fetch with @x402/evm's exact scheme), whose
// signer is a WDK EVM account: it gets the device's 402, signs the EIP-3009
// authorization the device asks for, and retries. The device
// (CONFIG_MER_X402_SELL_PORT) checks it, has its facilitator settle it, and
// answers with the reading. The reading's signature is then checked against
// the device's DID.
//
// usage: node examples/x402/buy-from-device.js <url, e.g. http://192.168.31.20/reading>
//        <file with a WDK seed phrase, or JSON with "mnemonic"> [--account 0] [--count 3]
//        [--rpc url] [--chain-id 5042002] [--did did:mw:<the device>]
//        [--token 0x.. --max 10000]  (a token x402 does not know, e.g. USD₮0 on Stable)

import fs from 'fs'
import WDK from '@tetherto/wdk'
import WalletManagerEvm from '@tetherto/wdk-wallet-evm'
import { wrapFetchWithPayment, x402Client } from '@x402/fetch'
import { registerExactEvmScheme } from '@x402/evm/exact/client'
import boatPeer from 'boat-peer'

const { verifyReading } = boatPeer
const args = process.argv.slice(2)
const opt = (name, fallback) => {
  const i = args.indexOf('--' + name)
  return i >= 0 ? args[i + 1] : fallback
}
const [url, seedFile] = args
if (!url || !seedFile) {
  console.error('usage: node examples/x402/buy-from-device.js <url> <seed file> [--account 0] [--count 3]')
  process.exit(1)
}
const raw = fs.readFileSync(seedFile, 'utf8').trim()
const mnemonic = raw.startsWith('{') ? JSON.parse(raw).mnemonic : raw
const chainId = Number(opt('chain-id', 5042002))
const count = Number(opt('count', 3))
const log = (line) => console.log(`BUY|${line}`)

const wdk = new WDK(mnemonic).registerWallet('chain', WalletManagerEvm, { provider: opt('rpc', 'http://127.0.0.1:8549'), chainId })
const account = await wdk.getAccount('chain', Number(opt('account', 0)))
const signer = { address: account.address, signTypedData: (typed) => account.signTypedData(typed) }
// the client pays only assets it knows unless told: --token, at most --max units a reading
const client = opt('token')
  ? new x402Client().setSpendControls({ allowedAssets: [{ network: `eip155:${chainId}`, asset: opt('token'), maxAmountPerPayment: opt('max', '10000') }] })
  : new x402Client()
registerExactEvmScheme(client, { signer })
const pay = wrapFetchWithPayment(fetch, client)

let ok = 0
for (let i = 0; i < count; i++) {
  const t0 = Date.now()
  const res = await pay(url)
  const ms = Date.now() - t0
  if (res.status !== 200) {
    log(`#${i + 1} HTTP ${res.status} after ${ms} ms: ${(await res.text()).slice(0, 160)}`)
    continue
  }
  const receipt = JSON.parse(Buffer.from(res.headers.get('payment-response'), 'base64').toString())
  const text = await res.text()
  const reading = JSON.parse(text)
  // against the DID given, or else the one the reading names
  const v = verifyReading(opt('did', reading.did), text)
  if (v.ok) ok++
  log(`#${i + 1} paid in tx ${receipt.transaction}, reading ${reading.payload} from ${reading.did.slice(0, 23)}..., signature ${v.ok ? 'valid' : 'INVALID ' + JSON.stringify(v.checks)}, ${ms} ms`)
}
log(`${ok} of ${count} readings bought and verified, paid by ${account.address}`)
wdk.dispose()
process.exit(ok === count ? 0 : 1)
