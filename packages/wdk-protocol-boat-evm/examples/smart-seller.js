// Sells power to BoAT MER devices into a WDK ERC-4337 account (a Safe).
//
// A Safe cannot sign, so the seller's DID record names it in "pay", vouched
// for by the Safe's owner key; a device that reads the record pays the Safe
// and refuses to pay anyone else. Each payment is settled as a user operation
// through the bundler. Same seller as apps/pear-seller, other wallet: give it
// that app's identity file to keep its DID.
//
// usage: node examples/smart-seller.js <identity JSON with "seed" (hex) and "mnemonic">
//        --rpc url --bundler url [--chain-id 2201] [--token 0x78Cf..] [--token-name USD₮0]
//        [--token-version 1] [--seconds 120] [--batch 20] [--fund]
//
// --batch <s>: settle what came in every so many seconds in one user operation
// (the Safe calls the token once per payment, through MultiSend); without it
// each payment is a user operation of its own, one at a time.
// --fund: anvil_setBalance the Safe, for a local fork.

import fs from 'fs'
import HyperDHT from 'hyperdht'
import WDK from '@tetherto/wdk'
import WalletManagerEvmErc4337 from '@tetherto/wdk-wallet-evm-erc-4337'
import boatPeer from 'boat-peer'
import BoatProtocolEvm, { registerBoat } from '../index.js'

const { didOf, payeeOf } = boatPeer
const args = process.argv.slice(2)
const opt = (name, fallback) => {
  const i = args.indexOf('--' + name)
  return i >= 0 ? args[i + 1] : fallback
}
const file = args[0]
const rpc = opt('rpc')
const bundlerUrl = opt('bundler')
if (!file || !rpc || !bundlerUrl) {
  console.error('usage: node examples/smart-seller.js <identity file> --rpc url --bundler url')
  process.exit(1)
}
const cfg = {
  chainId: Number(opt('chain-id', 2201)),
  token: opt('token', '0x78Cf24370174180738C5B8E352B6D14c83a6c9A9'),
  tokenName: opt('token-name', 'USD₮0'),
  tokenVersion: opt('token-version', '1')
}
const seconds = Number(opt('seconds', 120))
const batch = Number(opt('batch', 0))
const RATE = 250000 // micro-units per kWh, as in apps/pear-seller
const log = (line) => console.log('SMART|' + line)

const id = JSON.parse(fs.readFileSync(file, 'utf8'))
const keyPair = HyperDHT.keyPair(Buffer.from(id.seed, 'hex'))
const did = didOf(keyPair.publicKey)

const wdk = new WDK(id.mnemonic).registerWallet('chain', WalletManagerEvmErc4337, {
  chainId: cfg.chainId, provider: rpc, bundlerUrl, safeModulesVersion: '0.3.0', useNativeCoins: true
})
registerBoat(wdk, 'chain', cfg)
const account = await wdk.getAccount('chain', 0)
const boat = await BoatProtocolEvm.create(account, cfg)
const safe = boat.address
if (args.includes('--fund')) {
  await fetch(rpc, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'anvil_setBalance', params: [safe, '0x' + (10n ** 20n).toString(16)] }) })
}
const balance = async () => BigInt(await account.getTokenBalance(cfg.token))

const dht = new HyperDHT()
const r = await boat.publishDidRecord(dht, keyPair)
log(`seller ${did}`)
log(`DID record published on ${r.nodes} nodes (seq ${r.seq}): eth ${r.record.eth} (owner), pay ${payeeOf(r.record)} (Safe)`)
const before = await balance()
log(`Safe ${safe} holds ${before}`)

const seller = boat.seller({ rate: RATE, power: () => 12, settle: 'slice' })
const totals = { verified: 0, refused: 0, settled: 0, failed: 0 }
seller.on('record', (e) => log(`buyer DID record ${e.valid ? 'valid' : 'INVALID'}, wallet ${e.eth}`))
seller.on('payment', async (p) => {
  if (!p.ok) {
    totals.refused++
    log(`REFUSED slice ${p.slice}: ${p.reason}`)
    return
  }
  totals.verified++
  log(`VERIFIED slice ${p.slice}: ${p.authorization.value} to ${p.authorization.to} from ${p.signer}`)
  if (batch) return queued.push(p.authorization)
  try {
    const { hash } = await boat.settle(p.authorization)
    const r = await boat.waitForSettlement(hash)
    r.ok ? totals.settled++ : totals.failed++
    log(`${r.ok ? 'SETTLED' : 'REVERTED'} slice ${p.slice} as a user operation, ${r.gasUsed} gas, bundle tx ${r.tx}`)
  } catch (err) {
    totals.failed++
    log(`SETTLEMENT FAILED slice ${p.slice}: ${err.shortMessage || err.message}`)
  }
})

// with --batch: what came in, in one user operation
const queued = []
async function flush () {
  if (queued.length === 0 || flush.busy) return
  flush.busy = true
  const items = queued.splice(0)
  try {
    const b = await boat.settleBatch(items)
    const r = b.hash ? await boat.waitForBatch(b) : { settled: [], gasUsed: 0n }
    totals.settled += r.settled.length
    totals.failed += items.length - r.settled.length
    log(`SETTLED BATCH of ${items.length} in one user operation: ${r.settled.length} settled, ${b.skipped.length} skipped, ${r.gasUsed} gas, bundle tx ${r.tx || b.hash}`)
  } catch (err) {
    totals.failed += items.length
    log(`BATCH SETTLEMENT FAILED (${items.length}): ${err.shortMessage || err.message}`)
  } finally {
    flush.busy = false
  }
}
if (batch) setInterval(flush, batch * 1000)

const conns = new Set()
const server = dht.createServer((conn) => {
  conns.add(conn)
  conn.on('close', () => conns.delete(conn))
  seller.serve(conn, dht)
})
await server.listen(keyPair)

setTimeout(async () => {
  await server.close() // no new payments, then settle what came in
  for (const conn of conns) conn.destroy()
  while (flush.busy) await new Promise((resolve) => setTimeout(resolve, 200))
  await flush()
  const after = await balance()
  log(`${totals.verified} verified, ${totals.refused} refused, ${totals.settled} settled, ${totals.failed} failed; the Safe got ${after - before}`)
  await dht.destroy()
  process.exit(totals.verified > 0 && totals.failed === 0 && after > before ? 0 : 1)
}, seconds * 1000)
