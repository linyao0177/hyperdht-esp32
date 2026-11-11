// An MQTT node that charges per message (boat-mqtt-node, in xid-network) and settles
// what devices pay into a WDK EVM account, in Multicall3 batches.
//
// Devices (examples/boat_mer with CONFIG_MER_MQTT_NODE) read the node's terms
// from its DHT record, publish, get invoices in their inbox and pay them with
// EIP-3009 authorizations signed by MER. The node checks each against the
// device's DID record; this script settles them every --batch seconds in one
// transaction from WDK account 0, which is also the payee.
//
// usage: node examples/mqtt-node.js --rpc url --mnemonic-file f [--key node.json]
//        [--network boat-mqtt] [--chain-id 2201] [--token 0x78Cf..] [--token-name USD₮0]
//        [--token-version 1] [--price-msg 100] [--price-kb 1000] [--credit 20000]
//        [--invoice 10] [--batch 30] [--seconds 300] [--fund]
//
// --fund: anvil_setBalance the payee for gas, on a local fork.

import fs from 'fs'
import WDK from '@tetherto/wdk'
import WalletManagerEvm from '@tetherto/wdk-wallet-evm'
import BoatProtocolEvm, { registerBoat } from '../index.js'
// boat-mqtt-node is in xid-network (https://github.com/linyao0177/xid-network): a checkout next to this one
import { createNode } from '../../../../xid-network/packages/boat-mqtt-node/index.js'
import { loadKeyPair } from '../../../../xid-network/packages/boat-mqtt-node/lib/keyfile.js'

const args = process.argv.slice(2)
const opt = (name, fallback) => {
  const i = args.indexOf('--' + name)
  return i >= 0 ? args[i + 1] : fallback
}
const rpc = opt('rpc')
const mnemonicFile = opt('mnemonic-file')
if (!rpc || !mnemonicFile) {
  console.error('usage: node examples/mqtt-node.js --rpc url --mnemonic-file file [options]')
  process.exit(1)
}
const cfg = {
  chainId: Number(opt('chain-id', 2201)),
  token: opt('token', '0x78Cf24370174180738C5B8E352B6D14c83a6c9A9'),
  tokenName: opt('token-name', 'USD₮0'),
  tokenVersion: opt('token-version', '1')
}
const batchS = Number(opt('batch', 30))
const log = (line) => console.log('PAIDNODE|' + new Date().toISOString().slice(11, 19) + ' ' + line)
const short = (k) => k.slice(0, 12) + '…'

const wdk = new WDK(fs.readFileSync(mnemonicFile, 'utf8').trim()).registerWallet('chain', WalletManagerEvm, { provider: rpc })
registerBoat(wdk, 'chain', cfg)
const account = await wdk.getAccount('chain', 0)
const boat = await BoatProtocolEvm.create(account, cfg)
if (args.includes('--fund')) {
  await fetch(rpc, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'anvil_setBalance', params: [boat.address, '0x' + (10n ** 20n).toString(16)] }) })
}
const balance = async () => BigInt(await account.getTokenBalance(cfg.token))
const before = await balance()

const node = await createNode({
  keyPair: loadKeyPair(opt('key', 'node.json')),
  network: opt('network', undefined),
  billing: {
    price: { message: opt('price-msg', 100), kb: opt('price-kb', 1000) },
    credit: opt('credit', 20000),
    payee: boat.address,
    token: cfg.token,
    chainId: cfg.chainId,
    domain: { name: cfg.tokenName, version: cfg.tokenVersion },
    invoiceMs: Number(opt('invoice', 10)) * 1000
  }
})
log(`node ${node.publicKey.toString('hex')} on "${node.network}", payee ${boat.address} holds ${before}`)
log(`terms ${JSON.stringify(node.billing.terms())}`)

node.on('client', (c) => log(`+ ${c.key ? 'key ' + short(c.key) : 'tcp ' + c.user}`))
node.on('clientDisconnect', (c) => log(`- ${c.key ? 'key ' + short(c.key) : 'tcp ' + c.user}`))
node.on('refused', (r) => log(`REFUSED ${r.client.key ? short(r.client.key) : r.client.user} -> ${r.topic}: ${r.reason}`))
node.billing.on('invoice', (i) => log(`INVOICE ${i.invoice} to ${short(i.key)}: owed ${i.owed}, paid ${i.paid}, due ${i.due}`))
node.billing.on('payment-refused', (r) => log(`PAYMENT REFUSED from ${short(r.key)}: ${r.reason}`))

const queued = []
const totals = { payments: 0, settled: 0, failed: 0, batches: 0 }
node.billing.on('payment', (p) => {
  totals.payments++
  queued.push(p.authorization)
  log(`PAYMENT from ${short(p.key)} for invoice ${p.invoice}: ${p.authorization.value} (owed ${p.owed}, paid ${p.paid})`)
})

let busy = false
async function flush () {
  if (busy || queued.length === 0) return
  busy = true
  const items = queued.splice(0)
  try {
    const b = await boat.settleBatch(items)
    const r = b.hash ? await boat.waitForBatch(b) : { settled: [], gasUsed: 0n }
    totals.batches++
    totals.settled += r.settled.length
    totals.failed += items.length - r.settled.length
    log(`SETTLED BATCH of ${items.length}: ${r.settled.length} settled, ${b.skipped.length} skipped, ${r.gasUsed} gas, tx ${r.tx || b.hash}`)
  } catch (err) {
    totals.failed += items.length
    log(`BATCH FAILED (${items.length}): ${err.shortMessage || err.message}`)
  } finally {
    busy = false
  }
}
setInterval(flush, batchS * 1000)

setTimeout(async () => {
  while (busy) await new Promise((resolve) => setTimeout(resolve, 200))
  await flush()
  const after = await balance()
  log(`accounts ${JSON.stringify(node.billing.summary())}`)
  log(`${totals.payments} payments, ${totals.settled} settled in ${totals.batches} batches, ${totals.failed} failed; the payee got ${after - before}`)
  await node.close()
  process.exit(totals.payments > 0 && totals.failed === 0 && after > before ? 0 : 1)
}, Number(opt('seconds', 300)) * 1000)
