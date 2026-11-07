// Checks a seller's receipts from scratch: replicates its receipts Hypercore
// by key from the swarm, then for every receipt recovers the EIP-3009 signer
// and compares it with the wallets in the buyer's and the seller's DID records,
// read from the DHT. Nothing of the seller's is trusted but the key.
//
// usage: node verify-receipts.js <receipts hypercore key hex> [seconds to wait for peers, default 60]

const fs = require('fs')
const os = require('os')
const path = require('path')
const Hyperswarm = require('hyperswarm')
const Corestore = require('corestore')
const { eth, resolveDid } = require('boat-peer')

const [keyHex, wait = '60'] = process.argv.slice(2)
if (!/^[0-9a-f]{64}$/.test(keyHex || '')) {
  console.error('usage: node verify-receipts.js <receipts hypercore key hex> [seconds]')
  process.exit(1)
}

async function main () {
  const store = new Corestore(fs.mkdtempSync(path.join(os.tmpdir(), 'boat-receipts-')))
  const core = store.get({ key: Buffer.from(keyHex, 'hex'), valueEncoding: 'json' })
  await core.ready()
  const swarm = new Hyperswarm()
  swarm.on('connection', (conn) => store.replicate(conn))
  const started = Date.now()
  swarm.join(core.discoveryKey, { client: true, server: false })
  await swarm.flush()
  await Promise.race([core.update({ wait: true }), new Promise((resolve) => setTimeout(resolve, Number(wait) * 1000))])
  const length = core.length // the seller may append more while this runs
  console.log(`VERIFY|replicated ${length} receipts in ${Date.now() - started} ms`)

  const records = new Map()
  const walletOf = async (did) => {
    if (!records.has(did)) {
      const res = await resolveDid(swarm.dht, did)
      records.set(did, res && res.record ? res.record.eth.toLowerCase() : null)
    }
    return records.get(did)
  }

  const nonces = new Set()
  let good = 0
  let micro = 0n
  for (let i = 0; i < length; i++) {
    const r = await core.get(i)
    const a = r.authorization
    let problem = null
    try {
      const signer = eth.verifyTransfer(r.domain, a, a.signature).toLowerCase()
      if (signer !== a.from.toLowerCase()) problem = 'signer is not from'
      else if (signer !== await walletOf(r.buyer)) problem = 'signer is not the buyer DID wallet'
      else if (a.to.toLowerCase() !== await walletOf(r.seller)) problem = 'payee is not the seller DID wallet'
      else if (nonces.has(a.nonce)) problem = 'nonce used twice'
    } catch (err) {
      problem = 'malformed: ' + err.message
    }
    nonces.add(a.nonce)
    if (problem) {
      console.log(`VERIFY|receipt #${i} slice ${r.slice} FAILED: ${problem}`)
    } else {
      good++
      micro += BigInt(a.value)
    }
  }
  console.log(`VERIFY|${good} of ${length} receipts valid, ${micro} micro-USDC, ${records.size} DID records read`)
  await swarm.destroy()
  await store.close()
}

main()
