// Checks a seller's receipts from scratch: replicates its receipts Hypercore
// by key from the swarm, then for every receipt recovers the EIP-3009 signer
// and compares it with the wallets in the buyer's and the seller's DID records,
// read from the DHT. Nothing of the seller's is trusted but the key.
// With --rpc, it also asks the token on-chain whether each authorization was
// used (authorizationState), so settlements the log claims can be checked too.
//
// usage: node verify-receipts.js <receipts hypercore key hex> [seconds to wait for peers, default 60] [--rpc url]

const fs = require('fs')
const os = require('os')
const path = require('path')
const Hyperswarm = require('hyperswarm')
const Corestore = require('corestore')
const { eth, resolveDid, verifyRecordVersion } = require('boat-peer')

const rpcAt = process.argv.indexOf('--rpc')
const rpc = rpcAt > 0 ? process.argv[rpcAt + 1] : null
const [keyHex, wait = '60'] = process.argv.slice(2).filter((a, i, all) => a !== '--rpc' && all[i - 1] !== '--rpc')
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

  // whether the token has used an authorization's nonce
  const used = async (token, from, nonce) => {
    const data = '0xe94a0102' + from.slice(2).toLowerCase().padStart(64, '0') + nonce.slice(2).toLowerCase()
    const res = await fetch(rpc, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_call', params: [{ to: token, data }, 'latest'] }) })
    return BigInt((await res.json()).result) !== 0n
  }

  const entries = []
  for (let i = 0; i < length; i++) entries.push(await core.get(i))
  const settlements = new Map() // receipt index -> settlement entry
  for (const e of entries) if (e.type === 'settlement') settlements.set(e.receipt, e)

  // the seller's DID record as the log last recorded it, when the log keeps
  // signed versions; otherwise the record now in the DHT
  const logged = new Map() // did -> wallet
  let versions = 0
  const nonces = new Set()
  let receipts = 0
  let good = 0
  let micro = 0n
  let claimed = 0
  let onChain = 0
  for (let i = 0; i < length; i++) {
    const r = entries[i]
    if (r.type === 'settlement') continue
    if (r.type === 'did-record') {
      const rec = verifyRecordVersion(r.did, r)
      if (rec) {
        logged.set(r.did, rec.eth.toLowerCase())
        versions++
      } else {
        console.log(`VERIFY|entry #${i}: a DID record version that does not verify`)
      }
      continue
    }
    receipts++
    const a = r.authorization
    let problem = null
    try {
      const signer = eth.verifyTransfer(r.domain, a, a.signature).toLowerCase()
      if (signer !== a.from.toLowerCase()) problem = 'signer is not from'
      else if (signer !== await walletOf(r.buyer)) problem = 'signer is not the buyer DID wallet'
      else if (logged.has(r.seller) ? a.to.toLowerCase() !== logged.get(r.seller) : a.to.toLowerCase() !== await walletOf(r.seller)) {
        problem = logged.has(r.seller) ? "payee is not the wallet in the seller's DID record logged before it" : "payee is not the wallet in the seller's current DID record (the log has no earlier version)"
      }
      else if (nonces.has(a.nonce)) problem = 'nonce used twice'
    } catch (err) {
      problem = 'malformed: ' + err.message
    }
    nonces.add(a.nonce)
    if (problem) {
      console.log(`VERIFY|receipt #${i} slice ${r.slice} FAILED: ${problem}`)
      continue
    }
    good++
    micro += BigInt(a.value)
    const s = settlements.get(i)
    if (s && s.ok) claimed++
    if (rpc && s && s.ok) {
      if (await used(r.domain.verifyingContract, a.from, a.nonce)) onChain++
      else console.log(`VERIFY|receipt #${i}: the log says settled in ${s.tx}, but the token has not used the authorization`)
    }
  }
  console.log(`VERIFY|${good} of ${receipts} receipts valid, ${micro} micro-USDC, ${records.size} DID records read, ${versions} logged DID record versions`)
  if (claimed) console.log(`VERIFY|${claimed} logged as settled${rpc ? `, ${onChain} of them used on-chain` : ' (add --rpc to check on-chain)'}`)
  await swarm.destroy()
  await store.close()
}

main()
