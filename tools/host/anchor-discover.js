// Lists the anchor nodes of an OpenAnchor deployment: looks up the
// deployment's topic, then resolves and checks each node's DID record, the
// same way the board does (examples/boat_mer/main/anchor.c).
//
// usage: node anchor-discover.js <bootstrap host:port | public>
//          [--network arc-testnet | local] [--contract addr] [--chain-id n]

const HyperDHT = require('hyperdht')
const { NETWORKS, topic, verifyRecord, isAnchorNode } = require('./open-anchor')

const positional = []
const opts = {}
for (let i = 2; i < process.argv.length; i++) {
  const a = process.argv[i]
  if (a.startsWith('--')) opts[a.slice(2)] = process.argv[++i]
  else positional.push(a)
}
const [where = 'public'] = positional
const bootstrap = where === 'public' ? undefined : [where]
const network = NETWORKS[opts.network || 'arc-testnet']
const contract = opts.contract || network.contract
const chainId = Number(opts['chain-id'] || network.chainId)

async function main () {
  const dht = new HyperDHT({ bootstrap })
  await dht.fullyBootstrapped()
  const t = topic(chainId, contract)
  console.log(`DISCOVER|chain ${chainId} contract ${contract} topic ${t.toString('hex')}`)

  const started = Date.now()
  const keys = new Map()
  for await (const reply of dht.lookup(t)) {
    for (const peer of reply.peers) keys.set(peer.publicKey.toString('hex'), peer.publicKey)
  }
  console.log(`DISCOVER|announced=${keys.size} lookup_ms=${Date.now() - started}`)

  let valid = 0
  await Promise.all([...keys.values()].map(async (pk) => {
    const res = await dht.mutableGet(pk).catch(() => null)
    const r = res && verifyRecord(pk, res.value)
    const ok = isAnchorNode(r, chainId, contract)
    if (ok) valid++
    console.log(`DISCOVER|did:mw:${pk.toString('hex')} ${ok ? `ok wallet=${r.eth} fee=${r.fee} log=${r.log}` : r ? 'record for another service or deployment' : 'no valid record'}`)
  }))

  console.log(`DISCOVER|summary announced=${keys.size} valid=${valid}`)
  await dht.destroy()
}

main()
