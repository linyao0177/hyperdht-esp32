// An open anchoring node: what a HashAnchor server does, as a peer anyone can
// run (examples/boat_mer, "Distributed anchoring").
//
// - Devices connect to it over HyperDHT by its key. The stream authenticates
//   the device's DID, so there is no API key.
// - Each submission is a 32-byte data hash, the device's Ed25519 signature of
//   it, and an EIP-3009 payment of the node's fee, signed by the wallet in the
//   device's DID record. Payments are verified, not settled.
// - Every --batch seconds the node builds a Merkle tree that HashAnchor's
//   public verifier accepts (keccak256, sorted pairs) and anchors the root in
//   the permissionless OpenAnchor contract from its own wallet.
// - The leaf binds the signature: keccak256(data hash || device public key ||
//   signature), so a receipt proves which device signed the data, not only that
//   the bytes existed.
// - Each batch, with all its leaves, is appended to a Hypercore that anyone can
//   replicate, so receipts can be rebuilt without this node (anchor-verify.js).
// - Receipts go back to the device over the same stream.
// - The node publishes a DID record with its wallet, fee, contract and log key.
//
// - The node announces itself under the deployment's topic (open-anchor.js),
//   so devices and clients find it without being told its key.
//
// usage: node anchor-node.js <bootstrap host:port | public>
//          [--network arc-testnet | local] [--contract addr] [--rpc url]
//          [--store dir] [--batch 20] [--fee 10] [--drop] [--dev 1-3]
//
// --store  the node's identity, wallet and batch log, created on first run
//          (default ~/.open-anchor/node). Fund the wallet it prints with gas.
// --fee    micro-USDC per submission
// --drop   accept submissions but never anchor them (a censoring node)
// --dev    use anvil dev account <n> and a fixed identity, for a local chain:
//          well-known test keys, never use them on a real network

const os = require('os')
const path = require('path')
const HyperDHT = require('hyperdht')
const Hyperswarm = require('hyperswarm')
const Corestore = require('corestore')
const sodium = require('sodium-universal')
const { MerkleTree } = require('merkletreejs')
const { Contract, Wallet, formatEther, keccak256, verifyTypedData } = require('ethers')
const { NETWORKS, ABI, provider, topic, verifyRecord, nodeKeys } = require('./open-anchor')

const positional = []
const opts = {}
for (let i = 2; i < process.argv.length; i++) {
  const a = process.argv[i]
  if (a === '--drop') opts.drop = true
  else if (a.startsWith('--')) opts[a.slice(2)] = process.argv[++i]
  else positional.push(a)
}
const [where = 'public'] = positional
const bootstrap = where === 'public' ? undefined : [where]
const dev = opts.dev ? Number(opts.dev) : 0
const network = NETWORKS[opts.network || (dev ? 'local' : 'arc-testnet')]
const rpc = opts.rpc || network.rpc
const contractAddress = opts.contract || network.contract
const BATCH_S = Number(opts.batch || 20)
const FEE = BigInt(opts.fee || 10) // micro-USDC per submission
const drop = !!opts.drop

if (!network || !contractAddress) {
  console.error('usage: node anchor-node.js <bootstrap | public> [--network n] [--contract addr] [--rpc url] [--store dir] [--batch s] [--fee n] [--drop] [--dev n]')
  process.exit(1)
}

const ANVIL_KEYS = [
  null,
  '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d',
  '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a',
  '0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6'
]

// the EIP-712 domain the board pays under (examples/boat_mer Kconfig defaults)
const domain = {
  name: 'GatewayWalletBatched',
  version: '1',
  chainId: 5042002,
  verifyingContract: '0x0077777d7EBA4688BDeF3E311b846F25870A19B9'
}
const types = {
  TransferWithAuthorization: [
    { name: 'from', type: 'address' },
    { name: 'to', type: 'address' },
    { name: 'value', type: 'uint256' },
    { name: 'validAfter', type: 'uint256' },
    { name: 'validBefore', type: 'uint256' },
    { name: 'nonce', type: 'bytes32' }
  ]
}

const storeDir = opts.store || (dev ? path.join(os.tmpdir(), `anchor-node-${dev}-${contractAddress.slice(2, 10).toLowerCase()}`) : path.join(os.homedir(), '.open-anchor', 'node'))
const keys = dev ? { keyPair: HyperDHT.keyPair(Buffer.alloc(32, 0x60 + dev)), walletKey: ANVIL_KEYS[dev] } : nodeKeys(storeDir)
const keyPair = keys.keyPair
const did = 'did:mw:' + keyPair.publicKey.toString('hex')
const chain = provider(rpc)
const wallet = new Wallet(keys.walletKey, chain)
const contract = new Contract(contractAddress, ABI, wallet) // one transaction at a time

const keccak = (b) => Buffer.from(keccak256(b).slice(2), 'hex')
const hex = (b) => '0x' + b.toString('hex')
const tag = `NODE${dev || ''}${dev ? '' : '[' + path.basename(storeDir) + ']'}|`

let pending = [] // { leaf, hash, pk, sig, conn }
const conns = new Set()
const usedNonces = new Set()
const totals = { accepted: 0, rejected: 0, anchored: 0, batches: 0, shared: 0 }

function send (conn, msg) {
  if (!conn.destroyed) conn.write(Buffer.from(JSON.stringify(msg)))
}

function serve (conn, dht) {
  const pk = conn.remotePublicKey
  conns.add(conn)
  conn.on('close', () => conns.delete(conn))
  const deviceDid = 'did:mw:' + pk.toString('hex')
  console.log(tag + 'device connected', deviceDid.slice(0, 23) + '...')

  // the payer must be the wallet in the device's own DID record
  const record = dht.mutableGet(pk).then((res) => {
    const r = res && verifyRecord(pk, res.value)
    console.log(`${tag}device record ${r ? 'valid eth=' + r.eth : 'missing or invalid'}`)
    return r
  }).catch(() => null)

  const validBefore = Math.floor(Date.now() / 1000) + 7 * 24 * 3600
  send(conn, { t: 'quote', pay_to: wallet.address, amount: String(FEE), valid_before: validBefore, batch_s: BATCH_S })

  conn.on('data', async (data) => {
    let m
    try {
      m = JSON.parse(data.toString())
    } catch {
      return
    }
    if (m.t !== 'submit') return

    const reject = (reason) => {
      totals.rejected++
      console.log(`${tag}reject hash=${String(m.hash).slice(0, 18)}... ${reason}`)
      send(conn, { t: 'rejected', hash: m.hash, reason })
    }

    const hash = Buffer.from(m.hash || '', 'hex')
    const sig = Buffer.from(m.sig || '', 'hex')
    if (hash.length !== 32 || sig.length !== 64) return reject('malformed')
    if (!sodium.crypto_sign_verify_detached(sig, hash, pk)) return reject('bad device signature')

    const r = await record
    const p = m.pay || {}
    let signer = null
    try {
      signer = verifyTypedData(domain, types, { from: p.from, to: p.to, value: BigInt(p.value), validAfter: p.validAfter, validBefore: p.validBefore, nonce: p.nonce }, p.sig)
    } catch {}
    if (!r) return reject('no valid DID record')
    if (!signer || signer.toLowerCase() !== r.eth.toLowerCase() || p.from.toLowerCase() !== r.eth.toLowerCase()) return reject('payment not signed by the DID wallet')
    if (p.to.toLowerCase() !== wallet.address.toLowerCase() || BigInt(p.value) < FEE) return reject('wrong payee or amount')
    if (usedNonces.has(p.nonce)) return reject('payment nonce reused')
    usedNonces.add(p.nonce)

    totals.accepted++
    send(conn, { t: 'accepted', hash: m.hash })
    if (drop) {
      console.log(`${tag}accepted hash=${m.hash.slice(0, 16)}... (--drop: will not anchor)`)
      return
    }
    const leaf = keccak(Buffer.concat([hash, pk, sig]))
    pending.push({ leaf, hash, pk, sig, conn })
    console.log(`${tag}accepted hash=${m.hash.slice(0, 16)}... leaf=${hex(leaf).slice(0, 18)}... fee=${p.value} pending=${pending.length}`)
  })

  conn.on('error', () => {})
  conn.on('close', () => console.log(tag + 'device disconnected'))
}

async function anchorBatch (core) {
  if (pending.length === 0) return
  const batch = pending
  pending = []

  // keccak256 with sorted pairs, as HashAnchor's verifyReceiptProof expects;
  // sorted leaves make the root independent of arrival order
  batch.sort((a, b) => Buffer.compare(a.leaf, b.leaf))
  const tree = new MerkleTree(batch.map((e) => e.leaf), keccak, { sortPairs: true })
  const root = tree.getRoot()

  const started = Date.now()
  // Another node may anchor the same root: a device that submits one reading
  // to several nodes makes identical single-leaf batches. The root is on chain
  // either way, so reuse that transaction, also when the other node's landed
  // between our check and our own transaction.
  const anchoredBy = async () => {
    const existing = await contract.anchors(root)
    if (existing.timestamp === 0n) return null
    // public RPCs limit log ranges; the other node anchored it moments ago
    const latest = await chain.getBlockNumber()
    const [ev] = await contract.queryFilter(contract.filters.RootAnchored(root), Math.max(0, latest - 9000))
    if (!ev) throw new Error('anchored root without a recent event')
    totals.shared++
    return { rc: { hash: ev.transactionHash, blockNumber: ev.blockNumber }, anchorer: existing.anchorer }
  }

  let rc, anchorer
  try {
    let shared = await anchoredBy()
    if (!shared) {
      try {
        rc = await (await contract.anchorRoot(root)).wait()
        anchorer = wallet.address
      } catch (err) {
        shared = await anchoredBy()
        if (!shared) throw err
      }
    }
    if (shared) ({ rc, anchorer } = shared)
  } catch (err) {
    pending = batch.concat(pending) // try again next round
    throw err
  }
  const block = await chain.getBlock(rc.blockNumber)
  const { chainId } = await chain.getNetwork()
  totals.batches++
  totals.anchored += batch.length
  const by = anchorer === wallet.address ? 'self' : 'shared, anchored by ' + anchorer
  console.log(`${tag}anchored root=${hex(root).slice(0, 18)}... leaves=${batch.length} tx=${rc.hash.slice(0, 18)}... block=${rc.blockNumber} (${by}) ms=${Date.now() - started}`)

  const anchor = { chainId: Number(chainId), contractAddress, txHash: rc.hash, blockNumber: rc.blockNumber, blockTimestamp: block.timestamp }
  await core.append({
    root: hex(root),
    anchor,
    anchorer,
    leaves: batch.map((e) => ({ leaf: hex(e.leaf), hash: hex(e.hash), did: 'did:mw:' + e.pk.toString('hex'), sig: hex(e.sig) }))
  })

  for (const e of batch) {
    const proof = tree.getProof(e.leaf).map((x) => ({ position: x.position, data: hex(x.data) }))
    send(e.conn, { t: 'receipt', hash: e.hash.toString('hex'), leaf: hex(e.leaf), root: hex(root), proof, tx: rc.hash, block: rc.blockNumber, chain_id: anchor.chainId })
  }
}

async function main () {
  const { chainId } = await chain.getNetwork()
  const balance = await chain.getBalance(wallet.address)
  console.log(`${tag}chain ${chainId} contract ${contractAddress} wallet ${wallet.address} balance=${formatEther(balance)}`)
  if (balance === 0n) console.log(`${tag}WALLET EMPTY: fund ${wallet.address} with gas${network.faucet ? ' (' + network.faucet + ')' : ''}; anchoring retries until then`)

  // the batch log anyone can replicate
  const store = new Corestore(path.join(storeDir, 'log'))
  const core = store.get({ name: 'batches', valueEncoding: 'json' })
  await core.ready()
  const swarm = new Hyperswarm({ bootstrap })
  swarm.on('connection', (c) => store.replicate(c))
  swarm.join(core.discoveryKey, { server: true, client: false })

  const dht = new HyperDHT({ bootstrap })
  const server = dht.createServer((conn) => serve(conn, dht))
  await server.listen(keyPair)

  const record = {
    v: 1,
    did,
    eth: wallet.address,
    eth_sig: await wallet.signMessage(did),
    svc: 'anchor/1',
    fee: String(FEE),
    chain_id: Number(chainId),
    contract: contractAddress,
    log: core.key.toString('hex')
  }
  const value = Buffer.from(JSON.stringify(record))
  const seq = Math.floor(Date.now() / 1000)
  const deployment = topic(chainId, contractAddress)

  // Announcements expire after about 20 minutes and records after 48 hours,
  // so both are refreshed while the node runs.
  let refreshes = 0
  const refresh = async () => {
    try {
      if (refreshes++ % 36 === 0) await dht.mutablePut(keyPair, value, { seq })
      await dht.announce(deployment, keyPair, []).finished()
    } catch (err) {
      console.log(tag + 'refresh failed', err.message)
    }
  }
  await refresh()
  setInterval(refresh, 10 * 60 * 1000)

  console.log(`${tag}listening ${did}`)
  console.log(`${tag}record published, announced on topic ${deployment.toString('hex').slice(0, 16)}... fee=${FEE} log=${record.log.slice(0, 16)}... batch_s=${BATCH_S}${drop ? ' --drop' : ''}`)

  let busy = null // the running batch
  const runBatch = async () => {
    try {
      await anchorBatch(core)
    } catch (err) {
      console.log(tag + 'anchor failed', err.shortMessage || err.message)
    }
  }
  const timer = setInterval(async () => {
    if (busy) return
    busy = runBatch()
    await busy
    busy = null
  }, BATCH_S * 1000)

  // Accepted submissions live in memory until their batch is anchored, so
  // anchor what is left before exiting; receipts still reach open streams.
  let stopping = false
  const stop = async () => {
    if (stopping) return
    stopping = true
    clearInterval(timer)
    if (busy) await busy
    if (pending.length) {
      console.log(`${tag}anchoring ${pending.length} pending before exit`)
      await runBatch()
    }
    // let the last receipts reach the devices, and stop being discovered
    const closed = [...conns].map((c) => new Promise((resolve) => { c.on('close', resolve); c.end() }))
    await Promise.race([Promise.all([...closed, dht.unannounce(deployment, keyPair)]), new Promise((resolve) => setTimeout(resolve, 3000))])
    console.log(`${tag}summary accepted=${totals.accepted} rejected=${totals.rejected} anchored=${totals.anchored} batches=${totals.batches} shared_roots=${totals.shared} log_length=${core.length}`)
    process.exit(0)
  }
  process.on('SIGINT', stop)
  process.on('SIGTERM', stop)
}

main()
