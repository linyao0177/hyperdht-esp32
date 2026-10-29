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
// usage: node anchor-node.js <bootstrap host:port | public> <index 1-3> <contract>
//          [--rpc http://127.0.0.1:8545] [--batch 20] [--store dir] [--drop]
//
// --store  where the batch log lives, so it survives restarts
//          (default: <tmp>/anchor-node-<index>-<contract>)
// --drop   accept submissions but never anchor them (a censoring node)
//
// The node's wallet is anvil dev account <index>, a well-known test key: never
// use it on a real network.

const os = require('os')
const path = require('path')
const HyperDHT = require('hyperdht')
const Hyperswarm = require('hyperswarm')
const Corestore = require('corestore')
const sodium = require('sodium-universal')
const { MerkleTree } = require('merkletreejs')
const { Contract, JsonRpcProvider, Wallet, keccak256, verifyMessage, verifyTypedData } = require('ethers')

const positional = []
const opts = {}
for (let i = 2; i < process.argv.length; i++) {
  const a = process.argv[i]
  if (a === '--drop') opts.drop = true
  else if (a.startsWith('--')) opts[a.slice(2)] = process.argv[++i]
  else positional.push(a)
}
const [where = 'public', index = '1', contractAddress] = positional
const bootstrap = where === 'public' ? undefined : [where]
const rpc = opts.rpc || 'http://127.0.0.1:8545'
const BATCH_S = Number(opts.batch || 20)
const drop = !!opts.drop

if (!contractAddress) {
  console.error('usage: node anchor-node.js <bootstrap | public> <index 1-3> <contract> [--rpc url] [--batch s] [--drop]')
  process.exit(1)
}

const ANVIL_KEYS = [
  null,
  '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d',
  '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a',
  '0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6'
]

const FEE = 10n // micro-USDC per submission

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

const ABI = [
  'function anchorRoot(bytes32 merkleRoot)',
  'function anchors(bytes32) view returns (uint64 timestamp, address anchorer)',
  'event RootAnchored(bytes32 indexed merkleRoot, address indexed anchorer, uint256 timestamp)'
]

const keyPair = HyperDHT.keyPair(Buffer.alloc(32, 0x60 + Number(index)))
const did = 'did:mw:' + keyPair.publicKey.toString('hex')
const provider = new JsonRpcProvider(rpc)
const wallet = new Wallet(ANVIL_KEYS[Number(index)], provider)
const contract = new Contract(contractAddress, ABI, wallet) // one transaction at a time

const keccak = (b) => Buffer.from(keccak256(b).slice(2), 'hex')
const hex = (b) => '0x' + b.toString('hex')
const tag = `NODE${index}|`

let pending = [] // { leaf, hash, pk, sig, conn }
const usedNonces = new Set()
const totals = { accepted: 0, rejected: 0, anchored: 0, batches: 0, shared: 0 }

// A DID record is valid when its did is the key it is stored under and its
// eth_sig (EIP-191 over the did) recovers to its eth address.
function verifyRecord (publicKey, value) {
  const r = JSON.parse(value.toString())
  if (r.did !== 'did:mw:' + publicKey.toString('hex')) return null
  if (verifyMessage(r.did, r.eth_sig).toLowerCase() !== r.eth.toLowerCase()) return null
  return r
}

function send (conn, msg) {
  if (!conn.destroyed) conn.write(Buffer.from(JSON.stringify(msg)))
}

function serve (conn, dht) {
  const pk = conn.remotePublicKey
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
  let rc, anchorer
  try {
    // Another node may already have anchored the same root: a device that
    // submits one reading to several nodes makes identical single-leaf batches.
    // The root is on chain either way, so reuse that transaction.
    const existing = await contract.anchors(root)
    if (existing.timestamp > 0n) {
      const [ev] = await contract.queryFilter(contract.filters.RootAnchored(root))
      rc = { hash: ev.transactionHash, blockNumber: ev.blockNumber }
      anchorer = existing.anchorer
      totals.shared++
    } else {
      rc = await (await contract.anchorRoot(root)).wait()
      anchorer = wallet.address
    }
  } catch (err) {
    pending = batch.concat(pending) // try again next round
    throw err
  }
  const block = await provider.getBlock(rc.blockNumber)
  const { chainId } = await provider.getNetwork()
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
  // the batch log anyone can replicate
  const store = new Corestore(opts.store || path.join(os.tmpdir(), `anchor-node-${index}-${contractAddress.slice(2, 10).toLowerCase()}`))
  const core = store.get({ name: 'batches', valueEncoding: 'json' })
  await core.ready()
  const swarm = new Hyperswarm({ bootstrap })
  swarm.on('connection', (c) => store.replicate(c))
  swarm.join(core.discoveryKey, { server: true, client: false })

  const dht = new HyperDHT({ bootstrap })
  const server = dht.createServer((conn) => serve(conn, dht))
  await server.listen(keyPair)

  const { chainId } = await provider.getNetwork()
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
  const seq = Math.floor(Date.now() / 1000)
  await dht.mutablePut(keyPair, Buffer.from(JSON.stringify(record)), { seq })
  console.log(`${tag}listening ${did}`)
  console.log(`${tag}record published wallet=${wallet.address} log=${record.log.slice(0, 16)}... batch_s=${BATCH_S}${drop ? ' --drop' : ''}`)

  let busy = false
  setInterval(async () => {
    if (busy) return
    busy = true
    try {
      await anchorBatch(core)
    } catch (err) {
      console.log(tag + 'anchor failed', err.shortMessage || err.message)
    }
    busy = false
  }, BATCH_S * 1000)

  const summary = () => {
    console.log(`${tag}summary accepted=${totals.accepted} rejected=${totals.rejected} anchored=${totals.anchored} batches=${totals.batches} shared_roots=${totals.shared} log_length=${core.length}`)
    process.exit(0)
  }
  process.on('SIGINT', summary)
  process.on('SIGTERM', summary)
}

main()
