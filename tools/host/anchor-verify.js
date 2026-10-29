// Verifies everything an anchor node did for one device, trusting neither the
// node nor the device: only the two DIDs and the chain (anchor-node.js).
//
// 1. Resolves the node's DID record (wallet, contract, batch log key) and the
//    device's DID record, and checks both.
// 2. Replicates the node's batch log (a Hypercore) from the swarm.
// 3. For every leaf of the device: checks the device's Ed25519 signature of
//    the data hash, recomputes the leaf, rebuilds the batch tree, and checks
//    the receipt with HashAnchor's own verifyReceiptProof.
// 4. Reads the contract: the root must be anchored, by the wallet the log
//    names. That is usually the node's own; when several nodes built the same
//    root, the first one's transaction counts for all of them.
//
// usage: node anchor-verify.js <bootstrap host:port | public> <node did> <device did> [--rpc http://127.0.0.1:8545]

const os = require('os')
const path = require('path')
const crypto = require('crypto')
const HyperDHT = require('hyperdht')
const Hyperswarm = require('hyperswarm')
const Corestore = require('corestore')
const sodium = require('sodium-universal')
const { MerkleTree } = require('merkletreejs')
const { Contract, JsonRpcProvider, keccak256, verifyMessage } = require('ethers')

const argv = process.argv.slice(2)
const rpcIndex = argv.indexOf('--rpc')
const rpc = rpcIndex >= 0 ? argv[rpcIndex + 1] : 'http://127.0.0.1:8545'
const [where, nodeDid, deviceDid] = argv.filter((a, i) => !a.startsWith('--') && argv[i - 1] !== '--rpc')
const bootstrap = where === 'public' ? undefined : [where]

if (!/^did:mw:[0-9a-f]{64}$/.test(nodeDid || '') || !/^did:mw:[0-9a-f]{64}$/.test(deviceDid || '')) {
  console.error('usage: node anchor-verify.js <bootstrap | public> <node did> <device did> [--rpc url]')
  process.exit(1)
}

const ABI = ['function anchors(bytes32) view returns (uint64 timestamp, address anchorer)']
const keccak = (b) => Buffer.from(keccak256(b).slice(2), 'hex')
const hex = (b) => '0x' + b.toString('hex')

async function resolve (dht, didStr) {
  const pk = Buffer.from(didStr.slice(7), 'hex')
  const res = await dht.mutableGet(pk)
  if (!res) return null
  const r = JSON.parse(res.value.toString())
  if (r.did !== didStr || verifyMessage(r.did, r.eth_sig).toLowerCase() !== r.eth.toLowerCase()) return null
  return r
}

async function main () {
  const { verifyReceiptProof } = await import('@tlay/hashanchor-client')
  const dht = new HyperDHT({ bootstrap })
  await dht.fullyBootstrapped()

  const node = await resolve(dht, nodeDid)
  const device = await resolve(dht, deviceDid)
  console.log(`VERIFY|node record ${node ? 'valid wallet=' + node.eth + ' contract=' + node.contract : 'INVALID'}`)
  console.log(`VERIFY|device record ${device ? 'valid wallet=' + device.eth : 'INVALID'}`)
  if (!node || !device) process.exit(1)

  // replicate the node's batch log; it is not trusted, only read
  const store = new Corestore(path.join(os.tmpdir(), 'anchor-verify-' + crypto.randomBytes(4).toString('hex')))
  const core = store.get({ key: Buffer.from(node.log, 'hex'), valueEncoding: 'json' })
  await core.ready()
  const swarm = new Hyperswarm({ bootstrap })
  swarm.on('connection', (c) => store.replicate(c))
  swarm.join(core.discoveryKey, { server: false, client: true })
  const started = Date.now()
  await swarm.flush()
  await core.update({ wait: true })
  console.log(`VERIFY|replicated batch log length=${core.length} ms=${Date.now() - started}`)

  const contract = new Contract(node.contract, ABI, new JsonRpcProvider(rpc))
  const devicePk = Buffer.from(deviceDid.slice(7), 'hex')
  const totals = { pass: 0, fail: 0 }

  for (let i = 0; i < core.length; i++) {
    const batch = await core.get(i)
    const leaves = batch.leaves.map((l) => Buffer.from(l.leaf.slice(2), 'hex'))
    const tree = new MerkleTree(leaves, keccak, { sortPairs: true })
    const onChain = await contract.anchors(batch.root)

    for (const l of batch.leaves.filter((x) => x.did === deviceDid)) {
      const hash = Buffer.from(l.hash.slice(2), 'hex')
      const sig = Buffer.from(l.sig.slice(2), 'hex')
      const leaf = keccak(Buffer.concat([hash, devicePk, sig]))
      const receipt = {
        '@context': 'https://hashanchor.io/receipt/v1',
        hash: hex(leaf),
        merkleRoot: batch.root,
        proof: tree.getProof(leaf).map((x) => ({ position: x.position, data: hex(x.data) })),
        anchor: batch.anchor
      }
      const checks = {
        device_signed_hash: sodium.crypto_sign_verify_detached(sig, hash, devicePk),
        leaf_matches: hex(leaf) === l.leaf,
        tree_root_matches: hex(tree.getRoot()) === batch.root,
        hashanchor_receipt_valid: verifyReceiptProof(receipt),
        root_on_chain: onChain.timestamp > 0n,
        anchorer_matches_log: onChain.anchorer.toLowerCase() === batch.anchorer.toLowerCase()
      }
      const ok = Object.values(checks).every(Boolean)
      if (ok) totals.pass++
      else totals.fail++
      const by = onChain.anchorer.toLowerCase() === node.eth.toLowerCase() ? 'node' : 'another node ' + onChain.anchorer
      console.log(`VERIFY|batch ${i} hash=${l.hash.slice(0, 18)}... ${ok ? 'PASS' : 'FAIL'} anchored_by=${by} ${JSON.stringify(checks)}`)
    }
  }

  console.log(`VERIFY|summary pass=${totals.pass} fail=${totals.fail} batches=${core.length}`)
  await swarm.destroy()
  await dht.destroy()
  await store.close()
  process.exit(totals.fail === 0 && totals.pass > 0 ? 0 : 1)
}

main()
