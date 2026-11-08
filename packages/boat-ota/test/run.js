// Tests for boat-ota: node test/run.js
//
// A publisher appends two releases to a Hypercore; a seeder that holds no key
// of the publisher replicates it and serves it to devices over a local
// HyperDHT testnet. The client checks it all the way a device does. Proofs
// are also written out and checked by the device's C code
// (components/hdht_ota/hc_proof.c, built for the desktop) when clang and
// libsodium are there.

const fs = require('fs')
const os = require('os')
const path = require('path')
const crypto = require('crypto')
const { execFileSync } = require('child_process')
const b4a = require('b4a')
const Corestore = require('corestore')
const HyperDHT = require('hyperdht')
const createTestnet = require('hyperdht/testnet')
const { publish, latest, serve, signedHead, blockProof, fetchLatest, verifyHead, verifyBlock, wire } = require('..')

const COMPONENT = path.join(__dirname, '..', '..', '..', 'components', 'hdht_ota')
let passed = 0
let failed = 0
function check (name, ok, detail = '') {
  ok ? passed++ : failed++
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? '  ' + detail : ''}`)
}

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'boat-ota-'))

function buildC () {
  const sodium = ['/opt/homebrew', '/usr/local', '/usr'].find((p) => fs.existsSync(path.join(p, 'include', 'sodium.h')))
  if (!sodium) return null
  const out = path.join(tmp, 'test_hc_proof')
  try {
    execFileSync('clang', ['-O1', '-Wall', '-I' + path.join(COMPONENT, 'include'), '-I' + path.join(sodium, 'include'), path.join(COMPONENT, 'hc_proof.c'), path.join(COMPONENT, 'test', 'test_hc_proof.c'), '-L' + path.join(sodium, 'lib'), '-lsodium', '-o', out])
    return out
  } catch {
    return null
  }
}

async function main () {
  // the publisher
  const publisherStore = new Corestore(path.join(tmp, 'publisher'))
  const core = publisherStore.get({ name: 'firmware/boat_mer' })
  await core.ready()
  const signer = core.manifest.signers[0].publicKey
  const v1 = crypto.randomBytes(50000)
  const v2 = crypto.randomBytes(70001)
  const r1 = await publish(core, { name: 'boat_mer', version: '0.7.0', image: v1 })
  const r2 = await publish(core, { name: 'boat_mer', version: '0.7.1', image: v2 })
  check('two releases appended', r1.index === 0 && r2.index === 1 + r1.manifest.blocks && core.length === 2 + r1.manifest.blocks + r2.manifest.blocks, `length ${core.length}, ${r2.manifest.blocks} blocks of ${r2.manifest.chunk} bytes`)
  check('the latest release is found', (await latest(core, 'boat_mer')) === r2.index && (await latest(core, 'boat_mer', r2.index)) === r1.index && (await latest(core, 'other')) === -1)

  // a seeder, replicating it without any key of the publisher
  const seederStore = new Corestore(path.join(tmp, 'seeder'))
  const s1 = publisherStore.replicate(true)
  const s2 = seederStore.replicate(false)
  s1.pipe(s2).pipe(s1)
  const copy = seederStore.get({ key: core.key })
  await copy.ready()
  await copy.update({ wait: true })
  await copy.download({ start: 0, end: core.length }).done()
  check('a seeder replicates the core', copy.length === core.length && !copy.writable)

  const head = signedHead(copy)
  check("the seeder's head verifies against the core key and the publisher", verifyHead(head, core.key, signer) === null, `${head.roots.length} roots`)
  check('a head checked against another signer fails', verifyHead(head, core.key, crypto.randomBytes(32)) === 'bad signature')
  const proof = await blockProof(copy, r2.manifest.first + 3, head.length)
  check("the seeder's block proofs verify", verifyBlock(head, proof) === null, `${proof.nodes.length} sibling nodes`)
  const flipped = b4a.from(proof.data)
  flipped[0] ^= 1
  check('a changed block fails', verifyBlock(head, { ...proof, data: flipped }) === 'does not hash to the signed root')

  // the device's C code on the same proofs
  const c = buildC()
  if (c) {
    const lines = [`key ${core.key.toString('hex')}`, `signer ${b4a.toString(signer, 'hex')}`]
    const enc = (h) => wire.encodeHead({ ...h, latest: r2.index }).toString('hex')
    lines.push(`head ok ${enc(head)}`)
    for (const i of [0, 1, r1.index + 5, r2.index, r2.manifest.first + r2.manifest.blocks - 1]) {
      lines.push(`block ok ${wire.encodeBlock(await blockProof(copy, i, head.length)).toString('hex')}`)
    }
    lines.push(`block does_not_hash_to_the_signed_root ${wire.encodeBlock({ ...proof, data: flipped }).toString('hex')}`)
    lines.push(`block node_is_not_the_sibling ${wire.encodeBlock({ ...proof, nodes: [proof.nodes[1], proof.nodes[0], ...proof.nodes.slice(2)] }).toString('hex')}`)
    lines.push(`block nodes_end_before_a_root ${wire.encodeBlock({ ...proof, nodes: proof.nodes.slice(0, -1) }).toString('hex')}`)
    lines.push(`block block_beyond_the_signed_length ${wire.encodeBlock({ ...proof, index: head.length }).toString('hex')}`)
    const forged = { ...head, roots: head.roots.map((r, i) => i === 0 ? { ...r, hash: crypto.randomBytes(32) } : r) }
    lines.push(`head bad_signature ${enc(forged)}`)
    lines.push(`head roots_do_not_match_the_length ${enc({ ...head, length: head.length + 1 })}`)
    const file = path.join(tmp, 'vectors.txt')
    fs.writeFileSync(file, lines.join('\n') + '\n')
    let out
    try {
      out = execFileSync(c, [file], { encoding: 'utf8' })
    } catch (err) {
      out = err.stdout
    }
    const summary = out.trim().split('\n').pop()
    check("the device's C code agrees on all of them", /^(\d+) of \1 passed$/.test(summary), summary)
    if (!/^(\d+) of \1 passed$/.test(summary)) console.log(out)
  } else {
    console.log('SKIP C checks: clang or libsodium not found')
  }

  // devices fetch it from the seeder over HyperDHT
  const testnet = await createTestnet(3)
  const seederDht = testnet.createNode()
  const deviceDht = testnet.createNode()
  const bridgeKey = HyperDHT.keyPair()
  const requests = []
  const server = await serve(seederDht, bridgeKey, copy, { onrequest: (r) => requests.push(r.op) })
  let t = Date.now()
  const got = await fetchLatest(deviceDht, { server: bridgeKey.publicKey, key: core.key, signer, name: 'boat_mer' })
  check('a device fetches the latest release from the seeder and checks it', got.manifest.version === '0.7.1' && b4a.equals(got.image, v2), `${got.image.length} bytes in ${requests.length} requests, ${Date.now() - t} ms`)

  const wrong = await fetchLatest(deviceDht, { server: bridgeKey.publicKey, key: core.key, signer: crypto.randomBytes(32), name: 'boat_mer' }).then(() => null, (err) => err.message)
  check('a device that trusts another publisher refuses it', wrong === 'head: bad signature', wrong)

  // a bridge that lies
  const liarKey = HyperDHT.keyPair()
  const liar = seederDht.createServer((conn) => {
    conn.on('data', async (data) => {
      const req = JSON.parse(b4a.toString(data))
      if (req.op === 'head') return conn.write(wire.encodeHead({ ...signedHead(copy), latest: r2.index }))
      const p = await blockProof(copy, req.index, req.length)
      if (req.index === r2.manifest.first + 10) p.data = b4a.concat([p.data.subarray(0, 100), b4a.alloc(p.data.length - 100)])
      conn.write(wire.encodeBlock(p))
    })
  })
  await liar.listen(liarKey)
  const lied = await fetchLatest(deviceDht, { server: liarKey.publicKey, key: core.key, signer, name: 'boat_mer' }).then(() => null, (err) => err.message)
  check('a bridge that changes a block is caught at that block', lied === `block ${r2.manifest.first + 10}: does not hash to the signed root`, lied)

  // a new release reaches the seeder by replication, and devices see it
  const v3 = crypto.randomBytes(9000)
  await publish(core, { name: 'boat_mer', version: '0.7.2', image: v3 })
  await copy.update({ wait: true })
  t = Date.now()
  const next = await fetchLatest(deviceDht, { server: bridgeKey.publicKey, key: core.key, signer, name: 'boat_mer' })
  check('a new release replicates to the seeder and reaches devices', next.manifest.version === '0.7.2' && b4a.equals(next.image, v3), `${Date.now() - t} ms`)

  await server.close()
  await liar.close()
  await testnet.destroy()
  s1.destroy()
  s2.destroy()
  await seederStore.close()
  await publisherStore.close()
  console.log(`\n${passed} of ${passed + failed} passed`)
  process.exit(failed ? 1 : 0)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
