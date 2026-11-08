// Serves a firmware core to devices over HyperDHT (lib/wire.js). Any peer
// that holds the core can run it: a seeder replicating it over Hyperswarm,
// the publisher, a Pear app. Devices trust the publisher's signature, not the
// bridge, so a bridge needs no key of the publisher.

const b4a = require('b4a')
const wire = require('./wire')
const { latest } = require('./release')

// the head devices verify: the tree's roots, length, fork and the writer's
// Ed25519 signature (a manifest v1 core's signature is [1, 0, sig, ...])
function signedHead (core) {
  const state = core.core.state
  const sig = state.signature
  if (!sig) throw new Error('the core has no signature yet')
  if (core.manifest.version === 0) return { length: state.length, fork: state.fork, signature: b4a.from(sig.subarray(0, 64)), roots: state.roots }
  if (sig[0] !== 1 || sig[1] !== 0) throw new Error('not a single-signer core')
  return { length: state.length, fork: state.fork, signature: b4a.from(sig.subarray(2, 66)), roots: state.roots }
}

// a block and its sibling nodes up to a root of the tree at `length`
async function blockProof (core, index, length) {
  const proof = await core.proof({ block: { index, nodes: 0 }, upgrade: { start: 0, length } })
  return { index, nodes: proof.block.nodes, data: proof.block.value }
}

function serve (dht, keyPair, core, { onrequest = () => {} } = {}) {
  const server = dht.createServer((conn) => {
    conn.on('error', () => {})
    conn.on('data', async (data) => {
      let req
      try {
        req = JSON.parse(b4a.toString(data))
      } catch {
        conn.write(wire.encodeError('bad request'))
        return
      }
      try {
        if (req.op === 'head') {
          await core.update({ wait: false })
          const head = signedHead(core)
          const hint = req.name ? await latest(core, req.name, head.length) : -1
          onrequest({ op: 'head', length: head.length, latest: hint, peer: conn.remotePublicKey })
          conn.write(wire.encodeHead({ ...head, latest: hint }))
        } else if (req.op === 'block') {
          const index = Number(req.index)
          const length = Number(req.length || core.length)
          if (!(index >= 0 && index < length && length <= core.length)) throw new Error('no such block')
          onrequest({ op: 'block', index, peer: conn.remotePublicKey })
          conn.write(wire.encodeBlock(await blockProof(core, index, length)))
        } else {
          conn.write(wire.encodeError('unsupported op'))
        }
      } catch (err) {
        conn.write(wire.encodeError(err.message))
      }
    })
  })
  return server.listen(keyPair).then(() => server)
}

module.exports = { serve, signedHead, blockProof }
