// What a device checks (components/hdht_ota/hc_proof.c), in JS: for tests,
// and for clients other than devices. Uses hypercore-crypto's own hashing.

const b4a = require('b4a')
const crypto = require('hypercore-crypto')
const flat = require('flat-tree')
const sodium = require('sodium-universal')

const [TREE] = crypto.namespace('hypercore', 6)

function u64 (v) {
  const b = b4a.alloc(8)
  b.writeBigUInt64LE(BigInt(v))
  return b
}

function verifyHead (head, key, signer) {
  if (head.length === 0) return 'empty core'
  const want = flat.fullRoots(2 * head.length)
  if (want.length !== head.roots.length || want.some((w, i) => head.roots[i].index !== w)) return 'roots do not match the length'
  const signable = b4a.concat([TREE, key, crypto.tree(head.roots), u64(head.length), u64(head.fork)])
  return sodium.crypto_sign_verify_detached(head.signature, signable, signer) ? null : 'bad signature'
}

function verifyBlock (head, { index, nodes, data }) {
  if (index >= head.length) return 'block beyond the signed length'
  let node = { index: 2 * index, size: data.length, hash: crypto.data(data) }
  for (let i = 0; ; i++) {
    const root = head.roots.find((r) => r.index === node.index)
    if (root) {
      if (root.size !== node.size || !b4a.equals(root.hash, node.hash)) return 'does not hash to the signed root'
      return i === nodes.length ? null : 'extra nodes'
    }
    if (i === nodes.length) return 'nodes end before a root'
    if (nodes[i].index !== flat.sibling(node.index)) return 'node is not the sibling'
    node = { index: flat.parent(node.index), size: node.size + nodes[i].size, hash: crypto.parent(node, nodes[i]) }
  }
}

module.exports = { verifyHead, verifyBlock }
