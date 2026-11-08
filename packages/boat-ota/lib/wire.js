// The device protocol, over a HyperDHT stream (components/hdht_ota).
//
// The device sends JSON requests, one per message:
//   {"op":"head","name":"<product>"}
//   {"op":"block","index":<n>,"length":<the head's length>}
// and gets binary answers, little-endian:
//   'H' u64 length, u64 fork, signature[64], u64 latest release of name
//       (2^64-1 for none), u8 roots, roots × (u64 index, u64 size, hash[32])
//   'B' u64 index, u8 nodes, nodes × (u64 index, u64 size, hash[32]), data
//   'E' message (UTF-8)
// Everything in an answer is checked by the device; the "latest" hint is
// only where to look.

const b4a = require('b4a')

const NONE = 0xffffffffffffffffn

function writeU64 (buf, offset, v) {
  buf.writeBigUInt64LE(BigInt(v), offset)
}

function encodeNodes (nodes) {
  const out = b4a.alloc(1 + nodes.length * 48)
  out[0] = nodes.length
  nodes.forEach((n, i) => {
    writeU64(out, 1 + i * 48, n.index)
    writeU64(out, 9 + i * 48, n.size)
    n.hash.copy(out, 17 + i * 48)
  })
  return out
}

function decodeNodes (buf, offset) {
  const n = buf[offset]
  const nodes = []
  for (let i = 0; i < n; i++) {
    const o = offset + 1 + i * 48
    nodes.push({ index: Number(buf.readBigUInt64LE(o)), size: Number(buf.readBigUInt64LE(o + 8)), hash: buf.subarray(o + 16, o + 48) })
  }
  return { nodes, end: offset + 1 + n * 48 }
}

function encodeHead ({ length, fork, signature, latest, roots }) {
  const head = b4a.alloc(1 + 8 + 8 + 64 + 8)
  head[0] = 0x48
  writeU64(head, 1, length)
  writeU64(head, 9, fork)
  signature.copy(head, 17)
  writeU64(head, 81, latest < 0 ? NONE : latest)
  return b4a.concat([head, encodeNodes(roots)])
}

function decodeHead (buf) {
  if (buf[0] !== 0x48) throw new Error('not a head')
  const latest = buf.readBigUInt64LE(81)
  const { nodes } = decodeNodes(buf, 89)
  return { length: Number(buf.readBigUInt64LE(1)), fork: Number(buf.readBigUInt64LE(9)), signature: buf.subarray(17, 81), latest: latest === NONE ? -1 : Number(latest), roots: nodes }
}

function encodeBlock ({ index, nodes, data }) {
  const head = b4a.alloc(9)
  head[0] = 0x42
  writeU64(head, 1, index)
  return b4a.concat([head, encodeNodes(nodes), data])
}

function decodeBlock (buf) {
  if (buf[0] !== 0x42) throw new Error('not a block')
  const { nodes, end } = decodeNodes(buf, 9)
  return { index: Number(buf.readBigUInt64LE(1)), nodes, data: buf.subarray(end) }
}

const encodeError = (message) => b4a.concat([b4a.from([0x45]), b4a.from(message)])

module.exports = { encodeHead, decodeHead, encodeBlock, decodeBlock, encodeError }
