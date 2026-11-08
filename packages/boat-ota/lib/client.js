// Fetches the latest release from a bridge and checks it the way a device
// does (components/hdht_ota): the signed head against the core key and the
// publisher, every block against the head, the image against the manifest.

const b4a = require('b4a')
const crypto = require('crypto')
const wire = require('./wire')
const { verifyHead, verifyBlock } = require('./verify')
const { parseManifest } = require('./release')

function connect (dht, serverKey) {
  const conn = dht.connect(serverKey)
  const waiting = []
  conn.on('data', (data) => {
    const w = waiting.shift()
    if (w) w(data)
  })
  conn.on('error', () => {})
  const ask = (req) => new Promise((resolve) => {
    waiting.push(resolve)
    conn.write(b4a.from(JSON.stringify(req)))
  })
  return new Promise((resolve, reject) => {
    conn.once('open', () => resolve({ conn, ask }))
    conn.once('error', reject)
  })
}

const failure = (data) => data[0] === 0x45 ? b4a.toString(data.subarray(1)) : null

async function fetchLatest (dht, { server, key, signer, name }) {
  const { conn, ask } = await connect(dht, server)
  try {
    const h = await ask({ op: 'head', name })
    if (failure(h)) throw new Error('bridge: ' + failure(h))
    const head = wire.decodeHead(h)
    let why = verifyHead(head, key, signer)
    if (why) throw new Error('head: ' + why)
    if (head.latest < 0) return { head, manifest: null }

    const getBlock = async (index) => {
      const data = await ask({ op: 'block', index, length: head.length })
      if (failure(data)) throw new Error('bridge: ' + failure(data))
      const block = wire.decodeBlock(data)
      if (block.index !== index) throw new Error('bridge sent another block')
      why = verifyBlock(head, block)
      if (why) throw new Error(`block ${index}: ${why}`)
      return block.data
    }
    const manifest = parseManifest(await getBlock(head.latest))
    if (!manifest || manifest.name !== name) throw new Error('not a release of ' + name)
    const chunks = []
    for (let i = 0; i < manifest.blocks; i++) chunks.push(await getBlock(manifest.first + i))
    const image = b4a.concat(chunks)
    if (image.length !== manifest.size || crypto.createHash('sha256').update(image).digest('hex') !== manifest.sha256) throw new Error('image does not match the manifest')
    return { head, manifest, image }
  } finally {
    conn.end()
  }
}

module.exports = { fetchLatest, connect }
