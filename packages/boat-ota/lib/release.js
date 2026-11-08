// Releases in a Hypercore. The core is the product's firmware channel: an
// append-only log, so every release a device was ever offered stays in it.
// A release is a manifest block followed by the image, in chunks:
//
//   {"type":"boat-ota/1","name","version","size","sha256","chunk","first","blocks","t"}
//
// `first` is the index of the image's first block. The device checks every
// block against the publisher's signed tree (hc_proof.h) and the image
// against `sha256`.

const crypto = require('crypto')
const b4a = require('b4a')

const TYPE = 'boat-ota/1'
const CHUNK = 4096

async function publish (core, { name, version, image, chunk = CHUNK }) {
  if (!name || !version) throw new Error('name and version are required')
  if (!b4a.isBuffer(image) || image.length === 0) throw new Error('no image')
  const manifestIndex = core.length
  const blocks = Math.ceil(image.length / chunk)
  const manifest = {
    type: TYPE,
    name,
    version,
    size: image.length,
    sha256: crypto.createHash('sha256').update(image).digest('hex'),
    chunk,
    first: manifestIndex + 1,
    blocks,
    t: Math.floor(Date.now() / 1000)
  }
  const batch = [b4a.from(JSON.stringify(manifest))]
  for (let i = 0; i < blocks; i++) batch.push(image.subarray(i * chunk, (i + 1) * chunk))
  await core.append(batch)
  return { index: manifestIndex, manifest }
}

function parseManifest (block) {
  try {
    const m = JSON.parse(b4a.toString(block))
    return m && m.type === TYPE ? m : null
  } catch {
    return null
  }
}

// the index of the latest release of `name` at or below `length`, or -1
async function latest (core, name, length = core.length) {
  for (let i = length - 1; i >= 0; i--) {
    const block = await core.get(i)
    if (block.length > 1024 || block[0] !== 0x7b) continue // not JSON: image data
    const m = parseManifest(block)
    if (m && m.name === name && m.first + m.blocks <= length) return i
  }
  return -1
}

module.exports = { publish, latest, parseManifest, TYPE, CHUNK }
