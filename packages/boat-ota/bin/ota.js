#!/usr/bin/env node
// boat-ota: firmware releases in a Hypercore, for devices to update from.
//
//   boat-ota publish <image.bin> --storage <dir> [--name n] [--version v]
//       appends a release (name and version read from the ESP-IDF image's app
//       description unless given) to the core this storage writes, and prints
//       the core key and publisher key a device is built with
//   boat-ota seed --storage <dir> [--key <core key>] [--bridge <seed file>]
//       holds the core (the storage's own, or another's by key, replicated
//       over Hyperswarm), keeps it replicated, and serves it to devices over
//       HyperDHT; prints the bridge key a device dials (CONFIG_MER_OTA_SERVER)
//   boat-ota list --storage <dir> [--key <core key>]

const fs = require('fs')
const path = require('path')
const crypto = require('crypto')
const Corestore = require('corestore')
const Hyperswarm = require('hyperswarm')
const HyperDHT = require('hyperdht')
const b4a = require('b4a')
const { publish, parseManifest, serve } = require('..')

const args = process.argv.slice(2)
const opt = (name, fallback) => {
  const i = args.indexOf('--' + name)
  return i >= 0 ? args[i + 1] : fallback
}
const cmd = args[0]
const storage = opt('storage')
const log = (line) => console.log('OTA|' + line)
if (!cmd || !storage) {
  console.error('usage: boat-ota <publish <image> | seed | list> --storage <dir> [--key <core>] [--name n] [--version v]')
  process.exit(1)
}

// the ESP-IDF app description: after the image header (24 bytes) and the first
// segment header (8), magic 0xABCD5432, then version[32] at +16, project_name[32] at +48
function appDescription (image) {
  const at = 32
  if (image.length < at + 80 || image.readUInt32LE(at) !== 0xabcd5432) return null
  const str = (o) => b4a.toString(image.subarray(at + o, at + o + 32)).replace(/\0.*$/s, '')
  return { version: str(16), name: str(48) }
}

async function openCore (store) {
  const key = opt('key')
  const core = key ? store.get({ key: b4a.from(key, 'hex') }) : store.get({ name: 'firmware' })
  await core.ready()
  return core
}

async function main () {
  const store = new Corestore(path.resolve(storage))
  const core = await openCore(store)

  if (cmd === 'publish') {
    const image = fs.readFileSync(args[1])
    const desc = appDescription(image) || {}
    const name = opt('name', desc.name)
    const version = opt('version', desc.version)
    if (!core.writable) throw new Error('this storage does not write the core')
    const { index, manifest } = await publish(core, { name, version, image })
    log(`published ${name} ${version}: ${manifest.size} bytes in ${manifest.blocks} blocks, manifest at ${index}, core length ${core.length}`)
    log(`CONFIG_MER_OTA_CORE=${b4a.toString(core.key, 'hex')}`)
    log(`CONFIG_MER_OTA_SIGNER=${b4a.toString(core.manifest.signers[0].publicKey, 'hex')}`)
    await store.close()
    return
  }

  if (cmd === 'list') {
    if (opt('key')) await core.update({ wait: true })
    for (let i = 0; i < core.length; i++) {
      const block = await core.get(i)
      const m = block[0] === 0x7b ? parseManifest(block) : null
      if (m) log(`#${i} ${m.name} ${m.version} ${m.size} bytes sha256 ${m.sha256.slice(0, 16)}... ${new Date(m.t * 1000).toISOString()}`)
    }
    await store.close()
    return
  }

  if (cmd === 'seed') {
    const seedFile = opt('bridge', path.join(storage, 'bridge.seed'))
    if (!fs.existsSync(seedFile)) fs.writeFileSync(seedFile, crypto.randomBytes(32).toString('hex'), { mode: 0o600 })
    const keyPair = HyperDHT.keyPair(b4a.from(fs.readFileSync(seedFile, 'utf8').trim(), 'hex'))
    const swarm = new Hyperswarm()
    swarm.on('connection', (conn) => store.replicate(conn))
    swarm.join(core.discoveryKey, { server: true, client: true })
    if (!core.writable) {
      await swarm.flush()
      await core.update({ wait: true })
      core.download({ start: 0, end: -1 })
    }
    let blocks = 0
    const server = await serve(swarm.dht, keyPair, core, {
      onrequest: (r) => {
        if (r.op === 'head') log(`device ${b4a.toString(r.peer, 'hex').slice(0, 16)}... asked for the head: length ${r.length}, latest release at ${r.latest}`)
        else if (++blocks % 64 === 0) log(`${blocks} blocks served`)
      }
    })
    log(`seeding core ${b4a.toString(core.key, 'hex')} (length ${core.length}, ${core.writable ? 'publisher' : 'replica'})`)
    log(`CONFIG_MER_OTA_SERVER=${b4a.toString(keyPair.publicKey, 'hex')}`)
    core.on('append', () => log(`core grew to ${core.length}`))
    const stop = async () => {
      await server.close()
      await swarm.destroy()
      await store.close()
      process.exit(0)
    }
    process.on('SIGINT', stop)
    process.on('SIGTERM', stop)
    return
  }
  throw new Error('unknown command ' + cmd)
}

main().catch((err) => {
  console.error(err.message)
  process.exit(1)
})
