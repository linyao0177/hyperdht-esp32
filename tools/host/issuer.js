// A manufacturer's tool: vouch for devices with credentials, revoke them, and
// check a device the way any verifier would (docs/credentials.md).
//
// usage: node issuer.js <command> [args] [--name issuer] [--bootstrap host:port]
//
//   init <display name>                 create the issuer key (~/.hdht-issuer/<name>) and publish its record
//   show                                the issuer's DID and current record
//   issue <device did> <model> [--provision]
//                                       sign a credential; with --provision, hand it to the device
//                                       over HyperDHT (examples/app_template accepts it when the
//                                       firmware trusts this issuer)
//   revoke <credential id>              add it to the revoked list in the issuer record
//   verify <device did> [--issuer did]  check a device: its record's credential, issuer, revocation.
//                                       Trusts this issuer, or the one given
//
// --name picks one of several issuers on this machine (default "default").

const fs = require('fs')
const os = require('os')
const path = require('path')
const crypto = require('crypto')
const HyperDHT = require('hyperdht')
const { issue, verifyDevice, keyOf } = require('./credential')

const positional = []
const opts = {}
for (let i = 2; i < process.argv.length; i++) {
  const a = process.argv[i]
  if (a === '--provision') opts.provision = true
  else if (a.startsWith('--')) opts[a.slice(2)] = process.argv[++i]
  else positional.push(a)
}
const [command, ...args] = positional
const home = path.join(os.homedir(), '.hdht-issuer', opts.name || 'default')
const bootstrap = opts.bootstrap ? [opts.bootstrap] : undefined

function issuerKeys (create) {
  const file = path.join(home, 'identity.key')
  if (!fs.existsSync(file)) {
    if (!create) throw new Error('no issuer here yet: run init first')
    fs.mkdirSync(home, { recursive: true, mode: 0o700 })
    fs.writeFileSync(file, crypto.randomBytes(32).toString('hex') + '\n', { mode: 0o600 })
  }
  return HyperDHT.keyPair(Buffer.from(fs.readFileSync(file, 'utf8').trim(), 'hex'))
}

async function readRecord (dht, keyPair) {
  const res = await dht.mutableGet(keyPair.publicKey)
  return res ? { seq: res.seq, record: JSON.parse(res.value.toString()) } : { seq: 0, record: null }
}

async function putRecord (dht, keyPair, record, seq) {
  const value = Buffer.from(JSON.stringify(record))
  if (value.length > 1000) throw new Error('issuer record over 1000 bytes: too many revocations for one record')
  await dht.mutablePut(keyPair, value, { seq })
}

const commands = {
  async init (dht, [name]) {
    const kp = issuerKeys(true)
    const did = 'did:mw:' + kp.publicKey.toString('hex')
    const { seq, record } = await readRecord(dht, kp)
    const next = { v: 1, did, name: name || (record && record.name) || 'issuer', revoked: (record && record.revoked) || [] }
    await putRecord(dht, kp, next, Math.max(seq + 1, Math.floor(Date.now() / 1000)))
    console.log(`ISSUER|${did} name=${next.name} record published`)
  },

  async show (dht) {
    const kp = issuerKeys(false)
    const { seq, record } = await readRecord(dht, kp)
    console.log(`ISSUER|did:mw:${kp.publicKey.toString('hex')} seq=${seq} ${JSON.stringify(record)}`)
  },

  async issue (dht, [deviceDid, model]) {
    const kp = issuerKeys(false)
    const c = issue(kp, deviceDid, model)
    console.log('CREDENTIAL|' + JSON.stringify(c))
    if (!opts.provision) return

    // the device fills in sub (itself) and checks the rest against the issuer it trusts
    const conn = dht.connect(keyOf(deviceDid))
    conn.on('error', (err) => console.log('PROVISION|error ' + err.message))
    const reply = await new Promise((resolve) => {
      conn.on('data', (data) => {
        const m = JSON.parse(data.toString())
        if (m.t === 'hi') conn.write(Buffer.from(JSON.stringify({ t: 'provision', id: c.id, iss: c.iss, iat: c.iat, model: c.model, sig: c.sig })))
        else resolve(m)
      })
      conn.on('close', () => resolve({ t: 'error', reason: 'closed' }))
    })
    console.log(reply.t === 'ok' ? 'PROVISION|accepted by the device' : 'PROVISION|refused: ' + reply.reason)
    conn.end()
    if (reply.t !== 'ok') process.exitCode = 1
  },

  async revoke (dht, [id]) {
    if (!/^[0-9a-f]{16}$/.test(id || '')) throw new Error('expected a 16-hex credential id')
    const kp = issuerKeys(false)
    const { seq, record } = await readRecord(dht, kp)
    if (!record) throw new Error('no issuer record found: run init')
    if (!record.revoked.includes(id)) record.revoked.push(id)
    await putRecord(dht, kp, record, seq + 1)
    console.log(`ISSUER|revoked ${id}; ${record.revoked.length} revoked, record seq ${seq + 1}`)
  },

  async verify (dht, [deviceDid]) {
    const trusted = opts.issuer || 'did:mw:' + issuerKeys(false).publicKey.toString('hex')
    const r = await verifyDevice(dht, deviceDid, [trusted])
    const c = r.credential
    console.log(`VERIFY|${r.ok ? 'VALID' : 'INVALID'} ${r.reason}${c ? ` id=${c.id} model="${c.model}" issued=${new Date(c.iat * 1000).toISOString()}` : ''}${r.issuer ? ` issuer="${r.issuer.name}"` : ''}`)
    if (!r.ok) process.exitCode = 1
  }
}

async function main () {
  if (!commands[command]) {
    console.error('usage: node issuer.js <init | show | issue | revoke | verify> [args] [--name issuer]')
    process.exit(1)
  }
  const dht = new HyperDHT({ bootstrap })
  try {
    await commands[command](dht, args)
  } catch (err) {
    console.error('error: ' + err.message)
    process.exitCode = 1
  }
  await new Promise((resolve) => setTimeout(resolve, 300))
  await dht.destroy()
  process.exit()
}

main()
