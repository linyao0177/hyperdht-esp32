// The other side of examples/app_template: a peer that owns, reads or keeps
// copies of a device's data, with no server in between.
//
// usage: node app-peer.js <command> [args] [--id name] [--bootstrap host:port]
//
//   whoami                                   this peer's DID (key kept in ~/.app-peer/<id>)
//   resolve <device did> [--issuer did]      read and check the device's record, and its
//                                            manufacturer credential against that issuer
//   claim <device did> <setup code>          become the device's owner
//   state <device did> [--grant file]        print the device's state
//   set <device did> <key>=<value>           change a setting (owner)
//   grant <device did> <peer did> [--hours 24]
//                                            sign a read grant for another peer (owner); prints it
//   revoke <device did>                      end every grant (owner)
//   release <device did>                     give the device up (owner)
//   replica <device did> [--grant file]      keep the device's signed readings in a Hypercore
//                                            and share it; runs until stopped
//   check <device did> <log key>             replicate a log from whoever has it and check
//                                            every reading against the device's key
//
// --id picks one of several identities on this machine (default "me").

const fs = require('fs')
const os = require('os')
const path = require('path')
const crypto = require('crypto')
const HyperDHT = require('hyperdht')
const Hyperswarm = require('hyperswarm')
const Corestore = require('corestore')
const sodium = require('sodium-universal')
const credential = require('./credential')

const positional = []
const opts = {}
for (let i = 2; i < process.argv.length; i++) {
  const a = process.argv[i]
  if (a.startsWith('--')) opts[a.slice(2)] = process.argv[++i]
  else positional.push(a)
}
const [command, ...args] = positional
const bootstrap = opts.bootstrap ? [opts.bootstrap] : undefined
const home = path.join(os.homedir(), '.app-peer', opts.id || 'me')

// identity: a seed created on first use, never leaving this machine
function identity () {
  const file = path.join(home, 'identity.key')
  let seed
  try {
    seed = Buffer.from(fs.readFileSync(file, 'utf8').trim(), 'hex')
  } catch {
    seed = crypto.randomBytes(32)
    fs.mkdirSync(home, { recursive: true, mode: 0o700 })
    fs.writeFileSync(file, seed.toString('hex') + '\n', { mode: 0o600 })
  }
  return HyperDHT.keyPair(seed)
}

const keyPair = identity()
const conns = [] // closed cleanly before exiting
const me = 'did:mw:' + keyPair.publicKey.toString('hex')

function keyOf (did) {
  if (!/^did:mw:[0-9a-f]{64}$/.test(did || '')) throw new Error('expected did:mw:<64 hex>, got ' + did)
  return Buffer.from(did.slice(7), 'hex')
}

function sign (text) {
  const sig = Buffer.alloc(64)
  sodium.crypto_sign_detached(sig, Buffer.from(text), keyPair.secretKey)
  return sig
}

function verify (sig, data, publicKey) {
  return sig.length === 64 && sodium.crypto_sign_verify_detached(sig, data, publicKey)
}

// The device's record. hyperdht checks the signature against the key it is
// stored under; the did inside must match that key too.
async function resolve (dht, did) {
  const res = await dht.mutableGet(keyOf(did))
  if (!res) return null
  const r = JSON.parse(res.value.toString())
  return r.did === did ? { ...r, seq: res.seq } : null
}

// A stream to the device, with a way to wait for its next message of a type.
async function open (dht, did) {
  const conn = dht.connect(keyOf(did), { keyPair })
  conns.push(conn)
  conn.on('end', () => conn.end()) // the device ended: close our side too
  const queue = []
  const waiters = []
  let other = null // takes unawaited messages instead of the queue
  conn.on('data', (data) => {
    let m
    try {
      m = JSON.parse(data.toString())
    } catch {
      return
    }
    const w = waiters.findIndex((x) => x.types.includes(m.t) || m.t === 'error')
    if (w >= 0) waiters.splice(w, 1)[0].resolve(m)
    else if (other) other(m)
    else queue.push(m)
  })
  conn.on('error', () => {})
  const next = (...types) => {
    const i = queue.findIndex((m) => types.includes(m.t) || m.t === 'error')
    if (i >= 0) return Promise.resolve(queue.splice(i, 1)[0])
    return new Promise((resolve) => waiters.push({ types, resolve }))
  }
  const send = (m) => conn.write(Buffer.from(JSON.stringify(m)))
  const hi = await next('hi')
  return { conn, hi, next, send, onMessage: (fn) => { other = fn } }
}

// Presents a grant file when given one; the owner needs none.
async function authenticate (session) {
  if (session.hi.role === 'owner') return 'owner'
  if (!opts.grant) throw new Error('not the owner: pass --grant <file> from the owner')
  const g = JSON.parse(fs.readFileSync(opts.grant, 'utf8'))
  session.send({ t: 'hello', role: g.role, epoch: g.epoch, exp: g.exp, sig: g.sig })
  const m = await session.next('role')
  if (m.t === 'error') throw new Error('grant refused: ' + m.reason)
  return m.role
}

async function request (session, msg, type) {
  session.send(msg)
  const m = await session.next(type)
  if (m.t === 'error') throw new Error(m.reason)
  return m
}

const commands = {
  async whoami () {
    console.log(me)
  },

  async resolve (dht, [did]) {
    const r = await resolve(dht, did)
    console.log(r ? JSON.stringify(r) : 'no valid record')
    if (!r) return
    if (opts.issuer) {
      const v = await credential.verifyDevice(dht, did, [opts.issuer])
      console.log(`credential: ${v.ok ? 'VALID' : 'INVALID'} ${v.reason}${v.issuer ? ` (issuer "${v.issuer.name}")` : ''}`)
    } else if (r.cred) {
      const bad = credential.check(r.cred, did)
      console.log(`credential: ${bad || 'signed'} by ${r.cred.iss}, model "${r.cred.model}"; not trusted until you pass --issuer`)
    } else {
      console.log('credential: none')
    }
  },

  async claim (dht, [did, code]) {
    const s = await open(dht, did)
    await request(s, { t: 'claim', code }, 'claimed')
    console.log(`claimed ${did}; owner ${me}`)
  },

  async state (dht, [did]) {
    const s = await open(dht, did)
    const role = await authenticate(s)
    const m = await request(s, { t: 'get' }, 'state')
    delete m.t
    console.log(`role=${role}`, JSON.stringify(m))
  },

  async set (dht, [did, kv]) {
    const [key, value] = String(kv).split('=')
    const s = await open(dht, did)
    await request(s, { t: 'set', key, value }, 'ok')
    console.log(`set ${key}=${value}`)
  },

  // Offline except for reading the record: the grant is just a signature, and
  // whoever holds it presents it to the device.
  async grant (dht, [did, to]) {
    keyOf(to)
    const r = await resolve(dht, did)
    if (!r) throw new Error('no valid record for ' + did)
    if (r.owner !== keyPair.publicKey.toString('hex')) throw new Error('this peer is not the owner in the device record')
    const exp = Math.floor(Date.now() / 1000) + Math.round(Number(opts.hours || 24) * 3600)
    const text = `app-template/grant/1 ${did.slice(7)} ${to.slice(7)} read ${r.epoch} ${exp}`
    console.log(JSON.stringify({ v: 1, device: did, to, role: 'read', epoch: r.epoch, exp, sig: sign(text).toString('hex') }))
  },

  async revoke (dht, [did]) {
    const s = await open(dht, did)
    const m = await request(s, { t: 'revoke' }, 'ok')
    console.log(`revoked every grant; epoch=${m.epoch}`)
  },

  async release (dht, [did]) {
    const s = await open(dht, did)
    await request(s, { t: 'release' }, 'ok')
    console.log('released; the device prints a new setup code')
  },

  // Keeps the device's signed readings and serves them to anyone. The copies
  // need no trust in this peer: each reading carries the device's signature.
  async replica (dht, [did]) {
    const devicePk = keyOf(did)
    const store = new Corestore(opts.store || path.join(home, 'replica'))
    const core = store.get({ name: 'readings-' + did.slice(7, 23), valueEncoding: 'json' })
    await core.ready()
    const swarm = new Hyperswarm({ bootstrap })
    swarm.on('connection', (c) => store.replicate(c))
    swarm.join(core.discoveryKey, { server: true, client: false })
    console.log(`REPLICA|log ${core.key.toString('hex')} length=${core.length}`)

    for (;;) {
      try {
        const s = await open(dht, did)
        const role = await authenticate(s)
        await request(s, { t: 'subscribe' }, 'ok')
        console.log(`REPLICA|subscribed as ${role}`)
        await new Promise((resolve) => {
          s.conn.on('close', resolve)
          s.onMessage(async (m) => {
            if (m.t !== 'reading') return
            const ok = verify(Buffer.from(m.sig, 'hex'), Buffer.from(m.data), devicePk) && JSON.parse(m.data).did === did
            if (!ok) return console.log('REPLICA|reading with a bad signature dropped')
            await core.append({ data: m.data, sig: m.sig })
            console.log(`REPLICA|#${core.length - 1} ${m.data}`)
          })
        })
        console.log('REPLICA|device disconnected; reconnecting')
      } catch (err) {
        console.log('REPLICA|' + err.message + '; retrying')
      }
      await new Promise((resolve) => setTimeout(resolve, 10000))
    }
  },

  async check (dht, [did, logKey]) {
    const devicePk = keyOf(did)
    const store = new Corestore(path.join(os.tmpdir(), 'app-peer-check-' + crypto.randomBytes(4).toString('hex')))
    const core = store.get({ key: Buffer.from(logKey, 'hex'), valueEncoding: 'json' })
    await core.ready()
    const swarm = new Hyperswarm({ bootstrap })
    swarm.on('connection', (c) => store.replicate(c))
    swarm.join(core.discoveryKey, { server: false, client: true })
    const started = Date.now()
    await swarm.flush()
    await core.update({ wait: true })
    console.log(`CHECK|replicated length=${core.length} ms=${Date.now() - started}`)

    const seen = new Set()
    let pass = 0
    let fail = 0
    let dup = 0
    for (let i = 0; i < core.length; i++) {
      const e = await core.get(i)
      const d = JSON.parse(e.data)
      const ok = verify(Buffer.from(e.sig, 'hex'), Buffer.from(e.data), devicePk) && d.did === did
      const id = `${d.boot}/${d.n}`
      if (!ok) fail++
      else if (seen.has(id)) dup++
      else pass++
      seen.add(id)
    }
    console.log(`CHECK|signed by ${did.slice(0, 23)}...: pass=${pass} fail=${fail} duplicates=${dup}`)
    await swarm.destroy()
    await store.close()
  }
}

async function main () {
  const run = commands[command]
  if (!run) {
    console.error('usage: node app-peer.js <whoami | resolve | claim | state | set | grant | revoke | release | replica | check> [args] [--id name]')
    process.exit(1)
  }
  if (command === 'whoami') return run()
  const dht = new HyperDHT({ bootstrap })
  try {
    await run(dht, args)
  } catch (err) {
    console.error('error: ' + err.message)
    process.exitCode = 1
  }
  const closed = conns.filter((c) => !c.destroyed).map((c) => new Promise((resolve) => { c.on('close', resolve); c.end() }))
  await Promise.race([Promise.all(closed), new Promise((resolve) => setTimeout(resolve, 2000))])
  await dht.destroy()
  process.exit()
}

main()
