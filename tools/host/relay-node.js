// A public blind-relay node: lets peers that cannot holepunch each other, such
// as devices behind random (symmetric) NATs or 4G, meet and exchange
// encrypted packets it cannot read (docs/relay-node.md).
//
// - It listens on the HyperDHT under its own key and accepts blind-relay
//   sessions from anyone, up to --max-sessions at a time.
// - It announces itself under the relay topic, BLAKE2b-256("hdht-relay/1"),
//   so devices find it with hdht_relay_find, and publishes a record
//   {"v":1,"did","svc":"relay/1","max_sessions"} under its key.
// - It announces only when the DHT says it is reachable without holepunching
//   (a public address with open UDP), as devices can use no other relay.
//   --force announces anyway, for tests on a LAN.
//
// usage: node relay-node.js <bootstrap host:port | public> [--store dir] [--max-sessions 256] [--force]
//        node relay-node.js <bootstrap host:port | public> --list
//
// --store  the node's identity, created on first run (default ~/.hdht-relay/node)
// --list   look up the topic and check every relay found, as a device would

const fs = require('fs')
const os = require('os')
const path = require('path')
const crypto = require('crypto')
const sodium = require('sodium-universal')
const HyperDHT = require('hyperdht')
const relay = require('blind-relay')

const positional = []
const opts = {}
for (let i = 2; i < process.argv.length; i++) {
  const a = process.argv[i]
  if (a === '--force' || a === '--list') opts[a.slice(2)] = true
  else if (a.startsWith('--')) opts[a.slice(2)] = process.argv[++i]
  else positional.push(a)
}
const [where = 'public'] = positional
const bootstrap = where === 'public' ? undefined : [where]
const storeDir = opts.store || path.join(os.homedir(), '.hdht-relay', 'node')
const MAX_SESSIONS = Number(opts['max-sessions'] || 256)
const tag = `RELAY[${path.basename(storeDir)}]|`

function topic () {
  const out = Buffer.alloc(32)
  sodium.crypto_generichash(out, Buffer.from('hdht-relay/1'))
  return out
}

function identity () {
  const file = path.join(storeDir, 'identity.key')
  if (!fs.existsSync(file)) {
    fs.mkdirSync(storeDir, { recursive: true, mode: 0o700 })
    fs.writeFileSync(file, crypto.randomBytes(32).toString('hex') + '\n', { mode: 0o600 })
  }
  return HyperDHT.keyPair(Buffer.from(fs.readFileSync(file, 'utf8').trim(), 'hex'))
}

// what a device's probe checks: we connect and the relay opens its channel
function probe (dht, publicKey) {
  return new Promise((resolve) => {
    const started = Date.now()
    const socket = dht.connect(publicKey)
    const done = (ok, why) => {
      clearTimeout(timer)
      socket.destroy()
      resolve({ ok, why, ms: Date.now() - started })
    }
    const timer = setTimeout(() => done(false, 'timeout'), 15000)
    socket.on('error', (err) => done(false, err.message))
    const client = new relay.Client(socket, { id: dht.defaultKeyPair.publicKey })
    client.on('open', () => done(true, `direct=${!socket.rawStream.socket || socket.rawStream.socket === dht.socket}`))
    client.on('error', () => {})
  })
}

async function list (dht) {
  const found = new Map()
  for await (const reply of dht.lookup(topic())) {
    for (const peer of reply.peers) found.set(peer.publicKey.toString('hex'), peer)
  }
  console.log(`LIST|${found.size} relay(s) announced on ${topic().toString('hex').slice(0, 16)}...`)
  for (const key of found.keys()) {
    const res = await dht.mutableGet(Buffer.from(key, 'hex')).catch(() => null)
    let record = null
    try {
      record = res && JSON.parse(res.value.toString())
    } catch {}
    const p = await probe(dht, Buffer.from(key, 'hex'))
    const svc = record && record.svc === 'relay/1' ? 'relay/1' : 'no relay record'
    console.log(`LIST|did:mw:${key.slice(0, 16)}... ${svc} ${p.ok ? 'ok' : 'FAILED'} ${p.why} ${p.ms} ms`)
  }
}

async function run (dht) {
  const keyPair = identity()
  const did = 'did:mw:' + keyPair.publicKey.toString('hex')
  const relayServer = new relay.Server({
    createStream (o) {
      return dht.createRawStream({ ...o, framed: true })
    }
  })

  let refused = 0
  const server = dht.createServer((socket) => {
    socket.on('error', () => {})
    if (relayServer.stats.sessions.active >= MAX_SESSIONS) {
      refused++
      socket.destroy()
      return
    }
    const session = relayServer.accept(socket, { id: socket.remotePublicKey })
    session.on('error', () => {})
  })
  await server.listen(keyPair)
  await dht.fullyBootstrapped()

  const reachable = !dht.firewalled
  console.log(`${tag}listening ${did} on ${dht.host}:${dht.port} ${reachable ? 'reachable' : 'FIREWALLED: devices outside this network cannot use it'}`)

  const record = Buffer.from(JSON.stringify({ v: 1, did, svc: 'relay/1', max_sessions: MAX_SESSIONS }))
  const seq = Math.floor(Date.now() / 1000)
  const announce = reachable || opts.force

  // announcements expire after about 20 minutes and records after 48 hours
  let refreshes = 0
  const refresh = async () => {
    try {
      if (refreshes++ % 36 === 0) await dht.mutablePut(keyPair, record, { seq })
      if (announce) await dht.announce(topic(), keyPair, []).finished()
    } catch (err) {
      console.log(tag + 'refresh failed', err.message)
    }
  }
  await refresh()
  setInterval(refresh, 10 * 60 * 1000)
  console.log(`${tag}record published${announce ? `, announced on ${topic().toString('hex').slice(0, 16)}...` : ', not announced (use --force on a LAN)'} max_sessions=${MAX_SESSIONS}`)

  const stats = () => {
    const s = relayServer.stats
    return `sessions=${s.sessions.active} accepted=${s.sessions.accepted} pairings_matched=${s.pairings.matched} pending=${s.pairings.pending} active=${s.pairings.active} streams=${s.streams.active} refused=${refused}`
  }
  setInterval(() => console.log(tag + 'stats ' + stats()), 60 * 1000).unref()

  let stopping = false
  const stop = async () => {
    if (stopping) return
    stopping = true
    await Promise.race([
      Promise.all([announce ? dht.unannounce(topic(), keyPair) : null, relayServer.close()]),
      new Promise((resolve) => setTimeout(resolve, 3000))
    ])
    console.log(tag + 'summary ' + stats())
    process.exit(0)
  }
  process.on('SIGINT', stop)
  process.on('SIGTERM', stop)
}

async function main () {
  const dht = new HyperDHT({ bootstrap })
  if (opts.list) {
    await list(dht)
    await dht.destroy()
    process.exit(0)
  }
  await run(dht)
}

main()
