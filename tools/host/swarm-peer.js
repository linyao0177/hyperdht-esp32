// Hyperswarm peers for checking that Hyperswarm apps (and Pear apps, which use
// the same module) work with a device running hyperdht-esp32.
//
// usage: node swarm-peer.js <command> [args] [--bootstrap host:port]
//
//   dial <did> <text> [rounds]  swarm.joinPeer(key): sends text on each
//                               connection and prints the reply, then
//                               leavePeer; repeats rounds times (default 1)
//   serve <topic name>          swarm.join(BLAKE2b-256(topic name), server
//                               only): prints PEER|did, echoes every message
//
// Every output line starts with PEER| so a test can find it.

const Hyperswarm = require('hyperswarm')
const sodium = require('sodium-universal')

const positional = []
const opts = {}
for (let i = 2; i < process.argv.length; i++) {
  const a = process.argv[i]
  if (a.startsWith('--')) opts[a.slice(2)] = process.argv[++i]
  else positional.push(a)
}
const [command, ...args] = positional
const swarm = new Hyperswarm({ bootstrap: opts.bootstrap ? [opts.bootstrap] : undefined })
const keyOf = (did) => Buffer.from(did.replace(/^did:mw:/, ''), 'hex')
const didOf = (key) => 'did:mw:' + key.toString('hex')

async function dial (did, text, rounds = '1') {
  const key = keyOf(did)
  let ok = 0
  for (let i = 0; i < Number(rounds); i++) {
    const t0 = Date.now()
    const reply = new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('timeout')), 60000)
      swarm.once('connection', (conn, info) => {
        const t1 = Date.now()
        console.log(`PEER|connection ${didOf(conn.remotePublicKey)} client=${info.client} ${t1 - t0} ms`)
        conn.on('error', () => {})
        conn.once('data', (data) => {
          clearTimeout(timer)
          resolve({ data, conn, open: t1 - t0, rtt: Date.now() - t1 })
        })
        conn.write(Buffer.from(text))
      })
    })
    swarm.joinPeer(key)
    try {
      const { data, conn, open, rtt } = await reply
      const good = conn.remotePublicKey.equals(key)
      if (good) ok++
      console.log(`PEER|round ${i} reply ${JSON.stringify(data.toString())} open=${open} ms rtt=${rtt} ms key=${good ? 'ok' : 'WRONG'}`)
      swarm.leavePeer(key)
      conn.end()
      await new Promise((resolve) => conn.once('close', resolve))
    } catch (err) {
      console.log(`PEER|round ${i} ${err.message}`)
      swarm.leavePeer(key)
    }
  }
  console.log(`PEER|done ${ok}/${rounds}`)
  await swarm.destroy()
}

async function serve (name) {
  const topic = Buffer.alloc(32)
  sodium.crypto_generichash(topic, Buffer.from(name))
  swarm.on('connection', (conn, info) => {
    console.log(`PEER|connection from ${didOf(conn.remotePublicKey)} client=${info.client}`)
    conn.on('data', (data) => {
      console.log('PEER|echo ' + data.length + ' bytes')
      conn.write(data)
    })
    conn.on('end', () => conn.end())
    conn.on('error', () => {})
    conn.on('close', () => console.log('PEER|closed'))
  })
  await swarm.join(topic, { server: true, client: false }).flushed()
  console.log(`PEER|${didOf(swarm.keyPair.publicKey)} topic=${topic.toString('hex')}`)
}

const commands = { dial, serve }
if (!commands[command]) {
  console.error('usage: node swarm-peer.js <dial | serve> [args]')
  process.exit(1)
}
commands[command](...args)
