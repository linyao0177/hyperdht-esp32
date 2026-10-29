// Peers for testing hdht's blind relay support (components/hdht relay.c).
//
// usage: node relay-test.js <bootstrap host:port | public> <command> [args]
//
//   relay                      a blind-relay node: prints RELAY|<key>, logs pairings
//   server [relay key]         echo server (seed 0x23 * 32); with a key, it asks
//                              clients to pair at that relay (relayThrough)
//   client <key> [relay key]   connects, sends a message, prints the echo and
//                              the address the stream runs over
//
// Every output line starts with RELAY|, SERVER| or CLIENT|.

const HyperDHT = require('hyperdht')
const relay = require('blind-relay')

const [where, command, ...args] = process.argv.slice(2)
const dht = new HyperDHT({ bootstrap: where === 'public' ? undefined : [where] })
const hex = (k) => Buffer.from(k, 'hex')

async function runRelay () {
  const server = new relay.Server({
    createStream (opts) {
      return dht.createRawStream({ ...opts, framed: true })
    }
  })
  const s = dht.createServer((socket) => {
    const session = server.accept(socket, { id: socket.remotePublicKey })
    session.on('pair', (isInitiator, token) => console.log(`RELAY|paired ${isInitiator ? 'initiator' : 'other side'} token=${token.toString('hex').slice(0, 8)}`))
    session.on('error', (err) => console.log('RELAY|session error ' + err.message))
    socket.on('error', () => {})
  })
  const keyPair = HyperDHT.keyPair(Buffer.alloc(32, 0x24))
  await s.listen(keyPair)
  console.log('RELAY|' + keyPair.publicKey.toString('hex'))
  setInterval(() => console.log('RELAY|stats ' + JSON.stringify(server.stats.pairings)), 10000).unref()
}

async function runServer (relayKey) {
  const s = dht.createServer({ relayThrough: relayKey ? hex(relayKey) : null }, (conn) => {
    const raw = conn.rawStream
    console.log(`SERVER|connection from ${conn.remotePublicKey.toString('hex').slice(0, 16)} over ${raw.remoteHost}:${raw.remotePort}`)
    conn.on('data', (data) => conn.write(data))
    conn.on('end', () => conn.end())
    conn.on('error', (err) => console.log('SERVER|error ' + err.message))
  })
  const keyPair = HyperDHT.keyPair(Buffer.alloc(32, 0x23))
  await s.listen(keyPair)
  console.log('SERVER|' + keyPair.publicKey.toString('hex'))
}

async function runClient (key, relayKey) {
  const started = Date.now()
  const conn = dht.connect(hex(key), { relayThrough: relayKey ? hex(relayKey) : null })
  conn.on('error', async (err) => {
    console.log('CLIENT|error ' + err.message)
    await dht.destroy()
    process.exit(1)
  })
  conn.on('open', () => {
    const raw = conn.rawStream
    console.log(`CLIENT|open after ${Date.now() - started} ms over ${raw.remoteHost}:${raw.remotePort}`)
    conn.write(Buffer.from('hello through the relay'))
  })
  conn.once('data', async (data) => {
    console.log('CLIENT|echo ' + data.toString())
    conn.end()
    await new Promise((resolve) => setTimeout(resolve, 300))
    await dht.destroy()
    process.exit(0)
  })
}

const commands = { relay: runRelay, server: runServer, client: runClient }
if (!commands[command]) {
  console.error('usage: node relay-test.js <bootstrap | public> <relay | server | client> [args]')
  process.exit(1)
}
commands[command](...args)
