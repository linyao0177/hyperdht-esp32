// Network peers for testing examples/uart_module (tools/module_test.py).
//
// usage: node module-peer.js <command> [args] [--bootstrap host:port]
//
//   serve <topic name> [--half-open yes]
//                             echo server: prints PEER|did, announces itself
//                             under BLAKE2b-256(topic name), echoes every message;
//                             --half-open never ends its side, like a stuck peer
//   dial <did> <text>         connects, sends text, prints the first reply
//   get <did>                 reads and prints a mutable record (checked by hyperdht)
//   lookup <hex topic>        prints the keys announced under a topic, each with
//                             the number of nodes listing it
//
// Every output line starts with PEER| so a test can find it.

const crypto = require('crypto')
const HyperDHT = require('hyperdht')
const sodium = require('sodium-universal')

const positional = []
const opts = {}
for (let i = 2; i < process.argv.length; i++) {
  const a = process.argv[i]
  if (a.startsWith('--')) opts[a.slice(2)] = process.argv[++i]
  else positional.push(a)
}
const [command, ...args] = positional
const dht = new HyperDHT({ bootstrap: opts.bootstrap ? [opts.bootstrap] : undefined })
const keyOf = (did) => Buffer.from(did.replace(/^did:mw:/, ''), 'hex')

async function serve (name) {
  const keyPair = HyperDHT.keyPair(crypto.randomBytes(32))
  const server = dht.createServer((conn) => {
    console.log('PEER|connection from did:mw:' + conn.remotePublicKey.toString('hex'))
    conn.on('data', (data) => {
      console.log('PEER|echo ' + data.length + ' bytes')
      conn.write(data)
    })
    if (!opts['half-open']) conn.on('end', () => conn.end())
    conn.on('error', () => {})
    conn.on('close', () => console.log('PEER|closed'))
  })
  await server.listen(keyPair)
  const topic = Buffer.alloc(32)
  sodium.crypto_generichash(topic, Buffer.from(name))
  await dht.announce(topic, keyPair, []).finished()
  console.log('PEER|did:mw:' + keyPair.publicKey.toString('hex') + ' topic=' + topic.toString('hex'))
}

async function dial (did, text) {
  const conn = dht.connect(keyOf(did))
  conn.on('error', (err) => {
    console.log('PEER|error ' + err.message)
    process.exit(1)
  })
  conn.on('open', () => {
    console.log('PEER|open')
    conn.write(Buffer.from(text))
  })
  conn.once('data', async (data) => {
    console.log('PEER|reply ' + data.toString())
    conn.end()
    await new Promise((resolve) => setTimeout(resolve, 500))
    await dht.destroy()
    process.exit(0)
  })
}

async function get (did) {
  const res = await dht.mutableGet(keyOf(did))
  console.log(res ? `PEER|record seq=${res.seq} value=${res.value.toString()}` : 'PEER|record none')
  await dht.destroy()
}

async function lookup (topic) {
  const keys = new Map()
  for await (const reply of dht.lookup(Buffer.from(topic, 'hex'))) {
    for (const peer of reply.peers) {
      const did = 'did:mw:' + peer.publicKey.toString('hex')
      keys.set(did, (keys.get(did) || 0) + 1)
    }
  }
  console.log('PEER|found ' + [...keys].map(([did, n]) => did + '=' + n).join(','))
  await dht.destroy()
}

const commands = { serve, dial, get, lookup }
if (!commands[command]) {
  console.error('usage: node module-peer.js <serve | dial | get | lookup> [args]')
  process.exit(1)
}
commands[command](...args)
