// Private HyperDHT testnet plus a reference peer for interop tests with the C port.
//
//   node testnet.js [--host 192.168.31.89] [--port 49800] [--size 10]
//                   [--server] [--firewalled] [--connect <hex public key>]
//
// --server      run a JS echo server on a fixed key pair (seed 0x11 * 32) and print its key
// --firewalled  make the JS server's DHT node firewalled so connections have to holepunch
// --connect     connect to a server (e.g. the C one) as a JS client and echo-test it
// --public      no testnet: use the public HyperDHT bootstrap nodes
//
// Prints one line per event, prefixed with "TESTNET|".

const createTestnet = require('hyperdht/testnet')
const DHT = require('hyperdht')
const b4a = require('b4a')

const args = parseArgs(process.argv.slice(2))
const host = args.host || '127.0.0.1'
const port = Number(args.port || 49800)
const size = Number(args.size || 10)

main().catch((err) => {
  console.error(err)
  process.exit(1)
})

async function main() {
  const testnet = args.public ? { bootstrap: undefined, destroy: async () => {} } : await createTestnet(size, { host, port })
  const bootstrap = testnet.bootstrap ? testnet.bootstrap.map((b) => `${b.host}:${b.port}`).join(',') : 'public'
  log('bootstrap', bootstrap)

  if (args.server) await runServer(testnet)
  if (args.connect) await runClient(testnet, args.connect)

  process.on('SIGINT', async () => {
    await testnet.destroy()
    process.exit(0)
  })
}

async function runServer(testnet) {
  const node = new DHT({
    bootstrap: testnet.bootstrap,
    host: '0.0.0.0',
    ...(args.firewalled ? { firewalled: true, ephemeral: true, adaptive: false } : {})
  })
  await node.fullyBootstrapped()

  const keyPair = DHT.keyPair(b4a.alloc(32, 0x11))
  const server = node.createServer((socket) => {
    const remote = b4a.toString(socket.remotePublicKey, 'hex')
    log('server-connection', remote, `${socket.rawStream.remoteHost}:${socket.rawStream.remotePort}`)
    socket.on('data', (data) => socket.write(data))
    socket.on('error', (err) => log('server-socket-error', err.message))
    socket.on('close', () => log('server-socket-close', remote))
  })

  await server.listen(keyPair)
  log('server', b4a.toString(keyPair.publicKey, 'hex'), `firewalled=${node.firewalled}`)
}

async function runClient(testnet, hexKey) {
  const node = new DHT({ bootstrap: testnet.bootstrap, host: '0.0.0.0' })
  await node.fullyBootstrapped()

  const started = Date.now()
  const socket = node.connect(b4a.from(hexKey, 'hex'))
  socket.on('open', () => {
    log('client-open', `${Date.now() - started}ms`, `${socket.rawStream.remoteHost}:${socket.rawStream.remotePort}`)
    socket.write(b4a.from('hello from js'))
  })
  socket.on('data', (data) => log('client-data', b4a.toString(data)))
  socket.on('error', (err) => log('client-error', err.message))
  socket.on('close', () => log('client-close'))
}

function log(...parts) {
  console.log(['TESTNET', ...parts].join('|'))
}

function parseArgs(argv) {
  const out = {}
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (!a.startsWith('--')) continue
    const key = a.slice(2)
    const next = argv[i + 1]
    if (next === undefined || next.startsWith('--')) out[key] = true
    else out[key] = argv[++i]
  }
  return out
}
