// Connects to the board's HyperDHT server several times and checks the echo.
//
//   node connect-board.js <bootstrap host:port | public> [rounds] [seed byte] [interval ms] [mode]
//
// mode: lan (default, allows the LAN shortcut), punch (localConnection: false,
// forces holepunching unless our node looks OPEN), punchfw (also makes our node
// firewalled, so the board has to holepunch as a server), alt (lan/punch per round)

const DHT = require('hyperdht')
const b4a = require('b4a')

const [host, port] = (process.argv[2] || 'public').split(':')
const rounds = Number(process.argv[3] || 5)
const seedByte = Number(process.argv[4] || 0x33)
const interval = Number(process.argv[5] || 1000)
const mode = process.argv[6] || 'lan'
const serverKey = DHT.keyPair(b4a.alloc(32, seedByte)).publicKey

main().catch((err) => {
  console.error(err)
  process.exit(1)
})

async function main() {
  // quickFirewall would flip the node to OPEN as soon as a LAN PING_NAT comes back
  const firewalled = mode === 'punchfw' ? { firewalled: true, ephemeral: true, quickFirewall: false } : {}
  const bootstrap = host === 'public' ? {} : { bootstrap: [{ host, port: Number(port) }] }
  const node = new DHT({ ...bootstrap, ...firewalled })
  await node.fullyBootstrapped()
  console.log(`BOARD|key|${b4a.toString(serverKey, 'hex')}`)

  let ok = 0
  for (let i = 1; i <= rounds; i++) {
    const punch = mode === 'punch' || mode === 'punchfw' || (mode === 'alt' && i % 2 === 0)
    // FRESH=1: a new node per round, so hyperdht's per-node random-punch limit does not carry over
    const roundNode = process.env.FRESH ? new DHT({ ...bootstrap, ...firewalled }) : node
    if (roundNode !== node) await roundNode.fullyBootstrapped()
    const result = await once(roundNode, i, punch)
    if (roundNode !== node) await roundNode.destroy()
    if (result.ok) ok++
    console.log(`BOARD|round|${i}|path=${punch ? 'punch' : 'lan'}|ok=${result.ok}|open_ms=${result.openMs}|echo_ms=${result.echoMs}|remote=${result.remote}|error=${result.error || '-'}|${new Date().toISOString()}`)
    await new Promise((resolve) => setTimeout(resolve, interval))
  }

  console.log(`BOARD|done|${ok}/${rounds}`)
  await node.destroy()
}

function once(node, i, punch) {
  return new Promise((resolve) => {
    const message = `ping ${i} from js`
    const started = Date.now()
    const socket = node.connect(serverKey, { localConnection: !punch })
    const result = { ok: false, openMs: -1, echoMs: -1, remote: '-', error: null }

    const timeout = setTimeout(() => {
      result.error = 'timeout'
      socket.destroy()
    }, 60000) // random-port holepunching can take ~35 s

    socket.on('open', () => {
      result.openMs = Date.now() - started
      result.remote = `${socket.rawStream.remoteHost}:${socket.rawStream.remotePort}`
      socket.write(b4a.from(message))
    })
    socket.on('data', (data) => {
      result.echoMs = Date.now() - started
      result.ok = b4a.toString(data) === message
      socket.end()
    })
    socket.on('error', (err) => {
      if (!result.error) result.error = err.message
    })
    socket.on('close', () => {
      clearTimeout(timeout)
      resolve(result)
    })
  })
}
