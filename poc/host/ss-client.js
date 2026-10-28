// Official @hyperswarm/secret-stream as initiator over TCP, against the C
// responder in hdht/test/test_ss.c. Checks the remote key and the echo.
//
//   node ss-client.js <port> <xx|ik>

const net = require('net')
const NoiseSecretStream = require('@hyperswarm/secret-stream')
const b4a = require('b4a')

const port = Number(process.argv[2] || 7777)
const pattern = (process.argv[3] || 'xx').toUpperCase()
const deviceKey = NoiseSecretStream.keyPair(b4a.alloc(32, 0x44)).publicKey

const socket = net.connect(port, '127.0.0.1')
const opts = pattern === 'IK' ? { pattern: 'IK', remotePublicKey: deviceKey } : {}
const stream = new NoiseSecretStream(true, socket, opts)
const message = `hello over ${pattern}`

stream.on('open', () => {
  const keyOk = b4a.equals(stream.remotePublicKey, deviceKey)
  console.log(`open, remote key matches device key: ${keyOk}`)
  stream.write(b4a.from(message))
})
stream.on('data', (data) => {
  console.log(`echo: ${b4a.toString(data)} (${b4a.toString(data) === message ? 'ok' : 'MISMATCH'})`)
  stream.end()
})
stream.on('error', (err) => console.log('error', err.message))
stream.on('close', () => socket.destroy())
