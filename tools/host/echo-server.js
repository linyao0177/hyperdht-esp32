// UDX echo peer for the ESP32-C3 PoC.
//
// The device sends "hello <deviceStreamId>" over the raw socket; we answer
// "ready <ourStreamId>" and echo everything received on the UDX stream.
//
//   node echo-server.js [port]

const UDX = require('udx-native')

const port = Number(process.argv[2]) || 9000
const udx = new UDX()
const socket = udx.createSocket()

// Must match pattern_at() in main/udx_echo.c.
const patternAt = (o) => (Math.imul(o, 31) + (o >>> 8)) & 0xff

// Offset delta at which the bytes match the pattern, or 'none'.
function findShift (data, at, offset) {
  const probe = Math.min(32, data.byteLength - at)
  for (let d = -16384; d <= 16384; d++) {
    if (d === 0 || offset + d < 0) continue
    let k = 0
    while (k < probe && data[at + k] === patternAt(offset + d + k)) k++
    if (k === probe) return d
  }
  return 'none'
}

let nextId = 1000
const sessions = new Map() // `${host}:${port}:${deviceId}` -> { id, stream }

socket.on('message', (buf, rinfo) => {
  const match = /^hello (\d+)$/.exec(buf.toString())
  if (!match) return

  const deviceId = Number(match[1])
  const key = `${rinfo.host}:${rinfo.port}:${deviceId}`
  let session = sessions.get(key)

  if (!session) {
    const id = nextId++
    const stream = udx.createStream(id)
    const started = Date.now()
    let bytes = 0

    stream.connect(socket, deviceId, rinfo.port, rinfo.host)
    let stats = ''
    const snapshot = () => {
      try {
        stats = `pkts_tx=${stream.packetsTransmitted} pkts_rx=${stream.packetsReceived} ` +
          `retransmits=${stream.retransmits} fast_recoveries=${stream.fastRecoveries} ` +
          `rtos=${stream.rtoCount} rtt=${stream.rtt} cwnd=${stream.cwnd}`
      } catch {}
    }

    let mismatched = false
    stream.on('data', (data) => {
      if (!mismatched) {
        for (let i = 0; i < data.byteLength; i++) {
          if (data[i] !== patternAt(bytes + i)) {
            mismatched = true
            console.log(`[${id}] MISMATCH from device at offset ${bytes + i} ` +
              `(chunk at ${bytes}, len ${data.byteLength}, index ${i}): ` +
              `expected ${patternAt(bytes + i).toString(16)} got ${data[i].toString(16)}, ` +
              `shift ${findShift(data, i, bytes + i)}, bytes ${data.subarray(i, i + 16).toString('hex')}`)
            break
          }
        }
      }
      bytes += data.byteLength
      stream.write(data)
      snapshot()
    })
    stream.on('error', (err) => {
      snapshot()
      console.log(`[${id}] error: ${err.message}`)
    })
    stream.on('close', () => {
      const secs = (Date.now() - started) / 1000
      console.log(`[${id}] closed: echoed ${bytes} bytes in ${secs.toFixed(1)}s ${stats}`)
      sessions.delete(key)
    })

    session = { id, stream }
    sessions.set(key, session)
    console.log(`[${id}] session from ${rinfo.host}:${rinfo.port} device stream ${deviceId}`)
  }

  socket.trySend(Buffer.from(`ready ${session.id}`), rinfo.port, rinfo.host)
})

socket.bind(port, '0.0.0.0')
console.log(`udx echo server on udp ${socket.address().port}`)
