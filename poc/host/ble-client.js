// BLE central for ble/ (the ESP32-C3 SecretStream-over-GATT demo).
//
// Scans for the hdht service, checks the advertised key hash, connects, runs
// the official @hyperswarm/secret-stream (Noise XX, initiator) over the two
// characteristics, checks the device key, then measures echo latency and
// throughput. Prints "BLECLIENT|..." lines.
//
//   node ble-client.js [seed byte, default 0x33] [throughput bytes, default 32768] [rsp|norsp]
//
// rsp (default) uses acknowledged GATT writes; norsp uses write-without-response,
// which is faster. A lost write would break SecretStream decryption, not pass silently.
//
// On macOS, run it through make-ble-app.sh: Bluetooth needs an app bundle
// with NSBluetoothAlwaysUsageDescription.

const noble = require('@abandonware/noble')
const NoiseSecretStream = require('@hyperswarm/secret-stream')
const { Duplex } = require('streamx')
const sodium = require('sodium-universal')
const b4a = require('b4a')

const SVC = '1d9e00013c2a4b8e9f5e6864687462ee'
const RX = '1d9e00023c2a4b8e9f5e6864687462ee'
const TX = '1d9e00033c2a4b8e9f5e6864687462ee'

const seedByte = Number(process.argv[2] || 0x33)
const throughputBytes = Number(process.argv[3] || 32768)
const withoutResponse = process.argv[4] === 'norsp'
const deviceKey = NoiseSecretStream.keyPair(b4a.alloc(32, seedByte)).publicKey
const deviceHash = b4a.alloc(32)
sodium.crypto_generichash(deviceHash, deviceKey)

const started = Date.now()
const log = (...parts) => console.log(['BLECLIENT', ...parts].join('|'))
const fail = (msg) => {
  log('error', msg)
  process.exit(1)
}

setTimeout(() => fail('timeout'), 120000)

noble.on('stateChange', (state) => {
  log('state', state)
  // duplicates on: the first report can arrive before the scan response (name + key hash)
  if (state === 'poweredOn') noble.startScanning([SVC], true)
  else if (state !== 'unknown') fail(`bluetooth ${state}`)
})

let connecting = false

noble.on('discover', async (peripheral) => {
  const mfg = peripheral.advertisement.manufacturerData
  if (connecting || !mfg) return
  const hashOk = !!mfg && mfg.length >= 10 && b4a.equals(mfg.subarray(2, 10), deviceHash.subarray(0, 8))
  log('found', peripheral.advertisement.localName, `rssi=${peripheral.rssi}`, `key_hash_matches=${hashOk}`, `${Date.now() - started}ms`)
  if (!hashOk) return

  connecting = true
  await noble.stopScanningAsync()
  try {
    await run(peripheral)
  } catch (err) {
    fail(err.message)
  }
})

async function run(peripheral) {
  const t0 = Date.now()
  await peripheral.connectAsync()
  const { characteristics } = await peripheral.discoverSomeServicesAndCharacteristicsAsync([SVC], [RX, TX])
  const rx = characteristics.find((c) => c.uuid === RX)
  const tx = characteristics.find((c) => c.uuid === TX)
  const chunk = Math.max(20, (peripheral.mtu || 185) - 3)
  log('connected', `${Date.now() - t0}ms`, `mtu=${peripheral.mtu}`, `chunk=${chunk}`, `writes=${withoutResponse ? 'norsp' : 'rsp'}`)

  const gatt = new Duplex({
    async write(data, cb) {
      try {
        for (let i = 0; i < data.length; i += chunk) await rx.writeAsync(data.subarray(i, i + chunk), withoutResponse)
        cb(null)
      } catch (err) {
        cb(err)
      }
    }
  })
  tx.on('data', (data) => gatt.push(data))
  await tx.subscribeAsync()

  const hs = Date.now()
  const stream = new NoiseSecretStream(true, gatt)
  await new Promise((resolve, reject) => {
    stream.once('open', resolve)
    stream.once('error', reject)
  })
  const keyOk = b4a.equals(stream.remotePublicKey, deviceKey)
  log('open', `handshake=${Date.now() - hs}ms`, `device_key_matches=${keyOk}`)
  if (!keyOk) throw new Error('device key mismatch')

  const queue = []
  stream.on('data', (data) => queue.shift()(data))
  const echo = (msg) =>
    new Promise((resolve) => {
      queue.push(resolve)
      stream.write(msg)
    })

  // latency: 10 sequential round trips
  const rtts = []
  for (let i = 0; i < 10; i++) {
    const msg = b4a.from(`ping ${i}`)
    const t = Date.now()
    const back = await echo(msg)
    if (!b4a.equals(back, msg)) throw new Error('echo mismatch')
    rtts.push(Date.now() - t)
  }
  rtts.sort((a, b) => a - b)
  log('latency', `min=${rtts[0]}ms`, `median=${rtts[5]}ms`, `max=${rtts[9]}ms`)

  // throughput: 200-byte messages, 8 in flight
  const size = 200
  const total = Math.ceil(throughputBytes / size)
  const t1 = Date.now()
  let sent = 0
  let ok = 0
  await new Promise((resolve, reject) => {
    const pump = () => {
      while (sent < total && sent - ok < 8) {
        const msg = b4a.alloc(size, sent & 0xff)
        sent++
        echo(msg).then((back) => {
          if (!b4a.equals(back, msg)) return reject(new Error('echo mismatch'))
          ok++
          if (ok === total) resolve()
          else pump()
        })
      }
    }
    pump()
  })
  const secs = (Date.now() - t1) / 1000
  log('throughput', `bytes=${total * size}`, `secs=${secs.toFixed(2)}`, `each_way=${((total * size) / 1024 / secs).toFixed(1)}KiB/s`)

  stream.end()
  await new Promise((resolve) => setTimeout(resolve, 300))
  await peripheral.disconnectAsync()
  log('done', 'ok')
  process.exit(0)
}
