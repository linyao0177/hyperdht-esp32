// A BoAT MER 0xEE00 seller over HyperDHT, the other end of examples/boat_mer.
//
// It speaks MER's streaming nanopayment protocol unchanged, one GATT operation
// per HyperDHT message (op | uuid16 LE | value), simulates a power output that
// switches on and off, and verifies every EIP-3009 authorization the board
// signs, the way a settlement service would. Nothing is submitted on-chain.
//
// It publishes its DID record ({"v":1,"did","eth","eth_sig"}, a HyperDHT
// mutable record under its key) so buyers can check the payee, and reads each
// buyer's record to check that the payments are signed by the buyer DID's own
// wallet.
//
// usage: node mer-seller.js <bootstrap host:port | public> [seconds, default 150] [--wrong-payee]
//
// --wrong-payee  bill to a wallet other than the one in the DID record (the
//                board should refuse to sign)

const crypto = require('crypto')
const HyperDHT = require('hyperdht')
const { Wallet, verifyMessage, verifyTypedData } = require('ethers')

const args = process.argv.slice(2).filter((a) => !a.startsWith('--'))
const wrongPayee = process.argv.includes('--wrong-payee')
const [where = 'public', seconds = '150'] = args
const bootstrap = where === 'public' ? undefined : [where]

const OP_WRITE = 1
const OP_READ = 2
const OP_READ_RESULT = 3
const OP_NOTIFY = 4

const CHR_STREAM_REQUEST = 0xee01
const CHR_STREAM_OFFER = 0xee02
const CHR_SLICE_REQUEST = 0xee03
const CHR_SLICE_PAYMENT = 0xee04
const CHR_STREAM_STATUS = 0xee05

const RATE = 250000 // micro-USDC per kWh ($0.25)
const SLICE_MS = 5000
const MAX_SESSION = 500000
const POWER_ON_S = 40 // simulated output: 12 W for 40 s, then 0 W for 20 s
const POWER_OFF_S = 20

// the EIP-712 domain the board signs under (examples/boat_mer Kconfig defaults)
const domain = {
  name: 'GatewayWalletBatched',
  version: '1',
  chainId: 5042002,
  verifyingContract: '0x0077777d7EBA4688BDeF3E311b846F25870A19B9'
}
const types = {
  TransferWithAuthorization: [
    { name: 'from', type: 'address' },
    { name: 'to', type: 'address' },
    { name: 'value', type: 'uint256' },
    { name: 'validAfter', type: 'uint256' },
    { name: 'validBefore', type: 'uint256' },
    { name: 'nonce', type: 'bytes32' }
  ]
}

const keyPair = HyperDHT.keyPair(Buffer.alloc(32, 0x44))
const wallet = new Wallet('0x' + Buffer.alloc(32, 0x45).toString('hex')) // receives the payments
const billTo = wrongPayee ? new Wallet('0x' + Buffer.alloc(32, 0x46).toString('hex')).address : wallet.address
const USDC = Buffer.from('3600000000000000000000000000000000000000', 'hex') // Arc testnet

const totals = { verified: 0, failed: 0, micro: 0 }

// A DID record is valid when its did is the key it is stored under and its
// eth_sig (EIP-191 over the did) recovers to its eth address.
function verifyRecord (publicKey, value) {
  const r = JSON.parse(value.toString())
  if (r.did !== 'did:mw:' + publicKey.toString('hex')) return null
  if (verifyMessage(r.did, r.eth_sig).toLowerCase() !== r.eth.toLowerCase()) return null
  return r
}

function frame (op, uuid16, value = Buffer.alloc(0)) {
  const head = Buffer.from([op, uuid16 & 0xff, uuid16 >> 8])
  return Buffer.concat([head, value])
}

function powerDw (startedAt) {
  const t = Math.floor((Date.now() - startedAt) / 1000) % (POWER_ON_S + POWER_OFF_S)
  return t < POWER_ON_S ? 120 : 0
}

function serve (conn, dht) {
  const buyerDid = 'did:mw:' + conn.remotePublicKey.toString('hex')
  console.log('SELLER|buyer connected', buyerDid.slice(0, 23) + '...')

  let buyerEth = null // from the buyer's DID record
  const lookupStarted = Date.now()
  dht.mutableGet(conn.remotePublicKey).then((res) => {
    const r = res && verifyRecord(conn.remotePublicKey, res.value)
    buyerEth = r ? r.eth.toLowerCase() : null
    console.log(`SELLER|buyer record ${res ? 'seq=' + res.seq : 'not found'} valid=${r ? 'yes' : 'no'} eth=${r ? r.eth : '-'} lookup_ms=${Date.now() - lookupStarted}`)
  }).catch((err) => console.log('SELLER|buyer record lookup failed', err.message))

  const startedAt = Date.now()
  let heartbeat = 0
  let sessionId = 0
  let streaming = false
  let sliceId = 0
  let samples = []
  let lastRx = Date.now()
  const pending = new Map() // nonce -> requested slice

  const sampler = setInterval(() => samples.push(powerDw(startedAt) / 10), 1000)
  let slicer = null

  function status () {
    const b = Buffer.alloc(20)
    b.writeUInt8(2, 0) // proto_ver: ac_output_dw is valid
    b.writeUInt8(streaming ? 1 : 0, 1)
    b.writeUInt32LE(sessionId, 4)
    b.writeUInt32LE(++heartbeat, 8)
    b.writeUInt32LE(Date.now() - lastRx, 12)
    b.writeUInt16LE(powerDw(startedAt), 16)
    return b
  }

  function offer () {
    const b = Buffer.alloc(50)
    b.writeUInt32LE(RATE, 0)
    b.writeUInt32LE(SLICE_MS, 4)
    b.writeUInt16LE(1, 8)
    b.writeUInt32LE(MAX_SESSION, 10)
    b.writeUInt32LE(3, 14)
    b.writeUInt32LE(50, 18)
    USDC.copy(b, 22)
    return b
  }

  function sendSlice () {
    const avgW = samples.length ? samples.reduce((a, b) => a + b, 0) / samples.length : 0
    samples = []
    const wh = Math.round(avgW * (SLICE_MS / 1000) * 1e6 / 3600)
    const amount = Math.round(wh * RATE / 1e9)
    const nonce = crypto.randomBytes(32)
    const now = Math.floor(Date.now() / 1000)

    const b = Buffer.alloc(88)
    b.writeUInt32LE(++sliceId, 0)
    b.writeUInt32LE(0, 4)
    b.writeUInt32LE(now + 7 * 24 * 3600, 8)
    nonce.copy(b, 12)
    Buffer.from(billTo.slice(2), 'hex').copy(b, 44)
    b.writeBigUInt64LE(BigInt(amount), 64)
    b.writeUInt32LE(wh, 72)
    b.writeUInt32LE(Math.round(avgW * 1000), 76)

    pending.set(nonce.toString('hex'), { sliceId, amount, sentAt: Date.now() })
    console.log(`SELLER|slice request id=${sliceId} avg_w=${avgW.toFixed(1)} amount=${amount}`)
    conn.write(frame(OP_NOTIFY, CHR_SLICE_REQUEST, b))
  }

  function checkProof (json) {
    const p = JSON.parse(json)
    const req = pending.get(p.nonce.slice(2))
    pending.delete(p.nonce.slice(2))
    const message = { from: p.from, to: p.to, value: BigInt(p.value), validAfter: p.validAfter, validBefore: p.validBefore, nonce: p.nonce }
    const signer = verifyTypedData(domain, types, message, p.sig)
    const bound = buyerEth === null ? 'unknown' : signer.toLowerCase() === buyerEth ? 'yes' : 'no'
    const ok = req !== undefined &&
      signer.toLowerCase() === p.from.toLowerCase() &&
      bound === 'yes' &&
      p.to.toLowerCase() === billTo.toLowerCase() &&
      Number(p.value) === req.amount &&
      p.slice_id === req.sliceId
    if (ok) {
      totals.verified++
      totals.micro += req.amount
    } else {
      totals.failed++
    }
    const rtt = req ? Date.now() - req.sentAt : -1
    console.log(`SELLER|proof slice=${p.slice_id} value=${p.value} signer=${signer} signer_is_buyer_did=${bound} ${ok ? 'VERIFIED' : 'REJECTED'} rtt_ms=${rtt}`)
  }

  conn.on('data', (msg) => {
    lastRx = Date.now()
    if (msg.length < 3) return
    const op = msg[0]
    const uuid16 = msg[1] | msg[2] << 8
    const value = msg.subarray(3)

    if (op === OP_READ && uuid16 === CHR_STREAM_STATUS) {
      conn.write(frame(OP_READ_RESULT, uuid16, Buffer.concat([Buffer.from([0]), status()])))
    } else if (op === OP_WRITE && uuid16 === CHR_STREAM_REQUEST) {
      if (value.length === 0 || value[0] === 2) {
        sessionId++
        streaming = true
        sliceId = 0
        samples = []
        console.log(`SELLER|stream open session=${sessionId}`)
        conn.write(frame(OP_NOTIFY, CHR_STREAM_OFFER, offer()))
        clearInterval(slicer)
        slicer = setInterval(sendSlice, SLICE_MS)
      } else {
        streaming = false
        clearInterval(slicer)
        console.log(`SELLER|stream closed session=${sessionId}`)
      }
    } else if (op === OP_WRITE && uuid16 === CHR_SLICE_PAYMENT) {
      try {
        checkProof(value.toString())
      } catch (err) {
        totals.failed++
        console.log('SELLER|bad proof', err.message)
      }
    }
  })

  conn.on('error', (err) => console.log('SELLER|connection error', err.message))
  conn.on('close', () => {
    clearInterval(sampler)
    clearInterval(slicer)
    console.log('SELLER|buyer disconnected')
  })
}

async function main () {
  const dht = new HyperDHT({ bootstrap })
  const server = dht.createServer((conn) => serve(conn, dht))
  await server.listen(keyPair)
  const did = 'did:mw:' + keyPair.publicKey.toString('hex')
  console.log('SELLER|listening ' + did)

  const record = { v: 1, did, eth: wallet.address, eth_sig: await wallet.signMessage(did) }
  const seq = Math.floor(Date.now() / 1000) // rises across restarts
  const put = await dht.mutablePut(keyPair, Buffer.from(JSON.stringify(record)), { seq })
  console.log(`SELLER|record published seq=${seq} nodes=${put.closestNodes.length} payee=${wallet.address}`)
  if (wrongPayee) console.log('SELLER|--wrong-payee: billing to', billTo)

  setTimeout(async () => {
    console.log(`SELLER|summary verified=${totals.verified} failed=${totals.failed} micro_usdc=${totals.micro}`)
    await dht.destroy()
    process.exit(0)
  }, Number(seconds) * 1000)
}

main()
