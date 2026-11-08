// Tests for boat-peer. They run the same in Node.js and in Bare:
//
//   node test/run.js
//   node_modules/bare/bin/bare test/run.js
//
// The Ethereum signatures are checked against vectors made with ethers
// (test/gen-vectors.js). The seller is driven by a buyer on an in-memory
// stream that signs the way MER's buyer does.

const b4a = require('b4a')
const sodium = require('sodium-universal')
const EventEmitter = require('bare-events')
const { eth, didOf, makeRecord, verifyRecord, payeeOf, verifyReading, sha256, Seller, frame, OP, CHR, signRecordVersion, verifyRecordVersion } = require('..')
const vectors = require('./vectors.json')

const runtime = typeof Bare !== 'undefined' ? 'bare' : 'node' // eslint-disable-line no-undef
let passed = 0
let failed = 0
function check (name, ok, detail = '') {
  if (ok) passed++
  else failed++
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? '  ' + detail : ''}`)
}

const key = (hex) => b4a.from(hex.replace(/^0x/, ''), 'hex')

function ed25519 (seedByte) {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, b4a.alloc(32, seedByte))
  return { publicKey, secretKey }
}

// a pair of in-memory streams, delivering asynchronously like a real one
function pair (aKey, bKey) {
  const a = new EventEmitter()
  const b = new EventEmitter()
  a.remotePublicKey = bKey
  b.remotePublicKey = aKey
  a.write = (m) => setTimeout(() => b.emit('data', b4a.from(m)), 1)
  b.write = (m) => setTimeout(() => a.emit('data', b4a.from(m)), 1)
  a.end = b.end = () => setTimeout(() => { a.emit('close'); b.emit('close') }, 1)
  return [a, b]
}

async function main () {
  // EIP-191 and EIP-712, against ethers
  for (const v of vectors.messages) {
    check(`address of key ${v.address.slice(0, 8)}`, eth.addressOf(key(v.key)) === v.address)
    check('personal_sign matches ethers', eth.signMessage(v.message, key(v.key)) === v.sig)
    check('personal_sign recovers', eth.verifyMessage(v.message, v.sig) === v.address)
  }
  for (const v of vectors.transfers) {
    check('EIP-712 transfer matches ethers', eth.signTransfer(vectors.domain, v.transfer, key(v.key)) === v.sig)
    check('EIP-712 transfer recovers', eth.verifyTransfer(vectors.domain, v.transfer, v.sig) === v.transfer.from)
    const changed = { ...v.transfer, value: String(Number(v.transfer.value) + 1) }
    check('EIP-712 changed value recovers someone else', eth.verifyTransfer(vectors.domain, changed, v.sig) !== v.transfer.from)
  }

  // DID records
  const device = ed25519(1)
  const deviceEth = key(vectors.messages[0].key)
  const record = makeRecord(device.publicKey, deviceEth)
  const value = b4a.from(JSON.stringify(record))
  check('DID record verifies', verifyRecord(device.publicKey, value) !== null)
  check('DID record under another key is refused', verifyRecord(ed25519(2).publicKey, value) === null)
  const otherWallet = { ...record, eth: vectors.messages[1].address }
  check('DID record claiming another wallet is refused', verifyRecord(device.publicKey, b4a.from(JSON.stringify(otherWallet))) === null)

  // DID record versions, kept in a log
  const version = signRecordVersion(device, record, 7)
  check('record version verifies', verifyRecordVersion(record.did, version) !== null)
  check('record version with another seq is refused', verifyRecordVersion(record.did, { ...version, seq: 8 }) === null)
  check('record version signed by another key is refused', verifyRecordVersion(record.did, signRecordVersion(ed25519(2), record, 7)) === null)
  check('record version claiming another wallet is refused', verifyRecordVersion(record.did, signRecordVersion(device, otherWallet, 7)) === null)

  // a record paying a smart account, the owner key vouching for it
  const safe = '0x97682ff1A980a96D65Ea606b717441E3662c557E'
  const paying = makeRecord(device.publicKey, deviceEth, { pay: safe })
  const payingValue = b4a.from(JSON.stringify(paying))
  check('record with a payee verifies, paid at the payee', verifyRecord(device.publicKey, payingValue) !== null && payeeOf(paying) === safe && payeeOf(record) === record.eth)
  check('record with its payee changed is refused', verifyRecord(device.publicKey, b4a.from(JSON.stringify({ ...paying, pay: '0x' + '11'.repeat(20) }))) === null)
  check('record with its payee dropped is refused', verifyRecord(device.publicKey, b4a.from(JSON.stringify({ ...paying, pay: undefined }))) === null)
  check('record with a payee signed as a plain one is refused', verifyRecord(device.publicKey, b4a.from(JSON.stringify({ ...record, pay: safe }))) === null)
  check('record with a malformed payee is refused', verifyRecord(device.publicKey, b4a.from(JSON.stringify({ ...paying, pay: 'nobody' }))) === null)

  // attested readings, made the way the device makes them
  const payload = JSON.stringify({ power_w: 12.0, t: 1793720788 })
  const hash = sha256(payload)
  const sig = b4a.alloc(64)
  sodium.crypto_sign_detached(sig, hash, device.secretKey)
  const reading = { did: didOf(device.publicKey), eth: record.eth, payload, hash: b4a.toString(hash, 'hex'), sig: b4a.toString(sig, 'hex') }
  const good = verifyReading(record.did, JSON.stringify(reading), { remotePublicKey: device.publicKey, record })
  check('reading verifies', good.ok, JSON.stringify(good.checks))
  const bad = verifyReading(record.did, JSON.stringify({ ...reading, payload: payload.replace('12', '13') }), { record })
  check('changed reading is refused', !bad.ok && !bad.checks.hash_matches_payload)
  check('reading from another stream peer is refused', !verifyReading(record.did, JSON.stringify(reading), { remotePublicKey: ed25519(2).publicKey }).ok)

  // the seller, with a buyer that signs like MER's
  const sellerEth = key(vectors.messages[2].key)
  const payee = eth.addressOf(sellerEth)
  const sellerA = new Seller({ payee, domain: vectors.domain, token: '0x3600000000000000000000000000000000000000', rate: 250000, sliceMs: 300, power: () => 1200 })
  const records = new Map([[b4a.toString(device.publicKey, 'hex'), value]])
  const dht = { mutableGet: async (k) => records.has(b4a.toString(k, 'hex')) ? { value: records.get(b4a.toString(k, 'hex')), seq: 1 } : null }

  async function session (buyerEthKey, { slices = 3, payTo = null, seller = sellerA, cumulative = null } = {}) {
    const [sellerSide, buyerSide] = pair(ed25519(9).publicKey, device.publicKey)
    const payments = []
    const sessions = []
    const onPayment = (p) => payments.push(p)
    const onSession = (e) => sessions.push(e)
    seller.on('payment', onPayment)
    seller.on('session', onSession)
    seller.serve(sellerSide, dht)
    let total = 0n
    await new Promise((resolve) => setTimeout(resolve, 20)) // record lookup
    let offer = null
    let n = 0
    await new Promise((resolve) => {
      buyerSide.on('data', (msg) => {
        const uuid16 = msg[1] | msg[2] << 8
        const v = msg.subarray(3)
        if (uuid16 === CHR.STREAM_OFFER) offer = v
        if (uuid16 !== CHR.SLICE_REQUEST) return
        const dv = new DataView(v.buffer, v.byteOffset, v.byteLength)
        // like MER: the running total when the offer asks for session settlement
        const sessionSettle = cumulative === null ? (offer[42] & 1) === 1 : cumulative
        total += dv.getBigUint64(64, true)
        const transfer = {
          from: eth.addressOf(buyerEthKey),
          to: payTo || '0x' + b4a.toString(v.subarray(44, 64), 'hex'),
          value: String(sessionSettle ? total : dv.getBigUint64(64, true)),
          validAfter: dv.getUint32(4, true),
          validBefore: dv.getUint32(8, true),
          nonce: '0x' + b4a.toString(v.subarray(12, 44), 'hex')
        }
        const proof = { ...transfer, sig: eth.signTransfer(vectors.domain, transfer, buyerEthKey), slice_id: dv.getUint32(0, true) }
        buyerSide.write(frame(OP.WRITE, CHR.SLICE_PAYMENT, b4a.from(JSON.stringify(proof))))
        if (++n === slices) {
          buyerSide.write(frame(OP.WRITE, CHR.STREAM_REQUEST, b4a.from([1])))
          setTimeout(resolve, 50)
        }
      })
      buyerSide.write(frame(OP.WRITE, CHR.STREAM_REQUEST, b4a.from([2])))
    })
    buyerSide.end()
    await new Promise((resolve) => setTimeout(resolve, 10))
    seller.off('payment', onPayment)
    seller.off('session', onSession)
    return { payments, offer, sessions }
  }

  const ok = await session(deviceEth)
  check('seller sends a 50-byte offer', ok.offer && ok.offer.length === 50)
  check('seller verifies 3 slices paid by the DID wallet', ok.payments.length === 3 && ok.payments.every((p) => p.ok), ok.payments.map((p) => p.reason || p.authorization.value).join(','))
  const stranger = await session(key(vectors.messages[3].key), { slices: 1 })
  check('payment by another wallet is refused', stranger.payments.length === 1 && stranger.payments[0].reason === 'signer is not the wallet in the buyer DID record', stranger.payments[0] && stranger.payments[0].reason)
  const redirected = await session(deviceEth, { slices: 1, payTo: vectors.messages[3].address })
  check('payment to another payee is refused', redirected.payments.length === 1 && redirected.payments[0].reason === 'wrong payee', redirected.payments[0] && redirected.payments[0].reason)

  // session settlement: one nonce, the running total, one 'session' to settle
  const sellerS = new Seller({ payee, domain: vectors.domain, token: '0x3600000000000000000000000000000000000000', rate: 250000, sliceMs: 300, power: () => 1200, settle: 'session' })
  const ss = await session(deviceEth, { seller: sellerS })
  const nonces = new Set(ss.payments.map((p) => p.authorization && p.authorization.nonce))
  check('session offer carries the flag', ss.offer[42] === 1)
  check('session: 3 running totals accepted on one nonce', ss.payments.length === 3 && ss.payments.every((p) => p.ok && p.cumulative) && nonces.size === 1, ss.payments.map((p) => p.reason || p.authorization.value).join(','))
  check('session: one authorization to settle, for the total', ss.sessions.length === 1 && ss.sessions[0].total === '75' && ss.sessions[0].authorization.value === '75' && ss.sessions[0].slices === 3)
  const perSlice = await session(deviceEth, { seller: sellerS, slices: 2, cumulative: false })
  check('session: a buyer signing the slice alone is refused', perSlice.payments.length === 2 && perSlice.payments[0].ok && perSlice.payments[1].reason === 'wrong amount' && perSlice.sessions.length === 1 && perSlice.sessions[0].total === '25', perSlice.payments.map((p) => p.reason || 'ok').join(','))

  console.log(`\n${runtime}: ${passed} of ${passed + failed} passed`)
  if (failed) throw new Error(failed + ' failed')
}

main()
