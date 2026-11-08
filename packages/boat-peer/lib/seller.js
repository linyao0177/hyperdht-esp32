// A seller for BoAT MER's streaming nanopayment protocol (0xEE00), over any
// Holepunch stream: a HyperDHT connection or a Hyperswarm one.
//
// MER's buyer was written for BLE GATT. Over a stream, each message carries one
// GATT operation, with the characteristic values unchanged:
//
//   op (1 byte) | characteristic uuid16 (little-endian) | value
//
// The seller offers a rate, bills the buyer once per slice for what it metered,
// and checks every EIP-3009 authorization the buyer signs: the signer must be
// the wallet in the buyer's DID record, and the payee, amount and slice must be
// what was billed. Settling the authorizations on-chain is the app's job.
//
// settle: 'session' asks for session settlement (BOAT_NANO_OFFER_SESSION_SETTLE,
// a BoAT MER buyer with patches/boat-mer 0002): every slice of a paying
// session carries one nonce and validity, and the buyer signs the session's
// running total. Only one of those authorizations can ever be executed, so the
// app settles the last one when the session ends ('session' event): one
// transfer per session instead of one per slice.

const b4a = require('b4a')
const sodium = require('sodium-universal')
const EventEmitter = require('bare-events')
const eth = require('./eth')
const { didOf, resolveDid } = require('./did')

const OP = { WRITE: 1, READ: 2, READ_RESULT: 3, NOTIFY: 4 }
const CHR = { STREAM_REQUEST: 0xee01, STREAM_OFFER: 0xee02, SLICE_REQUEST: 0xee03, SLICE_PAYMENT: 0xee04, STREAM_STATUS: 0xee05 }

function frame (op, uuid16, value = b4a.alloc(0)) {
  return b4a.concat([b4a.from([op, uuid16 & 0xff, uuid16 >> 8]), value])
}

function view (bytes) {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
}

class Seller extends EventEmitter {
  // payee: the wallet that is billed (the one in this seller's DID record)
  // domain: the EIP-712 domain buyers sign under ({name, version, chainId, verifyingContract})
  // token: the payment token's address; rate: micro-USDC per kWh
  // power: () => watts the seller is delivering now
  constructor ({ payee, domain, token, rate, sliceMs = 5000, maxSession = 500000, powerRange = [3, 50], power, settle = 'slice' }) {
    super()
    if (settle !== 'slice' && settle !== 'session') throw new Error("settle must be 'slice' or 'session'")
    this.settle = settle
    this.payee = payee
    this.domain = domain
    this.token = token
    this.rate = rate
    this.sliceMs = sliceMs
    this.maxSession = maxSession
    this.powerRange = powerRange
    this.power = power
  }

  // serves one buyer on a stream; `dht` reads the buyer's DID record
  serve (conn, dht) {
    const buyer = conn.remotePublicKey
    const buyerDid = didOf(buyer)
    const s = { buyerDid, eth: null, session: 0, streaming: false, sliceId: 0, heartbeat: 0, samples: [], lastRx: Date.now(), pending: new Map(), slicer: null, nonce: null, validBefore: 0, paid: 0n, paidSlices: 0, last: null }
    this.emit('buyer', { did: buyerDid })

    const started = Date.now()
    resolveDid(dht, buyer).then((res) => {
      s.eth = res && res.record ? res.record.eth.toLowerCase() : null
      this.emit('record', { did: buyerDid, found: !!res, valid: !!(res && res.record), eth: res && res.record ? res.record.eth : null, ms: Date.now() - started })
    }, (err) => this.emit('record', { did: buyerDid, found: false, valid: false, eth: null, error: err.message }))

    const sampler = setInterval(() => s.samples.push(this.power()), Math.min(1000, this.sliceMs / 5))

    const status = () => {
      const b = b4a.alloc(20)
      const v = view(b)
      v.setUint8(0, 2) // proto_ver: ac_output_dw is valid
      v.setUint8(1, s.streaming ? 1 : 0)
      v.setUint32(4, s.session, true)
      v.setUint32(8, ++s.heartbeat, true)
      v.setUint32(12, Date.now() - s.lastRx, true)
      v.setUint16(16, Math.round(this.power() * 10), true)
      return b
    }

    const offer = () => {
      const b = b4a.alloc(50)
      const v = view(b)
      v.setUint32(0, this.rate, true)
      v.setUint32(4, this.sliceMs, true)
      v.setUint16(8, 1, true) // batch size
      v.setUint32(10, this.maxSession, true)
      v.setUint32(14, this.powerRange[0], true)
      v.setUint32(18, this.powerRange[1], true)
      b4a.from(this.token.slice(2), 'hex').copy(b, 22)
      v.setUint8(42, this.settle === 'session' ? 1 : 0) // flags: BOAT_NANO_OFFER_SESSION_SETTLE
      return b
    }

    // a session's paid total and its last authorization, for session settlement
    const endSession = () => {
      if (s.last) this.emit('session', { did: buyerDid, session: s.session, authorization: s.last, total: String(s.paid), slices: s.paidSlices })
      s.last = null
    }

    const bill = () => {
      const watts = s.samples.length ? s.samples.reduce((a, b) => a + b, 0) / s.samples.length : 0
      s.samples = []
      const microWh = Math.round(watts * (this.sliceMs / 1000) * 1e6 / 3600)
      const amount = Math.round(microWh * this.rate / 1e9)
      let nonce = s.nonce
      if (this.settle === 'slice') {
        nonce = b4a.alloc(32)
        sodium.randombytes_buf(nonce)
      }

      const b = b4a.alloc(88)
      const v = view(b)
      v.setUint32(0, ++s.sliceId, true)
      v.setUint32(4, 0, true) // valid after
      v.setUint32(8, this.settle === 'session' ? s.validBefore : Math.floor(Date.now() / 1000) + 7 * 24 * 3600, true) // valid before
      nonce.copy(b, 12)
      b4a.from(this.payee.slice(2), 'hex').copy(b, 44)
      v.setBigUint64(64, BigInt(amount), true)
      v.setUint32(72, microWh, true)
      v.setUint32(76, Math.round(watts * 1000), true)

      s.pending.set(s.sliceId, { slice: s.sliceId, nonce: b4a.toString(nonce, 'hex'), amount, sentAt: Date.now() })
      this.emit('slice', { did: buyerDid, slice: s.sliceId, watts, amount })
      conn.write(frame(OP.NOTIFY, CHR.SLICE_REQUEST, b))
    }

    const check = (json) => {
      const p = JSON.parse(json)
      const nonce = String(p.nonce).replace(/^0x/, '').toLowerCase()
      const req = s.pending.get(p.slice_id)
      s.pending.delete(p.slice_id)
      // session settlement: the buyer signs what it has paid so far plus this slice
      const expected = req ? (this.settle === 'session' ? s.paid + BigInt(req.amount) : BigInt(req.amount)) : 0n
      const transfer = { from: p.from, to: p.to, value: p.value, validAfter: p.validAfter, validBefore: p.validBefore, nonce: p.nonce }
      const signer = eth.verifyTransfer(this.domain, transfer, p.sig)
      let reason = null
      if (!req || req.nonce !== nonce) reason = 'not billed'
      else if (signer.toLowerCase() !== String(p.from).toLowerCase()) reason = 'signer is not from'
      else if (s.eth === null) reason = 'buyer has no valid DID record'
      else if (signer.toLowerCase() !== s.eth) reason = 'signer is not the wallet in the buyer DID record'
      else if (String(p.to).toLowerCase() !== this.payee.toLowerCase()) reason = 'wrong payee'
      else if (BigInt(p.value) !== expected) reason = 'wrong amount'
      const authorization = { ...transfer, value: String(p.value), signature: p.sig }
      if (reason === null && this.settle === 'session') {
        s.paid = expected
        s.paidSlices++
        s.last = authorization
      }
      this.emit('payment', {
        ok: reason === null,
        reason,
        did: buyerDid,
        slice: p.slice_id,
        signer,
        session: s.session,
        cumulative: this.settle === 'session',
        authorization,
        rttMs: req ? Date.now() - req.sentAt : -1
      })
    }

    conn.on('data', (msg) => {
      s.lastRx = Date.now()
      if (msg.length < 3) return
      const op = msg[0]
      const uuid16 = msg[1] | msg[2] << 8
      const value = msg.subarray(3)

      if (op === OP.READ && uuid16 === CHR.STREAM_STATUS) {
        conn.write(frame(OP.READ_RESULT, uuid16, b4a.concat([b4a.from([0]), status()])))
      } else if (op === OP.WRITE && uuid16 === CHR.STREAM_REQUEST) {
        clearInterval(s.slicer)
        if (value.length === 0 || value[0] === 2) {
          endSession()
          s.session++
          s.paid = 0n
          s.paidSlices = 0
          s.nonce = b4a.alloc(32)
          sodium.randombytes_buf(s.nonce)
          s.validBefore = Math.floor(Date.now() / 1000) + 7 * 24 * 3600
          s.streaming = true
          s.sliceId = 0
          s.samples = []
          this.emit('open', { did: buyerDid, session: s.session })
          conn.write(frame(OP.NOTIFY, CHR.STREAM_OFFER, offer()))
          s.slicer = setInterval(bill, this.sliceMs)
        } else {
          s.streaming = false
          this.emit('end', { did: buyerDid, session: s.session })
          endSession()
        }
      } else if (op === OP.WRITE && uuid16 === CHR.SLICE_PAYMENT) {
        try {
          check(b4a.toString(value))
        } catch (err) {
          this.emit('payment', { ok: false, reason: 'malformed: ' + err.message, did: buyerDid })
        }
      }
    })

    conn.on('error', () => {})
    conn.on('close', () => {
      clearInterval(sampler)
      clearInterval(s.slicer)
      endSession()
      this.emit('close', { did: buyerDid })
    })
    return s
  }
}

module.exports = { Seller, frame, OP, CHR }
