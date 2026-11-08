// A device's owner channel: the owner's app connects to the device's DID with
// the owner key (CONFIG_MER_OWNER_KEY on examples/boat_mer) and sends signing
// requests, one JSON object per message, answered {"id","ok":true,...} or
// {"id","ok":false,"error"}. A device that does not take the key as its owner
// answers with an attested reading instead. The wallet signers built on it
// (wdk-protocol-boat-evm, wdk-protocol-boat-solana) check every signature
// they get back.

const b4a = require('b4a')
const { keyOf, didOf } = require('./did')

class OwnerChannel {
  // dht: a HyperDHT (or a Hyperswarm's swarm.dht); did: the device's DID;
  // keyPair: the owner's Ed25519 key pair, the one the device trusts
  constructor ({ dht, did, keyPair, timeout = 60000 }) {
    this.dht = dht
    this.deviceKey = keyOf(did)
    this.did = didOf(this.deviceKey)
    this.keyPair = keyPair
    this.timeout = timeout
    this.conn = null
    this._pending = new Map()
    this._nextId = 1
  }

  async open () {
    const conn = this.dht.connect(this.deviceKey, { keyPair: this.keyPair })
    this.conn = conn
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('device did not answer')), this.timeout)
      conn.once('open', () => { clearTimeout(timer); resolve() })
      conn.once('error', (err) => { clearTimeout(timer); reject(err) })
    })
    conn.on('data', (data) => this._ondata(data))
    conn.on('error', () => {})
    conn.on('close', () => this._failAll('the device closed the connection'))
  }

  _failAll (why) {
    for (const p of this._pending.values()) {
      clearTimeout(p.timer)
      p.reject(new Error(why))
    }
    this._pending.clear()
  }

  _ondata (data) {
    let res
    try {
      res = JSON.parse(b4a.toString(data))
    } catch {
      // not an answer: the device sent an attested reading, so it does not
      // take this key as its owner
      this._failAll('the device does not accept this key as its owner')
      return
    }
    const p = this._pending.get(res.id)
    if (!p) {
      if (res.payload !== undefined) this._failAll('the device does not accept this key as its owner')
      return
    }
    this._pending.delete(res.id)
    clearTimeout(p.timer)
    if (res.ok) p.resolve(res)
    else p.reject(new Error('the device refused: ' + res.error))
  }

  request (body) {
    if (!this.conn) return Promise.reject(new Error('the owner channel is not open'))
    const id = String(this._nextId++)
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this._pending.delete(id)
        reject(new Error('the device did not answer in time'))
      }, this.timeout)
      this._pending.set(id, { resolve, reject, timer })
      this.conn.write(b4a.from(JSON.stringify({ id, ...body })))
    })
  }

  close () {
    if (this.conn) this.conn.end()
    this.conn = null
  }
}

module.exports = { OwnerChannel }
