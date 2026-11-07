// A WDK EVM signer whose key stays on a BoAT MER device.
//
// The device (examples/boat_mer with CONFIG_MER_OWNER_KEY) is reached by its
// DID over HyperDHT, authenticated as the owner's key. WDK hands this signer
// what to sign; the device signs and sends the signature back, like a
// hardware wallet does over USB. Every signature is checked here against the
// device's address before it goes back to WDK.
//
// What the device signs: EIP-191 messages, and EIP-712 typed data of one
// type, EIP-3009 TransferWithAuthorization from its own address, within its
// own limits. It signs no transactions, so it needs no gas: another account
// submits its authorizations (BoatProtocolEvm.settle).
//
//   const signer = await BoatDeviceSignerEvm.connect({ dht, did, keyPair })
//   const account = new WalletAccountEvm(signer, { provider })

import boatPeer from 'boat-peer'

const { keyOf, didOf, eth } = boatPeer

class UnsupportedOperationError extends Error {
  constructor (operation, why) {
    super(`${operation} is not supported by a BoAT device signer: ${why}`)
    this.name = 'UnsupportedOperationError'
  }
}

export default class BoatDeviceSignerEvm {
  // dht: a HyperDHT (or a Hyperswarm's swarm.dht); did: the device's DID;
  // keyPair: the owner's Ed25519 key pair, the one the device trusts
  constructor ({ dht, did, keyPair, timeout = 60000 }) {
    this._dht = dht
    this._deviceKey = keyOf(did)
    this._keyPair = keyPair
    this._timeout = timeout
    this._conn = null
    this._pending = new Map()
    this._nextId = 1
    this._address = null
    this._did = didOf(this._deviceKey)
  }

  static async connect (options) {
    const signer = new BoatDeviceSignerEvm(options)
    await signer.open()
    return signer
  }

  async open () {
    const conn = this._dht.connect(this._deviceKey, { keyPair: this._keyPair })
    this._conn = conn
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('device did not answer')), this._timeout)
      conn.once('open', () => { clearTimeout(timer); resolve() })
      conn.once('error', (err) => { clearTimeout(timer); reject(err) })
    })
    conn.on('data', (data) => this._ondata(data))
    conn.on('error', () => {})
    conn.on('close', () => {
      for (const { reject } of this._pending.values()) reject(new Error('the device closed the connection'))
      this._pending.clear()
    })
    const res = await this._request({ op: 'address' })
    if (res.did !== this._did) throw new Error('the device answered with another DID')
    this._address = eth.checksum(Buffer.from(res.address.slice(2), 'hex'))
  }

  _ondata (data) {
    let res
    try {
      res = JSON.parse(data.toString())
    } catch {
      // not a signer answer: the device sent an attested reading, so it does
      // not take this key as its owner
      for (const { reject } of this._pending.values()) reject(new Error('the device does not accept this key as its owner'))
      this._pending.clear()
      return
    }
    const p = this._pending.get(res.id)
    if (!p) {
      if (res.payload !== undefined) {
        for (const { reject } of this._pending.values()) reject(new Error('the device does not accept this key as its owner'))
        this._pending.clear()
      }
      return
    }
    this._pending.delete(res.id)
    clearTimeout(p.timer)
    if (res.ok) p.resolve(res)
    else p.reject(new Error('the device refused: ' + res.error))
  }

  _request (body) {
    const id = String(this._nextId++)
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this._pending.delete(id)
        reject(new Error('the device did not answer in time'))
      }, this._timeout)
      this._pending.set(id, { resolve, reject, timer })
      this._conn.write(Buffer.from(JSON.stringify({ id, ...body })))
    })
  }

  get isDerivable () { return false }
  get path () { return null }
  get address () { return this._address }
  get did () { return this._did }
  // the key never leaves the device
  get keyPair () { return { privateKey: null, publicKey: null } }

  async derive () {
    throw new UnsupportedOperationError('derive(path)', 'the device holds one key')
  }

  async getAddress () {
    return this._address
  }

  // EIP-191 personal_sign, on the device
  async sign (message) {
    const { signature } = await this._request({ op: 'sign', message: String(message) })
    if (eth.verifyMessage(String(message), signature) !== this._address) throw new Error('the device returned a signature by another key')
    return signature
  }

  // EIP-712: TransferWithAuthorization only, from the device's address
  async signTypedData ({ domain, types, message }) {
    const names = Object.keys(types).filter((t) => t !== 'EIP712Domain')
    if (names.length !== 1 || names[0] !== 'TransferWithAuthorization') {
      throw new UnsupportedOperationError('signTypedData', 'the device signs only EIP-3009 TransferWithAuthorization')
    }
    if (String(message.from).toLowerCase() !== this._address.toLowerCase()) throw new Error('the authorization is not from the device')
    const { signature } = await this._request({
      op: 'transfer',
      chainId: String(domain.chainId),
      token: domain.verifyingContract,
      name: domain.name,
      version: domain.version,
      to: message.to,
      value: String(message.value),
      validAfter: String(message.validAfter),
      validBefore: String(message.validBefore),
      nonce: message.nonce
    })
    const signer = eth.verifyTransfer(domain, { ...message, value: String(message.value) }, signature)
    if (signer !== this._address) throw new Error('the device returned a signature by another key')
    return signature
  }

  async signTransaction () {
    throw new UnsupportedOperationError('signTransaction', 'the device holds no gas; have another account submit its EIP-3009 authorizations')
  }

  async signAuthorization () {
    throw new UnsupportedOperationError('signAuthorization', 'the device does not delegate its account (EIP-7702)')
  }

  dispose () {
    if (this._conn) this._conn.end()
    this._conn = null
  }
}
