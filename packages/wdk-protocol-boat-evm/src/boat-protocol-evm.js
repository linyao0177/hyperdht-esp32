// BoAT MER devices for a WDK EVM account.
//
// A BoAT MER device signs an EIP-3009 TransferWithAuthorization for every
// slice it pays for. This protocol lets a WDK account take the other side:
// it signs the seller's DID record with the account, sells to devices over
// Holepunch (boat-peer's Seller, paid to the account), and settles each
// authorization by calling the token's transferWithAuthorization from the
// account, which pays the gas. It also gives x402 a facilitator signer
// backed by the same account.

import boatPeer from 'boat-peer'

const { Seller, didOf, verifyRecord, walletMessage, eth } = boatPeer

// transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)
const TRANSFER_WITH_AUTHORIZATION = '0xe3ee160e'
// authorizationState(address,bytes32)
const AUTHORIZATION_STATE = '0xe94a0102'

const strip = (hex) => String(hex).replace(/^0x/, '').toLowerCase()

function word (n) {
  const v = BigInt(n)
  if (v < 0n || v >= 1n << 256n) throw new Error('uint256 out of range')
  return v.toString(16).padStart(64, '0')
}

function addressWord (address) {
  const a = strip(address)
  if (!/^[0-9a-f]{40}$/.test(a)) throw new Error('bad address: ' + address)
  return a.padStart(64, '0')
}

function bytes32 (hex) {
  const b = strip(hex)
  if (!/^[0-9a-f]{64}$/.test(b)) throw new Error('bad bytes32: ' + hex)
  return b
}

// Multicall3, at the same address on most EVM chains (Arc and Stable included)
export const MULTICALL3 = '0xcA11bde05977b3631167028862bE2a173976CA11'
// aggregate3((address target, bool allowFailure, bytes callData)[])
const AGGREGATE3 = '0x82ad56cb'

const pad32 = (hex) => hex + '0'.repeat((64 - hex.length % 64) % 64)

// call data for Multicall3's aggregate3, every call allowed to fail or none
export function aggregate3Data (target, calls, { allowFailure = true } = {}) {
  const tuples = calls.map((data) => {
    const d = strip(data)
    return addressWord(target) + word(allowFailure ? 1 : 0) + word(0x60) + word(d.length / 2) + pad32(d)
  })
  let offset = calls.length * 32
  let head = ''
  for (const t of tuples) {
    head += word(offset)
    offset += t.length / 2
  }
  return AGGREGATE3 + word(0x20) + word(calls.length) + head + tuples.join('')
}

// aggregate3's (bool success, bytes returnData)[] as [{ ok, error }]
function decodeAggregate3 (hex) {
  const h = strip(hex)
  const at = (byte) => BigInt('0x' + h.slice(byte * 2, byte * 2 + 64))
  const array = Number(at(0))
  const n = Number(at(array))
  const out = []
  for (let i = 0; i < n; i++) {
    const tuple = array + 32 + Number(at(array + 32 + i * 32))
    const ok = at(tuple) === 1n
    const bytes = tuple + Number(at(tuple + 32))
    const len = Number(at(bytes))
    const ret = h.slice((bytes + 32) * 2, (bytes + 32 + len) * 2)
    out.push({ ok, error: ok ? null : revertReason(ret) })
  }
  return out
}

// the message of an Error(string) revert, or its raw data
function revertReason (ret) {
  if (!ret.startsWith('08c379a0') || ret.length < 8 + 128) return ret ? '0x' + ret : 'reverted'
  const len = parseInt(ret.slice(8 + 64, 8 + 128), 16)
  const text = ret.slice(8 + 128, 8 + 128 + len * 2)
  try {
    return decodeURIComponent(text.replace(/../g, '%$&')) // UTF-8, without Buffer (this runs in Bare too)
  } catch {
    return '0x' + ret
  }
}

// the call data for the token's transferWithAuthorization, from an
// authorization as boat-peer's Seller reports it
export function transferWithAuthorizationData (a) {
  const sig = strip(a.signature)
  if (sig.length !== 130) throw new Error('bad signature length')
  let v = parseInt(sig.slice(128, 130), 16)
  if (v < 27) v += 27
  return TRANSFER_WITH_AUTHORIZATION +
    addressWord(a.from) + addressWord(a.to) + word(a.value) + word(a.validAfter) + word(a.validBefore) + bytes32(a.nonce) +
    word(v) + sig.slice(0, 64) + sig.slice(64, 128)
}

export default class BoatProtocolEvm {
  // config.token: the EIP-3009 token's address; config.chainId; and the
  // token's own EIP-712 domain name and version (they differ per chain:
  // "USDC"/"2" on Circle's chains, "USD₮0"/"1" on Stable)
  constructor (account, config = {}) {
    const { token, chainId, tokenName, tokenVersion } = config
    if (!token || !chainId || !tokenName || !tokenVersion) throw new Error('token, chainId, tokenName and tokenVersion are required')
    this._account = account
    this._config = config
    this._address = account.address // an ERC-4337 account knows its address only asynchronously: use create()
  }

  // works for any WDK EVM account, ERC-4337 smart accounts included
  static async create (account, config) {
    const protocol = new BoatProtocolEvm(account, config)
    protocol._address ??= await account.getAddress()
    return protocol
  }

  get address () {
    if (!this._address) throw new Error('the account has no address yet: make the protocol with BoatProtocolEvm.create()')
    return this._address
  }

  // an ERC-4337 smart account (WDK's wdk-wallet-evm-erc-4337): its
  // transactions are user operations, and its key is its owner's, not its own
  get isSmartAccount () {
    return typeof this._account.getUserOperationReceipt === 'function'
  }

  // reads go through the account's read-only view: on a policy-governed
  // account the proxy hides _-prefixed members, and reads need no policy
  async _provider () {
    this._readOnly ??= await this._account.toReadOnlyAccount()
    const provider = this._readOnly._provider
    if (!provider) throw new Error('the account has no provider')
    return provider
  }

  // the EIP-712 domain devices must sign under for the token to accept their authorizations
  get domain () {
    const { tokenName, tokenVersion, chainId, token } = this._config
    return { name: tokenName, version: tokenVersion, chainId, verifyingContract: token }
  }

  // a DID record for an Ed25519 key, with the account as its wallet:
  // {"v":1,"did","eth","eth_sig"}, eth_sig being the account's EIP-191 signature of the DID.
  // A smart account cannot sign as itself, so its record names it as the
  // payee, vouched for by its owner key: {"v":1,"did","eth":<owner>,"pay":<account>,"eth_sig"}
  async didRecord (publicKey) {
    const did = didOf(publicKey)
    if (!this.isSmartAccount) return { v: 1, did, eth: this.address, eth_sig: await this._account.sign(did) }
    const message = walletMessage(did, this.address)
    const sig = await this._account.sign(message)
    return { v: 1, did, eth: eth.verifyMessage(message, sig), pay: this.address, eth_sig: sig }
  }

  // publishes that record as a HyperDHT mutable record under the key
  async publishDidRecord (dht, keyPair, { seq = Math.floor(Date.now() / 1000) } = {}) {
    const record = await this.didRecord(keyPair.publicKey)
    const value = Buffer.from(JSON.stringify(record))
    if (!verifyRecord(keyPair.publicKey, value)) throw new Error('the account made a DID record that does not verify')
    const put = await dht.mutablePut(keyPair, value, { seq })
    return { record, seq, nodes: put.closestNodes.length }
  }

  // a boat-peer Seller that bills devices to this account under the token's domain
  seller (options = {}) {
    return new Seller({ ...options, payee: this.address, domain: this.domain, token: this._config.token })
  }

  // submits an authorization to the token; the account pays the gas.
  // Returns { hash, fee }. Settlements are sent one at a time, so payments
  // that arrive together do not race for the account's transaction nonce.
  settle (authorization) {
    if (strip(authorization.to) !== strip(this.address)) return Promise.reject(new Error('the authorization does not pay this account'))
    const tx = { to: this._config.token, data: transferWithAuthorizationData(authorization), value: 0n }
    return this._send(tx)
  }

  // sends a transaction from the account, one at a time
  _send (tx) {
    const run = async () => {
      for (let attempt = 0; ; attempt++) {
        try {
          const sent = await this._account.sendTransaction(tx)
          // a smart account's next user operation is built on its nonce (and,
          // for the first, on the Safe being deployed): send it only once this
          // one is included, or the bundler refuses it
          if (this.isSmartAccount) {
            await this._provider()
            await this._readOnly.waitForTransaction(sent.hash)
          }
          return sent
        } catch (err) {
          // the provider can hand out a stale nonce right after the previous
          // settlement was mined (ethers caches identical calls briefly)
          if (err.code !== 'NONCE_EXPIRED' || attempt >= 4) throw err
          await new Promise((resolve) => setTimeout(resolve, 500))
        }
      }
    }
    const result = (this._queue || Promise.resolve()).then(run, run)
    this._queue = result.catch(() => {})
    return result
  }

  // Settles many authorizations in one transaction, through Multicall3: the
  // 21,000 gas every transaction costs is paid once. Anyone may call
  // transferWithAuthorization, so the multicall contract submitting them makes
  // no difference to the token.
  //
  // The batch is simulated first; authorizations the token would refuse
  // (already used, expired, bad signature) are left out and returned in
  // `skipped`. Inside the batch every call may fail on its own, so one that
  // turns bad between the simulation and the block does not take the others
  // down: waitForBatch tells which went through.
  //
  // Returns { hash, fee, included, skipped }, hash null when nothing is left.
  async settleBatch (authorizations, { multicall = this._config.multicall || MULTICALL3 } = {}) {
    for (const a of authorizations) {
      if (strip(a.to) !== strip(this.address)) throw new Error('an authorization does not pay this account')
    }
    const provider = await this._provider()
    const calls = authorizations.map(transferWithAuthorizationData)
    let sim
    if (this.isSmartAccount) {
      sim = await Promise.all(calls.map((data) => provider.call({ to: this._config.token, data, from: this.address }).then(() => ({ ok: true }), (err) => ({ ok: false, error: err.reason || err.shortMessage || err.message }))))
    } else {
      if ((await provider.getCode(multicall)) === '0x') throw new Error('no Multicall3 at ' + multicall + ' on this chain')
      sim = decodeAggregate3(await provider.call({ to: multicall, data: aggregate3Data(this._config.token, calls), from: this.address }))
    }
    const included = []
    const skipped = []
    authorizations.forEach((a, i) => sim[i].ok ? included.push(a) : skipped.push({ authorization: a, reason: sim[i].error }))
    if (included.length === 0) return { hash: null, fee: 0n, included, skipped }
    if (included.length === 1) return { ...(await this.settle(included[0])), included, skipped } // a batch of one costs more
    if (this.isSmartAccount) {
      // a smart account batches by itself: one user operation, its calls run
      // in order and all or none (so a race since the simulation fails them all)
      const txs = included.map((a) => ({ to: this._config.token, data: transferWithAuthorizationData(a), value: 0n }))
      return { ...(await this._send(txs)), included, skipped }
    }
    // Gas is estimated with no call allowed to fail: estimated as sent, the
    // lowest gas that does not revert is one where the transfers run out of
    // gas inside the batch and the batch itself succeeds
    const strict = aggregate3Data(this._config.token, included.map(transferWithAuthorizationData), { allowFailure: false })
    const gas = await provider.estimateGas({ from: this.address, to: multicall, data: strict })
    const data = aggregate3Data(this._config.token, included.map(transferWithAuthorizationData))
    const { hash, fee } = await this._send({ to: multicall, data, value: 0n, gasLimit: gas + gas / 5n })
    return { hash, fee, included, skipped }
  }

  // waits for a batch and returns { ok, block, gasUsed, settled, failed },
  // settled and failed being the batch's authorizations by their on-chain state
  async waitForBatch (batch, options) {
    const r = await this.waitForSettlement(batch.hash, options)
    const settled = []
    const failed = []
    for (const a of batch.included) (await this.isSettled(a.from, a.nonce) ? settled : failed).push(a)
    return { ...r, settled, failed }
  }

  // whether the token has used this authorization's nonce (settled or cancelled)
  async isSettled (from, nonce) {
    const provider = await this._provider()
    const out = await provider.call({ to: this._config.token, data: AUTHORIZATION_STATE + addressWord(from) + bytes32(nonce) })
    return BigInt(out) !== 0n
  }

  // waits for a settlement and returns { ok, block, gasUsed, fee, tx }. For a
  // smart account, hash is a user operation's, tx the bundle transaction it went
  // out in, and gasUsed and fee its own share
  async waitForSettlement (hash, { timeout } = {}) {
    await this._provider()
    const r = await this._readOnly.waitForTransaction(hash, timeout ? { timeout } : {})
    if (r.finality === 'dropped') throw new Error('the transaction was dropped: ' + hash)
    const op = r.userOperationReceipt
    return {
      ok: r.success === true,
      block: r.block,
      gasUsed: op ? BigInt(op.actualGasUsed) : r.receipt.gasUsed,
      fee: op ? BigInt(op.actualGasCost) : r.fee,
      tx: r.receipt ? r.receipt.hash : hash
    }
  }

}

// adds account.getBoatProtocol() to every account of a blockchain in a WDK
// instance. WDK's protocol types are swap, bridge, lending, fiat, swidge and
// sda; this is none of them, so it is added as middleware.
//
// The protocol is built on the account it is called on. Through a policy
// proxy that is the governed account, so settlements (sendTransaction) and DID
// records (sign) are policy-checked; the proxy denies getBoatProtocol itself
// unless it is listed: new WDK(seed, { policyExclusions: ['getBoatProtocol'] }).
export function registerBoat (wdk, blockchain, config) {
  const protocols = new WeakMap() // one per account object, so its settlement queue is shared
  return wdk.registerMiddleware(blockchain, async (account) => {
    const address = account.address ?? await account.getAddress() // ERC-4337 accounts: only asynchronously
    account.getBoatProtocol = function () {
      const self = this || account
      if (!protocols.has(self)) {
        const protocol = new BoatProtocolEvm(self, config)
        protocol._address ??= address
        protocols.set(self, protocol)
      }
      return protocols.get(self)
    }
  })
}
