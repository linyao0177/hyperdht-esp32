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

const { Seller, didOf, verifyRecord } = boatPeer

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
  }

  get address () {
    return this._account.address
  }

  // the EIP-712 domain devices must sign under for the token to accept their authorizations
  get domain () {
    const { tokenName, tokenVersion, chainId, token } = this._config
    return { name: tokenName, version: tokenVersion, chainId, verifyingContract: token }
  }

  // a DID record for an Ed25519 key, with the account as its wallet:
  // {"v":1,"did","eth","eth_sig"}, eth_sig being the account's EIP-191 signature of the DID
  async didRecord (publicKey) {
    const did = didOf(publicKey)
    return { v: 1, did, eth: this.address, eth_sig: await this._account.sign(did) }
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
    const run = async () => {
      for (let attempt = 0; ; attempt++) {
        try {
          return await this._account.sendTransaction(tx)
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

  // whether the token has used this authorization's nonce (settled or cancelled)
  async isSettled (from, nonce) {
    const provider = this._account._provider
    if (!provider) throw new Error('the account has no provider')
    const out = await provider.call({ to: this._config.token, data: AUTHORIZATION_STATE + addressWord(from) + bytes32(nonce) })
    return BigInt(out) !== 0n
  }

  // waits for a settlement and returns { ok, block, gasUsed }
  async waitForSettlement (hash, { confirmations = 1, timeout = 120000 } = {}) {
    const provider = this._account._provider
    const receipt = await provider.waitForTransaction(hash, confirmations, timeout)
    return { ok: receipt.status === 1, block: receipt.blockNumber, gasUsed: receipt.gasUsed }
  }

  // an x402 FacilitatorEvmSigner (@x402/evm) backed by this account, so an
  // x402 facilitator verifies and settles with WDK. Needs ethers (Node.js).
  async x402FacilitatorSigner () {
    const { Interface, verifyTypedData } = await import('ethers')
    const account = this._account
    const provider = account._provider
    // x402 names functions without their signature; tokens such as USDC
    // overload transferWithAuthorization (v, r, s or a bytes signature), so
    // pick the overload by argument count
    const fn = (iface, name, args) => {
      const all = iface.fragments.filter((f) => f.type === 'function' && f.name === name)
      return all.find((f) => f.inputs.length === args.length) || all[0]
    }
    return {
      getAddresses: () => [account.address],
      async readContract ({ address, abi, functionName, args = [] }) {
        const iface = new Interface(abi)
        const f = fn(iface, functionName, args)
        const out = await provider.call({ to: address, data: iface.encodeFunctionData(f, args) })
        const decoded = iface.decodeFunctionResult(f, out)
        return decoded.length === 1 ? decoded[0] : decoded
      },
      async verifyTypedData ({ address, domain, types, message, signature }) {
        const { EIP712Domain, ...rest } = types
        return verifyTypedData(domain, rest, message, signature).toLowerCase() === address.toLowerCase()
      },
      async writeContract ({ address, abi, functionName, args, dataSuffix }) {
        const iface = new Interface(abi)
        const data = iface.encodeFunctionData(fn(iface, functionName, args), args) + (dataSuffix ? strip(dataSuffix) : '')
        const { hash } = await account.sendTransaction({ to: address, data, value: 0n })
        return hash
      },
      async sendTransaction ({ to, data }) {
        const { hash } = await account.sendTransaction({ to, data, value: 0n })
        return hash
      },
      async waitForTransactionReceipt ({ hash, timeout = 120000 }) {
        const r = await provider.waitForTransaction(hash, 1, timeout)
        return { status: r.status === 1 ? 'success' : 'reverted', logs: r.logs }
      },
      async getCode ({ address }) {
        const code = await provider.getCode(address)
        return code === '0x' ? undefined : code
      }
    }
  }
}

// adds account.getBoatProtocol() to every account of a blockchain in a WDK
// instance. WDK's protocol types are swap, bridge, lending, fiat, swidge and
// sda; this is none of them, so it is added as middleware.
export function registerBoat (wdk, blockchain, config) {
  return wdk.registerMiddleware(blockchain, async (account) => {
    let protocol = null
    account.getBoatProtocol = () => (protocol ??= new BoatProtocolEvm(account, config))
  })
}
