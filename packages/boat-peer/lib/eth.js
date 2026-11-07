// The Ethereum signatures BoAT MER uses, in plain JavaScript (no Node.js
// crypto), so they work in Bare: EIP-191 for DID records and EIP-712
// TransferWithAuthorization (EIP-3009) for payments.

const b4a = require('b4a')
require('./encoding')
const { secp256k1 } = require('@noble/curves/secp256k1.js')
const { keccak_256: keccak } = require('@noble/hashes/sha3.js')

const hex = (bytes) => b4a.toString(b4a.from(bytes), 'hex')
const unhex = (s) => b4a.from(s.replace(/^0x/, ''), 'hex')
const utf8 = (s) => b4a.from(s, 'utf8')

// EIP-55 mixed-case address
function checksum (address) {
  const lower = hex(address)
  const h = hex(keccak(utf8(lower)))
  let out = '0x'
  for (let i = 0; i < 40; i++) out += parseInt(h[i], 16) >= 8 ? lower[i].toUpperCase() : lower[i]
  return out
}

function addressOfPublicKey (uncompressed) {
  return checksum(keccak(uncompressed.subarray(1)).subarray(12))
}

function addressOf (privateKey) {
  return addressOfPublicKey(secp256k1.getPublicKey(privateKey, false))
}

// noble's 'recovered' format is v | r | s with v 0/1; Ethereum's is r | s | v+27
function sign (digest, privateKey) {
  const s = secp256k1.sign(digest, privateKey, { prehash: false, format: 'recovered' })
  return '0x' + hex(s.subarray(1)) + (27 + s[0]).toString(16)
}

// the address that made a 65-byte signature (r | s | v, v 27/28 or 0/1)
function recover (digest, signature) {
  const sig = unhex(signature)
  if (sig.length !== 65) throw new Error('bad signature length')
  const v = sig[64] >= 27 ? sig[64] - 27 : sig[64]
  const recovered = b4a.concat([b4a.from([v]), sig.subarray(0, 64)])
  const compressed = secp256k1.recoverPublicKey(recovered, digest, { prehash: false })
  return addressOfPublicKey(secp256k1.Point.fromBytes(compressed).toBytes(false))
}

// EIP-191 personal_sign
function messageHash (message) {
  const m = utf8(message)
  return keccak(b4a.concat([utf8('\x19Ethereum Signed Message:\n' + m.length), m]))
}

const signMessage = (message, privateKey) => sign(messageHash(message), privateKey)
const verifyMessage = (message, signature) => recover(messageHash(message), signature)

// EIP-712 for TransferWithAuthorization, the only type MER signs
function word (n) {
  const out = b4a.alloc(32)
  let v = BigInt(n)
  if (v < 0n || v >= 1n << 256n) throw new Error('uint256 out of range')
  for (let i = 31; v > 0n; i--, v >>= 8n) out[i] = Number(v & 0xffn)
  return out
}

function addressWord (address) {
  const a = unhex(address)
  if (a.length !== 20) throw new Error('bad address')
  return b4a.concat([b4a.alloc(12), a])
}

const DOMAIN_TYPE = keccak(utf8('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'))
const TRANSFER_TYPE = keccak(utf8('TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)'))

function domainSeparator (domain) {
  return keccak(b4a.concat([DOMAIN_TYPE, keccak(utf8(domain.name)), keccak(utf8(domain.version)), word(domain.chainId), addressWord(domain.verifyingContract)]))
}

function transferHash (domain, t) {
  const nonce = unhex(t.nonce)
  if (nonce.length !== 32) throw new Error('bad nonce')
  const struct = keccak(b4a.concat([TRANSFER_TYPE, addressWord(t.from), addressWord(t.to), word(t.value), word(t.validAfter), word(t.validBefore), nonce]))
  return keccak(b4a.concat([b4a.from([0x19, 0x01]), domainSeparator(domain), struct]))
}

const signTransfer = (domain, t, privateKey) => sign(transferHash(domain, t), privateKey)
const verifyTransfer = (domain, t, signature) => recover(transferHash(domain, t), signature)

module.exports = { checksum, addressOf, signMessage, verifyMessage, signTransfer, verifyTransfer, transferHash }
