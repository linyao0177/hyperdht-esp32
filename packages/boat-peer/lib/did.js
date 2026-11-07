// DIDs and DID records. A device's DID, did:mw:<Ed25519 public key>, is also
// its HyperDHT address. Its DID record binds it to a wallet:
//
//   {"v":1,"did":"did:mw:<hex>","eth":"0x<wallet>","eth_sig":"0x<65 bytes>"}
//
// stored as a HyperDHT mutable record under the DID key (so the DID key signed
// it), with eth_sig an EIP-191 signature of the DID by the wallet (so the
// wallet claims the DID). Checking one needs the DID and nothing else.

const b4a = require('b4a')
const sodium = require('sodium-universal')
const eth = require('./eth')

const didOf = (publicKey) => 'did:mw:' + b4a.toString(publicKey, 'hex')

function keyOf (did) {
  if (typeof did !== 'string') return did
  if (!/^did:mw:[0-9a-f]{64}$/.test(did)) throw new Error('bad did: ' + did)
  return b4a.from(did.slice(7), 'hex')
}

function makeRecord (publicKey, ethPrivateKey) {
  const did = didOf(publicKey)
  return { v: 1, did, eth: eth.addressOf(ethPrivateKey), eth_sig: eth.signMessage(did, ethPrivateKey) }
}

// the record if it belongs to this key and its wallet signed the DID, else null
function verifyRecord (publicKey, value) {
  try {
    const r = JSON.parse(b4a.toString(value))
    if (r.did !== didOf(publicKey)) return null
    if (eth.verifyMessage(r.did, r.eth_sig).toLowerCase() !== r.eth.toLowerCase()) return null
    return r
  } catch {
    return null
  }
}

// looks a DID up on the DHT: { record, seq } with record null when it is not valid
async function resolveDid (dht, did) {
  const publicKey = keyOf(did)
  const res = await dht.mutableGet(publicKey)
  if (!res) return null
  return { record: verifyRecord(publicKey, res.value), seq: res.seq }
}

async function publishRecord (dht, keyPair, ethPrivateKey, { seq = Math.floor(Date.now() / 1000) } = {}) {
  const record = makeRecord(keyPair.publicKey, ethPrivateKey)
  const put = await dht.mutablePut(keyPair, b4a.from(JSON.stringify(record)), { seq })
  return { record, seq, nodes: put.closestNodes.length }
}

// A DID record version kept outside the DHT, which stores only the latest:
// the record, its seq, and the DID key's Ed25519 signature over both. A log
// that keeps these (apps/pear-seller's receipts) can still prove which wallet
// a DID named when, after the DID moves to another wallet.
function recordMessage (seq, record) {
  return b4a.from('boat-did-record\0' + String(seq) + '\0' + JSON.stringify(record))
}

function signRecordVersion (keyPair, record, seq) {
  const sig = b4a.alloc(64)
  sodium.crypto_sign_detached(sig, recordMessage(seq, record), keyPair.secretKey)
  return { seq, record, sig: b4a.toString(sig, 'hex') }
}

// the record if the version is signed by the DID's key and the record itself is valid, else null
function verifyRecordVersion (did, version) {
  try {
    const publicKey = keyOf(did)
    const sig = b4a.from(String(version.sig), 'hex')
    if (sig.length !== 64 || !sodium.crypto_sign_verify_detached(sig, recordMessage(version.seq, version.record), publicKey)) return null
    return verifyRecord(publicKey, b4a.from(JSON.stringify(version.record)))
  } catch {
    return null
  }
}

module.exports = { didOf, keyOf, makeRecord, verifyRecord, resolveDid, publishRecord, signRecordVersion, verifyRecordVersion }
