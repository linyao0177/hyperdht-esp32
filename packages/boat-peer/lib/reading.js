// Attested readings. A BoAT MER device that is dialed by its DID answers with
// one JSON message and ends the stream:
//
//   {"did","eth","payload","hash":"<sha256(payload) hex>","sig":"<Ed25519 hex>"}
//
// The signature is the DID key's over the hash, so a reading proves which
// device made it, wherever it is kept.

const b4a = require('b4a')
const sodium = require('sodium-universal')
const { keyOf } = require('./did')

function sha256 (data) {
  const out = b4a.alloc(32)
  sodium.crypto_hash_sha256(out, b4a.from(data))
  return out
}

// { ok, checks, reading }: every check must hold
function verifyReading (did, message, { remotePublicKey = null, record = null } = {}) {
  const publicKey = keyOf(did)
  let r
  try {
    r = JSON.parse(typeof message === 'string' ? message : b4a.toString(message))
  } catch {
    return { ok: false, checks: { json: false }, reading: null }
  }
  const sig = b4a.from(String(r.sig), 'hex')
  const hash = sha256(String(r.payload))
  const checks = {
    did_matches: r.did === 'did:mw:' + b4a.toString(publicKey, 'hex'),
    hash_matches_payload: b4a.toString(hash, 'hex') === r.hash,
    signed_by_did: sig.length === 64 && sodium.crypto_sign_verify_detached(sig, hash, publicKey)
  }
  if (remotePublicKey) checks.stream_peer_is_did = b4a.equals(remotePublicKey, publicKey)
  if (record) checks.eth_matches_record = String(r.eth).toLowerCase() === record.eth.toLowerCase()
  return { ok: Object.values(checks).every(Boolean), checks, reading: r }
}

// dials the device by its DID and checks the reading it sends. `dht` is a
// HyperDHT (with Hyperswarm: swarm.dht, which dials with a fresh key)
function dialReading (dht, did, { record = null, timeout = 60000 } = {}) {
  const publicKey = keyOf(did)
  return new Promise((resolve) => {
    const started = Date.now()
    const conn = dht.connect(publicKey)
    const chunks = []
    let openMs = 0
    const timer = setTimeout(() => conn.destroy(new Error('timeout')), timeout)
    conn.on('open', () => { openMs = Date.now() - started })
    conn.on('data', (d) => chunks.push(d))
    conn.on('end', () => conn.end())
    conn.on('error', (err) => {
      clearTimeout(timer)
      resolve({ ok: false, error: err.message })
    })
    conn.on('close', () => {
      clearTimeout(timer)
      if (!chunks.length) return resolve({ ok: false, error: 'no data' })
      const res = verifyReading(did, b4a.concat(chunks), { remotePublicKey: conn.remotePublicKey, record })
      resolve({ ...res, openMs, totalMs: Date.now() - started })
    })
  })
}

module.exports = { verifyReading, dialReading, sha256 }
