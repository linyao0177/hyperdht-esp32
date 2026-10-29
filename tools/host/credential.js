// Manufacturer credentials for devices (docs/credentials.md).
//
// An issuer (a manufacturer) has an Ed25519 key; its DID is did:mw:<key>. It
// vouches for a device by signing
//   "hdht-credential/1 <id> <issuer key hex> <device key hex> <iat> <model>"
// The device keeps the credential and shows it in its own DID record under
// "cred", so anyone resolving the device can check it without asking the
// issuer. The issuer's own record lists revoked credential ids.
//
//   credential  {"v":1,"id","iss","sub","iat","model","sig"}
//   issuer record  {"v":1,"did","name","revoked":[id, ...]}

const sodium = require('sodium-universal')

const MODEL = /^[A-Za-z0-9 ._-]{1,32}$/

function keyOf (did) {
  if (!/^did:mw:[0-9a-f]{64}$/.test(did || '')) throw new Error('expected did:mw:<64 hex>, got ' + did)
  return Buffer.from(did.slice(7), 'hex')
}

function signable (c) {
  return Buffer.from(`hdht-credential/1 ${c.id} ${c.iss.slice(7)} ${c.sub.slice(7)} ${c.iat} ${c.model}`)
}

function issue (issuerKeyPair, deviceDid, model, iat = Math.floor(Date.now() / 1000)) {
  keyOf(deviceDid)
  if (!MODEL.test(model)) throw new Error('model: 1-32 of A-Z a-z 0-9 space . _ -')
  const id = Buffer.alloc(8)
  sodium.randombytes_buf(id)
  const c = { v: 1, id: id.toString('hex'), iss: 'did:mw:' + issuerKeyPair.publicKey.toString('hex'), sub: deviceDid, iat, model }
  const sig = Buffer.alloc(64)
  sodium.crypto_sign_detached(sig, signable(c), issuerKeyPair.secretKey)
  return { ...c, sig: sig.toString('hex') }
}

// Checks a credential's own signature and that it is for deviceDid. Says
// nothing about whether the issuer is one you trust, or about revocation.
function check (c, deviceDid) {
  try {
    if (!c || c.v !== 1 || !/^[0-9a-f]{16}$/.test(c.id) || !MODEL.test(c.model) || !Number.isInteger(c.iat)) return 'malformed'
    if (c.sub !== deviceDid) return 'for another device'
    const sig = Buffer.from(c.sig, 'hex')
    if (sig.length !== 64 || !sodium.crypto_sign_verify_detached(sig, signable(c), keyOf(c.iss))) return 'bad signature'
    return null
  } catch {
    return 'malformed'
  }
}

// The whole check a verifier makes: the device's record carries a credential
// for that device, signed by a trusted issuer, and not revoked in the
// issuer's current record. Returns { ok, reason, credential, issuer }.
async function verifyDevice (dht, deviceDid, trustedIssuers) {
  const res = await dht.mutableGet(keyOf(deviceDid))
  if (!res) return { ok: false, reason: 'no device record' }
  let record
  try {
    record = JSON.parse(res.value.toString())
  } catch {
    return { ok: false, reason: 'device record is not JSON' }
  }
  const c = record.cred
  if (!c) return { ok: false, reason: 'no credential in the device record' }
  const bad = check(c, deviceDid)
  if (bad) return { ok: false, reason: 'credential ' + bad, credential: c }
  if (!trustedIssuers.includes(c.iss)) return { ok: false, reason: 'issuer not trusted', credential: c }

  const ir = await dht.mutableGet(keyOf(c.iss))
  if (!ir) return { ok: false, reason: 'issuer record not found, cannot check revocation', credential: c }
  let issuer
  try {
    issuer = JSON.parse(ir.value.toString())
  } catch {
    return { ok: false, reason: 'issuer record is not JSON', credential: c }
  }
  if (issuer.did !== c.iss) return { ok: false, reason: 'issuer record is for another key', credential: c }
  if ((issuer.revoked || []).includes(c.id)) return { ok: false, reason: 'revoked', credential: c, issuer }
  return { ok: true, reason: 'valid', credential: c, issuer }
}

module.exports = { issue, check, verifyDevice, signable, keyOf }
