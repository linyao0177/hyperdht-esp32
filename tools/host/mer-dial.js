// Connects to a device by its BoAT MER DID and checks the attested reading it
// returns (examples/boat_mer).
//
// usage: node mer-dial.js did:mw:<hex> <bootstrap host:port | public> [rounds, default 3]

const crypto = require('crypto')
const HyperDHT = require('hyperdht')
const sodium = require('sodium-universal')

const [did, where = 'public', rounds = '3'] = process.argv.slice(2)
const bootstrap = where === 'public' ? undefined : [where]

if (!/^did:mw:[0-9a-f]{64}$/.test(did || '')) {
  console.error('usage: node mer-dial.js did:mw:<hex> <bootstrap host:port | public> [rounds]')
  process.exit(1)
}

// the DID is the device's Ed25519 public key, which is its HyperDHT address
const publicKey = Buffer.from(did.slice(7), 'hex')

function dial (dht) {
  return new Promise((resolve) => {
    const started = Date.now()
    const conn = dht.connect(publicKey)
    const chunks = []
    let opened = 0

    conn.on('open', () => { opened = Date.now() - started })
    conn.on('data', (d) => chunks.push(d))
    conn.on('end', () => conn.end()) // the device ends after one message
    conn.on('error', (err) => resolve({ ok: false, error: err.message }))
    conn.on('close', () => {
      if (!chunks.length) return resolve({ ok: false, error: 'no data' })

      const r = JSON.parse(Buffer.concat(chunks).toString())
      const hash = crypto.createHash('sha256').update(r.payload).digest()
      const sig = Buffer.from(r.sig, 'hex')
      const checks = {
        noise_peer_is_did: conn.remotePublicKey.equals(publicKey),
        did_field_matches: r.did === did,
        hash_matches_payload: hash.toString('hex') === r.hash,
        ed25519_sig_valid: sodium.crypto_sign_verify_detached(sig, hash, publicKey)
      }
      const ok = Object.values(checks).every(Boolean)
      resolve({ ok, open_ms: opened, total_ms: Date.now() - started, eth: r.eth, payload: r.payload, sign_ms: r.sign_ms, checks })
    })
  })
}

async function main () {
  const dht = new HyperDHT({ bootstrap })
  await dht.fullyBootstrapped()
  let passed = 0

  for (let i = 1; i <= Number(rounds); i++) {
    const res = await dial(dht)
    if (res.ok) passed++
    console.log(`DIAL|round ${i} ${res.ok ? 'PASS' : 'FAIL'}`, JSON.stringify(res))
    await new Promise((resolve) => setTimeout(resolve, 2000))
  }

  console.log(`DIAL|summary ${passed}/${rounds}`)
  await dht.destroy()
}

main()
