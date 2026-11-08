// Devices and issuers for every result of a credential check, published on a
// DHT, for components/hdht_cred/test/test_cred.c (and anyone else checking).
//
// usage: node cred-fixture.js <bootstrap host:port | public>
//
// Prints one line per case: FIXTURE|<case> <device did> <trusted issuer did> <expected result>
// The expected results are hdht_cred_result_t values.

const crypto = require('crypto')
const HyperDHT = require('hyperdht')
const credential = require('./credential')

const [where = 'public'] = process.argv.slice(2)
const dht = new HyperDHT({ bootstrap: where === 'public' ? undefined : [where] })
const did = (kp) => 'did:mw:' + kp.publicKey.toString('hex')
const keyPair = () => HyperDHT.keyPair(crypto.randomBytes(32))
const put = (kp, value) => dht.mutablePut(kp, Buffer.from(JSON.stringify(value)), { seq: Math.floor(Date.now() / 1000) })

async function main () {
  await dht.fullyBootstrapped()
  const maker = keyPair() // trusted, publishes its record
  const other = keyPair() // not trusted
  const silent = keyPair() // trusted, never publishes a record
  const devices = Array.from({ length: 7 }, keyPair)

  const valid = credential.issue(maker, did(devices[0]), 'meter X1')
  const revoked = credential.issue(maker, did(devices[1]), 'meter X1')
  const tampered = { ...credential.issue(maker, did(devices[2]), 'meter X1'), model: 'meter X9' }
  const untrusted = credential.issue(other, did(devices[3]), 'meter X1')
  const unknownIssuer = credential.issue(silent, did(devices[5]), 'meter X1')

  await put(maker, { v: 1, did: did(maker), name: 'Fixture Maker', revoked: [revoked.id] })
  await put(other, { v: 1, did: did(other), name: 'Other Maker' })
  await put(devices[0], { v: 1, did: did(devices[0]), svc: 'meter/1', cred: valid })
  await put(devices[1], { v: 1, did: did(devices[1]), svc: 'meter/1', cred: revoked })
  await put(devices[2], { v: 1, did: did(devices[2]), svc: 'meter/1', cred: tampered })
  await put(devices[3], { v: 1, did: did(devices[3]), svc: 'meter/1', cred: untrusted })
  await put(devices[4], { v: 1, did: did(devices[4]), svc: 'meter/1' })
  await put(devices[5], { v: 1, did: did(devices[5]), svc: 'meter/1', cred: unknownIssuer })
  // devices[6] publishes nothing

  const cases = [
    ['valid', devices[0], maker, 0],
    ['revoked', devices[1], maker, -8],
    ['tampered', devices[2], maker, -5],
    ['untrusted', devices[3], maker, -6],
    ['no-credential', devices[4], maker, -2],
    ['issuer-unknown', devices[5], silent, -7],
    ['no-record', devices[6], maker, -1]
  ]
  for (const [name, device, issuer, expected] of cases) console.log(`FIXTURE|${name} ${did(device)} ${did(issuer)} ${expected}`)
  await dht.destroy()
}

main()
