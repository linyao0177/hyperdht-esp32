// The app's worker, where the peer-to-peer work runs (Bare). Based on
// hello-pear-worker v1.2.0 (Apache-2.0), which keeps the Pear updater.
//
// It sells power to BoAT MER devices: a device connects to the seller's DID
// over Hyperswarm, opens a paying stream, and signs an EIP-3009 authorization
// for every slice it is billed. boat-peer checks each one against the device's
// DID record. Accepted authorizations are appended to a Hypercore, so anyone
// with its key can replicate them and check them again (verify-receipts.js).
// The seller's wallet is a WDK (Tether's Wallet Development Kit) EVM account:
// it signs the seller's DID record, and with --settle it submits each
// authorization to the token's transferWithAuthorization and pays the gas
// (wdk-protocol-boat-evm). With --dial, it also reads a device's attested
// reading by its DID.

const PearRuntime = require('pear-runtime') // pear-runtime on desktop; pear-mobile on mobile
const Hyperswarm = require('hyperswarm')
const HyperDHT = require('hyperdht')
const Corestore = require('corestore')
const goodbye = require('graceful-goodbye')
const FramedStream = require('framed-stream')
const path = require('bare-path')
const fs = require('bare-fs')
const dir = require('bare-storage')
const b4a = require('b4a')
const sodium = require('sodium-universal')
const { isBareKit } = require('which-runtime')
const { resolveDid, dialReading, didOf } = require('boat-peer')
const WDK = require('@tetherto/wdk').default
const WalletManagerEvm = require('@tetherto/wdk-wallet-evm').default
const { registerBoat } = require('wdk-protocol-boat-evm')

// mobile doesn't have the executable path (argv[0]) and the worker entry path
// (argv[1]) in the worker's argv
const argv = (index) => Bare.argv[index + (isBareKit ? 0 : 2)]

const updaterConfig = {
  updates: argv(0) !== 'false',
  version: argv(1),
  upgrade: argv(2),
  name: argv(3),
  dir: argv(4) || dir.persistent(), // argv[4] is undefined in mobile
  app: argv(5) // argv[5] is undefined in mobile
}
const dialDid = argv(6) || ''
// the chain and the EIP-3009 token devices pay in, and whether to settle (bin.mjs)
const chain = JSON.parse(argv(7) || '{}')

const RATE = 250000 // micro-units of the token per kWh ($0.25)

const pipe = new FramedStream(Bare.IPC)
const say = (line) => pipe.write(line)

const store = new Corestore(path.join(updaterConfig.dir, 'pear-runtime', 'corestore'))
const swarm = new Hyperswarm()
const pear = new PearRuntime({ ...updaterConfig, swarm, store })

pear.updater.on('error', (err) => say('updater-error ' + err.message))
swarm.on('connection', (connection) => store.replicate(connection))
if (updaterConfig.updates !== false) {
  swarm.join(pear.updater.drive.core.discoveryKey, { client: true, server: false })
}
pear.updater.on('update-scheduled', (delay) => say('update-scheduled ' + delay))
pear.updater.on('updating', () => say('updating'))
pear.updater.on('updated', () => say('updated'))
pear.on('minver-required', () => say('minver-required'))

// the seller's identity: an Ed25519 seed (its DID and HyperDHT key) and a
// WDK seed phrase (the wallet it is paid to), made on first start
function identity () {
  const file = path.join(updaterConfig.dir, 'seller-identity.json')
  let id = {}
  if (fs.existsSync(file)) id = JSON.parse(b4a.toString(fs.readFileSync(file)))
  if (!id.seed || !id.mnemonic) {
    if (!id.seed) {
      const seed = b4a.alloc(32)
      sodium.randombytes_buf(seed)
      id.seed = b4a.toString(seed, 'hex')
    }
    if (!id.mnemonic) id.mnemonic = WDK.getRandomSeedPhrase()
    delete id.wallet // the raw key of earlier versions, before WDK
    fs.mkdirSync(updaterConfig.dir, { recursive: true })
    fs.writeFileSync(file, JSON.stringify(id))
  }
  const keyPair = { publicKey: b4a.alloc(32), secretKey: b4a.alloc(64) }
  sodium.crypto_sign_seed_keypair(keyPair.publicKey, keyPair.secretKey, b4a.from(id.seed, 'hex'))
  return { keyPair, mnemonic: id.mnemonic }
}

// simulated output: 12 W for 40 s, then 0 W for 20 s, so a device opens and
// closes paying sessions on its own
const started = Date.now()
const power = () => (Math.floor((Date.now() - started) / 1000) % 60) < 40 ? 12 : 0

const totals = { verified: 0, refused: 0, micro: 0, settled: 0, failed: 0 }

async function main () {
  const { keyPair, mnemonic } = identity()
  const did = didOf(keyPair.publicKey)

  // the wallet: a WDK EVM account with the BoAT protocol
  const wdk = new WDK(mnemonic).registerWallet('chain', WalletManagerEvm, { provider: chain.rpc, chainId: chain.chainId })
  registerBoat(wdk, 'chain', { token: chain.token, chainId: chain.chainId, tokenName: chain.tokenName, tokenVersion: chain.tokenVersion })
  const account = await wdk.getAccount('chain', 0)
  const boat = account.getBoatProtocol()
  const payee = boat.address

  const receipts = store.get({ name: 'receipts', valueEncoding: 'json' })
  await receipts.ready()
  swarm.join(receipts.discoveryKey, { server: true, client: false })

  // buyers dial the seller's DID; this swarm only carries MER streams
  const sellerSwarm = new Hyperswarm({ keyPair, dht: swarm.dht })
  const seller = boat.seller({ rate: RATE, power })
  sellerSwarm.on('connection', (conn) => seller.serve(conn, swarm.dht))
  await sellerSwarm.listen()

  say(`seller ${did}`)
  say(`payee ${payee} (WDK account), ${chain.tokenName} at ${chain.token} on chain ${chain.chainId}, settlement ${chain.settle ? 'on' : 'off'}`)
  if (chain.settle) {
    account.getTokenBalance(chain.token).then((b) => say(`payee balance ${b} micro-units`), (err) => say('balance check failed: ' + err.message))
  }
  say(`receipts hypercore ${b4a.toString(receipts.key, 'hex')}, ${receipts.length} so far`)

  seller.on('buyer', ({ did }) => say(`buyer connected ${did.slice(0, 23)}...`))
  seller.on('record', (r) => say(`buyer DID record ${r.valid ? 'valid' : r.found ? 'INVALID' : 'not found'}${r.eth ? ', wallet ' + r.eth : ''} (${r.ms} ms)`))
  seller.on('open', ({ session }) => say(`paying stream open, session ${session}`))
  seller.on('end', ({ session }) => say(`paying stream closed, session ${session}`))
  seller.on('slice', ({ slice, watts, amount }) => say(`billed slice ${slice}: ${watts.toFixed(1)} W, ${amount} micro-USDC`))
  seller.on('close', () => say('buyer disconnected'))
  seller.on('payment', async (p) => {
    if (!p.ok) {
      totals.refused++
      say(`REFUSED slice ${p.slice}: ${p.reason}`)
      return
    }
    totals.verified++
    totals.micro += Number(p.authorization.value)
    const seq = receipts.length
    await receipts.append({ t: Date.now(), seller: did, buyer: p.did, slice: p.slice, domain: boat.domain, authorization: p.authorization })
    say(`VERIFIED slice ${p.slice}: ${p.authorization.value} micro-USDC from ${p.signer}, ${p.rttMs} ms, receipt #${seq}`)
    if (!chain.settle) return

    // settle it on-chain from the WDK account, and log the transaction next to the receipt
    const t0 = Date.now()
    try {
      const { hash, fee } = await boat.settle(p.authorization)
      const r = await boat.waitForSettlement(hash)
      if (r.ok) totals.settled++
      else totals.failed++
      await receipts.append({ type: 'settlement', receipt: seq, tx: hash, block: r.block, ok: r.ok, fee: String(fee) })
      say(`${r.ok ? 'SETTLED' : 'SETTLEMENT REVERTED'} receipt #${seq} in block ${r.block}, tx ${hash}, ${Date.now() - t0} ms`)
    } catch (err) {
      totals.failed++
      await receipts.append({ type: 'settlement', receipt: seq, ok: false, error: err.shortMessage || err.message })
      say(`SETTLEMENT FAILED receipt #${seq}: ${err.shortMessage || err.message}`)
    }
  })

  const publish = () => boat.publishDidRecord(swarm.dht, keyPair).then(
    (r) => say(`DID record published on ${r.nodes} nodes (seq ${r.seq})`),
    (err) => say('DID record publish failed: ' + err.message))
  await publish()
  const republish = setInterval(publish, 30 * 60 * 1000)

  const summary = setInterval(() => say(`summary: ${totals.verified} verified, ${totals.refused} refused, ${totals.micro} micro-USDC, ${totals.settled} settled, ${totals.failed} settlement failures, ${receipts.length} log entries`), 30000)

  // Readings are dialed from a DHT of their own: dialed from the swarm's DHT,
  // they timed out every time in this app, though the same dial from a
  // swarm's DHT works in a script (not understood yet)
  let dialer = null
  let readerDht = null
  if (dialDid) {
    readerDht = new HyperDHT()
    const read = async () => {
      const res = await resolveDid(readerDht, dialDid)
      const record = res && res.record
      const r = await dialReading(readerDht, dialDid, { record })
      say(r.ok
        ? `reading from ${dialDid.slice(0, 23)}... verified (${r.openMs} ms): ${r.reading.payload}`
        : `reading from ${dialDid.slice(0, 23)}... FAILED: ${r.error || JSON.stringify(r.checks)}`)
    }
    read()
    dialer = setInterval(read, 60000)
  }

  goodbye(async () => {
    clearInterval(republish)
    clearInterval(summary)
    clearInterval(dialer)
    if (readerDht) await readerDht.destroy()
    await sellerSwarm.destroy()
    wdk.dispose()
  }, 0)
}

goodbye(async () => {
  await swarm.destroy()
  await pear.close()
  await store.close()
}, 1)

pipe.on('data', async (data) => {
  const message = data.toString()
  if (message !== 'pear:applyUpdate') {
    say('unknown-message ' + message)
    return
  }
  try {
    await pear.ready()
    await pear.updater.applyUpdate()
    say('pear:updateApplied')
  } catch (err) {
    say('pear:updateFailed ' + err.message)
  }
})

main().catch((err) => say('error ' + err.stack))
