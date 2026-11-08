// A BoAT MER device's Solana wallet, its key staying on the device.
//
// The owner's app connects to the device over HyperDHT, gets its Solana
// address (derived from its DID key), and has it sign a transfer of the
// token to the owner's WDK Solana account, which pays the fee. Then it checks
// what the device refuses.
//
// usage: node examples/device-wallet.js <device did> <owner seed file> <WDK seed phrase file>
//        --mint <base58> [--rpc http://127.0.0.1:8899] [--decimals 6] [--amount 100000]
//
// The device needs CONFIG_MER_OWNER_KEY (the owner seed file's public key) and
// CONFIG_MER_SOL_MINT; its token account must exist and hold the token, and so
// must the owner account's.

import fs from 'fs'
import crypto from 'crypto'
import HyperDHT from 'hyperdht'
import WalletManagerSolana from '@tetherto/wdk-wallet-solana'
import BoatDeviceSignerSolana, { deviceTransferMessage } from '../index.js'

const args = process.argv.slice(2)
const opt = (name, fallback) => {
  const i = args.indexOf('--' + name)
  return i >= 0 ? args[i + 1] : fallback
}
const [did, ownerFile, seedFile] = args
const mint = opt('mint')
if (!did || !ownerFile || !seedFile || !mint) {
  console.error('usage: node examples/device-wallet.js <device did> <owner seed file> <WDK seed phrase file> --mint <base58>')
  process.exit(1)
}
const rpc = opt('rpc', 'http://127.0.0.1:8899')
const decimals = Number(opt('decimals', 6))
const amount = BigInt(opt('amount', 100000))
const log = (line) => console.log('SOLWALLET|' + line)

if (!fs.existsSync(ownerFile)) fs.writeFileSync(ownerFile, crypto.randomBytes(32).toString('hex'), { mode: 0o600 })
const owner = HyperDHT.keyPair(Buffer.from(fs.readFileSync(ownerFile, 'utf8').trim(), 'hex'))
const raw = fs.readFileSync(seedFile, 'utf8').trim()
const mnemonic = raw.startsWith('{') ? JSON.parse(raw).mnemonic : raw

let passed = 0
let failed = 0
const check = (name, ok, detail = '') => {
  ok ? passed++ : failed++
  log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? '  ' + detail : ''}`)
}

const dht = new HyperDHT()
const wallet = new WalletManagerSolana(mnemonic, { provider: rpc, commitment: 'confirmed' })
const account = await wallet.getAccount(0)
const ownerAddress = await account.getAddress()

let t = Date.now()
const device = await BoatDeviceSignerSolana.connect({ dht, did, keyPair: owner })
check('the device answers with its Solana address', typeof device.address === 'string', `${device.address}, connected in ${Date.now() - t} ms`)

const before = await account.getTokenBalance(mint)
t = Date.now()
const { hash, fee } = await account.sendTransaction(await deviceTransferMessage({ device, mint, to: ownerAddress, amount, decimals }))
const r = await account.waitForTransaction(hash)
const after = await account.getTokenBalance(mint)
check('the device signs a transfer to the owner, the owner account pays the fee', r.success === true && after - before === amount, `${amount} units, ${hash.slice(0, 16)}..., fee ${fee} lamports, ${Date.now() - t} ms`)

const refusal = async (message) => account.sendTransaction(message).then(() => null, (err) => err.message)
const over = await refusal(await deviceTransferMessage({ device, mint, to: ownerAddress, amount: 10n ** 12n, decimals }))
check('the device refuses an amount over its limit', /over the device limit/.test(over), over)

const stranger = await BoatDeviceSignerSolana.connect({ dht, did, keyPair: HyperDHT.keyPair(), timeout: 20000 }).then(() => null, (err) => err.message)
check('another key cannot use the device as a signer', stranger !== null, stranger)

device.dispose()
wallet.dispose()
await dht.destroy()
log(`${passed} of ${passed + failed} passed`)
process.exit(failed ? 1 : 0)
