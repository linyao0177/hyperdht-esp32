// A BoAT MER device's wallet in WDK, its key staying on the device.
//
// The owner's app makes a WDK account whose signer is the device
// (BoatDeviceSignerEvm), reads its balance, has it sign a message, and sweeps
// some of its tokens to the owner's own WDK account: the device signs an
// EIP-3009 authorization, the owner's account submits it and pays the gas.
// Then it checks what the device refuses.
//
// usage: node examples/device-wallet.js <device did> <owner seed file> <WDK seed phrase file>
//        [--rpc url] [--chain-id 5042002] [--token 0x36..] [--token-name USDC] [--token-version 2]
//        [--sweep 50000]
//
// The owner seed file holds 32 bytes of hex (made if missing); the device
// trusts that key through CONFIG_MER_OWNER_KEY.

import fs from 'fs'
import crypto from 'crypto'
import HyperDHT from 'hyperdht'
import WDK from '@tetherto/wdk'
import WalletManagerEvm, { WalletAccountEvm } from '@tetherto/wdk-wallet-evm'
import { registerBoat, BoatDeviceSignerEvm } from '../index.js'

const args = process.argv.slice(2)
const opt = (name, fallback) => {
  const i = args.indexOf('--' + name)
  return i >= 0 ? args[i + 1] : fallback
}
const [did, ownerFile, seedFile] = args
if (!did || !ownerFile || !seedFile) {
  console.error('usage: node examples/device-wallet.js <device did> <owner seed file> <WDK seed phrase file>')
  process.exit(1)
}
const rpc = opt('rpc', 'http://127.0.0.1:8549')
const chainId = Number(opt('chain-id', 5042002))
const token = opt('token', '0x3600000000000000000000000000000000000000')
const tokenName = opt('token-name', 'USDC')
const tokenVersion = opt('token-version', '2')
const sweep = BigInt(opt('sweep', 50000))
const log = (line) => console.log('WALLET|' + line)

if (!fs.existsSync(ownerFile)) fs.writeFileSync(ownerFile, crypto.randomBytes(32).toString('hex'), { mode: 0o600 })
const owner = HyperDHT.keyPair(Buffer.from(fs.readFileSync(ownerFile, 'utf8').trim(), 'hex'))
log(`owner key ${owner.publicKey.toString('hex')} (CONFIG_MER_OWNER_KEY)`)
const raw = fs.readFileSync(seedFile, 'utf8').trim()
const mnemonic = raw.startsWith('{') ? JSON.parse(raw).mnemonic : raw

const domain = { name: tokenName, version: tokenVersion, chainId, verifyingContract: token }
const types = {
  TransferWithAuthorization: [
    { name: 'from', type: 'address' }, { name: 'to', type: 'address' }, { name: 'value', type: 'uint256' },
    { name: 'validAfter', type: 'uint256' }, { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'bytes32' }
  ]
}
const authorization = (from, to, value) => ({ from, to, value: String(value), validAfter: '0', validBefore: String(Math.floor(Date.now() / 1000) + 3600), nonce: '0x' + crypto.randomBytes(32).toString('hex') })

let passed = 0
let failed = 0
const check = (name, ok, detail = '') => {
  ok ? passed++ : failed++
  log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? '  ' + detail : ''}`)
}
async function refused (fn) {
  try {
    await fn()
    return null
  } catch (err) {
    return err.message
  }
}

const dht = new HyperDHT()
const wdk = new WDK(mnemonic).registerWallet('chain', WalletManagerEvm, { provider: rpc, chainId })
registerBoat(wdk, 'chain', { token, chainId, tokenName, tokenVersion })
const mine = await wdk.getAccount('chain', 0) // the owner's own WDK account, with gas
const boat = mine.getBoatProtocol()

let t = Date.now()
const signer = await BoatDeviceSignerEvm.connect({ dht, did, keyPair: owner })
const device = new WalletAccountEvm(signer, { provider: rpc, chainId })
check('WDK account with the device as its signer', device.address === signer.address && device.keyPair.privateKey === null, `${device.address}, connected in ${Date.now() - t} ms`)

const before = await device.getTokenBalance(token)
const mineBefore = await mine.getTokenBalance(token)
log(`device balance ${before}, owner account ${mine.address} balance ${mineBefore}`)

t = Date.now()
const message = 'owner check ' + new Date().toISOString()
const sig = await device.sign(message)
check('the device signs a message (EIP-191)', typeof sig === 'string' && sig.length === 132, `${Date.now() - t} ms`)

t = Date.now()
const auth = authorization(device.address, mine.address, sweep)
const authSig = await device.signTypedData({ domain, types, message: auth })
check('the device signs a sweep to the owner (EIP-3009)', authSig.length === 132, `${sweep} units, ${Date.now() - t} ms`)
t = Date.now()
const { hash } = await boat.settle({ ...auth, signature: authSig })
const r = await boat.waitForSettlement(hash)
const after = await device.getTokenBalance(token)
const mineAfter = await mine.getTokenBalance(token)
check('the owner account submits it', r.ok && before - after === sweep, `tx ${hash}, block ${r.block}, ${Date.now() - t} ms`)
log(`device balance ${after}, owner account balance ${mineAfter} (gas paid by the owner account)`)

const tooMuch = await refused(() => device.signTypedData({ domain, types, message: authorization(device.address, mine.address, 10n ** 9n) }))
check('the device refuses an amount over its limit', tooMuch && /over the device limit/.test(tooMuch), tooMuch)
const otherType = await refused(() => device.signTypedData({ domain, types: { Permit: types.TransferWithAuthorization }, message: auth }))
check('the signer refuses other typed data', otherType && /only EIP-3009/.test(otherType), otherType && otherType.slice(0, 60))
const tx = await refused(() => device.sendTransaction({ to: mine.address, value: 1n }))
check('the device signs no transactions', tx !== null, tx && tx.slice(0, 70))

const stranger = await refused(async () => {
  const s = await BoatDeviceSignerEvm.connect({ dht, did, keyPair: HyperDHT.keyPair(), timeout: 20000 })
  s.dispose()
})
check('another key cannot use the device as a signer', stranger !== null, stranger)

signer.dispose()
wdk.dispose()
await dht.destroy()
log(`${passed} of ${passed + failed} passed`)
process.exit(failed ? 1 : 0)
