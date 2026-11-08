// A device selling readings with x402, end to end on anvil: node tests/x402-device.js
//
// The buyer is a standard x402 client (@x402/fetch, @x402/evm) signing with a
// WDK account; the facilitator is examples/x402/facilitator.js, a WDK account
// paying the gas; the device is emulated over HTTP the way
// examples/boat_mer/main/x402_sell.c answers, its payment checks done by the
// device's own C code when X402_HOST names examples/boat_mer/test/x402_host.c
// built for the desktop (else by ethers, the same checks).

import { spawn, execFileSync } from 'child_process'
import fs from 'fs'
import os from 'os'
import path from 'path'
import http from 'http'
import crypto from 'crypto'
import { fileURLToPath } from 'url'
import WDK from '@tetherto/wdk'
import WalletManagerEvm from '@tetherto/wdk-wallet-evm'
import { wrapFetchWithPayment, x402Client } from '@x402/fetch'
import { registerExactEvmScheme } from '@x402/evm/exact/client'
import { JsonRpcProvider, HDNodeWallet, Contract, Wallet, verifyTypedData } from 'ethers'

const here = path.dirname(fileURLToPath(import.meta.url))
const MNEMONIC = 'test test test test test test test test test test test junk'
const PORT = 8552
const FACILITATOR_PORT = 4122
const DEVICE_PORT = 4123
const PRICE = 1000n

let passed = 0
let failed = 0
function check (name, ok, detail = '') {
  if (ok) passed++
  else failed++
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? '  ' + detail : ''}`)
}
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))
const b64 = (s) => Buffer.from(s).toString('base64')

const TYPES = { TransferWithAuthorization: [{ name: 'from', type: 'address' }, { name: 'to', type: 'address' }, { name: 'value', type: 'uint256' }, { name: 'validAfter', type: 'uint256' }, { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'bytes32' }] }

// the device's checks: its C code, or the same in JS
function devicePaymentCheck ({ token, payee }, header) {
  const now = Math.floor(Date.now() / 1000)
  if (process.env.X402_HOST) {
    try {
      return execFileSync(process.env.X402_HOST, ['31337', token, 'USD₮0', '1', payee, String(PRICE), String(now), header], { encoding: 'utf8' }).trim()
    } catch (err) {
      return String(err.stdout).trim()
    }
  }
  const p = JSON.parse(Buffer.from(header, 'base64').toString())
  const a = p.payload.authorization
  if (a.to.toLowerCase() !== payee.toLowerCase()) return 'REFUSED pays someone else'
  if (BigInt(a.value) < PRICE) return 'REFUSED pays less than the price'
  const signer = verifyTypedData({ name: 'USD₮0', version: '1', chainId: 31337, verifyingContract: token }, TYPES, a, p.payload.signature)
  if (signer.toLowerCase() !== a.from.toLowerCase()) return 'REFUSED not signed by the payer'
  return `OK ${a.from} ${a.value}`
}

// the device, as x402_sell.c answers
function emulateDevice ({ token, payee }) {
  const requirements = `{"scheme":"exact","network":"eip155:31337","amount":"${PRICE}","asset":"${token}","payTo":"${payee}","maxTimeoutSeconds":300,"extra":{"name":"USD₮0","version":"1"}}`
  const seen = new Set()
  const stats = { sold: 0, refused: [] }
  const required = (res, host, error) => {
    const body = `{"x402Version":2,"error":"${error}","resource":{"url":"http://${host}/reading","description":"A reading attested by the device (did:mw)","mimeType":"application/json"},"accepts":[${requirements}]}`
    res.writeHead(402, { 'content-type': 'application/json', 'PAYMENT-REQUIRED': b64(body) })
    res.end(body)
  }
  const server = http.createServer(async (req, res) => {
    const header = req.headers['payment-signature']
    if (!header) return required(res, req.headers.host, 'PAYMENT-SIGNATURE header is required')
    const json = Buffer.from(header, 'base64').toString()
    let verdict = devicePaymentCheck({ token, payee }, header)
    const nonce = JSON.parse(json).payload.authorization.nonce
    if (verdict.startsWith('OK') && seen.has(nonce)) verdict = 'REFUSED payment already used'
    if (!verdict.startsWith('OK')) {
      stats.refused.push(verdict.slice(8))
      return required(res, req.headers.host, verdict.slice(8))
    }
    seen.add(nonce)
    const r = await fetch(`http://127.0.0.1:${FACILITATOR_PORT}/settle`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: `{"x402Version":2,"paymentPayload":${json},"paymentRequirements":${requirements}}` })
    const settled = await r.json()
    if (!settled.success) {
      stats.refused.push('settlement failed: ' + settled.errorReason)
      return required(res, req.headers.host, 'settlement failed')
    }
    stats.sold++
    const payer = verdict.split(' ')[1]
    res.writeHead(200, { 'content-type': 'application/json', 'PAYMENT-RESPONSE': b64(`{"success":true,"transaction":"${settled.transaction}","network":"eip155:31337","payer":"${payer}"}`) })
    res.end('{"payload":"{\\"uptime_s\\":1}"}')
  })
  return new Promise((resolve) => server.listen(DEVICE_PORT, '127.0.0.1', () => resolve({ server, stats })))
}

async function main () {
  try {
    execFileSync('anvil', ['--version'], { stdio: 'ignore' })
  } catch {
    console.log('SKIP: anvil not found')
    return
  }
  console.log(process.env.X402_HOST ? `device checks: ${process.env.X402_HOST} (C)` : 'device checks: ethers (set X402_HOST for the device\'s C code)')
  const url = `http://127.0.0.1:${PORT}`
  const anvil = spawn('anvil', ['--port', String(PORT), '--silent', '--mnemonic', MNEMONIC], { stdio: 'ignore' })
  const provider = new JsonRpcProvider(url, undefined, { staticNetwork: true })
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'boat-x402-'))
  let facilitator = null
  let device = null
  try {
    for (let i = 0; i < 50; i++) {
      try {
        if ((await provider.send('eth_chainId', [])) === '0x7a69') break
      } catch {}
      await sleep(200)
    }
    const deployer = HDNodeWallet.fromPhrase(MNEMONIC, undefined, "m/44'/60'/0'/0/2").connect(provider)
    const root = fs.mkdtempSync(path.join(tmp, 'token-'))
    fs.mkdirSync(path.join(root, 'src'))
    fs.copyFileSync(path.join(here, 'fixtures', 'TestToken3009.sol'), path.join(root, 'src', 'TestToken3009.sol'))
    const out = execFileSync('forge', ['create', 'src/TestToken3009.sol:TestToken3009', '--root', root, '--rpc-url', url, '--private-key', deployer.privateKey, '--broadcast', '--constructor-args', 'USD₮0', '1'], { encoding: 'utf8' })
    const token = out.match(/Deployed to: (0x[0-9a-fA-F]{40})/)[1]
    const erc20 = new Contract(token, ['function mint(address,uint256)', 'function balanceOf(address) view returns (uint256)'], deployer)

    const wdk = new WDK(MNEMONIC).registerWallet('local', WalletManagerEvm, { provider: url, chainId: 31337 })
    const buyer = await wdk.getAccount('local', 0)
    await (await erc20.mint(buyer.address, 100000n)).wait()
    const payee = Wallet.createRandom().address // the device's own address

    const seedFile = path.join(tmp, 'seed')
    fs.writeFileSync(seedFile, MNEMONIC)
    facilitator = spawn('node', [path.join(here, '..', 'examples', 'x402', 'facilitator.js'), seedFile, '--rpc', url, '--chain-id', '31337', '--account', '1', '--port', String(FACILITATOR_PORT), '--host', '127.0.0.1'], { stdio: ['ignore', 'pipe', 'inherit'] })
    let facilitatorLog = ''
    facilitator.stdout.on('data', (d) => { facilitatorLog += d; if (process.env.VERBOSE) process.stdout.write(d) })
    for (let i = 0; i < 100 && !facilitatorLog.includes('listening'); i++) await sleep(100)
    const facilitatorAddress = HDNodeWallet.fromPhrase(MNEMONIC, undefined, "m/44'/60'/0'/0/1").address
    const gasBefore = await provider.getBalance(facilitatorAddress)

    device = await emulateDevice({ token, payee })
    // the client pays only known assets unless told: this token, at most the price
    const client = new x402Client().setSpendControls({ allowedAssets: [{ network: 'eip155:31337', asset: token, maxAmountPerPayment: String(PRICE) }] })
    registerExactEvmScheme(client, { signer: { address: buyer.address, signTypedData: (typed) => buyer.signTypedData(typed) } })
    const pay = wrapFetchWithPayment(fetch, client)

    const first = await fetch(`http://127.0.0.1:${DEVICE_PORT}/reading`)
    const req = JSON.parse(Buffer.from(first.headers.get('payment-required'), 'base64').toString())
    check('without a payment the device answers 402 with x402 v2 requirements', first.status === 402 && req.x402Version === 2 && req.accepts[0].payTo === payee && req.accepts[0].amount === String(PRICE))

    let bought = 0
    let lastHeader = null
    const capture = async (input, init) => {
      const h = new Headers(input instanceof Request ? input.headers : init?.headers).get('PAYMENT-SIGNATURE')
      if (h) lastHeader = h
      return fetch(input, init)
    }
    const payCapturing = wrapFetchWithPayment(capture, client)
    for (let i = 0; i < 3; i++) {
      const res = await (i === 0 ? payCapturing : pay)(`http://127.0.0.1:${DEVICE_PORT}/reading`)
      const receipt = res.headers.get('payment-response') && JSON.parse(Buffer.from(res.headers.get('payment-response'), 'base64').toString())
      if (res.status === 200 && receipt.success && (await provider.getTransactionReceipt(receipt.transaction)).status === 1) bought++
      else console.log(`  #${i + 1}: HTTP ${res.status}, device: ${device.stats.refused.at(-1)}`)
    }
    check('a WDK account buys 3 readings with a standard x402 client', bought === 3 && (await erc20.balanceOf(payee)) === 3n * PRICE, `device paid ${await erc20.balanceOf(payee)} units`)
    check("the facilitator's WDK account paid the gas, the device none", (await provider.getBalance(facilitatorAddress)) < gasBefore && (await provider.getBalance(payee)) === 0n)

    const again = await fetch(`http://127.0.0.1:${DEVICE_PORT}/reading`, { headers: { 'PAYMENT-SIGNATURE': lastHeader } })
    check('a payment sent again is refused', again.status === 402 && device.stats.refused.at(-1) === 'payment already used', device.stats.refused.at(-1))

    const forged = async (change, sign = true) => {
      const p = JSON.parse(Buffer.from(lastHeader, 'base64').toString())
      const a = { ...p.payload.authorization, nonce: '0x' + crypto.randomBytes(32).toString('hex'), ...change }
      const signature = sign ? await buyer.signTypedData({ domain: { name: 'USD₮0', version: '1', chainId: 31337, verifyingContract: token }, types: TYPES, primaryType: 'TransferWithAuthorization', message: a }) : p.payload.signature
      const res = await fetch(`http://127.0.0.1:${DEVICE_PORT}/reading`, { headers: { 'PAYMENT-SIGNATURE': b64(JSON.stringify({ ...p, payload: { authorization: a, signature } })) } })
      return { status: res.status, why: device.stats.refused.at(-1) }
    }
    let r = await forged({ value: String(PRICE - 1n) })
    check('the device refuses less than its price', r.status === 402 && r.why === 'pays less than the price', r.why)
    r = await forged({ to: Wallet.createRandom().address })
    check('the device refuses a payment to someone else', r.status === 402 && r.why === 'pays someone else', r.why)
    r = await forged({}, false)
    check('the device refuses an authorization not signed by its payer', r.status === 402 && r.why === 'not signed by the payer', r.why)
    check('nothing more was settled', (await erc20.balanceOf(payee)) === 3n * PRICE && device.stats.sold === 3)
    wdk.dispose()
  } finally {
    if (device) device.server.close()
    if (facilitator) facilitator.kill()
    anvil.kill()
  }
  console.log(`\n${passed} of ${passed + failed} passed`)
  if (failed) process.exit(1)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
