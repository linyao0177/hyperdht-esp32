// An x402 resource server whose facilitator is a WDK account.
//
// GET /reading costs `price` units of an EIP-3009 token. Without a payment it
// answers 402 with the payment requirements, in the PAYMENT-REQUIRED header
// and in the body (BoAT MER's x402 client reads the body). With a
// PAYMENT-SIGNATURE (x402 v2) or X-PAYMENT (v1) header, the x402 facilitator
// verifies the EIP-3009 authorization and settles it on-chain, signing and
// paying gas with a WDK EVM account (wdk-protocol-boat-evm's facilitator
// signer). The payee is another account of the same WDK wallet.
//
// usage: node examples/x402/server.js <file with a WDK seed phrase, or JSON with "mnemonic">
//        [--rpc url] [--chain-id 5042002] [--token 0x36..] [--token-name USDC]
//        [--token-version 2] [--price 1000] [--port 4021]

import fs from 'fs'
import http from 'http'
import WDK from '@tetherto/wdk'
import WalletManagerEvm from '@tetherto/wdk-wallet-evm'
import { x402Facilitator } from '@x402/core/facilitator'
import { registerExactEvmScheme } from '@x402/evm/exact/facilitator'
import { registerBoat } from '../../index.js'
import { x402FacilitatorSigner } from '../../x402.js'

const args = process.argv.slice(2)
const opt = (name, fallback) => {
  const i = args.indexOf('--' + name)
  return i >= 0 ? args[i + 1] : fallback
}
const seedFile = args[0]
if (!seedFile || seedFile.startsWith('--')) {
  console.error('usage: node examples/x402/server.js <seed file> [--rpc url] [--price units] [--port 4021]')
  process.exit(1)
}
const raw = fs.readFileSync(seedFile, 'utf8').trim()
const mnemonic = raw.startsWith('{') ? JSON.parse(raw).mnemonic : raw

const chainId = Number(opt('chain-id', 5042002))
const token = opt('token', '0x3600000000000000000000000000000000000000')
const tokenName = opt('token-name', 'USDC')
const tokenVersion = opt('token-version', '2')
const price = String(opt('price', 1000))
const port = Number(opt('port', 4021))
const network = `eip155:${chainId}`

const wdk = new WDK(mnemonic).registerWallet('chain', WalletManagerEvm, { provider: opt('rpc', 'http://127.0.0.1:8549'), chainId })
registerBoat(wdk, 'chain', { token, chainId, tokenName, tokenVersion })
const payee = await wdk.getAccount('chain', 0)
const facilitatorAccount = await wdk.getAccount('chain', 1)

const facilitator = new x402Facilitator()
registerExactEvmScheme(facilitator, { signer: await x402FacilitatorSigner(facilitatorAccount), networks: network })

const requirement = {
  scheme: 'exact',
  network,
  amount: price,
  asset: token,
  payTo: payee.address,
  maxTimeoutSeconds: 300,
  extra: { name: tokenName, version: tokenVersion, verifyingContract: token }
}

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64')
const log = (line) => console.log(`X402|${line}`)

http.createServer(async (req, res) => {
  if (!req.url.startsWith('/reading')) {
    res.writeHead(404).end()
    return
  }
  const header = req.headers['payment-signature'] || req.headers['x-payment']
  const resource = { url: `http://${req.headers.host}${req.url}`, description: 'a signed meter reading', mimeType: 'application/json' }
  const required = { x402Version: 2, error: 'payment required', resource, accepts: [requirement] }
  if (!header) {
    log(`402 for ${req.method} ${req.url}`)
    res.writeHead(402, { 'content-type': 'application/json', 'payment-required': b64(required) })
    res.end(JSON.stringify(required))
    return
  }
  const t0 = Date.now()
  try {
    const payload = JSON.parse(Buffer.from(String(header), 'base64').toString())
    const a = payload.payload && payload.payload.authorization
    log(`payment from ${a && a.from}, value ${a && a.value}, x402 v${payload.x402Version}`)
    const verified = await facilitator.verify(payload, requirement)
    if (!verified.isValid) {
      log(`REFUSED: ${verified.invalidReason}${verified.invalidMessage ? ' ' + verified.invalidMessage : ''}`)
      res.writeHead(402, { 'content-type': 'application/json', 'payment-required': b64({ ...required, error: verified.invalidReason }) })
      res.end(JSON.stringify({ ...required, error: verified.invalidReason }))
      return
    }
    const settled = await facilitator.settle(payload, requirement)
    if (!settled.success) {
      log(`SETTLEMENT FAILED: ${settled.errorReason}`)
      res.writeHead(402, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ...required, error: settled.errorReason }))
      return
    }
    log(`SETTLED tx ${settled.transaction} for ${settled.payer}, ${Date.now() - t0} ms`)
    const body = { reading: { power_w: 12.0, t: Date.now() }, tx: settled.transaction }
    res.writeHead(200, { 'content-type': 'application/json', 'payment-response': b64(settled), 'x-payment-response': b64(settled) })
    res.end(JSON.stringify(body))
  } catch (err) {
    log(`ERROR ${err.stack}`)
    res.writeHead(500, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ error: err.message }))
  }
}).listen(port, () => {
  log(`listening on http://127.0.0.1:${port}/reading, ${price} units of ${tokenName} (${token}) on ${network}`)
  log(`payee ${payee.address}, facilitator ${facilitatorAccount.address}`)
})
