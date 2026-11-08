// An x402 facilitator that is a WDK account: POST /verify, POST /settle,
// GET /supported, as @x402/core's HTTPFacilitatorClient calls them.
//
// A device that sells with x402 (examples/boat_mer with
// CONFIG_MER_X402_SELL_PORT) checks each payment itself and sends it here to
// be settled: this account submits the EIP-3009 authorization and pays the
// gas, so the device needs none. Any x402 resource server can use it too.
//
// usage: node examples/x402/facilitator.js <file with a WDK seed phrase, or JSON with "mnemonic">
//        [--rpc url] [--chain-id 5042002] [--account 1] [--port 4022] [--host 0.0.0.0]

import fs from 'fs'
import http from 'http'
import WDK from '@tetherto/wdk'
import WalletManagerEvm from '@tetherto/wdk-wallet-evm'
import { x402Facilitator } from '@x402/core/facilitator'
import { registerExactEvmScheme } from '@x402/evm/exact/facilitator'
import { x402FacilitatorSigner } from '../../x402.js'

const args = process.argv.slice(2)
const opt = (name, fallback) => {
  const i = args.indexOf('--' + name)
  return i >= 0 ? args[i + 1] : fallback
}
const seedFile = args[0]
if (!seedFile || seedFile.startsWith('--')) {
  console.error('usage: node examples/x402/facilitator.js <seed file> [--rpc url] [--chain-id id] [--port 4022]')
  process.exit(1)
}
const raw = fs.readFileSync(seedFile, 'utf8').trim()
const mnemonic = raw.startsWith('{') ? JSON.parse(raw).mnemonic : raw
const chainId = Number(opt('chain-id', 5042002))
const network = `eip155:${chainId}`
const port = Number(opt('port', 4022))
const log = (line) => console.log(`FACILITATOR|${line}`)

const wdk = new WDK(mnemonic).registerWallet('chain', WalletManagerEvm, { provider: opt('rpc', 'http://127.0.0.1:8549'), chainId })
const account = await wdk.getAccount('chain', Number(opt('account', 1)))
const facilitator = new x402Facilitator()
registerExactEvmScheme(facilitator, { signer: await x402FacilitatorSigner(account), networks: network })

const stats = { verified: 0, settled: 0, refused: 0 }
const json = (res, status, body) => {
  res.writeHead(status, { 'content-type': 'application/json' })
  res.end(JSON.stringify(body, (k, v) => typeof v === 'bigint' ? v.toString() : v))
}

http.createServer((req, res) => {
  if (req.method === 'GET' && req.url === '/supported') return json(res, 200, facilitator.getSupported())
  if (req.method !== 'POST' || (req.url !== '/verify' && req.url !== '/settle')) return json(res, 404, { error: 'not found' })
  let body = ''
  req.on('data', (d) => { body += d })
  req.on('end', async () => {
    const t0 = Date.now()
    try {
      const { paymentPayload, paymentRequirements } = JSON.parse(body)
      const a = paymentPayload?.payload?.authorization
      if (req.url === '/verify') {
        const r = await facilitator.verify(paymentPayload, paymentRequirements)
        r.isValid ? stats.verified++ : stats.refused++
        log(`verify from ${a?.from} to ${a?.to} value ${a?.value}: ${r.isValid ? 'valid' : r.invalidReason}`)
        return json(res, 200, r)
      }
      const r = await facilitator.settle(paymentPayload, paymentRequirements)
      r.success ? stats.settled++ : stats.refused++
      log(`settle from ${a?.from} to ${a?.to} value ${a?.value}: ${r.success ? 'tx ' + r.transaction : r.errorReason} (${Date.now() - t0} ms; ${stats.settled} settled, ${stats.refused} refused)`)
      return json(res, 200, r)
    } catch (err) {
      log(`ERROR ${err.message}`)
      return json(res, 500, { error: err.message })
    }
  })
}).listen(port, opt('host', '0.0.0.0'), () => {
  log(`listening on :${port}, ${network}, signing and paying gas as ${account.address}`)
})
