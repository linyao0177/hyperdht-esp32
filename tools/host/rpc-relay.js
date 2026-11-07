// Forwards JSON-RPC from a local port to a remote chain RPC, through the
// HTTPS proxy in HTTPS_PROXY when one is set. For apps whose HTTP client does
// not use a proxy (Bare, Node's fetch) on networks where the RPC is only
// reachable through one.
//
// usage: node rpc-relay.js <upstream https URL> [port, default 8549]

const http = require('http')
const https = require('https')

const [upstream, port = '8549'] = process.argv.slice(2)
if (!/^https:\/\//.test(upstream || '')) {
  console.error('usage: node rpc-relay.js <upstream https URL> [port]')
  process.exit(1)
}
const proxy = process.env.HTTPS_PROXY || process.env.https_proxy
const agent = proxy ? new (require('https-proxy-agent').HttpsProxyAgent)(proxy) : undefined

http.createServer((req, res) => {
  const chunks = []
  req.on('data', (c) => chunks.push(c))
  req.on('end', () => {
    const body = Buffer.concat(chunks)
    const out = https.request(upstream, { method: 'POST', agent, headers: { 'content-type': 'application/json', 'content-length': body.length } }, (up) => {
      res.writeHead(up.statusCode, { 'content-type': up.headers['content-type'] || 'application/json' })
      up.pipe(res)
    })
    out.on('error', (err) => {
      res.writeHead(502, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32603, message: 'relay: ' + err.message } }))
    })
    out.end(body)
  })
}).listen(Number(port), '127.0.0.1', () => {
  console.log(`RELAY|http://127.0.0.1:${port} -> ${upstream}${agent ? ' via ' + proxy : ''}`)
})
