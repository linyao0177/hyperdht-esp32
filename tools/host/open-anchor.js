// Shared by the open anchoring tools: networks, discovery topic, node keys and
// DID record checks (anchor-node.js, anchor-discover.js, anchor-verify.js).

const fs = require('fs')
const path = require('path')
const crypto = require('crypto')
const sodium = require('sodium-universal')
const HyperDHT = require('hyperdht')
const { FetchRequest, JsonRpcProvider, Wallet, verifyMessage } = require('ethers')

// Public deployments of contracts/OpenAnchor.sol. Anyone can anchor in them.
const NETWORKS = {
  'arc-testnet': {
    rpc: 'https://rpc.testnet.arc.network',
    chainId: 5042002,
    contract: '0xd7d651a6fecE5C9ed96796678ED995Fb12dAbeCA',
    explorer: 'https://explorer.testnet.arc.io',
    faucet: 'https://faucet.circle.com'
  },
  local: {
    rpc: 'http://127.0.0.1:8545',
    chainId: 31337,
    contract: '0x5FbDB2315678afecb367f032d93F642f64180aa3' // first deploy on a fresh anvil
  }
}

const ABI = [
  'function anchorRoot(bytes32 merkleRoot)',
  'function anchors(bytes32) view returns (uint64 timestamp, address anchorer)',
  'event RootAnchored(bytes32 indexed merkleRoot, address indexed anchorer, uint256 timestamp)'
]

// Nodes of one deployment announce under this topic; devices and clients look
// it up to find them. BLAKE2b-256("open-anchor/1 <chain id> <contract, lowercase>")
function topic (chainId, contract) {
  const out = Buffer.alloc(32)
  sodium.crypto_generichash(out, Buffer.from(`open-anchor/1 ${chainId} ${contract.toLowerCase()}`))
  return out
}

// JSON-RPC over HTTPS_PROXY when one is set (Node's own HTTP client ignores it)
function provider (rpc) {
  const req = new FetchRequest(rpc)
  const proxy = process.env.HTTPS_PROXY || process.env.https_proxy
  if (proxy && !/^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])[:/]/.test(rpc)) {
    const { HttpsProxyAgent } = require('https-proxy-agent')
    req.getUrlFunc = FetchRequest.createGetUrlFunc({ agent: new HttpsProxyAgent(proxy) })
  }
  return new JsonRpcProvider(req)
}

// A DID record is valid when its did is the key it is stored under and its
// eth_sig (EIP-191 over the did) recovers to its eth address.
function verifyRecord (publicKey, value) {
  try {
    const r = JSON.parse(value.toString())
    if (r.did !== 'did:mw:' + publicKey.toString('hex')) return null
    if (verifyMessage(r.did, r.eth_sig).toLowerCase() !== r.eth.toLowerCase()) return null
    return r
  } catch {
    return null
  }
}

// An anchor node's record must also name the deployment we are looking for.
function isAnchorNode (r, chainId, contract) {
  return !!r && r.svc === 'anchor/1' && r.chain_id === chainId && String(r.contract).toLowerCase() === contract.toLowerCase()
}

function readOrCreate (file, make) {
  try {
    return fs.readFileSync(file, 'utf8').trim()
  } catch {
    const v = make()
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 })
    fs.writeFileSync(file, v + '\n', { mode: 0o600 })
    return v
  }
}

// The node's HyperDHT identity (its DID) and its wallet, kept in the store
// directory and created on first use. Neither ever leaves the machine.
function nodeKeys (store) {
  const seed = readOrCreate(path.join(store, 'identity.key'), () => crypto.randomBytes(32).toString('hex'))
  const walletKey = readOrCreate(path.join(store, 'wallet.key'), () => Wallet.createRandom().privateKey)
  return { keyPair: HyperDHT.keyPair(Buffer.from(seed, 'hex')), walletKey }
}

module.exports = { NETWORKS, ABI, provider, topic, verifyRecord, isAnchorNode, nodeKeys }
