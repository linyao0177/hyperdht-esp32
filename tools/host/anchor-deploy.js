// Compiles contracts/OpenAnchor.sol with Foundry and deploys it. Prints the
// contract address.
//
// usage: node anchor-deploy.js [--network local | arc-testnet] [--rpc url] [--store dir]
//
// --store  an anchor node store (anchor-node.js) whose wallet pays for the
//          deployment; required on a public network
//
// On the local network without --store it uses anvil's first dev account, a
// well-known test key: never use it on a real network.

const { execFileSync } = require('child_process')
const fs = require('fs')
const os = require('os')
const path = require('path')
const { Wallet, ContractFactory, formatEther } = require('ethers')
const { NETWORKS, provider, nodeKeys } = require('./open-anchor')

const opts = {}
for (let i = 2; i < process.argv.length; i++) opts[process.argv[i].replace(/^--/, '')] = process.argv[++i]
const network = NETWORKS[opts.network || 'local']
const rpc = opts.rpc || network.rpc
const ANVIL_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'

function compile () {
  // build in a temporary Foundry root so nothing is written next to the sources
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'open-anchor-'))
  fs.mkdirSync(path.join(root, 'src'))
  fs.copyFileSync(path.join(__dirname, 'contracts', 'OpenAnchor.sol'), path.join(root, 'src', 'OpenAnchor.sol'))
  const forge = process.env.FORGE || path.join(os.homedir(), '.foundry', 'bin', 'forge')
  execFileSync(forge, ['build', '--root', root], { stdio: 'ignore' })
  const artifact = JSON.parse(fs.readFileSync(path.join(root, 'out', 'OpenAnchor.sol', 'OpenAnchor.json')))
  fs.rmSync(root, { recursive: true, force: true })
  return artifact
}

async function main () {
  if (!opts.store && network !== NETWORKS.local) throw new Error('--store is required on a public network')
  const { abi, bytecode } = compile()
  const p = provider(rpc)
  const wallet = new Wallet(opts.store ? nodeKeys(opts.store).walletKey : ANVIL_KEY, p)
  console.log(`DEPLOY|from ${wallet.address} balance=${formatEther(await p.getBalance(wallet.address))}`)
  const contract = await new ContractFactory(abi, bytecode.object, wallet).deploy()
  const rc = await contract.deploymentTransaction().wait()
  console.log('DEPLOY|OpenAnchor', await contract.getAddress(), `tx=${rc.hash} block=${rc.blockNumber} gas=${rc.gasUsed}`)
  process.exit(0)
}

main().catch((err) => {
  console.error('DEPLOY|failed', err.shortMessage || err.message)
  process.exit(1)
})
