// Compiles contracts/OpenAnchor.sol with Foundry and deploys it to a local
// chain, such as `anvil`. Prints the contract address.
//
// usage: node anchor-deploy.js [rpc url, default http://127.0.0.1:8545]
//
// Uses anvil's first dev account, a well-known test key: never use it on a
// real network.

const { execFileSync } = require('child_process')
const fs = require('fs')
const os = require('os')
const path = require('path')
const { JsonRpcProvider, Wallet, ContractFactory } = require('ethers')

const rpc = process.argv[2] || 'http://127.0.0.1:8545'
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
  const { abi, bytecode } = compile()
  const wallet = new Wallet(ANVIL_KEY, new JsonRpcProvider(rpc))
  const contract = await new ContractFactory(abi, bytecode.object, wallet).deploy()
  await contract.waitForDeployment()
  console.log('DEPLOY|OpenAnchor', await contract.getAddress())
}

main()
