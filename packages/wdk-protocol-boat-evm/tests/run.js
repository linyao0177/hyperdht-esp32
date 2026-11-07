// Tests for wdk-protocol-boat-evm: node tests/run.js
//
// With Foundry installed, it also starts anvil, deploys a minimal EIP-3009
// token (tests/fixtures) under a "USD₮0"/"1" domain, and settles real
// device-style authorizations from a WDK account, end to end.

import { spawn, execFileSync } from 'child_process'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { fileURLToPath } from 'url'
import EventEmitter from 'events'
import WDK from '@tetherto/wdk'
import WalletManagerEvm from '@tetherto/wdk-wallet-evm'
import crypto from 'crypto'
import { Interface, JsonRpcProvider, HDNodeWallet, Contract } from 'ethers'
import boatPeer from 'boat-peer'
import BoatProtocolEvm, { registerBoat, transferWithAuthorizationData } from '../index.js'

const { eth, frame, OP, CHR, verifyRecord } = boatPeer
const here = path.dirname(fileURLToPath(import.meta.url))
const MNEMONIC = 'test test test test test test test test test test test junk' // anvil's own test accounts
const BUYER_KEY = Buffer.from(HDNodeWallet.fromPhrase(MNEMONIC, undefined, "m/44'/60'/0'/0/1").privateKey.slice(2), 'hex')

let passed = 0
let failed = 0
function check (name, ok, detail = '') {
  if (ok) passed++
  else failed++
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? '  ' + detail : ''}`)
}

const ABI = ['function transferWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, uint8 v, bytes32 r, bytes32 s)', 'function balanceOf(address) view returns (uint256)', 'function mint(address to, uint256 value)', 'function name() view returns (string)']


// a buyer on an in-memory stream that signs each bill the way MER's buyer does
async function buy (seller, domain, buyerKey, slices) {
  const a = new EventEmitter()
  const b = new EventEmitter()
  const buyerPk = Buffer.alloc(32, 7)
  a.remotePublicKey = buyerPk
  b.remotePublicKey = Buffer.alloc(32, 9)
  a.write = (m) => setTimeout(() => b.emit('data', Buffer.from(m)), 1)
  b.write = (m) => setTimeout(() => a.emit('data', Buffer.from(m)), 1)
  const record = Buffer.from(JSON.stringify({ v: 1, did: 'did:mw:' + buyerPk.toString('hex'), eth: eth.addressOf(buyerKey), eth_sig: eth.signMessage('did:mw:' + buyerPk.toString('hex'), buyerKey) }))
  const dht = { mutableGet: async () => ({ value: record, seq: 1 }) }
  const payments = []
  seller.on('payment', (p) => payments.push(p))
  seller.serve(a, dht)
  await new Promise((resolve) => setTimeout(resolve, 20))
  let n = 0
  await new Promise((resolve) => {
    b.on('data', (msg) => {
      const uuid16 = msg[1] | msg[2] << 8
      if (uuid16 !== CHR.SLICE_REQUEST) return
      const v = msg.subarray(3)
      const dv = new DataView(v.buffer, v.byteOffset, v.byteLength)
      const t = { from: eth.addressOf(buyerKey), to: '0x' + v.subarray(44, 64).toString('hex'), value: String(dv.getBigUint64(64, true)), validAfter: dv.getUint32(4, true), validBefore: dv.getUint32(8, true), nonce: '0x' + v.subarray(12, 44).toString('hex') }
      b.write(frame(OP.WRITE, CHR.SLICE_PAYMENT, Buffer.from(JSON.stringify({ ...t, sig: eth.signTransfer(domain, t, buyerKey), slice_id: dv.getUint32(0, true) }))))
      if (++n === slices) {
        b.write(frame(OP.WRITE, CHR.STREAM_REQUEST, Buffer.from([1])))
        setTimeout(() => { a.emit('close'); resolve() }, 50)
      }
    })
    b.write(frame(OP.WRITE, CHR.STREAM_REQUEST, Buffer.from([2])))
  })
  return payments
}

async function startChain () {
  try {
    execFileSync('anvil', ['--version'], { stdio: 'ignore' })
  } catch {
    return null
  }
  const port = 8547
  const anvil = spawn('anvil', ['--port', String(port), '--silent', '--mnemonic', MNEMONIC], { stdio: 'ignore' })
  const url = `http://127.0.0.1:${port}`
  const provider = new JsonRpcProvider(url)
  for (let i = 0; i < 50; i++) {
    try {
      await provider.getBlockNumber()
      return { anvil, url, provider }
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 200))
    }
  }
  anvil.kill()
  throw new Error('anvil did not start')
}

function deploy (url, deployerKey, name, version) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'boat-token-'))
  fs.mkdirSync(path.join(root, 'src'))
  fs.copyFileSync(path.join(here, 'fixtures', 'TestToken3009.sol'), path.join(root, 'src', 'TestToken3009.sol'))
  const out = execFileSync('forge', ['create', 'src/TestToken3009.sol:TestToken3009', '--root', root, '--rpc-url', url, '--private-key', deployerKey, '--broadcast', '--constructor-args', name, version], { encoding: 'utf8' })
  return out.match(/Deployed to: (0x[0-9a-fA-F]{40})/)[1]
}

async function main () {
  // call data, against ethers
  const sig = eth.signTransfer({ name: 'USDC', version: '2', chainId: 5042002, verifyingContract: '0x3600000000000000000000000000000000000000' }, { from: eth.addressOf(BUYER_KEY), to: '0x05DEB6dE3CA53eb0729a59dDCb5f48B0FBd53c60', value: '4', validAfter: 0, validBefore: 1800000000, nonce: '0x' + 'ab'.repeat(32) }, BUYER_KEY)
  const auth = { from: eth.addressOf(BUYER_KEY), to: '0x05DEB6dE3CA53eb0729a59dDCb5f48B0FBd53c60', value: '4', validAfter: 0, validBefore: 1800000000, nonce: '0x' + 'ab'.repeat(32), signature: sig }
  const decoded = new Interface(ABI).decodeFunctionData('transferWithAuthorization', transferWithAuthorizationData(auth))
  check('transferWithAuthorization call data decodes with ethers', decoded[0] === auth.from && decoded[1] === auth.to && decoded[2] === 4n && decoded[5] === auth.nonce && Number(decoded[6]) === parseInt(sig.slice(-2), 16) && decoded[7] === '0x' + sig.slice(2, 66))

  const chain = await startChain()
  if (!chain) {
    console.log('SKIP local chain: anvil not found')
  } else {
    try {
      const deployer = HDNodeWallet.fromPhrase(MNEMONIC, undefined, "m/44'/60'/0'/0/2")
      const token = deploy(chain.url, deployer.privateKey, 'USD₮0', '1')
      const buyerAddress = eth.addressOf(BUYER_KEY)
      const minter = new Contract(token, ABI, deployer.connect(chain.provider))
      await (await minter.mint(buyerAddress, 1000000n)).wait()
      check('test token deployed and minted', (await minter.balanceOf(buyerAddress)) === 1000000n, token)

      const wdk = new WDK(MNEMONIC)
      wdk.registerWallet('local', WalletManagerEvm, { provider: chain.url })
      registerBoat(wdk, 'local', { token, chainId: 31337, tokenName: 'USD₮0', tokenVersion: '1' })
      const account = await wdk.getAccount('local', 0)
      const boat = account.getBoatProtocol()
      check('registerBoat adds account.getBoatProtocol()', boat instanceof BoatProtocolEvm && account.getBoatProtocol() === boat)

      const devicePk = crypto.randomBytes(32)
      const record = await boat.didRecord(devicePk)
      check('DID record signed by the WDK account verifies', verifyRecord(devicePk, Buffer.from(JSON.stringify(record))) !== null && record.eth === account.address)

      const seller = boat.seller({ rate: 250000, sliceMs: 300, power: () => 1200 })
      const payments = await buy(seller, boat.domain, BUYER_KEY, 3)
      check('the seller accepts 3 slices signed under the token domain', payments.length === 3 && payments.every((p) => p.ok), payments.map((p) => p.reason || p.authorization.value).join(','))

      const before = await minter.balanceOf(account.address)
      let total = 0n
      let settled = 0
      for (const p of payments) {
        const { hash } = await boat.settle(p.authorization)
        const r = await boat.waitForSettlement(hash)
        if (r.ok && await boat.isSettled(p.authorization.from, p.authorization.nonce)) settled++
        total += BigInt(p.authorization.value)
      }
      const after = await minter.balanceOf(account.address)
      check('WDK account settles all 3 on-chain', settled === 3 && after - before === total, `${total} units moved`)

      let replay = null
      try {
        await boat.settle(payments[0].authorization)
      } catch (err) {
        replay = err.message
      }
      check('settling the same authorization again fails', replay !== null && /used/.test(replay), replay && replay.slice(0, 60))

      // a fresh authorization, with its amount changed after signing
      const fresh = { from: buyerAddress, to: account.address, value: '25', validAfter: 0, validBefore: Math.floor(Date.now() / 1000) + 3600, nonce: '0x' + crypto.randomBytes(32).toString('hex') }
      const freshSig = eth.signTransfer(boat.domain, fresh, BUYER_KEY)
      let tampered = null
      try {
        await boat.settle({ ...fresh, signature: freshSig, value: '999' })
      } catch (err) {
        tampered = err.message
      }
      check('a changed amount fails', tampered !== null && /invalid signature/.test(tampered), tampered && tampered.slice(0, 60))

      const signer = await boat.x402FacilitatorSigner()
      const name = await signer.readContract({ address: token, abi: ABI, functionName: 'name' })
      check('x402 facilitator signer reads the token', name === 'USD₮0' && signer.getAddresses()[0] === account.address)
      check('x402 facilitator signer finds the contract code', (await signer.getCode({ address: token })) !== undefined)
      wdk.dispose()
    } finally {
      chain.anvil.kill()
    }
  }

  console.log(`\n${passed} of ${passed + failed} passed`)
  if (failed) process.exit(1)
}

main()
