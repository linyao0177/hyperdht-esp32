// ERC-4337 tests for wdk-protocol-boat-evm: node tests/aa.js
//
// A WDK smart account (@tetherto/wdk-wallet-evm-erc-4337, a Safe with the
// 4337 module) as the seller's payee and settler. Needs Foundry and the
// network: it forks the Stable testnet (chain 2201), which has EntryPoint
// v0.7, the Safe 4337 modules and the real USD₮0, and runs a local bundler
// (Pimlico's alto) against the fork.
//
// On the fork the account pays gas in native coin, set with anvil. On the
// real Stable chain the native coin is USD₮0 itself, so the account pays its
// gas from the USD₮0 it is paid.

import { spawn, execFileSync } from 'child_process'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { fileURLToPath } from 'url'
import crypto from 'crypto'
import WDK from '@tetherto/wdk'
import WalletManagerEvmErc4337 from '@tetherto/wdk-wallet-evm-erc-4337'
import WalletManagerEvm from '@tetherto/wdk-wallet-evm'
import { JsonRpcProvider, HDNodeWallet } from 'ethers'
import boatPeer from 'boat-peer'
import BoatProtocolEvm, { registerBoat } from '../index.js'
import { createSponsor, paymasterHash } from '../paymaster.js'

const { eth, verifyRecord, payeeOf } = boatPeer
const here = path.dirname(fileURLToPath(import.meta.url))
const MNEMONIC = 'test test test test test test test test test test test junk'
const FORK = process.env.STABLE_RPC || 'https://rpc.testnet.stable.xyz'
const ANVIL_PORT = 8548
const BUNDLER_PORT = 4337
const PAYMASTER_PORT = 4338
const ENTRY_POINT = '0x0000000071727De22E5E9d8BAf0edAc6f37da032'
const TOKEN = '0x78Cf24370174180738C5B8E352B6D14c83a6c9A9' // USD₮0 on the Stable testnet
const HOLDER = '0x93354845030274cd4bf1686abd60ab28ec52e1a7' // a USD₮0 holder there, impersonated to fund the buyer
const cfg = { token: TOKEN, chainId: 2201, tokenName: 'USD₮0', tokenVersion: '1' }
const key = (i) => HDNodeWallet.fromPhrase(MNEMONIC, undefined, `m/44'/60'/0'/0/${i}`).privateKey

let passed = 0
let failed = 0
function check (name, ok, detail = '') {
  if (ok) passed++
  else failed++
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? '  ' + detail : ''}`)
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

async function waitFor (fn, what) {
  for (let i = 0; i < 100; i++) {
    try {
      if (await fn()) return
    } catch {}
    await sleep(300)
  }
  throw new Error(what + ' did not start')
}

// eth-infinitism's VerifyingPaymaster (v0.7), compiled from node_modules
function deployPaymaster (url, deployerKey, signer) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'boat-paymaster-'))
  const modules = path.join(here, '..', 'node_modules')
  fs.cpSync(path.join(modules, '@account-abstraction', 'contracts'), path.join(root, 'src', 'aa'), { recursive: true })
  fs.writeFileSync(path.join(root, 'remappings.txt'), `@openzeppelin/=${path.join(modules, '@openzeppelin')}/\n`)
  const out = execFileSync('forge', ['create', 'src/aa/samples/VerifyingPaymaster.sol:VerifyingPaymaster', '--root', root, '--rpc-url', url, '--private-key', deployerKey, '--broadcast', '--constructor-args', ENTRY_POINT, signer], { encoding: 'utf8' })
  return out.match(/Deployed to: (0x[0-9a-fA-F]{40})/)[1]
}

async function main () {
  try {
    execFileSync('anvil', ['--version'], { stdio: 'ignore' })
  } catch {
    console.log('SKIP: anvil not found')
    return
  }
  const url = `http://127.0.0.1:${ANVIL_PORT}`
  const bundlerUrl = `http://127.0.0.1:${BUNDLER_PORT}`
  const anvil = spawn('anvil', ['--fork-url', FORK, '--port', String(ANVIL_PORT), '--silent', '--mnemonic', MNEMONIC], { stdio: 'ignore' })
  let alto = null
  const provider = new JsonRpcProvider(url, undefined, { staticNetwork: true })
  try {
    await waitFor(async () => anvil.exitCode === null && (await provider.send('eth_chainId', [])) === '0x899', 'the Stable fork')
    alto = spawn(path.join(here, '..', 'node_modules', '.bin', 'alto'), [
      '--entrypoints', ENTRY_POINT, '--rpc-url', url, '--port', String(BUNDLER_PORT),
      '--executor-private-keys', key(8), '--utility-private-key', key(9), '--safe-mode', 'false'
    ], { stdio: 'ignore' })
    await waitFor(async () => {
      const res = await fetch(bundlerUrl, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_supportedEntryPoints', params: [] }) })
      return (await res.json()).result?.[0]?.toLowerCase() === ENTRY_POINT.toLowerCase()
    }, 'the bundler')

    const wdk = new WDK(MNEMONIC).registerWallet('stable', WalletManagerEvmErc4337, {
      chainId: 2201, provider: url, bundlerUrl, safeModulesVersion: '0.3.0', useNativeCoins: true
    })
    registerBoat(wdk, 'stable', cfg)
    const account = await wdk.getAccount('stable', 0)
    const safe = await account.getAddress()
    const boat = await BoatProtocolEvm.create(account, cfg)
    check('the protocol takes a WDK ERC-4337 account', boat.isSmartAccount && boat.address === safe && account.getBoatProtocol().address === safe, `Safe ${safe}`)

    // gas for the Safe (its first user operation deploys it)
    await provider.send('anvil_setBalance', [safe, '0x' + (10n ** 20n).toString(16)])

    // a buyer with USD₮0, standing in for a device
    const buyerKey = crypto.randomBytes(32)
    const buyer = eth.addressOf(buyerKey)
    await provider.send('anvil_impersonateAccount', [HOLDER])
    const fund = '0xa9059cbb' + buyer.slice(2).toLowerCase().padStart(64, '0') + (10n ** 6n).toString(16).padStart(64, '0')
    await provider.waitForTransaction(await provider.send('eth_sendTransaction', [{ from: HOLDER, to: TOKEN, data: fund }]))
    const auth = (value = '1000') => {
      const a = { from: buyer, to: safe, value, validAfter: 0, validBefore: Math.floor(Date.now() / 1000) + 3600, nonce: '0x' + crypto.randomBytes(32).toString('hex') }
      return { ...a, signature: eth.signTransfer(boat.domain, a, buyerKey) }
    }
    const balance = async (a) => BigInt(await provider.call({ to: TOKEN, data: '0x70a08231' + a.slice(2).toLowerCase().padStart(64, '0') }))

    const pk = crypto.randomBytes(32)
    const record = await boat.didRecord(pk)
    const owner = HDNodeWallet.fromPhrase(MNEMONIC, undefined, "m/44'/60'/0'/0/0").address
    check('its DID record pays the Safe, vouched for by the owner key', verifyRecord(pk, Buffer.from(JSON.stringify(record))) !== null && payeeOf(record) === safe && record.eth === owner, `eth ${record.eth}, pay ${record.pay}`)
    check('its seller bills devices to the Safe', boat.seller({ power: () => 0 }).payee === safe)

    let before = await balance(safe)
    const one = auth()
    const t0 = Date.now()
    const { hash } = await boat.settle(one)
    const r1 = await boat.waitForSettlement(hash)
    check('a settlement goes out as a user operation (and deploys the Safe)', r1.ok && (await balance(safe)) - before === 1000n && await boat.isSettled(buyer, one.nonce), `${r1.gasUsed} gas, bundle tx ${r1.tx.slice(0, 10)}..., ${Date.now() - t0} ms`)

    const t1 = Date.now()
    const second = auth()
    const r2 = await boat.waitForSettlement((await boat.settle(second)).hash)
    check('a settlement from the deployed Safe', r2.ok && await boat.isSettled(buyer, second.nonce), `${r2.gasUsed} gas, fee ${r2.fee} wei, ${Date.now() - t1} ms`)

    before = await balance(safe)
    const five = Array.from({ length: 5 }, () => auth())
    const batch = await boat.settleBatch(five)
    const rb = await boat.waitForBatch(batch)
    check('5 authorizations in one user operation', rb.ok && rb.settled.length === 5 && (await balance(safe)) - before === 5000n, `${rb.gasUsed} gas, ${rb.gasUsed / 5n} each against ${r2.gasUsed} alone`)

    const mixed = await boat.settleBatch([auth(), five[0], { ...auth(), value: '7' }])
    const rm = await boat.waitForBatch(mixed)
    check('a batch leaves out used and bad authorizations', rm.ok && rm.settled.length === 1 && mixed.skipped.length === 2, mixed.skipped.map((s) => s.reason).join(' | '))

    let other = null
    try {
      await boat.settle({ ...auth(), to: buyer })
    } catch (err) {
      other = err.message
    }
    check('an authorization paying someone else is refused', other && /does not pay this account/.test(other))

    // gas sponsorship: an operator's paymaster pays a seller's settlements
    const operator = await new WalletManagerEvm(MNEMONIC, { provider: url }).getAccount(3)
    const paymaster = deployPaymaster(url, key(3), operator.address)
    const depositOf = async () => BigInt(await provider.call({ to: ENTRY_POINT, data: '0x70a08231' + paymaster.slice(2).toLowerCase().padStart(64, '0') }))
    await operator.sendTransaction({ to: paymaster, data: '0xd0e30db0', value: 10n ** 19n }) // deposit()
    await sleep(1500)
    const depositBefore = await depositOf()
    check('the operator deploys a VerifyingPaymaster and funds it', depositBefore === 10n ** 19n, paymaster)

    const sponsoredCfg = { chainId: 2201, provider: url, bundlerUrl, safeModulesVersion: '0.3.0', isSponsored: true, paymasterUrl: `http://127.0.0.1:${PAYMASTER_PORT}` }
    const seller2 = await new WalletManagerEvmErc4337(MNEMONIC, sponsoredCfg).getAccount(1)
    const safe2 = await seller2.getAddress()
    const stranger = await new WalletManagerEvmErc4337(MNEMONIC, sponsoredCfg).getAccount(2)
    const sponsor = createSponsor({ operator, paymaster, chainId: 2201, token: TOKEN, sellers: [safe2] })
    const server = await sponsor.listen(PAYMASTER_PORT)
    try {
      const boat2 = await BoatProtocolEvm.create(seller2, cfg)
      const auth2 = (value = '1000') => {
        const a = { from: buyer, to: safe2, value, validAfter: 0, validBefore: Math.floor(Date.now() / 1000) + 3600, nonce: '0x' + crypto.randomBytes(32).toString('hex') }
        return { ...a, signature: eth.signTransfer(boat2.domain, a, buyerKey) }
      }
      const gasBefore = await provider.getBalance(safe2)
      const t2 = Date.now()
      const s1 = await boat2.waitForSettlement((await boat2.settle(auth2())).hash)
      check('a seller with no gas settles, sponsored (and its Safe deployed)', s1.ok && gasBefore === 0n && (await provider.getBalance(safe2)) === 0n && (await balance(safe2)) === 1000n, `${s1.gasUsed} gas, ${Date.now() - t2} ms`)
      const b2 = await boat2.waitForBatch(await boat2.settleBatch([auth2(), auth2(), auth2()]))
      const spent = depositBefore - await depositOf()
      check('a sponsored batch, paid from the operator\'s deposit', b2.ok && b2.settled.length === 3 && (await provider.getBalance(safe2)) === 0n && spent > 0n, `deposit spent ${spent} wei over ${sponsor.stats.sponsored} operations`)

      let notSettlement = null
      try {
        await seller2.sendTransaction({ to: TOKEN, data: '0xa9059cbb' + buyer.slice(2).toLowerCase().padStart(64, '0') + '1'.padStart(64, '0'), value: 0n })
      } catch (err) {
        notSettlement = String(err.message + ' ' + (err.cause?.message || '') + ' ' + (err.cause?.cause?.message || ''))
      }
      check('the operator does not sponsor anything else (a token transfer out)', notSettlement && /not sponsored: a call that is not a settlement/.test(notSettlement), (notSettlement || '').match(/not sponsored: [^.,"]*/)?.[0])

      let notSeller = null
      try {
        const boat3 = await BoatProtocolEvm.create(stranger, cfg)
        const a = { from: buyer, to: boat3.address, value: '1', validAfter: 0, validBefore: Math.floor(Date.now() / 1000) + 3600, nonce: '0x' + crypto.randomBytes(32).toString('hex') }
        await boat3.settle({ ...a, signature: eth.signTransfer(boat3.domain, a, buyerKey) })
      } catch (err) {
        notSeller = String(err.message + ' ' + (err.cause?.message || '') + ' ' + (err.cause?.cause?.message || ''))
      }
      check('nor a Safe that is not one of its sellers', notSeller && /not sponsored: the sender is not a sponsored seller/.test(notSeller), (notSeller || '').match(/not sponsored: [^.,"]*/)?.[0])

      // the service's hash is the contract's
      const op = { sender: safe2, nonce: '0x5', factory: null, callData: '0x1234', callGasLimit: '0x10', verificationGasLimit: '0x20', preVerificationGas: '0x30', maxFeePerGas: '0x40', maxPriorityFeePerGas: '0x50', paymasterVerificationGasLimit: '0x60', paymasterPostOpGasLimit: '0x70' }
      const packed = [safe2, 5n, '0x', '0x1234', '0x' + (0x20n << 128n | 0x10n).toString(16).padStart(64, '0'), 0x30n, '0x' + (0x50n << 128n | 0x40n).toString(16).padStart(64, '0'), paymaster + (0x60n).toString(16).padStart(32, '0') + (0x70n).toString(16).padStart(32, '0') + '00'.repeat(64), '0x']
      const { Interface } = await import('ethers')
      const pm = new Interface(['function getHash((address sender,uint256 nonce,bytes initCode,bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,bytes paymasterAndData,bytes signature) userOp, uint48 validUntil, uint48 validAfter) view returns (bytes32)'])
      const onChain = pm.decodeFunctionResult('getHash', await provider.call({ to: paymaster, data: pm.encodeFunctionData('getHash', [packed, 1234, 5]) }))[0]
      check("the service's paymaster hash is the contract's getHash", onChain === paymasterHash(op, { paymaster, chainId: 2201, validUntil: 1234, validAfter: 5 }))
    } finally {
      server.close()
    }
    wdk.dispose()
  } finally {
    if (alto) alto.kill()
    anvil.kill()
  }
  console.log(`\n${passed} of ${passed + failed} passed`)
  if (failed) process.exit(1)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
