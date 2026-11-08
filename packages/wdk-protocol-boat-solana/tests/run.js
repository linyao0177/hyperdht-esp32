// Tests for wdk-protocol-boat-solana: node tests/run.js
//
// The device is emulated on a local HyperDHT testnet, its policy and signing
// done by the device's own C code (examples/boat_mer/main/solana.c, built for
// the desktop as test/sol_host.c). The chain is a local solana-test-validator
// with a 6-decimal SPL token standing in for USD₮, and the fee payer a WDK
// Solana account. Needs clang, libsodium and the Solana CLI (spl-token);
// without them only the offline checks run.

import { spawn, execFileSync } from 'child_process'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { fileURLToPath } from 'url'
import crypto from 'crypto'
import HyperDHT from 'hyperdht'
import createTestnet from 'hyperdht/testnet.js'
import WalletManagerSolana from '@tetherto/wdk-wallet-solana'
import { AccountRole } from '@solana/instructions'
import { createTransactionMessage, appendTransactionMessageInstruction, setTransactionMessageFeePayer, setTransactionMessageLifetimeUsingBlockhash } from '@solana/transaction-messages'
import { compileTransaction } from '@solana/transactions'
import BoatDeviceSignerSolana, { deriveSolanaKeyPair, associatedTokenAddress, deviceTransferInstruction, deviceTransferMessage } from '../index.js'

const here = path.dirname(fileURLToPath(import.meta.url))
const MER = path.join(here, '..', '..', '..', 'examples', 'boat_mer')
const MNEMONIC = 'test test test test test test test test test test test junk'
const RPC_PORT = 18899
const LIMIT = 5000000n // the device signs at most 5 tokens per transaction

let passed = 0
let failed = 0
function check (name, ok, detail = '') {
  if (ok) passed++
  else failed++
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? '  ' + detail : ''}`)
}

const has = (cmd, args = ['--version']) => {
  try {
    execFileSync(cmd, args, { stdio: 'ignore' })
    return true
  } catch {
    return false
  }
}

function buildHost () {
  const out = path.join(os.tmpdir(), 'boat-sol-host')
  const sodium = ['/opt/homebrew', '/usr/local', '/usr'].find((p) => fs.existsSync(path.join(p, 'include', 'sodium.h')))
  if (!sodium || !has('clang')) return null
  execFileSync('clang', ['-O1', '-I' + path.join(MER, 'main'), '-I' + path.join(sodium, 'include'), path.join(MER, 'test', 'sol_host.c'), path.join(MER, 'main', 'solana.c'), '-L' + path.join(sodium, 'lib'), '-lsodium', '-o', out])
  return out
}

// the device: serves its owner channel (examples/boat_mer/main/signer.c) with sol_host
function emulateDevice (dht, { host, didKeyPair, owner, mint }) {
  const seedHex = didKeyPair.secretKey.subarray(0, 32).toString('hex')
  const [keyHex] = execFileSync(host, ['key', seedHex], { encoding: 'utf8' }).trim().split(' ')
  const did = 'did:mw:' + didKeyPair.publicKey.toString('hex')
  const server = dht.createServer((conn) => {
    conn.on('error', () => {})
    if (!conn.remotePublicKey.equals(owner)) {
      conn.write(Buffer.from(JSON.stringify({ payload: '{"uptime_s":1}', sig: '00' })))
      return
    }
    conn.on('data', (data) => {
      const req = JSON.parse(data.toString())
      let res
      if (req.op === 'sol_address') {
        res = { id: req.id, ok: true, key: keyHex, did }
      } else if (req.op === 'sol_transfer') {
        let out
        try {
          out = execFileSync(host, ['sign', seedHex, mint, String(LIMIT), req.message], { encoding: 'utf8' })
        } catch (err) {
          out = err.stdout
        }
        const [verdict, ...rest] = out.trim().split(' ')
        res = verdict === 'OK' ? { id: req.id, ok: true, signature: rest[1] } : { id: req.id, ok: false, error: rest.join(' ') }
      } else {
        res = { id: req.id, ok: false, error: 'unsupported op' }
      }
      conn.write(Buffer.from(JSON.stringify(res)))
    })
  })
  return server.listen(didKeyPair).then(() => ({ server, did, keyHex }))
}

const sh = (cmd, args) => execFileSync(cmd, args, { encoding: 'utf8' }).trim()

async function main () {
  // offline: the key derivation is the device's
  const host = buildHost()
  const didKeyPair = HyperDHT.keyPair(crypto.randomBytes(32))
  const derived = deriveSolanaKeyPair(didKeyPair.secretKey)
  if (host) {
    const [hex, b58] = sh(host, ['key', didKeyPair.secretKey.subarray(0, 32).toString('hex')]).split(' ')
    check('the Solana key derived in JS is the device\'s (C)', hex === derived.publicKey.toString('hex') && b58 === derived.address, derived.address)
  } else {
    console.log('SKIP device checks: clang or libsodium not found')
  }
  check('the Solana key is not the DID key', !derived.publicKey.equals(didKeyPair.publicKey))

  if (!host || !has('solana-test-validator') || !has('spl-token')) {
    console.log('SKIP chain: Solana CLI not found')
    return finish()
  }

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'boat-sol-'))
  const url = `http://127.0.0.1:${RPC_PORT}`
  const validator = spawn('solana-test-validator', ['--reset', '--quiet', '--ledger', path.join(tmp, 'ledger'), '--rpc-port', String(RPC_PORT), '--faucet-port', String(RPC_PORT + 2), '--gossip-port', String(RPC_PORT + 4), '--dynamic-port-range', `${RPC_PORT + 10}-${RPC_PORT + 40}`], {
    stdio: 'ignore',
    env: { ...process.env, COPYFILE_DISABLE: '1' } // macOS tar adds ._ files the validator's genesis unpacking refuses
  })
  const testnet = await createTestnet(3)
  const nodes = []
  try {
    for (let i = 0; i < 120; i++) {
      if (validator.exitCode !== null) throw new Error('solana-test-validator exited')
      try {
        const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getHealth' }) })
        if ((await r.json()).result === 'ok') break
      } catch {}
      await new Promise((resolve) => setTimeout(resolve, 500))
    }
    const payerFile = path.join(tmp, 'payer.json')
    sh('solana-keygen', ['new', '--no-bip39-passphrase', '--silent', '--force', '-o', payerFile])
    const cli = (...args) => sh('spl-token', [...args, '--url', url, '--fee-payer', payerFile, '--output', 'json-compact'])
    sh('solana', ['airdrop', '10', '--url', url, '--keypair', payerFile])
    const mint = JSON.parse(cli('create-token', '--decimals', '6', '--mint-authority', payerFile)).commandOutput.address
    const otherMint = JSON.parse(cli('create-token', '--decimals', '6', '--mint-authority', payerFile)).commandOutput.address

    const wallet = new WalletManagerSolana(MNEMONIC, { provider: url, commitment: 'confirmed' })
    const account = await wallet.getAccount(0)
    const ownerAddress = await account.getAddress()
    sh('solana', ['airdrop', '1', ownerAddress, '--url', url, '--keypair', payerFile])

    const device = derived.address
    cli('create-account', mint, '--owner', device)
    cli('create-account', mint, '--owner', ownerAddress)
    cli('create-account', otherMint, '--owner', device)
    cli('create-account', otherMint, '--owner', ownerAddress)
    cli('mint', mint, '10', await associatedTokenAddress(device, mint), '--mint-authority', payerFile)
    cli('mint', otherMint, '10', await associatedTokenAddress(device, otherMint), '--mint-authority', payerFile)
    const tokens = async (owner, m = mint) => BigInt(JSON.parse(cli('balance', m, '--owner', owner)).amount)
    check('the device holds 10 test USD₮ and no SOL', (await tokens(device)) === 10000000n && sh('solana', ['balance', device, '--url', url, '--lamports']).startsWith('0 '))

    // the device on HyperDHT, its owner's app connecting to it
    const ownerKey = HyperDHT.keyPair()
    const deviceNode = testnet.createNode()
    const appNode = testnet.createNode()
    nodes.push(deviceNode, appNode)
    const { did } = await emulateDevice(deviceNode, { host, didKeyPair, owner: ownerKey.publicKey, mint })
    const signer = await BoatDeviceSignerSolana.connect({ dht: appNode, did, keyPair: ownerKey })
    check('the owner connects to the device as a Solana signer', signer.address === device, signer.address)

    const before = await tokens(ownerAddress)
    const t0 = Date.now()
    const { hash, fee } = await account.sendTransaction(await deviceTransferMessage({ device: signer, mint, to: ownerAddress, amount: 1500000n, decimals: 6 }))
    const r = await account.waitForTransaction(hash)
    check('the device signs a USD₮ transfer, the WDK account pays the fee', r.success === true && (await tokens(ownerAddress)) - before === 1500000n && (await tokens(device)) === 8500000n, `${hash.slice(0, 12)}..., fee ${fee} lamports paid by the WDK account, ${Date.now() - t0} ms`)
    check('the device still has no SOL', sh('solana', ['balance', device, '--url', url, '--lamports']).startsWith('0 '))

    const refused = async (message) => {
      try {
        await account.sendTransaction(message)
        return null
      } catch (err) {
        return err.message
      }
    }
    let why = await refused(await deviceTransferMessage({ device: signer, mint, to: ownerAddress, amount: LIMIT + 1n, decimals: 6 }))
    check('the device refuses an amount over its limit', /over the device limit/.test(why), why)
    why = await refused(await deviceTransferMessage({ device: signer, mint: otherMint, to: ownerAddress, amount: 1n, decimals: 6 }))
    check('the device refuses another mint', /another mint/.test(why), why)

    const transfer = await deviceTransferInstruction({ device: signer, mint, to: ownerAddress, amount: 1n, decimals: 6 })
    const memo = { programAddress: 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr', accounts: [{ address: signer.address, role: AccountRole.READONLY_SIGNER, signer }], data: new Uint8Array(Buffer.from('hi')) }
    why = await refused(appendTransactionMessageInstruction(memo, appendTransactionMessageInstruction(transfer, createTransactionMessage({ version: 0 }))))
    check('the device refuses an instruction of another program', /another program/.test(why), why)

    const signDirect = async (message) => {
      try {
        await signer.signTransactions([compileTransaction(message)])
        return null
      } catch (err) {
        return err.message
      }
    }
    const blockhash = { blockhash: '4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY', lastValidBlockHeight: 1000n }
    const asFeePayer = setTransactionMessageLifetimeUsingBlockhash(blockhash, setTransactionMessageFeePayer(signer.address, appendTransactionMessageInstruction(transfer, createTransactionMessage({ version: 0 }))))
    why = await signDirect(asFeePayer)
    check('the device refuses to pay the fee', /would pay the fee/.test(why), why)
    const writable = { ...transfer, accounts: transfer.accounts.map((a, i) => i === 3 ? { ...a, role: AccountRole.WRITABLE_SIGNER } : a) }
    why = await signDirect(setTransactionMessageLifetimeUsingBlockhash(blockhash, setTransactionMessageFeePayer(ownerAddress, appendTransactionMessageInstruction(writable, createTransactionMessage({ version: 0 })))))
    check('the device refuses to be a writable account', /would be writable/.test(why), why)
    const legacy = setTransactionMessageLifetimeUsingBlockhash(blockhash, setTransactionMessageFeePayer(ownerAddress, appendTransactionMessageInstruction(transfer, createTransactionMessage({ version: 'legacy' }))))
    why = await signDirect(legacy)
    check('a legacy message is signed too', why === null, why)

    const strangerFails = await BoatDeviceSignerSolana.connect({ dht: appNode, did, keyPair: HyperDHT.keyPair(), timeout: 20000 }).then(() => null, (err) => err.message)
    check('another key cannot use the device as a signer', /does not accept this key/.test(strangerFails), strangerFails)

    signer.dispose()
    wallet.dispose()
  } finally {
    for (const n of nodes) await n.destroy()
    await testnet.destroy()
    validator.kill()
  }
  finish()
}

function finish () {
  console.log(`\n${passed} of ${passed + failed} passed`)
  if (failed) process.exit(1)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
