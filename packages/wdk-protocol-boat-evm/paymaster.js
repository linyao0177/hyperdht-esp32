// Gas sponsorship for BoAT settlements: an ERC-7677 paymaster service.
//
// A seller paid to an ERC-4337 smart account (a WDK wdk-wallet-evm-erc-4337
// Safe) settles its devices' EIP-3009 authorizations as user operations. With
// this service an operator pays their gas instead: the seller's account then
// needs no gas at all, in any coin.
//
// On-chain it is eth-infinitism's VerifyingPaymaster for EntryPoint v0.7
// (@account-abstraction/contracts 0.7.0, samples/VerifyingPaymaster.sol),
// deployed with the operator as its verifying signer and funded with a deposit
// at the EntryPoint. Off-chain, this service answers pm_getPaymasterStubData
// and pm_getPaymasterData (ERC-7677), which is what WDK asks for when an
// account is configured with isSponsored and paymasterUrl. It signs a user
// operation only when the sponsorship policy holds:
//
//   - the sender is one of the operator's sellers (`sellers`), and
//   - everything the operation does is settlements of `token`'s
//     transferWithAuthorization paying the sender itself: one call, or a
//     MultiSend batch of them, as WDK's Safe accounts make them, and
//   - its maximum gas cost is within `maxCost` (wei), when set.
//
// So the operator's deposit only ever pays for sellers collecting what devices
// paid them. Node only (ethers).
//
//   const sponsor = createSponsor({ operator, paymaster, chainId, token, sellers })
//   const server = await sponsor.listen(4338)  // paymasterUrl: http://host:4338

import http from 'http'
import { AbiCoder, Wallet, keccak256, getBytes, hexlify, concat, toBeHex, zeroPadValue, dataSlice } from 'ethers'

export const ENTRY_POINT_V07 = '0x0000000071727De22E5E9d8BAf0edAc6f37da032'
// the MultiSend that WDK's Safe accounts (abstractionkit) batch through
export const SAFE_MULTISEND = '0x38869bf66a61cF6bDB996A6aE40D5853Fd43B526'

const EXECUTE_USER_OP = '0x7bb37428' // executeUserOp(address,uint256,bytes,uint8), Safe4337Module
const EXECUTE_USER_OP_WITH_ERROR_STRING = '0x541d63c8'
const MULTI_SEND = '0x8d80ff0a' // multiSend(bytes)
const TRANSFER_WITH_AUTHORIZATION = '0xe3ee160e'

const abi = AbiCoder.defaultAbiCoder()
const STUB_SIGNATURE = Wallet.createRandom().signingKey.sign(keccak256('0x00')).serialized
const lower = (a) => String(a).toLowerCase()
const big = (v) => BigInt(v ?? 0)

class PolicyError extends Error {}

// the settlements a Safe user operation makes, or a PolicyError
export function settlementsOf (callData, { token, sender, multiSend = SAFE_MULTISEND }) {
  const selector = dataSlice(callData, 0, 4)
  if (selector !== EXECUTE_USER_OP && selector !== EXECUTE_USER_OP_WITH_ERROR_STRING) throw new PolicyError('not a Safe 4337 execution')
  const [to, value, data, operation] = abi.decode(['address', 'uint256', 'bytes', 'uint8'], dataSlice(callData, 4))
  let calls
  if (Number(operation) === 1) {
    if (lower(to) !== lower(multiSend) || dataSlice(data, 0, 4) !== MULTI_SEND) throw new PolicyError('delegate call to something other than MultiSend')
    calls = unpackMultiSend(abi.decode(['bytes'], dataSlice(data, 4))[0])
  } else {
    calls = [{ operation: Number(operation), to, value, data }]
  }
  if (calls.length === 0) throw new PolicyError('no calls')
  return calls.map((c) => {
    if (c.operation !== 0 || lower(c.to) !== lower(token) || c.value !== 0n || dataSlice(c.data, 0, 4) !== TRANSFER_WITH_AUTHORIZATION) {
      throw new PolicyError('a call that is not a settlement of the token')
    }
    const [from, payee, amount] = abi.decode(['address', 'address', 'uint256'], dataSlice(c.data, 4, 100))
    if (lower(payee) !== lower(sender)) throw new PolicyError('a settlement paying someone other than the sender')
    return { from, to: payee, value: amount }
  })
}

function unpackMultiSend (packed) {
  const b = getBytes(packed)
  const calls = []
  for (let i = 0; i < b.length;) {
    if (i + 85 > b.length) throw new PolicyError('truncated MultiSend')
    const operation = b[i]
    const to = hexlify(b.subarray(i + 1, i + 21))
    const value = BigInt(hexlify(b.subarray(i + 21, i + 53)))
    const len = Number(BigInt(hexlify(b.subarray(i + 53, i + 85))))
    if (i + 85 + len > b.length) throw new PolicyError('truncated MultiSend')
    calls.push({ operation, to, value, data: hexlify(b.subarray(i + 85, i + 85 + len)) })
    i += 85 + len
  }
  return calls
}

// VerifyingPaymaster.getHash (v0.7), for an unpacked user operation as ERC-7677 sends it
export function paymasterHash (op, { paymaster, chainId, validUntil, validAfter }) {
  const initCode = op.factory ? concat([op.factory, op.factoryData || '0x']) : '0x'
  const pack = (hi, lo) => zeroPadValue(toBeHex((big(hi) << 128n) | big(lo)), 32)
  return keccak256(abi.encode(
    ['address', 'uint256', 'bytes32', 'bytes32', 'bytes32', 'uint256', 'uint256', 'bytes32', 'uint256', 'address', 'uint48', 'uint48'],
    [
      op.sender, big(op.nonce), keccak256(initCode), keccak256(op.callData),
      pack(op.verificationGasLimit, op.callGasLimit),
      (big(op.paymasterVerificationGasLimit) << 128n) | big(op.paymasterPostOpGasLimit),
      big(op.preVerificationGas),
      pack(op.maxPriorityFeePerGas, op.maxFeePerGas),
      BigInt(chainId), paymaster, validUntil, validAfter
    ]
  ))
}

// operator: the WDK EVM account that is the paymaster's verifying signer;
// paymaster: the VerifyingPaymaster's address; sellers: the smart accounts it
// sponsors (addresses), or a function (address) => boolean
export function createSponsor ({ operator, paymaster, chainId, token, sellers, maxCost = null, validFor = 600, verificationGas = 60000n, postOpGas = 1n, entryPoint = ENTRY_POINT_V07, multiSend = SAFE_MULTISEND }) {
  const wallet = new Wallet(hexlify(operator.keyPair.privateKey))
  const isSeller = typeof sellers === 'function' ? sellers : ((list) => (a) => list.has(lower(a)))(new Set(sellers.map(lower)))
  const stats = { sponsored: 0, refused: 0 }

  function check (op, ep, chain) {
    if (lower(ep) !== lower(entryPoint)) throw new PolicyError('another EntryPoint')
    if (BigInt(chain) !== BigInt(chainId)) throw new PolicyError('another chain')
    if (!isSeller(op.sender)) throw new PolicyError('the sender is not a sponsored seller')
    return settlementsOf(op.callData, { token, sender: op.sender, multiSend })
  }

  const paymasterData = (validUntil, validAfter, signature) => concat([abi.encode(['uint48', 'uint48'], [validUntil, validAfter]), signature])
  const fields = (data) => ({ paymaster, paymasterData: data, paymasterVerificationGasLimit: toBeHex(verificationGas), paymasterPostOpGasLimit: toBeHex(postOpGas) })

  async function handle (method, params) {
    const [op, ep, chain] = params
    if (method === 'pm_getPaymasterStubData') {
      check(op, ep, chain)
      // a well-formed signature by another key, for estimation: it fails the
      // signer check (a validation failure the bundler ignores while
      // estimating) where a malformed one would revert
      return { ...fields(paymasterData(0, 0, STUB_SIGNATURE)), isFinal: false }
    }
    if (method === 'pm_getPaymasterData') {
      const settlements = check(op, ep, chain)
      if (maxCost !== null) {
        const gas = big(op.preVerificationGas) + big(op.verificationGasLimit) + big(op.callGasLimit) + big(op.paymasterVerificationGasLimit ?? verificationGas) + big(op.paymasterPostOpGasLimit ?? postOpGas)
        if (gas * big(op.maxFeePerGas) > BigInt(maxCost)) throw new PolicyError('over the gas cost limit')
      }
      const validAfter = 0
      const validUntil = Math.floor(Date.now() / 1000) + validFor
      const hash = paymasterHash({ ...op, paymasterVerificationGasLimit: op.paymasterVerificationGasLimit ?? verificationGas, paymasterPostOpGasLimit: op.paymasterPostOpGasLimit ?? postOpGas }, { paymaster, chainId, validUntil, validAfter })
      const signature = await wallet.signMessage(getBytes(hash))
      stats.sponsored++
      stats.last = { sender: op.sender, settlements: settlements.length }
      return { paymaster, paymasterData: paymasterData(validUntil, validAfter, signature) }
    }
    throw Object.assign(new Error('method not found: ' + method), { code: -32601 })
  }

  function listen (port, host = '127.0.0.1') {
    const server = http.createServer((req, res) => {
      let body = ''
      req.on('data', (d) => { body += d })
      req.on('end', async () => {
        let id = null
        let reply
        try {
          const msg = JSON.parse(body)
          id = msg.id
          reply = { jsonrpc: '2.0', id, result: await handle(msg.method, msg.params || []) }
        } catch (err) {
          if (err instanceof PolicyError) stats.refused++
          reply = { jsonrpc: '2.0', id, error: { code: err.code || (err instanceof PolicyError ? -32602 : -32603), message: err instanceof PolicyError ? 'not sponsored: ' + err.message : err.message } }
        }
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify(reply))
      })
    })
    return new Promise((resolve) => server.listen(port, host, () => resolve(server)))
  }

  return { handle, listen, stats, signer: wallet.address }
}
