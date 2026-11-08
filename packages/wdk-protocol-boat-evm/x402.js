// An x402 FacilitatorEvmSigner (@x402/evm) backed by a WDK account, so an x402
// facilitator verifies and settles with WDK. Node.js only: it uses ethers for
// ABI encoding, which is why it is not part of the main module (Bare apps
// bundle that one).
//
//   import { x402FacilitatorSigner } from 'wdk-protocol-boat-evm/x402'
//   registerExactEvmScheme(facilitator, { signer: await x402FacilitatorSigner(account) })

import { Interface, verifyTypedData } from 'ethers'

const strip = (hex) => String(hex).replace(/^0x/, '').toLowerCase()

export async function x402FacilitatorSigner (account) {
  const provider = (await account.toReadOnlyAccount())._provider
  // x402 names functions without their signature; tokens such as USDC
  // overload transferWithAuthorization (v, r, s or a bytes signature), so
  // pick the overload by argument count
  const fn = (iface, name, args) => {
    const all = iface.fragments.filter((f) => f.type === 'function' && f.name === name)
    return all.find((f) => f.inputs.length === args.length) || all[0]
  }
  // one transaction at a time, retried when the provider hands out a nonce
  // the previous settlement already used (ethers caches identical calls briefly)
  let queue = Promise.resolve()
  const send = (tx) => {
    const run = async () => {
      for (let attempt = 0; ; attempt++) {
        try {
          return (await account.sendTransaction(tx)).hash
        } catch (err) {
          if ((err.code !== 'NONCE_EXPIRED' && !/nonce too low/i.test(err.message)) || attempt >= 4) throw err
          await new Promise((resolve) => setTimeout(resolve, 500))
        }
      }
    }
    const result = queue.then(run, run)
    queue = result.catch(() => {})
    return result
  }
  return {
    getAddresses: () => [account.address],
    async readContract ({ address, abi, functionName, args = [] }) {
      const iface = new Interface(abi)
      const f = fn(iface, functionName, args)
      const out = await provider.call({ to: address, data: iface.encodeFunctionData(f, args) })
      const decoded = iface.decodeFunctionResult(f, out)
      return decoded.length === 1 ? decoded[0] : decoded
    },
    async verifyTypedData ({ address, domain, types, message, signature }) {
      const { EIP712Domain, ...rest } = types
      return verifyTypedData(domain, rest, message, signature).toLowerCase() === address.toLowerCase()
    },
    async writeContract ({ address, abi, functionName, args, dataSuffix }) {
      const iface = new Interface(abi)
      const data = iface.encodeFunctionData(fn(iface, functionName, args), args) + (dataSuffix ? strip(dataSuffix) : '')
      return send({ to: address, data, value: 0n })
    },
    async sendTransaction ({ to, data }) {
      return send({ to, data, value: 0n })
    },
    async waitForTransactionReceipt ({ hash, timeout = 120000 }) {
      const r = await provider.waitForTransaction(hash, 1, timeout)
      return { status: r.status === 1 ? 'success' : 'reverted', logs: r.logs }
    },
    async getCode ({ address }) {
      const code = await provider.getCode(address)
      return code === '0x' ? undefined : code
    }
  }
}
