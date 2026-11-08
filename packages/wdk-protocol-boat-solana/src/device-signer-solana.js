// A BoAT MER device as a Solana signer, its key staying on the device.
//
// The device's Solana key is derived from its DID key (examples/boat_mer,
// main/solana.h). The device signs SPL Token transfers out of its own token
// accounts, within its limit, in transactions whose fee someone else pays. So
// a device holds USD₮ on Solana and no SOL, the way it holds USD₮0 or USDC on
// EVM chains and no gas (EIP-3009).
//
// This is a Solana Kit TransactionPartialSigner: put it on a transfer
// instruction as the authority (deviceTransferInstruction) and the account
// that signs the message, a WDK Solana account as fee payer, gets the
// device's signature along with its own:
//
//   const device = await BoatDeviceSignerSolana.connect({ dht, did, keyPair })
//   const message = await deviceTransferMessage({ device, mint, to, amount, decimals })
//   const { hash } = await wdkSolanaAccount.sendTransaction(message)

import boatPeer from 'boat-peer'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { getAddressDecoder, getAddressEncoder, getProgramDerivedAddress } from '@solana/addresses'
import { AccountRole } from '@solana/instructions'
import { createTransactionMessage, appendTransactionMessageInstruction } from '@solana/transaction-messages'

const { OwnerChannel } = boatPeer

export const TOKEN_PROGRAM_ADDRESS = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
export const ASSOCIATED_TOKEN_PROGRAM_ADDRESS = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL'

const encoder = getAddressEncoder()
const decoder = getAddressDecoder()

// the device's Solana key, from its DID key's 32-byte seed: what the device
// derives (main/solana.c), for tests and for tools that hold a device's seed
export function deriveSolanaKeyPair (didSeed) {
  const seed = b4a.alloc(32)
  sodium.crypto_generichash(seed, b4a.from('boat-solana/1'), didSeed.subarray(0, 32))
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, seed)
  return { publicKey, secretKey, address: decoder.decode(publicKey) }
}

// an owner's associated token account for a mint
export async function associatedTokenAddress (owner, mint) {
  const [pda] = await getProgramDerivedAddress({
    programAddress: ASSOCIATED_TOKEN_PROGRAM_ADDRESS,
    seeds: [encoder.encode(owner), encoder.encode(TOKEN_PROGRAM_ADDRESS), encoder.encode(mint)]
  })
  return pda
}

// Token transferChecked out of the device's associated token account, the
// device signing as its authority
export async function deviceTransferInstruction ({ device, mint, to, amount, decimals }) {
  const data = b4a.alloc(10)
  data[0] = 12 // TransferChecked
  new DataView(data.buffer, data.byteOffset).setBigUint64(1, BigInt(amount), true)
  data[9] = decimals
  return {
    programAddress: TOKEN_PROGRAM_ADDRESS,
    accounts: [
      { address: await associatedTokenAddress(device.address, mint), role: AccountRole.WRITABLE },
      { address: mint, role: AccountRole.READONLY },
      { address: await associatedTokenAddress(to, mint), role: AccountRole.WRITABLE },
      { address: device.address, role: AccountRole.READONLY_SIGNER, signer: device }
    ],
    data: new Uint8Array(data)
  }
}

// a transaction message with that transfer alone; the WDK account that sends
// it adds itself as fee payer and a recent blockhash. `to` is the owner of the
// destination token account, which must exist.
export async function deviceTransferMessage (options) {
  return appendTransactionMessageInstruction(await deviceTransferInstruction(options), createTransactionMessage({ version: 0 }))
}

export default class BoatDeviceSignerSolana {
  // dht: a HyperDHT (or a Hyperswarm's swarm.dht); did: the device's DID;
  // keyPair: the owner's Ed25519 key pair, the one the device trusts
  constructor ({ dht, did, keyPair, timeout = 60000 }) {
    this._channel = new OwnerChannel({ dht, did, keyPair, timeout })
    this.did = this._channel.did
    this.address = null
    this._publicKey = null
  }

  static async connect (options) {
    const signer = new BoatDeviceSignerSolana(options)
    await signer.open()
    return signer
  }

  async open () {
    await this._channel.open()
    const res = await this._channel.request({ op: 'sol_address' })
    if (res.did !== this.did) throw new Error('the device answered with another DID')
    this._publicKey = b4a.from(res.key, 'hex')
    if (this._publicKey.length !== 32) throw new Error('the device sent a bad key')
    this.address = decoder.decode(this._publicKey)
  }

  // TransactionPartialSigner: the device checks and signs each message
  async signTransactions (transactions) {
    const out = []
    for (const tx of transactions) {
      const message = b4a.from(tx.messageBytes)
      const res = await this._channel.request({ op: 'sol_transfer', message: b4a.toString(message, 'base64') })
      const signature = b4a.from(res.signature, 'hex')
      if (signature.length !== 64 || !sodium.crypto_sign_verify_detached(signature, message, this._publicKey)) {
        throw new Error('the device returned a signature by another key')
      }
      out.push(Object.freeze({ [this.address]: new Uint8Array(signature) }))
    }
    return out
  }

  dispose () {
    this._channel.close()
  }
}
