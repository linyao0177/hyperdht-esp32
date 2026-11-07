// Makes test/vectors.json with ethers, the reference the tests check
// lib/eth.js against (the tests themselves run without ethers, in Bare too).
//
// usage: node test/gen-vectors.js

const fs = require('fs')
const path = require('path')
const { Wallet, keccak256, toUtf8Bytes } = require('ethers')

const domain = { name: 'GatewayWalletBatched', version: '1', chainId: 5042002, verifyingContract: '0x0077777d7EBA4688BDeF3E311b846F25870A19B9' }
const types = {
  TransferWithAuthorization: [
    { name: 'from', type: 'address' },
    { name: 'to', type: 'address' },
    { name: 'value', type: 'uint256' },
    { name: 'validAfter', type: 'uint256' },
    { name: 'validBefore', type: 'uint256' },
    { name: 'nonce', type: 'bytes32' }
  ]
}

async function main () {
  const out = { domain, messages: [], transfers: [] }
  for (let i = 1; i <= 4; i++) {
    const key = keccak256(toUtf8Bytes('boat-peer test key ' + i))
    const w = new Wallet(key)
    const message = 'did:mw:' + keccak256(toUtf8Bytes('did ' + i)).slice(2)
    out.messages.push({ key, address: w.address, message, sig: await w.signMessage(message) })
    const t = {
      from: w.address,
      to: new Wallet(keccak256(toUtf8Bytes('payee ' + i))).address,
      value: String(i * 12345),
      validAfter: 0,
      validBefore: 1800000000 + i,
      nonce: keccak256(toUtf8Bytes('nonce ' + i))
    }
    out.transfers.push({ key, transfer: t, sig: await w.signTypedData(domain, types, t) })
  }
  fs.writeFileSync(path.join(__dirname, 'vectors.json'), JSON.stringify(out, null, 2) + '\n')
  console.log('wrote test/vectors.json')
}

main()
