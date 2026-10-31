# Running an open anchor node

An anchor node does for devices what a HashAnchor server does: it takes signed data hashes, batches them into Merkle trees, anchors each root on chain and returns receipts that anyone can verify offline. Anyone can run one. Nodes need no permission from anyone: the contract lets any wallet anchor, devices find nodes on the DHT, and each node is paid per hash by the devices it serves.

This is a public testnet. Payments are verified but not yet settled, so running a node today costs a little testnet gas and earns nothing. See [What is not done yet](#what-is-not-done-yet).

## The network

| | Arc testnet |
|---|---|
| Contract | [`OpenAnchor`](../tools/host/contracts/OpenAnchor.sol) at [`0xd7d651a6fecE5C9ed96796678ED995Fb12dAbeCA`](https://explorer.testnet.arc.io/address/0xd7d651a6fecE5C9ed96796678ED995Fb12dAbeCA) |
| Chain id | 5042002 |
| RPC | `https://rpc.testnet.arc.network` |
| Gas | USDC, from the [Circle faucet](https://faucet.circle.com) (pick Arc Testnet) |
| Explorer | `https://explorer.testnet.arc.io` |
| Discovery topic | `BLAKE2b-256("open-anchor/1 5042002 <contract, lowercase>")` on the public HyperDHT |
| Running node | `did:mw:e8f0b35d17b6e4126591da9dd03a81f112421ffd71600ee6e692522da455693a`, on a cloud VM since 2026-10-31 ([results](../examples/boat_mer/README.md#results-a-node-on-a-cloud-vm-2026-10-31-same-board)); more operators are needed |

The contract has no owner, no operator role and no upgrade path. The first anchor of a root is kept, with the wallet that anchored it and the block time.

The explorer shows the verified source (solc 0.8.28, optimizer off), so anyone can check the contract against [`OpenAnchor.sol`](../tools/host/contracts/OpenAnchor.sol). It was verified on 2026-10-29 with:

```bash
forge verify-contract --chain-id 5042002 --verifier blockscout --verifier-url https://explorer.testnet.arc.io/api/ --compiler-version 0.8.28 0xd7d651a6fecE5C9ed96796678ED995Fb12dAbeCA src/OpenAnchor.sol:OpenAnchor
```

## What a node does

1. It listens on the HyperDHT under its own key. Its DID is `did:mw:<that key>`.
2. It publishes a DID record under that key, with its wallet, fee, contract and the key of its batch log. It announces itself under the deployment's topic, so devices find it without being configured. Both are refreshed while it runs.
3. For each submission, it checks:
   - the device's Ed25519 signature of the hash;
   - that the EIP-3009 payment is signed by the wallet in the device's own DID record;
   - the payee and the amount;
   - that the payment nonce is new.
4. Every `--batch` seconds, it builds a keccak256 sorted-pair Merkle tree over `keccak256(hash ‖ device key ‖ signature)` leaves. This is the format HashAnchor's `verifyReceiptProof` accepts. It anchors the root from its own wallet. If another node already anchored the same root, it reuses that transaction instead.
5. It appends the batch, with every leaf, to a Hypercore that anyone can replicate. It also sends each device its receipt.

## Run one

You need Node.js 20 or newer and outbound UDP. No open ports or public IP are needed.

```bash
git clone https://github.com/linyao0177/hyperdht-esp32.git && cd hyperdht-esp32/tools/host && npm ci
```

```bash
node anchor-node.js public
```

The first run creates `~/.open-anchor/node`. It holds:
- `identity.key`, the node's HyperDHT seed and so its DID;
- `wallet.key`, its wallet;
- `log/`, its batch log.

The key files are mode 0600 and never leave the machine. Back them up: losing `identity.key` loses the node's DID, and losing `log/` loses the batches only this node holds.

The node prints its wallet and warns when the balance is zero. On Ctrl-C or SIGTERM, it anchors what it has accepted, lets the last receipts reach the devices, and unannounces itself before exiting. Fund that address from the faucet. The node keeps accepting submissions and anchors them once it has gas. One anchor costs about 0.001 USDC of testnet gas, whatever the batch size.

Options:

| Option | Default | |
|---|---|---|
| `--store <dir>` | `~/.open-anchor/node` | identity, wallet and log; use one directory per node |
| `--batch <s>` | 20 | seconds between batches |
| `--fee <n>` | 10 | micro-USDC per hash; devices refuse fees above their limit (100 on the example board) |
| `--network <name>` | `arc-testnet` | `local` for an anvil chain |
| `--contract <addr>`, `--rpc <url>` | from the network | another deployment or RPC |

Behind an HTTP proxy, set `HTTPS_PROXY`; the chain RPC goes through it. The DHT is UDP and does not.

To keep it running on a server, use [`deploy/`](../deploy):
- `docker compose -f deploy/docker-compose.yml up -d --build` runs it next to a public relay node ([relay-node.md](relay-node.md)), with its keys and log in a volume;
- `deploy/systemd/open-anchor-node.service` runs it as a systemd service.

The first start prints the wallet to fund. Back up the volume or `~/.open-anchor`.

## Check that devices can find you

```bash
node anchor-discover.js public
```

It lists every node announced on the topic and checks each one's DID record the way a device does: the record must be signed, and must be an `anchor/1` record for this chain and contract. Your node should be listed as `ok` within a minute of starting.

## Verify a node's work

Anyone can check what a node did for a device. All they need is the two DIDs:

```bash
node anchor-verify.js public did:mw:<node> did:mw:<device>
```

The verifier:
- replicates the node's log;
- checks each of the device's leaves: device signature, leaf, tree root, HashAnchor's own `verifyReceiptProof`;
- reads the contract to confirm that the root is anchored by the wallet the log names.

It needs the node, or a mirror of its log, to be online.

## Devices

A device built from [`examples/boat_mer`](../examples/boat_mer) with `CONFIG_MER_ANCHOR_CONTRACT` set does the following:
- looks up the topic, resolves each node's record, and keeps up to three nodes;
- sends every signed reading to all of them, each with its own payment;
- checks every receipt's Merkle proof;
- logs receipts that do not arrive within 120 s.

It drops a discovered node that has no valid record for the deployment, or that fails to connect three times, and looks again.

## Trust

- **Devices** do not trust nodes. They pay only the wallet named in a node's signed record, check every proof, and use several nodes, so one node cannot censor a reading.
- **Nodes** do not trust devices. A submission must be signed by the device's key and paid from the wallet in the device's signed record.
- **Nobody needs to trust the DHT.** Lookup replies are hints. Records are signed, and streams are authenticated by key.
- **What only the chain shows**: whether a root is really anchored. A device has no chain access, so a receipt it holds is only proven once someone checks the chain with `anchor-verify.js`.

## What is not done yet

- **Settlement.** Nodes verify payments but do not collect them. Settlement through Circle Gateway's batched transfers is next.
- **Mirrors.** A node's log is served only while the node runs. Independent mirrors that keep replicating logs are needed, so that receipts outlive nodes.
- **Node-signed receipts.** HashAnchor receipts have an optional `signature` field. Nodes do not fill it yet, so a receipt shown to a third party carries no statement from the node.
- **Mainnet.** The contract is on testnet only, and nobody has audited it.
