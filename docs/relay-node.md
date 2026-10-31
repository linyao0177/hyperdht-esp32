# Running a public relay node

Two peers that cannot holepunch each other can meet at a blind-relay node. This happens when one side is behind a random (symmetric) NAT, which is common on 4G routers and some corporate networks. The relay forwards the UDX packets of their SecretStream. It never has the keys, so it cannot read or change what they send. It can only drop it.

[`tools/host/relay-node.js`](../tools/host/relay-node.js) is such a node, made for running in public. Devices find relay nodes on the DHT, so anyone can add one, and no device has a relay's key built in.

## How devices find relays

- A relay node announces itself under the relay topic, `BLAKE2b-256("hdht-relay/1")`, every 10 minutes. It also publishes a record under its key: `{"v":1,"did","svc":"relay/1","max_sessions"}`.
- A device calls `hdht_relay_find` (in the UART module, `AT+RELAY=AUTO`). It looks up the topic and probes the nodes it finds, in random order, until one works.
  - A probe connects to the node and opens the `blind-relay` channel. It succeeds when the node opens the channel too.
  - The connection must run over the device's main socket, because that is the only socket a relayed stream can use.
  - Each probe has an 8 s limit. Nodes that are gone or that do not answer are skipped.
- The device then uses that relay for every connection (`hdht_set_relay`).
- In auto mode, the module looks for another relay when a relayed connect fails with -107. It also probes its relay every 10 minutes. Inbound connections cannot report a failed pairing, so the periodic probe is what catches a dead relay for them.

Anyone can announce under the topic, so the topic is only a list of hints, as all lookups are. A node that says it is a relay but is not one can make a device try another relay. It cannot read the device's traffic or pose as its peers, because both ends authenticate each other by key.

## Requirements

- A public IPv4 address with UDP open, in and out. A cloud VM is enough. The node checks this at start.
  - If the DHT finds it firewalled, it still serves by key but does not announce, because devices outside its network could not use it.
  - `--force` announces anyway. It is meant for tests where the devices share the node's LAN.
- Node.js 20 or newer.
- Bandwidth: a relayed connection costs about twice its own traffic. Sensor data is small, but set `--max-sessions` to what the link can carry.

## Run one

```bash
git clone https://github.com/linyao0177/hyperdht-esp32.git && cd hyperdht-esp32/tools/host && npm ci
```

```bash
node relay-node.js public
```

```
RELAY[node]|listening did:mw:5dfe... on 203.0.113.7:49737 reachable
RELAY[node]|record published, announced on b32e3f5195b6ef50... max_sessions=256
RELAY[node]|stats sessions=3 accepted=41 pairings_matched=12 pending=0 active=2 streams=4 refused=0
```

The first run creates `~/.hdht-relay/node/identity.key` (mode 0600), the node's key and so its DID. The node logs its stats every minute. On Ctrl-C or SIGTERM, it unannounces itself and ends its sessions.

| Option | Default | |
|---|---|---|
| `--store <dir>` | `~/.hdht-relay/node` | identity; use one directory per node |
| `--max-sessions <n>` | 256 | connections from peers at once; more are refused |
| `--force` | off | announce even when firewalled (LAN tests) |

To keep it running, use [`deploy/`](../deploy):
- `docker compose -f deploy/docker-compose.yml up -d --build` runs a relay node and an anchor node, with host networking and their keys in volumes (Linux).
- Or `deploy/systemd/hdht-relay.service` and `open-anchor-node.service` run them as systemd services.

## Check the relays

```bash
node relay-node.js public --list
```

It looks up the topic and probes every node the way a device does:

```
LIST|2 relay(s) announced on b32e3f5195b6ef50...
LIST|did:mw:5dfead7ad7dd0715... relay/1 ok direct=true 180 ms
LIST|did:mw:2012cb90ca60e8e5... no relay record FAILED timeout 15004 ms
```

## Trust and abuse

- **Privacy**: the relay sees which two keys pair, when, and how many bytes they send. It does not see content. A device that must hide who it talks to should not use a public relay.
- **Availability**: a relay can drop traffic. Devices move to another relay when connects through it fail, and when the periodic probe fails.
- **Abuse of the operator**: anyone can use a public relay's bandwidth. `--max-sessions` caps the sessions. There is no payment or rate limit per key yet.

## Results (2026-10-29)

| | Result |
|---|---|
| Desktop, local testnet | `test_connect` with `HDHT_RELAY=find` found the relay node and connected through it in 5 of 5 runs. The topic also listed a key with no node behind it and a node that accepts connections but never answers. The device skipped both: the dead key at once, the silent node after 8 s |
| ESP32-C3, public HyperDHT | `AT+RELAY=AUTO` found a relay node on the module's LAN in 8.8 s, and links ran through it. Killing that node without unannouncing made the next connect fail with -107. The module then found a second node by itself, and the next connect went through it (`tools/module_test.py`, 54 of 54) |
| `--list` | Showed the working node as `ok direct=true` and both broken ones as `FAILED` |
| ESP32-C3, relay on a cloud VM (2026-10-31) | A node on a Google Cloud e2-small in Taiwan found itself reachable and announced without `--force`. `AT+RELAY=AUTO` on the board found it in 4.5 s. Two of three connects from the board to a peer on the same LAN ran through it (the peer saw the VM's address); the first failed with -101, as first connects to a fresh server sometimes do. In a `tools/module_test.py` run (54 of 54), the module moved to this node by itself when the test's own relay node died |

Not tested: a device behind a real random NAT or 4G. In every run, the two peers could also have reached each other directly.

## What is not done yet

- **More public nodes.** One relay node runs on a cloud VM, set up with `deploy/systemd`. Devices need more than one operator's nodes before relaying stops depending on a single machine.
- **Choosing by distance or load.** Devices pick a working relay at random. They do not measure latency or read the node's load.
- **Moving to a direct path.** A relayed connection stays relayed, as everywhere in hdht.
- **Paying relays.** Unlike anchor nodes, relay nodes earn nothing.
