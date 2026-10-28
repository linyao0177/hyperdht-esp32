# HyperDHT wire protocol notes (for the C port)

Read from the JS sources installed in `poc/host/node_modules`:
hyperdht 6.35.0, dht-rpc 6.28.0, noise-handshake 4.2.0, noise-curve-ed 2.1.0,
compact-encoding 3.5.2, @hyperswarm/secret-stream 6.9.2. Line refs are to those versions.

## compact-encoding primitives

| type | encoding |
|---|---|
| `uint` | varint: `n <= 0xfc` → 1 byte; else `0xfd`+u16, `0xfe`+u32, `0xff`+u64 (all little-endian) |
| `uint8/16/24/32` | fixed little-endian |
| `bool` | 1 byte, decoded as `== 1` |
| `buffer` | `uint` length + bytes (decode of length 0 gives an empty buffer) |
| `fixed32` / `fixed64` | raw bytes |
| `array(T)` | `uint` count + items (decode rejects > 0x100000) |
| `ipv4Address` | 4 bytes IP in dotted order + `uint16` LE port (6 bytes) |
| `string` | `uint` byte length + utf8 |

## dht-rpc

### Node id

`id(host, port) = BLAKE2b-256(ipv4Address(host, port))` (6 input bytes, unkeyed, `crypto_generichash`).
A reply/request only carries an id if the sender is persistent; the receiver validates it against
the sender's observed address and ignores it on mismatch (`validateId`).

### Datagram format (lib/io.js)

Byte 0: `0x03` request, `0x13` response (version `0b11`, type in high nibble).

Request:
```
u8   0x03
u8   flags   1=id 2=token 4=internal 8=target 16=value   (decoded as uint)
u16  tid
ipv4Address to          // the address the sender sent to (lets the receiver learn its public addr)
[fixed32 id]            // sender's node id (persistent nodes only)
[fixed32 token]
uint command
[fixed32 target]
[buffer value]
```

Response:
```
u8   0x13
u8   flags   1=id 2=token 4=closerNodes 8=error 16=value
u16  tid
ipv4Address to          // requester's address as seen by the responder → NAT sampling
[fixed32 id]
[fixed32 token]         // round-trip token for the requester's address
[array(ipv4Address) closerNodes]
[uint error]
[buffer value]
```

Errors: `UNKNOWN_COMMAND = 1`, `INVALID_TOKEN = 2` (lib/errors.js).

Internal commands (flag 4): `PING 0, PING_NAT 1, FIND_NODE 2, DOWN_HINT 3, DELAYED_PING 4`.
User (HyperDHT) commands are sent without the internal flag.

Tokens: `BLAKE2b-256(host string as utf8, key = secret)`, two rotating secrets; a request with a token
is rejected with INVALID_TOKEN unless it matches. Tokens are only needed for commit-style requests
(announce/unannounce/mutable put), obtained from the reply of the query that found the node.

### Requests, timeouts

- tid: 16-bit counter starting at a random value.
- Retries: default `retries = 3` per request (queries use 5), timeout 1000 ms per send (adaptive optional).
  Destroyed with REQUEST_TIMEOUT after `sent > retries`.
- Congestion window: max 80 sends per 750 ms slot, 4 slots.

### Ephemeral / firewalled client behaviour (what the C3 is)

- Starts `ephemeral = true`, `firewalled = true`: requests carry no id, sent from the "client" socket.
- Replies to internal requests: PING → empty reply; FIND_NODE → reply with closer nodes (from table);
  PING_NAT → reply to the port given in the 2-byte value; DOWN_HINT → reply. Unknown → UNKNOWN_COMMAND.
- Only nodes that present a valid id are added to the routing table (k = 20 per bucket).
- Own public address: NatSampler over the `to` field of replies (consensus over up to 16 samples;
  returns host+port, host with port 0 = "randomized" NAT, or null).
- Bootstrap: background FIND_NODE query for a random/own id seeded from the bootstrap nodes.
  Default HyperDHT bootstrap list is in hyperdht/lib/constants.js.

### Query (lib/query.js)

Iterative Kademlia lookup towards `target` (32 bytes), `k = 20`, concurrency 10 (background 2).
- Seed: table.closest(target, k), else bootstrap nodes.
- Each reply: if no error and the sender has an id and is closer than the current k-th → insert into
  `closestReplies` (sorted by XOR distance to target, max k). Add `closerNodes` (id derived from address)
  to pending if closer.
- Done when nothing pending and nothing inflight. Optional commit phase: for each of the closest replies,
  send `{token: reply.token, target, command, value}` directly to that node.
- Each reply (including errors) is emitted to the caller; HyperDHT inspects `value` per reply.

## HyperDHT constants (lib/constants.js)

Commands (non-internal): `PEER_HANDSHAKE 0, PEER_HOLEPUNCH 1, FIND_PEER 2, LOOKUP 3, ANNOUNCE 4,
UNANNOUNCE 5, MUTABLE_PUT 6, MUTABLE_GET 7, IMMUTABLE_PUT 8, IMMUTABLE_GET 9, PLUGIN 10`.

FIREWALL: `UNKNOWN 0, OPEN 1, CONSISTENT 2, RANDOM 3`. ERROR: `NONE 0, ABORTED 1, VERSION_MISMATCH 2,
TRY_LATER 3, SEQ_REUSED 16, SEQ_TOO_LOW 17`.

Bootstrap: `node1.hyperdht.org:49737` (88.99.3.86), `node2...` (142.93.90.113), `node3...` (138.68.147.8).

Namespaces: `namespace(name, ids)[i] = BLAKE2b-256(BLAKE2b-256(name) || u8 id)`. Precomputed:

| name | hex |
|---|---|
| NS_ANNOUNCE (4) | 36386adddf9f6fd60db83a6f42fc159d1146aa8644037664230aaa1f0179d497 |
| NS_UNANNOUNCE (5) | ded293cd93fb395e756ecf5fff426529e72c36eacc22e5ed944d9099a2561e32 |
| NS_MUTABLE_PUT (6) | 668e823edd5ce7f5338d68bf1161f4a3c28ce437ee2ab49efd30d99366039b1e |
| NS_PEER_HANDSHAKE (0) | 14d6d4b49214ab1033ed204976caa258bae9e1e8543b9ad1fd996a910b0c4e3a |
| NS_PEER_HOLEPUNCH (1) | f1191cd5e67b10b54a507033280ed1ff0e12278268d5679c8f93d417210d168b |
| secret-stream INITIATOR (0) | a931a0155b5c09e6d28628236af83c4b8a6af9af60986edeede9dc5d63192bf7 |
| secret-stream RESPONDER (1) | 742c9d833d430af4c48a8705e91631eecf295442bbca18996e597097723b1061 |
| secret-stream SEND (2) | aab97d097471f56651b0460ffc8aaa7d3342f7377597d60b925a1dac689adcbf |

Key pair: Ed25519 (`crypto_sign_seed_keypair`). Peer target = `BLAKE2b-256(publicKey)`.

## HyperDHT messages (lib/messages.js)

`ipv4` = compact `ipv4Address` (6 bytes). All `uint` are compact varints.

- **handshake** (PEER_HANDSHAKE value): `uint flags (1=peerAddress 2=relayAddress), uint mode,
  buffer noise, [ipv4 peerAddress], [ipv4 relayAddress]`.
  mode: `FROM_CLIENT 0, FROM_SERVER 1, FROM_RELAY 2, FROM_SECOND_RELAY 3, REPLY 4`.
- **holepunch** (PEER_HOLEPUNCH value): `uint flags (1=peerAddress), uint mode, uint id, buffer payload,
  [ipv4 peerAddress]`.
- **noisePayload** (inside Noise messages): `uint version(=1), uint flags, uint error, uint firewall`,
  then by flag: 1 `holepunch{uint id, array(relayInfo{ipv4 relayAddress, ipv4 peerAddress})}`,
  2 `array(ipv4) addresses4`, 4 `array(ipv6) addresses6`, 8 `udx{uint version=1, uint features(1=reusableSocket),
  uint id, uint seq}`, 16 `secretStream{uint version=1}`, 32 `relayThrough{uint 1, uint 0, fixed32 publicKey,
  fixed32 token}`, 64 `array(ipv4) relayAddresses`. Version != 1 → stop decoding.
- **holepunchPayload** (encrypted): `uint flags (1=connected 2=punching 4=addresses 8=remoteAddress 16=token
  32=remoteToken), uint error, uint firewall, uint round, [array(ipv4) addresses], [ipv4 remoteAddress],
  [fixed32 token], [fixed32 remoteToken]`.
  Encryption (lib/secure-payload.js): `nonce(24) || crypto_secretbox_easy(MAC16||ct)` with key
  `holepunchSecret`. `token(addr) = BLAKE2b-256(host utf8, key = random localSecret)`.
- **peer**: `fixed32 publicKey, array(ipv4) relayAddresses`. FIND_PEER reply value = peer.
- **lookupRawReply**: `array(peer) peers, [uint bump]`.
- **announce**: `uint flags (1=peer 2=refresh 4=signature 8=bump), [peer], [fixed32 refresh],
  [fixed64 signature], [uint bump]`.

## Noise IK (noise-handshake 4.2.0 + noise-curve-ed 2.1.0, lib/noise-wrap.js)

- Protocol name `Noise_IK_Ed25519_ChaChaPoly_BLAKE2b` (35 bytes). HASHLEN = **64** (BLAKE2b-512 everywhere:
  `h` and `ck` are 64 bytes). `h = name zero-padded to 64`, `ck = h`.
- Prologue: `mixHash(NS_PEER_HANDSHAKE)`. Pre-message: `mixHash(responder static pk)`.
- `mixHash(d)`: `h = BLAKE2b-512(h || d)`.
- HMAC: BLAKE2b-512, block 128 (key zero-padded, ipad 0x36, opad 0x5c).
  HKDF(ck, ikm) → `prk = HMAC(ck, ikm)`, `T1 = HMAC(prk, 0x01)`, `T2 = HMAC(prk, T1 || 0x02)` (info empty).
- `mixKey(dh)`: `ck = T1`, cipher key = `T2[0..32]`, nonce = 0.
- Cipher: ChaCha20-Poly1305 IETF, 12-byte nonce = `00000000 || u32le(counter) || 00000000`, AD = h (64 bytes).
  `encryptAndHash`: encrypt only once a key is set; then `mixHash(ciphertext)`.
- DH (noise-curve-ed): local scalar = clamp(SHA-512(seed)[0..32]); `crypto_scalarmult_ed25519_noclamp(scalar,
  remote Ed25519 pk)`. Ephemeral keys are fresh Ed25519 keypairs.
- IK msg1 (initiator→responder): `e.pk(32) || enc(s.pk)(48) || enc(payload)(+16)` with tokens e, es, s, ss.
  msg2: `e.pk(32) || enc(payload)(+16)` with tokens e, ee, se.
- Split: `HKDF(ck, empty)` → `k1, k2` (first 32 bytes each). Initiator tx = k1, rx = k2.
  Handshake hash = final `h` (64 bytes).
- After handshake (noise-wrap.final): `holepunchSecret = BLAKE2b-256(NS_PEER_HOLEPUNCH, key = h)`.

## SecretStream (@hyperswarm/secret-stream 6.9.2)

- Framing: `u24le length || message`.
- First message each way (56 bytes): `streamId(32) || secretstream header(24)`.
  `streamId = BLAKE2b-256(NS_INITIATOR or NS_RESPONDER, key = h)` (own role). Receiver checks the remote's id.
  Push key = tx[0..32], pull key = rx[0..32] (libsodium `crypto_secretstream_xchacha20poly1305`, TAG_MESSAGE, no AD).
- Data message: secretstream ciphertext (plain + 17). Zero-length plaintexts are keepalives (HyperDHT default
  `connectionKeepAlive = 5000` ms), filtered by the receiver when keepalive is enabled.
- Unordered UDX messages (`send`/`message`): optional, not needed.

## Client connect (lib/connect.js)

1. `target = BLAKE2b-256(serverPublicKey)`. `findPeer` = query(target, FIND_PEER, no value), map replies whose
   value decodes as `peer`. Up to 2 parallel `connectThroughNode` attempts; tries twice if relay addresses known.
2. `connectThroughNode(node)`: Noise msg1 with payload `{error 0, firewall (OPEN if we have a stable public
   server address else UNKNOWN), addresses4 [our public addr if known + LAN addrs], udx {reusableSocket,
   id = our raw stream id, seq 0}, secretStream {}}`. Sent as PEER_HANDSHAKE request (target, handshake{mode
   FROM_CLIENT, noise}) to the node. Reply value: handshake{mode REPLY, noise, peerAddress?}. Must come from the
   same node. `relayed = !!peerAddress`, `serverAddress = peerAddress || node`, `clientAddress = res.to`.
3. Decode Noise msg2 → server payload (version 1, error 0, must have udx). `final()` → keys, holepunchSecret.
4. If not relayed (we talked to the server directly) → connect UDX stream to the node address on the DHT socket.
   If the server is `OPEN` (or relayed and not holepunchable) → connect to first non-bogon `addresses4` or
   serverAddress on the DHT socket.
5. Else holepunch (needs `payload.holepunch.relays`): new socket ("puncher"), NAT sample with 4 PINGs from that
   socket, pick `serverRelay` (same relay as ours if listed). Probe round: `openSession(serverAddress)` (1-byte
   `0x00` UDP with TTL 5), PEER_HOLEPUNCH via serverRelay.relayAddress with `{id: payload.holepunch.id,
   payload: encrypted holepunchPayload{firewall, round, addresses = our sampled, remoteAddress = serverAddress},
   peerAddress: serverRelay.peerAddress}` sent **from the puncher socket**. Reply payload decrypted →
   remote firewall/addresses/token. Then punch round with `punching: true, token = payload.token(serverAddress),
   remoteToken`. Then probes: consistent/consistent → send `0x00` to remote addresses every 1 s (10 tries);
   we consistent + remote random → 1750 probes to random ports every 20 ms. The first 1-byte message received
   on the puncher socket wins → connect UDX stream on that socket to that address.
6. UDX: our stream id = random u32; remote id = `payload.udx.id`. SecretStream started with the Noise result
   as handshake (no in-band Noise).

## Relaying (lib/router.js)

A DHT node relays by re-encoding a **request** with the same tid/command/target (no token, no id) and sending
it to another address (`req.relay(value, to)`), so the eventual reply to the client reuses the client's tid.

PEER_HANDSHAKE at a node that holds a record for target (relay = address the server announced from):
- `FROM_CLIENT` → relay to `relay` as `FROM_RELAY` with `peerAddress = client addr`.
- At the server, `FROM_RELAY` → server sends `FROM_SERVER{noise reply, peerAddress}` as a request back to the
  relay node (from the puncher socket when it will holepunch), the node replies to `peerAddress` (the client)
  with `REPLY{noise, peerAddress = address the server's message came from}`.
- A server reached directly (`FROM_CLIENT` at the server) replies `REPLY{noise}` with no peerAddress.
- A node with no record replies with closer nodes only (empty value).

PEER_HOLEPUNCH: client → node `FROM_CLIENT{id, payload, peerAddress = server addr as seen by that node}`,
node relays `FROM_RELAY{peerAddress = client}` to peerAddress, server answers with a `FROM_SERVER{id 0, payload,
peerAddress}` request to the node (from its puncher socket), node replies `REPLY{payload, peerAddress = server
puncher addr}` to the client.

## Server (lib/server.js, lib/announcer.js, lib/persistent.js)

- `target = BLAKE2b-256(publicKey)`. Register a router entry for target so PEER_HANDSHAKE/PEER_HOLEPUNCH with
  that target are handled locally.
- Announcer: `findPeer(target)` query; for the best 3 closest replies (persistent nodes with token + id),
  send ANNOUNCE `{token, target, value = announce{peer{publicKey, relayAddresses: []}, signature}}`.
  Signature: Ed25519 over `NS_ANNOUNCE(32) || BLAKE2b-256(target || node.id || token || encode(peer) || refresh?)`
  (`crypto_generichash_batch`, refresh omitted when null). UNANNOUNCE likewise with NS_UNANNOUNCE.
  The node stores `relay = req.from` (our address as it saw it) and a record = encode(peer).
- Keep-alive: ping the announced relay nodes every 3 s; re-announce every ~5 min (100 cycles) or if fewer than
  min(3, n) pings succeed. Node-side records expire after 20 min.
- `relays = [{relayAddress: node, peerAddress: our address as seen by node (reply.to)}]`,
  `relayAddresses = up to 3 node addresses`.
- On PEER_HANDSHAKE for our target: Noise responder (`recv` msg1, `send` msg2) with payload
  `{error, firewall: OPEN if we have a public server address else UNKNOWN, holepunch: {id = slot index,
  relays} (only when not OPEN), addresses4: [public addr?, LAN addrs], udx {id = new raw stream id}, secretStream {},
  relayAddresses}`. error = NONE if client payload v1 with udx, else ABORTED / VERSION_MISMATCH.
  If the client is OPEN or we were reached directly → connect the stream to the client address now.
  Else create a puncher (new socket, NAT sampling) and reply from the puncher socket. Handshake state is kept
  10 s (`HANDSHAKE_INITIAL_TIMEOUT`); duplicate msg1 (same noise bytes) maps to the same state.
- On PEER_HOLEPUNCH `{id, payload, peerAddress}`: decrypt with holepunchSecret, update remote state when
  `round >= h.round`, wait for NAT analysis, fast-mode ping if `remoteAddress` matches our sampled address,
  if remote `punching` → start punching; reply `{error, firewall, round, connected, punching, addresses =
  our sampled, token: payload.token(peerAddress) if from one of our relays, remoteToken: their token}`.
- Responder side of the puncher answers every received `0x00` probe with a probe back; the stream is connected
  when the first UDX packet arrives (raw stream firewall hook) on any socket → `connect(socket, remote udx id,
  port, host)` and start SecretStream as responder.
