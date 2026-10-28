# Feasibility study: Holepunch on the ESP32-C3

Written 2026-10-27, before any code, and kept as the record of why the project is shaped the way it is. Results from each phase are added at the end. Source versions studied: hyperdht 6.34.1, libudx (main), hyperdht-cpp (main as of 2026-10-27).

## 1. Conclusions

| Goal | Feasible? | Notes |
|---|---|---|
| Full Holepunch stack (Bare/Pear + Hypercore/Hyperbee/Autobase) | **No** | V8 cannot run on the C3. Micro QuickJS only supports an ES5 subset, while the npm modules use classes, async/await and streamx throughout. Hypercore also needs persistent storage and Merkle trees |
| Native **HyperDHT subset** on the C3 (connect by public key, holepunching, end-to-end encrypted streams) | **Yes, but memory is tight** | Needs a lean C implementation: 1–2 concurrent connections, ephemeral node, regular holepunching with relay fallback. Estimated 80–120 KB of heap for the application on top of ~200 KB free after WiFi |
| Port the existing hyperdht-cpp to the C3 | **High risk** | Its author estimates 2–3 MB of heap and it requires PSRAM, which the C3 lacks. Its TODO says running on a board was not yet verified. LGPL-3.0 |
| Gateway architecture (C3 talks MQTT/WS/BLE to an S3 or Raspberry Pi that joins Hyperswarm) | **Safest** | Least work, but the C3 itself is not a P2P node |

**Recommendation at the time**: if the device itself must be a Hyperswarm node (reachable by public key), prefer an **ESP32-S3 with 8 MB PSRAM** running hyperdht-cpp. If the hardware has to be the C3, write a lean HyperDHT client in C, starting with a 1–2 week memory PoC before committing.

## 2. The Holepunch stack

```
Pear / Bare (JS runtime, libjs -> V8)               <- not possible on the C3
Hypercore / Hyperbee / Autobase / Corestore         <- not recommended on the C3
Hyperswarm   (topic discovery, connection management, ~1.3k lines of JS)
Protomux     (stream multiplexing, ~0.9k lines of JS)
SecretStream (Noise IK + XChaCha20-Poly1305, ~0.7k lines of JS)
HyperDHT     (announce/lookup/connect/holepunch/relay, ~5.5k lines of JS)
dht-rpc      (Kademlia, NAT sampling, ~3.7k lines of JS)
libudx       (reliable streams over UDP + BBR, ~5.6k lines of C, depends on libuv)
```

Counted locally without tests: the C3 needs libudx plus ~12k lines of JS protocol logic, estimated at ~10k lines of C.

### 2.1 Cryptographic primitives (all from libsodium)

- Ed25519: `crypto_sign_*`, `crypto_scalarmult_ed25519_noclamp` (noise-curve-ed uses Ed25519 for DH)
- BLAKE2b: `crypto_generichash`, used everywhere (node ids, topics, tokens)
- SHA-512: `crypto_hash_sha512`
- XChaCha20-Poly1305 secretstream, ChaCha20-Poly1305 IETF, `crypto_secretbox`

The ESP-IDF component registry has `espressif/libsodium ^1.0.20` (hyperdht-cpp uses it). To check: whether it is built with `SODIUM_LIBRARY_MINIMAL`, which would drop `crypto_scalarmult_ed25519_noclamp`. (It is not; see phase 0.)

The C3's crypto accelerators cover SHA-1/224/256, AES and RSA, which **does not help Ed25519, SHA-512 or BLAKE2b**. All of those run in software.

### 2.2 What libudx needs from libuv

Only `uv_udp_*`, `uv_timer_*`, `uv_prepare/check`, `uv_getaddrinfo` and `uv_interface_addresses`: no files, no thread pool. hyperdht-cpp has a ~2.7k-line libuv shim for ESP32 (lwIP `select()` plus a min-heap of timers) for reference, but it is LGPL.

Porting notes:
- `udx_bbr.c` computes gains with `double`; the C3 is RV32IMC **without an FPU**, so this is soft-float. Acceptable at low rates; fixed point or simpler congestion control are options.
- lwIP has no `IP_MTU_DISCOVER`/`DONTFRAG`, so MTU discovery is off and the 1200-byte base MTU is used.

## 3. ESP32-C3 constraints

| Item | C3 | Impact |
|---|---|---|
| CPU | RV32IMC single core, 160 MHz, no FPU | Ed25519 ops expected at tens of ms each; a Noise handshake needs several DHs, so a few hundred ms. Acceptable |
| SRAM | 400 KB (16 KB of it is cache), **no PSRAM** | The main constraint |
| Flash | Usually 4 MB | A lean implementation plus libsodium is ~1 MB. Fits |
| Radio | 2.4 GHz WiFi 4 + BLE 5 | Enough throughput for IoT |

### 3.1 Memory estimate (lean C implementation, one connection)

libudx struct sizes measured on a 64-bit host: `udx_t` 8.3 KB, `udx_socket_t` 2.7 KB, `udx_stream_t` 1.4 KB, `udx_packet_t` 0.7 KB (smaller on RV32).

| Part | Estimate |
|---|---|
| Routing table (ephemeral, k = 10–20) | 10–20 KB |
| A query in progress (findPeer/announce) | 5–10 KB |
| udx instance + 1–2 sockets | ~10 KB |
| Each UDX stream (send window capped at 16 packets) | 20–40 KB |
| Noise / SecretStream state | < 2 KB |
| DHT task stack (Ed25519 is stack hungry) | 12–16 KB |
| **Total** | **~80–120 KB** |

After WiFi the C3 has roughly 200 KB of free heap (depends on sdkconfig; **must be measured**), so there is room but not much. Fragmentation and lwIP pbuf bursts are the likely trouble spots.

> **Phase 0 measurement (2026-10-28, see `research/phase0/README.md`)**: 215 KB free after WiFi. With one UDX echo stream (256 KB), the lowest free heap was 108.5 KB; libudx itself peaked at 29–62 KB with no leaks. Struct sizes on RV32: `udx_t` 4.2 KB, `udx_socket_t` 2.3 KB, `udx_stream_t` 0.9 KB, `udx_packet_t` 0.3 KB. libudx's `_send_packet` puts an 11.6 KB array on the stack, so the task running the libudx loop needs at least 16 KB of stack. With lwIP's per-socket UDP receive queue raised from 6 to 32, LAN echo reached 313–365 KiB/s at no extra heap; the remaining bottleneck is the CPU (instruction-cache misses running from flash, soft-float).

By comparison, hyperdht-cpp reports "about 2–3 MB" on the S3. It leans on `std::function`, `std::vector`, `std::unordered_map` and `std::string`; squeezing it onto the C3 would mean a rewrite, so writing C directly is the better path.

## 4. Existing implementations

| Project | Language | Status | Relevance to the C3 |
|---|---|---|---|
| [holepunchto/hyperdht](https://github.com/holepunchto/hyperdht) | JS | Official reference, MIT | The protocol authority |
| [holepunchto/libudx](https://github.com/holepunchto/libudx) | C | Official, Apache-2.0 | **Reusable as is** |
| [jjacke13/hyperdht-cpp](https://github.com/jjacke13/hyperdht-cpp) | C++ | Wire compatible with hyperdht@6.29.1, reports ~93% behavioural parity, has an ESP32-S3 example | Needs PSRAM; its TODO lists "ESP32-S3 firmware linking, flashing and an actual board connection" as unverified; **LGPL-3.0**; its `PROTOCOL.md` is a useful spec reference |
| [hyperdht](https://docs.rs/hyperdht/) / [hyperswarm](https://docs.rs/crate/hyperswarm/latest) crates | Rust | 0.1.x, unstable | Could in theory run on the C3 via esp-idf-svc; not mature |
| [holepunchto/libmqjs](https://github.com/holepunchto/libmqjs) | C | libjs on Micro QuickJS | ES5 subset only; the Holepunch JS modules do not run on it |
| [hyperswarm#89](https://github.com/holepunchto/hyperswarm/issues/89) | n/a | Community request for a C implementation for IoT/ESP32 | No official follow-up |

## 5. Proposed scope for the C3

**Keep**
- Bootstrap (`node1-3.hyperdht.org:49737`), ephemeral mode (not a DHT routing node)
- `connect(publicKey)`: findPeer → PEER_HANDSHAKE (Noise IK) → PEER_HOLEPUNCH → UDX stream → SecretStream
- `createServer().listen(keyPair)`: announce, refresh every ~5 min, handle relayed handshakes
- Optional: Protomux, mutable/immutable storage (cheap)

**Cut or simplify**
- Birthday-paradox holepunching: the JS opens 256 sockets, which the C3 cannot. A device behind a random NAT (CGNAT, LTE) talking to a restricted peer will mostly fail, leaving blind-relay as the fallback
- BBR in fixed point or simpler congestion control; MTU probing off; IPv4 only
- No Hypercore replication

## 6. Main risks

1. **Memory**: the biggest unknown; the PoC has to measure peak heap for "WiFi + libsodium + one encrypted stream".
2. **Keeping up with the protocol**: hyperdht moves fast (hyperdht-cpp was 5 minor versions behind), so an independent implementation has to track wire changes.
3. **NAT traversal rate**: an embedded device can open few sockets, so success behind random NATs will be clearly lower than on desktops.
4. **Power**: an always-on server announces and keeps NAT mappings alive, which conflicts with deep sleep. Battery devices fit the on-demand client role.
5. **Licensing**: reusing hyperdht-cpp code (including its libuv shim) means LGPL-3.0, with relinking obligations for closed firmware and "installation information" duties for consumer devices under LGPLv3. libudx, SecretStream and the Noise modules are Apache-2.0 and hyperdht/dht-rpc are MIT, so an independent implementation is unaffected.

## 7. Roadmap and results

**Phase 0: PoC (1–2 weeks)**
- ESP-IDF 5.5 + `espressif/libsodium`: confirm `crypto_scalarmult_ed25519_noclamp` and time Ed25519, BLAKE2b and XChaCha20 on the C3
- Port libudx with a minimal uv shim, echo against `udx-native` on a PC, measure heap
- Pass criterion: more than 60 KB of free heap with WiFi up and one UDX stream running
- **Result (2026-10-28): passed.** At worst 108.5 KB stayed free; all 15 libsodium checks matched the desktop byte for byte

**Phase 1: DHT client (4–6 weeks)**
- compact-encoding, dht-rpc client (ping, find_node, query), HyperDHT findPeer + connect + SecretStream
- Interop with the JS `hyperdht` server
- **Result (2026-10-28): passed on the board** (`components/hdht`, demo in `examples/hyperdht_demo`). On a LAN testnet the board connected by key to a firewalled JS server 9/9 times, ~0.5 s each, always holepunched; ~25 KB peak heap per connection, no leaks

**Phase 2: server and hardening (4–6 weeks)**
- announce/listen, relayed handshakes, holepunch state machine, blind-relay fallback, long-running stability
- **Result (2026-10-28): passed on the board, without blind-relay.** JS clients connecting by key: LAN 5/5, board holepunching as server 10/10, 30-minute run 52/52 (6 re-announces, flat heap)
- **Public HyperDHT: passed.** Bootstrap 3.1 s; board as client 3/3; board as server LAN 5/5 and forced holepunch 5/5 (through the home router's hairpin NAT); no leaks
- **Two real NATs: passed.** Board behind a home router (consistent NAT), peer on a phone hotspot whose carrier NAT is random, so only random-port punching works. Board → JS server 3/3 (12–32 s); JS → board 3/4 once JS's own random-punch rate limit was ruled out (9–20 s), one real failure. Random-port punching is probabilistic in hyperdht as well

**Beyond the plan**
- SecretStream over BLE with the same key pair (`examples/ble_echo`): Noise XX in ~190 ms, ~10 KiB/s each way
- WiFi + HyperDHT + BLE on one C3: works with ~50 KB of heap left; both links ~20–30% slower while busy

**Fallback** (not needed): ESP32-S3 with PSRAM + hyperdht-cpp, or the gateway architecture.
