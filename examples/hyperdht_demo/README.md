# hyperdht_demo: connect by key, then serve

The test firmware used to validate `hdht` on the board. One boot runs both phases:
1. **Client**: join the DHT, connect to a server by public key `HDHT_CONNECT_ROUNDS` times, and check the echo.
2. **Server**: announce a key pair (seed = 32 × `HDHT_SERVER_SEED_BYTE`), then echo every connection for `HDHT_SERVE_SECONDS`.

With `HDHT_BLE=1`, the device also runs the BLE link (`components/hdht_ble`) with the same key pair. Results are printed as `HDHT|...` lines, for scripts to parse. For a clean starting point for your own app, see `../minimal`.

The fixed seeds keep keys predictable for the test scripts. **Never use fixed seeds in a product.**

## Running

WiFi credentials come from the repo root's `sdkconfig.wifi` (copy `sdkconfig.wifi.example`). Settings are under `idf.py menuconfig` → "hdht demo". `HDHT_BOOTSTRAP` is empty by default, which means the public HyperDHT.

To test against a private testnet on your computer (`<LAN IP>` is that computer's address):

1. Install the Node tools once:

   ```bash
   cd ../../tools/host && npm install
   ```

2. Start a 10-node testnet with a firewalled JS echo server (the client-phase target):

   ```bash
   node ../../tools/host/testnet.js --host <LAN IP> --server --firewalled
   ```

3. Set `HDHT_BOOTSTRAP` to `<LAN IP>:49800`, then build, flash and capture:

   ```bash
   idf.py build flash && python ../../tools/capture.py <port> 400
   ```

4. Once the board prints `HDHT|listening`, connect to it from JS. In `punchfw` mode the JS node is truly firewalled, so the board has to holepunch as a server:

   ```bash
   node ../../tools/host/connect-board.js <LAN IP>:49800 10 0x33 2000 punchfw
   ```

For the public DHT, leave `HDHT_BOOTSTRAP` empty and use `testnet.js --public --server` and `connect-board.js public ...`.

## Measured results (2026-10-28, ESP32-C3 rev v0.4, 2.4G WiFi, LAN testnet of 10 hyperdht 6.35.0 nodes)

### Phase 1: board → JS server

| Item | Result |
|---|---|
| Bootstrap (FIND_NODE, 9 nodes in the table) | 218–358 ms |
| `connect()` to a firewalled JS server, open | 519–612 ms, 9/9 OK (3 boots × 3), always over a holepunched socket |
| Heap during one connect | ~25 KB peak (190 KB → 165 KB free) |
| Heap after each connect | Back to the same value (±50 B) |

### Phase 2: JS clients → board

| Item | Result |
|---|---|
| Announce (FIND_PEER + 3 signed ANNOUNCEs), until `listening` | 228–241 ms |
| 5 connections, LAN shortcut | 5/5 OK, open 366–485 ms (one at 4.4 s) |
| 10 connections, JS client firewalled → board holepunches as server | 10/10 OK over the board's puncher socket, open 335–468 ms (two at ~1.4 s) |
| 30 min run: 52 connections every 30 s (LAN / OPEN alternating) | 52/52 OK, open median 387 ms, max 807 ms |
| Re-announce in 30 min | 6 rounds (initial + every ~5 min), 2114 RPC requests, 1 timeout |
| Heap after each served connection (30 min run) | Flat: 187,416 → 187,432 |
| Heap after closing the server vs. before listening | 189,716 vs. 189,428 (no leak) |

### Footprint

| Item | Value |
|---|---|
| Free heap after WiFi | ~206 KB |
| `hdht_init` (node, socket, timers) | ~0.5 KB, plus the 20 KB loop task stack |
| Lowest free heap seen in any run | 163 KB |
| Loop task stack used | 12.5–13.5 KB of 20 KB |

### Public HyperDHT (2026-10-28, public bootstrap nodes, board and Mac behind the same home router)

Set `HDHT_BOOTSTRAP` to empty for the public nodes. On the computer, `node ../../tools/host/testnet.js --public --server` runs the JS echo server, and `node ../../tools/host/connect-board.js public 5 0x33 1000 <lan|punchfw>` connects to the board.

| Item | Result |
|---|---|
| Bootstrap | 3.1 s, routing table full (32 public nodes) |
| Phase 1: board → JS server | 3/3 OK, open 1.4–1.9 s (LAN shortcut: same public IP) |
| Announce on the public DHT | 4.4 s, 3 public relay nodes |
| Phase 2: JS → board, LAN shortcut | 5/5 OK, open 0.9–3.5 s |
| Phase 2: JS → board, forced holepunch | 5/5 OK, open 1.0–4.1 s. Both sides reached each other at the router's public IP and mapped ports (through the router's hairpin NAT), the board on its puncher socket |
| RPC over the run | 456 requests, 2 timeouts |
| Heap after closing the server | 189,716 (same as on the LAN testnet), no crashes |

### Across two real NATs (2026-10-28, public DHT)

The board stayed on the home router (consistent NAT); the Mac moved to an iPhone hotspot on a mobile carrier, whose NAT hyperdht reports as **random** (`randomized: true`). So every connection needs random-port holepunching: the JS side opens up to 256 sockets ("birthday" sockets) and the board probes random ports every 20 ms for up to ~35 s. Settings: `HDHT_ROUND_INTERVAL_MS=25000` (hyperdht allows one random punch per 20 s per node), client timeout 60 s.

| Direction | Result |
|---|---|
| Phase 1: board → JS server behind the carrier NAT | 3/3 OK, open 12–32 s, all on the board's puncher socket |
| Phase 2: JS (carrier NAT) → board, one JS node reused | 2/5 OK (5–6 s). The 3 failures were `HOLEPUNCH_ABORTED` within ~2 s from hyperdht's own per-node random-punch limit on the JS side |
| Phase 2: JS → board, new JS node per round (`FRESH=1`) | 3/4 OK (9–20 s), 1 real punch failure after ~50 s. A 5th attempt came after the board's serve window had closed |
| Board during phase 2 | 9 handshakes, 5 connections (all over its puncher socket), heap back to 189,712 after closing, no crashes |

Random-port punching is probabilistic in hyperdht as well; through this carrier NAT it took 5–32 s and failed about 1 time in 8 when neither side was rate limited.

### WiFi + HyperDHT + BLE on one C3 (2026-10-28, LAN testnet)

Build with the BLE link (`components/hdht_ble`, same key pair as the DHT server). The image is 1.28 MB; `sdkconfig.ble` switches to a larger app partition anyway:

```bash
rm -f sdkconfig && HDHT_BLE=1 idf.py build flash
```

ESP-IDF enables WiFi/BLE software coexistence automatically (one shared radio, time-sliced).

**Heap**

| Point | WiFi + DHT only | WiFi + DHT + BLE |
|---|---|---|
| Boot | 258.6 KB | 220.5 KB (the BT controller reserves ~38 KB at boot) |
| After WiFi | 206 KB | 168 KB |
| After NimBLE init + advertising | n/a | 98.9 KB |
| After DHT bootstrap | 185 KB | 77.6 KB |
| Lowest during a client connect | ~165 KB | 53.7 KB |
| Lowest over the whole run | 163 KB | **50.7 KB** |

**Performance** (same boot, A/B/C back to back)

| Test | Alone (earlier builds) | Combined build, other side idle | Both at the same time |
|---|---|---|---|
| Board → JS server connect | 519–612 ms | 724–755 ms (BLE advertising only), 3/3 | n/a |
| JS (firewalled) → board, holepunch | 335–468 ms | 446–610 ms, 5/5 | 410–629 ms, with 2 of 10 at ~7.5 s (a lost packet waits for a 1 s RPC retry cycle); 10/10 OK |
| BLE echo throughput (norsp) | 10.1 KiB/s each way | 10.1 KiB/s | 8.2 KiB/s (−19%) |
| BLE round trip, median | 60 ms | 61 ms | 89 ms |

No crashes; the BLE streams (72 KB and 145 KB) were verified end to end; heap after the run was back at its start value. Takeaways:
- It works, but **memory is the limit**: ~50 KB of headroom left with one DHT connection and one BLE connection at once. Running more connections, a bigger BLE queue, or lwIP IRAM optimisation would need cuts elsewhere (e.g. a smaller NimBLE config, or `CONFIG_BT_NIMBLE_MEM_ALLOC_MODE` tuning).
- Radio sharing costs ~20–30% latency on both sides and occasional multi-second outliers on the DHT side while BLE is busy.

## Not covered yet

- Mobile-style random NATs on the board's side cannot holepunch (see the hdht README).
- Power: the server keeps WiFi on and pings its 3 relay nodes every 3 s.
