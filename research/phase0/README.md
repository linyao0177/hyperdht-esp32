# Phase 0 PoC: libsodium and libudx on the ESP32-C3

The ESP-IDF v5.5.1 app used for the feasibility phase (see `docs/feasibility.md`), on an ESP32-C3 (QFN32 rev v0.4, 4 MB embedded flash). It is kept for reference and for re-running the measurements; new projects should start from `examples/`.

The PoC answers three questions:
1. Does libsodium provide every primitive HyperDHT needs, byte-identical to desktop builds, and how fast is it?
2. Does the official libudx (with only two bug fixes) run on lwIP through a small libuv shim, and interoperate with the official `udx-native`?
3. How much heap and stack does that take in internal SRAM?

## Layout

| Path | Contents |
|---|---|
| `../../components/uv_esp/` | Minimal libuv shim written for this project (UDP, timers, prepare/check, async, getaddrinfo). It contains **no** code from hyperdht-cpp's LGPL shim |
| `../../components/libudx/libudx/` | Vendored holepunchto/libudx `9c9a0e7`, with two bug fixes in `src/udx.c` (see `VENDORED.txt`) |
| `../../components/libudx/port/` | `io_esp.c` (replaces io_posix.c) and `udx_alloc.*` (counts libudx's own heap use) |
| `main/sodium_check.c` | libsodium conformance checks and benchmarks |
| `main/sodium_vectors.h` | Reference vectors from desktop libsodium (`tools/gen_vectors.c`) |
| `main/udx_echo.c` | UDX echo against the Mac, with heap measurements |
| `../../tools/host/echo-server.js` | The Mac-side echo peer (udx-native 1.22.0) |
| `../../tools/capture.py` | Resets the board and prints its output until a `POC|done` line |

## Running

1. Copy `sdkconfig.wifi.example` to `sdkconfig.wifi` at the repo root, and fill in a 2.4 GHz SSID and password, plus `CONFIG_POC_PEER_HOST` (the Mac's LAN IP).

2. Build and flash:

   ```bash
   rm -f sdkconfig && idf.py build flash
   ```

3. Start the echo peer on the Mac:

   ```bash
   cd ../../tools/host && npm install && node echo-server.js 9000
   ```

4. Capture the board's output:

   ```bash
   python ../../tools/capture.py <port> 300   # e.g. /dev/cu.usbmodem*, /dev/ttyACM0
   ```

## Results (2026-10-27/28, on the board)

### libsodium (1.0.21 on the board, `espressif/libsodium` component)

All 15 conformance checks pass and match desktop libsodium 1.0.20 byte for byte. They cover Ed25519 signatures, `crypto_scalarmult_ed25519_noclamp` (noise-curve-ed's DH), keyed and unkeyed BLAKE2b, SHA-512, ChaCha20-Poly1305, XChaCha20-Poly1305, secretbox and secretstream.

| Operation | Per call | Throughput |
|---|---|---|
| Ed25519 seed key pair | 12.6 ms | |
| Ed25519 sign (64 B) | 15.0 ms | |
| Ed25519 verify (64 B) | 24.1 ms | |
| Ed25519 DH (SHA-512 + noclamp) | 40.5 ms | |
| BLAKE2b 64 B (code in flash) | 1540 µs | 41 KiB/s |
| BLAKE2b 1 KiB (code in flash) | 11.4 ms | 88 KiB/s |
| BLAKE2b 64 B (`POC_BLAKE2B_IRAM=y`) | 63 µs | 987 KiB/s |
| BLAKE2b 1 KiB (`POC_BLAKE2B_IRAM=y`) | 440 µs | 2274 KiB/s |
| SHA-512 1 KiB (via mbedTLS) | 806 µs | 1240 KiB/s |
| ChaCha20-Poly1305 1 KiB | 374 µs | 2671 KiB/s |
| secretbox 1 KiB | 458 µs | 2184 KiB/s |
| secretstream push 1 KiB | 400 µs | 2499 KiB/s |

- **Noise IK estimate**: about one key generation and four DHs per side, so ~0.18 s per side. Acceptable.
- **BLAKE2b runs slowly from flash**: the fully unrolled `blake2b_compress_ref` is 21 KB, more than the C3's 16 KB instruction cache. Running it from flash thrashes the cache and is ~25× slower. Placing it in IRAM fixes this at the cost of 21 KB of RAM. A round-looped BLAKE2b (~2 KB of code) would be the better fix.
- **Stack**: 5.9 KB at most during the checks.

### Memory and flash

| Item | Value |
|---|---|
| Free heap after boot (no WiFi) | 267,416 B |
| Image size (WiFi, libsodium, libudx) | 1.03 MB (single-app partition 33% free) |
| libsodium in flash | 152 KB |
| libudx in flash | 25 KB |
| uv_esp in flash | 4 KB |

### UDX echo (board + udx-native 1.22.0 on a Mac, same LAN)

The board is on 2.4 GHz WiFi (WPA2, RSSI −33). Each run sends 256 KB as 1 KB writes, with at most 16 writes in flight, and the echo is verified byte for byte. This table uses lwIP defaults; the next section shows the fix that more than doubled throughput.

| Receive window | Result | Time | Throughput | Min RTT | Lowest free heap | Peak heap use | libudx peak | libudx allocations | Leaked |
|---|---|---|---|---|---|---|---|---|---|
| 16 KB | pass | 1638 ms | 156 KiB/s | 1 ms | 130,848 B | 67,392 B | 29,332 B | 350 | 0 |
| 64 KB | pass | 1686 ms | 152 KiB/s | 1 ms | 108,556 B | 89,220 B | 62,352 B | 382 | 0 |
| default (4 MB) | pass | 1599 ms | 160 KiB/s | 1 ms | 119,908 B | 77,912 B | 43,556 B | 323 | 0 |

- **Peak heap use** is the free heap before the run minus the lowest free heap during it. It includes libudx, lwIP/WiFi buffers and the test's own 17 KB of buffers. Free heap returns to its starting value after every run, within 400 B of lwIP/WiFi noise.
- With WiFi up, 215,056 B are free; the lowest during the test is 108,556 B, which meets the "more than 60 KB left" criterion.
- In-flight data is capped by the test (16 × 1 KB), so the receive window barely matters. Differences between rows are timing noise (one run each).
- Struct sizes on RV32: `udx_t` 4168 B, `udx_socket_t` 2344 B, `udx_stream_t` 880 B, `udx_packet_t` 304 B, `uv_udp_send_t` 96 B, `uv_timer_t` 64 B.

### Throughput: lwIP's UDP receive queue is too small

**Finding**: by default lwIP queues at most 6 datagrams per UDP socket (`CONFIG_LWIP_UDP_RECVMBOX_SIZE=6`). The device takes 10–50 ms to process a batch, during which the peer's packets overflow that queue and are dropped. About 22% of the Mac's packets were retransmissions, and recovery stalls added 0.5–1 s per run. Every project now sets this to 32.

| Configuration (16 writes in flight, 6 runs) | Throughput | Retransmits on the Mac | Lowest free heap |
|---|---|---|---|
| lwIP default (queue of 6) | 150–170 KiB/s | 110–119 (~22%), 6 fast recoveries | 108.5 KB |
| **Queue of 32 (now the default)** | **313–365 KiB/s** | 2–3 | 108.5 KB |
| Queue of 32 + `LWIP_IRAM_OPTIMIZATION` + `LWIP_EXTRA_IRAM_OPTIMIZATION` | 382–502 KiB/s | 1–2 | 78 KB |

How it was found:
1. **WiFi power save is not the cause**: modem sleep (`WIFI_PS_MIN_MODEM`, the default) vs `WIFI_PS_NONE` differ by ~10%. The test runs both; result lines carry `ps=`.
2. **Neither write latency nor windows**: 64 writes in flight instead of 16 change nothing. srtt ~10 ms, cwnd ~20 packets and pacing 2–3 MB/s are all far above the actual rate.
3. **Counters in uv_esp** (`uv_esp_stats_get`, `uv_esp_trace_get`, printed as `POC|uvstats` and `POC|uvtrace`) show the loop turning only 28 times in 1.6 s, with several 180–920 ms waits in which no packet arrived at all.
4. **udx-native's stream stats in the Mac's echo server** show 110+ retransmissions out of ~535 packets: confirmed packet loss, at the device's receive queue while it is busy.

**The remaining bottleneck is the CPU.** A run now takes ~700 ms, of which `select()` blocks only 100–180 ms:
- `sendmsg` costs ~0.7 ms, or ~0.3 ms with lwIP's IRAM optimisations. So it is mostly instruction-cache misses.
- libudx's receive path costs ~0.5 ms per packet, excluding the sends it makes.

Ideas not pursued yet:
- Put libudx's hot paths in IRAM.
- BBR's `double`/`float` maths is soft-float on the C3, and a fixed-point version may be worth it.
- lwIP's IRAM options cost 33 KB of heap, so whether to enable them depends on the application's budget.

### Corruption under memory pressure: a libudx bug, fixed

**Symptom**: one echo failed verification when the heap was nearly exhausted. The Mac received 64 extra bytes, and the device saw zeros where the stream diverged.

**Reproduction**: `CONFIG_POC_HEAP_LEAVE_FREE` allocates ballast before each run to squeeze free heap down to a given value. At 70,000 it reproduced in 1 of 6 runs.
- Both ends now verify the data pattern byte for byte and print where it diverges (`POC|mismatch` on the device, `MISMATCH` on the Mac). Both showed the corruption originating on the device-to-Mac path, as zeros.
- uv_esp gained a check (`queued_head_changed`) that records the first 4 bytes of each queued send and compares them just before transmission. The failing run had 2 queued packets modified before they went out, and `rtos=2`.

**Root cause**: in `udx.c`'s RTO path, two steps ran in the wrong order:
1. `mtu_unprobeify_packet()` cleared the padding length (`header[3]`) of an MTU probe.
2. Only then did it check `pkt->ref_count == 2`, which means the packet is already queued for sending.

When `uv_udp_try_send` returns EAGAIN, the probe is queued along with its zero padding. If the RTO then fires, the header is changed in place while the queued send still carries the padding, so the receiver reads the padding as stream data. The RACK path checks `ref_count` first and is fine. Desktop `try_send` rarely returns EAGAIN, which is why the bug stays hidden there; on the C3, lwIP returns ENOMEM as soon as memory is tight.

**A crash fixed along the way**: `process_data_packet` did not check calloc/malloc for NULL when buffering out-of-order data, and would memset through NULL under memory pressure. It now drops the packet and lets the remote retransmit it.

Both fixes are described in `components/libudx/libudx/VENDORED.txt`. `patches/libudx/` has them as upstream patches with a PR description.

**Verification**:
- 20 runs squeezed to 70 KB: no corruption, and `queued_head_changed` always 0, although 14 of the runs had 7 or more RTOs, the condition that triggered the bug. libudx saw about 10 allocation failures over these runs and never crashed.
- 6 runs at normal memory all pass, with the lowest free heap at ~109 KB.

**Still open (no corruption, but connections drop)**:
- With only 1–3 KB free, most runs end in `Connection timed out`: WiFi and lwIP cannot take in packets, and libudx gives up after 7 RTOs.
- One run in 20 stalled for 120 s without an RTO; the cause is not known yet.
- Some runs ended with 9–24 KB less free heap, which came back before the next run. This looks like lwIP/WiFi buffers being held briefly at close, not a leak.

In practice, leave the network stack headroom and treat ENOMEM from lwIP as an exception, not a steady state.

### Stack: libudx needs a 16 KB task stack

With an 8 KB stack the UDX task hit a `Stack protection fault`. `udx.c`'s `_send_packet` declares `uv_buf_t _bufs[UDX_MAX_COMBINED_WRITES + 2]` on the stack: 1474 × 8 B, for an 11,648 B frame. The array is only used for MTU probes, and is sized for the worst case of one write per byte. A 16 KB stack works (12,944 B used). An upstream change could size it dynamically from `nwbufs`, or make the constant overridable, bringing the frame under 1 KB.
