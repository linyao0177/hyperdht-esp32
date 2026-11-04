# uart_module: the ESP32-C3 as a network module

Firmware that makes the C3 a module a host MCU drives over a serial line, like an AT-command WiFi module. The host gets an identity (`did:mw:<key>`), encrypted connections to any peer by DID (through a blind relay where holepunching cannot work), signed records, topic lookup and announce, and Ed25519 signing. It can also check camera events that carry a zero-knowledge proof as they arrive. It needs no network stack or cryptography of its own, and no changes to this firmware.

The command reference is [docs/module-uart.md](../../docs/module-uart.md).

| File | |
|---|---|
| [`main/port.c`](main/port.c) | The command port: USB Serial/JTAG for development, UART1 on two pins for a host MCU. Whole lines in and out, safe from any task |
| [`main/main.c`](main/main.c) | Identity from a seed in NVS, WiFi from `AT+WIFI` or the firmware's default, and the hdht task |
| [`main/at.c`](main/at.c) | The commands and events |
| [`main/zk.c`](main/zk.c) | Checks camera events with proofs (`AT+ZKROOT`, `+ZK`) on a task of its own, with the time window and replay check. [`main/zk_vk.h`](main/zk_vk.h) is the event_v2 circuit's verifying key, made with [`components/zk/gen/vk_header.py`](../../components/zk/gen/vk_header.py) |
| [`tools/module_host.py`](../../tools/module_host.py) | A host on a computer: an interactive terminal, and the library the test uses. Read it as a reference for a host MCU's driver: send a line, collect result lines until `OK` or `ERROR`, and take everything else starting with `+` as an event |
| [`tools/module_test.py`](../../tools/module_test.py) | End-to-end test: the computer is the host MCU, and Node.js peers ([`tools/host/module-peer.js`](../../tools/host/module-peer.js)) are the network |

## Run it

1. Copy `sdkconfig.wifi.example` to `sdkconfig.wifi` at the repo root and fill in a 2.4 GHz network. That network is the default, until the host sets another with `AT+WIFI`.

2. Build and flash:

   ```bash
   cd examples/uart_module && idf.py set-target esp32c3 && idf.py build flash
   ```

3. Talk to it from the computer, which plays the host MCU. Use the ESP-IDF Python environment:

   ```bash
   python tools/module_host.py /dev/cu.usbmodem21101 --reset
   ```

   ```
   < +BOOT:hdht-module/0.1,did:mw:b45dc638...
   < +NET:CONNECTED,192.168.31.7
   < +READY:did:mw:b45dc638...,0,32
   AT+INFO
   < +INFO:hdht-module/0.1,did:mw:b45dc638...,1,1,0,0,146380
   < OK
   ```

4. Run the full test (needs `npm ci` in `tools/host`):

   ```bash
   python tools/module_test.py /dev/cu.usbmodem21101
   ```

With the default USB port, the module's logs go to UART0 (GPIO21) so they never mix with responses. For a product, select `CONFIG_MODULE_PORT_UART` and wire the host to GPIO4 (module TX) and GPIO5 (module RX). The console can then stay on USB.

## Results (2026-10-29, ESP32-C3 on the public HyperDHT)

`module_test.py` passed all 54 checks on firmware 0.4 (48 on 0.3, 45 on 0.2, and 35–36 on the first version in its last three runs):

| | Result |
|---|---|
| Startup | `+READY` 6–7 s after reset |
| Identity | `AT+HASH` matches Python's BLAKE2b. `AT+SIGNT` verifies with Python's Ed25519 against the DID. `AT+VERIFY` accepts a good signature and rejects a tampered message |
| Records | `AT+PUTT` stored on 20 nodes in 4–10 s. `AT+GET` and a Node.js peer read back the same value and seq. After `AT+RESTART`, the module republished the same record and seq on its own |
| Lookup | `AT+LOOKUP` found an echo server announced from Node.js under `BLAKE2b("uart-module-test")` |
| Outbound | `AT+CONNECT` in about 3 s. 512 bytes of hex came back echoed in one message. Text with commas went through `AT+SENDT`. `AT+CLOSE` ended cleanly |
| Stuck peer | A peer that never ended its side was closed 5 s after `AT+CLOSE` (`+CLOSED:0,-12`) |
| Inbound | After `AT+LISTEN=1`, a Node.js peer connected by DID. Its message arrived as `+DATA`, and the host's `AT+SENDT` reply reached it |
| Allow list | A peer missing from the list got `+DENIED:...,not allowed`. Clearing the list opened it again |
| Credential | `AT+CRED` refused a credential whose model was changed after signing, and accepted the genuine one. The host published it in its record, and `issuer.js verify` returned VALID |
| Relay | With `AT+RELAY` set to a blind-relay node on the computer, an outbound link to a Node.js server and an inbound link from a Node.js client both ran through the relay. Both peers saw the relay's address (192.168.31.152:49738), not the module's, and data went both ways |
| Relay found by topic | `AT+RELAY=AUTO` found a `relay-node.js` on the computer in 8.8 s, and an outbound link ran through it. That relay was then killed without unannouncing, and a second one started. The next connect failed with -107, the module found the second relay on its own, and the connect after that ran through it in 4.3 s |
| Announce | `AT+ANNOUNCE` was stored on 20 nodes in 4–7 s, and a Node.js lookup found the module on 19 nodes. `AT+ANNOUNCE=` then unannounced it from all of them |
| Errors | Unknown command, bad DID, bad hex, a send on a closed link, and a 2408-character line (`ERROR:line too long`) were all reported, and the module kept working |
| WiFi | `AT+WIFI` to a missing network gave `+NET:DISCONNECTED` at once. `AT+WIFI=` reconnected to the default network in 2 s, and the DHT worked again right away |
| Free heap | ~146 KB idle, ~154 KB with one link open (the reading varies with WiFi buffers) |
| Image | 1.03 MB (0x108650); 30% of the app partition free |

Connects to peers that had started seconds earlier failed 5 times in 22 attempts during testing: four with -100 (peer not found), and one with no `+CONN` within 60 s. Every retry worked. The test now retries once, as a host should; see [host notes](../../docs/module-uart.md#host-notes).

The test runs found three problems, all fixed above:

- `AT+CLOSE` waited forever for a peer that never ended its side. It now closes the link after 5 s.
- `AT+PUT` answered `busy` while the module was republishing at startup. It now queues the new record, and returns the seq to wait for.
- Some event names were the same as result names (`+WIFI`, `+LISTEN`), so a host could not tell them apart. The events are now `+NET` and `+LISTENING`.

## Camera events with proofs (2026-11-04, firmware 0.6)

A reCamera on the same LAN connected to the module by DID, over a direct link, and sent event_v2 messages: each a person detection with a Groth16 proof, made on the camera in about 2.1 s. The module had `AT+ZKROOT` set to the test registry's root, and the host answered each `+ZK` with an ack.

| | Result |
|---|---|
| 10 events, 2 of them with `conf` raised by 0.001 after proving | 8 `VALID`, the 2 changed ones `INVALID`. Every event was acked |
| The first event sent again, byte for byte | `REPLAY`, 130 ms after its `+DATA` (no proof check needed) |
| Time per event on the module | 1.24 s from `+DATA` to `+ZK`. The camera saw 1.30–1.40 s from sending to its ack |
| An event proven a day earlier | `STALE` |
| `conf` with 4 decimals | `BAD` |
| Plain text on the same link | `+DATA` only, no `+ZK` |
| Clock | set by SNTP about 6 s after reset, 0.01–0.13 s from the computer's |
| Free heap | 89–95 KB with the verify task running (its 24 KB stack peaked at 21 KB) |
| Image | 1.26 MB (0x1336e0); 18% of the app partition free |

The camera's proving key stays with the camera team, so `module_test.py` checks the module with old events and changed ones (`STALE`, `INVALID`, `BAD`). `VALID` and `REPLAY` need a camera, or that key.

## Not covered yet

- **A real host MCU on UART1.** UART1 builds, but the test ran over USB Serial/JTAG. The two ports share all code above the read and write calls.
- **`AT+WIFI` to a working network other than the default**, which would need its password in the test.
- **Anchoring and payments.** [`examples/boat_mer`](../boat_mer) does them in firmware; they are not commands yet.
- **A real random NAT.** The relay was tested with the module and its peers on the same LAN as the relay node, with the relay given by `AT+RELAY` or found by `AT+RELAY=AUTO` (`relay-node.js --force`). A 4G router with a symmetric NAT has not been tried.
- **A host-side C driver.** `module_host.py` shows the parsing a host needs.
