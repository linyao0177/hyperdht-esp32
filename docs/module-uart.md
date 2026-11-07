# Module command interface (UART)

[`examples/uart_module`](../examples/uart_module) turns the ESP32-C3 into a network module. A host MCU uses it the way it would use an AT-command WiFi module: one text command per line over a serial port. The module handles WiFi, its identity, peer-to-peer connections by DID, signed records and topic lookup. The host needs no network stack and no cryptography of its own.

Version: `hdht-module/0.6.1`.

## Wiring

| Port | Settings | Use |
|---|---|---|
| USB Serial/JTAG (default) | the dev board's USB port; logs move to UART0 (GPIO21) | development, and a computer as host |
| UART1 | `CONFIG_MODULE_PORT_UART`; TX GPIO4, RX GPIO5, 115200 8N1 by default | a host MCU in a product |

Lines end in CR LF from the module. The module accepts LF or CR LF. A line may be up to 2304 characters.

## Lines

- **Command** (host → module): `AT+NAME`, `AT+NAME?` (query) or `AT+NAME=<args>`. The name is case-insensitive and the arguments are not.
- **Response** (module → host): zero or more result lines `+NAME:...`, then `OK` or `ERROR:<reason>`. Send the next command only after `OK` or `ERROR`.
- **Event** (module → host, at any time, even between a command's response lines): `+EVENT:...`. Event names never match a result name, so a host can tell them apart by name.

Bytes travel as lowercase hex. The commands ending in `T` (`SENDT`, `PUTT`, `SIGNT`) take the rest of the line as text instead. That text may contain commas, but not line breaks.

A DID argument is `did:mw:<64 hex>` or the 64 hex characters alone. Results always use the `did:mw:` form.

## Startup

```
+BOOT:hdht-module/0.1,did:mw:b45d...           identity loaded; commands work
+NET:CONNECTED,192.168.31.7                     WiFi up
+READY:did:mw:b45d...,0,32                      DHT bootstrapped (status, routing table size)
```

Commands marked **DHT** in the tables below answer `ERROR:not ready` until `+READY` with status 0. In the test runs, `+READY` arrived 6–7 s after reset.

## Commands

### Module

| Command | Result | |
|---|---|---|
| `AT` | — | ping |
| `AT+INFO` | `+INFO:<version>,<did>,<wifi 0/1>,<dht 0/1>,<listening 0/1>,<open links>,<free heap>` | |
| `AT+ID?` | `+ID:<did>` | the module's identity, kept in NVS |
| `AT+WIFI=<ssid>,<password>` | — | stores the network and reconnects. The password is everything after the first comma |
| `AT+WIFI=` | — | forgets it; back to the network built into the firmware |
| `AT+WIFI?` | `+WIFI:<ssid>,<connected 0/1>,<ip>` | |
| `AT+RESTART` | — | restarts after `OK` |

### Identity

| Command | Result | |
|---|---|---|
| `AT+SIGN=<hex>` / `AT+SIGNT=<text>` | `+SIGN:<signature hex>` | Ed25519 with the module's key, up to 1024 bytes. Anyone can verify it against the DID |
| `AT+VERIFY=<did>,<hex>,<signature hex>` | `+VERIFY:<1/0>` | |
| `AT+HASH=<text>` | `+HASH:<hex>` | BLAKE2b-256, for example to make a topic from a name |
| `AT+CRED=<id>,<issuer did>,<iat>,<model>,<signature>` | — | Stores a manufacturer credential for this module ([credentials.md](credentials.md)) after checking its signature, that it is for this module's key, and, if `CONFIG_MODULE_ISSUER` is set, the issuer. Kept in NVS |
| `AT+CRED?` | `+CRED:<credential JSON>`, or nothing | Put it in your record as `"cred":<JSON>` with `AT+PUTT`, so verifiers find it |
| `AT+CRED=` | — | Forgets it |

### Connections

Up to 4 links at a time, numbered 0–3.

| Command | Result | |
|---|---|---|
| `AT+CONNECT=<did>` | `+CONNECT:<link>` | **DHT**. Then `+CONN` or `+CLOSED` for that link. The peer sees the module's own DID (before 0.6.1, a random key that changed at each boot) |
| `AT+LISTEN=1` / `AT+LISTEN=0` | — | accept connections / stop. A `LISTEN=1` sent before `+READY` takes effect once ready |
| `AT+LISTEN?` | `+LISTEN:<0/1>` | |
| `AT+ALLOW=<did>` | — | adds to the allow list (up to 8, kept in NVS). While the list is not empty, only peers on it can connect |
| `AT+ALLOW=` | — | clears it: anyone can connect |
| `AT+ALLOW?` | `+ALLOW:<did>` per entry | |
| `AT+SEND=<link>,<hex>` / `AT+SENDT=<link>,<text>` | — | up to 1024 bytes, delivered as one message |
| `AT+CLOSE=<link>` | — | graceful end. If the peer has not ended its side 5 s later, the link is closed anyway |
| `AT+LINKS?` | `+LINK:<link>,<did>,<IN/OUT>,<open 0/1>,<path>` per link | path is `RELAY`, `DIRECT`, or `-` while not open |

### Records and lookup

| Command | Result | |
|---|---|---|
| `AT+PUT=<hex>` / `AT+PUTT=<text>` | `+RECORD:<seq>` | **DHT**. Publishes the module's own record, up to 1000 bytes, under its DID. Then `+PUT` for that seq. The record is kept in NVS and republished after every restart and every 12 h. A put sent while another is in flight waits for it |
| `AT+GET=<did>` | — | **DHT**. Then `+GET` with the record of that DID, checked against its key |
| `AT+LOOKUP=<topic hex>` | — | **DHT**. Then `+LOOKUP` with the DIDs announced under the topic |
| `AT+ANNOUNCE=<topic hex>` | — | **DHT**. Announces the module under the topic (up to 4, kept in NVS, refreshed every 10 min and after each restart). Then `+ANNOUNCE`. Use with `AT+LISTEN=1`, so that peers who find it can connect |
| `AT+ANNOUNCE=` | — | **DHT**. Stops announcing and unannounces every topic. Then `+UNANNOUNCE` per topic. A few copies can remain until they expire (20 min) |
| `AT+ANNOUNCE?` | `+TOPIC:<topic hex>` per topic | **DHT** |

### Relay

| Command | Result | |
|---|---|---|
| `AT+RELAY=<did>` | — | **DHT**. From now on every connection, outbound and inbound, pairs at this blind-relay node. Holepunching runs alongside: a link takes whichever path works first, and a link on the relay moves to the direct path when holepunching gets through later (`+DIRECT`). Kept in NVS. This is for modules behind a random (symmetric) NAT, such as many 4G routers, which cannot be holepunched. The relay forwards encrypted packets and cannot read them |
| `AT+RELAY=AUTO` | — | **DHT**. The same, through a public relay node the module finds by topic ([relay-node.md](relay-node.md)). Then `+RELAYFOUND`. The module looks again when a relayed connect fails with -107, and checks its relay every 10 minutes (a connect through a dead relay still succeeds when holepunching does, so this check may be what notices it). Kept in NVS: after a restart it finds a relay again |
| `AT+RELAY=` | — | **DHT**. Back to direct connections. A peer that asks for a relay still gets one |
| `AT+RELAY?` | `+RELAY:<did>`, `+RELAY:AUTO,<did or empty>`, or nothing | **DHT** |
| `AT+RELAYONLY=1` / `AT+RELAYONLY=0` | — | 1: no holepunching next to the relay, outbound or inbound, so peers never see the module's address. Kept in NVS. Default 0 |
| `AT+RELAYONLY?` | `+RELAYONLY:<0/1>` | |

### Camera events with proofs

The module can check event_v2 messages that cameras send on a link: JSON objects with a zero-knowledge proof (`"zk"`) that a registered device signed the event ([components/zk](../components/zk/README.md#event_v2)). It needs the root of the device registry. Built with `CONFIG_MODULE_ZK` (on by default).

| Command | Result | |
|---|---|---|
| `AT+ZKROOT=<64 hex>` | — | the registry root, big-endian and below the group order. Kept in NVS. From now on every event that arrives gets a `+ZK` after its `+DATA`. The verifier needs about 2.5 s to start; events wait for it |
| `AT+ZKROOT=` | — | stops checking |
| `AT+ZKROOT?` | `+ZKROOT:<hex>`, or nothing | |
| `AT+TIME?` | `+TIME:<unix ms>` | the clock, set by SNTP after WiFi comes up. 0 until then |

Every message on a link that contains the key `"zk"` gets one `+ZK:<link>,<seq>,<result>` (seq is `-` if the message could not be read):

| Result | |
|---|---|
| `VALID` | the proof fits the event and the root |
| `INVALID` | it does not: a field was changed, or it was made for another root |
| `REPLAY` | an event with the same M was accepted before |
| `STALE` | `t` is more than `CONFIG_MODULE_ZK_WINDOW` seconds (default 30) from the module's clock |
| `NOTIME` | the clock is not set yet |
| `BAD` | not a well-formed event or proof |
| `BUSY` | 4 events are already waiting |

Each takes 1.24 s on the C3, one at a time and below the network's priority. The messages themselves still arrive as `+DATA` at once. The checks do not use the sender's DID: anyone can connect with a new key and send a copied message, which is why `t` and M are checked instead.

## Events

| Event | When |
|---|---|
| `+BOOT:<version>,<did>` | after reset |
| `+NET:CONNECTED,<ip>` / `+NET:DISCONNECTED,<reason>` | WiFi. The module keeps reconnecting by itself |
| `+READY:<did>,<status>,<nodes>` | DHT bootstrapped, once per boot |
| `+LISTENING:<status>` / `+LISTENING:CLOSED` | the module announced itself, or stopped |
| `+CONN:<link>,<did>,<IN/OUT>` | a link opened. The peer's DID is authenticated by the handshake |
| `+DIRECT:<link>` | a link that opened through the relay moved to a direct path, and its relay connection closed |
| `+DENIED:<did>,<reason>` | an inbound peer was refused: `not allowed` or `no free link` |
| `+DATA:<link>,<length>,<hex>` | a message from the peer. A message over 1024 bytes arrives as several events, in order |
| `+CLOSED:<link>,<error>` | the link is gone. 0 is a clean end, -12 means closed by `AT+CLOSE` after the timeout, -100…-106 mean a connect failed, and -107 means the relay could not pair the two sides |
| `+RELAYFOUND:<did>` or `+RELAYFOUND:` | in `AT+RELAY=AUTO`: the relay now in use, or none found (direct connections until one is; the module looks again every minute) |
| `+PUT:<status>,<nodes stored>,<seq>` | a record put finished. Status 0 means at least one node stored it |
| `+GET:<did>,<status>,<seq>,<hex>` | status 0 with the value, or -110 if not found |
| `+LOOKUP:<topic>,<status>,<count>[,<did>...]` | up to 16 DIDs. They are hints, not proof: connect to authenticate, and check the peer's record |
| `+ANNOUNCE:<topic>,<status>,<nodes>` / `+UNANNOUNCE:<topic>,<status>,<nodes>` | an announce or unannounce finished. Status 0 means at least one node took it |
| `+ZK:<link>,<seq>,<result>` | an event with a proof was checked (see [Camera events with proofs](#camera-events-with-proofs)) |

## A session

The host is a meter. It publishes what it is, waits for its operator's app to connect, answers a request, then calls a collector found by topic:

```
> AT+PUTT={"v":1,"svc":"meter/1","name":"line 3 meter"}
< +RECORD:1
< OK
< +PUT:0,20,1
> AT+ALLOW=did:mw:59940ba5...
< OK
> AT+LISTEN=1
< OK
< +LISTENING:0
< +CONN:0,did:mw:59940ba5...,IN
< +DATA:0,4,72656164                              "read"
> AT+SENDT=0,{"kwh":1234.5}
< OK
> AT+HASH=collectors/line-3
< +HASH:5ccdab3f...
< OK
> AT+LOOKUP=5ccdab3f...
< OK
< +LOOKUP:5ccdab3f...,0,1,did:mw:7d8e...
> AT+CONNECT=did:mw:7d8e...
< +CONNECT:1
< OK
< +CONN:1,did:mw:7d8e...,OUT
> AT+SIGNT={"kwh":1234.5,"t":1793262832}
< +SIGN:9f3a...
< OK
> AT+SENDT=1,{"kwh":1234.5,"t":1793262832,"sig":"9f3a..."}
< OK
```

## Host notes

- **Retry connects, and time them out.** A connect can fail with `+CLOSED:<link>,-100` (peer not found), most often right after the peer starts, before its announcement has spread. In the test runs, 5 of 22 connects to peers started seconds earlier failed: four with -100, and one that gave no `+CONN` within 60 s. Every retry worked.
- **Network operations take seconds.** In the test runs, a connect took about 3 s, a record put 4–10 s, and a get about 5 s. Do not block the host's main loop waiting for them.
- **One command at a time.** Wait for `OK` or `ERROR`. The module queues up to 4 lines and answers `ERROR:busy` beyond that.
- **The module keeps the identity, network, allow list, record, topics, relay, credential and registry root across restarts.** Listening does not persist: send `AT+LISTEN=1` after each boot.
- **Signing is the module's key, not the host's.** What it proves is that this module produced the signature. Data the host feeds in is only as trustworthy as the host and its wiring.
