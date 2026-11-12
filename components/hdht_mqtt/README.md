# hdht_mqtt

MQTT over HyperDHT for ESP-IDF's esp-mqtt. It is an `esp_transport` that carries esp-mqtt's bytes over an encrypted HyperDHT stream instead of TCP. A device reaches an MQTT node ([`packages/boat-mqtt-node`](../../packages/boat-mqtt-node)) by public key, through NATs, with no broker address, password or certificate. The node knows the device by the key it proved in the Noise handshake: the default key pair of the `hdht_t`.

```c
// on the hdht task, once bootstrapped
esp_transport_handle_t t = hdht_mqtt_transport_new(&dht, NULL);
esp_mqtt_client_config_t cfg = {
  .broker.address.hostname = "boat-mqtt",   // a network name, or a node's public key in hex
  .network.transport = t,
  .network.timeout_ms = 30000,              // a lookup and a holepunch, not a TCP handshake
  .credentials.client_id = my_public_key_hex, // nodes want it to start with the key
};
esp_mqtt_client_handle_t client = esp_mqtt_client_init(&cfg);
esp_mqtt_client_start(client);
```

The rest is esp-mqtt as usual: `esp_mqtt_client_publish`, `esp_mqtt_client_subscribe` and events, from any task.

- **Finding a node.** The hostname is either a node's public key in hex (64 characters) or a network name. For a name, the transport looks up BLAKE2b-256(name) (`hdht_mqtt_topic`) and dials the nodes it finds, in random order, until one opens. Each reconnect looks up again, so the device moves to another node when its node goes away. The node it just lost is tried last, since its announcement stays on the DHT for up to 20 minutes. The port is ignored.
- **Threads.** esp-mqtt calls the transport from its own task. The transport never touches hdht from there: it sets a command, wakes the hdht loop with `uv_async_send` and waits on an event group. Bytes go through two FreeRTOS stream buffers (4 KB in, 2 KB out by default, `hdht_mqtt_config_t`). Create the transport on the hdht task. `esp_mqtt_client_destroy` destroys it; call that from any task except the hdht task.
- **Node list.**
    - `hdht_mqtt_nodelist_keep` keeps the transport on the staked nodes a quorum of trusted verifiers lists:
        1. It reads their HyperDHT records and takes the main record a quorum put out byte for byte (2 of 3, or ceil(2n/3)).
        2. It reads one page of nodes, an immutable record checked against its hash, chosen by the device's key.
        3. It hands those nodes to the transport, which then dials them with no lookup.
        4. It does this again every 10 minutes, and moves to the verifiers an agreed list names, keeping them in NVS.
    - The device needs no chain, and one verifier alone cannot steer it.
    - Lower down: `hdht_mqtt_nodelist_fetch`, `hdht_mqtt_transport_set_nodes` and `hdht_mqtt_transport_prefer` (a listed node to dial first).
    - Verifier nodes publish the list ([`boat-registry`](https://github.com/linyao0177/xid-network/tree/main/packages/boat-registry) in xid-network, `lib/nodelist.js`). The decoding and tally in `nodelist.c` are checked against the JS on the desktop (`test/test_nodelist.c`).
- **Status.** `hdht_mqtt_get_info` reports the node, how many nodes the lookup found, lookup and connect times, whether the stream is relayed, and the last error.
- **Relays.** A device behind a random NAT uses `hdht_set_relay` as with any hdht connection; the transport needs nothing more.
- **Never call esp-mqtt from the hdht task.** esp-mqtt's task holds its API lock while it waits for the hdht task (during a connect, for one), so such a call waits for itself until the connect times out. Hand esp-mqtt calls to another task, as `examples/uart_module` (`main/mqtt.c`) and `examples/boat_mer` do.

If esp-mqtt falls a whole rx buffer behind, the transport closes the connection rather than drop part of an MQTT packet, and esp-mqtt reconnects.

## Signed messages

A node checks who publishes, but a node is anyone's machine: it, or a bridge, could change a message or play an old one again. [`hdht_mqtt_signed.h`](include/hdht_mqtt_signed.h) adds the publisher's own Ed25519 signature over the topic, a sequence number and the payload (74 bytes per message). A subscriber checks it against the key in the topic, whatever node the message came through, and refuses a sequence number it has seen (`SignedInbox` in `packages/boat-mqtt-node`). `signed.c` is plain C over libsodium and is checked against the JS on the desktop (`test/test_signed.c`, run by the package's tests). Signing takes 20–25 ms on the C3.

`hdht_mqtt_receipt_open` and `hdht_mqtt_receipt_check` read a node's signed receipt: what it says it got from the device, compared with what the device sent. A receipt that names a sequence number the device never sent is the node's signed word against itself.

See [`examples/mqtt_p2p`](https://github.com/linyao0177/xid-network/tree/main/examples/mqtt_p2p) (in xid-network) for a device that publishes telemetry and answers commands, and the measurements.
