// hdht_mqtt: MQTT over HyperDHT for ESP-IDF's esp-mqtt.
//
// An esp_transport that carries esp-mqtt's bytes over an encrypted HyperDHT
// stream instead of TCP, so a device reaches an MQTT node (packages/
// boat-mqtt-node) by public key: no IP address, domain or certificate on
// either side, through NATs. The node knows the device by the key it proved
// in the Noise handshake (the hdht default key pair), so no password either.
//
//   // on the hdht task, once bootstrapped
//   esp_transport_handle_t t = hdht_mqtt_transport_new(&dht, NULL);
//   esp_mqtt_client_config_t cfg = {
//     .broker.address.hostname = "boat-mqtt", // a network name, or a node's key in hex
//     .network.transport = t,
//     .network.timeout_ms = 30000,
//     .credentials.client_id = my_key_hex, // the node wants it to start with the key
//   };
//   esp_mqtt_client_handle_t c = esp_mqtt_client_init(&cfg);
//   esp_mqtt_client_start(c);
//
// The hostname is either a node's public key in hex (64 characters) or a
// network name: the transport looks up BLAKE2b-256(name) and dials the nodes
// it finds, in random order, until one opens. Each reconnect looks up again,
// so a device moves to another node when its node goes away. The port is
// ignored.
//
// Threads: esp-mqtt calls the transport from its own task; the transport
// hands each call to the hdht task (uv_async_send) and waits. Create it on the
// hdht task. Never call esp-mqtt's API from the hdht task: esp-mqtt's task
// holds its API lock while it waits for the hdht task (in a connect, say), so
// that call would wait for the hdht task itself. Use another task (a queue
// and a worker task, as examples/uart_module does). esp_mqtt_client_destroy
// destroys the transport.

#ifndef HDHT_MQTT_H
#define HDHT_MQTT_H

#include <stddef.h>
#include <stdint.h>

#include "esp_transport.h"
#include "hdht.h"
#include "hdht_mqtt_signed.h"

typedef struct {
  size_t rx_buffer; // bytes from the node not yet read by esp-mqtt; default 4096
  size_t tx_buffer; // bytes from esp-mqtt not yet written; default 2048
} hdht_mqtt_config_t;

// NULL config = defaults. Returns NULL when out of memory.
esp_transport_handle_t
hdht_mqtt_transport_new (hdht_t *dht, const hdht_mqtt_config_t *config);

// The topic nodes of a network announce under: BLAKE2b-256(name).
void
hdht_mqtt_topic (const char *network, uint8_t topic[32]);

typedef struct {
  uint8_t node[32];     // the node of the current or last connection
  size_t nodes_found;   // by the last lookup (0 when dialing a key)
  uint32_t lookup_ms;   // time of the last lookup
  uint32_t connect_ms;  // from the connect call to the open stream
  bool relayed;         // the stream runs through a blind relay
  int error;            // why the last connection closed or failed (hdht error)
  uint32_t connects;    // streams opened so far
} hdht_mqtt_info_t;

void
hdht_mqtt_get_info (esp_transport_handle_t t, hdht_mqtt_info_t *info);

#endif
