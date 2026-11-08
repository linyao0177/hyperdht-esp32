// MQTT over HyperDHT, paid per message (CONFIG_MER_MQTT_NODE).
//
// The device joins an MQTT network of nodes anyone can run
// (packages/boat-mqtt-node) and publishes attested readings to
// d/<its key>/telemetry. Its DID record names the node it is on ("mqtt"), so
// apps and other nodes find it. A node that charges puts its terms in its own
// DHT record; it sends invoices to the device's inbox, and the device pays them
// with EIP-3009 authorizations signed by MER, published to
// d/<its key>/to/<node>/pay. The node settles them (wdk-protocol-boat-evm).
//
// What the device pays, and does not:
// - only the payee and token in the node's signed terms, and only in the
//   token and EIP-712 domain its buyer uses (CONFIG_MER_BUYER_*), which also
//   leaves MER's one global domain as the buyer set it;
// - at most what it counted itself (price × its own messages and bytes) plus
//   the node's stated credit, and at most CONFIG_MER_MQTT_MAX_PAY at once.
//
// Threads: hdht calls and payment signing run on the hdht task (MER keeps one
// EIP-712 domain, and the buyer and anchoring sign there too); esp-mqtt calls
// and the readings' attestation (~480 ms of TweetNaCl, kept off the hdht
// task) on the "mqtt_out" task, never esp-mqtt on the hdht task
// (hdht_mqtt.h); events on esp-mqtt's task.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "mqtt_client.h"

#include "boat_crypto.h"
#include "boat_pay.h"
#include "hdht_mqtt.h"
#include "mer.h"

#define MAX_MSG 640

typedef struct {
  char topic[160];
  char *payload; // heap; NULL: attest a reading and publish it as telemetry
  int len;
} out_t;

typedef struct {
  bool ok;
  uint8_t pay[20];
  char pay_hex[43];
  char token[43];
  uint32_t chain_id;
  uint64_t price_msg, price_kb, credit;
} terms_t;

static esp_transport_handle_t transport;
static esp_mqtt_client_handle_t client;
static QueueHandle_t outbox;
static uv_async_t wake;
static char me[65];

// set on esp-mqtt's task, read on the hdht task after `wake`
static volatile bool connected;
static uint8_t node[32];
static volatile bool node_changed;
static char invoice[384];
static volatile bool invoice_pending;

// hdht task
static terms_t terms;
static uint8_t terms_node[32];
static bool terms_busy;
static uint64_t own_msgs, own_bytes, own_paid; // msgs and bytes: also mqtt_out, under mux
static portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;
static uint32_t paid_count, refused_count;

bool
mqtt_enabled (void) {
  return CONFIG_MER_MQTT_NODE[0] != '\0';
}

static uint64_t
own_owed (void) {
  taskENTER_CRITICAL(&mux);
  uint64_t msgs = own_msgs, bytes = own_bytes;
  taskEXIT_CRITICAL(&mux);
  return terms.price_msg * msgs + (terms.price_kb * bytes + 1023) / 1024;
}

static void
post (const char *topic, const char *payload, int len) {
  out_t o;
  snprintf(o.topic, sizeof(o.topic), "%s", topic);
  o.payload = malloc(len);
  if (o.payload == NULL) return;
  memcpy(o.payload, payload, len);
  o.len = len;
  if (xQueueSend(outbox, &o, 0) != pdTRUE) free(o.payload);
}

// esp-mqtt's task -------------------------------------------------------------------------

static void
on_event (void *arg, esp_event_base_t base, int32_t id, void *data) {
  (void) arg;
  (void) base;
  esp_mqtt_event_handle_t e = data;
  if (id == MQTT_EVENT_CONNECTED) {
    hdht_mqtt_info_t info;
    hdht_mqtt_get_info(transport, &info);
    memcpy(node, info.node, 32);
    node_changed = true;
    connected = true;
    char topic[100];
    snprintf(topic, sizeof(topic), "d/+/to/%s/#", me);
    esp_mqtt_client_subscribe(client, topic, 1);
    printf("MER|mqtt connected node=%02x%02x%02x%02x... found=%u lookup_ms=%u connect_ms=%u\n", info.node[0], info.node[1], info.node[2], info.node[3], (unsigned) info.nodes_found, (unsigned) info.lookup_ms, (unsigned) info.connect_ms);
    uv_async_send(&wake);
  } else if (id == MQTT_EVENT_DISCONNECTED) {
    if (connected) printf("MER|mqtt disconnected\n");
    connected = false;
  } else if (id == MQTT_EVENT_DATA && e->current_data_offset == 0) {
    // an invoice from the node we are on: d/<node>/to/<me>/invoice
    char want[200], node_hex[65];
    sodium_bin2hex(node_hex, sizeof(node_hex), node, 32);
    int n = snprintf(want, sizeof(want), "d/%s/to/%s/invoice", node_hex, me);
    if (e->topic_len == n && memcmp(e->topic, want, n) == 0 && e->data_len < (int) sizeof(invoice) && !invoice_pending) {
      memcpy(invoice, e->data, e->data_len);
      invoice[e->data_len] = '\0';
      invoice_pending = true;
      uv_async_send(&wake);
    } else if (e->topic_len != n || memcmp(e->topic, want, n) != 0) {
      printf("MER|mqtt message %.*s: %.*s\n", e->topic_len > 120 ? 120 : e->topic_len, e->topic, e->data_len > 120 ? 120 : e->data_len, e->data);
    }
  }
}

// the mqtt_out task: everything that calls esp-mqtt ---------------------------------------

static void
out_task (void *arg) {
  (void) arg;
  esp_mqtt_client_config_t cfg = {
    .broker.address.hostname = CONFIG_MER_MQTT_NODE,
    .network.transport = transport,
    .network.timeout_ms = 30000,
    .network.reconnect_timeout_ms = 5000,
    .credentials.client_id = me,
    .session.keepalive = 60,
    .buffer.size = 1024,
  };
  client = esp_mqtt_client_init(&cfg);
  esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID, on_event, NULL);
  esp_mqtt_client_start(client);
  printf("MER|mqtt starting, node %s\n", CONFIG_MER_MQTT_NODE);
  out_t o;
  static char reading[MAX_MSG];
  char telemetry[100];
  snprintf(telemetry, sizeof(telemetry), "d/%s/telemetry", me);
  for (;;) {
    if (xQueueReceive(outbox, &o, portMAX_DELAY) != pdTRUE) continue;
    if (o.payload == NULL) { // a reading, attested here rather than on the hdht task
      int len = connected ? attested_reading(reading, sizeof(reading)) : 0;
      if (len > 0 && esp_mqtt_client_publish(client, telemetry, reading, len, 1, 0) >= 0) {
        taskENTER_CRITICAL(&mux);
        own_msgs++;
        own_bytes += (uint64_t) len;
        taskEXIT_CRITICAL(&mux);
      }
      continue;
    }
    if (connected) esp_mqtt_client_publish(client, o.topic, o.payload, o.len, 1, 0);
    free(o.payload);
  }
}

// the hdht task ---------------------------------------------------------------------------

static bool
parse_u64 (const char *json, const char *key, uint64_t *out) {
  char s[24];
  if (!json_str(json, key, s, sizeof(s))) return false;
  char *end;
  unsigned long long v = strtoull(s, &end, 10);
  if (end == s || *end) return false;
  *out = v;
  return true;
}

static void
on_terms (hdht_t *d, int status, uint64_t seq, const uint8_t *value, size_t len, void *data) {
  (void) d;
  (void) seq;
  (void) data;
  terms_busy = false;
  static char json[HDHT_MUTABLE_MAX_VALUE + 1];
  terms_t t = {0};
  if (status != 0 || len >= sizeof(json)) {
    printf("MER|mqtt node terms: none (status %d), not paying it\n", status);
    terms = t;
    return;
  }
  memcpy(json, value, len);
  json[len] = '\0';
  char chain[12], name[32], version[8];
  uint64_t chain_id = 0;
  bool ok = json_str(json, "pay", t.pay_hex, sizeof(t.pay_hex)) && strlen(t.pay_hex) == 42 &&
            json_str(json, "token", t.token, sizeof(t.token)) &&
            json_str(json, "chain_id", chain, sizeof(chain)) && parse_u64(json, "chain_id", &chain_id) &&
            json_str(json, "domain_name", name, sizeof(name)) && json_str(json, "domain_version", version, sizeof(version)) &&
            parse_u64(json, "price_msg", &t.price_msg) && parse_u64(json, "price_kb", &t.price_kb) && parse_u64(json, "credit", &t.credit);
  t.chain_id = (uint32_t) chain_id;
  if (ok) boat_hex_to_bytes(t.pay_hex, t.pay, 20);
  // our token only: the buyer's own domain
  uint32_t our_chain = CONFIG_MER_BUYER_CHAIN_ID ? CONFIG_MER_BUYER_CHAIN_ID : CONFIG_MER_CHAIN_ID;
  bool ours = ok && strcasecmp(t.token, CONFIG_MER_BUYER_VERIFYING_CONTRACT) == 0 && t.chain_id == our_chain &&
              strcmp(name, CONFIG_MER_BUYER_DOMAIN_NAME) == 0 && strcmp(version, CONFIG_MER_BUYER_DOMAIN_VERSION) == 0;
  t.ok = ours;
  terms = t;
  printf("MER|mqtt node terms: %s pay=%s token=%s chain=%u price_msg=%llu price_kb=%llu credit=%llu\n", ours ? "accepted" : (ok ? "REFUSED (not our token or domain)" : "unreadable"), t.pay_hex, t.token, (unsigned) t.chain_id,
         (unsigned long long) t.price_msg, (unsigned long long) t.price_kb, (unsigned long long) t.credit);
}

static void
handle_invoice (const char *json) {
  char pay[43], token[43], number[12];
  uint64_t due = 0, chain = 0;
  if (!json_str(json, "pay", pay, sizeof(pay)) || !json_str(json, "token", token, sizeof(token)) || !parse_u64(json, "due", &due) || !parse_u64(json, "chain_id", &chain) || !json_str(json, "invoice", number, sizeof(number))) {
    printf("MER|mqtt invoice unreadable\n");
    return;
  }
  if (!terms.ok || memcmp(terms_node, node, 32) != 0) {
    printf("MER|mqtt invoice %s: no accepted terms from this node, not paying\n", number);
    return;
  }
  if (strcasecmp(pay, terms.pay_hex) != 0 || strcasecmp(token, terms.token) != 0 || chain != terms.chain_id) {
    printf("MER|mqtt invoice %s REFUSED: payee or token differs from the node's terms\n", number);
    refused_count++;
    return;
  }
  uint64_t owed = own_owed();
  uint64_t mine = owed > own_paid ? owed - own_paid : 0;
  uint64_t payable = due;
  if (payable > mine + terms.credit) payable = mine + terms.credit;
  if (payable > CONFIG_MER_MQTT_MAX_PAY) payable = CONFIG_MER_MQTT_MAX_PAY;
  if (payable == 0) return;
  time_t now = time(NULL);
  if (now < MER_CLOCK_SET) {
    printf("MER|mqtt invoice %s: clock not set yet\n", number);
    return;
  }

  boat_payment_t p = {.valid_after = 0, .valid_before = (uint32_t) now + 3600};
  memcpy(p.to, terms.pay, 20);
  for (int i = 0; i < 8; i++) p.value[31 - i] = (uint8_t) (payable >> (8 * i));
  randombytes_buf(p.nonce, 32);
  uint8_t token_bytes[20], sig[65];
  boat_hex_to_bytes(terms.token, token_bytes, 20);
  int64_t t0 = esp_timer_get_time();
  boat_pay_set_domain_ext(terms.chain_id, token_bytes, CONFIG_MER_BUYER_DOMAIN_NAME, CONFIG_MER_BUYER_DOMAIN_VERSION); // the buyer's own values
  if (boat_pay_authorize(&kp, &p, sig) != BOAT_OK) {
    printf("MER|mqtt invoice %s: signing failed\n", number);
    return;
  }
  long ms = (long) ((esp_timer_get_time() - t0) / 1000);

  char nonce_hex[65], sig_hex[131], body[MAX_MSG], topic[200], node_hex[65];
  boat_bytes_to_hex(p.nonce, 32, nonce_hex);
  boat_bytes_to_hex(sig, 65, sig_hex);
  int n = snprintf(body, sizeof(body), "{\"from\":\"%s\",\"to\":\"%s\",\"value\":\"%llu\",\"validAfter\":0,\"validBefore\":%u,\"nonce\":\"0x%s\",\"signature\":\"0x%s\",\"invoice\":\"%s\"}",
                   kp.eth_addr_hex, terms.pay_hex, (unsigned long long) payable, (unsigned) p.valid_before, nonce_hex, sig_hex, number);
  sodium_bin2hex(node_hex, sizeof(node_hex), node, 32);
  snprintf(topic, sizeof(topic), "d/%s/to/%s/pay", me, node_hex);
  post(topic, body, n);
  own_paid += payable;
  paid_count++;
  printf("MER|mqtt PAID invoice %s: %llu of %llu due (own count %llu, paid %llu, %u payments) sign_ms=%ld%s\n", number, (unsigned long long) payable, (unsigned long long) due,
         (unsigned long long) owed, (unsigned long long) own_paid, (unsigned) paid_count, ms, payable < due ? " DISPUTED: the node asks for more than we counted" : "");
}

static void
on_wake (uv_async_t *h) {
  (void) h;
  if (node_changed) {
    node_changed = false;
    record_set_home(node); // our DID record names the node we are on
    if (memcmp(terms_node, node, 32) != 0 || !terms.ok) {
      memcpy(terms_node, node, 32);
      if (!terms_busy && hdht_mutable_get(&dht, node, 0, on_terms, NULL) == 0) terms_busy = true;
    }
  }
  if (invoice_pending) {
    handle_invoice(invoice);
    invoice_pending = false;
  }
}

void
mqtt_tick (uint32_t ticks) {
  if (!mqtt_enabled() || !connected || ticks % CONFIG_MER_MQTT_INTERVAL_S) return;
  out_t o = {.payload = NULL};
  xQueueSend(outbox, &o, 0);
  if (ticks % (CONFIG_MER_MQTT_INTERVAL_S * 10) == 0) {
    taskENTER_CRITICAL(&mux);
    uint64_t msgs = own_msgs, bytes = own_bytes;
    taskEXIT_CRITICAL(&mux);
    printf("MER|mqtt usage msgs=%llu bytes=%llu owed=%llu paid=%llu\n", (unsigned long long) msgs, (unsigned long long) bytes, (unsigned long long) own_owed(), (unsigned long long) own_paid);
  }
}

void
mqtt_start (void) {
  if (!mqtt_enabled() || transport) return;
  sodium_bin2hex(me, sizeof(me), kp.ed25519_pk, 32);
  uv_async_init(dht.loop, &wake, on_wake);
  transport = hdht_mqtt_transport_new(&dht, NULL);
  outbox = xQueueCreate(8, sizeof(out_t));
  xTaskCreate(out_task, "mqtt_out", 6144, NULL, 3, NULL); // below the hdht task (5)
}
