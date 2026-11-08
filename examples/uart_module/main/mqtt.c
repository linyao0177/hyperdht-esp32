// AT+MQTT*: MQTT over HyperDHT for the host MCU (components/hdht_mqtt).
//
// The module logs in to an MQTT node (packages/boat-mqtt-node) with its DID
// key, so the host needs no broker address, password or certificate.
//
// esp-mqtt must never be called from the hdht task (its task holds its API
// lock while it waits for the hdht task), and AT lines run on the hdht task.
// So mqtt_at() only copies the command into a queue; a worker task of its own
// calls esp-mqtt and writes the reply. esp-mqtt's events come on its task.
// port_printf is safe from any task.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "mqtt_client.h"
#include "nvs.h"

#include "hdht_mqtt.h"
#include "module.h"
#include "port.h"

#define MAX_SUBS    8
#define MAX_PAYLOAD 1024 // per AT+MQTTPUB, and per +MQTTMSG chunk
#define MAX_TOPIC   160

typedef struct {
  char name[16];
  char *args; // heap copy
  bool set, query;
} job_t;

static QueueHandle_t jobs;
static esp_transport_handle_t transport; // made on the hdht task
static esp_mqtt_client_handle_t client;
static SemaphoreHandle_t lock; // target, subs, connected, node
static char target[80];   // network name or node key hex
static char me[65];       // our DID key in hex
static bool started;
static volatile bool connected;
static struct {
  char filter[MAX_TOPIC];
  int qos;
} subs[MAX_SUBS];
static size_t subs_len;
static uint32_t boot; // high 32 bits of signed message sequence numbers
static uint32_t signed_count;

// worker buffers (the worker task only)
static char topic_buf[MAX_TOPIC];
static uint8_t payload[MAX_PAYLOAD];
static uint8_t sealed[MAX_PAYLOAD + HDHT_MQTT_SIGNED_OVERHEAD];
static char hex_out[2 * MAX_PAYLOAD + 1];

static void
ok (void) {
  port_line("OK");
}

static void
error (const char *reason) {
  port_printf("ERROR:%s", reason);
}

// "~/rest" -> "d/<our key>/rest"
static bool
expand (const char *in, size_t in_len, char *out, size_t cap) {
  int n;
  if (in_len >= 2 && in[0] == '~' && in[1] == '/') n = snprintf(out, cap, "d/%s/%.*s", me, (int) (in_len - 2), in + 2);
  else n = snprintf(out, cap, "%.*s", (int) in_len, in);
  return n > 0 && (size_t) n < cap;
}

// esp-mqtt's task -----------------------------------------------------------------

static void
on_event (void *arg, esp_event_base_t base, int32_t id, void *data) {
  (void) arg;
  (void) base;
  esp_mqtt_event_handle_t e = data;
  switch ((esp_mqtt_event_id_t) id) {
  case MQTT_EVENT_CONNECTED: {
    connected = true;
    hdht_mqtt_info_t info;
    hdht_mqtt_get_info(transport, &info);
    char node[65];
    sodium_bin2hex(node, sizeof(node), info.node, 32);
    port_printf("+MQTTCONN:did:mw:%s,%u,%d", node, (unsigned) info.connect_ms, info.relayed);
    // a clean session: subscribe again to what the host asked for
    xSemaphoreTake(lock, portMAX_DELAY);
    for (size_t i = 0; i < subs_len; i++) esp_mqtt_client_subscribe(client, subs[i].filter, subs[i].qos);
    xSemaphoreGive(lock);
    break;
  }
  case MQTT_EVENT_DISCONNECTED:
    if (connected) port_line("+MQTTDISC");
    connected = false;
    break;
  case MQTT_EVENT_SUBSCRIBED:
    port_printf("+MQTTACK:SUB,%d", e->msg_id);
    break;
  case MQTT_EVENT_PUBLISHED:
    port_printf("+MQTTACK:PUB,%d", e->msg_id);
    break;
  case MQTT_EVENT_DATA: {
    // +MQTTMSG:<total>,<offset>,<hex>,<topic>: the topic last, as it may hold commas;
    // a message over the buffer comes in several, the topic only in the first
    static char h[2 * MAX_PAYLOAD + 1];
    int n = e->data_len > MAX_PAYLOAD ? MAX_PAYLOAD : e->data_len;
    sodium_bin2hex(h, sizeof(h), (const uint8_t *) e->data, n);
    port_printf("+MQTTMSG:%d,%d,%s,%.*s", e->total_data_len, e->current_data_offset, h, e->topic_len > MAX_TOPIC ? MAX_TOPIC : e->topic_len, e->topic ? e->topic : "");
    break;
  }
  default:
    break;
  }
}

// the worker task -------------------------------------------------------------------

static void
cmd_conn (const char *args) {
  const char *t = strncmp(args, "did:mw:", 7) == 0 ? args + 7 : args;
  if (*t == '\0' || strlen(t) >= sizeof(target)) {
    error("bad target");
    return;
  }
  if (started) {
    esp_mqtt_client_stop(client); // waits for esp-mqtt's task, up to a connect timeout
    started = false;
    connected = false;
  }
  xSemaphoreTake(lock, portMAX_DELAY);
  snprintf(target, sizeof(target), "%s", t);
  xSemaphoreGive(lock);

  esp_mqtt_client_config_t cfg = {
    .broker.address.hostname = target,
    .network.transport = transport,
    .network.timeout_ms = 30000, // a lookup and a holepunch
    .network.reconnect_timeout_ms = 5000,
    .credentials.client_id = me, // nodes want it to start with our key
    .session.keepalive = 60,
    .buffer.size = MAX_PAYLOAD + 256,
  };
  if (client == NULL) {
    client = esp_mqtt_client_init(&cfg);
    if (client == NULL) {
      error("no memory");
      return;
    }
    esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID, on_event, NULL);
  } else if (esp_mqtt_set_config(client, &cfg) != ESP_OK) {
    error("config");
    return;
  }
  if (esp_mqtt_client_start(client) != ESP_OK) {
    error("start");
    return;
  }
  started = true;
  ok();
}

static void
cmd_close (void) {
  if (started) esp_mqtt_client_stop(client);
  started = false;
  connected = false;
  ok();
}

// <topic>,<qos>,<retain>,<payload>; the topic may not hold commas
static void
cmd_pub (const char *args, char kind) {
  const char *c1 = strchr(args, ',');
  const char *c2 = c1 ? strchr(c1 + 1, ',') : NULL;
  const char *c3 = c2 ? strchr(c2 + 1, ',') : NULL;
  if (c3 == NULL || !expand(args, (size_t) (c1 - args), topic_buf, sizeof(topic_buf))) {
    error("usage: <topic>,<qos>,<retain>,<payload>");
    return;
  }
  int qos = atoi(c1 + 1), retain = atoi(c2 + 1);
  const char *p = c3 + 1;
  int len;
  if (kind == 'H') {
    size_t hl = strlen(p), out = 0;
    if (hl % 2 || hl / 2 > MAX_PAYLOAD || sodium_hex2bin(payload, MAX_PAYLOAD, p, hl, NULL, &out, NULL) != 0) {
      error("bad hex or too long");
      return;
    }
    len = (int) out;
  } else {
    len = (int) strlen(p);
    if (len > MAX_PAYLOAD) {
      error("too long");
      return;
    }
    memcpy(payload, p, len);
  }
  if (qos < 0 || qos > 2) {
    error("bad qos");
    return;
  }
  if (!connected) {
    error("not connected");
    return;
  }
  const uint8_t *out = payload;
  uint64_t seq = 0;
  unsigned sign_us = 0;
  if (kind == 'S') { // signed with the DID key (hdht_mqtt_signed.h)
    seq = ((uint64_t) boot << 32) | ++signed_count;
    int64_t t0 = esp_timer_get_time();
    len = hdht_mqtt_sign(sk, topic_buf, seq, payload, (size_t) len, sealed, sizeof(sealed));
    sign_us = (unsigned) (esp_timer_get_time() - t0);
    if (len < 0) {
      error("sign");
      return;
    }
    out = sealed;
  }
  int id = esp_mqtt_client_publish(client, topic_buf, (const char *) out, len, qos, retain);
  if (id < 0) {
    error("publish failed");
    return;
  }
  if (kind == 'S') port_printf("+MQTTPUB:%d,%llu,%u", id, (unsigned long long) seq, sign_us);
  else port_printf("+MQTTPUB:%d", id);
  ok();
}

// <filter>,<qos>
static void
cmd_sub (const char *args, bool unsub) {
  const char *comma = strchr(args, ',');
  size_t flen = comma ? (size_t) (comma - args) : strlen(args);
  char filter[MAX_TOPIC];
  if (flen == 0 || !expand(args, flen, filter, sizeof(filter))) {
    error("bad filter");
    return;
  }
  int qos = comma ? atoi(comma + 1) : 0;
  xSemaphoreTake(lock, portMAX_DELAY);
  size_t i = 0;
  while (i < subs_len && strcmp(subs[i].filter, filter) != 0) i++;
  if (unsub) {
    if (i < subs_len) subs[i] = subs[--subs_len];
  } else if (i == subs_len) {
    if (subs_len == MAX_SUBS) {
      xSemaphoreGive(lock);
      error("too many subscriptions");
      return;
    }
    snprintf(subs[subs_len].filter, MAX_TOPIC, "%s", filter);
    subs[subs_len++].qos = qos;
  } else {
    subs[i].qos = qos;
  }
  xSemaphoreGive(lock);
  // kept for the next connect when not connected now
  if (connected) {
    int id = unsub ? esp_mqtt_client_unsubscribe(client, filter) : esp_mqtt_client_subscribe(client, filter, qos);
    port_printf("+MQTTSUB:%d", id);
  }
  ok();
}

static void
cmd_status (void) {
  hdht_mqtt_info_t info = {0};
  if (transport) hdht_mqtt_get_info(transport, &info);
  sodium_bin2hex(hex_out, sizeof(hex_out), info.node, 32);
  xSemaphoreTake(lock, portMAX_DELAY);
  port_printf("+MQTTSTATE:%d,%s,%s%s,%u,%d,%u,%u", connected, target, connected ? "did:mw:" : "", connected ? hex_out : "", (unsigned) info.nodes_found, info.error, (unsigned) info.connects, (unsigned) subs_len);
  xSemaphoreGive(lock);
  ok();
}

static void
worker (void *arg) {
  (void) arg;
  job_t j;
  for (;;) {
    if (xQueueReceive(jobs, &j, portMAX_DELAY) != pdTRUE) continue;
    const char *a = j.args ? j.args : "";
    if (transport == NULL) error("DHT not ready");
    else if (strcmp(j.name, "AT+MQTTCONN") == 0 && j.query) cmd_status();
    else if (strcmp(j.name, "AT+MQTTCONN") == 0 && j.set) cmd_conn(a);
    else if (strcmp(j.name, "AT+MQTTCLOSE") == 0) cmd_close();
    else if (strcmp(j.name, "AT+MQTTPUB") == 0 && j.set) cmd_pub(a, 'H');
    else if (strcmp(j.name, "AT+MQTTPUBT") == 0 && j.set) cmd_pub(a, 'T');
    else if (strcmp(j.name, "AT+MQTTPUBS") == 0 && j.set) cmd_pub(a, 'S');
    else if (strcmp(j.name, "AT+MQTTSUB") == 0 && j.set) cmd_sub(a, false);
    else if (strcmp(j.name, "AT+MQTTUNSUB") == 0 && j.set) cmd_sub(a, true);
    else error("unknown command");
    free(j.args);
  }
}

// the hdht task -----------------------------------------------------------------------

bool
mqtt_at (const char *name, const char *args, bool set, bool query) {
  if (strncmp(name, "AT+MQTT", 7) != 0) return false;
  job_t j = {.set = set, .query = query};
  snprintf(j.name, sizeof(j.name), "%s", name);
  j.args = strdup(args);
  if (j.args == NULL || xQueueSend(jobs, &j, 0) != pdTRUE) {
    free(j.args);
    error("busy");
  }
  return true;
}

void
mqtt_init (void) {
  sodium_bin2hex(me, sizeof(me), pk, 32);
  lock = xSemaphoreCreateMutex();
  jobs = xQueueCreate(4, sizeof(job_t));

  // signed messages: a boot counter keeps sequence numbers rising across restarts
  nvs_handle_t nvs;
  if (nvs_open("module", NVS_READWRITE, &nvs) == ESP_OK) {
    nvs_get_u32(nvs, "mqtt_boot", &boot);
    boot++;
    nvs_set_u32(nvs, "mqtt_boot", boot);
    nvs_commit(nvs);
    nvs_close(nvs);
  }
  xTaskCreate(worker, "mqtt_at", 4096, NULL, 4, NULL);
}

void
mqtt_dht_ready (void) {
  if (transport == NULL) transport = hdht_mqtt_transport_new(&dht, NULL);
}
