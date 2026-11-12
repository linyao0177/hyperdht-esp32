// hdht_mqtt: an esp_transport over HyperDHT (see include/hdht_mqtt.h).
//
// Two tasks share a context:
// - esp-mqtt's task calls connect/read/write/poll/close/destroy. It never
//   touches hdht: it sets a command bit, wakes the hdht loop with
//   uv_async_send, and waits on the event group.
// - the hdht task runs the commands and the stream callbacks. Bytes from the
//   node go into the rx stream buffer, bytes for the node come out of the tx
//   one. Each buffer has one writer task and one reader task, as FreeRTOS
//   stream buffers need.

#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/stream_buffer.h"
#include "freertos/task.h"
#include <sodium.h>

#include "hdht_mqtt.h"

static const char *TAG = "hdht_mqtt";

#define CLOSE_GRACE_MS 2000 // after hdht_stream_end, destroy the stream if it has not closed
#define CLOSE_WAIT_MS  (CLOSE_GRACE_MS + 1000)
#define PREFER_AGAIN_MS (10 * 60 * 1000) // on another node than the preferred one: try it again after this
#define WRITE_CHUNK    1024 // one encrypted message on the stream

// event bits, set on the hdht task
#define EV_OPEN      BIT0 // the stream is open
#define EV_CLOSED    BIT1 // the connection ended, or the attempt failed
#define EV_IDLE      BIT2 // no stream in use: a connect may start
#define EV_RX        BIT3 // bytes arrived in rx
#define EV_DESTROYED BIT4 // the loop handles are closed

// commands, set by the esp-mqtt task
#define CMD_CONNECT BIT0
#define CMD_CLOSE   BIT1
#define CMD_WRITE   BIT2
#define CMD_DESTROY BIT3

typedef enum {
  S_IDLE,
  S_LOOKUP,
  S_CONNECTING, // dialing candidates[next - 1], or waiting to dial the next one
  S_OPEN,
  S_CLOSING,
} state_t;

typedef struct {
  hdht_t *dht;
  TaskHandle_t loop_task;
  uv_async_t async;
  uv_timer_t timer; // next candidate, or the close grace period
  uint8_t handles; // open uv handles

  StreamBufferHandle_t rx, tx;
  size_t tx_size;
  EventGroupHandle_t ev;
  uint32_t cmd; // CMD_* bits, atomic

  // the connect request, written by the esp-mqtt task before CMD_CONNECT
  bool by_key;
  uint8_t key[32];
  uint8_t topic[32];
  int64_t started_us;

  // hdht task only
  state_t state;
  uint8_t candidates[HDHT_LOOKUP_MAX_PEERS][32];
  size_t candidates_len, next;
  hdht_stream_t stream;
  uint8_t lost[32]; // the node of the last open connection: tried last next time
  bool has_lost;
  uint8_t listed[HDHT_MQTT_NODELIST_PAGE][32]; // hdht_mqtt_transport_set_nodes
  size_t listed_len;
  uint8_t preferred[32]; // hdht_mqtt_transport_prefer
  bool has_preferred;
  int64_t off_preferred_us; // open to another node since then, the preferred one a candidate; 0: no
  bool destroy_pending;
  bool free_on_destroyed; // destroyed from the hdht task itself: nobody waits
  uint8_t chunk[WRITE_CHUNK];

  hdht_mqtt_info_t info;
} ctx_t;

static void
command (ctx_t *c, uint32_t bits) {
  __atomic_fetch_or(&c->cmd, bits, __ATOMIC_SEQ_CST);
  uv_async_send(&c->async);
}

static void
free_ctx (ctx_t *c) {
  vStreamBufferDelete(c->rx);
  vStreamBufferDelete(c->tx);
  vEventGroupDelete(c->ev);
  free(c);
}

// hdht task --------------------------------------------------------------

static void
on_handle_closed (uv_handle_t *h) {
  ctx_t *c = h->data;
  if (--c->handles) return;
  if (c->free_on_destroyed) free_ctx(c);
  else xEventGroupSetBits(c->ev, EV_DESTROYED);
}

static void
close_handles (ctx_t *c) {
  uv_timer_stop(&c->timer);
  uv_close((uv_handle_t *) &c->async, on_handle_closed);
  uv_close((uv_handle_t *) &c->timer, on_handle_closed);
}

static void
become_idle (ctx_t *c, int error) {
  c->state = S_IDLE;
  c->info.error = error;
  uv_timer_stop(&c->timer);
  xEventGroupClearBits(c->ev, EV_OPEN);
  xEventGroupSetBits(c->ev, EV_CLOSED | EV_IDLE | EV_RX);
  if (c->destroy_pending) {
    c->destroy_pending = false;
    close_handles(c);
  }
}

static void dial_next (ctx_t *c);

static void
on_retry (uv_timer_t *t) {
  ctx_t *c = t->data;
  if (c->state == S_CONNECTING) dial_next(c);
  else if (c->state == S_CLOSING) hdht_stream_destroy(&c->stream, HDHT_STREAM_ECLOSED); // the grace period ran out
}

static void
on_open (hdht_stream_t *s) {
  ctx_t *c = s->data;
  c->state = S_OPEN;
  c->info.connects++;
  c->info.error = 0;
  c->info.relayed = s->relay != NULL;
  c->info.connect_ms = (uint32_t) ((esp_timer_get_time() - c->started_us) / 1000);
  memcpy(c->info.node, s->remote_public_key, 32);
  c->off_preferred_us = 0;
  for (size_t i = 0; c->has_preferred && memcmp(s->remote_public_key, c->preferred, 32) != 0 && i < c->candidates_len; i++) {
    if (memcmp(c->candidates[i], c->preferred, 32) == 0) c->off_preferred_us = esp_timer_get_time();
  }
  ESP_LOGI(TAG, "open to node %02x%02x%02x%02x... in %u ms%s", s->remote_public_key[0], s->remote_public_key[1], s->remote_public_key[2], s->remote_public_key[3], (unsigned) c->info.connect_ms, c->info.relayed ? " (relayed)" : "");
  xEventGroupSetBits(c->ev, EV_OPEN);
}

static void
on_data (hdht_stream_t *s, const uint8_t *data, size_t len) {
  ctx_t *c = s->data;
  size_t n = xStreamBufferSend(c->rx, data, len, 0);
  xEventGroupSetBits(c->ev, EV_RX);
  if (n < len) {
    // esp-mqtt fell behind by a whole buffer: drop the connection rather
    // than a part of an MQTT packet (it reconnects)
    ESP_LOGW(TAG, "rx buffer full, closing");
    hdht_stream_destroy(s, HDHT_STREAM_ENOMEM);
  }
}

static void
on_close (hdht_stream_t *s, int error) {
  ctx_t *c = s->data;
  if (c->state == S_CONNECTING && c->next < c->candidates_len) {
    // that node did not answer: the next one, once the stream has let go
    const uint8_t *k = c->candidates[c->next - 1];
    ESP_LOGI(TAG, "node %zu of %zu (%02x%02x%02x%02x...) failed (%d), trying the next", c->next, c->candidates_len, k[0], k[1], k[2], k[3], error);
    c->info.error = error;
    uv_timer_start(&c->timer, on_retry, 0, 0);
    return;
  }
  if (c->state == S_CONNECTING) ESP_LOGW(TAG, "could not connect to %02x%02x%02x%02x... (%d)", c->info.node[0], c->info.node[1], c->info.node[2], c->info.node[3], error);
  else if (c->state == S_OPEN) ESP_LOGI(TAG, "closed by the node or the network (%d)", error);
  if (c->state == S_OPEN || c->state == S_CLOSING) {
    // its announcement outlives it on the DHT for up to 20 minutes
    memcpy(c->lost, s->remote_public_key, 32);
    c->has_lost = true;
  }
  become_idle(c, error);
}

static void
dial_next (ctx_t *c) {
  while (c->next < c->candidates_len) {
    const uint8_t *key = c->candidates[c->next++];
    memset(&c->stream, 0, sizeof(c->stream));
    if (hdht_connect(c->dht, &c->stream, key, on_open, on_data, on_close, c) == 0) {
      memcpy(c->info.node, key, 32);
      c->state = S_CONNECTING;
      return;
    }
  }
  ESP_LOGW(TAG, "no node to connect to");
  become_idle(c, HDHT_CONNECT_EPEER_NOT_FOUND);
}

// random order, spreading devices over nodes; the node we just lost goes
// last, and the preferred one (when it is a candidate and not just lost) first
static void
order_candidates (ctx_t *c) {
  for (size_t i = c->candidates_len; i > 1; i--) {
    size_t j = randombytes_uniform((uint32_t) i);
    uint8_t tmp[32];
    memcpy(tmp, c->candidates[i - 1], 32);
    memcpy(c->candidates[i - 1], c->candidates[j], 32);
    memcpy(c->candidates[j], tmp, 32);
  }
  for (size_t i = 0; c->has_lost && i + 1 < c->candidates_len; i++) {
    if (memcmp(c->candidates[i], c->lost, 32) != 0) continue;
    uint8_t tmp[32];
    memcpy(tmp, c->candidates[i], 32);
    memmove(c->candidates[i], c->candidates[i + 1], (c->candidates_len - i - 1) * 32);
    memcpy(c->candidates[c->candidates_len - 1], tmp, 32);
    break;
  }
  if (!c->has_preferred || (c->has_lost && memcmp(c->preferred, c->lost, 32) == 0)) return;
  for (size_t i = 1; i < c->candidates_len; i++) {
    if (memcmp(c->candidates[i], c->preferred, 32) != 0) continue;
    memmove(c->candidates[1], c->candidates[0], i * 32);
    memcpy(c->candidates[0], c->preferred, 32);
    break;
  }
}

static void
on_lookup (hdht_t *dht, int status, const uint8_t (*peers)[32], size_t len, void *data) {
  (void) dht;
  ctx_t *c = data;
  // an attempt given up during its lookup: the reply finds S_IDLE. (If a new
  // lookup already started, this reply serves it: the same network's nodes.)
  if (c->state != S_LOOKUP) return;
  c->info.lookup_ms = (uint32_t) ((esp_timer_get_time() - c->started_us) / 1000);
  c->info.nodes_found = len;
  ESP_LOGI(TAG, "lookup: %u node(s) in %u ms (status %d)", (unsigned) len, (unsigned) c->info.lookup_ms, status);

  c->candidates_len = len < HDHT_LOOKUP_MAX_PEERS ? len : HDHT_LOOKUP_MAX_PEERS;
  memcpy(c->candidates, peers, c->candidates_len * 32);
  order_candidates(c);
  c->next = 0;
  dial_next(c);
}

static void
start_connect (ctx_t *c) {
  if (c->state != S_IDLE) { // esp-mqtt waits for EV_IDLE first, so this is a bug
    xEventGroupSetBits(c->ev, EV_CLOSED);
    return;
  }
  c->info.nodes_found = 0;
  c->info.lookup_ms = 0;
  c->info.relayed = false;
  if (c->by_key) {
    memcpy(c->candidates[0], c->key, 32);
    c->candidates_len = 1;
    c->next = 0;
    dial_next(c);
    return;
  }
  if (c->listed_len > 0) { // the node list: no lookup
    size_t n = c->listed_len < HDHT_LOOKUP_MAX_PEERS ? c->listed_len : HDHT_LOOKUP_MAX_PEERS;
    memcpy(c->candidates, c->listed, n * 32);
    c->candidates_len = n;
    order_candidates(c);
    c->next = 0;
    dial_next(c);
    return;
  }
  c->state = S_LOOKUP;
  if (hdht_lookup(c->dht, c->topic, on_lookup, c) != 0) become_idle(c, HDHT_CONNECT_ENOMEM);
}

static void
abort_connection (ctx_t *c) {
  switch (c->state) {
  case S_IDLE:
  case S_CLOSING:
    break;
  case S_LOOKUP:
    become_idle(c, HDHT_STREAM_ECLOSED); // the lookup reply finds S_IDLE and is dropped
    break;
  case S_CONNECTING:
    c->candidates_len = c->next; // no further candidates
    if (uv_is_active((uv_handle_t *) &c->timer)) become_idle(c, HDHT_STREAM_ECLOSED); // between two dials
    else hdht_stream_destroy(&c->stream, HDHT_STREAM_ECLOSED);
    break;
  case S_OPEN:
    c->state = S_CLOSING;
    if (hdht_stream_end(&c->stream) != 0) hdht_stream_destroy(&c->stream, HDHT_STREAM_ECLOSED);
    else uv_timer_start(&c->timer, on_retry, CLOSE_GRACE_MS, 0);
    break;
  }
}

static void
flush_tx (ctx_t *c) {
  size_t n;
  while ((n = xStreamBufferReceive(c->tx, c->chunk, sizeof(c->chunk), 0)) > 0) {
    if (c->state != S_OPEN) continue; // closing: drop it
    if (hdht_stream_write(&c->stream, c->chunk, n) != 0) {
      hdht_stream_destroy(&c->stream, HDHT_STREAM_ECLOSED);
      return;
    }
  }
}

static void
on_command (uv_async_t *h) {
  ctx_t *c = h->data;
  uint32_t cmd = __atomic_exchange_n(&c->cmd, 0, __ATOMIC_SEQ_CST);
  if (cmd & CMD_WRITE) flush_tx(c);
  // on another node than the preferred one (it failed when dialed): leave
  // it now and then (esp-mqtt writes at least once a keepalive), so the
  // next connect tries the preferred one first again
  if (c->state == S_OPEN && c->off_preferred_us && esp_timer_get_time() - c->off_preferred_us > PREFER_AGAIN_MS * 1000LL) {
    ESP_LOGI(TAG, "back to the preferred node");
    c->off_preferred_us = 0;
    abort_connection(c);
  }
  if (cmd & (CMD_CLOSE | CMD_DESTROY)) abort_connection(c);
  if (cmd & CMD_DESTROY) {
    if (c->state == S_IDLE) close_handles(c);
    else c->destroy_pending = true;
    return;
  }
  if (cmd & CMD_CONNECT) start_connect(c);
}

// esp-mqtt task ---------------------------------------------------------------

static ctx_t *
ctx_of (esp_transport_handle_t t) {
  return esp_transport_get_context_data(t);
}

static TickType_t
ticks (int ms) {
  return ms <= 0 ? 0 : pdMS_TO_TICKS(ms) + 1;
}

static bool
parse_key (const char *host, uint8_t key[32]) {
  if (host == NULL || strlen(host) != 64) return false;
  size_t len = 0;
  return sodium_hex2bin(key, 32, host, 64, NULL, &len, NULL) == 0 && len == 32;
}

static int
t_connect (esp_transport_handle_t t, const char *host, int port, int timeout_ms) {
  (void) port;
  ctx_t *c = ctx_of(t);
  int64_t deadline = esp_timer_get_time() + (int64_t) timeout_ms * 1000;

  // the last connection must have let go of the stream
  if (!(xEventGroupWaitBits(c->ev, EV_IDLE, pdFALSE, pdTRUE, ticks(CLOSE_WAIT_MS)) & EV_IDLE)) {
    ESP_LOGE(TAG, "the last connection is still closing");
    return -1;
  }
  xStreamBufferReset(c->rx);
  xStreamBufferReset(c->tx);
  c->by_key = parse_key(host, c->key);
  if (!c->by_key) hdht_mqtt_topic(host ? host : "", c->topic);
  c->started_us = esp_timer_get_time();
  xEventGroupClearBits(c->ev, EV_OPEN | EV_CLOSED | EV_IDLE | EV_RX);
  command(c, CMD_CONNECT);

  int left = (int) ((deadline - esp_timer_get_time()) / 1000);
  EventBits_t bits = xEventGroupWaitBits(c->ev, EV_OPEN | EV_CLOSED, pdFALSE, pdFALSE, ticks(left));
  if ((bits & EV_OPEN) && !(bits & EV_CLOSED)) return 0;
  if (!(bits & EV_CLOSED)) {
    ESP_LOGW(TAG, "connect timed out after %d ms", timeout_ms);
    command(c, CMD_CLOSE);
  }
  return -1;
}

// Waits for bytes, or for the end. Returns >0 with bytes in rx, 0 on timeout,
// -1 when closed and nothing is left.
static int
wait_rx (ctx_t *c, int timeout_ms) {
  int64_t deadline = esp_timer_get_time() + (int64_t) (timeout_ms < 0 ? 0 : timeout_ms) * 1000;
  for (;;) {
    xEventGroupClearBits(c->ev, EV_RX);
    if (xStreamBufferBytesAvailable(c->rx) > 0) return 1;
    EventBits_t bits = xEventGroupGetBits(c->ev);
    if ((bits & EV_CLOSED) || !(bits & EV_OPEN)) return xStreamBufferBytesAvailable(c->rx) > 0 ? 1 : -1;
    int left = (int) ((deadline - esp_timer_get_time()) / 1000);
    if (left <= 0) return 0;
    xEventGroupWaitBits(c->ev, EV_RX | EV_CLOSED, pdFALSE, pdFALSE, ticks(left));
  }
}

static int
t_read (esp_transport_handle_t t, char *buffer, int len, int timeout_ms) {
  ctx_t *c = ctx_of(t);
  int r = wait_rx(c, timeout_ms);
  if (r < 0) return ERR_TCP_TRANSPORT_CONNECTION_CLOSED_BY_FIN;
  if (r == 0) return ERR_TCP_TRANSPORT_CONNECTION_TIMEOUT;
  return (int) xStreamBufferReceive(c->rx, buffer, len, 0);
}

static int
t_poll_read (esp_transport_handle_t t, int timeout_ms) {
  return wait_rx(ctx_of(t), timeout_ms);
}

static int
t_poll_write (esp_transport_handle_t t, int timeout_ms) {
  (void) timeout_ms;
  EventBits_t bits = xEventGroupGetBits(ctx_of(t)->ev);
  return (bits & EV_OPEN) && !(bits & EV_CLOSED) ? 1 : -1;
}

static int
t_write (esp_transport_handle_t t, const char *buffer, int len, int timeout_ms) {
  ctx_t *c = ctx_of(t);
  int64_t deadline = esp_timer_get_time() + (int64_t) (timeout_ms < 0 ? 0 : timeout_ms) * 1000;
  int done = 0;
  while (done < len) {
    if (t_poll_write(t, 0) < 0) return done > 0 ? done : -1;
    size_t chunk = (size_t) (len - done);
    if (chunk > c->tx_size / 2) chunk = c->tx_size / 2; // the hdht task drains as we go
    int left = (int) ((deadline - esp_timer_get_time()) / 1000);
    size_t n = xStreamBufferSend(c->tx, buffer + done, chunk, ticks(left));
    if (n > 0) command(c, CMD_WRITE);
    done += (int) n;
    if (n < chunk) break; // timed out
  }
  return done;
}

static int
t_close (esp_transport_handle_t t) {
  ctx_t *c = ctx_of(t);
  if (xEventGroupGetBits(c->ev) & EV_IDLE) return 0;
  command(c, CMD_CLOSE);
  xEventGroupWaitBits(c->ev, EV_IDLE, pdFALSE, pdTRUE, ticks(CLOSE_WAIT_MS));
  return 0;
}

static int
t_destroy (esp_transport_handle_t t) {
  ctx_t *c = ctx_of(t);
  if (c == NULL) return 0;
  esp_transport_set_context_data(t, NULL);
  if (xTaskGetCurrentTaskHandle() == c->loop_task) {
    // on the hdht task: we cannot wait for the loop, so it frees c when done
    c->free_on_destroyed = true;
    c->cmd = 0;
    abort_connection(c);
    if (c->state == S_IDLE) close_handles(c);
    else c->destroy_pending = true;
    return 0;
  }
  command(c, CMD_DESTROY);
  if (xEventGroupWaitBits(c->ev, EV_DESTROYED, pdFALSE, pdTRUE, ticks(CLOSE_WAIT_MS * 2)) & EV_DESTROYED) {
    free_ctx(c);
  } else {
    ESP_LOGE(TAG, "the hdht task did not let go of the transport; leaking it");
  }
  return 0;
}

// public ----------------------------------------------------------------------

void
hdht_mqtt_topic (const char *network, uint8_t topic[32]) {
  crypto_generichash(topic, 32, (const uint8_t *) network, strlen(network), NULL, 0);
}

void
hdht_mqtt_get_info (esp_transport_handle_t t, hdht_mqtt_info_t *info) {
  ctx_t *c = ctx_of(t);
  if (c) *info = c->info;
  else memset(info, 0, sizeof(*info));
}

esp_transport_handle_t
hdht_mqtt_transport_new (hdht_t *dht, const hdht_mqtt_config_t *config) {
  size_t rx_size = config && config->rx_buffer ? config->rx_buffer : 4096;
  size_t tx_size = config && config->tx_buffer ? config->tx_buffer : 2048;

  ctx_t *c = calloc(1, sizeof(ctx_t));
  if (c == NULL) return NULL;
  c->dht = dht;
  c->loop_task = xTaskGetCurrentTaskHandle();
  c->tx_size = tx_size;
  c->state = S_IDLE;
  c->rx = xStreamBufferCreate(rx_size, 1);
  c->tx = xStreamBufferCreate(tx_size, 1);
  c->ev = xEventGroupCreate();
  esp_transport_handle_t t = esp_transport_init();
  if (c->rx == NULL || c->tx == NULL || c->ev == NULL || t == NULL) goto fail;

  uv_loop_t *loop = dht->loop;
  if (uv_async_init(loop, &c->async, on_command) != 0) goto fail;
  if (uv_timer_init(loop, &c->timer) != 0) {
    uv_close((uv_handle_t *) &c->async, NULL); // still referenced by the loop: leak c, this does not happen
    esp_transport_destroy(t);
    return NULL;
  }
  c->async.data = c;
  c->timer.data = c;
  c->handles = 2;
  xEventGroupSetBits(c->ev, EV_IDLE);

  esp_transport_set_context_data(t, c);
  esp_transport_set_func(t, t_connect, t_read, t_write, t_close, t_poll_read, t_poll_write, t_destroy);
  esp_transport_set_default_port(t, 1883);
  return t;

fail:
  if (t) esp_transport_destroy(t);
  if (c->rx) vStreamBufferDelete(c->rx);
  if (c->tx) vStreamBufferDelete(c->tx);
  if (c->ev) vEventGroupDelete(c->ev);
  free(c);
  return NULL;
}

void
hdht_mqtt_transport_set_nodes (esp_transport_handle_t t, const uint8_t (*nodes)[32], size_t n) {
  ctx_t *c = ctx_of(t);
  if (n > HDHT_MQTT_NODELIST_PAGE) n = HDHT_MQTT_NODELIST_PAGE;
  if (n) memcpy(c->listed, nodes, n * 32);
  c->listed_len = n;
}

void
hdht_mqtt_transport_prefer (esp_transport_handle_t t, const uint8_t key[32]) {
  ctx_t *c = ctx_of(t);
  if (key) memcpy(c->preferred, key, 32);
  c->has_preferred = key != NULL;
}

// ---- the node list: the trusted verifiers' records, tallied ----

typedef struct fetch_s fetch_t;

typedef struct {
  fetch_t *f;
  size_t i;
} fetch_slot_t;

struct fetch_s {
  hdht_t *dht;
  size_t n, left;
  uint32_t pick;
  uint8_t tries; // pages tried
  size_t votes;
  hdht_mqtt_nodelist_cb cb;
  void *data;
  uint8_t *blobs[HDHT_MQTT_NODELIST_VERIFIERS];
  size_t lens[HDHT_MQTT_NODELIST_VERIFIERS];
  fetch_slot_t slots[HDHT_MQTT_NODELIST_VERIFIERS];
  hdht_mqtt_nodelist_t list;
};

static void
fetch_free (fetch_t *f) {
  for (size_t i = 0; i < f->n; i++) free(f->blobs[i]);
  free(f);
}

static void fetch_page (fetch_t *f);

static void
on_page (hdht_t *dht, int status, const uint8_t *value, size_t len, void *data) {
  (void) dht;
  fetch_t *f = data;
  uint8_t index = (uint8_t) ((f->pick + f->tries - 1) % f->list.pages_len);
  if (status == 0 && hdht_mqtt_nodelist_decode_page(value, len, index, &f->list) == 0) {
    f->cb(0, &f->list, f->votes, f->data);
    fetch_free(f);
    return;
  }
  fetch_page(f);
}

static void
fetch_page (fetch_t *f) {
  if (f->tries >= f->list.pages_len) {
    f->cb(-1, NULL, 0, f->data);
    fetch_free(f);
    return;
  }
  uint8_t index = (uint8_t) ((f->pick + f->tries) % f->list.pages_len);
  f->tries++;
  if (hdht_immutable_get(f->dht, f->list.pages[index], on_page, f) != 0) fetch_page(f);
}

static void
fetch_done (fetch_t *f) {
  size_t votes = 0;
  if (hdht_mqtt_nodelist_tally((const uint8_t *const *) f->blobs, f->lens, f->n, f->n, &f->list, &votes) != 0) {
    f->cb(-1, NULL, 0, f->data);
    fetch_free(f);
    return;
  }
  f->votes = votes;
  if (f->list.pages_len == 0) { // a list with no nodes
    f->cb(0, &f->list, votes, f->data);
    fetch_free(f);
    return;
  }
  fetch_page(f);
}

static void
on_list_record (hdht_t *dht, int status, uint64_t seq, const uint8_t *value, size_t len, void *data) {
  (void) dht;
  (void) seq;
  fetch_slot_t *s = data;
  fetch_t *f = s->f;
  if (status == 0) {
    uint8_t *b = malloc(HDHT_MUTABLE_MAX_VALUE);
    int n = b ? hdht_mqtt_nodelist_from_record(value, len, b, HDHT_MUTABLE_MAX_VALUE) : -1;
    if (n > 0) {
      f->blobs[s->i] = b;
      f->lens[s->i] = (size_t) n;
    } else {
      free(b);
    }
  }
  if (--f->left == 0) fetch_done(f);
}

int
hdht_mqtt_nodelist_fetch (hdht_t *dht, const uint8_t (*trusted)[32], size_t n, uint32_t pick, hdht_mqtt_nodelist_cb cb, void *data) {
  if (n == 0 || n > HDHT_MQTT_NODELIST_VERIFIERS) return -1;
  fetch_t *f = calloc(1, sizeof(*f));
  if (f == NULL) return -1;
  f->dht = dht;
  f->n = n;
  f->left = n;
  f->pick = pick;
  f->cb = cb;
  f->data = data;
  size_t failed = 0;
  for (size_t i = 0; i < n; i++) {
    f->slots[i] = (fetch_slot_t) { f, i };
    if (hdht_mutable_get(dht, trusted[i], 0, on_list_record, &f->slots[i]) != 0) failed++;
  }
  // the ones that could not start count as answered with nothing
  if (failed) {
    f->left -= failed;
    if (f->left == 0) fetch_done(f);
  }
  return 0;
}
