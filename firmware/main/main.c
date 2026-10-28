// hdht on the ESP32-C3, phase 1: bootstrap, then connect to a HyperDHT
// server by public key a few times and check the echo. Results are printed
// as "HDHT|..." lines.

#include <stdio.h>
#include <string.h>

#include "esp_heap_caps.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "protocol_examples_common.h"
#include "sdkconfig.h"

#include "hdht.h"
#include "hdht_ble.h"

static const char MESSAGE[] = "hello from esp32-c3";

static uv_loop_t loop;
static hdht_t dht;
static hdht_stream_t stream;
static uv_timer_t round_timer;
static uint8_t server_key[32];
static int round_no = 0;
static int64_t round_started;
static size_t heap_before;
static bool echoed;

static hdht_server_t server;
static int served = 0;

static void
start_round (uv_timer_t *timer);

static void
start_server (void);

static void
on_destroyed (hdht_t *d) {
  (void) d;
  uv_close((uv_handle_t *) &round_timer, NULL);
}

static uint32_t
ms_since (int64_t start) {
  return (uint32_t) ((esp_timer_get_time() - start) / 1000);
}

static void
on_open (hdht_stream_t *s) {
  printf("HDHT|open|round=%d|ms=%lu|remote=%s|puncher_socket=%d\n", round_no, (unsigned long) ms_since(round_started), hdht_addr_str(&s->remote_addr), s->socket != &dht.socket);
  hdht_stream_write(s, (const uint8_t *) MESSAGE, sizeof(MESSAGE) - 1);
}

static void
on_data (hdht_stream_t *s, const uint8_t *data, size_t len) {
  echoed = len == sizeof(MESSAGE) - 1 && memcmp(data, MESSAGE, len) == 0;
  printf("HDHT|echo|round=%d|ok=%d|ms=%lu\n", round_no, echoed, (unsigned long) ms_since(round_started));
  hdht_stream_destroy(s, 0);
}

static void
on_close (hdht_stream_t *s, int error) {
  // read the local minimum before stopping the monitor, which restores the global one
  size_t low = heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT);
  heap_caps_monitor_local_minimum_free_size_stop();
  printf("HDHT|connect|round=%d|ok=%d|error=%d|ms=%lu|heap_before=%u|heap_low=%u|heap_after=%u|bytes_in=%llu|bytes_out=%llu\n",
         round_no, echoed, error, (unsigned long) ms_since(round_started),
         (unsigned) heap_before, (unsigned) low, (unsigned) heap_caps_get_free_size(MALLOC_CAP_8BIT),
         (unsigned long long) s->stats.bytes_in, (unsigned long long) s->stats.bytes_out);

  if (round_no < CONFIG_HDHT_CONNECT_ROUNDS) {
    uv_timer_start(&round_timer, start_round, CONFIG_HDHT_ROUND_INTERVAL_MS, 0);
    return;
  }

  start_server();
}

static void
print_dht_stats (void) {
  printf("HDHT|dht|table=%u|requests=%lu|responses=%lu|timeouts=%lu|retries=%lu\n", dht.table_len,
         (unsigned long) dht.stats.requests, (unsigned long) dht.stats.responses, (unsigned long) dht.stats.timeouts, (unsigned long) dht.stats.retries);
}

// phase 2: accept connections and echo

static void
on_server_closed (hdht_server_t *s) {
  printf("HDHT|server_closed|announces=%lu|handshakes=%lu|connections=%lu|punches=%lu|served=%d|heap=%u\n",
         (unsigned long) s->stats.announces, (unsigned long) s->stats.handshakes, (unsigned long) s->stats.connections, (unsigned long) s->stats.punches,
         served, (unsigned) heap_caps_get_free_size(MALLOC_CAP_8BIT));
  print_dht_stats();
  hdht_destroy(&dht, on_destroyed);
}

static void
on_serve_timeout (uv_timer_t *timer) {
  (void) timer;
  hdht_server_close(&server, on_server_closed);
}

static void
on_server_data (hdht_stream_t *s, const uint8_t *data, size_t len) {
  hdht_stream_write(s, data, len);
}

static void
on_server_stream_close (hdht_stream_t *s, int error) {
  printf("HDHT|served|n=%d|error=%d|bytes_in=%llu|bytes_out=%llu|heap=%u\n", served, error,
         (unsigned long long) s->stats.bytes_in, (unsigned long long) s->stats.bytes_out, (unsigned) heap_caps_get_free_size(MALLOC_CAP_8BIT));
}

static void
on_connection (hdht_server_t *s, hdht_stream_t *stream) {
  (void) s;
  served++;
  printf("HDHT|connection|n=%d|remote=%s|puncher_socket=%d|heap=%u\n", served, hdht_addr_str(&stream->remote_addr), stream->owned_socket != NULL, (unsigned) heap_caps_get_free_size(MALLOC_CAP_8BIT));
  stream->on_data = on_server_data;
  stream->on_close = on_server_stream_close;
}

static void
on_listening (hdht_server_t *s, int status) {
  char hex[65];
  sodium_bin2hex(hex, sizeof(hex), s->public_key, 32);
  printf("HDHT|listening|status=%d|relays=%u|key=%s|ms=%lu|heap=%u\n", status, s->relays_len, hex, (unsigned long) ms_since(round_started), (unsigned) heap_caps_get_free_size(MALLOC_CAP_8BIT));
  uv_timer_start(&round_timer, on_serve_timeout, (uint64_t) CONFIG_HDHT_SERVE_SECONDS * 1000, 0);
}

static void
start_server (void) {
  if (CONFIG_HDHT_SERVE_SECONDS == 0) {
    print_dht_stats();
    hdht_destroy(&dht, on_destroyed);
    return;
  }

  uint8_t seed[32], pk[32], sk[64];
  memset(seed, CONFIG_HDHT_SERVER_SEED_BYTE, sizeof(seed));
  hdht_keypair(pk, sk, seed);
  sodium_memzero(seed, sizeof(seed));

  round_started = esp_timer_get_time();
  hdht_listen(&dht, &server, pk, sk, on_connection, on_listening, NULL);
  sodium_memzero(sk, sizeof(sk));
}

static void
start_round (uv_timer_t *timer) {
  (void) timer;
  round_no++;
  echoed = false;
  heap_before = heap_caps_get_free_size(MALLOC_CAP_8BIT);
  heap_caps_monitor_local_minimum_free_size_start();
  round_started = esp_timer_get_time();
  hdht_connect(&dht, &stream, server_key, on_open, on_data, on_close, NULL);
}

static void
on_ready (hdht_t *d, int status) {
  printf("HDHT|bootstrap|status=%d|table=%u|ms=%lu|heap=%u\n", status, d->table_len, (unsigned long) ms_since(round_started), (unsigned) heap_caps_get_free_size(MALLOC_CAP_8BIT));
  start_round(NULL);
}

static void
loop_task (void *arg) {
  (void) arg;

  size_t heap_start = heap_caps_get_free_size(MALLOC_CAP_8BIT);
  uv_loop_init(&loop);
  uv_timer_init(&loop, &round_timer);

  const char *bootstrap[] = {CONFIG_HDHT_BOOTSTRAP};
  hdht_opts_t opts = {0};
  if (strlen(CONFIG_HDHT_BOOTSTRAP) > 0) {
    opts.bootstrap = bootstrap;
    opts.bootstrap_len = 1;
  }

  int err = hdht_init(&dht, &loop, &opts);
  printf("HDHT|init|err=%d|port=%u|heap_used=%u\n", err, dht.socket.local_port, (unsigned) (heap_start - heap_caps_get_free_size(MALLOC_CAP_8BIT)));

  esp_netif_ip_info_t ip;
  esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
  if (netif && esp_netif_get_ip_info(netif, &ip) == ESP_OK) hdht_add_local_address(&dht, (const uint8_t *) &ip.ip.addr);

  round_started = esp_timer_get_time();
  if (err == 0) hdht_bootstrap(&dht, on_ready);

  uv_run(&loop, UV_RUN_DEFAULT);
  uv_loop_close(&loop);

  printf("HDHT|stack|size=%u|used=%u\n", CONFIG_HDHT_TASK_STACK, (unsigned) (CONFIG_HDHT_TASK_STACK - uxTaskGetStackHighWaterMark(NULL)));
  printf("HDHT|heap|start=%u|end=%u|min_ever=%u\n", (unsigned) heap_start, (unsigned) heap_caps_get_free_size(MALLOC_CAP_8BIT), (unsigned) heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT));
  printf("HDHT|done\n");
  vTaskDelete(NULL);
}

void
app_main (void) {
  printf("HDHT|start|heap=%u\n", (unsigned) heap_caps_get_free_size(MALLOC_CAP_8BIT));

  if (sodium_init() < 0 || sodium_hex2bin(server_key, 32, CONFIG_HDHT_SERVER_KEY, strlen(CONFIG_HDHT_SERVER_KEY), NULL, NULL, NULL) != 0) {
    printf("HDHT|error|bad server key\n");
    return;
  }

  ESP_ERROR_CHECK(nvs_flash_init());
  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());
  if (example_connect() != ESP_OK) {
    printf("HDHT|error|wifi\n");
    return;
  }
  printf("HDHT|wifi|heap=%u\n", (unsigned) heap_caps_get_free_size(MALLOC_CAP_8BIT));

#if CONFIG_BT_NIMBLE_ENABLED
  // the BLE link uses the same key pair as the DHT server, so one key reaches the device both ways
  {
    uint8_t seed[32], pk[32], sk[64];
    memset(seed, CONFIG_HDHT_SERVER_SEED_BYTE, sizeof(seed));
    hdht_keypair(pk, sk, seed);
    hdht_ble_start(pk, sk);
    sodium_memzero(seed, sizeof(seed));
    sodium_memzero(sk, sizeof(sk));
    printf("HDHT|ble_started|heap=%u\n", (unsigned) heap_caps_get_free_size(MALLOC_CAP_8BIT));
  }
#endif

  xTaskCreate(loop_task, "hdht", CONFIG_HDHT_TASK_STACK, NULL, 5, NULL);
}
