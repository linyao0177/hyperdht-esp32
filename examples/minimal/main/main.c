// Minimal hyperdht-esp32 integration.
//
// - The device's key pair comes from a random seed kept in NVS, so its public
//   key (its address on HyperDHT) survives reboots.
// - A HyperDHT server on the public DHT echoes whatever peers send.
// - A separate "sensor" task pushes a reading every 5 s to every connected
//   peer. hdht is single-threaded, so the task hands messages to the hdht
//   loop through a FreeRTOS queue and wakes it with uv_async_send.

#include <stdio.h>
#include <string.h>

#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "protocol_examples_common.h"

#include "hdht.h"

#define MAX_PEERS 2

typedef struct {
  char text[64];
} message_t;

static uv_loop_t loop;
static hdht_t dht;
static hdht_server_t server;
static uv_async_t wake;
static QueueHandle_t outbox;
static hdht_stream_t *peers[MAX_PEERS];

// Loads the 32-byte key seed from NVS, creating it on first boot.
static esp_err_t
load_seed (uint8_t seed[32]) {
  nvs_handle_t nvs;
  esp_err_t err = nvs_open("hdht", NVS_READWRITE, &nvs);
  if (err != ESP_OK) return err;

  size_t len = 32;
  err = nvs_get_blob(nvs, "seed", seed, &len);
  if (err == ESP_ERR_NVS_NOT_FOUND) {
    randombytes_buf(seed, 32);
    err = nvs_set_blob(nvs, "seed", seed, 32);
    if (err == ESP_OK) err = nvs_commit(nvs);
  }

  nvs_close(nvs);
  return err;
}

// everything below runs on the hdht task, except sensor_task

static void
on_data (hdht_stream_t *stream, const uint8_t *data, size_t len) {
  hdht_stream_write(stream, data, len); // echo
}

static void
on_close (hdht_stream_t *stream, int error) {
  for (int i = 0; i < MAX_PEERS; i++) {
    if (peers[i] == stream) peers[i] = NULL;
  }
  printf("peer closed (error %d)\n", error);
}

static void
on_connection (hdht_server_t *s, hdht_stream_t *stream) {
  (void) s;
  char hex[65];
  sodium_bin2hex(hex, sizeof(hex), stream->remote_public_key, 32);
  printf("peer connected: %.16s... from %s\n", hex, hdht_addr_str(&stream->remote_addr));

  // a real device would check remote_public_key against an allow list here
  stream->on_data = on_data;
  stream->on_close = on_close;

  for (int i = 0; i < MAX_PEERS; i++) {
    if (peers[i] == NULL) {
      peers[i] = stream;
      return;
    }
  }
  hdht_stream_end(stream); // full
}

// Runs on the hdht task after uv_async_send from any task.
static void
on_wake (uv_async_t *handle) {
  (void) handle;
  message_t msg;
  while (xQueueReceive(outbox, &msg, 0) == pdTRUE) {
    for (int i = 0; i < MAX_PEERS; i++) {
      if (peers[i]) hdht_stream_write(peers[i], (const uint8_t *) msg.text, strlen(msg.text));
    }
  }
}

static void
on_listening (hdht_server_t *s, int status) {
  char hex[65];
  sodium_bin2hex(hex, sizeof(hex), s->public_key, 32);
  printf("listening (status %d), public key:\n%s\n", status, hex);
}

static void
on_ready (hdht_t *d, int status) {
  printf("bootstrapped (status %d, %u nodes)\n", status, d->table_len);

  uint8_t seed[32], pk[32], sk[64];
  if (load_seed(seed) != ESP_OK) {
    printf("could not load the key seed\n");
    return;
  }
  hdht_keypair(pk, sk, seed);
  hdht_listen(d, &server, pk, sk, on_connection, on_listening, NULL);

  sodium_memzero(seed, sizeof(seed));
  sodium_memzero(sk, sizeof(sk));
}

// another task: never calls hdht directly
static void
sensor_task (void *arg) {
  (void) arg;
  for (;;) {
    vTaskDelay(pdMS_TO_TICKS(5000));

    message_t msg;
    snprintf(msg.text, sizeof(msg.text), "uptime=%llus free_heap=%u\n", (unsigned long long) (esp_timer_get_time() / 1000000), (unsigned) heap_caps_get_free_size(MALLOC_CAP_8BIT));
    if (xQueueSend(outbox, &msg, 0) == pdTRUE) uv_async_send(&wake);
  }
}

static void
hdht_task (void *arg) {
  (void) arg;
  uv_loop_init(&loop);
  uv_async_init(&loop, &wake, on_wake);

  hdht_opts_t opts = {0}; // NULL bootstrap = the public HyperDHT nodes
  if (hdht_init(&dht, &loop, &opts) != 0) {
    printf("hdht_init failed\n");
    vTaskDelete(NULL);
  }

  // lets peers behind the same router connect over the LAN
  esp_netif_ip_info_t ip;
  esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
  if (netif && esp_netif_get_ip_info(netif, &ip) == ESP_OK) hdht_add_local_address(&dht, (const uint8_t *) &ip.ip.addr);

  hdht_bootstrap(&dht, on_ready);

  // the async handle exists now, so other tasks may wake the loop
  xTaskCreate(sensor_task, "sensor", 3072, NULL, 4, NULL);

  uv_run(&loop, UV_RUN_DEFAULT); // runs for as long as the server and wake handle are open
}

void
app_main (void) {
  esp_err_t err = nvs_flash_init();
  if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    err = nvs_flash_init();
  }
  ESP_ERROR_CHECK(err);
  if (sodium_init() < 0) return;

  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());
  ESP_ERROR_CHECK(example_connect());

  outbox = xQueueCreate(8, sizeof(message_t));
  xTaskCreate(hdht_task, "hdht", 20480, NULL, 5, NULL);
}
