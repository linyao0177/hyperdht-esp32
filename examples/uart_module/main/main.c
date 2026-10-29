// hyperdht-esp32 as a network module: a host MCU drives it with AT-style
// commands over a serial line (docs/module-uart.md).
//
// - port.c: the command port, USB Serial/JTAG or UART1, one command per line.
// - main.c: identity (a seed in NVS), WiFi (from AT+WIFI or the firmware's
//   default), and the hdht task that runs every command.
// - at.c: the commands: connections by DID, records, topic lookup, signing.
//
// The reader task hands each line to the hdht task through a queue and
// uv_async_send, because hdht is single-threaded. Output is written whole
// lines at a time from either task, so responses and events never interleave.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "nvs.h"
#include "nvs_flash.h"

#include "module.h"
#include "port.h"

uv_loop_t loop;
hdht_t dht;
bool dht_ready;
uint8_t pk[32], sk[64];
char did[72];

static QueueHandle_t lines;
static uv_async_t line_async, net_async;
static bool dht_started;

static char ssid[33];
static char ip[16];
static volatile bool connected;

// identity

static void
load_identity (void) {
  nvs_handle_t nvs;
  uint8_t seed[32];
  size_t len = 32;
  ESP_ERROR_CHECK(nvs_open("module", NVS_READWRITE, &nvs));
  if (nvs_get_blob(nvs, "seed", seed, &len) != ESP_OK) {
    randombytes_buf(seed, 32);
    nvs_set_blob(nvs, "seed", seed, 32);
    nvs_commit(nvs);
  }
  nvs_close(nvs);
  hdht_keypair(pk, sk, seed);
  sodium_memzero(seed, sizeof(seed));

  char hex[65];
  sodium_bin2hex(hex, sizeof(hex), pk, 32);
  snprintf(did, sizeof(did), "did:mw:%s", hex);
}

// WiFi

bool
wifi_connected (void) {
  return connected;
}

const char *
wifi_ip (void) {
  return connected ? ip : "";
}

const char *
wifi_ssid (void) {
  return ssid;
}

static void
wifi_apply (void) {
  wifi_config_t config = {0};
  char password[65] = "";
  nvs_handle_t nvs;
  size_t len;
  ssid[0] = '\0';
  if (nvs_open("module", NVS_READONLY, &nvs) == ESP_OK) {
    len = sizeof(ssid);
    if (nvs_get_str(nvs, "ssid", ssid, &len) == ESP_OK) {
      len = sizeof(password);
      nvs_get_str(nvs, "pass", password, &len);
    }
    nvs_close(nvs);
  }
#ifdef CONFIG_EXAMPLE_WIFI_SSID
  if (ssid[0] == '\0') {
    snprintf(ssid, sizeof(ssid), "%s", CONFIG_EXAMPLE_WIFI_SSID);
    snprintf(password, sizeof(password), "%s", CONFIG_EXAMPLE_WIFI_PASSWORD);
  }
#endif
  memcpy(config.sta.ssid, ssid, strlen(ssid));
  memcpy(config.sta.password, password, strlen(password));
  sodium_memzero(password, sizeof(password));
  esp_wifi_set_config(WIFI_IF_STA, &config);
}

void
wifi_set (const char *new_ssid, const char *password) {
  nvs_handle_t nvs;
  if (nvs_open("module", NVS_READWRITE, &nvs) == ESP_OK) {
    if (new_ssid[0]) {
      nvs_set_str(nvs, "ssid", new_ssid);
      nvs_set_str(nvs, "pass", password);
    } else {
      nvs_erase_key(nvs, "ssid");
      nvs_erase_key(nvs, "pass");
    }
    nvs_commit(nvs);
    nvs_close(nvs);
  }
  esp_wifi_disconnect(); // reconnects with the new network from the event handler
  wifi_apply();
}

static void
on_wifi_event (void *arg, esp_event_base_t base, int32_t id, void *data) {
  (void) arg;
  if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
    esp_wifi_connect();
  } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
    wifi_event_sta_disconnected_t *e = data;
    if (connected) port_printf("+NET:DISCONNECTED,%d", e->reason);
    connected = false;
    vTaskDelay(pdMS_TO_TICKS(1000));
    esp_wifi_connect();
  } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
    ip_event_got_ip_t *e = data;
    snprintf(ip, sizeof(ip), IPSTR, IP2STR(&e->ip_info.ip));
    connected = true;
    port_printf("+NET:CONNECTED,%s", ip);
    uv_async_send(&net_async);
  }
}

static void
wifi_start (void) {
  esp_netif_create_default_wifi_sta();
  wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&init));
  esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, on_wifi_event, NULL);
  esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, on_wifi_event, NULL);
  esp_wifi_set_mode(WIFI_MODE_STA);
  wifi_apply();
  esp_wifi_start();
}

// the hdht task

static void
on_ready (hdht_t *d, int status) {
  dht_ready = status == 0;
  port_printf("+READY:%s,%d,%u", did, status, d->table_len);
  if (dht_ready) at_dht_ready();
}

// first IP: start the DHT
static void
on_net (uv_async_t *handle) {
  (void) handle;
  if (dht_started || !connected) return;
  dht_started = true;

  const char *bootstrap[] = {CONFIG_MODULE_BOOTSTRAP};
  hdht_opts_t opts = {0};
  if (CONFIG_MODULE_BOOTSTRAP[0]) {
    opts.bootstrap = bootstrap;
    opts.bootstrap_len = 1;
  }
  if (hdht_init(&dht, &loop, &opts) != 0) {
    port_line("+READY:ERROR");
    return;
  }
  esp_netif_ip_info_t info;
  esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
  if (netif && esp_netif_get_ip_info(netif, &info) == ESP_OK) hdht_add_local_address(&dht, (const uint8_t *) &info.ip.addr);
  hdht_bootstrap(&dht, on_ready);
}

static void
on_lines (uv_async_t *handle) {
  (void) handle;
  char *line;
  while (xQueueReceive(lines, &line, 0) == pdTRUE) {
    at_line(line);
    free(line);
  }
}

// reader task
static void
on_port_line (char *line, size_t len) {
  char *copy = malloc(len + 1);
  if (copy == NULL) {
    port_line("ERROR:out of memory");
    return;
  }
  memcpy(copy, line, len + 1);
  if (xQueueSend(lines, &copy, 0) != pdTRUE) {
    free(copy);
    port_line("ERROR:busy");
    return;
  }
  uv_async_send(&line_async);
}

static void
hdht_task (void *arg) {
  (void) arg;
  uv_loop_init(&loop);
  uv_async_init(&loop, &line_async, on_lines);
  uv_async_init(&loop, &net_async, on_net);
  at_init();
  port_init(on_port_line);
  port_printf("+BOOT:%s,%s", MODULE_VERSION, did);
  wifi_start();
  uv_run(&loop, UV_RUN_DEFAULT);
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
  load_identity();

  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());

  lines = xQueueCreate(4, sizeof(char *));
  xTaskCreate(hdht_task, "hdht", 20480, NULL, 5, NULL);
}
