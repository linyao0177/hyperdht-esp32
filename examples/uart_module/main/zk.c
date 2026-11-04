// Verifying camera events (components/zk) as they arrive on links.
//
// With a registry root set (AT+ZKROOT), every message that is an event_v2
// JSON object gets a +ZK event after its +DATA. A proof takes 1.2 s on the
// C3, so the hdht task only parses the message and queues it; a task below
// it checks it, so the network never waits.
//
// A copied message verifies as well as the original, so the checks around the
// proof are: the event's time t is within CONFIG_MODULE_ZK_WINDOW seconds of
// the clock (set by SNTP), and its M was not accepted before. M covers seq
// and t, so two different events never share one. These do not depend on the
// sender's DID, which says nothing about the camera: anyone can connect with
// a new key and send an old message.

#include "sdkconfig.h"

#if CONFIG_MODULE_ZK

#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "esp_netif_sntp.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "nvs.h"

#include "module.h"
#include "port.h"
#include "zk_event.h"
#include "zk_vk.h" // the event_v2 circuit's verifying key

#define QUEUE_LEN  4
#define SEEN_LEN   64    // accepted M values; a window of at most 60 s holds about 50
#define TASK_STACK 24576 // 22 KB used by a verification

static const char *TAG = "zk";

typedef struct {
  int link;
  uint8_t root[32];
  zk_event_t e;
} job_t;

static bool has_root;
static uint8_t root[32];
static QueueHandle_t jobs;

// the verify task's own
static g16_vk_t vk;
static uint8_t seen[SEEN_LEN][8];
static size_t seen_next;
static job_t job;

// 0 until SNTP has set the clock
uint64_t
zk_now_ms (void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  if (tv.tv_sec < 1735689600) return 0; // before 2025: not set yet
  return (uint64_t) tv.tv_sec * 1000 + (uint64_t) tv.tv_usec / 1000;
}

static const char *
check (const job_t *j) {
  uint64_t now = zk_now_ms();
  if (now == 0) return "NOTIME";
  uint64_t age = j->e.t_ms > now ? j->e.t_ms - now : now - j->e.t_ms;
  if (age > (uint64_t) CONFIG_MODULE_ZK_WINDOW * 1000) return "STALE";
  uint8_t m[32];
  zk_event_hash(m, &j->e);
  for (size_t i = 0; i < SEEN_LEN; i++) {
    if (memcmp(seen[i], m, 8) == 0) return "REPLAY";
  }
  int v = zk_event_verify(&vk, j->root, m, &j->e);
  if (v < 0) return "BAD";
  if (v == 0) return "INVALID";
  memcpy(seen[seen_next], m, 8);
  seen_next = (seen_next + 1) % SEEN_LEN;
  return "VALID";
}

static void
zk_task (void *arg) {
  (void) arg;
  int64_t t0 = esp_timer_get_time();
  if (g16_init() != 0 || g16_vk_load(&vk, zk_vk, sizeof(zk_vk)) != 0) {
    ESP_LOGE(TAG, "verifier failed to start");
    vTaskDelete(NULL);
  }
  ESP_LOGI(TAG, "verifier ready in %lld ms", (long long) (esp_timer_get_time() - t0) / 1000);
  // so the first M is never a match
  memset(seen, 0xff, sizeof(seen));
  for (;;) {
    xQueueReceive(jobs, &job, portMAX_DELAY);
    t0 = esp_timer_get_time();
    const char *r = check(&job);
    port_printf("+ZK:%d,%llu,%s", job.link, (unsigned long long) job.e.seq, r);
    vTaskDelay(1); // the idle task feeds the watchdog
    ESP_LOGI(TAG, "link %d seq %llu %s in %lld ms, stack left %u", job.link, (unsigned long long) job.e.seq, r, (long long) (esp_timer_get_time() - t0) / 1000, (unsigned) uxTaskGetStackHighWaterMark(NULL));
  }
}

// the first time a root is set; the task lives on after AT+ZKROOT=
static void
start_task (void) {
  if (jobs) return;
  jobs = xQueueCreate(QUEUE_LEN, sizeof(job_t));
  if (jobs == NULL || xTaskCreate(zk_task, "zk", TASK_STACK, NULL, 1, NULL) != pdPASS) {
    ESP_LOGE(TAG, "no memory for the verify task");
    if (jobs) vQueueDelete(jobs);
    jobs = NULL;
  }
}

void
zk_on_data (int link, const uint8_t *data, size_t len) {
  if (!has_root || jobs == NULL) return;
  static job_t j; // the hdht task's; too big for its stack
  int p = zk_event_parse(&j.e, (const char *) data, len);
  if (p == 1) return; // not an event
  if (p < 0) {
    port_printf("+ZK:%d,-,BAD", link);
    return;
  }
  j.link = link;
  memcpy(j.root, root, 32);
  if (xQueueSend(jobs, &j, 0) != pdTRUE) port_printf("+ZK:%d,%llu,BUSY", link, (unsigned long long) j.e.seq);
}

// AT+ZKROOT=<hex> / AT+ZKROOT= / AT+ZKROOT?
void
zk_cmd_root (const char *args, bool query) {
  if (query) {
    if (has_root) {
      char hex[65];
      sodium_bin2hex(hex, sizeof(hex), root, 32);
      port_printf("+ZKROOT:%s", hex);
    }
    port_line("OK");
    return;
  }
  uint8_t r[32];
  bool set = args[0] != '\0';
  if (set && (strlen(args) != 64 || sodium_hex2bin(r, 32, args, 64, NULL, NULL, NULL) != 0 || !zk_fr_ok(r))) {
    port_line("ERROR:bad root: 64 hex characters, below the group order");
    return;
  }
  nvs_handle_t nvs;
  if (nvs_open("module", NVS_READWRITE, &nvs) == ESP_OK) {
    if (set) nvs_set_blob(nvs, "zkroot", r, 32);
    else nvs_erase_key(nvs, "zkroot");
    nvs_commit(nvs);
    nvs_close(nvs);
  }
  has_root = set;
  if (set) {
    memcpy(root, r, 32);
    start_task();
  }
  port_line("OK");
}

void
zk_init (void) {
  nvs_handle_t nvs;
  size_t len = 32;
  if (nvs_open("module", NVS_READONLY, &nvs) == ESP_OK) {
    has_root = nvs_get_blob(nvs, "zkroot", root, &len) == ESP_OK && len == 32;
    nvs_close(nvs);
  }
  if (has_root) start_task();
}

// once WiFi is up
void
zk_time_start (void) {
  esp_sntp_config_t config = ESP_NETIF_SNTP_DEFAULT_CONFIG(CONFIG_MODULE_SNTP_SERVER);
  config.wait_for_sync = false;
  esp_netif_sntp_init(&config);
}

#endif
