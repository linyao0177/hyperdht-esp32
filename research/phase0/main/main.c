// Phase 0 PoC: libsodium primitives and a libudx echo session on ESP32-C3,
// with heap and stack measurements. Results are printed as `POC|...` lines.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_chip_info.h"
#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_idf_version.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "protocol_examples_common.h"
#include "sdkconfig.h"

#include "heap_report.h"
#include "sodium_check.h"
#include "udx_echo.h"

#define SODIUM_TASK_STACK 16384
#define UDX_TASK_STACK    16384 // libudx _send_packet alone has an 11.6 KB frame

typedef struct {
  void (*fn)(void *arg);
  void *arg;
  TaskHandle_t waiter;
  uint32_t stack_unused;
} task_job_t;

static void
task_trampoline (void *p) {
  task_job_t *job = p;
  job->fn(job->arg);
  job->stack_unused = uxTaskGetStackHighWaterMark(NULL);
  xTaskNotifyGive(job->waiter);
  vTaskDelete(NULL);
}

// Runs fn on a fresh task so its stack high-water mark can be measured.
static uint32_t
run_in_task (const char *name, uint32_t stack, void (*fn)(void *), void *arg) {
  task_job_t job = {fn, arg, xTaskGetCurrentTaskHandle(), 0};
  xTaskCreate(task_trampoline, name, stack, &job, 5, NULL);
  ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
  printf("POC|stack|%s|size=%lu|used=%lu\n", name, (unsigned long) stack, (unsigned long) (stack - job.stack_unused));
  return job.stack_unused;
}

static void
sodium_job (void *arg) {
  *(int *) arg = poc_sodium_run();
}

typedef struct {
  uint32_t rwnd;
  poc_echo_result_t result;
} echo_job_t;

static void
echo_job (void *arg) {
  echo_job_t *job = arg;
  poc_udx_echo_run(job->rwnd, &job->result);
}

static void
print_echo (const char *ps, const poc_echo_result_t *r) {
  double kbps = r->elapsed_ms ? (double) r->bytes / 1024.0 / (r->elapsed_ms / 1000.0) : 0;
  printf("POC|udx|run|ps=%s|rwnd=%lu|ok=%d|error=%s|bytes=%u|ms=%lu|KiB_per_s=%.0f|rtt_min_ms=%lu"
         "|srtt_ms=%lu|cwnd=%lu|pacing_B_per_ms=%lu|pkts_tx=%lu|pkts_rx=%lu|retransmits=%lu|rtos=%lu"
         "|heap_before=%u|heap_low=%u|heap_after=%u|peak_heap_used=%u"
         "|udx_baseline=%u|udx_peak=%u|udx_allocs=%u|udx_leaked=%u|udx_alloc_failures=%u|app_buffers=%u\n",
         ps, (unsigned long) r->rwnd_max, r->ok, r->error ? r->error : "-", (unsigned) r->bytes,
         (unsigned long) r->elapsed_ms, kbps, (unsigned long) r->rtt_min_ms,
         (unsigned long) r->srtt_ms, (unsigned long) r->cwnd, (unsigned long) r->pacing_bytes_per_ms,
         (unsigned long) r->packets_tx, (unsigned long) r->packets_rx,
         (unsigned long) r->retransmits, (unsigned long) r->rto_count,
         (unsigned) r->heap_before, (unsigned) r->heap_low, (unsigned) r->heap_after,
         (unsigned) (r->heap_before - r->heap_low),
         (unsigned) r->udx_baseline, (unsigned) r->udx_peak, (unsigned) r->udx_allocs,
         (unsigned) r->udx_leaked, (unsigned) r->udx_alloc_failures, (unsigned) r->app_buffers);
}

// Heap held back from the echo run to test it under memory pressure. The
// udx_echo task stack is allocated after this, so leave room for it.
typedef struct {
  void *blocks[32];
  int count;
  size_t bytes;
} ballast_t;

static void
ballast_fill (ballast_t *b, size_t leave_free) {
  memset(b, 0, sizeof(*b));
  if (leave_free == 0) return;

  leave_free += UDX_TASK_STACK;
  while (b->count < 32) {
    size_t free_now = heap_caps_get_free_size(MALLOC_CAP_8BIT);
    size_t largest = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
    if (free_now <= leave_free + 256) break;

    size_t size = free_now - leave_free;
    if (size > largest - 64) size = largest - 64;
    if (size < 256) break;

    void *p = malloc(size);
    if (p == NULL) break;
    b->blocks[b->count++] = p;
    b->bytes += size;
  }
  printf("POC|ballast|bytes=%u|free=%u\n", (unsigned) b->bytes, (unsigned) heap_caps_get_free_size(MALLOC_CAP_8BIT));
}

static void
ballast_free (ballast_t *b) {
  for (int i = 0; i < b->count; i++) free(b->blocks[i]);
  b->count = 0;
}

static void
run_udx_echo (void) {
  poc_udx_print_sizes();

  // The STA default is modem sleep, which only wakes for the AP's beacons.
  static const struct {
    wifi_ps_type_t type;
    const char *name;
  } ps_modes[] = {
    {WIFI_PS_MIN_MODEM, "min_modem"},
    {WIFI_PS_NONE, "none"},
  };

  for (size_t i = 0; i < sizeof(ps_modes) / sizeof(ps_modes[0]); i++) {
    ESP_ERROR_CHECK(esp_wifi_set_ps(ps_modes[i].type));

    char list[] = CONFIG_POC_RWND_LIST;
    for (char *tok = strtok(list, ","); tok; tok = strtok(NULL, ",")) {
      echo_job_t job = {.rwnd = (uint32_t) strtoul(tok, NULL, 10)};
      ballast_t ballast;
      ballast_fill(&ballast, CONFIG_POC_HEAP_LEAVE_FREE);
      run_in_task("udx_echo", UDX_TASK_STACK, echo_job, &job);
      ballast_free(&ballast);
      print_echo(ps_modes[i].name, &job.result);
      vTaskDelay(pdMS_TO_TICKS(1000));
    }
  }
}

void
app_main (void) {
  esp_chip_info_t chip;
  esp_chip_info(&chip);
  printf("POC|start|idf=%s|chip_model=%d|revision=%d|cores=%d\n", esp_get_idf_version(), chip.model, chip.revision, chip.cores);

  poc_heap_checkpoint("boot");

  int failures = 0;
  run_in_task("sodium", SODIUM_TASK_STACK, sodium_job, &failures);
  poc_heap_checkpoint("after_sodium");

  // volatile keeps the network path linked (and its size measured) even
  // when the SSID is still the placeholder.
  const char *volatile ssid = CONFIG_EXAMPLE_WIFI_SSID;
  if (strcmp(ssid, "myssid") == 0) {
    printf("POC|net|skipped|no WiFi credentials (see sdkconfig.wifi.example)\n");
    printf("POC|done\n");
    return;
  }

  ESP_ERROR_CHECK(nvs_flash_init());
  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());
  poc_heap_checkpoint("before_wifi");

  if (example_connect() != ESP_OK) {
    printf("POC|net|failed|example_connect\n");
    printf("POC|done\n");
    return;
  }
  poc_heap_checkpoint("wifi_connected");

  run_udx_echo();

  poc_heap_checkpoint("end");
  printf("POC|done\n");
}
