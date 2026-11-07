// The device pays for an HTTP API itself, with x402 (CONFIG_MER_X402_URL).
//
// Every CONFIG_MER_X402_INTERVAL_S seconds it calls the URL with BoAT MER's
// x402 client (boat_x402_pay). On 402 it signs an EIP-3009 authorization
// under the token domain the server names, at most CONFIG_MER_X402_MAX base
// units, and retries with the PAYMENT-SIGNATURE header; the server's
// facilitator settles it (packages/wdk-protocol-boat-evm/examples/x402).
// HTTP blocks, so this runs on a task of its own, not on the hdht loop.
//
// The authorization's validBefore comes from the device clock, so the task
// waits for SNTP first.
//
// MER keeps the EIP-712 domain in one global (boat_pay_set_domain_ext, then
// boat_pay_authorize), so two tasks signing at once can sign under each
// other's domain. Run this without the buyer and anchoring until MER takes
// the domain per call.

#include <stdio.h>
#include <sys/time.h>
#include <time.h>

#include "esp_heap_caps.h"
#include "esp_netif_sntp.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "boat_x402.h"
#include "mer.h"

static void
x402_task (void *arg) {
  (void) arg;
  while (kp.eth_addr_hex[0] == '\0') vTaskDelay(pdMS_TO_TICKS(100)); // MER loads the keys on the hdht task
  esp_sntp_config_t config = ESP_NETIF_SNTP_DEFAULT_CONFIG("pool.ntp.org");
  esp_netif_sntp_init(&config);
  if (esp_netif_sntp_sync_wait(pdMS_TO_TICKS(20000)) != ESP_OK) printf("MER|x402 clock not set by SNTP yet\n");
  printf("MER|x402 url=%s every %d s, clock %lld\n", CONFIG_MER_X402_URL, CONFIG_MER_X402_INTERVAL_S, (long long) time(NULL));

  for (unsigned round = 1;; round++) {
    boat_x402_pay_request_t req = {
      .url = CONFIG_MER_X402_URL,
      .method = "GET",
      .timeout_ms = 60000,
      .max_amount = CONFIG_MER_X402_MAX,
    };
    boat_x402_pay_response_t res;
    int64_t t0 = esp_timer_get_time();
    boat_err_t err = boat_x402_pay(&kp, &req, &res, NULL, 0);
    long ms = (long) ((esp_timer_get_time() - t0) / 1000);
    printf("MER|x402 round=%u err=%d status=%d paid=%d ms=%ld heap=%u stack_free=%u\n", round, err, res.status_code, res.payment_made, ms,
           (unsigned) heap_caps_get_free_size(MALLOC_CAP_8BIT), (unsigned) uxTaskGetStackHighWaterMark(NULL));
    if (res.body) printf("MER|x402 body %.200s\n", res.body);
    boat_x402_pay_free(&res);
    vTaskDelay(pdMS_TO_TICKS(CONFIG_MER_X402_INTERVAL_S * 1000));
  }
}

void
x402_start (void) {
  if (CONFIG_MER_X402_URL[0] == '\0') return;
  xTaskCreate(x402_task, "x402", CONFIG_MER_X402_STACK, NULL, 4, NULL);
}
