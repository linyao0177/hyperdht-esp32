// SecretStream over BLE on the ESP32-C3, BLE only (no WiFi). See README.md.

#include <stdio.h>
#include <string.h>

#include <sodium.h>

#include "esp_heap_caps.h"
#include "nvs_flash.h"
#include "sdkconfig.h"

#include "hdht_ble.h"

void
app_main (void) {
  printf("BLE|start|heap=%u\n", (unsigned) heap_caps_get_free_size(MALLOC_CAP_8BIT));

  esp_err_t err = nvs_flash_init();
  if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    nvs_flash_erase();
    nvs_flash_init();
  }
  if (sodium_init() < 0) return;

  uint8_t seed[32], pk[32], sk[64];
  memset(seed, CONFIG_HDHT_BLE_SEED_BYTE, sizeof(seed));
  crypto_sign_seed_keypair(pk, sk, seed);
  sodium_memzero(seed, sizeof(seed));

  hdht_ble_start(pk, sk);
  sodium_memzero(sk, sizeof(sk));
}
