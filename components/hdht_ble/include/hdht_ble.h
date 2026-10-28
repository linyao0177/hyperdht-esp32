// SecretStream over a BLE GATT service, keyed by the device's Ed25519 key
// pair (see ble/README.md). Starts NimBLE and advertises; every message
// received over the encrypted stream is echoed. Prints "BLE|..." lines.

#ifndef HDHT_BLE_H
#define HDHT_BLE_H

#include <stdint.h>

// Requires nvs_flash_init() and sodium_init() first. Returns 0 or a NimBLE error.
int
hdht_ble_start (const uint8_t public_key[32], const uint8_t secret_key[64]);

#endif
