// Desktop check of hdht_mqtt_sign / hdht_mqtt_open against the JS
// (packages/boat-mqtt-node/test/run.js builds and drives it).
//   test_signed sign <seed hex> <topic> <seq> <payload text>  -> signed message hex
//   test_signed open <public key hex> <topic> <message hex>   -> "<seq> <payload>" or "BAD"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

#include "hdht_mqtt_signed.h"

int
main (int argc, char **argv) {
  if (sodium_init() < 0 || argc < 5) return 2;
  if (strcmp(argv[1], "sign") == 0) {
    uint8_t seed[32], pk[32], sk[64];
    sodium_hex2bin(seed, 32, argv[2], 64, NULL, NULL, NULL);
    crypto_sign_seed_keypair(pk, sk, seed);
    size_t len = strlen(argv[5]);
    uint8_t *out = malloc(HDHT_MQTT_SIGNED_OVERHEAD + len);
    int n = hdht_mqtt_sign(sk, argv[3], strtoull(argv[4], NULL, 10), (const uint8_t *) argv[5], len, out, HDHT_MQTT_SIGNED_OVERHEAD + len);
    for (int i = 0; i < n; i++) printf("%02x", out[i]);
    printf("\n");
    return n < 0;
  }
  uint8_t pk[32];
  sodium_hex2bin(pk, 32, argv[2], 64, NULL, NULL, NULL);
  size_t hex_len = strlen(argv[4]);
  uint8_t *msg = malloc(hex_len / 2 + 1);
  size_t len;
  sodium_hex2bin(msg, hex_len / 2, argv[4], hex_len, NULL, &len, NULL);
  uint64_t seq;
  const uint8_t *payload;
  size_t payload_len;
  if (hdht_mqtt_open(pk, argv[3], msg, len, &seq, &payload, &payload_len) != 0) {
    printf("BAD\n");
    return 0;
  }
  printf("%llu %.*s\n", (unsigned long long) seq, (int) payload_len, payload);
  return 0;
}
