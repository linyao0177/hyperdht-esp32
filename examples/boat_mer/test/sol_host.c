// main/solana.c on the desktop, for packages/wdk-protocol-boat-solana's tests:
// the device's Solana policy and signing, run as the device would.
//
//   sol_host key <DID seed hex>                     -> <Solana public key hex> <base58>
//   sol_host sign <DID seed hex> <mint base58> <max> <message base64>
//                                                  -> OK <amount> <signature hex>, or REFUSED <why>
//   sol_host base58 <hex 32 bytes> | unbase58 <base58>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "solana.h"

static int
seed_of (const char *hex, uint8_t sk[64]) {
  uint8_t seed[32], pk[32];
  if (strlen(hex) != 64 || sodium_hex2bin(seed, 32, hex, 64, NULL, NULL, NULL) != 0) return -1;
  crypto_sign_seed_keypair(pk, sk, seed);
  return 0;
}

int
main (int argc, char **argv) {
  if (sodium_init() < 0 || argc < 3) return 2;
  char hex[129];
  if (strcmp(argv[1], "base58") == 0) {
    uint8_t b[32];
    char out[45];
    if (sodium_hex2bin(b, 32, argv[2], strlen(argv[2]), NULL, NULL, NULL) != 0) return 2;
    sol_base58_encode(b, out);
    printf("%s\n", out);
    return 0;
  }
  if (strcmp(argv[1], "unbase58") == 0) {
    uint8_t b[32];
    if (!sol_base58_decode(argv[2], b)) {
      printf("INVALID\n");
      return 1;
    }
    sodium_bin2hex(hex, sizeof(hex), b, 32);
    printf("%s\n", hex);
    return 0;
  }
  uint8_t did_sk[64];
  if (seed_of(argv[2], did_sk) != 0) return 2;
  sol_keypair_t kp;
  sol_derive(&kp, did_sk);
  if (strcmp(argv[1], "key") == 0) {
    char b58[45];
    sodium_bin2hex(hex, sizeof(hex), kp.pk, 32);
    sol_base58_encode(kp.pk, b58);
    printf("%s %s\n", hex, b58);
    return 0;
  }
  if (strcmp(argv[1], "sign") == 0 && argc == 6) {
    uint8_t mint[32], msg[1024];
    size_t len;
    if (!sol_base58_decode(argv[3], mint)) return 2;
    if (sodium_base642bin(msg, sizeof(msg), argv[5], strlen(argv[5]), NULL, &len, NULL, sodium_base64_VARIANT_ORIGINAL) != 0) {
      printf("REFUSED bad base64\n");
      return 1;
    }
    sol_transfer_t t;
    const char *why = sol_check_transfer(msg, len, kp.pk, mint, strtoull(argv[4], NULL, 10), &t);
    if (why) {
      printf("REFUSED %s\n", why);
      return 1;
    }
    uint8_t sig[64];
    crypto_sign_detached(sig, NULL, msg, len, kp.sk);
    sodium_bin2hex(hex, sizeof(hex), sig, 64);
    printf("OK %llu %s\n", (unsigned long long) t.amount, hex);
    return 0;
  }
  return 2;
}
