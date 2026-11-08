// main/x402_check.c on the desktop, for packages/wdk-protocol-boat-evm's
// tests: the device's check of an x402 payment, run as the device would.
//
//   x402_host <chain id> <token> <name> <version> <payee> <price> <now> <PAYMENT-SIGNATURE (base64)>
//     -> OK <payer> <value>, or REFUSED <why>
//
// Link with MER built for the desktop (libboat_mer.a, its tests' CMake build).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "boat_crypto.h"
#include "x402_check.h"

int
main (int argc, char **argv) {
  if (argc != 9 || sodium_init() < 0) return 2;
  x402_terms_t t = {0};
  t.chain_id = (uint32_t) strtoul(argv[1], NULL, 10);
  if (boat_hex_to_bytes(argv[2], t.token, 20) != 20 || boat_hex_to_bytes(argv[5], t.payee, 20) != 20) return 2;
  t.name = argv[3];
  t.version = argv[4];
  t.price = strtoull(argv[6], NULL, 10);
  t.max_timeout_s = 300;
  uint64_t now = strtoull(argv[7], NULL, 10);

  size_t cap = strlen(argv[8]), len;
  char *json = malloc(cap + 1);
  if (sodium_base642bin((unsigned char *) json, cap, argv[8], cap, NULL, &len, NULL, sodium_base64_VARIANT_ORIGINAL) != 0) {
    printf("REFUSED PAYMENT-SIGNATURE is not base64\n");
    return 1;
  }
  json[len] = '\0';
  x402_auth_t a;
  const char *why = x402_parse_payment(json, &a);
  if (!why) why = x402_check_payment(&t, &a, now);
  if (why) {
    printf("REFUSED %s\n", why);
    return 1;
  }
  char from[41];
  sodium_bin2hex(from, sizeof(from), a.from, 20);
  printf("OK 0x%s %llu\n", from, (unsigned long long) a.value);
  return 0;
}
