// BoAT MER's x402 client against a WDK-facilitated x402 server
// (examples/x402/server.js): GET a URL, and on 402 sign an EIP-3009
// authorization under the token domain the server names, retry with the
// PAYMENT-SIGNATURE header, and print what came back.
//
// usage: mer_x402_client <url> [max amount in base units, default 10000]
// Keys: MER's own, in $HOME/.boat-mer (set HOME to keep a test identity apart).

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include "boat_mer.h"
#include "boat_pal.h"
#include "boat_x402.h"

int
main (int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <url> [max amount]\n", argv[0]);
    return 1;
  }
  boat_keypair_t kp;
  if (boat_crypto_init(&kp) != BOAT_OK) {
    fprintf(stderr, "MER|crypto init failed\n");
    return 1;
  }
  printf("MER|wallet %s did %s\n", kp.eth_addr_hex, kp.did);

  boat_x402_pay_request_t req = {
    .url = argv[1],
    .method = "GET",
    .timeout_ms = 60000,
    .max_amount = argc > 2 ? strtoull(argv[2], NULL, 10) : 10000,
  };
  boat_x402_pay_response_t res;
  int64_t t0 = (int64_t) boat_pal_time();
  boat_err_t err = boat_x402_pay(&kp, &req, &res, NULL, 0);
  printf("MER|x402 err=%d status=%d paid=%d seconds=%" PRId64 "\n", err, res.status_code, res.payment_made, (int64_t) boat_pal_time() - t0);
  if (res.body) printf("MER|body %s\n", res.body);
  int ok = err == BOAT_OK && res.status_code == 200 && res.payment_made;
  boat_x402_pay_free(&res);
  return ok ? 0 : 2;
}
