// Bootstraps against a testnet and runs FIND_PEER for a public key.
//
//   test_query <bootstrap host:port> <hex public key>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "../src/crypto.h"
#include "../src/dht.h"
#include "../src/messages.h"

static hdht_t dht;
static uint8_t public_key[32];
static int found = 0;

static void
on_destroyed (hdht_t *d) {
  (void) d;
}

static void
on_peer_reply (hdht_query_t *q, const hdht_response_t *res) {
  (void) q;
  if (res->value == NULL) return;

  hdht_peer_t peer;
  if (hdht_peer_decode(&peer, res->value, res->value_len) != 0) return;
  if (memcmp(peer.public_key, public_key, 32) != 0) return;

  found++;
  printf("record at %s (relay addresses %u)\n", hdht_addr_str(&res->from), peer.relay_addresses_len);
}

static void
on_peer_done (hdht_query_t *q, int status) {
  printf("find_peer done: status=%d closest=%u successes=%u errors=%u found=%d\n", status, q->closest_len, q->successes, q->errors, found);
  printf("table=%u requests=%u responses=%u timeouts=%u\n", dht.table_len, dht.stats.requests, dht.stats.responses, dht.stats.timeouts);
  hdht_dht_destroy(&dht, on_destroyed);
}

static void
on_bootstrap_done (hdht_query_t *q, int status) {
  printf("bootstrap done: status=%d closest=%u table=%u\n", status, q->closest_len, dht.table_len);

  uint8_t target[32];
  hdht_hash(target, public_key, 32);
  hdht_query(&dht, target, false, HDHT_CMD_FIND_PEER, NULL, 0, NULL, 0, on_peer_reply, on_peer_done, NULL);
}

int
main (int argc, char **argv) {
  if (argc < 3 || sodium_init() < 0) {
    fprintf(stderr, "usage: test_query <host:port> <hex public key>\n");
    return 1;
  }

  char host[64];
  unsigned port;
  if (sscanf(argv[1], "%63[^:]:%u", host, &port) != 2) return 1;
  if (sodium_hex2bin(public_key, 32, argv[2], strlen(argv[2]), NULL, NULL, NULL) != 0) return 1;

  if (hdht_dht_init(&dht, uv_default_loop(), 0) != 0) return 1;

  hdht_addr_t bootstrap;
  if (hdht_addr_parse(&bootstrap, host, (uint16_t) port) != 0) return 1;
  hdht_dht_add_bootstrap(&dht, &bootstrap);

  hdht_query(&dht, dht.table_id, true, HDHT_RPC_FIND_NODE, NULL, 0, NULL, 0, NULL, on_bootstrap_done, NULL);

  uv_run(uv_default_loop(), UV_RUN_DEFAULT);
  return found ? 0 : 1;
}
