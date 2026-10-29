#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "crypto.h"
#include "hdht.h"

// hyperdht/lib/constants.js BOOTSTRAP_NODES
static const char *const DEFAULT_BOOTSTRAP[] = {
  "88.99.3.86@node1.hyperdht.org:49737",
  "142.93.90.113@node2.hyperdht.org:49737",
  "138.68.147.8@node3.hyperdht.org:49737",
};

// server.c
bool
hdht__server_on_request (hdht_t *dht, const hdht_incoming_t *req);

void
hdht_keypair (uint8_t public_key[32], uint8_t secret_key[64], const uint8_t *seed) {
  if (seed) crypto_sign_seed_keypair(public_key, secret_key, seed);
  else crypto_sign_keypair(public_key, secret_key);
}

// Parses "ip:port" or "ip@name:port" (the name is only informational).
static int
parse_node (hdht_addr_t *addr, const char *s) {
  char host[64];
  unsigned port;
  const char *colon = strrchr(s, ':');
  if (colon == NULL || sscanf(colon + 1, "%u", &port) != 1 || port == 0 || port > 65535) return -1;

  size_t len = (size_t) (colon - s);
  const char *at = memchr(s, '@', len);
  if (at) len = (size_t) (at - s);
  if (len >= sizeof(host)) return -1;
  memcpy(host, s, len);
  host[len] = '\0';

  return hdht_addr_parse(addr, host, (uint16_t) port);
}

static bool
on_request (hdht_t *dht, const hdht_incoming_t *req) {
  switch (req->command) {
  case HDHT_CMD_PEER_HANDSHAKE:
  case HDHT_CMD_PEER_HOLEPUNCH:
    return hdht__server_on_request(dht, req);
  }
  return false; // FIND_PEER, LOOKUP, ... are only served by persistent nodes
}

int
hdht_init (hdht_t *dht, uv_loop_t *loop, const hdht_opts_t *opts) {
  hdht_opts_t defaults = {0};
  if (opts == NULL) opts = &defaults;

  int err = hdht_dht_init(dht, loop, opts->port);
  if (err) return err;

  dht->on_request = on_request;
  hdht_keypair(dht->public_key, dht->secret_key, opts->seed);

  const char *const *nodes = opts->bootstrap ? opts->bootstrap : DEFAULT_BOOTSTRAP;
  size_t len = opts->bootstrap ? opts->bootstrap_len : sizeof(DEFAULT_BOOTSTRAP) / sizeof(DEFAULT_BOOTSTRAP[0]);
  for (size_t i = 0; i < len; i++) {
    hdht_addr_t addr;
    if (parse_node(&addr, nodes[i]) == 0) hdht_dht_add_bootstrap(dht, &addr);
  }

  return 0;
}

void
hdht_add_local_address (hdht_t *dht, const uint8_t ip[4]) {
  if (dht->local_addresses_len == 2) return;
  for (int i = 0; i < dht->local_addresses_len; i++) {
    if (memcmp(dht->local_addresses[i].ip, ip, 4) == 0) return;
  }
  hdht_addr_t *a = &dht->local_addresses[dht->local_addresses_len++];
  memcpy(a->ip, ip, 4);
  a->port = dht->socket.local_port;
}

void
hdht_set_relay (hdht_t *dht, const uint8_t relay_public_key[32]) {
  dht->has_relay = relay_public_key != NULL;
  if (relay_public_key) memcpy(dht->relay, relay_public_key, 32);
}

typedef struct {
  hdht_ready_cb cb;
} bootstrap_req_t;

static void
on_bootstrap_done (hdht_query_t *q, int status) {
  bootstrap_req_t *b = q->data;
  hdht_ready_cb cb = b->cb;
  free(b);
  if (cb) cb(q->dht, status);
}

int
hdht_bootstrap (hdht_t *dht, hdht_ready_cb cb) {
  bootstrap_req_t *b = malloc(sizeof(bootstrap_req_t));
  if (b == NULL) return HDHT_ENOMEM;
  b->cb = cb;

  hdht_query_t *q = hdht_query(dht, dht->table_id, true, HDHT_RPC_FIND_NODE, NULL, 0, NULL, 0, NULL, on_bootstrap_done, b);
  if (q == NULL) {
    free(b);
    return HDHT_ENOMEM;
  }
  return 0;
}

void
hdht_destroy (hdht_t *dht, void (*on_destroyed)(hdht_t *dht)) {
  sodium_memzero(dht->secret_key, sizeof(dht->secret_key));
  hdht_dht_destroy(dht, on_destroyed);
}
