// Topic lookup, as hyperdht's lookup (see docs/protocol.md).
//
// A LOOKUP query towards the topic; each node near it replies with the peers
// announced there: lookupRawReply = array(peer) [, uint bump], where
// peer = fixed32 publicKey, array(ipv4 address) relayAddresses.
// Peers are not signed in the reply, so a key found here is only a hint:
// connecting to it is what authenticates it.

#include <stdlib.h>
#include <string.h>

#include "cenc.h"
#include "hdht.h"

typedef struct {
  hdht_t *dht;
  uint8_t peers[HDHT_LOOKUP_MAX_PEERS][32];
  size_t peers_len;
  hdht_lookup_cb cb;
  void *data;
} lookup_op_t;

static void
add_peer (lookup_op_t *op, const uint8_t *public_key) {
  for (size_t i = 0; i < op->peers_len; i++) {
    if (memcmp(op->peers[i], public_key, 32) == 0) return;
  }
  if (op->peers_len < HDHT_LOOKUP_MAX_PEERS) memcpy(op->peers[op->peers_len++], public_key, 32);
}

static void
on_lookup_reply (hdht_query_t *q, const hdht_response_t *res) {
  lookup_op_t *op = q->data;
  if (res->value == NULL || res->value_len == 0) return;

  cdec_t d;
  cdec_init(&d, res->value, res->value_len);
  uint64_t n = cdec_uint(&d);
  for (uint64_t i = 0; i < n && !d.err; i++) {
    const uint8_t *public_key = cdec_raw(&d, 32);
    uint64_t relays = cdec_uint(&d);
    for (uint64_t j = 0; j < relays && !d.err; j++) cdec_raw(&d, 6);
    if (!d.err) add_peer(op, public_key);
  }
}

static void
on_lookup_done (hdht_query_t *q, int status) {
  (void) status;
  lookup_op_t *op = q->data;
  op->cb(op->dht, HDHT_OK, (const uint8_t (*)[32]) op->peers, op->peers_len, op->data);
  free(op);
}

int
hdht_lookup (hdht_t *dht, const uint8_t topic[32], hdht_lookup_cb cb, void *data) {
  lookup_op_t *op = calloc(1, sizeof(lookup_op_t));
  if (op == NULL) return HDHT_ENOMEM;
  op->dht = dht;
  op->cb = cb;
  op->data = data;

  if (hdht_query(dht, topic, false, HDHT_CMD_LOOKUP, NULL, 0, NULL, 0, on_lookup_reply, on_lookup_done, op) == NULL) {
    free(op);
    return HDHT_ENOMEM;
  }
  return 0;
}
