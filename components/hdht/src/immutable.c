// Immutable records, as hyperdht's immutableGet: a value stored under
// BLAKE2b-256(value). The query asks the nodes closest to the hash; the first
// value whose hash matches wins (a node cannot forge one).

#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "crypto.h"
#include "hdht.h"

typedef struct {
  hdht_t *dht;
  uint8_t hash[32];
  bool found;
  uint8_t value[HDHT_MUTABLE_MAX_VALUE];
  size_t value_len;
  hdht_immutable_get_cb on_get;
  void *data;
} immutable_op_t;

static void
on_get_reply (hdht_query_t *q, const hdht_response_t *res) {
  immutable_op_t *op = q->data;
  if (op->found || res->value == NULL || res->value_len == 0 || res->value_len > HDHT_MUTABLE_MAX_VALUE) return;
  uint8_t check[32];
  crypto_generichash(check, 32, res->value, res->value_len, NULL, 0);
  if (sodium_memcmp(check, op->hash, 32) != 0) return;
  op->found = true;
  memcpy(op->value, res->value, res->value_len);
  op->value_len = res->value_len;
}

static void
on_get_query_done (hdht_query_t *q, int status) {
  (void) status;
  immutable_op_t *op = q->data;
  if (op->found) op->on_get(op->dht, HDHT_OK, op->value, op->value_len, op->data);
  else op->on_get(op->dht, HDHT_MUTABLE_ENOT_FOUND, NULL, 0, op->data);
  free(op);
}

int
hdht_immutable_get (hdht_t *dht, const uint8_t hash[32], hdht_immutable_get_cb cb, void *data) {
  immutable_op_t *op = calloc(1, sizeof(immutable_op_t));
  if (op == NULL) return HDHT_ENOMEM;
  op->dht = dht;
  memcpy(op->hash, hash, 32);
  op->on_get = cb;
  op->data = data;
  if (hdht_query(dht, hash, false, HDHT_CMD_IMMUTABLE_GET, NULL, 0, NULL, 0, on_get_reply, on_get_query_done, op) == NULL) {
    free(op);
    return HDHT_ENOMEM;
  }
  return 0;
}
