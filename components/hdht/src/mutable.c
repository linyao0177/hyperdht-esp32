// Mutable records, as hyperdht's mutablePut / mutableGet (see docs/protocol.md).
//
// put: MUTABLE_GET query towards BLAKE2b(public key) to collect tokens, then a
//      signed MUTABLE_PUT to every closest node that gave one.
// get: MUTABLE_GET query; every value returned is checked against the public
//      key and the highest valid seq wins.

#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "crypto.h"
#include "hdht.h"

typedef struct {
  hdht_t *dht;
  uint8_t public_key[32];
  uint64_t min_seq;

  // put
  uint8_t *request; // encoded mutablePutRequest
  size_t request_len;
  uint8_t pending;
  uint8_t stored;
  uint32_t rejected; // last remote error code
  hdht_mutable_put_cb on_put;

  // get
  bool found;
  uint64_t seq;
  uint8_t value[HDHT_MUTABLE_MAX_VALUE];
  size_t value_len;
  hdht_mutable_get_cb on_get;

  void *data;
} mutable_op_t;

// NS_MUTABLE_PUT || BLAKE2b-256(c.uint(seq) || c.buffer(value))
static void
mutable_signable (uint8_t out[64], uint64_t seq, const uint8_t *value, size_t len) {
  uint8_t head[18];
  cenc_t e;
  cenc_init(&e, head, sizeof(head));
  cenc_uint(&e, seq);
  cenc_uint(&e, len);

  crypto_generichash_state st;
  crypto_generichash_init(&st, NULL, 0, 32);
  crypto_generichash_update(&st, head, e.pos);
  crypto_generichash_update(&st, value, len);
  crypto_generichash_final(&st, out + 32, 32);
  memcpy(out, HDHT_NS_MUTABLE_PUT, 32);
}

bool
hdht_mutable_verify (const uint8_t public_key[32], uint64_t seq, const uint8_t *value, size_t len, const uint8_t signature[64]) {
  uint8_t signable[64];
  mutable_signable(signable, seq, value, len);
  return crypto_sign_verify_detached(signature, signable, sizeof(signable), public_key) == 0;
}

static void
op_free (mutable_op_t *op) {
  free(op->request);
  free(op);
}

// put

static void
put_finished (mutable_op_t *op) {
  int status = HDHT_OK;
  if (op->stored == 0) {
    status = op->rejected == HDHT_ERROR_SEQ_REUSED  ? HDHT_MUTABLE_ESEQ_REUSED
             : op->rejected == HDHT_ERROR_SEQ_TOO_LOW ? HDHT_MUTABLE_ESEQ_TOO_LOW
                                                      : HDHT_ETIMEDOUT;
  }
  op->on_put(op->dht, status, op->stored, op->data);
  op_free(op);
}

static void
on_put_reply (hdht_request_t *req, const hdht_response_t *res) {
  mutable_op_t *op = req->data;
  if (res->status == HDHT_OK) {
    if (res->error == 0) op->stored++;
    else op->rejected = res->error;
  }
  if (--op->pending == 0) put_finished(op);
}

static void
on_put_query_done (hdht_query_t *q, int status) {
  (void) status;
  mutable_op_t *op = q->data;

  for (int i = 0; i < q->closest_len; i++) {
    const hdht_reply_ref_t *ref = &q->closest[i];
    if (!ref->has_token) continue;
    if (hdht_request(op->dht, NULL, &ref->from, false, HDHT_CMD_MUTABLE_PUT, q->target, ref->token, op->request, op->request_len, on_put_reply, op)) op->pending++;
  }

  if (op->pending == 0) put_finished(op);
}

int
hdht_mutable_put (hdht_t *dht, const uint8_t public_key[32], const uint8_t secret_key[64], uint64_t seq, const uint8_t *value, size_t len, hdht_mutable_put_cb cb, void *data) {
  if (len == 0 || len > HDHT_MUTABLE_MAX_VALUE) return HDHT_MUTABLE_ETOO_BIG;

  mutable_op_t *op = calloc(1, sizeof(mutable_op_t));
  if (op == NULL) return HDHT_ENOMEM;
  op->dht = dht;
  op->on_put = cb;
  op->data = data;

  uint8_t signable[64], signature[64];
  mutable_signable(signable, seq, value, len);
  crypto_sign_detached(signature, NULL, signable, sizeof(signable), secret_key);

  // mutablePutRequest: fixed32 publicKey, uint seq, buffer value, fixed64 signature
  size_t cap = 32 + 9 + 9 + len + 64;
  op->request = malloc(cap);
  if (op->request == NULL) {
    free(op);
    return HDHT_ENOMEM;
  }
  cenc_t e;
  cenc_init(&e, op->request, cap);
  cenc_fixed32(&e, public_key);
  cenc_uint(&e, seq);
  cenc_buffer(&e, value, len);
  cenc_raw(&e, signature, 64);
  op->request_len = e.pos;

  uint8_t target[32];
  hdht_hash(target, public_key, 32);

  // seq 0 for the token query: only the closest nodes matter, not their values
  const uint8_t zero = 0;
  if (hdht_query(dht, target, false, HDHT_CMD_MUTABLE_GET, &zero, 1, NULL, 0, NULL, on_put_query_done, op) == NULL) {
    op_free(op);
    return HDHT_ENOMEM;
  }
  return 0;
}

// get

static void
on_get_reply (hdht_query_t *q, const hdht_response_t *res) {
  mutable_op_t *op = q->data;
  if (res->value == NULL || res->value_len == 0) return;

  // mutableGetResponse: uint seq, buffer value, fixed64 signature
  cdec_t d;
  cdec_init(&d, res->value, res->value_len);
  uint64_t seq = cdec_uint(&d);
  cenc_bytes_t value = cdec_buffer(&d);
  const uint8_t *signature = cdec_raw(&d, 64);
  if (d.err || value.len == 0 || value.len > HDHT_MUTABLE_MAX_VALUE) return;

  if (seq < op->min_seq || (op->found && seq <= op->seq)) return;
  if (!hdht_mutable_verify(op->public_key, seq, value.data, value.len, signature)) return;

  op->found = true;
  op->seq = seq;
  memcpy(op->value, value.data, value.len);
  op->value_len = value.len;
}

static void
on_get_query_done (hdht_query_t *q, int status) {
  (void) status;
  mutable_op_t *op = q->data;
  if (op->found) op->on_get(op->dht, HDHT_OK, op->seq, op->value, op->value_len, op->data);
  else op->on_get(op->dht, HDHT_MUTABLE_ENOT_FOUND, 0, NULL, 0, op->data);
  op_free(op);
}

int
hdht_mutable_get (hdht_t *dht, const uint8_t public_key[32], uint64_t min_seq, hdht_mutable_get_cb cb, void *data) {
  mutable_op_t *op = calloc(1, sizeof(mutable_op_t));
  if (op == NULL) return HDHT_ENOMEM;
  op->dht = dht;
  memcpy(op->public_key, public_key, 32);
  op->min_seq = min_seq;
  op->on_get = cb;
  op->data = data;

  uint8_t target[32], seq[9];
  hdht_hash(target, public_key, 32);
  cenc_t e;
  cenc_init(&e, seq, sizeof(seq));
  cenc_uint(&e, min_seq);

  if (hdht_query(dht, target, false, HDHT_CMD_MUTABLE_GET, seq, e.pos, NULL, 0, on_get_reply, on_get_query_done, op) == NULL) {
    free(op);
    return HDHT_ENOMEM;
  }
  return 0;
}
