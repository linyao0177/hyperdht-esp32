// Topic lookup, as hyperdht's lookup (see docs/protocol.md).
//
// A LOOKUP query towards the topic; each node near it replies with the peers
// announced there: lookupRawReply = array(peer) [, uint bump], where
// peer = fixed32 publicKey, array(ipv4 address) relayAddresses.
// Peers are not signed in the reply, so a key found here is only a hint:
// connecting to it is what authenticates it.

#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "cenc.h"
#include "crypto.h"
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

// Announce under a topic, as hyperdht's announce: a LOOKUP query towards the
// topic collects tokens, then every closest node that gave one gets a signed
// ANNOUNCE of our public key (no relay addresses: peers find us by key).
// Nodes keep it for 20 minutes. Unannounce sends UNANNOUNCE to every node on
// the way that still holds our key, as lookupAndUnannounce, and then to the
// closest ones, and does it twice: on the public DHT one pass left about half
// of the copies (a lookup walks a slightly different set of nodes each time),
// two left 2 of 19, about what hyperdht's unannounce leaves. The rest expire.

typedef struct {
  hdht_t *dht;
  uint8_t topic[32];
  uint8_t public_key[32];
  uint8_t secret_key[64];
  bool unannounce;
  bool querying; // the lookup still runs: requests may finish before it
  uint8_t passes; // lookups left
  uint8_t pending;
  unsigned stored;
  hdht_addr_t sent[HDHT_K + 16]; // nodes already asked
  uint8_t sent_len;
  hdht_announce_cb cb;
  void *data;
} announce_op_t;

static void
start_pass (announce_op_t *op);

static void
announce_finished (announce_op_t *op) {
  if (--op->passes > 0) {
    start_pass(op);
    return;
  }
  if (op->cb) op->cb(op->dht, op->stored ? HDHT_OK : HDHT_ETIMEDOUT, op->stored, op->data);
  sodium_memzero(op->secret_key, sizeof(op->secret_key));
  free(op);
}

static void
on_announce_reply (hdht_request_t *req, const hdht_response_t *res) {
  announce_op_t *op = req->data;
  if (res->status == HDHT_OK && res->error == 0) op->stored++;
  if (--op->pending == 0 && !op->querying) announce_finished(op);
}

static void
send_announce (announce_op_t *op, const hdht_addr_t *to, const uint8_t id[32], const uint8_t token[32]) {
  for (int i = 0; i < op->sent_len; i++) {
    if (hdht_addr_eq(&op->sent[i], to)) return;
  }
  if (op->sent_len == sizeof(op->sent) / sizeof(op->sent[0])) return;
  op->sent[op->sent_len++] = *to;

  const uint8_t *ns = op->unannounce ? HDHT_NS_UNANNOUNCE : HDHT_NS_ANNOUNCE;
  uint32_t command = op->unannounce ? HDHT_CMD_UNANNOUNCE : HDHT_CMD_ANNOUNCE;
  uint8_t value[128];
  int n = hdht_announce_encode_signed(value, sizeof(value), ns, op->topic, id, token, op->public_key, op->secret_key);
  if (n > 0 && hdht_request(op->dht, NULL, to, false, command, op->topic, token, value, (size_t) n, on_announce_reply, op)) op->pending++;
}

// unannounce: any node on the way that still lists our key
static void
on_unannounce_lookup_reply (hdht_query_t *q, const hdht_response_t *res) {
  announce_op_t *op = q->data;
  if (res->value == NULL || !res->has_token || !res->has_id) return;

  cdec_t d;
  cdec_init(&d, res->value, res->value_len);
  uint64_t n = cdec_uint(&d);
  for (uint64_t i = 0; i < n && !d.err; i++) {
    const uint8_t *public_key = cdec_raw(&d, 32);
    uint64_t relays = cdec_uint(&d);
    for (uint64_t j = 0; j < relays && !d.err; j++) cdec_raw(&d, 6);
    if (!d.err && memcmp(public_key, op->public_key, 32) == 0) {
      send_announce(op, &res->from, res->id, res->token);
      return;
    }
  }
}

static void
on_announce_lookup_done (hdht_query_t *q, int status) {
  (void) status;
  announce_op_t *op = q->data;
  op->querying = false;

  for (int i = 0; i < q->closest_len; i++) {
    const hdht_reply_ref_t *ref = &q->closest[i];
    if (ref->has_token) send_announce(op, &ref->from, ref->id, ref->token);
  }

  if (op->pending == 0) announce_finished(op);
}

static bool
query_pass (announce_op_t *op) {
  op->querying = true;
  op->sent_len = 0; // fresh tokens: every node may be asked again
  return hdht_query(op->dht, op->topic, false, HDHT_CMD_LOOKUP, NULL, 0, NULL, 0, op->unannounce ? on_unannounce_lookup_reply : NULL, on_announce_lookup_done, op) != NULL;
}

static void
start_pass (announce_op_t *op) {
  if (!query_pass(op)) {
    op->passes = 1;
    announce_finished(op);
  }
}

static int
announce_start (hdht_t *dht, const uint8_t topic[32], const uint8_t public_key[32], const uint8_t secret_key[64], bool unannounce, hdht_announce_cb cb, void *data) {
  announce_op_t *op = calloc(1, sizeof(announce_op_t));
  if (op == NULL) return HDHT_ENOMEM;
  op->dht = dht;
  memcpy(op->topic, topic, 32);
  memcpy(op->public_key, public_key, 32);
  memcpy(op->secret_key, secret_key, 64);
  op->unannounce = unannounce;
  op->passes = unannounce ? 2 : 1;
  op->cb = cb;
  op->data = data;

  if (!query_pass(op)) {
    sodium_memzero(op->secret_key, sizeof(op->secret_key));
    free(op);
    return HDHT_ENOMEM;
  }
  return 0;
}

int
hdht_announce (hdht_t *dht, const uint8_t topic[32], const uint8_t public_key[32], const uint8_t secret_key[64], hdht_announce_cb cb, void *data) {
  return announce_start(dht, topic, public_key, secret_key, false, cb, data);
}

int
hdht_unannounce (hdht_t *dht, const uint8_t topic[32], const uint8_t public_key[32], const uint8_t secret_key[64], hdht_announce_cb cb, void *data) {
  return announce_start(dht, topic, public_key, secret_key, true, cb, data);
}
