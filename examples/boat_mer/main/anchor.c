// Distributed anchoring: the device submits each signed reading to several
// open anchor nodes (tools/host/anchor-node.js) instead of one HashAnchor
// server.
//
// - Nodes are found by key (CONFIG_MER_ANCHOR_NODES). Before connecting, the
//   device reads the node's DID record; the node's quote must name the wallet
//   in that record, or the device does not pay.
// - Every CONFIG_MER_ANCHOR_INTERVAL_S seconds MER attests a reading (SHA-256 +
//   Ed25519). The hash and signature go to every connected node, each with an
//   EIP-3009 payment of the node's fee.
// - A node answers with a receipt once its batch is anchored. The device
//   recomputes the leaf, keccak256(hash || public key || signature), and walks
//   the Merkle proof to the root before accepting it. It cannot check the
//   chain itself; anchor-verify.js does that.
// - Submitting to several nodes means one node that drops a hash cannot
//   censor it; overdue receipts are logged.
//
// Messages are JSON, one per stream message:
//   node -> device  {"t":"quote","pay_to","amount","valid_before","batch_s"}
//   device -> node  {"t":"submit","hash","sig","pay":{EIP-3009 proof}}
//   node -> device  {"t":"accepted"|"rejected","hash","reason"?}
//   node -> device  {"t":"receipt","hash","leaf","root","proof":[...],"tx","block","chain_id"}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_random.h"
#include "esp_timer.h"

#include "boat_attest.h"
#include "boat_crypto.h"
#include "boat_nano.h"
#include "esp_heap_caps.h"
#include "mer.h"

#define MAX_NODES   3
#define MAX_PENDING 8
#define MAX_FEE     100 // micro-USDC we accept to pay per submission
#define OVERDUE_S   120

typedef struct {
  uint8_t hash[32];
  uint8_t sig[64];
  int64_t sent_at;
  bool used;
  bool overdue_logged;
} pending_t;

typedef struct {
  int index;
  uint8_t key[32];
  hdht_stream_t stream;
  bool up;
  bool busy;
  uint32_t ticks_down;

  bool has_record;
  uint8_t wallet[20]; // from the node's DID record
  bool has_quote;
  uint64_t amount;
  uint32_t valid_before;

  pending_t pending[MAX_PENDING];

  struct {
    uint32_t submitted;
    uint32_t accepted;
    uint32_t rejected;
    uint32_t receipts;
    uint32_t bad_receipts;
    uint32_t overdue;
  } stats;
} node_t;

static node_t nodes[MAX_NODES];
static int nodes_len;
static bool started;
static uint32_t readings;

static void
connect_node (node_t *n);

static node_t *
node_of (hdht_stream_t *s) {
  return (node_t *) s->data;
}

static void
hex_to (const char *hex, uint8_t *out, size_t len) {
  if (boat_hex_to_bytes(hex, out, len) != (int) len) memset(out, 0, len);
}

// receipt: leaf = keccak(hash || pk || sig), then sorted-pair keccak up to the root
static bool
check_receipt (const pending_t *p, const char *json, char *root_hex, size_t root_cap) {
  char leaf_hex[70], data_hex[70];
  if (!json_str(json, "leaf", leaf_hex, sizeof(leaf_hex)) || !json_str(json, "root", root_hex, root_cap)) return false;

  uint8_t buf[128], leaf[32], claimed[32], root[32];
  memcpy(buf, p->hash, 32);
  memcpy(buf + 32, kp.ed25519_pk, 32);
  memcpy(buf + 64, p->sig, 64);
  boat_keccak256(buf, 128, leaf);
  hex_to(leaf_hex, claimed, 32);
  if (memcmp(leaf, claimed, 32) != 0) return false;

  uint8_t h[32];
  memcpy(h, leaf, 32);
  const char *proof = strstr(json, "\"proof\":[");
  for (const char *q = proof; q && (q = strstr(q, "\"data\":\"")) != NULL; q++) {
    const char *end = strchr(q + 8, '"');
    if (end == NULL || (size_t) (end - (q + 8)) >= sizeof(data_hex)) return false;
    memcpy(data_hex, q + 8, end - (q + 8));
    data_hex[end - (q + 8)] = '\0';
    uint8_t d[32], pair[64];
    hex_to(data_hex, d, 32);
    bool first = memcmp(h, d, 32) <= 0;
    memcpy(pair, first ? h : d, 32);
    memcpy(pair + 32, first ? d : h, 32);
    boat_keccak256(pair, 64, h);
  }
  hex_to(root_hex, root, 32);
  return memcmp(h, root, 32) == 0;
}

static pending_t *
find_pending (node_t *n, const char *hash_hex) {
  uint8_t hash[32];
  hex_to(hash_hex, hash, 32);
  for (int i = 0; i < MAX_PENDING; i++) {
    if (n->pending[i].used && memcmp(n->pending[i].hash, hash, 32) == 0) return &n->pending[i];
  }
  return NULL;
}

static void
on_node_data (hdht_stream_t *s, const uint8_t *data, size_t len) {
  node_t *n = node_of(s);
  static char json[1024];
  if (len >= sizeof(json)) return;
  memcpy(json, data, len);
  json[len] = '\0';

  char t[16], hash_hex[70];
  if (!json_str(json, "t", t, sizeof(t))) return;

  if (strcmp(t, "quote") == 0) {
    char pay_to[48], amount[24];
    uint8_t to[20];
    if (!json_str(json, "pay_to", pay_to, sizeof(pay_to)) || !json_str(json, "amount", amount, sizeof(amount))) return;
    hex_to(pay_to, to, 20);
    const char *vb = strstr(json, "\"valid_before\":");
    n->amount = strtoull(amount, NULL, 10);
    n->valid_before = vb ? (uint32_t) strtoul(vb + 15, NULL, 10) : 0;
    // pay only the wallet the node's DID record names, and only a sane fee
    n->has_quote = memcmp(to, n->wallet, 20) == 0 && n->amount <= MAX_FEE && n->valid_before > 0;
    printf("MER|anchor node%d quote pay_to=%s amount=%llu %s\n", n->index, pay_to, (unsigned long long) n->amount, n->has_quote ? "ok" : "REFUSED (not the record wallet or fee too high)");
    if (!n->has_quote) hdht_stream_destroy(s, HDHT_STREAM_ECLOSED);
  } else if (strcmp(t, "accepted") == 0) {
    n->stats.accepted++;
  } else if (strcmp(t, "rejected") == 0) {
    char reason[64] = "";
    json_str(json, "reason", reason, sizeof(reason));
    n->stats.rejected++;
    printf("MER|anchor node%d rejected: %s\n", n->index, reason);
  } else if (strcmp(t, "receipt") == 0) {
    if (!json_str(json, "hash", hash_hex, sizeof(hash_hex))) return;
    pending_t *p = find_pending(n, hash_hex);
    if (p == NULL) return;
    char root_hex[70], tx[70] = "";
    json_str(json, "tx", tx, sizeof(tx));
    const char *blk = strstr(json, "\"block\":");
    bool ok = check_receipt(p, json, root_hex, sizeof(root_hex));
    long ms = (long) ((esp_timer_get_time() - p->sent_at) / 1000);
    if (ok) n->stats.receipts++;
    else n->stats.bad_receipts++;
    printf("MER|anchor node%d receipt hash=%.16s... proof=%s root=%.18s... tx=%.18s... block=%lu latency_ms=%ld\n", n->index, hash_hex, ok ? "valid" : "INVALID", root_hex, tx, blk ? strtoul(blk + 8, NULL, 10) : 0, ms);
    p->used = false;
  }
}

static void
on_node_open (hdht_stream_t *s) {
  node_t *n = node_of(s);
  n->up = true;
  printf("MER|anchor node%d connected via %s\n", n->index, hdht_addr_str(&s->remote_addr));
}

static void
on_node_close (hdht_stream_t *s, int error) {
  node_t *n = node_of(s);
  if (n->up || error) printf("MER|anchor node%d closed error=%d\n", n->index, error);
  n->up = false;
  n->busy = false;
  n->has_quote = false;
  n->ticks_down = 0;
}

static void
on_node_record (hdht_t *d, int status, uint64_t seq, const uint8_t *value, size_t len, void *data) {
  (void) d;
  (void) seq;
  node_t *n = data;
  n->has_record = status == 0 && verify_record(n->key, value, len, n->wallet);
  printf("MER|anchor node%d record %s\n", n->index, n->has_record ? "valid" : "missing or invalid: not connecting");
  if (!n->has_record) {
    n->busy = false;
    n->ticks_down = 0;
    return;
  }
  connect_node(n);
}

static void
connect_node (node_t *n) {
  if (hdht_connect(&dht, &n->stream, n->key, on_node_open, on_node_data, on_node_close, n) != 0) {
    n->busy = false;
    n->ticks_down = 0;
  }
}

static void
resolve_node (node_t *n) {
  n->busy = true;
  if (hdht_mutable_get(&dht, n->key, 0, on_node_record, n) != 0) n->busy = false;
}

static void
submit (node_t *n, const boat_attestation_t *att) {
  pending_t *p = NULL;
  for (int i = 0; i < MAX_PENDING && p == NULL; i++) {
    if (!n->pending[i].used) p = &n->pending[i];
  }
  if (p == NULL) return; // too many outstanding; the overdue log shows it

  uint8_t gateway[20];
  hex_to(CONFIG_MER_GATEWAY_CONTRACT, gateway, 20);
  boat_nano_slice_t slice = {.valid_after = 0, .valid_before = n->valid_before};
  esp_fill_random(slice.nonce, 32);
  boat_nano_auth_t auth;
  int64_t t0 = esp_timer_get_time();
  if (boat_nano_sign(&kp, n->wallet, n->amount, CONFIG_MER_CHAIN_ID, gateway, "GatewayWalletBatched", "1", &slice, &auth) != BOAT_OK) return;
  long pay_ms = (long) ((esp_timer_get_time() - t0) / 1000);

  uint8_t sig65[65];
  memcpy(sig65, auth.r, 32);
  memcpy(sig65 + 32, auth.s, 32);
  sig65[64] = auth.v;
  char hash_hex[65], sig_hex[129], pay_sig[131], from[41], to[41], nonce[65];
  boat_bytes_to_hex(att->hash, 32, hash_hex);
  boat_bytes_to_hex(att->signature, 64, sig_hex);
  boat_bytes_to_hex(sig65, 65, pay_sig);
  boat_bytes_to_hex(auth.from, 20, from);
  boat_bytes_to_hex(auth.to, 20, to);
  boat_bytes_to_hex(auth.nonce, 32, nonce);

  static char msg[900];
  int len = snprintf(msg, sizeof(msg), "{\"t\":\"submit\",\"hash\":\"%s\",\"sig\":\"%s\",\"pay\":{\"sig\":\"0x%s\",\"from\":\"0x%s\",\"to\":\"0x%s\",\"value\":\"%llu\",\"validAfter\":%lu,\"validBefore\":%lu,\"nonce\":\"0x%s\"}}", hash_hex, sig_hex, pay_sig, from, to, (unsigned long long) n->amount, (unsigned long) auth.valid_after, (unsigned long) auth.valid_before, nonce);
  if (len <= 0 || (size_t) len >= sizeof(msg)) return;
  if (hdht_stream_write(&n->stream, (const uint8_t *) msg, (size_t) len) != 0) return;

  memcpy(p->hash, att->hash, 32);
  memcpy(p->sig, att->signature, 64);
  p->sent_at = esp_timer_get_time();
  p->used = true;
  p->overdue_logged = false;
  n->stats.submitted++;
  printf("MER|anchor node%d submit hash=%.16s... pay_sign_ms=%ld\n", n->index, hash_hex, pay_ms);
}

static void
attest_and_submit (void) {
  int ready = 0;
  for (int i = 0; i < nodes_len; i++) ready += nodes[i].up && nodes[i].has_quote;
  if (ready == 0) return;

  char payload[96];
  snprintf(payload, sizeof(payload), "{\"reading\":%lu,\"uptime_s\":%llu,\"free_heap\":%u}", (unsigned long) ++readings, (unsigned long long) (esp_timer_get_time() / 1000000), (unsigned) heap_caps_get_free_size(MALLOC_CAP_8BIT));
  boat_attestation_t att;
  int64_t t0 = esp_timer_get_time();
  if (boat_attest_create(&kp, payload, &att) != BOAT_OK) return;
  char hash_hex[65];
  boat_bytes_to_hex(att.hash, 32, hash_hex);
  printf("MER|anchor reading %lu hash=%s attest_ms=%ld nodes=%d payload=%s\n", (unsigned long) readings, hash_hex, (long) ((esp_timer_get_time() - t0) / 1000), ready, payload);

  for (int i = 0; i < nodes_len; i++) {
    if (nodes[i].up && nodes[i].has_quote) submit(&nodes[i], &att);
  }
}

bool
anchor_enabled (void) {
  return CONFIG_MER_ANCHOR_NODES[0] != '\0';
}

void
anchor_start (void) {
  if (started || !anchor_enabled()) return;
  started = true;

  // comma-separated hex keys
  const char *s = CONFIG_MER_ANCHOR_NODES;
  while (*s && nodes_len < MAX_NODES) {
    node_t *n = &nodes[nodes_len];
    if (strlen(s) < 64 || sodium_hex2bin(n->key, 32, s, 64, NULL, NULL, NULL) != 0) break;
    n->index = ++nodes_len;
    n->stream.data = n;
    s += 64;
    while (*s == ',' || *s == ' ') s++;
  }
  printf("MER|anchor nodes=%d interval_s=%d\n", nodes_len, CONFIG_MER_ANCHOR_INTERVAL_S);
  for (int i = 0; i < nodes_len; i++) resolve_node(&nodes[i]);
}

void
anchor_tick (uint32_t ticks) {
  if (!started) return;
  int64_t now = esp_timer_get_time();

  for (int i = 0; i < nodes_len; i++) {
    node_t *n = &nodes[i];
    if (!n->up && !n->busy && ++n->ticks_down >= 5) resolve_node(n);

    for (int j = 0; j < MAX_PENDING; j++) {
      pending_t *p = &n->pending[j];
      if (p->used && !p->overdue_logged && now - p->sent_at > OVERDUE_S * 1000000LL) {
        p->overdue_logged = true;
        n->stats.overdue++;
        char hex[17];
        boat_bytes_to_hex(p->hash, 8, hex);
        printf("MER|anchor node%d receipt OVERDUE hash=%s... (accepted but not anchored after %d s)\n", n->index, hex, OVERDUE_S);
      }
    }
  }

  if (ticks % CONFIG_MER_ANCHOR_INTERVAL_S == 0) attest_and_submit();

  if (ticks % 60 == 0) {
    for (int i = 0; i < nodes_len; i++) {
      node_t *n = &nodes[i];
      printf("MER|anchor node%d stats submitted=%lu accepted=%lu rejected=%lu receipts=%lu bad=%lu overdue=%lu\n", n->index, (unsigned long) n->stats.submitted, (unsigned long) n->stats.accepted, (unsigned long) n->stats.rejected, (unsigned long) n->stats.receipts, (unsigned long) n->stats.bad_receipts, (unsigned long) n->stats.overdue);
    }
  }
}
