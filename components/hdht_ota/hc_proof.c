// See hc_proof.h.

#include <string.h>

#include <sodium.h>

#include "hc_proof.h"

static void
u64le (uint8_t out[8], uint64_t v) {
  for (int i = 0; i < 8; i++) out[i] = (uint8_t) (v >> (8 * i));
}

static unsigned
depth (uint64_t index) {
  unsigned d = 0;
  while (index & 1) {
    index >>= 1;
    d++;
  }
  return d;
}

static uint64_t
offset (uint64_t index, unsigned d) {
  if (!(index & 1)) return index / 2;
  return ((index + 1) / ((uint64_t) 1 << d) - 1) / 2;
}

static uint64_t
flat_index (unsigned d, uint64_t off) {
  return (1 + 2 * off) * ((uint64_t) 1 << d) - 1;
}

uint64_t
hc_flat_parent (uint64_t index) {
  unsigned d = depth(index);
  return flat_index(d + 1, offset(index, d) >> 1);
}

uint64_t
hc_flat_sibling (uint64_t index) {
  unsigned d = depth(index);
  uint64_t off = offset(index, d);
  return flat_index(d, off & 1 ? off - 1 : off + 1);
}

size_t
hc_full_roots (uint64_t length, uint64_t *out, size_t cap) {
  size_t n = 0;
  uint64_t index = length, off = 0;
  while (index) {
    uint64_t factor = 1;
    while (factor * 2 <= index) factor *= 2;
    if (n == cap) return cap + 1;
    out[n++] = off + factor - 1;
    off += 2 * factor;
    index -= factor;
  }
  return n;
}

void
hc_leaf_hash (const uint8_t *data, size_t len, uint8_t out[32]) {
  crypto_generichash_state st;
  uint8_t type = 0, size[8];
  u64le(size, len);
  crypto_generichash_init(&st, NULL, 0, 32);
  crypto_generichash_update(&st, &type, 1);
  crypto_generichash_update(&st, size, 8);
  crypto_generichash_update(&st, data, len);
  crypto_generichash_final(&st, out, 32);
}

void
hc_parent_hash (const hc_node_t *a, const hc_node_t *b, uint8_t out[32]) {
  if (a->index > b->index) {
    const hc_node_t *t = a;
    a = b;
    b = t;
  }
  crypto_generichash_state st;
  uint8_t type = 1, size[8];
  u64le(size, a->size + b->size);
  crypto_generichash_init(&st, NULL, 0, 32);
  crypto_generichash_update(&st, &type, 1);
  crypto_generichash_update(&st, size, 8);
  crypto_generichash_update(&st, a->hash, 32);
  crypto_generichash_update(&st, b->hash, 32);
  crypto_generichash_final(&st, out, 32);
}

void
hc_tree_hash (const hc_node_t *roots, size_t nroots, uint8_t out[32]) {
  crypto_generichash_state st;
  uint8_t type = 2, w[8];
  crypto_generichash_init(&st, NULL, 0, 32);
  crypto_generichash_update(&st, &type, 1);
  for (size_t i = 0; i < nroots; i++) {
    crypto_generichash_update(&st, roots[i].hash, 32);
    u64le(w, roots[i].index);
    crypto_generichash_update(&st, w, 8);
    u64le(w, roots[i].size);
    crypto_generichash_update(&st, w, 8);
  }
  crypto_generichash_final(&st, out, 32);
}

// hypercore-crypto namespace('hypercore', ...)[0]: BLAKE2b(BLAKE2b("hypercore") ‖ 0)
static void
tree_namespace (uint8_t out[32]) {
  uint8_t ns[33];
  crypto_generichash(ns, 32, (const uint8_t *) "hypercore", 9, NULL, 0);
  ns[32] = 0;
  crypto_generichash(out, 32, ns, 33, NULL, 0);
}

const char *
hc_verify_head (const hc_head_t *head, const uint8_t key[32], const uint8_t signer[32]) {
  if (head->length == 0) return "empty core";
  uint64_t want[HC_MAX_ROOTS];
  size_t n = hc_full_roots(head->length, want, HC_MAX_ROOTS);
  if (n != head->nroots) return "wrong number of roots";
  for (size_t i = 0; i < n; i++) {
    if (head->roots[i].index != want[i]) return "roots do not match the length";
  }

  uint8_t signable[112];
  tree_namespace(signable);
  memcpy(signable + 32, key, 32);
  hc_tree_hash(head->roots, head->nroots, signable + 64);
  u64le(signable + 96, head->length);
  u64le(signable + 104, head->fork);
  if (crypto_sign_verify_detached(head->signature, signable, sizeof(signable), signer) != 0) return "bad signature";
  return NULL;
}

const char *
hc_verify_block (const hc_head_t *head, uint64_t index, const uint8_t *data, size_t len, const hc_node_t *nodes, size_t nnodes) {
  if (index >= head->length) return "block beyond the signed length";
  hc_node_t node = {.index = 2 * index, .size = len};
  hc_leaf_hash(data, len, node.hash);
  for (size_t i = 0;; i++) {
    for (size_t r = 0; r < head->nroots; r++) {
      if (head->roots[r].index == node.index) {
        if (head->roots[r].size != node.size || sodium_memcmp(head->roots[r].hash, node.hash, 32) != 0) return "does not hash to the signed root";
        return i == nnodes ? NULL : "extra nodes";
      }
    }
    if (i == nnodes) return "nodes end before a root";
    if (nodes[i].index != hc_flat_sibling(node.index)) return "node is not the sibling";
    hc_node_t parent = {.index = hc_flat_parent(node.index), .size = node.size + nodes[i].size};
    hc_parent_hash(&node, &nodes[i], parent.hash);
    node = parent;
  }
}

static uint64_t
read_u64 (const uint8_t *p) {
  uint64_t v = 0;
  for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
  return v;
}

static const char *
decode_nodes (const uint8_t *buf, size_t len, size_t *at, hc_node_t *nodes, size_t *n, size_t cap) {
  if (*at >= len) return "truncated";
  size_t count = buf[(*at)++];
  if (count > cap) return "too many nodes";
  if (len - *at < count * 48) return "truncated nodes";
  for (size_t i = 0; i < count; i++) {
    const uint8_t *p = buf + *at + i * 48;
    nodes[i].index = read_u64(p);
    nodes[i].size = read_u64(p + 8);
    memcpy(nodes[i].hash, p + 16, 32);
  }
  *at += count * 48;
  *n = count;
  return NULL;
}

const char *
hc_decode_head (const uint8_t *buf, size_t len, hc_head_t *head, uint64_t *latest) {
  if (len < 89 || buf[0] != 'H') return "not a head";
  head->length = read_u64(buf + 1);
  head->fork = read_u64(buf + 9);
  memcpy(head->signature, buf + 17, 64);
  *latest = read_u64(buf + 81);
  size_t at = 89;
  const char *why = decode_nodes(buf, len, &at, head->roots, &head->nroots, HC_MAX_ROOTS);
  if (why) return why;
  return at == len ? NULL : "trailing bytes";
}

const char *
hc_decode_block (const uint8_t *buf, size_t len, uint64_t *index, hc_node_t *nodes, size_t *nnodes, const uint8_t **data, size_t *data_len) {
  if (len < 10 || buf[0] != 'B') return "not a block";
  *index = read_u64(buf + 1);
  size_t at = 9;
  const char *why = decode_nodes(buf, len, &at, nodes, nnodes, HC_MAX_NODES);
  if (why) return why;
  *data = buf + at;
  *data_len = len - at;
  return NULL;
}
