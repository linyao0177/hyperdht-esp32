// Hypercore proofs, checked on a device.
//
// A Hypercore is an append-only log signed by its writer: a Merkle tree over
// its blocks (BLAKE2b-256, flat-tree layout), whose roots the writer signs.
// With the core's key and its signer's public key, a device can check that a
// block belongs to the core without trusting whoever sent it:
//
//   - a signed tree head: the roots, the length, the fork and the signature,
//     over TREE ‖ key ‖ BLAKE2b(0x02 ‖ roots) ‖ length ‖ fork (hypercore 11,
//     manifest version 1, lib/caps.js treeSignable)
//   - per block: its data and the sibling nodes from its leaf up to a root
//
// This is hypercore's own hashing (hypercore-crypto), so the proofs come from
// any peer that holds the core (packages/boat-ota makes them).

#ifndef HC_PROOF_H
#define HC_PROOF_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define HC_MAX_ROOTS 64
#define HC_MAX_NODES 64

typedef struct {
  uint64_t index; // flat-tree index
  uint64_t size;  // bytes under the node
  uint8_t hash[32];
} hc_node_t;

typedef struct {
  uint64_t length;
  uint64_t fork;
  uint8_t signature[64];
  size_t nroots;
  hc_node_t roots[HC_MAX_ROOTS];
} hc_head_t;

// flat-tree
uint64_t
hc_flat_parent (uint64_t index);

uint64_t
hc_flat_sibling (uint64_t index);

// the root indexes of a tree of `length` blocks; their count
size_t
hc_full_roots (uint64_t length, uint64_t *out, size_t cap);

// hypercore-crypto
void
hc_leaf_hash (const uint8_t *data, size_t len, uint8_t out[32]);

void
hc_parent_hash (const hc_node_t *a, const hc_node_t *b, uint8_t out[32]);

void
hc_tree_hash (const hc_node_t *roots, size_t nroots, uint8_t out[32]);

// NULL when the head is signed by `signer` for the core `key` and its roots
// are the roots of a tree of its length, else why not
const char *
hc_verify_head (const hc_head_t *head, const uint8_t key[32], const uint8_t signer[32]);

// NULL when block `index` with these sibling nodes leads to a root of a head
// already verified, else why not
const char *
hc_verify_block (const hc_head_t *head, uint64_t index, const uint8_t *data, size_t len, const hc_node_t *nodes, size_t nnodes);

// packages/boat-ota/lib/wire.js answers, little-endian. NULL when well formed.
// head: 'H' length fork signature[64] latest roots; *latest is UINT64_MAX for none
const char *
hc_decode_head (const uint8_t *buf, size_t len, hc_head_t *head, uint64_t *latest);

// block: 'B' index nodes data; *data points into buf
const char *
hc_decode_block (const uint8_t *buf, size_t len, uint64_t *index, hc_node_t *nodes, size_t *nnodes, const uint8_t **data, size_t *data_len);

#endif
