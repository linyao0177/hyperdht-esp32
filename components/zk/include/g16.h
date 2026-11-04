// Groth16 verification on alt_bn128 (the curve of snarkjs/circom and the
// EVM precompiles), on top of mcl.
//
// Encoding is the EVM calldata one: field elements 32 bytes big-endian, an
// Fp2 element imaginary part first. A proof is A.x A.y | B.x1 B.x0 B.y1 B.y0
// | C.x C.y (256 bytes); a public input is 32 bytes big-endian, < r.
// A verifying key is alpha (64) | beta (128) | gamma (128) | delta (128) |
// IC[0..n] (64 each).

#pragma once

#include <stddef.h>
#include <stdint.h>

#include <mcl/bn.h>

#define G16_MAX_PUBLIC 8
#define G16_PROOF_LEN 256

typedef struct {
  size_t n_public;
  mclBnGT alpha_beta;              // e(alpha, beta)
  mclBnG2 gamma_neg, delta_neg;    // negated: e(A, B) e(L, -gamma) e(C, -delta) = e(alpha, beta)
  mclBnG1 ic[G16_MAX_PUBLIC + 1];
} g16_vk_t;

// once, before anything else; 0 on success
int
g16_init (void);

// 0 on success, -1 if malformed or a point is off the curve or out of the group
int
g16_vk_load (g16_vk_t *vk, const uint8_t *buf, size_t len);

// 1 valid, 0 invalid, -1 malformed (a point off the curve or out of the
// group, a value out of range, or the wrong number of public inputs)
int
g16_verify (const g16_vk_t *vk, const uint8_t proof[G16_PROOF_LEN], const uint8_t (*pub)[32], size_t n_public);

// circomlib's Poseidon of 5 field elements (t = 6, 8 full and 60 partial
// rounds). g16_init loads its constants (14 KB of RAM)
void
g16_poseidon5 (mclBnFr *out, const mclBnFr in[5]);

// M of a camera event: Poseidon(seq, t_ms, ev_id, conf_permille, box_packed)
// with box_packed = x | y << 16 | w << 32 | h << 48, as 32 bytes big-endian
void
g16_event_hash (uint8_t out[32], uint64_t seq, uint64_t t_ms, uint64_t ev_id, uint64_t conf_permille, const uint16_t box[4]);
