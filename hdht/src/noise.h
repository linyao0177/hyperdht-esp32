// Noise handshakes as used by Holepunch: Noise_{IK,XX}_Ed25519_ChaChaPoly_BLAKE2b
// (noise-handshake + noise-curve-ed). HyperDHT uses IK through the DHT;
// SecretStream uses XX (or IK) in-band. See docs/PROTOCOL.md for the details
// that differ from the Noise spec defaults (64-byte hash, Ed25519 DH).

#ifndef HDHT_NOISE_H
#define HDHT_NOISE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define HDHT_NOISE_HASHLEN 64
#define HDHT_NOISE_MSG1_OVERHEAD (32 + 48 + 16)
#define HDHT_NOISE_MSG2_OVERHEAD (32 + 16)

typedef enum {
  HDHT_NOISE_IK,
  HDHT_NOISE_XX,
} hdht_noise_pattern_t;

typedef struct {
  hdht_noise_pattern_t pattern;
  uint8_t h[HDHT_NOISE_HASHLEN];
  uint8_t ck[HDHT_NOISE_HASHLEN];
  uint8_t k[32];
  bool has_key;
  uint32_t nonce;

  bool initiator;
  int step; // messages processed so far
  bool complete;

  uint8_t s_pk[32];
  uint8_t s_sk[64]; // libsodium Ed25519 secret key (seed || pk)
  uint8_t e_pk[32];
  uint8_t e_sk[64];
  bool has_e;
  uint8_t rs[32];
  uint8_t re[32];

  // valid once complete
  uint8_t tx[32];
  uint8_t rx[32];
  uint8_t hash[HDHT_NOISE_HASHLEN];
} hdht_noise_t;

// IK with a 32-byte prologue (HyperDHT). remote_static is required for the
// initiator and ignored for the responder.
void
hdht_noise_init (hdht_noise_t *n, bool initiator, const uint8_t s_pk[32], const uint8_t s_sk[64], const uint8_t *remote_static, const uint8_t prologue[32]);

// Any supported pattern and prologue. For IK the initiator needs remote_static.
void
hdht_noise_init_pattern (hdht_noise_t *n, hdht_noise_pattern_t pattern, bool initiator, const uint8_t s_pk[32], const uint8_t s_sk[64], const uint8_t *remote_static, const uint8_t *prologue, size_t prologue_len);

// Whether the next handshake message is ours to send.
bool
hdht_noise_my_turn (const hdht_noise_t *n);

// For tests: use a fixed ephemeral key pair instead of a random one.
void
hdht_noise_set_ephemeral (hdht_noise_t *n, const uint8_t e_pk[32], const uint8_t e_sk[64]);

// Writes the next handshake message. Returns its length, or -1.
int
hdht_noise_send (hdht_noise_t *n, const uint8_t *payload, size_t payload_len, uint8_t *out, size_t out_cap);

// Reads the next handshake message, writing the decrypted payload to out.
// Returns the payload length, or -1 if the message is malformed or forged.
int
hdht_noise_recv (hdht_noise_t *n, const uint8_t *msg, size_t msg_len, uint8_t *out, size_t out_cap);

// Wipes key material.
void
hdht_noise_clear (hdht_noise_t *n);

// Ed25519 DH as in noise-curve-ed. Returns 0 on success.
int
hdht_ed25519_dh (uint8_t out[32], const uint8_t local_sk[64], const uint8_t remote_pk[32]);

#endif
