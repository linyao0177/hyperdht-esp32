#include <string.h>

#include <sodium.h>

#include "noise.h"

#define HASHLEN  HDHT_NOISE_HASHLEN
#define BLOCKLEN 128

enum {
  TOK_E,
  TOK_S,
  TOK_EE,
  TOK_ES,
  TOK_SE,
  TOK_SS,
  TOK_END,
};

// Message patterns (noise-handshake HANDSHAKES); each list ends with TOK_END.
static const uint8_t IK_MESSAGES[][5] = {
  {TOK_E, TOK_ES, TOK_S, TOK_SS, TOK_END},
  {TOK_E, TOK_EE, TOK_SE, TOK_END},
};

static const uint8_t XX_MESSAGES[][5] = {
  {TOK_E, TOK_END},
  {TOK_E, TOK_EE, TOK_S, TOK_ES, TOK_END},
  {TOK_S, TOK_SE, TOK_END},
};

static int
message_count (const hdht_noise_t *n) {
  return n->pattern == HDHT_NOISE_IK ? 2 : 3;
}

static const uint8_t *
message_tokens (const hdht_noise_t *n, int step) {
  return n->pattern == HDHT_NOISE_IK ? IK_MESSAGES[step] : XX_MESSAGES[step];
}

// HMAC-BLAKE2b-512 over the concatenation of up to three inputs.
static void
hmac (uint8_t out[HASHLEN], const uint8_t *key, size_t key_len, const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len, const uint8_t *c, size_t c_len) {
  uint8_t k[BLOCKLEN] = {0};
  uint8_t pad[BLOCKLEN];

  if (key_len > BLOCKLEN) crypto_generichash(k, HASHLEN, key, key_len, NULL, 0);
  else memcpy(k, key, key_len);

  crypto_generichash_state st;

  for (int i = 0; i < BLOCKLEN; i++) pad[i] = k[i] ^ 0x36;
  crypto_generichash_init(&st, NULL, 0, HASHLEN);
  crypto_generichash_update(&st, pad, BLOCKLEN);
  if (a_len) crypto_generichash_update(&st, a, a_len);
  if (b_len) crypto_generichash_update(&st, b, b_len);
  if (c_len) crypto_generichash_update(&st, c, c_len);
  crypto_generichash_final(&st, out, HASHLEN);

  for (int i = 0; i < BLOCKLEN; i++) pad[i] = k[i] ^ 0x5c;
  crypto_generichash_init(&st, NULL, 0, HASHLEN);
  crypto_generichash_update(&st, pad, BLOCKLEN);
  crypto_generichash_update(&st, out, HASHLEN);
  crypto_generichash_final(&st, out, HASHLEN);

  sodium_memzero(k, sizeof(k));
  sodium_memzero(pad, sizeof(pad));
  sodium_memzero(&st, sizeof(st));
}

// HKDF with empty info producing two HASHLEN outputs.
static void
hkdf (uint8_t out1[HASHLEN], uint8_t out2[HASHLEN], const uint8_t salt[HASHLEN], const uint8_t *ikm, size_t ikm_len) {
  uint8_t prk[HASHLEN];
  const uint8_t one = 1, two = 2;

  hmac(prk, salt, HASHLEN, ikm, ikm_len, NULL, 0, NULL, 0);
  hmac(out1, prk, HASHLEN, &one, 1, NULL, 0, NULL, 0);
  hmac(out2, prk, HASHLEN, out1, HASHLEN, &two, 1, NULL, 0);

  sodium_memzero(prk, sizeof(prk));
}

static void
mix_hash (hdht_noise_t *n, const uint8_t *data, size_t len) {
  crypto_generichash_state st;
  crypto_generichash_init(&st, NULL, 0, HASHLEN);
  crypto_generichash_update(&st, n->h, HASHLEN);
  crypto_generichash_update(&st, data, len);
  crypto_generichash_final(&st, n->h, HASHLEN);
}

static int
mix_key (hdht_noise_t *n, const uint8_t local_sk[64], const uint8_t remote_pk[32]) {
  uint8_t dh[32];
  uint8_t t1[HASHLEN], t2[HASHLEN];

  if (hdht_ed25519_dh(dh, local_sk, remote_pk) != 0) return -1;

  hkdf(t1, t2, n->ck, dh, sizeof(dh));
  memcpy(n->ck, t1, HASHLEN);
  memcpy(n->k, t2, 32);
  n->has_key = true;
  n->nonce = 0;

  sodium_memzero(dh, sizeof(dh));
  sodium_memzero(t1, sizeof(t1));
  sodium_memzero(t2, sizeof(t2));
  return 0;
}

static void
nonce_bytes (uint8_t out[12], uint32_t counter) {
  memset(out, 0, 12);
  out[4] = (uint8_t) counter;
  out[5] = (uint8_t) (counter >> 8);
  out[6] = (uint8_t) (counter >> 16);
  out[7] = (uint8_t) (counter >> 24);
}

// Returns bytes written to out, or -1.
static int
encrypt_and_hash (hdht_noise_t *n, const uint8_t *plain, size_t len, uint8_t *out, size_t cap) {
  size_t out_len = n->has_key ? len + 16 : len;
  if (out_len > cap) return -1;

  if (n->has_key) {
    uint8_t nonce[12];
    unsigned long long clen;
    nonce_bytes(nonce, n->nonce++);
    crypto_aead_chacha20poly1305_ietf_encrypt(out, &clen, plain, len, n->h, HASHLEN, NULL, nonce, n->k);
  } else {
    memmove(out, plain, len);
  }

  mix_hash(n, out, out_len);
  return (int) out_len;
}

static int
decrypt_and_hash (hdht_noise_t *n, const uint8_t *cipher, size_t len, uint8_t *out, size_t cap) {
  if (!n->has_key) {
    if (len > cap) return -1;
    memmove(out, cipher, len);
    mix_hash(n, cipher, len);
    return (int) len;
  }

  if (len < 16 || len - 16 > cap) return -1;

  uint8_t nonce[12];
  unsigned long long plen;
  nonce_bytes(nonce, n->nonce++);
  if (crypto_aead_chacha20poly1305_ietf_decrypt(out, &plen, NULL, cipher, len, n->h, HASHLEN, nonce, n->k) != 0) {
    return -1;
  }

  mix_hash(n, cipher, len);
  return (int) plen;
}

static void
split (hdht_noise_t *n) {
  uint8_t k1[HASHLEN], k2[HASHLEN];
  hkdf(k1, k2, n->ck, NULL, 0);

  memcpy(n->tx, n->initiator ? k1 : k2, 32);
  memcpy(n->rx, n->initiator ? k2 : k1, 32);
  memcpy(n->hash, n->h, HASHLEN);
  n->complete = true;

  sodium_memzero(k1, sizeof(k1));
  sodium_memzero(k2, sizeof(k2));
  sodium_memzero(n->ck, sizeof(n->ck));
  sodium_memzero(n->k, sizeof(n->k));
  sodium_memzero(n->e_sk, sizeof(n->e_sk));
}

int
hdht_ed25519_dh (uint8_t out[32], const uint8_t local_sk[64], const uint8_t remote_pk[32]) {
  uint8_t h[64];
  crypto_hash_sha512(h, local_sk, 32); // libsodium keeps the seed, not the scalar
  h[0] &= 248;
  h[31] &= 127;
  h[31] |= 64;

  int r = crypto_scalarmult_ed25519_noclamp(out, h, remote_pk);
  sodium_memzero(h, sizeof(h));
  return r;
}

void
hdht_noise_init_pattern (hdht_noise_t *n, hdht_noise_pattern_t pattern, bool initiator, const uint8_t s_pk[32], const uint8_t s_sk[64], const uint8_t *remote_static, const uint8_t *prologue, size_t prologue_len) {
  memset(n, 0, sizeof(*n));
  n->pattern = pattern;
  n->initiator = initiator;
  memcpy(n->s_pk, s_pk, 32);
  memcpy(n->s_sk, s_sk, 64);

  // "Noise_IK_Ed25519_ChaChaPoly_BLAKE2b" is 35 bytes, so it fits the 64-byte hash as is
  const char *name = pattern == HDHT_NOISE_IK ? "Noise_IK_Ed25519_ChaChaPoly_BLAKE2b" : "Noise_XX_Ed25519_ChaChaPoly_BLAKE2b";
  memcpy(n->h, name, strlen(name));
  memcpy(n->ck, n->h, HASHLEN);

  mix_hash(n, prologue, prologue_len);

  // IK pre-message: the responder's static key
  if (pattern == HDHT_NOISE_IK) {
    if (initiator) {
      memcpy(n->rs, remote_static, 32);
      mix_hash(n, n->rs, 32);
    } else {
      mix_hash(n, n->s_pk, 32);
    }
  }
}

void
hdht_noise_init (hdht_noise_t *n, bool initiator, const uint8_t s_pk[32], const uint8_t s_sk[64], const uint8_t *remote_static, const uint8_t prologue[32]) {
  hdht_noise_init_pattern(n, HDHT_NOISE_IK, initiator, s_pk, s_sk, remote_static, prologue, 32);
}

void
hdht_noise_set_ephemeral (hdht_noise_t *n, const uint8_t e_pk[32], const uint8_t e_sk[64]) {
  memcpy(n->e_pk, e_pk, 32);
  memcpy(n->e_sk, e_sk, 64);
  n->has_e = true;
}

bool
hdht_noise_my_turn (const hdht_noise_t *n) {
  // the initiator sends the even-numbered messages
  return !n->complete && (n->step % 2 == 0) == n->initiator;
}

// DH for a mixed token: which of our keys and which remote key (noise.js keyPattern)
static int
mix_token (hdht_noise_t *n, int tok) {
  bool local_static, remote_static;
  switch (tok) {
  case TOK_EE:
    local_static = false;
    remote_static = false;
    break;
  case TOK_ES:
    local_static = !n->initiator;
    remote_static = n->initiator;
    break;
  case TOK_SE:
    local_static = n->initiator;
    remote_static = !n->initiator;
    break;
  default: // TOK_SS
    local_static = true;
    remote_static = true;
  }
  return mix_key(n, local_static ? n->s_sk : n->e_sk, remote_static ? n->rs : n->re);
}

static void
finish_message (hdht_noise_t *n) {
  n->step++;
  if (n->step == message_count(n)) split(n);
}

int
hdht_noise_send (hdht_noise_t *n, const uint8_t *payload, size_t payload_len, uint8_t *out, size_t out_cap) {
  if (!hdht_noise_my_turn(n)) return -1;

  size_t pos = 0;
  int r;

  for (const uint8_t *tok = message_tokens(n, n->step); *tok != TOK_END; tok++) {
    switch (*tok) {
    case TOK_E:
      if (out_cap - pos < 32) return -1;
      if (!n->has_e) {
        crypto_sign_keypair(n->e_pk, n->e_sk);
        n->has_e = true;
      }
      mix_hash(n, n->e_pk, 32);
      memcpy(out + pos, n->e_pk, 32);
      pos += 32;
      break;

    case TOK_S:
      r = encrypt_and_hash(n, n->s_pk, 32, out + pos, out_cap - pos);
      if (r < 0) return -1;
      pos += (size_t) r;
      break;

    default:
      if (mix_token(n, *tok) != 0) return -1;
    }
  }

  r = encrypt_and_hash(n, payload, payload_len, out + pos, out_cap - pos);
  if (r < 0) return -1;
  pos += (size_t) r;

  finish_message(n);
  return (int) pos;
}

int
hdht_noise_recv (hdht_noise_t *n, const uint8_t *msg, size_t msg_len, uint8_t *out, size_t out_cap) {
  if (n->complete || hdht_noise_my_turn(n)) return -1;

  size_t pos = 0;

  for (const uint8_t *tok = message_tokens(n, n->step); *tok != TOK_END; tok++) {
    switch (*tok) {
    case TOK_E:
      if (msg_len - pos < 32) return -1;
      memcpy(n->re, msg + pos, 32);
      mix_hash(n, n->re, 32);
      pos += 32;
      break;

    case TOK_S: {
      size_t klen = n->has_key ? 48 : 32;
      if (msg_len - pos < klen) return -1;
      uint8_t rs[32];
      if (decrypt_and_hash(n, msg + pos, klen, rs, sizeof(rs)) != 32) return -1;
      memcpy(n->rs, rs, 32);
      pos += klen;
      break;
    }

    default:
      if (mix_token(n, *tok) != 0) return -1;
    }
  }

  int r = decrypt_and_hash(n, msg + pos, msg_len - pos, out, out_cap);
  if (r < 0) return -1;

  finish_message(n);
  return r;
}

void
hdht_noise_clear (hdht_noise_t *n) {
  sodium_memzero(n, sizeof(*n));
}
