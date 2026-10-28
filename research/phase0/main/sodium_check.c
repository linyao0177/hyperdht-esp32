#include <stdio.h>
#include <string.h>

#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sodium.h"

#include "sodium_check.h"
#include "sodium_vectors.h"

#define BENCH_BUF 1024

static int failures;

static void
check (const char *name, int ok) {
  printf("POC|sodium|check|%s|%s\n", name, ok ? "ok" : "FAIL");
  if (!ok) failures++;
}

static void
make_seeds (unsigned char a[32], unsigned char b[32]) {
  for (int i = 0; i < 32; i++) a[i] = (unsigned char) (i + 1);
  for (int i = 0; i < 32; i++) b[i] = (unsigned char) (i + 0x21);
}

// noise-curve-ed's dh(): the Ed25519 seed is hashed and clamped into a scalar.
static int
ed_dh (unsigned char out[32], const unsigned char seed[32], const unsigned char pk[32]) {
  unsigned char sk[64];
  crypto_hash_sha512(sk, seed, 32);
  sk[0] &= 248;
  sk[31] &= 127;
  sk[31] |= 64;
  return crypto_scalarmult_ed25519_noclamp(out, sk, pk);
}

static void
run_checks (void) {
  unsigned char seed_a[32], seed_b[32], nonce12[12], nonce24[24];
  make_seeds(seed_a, seed_b);
  for (int i = 0; i < 12; i++) nonce12[i] = (unsigned char) i;
  for (int i = 0; i < 24; i++) nonce24[i] = (unsigned char) i;

  const unsigned char *msg = (const unsigned char *) VEC_MSG;
  size_t msg_len = strlen(VEC_MSG);

  unsigned char pk_a[32], sk_a[64], pk_b[32], sk_b[64];
  crypto_sign_seed_keypair(pk_a, sk_a, seed_a);
  crypto_sign_seed_keypair(pk_b, sk_b, seed_b);
  check("ed25519_seed_keypair", memcmp(pk_a, vec_pk_a, 32) == 0 && memcmp(pk_b, vec_pk_b, 32) == 0);

  unsigned char sig[64];
  crypto_sign_detached(sig, NULL, msg, msg_len, sk_a);
  check("ed25519_sign", memcmp(sig, vec_sig_a, 64) == 0);
  check("ed25519_verify", crypto_sign_verify_detached(sig, msg, msg_len, pk_a) == 0);
  sig[0] ^= 1;
  check("ed25519_verify_rejects_tampered", crypto_sign_verify_detached(sig, msg, msg_len, pk_a) != 0);

  unsigned char dh_ab[32], dh_ba[32];
  int r1 = ed_dh(dh_ab, seed_a, pk_b);
  int r2 = ed_dh(dh_ba, seed_b, pk_a);
  check("ed25519_dh_noclamp", r1 == 0 && memcmp(dh_ab, vec_dh_ab, 32) == 0);
  check("ed25519_dh_symmetric", r2 == 0 && memcmp(dh_ab, dh_ba, 32) == 0);

  unsigned char out32[32], out64[64];
  crypto_generichash(out32, 32, msg, msg_len, NULL, 0);
  check("blake2b", memcmp(out32, vec_blake2b, 32) == 0);
  crypto_generichash(out32, 32, msg, msg_len, pk_a, 32);
  check("blake2b_keyed", memcmp(out32, vec_blake2b_keyed, 32) == 0);
  crypto_hash_sha512(out64, msg, msg_len);
  check("sha512", memcmp(out64, vec_sha512, 64) == 0);

  unsigned char ct[64], pt[64];
  unsigned long long ct_len, pt_len;
  crypto_aead_chacha20poly1305_ietf_encrypt(ct, &ct_len, msg, msg_len, pk_a, 32, NULL, nonce12, seed_a);
  check("chacha20poly1305_ietf", ct_len == sizeof(vec_chacha20poly1305_ietf) && memcmp(ct, vec_chacha20poly1305_ietf, ct_len) == 0);

  crypto_aead_xchacha20poly1305_ietf_encrypt(ct, &ct_len, msg, msg_len, pk_a, 32, NULL, nonce24, seed_a);
  check("xchacha20poly1305_ietf", ct_len == sizeof(vec_xchacha20poly1305_ietf) && memcmp(ct, vec_xchacha20poly1305_ietf, ct_len) == 0);

  crypto_secretbox_easy(ct, msg, msg_len, nonce24, seed_b);
  check("secretbox", memcmp(ct, vec_secretbox, sizeof(vec_secretbox)) == 0);
  check("secretbox_open", crypto_secretbox_open_easy(pt, ct, sizeof(vec_secretbox), nonce24, seed_b) == 0 && memcmp(pt, msg, msg_len) == 0);

  // secretstream headers are random, so check a push/pull round trip instead.
  crypto_secretstream_xchacha20poly1305_state tx, rx;
  unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
  crypto_secretstream_xchacha20poly1305_init_push(&tx, header, seed_a);
  crypto_secretstream_xchacha20poly1305_push(&tx, ct, &ct_len, msg, msg_len, NULL, 0, 0);
  unsigned char tag = 0xff;
  int ok = crypto_secretstream_xchacha20poly1305_init_pull(&rx, header, seed_a) == 0 &&
           crypto_secretstream_xchacha20poly1305_pull(&rx, pt, &pt_len, &tag, ct, ct_len, NULL, 0) == 0 &&
           pt_len == msg_len && memcmp(pt, msg, msg_len) == 0 && tag == 0;
  check("secretstream_xchacha20poly1305", ok);
}

typedef struct {
  const char *name;
  int iterations;
  size_t bytes; // bytes processed per iteration, 0 for fixed-size ops
} bench_t;

static void
report (const bench_t *b, int64_t elapsed_us) {
  double per_op = (double) elapsed_us / b->iterations;
  if (b->bytes) {
    double kbps = (double) b->bytes * b->iterations / 1024.0 / ((double) elapsed_us / 1e6);
    printf("POC|sodium|bench|%s|iterations=%d|us_per_op=%.1f|KiB_per_s=%.0f\n", b->name, b->iterations, per_op, kbps);
  } else {
    printf("POC|sodium|bench|%s|iterations=%d|us_per_op=%.1f\n", b->name, b->iterations, per_op);
  }
  // Let the idle task run so the task watchdog stays quiet.
  vTaskDelay(1);
}

#define BENCH(_name, _iters, _bytes, _body) \
  do { \
    bench_t _b = {_name, _iters, _bytes}; \
    int64_t _t0 = esp_timer_get_time(); \
    for (int _i = 0; _i < _iters; _i++) { \
      _body; \
    } \
    report(&_b, esp_timer_get_time() - _t0); \
  } while (0)

static void
run_bench (void) {
  static unsigned char buf[BENCH_BUF + 64];
  static unsigned char out[BENCH_BUF + 64];

  unsigned char seed_a[32], seed_b[32], pk_a[32], sk_a[64], pk_b[32], sk_b[64];
  unsigned char sig[64], h32[32], h64[64], nonce24[24] = {0}, nonce12[12] = {0};
  unsigned long long out_len;

  make_seeds(seed_a, seed_b);
  crypto_sign_seed_keypair(pk_a, sk_a, seed_a);
  crypto_sign_seed_keypair(pk_b, sk_b, seed_b);
  for (int i = 0; i < BENCH_BUF; i++) buf[i] = (unsigned char) i;

  BENCH("ed25519_seed_keypair", 20, 0, crypto_sign_seed_keypair(pk_a, sk_a, seed_a));
  BENCH("ed25519_sign_64B", 20, 0, crypto_sign_detached(sig, NULL, buf, 64, sk_a));
  BENCH("ed25519_verify_64B", 20, 0, if (crypto_sign_verify_detached(sig, buf, 64, pk_a) != 0) failures++);
  BENCH("ed25519_dh", 20, 0, ed_dh(h32, seed_a, pk_b));
  BENCH("blake2b_32B_out_64B_in", 1000, 64, crypto_generichash(h32, 32, buf, 64, NULL, 0));
  BENCH("blake2b_1KiB", 200, BENCH_BUF, crypto_generichash(h32, 32, buf, BENCH_BUF, NULL, 0));
  BENCH("sha512_1KiB", 200, BENCH_BUF, crypto_hash_sha512(h64, buf, BENCH_BUF));
  BENCH("chacha20poly1305_ietf_1KiB", 200, BENCH_BUF, crypto_aead_chacha20poly1305_ietf_encrypt(out, &out_len, buf, BENCH_BUF, NULL, 0, NULL, nonce12, seed_a));
  BENCH("secretbox_1KiB", 200, BENCH_BUF, crypto_secretbox_easy(out, buf, BENCH_BUF, nonce24, seed_a));

  crypto_secretstream_xchacha20poly1305_state st;
  unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
  crypto_secretstream_xchacha20poly1305_init_push(&st, header, seed_a);
  BENCH("secretstream_push_1KiB", 200, BENCH_BUF, crypto_secretstream_xchacha20poly1305_push(&st, out, &out_len, buf, BENCH_BUF, NULL, 0, 0));
}

int
poc_sodium_run (void) {
  failures = 0;

  if (sodium_init() < 0) {
    printf("POC|sodium|check|sodium_init|FAIL\n");
    return 1;
  }

  printf("POC|sodium|version|%s\n", sodium_version_string());
  run_checks();
  run_bench();
  printf("POC|sodium|failures|%d\n", failures);
  return failures;
}
