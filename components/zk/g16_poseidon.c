#include <string.h>

#include "g16.h"
#include "poseidon_t6.h"

#define T 6

static mclBnFr rc[POSEIDON_T6_ROUNDS * T], mds[T][T];

static void
fr_from_be (mclBnFr *x, const uint8_t *be) {
  uint8_t le[32];
  for (int i = 0; i < 32; i++) le[i] = be[31 - i];
  mclBnFr_deserialize(x, le, 32); // the constants are all < r
}

static void
fr_from_u64 (mclBnFr *x, uint64_t v) {
  uint8_t le[32] = {0};
  for (int i = 0; i < 8; i++) le[i] = (uint8_t) (v >> (8 * i));
  mclBnFr_deserialize(x, le, 32);
}

void
g16_poseidon_init (void) {
  for (int i = 0; i < POSEIDON_T6_ROUNDS * T; i++) fr_from_be(&rc[i], poseidon_t6_c[i]);
  for (int i = 0; i < T; i++) {
    for (int j = 0; j < T; j++) fr_from_be(&mds[i][j], poseidon_t6_m[i][j]);
  }
}

static void
pow5 (mclBnFr *x) {
  mclBnFr t;
  mclBnFr_sqr(&t, x);
  mclBnFr_sqr(&t, &t);
  mclBnFr_mul(x, x, &t);
}

void
g16_poseidon5 (mclBnFr *out, const mclBnFr in[5]) {
  mclBnFr s[T], n[T], t;
  mclBnFr_clear(&s[0]);
  memcpy(&s[1], in, 5 * sizeof(mclBnFr));
  for (int r = 0; r < POSEIDON_T6_ROUNDS; r++) {
    for (int i = 0; i < T; i++) mclBnFr_add(&s[i], &s[i], &rc[r * T + i]);
    if (r < 4 || r >= POSEIDON_T6_ROUNDS - 4) {
      for (int i = 0; i < T; i++) pow5(&s[i]);
    } else {
      pow5(&s[0]);
    }
    for (int i = 0; i < T; i++) {
      mclBnFr_clear(&n[i]);
      for (int j = 0; j < T; j++) {
        mclBnFr_mul(&t, &mds[i][j], &s[j]);
        mclBnFr_add(&n[i], &n[i], &t);
      }
    }
    memcpy(s, n, sizeof(s));
  }
  *out = s[0];
}

void
g16_event_hash (uint8_t out[32], uint64_t seq, uint64_t t_ms, uint64_t ev_id, uint64_t conf_permille, const uint16_t box[4]) {
  uint64_t box_packed = box[0] | (uint64_t) box[1] << 16 | (uint64_t) box[2] << 32 | (uint64_t) box[3] << 48;
  mclBnFr in[5], h;
  fr_from_u64(&in[0], seq);
  fr_from_u64(&in[1], t_ms);
  fr_from_u64(&in[2], ev_id);
  fr_from_u64(&in[3], conf_permille);
  fr_from_u64(&in[4], box_packed);
  g16_poseidon5(&h, in);
  uint8_t le[32];
  mclBnFr_serialize(le, 32, &h);
  for (int i = 0; i < 32; i++) out[i] = le[31 - i];
}
