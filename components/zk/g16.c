#include <string.h>

#include "g16.h"

// mcl's serialization is little-endian and rejects values >= the modulus
static int
read_fp (mclBnFp *x, const uint8_t *be) {
  uint8_t le[32];
  for (int i = 0; i < 32; i++) le[i] = be[31 - i];
  return mclBnFp_deserialize(x, le, 32) == 32 ? 0 : -1;
}

static int
read_fr (mclBnFr *x, const uint8_t *be) {
  uint8_t le[32];
  for (int i = 0; i < 32; i++) le[i] = be[31 - i];
  return mclBnFr_deserialize(x, le, 32) == 32 ? 0 : -1;
}

// affine (x, y); (0, 0), the EVM's point at infinity, is refused as off the curve
static int
read_g1 (mclBnG1 *p, const uint8_t *buf) {
  if (read_fp(&p->x, buf) || read_fp(&p->y, buf + 32)) return -1;
  mclBnFp_setInt(&p->z, 1);
  return mclBnG1_isValid(p) ? 0 : -1;
}

static int
read_g2 (mclBnG2 *p, const uint8_t *buf) {
  if (read_fp(&p->x.d[1], buf) || read_fp(&p->x.d[0], buf + 32)) return -1;
  if (read_fp(&p->y.d[1], buf + 64) || read_fp(&p->y.d[0], buf + 96)) return -1;
  mclBnFp_setInt(&p->z.d[0], 1);
  mclBnFp_clear(&p->z.d[1]);
  return mclBnG2_isValid(p) ? 0 : -1; // with the subgroup check, see g16_init
}

void
g16_poseidon_init (void); // g16_poseidon.c

int
g16_init (void) {
  if (mclBn_init(MCL_BN_SNARK1, MCLBN_COMPILED_TIME_VAR) != 0) return -1;
  mclBn_verifyOrderG1(1); // a no-op on BN curves (cofactor 1)
  mclBn_verifyOrderG2(1); // G2 has a cofactor: points outside the subgroup are refused
  g16_poseidon_init();
  return 0;
}

int
g16_vk_load (g16_vk_t *vk, const uint8_t *buf, size_t len) {
  memset(vk, 0, sizeof(*vk));
  if (len < 64 + 3 * 128 + 64 || (len - 64 - 3 * 128) % 64 != 0) return -1;
  size_t n = (len - 64 - 3 * 128) / 64 - 1;
  if (n > G16_MAX_PUBLIC) return -1;
  mclBnG1 alpha;
  mclBnG2 g2;
  if (read_g1(&alpha, buf) || read_g2(&g2, buf + 64)) return -1;
  mclBn_pairing(&vk->alpha_beta, &alpha, &g2);
  if (read_g2(&g2, buf + 192)) return -1;
  mclBnG2_neg(&vk->gamma_neg, &g2);
  if (read_g2(&g2, buf + 320)) return -1;
  mclBnG2_neg(&vk->delta_neg, &g2);
  for (size_t i = 0; i <= n; i++) {
    if (read_g1(&vk->ic[i], buf + 448 + 64 * i)) return -1;
  }
  vk->n_public = n;
  return 0;
}

// e(A, B) e(L, -gamma) e(C, -delta) = e(alpha, beta): three Miller loops, one final exponentiation
int
g16_verify (const g16_vk_t *vk, const uint8_t proof[G16_PROOF_LEN], const uint8_t (*pub)[32], size_t n_public) {
  if (n_public != vk->n_public) return -1;
  mclBnG1 g1[3];
  mclBnG2 g2[3];
  if (read_g1(&g1[0], proof) || read_g2(&g2[0], proof + 64) || read_g1(&g1[2], proof + 192)) return -1;

  // L = IC[0] + sum pub[i] IC[i+1]
  mclBnG1 t;
  mclBnFr s;
  g1[1] = vk->ic[0];
  for (size_t i = 0; i < n_public; i++) {
    if (read_fr(&s, pub[i])) return -1;
    mclBnG1_mul(&t, &vk->ic[i + 1], &s);
    mclBnG1_add(&g1[1], &g1[1], &t);
  }

  g2[1] = vk->gamma_neg;
  g2[2] = vk->delta_neg;
  mclBnGT f;
  mclBn_millerLoopVec(&f, g1, g2, 3);
  mclBn_finalExp(&f, &f);
  return mclBnGT_isEqual(&f, &vk->alpha_beta) ? 1 : 0;
}
