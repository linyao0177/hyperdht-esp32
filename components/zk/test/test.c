// zk on the host: Poseidon against circomlibjs, camera messages through the
// parser and the verifier, and proofs with malformed points.
//
// ./run.sh builds it with the settings of the ESP-IDF component and runs it.

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "g16.h"
#include "poseidon_t6.h"
#include "vectors.h"
#include "zk_event.h"

static int fails;

static void
check (const char *name, int ok) {
  printf("%-28s %s\n", name, ok ? "ok" : "FAIL");
  fails += !ok;
}

static double
now_ms (void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}

static void
fp_write (uint8_t *be, const mclBnFp *x) {
  uint8_t le[32];
  mclBnFp_serialize(le, 32, x);
  for (int i = 0; i < 32; i++) be[i] = le[31 - i];
}

// a point on the twist y^2 = x^3 + 3/(9+i) outside the r-order subgroup
static int
off_subgroup_g2 (uint8_t out[128]) {
  mclBnFp2 b, xi, x, y, t;
  memset(&b, 0, sizeof(b));
  memset(&xi, 0, sizeof(xi));
  memset(&x, 0, sizeof(x));
  mclBnFp_setInt(&b.d[0], 3);
  mclBnFp_setInt(&xi.d[0], 9);
  mclBnFp_setInt(&xi.d[1], 1);
  mclBnFp2_inv(&xi, &xi);
  mclBnFp2_mul(&b, &b, &xi);
  for (int k = 1; k < 100; k++) {
    mclBnFp_setInt(&x.d[0], k);
    mclBnFp2_sqr(&t, &x);
    mclBnFp2_mul(&t, &t, &x);
    mclBnFp2_add(&t, &t, &b);
    if (mclBnFp2_squareRoot(&y, &t) != 0) continue;
    mclBnG2 p;
    memset(&p, 0, sizeof(p));
    p.x = x;
    p.y = y;
    mclBnFp_setInt(&p.z.d[0], 1);
    mclBn_verifyOrderG2(0);
    int on_curve = mclBnG2_isValid(&p);
    mclBn_verifyOrderG2(1);
    if (!on_curve || mclBnG2_isValidOrder(&p)) continue;
    fp_write(out, &x.d[1]);
    fp_write(out + 32, &x.d[0]);
    fp_write(out + 64, &y.d[1]);
    fp_write(out + 96, &y.d[0]);
    return 0;
  }
  return -1;
}

int
main (void) {
  static g16_vk_t vk;
  check("init", g16_init() == 0);
  check("vk load", g16_vk_load(&vk, vk_bin, sizeof(vk_bin)) == 0 && vk.n_public == 2);

  for (int i = 0; i < 4; i++) {
    const uint64_t *v = poseidon_t6_vectors[i].in;
    uint16_t box[4] = {(uint16_t) v[4], (uint16_t) (v[4] >> 16), (uint16_t) (v[4] >> 32), (uint16_t) (v[4] >> 48)};
    uint8_t m[32];
    char name[32];
    g16_event_hash(m, v[0], v[1], v[2], v[3], box);
    snprintf(name, sizeof(name), "poseidon vector %d", i);
    check(name, memcmp(m, poseidon_t6_vectors[i].out, 32) == 0);
  }

  uint8_t other_root[32];
  memcpy(other_root, root, 32);
  other_root[31] ^= 1;
  zk_event_t e;
  double ms = 0;
  int n = 0;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    int p = zk_event_parse(&e, cases[i].json, strlen(cases[i].json));
    int ok = p == cases[i].parse;
    if (ok && p == 0) {
      uint8_t m[32];
      double t = now_ms();
      zk_event_hash(m, &e);
      int v = zk_event_verify(&vk, cases[i].other_root ? other_root : root, m, &e);
      ms += now_ms() - t;
      n++;
      ok = v == cases[i].verify;
    }
    check(cases[i].name, ok);
  }
  printf("hash and verify: %.1f ms on this machine\n", ms / n);

  // malformed proofs: -1, not merely invalid
  zk_event_parse(&e, cases[0].json, strlen(cases[0].json));
  uint8_t m[32];
  zk_event_hash(m, &e);
  zk_event_t bad = e;
  bad.proof[63] ^= 1;
  check("A off the curve", zk_event_verify(&vk, root, m, &bad) == -1);
  bad = e;
  bad.proof[64 + 63] ^= 1;
  check("B off the twist", zk_event_verify(&vk, root, m, &bad) == -1);
  bad = e;
  check("B outside G2", off_subgroup_g2(bad.proof + 64) == 0 && zk_event_verify(&vk, root, m, &bad) == -1);
  bad = e;
  memcpy(bad.proof, e.proof + 192, 64);
  memcpy(bad.proof + 192, e.proof, 64);
  check("A and C swapped", zk_event_verify(&vk, root, m, &bad) == 0);
  uint8_t big[32];
  memset(big, 0xff, 32);
  check("root >= r", !zk_fr_ok(big) && zk_event_verify(&vk, big, m, &e) == -1);
  check("root < r", zk_fr_ok(root));

  printf(fails ? "FAILED %d\n" : "ALL OK\n", fails);
  return fails != 0;
}
