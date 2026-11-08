// Tests for hdht_cred.
//
//   test_cred                                      parsing and checks, offline
//   test_cred <host:port | public> <device did> <trusted issuer did> <expected result>
//                                                  hdht_cred_verify_device against a DHT;
//                                                  exit 0 when the result is the expected one
//
// tools/host/cred-fixture.js publishes devices and issuers for every result.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "hdht.h"
#include "hdht_cred.h"

static int passed, failed;

static void
check (const char *name, bool ok) {
  if (ok) passed++;
  else failed++;
  printf("%s %s\n", ok ? "PASS" : "FAIL", name);
}

static void
did (char out[72], const uint8_t key[32]) {
  char hex[65];
  sodium_bin2hex(hex, sizeof(hex), key, 32);
  snprintf(out, 72, "did:mw:%s", hex);
}

// a credential's JSON, signed by the issuer, as tools/host/credential.js makes it
static void
make (char *out, size_t cap, const uint8_t issuer_pk[32], const uint8_t issuer_sk[64], const uint8_t device[32], const char *id, const char *model, const char *signed_model) {
  char iss[72], sub[72], text[200], sig_hex[129];
  did(iss, issuer_pk);
  did(sub, device);
  int n = snprintf(text, sizeof(text), "hdht-credential/1 %s %s %s 1793269310 %s", id, iss + 7, sub + 7, signed_model ? signed_model : model);
  uint8_t sig[64];
  crypto_sign_detached(sig, NULL, (const uint8_t *) text, (size_t) n, issuer_sk);
  sodium_bin2hex(sig_hex, sizeof(sig_hex), sig, 64);
  snprintf(out, cap, "{\"v\":1,\"id\":\"%s\",\"iss\":\"%s\",\"sub\":\"%s\",\"iat\":1793269310,\"model\":\"%s\",\"sig\":\"%s\"}", id, iss, sub, model, sig_hex);
}

static int
offline (void) {
  uint8_t ipk[32], isk[64], dpk[32], dsk[64], opk[32], osk[64];
  crypto_sign_keypair(ipk, isk);
  crypto_sign_keypair(dpk, dsk);
  crypto_sign_keypair(opk, osk);
  char json[600], record[800];
  hdht_cred_t c;

  make(json, sizeof(json), ipk, isk, dpk, "63590727e6aeffe2", "meter X1", NULL);
  check("parses a credential", hdht_cred_parse(&c, json, strlen(json)) == 0 && strcmp(c.model, "meter X1") == 0 && c.iat == 1793269310);
  check("valid for its device", hdht_cred_check(&c, dpk) == 0);
  check("refused for another device", hdht_cred_check(&c, opk) == HDHT_CRED_OTHER_DEVICE);

  char dev[72];
  did(dev, dpk);
  snprintf(record, sizeof(record), "{\"v\":1,\"did\":\"%s\",\"svc\":\"meter/1\",\"cred\":%s,\"name\":\"x\"}", dev, json);
  check("parses from a record's \"cred\"", hdht_cred_parse(&c, record, strlen(record)) == 0 && hdht_cred_check(&c, dpk) == 0);
  snprintf(record, sizeof(record), "{\"v\":1,\"did\":\"%s\",\"svc\":\"meter/1\"}", dev);
  check("a record without one: NO_CRED", hdht_cred_parse(&c, record, strlen(record)) == HDHT_CRED_NO_CRED);

  make(json, sizeof(json), ipk, isk, dpk, "63590727e6aeffe2", "meter X9", "meter X1");
  check("model changed after signing: BAD_SIGNATURE", hdht_cred_parse(&c, json, strlen(json)) == 0 && hdht_cred_check(&c, dpk) == HDHT_CRED_BAD_SIGNATURE);

  const char *bad_models[] = {"meter\\\"X1", "", "meter/X1", "a model name that is longer than 32"};
  for (int i = 0; i < 4; i++) {
    make(json, sizeof(json), ipk, isk, dpk, "63590727e6aeffe2", bad_models[i], NULL);
    char name[80];
    snprintf(name, sizeof(name), "model \"%s\": MALFORMED", bad_models[i]);
    check(name, hdht_cred_parse(&c, json, strlen(json)) == HDHT_CRED_MALFORMED);
  }
  make(json, sizeof(json), ipk, isk, dpk, "63590727E6AEFFE2", "meter X1", NULL);
  check("upper-case id: MALFORMED", hdht_cred_parse(&c, json, strlen(json)) == HDHT_CRED_MALFORMED);
  make(json, sizeof(json), ipk, isk, dpk, "63590727e6aeffe2", "meter X1", NULL);
  json[5] = '2'; // "v":2
  check("v 2: MALFORMED", hdht_cred_parse(&c, json, strlen(json)) == HDHT_CRED_MALFORMED);

  char iss[72];
  did(iss, ipk);
  snprintf(record, sizeof(record), "{\"v\":1,\"did\":\"%s\",\"name\":\"Test\",\"revoked\":[\"0000000000000001\",\"63590727e6aeffe2\"]}", iss);
  check("issuer record revoking it: REVOKED", hdht_cred_check_issuer_record(record, strlen(record), ipk, "63590727e6aeffe2") == HDHT_CRED_REVOKED);
  check("issuer record revoking another: valid", hdht_cred_check_issuer_record(record, strlen(record), ipk, "1111111111111111") == 0);
  snprintf(record, sizeof(record), "{\"v\":1,\"did\":\"%s\",\"name\":\"Test\"}", iss);
  check("issuer record without revocations: valid", hdht_cred_check_issuer_record(record, strlen(record), ipk, "63590727e6aeffe2") == 0);
  check("another issuer's record: MALFORMED", hdht_cred_check_issuer_record(record, strlen(record), opk, "63590727e6aeffe2") == HDHT_CRED_MALFORMED);

  printf("\n%d of %d passed\n", passed, passed + failed);
  return failed ? 1 : 0;
}

// against a DHT
static uv_loop_t loop;
static hdht_t dht;
static uint8_t device[32], trusted[1][32];
static int expected, exit_code = 1;
static hdht_cred_verify_t verify;

static void
on_destroyed (hdht_t *d) {
  (void) d;
}

static void
on_verified (hdht_cred_verify_t *v, int result, const hdht_cred_t *cred) {
  (void) v;
  printf("CRED|result %d %s%s%s\n", result, hdht_cred_reason(result), cred ? " model=" : "", cred ? cred->model : "");
  exit_code = result == expected ? 0 : 1;
  hdht_destroy(&dht, on_destroyed);
}

static void
on_ready (hdht_t *d, int status) {
  if (status != 0 || hdht_cred_verify_device(&verify, d, device, (const uint8_t (*)[32]) trusted, 1, on_verified, NULL) != 0) {
    printf("CRED|could not start (%d)\n", status);
    hdht_destroy(d, on_destroyed);
  }
}

int
main (int argc, char **argv) {
  if (sodium_init() < 0) return 1;
  if (argc == 1) return offline();
  if (argc != 5) {
    fprintf(stderr, "usage: test_cred [<host:port | public> <device did> <issuer did> <expected>]\n");
    return 1;
  }
  if (sodium_hex2bin(device, 32, argv[2] + 7, 64, NULL, NULL, NULL) != 0 ||
      sodium_hex2bin(trusted[0], 32, argv[3] + 7, 64, NULL, NULL, NULL) != 0) return 1;
  expected = atoi(argv[4]);

  uv_loop_init(&loop);
  const char *nodes[] = {argv[1]};
  hdht_opts_t opts = {0};
  if (strcmp(argv[1], "public") != 0) {
    opts.bootstrap = nodes;
    opts.bootstrap_len = 1;
  }
  hdht_init(&dht, &loop, &opts);
  hdht_bootstrap(&dht, on_ready);
  uv_run(&loop, UV_RUN_DEFAULT);
  return exit_code;
}
