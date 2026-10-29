// Stores or reads a mutable record.
//
//   test_mutable <host:port | public> put <hex seed> <seq> <value>
//   test_mutable <host:port | public> get <hex public key> [min seq]

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "hdht.h"

static hdht_t dht;
static int exit_code = 1;

static uint8_t public_key[32], secret_key[64];
static uint64_t seq;
static const char *value;
static bool put;

static void
on_destroyed (hdht_t *d) {
  (void) d;
}

static void
on_put (hdht_t *d, int status, unsigned stored, void *data) {
  (void) data;
  printf("put status=%d stored=%u seq=%llu\n", status, stored, (unsigned long long) seq);
  exit_code = status == 0 ? 0 : 1;
  hdht_destroy(d, on_destroyed);
}

static void
on_get (hdht_t *d, int status, uint64_t s, const uint8_t *v, size_t len, void *data) {
  (void) data;
  printf("get status=%d seq=%llu len=%zu value=%.*s\n", status, (unsigned long long) s, len, (int) len, v ? (const char *) v : "");
  exit_code = status == 0 ? 0 : 1;
  hdht_destroy(d, on_destroyed);
}

static void
on_ready (hdht_t *d, int status) {
  printf("bootstrapped status=%d table=%u\n", status, d->table_len);
  int err = put
              ? hdht_mutable_put(d, public_key, secret_key, seq, (const uint8_t *) value, strlen(value), on_put, NULL)
              : hdht_mutable_get(d, public_key, seq, on_get, NULL);
  if (err) {
    printf("start failed %d\n", err);
    hdht_destroy(d, on_destroyed);
  }
}

int
main (int argc, char **argv) {
  if (argc < 4 || sodium_init() < 0) {
    fprintf(stderr, "usage: test_mutable <host:port | public> put <hex seed> <seq> <value>\n"
                    "       test_mutable <host:port | public> get <hex public key> [min seq]\n");
    return 1;
  }

  put = strcmp(argv[2], "put") == 0;
  uint8_t key[32];
  if (sodium_hex2bin(key, 32, argv[3], strlen(argv[3]), NULL, NULL, NULL) != 0) return 1;

  if (put) {
    if (argc < 6) return 1;
    hdht_keypair(public_key, secret_key, key);
    seq = strtoull(argv[4], NULL, 10);
    value = argv[5];
    char hex[65];
    sodium_bin2hex(hex, sizeof(hex), public_key, 32);
    printf("public key %s\n", hex);
  } else {
    memcpy(public_key, key, 32);
    seq = argc > 4 ? strtoull(argv[4], NULL, 10) : 0;
  }

  const char *bootstrap[] = {argv[1]};
  hdht_opts_t opts = {0};
  if (strcmp(argv[1], "public") != 0) {
    opts.bootstrap = bootstrap;
    opts.bootstrap_len = 1;
  }
  if (hdht_init(&dht, uv_default_loop(), &opts) != 0) return 1;
  hdht_bootstrap(&dht, on_ready);

  uv_run(uv_default_loop(), UV_RUN_DEFAULT);
  return exit_code;
}
