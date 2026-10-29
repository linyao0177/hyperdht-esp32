// Lists the public keys announced under a topic.
//
//   test_lookup <host:port | public> <hex topic>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "hdht.h"

static hdht_t dht;
static int exit_code = 1;
static uint8_t topic[32];

static void
on_destroyed (hdht_t *d) {
  (void) d;
}

static void
on_lookup (hdht_t *d, int status, const uint8_t (*peers)[32], size_t len, void *data) {
  (void) data;
  printf("lookup status=%d peers=%zu\n", status, len);
  for (size_t i = 0; i < len; i++) {
    char hex[65];
    sodium_bin2hex(hex, sizeof(hex), peers[i], 32);
    printf("peer %s\n", hex);
  }
  exit_code = status == 0 && len > 0 ? 0 : 1;
  hdht_destroy(d, on_destroyed);
}

static void
on_ready (hdht_t *d, int status) {
  printf("bootstrapped status=%d table=%u\n", status, d->table_len);
  if (hdht_lookup(d, topic, on_lookup, NULL) != 0) {
    printf("start failed\n");
    hdht_destroy(d, on_destroyed);
  }
}

int
main (int argc, char **argv) {
  if (argc < 3 || sodium_init() < 0 || sodium_hex2bin(topic, 32, argv[2], strlen(argv[2]), NULL, NULL, NULL) != 0) {
    fprintf(stderr, "usage: test_lookup <host:port | public> <hex topic>\n");
    return 1;
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
