// SecretStream responder over plain TCP (stand-in for BLE), echoing messages.
//
//   test_ss <port> <xx|ik> [connections]
//
// Key pair: seed 0x44 * 32. Pair with tools/host/ss-client.js.

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <sodium.h>

#include "../src/secret_stream.h"

static int fd = -1;
static int echoed = 0;

static void
on_send (hdht_ss_t *ss, const uint8_t *data, size_t len) {
  (void) ss;
  if (write(fd, data, len) != (ssize_t) len) perror("write");
}

static void
on_open (hdht_ss_t *ss) {
  char hex[65];
  sodium_bin2hex(hex, sizeof(hex), ss->remote_public_key, 32);
  printf("open: remote %.16s...\n", hex);
}

static void
on_data (hdht_ss_t *ss, const uint8_t *data, size_t len) {
  echoed++;
  hdht_ss_write(ss, data, len);
}

static void
on_error (hdht_ss_t *ss, int error) {
  (void) ss;
  printf("error %d\n", error);
}

int
main (int argc, char **argv) {
  if (argc < 3 || sodium_init() < 0) return 1;
  int port = atoi(argv[1]);
  hdht_noise_pattern_t pattern = strcmp(argv[2], "ik") == 0 ? HDHT_NOISE_IK : HDHT_NOISE_XX;
  int connections = argc > 3 ? atoi(argv[3]) : 1;

  uint8_t seed[32], pk[32], sk[64];
  memset(seed, 0x44, sizeof(seed));
  crypto_sign_seed_keypair(pk, sk, seed);

  int srv = socket(AF_INET, SOCK_STREAM, 0);
  int one = 1;
  setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons((uint16_t) port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
  if (bind(srv, (struct sockaddr *) &addr, sizeof(addr)) != 0 || listen(srv, 1) != 0) {
    perror("listen");
    return 1;
  }
  printf("listening on %d (%s)\n", port, argv[2]);
  fflush(stdout);

  int ok = 0;
  for (int i = 0; i < connections; i++) {
    fd = accept(srv, NULL, NULL);
    if (fd < 0) return 1;

    hdht_ss_t ss;
    hdht_ss_init(&ss, false, pattern, pk, sk, NULL);
    ss.on_send = on_send;
    ss.on_open = on_open;
    ss.on_data = on_data;
    ss.on_error = on_error;

    int before = echoed;
    uint8_t buf[4096];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
      if (hdht_ss_feed(&ss, buf, (size_t) n) != 0) break;
    }
    if (ss.opened && echoed > before) ok++;
    hdht_ss_destroy(&ss);
    close(fd);
    printf("connection %d done: echoed %d\n", i + 1, echoed - before);
    fflush(stdout);
  }

  printf(ok == connections ? "PASSED\n" : "FAILED\n");
  return ok == connections ? 0 : 1;
}
