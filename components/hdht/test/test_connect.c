// Connects to a HyperDHT server, sends a message and waits for the echo.
//
//   test_connect <bootstrap host:port> <hex server public key> [message]
//
// HDHT_RELAY=<hex key> connects (or accepts) through that blind relay only;
// HDHT_RELAY=find uses the first relay hdht_relay_find finds.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "hdht.h"

static hdht_t dht;
static hdht_stream_t stream;
static uint8_t server_key[32];
static const char *message = "hello from c";
static uint64_t started;
static int result = 1;

static void
on_destroyed (hdht_t *d) {
  (void) d;
}

static void
on_open (hdht_stream_t *s) {
  printf("open after %llu ms via %s (owned socket: %s)\n", (unsigned long long) (uv_now(dht.loop) - started), hdht_addr_str(&s->remote_addr), s->socket == &dht.socket ? "no, main" : "yes, puncher");
  hdht_stream_write(s, (const uint8_t *) message, strlen(message));
}

static void
on_data (hdht_stream_t *s, const uint8_t *data, size_t len) {
  printf("echo: %.*s\n", (int) len, (const char *) data);
  if (len == strlen(message) && memcmp(data, message, len) == 0) result = 0;
  hdht_stream_destroy(s, 0);
}

static void
on_close (hdht_stream_t *s, int error) {
  printf("closed: error=%d in=%llu out=%llu\n", error, (unsigned long long) s->stats.bytes_in, (unsigned long long) s->stats.bytes_out);
  printf("dht: table=%u requests=%u responses=%u timeouts=%u\n", dht.table_len, dht.stats.requests, dht.stats.responses, dht.stats.timeouts);
  hdht_destroy(&dht, on_destroyed);
}

static bool find_relay;

static void
connect_now (hdht_t *d) {
  started = uv_now(d->loop);
  hdht_connect(d, &stream, server_key, on_open, on_data, on_close, NULL);
}

static void
on_relay_found (hdht_t *d, int status, const uint8_t key[32], void *data) {
  (void) data;
  char hex[65];
  if (status != 0) {
    printf("relay find: none usable (%d)\n", status);
    hdht_destroy(d, on_destroyed);
    return;
  }
  printf("relay find: %s after %llu ms\n", sodium_bin2hex(hex, sizeof(hex), key, 32), (unsigned long long) (uv_now(d->loop) - started));
  hdht_set_relay(d, key);
  connect_now(d);
}

static void
on_ready (hdht_t *d, int status) {
  printf("bootstrapped: status=%d table=%u\n", status, d->table_len);
  started = uv_now(d->loop);
  if (find_relay) hdht_relay_find(d, NULL, on_relay_found, NULL);
  else connect_now(d);
}

static void
add_local_addresses (void) {
  uv_interface_address_t *addrs;
  int count;
  if (uv_interface_addresses(&addrs, &count) != 0) return;
  for (int i = 0; i < count; i++) {
    if (addrs[i].is_internal || addrs[i].address.address4.sin_family != AF_INET) continue;
    hdht_add_local_address(&dht, (const uint8_t *) &addrs[i].address.address4.sin_addr.s_addr);
  }
  uv_free_interface_addresses(addrs, count);
}

int
main (int argc, char **argv) {
  if (argc < 3 || sodium_init() < 0) {
    fprintf(stderr, "usage: test_connect <host:port> <hex public key> [message]\n");
    return 1;
  }
  if (sodium_hex2bin(server_key, 32, argv[2], strlen(argv[2]), NULL, NULL, NULL) != 0) return 1;
  if (argc > 3) message = argv[3];

  const char *bootstrap[] = {argv[1]};
  hdht_opts_t opts = {.bootstrap = bootstrap, .bootstrap_len = 1};
  if (hdht_init(&dht, uv_default_loop(), &opts) != 0) return 1;
  const char *relay = getenv("HDHT_RELAY");
  uint8_t relay_key[32];
  find_relay = relay && strcmp(relay, "find") == 0;
  if (relay && !find_relay && sodium_hex2bin(relay_key, 32, relay, strlen(relay), NULL, NULL, NULL) == 0) hdht_set_relay(&dht, relay_key);
  add_local_addresses();

  hdht_bootstrap(&dht, on_ready);
  uv_run(uv_default_loop(), UV_RUN_DEFAULT);
  printf(result ? "FAILED\n" : "PASSED\n");
  return result;
}
