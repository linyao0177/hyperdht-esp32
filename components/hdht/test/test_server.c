// Announces a server (seed 0x22 * 32) and echoes every connection.
//
//   test_server <bootstrap host:port> [seconds]
//
// HDHT_RELAY=<hex key> connects (or accepts) through that blind relay only.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "hdht.h"

static hdht_t dht;
static hdht_server_t server;
static uv_timer_t stop_timer;
static int connections = 0;
static int echoed = 0;

static void
on_destroyed (hdht_t *d) {
  (void) d;
  uv_close((uv_handle_t *) &stop_timer, NULL);
}

static void
on_closed (hdht_server_t *s) {
  printf("server closed: announces=%u handshakes=%u connections=%u punches=%u\n", s->stats.announces, s->stats.handshakes, s->stats.connections, s->stats.punches);
  hdht_destroy(&dht, on_destroyed);
}

static void
on_stop (uv_timer_t *t) {
  (void) t;
  hdht_server_close(&server, on_closed);
}

static void
on_open (hdht_stream_t *s) {
  printf("stream open from %s\n", hdht_addr_str(&s->remote_addr));
}

static void
on_data (hdht_stream_t *s, const uint8_t *data, size_t len) {
  printf("data: %.*s\n", (int) len, (const char *) data);
  echoed++;
  hdht_stream_write(s, data, len);
}

static void
on_stream_close (hdht_stream_t *s, int error) {
  (void) s;
  printf("stream closed: error=%d\n", error);
}

static void
on_connection (hdht_server_t *s, hdht_stream_t *stream) {
  (void) s;
  connections++;
  char hex[65];
  sodium_bin2hex(hex, sizeof(hex), stream->remote_public_key, 32);
  printf("connection %d from %s key %.16s... (puncher socket: %s)\n", connections, hdht_addr_str(&stream->remote_addr), hex, stream->owned_socket ? "yes" : "no");
  stream->on_open = on_open;
  stream->on_data = on_data;
  stream->on_close = on_stream_close;
}

static void
on_listening (hdht_server_t *s, int status) {
  char hex[65];
  sodium_bin2hex(hex, sizeof(hex), s->public_key, 32);
  printf("listening: status=%d relays=%u key=%s\n", status, s->relays_len, hex);
  for (int i = 0; i < s->relays_len; i++) {
    char relay[24];
    snprintf(relay, sizeof(relay), "%s", hdht_addr_str(&s->relays[i].relay_address));
    printf("  relay %s sees us as %s\n", relay, hdht_addr_str(&s->relays[i].peer_address));
  }
  fflush(stdout);
}

static void
on_ready (hdht_t *d, int status) {
  printf("bootstrapped: status=%d table=%u\n", status, d->table_len);

  uint8_t seed[32], pk[32], sk[64];
  memset(seed, 0x22, sizeof(seed));
  hdht_keypair(pk, sk, seed);
  hdht_listen(d, &server, pk, sk, on_connection, on_listening, NULL);
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
  if (argc < 2 || sodium_init() < 0) {
    fprintf(stderr, "usage: test_server <host:port> [seconds]\n");
    return 1;
  }
  int seconds = argc > 2 ? atoi(argv[2]) : 30;

  const char *bootstrap[] = {argv[1]};
  hdht_opts_t opts = {.bootstrap = bootstrap, .bootstrap_len = 1};
  if (hdht_init(&dht, uv_default_loop(), &opts) != 0) return 1;
  const char *relay = getenv("HDHT_RELAY");
  uint8_t relay_key[32];
  if (relay && sodium_hex2bin(relay_key, 32, relay, strlen(relay), NULL, NULL, NULL) == 0) hdht_set_relay(&dht, relay_key);
  add_local_addresses();

  uv_timer_init(uv_default_loop(), &stop_timer);
  uv_timer_start(&stop_timer, on_stop, (uint64_t) seconds * 1000, 0);

  hdht_bootstrap(&dht, on_ready);
  uv_run(uv_default_loop(), UV_RUN_DEFAULT);

  printf(connections > 0 && echoed > 0 ? "PASSED\n" : "FAILED\n");
  return connections > 0 && echoed > 0 ? 0 : 1;
}
