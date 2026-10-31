// Connects to a HyperDHT server, sends a message and waits for the echo.
//
//   test_connect <bootstrap host:port | public> <hex server public key> [message]
//
// HDHT_RELAY=<hex key> connects through that blind relay, holepunching
// alongside it; HDHT_RELAY=find uses the first relay hdht_relay_find finds.
// HDHT_RELAY_ONLY=1 keeps the stream on the relay. HDHT_HOLD=<seconds> keeps
// the stream open after the echo, writing once a second, to watch it move
// from the relay to a direct path. HDHT_PUNCH_DELAY=<ms> holepunches that
// much after the relay starts (on a local testnet holepunching wins at once).

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
static int hold_s;
static int held;
static uv_timer_t hold_timer;

static void
on_destroyed (hdht_t *d) {
  (void) d;
}

static void
on_direct (hdht_stream_t *s) {
  printf("direct after %llu ms via %s, relay closed\n", (unsigned long long) (uv_now(dht.loop) - started), hdht_addr_str(&s->remote_addr));
}

static void
on_hold (uv_timer_t *t) {
  (void) t;
  if (++held > hold_s) {
    uv_timer_stop(&hold_timer);
    uv_close((uv_handle_t *) &hold_timer, NULL);
    hdht_stream_destroy(&stream, 0);
    return;
  }
  char msg[32];
  snprintf(msg, sizeof(msg), "ping %d", held);
  hdht_stream_write(&stream, (const uint8_t *) msg, strlen(msg));
}

static void
on_open (hdht_stream_t *s) {
  printf("open after %llu ms via %s (owned socket: %s)\n", (unsigned long long) (uv_now(dht.loop) - started), hdht_addr_str(&s->remote_addr), s->socket == &dht.socket ? "no, main" : "yes, puncher");
  hdht_stream_write(s, (const uint8_t *) message, strlen(message));
}

static void
on_data (hdht_stream_t *s, const uint8_t *data, size_t len) {
  printf("echo: %.*s (via %s%s)\n", (int) len, (const char *) data, hdht_addr_str(&s->remote_addr), s->relay ? ", relayed" : "");
  if (held > 0) return;
  if (len == strlen(message) && memcmp(data, message, len) == 0) result = 0;
  if (hold_s == 0) {
    hdht_stream_destroy(s, 0);
    return;
  }
  held = 0;
  uv_timer_init(dht.loop, &hold_timer);
  uv_timer_start(&hold_timer, on_hold, 1000, 1000);
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
  stream.on_direct = on_direct;
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
  hdht_opts_t opts = {0};
  if (strcmp(argv[1], "public") != 0) {
    opts.bootstrap = bootstrap;
    opts.bootstrap_len = 1;
  }
  if (hdht_init(&dht, uv_default_loop(), &opts) != 0) return 1;
  const char *relay = getenv("HDHT_RELAY");
  uint8_t relay_key[32];
  find_relay = relay && strcmp(relay, "find") == 0;
  if (relay && !find_relay && sodium_hex2bin(relay_key, 32, relay, strlen(relay), NULL, NULL, NULL) == 0) hdht_set_relay(&dht, relay_key);
  hdht_set_relay_only(&dht, getenv("HDHT_RELAY_ONLY") != NULL);
  if (getenv("HDHT_HOLD")) hold_s = atoi(getenv("HDHT_HOLD"));
  if (getenv("HDHT_PUNCH_DELAY")) dht.test_punch_delay_ms = (uint32_t) atoi(getenv("HDHT_PUNCH_DELAY"));
  setvbuf(stdout, NULL, _IOLBF, 0);
  add_local_addresses();

  hdht_bootstrap(&dht, on_ready);
  uv_run(uv_default_loop(), UV_RUN_DEFAULT);
  printf(result ? "FAILED\n" : "PASSED\n");
  return result;
}
