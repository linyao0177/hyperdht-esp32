// The AT commands (docs/module-uart.md). Every handler runs on the hdht task.
//
// Commands answer with zero or more "+NAME:..." lines and then "OK" or
// "ERROR:<reason>". Work that takes the network a while (CONNECT, PUT, GET,
// LOOKUP) answers OK at once and reports later in an event that names what
// it is about. Bytes travel as hex; the *T variants take text instead.

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_heap_caps.h"
#include "esp_system.h"
#include "nvs.h"

#include "module.h"
#include "port.h"

#define MAX_LINKS    4
#define MAX_ALLOW    8
#define MAX_SEND     1024 // bytes per AT+SEND; also the +DATA chunk size
#define REPUBLISH_MS (12 * 3600 * 1000) // records live 48 h on the DHT
#define CLOSE_MS     5000 // AT+CLOSE: then closed outright if the peer has not ended
#define MAX_TOPICS   4
#define ANNOUNCE_MS  (10 * 60 * 1000) // announcements live 20 min on the DHT
#define RELAY_RETRY_MS (60 * 1000)      // AT+RELAY=AUTO found none: look again
#define RELAY_CHECK_MS (10 * 60 * 1000) // AT+RELAY=AUTO: is the relay still there

typedef struct {
  bool used;
  bool open;
  bool inbound;
  uint8_t key[32];
  hdht_stream_t stream; // outbound streams live here
  hdht_stream_t *s;     // the stream in use; inbound ones belong to the server
  uv_timer_t close_timer;
} link_t;

static link_t links[MAX_LINKS];
static hdht_server_t server;
static bool listening, listen_wanted;

static uint8_t allow[MAX_ALLOW][32];
static size_t allow_len;

static uint8_t record[HDHT_MUTABLE_MAX_VALUE];
static size_t record_len;
static uint64_t record_seq;
static bool putting, put_again; // put_again: the record changed during a put
static uint64_t putting_seq;
static uv_timer_t republish_timer, restart_timer, announce_timer, relay_timer;

static bool has_relay;
static uint8_t relay[32];
static bool relay_auto;   // AT+RELAY=AUTO: a public relay found by topic
static bool relay_finding;

static uint8_t topics[MAX_TOPICS][32];
static size_t topics_len;

static char cred[512]; // manufacturer credential JSON (docs/credentials.md), or empty

static char hex[2 * HDHT_MUTABLE_MAX_VALUE + 1 > 2 * MAX_SEND + 1 ? 2 * HDHT_MUTABLE_MAX_VALUE + 1 : 2 * MAX_SEND + 1];
static uint8_t bytes[HDHT_MUTABLE_MAX_VALUE > MAX_SEND ? HDHT_MUTABLE_MAX_VALUE : MAX_SEND];

// helpers

static void
ok (void) {
  port_line("OK");
}

static void
error (const char *reason) {
  port_printf("ERROR:%s", reason);
}

static const char *
to_hex (const uint8_t *data, size_t len) {
  sodium_bin2hex(hex, sizeof(hex), data, len);
  return hex;
}

// "did:mw:<hex>" or bare hex
static bool
parse_key (const char *arg, uint8_t key[32]) {
  if (strncmp(arg, "did:mw:", 7) == 0) arg += 7;
  return strlen(arg) == 64 && sodium_hex2bin(key, 32, arg, 64, NULL, NULL, NULL) == 0;
}

// hex into bytes; returns the length or -1
static int
parse_hex (const char *arg, size_t cap) {
  size_t len = strlen(arg);
  if (len % 2 || len / 2 > cap) return -1;
  size_t out;
  if (sodium_hex2bin(bytes, cap, arg, len, NULL, &out, NULL) != 0) return -1;
  return (int) out;
}

static void
did_of (const uint8_t key[32], char out[72]) {
  char h[65];
  sodium_bin2hex(h, sizeof(h), key, 32);
  snprintf(out, 72, "did:mw:%s", h);
}

static link_t *
link_arg (const char *arg) {
  char *end;
  long i = strtol(arg, &end, 10);
  if (end == arg || i < 0 || i >= MAX_LINKS || !links[i].used) return NULL;
  return &links[i];
}

static int
link_index (link_t *l) {
  return (int) (l - links);
}

static link_t *
link_new (void) {
  for (int i = 0; i < MAX_LINKS; i++) {
    if (!links[i].used) {
      link_t *l = &links[i];
      l->used = true;
      l->open = false;
      return l;
    }
  }
  return NULL;
}

// NVS

static void
save_allow (void) {
  nvs_handle_t nvs;
  if (nvs_open("module", NVS_READWRITE, &nvs) != ESP_OK) return;
  if (allow_len) nvs_set_blob(nvs, "allow", allow, allow_len * 32);
  else nvs_erase_key(nvs, "allow");
  nvs_commit(nvs);
  nvs_close(nvs);
}

static void
save_relay (void) {
  nvs_handle_t nvs;
  if (nvs_open("module", NVS_READWRITE, &nvs) != ESP_OK) return;
  if (has_relay && !relay_auto) nvs_set_blob(nvs, "relay", relay, 32);
  else nvs_erase_key(nvs, "relay");
  nvs_set_u8(nvs, "relay_auto", relay_auto);
  nvs_commit(nvs);
  nvs_close(nvs);
}

static void
save_topics (void) {
  nvs_handle_t nvs;
  if (nvs_open("module", NVS_READWRITE, &nvs) != ESP_OK) return;
  if (topics_len) nvs_set_blob(nvs, "topics", topics, topics_len * 32);
  else nvs_erase_key(nvs, "topics");
  nvs_commit(nvs);
  nvs_close(nvs);
}

static void
save_record (void) {
  nvs_handle_t nvs;
  if (nvs_open("module", NVS_READWRITE, &nvs) != ESP_OK) return;
  nvs_set_blob(nvs, "record", record, record_len);
  nvs_set_u64(nvs, "rec_seq", record_seq);
  nvs_commit(nvs);
  nvs_close(nvs);
}

// links

static void
on_link_data (hdht_stream_t *stream, const uint8_t *data, size_t len) {
  link_t *l = stream->data;
  // long messages arrive as several events, in order
  for (size_t off = 0; off < len; off += MAX_SEND) {
    size_t n = len - off < MAX_SEND ? len - off : MAX_SEND;
    port_printf("+DATA:%d,%u,%s", link_index(l), (unsigned) n, to_hex(data + off, n));
  }
}

static void find_relay (const uint8_t *avoid);
static void on_relay_timer (uv_timer_t *t);

static void
on_link_close (hdht_stream_t *stream, int err) {
  link_t *l = stream->data;
  port_printf("+CLOSED:%d,%d", link_index(l), err);
  // the relay we found stopped working: find another
  if (err == HDHT_CONNECT_ERELAY && relay_auto && has_relay) find_relay(relay);
  uv_timer_stop(&l->close_timer);
  l->used = false;
  l->open = false;
  l->s = NULL;
}

static void
on_link_open (hdht_stream_t *stream) {
  link_t *l = stream->data;
  char d[72];
  did_of(l->key, d);
  l->open = true;
  port_printf("+CONN:%d,%s,OUT", link_index(l), d);
}

static bool
allowed (const uint8_t key[32]) {
  if (allow_len == 0) return true;
  for (size_t i = 0; i < allow_len; i++) {
    if (memcmp(allow[i], key, 32) == 0) return true;
  }
  return false;
}

static void
on_connection (hdht_server_t *srv, hdht_stream_t *stream) {
  (void) srv;
  char d[72];
  did_of(stream->remote_public_key, d);
  link_t *l = allowed(stream->remote_public_key) ? link_new() : NULL;
  if (l == NULL) {
    port_printf("+DENIED:%s,%s", d, allow_len && !allowed(stream->remote_public_key) ? "not allowed" : "no free link");
    hdht_stream_destroy(stream, HDHT_STREAM_ECLOSED);
    return;
  }
  l->inbound = true;
  l->open = true;
  memcpy(l->key, stream->remote_public_key, 32);
  l->s = stream;
  stream->data = l;
  stream->on_data = on_link_data;
  stream->on_close = on_link_close;
  port_printf("+CONN:%d,%s,IN", link_index(l), d);
}

static void
on_listening (hdht_server_t *srv, int status) {
  (void) srv;
  port_printf("+LISTENING:%d", status);
}

static void
start_listening (void) {
  if (listening || !dht_ready) return;
  listening = hdht_listen(&dht, &server, pk, sk, on_connection, on_listening, NULL) == 0;
}

static void
on_server_closed (hdht_server_t *srv) {
  (void) srv;
  listening = false;
  port_line("+LISTENING:CLOSED");
  if (listen_wanted) start_listening(); // LISTEN=1 again while closing
}

// records

static int
put_record (void);

static void
on_put (hdht_t *d, int status, unsigned stored, void *data) {
  (void) d;
  (void) data;
  putting = false;
  port_printf("+PUT:%d,%u,%llu", status, stored, (unsigned long long) putting_seq);
  if (put_again) put_record();
}

// one put at a time; a newer record waits for the current put to finish
static int
put_record (void) {
  if (putting) {
    put_again = true;
    return 0;
  }
  put_again = false;
  putting_seq = record_seq;
  int err = hdht_mutable_put(&dht, pk, sk, record_seq, record, record_len, on_put, NULL);
  putting = err == 0;
  return err;
}

static void
on_republish (uv_timer_t *t) {
  (void) t;
  if (record_len && dht_ready) put_record();
}

static void
on_get (hdht_t *d, int status, uint64_t seq, const uint8_t *value, size_t len, void *data) {
  (void) d;
  char dd[72];
  did_of(data, dd);
  port_printf("+GET:%s,%d,%llu,%s", dd, status, (unsigned long long) seq, status == 0 ? to_hex(value, len) : "");
  free(data);
}

static void
on_lookup (hdht_t *d, int status, const uint8_t (*peers)[32], size_t len, void *data) {
  (void) d;
  static char line[96 + HDHT_LOOKUP_MAX_PEERS * 72];
  int pos = snprintf(line, sizeof(line), "+LOOKUP:%s,%d,%u", to_hex(data, 32), status, (unsigned) len);
  for (size_t i = 0; i < len; i++) {
    char dd[72];
    did_of(peers[i], dd);
    pos += snprintf(line + pos, sizeof(line) - pos, ",%s", dd);
  }
  port_line(line);
  free(data);
}

static void
on_close_timeout (uv_timer_t *t) {
  link_t *l = t->data;
  if (l->used && l->s) hdht_stream_destroy(l->s, HDHT_STREAM_ECLOSED);
}

// topics

static void
on_announced (hdht_t *d, int status, unsigned stored, void *data) {
  (void) d;
  port_printf("+ANNOUNCE:%s,%d,%u", to_hex(data, 32), status, stored);
  free(data);
}

static void
on_unannounced (hdht_t *d, int status, unsigned stored, void *data) {
  (void) d;
  port_printf("+UNANNOUNCE:%s,%d,%u", to_hex(data, 32), status, stored);
  free(data);
}

static int
announce_topic (const uint8_t topic[32], bool unannounce) {
  uint8_t *copy = malloc(32);
  if (copy == NULL) return HDHT_ENOMEM;
  memcpy(copy, topic, 32);
  int err = unannounce ? hdht_unannounce(&dht, copy, pk, sk, on_unannounced, copy) : hdht_announce(&dht, copy, pk, sk, on_announced, copy);
  if (err) free(copy);
  return err;
}

static void
on_announce_timer (uv_timer_t *t) {
  (void) t;
  for (size_t i = 0; i < topics_len && dht_ready; i++) announce_topic(topics[i], false);
}

static void
on_relay_found (hdht_t *d, int status, const uint8_t key[32], void *data) {
  (void) d;
  (void) data;
  relay_finding = false;
  if (!relay_auto) return; // switched off meanwhile
  if (status == 0) {
    char did[72];
    did_of(key, did);
    memcpy(relay, key, 32);
    has_relay = true;
    hdht_set_relay(&dht, relay);
    port_printf("+RELAYFOUND:%s", did);
    uv_timer_start(&relay_timer, on_relay_timer, RELAY_CHECK_MS, 0);
    return;
  }
  // none usable: connect directly until one turns up
  has_relay = false;
  hdht_set_relay(&dht, NULL);
  port_line("+RELAYFOUND:");
  uv_timer_start(&relay_timer, on_relay_timer, RELAY_RETRY_MS, 0);
}

static void
find_relay (const uint8_t *avoid) {
  if (relay_finding || !dht_ready) return;
  relay_finding = true;
  uv_timer_stop(&relay_timer);
  if (hdht_relay_find(&dht, avoid, on_relay_found, NULL) != 0) on_relay_found(&dht, HDHT_ENOMEM, NULL, NULL);
}

static void
on_relay_checked (hdht_relay_t *r, int status, uint32_t remote_id, void *data) {
  (void) r;
  (void) remote_id;
  (void) data;
  if (!relay_auto || !has_relay) return;
  if (status == 0) uv_timer_start(&relay_timer, on_relay_timer, RELAY_CHECK_MS, 0);
  else find_relay(relay);
}

// no relay yet: look again; a relay in use: check it still answers, so
// inbound connections, which cannot report a failed pairing, keep working
static void
on_relay_timer (uv_timer_t *t) {
  (void) t;
  if (!relay_auto) return;
  if (!has_relay) find_relay(NULL);
  else if (hdht_relay_probe(&dht, relay, on_relay_checked, NULL, NULL) != 0) uv_timer_start(&relay_timer, on_relay_timer, RELAY_RETRY_MS, 0);
}

static void
on_restart (uv_timer_t *t) {
  (void) t;
  esp_restart();
}

// commands

static void
cmd_send (const char *args, bool text) {
  const char *comma = strchr(args, ',');
  link_t *l = link_arg(args);
  if (l == NULL || comma == NULL) {
    error("bad link");
    return;
  }
  if (!l->open) {
    error("link not open");
    return;
  }
  const char *payload = comma + 1;
  int len;
  if (text) {
    len = (int) strlen(payload);
    if (len > MAX_SEND) {
      error("too long");
      return;
    }
    memcpy(bytes, payload, len);
  } else if ((len = parse_hex(payload, MAX_SEND)) < 0) {
    error("bad hex or too long");
    return;
  }
  if (len == 0) {
    error("empty");
    return;
  }
  if (hdht_stream_write(l->s, bytes, (size_t) len) != 0) {
    error("write failed");
    return;
  }
  ok();
}

static void
cmd_put (const char *args, bool text) {
  int len;
  if (text) {
    len = (int) strlen(args);
    if (len > HDHT_MUTABLE_MAX_VALUE) {
      error("too long");
      return;
    }
    memcpy(bytes, args, len);
  } else if ((len = parse_hex(args, HDHT_MUTABLE_MAX_VALUE)) < 0) {
    error("bad hex or too long");
    return;
  }
  if (len == 0) {
    error("empty");
    return;
  }
  if (!dht_ready) {
    error("not ready");
    return;
  }
  memcpy(record, bytes, len);
  record_len = (size_t) len;
  record_seq++;
  save_record();
  if (put_record() != 0) {
    error("put failed to start");
    return;
  }
  uv_timer_start(&republish_timer, on_republish, REPUBLISH_MS, REPUBLISH_MS);
  port_printf("+RECORD:%llu", (unsigned long long) record_seq);
  ok();
}

static void
cmd_sign (const char *args, bool text) {
  int len;
  if (text) {
    len = (int) strlen(args);
    if (len > MAX_SEND) {
      error("too long");
      return;
    }
    memcpy(bytes, args, len);
  } else if ((len = parse_hex(args, MAX_SEND)) < 0) {
    error("bad hex or too long");
    return;
  }
  uint8_t sig[64];
  crypto_sign_detached(sig, NULL, bytes, (size_t) len, sk);
  port_printf("+SIGN:%s", to_hex(sig, 64));
  ok();
}

static void
cmd_verify (char *args) {
  char *msg = strchr(args, ',');
  char *sig_hex = msg ? strchr(msg + 1, ',') : NULL;
  uint8_t key[32], sig[64];
  if (sig_hex == NULL) {
    error("expected did,hex,signature");
    return;
  }
  *msg++ = '\0';
  *sig_hex++ = '\0';
  if (!parse_key(args, key)) {
    error("bad did");
    return;
  }
  if (strlen(sig_hex) != 128 || sodium_hex2bin(sig, 64, sig_hex, 128, NULL, NULL, NULL) != 0) {
    error("bad signature");
    return;
  }
  int len = parse_hex(msg, MAX_SEND);
  if (len < 0) {
    error("bad hex or too long");
    return;
  }
  port_printf("+VERIFY:%d", crypto_sign_verify_detached(sig, bytes, (size_t) len, key) == 0);
  ok();
}

static void
cmd_allow (const char *args, bool query) {
  if (query) {
    for (size_t i = 0; i < allow_len; i++) {
      char d[72];
      did_of(allow[i], d);
      port_printf("+ALLOW:%s", d);
    }
    ok();
    return;
  }
  if (args[0] == '\0') {
    allow_len = 0;
    save_allow();
    ok();
    return;
  }
  uint8_t key[32];
  if (!parse_key(args, key)) {
    error("bad did");
    return;
  }
  if (allowed(key) && allow_len) {
    ok();
    return;
  }
  if (allow_len == MAX_ALLOW) {
    error("allow list full");
    return;
  }
  memcpy(allow[allow_len++], key, 32);
  save_allow();
  ok();
}

static bool
valid_model (const char *m) {
  size_t len = strlen(m);
  if (len == 0 || len > 32) return false;
  for (; *m; m++) {
    if (!isalnum((unsigned char) *m) && *m != ' ' && *m != '.' && *m != '_' && *m != '-') return false;
  }
  return true;
}

// AT+CRED=<id>,<issuer did>,<iat>,<model>,<signature>: a credential for us
static void
cmd_cred (char *args) {
  char *f[5];
  int n = 0;
  for (char *p = args; n < 5 && p; n++) {
    f[n] = p;
    p = strchr(p, ',');
    if (p) *p++ = '\0';
  }
  uint8_t issuer[32], sig[64];
  char *end;
  unsigned long long iat = n == 5 ? strtoull(f[2], &end, 10) : 0;
  if (n != 5 || strlen(f[0]) != 16 || *end != '\0' || !valid_model(f[3]) || !parse_key(f[1], issuer) || strlen(f[4]) != 128 || sodium_hex2bin(sig, 64, f[4], 128, NULL, NULL, NULL) != 0) {
    error("expected id,issuer did,iat,model,signature");
    return;
  }
  char iss[72];
  did_of(issuer, iss);
  if (CONFIG_MODULE_ISSUER[0] && strcmp(iss, CONFIG_MODULE_ISSUER) != 0) {
    error("not from the trusted issuer");
    return;
  }
  char text[220];
  int len = snprintf(text, sizeof(text), "hdht-credential/1 %s %s %s %llu %s", f[0], iss + 7, did + 7, iat, f[3]);
  if (crypto_sign_verify_detached(sig, (const uint8_t *) text, (size_t) len, issuer) != 0) {
    error("bad signature");
    return;
  }

  static char next[sizeof(cred)];
  len = snprintf(next, sizeof(next), "{\"v\":1,\"id\":\"%s\",\"iss\":\"%s\",\"sub\":\"%s\",\"iat\":%llu,\"model\":\"%s\",\"sig\":\"%s\"}", f[0], iss, did, iat, f[3], f[4]);
  if (len <= 0 || (size_t) len >= sizeof(next)) {
    error("too long");
    return;
  }
  memcpy(cred, next, (size_t) len + 1);
  nvs_handle_t nvs;
  if (nvs_open("module", NVS_READWRITE, &nvs) == ESP_OK) {
    nvs_set_str(nvs, "cred", cred);
    nvs_commit(nvs);
    nvs_close(nvs);
  }
  ok();
}

static void
cmd_links (void) {
  for (int i = 0; i < MAX_LINKS; i++) {
    if (!links[i].used) continue;
    char d[72];
    did_of(links[i].key, d);
    port_printf("+LINK:%d,%s,%s,%d", i, d, links[i].inbound ? "IN" : "OUT", links[i].open);
  }
  ok();
}

void
at_line (char *line) {
  // the command name is case-insensitive; arguments are not
  char *args = line + strcspn(line, "=?");
  for (char *c = line; c < args; c++) *c = (char) toupper((unsigned char) *c);
  bool query = *args == '?';
  bool set = *args == '=';
  char name[16];
  size_t name_len = (size_t) (args - line);
  if (name_len >= sizeof(name)) {
    error("unknown command");
    return;
  }
  memcpy(name, line, name_len);
  name[name_len] = '\0';
  if (*args) args++;

  if (strcmp(name, "AT") == 0) {
    ok();
    return;
  }
  if (strcmp(name, "AT+INFO") == 0) {
    int open = 0;
    for (int i = 0; i < MAX_LINKS; i++) open += links[i].open;
    port_printf("+INFO:%s,%s,%d,%d,%d,%d,%u", MODULE_VERSION, did, wifi_connected(), dht_ready, listening, open, (unsigned) heap_caps_get_free_size(MALLOC_CAP_8BIT));
    ok();
    return;
  }
  if (strcmp(name, "AT+ID") == 0) {
    port_printf("+ID:%s", did);
    ok();
    return;
  }
  if (strcmp(name, "AT+WIFI") == 0) {
    if (query) {
      port_printf("+WIFI:%s,%d,%s", wifi_ssid(), wifi_connected(), wifi_ip());
      ok();
      return;
    }
    if (!set) {
      error("expected AT+WIFI=<ssid>,<password>");
      return;
    }
    char *comma = strchr(args, ',');
    if (comma) *comma = '\0';
    if (strlen(args) > 32 || (comma && strlen(comma + 1) > 64)) {
      error("too long");
      return;
    }
    wifi_set(args, comma ? comma + 1 : "");
    if (comma) sodium_memzero(comma + 1, strlen(comma + 1));
    ok();
    return;
  }
  if (strcmp(name, "AT+RESTART") == 0) {
    ok();
    uv_timer_start(&restart_timer, on_restart, 100, 0);
    return;
  }

  // everything else needs the DHT, or is about identity and needs nothing
  if (strcmp(name, "AT+HASH") == 0 && set) {
    uint8_t out[32];
    crypto_generichash(out, 32, (const uint8_t *) args, strlen(args), NULL, 0);
    port_printf("+HASH:%s", to_hex(out, 32));
    ok();
    return;
  }
  if (strcmp(name, "AT+SIGN") == 0 && set) {
    cmd_sign(args, false);
    return;
  }
  if (strcmp(name, "AT+SIGNT") == 0 && set) {
    cmd_sign(args, true);
    return;
  }
  if (strcmp(name, "AT+VERIFY") == 0 && set) {
    cmd_verify(args);
    return;
  }
  if (strcmp(name, "AT+ALLOW") == 0 && (set || query)) {
    cmd_allow(args, query);
    return;
  }
  if (strcmp(name, "AT+CRED") == 0 && (set || query)) {
    if (query) {
      if (cred[0]) port_printf("+CRED:%s", cred);
      ok();
      return;
    }
    if (args[0]) {
      cmd_cred(args);
      return;
    }
    cred[0] = '\0';
    nvs_handle_t nvs;
    if (nvs_open("module", NVS_READWRITE, &nvs) == ESP_OK) {
      nvs_erase_key(nvs, "cred");
      nvs_commit(nvs);
      nvs_close(nvs);
    }
    ok();
    return;
  }
  if (strcmp(name, "AT+LINKS") == 0) {
    cmd_links();
    return;
  }
  if (strcmp(name, "AT+SEND") == 0 && set) {
    cmd_send(args, false);
    return;
  }
  if (strcmp(name, "AT+SENDT") == 0 && set) {
    cmd_send(args, true);
    return;
  }
  if (strcmp(name, "AT+CLOSE") == 0 && set) {
    link_t *l = link_arg(args);
    if (l == NULL) {
      error("bad link");
      return;
    }
    hdht_stream_end(l->s);
    uv_timer_start(&l->close_timer, on_close_timeout, CLOSE_MS, 0);
    ok();
    return;
  }
  if (strcmp(name, "AT+LISTEN") == 0) {
    if (query) {
      port_printf("+LISTEN:%d", listening);
      ok();
      return;
    }
    listen_wanted = strcmp(args, "1") == 0;
    if (listen_wanted) start_listening(); // or once the DHT is ready
    else if (listening) hdht_server_close(&server, on_server_closed);
    ok();
    return;
  }

  if (!dht_ready) {
    error("not ready");
    return;
  }

  if (strcmp(name, "AT+CONNECT") == 0 && set) {
    uint8_t key[32];
    if (!parse_key(args, key)) {
      error("bad did");
      return;
    }
    link_t *l = link_new();
    if (l == NULL) {
      error("no free link");
      return;
    }
    l->inbound = false;
    memcpy(l->key, key, 32);
    l->s = &l->stream;
    if (hdht_connect(&dht, &l->stream, key, on_link_open, on_link_data, on_link_close, l) != 0) {
      l->used = false;
      error("connect failed to start");
      return;
    }
    port_printf("+CONNECT:%d", link_index(l));
    ok();
    return;
  }
  if (strcmp(name, "AT+PUT") == 0 && set) {
    cmd_put(args, false);
    return;
  }
  if (strcmp(name, "AT+PUTT") == 0 && set) {
    cmd_put(args, true);
    return;
  }
  if (strcmp(name, "AT+GET") == 0 && set) {
    uint8_t *key = malloc(32);
    if (key == NULL || !parse_key(args, key)) {
      free(key);
      error("bad did");
      return;
    }
    if (hdht_mutable_get(&dht, key, 0, on_get, key) != 0) {
      free(key);
      error("get failed to start");
      return;
    }
    ok();
    return;
  }
  if (strcmp(name, "AT+RELAY") == 0 && (set || query)) {
    char d[72];
    if (query) {
      if (has_relay) did_of(relay, d);
      if (relay_auto) port_printf("+RELAY:AUTO,%s", has_relay ? d : "");
      else if (has_relay) port_printf("+RELAY:%s", d);
      ok();
      return;
    }
    bool to_auto = strcmp(args, "AUTO") == 0;
    uint8_t key[32];
    if (!to_auto && args[0] != '\0' && !parse_key(args, key)) {
      error("bad did");
      return;
    }
    relay_auto = to_auto;
    has_relay = !to_auto && args[0] != '\0';
    if (has_relay) memcpy(relay, key, 32);
    uv_timer_stop(&relay_timer);
    save_relay();
    hdht_set_relay(&dht, has_relay ? relay : NULL);
    if (to_auto) find_relay(NULL); // then +RELAYFOUND
    ok();
    return;
  }
  if (strcmp(name, "AT+ANNOUNCE") == 0 && (set || query)) {
    if (query) {
      for (size_t i = 0; i < topics_len; i++) port_printf("+TOPIC:%s", to_hex(topics[i], 32));
      ok();
      return;
    }
    if (args[0] == '\0') {
      for (size_t i = 0; i < topics_len; i++) announce_topic(topics[i], true);
      topics_len = 0;
      save_topics();
      ok();
      return;
    }
    uint8_t topic[32];
    if (strlen(args) != 64 || sodium_hex2bin(topic, 32, args, 64, NULL, NULL, NULL) != 0) {
      error("bad topic: 64 hex characters");
      return;
    }
    bool known = false;
    for (size_t i = 0; i < topics_len; i++) known = known || memcmp(topics[i], topic, 32) == 0;
    if (!known) {
      if (topics_len == MAX_TOPICS) {
        error("too many topics");
        return;
      }
      memcpy(topics[topics_len++], topic, 32);
      save_topics();
    }
    if (announce_topic(topic, false) != 0) {
      error("announce failed to start");
      return;
    }
    uv_timer_start(&announce_timer, on_announce_timer, ANNOUNCE_MS, ANNOUNCE_MS);
    ok();
    return;
  }
  if (strcmp(name, "AT+LOOKUP") == 0 && set) {
    uint8_t *topic = malloc(32);
    if (topic == NULL || strlen(args) != 64 || sodium_hex2bin(topic, 32, args, 64, NULL, NULL, NULL) != 0) {
      free(topic);
      error("bad topic: 64 hex characters");
      return;
    }
    if (hdht_lookup(&dht, topic, on_lookup, topic) != 0) {
      free(topic);
      error("lookup failed to start");
      return;
    }
    ok();
    return;
  }
  error("unknown command");
}

void
at_init (void) {
  uv_timer_init(&loop, &republish_timer);
  uv_timer_init(&loop, &restart_timer);
  uv_timer_init(&loop, &announce_timer);
  uv_timer_init(&loop, &relay_timer);
  for (int i = 0; i < MAX_LINKS; i++) {
    uv_timer_init(&loop, &links[i].close_timer);
    links[i].close_timer.data = &links[i];
  }

  nvs_handle_t nvs;
  if (nvs_open("module", NVS_READONLY, &nvs) != ESP_OK) return;
  size_t len = sizeof(allow);
  if (nvs_get_blob(nvs, "allow", allow, &len) == ESP_OK) allow_len = len / 32;
  len = sizeof(record);
  if (nvs_get_blob(nvs, "record", record, &len) == ESP_OK) record_len = len;
  nvs_get_u64(nvs, "rec_seq", &record_seq);
  len = 32;
  has_relay = nvs_get_blob(nvs, "relay", relay, &len) == ESP_OK;
  uint8_t a = 0;
  nvs_get_u8(nvs, "relay_auto", &a);
  relay_auto = a;
  len = sizeof(topics);
  if (nvs_get_blob(nvs, "topics", topics, &len) == ESP_OK) topics_len = len / 32;
  len = sizeof(cred);
  if (nvs_get_str(nvs, "cred", cred, &len) != ESP_OK) cred[0] = '\0';
  nvs_close(nvs);
}

// the DHT came up: use the relay, republish our record and topics, and
// listen if asked to
void
at_dht_ready (void) {
  if (relay_auto) find_relay(NULL);
  else if (has_relay) hdht_set_relay(&dht, relay);
  if (topics_len) {
    on_announce_timer(NULL);
    uv_timer_start(&announce_timer, on_announce_timer, ANNOUNCE_MS, ANNOUNCE_MS);
  }
  if (record_len) {
    put_record();
    uv_timer_start(&republish_timer, on_republish, REPUBLISH_MS, REPUBLISH_MS);
  }
  if (listen_wanted) start_listening();
}
