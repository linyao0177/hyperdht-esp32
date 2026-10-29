// Template for a distributed device app (see README.md).
//
// The device needs no server of its own:
// - Identity: an Ed25519 key pair from a seed kept in NVS. Its DID is
//   did:mw:<public key>.
// - Reachability: a HyperDHT server under that key. Any peer that knows the
//   key connects from anywhere, through NATs, over an encrypted stream that
//   authenticates both keys.
// - Record: a signed record under the same key that anyone can read: service,
//   name, owner and grant epoch.
// - Access: the first peer to send the setup code becomes the owner. The
//   owner signs grants that give other keys read access until they expire or
//   the owner revokes them all. Grants are checked from their signature alone,
//   so the device stores none.
// - Data: every reading is signed by the device, so any peer can keep and
//   pass on copies, and anyone can check them against the device's key
//   (tools/host/app-peer.js replica / check).
//
// app.c is the application: what to measure and what the owner may set.
//
// Messages are JSON, one per stream message (peer -> device unless noted):
//   device -> peer  {"t":"hi","did","svc","role":"owner"|"none","claimed"}
//   {"t":"claim","code"}                       -> {"t":"claimed"} (owner from now on)
//   {"t":"hello","role":"read","epoch","exp","sig"}  a grant -> {"t":"role","role":"read"}
//   {"t":"get"}                                -> {"t":"state",...}          read or owner
//   {"t":"subscribe"}                          -> {"t":"ok"}, then readings   read or owner
//   device -> peer  {"t":"reading","data":"<signed JSON text>","sig"}
//   {"t":"set","key","value"}                  -> {"t":"ok"}                 owner
//   {"t":"revoke"}                             -> {"t":"ok","epoch"}         owner: ends every grant
//   {"t":"release"}                            -> {"t":"ok"}                 owner: back to unclaimed
//   {"t":"provision","id","iss","iat","model","sig"}  -> {"t":"ok"}         anyone: a manufacturer
//                                                credential for this device (docs/credentials.md)
//   errors: {"t":"error","reason"}
//
// A credential is the issuer's signature of
//   "hdht-credential/1 <id> <issuer key hex> <device key hex> <iat> <model>"
// and is kept only when the issuer is CONFIG_APP_ISSUER. It goes into the
// record as "cred", so anyone who resolves the device can check it.
//
// A grant is the owner's Ed25519 signature of the text
//   "app-template/grant/1 <device key hex> <grantee key hex> read <epoch> <exp>"
// The device fills in its own key and the connecting peer's, so a grant works
// only for that device and that peer.

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_netif.h"
#include "esp_netif_sntp.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "protocol_examples_common.h"

#include "app.h"
#include "hdht.h"

#define MAX_SESSIONS   4
#define MAX_ATTEMPTS   5  // wrong setup codes before claims stop until reboot
#define REPUBLISH_MS   (12 * 3600 * 1000) // records live 48 h on the DHT
#define CLOCK_VALID    1700000000         // earlier than this: SNTP has not synced
#define CODE_ALPHABET  "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // no 0/O, 1/I

typedef enum {
  ROLE_NONE,
  ROLE_READ,
  ROLE_OWNER,
} role_t;

typedef struct {
  hdht_stream_t *stream;
  role_t role;
  bool subscribed;
} session_t;

static uv_loop_t loop;
static hdht_t dht;
static hdht_server_t server;
static uv_timer_t reading_timer, republish_timer;

static uint8_t pk[32], sk[64];
static char did[72];

// kept in NVS
static bool claimed;
static uint8_t owner[32];
static char code[10]; // XXXX-XXXX while unclaimed
static uint32_t epoch, boot;
static uint64_t record_seq;
static char cred[512]; // the credential's JSON, or empty

static session_t sessions[MAX_SESSIONS];
static uint32_t readings, attempts;
static bool republish_retried;

// NVS

static nvs_handle_t
store_open (void) {
  nvs_handle_t nvs = 0;
  nvs_open("tmpl", NVS_READWRITE, &nvs);
  return nvs;
}

static void
new_code (void) {
  for (int i = 0; i < 9; i++) code[i] = i == 4 ? '-' : CODE_ALPHABET[randombytes_uniform(32)];
  code[9] = '\0';
}

static void
save_state (void) {
  nvs_handle_t nvs = store_open();
  nvs_set_u8(nvs, "claimed", claimed);
  nvs_set_blob(nvs, "owner", owner, 32);
  nvs_set_str(nvs, "code", code);
  nvs_set_u32(nvs, "epoch", epoch);
  nvs_set_u64(nvs, "rec_seq", record_seq);
  nvs_commit(nvs);
  nvs_close(nvs);
}

static void
load_state (void) {
  nvs_handle_t nvs = store_open();
  uint8_t seed[32];
  size_t len = 32;
  if (nvs_get_blob(nvs, "seed", seed, &len) != ESP_OK) {
    randombytes_buf(seed, 32);
    nvs_set_blob(nvs, "seed", seed, 32);
  }
  hdht_keypair(pk, sk, seed);
  sodium_memzero(seed, sizeof(seed));

  uint8_t c = 0;
  nvs_get_u8(nvs, "claimed", &c);
  claimed = c;
  len = 32;
  nvs_get_blob(nvs, "owner", owner, &len);
  len = sizeof(code);
  if (nvs_get_str(nvs, "code", code, &len) != ESP_OK) new_code();
  nvs_get_u32(nvs, "epoch", &epoch);
  nvs_get_u64(nvs, "rec_seq", &record_seq);
  len = sizeof(cred);
  if (nvs_get_str(nvs, "cred", cred, &len) != ESP_OK) cred[0] = '\0';
  nvs_get_u32(nvs, "boot", &boot);
  nvs_set_u32(nvs, "boot", ++boot);
  nvs_commit(nvs);
  nvs_close(nvs);
  save_state();

  char hex[65];
  sodium_bin2hex(hex, sizeof(hex), pk, 32);
  snprintf(did, sizeof(did), "did:mw:%s", hex);
}

// JSON: flat objects only, as the messages above

static bool
json_str (const char *json, const char *key, char *out, size_t cap) {
  char pattern[24];
  snprintf(pattern, sizeof(pattern), "\"%s\":\"", key);
  const char *p = strstr(json, pattern);
  if (p == NULL) return false;
  p += strlen(pattern);
  const char *end = strchr(p, '"');
  if (end == NULL || (size_t) (end - p) >= cap) return false;
  memcpy(out, p, end - p);
  out[end - p] = '\0';
  return true;
}

static bool
json_u64 (const char *json, const char *key, uint64_t *out) {
  char pattern[24];
  snprintf(pattern, sizeof(pattern), "\"%s\":", key);
  const char *p = strstr(json, pattern);
  if (p == NULL) return false;
  char *end;
  *out = strtoull(p + strlen(pattern), &end, 10);
  return end != p + strlen(pattern);
}

static void
reply (session_t *s, const char *msg) {
  if (s->stream) hdht_stream_write(s->stream, (const uint8_t *) msg, strlen(msg));
}

static void
send_error (session_t *s, const char *reason) {
  char msg[96];
  snprintf(msg, sizeof(msg), "{\"t\":\"error\",\"reason\":\"%s\"}", reason);
  reply(s, msg);
}

// record

static void
publish_record (void);

static int
build_record (char *out, size_t cap) {
  char owner_hex[67] = "null";
  if (claimed) {
    owner_hex[0] = '"';
    sodium_bin2hex(owner_hex + 1, 65, owner, 32);
    strcat(owner_hex, "\"");
  }
  return snprintf(out, cap, "{\"v\":1,\"did\":\"%s\",\"svc\":\"%s\",\"name\":\"%s\",\"owner\":%s,\"epoch\":%lu%s%s}", did, APP_SERVICE, CONFIG_APP_NAME, owner_hex, (unsigned long) epoch, cred[0] ? ",\"cred\":" : "", cred);
}

static void
on_record_put (hdht_t *d, int status, unsigned stored, void *data) {
  (void) d;
  (void) data;
  // a new firmware may describe the same state differently: move to a new seq
  if (status == HDHT_MUTABLE_ESEQ_REUSED && !republish_retried) {
    republish_retried = true;
    record_seq++;
    save_state();
    publish_record();
    return;
  }
  printf("APP|record put status=%d stored=%u seq=%llu\n", status, stored, (unsigned long long) record_seq);
}

static void
publish_record (void) {
  static char record[900];
  int len = build_record(record, sizeof(record));
  if (len <= 0 || (size_t) len >= sizeof(record)) return;
  if (hdht_mutable_put(&dht, pk, sk, record_seq, (const uint8_t *) record, (size_t) len, on_record_put, NULL) != 0) printf("APP|record put failed to start\n");
}

// a changed record needs a higher seq
static void
record_changed (void) {
  record_seq++;
  save_state();
  republish_retried = false;
  publish_record();
}

static void
on_republish (uv_timer_t *t) {
  (void) t;
  republish_retried = false;
  publish_record();
}

// readings

// copies src into a JSON string body, escaping quotes and backslashes
static bool
json_escape (const char *src, char *out, size_t cap) {
  size_t o = 0;
  for (; *src; src++) {
    if (*src == '"' || *src == '\\') {
      if (o + 1 >= cap) return false;
      out[o++] = '\\';
    }
    if (o + 1 >= cap) return false;
    out[o++] = *src;
  }
  out[o] = '\0';
  return true;
}

static void
on_reading (uv_timer_t *t) {
  (void) t;
  char members[160];
  if (app_reading(members, sizeof(members)) < 0) return;

  // boot and n make every reading unique; t is 0 until the clock is set
  char data[256];
  time_t now = time(NULL);
  int len = snprintf(data, sizeof(data), "{\"did\":\"%s\",\"boot\":%lu,\"n\":%lu,\"t\":%lld,%s}", did, (unsigned long) boot, (unsigned long) ++readings, (long long) (now >= CLOCK_VALID ? now : 0), members);
  if (len <= 0 || (size_t) len >= sizeof(data)) return;

  uint8_t sig[64];
  crypto_sign_detached(sig, NULL, (const uint8_t *) data, (size_t) len, sk);
  char sig_hex[129], escaped[320];
  sodium_bin2hex(sig_hex, sizeof(sig_hex), sig, 64);
  if (!json_escape(data, escaped, sizeof(escaped))) return;

  static char msg[512];
  snprintf(msg, sizeof(msg), "{\"t\":\"reading\",\"data\":\"%s\",\"sig\":\"%s\"}", escaped, sig_hex);
  int subscribers = 0;
  for (int i = 0; i < MAX_SESSIONS; i++) {
    if (sessions[i].stream && sessions[i].subscribed && sessions[i].role != ROLE_NONE) {
      reply(&sessions[i], msg);
      subscribers++;
    }
  }
  printf("APP|reading %s subscribers=%d\n", data, subscribers);
}

static void
start_readings (void) {
  uint64_t ms = (uint64_t) app_interval_s() * 1000;
  uv_timer_start(&reading_timer, on_reading, ms, ms);
}

// access

static const char *
role_name (role_t r) {
  return r == ROLE_OWNER ? "owner" : r == ROLE_READ ? "read" : "none";
}

static void
on_claim (session_t *s, const char *json) {
  char got[16];
  if (claimed) {
    send_error(s, "already claimed");
    return;
  }
  if (attempts >= MAX_ATTEMPTS) {
    send_error(s, "too many attempts, reboot the device");
    return;
  }
  if (!json_str(json, "code", got, sizeof(got)) || strlen(got) != strlen(code) || sodium_memcmp(got, code, strlen(code)) != 0) {
    attempts++;
    printf("APP|claim refused: wrong code (%lu of %d)\n", (unsigned long) attempts, MAX_ATTEMPTS);
    send_error(s, "wrong code");
    return;
  }
  claimed = true;
  memcpy(owner, s->stream->remote_public_key, 32);
  code[0] = '\0';
  s->role = ROLE_OWNER;
  record_changed();
  char hex[17];
  sodium_bin2hex(hex, sizeof(hex), owner, 8);
  printf("APP|claimed by did:mw:%s...\n", hex);
  reply(s, "{\"t\":\"claimed\"}");
}

static void
on_hello (session_t *s, const char *json) {
  char role[8], sig_hex[136];
  uint64_t grant_epoch, exp;
  uint8_t sig[64];
  if (!claimed) {
    send_error(s, "not claimed");
    return;
  }
  if (!json_str(json, "role", role, sizeof(role)) || strcmp(role, "read") != 0) {
    send_error(s, "unknown role");
    return;
  }
  if (!json_u64(json, "epoch", &grant_epoch) || !json_u64(json, "exp", &exp) || !json_str(json, "sig", sig_hex, sizeof(sig_hex))) {
    send_error(s, "malformed grant");
    return;
  }
  if (sodium_hex2bin(sig, 64, sig_hex, strlen(sig_hex), NULL, NULL, NULL) != 0) {
    send_error(s, "malformed grant");
    return;
  }
  if (grant_epoch != epoch) {
    send_error(s, "grant revoked");
    return;
  }

  time_t now = time(NULL);
  if (now < CLOCK_VALID) {
    send_error(s, "device clock not set yet");
    return;
  }
  if ((uint64_t) now >= exp) {
    send_error(s, "grant expired");
    return;
  }

  char dev_hex[65], to_hex[65], text[200];
  sodium_bin2hex(dev_hex, sizeof(dev_hex), pk, 32);
  sodium_bin2hex(to_hex, sizeof(to_hex), s->stream->remote_public_key, 32);
  int len = snprintf(text, sizeof(text), "app-template/grant/1 %s %s read %llu %llu", dev_hex, to_hex, (unsigned long long) grant_epoch, (unsigned long long) exp);
  if (crypto_sign_verify_detached(sig, (const uint8_t *) text, (size_t) len, owner) != 0) {
    send_error(s, "grant not signed by the owner");
    return;
  }

  s->role = ROLE_READ;
  printf("APP|grant accepted for did:mw:%.16s... until %llu\n", to_hex, (unsigned long long) exp);
  reply(s, "{\"t\":\"role\",\"role\":\"read\"}");
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

// A manufacturer credential: self-authenticating, so any peer may deliver it.
static void
on_provision (session_t *s, const char *json) {
  char id[20], iss[80], model[40], sig_hex[136];
  uint64_t iat;
  uint8_t issuer[32], sig[64];
  if (CONFIG_APP_ISSUER[0] == '\0') {
    send_error(s, "provisioning disabled: no issuer in the firmware");
    return;
  }
  if (!json_str(json, "id", id, sizeof(id)) || strlen(id) != 16 || !json_str(json, "iss", iss, sizeof(iss)) || !json_u64(json, "iat", &iat) || !json_str(json, "model", model, sizeof(model)) || !valid_model(model) || !json_str(json, "sig", sig_hex, sizeof(sig_hex)) || sodium_hex2bin(sig, 64, sig_hex, strlen(sig_hex), NULL, NULL, NULL) != 0) {
    send_error(s, "malformed credential");
    return;
  }
  if (strcmp(iss, CONFIG_APP_ISSUER) != 0 || strlen(iss) != 71 || sodium_hex2bin(issuer, 32, iss + 7, 64, NULL, NULL, NULL) != 0) {
    send_error(s, "not from the trusted issuer");
    return;
  }

  char text[220];
  int len = snprintf(text, sizeof(text), "hdht-credential/1 %s %s %s %llu %s", id, iss + 7, did + 7, (unsigned long long) iat, model);
  if (crypto_sign_verify_detached(sig, (const uint8_t *) text, (size_t) len, issuer) != 0) {
    send_error(s, "bad signature");
    return;
  }

  // built aside: a credential that does not fit leaves the current one alone
  static char next[sizeof(cred)];
  int n = snprintf(next, sizeof(next), "{\"v\":1,\"id\":\"%s\",\"iss\":\"%s\",\"sub\":\"%s\",\"iat\":%llu,\"model\":\"%s\",\"sig\":\"%s\"}", id, iss, did, (unsigned long long) iat, model, sig_hex);
  if (n <= 0 || (size_t) n >= sizeof(next)) {
    send_error(s, "malformed credential");
    return;
  }
  memcpy(cred, next, (size_t) n + 1);
  nvs_handle_t nvs = store_open();
  nvs_set_str(nvs, "cred", cred);
  nvs_commit(nvs);
  nvs_close(nvs);
  record_changed();
  printf("APP|credential %s model=\"%s\" from %.23s...\n", id, model, iss);
  reply(s, "{\"t\":\"ok\"}");
}

static void
on_get (session_t *s) {
  char settings[160], msg[512];
  if (app_settings(settings, sizeof(settings)) < 0) settings[0] = '\0';
  snprintf(msg, sizeof(msg), "{\"t\":\"state\",\"did\":\"%s\",\"name\":\"%s\",\"uptime_s\":%llu,\"free_heap\":%u,\"boot\":%lu,\"readings\":%lu,\"epoch\":%lu,\"settings\":{%s}}", did, CONFIG_APP_NAME, (unsigned long long) (esp_timer_get_time() / 1000000), (unsigned) heap_caps_get_free_size(MALLOC_CAP_8BIT), (unsigned long) boot, (unsigned long) readings, (unsigned long) epoch, settings);
  reply(s, msg);
}

static void
on_set (session_t *s, const char *json) {
  char key[24], value[48];
  if (!json_str(json, "key", key, sizeof(key)) || !json_str(json, "value", value, sizeof(value))) {
    send_error(s, "malformed");
    return;
  }
  uint32_t interval = app_interval_s();
  if (!app_set(key, value)) {
    send_error(s, "unknown setting or bad value");
    return;
  }
  if (app_interval_s() != interval) start_readings();
  printf("APP|set %s=%s\n", key, value);
  reply(s, "{\"t\":\"ok\"}");
}

static void
on_revoke (session_t *s) {
  epoch++;
  // closed outright: a peer that never ends its side would keep the slot
  for (int i = 0; i < MAX_SESSIONS; i++) {
    if (sessions[i].stream && sessions[i].role == ROLE_READ) hdht_stream_destroy(sessions[i].stream, HDHT_STREAM_ECLOSED);
  }
  record_changed();
  printf("APP|grants revoked, epoch=%lu\n", (unsigned long) epoch);
  char msg[48];
  snprintf(msg, sizeof(msg), "{\"t\":\"ok\",\"epoch\":%lu}", (unsigned long) epoch);
  reply(s, msg);
}

static void
on_release (session_t *s) {
  claimed = false;
  memset(owner, 0, 32);
  new_code();
  attempts = 0;
  epoch++; // grants from the old owner end too
  reply(s, "{\"t\":\"ok\"}");
  hdht_stream_end(s->stream); // after the reply
  for (int i = 0; i < MAX_SESSIONS; i++) {
    if (sessions[i].stream && &sessions[i] != s) hdht_stream_destroy(sessions[i].stream, HDHT_STREAM_ECLOSED);
  }
  record_changed();
  printf("APP|released; new setup code: %s\n", code);
}

// sessions

static void
on_session_data (hdht_stream_t *stream, const uint8_t *data, size_t len) {
  session_t *s = stream->data;
  static char json[600];
  if (len >= sizeof(json)) {
    send_error(s, "too long");
    return;
  }
  memcpy(json, data, len);
  json[len] = '\0';

  char t[16];
  if (!json_str(json, "t", t, sizeof(t))) return;
  bool can_read = s->role != ROLE_NONE, is_owner = s->role == ROLE_OWNER;

  if (strcmp(t, "claim") == 0) on_claim(s, json);
  else if (strcmp(t, "hello") == 0) on_hello(s, json);
  else if (strcmp(t, "provision") == 0) on_provision(s, json);
  else if (strcmp(t, "get") == 0 && can_read) on_get(s);
  else if (strcmp(t, "subscribe") == 0 && can_read) {
    s->subscribed = true;
    reply(s, "{\"t\":\"ok\"}");
  } else if (strcmp(t, "set") == 0 && is_owner) on_set(s, json);
  else if (strcmp(t, "revoke") == 0 && is_owner) on_revoke(s);
  else if (strcmp(t, "release") == 0 && is_owner) on_release(s);
  else send_error(s, "not allowed");
}

static void
on_session_close (hdht_stream_t *stream, int error) {
  session_t *s = stream->data;
  printf("APP|peer closed role=%s error=%d\n", role_name(s->role), error);
  memset(s, 0, sizeof(*s));
}

static void
on_connection (hdht_server_t *srv, hdht_stream_t *stream) {
  (void) srv;
  session_t *s = NULL;
  for (int i = 0; i < MAX_SESSIONS && s == NULL; i++) {
    if (sessions[i].stream == NULL) s = &sessions[i];
  }
  if (s == NULL) {
    hdht_stream_end(stream);
    return;
  }
  s->stream = stream;
  s->role = claimed && memcmp(stream->remote_public_key, owner, 32) == 0 ? ROLE_OWNER : ROLE_NONE;
  s->subscribed = false;
  stream->data = s;
  stream->on_data = on_session_data;
  stream->on_close = on_session_close;

  char hex[65], msg[200];
  sodium_bin2hex(hex, sizeof(hex), stream->remote_public_key, 32);
  printf("APP|peer did:mw:%.16s... role=%s from %s\n", hex, role_name(s->role), hdht_addr_str(&stream->remote_addr));
  snprintf(msg, sizeof(msg), "{\"t\":\"hi\",\"did\":\"%s\",\"svc\":\"%s\",\"role\":\"%s\",\"claimed\":%s}", did, APP_SERVICE, role_name(s->role), claimed ? "true" : "false");
  reply(s, msg);
}

// startup

static void
on_listening (hdht_server_t *srv, int status) {
  (void) srv;
  static bool first = true;
  printf("APP|listening status=%d\n", status);
  if (!first || status != 0) return;
  first = false;
  printf("APP|device %s\n", did);
  if (!claimed) printf("APP|unclaimed; setup code: %s\n", code);
  printf("APP|%s%s\n", cred[0] ? "credential " : "no manufacturer credential", cred);

  if (record_seq == 0) record_seq = 1;
  publish_record();
  uv_timer_start(&republish_timer, on_republish, REPUBLISH_MS, REPUBLISH_MS);
  start_readings();
}

static void
on_ready (hdht_t *d, int status) {
  printf("APP|bootstrapped status=%d nodes=%u\n", status, d->table_len);
  hdht_listen(d, &server, pk, sk, on_connection, on_listening, NULL);
}

static void
hdht_task (void *arg) {
  (void) arg;
  uv_loop_init(&loop);
  uv_timer_init(&loop, &reading_timer);
  uv_timer_init(&loop, &republish_timer);
  app_init();

  const char *bootstrap[] = {CONFIG_APP_BOOTSTRAP};
  hdht_opts_t opts = {0};
  if (CONFIG_APP_BOOTSTRAP[0]) {
    opts.bootstrap = bootstrap;
    opts.bootstrap_len = 1;
  }
  if (hdht_init(&dht, &loop, &opts) != 0) {
    printf("APP|hdht_init failed\n");
    vTaskDelete(NULL);
  }

  // lets peers behind the same router connect over the LAN
  esp_netif_ip_info_t ip;
  esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
  if (netif && esp_netif_get_ip_info(netif, &ip) == ESP_OK) hdht_add_local_address(&dht, (const uint8_t *) &ip.ip.addr);

  hdht_bootstrap(&dht, on_ready);
  uv_run(&loop, UV_RUN_DEFAULT);
}

void
app_main (void) {
  esp_err_t err = nvs_flash_init();
  if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    err = nvs_flash_init();
  }
  ESP_ERROR_CHECK(err);
  if (sodium_init() < 0) return;
  load_state();

  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());
  ESP_ERROR_CHECK(example_connect());

  // grants expire, so the device needs the time; it does not wait for it
  esp_sntp_config_t sntp = ESP_NETIF_SNTP_DEFAULT_CONFIG("pool.ntp.org");
  esp_netif_sntp_init(&sntp);

  xTaskCreate(hdht_task, "hdht", 20480, NULL, 5, NULL);
}
