// See hdht_ota.h.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_app_desc.h"
#include "esp_ota_ops.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "sodium.h"

#include "hc_proof.h"
#include "hdht_ota.h"

#define TIMEOUT_S 30

typedef enum { IDLE, CONNECTING, HEAD, MANIFEST, IMAGE, REBOOT } state_t;

static hdht_t *dht;
static hdht_ota_config_t cfg;
static state_t state = IDLE;
static uint32_t due = 10, quiet;
static hdht_stream_t stream;
static bool stream_open;
static hc_head_t head;
static hc_node_t nodes[HC_MAX_NODES];
static uint64_t latest, next, first, blocks, size, written, max_length;
static char version[32];
static uint8_t sha256[32];
static crypto_hash_sha256_state hash;
static esp_ota_handle_t ota;
static bool ota_open;
static int64_t started;

int
hdht_ota_version_cmp (const char *a, const char *b) {
  while (*a || *b) {
    char *ea, *eb;
    unsigned long x = strtoul(a, &ea, 10), y = strtoul(b, &eb, 10);
    a = ea;
    b = eb;
    if (x != y) return x < y ? -1 : 1;
    if (*a == '.') a++;
    if (*b == '.') b++;
    if ((*a && (*a < '0' || *a > '9')) || (*b && (*b < '0' || *b > '9'))) return strcmp(a, b);
  }
  return 0;
}

static void
finish (const char *why) {
  if (ota_open) {
    esp_ota_abort(ota);
    ota_open = false;
  }
  if (why) printf("OTA|stopped: %s\n", why);
  if (state != REBOOT) state = IDLE; // before the destroy, whose on_close comes back here
  due = state == REBOOT ? due : cfg.interval_s;
  if (stream_open) {
    stream_open = false;
    hdht_stream_destroy(&stream, 0);
  }
}

static void
request (const char *json) {
  quiet = 0;
  hdht_stream_write(&stream, (const uint8_t *) json, strlen(json));
}

static void
request_block (uint64_t index) {
  char json[96];
  snprintf(json, sizeof(json), "{\"op\":\"block\",\"index\":%llu,\"length\":%llu}", (unsigned long long) index, (unsigned long long) head.length);
  request(json);
}

// a flat JSON string or number field of the manifest
static bool
manifest_field (const char *json, const char *key, char *out, size_t cap) {
  char pattern[24];
  snprintf(pattern, sizeof(pattern), "\"%s\":", key);
  const char *p = strstr(json, pattern);
  if (!p) return false;
  p += strlen(pattern);
  bool quoted = *p == '"';
  if (quoted) p++;
  size_t n = 0;
  while (p[n] && (quoted ? p[n] != '"' : (p[n] != ',' && p[n] != '}'))) n++;
  if (n >= cap) return false;
  memcpy(out, p, n);
  out[n] = '\0';
  return true;
}

static const char *
start_image (const uint8_t *data, size_t len) {
  static char json[1025];
  if (len > 1024) return "manifest too large";
  memcpy(json, data, len);
  json[len] = '\0';
  char type[16], name[48], n_size[16], n_first[24], n_blocks[16], hex[72];
  if (!manifest_field(json, "type", type, sizeof(type)) || strcmp(type, "boat-ota/1") != 0) return "not a release manifest";
  if (!manifest_field(json, "name", name, sizeof(name)) || strcmp(name, cfg.name) != 0) return "a release of another product";
  if (!manifest_field(json, "version", version, sizeof(version)) || !manifest_field(json, "size", n_size, sizeof(n_size)) ||
      !manifest_field(json, "first", n_first, sizeof(n_first)) || !manifest_field(json, "blocks", n_blocks, sizeof(n_blocks)) ||
      !manifest_field(json, "sha256", hex, sizeof(hex)) || strlen(hex) != 64 ||
      sodium_hex2bin(sha256, 32, hex, 64, NULL, NULL, NULL) != 0) {
    return "manifest fields missing";
  }
  size = strtoull(n_size, NULL, 10);
  first = strtoull(n_first, NULL, 10);
  blocks = strtoull(n_blocks, NULL, 10);
  if (first + blocks > head.length || first <= latest) return "manifest names blocks outside the core";

  const esp_app_desc_t *running = esp_app_get_description();
  if (hdht_ota_version_cmp(version, running->version) <= 0) {
    printf("OTA|up to date: running %s, latest release %s (core length %llu)\n", running->version, version, (unsigned long long) head.length);
    return "";
  }
  const esp_partition_t *part = esp_ota_get_next_update_partition(NULL);
  if (part == NULL) return "no OTA partition";
  if (size > part->size) return "image larger than the partition";
  if (esp_ota_begin(part, OTA_WITH_SEQUENTIAL_WRITES, &ota) != ESP_OK) return "esp_ota_begin failed";
  ota_open = true;
  crypto_hash_sha256_init(&hash);
  written = 0;
  next = first;
  started = esp_timer_get_time();
  printf("OTA|updating %s -> %s: %llu bytes in %llu blocks into %s\n", running->version, version, (unsigned long long) size, (unsigned long long) blocks, part->label);
  request_block(next);
  return NULL;
}

static const char *
on_image_block (const uint8_t *data, size_t len) {
  if (esp_ota_write(ota, data, len) != ESP_OK) return "esp_ota_write failed";
  crypto_hash_sha256_update(&hash, data, len);
  written += len;
  next++;
  if ((next - first) % 64 == 0) printf("OTA|%llu of %llu blocks\n", (unsigned long long) (next - first), (unsigned long long) blocks);
  if (next < first + blocks) {
    request_block(next);
    return NULL;
  }
  uint8_t got[32];
  crypto_hash_sha256_final(&hash, got);
  if (written != size || sodium_memcmp(got, sha256, 32) != 0) return "image does not match the manifest";
  if (esp_ota_end(ota) != ESP_OK) {
    ota_open = false;
    return "esp_ota_end rejected the image";
  }
  ota_open = false;
  const esp_partition_t *part = esp_ota_get_next_update_partition(NULL);
  if (esp_ota_set_boot_partition(part) != ESP_OK) return "could not set the boot partition";
  printf("OTA|done: %s, %llu bytes checked against the core in %lld ms; rebooting into %s\n", version, (unsigned long long) written, (long long) ((esp_timer_get_time() - started) / 1000), part->label);
  state = REBOOT;
  due = 2;
  return "";
}

static void
on_data (hdht_stream_t *s, const uint8_t *data, size_t len) {
  (void) s;
  quiet = 0;
  if (len > 0 && data[0] == 'E') {
    printf("OTA|server: %.*s\n", (int) (len - 1), (const char *) data + 1);
    finish("the server could not answer");
    return;
  }
  const char *why = NULL;
  if (state == HEAD) {
    why = hc_decode_head(data, len, &head, &latest);
    if (!why) why = hc_verify_head(&head, cfg.key, cfg.signer);
    if (!why && head.length < max_length) why = "the core is shorter than one seen before";
    if (why) {
      finish(why);
      return;
    }
    max_length = head.length;
    if (latest == UINT64_MAX) {
      printf("OTA|no release of %s in the core (length %llu)\n", cfg.name, (unsigned long long) head.length);
      finish(NULL);
      return;
    }
    state = MANIFEST;
    request_block(latest);
    return;
  }
  uint64_t index;
  size_t n, dlen;
  const uint8_t *block;
  why = hc_decode_block(data, len, &index, nodes, &n, &block, &dlen);
  if (!why && index != (state == MANIFEST ? latest : next)) why = "the server sent another block";
  if (!why) why = hc_verify_block(&head, index, block, dlen, nodes, n);
  if (why) {
    char msg[96];
    snprintf(msg, sizeof(msg), "block %llu: %s", (unsigned long long) index, why);
    finish(msg);
    return;
  }
  if (state == MANIFEST) {
    why = start_image(block, dlen);
    if (why == NULL) {
      state = IMAGE;
      return;
    }
  } else {
    why = on_image_block(block, dlen);
    if (why == NULL) return;
  }
  finish(why[0] ? why : NULL);
}

static void
on_open (hdht_stream_t *s) {
  (void) s;
  stream_open = true;
  state = HEAD;
  char json[96];
  snprintf(json, sizeof(json), "{\"op\":\"head\",\"name\":\"%s\"}", cfg.name);
  request(json);
}

static void
on_close (hdht_stream_t *s, int error) {
  (void) s;
  bool was_open = stream_open;
  stream_open = false;
  if (state == CONNECTING) {
    printf("OTA|could not reach the server (%d)\n", error);
    state = IDLE;
    due = cfg.interval_s;
  } else if (was_open && (state == HEAD || state == MANIFEST || state == IMAGE)) {
    finish("the connection closed");
  }
}

int
hdht_ota_start (hdht_t *d, const hdht_ota_config_t *config) {
  dht = d;
  cfg = *config;
  if (cfg.interval_s == 0) cfg.interval_s = 3600;
  char hex[17];
  sodium_bin2hex(hex, sizeof(hex), cfg.key, 8);
  printf("OTA|core %s... for %s, running %s, checking every %lu s\n", hex, cfg.name, esp_app_get_description()->version, (unsigned long) cfg.interval_s);
  return 0;
}

void
hdht_ota_tick (void) {
  if (dht == NULL) return;
  if (state == REBOOT) {
    if (due && --due == 0) esp_restart();
    return;
  }
  if (state != IDLE) {
    // a connection still being made ends by itself (on_open with an error)
    if (state != CONNECTING && ++quiet > TIMEOUT_S) finish("no answer");
    return;
  }
  if (due && --due) return;
  state = CONNECTING;
  quiet = 0;
  memset(&stream, 0, sizeof(stream));
  if (hdht_connect(dht, &stream, cfg.server, on_open, on_data, on_close, NULL) != 0) {
    state = IDLE;
    due = cfg.interval_s;
  }
}

void
hdht_ota_confirm (void) {
  const esp_partition_t *running = esp_ota_get_running_partition();
  esp_ota_img_states_t st;
  if (esp_ota_get_state_partition(running, &st) == ESP_OK && st == ESP_OTA_IMG_PENDING_VERIFY) {
    esp_ota_mark_app_valid_cancel_rollback();
    printf("OTA|%s confirmed\n", esp_app_get_description()->version);
  }
}
