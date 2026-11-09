// hdht_mqtt node list: decoding and tallying (see hdht_mqtt_nodelist.h).

#include <stdbool.h>
#include <string.h>
#include <sodium.h>

#include "hdht_mqtt_nodelist.h"

static const char FIELD[] = "\"boat_nodes\":\"";

int
hdht_mqtt_nodelist_from_record (const uint8_t *value, size_t len, uint8_t *blob, size_t cap) {
  if (value == NULL) return -1;
  size_t flen = sizeof(FIELD) - 1;
  for (size_t i = 0; i + flen <= len; i++) {
    if (memcmp(value + i, FIELD, flen) != 0) continue;
    const char *b64 = (const char *) value + i + flen;
    size_t end = 0;
    while (i + flen + end < len && b64[end] != '"') end++;
    if (i + flen + end >= len) return -1; // no closing quote
    size_t out = 0;
    if (sodium_base642bin(blob, cap, b64, end, NULL, &out, NULL, sodium_base64_VARIANT_ORIGINAL) != 0) return -1;
    return (int) out;
  }
  return -1;
}

static uint64_t
be64 (const uint8_t *p) {
  uint64_t v = 0;
  for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
  return v;
}

int
hdht_mqtt_nodelist_decode (const uint8_t *b, size_t len, hdht_mqtt_nodelist_t *out) {
  if (len < 44 || memcmp(b, "BNL2", 4) != 0) return -1;
  size_t o = 4;
  out->chain_id = be64(b + o);
  o += 8;
  memcpy(out->registry, b + o, 20);
  o += 20;
  out->epoch = be64(b + o);
  o += 8;
  size_t nv = b[o++];
  if (nv > HDHT_MQTT_NODELIST_VERIFIERS || len < o + 32 * nv + 3) return -1;
  memcpy(out->verifiers, b + o, 32 * nv);
  out->verifiers_len = (uint8_t) nv;
  o += 32 * nv;
  out->total = (uint16_t) ((b[o] << 8) | b[o + 1]);
  o += 2;
  size_t np = b[o++];
  if (np > HDHT_MQTT_NODELIST_PAGES || len != o + 32 * np) return -1;
  if (np != ((size_t) out->total + HDHT_MQTT_NODELIST_PAGE - 1) / HDHT_MQTT_NODELIST_PAGE) return -1;
  memcpy(out->pages, b + o, 32 * np);
  out->pages_len = (uint8_t) np;
  out->page = 0;
  out->nodes_len = 0;
  return 0;
}

int
hdht_mqtt_nodelist_decode_page (const uint8_t *p, size_t len, uint8_t index, hdht_mqtt_nodelist_t *list) {
  if (index >= list->pages_len || len < 5 || memcmp(p, "BNP1", 4) != 0) return -1;
  size_t n = p[4];
  if (n > HDHT_MQTT_NODELIST_PAGE || len != 5 + 32 * n) return -1;
  uint8_t hash[32];
  crypto_generichash(hash, 32, p, len, NULL, 0);
  if (sodium_memcmp(hash, list->pages[index], 32) != 0) return -1;
  memcpy(list->nodes, p + 5, 32 * n);
  list->nodes_len = (uint8_t) n;
  list->page = index;
  return 0;
}

size_t
hdht_mqtt_nodelist_quorum (size_t trusted) {
  return trusted <= 2 ? trusted : (2 * trusted + 2) / 3;
}

int
hdht_mqtt_nodelist_tally (const uint8_t *const *blobs, const size_t *lens, size_t n, size_t trusted, hdht_mqtt_nodelist_t *out, size_t *votes) {
  size_t quorum = hdht_mqtt_nodelist_quorum(trusted);
  int best = -1;
  size_t best_votes = 0;
  uint64_t best_epoch = 0;
  hdht_mqtt_nodelist_t l;
  for (size_t i = 0; i < n; i++) {
    if (blobs[i] == NULL || lens[i] == 0 || hdht_mqtt_nodelist_decode(blobs[i], lens[i], &l) != 0) continue;
    bool counted = false; // an earlier blob with the same bytes was counted already
    for (size_t j = 0; j < i && !counted; j++) counted = blobs[j] && lens[j] == lens[i] && memcmp(blobs[j], blobs[i], lens[i]) == 0;
    if (counted) continue;
    size_t v = 0;
    for (size_t j = i; j < n; j++) v += blobs[j] && lens[j] == lens[i] && memcmp(blobs[j], blobs[i], lens[i]) == 0;
    if (quorum == 0 || v < quorum) continue;
    if (best < 0 || l.epoch > best_epoch || (l.epoch == best_epoch && v > best_votes)) {
      best = (int) i;
      best_votes = v;
      best_epoch = l.epoch;
    }
  }
  if (best < 0) return -1;
  hdht_mqtt_nodelist_decode(blobs[best], lens[best], out);
  if (votes) *votes = best_votes;
  return 0;
}
