// Signed messages (include/hdht_mqtt_signed.h).

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "hdht_mqtt_signed.h"

static const char SIG_CONTEXT[] = "hdht-mqtt-sig/1"; // and its NUL

// "hdht-mqtt-sig/1" 0 | topic | 0 | seq | payload, in a buffer the caller frees
static uint8_t *
signable (const char *topic, const uint8_t seq_be[8], const uint8_t *payload, size_t len, size_t *out_len) {
  size_t topic_len = strlen(topic);
  size_t n = sizeof(SIG_CONTEXT) + topic_len + 1 + 8 + len;
  uint8_t *m = malloc(n);
  if (m == NULL) return NULL;
  uint8_t *p = m;
  memcpy(p, SIG_CONTEXT, sizeof(SIG_CONTEXT));
  p += sizeof(SIG_CONTEXT);
  memcpy(p, topic, topic_len);
  p += topic_len;
  *p++ = 0;
  memcpy(p, seq_be, 8);
  p += 8;
  if (len) memcpy(p, payload, len);
  *out_len = n;
  return m;
}

int
hdht_mqtt_sign (const uint8_t secret_key[64], const char *topic, uint64_t seq, const uint8_t *payload, size_t len, uint8_t *out, size_t cap) {
  if (cap < HDHT_MQTT_SIGNED_OVERHEAD + len) return -1;
  out[0] = 'S';
  out[1] = 1;
  for (int i = 0; i < 8; i++) out[2 + i] = (uint8_t) (seq >> (56 - 8 * i));
  size_t m_len;
  uint8_t *m = signable(topic, out + 2, payload, len, &m_len);
  if (m == NULL) return -1;
  crypto_sign_detached(out + 10, NULL, m, m_len, secret_key);
  free(m);
  if (len) memmove(out + HDHT_MQTT_SIGNED_OVERHEAD, payload, len);
  return (int) (HDHT_MQTT_SIGNED_OVERHEAD + len);
}

int
hdht_mqtt_open (const uint8_t public_key[32], const char *topic, const uint8_t *msg, size_t len, uint64_t *seq, const uint8_t **payload, size_t *payload_len) {
  if (len < HDHT_MQTT_SIGNED_OVERHEAD || msg[0] != 'S' || msg[1] != 1) return -1;
  size_t body = len - HDHT_MQTT_SIGNED_OVERHEAD;
  size_t m_len;
  uint8_t *m = signable(topic, msg + 2, msg + HDHT_MQTT_SIGNED_OVERHEAD, body, &m_len);
  if (m == NULL) return -1;
  int err = crypto_sign_verify_detached(msg + 10, m, m_len, public_key);
  free(m);
  if (err != 0) return -1;
  uint64_t s = 0;
  for (int i = 0; i < 8; i++) s = (s << 8) | msg[2 + i];
  *seq = s;
  *payload = msg + HDHT_MQTT_SIGNED_OVERHEAD;
  *payload_len = body;
  return 0;
}


// receipts --------------------------------------------------------------------

static const char RECEIPT_PREFIX[] = "boat-receipt/1|";

// the field `i` (0-based) of the body, split at '|'
static bool
field (const char *body, size_t len, int i, const char **out, size_t *out_len) {
  const char *p = body, *end = body + len;
  for (int k = 0; k < i; k++) {
    p = memchr(p, '|', (size_t) (end - p));
    if (p == NULL) return false;
    p++;
  }
  const char *e = memchr(p, '|', (size_t) (end - p));
  *out = p;
  *out_len = (size_t) ((e ? e : end) - p);
  return true;
}

static bool
parse_u64 (const char *p, size_t len, uint64_t *out) {
  if (len == 0 || len > 20) return false;
  uint64_t v = 0;
  for (size_t i = 0; i < len; i++) {
    if (p[i] < '0' || p[i] > '9') return false;
    v = v * 10 + (uint64_t) (p[i] - '0');
  }
  *out = v;
  return true;
}

static const char *
body_end (const char *line, size_t len) {
  for (size_t i = len; i > 0; i--) {
    if (line[i - 1] == '|') return line + i - 1;
  }
  return NULL;
}

int
hdht_mqtt_receipt_open (const uint8_t signer[32], const uint8_t *device, const char *line, size_t len, hdht_mqtt_receipt_t *out) {
  const char *cut = body_end(line, len);
  if (cut == NULL || len < sizeof(RECEIPT_PREFIX) || memcmp(line, RECEIPT_PREFIX, sizeof(RECEIPT_PREFIX) - 1) != 0) return -1;
  size_t body_len = (size_t) (cut - line);
  uint8_t sig[64];
  size_t sig_len = 0;
  if (len - body_len - 1 != 128 || sodium_hex2bin(sig, 64, cut + 1, 128, NULL, &sig_len, NULL) != 0 || sig_len != 64) return -1;

  hdht_mqtt_receipt_t r = {0};
  const char *f;
  size_t fl;
  size_t n;
  if (!field(line, body_len, 1, &f, &fl) || fl != 64 || sodium_hex2bin(r.signer, 32, f, 64, NULL, &n, NULL) != 0) return -1;
  if (!field(line, body_len, 2, &f, &fl) || fl != 64 || sodium_hex2bin(r.device, 32, f, 64, NULL, &n, NULL) != 0) return -1;
  if (memcmp(r.signer, signer, 32) != 0 || (device && memcmp(r.device, device, 32) != 0)) return -1;
  if (!field(line, body_len, 3, &f, &fl) || !parse_u64(f, fl, &r.count)) return -1;
  if (!field(line, body_len, 4, &f, &fl) || !parse_u64(f, fl, &r.bytes)) return -1;
  if (!field(line, body_len, 5, &f, &fl)) return -1;
  for (size_t i = 0; i < fl; i++) r.ranges += f[i] == ';';
  if (fl) r.ranges++;
  if (!field(line, body_len, 6, &f, &fl) || !parse_u64(f, fl, &r.t)) return -1;
  if (crypto_sign_verify_detached(sig, (const uint8_t *) line, body_len, signer) != 0) return -1;
  if (out) *out = r;
  return 0;
}

int
hdht_mqtt_receipt_check (const char *line, size_t len, uint64_t lo, uint64_t hi, uint64_t *covered, uint64_t *beyond) {
  const char *cut = body_end(line, len);
  const char *f;
  size_t fl;
  if (cut == NULL || !field(line, (size_t) (cut - line), 5, &f, &fl)) return -1;
  uint64_t c = 0, b = 0;
  const char *p = f, *end = f + fl;
  while (p < end) {
    const char *semi = memchr(p, ';', (size_t) (end - p));
    const char *stop = semi ? semi : end;
    const char *dash = memchr(p, '-', (size_t) (stop - p));
    uint64_t a, z;
    if (dash == NULL || !parse_u64(p, (size_t) (dash - p), &a) || !parse_u64(dash + 1, (size_t) (stop - dash - 1), &z) || z < a) return -1;
    uint64_t from = a > lo ? a : lo, to = z < hi ? z : hi;
    if (from <= to) c += to - from + 1;
    if (z > hi) b += z - (a > hi ? a : hi + 1) + 1;
    p = stop + 1;
  }
  *covered = c;
  *beyond = b;
  return 0;
}
