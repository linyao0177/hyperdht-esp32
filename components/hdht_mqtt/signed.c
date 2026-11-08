// Signed messages (include/hdht_mqtt_signed.h).

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

