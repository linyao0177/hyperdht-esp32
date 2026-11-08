// hdht_mqtt signed messages: plain C over libsodium, also built on the
// desktop (test/test_signed.c). Included by hdht_mqtt.h.

#ifndef HDHT_MQTT_SIGNED_H
#define HDHT_MQTT_SIGNED_H

#include <stddef.h>
#include <stdint.h>

// Signed messages
//
// A node checks who publishes, but a node is anyone's machine: it, or a
// bridge, could change a message or play an old one again. A signed message
// carries the publisher's own Ed25519 signature over the topic, a sequence
// number and the payload, so a subscriber checks it against the key in the
// topic (d/<key>/...) whatever node it came through, and refuses a sequence
// number it has seen. The layout, v1:
//
//   'S' 0x01 | seq: 8 bytes big-endian | signature: 64 bytes | payload
//
// signed over "hdht-mqtt-sig/1" 0x00 | topic | 0x00 | seq | payload.
// packages/boat-mqtt-node opens them (signed.js). Keep seq increasing across
// reboots: a boot counter in the high 32 bits and a message counter below.

#define HDHT_MQTT_SIGNED_OVERHEAD (2 + 8 + 64)

// Writes the signed message into out; returns its length, or -1 when out is
// too small or memory runs out.
int
hdht_mqtt_sign (const uint8_t secret_key[64], const char *topic, uint64_t seq, const uint8_t *payload, size_t len, uint8_t *out, size_t cap);

// Checks a signed message against public_key and topic. 0 with *seq and the
// payload (pointing into msg), or -1.
int
hdht_mqtt_open (const uint8_t public_key[32], const char *topic, const uint8_t *msg, size_t len, uint64_t *seq, const uint8_t **payload, size_t *payload_len);

#endif
