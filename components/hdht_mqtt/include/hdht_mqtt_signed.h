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

// Receipts (packages/boat-mqtt-node/lib/receipts.js): a hop's signed word on
// which of a device's signed messages it got, one text line:
//
//   boat-receipt/1|<signer>|<device>|<count>|<bytes>|<ranges a-b;c-d>|<t ms>|<signature>
//
// the signature by signer over everything before the last '|'.

typedef struct {
  uint8_t signer[32];
  uint8_t device[32];
  uint64_t count, bytes; // signed messages and payload bytes the signer got
  uint64_t t;            // unix ms
  uint32_t ranges;
} hdht_mqtt_receipt_t;

// 0 when line is a receipt signed by signer, for device (NULL: any device).
int
hdht_mqtt_receipt_open (const uint8_t signer[32], const uint8_t *device, const char *line, size_t len, hdht_mqtt_receipt_t *out);

// Against what the device sent, sequence numbers lo..hi: *covered = how many
// of them the receipt names, *beyond = how many it names above hi (messages
// the device never sent: the signer's word against itself). Ranges below lo
// (earlier boots) are left out. Check the receipt with _open first.
int
hdht_mqtt_receipt_check (const char *line, size_t len, uint64_t lo, uint64_t hi, uint64_t *covered, uint64_t *beyond);

#endif
