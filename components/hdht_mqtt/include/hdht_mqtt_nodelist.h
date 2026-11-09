// hdht_mqtt node list: the staked nodes a device may use, as a quorum of the
// verifiers it trusts puts them out (packages/boat-registry lib/nodelist.js).
// Plain C over libsodium, also built on the desktop (test/test_nodelist.c).
// Included by hdht_mqtt.h.
//
// Every verifier node puts, in the HyperDHT record under its verify key,
//
//   {"v":1,"boat_nodes":"<base64 of the main part>"}
//
//   main  'BNL2' | chain id u64 BE | registry 20 bytes | epoch u64 BE
//         | n verifiers u8 (<= 10) | n x 32 bytes
//         | n nodes u16 BE | n pages u8 (<= 8) | n x 32-byte page hash
//   page  'BNP1' | n u8 (<= 28) | n x 32 bytes, an immutable record
//         (stored under its BLAKE2b-256 hash)
//
// the forwarding nodes active on the registry (most stake first, 28 to a
// page) and the verify keys of the verifiers with the most stake. A device
// takes the main part a quorum of its trusted verifiers (ceil(2n/3), or n
// when n <= 2) put out byte for byte, the newest epoch first, then reads one
// page, chosen by its own key so devices spread over the nodes. It needs no
// chain, and no single verifier can steer it; when the agreed list names
// other verifiers, it trusts those next.

#ifndef HDHT_MQTT_NODELIST_H
#define HDHT_MQTT_NODELIST_H

#include <stddef.h>
#include <stdint.h>

#define HDHT_MQTT_NODELIST_VERIFIERS 10
#define HDHT_MQTT_NODELIST_PAGE      28 // nodes in a page
#define HDHT_MQTT_NODELIST_PAGES     8

typedef struct {
  uint64_t chain_id;
  uint8_t registry[20];
  uint64_t epoch;
  uint8_t verifiers_len;
  uint8_t verifiers[HDHT_MQTT_NODELIST_VERIFIERS][32];
  uint16_t total;   // nodes on all pages
  uint8_t pages_len;
  uint8_t pages[HDHT_MQTT_NODELIST_PAGES][32]; // page hashes
  uint8_t page;     // the page nodes[] holds
  uint8_t nodes_len;
  uint8_t nodes[HDHT_MQTT_NODELIST_PAGE][32];
} hdht_mqtt_nodelist_t;

// The list in a record's value, into blob: its length, or -1.
int
hdht_mqtt_nodelist_from_record (const uint8_t *value, size_t len, uint8_t *blob, size_t cap);

// The main part: 0 with the list (no nodes yet), or -1.
int
hdht_mqtt_nodelist_decode (const uint8_t *blob, size_t len, hdht_mqtt_nodelist_t *out);

// Page `index` of the list, checked against its hash: 0 with list->nodes, or -1.
int
hdht_mqtt_nodelist_decode_page (const uint8_t *page, size_t len, uint8_t index, hdht_mqtt_nodelist_t *list);

size_t
hdht_mqtt_nodelist_quorum (size_t trusted);

// The main part a quorum of `trusted` verifiers agree on, from their blobs
// (NULL or length 0 when one had none): 0 with *out and *votes, or -1.
int
hdht_mqtt_nodelist_tally (const uint8_t *const *blobs, const size_t *lens, size_t n, size_t trusted, hdht_mqtt_nodelist_t *out, size_t *votes);

#endif
