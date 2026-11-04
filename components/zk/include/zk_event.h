// Camera events with a zero-knowledge proof (event_v2): a message is one JSON
// object such as
//
//   {"seq":3,"t":1793720788109,"ev":"person","conf":0.872,"box":[0,80,64,128],"zk":"<512 hex>"}
//
// and "zk" is a Groth16 proof that one of the registered devices signed the
// event, without saying which. Its public inputs are the root of the device
// registry (a Poseidon Merkle tree the verifier trusts) and M, the Poseidon
// hash of the event's fields, which the verifier computes itself. So a proof
// fits only the event it came with.
//
// Replays are not caught here: a copied message verifies again. The caller
// checks t against its clock and remembers the M values it accepted.

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "g16.h"

typedef struct {
  uint64_t seq;
  uint64_t t_ms;     // milliseconds since 1970
  uint8_t ev;        // 0 motion, 1 person, 2 motion_end
  uint16_t conf;     // permille: "conf" has at most 3 decimals
  uint16_t box[4];   // x, y, w, h
  uint8_t proof[G16_PROOF_LEN];
} zk_event_t;

// 0 parsed, 1 not an event (no "zk" key), -1 an event but malformed. Keys
// other than these six are skipped; each of the six must appear once.
int
zk_event_parse (zk_event_t *e, const char *json, size_t len);

// M = Poseidon(seq, t_ms, ev, conf, x | y << 16 | w << 32 | h << 48), 32 bytes big-endian
void
zk_event_hash (uint8_t m[32], const zk_event_t *e);

// the proof against [root, m]: 1 valid, 0 invalid, -1 malformed (see g16_verify)
int
zk_event_verify (const g16_vk_t *vk, const uint8_t root[32], const uint8_t m[32], const zk_event_t *e);

// a field element is below r, the group order (a root has to be)
int
zk_fr_ok (const uint8_t be[32]);
