// Shared between main.c and anchor.c. Everything here runs on the hdht task.

#ifndef MER_H
#define MER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "boat_types.h"
#include "hdht.h"

extern hdht_t dht;
extern boat_keypair_t kp;

void
log_heap (const char *at);

// Copies the string value of "key" from a flat JSON object.
bool
json_str (const char *json, const char *key, char *out, size_t cap);

// Checks that a DID record belongs to public_key and that its eth_sig was made
// by its eth address; returns that address.
bool
verify_record (const uint8_t public_key[32], const uint8_t *value, size_t len, uint8_t eth[20]);

// anchor.c: finds open anchor nodes and submits signed readings to them
// (CONFIG_MER_ANCHOR_CONTRACT, CONFIG_MER_ANCHOR_NODES)

bool
anchor_enabled (void);

void
anchor_start (void); // once our DID record is published

void
anchor_tick (uint32_t ticks); // once a second

// signer.c: the device signs for its owner's wallet app (CONFIG_MER_OWNER_KEY)

void
signer_init (void);

bool
signer_is_owner (const uint8_t key[32]);

void
signer_serve (hdht_stream_t *stream);

// x402.c: the device pays an HTTP API with x402 (CONFIG_MER_X402_URL)

void
x402_start (void);

#endif
