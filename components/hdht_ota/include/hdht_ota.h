// Firmware updates over Holepunch, from a Hypercore.
//
// The publisher appends releases to a Hypercore (packages/boat-ota); any peer
// that holds the core serves it over HyperDHT. The device dials one, checks
// the signed tree head against the core key and the publisher's key it was
// built with, takes the latest release's manifest, and downloads the image
// block by block, each checked against the head (hc_proof.h), into the other
// OTA partition. When the image matches the manifest's SHA-256 it boots it.
// The peer serving it is not trusted: a changed block stops the update at
// that block.
//
// All on the hdht loop task: call hdht_ota_tick once a second.

#ifndef HDHT_OTA_H
#define HDHT_OTA_H

#include <stdbool.h>
#include <stdint.h>

#include "hdht.h"

typedef struct {
  uint8_t server[32];   // a peer serving the core (its HyperDHT key)
  uint8_t key[32];      // the core's key
  uint8_t signer[32];   // the publisher's Ed25519 public key
  const char *name;     // the product, as releases name it
  uint32_t interval_s;  // between checks; the first is 10 s after start
} hdht_ota_config_t;

int
hdht_ota_start (hdht_t *dht, const hdht_ota_config_t *config);

void
hdht_ota_tick (void);

// the image running now passed its first checks: keep it (with rollback on)
void
hdht_ota_confirm (void);

// newer than: compares dotted versions number by number ("0.10.0" > "0.9.1")
int
hdht_ota_version_cmp (const char *a, const char *b);

#endif
