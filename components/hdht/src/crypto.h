// HyperDHT hashing helpers and namespace constants (see docs/protocol.md).

#ifndef HDHT_CRYPTO_H
#define HDHT_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cenc.h"

extern const uint8_t HDHT_NS_ANNOUNCE[32];
extern const uint8_t HDHT_NS_UNANNOUNCE[32];
extern const uint8_t HDHT_NS_PEER_HANDSHAKE[32];
extern const uint8_t HDHT_NS_PEER_HOLEPUNCH[32];
extern const uint8_t HDHT_SS_NS_INITIATOR[32];
extern const uint8_t HDHT_SS_NS_RESPONDER[32];

// BLAKE2b-256, unkeyed.
void
hdht_hash (uint8_t out[32], const void *data, size_t len);

// dht-rpc node id: BLAKE2b-256 of the 6-byte encoded address.
void
hdht_node_id (uint8_t out[32], const hdht_addr_t *addr);

// BLAKE2b-256(NS_PEER_HOLEPUNCH, key = handshake hash).
void
hdht_holepunch_secret (uint8_t out[32], const uint8_t handshake_hash[64]);

// SecretStream id for the given role.
void
hdht_stream_id (uint8_t out[32], const uint8_t handshake_hash[64], bool initiator);

// BLAKE2b-256(host as dotted text, key = secret) as used for dht-rpc tokens
// and holepunch tokens.
void
hdht_addr_token (uint8_t out[32], const hdht_addr_t *addr, const uint8_t secret[32]);

// Formats "a.b.c.d" into out (at least 16 bytes). Returns the length.
int
hdht_ip_to_string (const uint8_t ip[4], char *out);

#endif
