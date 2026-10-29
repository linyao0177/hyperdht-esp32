// HyperDHT message encodings (hyperdht/lib/messages.js). Arrays are capped;
// longer arrays on the wire are decoded but truncated to the cap.

#ifndef HDHT_MESSAGES_H
#define HDHT_MESSAGES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cenc.h"

#define HDHT_MAX_ADDRESSES 4
#define HDHT_MAX_RELAYS    3

enum {
  HDHT_CMD_PEER_HANDSHAKE = 0,
  HDHT_CMD_PEER_HOLEPUNCH = 1,
  HDHT_CMD_FIND_PEER = 2,
  HDHT_CMD_LOOKUP = 3,
  HDHT_CMD_ANNOUNCE = 4,
  HDHT_CMD_UNANNOUNCE = 5,
  HDHT_CMD_MUTABLE_PUT = 6,
  HDHT_CMD_MUTABLE_GET = 7,
};

enum {
  HDHT_FIREWALL_UNKNOWN = 0,
  HDHT_FIREWALL_OPEN = 1,
  HDHT_FIREWALL_CONSISTENT = 2,
  HDHT_FIREWALL_RANDOM = 3,
};

enum {
  HDHT_ERROR_NONE = 0,
  HDHT_ERROR_ABORTED = 1,
  HDHT_ERROR_VERSION_MISMATCH = 2,
  HDHT_ERROR_TRY_LATER = 3,
  HDHT_ERROR_SEQ_REUSED = 16,
  HDHT_ERROR_SEQ_TOO_LOW = 17,
};

enum {
  HDHT_MODE_FROM_CLIENT = 0,
  HDHT_MODE_FROM_SERVER = 1,
  HDHT_MODE_FROM_RELAY = 2,
  HDHT_MODE_FROM_SECOND_RELAY = 3,
  HDHT_MODE_REPLY = 4,
};

typedef struct {
  hdht_addr_t relay_address;
  hdht_addr_t peer_address;
} hdht_relay_info_t;

typedef struct {
  uint32_t version;
  uint32_t error;
  uint32_t firewall;

  bool has_holepunch;
  uint32_t holepunch_id;
  hdht_relay_info_t relays[HDHT_MAX_RELAYS];
  uint8_t relays_len;

  hdht_addr_t addresses4[HDHT_MAX_ADDRESSES];
  uint8_t addresses4_len;

  bool has_udx;
  bool udx_reusable_socket;
  uint32_t udx_id;
  uint32_t udx_seq;

  bool has_secret_stream;

  bool has_relay_through;
  uint8_t relay_through_public_key[32];
  uint8_t relay_through_token[32];

  bool has_relay_addresses; // encoded even when empty, like the JS
  hdht_addr_t relay_addresses[HDHT_MAX_RELAYS];
  uint8_t relay_addresses_len;
} hdht_noise_payload_t;

typedef struct {
  uint32_t mode;
  const uint8_t *noise;
  size_t noise_len;
  bool has_peer_address;
  hdht_addr_t peer_address;
  bool has_relay_address;
  hdht_addr_t relay_address;
} hdht_handshake_msg_t;

typedef struct {
  uint32_t mode;
  uint32_t id;
  const uint8_t *payload;
  size_t payload_len;
  bool has_peer_address;
  hdht_addr_t peer_address;
} hdht_holepunch_msg_t;

typedef struct {
  uint32_t error;
  uint32_t firewall;
  uint32_t round;
  bool connected;
  bool punching;
  bool has_addresses;
  hdht_addr_t addresses[HDHT_MAX_ADDRESSES];
  uint8_t addresses_len;
  bool has_remote_address;
  hdht_addr_t remote_address;
  bool has_token;
  uint8_t token[32];
  bool has_remote_token;
  uint8_t remote_token[32];
} hdht_holepunch_payload_t;

typedef struct {
  uint8_t public_key[32];
  hdht_addr_t relay_addresses[HDHT_MAX_RELAYS];
  uint8_t relay_addresses_len;
} hdht_peer_t;

// All encoders return the encoded length or -1; decoders return 0 or -1.

int
hdht_noise_payload_encode (const hdht_noise_payload_t *m, uint8_t *out, size_t cap);

int
hdht_noise_payload_decode (hdht_noise_payload_t *m, const uint8_t *buf, size_t len);

int
hdht_handshake_encode (const hdht_handshake_msg_t *m, uint8_t *out, size_t cap);

int
hdht_handshake_decode (hdht_handshake_msg_t *m, const uint8_t *buf, size_t len);

int
hdht_holepunch_encode (const hdht_holepunch_msg_t *m, uint8_t *out, size_t cap);

int
hdht_holepunch_decode (hdht_holepunch_msg_t *m, const uint8_t *buf, size_t len);

int
hdht_holepunch_payload_encode (const hdht_holepunch_payload_t *m, uint8_t *out, size_t cap);

int
hdht_holepunch_payload_decode (hdht_holepunch_payload_t *m, const uint8_t *buf, size_t len);

// Encrypts a holepunch payload as nonce(24) || secretbox(payload).
int
hdht_holepunch_payload_seal (const hdht_holepunch_payload_t *m, const uint8_t secret[32], uint8_t *out, size_t cap);

int
hdht_holepunch_payload_open (hdht_holepunch_payload_t *m, const uint8_t secret[32], const uint8_t *buf, size_t len);

int
hdht_peer_encode (const hdht_peer_t *m, uint8_t *out, size_t cap);

int
hdht_peer_decode (hdht_peer_t *m, const uint8_t *buf, size_t len);

// announce{peer{public_key, []}, signature} signed for the given node.
// ns is HDHT_NS_ANNOUNCE or HDHT_NS_UNANNOUNCE.
int
hdht_announce_encode_signed (uint8_t *out, size_t cap, const uint8_t ns[32], const uint8_t target[32], const uint8_t node_id[32], const uint8_t token[32], const uint8_t public_key[32], const uint8_t secret_key[64]);

#endif
