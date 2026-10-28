// Transport-agnostic @hyperswarm/secret-stream: in-band Noise handshake
// (XX by default, or IK), u24 framing, the stream id header and
// crypto_secretstream encryption. Feed it received bytes; it hands back bytes
// to transmit through on_send. Used for BLE, where there is no DHT handshake.

#ifndef HDHT_SECRET_STREAM_H
#define HDHT_SECRET_STREAM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <sodium.h>

#include "noise.h"

#define HDHT_SS_MAX_MESSAGE (16 * 1024)

typedef struct hdht_ss_s hdht_ss_t;

typedef void (*hdht_ss_send_cb)(hdht_ss_t *ss, const uint8_t *data, size_t len);
typedef void (*hdht_ss_open_cb)(hdht_ss_t *ss);
typedef void (*hdht_ss_data_cb)(hdht_ss_t *ss, const uint8_t *data, size_t len);
typedef void (*hdht_ss_error_cb)(hdht_ss_t *ss, int error);

enum {
  HDHT_SS_EHANDSHAKE = -20,
  HDHT_SS_EHEADER = -21,
  HDHT_SS_EDECRYPT = -22,
  HDHT_SS_ETOOBIG = -23,
  HDHT_SS_ENOMEM = -24,
  HDHT_SS_ESTATE = -25,
};

struct hdht_ss_s {
  bool initiator;
  bool handshaking;
  bool opened; // remote header verified
  bool failed;

  hdht_noise_t noise;
  uint8_t remote_public_key[32];
  uint8_t handshake_hash[64];
  uint8_t tx[32];
  uint8_t rx[32];
  crypto_secretstream_xchacha20poly1305_state push;
  crypto_secretstream_xchacha20poly1305_state pull;

  // frame parser
  uint8_t len_buf[3];
  uint8_t len_have;
  uint32_t msg_len;
  uint32_t msg_have;
  uint8_t *msg;

  hdht_ss_send_cb on_send;
  hdht_ss_open_cb on_open;
  hdht_ss_data_cb on_data;
  hdht_ss_error_cb on_error;
  void *data;
};

// remote_public_key is required for IK initiators, optional otherwise.
void
hdht_ss_init (hdht_ss_t *ss, bool initiator, hdht_noise_pattern_t pattern, const uint8_t public_key[32], const uint8_t secret_key[64], const uint8_t *remote_public_key);

// The initiator sends the first handshake message.
int
hdht_ss_start (hdht_ss_t *ss);

// Processes received transport bytes. Returns 0, or a negative error after
// which the stream is unusable (on_error has been called).
int
hdht_ss_feed (hdht_ss_t *ss, const uint8_t *data, size_t len);

// Encrypts one message and passes the frame to on_send.
int
hdht_ss_write (hdht_ss_t *ss, const uint8_t *data, size_t len);

void
hdht_ss_destroy (hdht_ss_t *ss);

#endif
