#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "secret_stream.h"

#define HEADER_LEN (32 + crypto_secretstream_xchacha20poly1305_HEADERBYTES) // 56
#define ABYTES     crypto_secretstream_xchacha20poly1305_ABYTES              // 17

static const uint8_t EMPTY[1] = {0};

static int
fail (hdht_ss_t *ss, int error) {
  if (!ss->failed) {
    ss->failed = true;
    if (ss->on_error) ss->on_error(ss, error);
  }
  return error;
}

// Sends one u24-framed message.
static int
send_frame (hdht_ss_t *ss, const uint8_t *data, size_t len) {
  uint8_t stack[128];
  uint8_t *f = len + 3 <= sizeof(stack) ? stack : malloc(len + 3);
  if (f == NULL) return HDHT_SS_ENOMEM;

  f[0] = (uint8_t) len;
  f[1] = (uint8_t) (len >> 8);
  f[2] = (uint8_t) (len >> 16);
  memcpy(f + 3, data, len);
  ss->on_send(ss, f, len + 3);

  if (f != stack) free(f);
  return 0;
}

static int
send_handshake (hdht_ss_t *ss) {
  uint8_t msg[160];
  int n = hdht_noise_send(&ss->noise, EMPTY, 0, msg, sizeof(msg));
  if (n < 0) return HDHT_SS_EHANDSHAKE;
  return send_frame(ss, msg, (size_t) n);
}

// Handshake done: derive keys and send our id + secretstream header.
static int
setup (hdht_ss_t *ss) {
  ss->handshaking = false;
  memcpy(ss->tx, ss->noise.tx, 32);
  memcpy(ss->rx, ss->noise.rx, 32);
  memcpy(ss->handshake_hash, ss->noise.hash, 64);
  memcpy(ss->remote_public_key, ss->noise.rs, 32);
  hdht_noise_clear(&ss->noise);

  uint8_t header[HEADER_LEN];
  hdht_stream_id(header, ss->handshake_hash, ss->initiator);
  crypto_secretstream_xchacha20poly1305_init_push(&ss->push, header + 32, ss->tx);
  return send_frame(ss, header, sizeof(header));
}

static int
on_message (hdht_ss_t *ss, uint8_t *msg, size_t len) {
  if (ss->handshaking) {
    uint8_t payload[64];
    if (hdht_noise_recv(&ss->noise, msg, len, payload, sizeof(payload)) < 0) return fail(ss, HDHT_SS_EHANDSHAKE);

    if (!ss->noise.complete) {
      int err = send_handshake(ss);
      if (err) return fail(ss, err);
    }
    // the initiator of XX completes by sending, so check again
    if (ss->noise.complete) {
      int err = setup(ss);
      if (err) return fail(ss, err);
    }
    return 0;
  }

  if (!ss->opened) {
    uint8_t expected[32];
    hdht_stream_id(expected, ss->handshake_hash, !ss->initiator);
    if (len != HEADER_LEN || sodium_memcmp(msg, expected, 32) != 0) return fail(ss, HDHT_SS_EHEADER);
    if (crypto_secretstream_xchacha20poly1305_init_pull(&ss->pull, msg + 32, ss->rx) != 0) return fail(ss, HDHT_SS_EHEADER);

    ss->opened = true;
    if (ss->on_open) ss->on_open(ss);
    return 0;
  }

  if (len < ABYTES) return fail(ss, HDHT_SS_EDECRYPT);

  unsigned long long plain_len;
  unsigned char tag;
  if (crypto_secretstream_xchacha20poly1305_pull(&ss->pull, msg, &plain_len, &tag, msg, len, NULL, 0) != 0) {
    return fail(ss, HDHT_SS_EDECRYPT);
  }

  if (plain_len > 0 && ss->on_data) ss->on_data(ss, msg, (size_t) plain_len);
  return 0;
}

void
hdht_ss_init (hdht_ss_t *ss, bool initiator, hdht_noise_pattern_t pattern, const uint8_t public_key[32], const uint8_t secret_key[64], const uint8_t *remote_public_key) {
  memset(ss, 0, sizeof(*ss));
  ss->initiator = initiator;
  ss->handshaking = true;
  // SecretStream uses an empty prologue
  hdht_noise_init_pattern(&ss->noise, pattern, initiator, public_key, secret_key, remote_public_key, EMPTY, 0);
}

int
hdht_ss_start (hdht_ss_t *ss) {
  if (!ss->initiator || ss->noise.step != 0) return HDHT_SS_ESTATE;
  int err = send_handshake(ss);
  return err ? fail(ss, err) : 0;
}

int
hdht_ss_feed (hdht_ss_t *ss, const uint8_t *data, size_t len) {
  while (len > 0) {
    if (ss->failed) return HDHT_SS_ESTATE;

    if (ss->len_have < 3) {
      ss->len_buf[ss->len_have++] = *data++;
      len--;
      if (ss->len_have < 3) continue;

      ss->msg_len = ss->len_buf[0] | (ss->len_buf[1] << 8) | ((uint32_t) ss->len_buf[2] << 16);
      ss->msg_have = 0;
      if (ss->msg_len > HDHT_SS_MAX_MESSAGE) return fail(ss, HDHT_SS_ETOOBIG);
      ss->msg = malloc(ss->msg_len ? ss->msg_len : 1);
      if (ss->msg == NULL) return fail(ss, HDHT_SS_ENOMEM);
    }

    size_t take = ss->msg_len - ss->msg_have;
    if (take > len) take = len;
    memcpy(ss->msg + ss->msg_have, data, take);
    ss->msg_have += (uint32_t) take;
    data += take;
    len -= take;

    if (ss->msg_have == ss->msg_len) {
      uint8_t *msg = ss->msg;
      ss->msg = NULL;
      ss->len_have = 0;
      int err = on_message(ss, msg, ss->msg_len);
      free(msg);
      if (err) return err;
    }
  }
  return 0;
}

int
hdht_ss_write (hdht_ss_t *ss, const uint8_t *data, size_t len) {
  if (ss->handshaking || ss->failed) return HDHT_SS_ESTATE;
  if (len + ABYTES > HDHT_SS_MAX_MESSAGE) return HDHT_SS_ETOOBIG;

  size_t frame_len = 3 + len + ABYTES;
  uint8_t stack[256];
  uint8_t *f = frame_len <= sizeof(stack) ? stack : malloc(frame_len);
  if (f == NULL) return HDHT_SS_ENOMEM;

  uint32_t n = (uint32_t) (len + ABYTES);
  f[0] = (uint8_t) n;
  f[1] = (uint8_t) (n >> 8);
  f[2] = (uint8_t) (n >> 16);
  crypto_secretstream_xchacha20poly1305_push(&ss->push, f + 3, NULL, data, len, NULL, 0, crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
  ss->on_send(ss, f, frame_len);

  if (f != stack) free(f);
  return 0;
}

void
hdht_ss_destroy (hdht_ss_t *ss) {
  free(ss->msg);
  ss->msg = NULL;
  hdht_noise_clear(&ss->noise);
  sodium_memzero(&ss->push, sizeof(ss->push));
  sodium_memzero(&ss->pull, sizeof(ss->pull));
  sodium_memzero(ss->tx, sizeof(ss->tx));
  sodium_memzero(ss->rx, sizeof(ss->rx));
  ss->failed = true;
}
