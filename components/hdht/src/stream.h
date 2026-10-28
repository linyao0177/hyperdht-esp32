// Encrypted stream compatible with @hyperswarm/secret-stream, carried over a
// UDX stream and keyed by a finished Noise handshake.

#ifndef HDHT_STREAM_H
#define HDHT_STREAM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <sodium.h>
#include <udx.h>

#include "dht.h"

#define HDHT_STREAM_KEEPALIVE_MS 5000

typedef struct hdht_stream_s hdht_stream_t;

typedef void (*hdht_stream_open_cb)(hdht_stream_t *stream);
typedef void (*hdht_stream_data_cb)(hdht_stream_t *stream, const uint8_t *data, size_t len);
// Last callback; the stream memory may be released from here. error is 0 on a clean end.
typedef void (*hdht_stream_close_cb)(hdht_stream_t *stream, int error);
// Raw-stream firewall hook: the first packet arrived from `from` on `socket`.
// Return true after connecting the stream to accept it.
typedef bool (*hdht_stream_firewall_cb)(hdht_stream_t *stream, hdht_socket_t *socket, const hdht_addr_t *from);

enum {
  HDHT_STREAM_EOK = 0,
  HDHT_STREAM_EHANDSHAKE = -10, // bad header from the remote
  HDHT_STREAM_EDECRYPT = -11,
  HDHT_STREAM_ECLOSED = -12,
  HDHT_STREAM_ECONNECT = -13, // connection could not be established
  HDHT_STREAM_ENOMEM = -14,
};

struct hdht_stream_s {
  hdht_t *dht;
  udx_stream_t udx;
  uint32_t local_id;
  uint32_t remote_id;
  hdht_socket_t *socket;
  hdht_socket_t *owned_socket; // closed and freed with the stream (holepunched sockets)
  hdht_addr_t remote_addr;
  uint8_t pending_closes;
  bool free_on_close; // heap stream owned by the library (server side)

  bool initiator;
  bool keyed;
  bool connected; // udx connected and our header sent
  bool opened;    // remote header verified
  bool destroying;
  bool ended; // our side sent end
  bool udx_finalized;
  int error;

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

  uv_timer_t keepalive;
  uint64_t last_write;
  uint32_t keepalive_ms;

  hdht_stream_open_cb on_open;
  hdht_stream_data_cb on_data;
  hdht_stream_close_cb on_close;
  hdht_stream_firewall_cb on_firewall;
  void *data;  // user data
  void *owner; // connect/server state that created the stream

  struct {
    uint64_t bytes_in;
    uint64_t bytes_out;
  } stats;
};

// Prepares the UDX stream with a fresh random id so it can be announced in a
// handshake before the remote address is known.
int
hdht_stream_init (hdht_t *dht, hdht_stream_t *stream, bool initiator);

void
hdht_stream_set_keys (hdht_stream_t *stream, const uint8_t tx[32], const uint8_t rx[32], const uint8_t hash[64], const uint8_t remote_public_key[32]);

// Connects the UDX stream, sends our SecretStream header and starts reading.
int
hdht_stream_connect (hdht_stream_t *stream, hdht_socket_t *socket, uint32_t remote_id, const hdht_addr_t *addr);

// Encrypts and queues one message. Returns 0 or a negative error.
int
hdht_stream_write (hdht_stream_t *stream, const uint8_t *data, size_t len);

// Graceful end after queued writes.
int
hdht_stream_end (hdht_stream_t *stream);

void
hdht_stream_destroy (hdht_stream_t *stream, int error);

#endif
