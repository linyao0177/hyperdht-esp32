#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "stream.h"

#define HEADER_LEN  (32 + crypto_secretstream_xchacha20poly1305_HEADERBYTES) // 56
#define ABYTES      crypto_secretstream_xchacha20poly1305_ABYTES              // 17
#define MAX_MESSAGE (64 * 1024)

// One allocation per write: header, then the udx write request, then the
// frame bytes. Offsets are rounded so the request stays aligned.
typedef struct {
  hdht_stream_t *stream;
  size_t len;
} write_block_t;

#define ALIGN8(n) (((n) + 7) & ~(size_t) 7)

static udx_stream_write_t *
block_req (write_block_t *b) {
  return (udx_stream_write_t *) ((uint8_t *) b + ALIGN8(sizeof(write_block_t)));
}

static uint8_t *
block_frame (write_block_t *b) {
  return (uint8_t *) block_req(b) + ALIGN8(udx_stream_write_sizeof(1));
}

static void
fail (hdht_stream_t *stream, int error) {
  hdht_stream_destroy(stream, error);
}

static void
on_write_ack (udx_stream_write_t *req, int status, int unordered) {
  (void) status;
  (void) unordered;
  free(req->data);
}

static write_block_t *
alloc_block (hdht_stream_t *stream, size_t frame_len) {
  write_block_t *b = malloc(ALIGN8(sizeof(write_block_t)) + ALIGN8(udx_stream_write_sizeof(1)) + frame_len);
  if (b == NULL) return NULL;
  b->stream = stream;
  b->len = frame_len;
  return b;
}

static int
write_block (hdht_stream_t *stream, write_block_t *b) {
  udx_stream_write_t *req = block_req(b);
  req->data = b;

  uv_buf_t buf = uv_buf_init((char *) block_frame(b), (unsigned int) b->len);
  int err = udx_stream_write(req, &stream->udx, &buf, 1, on_write_ack);
  if (err < 0) {
    free(b);
    return err;
  }

  stream->stats.bytes_out += b->len;
  stream->last_write = uv_now(stream->dht->loop);
  return 0;
}

static int
send_header (hdht_stream_t *stream) {
  write_block_t *b = alloc_block(stream, 3 + HEADER_LEN);
  if (b == NULL) return HDHT_STREAM_ENOMEM;

  uint8_t *f = block_frame(b);
  f[0] = HEADER_LEN;
  f[1] = 0;
  f[2] = 0;
  hdht_stream_id(f + 3, stream->handshake_hash, stream->initiator);
  crypto_secretstream_xchacha20poly1305_init_push(&stream->push, f + 3 + 32, stream->tx);

  return write_block(stream, b);
}

int
hdht_stream_write (hdht_stream_t *stream, const uint8_t *data, size_t len) {
  if (!stream->connected || stream->destroying || stream->ended) return HDHT_STREAM_ECLOSED;
  if (len + ABYTES > 0xffffff) return HDHT_STREAM_ENOMEM;

  size_t frame_len = 3 + len + ABYTES;
  write_block_t *b = alloc_block(stream, frame_len);
  if (b == NULL) return HDHT_STREAM_ENOMEM;

  uint8_t *f = block_frame(b);
  uint32_t n = (uint32_t) (len + ABYTES);
  f[0] = (uint8_t) n;
  f[1] = (uint8_t) (n >> 8);
  f[2] = (uint8_t) (n >> 16);
  crypto_secretstream_xchacha20poly1305_push(&stream->push, f + 3, NULL, data, len, NULL, 0, crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);

  return write_block(stream, b);
}

static void
on_keepalive (uv_timer_t *timer) {
  hdht_stream_t *stream = timer->data;
  if (!stream->connected || stream->destroying) return;

  uint64_t now = uv_now(stream->dht->loop);
  if (now - stream->last_write >= stream->keepalive_ms) hdht_stream_write(stream, NULL, 0);
}

// reading

static void
on_message (hdht_stream_t *stream, uint8_t *msg, size_t len) {
  if (!stream->opened) {
    uint8_t expected[32];
    hdht_stream_id(expected, stream->handshake_hash, !stream->initiator);

    if (len != HEADER_LEN || sodium_memcmp(msg, expected, 32) != 0) {
      fail(stream, HDHT_STREAM_EHANDSHAKE);
      return;
    }
    if (crypto_secretstream_xchacha20poly1305_init_pull(&stream->pull, msg + 32, stream->rx) != 0) {
      fail(stream, HDHT_STREAM_EHANDSHAKE);
      return;
    }

    stream->opened = true;
    if (stream->on_open) stream->on_open(stream);
    return;
  }

  if (len < ABYTES) {
    fail(stream, HDHT_STREAM_EDECRYPT);
    return;
  }

  unsigned long long plain_len;
  unsigned char tag;
  // decrypt in place: the plaintext is written over the ciphertext
  if (crypto_secretstream_xchacha20poly1305_pull(&stream->pull, msg, &plain_len, &tag, msg, len, NULL, 0) != 0) {
    fail(stream, HDHT_STREAM_EDECRYPT);
    return;
  }

  if (plain_len == 0) return; // keepalive
  if (stream->on_data) stream->on_data(stream, msg, (size_t) plain_len);
}

static void
on_read (udx_stream_t *udx, ssize_t read_len, const uv_buf_t *buf) {
  hdht_stream_t *stream = udx->data;

  if (read_len == UV_EOF) {
    // remote ended: end our side too and let udx close once both are acked
    if (!stream->ended && hdht_stream_end(stream) != 0) hdht_stream_destroy(stream, 0);
    return;
  }

  if (read_len < 0) {
    hdht_stream_destroy(stream, (int) read_len);
    return;
  }

  stream->stats.bytes_in += (uint64_t) read_len;
  const uint8_t *p = (const uint8_t *) buf->base;
  size_t left = (size_t) read_len;

  while (left > 0 && !stream->destroying) {
    if (stream->len_have < 3) {
      stream->len_buf[stream->len_have++] = *p++;
      left--;
      if (stream->len_have < 3) continue;

      stream->msg_len = stream->len_buf[0] | (stream->len_buf[1] << 8) | ((uint32_t) stream->len_buf[2] << 16);
      stream->msg_have = 0;
      if (stream->msg_len > MAX_MESSAGE) {
        fail(stream, HDHT_STREAM_EDECRYPT);
        return;
      }
      stream->msg = malloc(stream->msg_len ? stream->msg_len : 1);
      if (stream->msg == NULL) {
        fail(stream, HDHT_STREAM_ENOMEM);
        return;
      }
    }

    size_t take = stream->msg_len - stream->msg_have;
    if (take > left) take = left;
    memcpy(stream->msg + stream->msg_have, p, take);
    stream->msg_have += (uint32_t) take;
    p += take;
    left -= take;

    if (stream->msg_have == stream->msg_len) {
      uint8_t *msg = stream->msg;
      stream->msg = NULL;
      stream->len_have = 0;
      on_message(stream, msg, stream->msg_len);
      free(msg);
    }
  }
}

// lifecycle

static void
closed_one (hdht_stream_t *stream) {
  if (--stream->pending_closes > 0) return;
  if (stream->relay) {
    struct hdht_relay_s *relay = stream->relay;
    stream->relay = NULL;
    hdht__relay_unbind(relay);
  }
  if (stream->on_close) stream->on_close(stream, stream->error);
  if (stream->free_on_close) free(stream);
}

static void
on_keepalive_close (uv_handle_t *handle) {
  closed_one(handle->data);
}

static void
on_owned_socket_close (hdht_socket_t *socket) {
  hdht_stream_t *stream = socket->data;
  free(socket);
  closed_one(stream);
}

static void
on_udx_close (udx_stream_t *udx, int status) {
  hdht_stream_t *stream = udx->data;
  if (status < 0 && stream->error == 0) stream->error = status;
}

static void
on_udx_finalize (udx_stream_t *udx) {
  hdht_stream_t *stream = udx->data;
  stream->udx_finalized = true;
  stream->connected = false;
  free(stream->msg);
  stream->msg = NULL;
  sodium_memzero(&stream->push, sizeof(stream->push));
  sodium_memzero(&stream->pull, sizeof(stream->pull));

  stream->pending_closes = stream->owned_socket ? 2 : 1;
  if (stream->owned_socket) {
    stream->owned_socket->data = stream;
    hdht_socket_close(stream->owned_socket, on_owned_socket_close);
    stream->owned_socket = NULL;
  }

  uv_timer_stop(&stream->keepalive);
  uv_close((uv_handle_t *) &stream->keepalive, on_keepalive_close);
}

static int
on_udx_firewall (udx_stream_t *udx, udx_socket_t *socket, const struct sockaddr *from) {
  hdht_stream_t *stream = udx->data;
  if (stream->on_firewall == NULL || from->sa_family != AF_INET) return 1;

  hdht_addr_t addr;
  hdht_addr_from_sockaddr(&addr, from);
  return stream->on_firewall(stream, socket->data, &addr) ? 0 : 1;
}

int
hdht_stream_init (hdht_t *dht, hdht_stream_t *stream, bool initiator) {
  memset(stream, 0, sizeof(*stream));
  stream->dht = dht;
  stream->initiator = initiator;
  stream->keepalive_ms = HDHT_STREAM_KEEPALIVE_MS;

  int err;
  do {
    stream->local_id = randombytes_random();
    err = udx_stream_init(&dht->udx, &stream->udx, stream->local_id, on_udx_close, on_udx_finalize);
  } while (err == UV_EADDRINUSE);
  if (err) return err;

  stream->udx.data = stream;
  udx_stream_firewall(&stream->udx, on_udx_firewall);

  uv_timer_init(dht->loop, &stream->keepalive);
  stream->keepalive.data = stream;
  return 0;
}

void
hdht_stream_set_keys (hdht_stream_t *stream, const uint8_t tx[32], const uint8_t rx[32], const uint8_t hash[64], const uint8_t remote_public_key[32]) {
  memcpy(stream->tx, tx, 32);
  memcpy(stream->rx, rx, 32);
  memcpy(stream->handshake_hash, hash, 64);
  memcpy(stream->remote_public_key, remote_public_key, 32);
  stream->keyed = true;
}

int
hdht_stream_connect (hdht_stream_t *stream, hdht_socket_t *socket, uint32_t remote_id, const hdht_addr_t *addr) {
  if (stream->connected || stream->destroying || !stream->keyed) return HDHT_STREAM_ECLOSED;

  struct sockaddr_in sa;
  hdht_addr_to_sockaddr(addr, &sa);

  int err = udx_stream_connect(&stream->udx, &socket->udx, remote_id, (const struct sockaddr *) &sa);
  if (err) return err;

  stream->socket = socket;
  stream->remote_id = remote_id;
  stream->remote_addr = *addr;
  stream->connected = true;

  err = udx_stream_read_start(&stream->udx, on_read);
  if (err == 0) err = send_header(stream);
  if (err) return err;

  uv_timer_start(&stream->keepalive, on_keepalive, stream->keepalive_ms, stream->keepalive_ms);
  return 0;
}

int
hdht_stream_end (hdht_stream_t *stream) {
  if (!stream->connected || stream->destroying || stream->ended) return HDHT_STREAM_ECLOSED;
  stream->ended = true;
  uv_timer_stop(&stream->keepalive);

  write_block_t *b = alloc_block(stream, 0);
  if (b == NULL) return HDHT_STREAM_ENOMEM;
  udx_stream_write_t *req = block_req(b);
  req->data = b;
  uv_buf_t buf = uv_buf_init(NULL, 0);
  int err = udx_stream_write_end(req, &stream->udx, &buf, 1, on_write_ack);
  if (err < 0) free(b);
  return err < 0 ? err : 0;
}

void
hdht_stream_destroy (hdht_stream_t *stream, int error) {
  if (stream->destroying) return;
  stream->destroying = true;
  if (stream->error == 0) stream->error = error;
  uv_timer_stop(&stream->keepalive);

  // finalize runs from the udx stream either way
  udx_stream_destroy(&stream->udx);
}
