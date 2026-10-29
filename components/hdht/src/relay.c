// Blind relay client (blind-relay over protomux, as hyperdht's relayThrough).
//
// When two peers cannot holepunch, both connect to a relay node and ask it to
// pair their streams under a shared token. The relay creates one UDX stream
// per side and forwards packets between them. It cannot read them: the
// SecretStream keys stay with the two peers. Each peer then connects its own
// stream to the relay's address, with the id of the stream the relay made for
// it.
//
// Every SecretStream message to or from the relay is one protomux frame:
//   uint channel, uint type, payload
// channel 0 is control: type 1 opens a channel (uint localId, string protocol,
// buffer id), type 2 rejects, type 3 closes, type 0 is a batch
// (uint channel, then repeated buffer frames, a 0 length switching channel).
// On the blind-relay channel, type 0 is pair:
//   u8 flags (1 = initiator), fixed32 token, uint stream id, uint seq
// We send open and pair at once; the relay answers with its own open and,
// once the other peer has asked too, pair with the id of our stream.

#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "cenc.h"
#include "hdht.h"

#define RELAY_TIMEOUT_MS 15000
#define LOCAL_CHANNEL    1
#define PROTOCOL         "blind-relay"

struct hdht_relay_s {
  hdht_t *dht;
  hdht_stream_t stream; // to the relay node
  uint8_t token[32];
  bool initiator;
  uint32_t stream_id; // ours, to be paired
  hdht_relay_cb cb;   // once: paired or failed
  void *data;
  hdht_stream_t *bound; // our stream, connected through the relay
  uv_timer_t timer;
  uint8_t pending_closes;
};

static void
on_timer_close (uv_handle_t *handle) {
  hdht_relay_t *r = handle->data;
  if (--r->pending_closes == 0) free(r);
}

static void
report (hdht_relay_t *r, int status, uint32_t remote_id) {
  hdht_relay_cb cb = r->cb;
  r->cb = NULL;
  uv_timer_stop(&r->timer);
  if (cb) cb(r, status, remote_id, r->data);
  if (status != 0) hdht_stream_destroy(&r->stream, HDHT_STREAM_ECLOSED);
}

static void
on_timeout (uv_timer_t *timer) {
  report(timer->data, HDHT_CONNECT_ERELAY, 0);
}

static void
on_message (hdht_relay_t *r, uint64_t channel, uint64_t type, cdec_t *d) {
  if (channel == 0) {
    // the relay's open needs no answer; a reject or close of ours ends it
    if (type == 2 || type == 3) report(r, HDHT_CONNECT_ERELAY, 0);
    return;
  }
  if (type != 0 || r->cb == NULL) return; // only pair matters

  cdec_u8(d); // flags: the relay echoes our side
  const uint8_t *token = cdec_raw(d, 32);
  uint64_t id = cdec_uint(d);
  cdec_uint(d); // seq
  if (d->err || sodium_memcmp(token, r->token, 32) != 0) return;
  report(r, 0, (uint32_t) id);
}

static void
on_relay_data (hdht_stream_t *stream, const uint8_t *data, size_t len) {
  hdht_relay_t *r = stream->data;
  cdec_t d;
  cdec_init(&d, data, len);
  uint64_t channel = cdec_uint(&d);
  uint64_t type = cdec_uint(&d);
  if (d.err) return;
  if (channel != 0 || type != 0) {
    on_message(r, channel, type, &d);
    return;
  }

  // batch: uint channel, then length-prefixed messages (type, payload)
  channel = cdec_uint(&d);
  while (!d.err && cdec_more(&d)) {
    uint64_t n = cdec_uint(&d);
    if (n == 0) {
      channel = cdec_uint(&d);
      continue;
    }
    const uint8_t *msg = cdec_raw(&d, (size_t) n);
    if (d.err) return;
    cdec_t m;
    cdec_init(&m, msg, (size_t) n);
    uint64_t t = cdec_uint(&m);
    if (!m.err) on_message(r, channel, t, &m);
  }
}

static void
on_relay_open (hdht_stream_t *stream) {
  hdht_relay_t *r = stream->data;
  uint8_t buf[128];
  cenc_t e;

  // open the blind-relay channel; its id is our key, as the relay expects
  cenc_init(&e, buf, sizeof(buf));
  cenc_uint(&e, 0);
  cenc_uint(&e, 1);
  cenc_uint(&e, LOCAL_CHANNEL);
  cenc_buffer(&e, PROTOCOL, strlen(PROTOCOL));
  cenc_buffer(&e, r->dht->public_key, 32);
  if (e.err || hdht_stream_write(stream, buf, e.pos) != 0) {
    report(r, HDHT_CONNECT_ERELAY, 0);
    return;
  }

  cenc_init(&e, buf, sizeof(buf));
  cenc_uint(&e, LOCAL_CHANNEL);
  cenc_uint(&e, 0); // pair
  cenc_u8(&e, r->initiator ? 1 : 0);
  cenc_fixed32(&e, r->token);
  cenc_uint(&e, r->stream_id);
  cenc_uint(&e, 0);
  if (e.err || hdht_stream_write(stream, buf, e.pos) != 0) report(r, HDHT_CONNECT_ERELAY, 0);
}

static void
on_relay_close (hdht_stream_t *stream, int error) {
  hdht_relay_t *r = stream->data;
  if (r->cb) report(r, error ? error : HDHT_CONNECT_ERELAY, 0);

  // our stream cannot work without the relay
  hdht_stream_t *bound = r->bound;
  r->bound = NULL;
  if (bound) {
    bound->relay = NULL;
    hdht_stream_destroy(bound, HDHT_STREAM_ECLOSED);
  }

  uv_close((uv_handle_t *) &r->timer, on_timer_close);
}

int
hdht_relay_pair (hdht_t *dht, const uint8_t relay_public_key[32], const uint8_t token[32], bool initiator, uint32_t stream_id, hdht_relay_cb cb, void *data, hdht_relay_t **out) {
  hdht_relay_t *r = calloc(1, sizeof(hdht_relay_t));
  if (r == NULL) return HDHT_ENOMEM;
  r->dht = dht;
  memcpy(r->token, token, 32);
  r->initiator = initiator;
  r->stream_id = stream_id;
  r->cb = cb;
  r->data = data;
  r->pending_closes = 1;
  uv_timer_init(dht->loop, &r->timer);
  r->timer.data = r;
  uv_timer_start(&r->timer, on_timeout, RELAY_TIMEOUT_MS, 0);

  // later failures arrive through on_relay_close
  int err = hdht__connect(dht, &r->stream, relay_public_key, on_relay_open, on_relay_data, on_relay_close, r, true);
  if (err) {
    uv_timer_stop(&r->timer);
    uv_close((uv_handle_t *) &r->timer, on_timer_close);
    return err;
  }
  *out = r;
  return 0;
}

void
hdht_relay_cancel (hdht_relay_t *r) {
  r->cb = NULL;
  uv_timer_stop(&r->timer);
  hdht_stream_destroy(&r->stream, HDHT_STREAM_ECLOSED);
}

int
hdht_relay_connect (hdht_relay_t *r, hdht_stream_t *stream, uint32_t remote_id) {
  // the relayed stream shares the relay connection's socket, which must
  // outlive it: only the main socket does
  if (r->stream.socket == NULL || r->stream.owned_socket != NULL) return HDHT_STREAM_ECONNECT;
  int err = hdht_stream_connect(stream, r->stream.socket, remote_id, &r->stream.remote_addr);
  if (err) return err;
  r->bound = stream;
  stream->relay = r;
  return 0;
}

// the relayed stream is gone: so is the relay connection
void
hdht__relay_unbind (hdht_relay_t *r) {
  r->bound = NULL;
  hdht_stream_destroy(&r->stream, 0);
}
