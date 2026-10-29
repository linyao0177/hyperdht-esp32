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
//
// Public relay nodes announce under HDHT_RELAY_TOPIC (BLAKE2b-256 of
// "hdht-relay/1"). hdht_relay_find looks the topic up and probes candidates:
// a probe opens the blind-relay channel and stops when the relay opens its
// side, which shows the node is a relay we reach on our main socket.

#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "cenc.h"
#include "hdht.h"

#define RELAY_TIMEOUT_MS 15000
#define PROBE_TIMEOUT_MS 8000 // a relay opens its channel as soon as we connect
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
  bool probe;           // only check that the relay answers
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
    if (type == 1 && r->probe && r->cb) {
      // usable only over the main socket, as hdht_relay_connect needs
      bool direct = r->stream.owned_socket == NULL;
      report(r, direct ? 0 : HDHT_CONNECT_ERELAY, 0);
      hdht_stream_destroy(&r->stream, HDHT_STREAM_ECLOSED);
    }
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
  if (r->probe) return;

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

static int
start (hdht_t *dht, const uint8_t relay_public_key[32], bool probe, const uint8_t token[32], bool initiator, uint32_t stream_id, hdht_relay_cb cb, void *data, hdht_relay_t **out) {
  hdht_relay_t *r = calloc(1, sizeof(hdht_relay_t));
  if (r == NULL) return HDHT_ENOMEM;
  r->dht = dht;
  r->probe = probe;
  if (token) memcpy(r->token, token, 32);
  r->initiator = initiator;
  r->stream_id = stream_id;
  r->cb = cb;
  r->data = data;
  r->pending_closes = 1;
  uv_timer_init(dht->loop, &r->timer);
  r->timer.data = r;
  uv_timer_start(&r->timer, on_timeout, probe ? PROBE_TIMEOUT_MS : RELAY_TIMEOUT_MS, 0);

  // later failures arrive through on_relay_close
  int err = hdht__connect(dht, &r->stream, relay_public_key, on_relay_open, on_relay_data, on_relay_close, r, true);
  if (err) {
    uv_timer_stop(&r->timer);
    uv_close((uv_handle_t *) &r->timer, on_timer_close);
    return err;
  }
  if (out) *out = r;
  return 0;
}

int
hdht_relay_pair (hdht_t *dht, const uint8_t relay_public_key[32], const uint8_t token[32], bool initiator, uint32_t stream_id, hdht_relay_cb cb, void *data, hdht_relay_t **out) {
  return start(dht, relay_public_key, false, token, initiator, stream_id, cb, data, out);
}

int
hdht_relay_probe (hdht_t *dht, const uint8_t relay_public_key[32], hdht_relay_cb cb, void *data, hdht_relay_t **out) {
  return start(dht, relay_public_key, true, NULL, false, 0, cb, data, out);
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

// finding a public relay

void
hdht_relay_topic (uint8_t out[32]) {
  static const char name[] = "hdht-relay/1";
  crypto_generichash(out, 32, (const uint8_t *) name, sizeof(name) - 1, NULL, 0);
}

typedef struct {
  hdht_t *dht;
  uint8_t candidates[HDHT_LOOKUP_MAX_PEERS][32];
  size_t len, next;
  uint8_t avoid[32];
  bool has_avoid;
  hdht_relay_find_cb cb;
  void *data;
} find_op_t;

static void
find_done (find_op_t *op, int status, const uint8_t *key) {
  op->cb(op->dht, status, key, op->data);
  free(op);
}

static void on_probe (hdht_relay_t *r, int status, uint32_t remote_id, void *data);

static void
probe_next (find_op_t *op) {
  while (op->next < op->len) {
    if (hdht_relay_probe(op->dht, op->candidates[op->next++], on_probe, op, NULL) == 0) return;
  }
  find_done(op, HDHT_CONNECT_ERELAY, NULL);
}

static void
on_probe (hdht_relay_t *r, int status, uint32_t remote_id, void *data) {
  (void) r;
  (void) remote_id;
  find_op_t *op = data;
  if (status == 0) find_done(op, 0, op->candidates[op->next - 1]);
  else probe_next(op);
}

static void
on_find_lookup (hdht_t *dht, int status, const uint8_t (*peers)[32], size_t len, void *data) {
  (void) status;
  find_op_t *op = data;
  for (size_t i = 0; i < len; i++) {
    if (memcmp(peers[i], dht->public_key, 32) == 0) continue;
    if (op->has_avoid && memcmp(peers[i], op->avoid, 32) == 0) continue;
    memcpy(op->candidates[op->len++], peers[i], 32);
  }
  // in random order, so devices spread over the relays
  for (size_t i = op->len; i > 1; i--) {
    size_t j = randombytes_uniform((uint32_t) i);
    uint8_t tmp[32];
    memcpy(tmp, op->candidates[i - 1], 32);
    memcpy(op->candidates[i - 1], op->candidates[j], 32);
    memcpy(op->candidates[j], tmp, 32);
  }
  probe_next(op);
}

int
hdht_relay_find (hdht_t *dht, const uint8_t avoid[32], hdht_relay_find_cb cb, void *data) {
  find_op_t *op = calloc(1, sizeof(find_op_t));
  if (op == NULL) return HDHT_ENOMEM;
  op->dht = dht;
  op->cb = cb;
  op->data = data;
  if (avoid) {
    memcpy(op->avoid, avoid, 32);
    op->has_avoid = true;
  }
  uint8_t topic[32];
  hdht_relay_topic(topic);
  int err = hdht_lookup(dht, topic, on_find_lookup, op);
  if (err) free(op);
  return err;
}
