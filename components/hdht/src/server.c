// Server (hyperdht/lib/server.js + announcer.js): announce our key to the
// closest nodes, answer relayed Noise handshakes, and holepunch with clients,
// or pair with them at a blind relay when either side asks (relay.c).
// Holepunching runs alongside the relay; when it gets through after the
// relay, the stream moves to the direct path.

#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "crypto.h"
#include "hdht.h"

#define ANNOUNCE_PING_MS      3000
#define ANNOUNCE_REFRESH_PING 100 // ~5 min of 3 s ping cycles
#define MIN_ACTIVE_RELAYS     3
#define HANDSHAKE_TIMEOUT_MS  10000
#define HANDSHAKE_CLEAR_MS    10000
#define UPGRADE_WAIT_MS       40000 // a relayed stream may move to a direct path this long

struct hdht_server_handshake_s {
  hdht_server_t *server;
  uint8_t id; // index in server->handshakes, sent as holepunch id

  uint8_t msg1_hash[32]; // dedupes retransmitted handshakes
  uint8_t reply[256];
  size_t reply_len;
  bool reply_from_puncher;
  int error;

  hdht_noise_payload_t remote;
  hdht_addr_t client_addr;
  hdht_stream_t *stream; // until connected, or until a relayed one moves
  hdht_puncher_t *puncher;
  uint8_t holepunch_secret[32];
  uint8_t local_secret[32];
  bool has_secret;
  uint32_t round;

  // blind relay, with holepunching alongside unless relay_only
  bool relaying;
  hdht_relay_t *relay; // pairing, until it reports
  uint8_t relay_token[32];
  bool upgrading; // stream runs through the relay; holepunching goes on

  // a holepunch request waiting for NAT analysis
  bool deferred;
  hdht_incoming_t deferred_req;
  hdht_addr_t deferred_peer;
  hdht_holepunch_payload_t deferred_payload;

  uv_timer_t timer; // prepunch timeout, then delayed clear
  bool clearing;
  bool closed;
};

static hdht_server_t *
find_server (hdht_t *dht, const uint8_t target[32]) {
  for (hdht_server_t *s = dht->servers; s != NULL; s = s->next) {
    if (s->listening && !s->closing && memcmp(s->target, target, 32) == 0) return s;
  }
  return NULL;
}

static bool
is_server_relay (hdht_server_t *s, const hdht_addr_t *addr) {
  for (int i = 0; i < s->announced_len; i++) {
    if (hdht_addr_eq(&s->announced[i].from, addr)) return true;
  }
  return false;
}

// handshake state

// Drops the stream of a handshake that never connected. A relayed stream
// stays on the relay.
static void
destroy_pending_stream (hdht_server_handshake_t *h) {
  hdht_stream_t *stream = h->stream;
  if (stream == NULL) return;
  h->stream = NULL;
  stream->owner = NULL;
  stream->on_firewall = NULL;
  stream->on_finalize = NULL;
  if (h->upgrading) h->upgrading = false;
  else hdht_stream_destroy(stream, HDHT_STREAM_ECONNECT);
}

static void
on_handshake_timer_close (uv_handle_t *handle) {
  hdht_server_handshake_t *h = handle->data;
  free(h);
}

static void
clear_now (hdht_server_handshake_t *h) {
  if (h->closed) return;
  h->closed = true;

  hdht_server_t *s = h->server;
  if (s->handshakes[h->id] == h) s->handshakes[h->id] = NULL;

  if (h->puncher) hdht_puncher_destroy(h->puncher);
  h->puncher = NULL;
  if (h->relay) hdht_relay_cancel(h->relay);
  h->relay = NULL;
  destroy_pending_stream(h);
  sodium_memzero(h->holepunch_secret, sizeof(h->holepunch_secret));

  uv_timer_stop(&h->timer);
  uv_close((uv_handle_t *) &h->timer, on_handshake_timer_close);
}

static void
on_clear_timer (uv_timer_t *timer) {
  clear_now(timer->data);
}

// Keeps the state around for a while so retransmitted handshakes get the same reply.
static void
clear_later (hdht_server_handshake_t *h) {
  if (h->clearing || h->closed) return;
  h->clearing = true;
  uv_timer_start(&h->timer, on_clear_timer, HANDSHAKE_CLEAR_MS, 0);
}

static void
abort_handshake (hdht_server_handshake_t *h) {
  if (h->puncher) hdht_puncher_destroy(h->puncher);
  h->puncher = NULL;
  if (h->relay) hdht_relay_cancel(h->relay);
  h->relay = NULL;
  destroy_pending_stream(h);
  clear_later(h);
}

// Holepunching is over without a direct path. A relayed handshake keeps its
// relay, still pairing or carrying the stream, and its puncher socket, which
// the client may already have got through to.
static void
punch_over (hdht_server_handshake_t *h) {
  if (!h->relaying) {
    abort_handshake(h);
    return;
  }
  if (h->puncher) hdht_puncher_stop(h->puncher);
  if (!h->upgrading) uv_timer_stop(&h->timer); // the relay times out by itself
}

static void
on_upgrade_timeout (uv_timer_t *timer) {
  abort_handshake(timer->data);
}

static void
on_prepunch_timeout (uv_timer_t *timer) {
  punch_over(timer->data);
}

// The client reached our stream: connect it there (server.js onsocket). A
// stream already on the relay moves to the puncher socket instead.
static void
on_socket (hdht_server_handshake_t *h, hdht_socket_t *socket, const hdht_addr_t *from) {
  hdht_stream_t *stream = h->stream;
  if (stream == NULL) return;
  h->stream = NULL;

  hdht_server_t *s = h->server;
  hdht_socket_t *punched = h->puncher && socket == h->puncher->socket ? hdht_puncher_release_socket(h->puncher) : NULL;
  if (h->puncher) hdht_puncher_destroy(h->puncher);
  h->puncher = NULL;
  if (h->relay) hdht_relay_cancel(h->relay); // the direct path won
  h->relay = NULL;

  stream->owner = NULL;
  stream->on_firewall = NULL;
  stream->on_finalize = NULL;

  uv_timer_stop(&h->timer);
  clear_later(h);

  if (h->upgrading) {
    h->upgrading = false;
    if (punched) hdht_stream_upgrade(stream, punched, h->remote.udx_id, from);
    return;
  }
  stream->owned_socket = punched;

  if (hdht_stream_connect(stream, socket, h->remote.udx_id, from) != 0) {
    hdht_stream_destroy(stream, HDHT_STREAM_ECONNECT);
    return;
  }

  s->stats.connections++;
  if (s->on_connection) s->on_connection(s, stream);
}

static bool
on_stream_firewall (hdht_stream_t *stream, hdht_socket_t *socket, const hdht_addr_t *from) {
  hdht_server_handshake_t *h = stream->owner;
  if (h == NULL || socket == NULL) return false;
  // with a relay, only the puncher socket brings the client directly; the
  // relay forwards before it tells us our stream id (UDX resends)
  if (h->relaying && !(h->puncher && socket == h->puncher->socket)) return false;
  on_socket(h, socket, from);
  return stream->connected;
}

// A relayed stream closed while holepunching went on.
static void
on_stream_finalize (hdht_stream_t *stream) {
  hdht_server_handshake_t *h = stream->owner;
  if (h) abort_handshake(h);
}

static void
on_puncher_abort (hdht_puncher_t *p) {
  hdht_server_handshake_t *h = p->data;
  if (h->relaying) {
    punch_over(h);
    return;
  }
  h->puncher = NULL;
  hdht_puncher_destroy(p);
  abort_handshake(h);
}

static void
send_holepunch_reply (hdht_server_handshake_t *h, const hdht_incoming_t *req, const hdht_addr_t *peer_addr, const hdht_holepunch_payload_t *payload, hdht_socket_t *socket);

static void
answer_holepunch (hdht_server_handshake_t *h, const hdht_incoming_t *req, const hdht_addr_t *peer_addr, const hdht_holepunch_payload_t *remote);

static void
on_puncher_analyzed (hdht_puncher_t *p) {
  hdht_server_handshake_t *h = p->data;
  if (!h->deferred) return;
  h->deferred = false;
  answer_holepunch(h, &h->deferred_req, &h->deferred_peer, &h->deferred_payload);
}

static bool
setup_puncher (hdht_server_handshake_t *h) {
  if (h->puncher) return true;
  h->puncher = hdht_puncher_create(h->server->dht, false, h->remote.firewall, h);
  if (h->puncher == NULL) return false;
  h->puncher->on_abort = on_puncher_abort;
  h->puncher->on_analyzed = on_puncher_analyzed;
  return true;
}

// PEER_HANDSHAKE

// blind relay (server.js _relayConnection)

static void
on_relay_paired (hdht_relay_t *r, int status, uint32_t remote_id, void *data) {
  hdht_server_handshake_t *h = data;
  h->relay = NULL;
  hdht_stream_t *stream = h->stream;
  if (status == 0 && (stream == NULL || hdht_relay_connect(r, stream, remote_id) != 0)) {
    hdht_relay_cancel(r);
    status = HDHT_CONNECT_ERELAY;
  }
  if (status != 0) {
    // holepunching may still get through
    if (stream && h->puncher) {
      h->relaying = false;
      if (!h->puncher->punching) uv_timer_start(&h->timer, on_prepunch_timeout, HANDSHAKE_TIMEOUT_MS, 0);
    } else {
      abort_handshake(h);
    }
    return;
  }

  if (h->puncher) {
    // holepunching goes on and may still move the stream
    h->upgrading = true;
    stream->on_finalize = on_stream_finalize;
    uv_timer_start(&h->timer, on_upgrade_timeout, UPGRADE_WAIT_MS, 0);
  } else {
    h->stream = NULL;
    stream->owner = NULL;
    stream->on_firewall = NULL;
    uv_timer_stop(&h->timer);
    clear_later(h);
  }

  hdht_server_t *s = h->server;
  s->stats.connections++;
  if (s->on_connection) s->on_connection(s, stream);
}

// Our relay when we have one, as server.js: then we are the initiator.
static bool
start_relay (hdht_server_handshake_t *h) {
  hdht_t *dht = h->server->dht;
  bool mine = dht->has_relay;
  const uint8_t *key = mine ? dht->relay : h->remote.relay_through_public_key;
  const uint8_t *token = mine ? h->relay_token : h->remote.relay_through_token;
  return hdht_relay_pair(dht, key, token, mine, h->stream->local_id, on_relay_paired, h, &h->relay) == 0;
}

static hdht_server_handshake_t *
add_handshake (hdht_server_t *s, const hdht_incoming_t *req, const hdht_handshake_msg_t *hs, const uint8_t msg1_hash[32]) {
  hdht_t *dht = s->dht;

  int id = -1;
  for (int i = 0; i < HDHT_SERVER_MAX_HANDSHAKES; i++) {
    if (s->handshakes[i] == NULL) {
      id = i;
      break;
    }
  }
  if (id < 0) return NULL; // busy: the client retries or times out

  hdht_server_handshake_t *h = calloc(1, sizeof(hdht_server_handshake_t));
  if (h == NULL) return NULL;
  h->server = s;
  h->id = (uint8_t) id;
  memcpy(h->msg1_hash, msg1_hash, 32);
  uv_timer_init(dht->loop, &h->timer);
  h->timer.data = h;
  s->handshakes[id] = h;
  s->stats.handshakes++;

  bool direct = !hs->has_peer_address;
  h->client_addr = direct ? req->from : hs->peer_address;

  hdht_noise_t noise;
  hdht_noise_init(&noise, false, s->public_key, s->secret_key, NULL, HDHT_NS_PEER_HANDSHAKE);

  uint8_t plain[256];
  int n = hdht_noise_recv(&noise, hs->noise, hs->noise_len, plain, sizeof(plain));
  if (n < 0 || hdht_noise_payload_decode(&h->remote, plain, (size_t) n) != 0) {
    hdht_noise_clear(&noise);
    clear_later(h);
    return h; // no reply
  }

  uint32_t error = h->remote.version != 1 ? HDHT_ERROR_VERSION_MISMATCH : h->remote.has_udx ? HDHT_ERROR_NONE : HDHT_ERROR_ABORTED;

  if (error == HDHT_ERROR_NONE) {
    h->stream = calloc(1, sizeof(hdht_stream_t));
    if (h->stream == NULL || hdht_stream_init(dht, h->stream, false) != 0) {
      free(h->stream);
      h->stream = NULL;
      error = HDHT_ERROR_ABORTED;
    } else {
      h->stream->free_on_close = true;
      h->stream->owner = h;
      h->stream->on_firewall = on_stream_firewall;
    }
  }

  h->relaying = error == HDHT_ERROR_NONE && (dht->has_relay || h->remote.has_relay_through);

  hdht_noise_payload_t payload = {0};
  payload.version = 1;
  payload.error = error;
  payload.firewall = HDHT_FIREWALL_UNKNOWN; // we never have a stable public address
  // holepunch info even when relaying: without it the client would try our
  // public address directly instead of waiting for the relay
  payload.has_holepunch = true;
  payload.holepunch_id = h->id;
  payload.relays_len = s->relays_len;
  memcpy(payload.relays, s->relays, sizeof(payload.relays));
  if (h->relaying && dht->has_relay) {
    payload.has_relay_through = true;
    memcpy(payload.relay_through_public_key, dht->relay, 32);
    randombytes_buf(h->relay_token, 32);
    memcpy(payload.relay_through_token, h->relay_token, 32);
  }
  // no LAN addresses when relaying, so the client tries no LAN shortcut
  for (int i = 0; !h->relaying && i < dht->local_addresses_len && payload.addresses4_len < HDHT_MAX_ADDRESSES; i++) {
    payload.addresses4[payload.addresses4_len] = dht->local_addresses[i];
    payload.addresses4[payload.addresses4_len++].port = dht->socket.local_port;
  }
  payload.has_udx = true;
  payload.udx_id = h->stream ? h->stream->local_id : 0;
  payload.has_secret_stream = true;
  if (s->announced_len > 0) {
    payload.has_relay_addresses = true;
    for (int i = 0; i < s->announced_len && i < HDHT_MAX_RELAYS; i++) payload.relay_addresses[payload.relay_addresses_len++] = s->announced[i].from;
  }

  n = hdht_noise_payload_encode(&payload, plain, sizeof(plain));
  n = n < 0 ? -1 : hdht_noise_send(&noise, plain, (size_t) n, h->reply, sizeof(h->reply));
  if (n < 0) {
    hdht_noise_clear(&noise);
    abort_handshake(h);
    return h;
  }
  h->reply_len = (size_t) n;

  if (h->stream) hdht_stream_set_keys(h->stream, noise.tx, noise.rx, noise.hash, noise.rs);
  hdht_holepunch_secret(h->holepunch_secret, noise.hash);
  hdht_noise_clear(&noise);

  if (error != HDHT_ERROR_NONE) {
    abort_handshake(h);
    return h;
  }

  // the client is reachable, or talked to us directly: connect right away
  if (h->remote.firewall == HDHT_FIREWALL_OPEN || direct) {
    on_socket(h, direct ? req->socket : &dht->socket, &h->client_addr);
    return h;
  }

  h->has_secret = true;
  randombytes_buf(h->local_secret, sizeof(h->local_secret));

  if (h->relaying && !start_relay(h)) {
    abort_handshake(h);
    return h;
  }
  // the relay times out by itself
  if (h->relaying && dht->relay_only) return h;

  // same public IP: the client will try our LAN address, keep replying from the main socket
  bool same_ip = memcmp(h->client_addr.ip, req->to.ip, 4) == 0;
  bool client_lan = false;
  for (int i = 0; i < h->remote.addresses4_len; i++) client_lan = client_lan || hdht_ip_is_private(h->remote.addresses4[i].ip);

  if (!setup_puncher(h)) {
    punch_over(h);
    return h;
  }
  h->reply_from_puncher = !(same_ip && client_lan && dht->local_addresses_len > 0);
  uv_timer_start(&h->timer, on_prepunch_timeout, HANDSHAKE_TIMEOUT_MS, 0);
  return h;
}

static void
reply_handshake (hdht_server_handshake_t *h, const hdht_incoming_t *req, const hdht_handshake_msg_t *hs) {
  if (h->reply_len == 0) return;

  hdht_socket_t *socket = h->reply_from_puncher && h->puncher ? h->puncher->socket : NULL;
  hdht_handshake_msg_t out = {.noise = h->reply, .noise_len = h->reply_len};
  uint8_t value[320];
  int n;

  switch (hs->mode) {
  case HDHT_MODE_FROM_CLIENT:
    out.mode = HDHT_MODE_REPLY;
    n = hdht_handshake_encode(&out, value, sizeof(value));
    if (n > 0) hdht_reply(h->server->dht, req, socket, &req->from, 0, value, (size_t) n, false);
    return;

  case HDHT_MODE_FROM_RELAY:
    out.mode = HDHT_MODE_FROM_SERVER;
    out.has_peer_address = hs->has_peer_address;
    out.peer_address = hs->peer_address;
    n = hdht_handshake_encode(&out, value, sizeof(value));
    if (n > 0) hdht_relay(h->server->dht, req, socket, &req->from, value, (size_t) n);
    return;

  case HDHT_MODE_FROM_SECOND_RELAY:
    if (!hs->has_relay_address) return;
    out.mode = HDHT_MODE_FROM_SERVER;
    out.has_peer_address = hs->has_peer_address;
    out.peer_address = hs->peer_address;
    n = hdht_handshake_encode(&out, value, sizeof(value));
    if (n > 0) hdht_relay(h->server->dht, req, socket, &hs->relay_address, value, (size_t) n);
    return;
  }
}

static void
on_peer_handshake (hdht_server_t *s, const hdht_incoming_t *req) {
  hdht_handshake_msg_t hs;
  if (req->value == NULL || hdht_handshake_decode(&hs, req->value, req->value_len) != 0 || hs.noise_len == 0) return;
  if (hs.mode != HDHT_MODE_FROM_CLIENT && hs.mode != HDHT_MODE_FROM_RELAY && hs.mode != HDHT_MODE_FROM_SECOND_RELAY) return;

  uint8_t key[32];
  hdht_hash(key, hs.noise, hs.noise_len);

  hdht_server_handshake_t *h = NULL;
  for (int i = 0; i < HDHT_SERVER_MAX_HANDSHAKES; i++) {
    if (s->handshakes[i] && memcmp(s->handshakes[i]->msg1_hash, key, 32) == 0) h = s->handshakes[i];
  }
  if (h == NULL) h = add_handshake(s, req, &hs, key);
  if (h == NULL || h->closed) return;

  reply_handshake(h, req, &hs);
}

// PEER_HOLEPUNCH

static void
send_holepunch_reply (hdht_server_handshake_t *h, const hdht_incoming_t *req, const hdht_addr_t *peer_addr, const hdht_holepunch_payload_t *payload, hdht_socket_t *socket) {
  uint8_t sealed[256];
  int sealed_len = hdht_holepunch_payload_seal(payload, h->holepunch_secret, sealed, sizeof(sealed));
  if (sealed_len < 0) return;

  hdht_holepunch_msg_t msg = {
    .mode = HDHT_MODE_FROM_SERVER,
    .id = 0,
    .payload = sealed,
    .payload_len = (size_t) sealed_len,
    .has_peer_address = true,
    .peer_address = *peer_addr,
  };
  uint8_t value[320];
  int n = hdht_holepunch_encode(&msg, value, sizeof(value));
  if (n > 0) hdht_relay(h->server->dht, req, socket, &req->from, value, (size_t) n);
}

static void
abort_holepunch (hdht_server_handshake_t *h, const hdht_incoming_t *req, const hdht_addr_t *peer_addr, uint32_t error) {
  hdht_holepunch_payload_t p = {0};
  p.error = error;
  p.round = h->round;
  send_holepunch_reply(h, req, peer_addr, &p, &h->server->dht->socket);
  punch_over(h);
}

static bool
nat_has_address (const hdht_nat_t *nat, const hdht_addr_t *addr) {
  if (!nat->has_addresses) return false;
  for (int i = 0; i < nat->addresses_len; i++) {
    if (hdht_addr_eq(&nat->addresses[i], addr)) return true;
  }
  return false;
}

// server.js _onpeerholepunch after the NAT analysis has a result.
static void
answer_holepunch (hdht_server_handshake_t *h, const hdht_incoming_t *req, const hdht_addr_t *peer_addr, const hdht_holepunch_payload_t *remote) {
  hdht_puncher_t *p = h->puncher;
  if (p == NULL || p->destroyed) return;

  if (!p->remote_punching && hdht_puncher_unstable(p)) {
    abort_holepunch(h, req, peer_addr, HDHT_ERROR_ABORTED);
    return;
  }

  // fast mode: the client opened a session towards an address we see as ours
  bool consistent = p->nat.firewall == HDHT_FIREWALL_CONSISTENT || p->nat.firewall == HDHT_FIREWALL_OPEN;
  if (consistent && remote->has_remote_address && nat_has_address(&p->nat, &remote->remote_address)) {
    hdht_puncher_probe(p, peer_addr, false);
  }

  if (p->remote_punching) {
    if (!h->upgrading) uv_timer_stop(&h->timer); // past the prepunch stage
    if (!hdht_puncher_punch(p)) {
      abort_holepunch(h, req, peer_addr, HDHT_ERROR_ABORTED);
      return;
    }
    h->server->stats.punches++;
  }

  if (p->nat.firewall != HDHT_FIREWALL_UNKNOWN) p->nat.frozen = true;

  bool from_relay = is_server_relay(h->server, &req->from);
  hdht_holepunch_payload_t out = {0};
  out.firewall = p->nat.firewall;
  out.round = h->round;
  out.connected = p->connected;
  out.punching = p->punching;
  out.has_addresses = p->nat.has_addresses;
  out.addresses_len = p->nat.addresses_len;
  memcpy(out.addresses, p->nat.addresses, sizeof(out.addresses));
  if (from_relay) {
    out.has_token = true;
    hdht_addr_token(out.token, peer_addr, h->local_secret);
  }
  if (remote->has_token) {
    out.has_remote_token = true;
    memcpy(out.remote_token, remote->token, 32);
  }

  send_holepunch_reply(h, req, peer_addr, &out, p->socket);
}

static void
on_peer_holepunch (hdht_server_t *s, const hdht_incoming_t *req) {
  hdht_holepunch_msg_t msg;
  if (req->value == NULL || hdht_holepunch_decode(&msg, req->value, req->value_len) != 0) return;
  if (msg.mode != HDHT_MODE_FROM_RELAY || !msg.has_peer_address) return;

  hdht_server_handshake_t *h = msg.id < HDHT_SERVER_MAX_HANDSHAKES ? s->handshakes[msg.id] : NULL;
  if (h == NULL || h->closed || !h->has_secret) return;

  // relaying without a puncher: refuse, so the client waits for the relay
  if (h->relaying && h->puncher == NULL) {
    hdht_holepunch_payload_t refuse = {0};
    refuse.error = HDHT_ERROR_ABORTED;
    refuse.round = h->round;
    send_holepunch_reply(h, req, &msg.peer_address, &refuse, &s->dht->socket);
    return;
  }
  if (h->puncher == NULL) return;

  hdht_holepunch_payload_t remote;
  if (hdht_holepunch_payload_open(&remote, h->holepunch_secret, msg.payload, msg.payload_len) != 0) return;

  if (remote.error != HDHT_ERROR_NONE) {
    if (remote.round >= h->round) h->round = remote.round;
    abort_holepunch(h, req, &msg.peer_address, HDHT_ERROR_ABORTED);
    return;
  }

  hdht_puncher_t *p = h->puncher;
  if (req->socket == p->socket) hdht_puncher_add_sample(p, &req->to, &req->from);

  if (remote.round >= h->round) {
    h->round = remote.round;

    uint8_t token[32];
    hdht_addr_token(token, &msg.peer_address, h->local_secret);
    bool echoed = is_server_relay(s, &req->from) && remote.has_remote_token && sodium_memcmp(token, remote.remote_token, 32) == 0;
    hdht_puncher_update_remote(p, remote.punching, remote.firewall, remote.addresses, remote.has_addresses ? remote.addresses_len : 0, echoed ? msg.peer_address.ip : NULL);
  }

  if (!p->analyzed) {
    // answer once sampling is done (latest request wins)
    h->deferred = true;
    h->deferred_req = *req;
    h->deferred_req.value = NULL;
    h->deferred_req.value_len = 0;
    h->deferred_peer = msg.peer_address;
    h->deferred_payload = remote;
    return;
  }

  answer_holepunch(h, req, &msg.peer_address, &remote);
}

bool
hdht__server_on_request (hdht_t *dht, const hdht_incoming_t *req) {
  if (!req->has_target) return false;
  hdht_server_t *s = find_server(dht, req->target);
  if (s == NULL) return false;

  if (req->command == HDHT_CMD_PEER_HANDSHAKE) on_peer_handshake(s, req);
  else on_peer_holepunch(s, req);
  return true;
}

// announcer

static void
announce_round (hdht_server_t *s);

static void
on_ping_cycle (uv_timer_t *timer);

static void
schedule_ping_cycle (hdht_server_t *s) {
  if (!s->closing) uv_timer_start(&s->timer, on_ping_cycle, ANNOUNCE_PING_MS, 0);
}

static void
on_relay_ping (hdht_request_t *req, const hdht_response_t *res) {
  hdht_server_t *s = req->data;
  s->pings_pending--;
  if (res->status == HDHT_OK) s->pings_ok++;
  if (s->pings_pending > 0 || s->closing) return;

  uint8_t want = s->announced_len < MIN_ACTIVE_RELAYS ? s->announced_len : MIN_ACTIVE_RELAYS;
  if (s->pings_ok < want) s->refresh = true;

  if (s->refresh) announce_round(s);
  else schedule_ping_cycle(s);
}

// Pings the announced relays every 3 s so our NAT mapping towards them stays open.
static void
on_ping_cycle (uv_timer_t *timer) {
  hdht_server_t *s = timer->data;
  if (s->closing) return;

  if (++s->cycles >= ANNOUNCE_REFRESH_PING || s->announced_len == 0) s->refresh = true;
  if (s->refresh || s->announced_len == 0) {
    announce_round(s);
    return;
  }

  s->pings_pending = 0;
  s->pings_ok = 0;
  for (int i = 0; i < s->announced_len; i++) {
    hdht_request_t *r = hdht_request(s->dht, NULL, &s->announced[i].from, true, HDHT_RPC_PING, NULL, NULL, NULL, 0, on_relay_ping, s);
    if (r) s->pings_pending++;
  }
  if (s->pings_pending == 0) schedule_ping_cycle(s);
}

static void
announce_finished (hdht_server_t *s) {
  // keep the previous relays if this round found none
  if (s->next_announced_len > 0) {
    s->announced_len = s->next_announced_len;
    memcpy(s->announced, s->next_announced, sizeof(s->announced));
    s->relays_len = s->announced_len;
    for (int i = 0; i < s->announced_len; i++) {
      s->relays[i].relay_address = s->announced[i].from;
      s->relays[i].peer_address = s->announced[i].to; // our address as that node sees us
    }
  }

  bool first = !s->listening;
  s->listening = true;
  s->refresh = false;
  s->cycles = 0;
  s->stats.announces++;

  if (first && s->on_listening) s->on_listening(s, s->announced_len > 0 ? 0 : HDHT_ETIMEDOUT);
  schedule_ping_cycle(s);
}

typedef struct {
  hdht_server_t *server;
  hdht_reply_ref_t ref;
} announce_req_t;

static void
on_announce_reply (hdht_request_t *req, const hdht_response_t *res) {
  announce_req_t *a = req->data;
  hdht_server_t *s = a->server;

  if (res->status == HDHT_OK && res->error == 0 && !s->closing && s->next_announced_len < HDHT_SERVER_RELAYS) {
    s->next_announced[s->next_announced_len++] = a->ref;
  }
  free(a);

  if (--s->announcing == 0 && !s->closing) announce_finished(s);
}

static void
on_announce_query_done (hdht_query_t *q, int status) {
  (void) status;
  hdht_server_t *s = q->data;
  s->query = NULL;
  if (s->closing) return;

  s->next_announced_len = 0;
  s->announcing = 0;

  // the 3 closest nodes that gave us a token (announcer.js pickBest)
  for (int i = 0; i < q->closest_len && s->announcing < HDHT_SERVER_RELAYS; i++) {
    const hdht_reply_ref_t *ref = &q->closest[i];
    if (!ref->has_token) continue;

    uint8_t value[128];
    int n = hdht_announce_encode_signed(value, sizeof(value), HDHT_NS_ANNOUNCE, s->target, ref->id, ref->token, s->public_key, s->secret_key);
    if (n < 0) continue;

    announce_req_t *a = malloc(sizeof(announce_req_t));
    if (a == NULL) continue;
    a->server = s;
    a->ref = *ref;

    if (hdht_request(s->dht, NULL, &ref->from, false, HDHT_CMD_ANNOUNCE, s->target, ref->token, value, (size_t) n, on_announce_reply, a)) s->announcing++;
    else free(a);
  }

  if (s->announcing == 0) announce_finished(s);
}

static void
announce_round (hdht_server_t *s) {
  if (s->closing || s->query) return;
  s->refresh = false;

  s->query = hdht_query(s->dht, s->target, false, HDHT_CMD_FIND_PEER, NULL, 0, NULL, 0, NULL, on_announce_query_done, s);
  if (s->query == NULL) schedule_ping_cycle(s);
}

int
hdht_listen (hdht_t *dht, hdht_server_t *server, const uint8_t public_key[32], const uint8_t secret_key[64], hdht_connection_cb on_connection, void (*on_listening)(hdht_server_t *server, int status), void *data) {
  memset(server, 0, sizeof(*server));
  server->dht = dht;
  memcpy(server->public_key, public_key, 32);
  memcpy(server->secret_key, secret_key, 64);
  hdht_hash(server->target, public_key, 32);
  server->on_connection = on_connection;
  server->on_listening = on_listening;
  server->data = data;

  uv_timer_init(dht->loop, &server->timer);
  server->timer.data = server;

  server->next = dht->servers;
  dht->servers = server;

  // handshakes can be answered as soon as the first announce lands
  server->listening = false;
  announce_round(server);
  return 0;
}

// close: unannounce from each relay (fresh token via FIND_PEER first)

typedef struct {
  hdht_server_t *server;
  hdht_reply_ref_t ref;
} unannounce_req_t;

static void
unannounce_done (hdht_server_t *s);

static void
on_unannounce_reply (hdht_request_t *req, const hdht_response_t *res) {
  (void) res;
  unannounce_req_t *u = req->data;
  hdht_server_t *s = u->server;
  free(u);
  if (--s->announcing == 0) unannounce_done(s);
}

static void
on_unannounce_token (hdht_request_t *req, const hdht_response_t *res) {
  unannounce_req_t *u = req->data;
  hdht_server_t *s = u->server;

  if (res->status == HDHT_OK && res->has_token && res->has_id && res->value != NULL) {
    uint8_t value[128];
    int n = hdht_announce_encode_signed(value, sizeof(value), HDHT_NS_UNANNOUNCE, s->target, res->id, res->token, s->public_key, s->secret_key);
    if (n > 0 && hdht_request(s->dht, NULL, &res->from, false, HDHT_CMD_UNANNOUNCE, s->target, res->token, value, (size_t) n, on_unannounce_reply, u)) return;
  }

  free(u);
  if (--s->announcing == 0) unannounce_done(s);
}

static void
on_server_timer_close (uv_handle_t *handle) {
  hdht_server_t *s = handle->data;
  sodium_memzero(s->secret_key, sizeof(s->secret_key));
  if (s->on_closed) s->on_closed(s);
}

static void
unannounce_done (hdht_server_t *s) {
  hdht_t *dht = s->dht;
  for (hdht_server_t **p = &dht->servers; *p != NULL; p = &(*p)->next) {
    if (*p == s) {
      *p = s->next;
      break;
    }
  }
  uv_close((uv_handle_t *) &s->timer, on_server_timer_close);
}

void
hdht_server_close (hdht_server_t *s, void (*on_closed)(hdht_server_t *server)) {
  if (s->closing) return;
  s->closing = true;
  s->on_closed = on_closed;
  uv_timer_stop(&s->timer);

  if (s->query) hdht_query_destroy(s->query);
  s->query = NULL;

  for (int i = 0; i < HDHT_SERVER_MAX_HANDSHAKES; i++) {
    if (s->handshakes[i]) clear_now(s->handshakes[i]);
  }

  s->announcing = 1; // guard while issuing
  for (int i = 0; i < s->announced_len; i++) {
    unannounce_req_t *u = malloc(sizeof(unannounce_req_t));
    if (u == NULL) continue;
    u->server = s;
    u->ref = s->announced[i];
    if (hdht_request(s->dht, NULL, &u->ref.from, false, HDHT_CMD_FIND_PEER, s->target, NULL, NULL, 0, on_unannounce_token, u)) s->announcing++;
    else free(u);
  }
  if (--s->announcing == 0) unannounce_done(s);
}
