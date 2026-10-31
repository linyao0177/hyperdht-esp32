// Client connect (hyperdht/lib/connect.js): find the server's relay nodes,
// run the Noise handshake through one of them, then connect directly, over
// the LAN, by holepunching, or through a blind relay when either side asks
// for one (relay.c). Holepunching runs alongside the relay; when it gets
// through after the relay, the stream moves to the direct path.

#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "crypto.h"
#include "hdht.h"

#define MAX_CANDIDATES      8
#define PARALLEL_HANDSHAKES 2
#define CONNECT_TIMEOUT_MS  40000
#define REMOTE_UNKNOWN_WAIT 1000

enum {
  C_FINDING,
  C_HOLEPUNCH_PROBE,
  C_HOLEPUNCH_WAIT,
  C_HOLEPUNCH_ROUND,
  C_PUNCHING,
  C_RELAYING,
  C_DONE,
};

struct hdht_connect_s {
  hdht_t *dht;
  hdht_stream_t *stream;
  uint8_t remote_public_key[32];
  uint8_t target[32];
  int state;

  hdht_noise_t noise;
  uint8_t msg1[256];
  size_t msg1_len;

  hdht_query_t *query;
  hdht_request_t *handshakes[PARALLEL_HANDSHAKES];
  hdht_addr_t candidates[MAX_CANDIDATES];
  uint8_t candidates_len;
  hdht_addr_t tried[MAX_CANDIDATES];
  uint8_t tried_len;

  // after the handshake
  hdht_noise_payload_t payload;
  bool relayed;
  hdht_addr_t relay_addr;
  hdht_addr_t server_addr;
  hdht_addr_t client_addr;
  uint8_t holepunch_secret[32];
  uint8_t local_secret[32];
  hdht_relay_info_t server_relay;
  uint32_t round;
  bool probe_retry;
  bool has_remote_token;
  uint8_t remote_token[32];
  hdht_addr_t peer_addr;

  hdht_puncher_t *puncher;
  hdht_request_t *holepunch_req;
  hdht_request_t *lan_req;
  hdht_addr_t lan_addr;

  hdht_relay_t *relay; // pairing, until it reports
  uint8_t relay_token[32];
  bool use_relay; // ours; off for the connection to a relay itself
  bool no_relay;  // never pair, even when the server asks
  bool upgrading; // the stream runs through the relay; holepunching goes on
  bool punch_later; // test_punch_delay_ms: holepunching starts on the timer

  uv_timer_t timer;    // sleeps between holepunch steps
  uv_timer_t deadline; // whole connect
  uint8_t pending_closes;
};

static void
finish (hdht_connect_t *c, int error);

static void
probe_round (hdht_connect_t *c);

static void
after_probe (hdht_connect_t *c);

// cleanup

static void
on_handle_close (uv_handle_t *handle) {
  hdht_connect_t *c = handle->data;
  if (--c->pending_closes == 0) free(c);
}

static void
cancel_requests (hdht_connect_t *c) {
  if (c->query) hdht_query_destroy(c->query);
  c->query = NULL;
  for (int i = 0; i < PARALLEL_HANDSHAKES; i++) {
    if (c->handshakes[i]) hdht_request_cancel(c->handshakes[i]);
    c->handshakes[i] = NULL;
  }
  if (c->holepunch_req) hdht_request_cancel(c->holepunch_req);
  c->holepunch_req = NULL;
  if (c->lan_req) hdht_request_cancel(c->lan_req);
  c->lan_req = NULL;
}

// Ends the connect attempt. On success the stream is already connected.
static void
finish (hdht_connect_t *c, int error) {
  if (c->state == C_DONE) return;
  c->state = C_DONE;
  if (c->upgrading) error = 0; // the stream stays on the relay

  cancel_requests(c);
  if (c->puncher) hdht_puncher_destroy(c->puncher);
  c->puncher = NULL;
  if (c->relay) hdht_relay_cancel(c->relay);
  c->relay = NULL;
  hdht_noise_clear(&c->noise);
  sodium_memzero(c->holepunch_secret, sizeof(c->holepunch_secret));

  hdht_stream_t *stream = c->stream;
  stream->owner = NULL;
  stream->on_firewall = NULL;
  stream->on_finalize = NULL;

  c->pending_closes = 2;
  uv_timer_stop(&c->timer);
  uv_timer_stop(&c->deadline);
  uv_close((uv_handle_t *) &c->timer, on_handle_close);
  uv_close((uv_handle_t *) &c->deadline, on_handle_close);

  if (error) hdht_stream_destroy(stream, error);
}

// Connects the stream on socket to addr; a puncher socket moves to the stream.
// A stream already on the relay moves to the puncher socket instead.
static void
connect_stream (hdht_connect_t *c, hdht_socket_t *socket, const hdht_addr_t *addr) {
  if (c->state == C_DONE) return;

  hdht_stream_t *stream = c->stream;
  bool punched = c->puncher && socket == c->puncher->socket;

  if (c->upgrading) {
    if (punched) hdht_stream_upgrade(stream, hdht_puncher_release_socket(c->puncher), c->payload.udx_id, addr);
    finish(c, 0);
    return;
  }

  if (punched) stream->owned_socket = hdht_puncher_release_socket(c->puncher);

  int err = hdht_stream_connect(stream, socket, c->payload.udx_id, addr);
  finish(c, err ? HDHT_CONNECT_EHANDSHAKE : 0);
}

static void
on_deadline (uv_timer_t *timer) {
  finish(timer->data, HDHT_CONNECT_ETIMEOUT);
}

// The server reached our raw stream first (e.g. it connected directly).
static bool
on_stream_firewall (hdht_stream_t *stream, hdht_socket_t *socket, const hdht_addr_t *from) {
  hdht_connect_t *c = stream->owner;
  if (c == NULL || c->state == C_FINDING || c->state == C_DONE || socket == NULL) return false;
  // with a relay, only the puncher socket brings the server directly; the
  // relay forwards before it tells us our stream id (UDX resends)
  bool relaying = c->relay != NULL || c->upgrading;
  if (relaying && !(c->puncher && socket == c->puncher->socket)) return false;
  connect_stream(c, socket, from);
  return stream->connected;
}

// The stream closed while we were still working on it.
static void
on_stream_finalize (hdht_stream_t *stream) {
  hdht_connect_t *c = stream->owner;
  if (c) finish(c, 0);
}

// Holepunching gave up. With a relay, that path goes on; the puncher socket
// stays until we finish, since the server may already have got through to it.
static void
punch_failed (hdht_connect_t *c, int error) {
  if (c->relay == NULL && !c->upgrading) {
    finish(c, error);
    return;
  }
  if (c->holepunch_req) hdht_request_cancel(c->holepunch_req);
  c->holepunch_req = NULL;
  if (c->puncher) hdht_puncher_stop(c->puncher);
  uv_timer_stop(&c->timer);
  c->state = C_RELAYING;
}

// holepunch requests

static int
send_holepunch (hdht_connect_t *c, const hdht_addr_t *relay, const hdht_addr_t *peer_addr, const hdht_holepunch_payload_t *payload, hdht_response_cb cb) {
  uint8_t sealed[256];
  int sealed_len = hdht_holepunch_payload_seal(payload, c->holepunch_secret, sealed, sizeof(sealed));
  if (sealed_len < 0) return -1;

  hdht_holepunch_msg_t msg = {
    .mode = HDHT_MODE_FROM_CLIENT,
    .id = c->payload.holepunch_id,
    .payload = sealed,
    .payload_len = (size_t) sealed_len,
    .has_peer_address = true,
    .peer_address = *peer_addr,
  };

  uint8_t value[320];
  int n = hdht_holepunch_encode(&msg, value, sizeof(value));
  if (n < 0) return -1;

  // sent from the puncher socket so the relay sees that socket's NAT mapping
  c->holepunch_req = hdht_request(c->dht, c->puncher->socket, relay, false, HDHT_CMD_PEER_HOLEPUNCH, c->target, NULL, value, (size_t) n, cb, c);
  return c->holepunch_req ? 0 : -1;
}

// Decodes a PEER_HOLEPUNCH reply. Returns 0 and fills out on success.
static int
open_holepunch_reply (hdht_connect_t *c, const hdht_response_t *res, const hdht_addr_t *relay, hdht_holepunch_payload_t *out, hdht_addr_t *peer_addr) {
  if (res->status != HDHT_OK || res->value == NULL || !hdht_addr_eq(&res->from, relay)) return -1;

  hdht_holepunch_msg_t msg;
  if (hdht_holepunch_decode(&msg, res->value, res->value_len) != 0 || msg.mode != HDHT_MODE_REPLY) return -1;
  if (hdht_holepunch_payload_open(out, c->holepunch_secret, msg.payload, msg.payload_len) != 0) return -1;

  *peer_addr = msg.has_peer_address ? msg.peer_address : *relay;
  return 0;
}

static void
fill_local (hdht_connect_t *c, hdht_holepunch_payload_t *p, uint32_t error) {
  memset(p, 0, sizeof(*p));
  p->error = error;
  p->round = c->round++;
  if (error) return;

  hdht_nat_t *nat = &c->puncher->nat;
  p->firewall = nat->firewall;
  p->has_addresses = nat->has_addresses;
  p->addresses_len = nat->addresses_len;
  memcpy(p->addresses, nat->addresses, sizeof(p->addresses));
}

// The connect state may be gone by the time this arrives, so it is not touched.
static void
on_abort_reply (hdht_request_t *req, const hdht_response_t *res) {
  (void) req;
  (void) res;
}

// Tells the server we give up, then fails.
static void
abort_holepunch (hdht_connect_t *c, int error) {
  hdht_holepunch_payload_t p;
  fill_local(c, &p, HDHT_ERROR_ABORTED);
  if (c->holepunch_req) hdht_request_cancel(c->holepunch_req);
  c->holepunch_req = NULL;
  send_holepunch(c, &c->server_relay.relay_address, &c->server_relay.peer_address, &p, on_abort_reply);
  c->holepunch_req = NULL; // fire and forget
  punch_failed(c, error);
}

static void
on_puncher_connect (hdht_puncher_t *p, const hdht_addr_t *from) {
  hdht_connect_t *c = p->data;
  connect_stream(c, p->socket, from);
}

static void
on_puncher_abort (hdht_puncher_t *p) {
  punch_failed(p->data, HDHT_CONNECT_EHOLEPUNCH);
}

static void
on_round_reply (hdht_request_t *req, const hdht_response_t *res) {
  hdht_connect_t *c = req->data;
  c->holepunch_req = NULL;
  if (c->state != C_HOLEPUNCH_ROUND) return;

  hdht_holepunch_payload_t remote;
  hdht_addr_t peer_addr;
  if (open_holepunch_reply(c, res, &c->relay_addr, &remote, &peer_addr) != 0 || remote.error != HDHT_ERROR_NONE) {
    punch_failed(c, HDHT_CONNECT_EHOLEPUNCH);
    return;
  }

  // the server echoes our token for its address: that address is verified
  uint8_t token[32];
  hdht_addr_token(token, &c->server_addr, c->local_secret);
  bool echoed = remote.has_remote_token && sodium_memcmp(remote.remote_token, token, 32) == 0;

  hdht_puncher_update_remote(c->puncher, remote.punching, remote.firewall, remote.addresses, remote.has_addresses ? remote.addresses_len : 0, echoed ? c->server_addr.ip : NULL);

  if (!c->puncher->remote_punching || !hdht_puncher_punch(c->puncher)) {
    punch_failed(c, HDHT_CONNECT_EHOLEPUNCH);
    return;
  }

  c->state = C_PUNCHING;
}

static void
round_punch (hdht_connect_t *c) {
  c->state = C_HOLEPUNCH_ROUND;
  c->puncher->nat.frozen = true;

  hdht_holepunch_payload_t p;
  fill_local(c, &p, HDHT_ERROR_NONE);
  p.punching = true;
  p.has_token = true;
  hdht_addr_token(p.token, &c->server_addr, c->local_secret);
  if (c->has_remote_token) {
    p.has_remote_token = true;
    memcpy(p.remote_token, c->remote_token, 32);
  }

  if (send_holepunch(c, &c->relay_addr, &c->server_addr, &p, on_round_reply) != 0) punch_failed(c, HDHT_CONNECT_ENOMEM);
}

static void
on_wait_timer (uv_timer_t *timer) {
  hdht_connect_t *c = timer->data;
  if (c->state == C_HOLEPUNCH_WAIT) after_probe(c);
}

static void
on_puncher_analyzed (hdht_puncher_t *p) {
  hdht_connect_t *c = p->data;
  if (c->state == C_HOLEPUNCH_WAIT && !uv_is_active((uv_handle_t *) &c->timer)) after_probe(c);
}

// connect.js probeRound, after the reply (and the optional 1 s pause).
static void
after_probe (hdht_connect_t *c) {
  hdht_puncher_t *p = c->puncher;
  if (!p->analyzed) return; // on_puncher_analyzed continues

  bool retry = c->probe_retry;
  c->probe_retry = false;

  if (hdht_puncher_unstable(p) || p->remote_firewall == HDHT_FIREWALL_UNKNOWN || !c->has_remote_token) {
    if (retry) {
      probe_round(c);
      return;
    }
  }

  if (p->remote_firewall == HDHT_FIREWALL_UNKNOWN || p->nat.firewall == HDHT_FIREWALL_UNKNOWN) {
    abort_holepunch(c, HDHT_CONNECT_EHOLEPUNCH);
    return;
  }
  if (p->remote_firewall >= HDHT_FIREWALL_RANDOM && p->nat.firewall >= HDHT_FIREWALL_RANDOM) {
    abort_holepunch(c, HDHT_CONNECT_ECANNOT_HOLEPUNCH);
    return;
  }

  // same relay as ours: use the address the server says it punches from
  if (hdht_addr_eq(&c->server_relay.relay_address, &c->relay_addr) && !hdht_addr_eq(&c->server_addr, &c->peer_addr)) {
    c->server_addr = c->peer_addr;
    hdht_puncher_probe(p, &c->server_addr, true);
  }

  round_punch(c);
}

static void
on_probe_reply (hdht_request_t *req, const hdht_response_t *res) {
  hdht_connect_t *c = req->data;
  c->holepunch_req = NULL;
  if (c->state != C_HOLEPUNCH_PROBE) return;

  hdht_holepunch_payload_t remote;
  hdht_addr_t peer_addr;
  if (open_holepunch_reply(c, res, &c->server_relay.relay_address, &remote, &peer_addr) != 0 || remote.error != HDHT_ERROR_NONE) {
    punch_failed(c, HDHT_CONNECT_EHOLEPUNCH);
    return;
  }

  hdht_puncher_update_remote(c->puncher, remote.punching, remote.firewall, remote.addresses, remote.has_addresses ? remote.addresses_len : 0, NULL);
  hdht_puncher_add_sample(c->puncher, &res->to, &res->from);

  c->has_remote_token = remote.has_token;
  if (remote.has_token) memcpy(c->remote_token, remote.token, 32);
  c->peer_addr = peer_addr;

  c->state = C_HOLEPUNCH_WAIT;
  if (c->puncher->remote_firewall == HDHT_FIREWALL_UNKNOWN) {
    // give the server a chance to finish its own NAT analysis
    uv_timer_start(&c->timer, on_wait_timer, REMOTE_UNKNOWN_WAIT, 0);
    return;
  }
  after_probe(c);
}

static void
probe_round (hdht_connect_t *c) {
  c->state = C_HOLEPUNCH_PROBE;

  // open a low-TTL session towards the server so its punch can come through
  hdht_puncher_probe(c->puncher, &c->server_addr, true);

  hdht_holepunch_payload_t p;
  fill_local(c, &p, HDHT_ERROR_NONE);
  p.has_remote_address = true;
  p.remote_address = c->server_addr;

  if (send_holepunch(c, &c->server_relay.relay_address, &c->server_relay.peer_address, &p, on_probe_reply) != 0) {
    punch_failed(c, HDHT_CONNECT_ENOMEM);
  }
}

static void
start_holepunch (hdht_connect_t *c) {
  c->puncher = hdht_puncher_create(c->dht, true, c->payload.firewall, c);
  if (c->puncher == NULL) {
    punch_failed(c, HDHT_CONNECT_ENOMEM);
    return;
  }
  c->puncher->on_connect = on_puncher_connect;
  c->puncher->on_abort = on_puncher_abort;
  c->puncher->on_analyzed = on_puncher_analyzed;

  randombytes_buf(c->local_secret, sizeof(c->local_secret));

  // prefer the relay we already talked to
  c->server_relay = c->payload.relays[0];
  for (int i = 0; i < c->payload.relays_len; i++) {
    if (hdht_addr_eq(&c->payload.relays[i].relay_address, &c->relay_addr)) {
      c->server_relay = c->payload.relays[i];
      break;
    }
  }

  c->probe_retry = true;
  probe_round(c);
}

// LAN shortcut

static void
on_lan_ping (hdht_request_t *req, const hdht_response_t *res) {
  hdht_connect_t *c = req->data;
  c->lan_req = NULL;
  if (c->state == C_DONE) return;

  if (res->status == HDHT_OK) {
    connect_stream(c, &c->dht->socket, &c->lan_addr);
    return;
  }

  bool holepunchable = c->payload.has_holepunch && c->payload.relays_len > 0;
  if (!holepunchable) finish(c, HDHT_CONNECT_ECANNOT_HOLEPUNCH);
}

// Picks the server LAN address sharing the longest prefix with ours.
static bool
pick_lan_address (hdht_connect_t *c, hdht_addr_t *out) {
  int best = -1, best_score = 0;
  for (int i = 0; i < c->payload.addresses4_len; i++) {
    const hdht_addr_t *a = &c->payload.addresses4[i];
    if (hdht_ip_is_reserved(a->ip)) continue;
    if (best < 0) best = i;
    for (int j = 0; j < c->dht->local_addresses_len; j++) {
      const uint8_t *l = c->dht->local_addresses[j].ip;
      int score = l[0] != a->ip[0] ? 0 : l[1] != a->ip[1] ? 1 : l[2] != a->ip[2] ? 2 : 3;
      if (score > best_score) {
        best = i;
        best_score = score;
      }
    }
  }
  if (best < 0) return false;
  *out = c->payload.addresses4[best];
  return true;
}

// blind relay (connect.js relayConnection)

static void
on_relay_paired (hdht_relay_t *r, int status, uint32_t remote_id, void *data) {
  hdht_connect_t *c = data;
  c->relay = NULL;
  if (status == 0 && hdht_relay_connect(r, c->stream, remote_id) == 0) {
    // holepunching goes on and may still move the stream
    if (c->puncher || c->punch_later) c->upgrading = true;
    else finish(c, 0);
    return;
  }
  if (status == 0) hdht_relay_cancel(r);
  // holepunching may still get through, unless it is over
  if (c->punch_later || (c->puncher && c->state != C_RELAYING)) return;
  finish(c, HDHT_CONNECT_ERELAY);
}

// The server's relay wins, as in connect.js; then we are not the initiator.
static void
start_relay (hdht_connect_t *c) {
  bool theirs = c->payload.has_relay_through;
  const uint8_t *key = theirs ? c->payload.relay_through_public_key : c->dht->relay;
  const uint8_t *token = theirs ? c->payload.relay_through_token : c->relay_token;
  c->state = C_RELAYING;
  if (hdht_relay_pair(c->dht, key, token, !theirs, c->stream->local_id, on_relay_paired, c, &c->relay) != 0) finish(c, HDHT_CONNECT_ERELAY);
}

static void
on_punch_later (uv_timer_t *timer) {
  hdht_connect_t *c = timer->data;
  c->punch_later = false;
  if (c->state == C_RELAYING) start_holepunch(c);
}

// connect.js holepunch(): choose how to reach the server.
static void
choose_path (hdht_connect_t *c) {
  bool holepunchable = c->payload.has_holepunch && c->payload.relays_len > 0;

  if (!c->relayed) {
    // the node we handshaked with is the server itself
    connect_stream(c, &c->dht->socket, &c->relay_addr);
    return;
  }

  // a relay was asked for: holepunching runs alongside it, unless we keep to the relay
  if (!c->no_relay && (c->use_relay || c->payload.has_relay_through)) {
    start_relay(c);
    if (c->state != C_RELAYING || !holepunchable || c->dht->relay_only) return;
    if (c->dht->test_punch_delay_ms == 0) {
      start_holepunch(c);
      return;
    }
    c->punch_later = true;
    uv_timer_start(&c->timer, on_punch_later, c->dht->test_punch_delay_ms, 0);
    return;
  }

  if (c->payload.firewall == HDHT_FIREWALL_OPEN || !holepunchable) {
    hdht_addr_t addr = c->server_addr;
    for (int i = 0; i < c->payload.addresses4_len; i++) {
      const uint8_t *ip = c->payload.addresses4[i].ip;
      if (!hdht_ip_is_private(ip) && !hdht_ip_is_reserved(ip)) {
        addr = c->payload.addresses4[i];
        break;
      }
    }
    connect_stream(c, &c->dht->socket, &addr);
    return;
  }

  // same public IP: race a LAN ping with holepunching
  if (memcmp(c->client_addr.ip, c->server_addr.ip, 4) == 0 && pick_lan_address(c, &c->lan_addr)) {
    c->lan_req = hdht_request(c->dht, NULL, &c->lan_addr, true, HDHT_RPC_PING, NULL, NULL, NULL, 0, on_lan_ping, c);
  }

  start_holepunch(c);
}

// handshake

static void
try_candidates (hdht_connect_t *c);

static void
on_handshake_failed (hdht_connect_t *c) {
  try_candidates(c);
  if (c->state != C_FINDING) return;

  bool waiting = c->query != NULL;
  for (int i = 0; i < PARALLEL_HANDSHAKES; i++) waiting = waiting || c->handshakes[i] != NULL;
  if (!waiting) finish(c, c->tried_len ? HDHT_CONNECT_EHANDSHAKE : HDHT_CONNECT_EPEER_NOT_FOUND);
}

static void
on_handshake_reply (hdht_request_t *req, const hdht_response_t *res) {
  hdht_connect_t *c = req->data;
  for (int i = 0; i < PARALLEL_HANDSHAKES; i++) {
    if (c->handshakes[i] == req) c->handshakes[i] = NULL;
  }
  if (c->state != C_FINDING) return;

  hdht_handshake_msg_t hs;
  bool ok = res->status == HDHT_OK &&
            res->value != NULL &&
            hdht_addr_eq(&res->from, &req->to) &&
            hdht_handshake_decode(&hs, res->value, res->value_len) == 0 &&
            hs.mode == HDHT_MODE_REPLY &&
            hs.noise_len > 0;
  if (!ok) {
    on_handshake_failed(c);
    return;
  }

  // decrypt on a copy so a bad reply cannot spoil the handshake state
  hdht_noise_t noise = c->noise;
  uint8_t plain[256];
  int n = hdht_noise_recv(&noise, hs.noise, hs.noise_len, plain, sizeof(plain));
  if (n < 0 || hdht_noise_payload_decode(&c->payload, plain, (size_t) n) != 0) {
    hdht_noise_clear(&noise);
    on_handshake_failed(c);
    return;
  }

  c->noise = noise;
  hdht_noise_clear(&noise);

  if (c->payload.version != 1 || c->payload.error != HDHT_ERROR_NONE || !c->payload.has_udx) {
    finish(c, HDHT_CONNECT_ESERVER_ERROR);
    return;
  }

  c->relayed = hs.has_peer_address;
  c->relay_addr = req->to;
  c->server_addr = hs.has_peer_address ? hs.peer_address : req->to;
  c->client_addr = res->to;

  hdht_stream_set_keys(c->stream, c->noise.tx, c->noise.rx, c->noise.hash, c->noise.rs);
  hdht_holepunch_secret(c->holepunch_secret, c->noise.hash);

  cancel_requests(c);
  c->state = C_HOLEPUNCH_PROBE; // leaves C_FINDING; choose_path sets the real state
  choose_path(c);
}

static bool
already_tried (hdht_connect_t *c, const hdht_addr_t *addr) {
  for (int i = 0; i < c->tried_len; i++) {
    if (hdht_addr_eq(&c->tried[i], addr)) return true;
  }
  for (int i = 0; i < c->candidates_len; i++) {
    if (hdht_addr_eq(&c->candidates[i], addr)) return true;
  }
  return false;
}

static void
try_candidates (hdht_connect_t *c) {
  for (int i = 0; i < PARALLEL_HANDSHAKES && c->candidates_len > 0 && c->state == C_FINDING; i++) {
    if (c->handshakes[i] != NULL) continue;

    hdht_addr_t to = c->candidates[0];
    memmove(&c->candidates[0], &c->candidates[1], (size_t) (--c->candidates_len) * sizeof(hdht_addr_t));
    if (c->tried_len < MAX_CANDIDATES) c->tried[c->tried_len++] = to;

    hdht_handshake_msg_t hs = {.mode = HDHT_MODE_FROM_CLIENT, .noise = c->msg1, .noise_len = c->msg1_len};
    uint8_t value[300];
    int n = hdht_handshake_encode(&hs, value, sizeof(value));
    if (n < 0) continue;

    c->handshakes[i] = hdht_request(c->dht, NULL, &to, false, HDHT_CMD_PEER_HANDSHAKE, c->target, NULL, value, (size_t) n, on_handshake_reply, c);
  }
}

static void
on_find_peer_reply (hdht_query_t *q, const hdht_response_t *res) {
  hdht_connect_t *c = q->data;
  if (c->state != C_FINDING || res->value == NULL) return;

  hdht_peer_t peer;
  if (hdht_peer_decode(&peer, res->value, res->value_len) != 0) return;
  if (already_tried(c, &res->from) || c->candidates_len == MAX_CANDIDATES) return;

  c->candidates[c->candidates_len++] = res->from;
  try_candidates(c);
}

static void
on_find_peer_done (hdht_query_t *q, int status) {
  (void) status;
  hdht_connect_t *c = q->data;
  if (c->query == q) c->query = NULL;
  if (c->state != C_FINDING) return;
  on_handshake_failed(c);
}

int
hdht__connect (hdht_t *dht, hdht_stream_t *stream, const uint8_t remote_public_key[32], hdht_stream_open_cb on_open, hdht_stream_data_cb on_data, hdht_stream_close_cb on_close, void *data, bool no_relay) {
  int err = hdht_stream_init(dht, stream, true);
  if (err) return err;
  stream->on_open = on_open;
  stream->on_data = on_data;
  stream->on_close = on_close;
  stream->data = data;

  hdht_connect_t *c = calloc(1, sizeof(hdht_connect_t));
  if (c == NULL) {
    hdht_stream_destroy(stream, HDHT_CONNECT_ENOMEM);
    return 0; // reported through on_close
  }

  c->dht = dht;
  c->stream = stream;
  c->state = C_FINDING;
  c->no_relay = no_relay;
  c->use_relay = dht->has_relay && !no_relay;
  memcpy(c->remote_public_key, remote_public_key, 32);
  hdht_hash(c->target, remote_public_key, 32);
  stream->owner = c;
  stream->on_firewall = on_stream_firewall;
  stream->on_finalize = on_stream_finalize;

  uv_timer_init(dht->loop, &c->timer);
  c->timer.data = c;
  uv_timer_init(dht->loop, &c->deadline);
  c->deadline.data = c;
  uv_timer_start(&c->deadline, on_deadline, CONNECT_TIMEOUT_MS, 0);

  // first Noise message, reused for every relay we try
  hdht_noise_payload_t payload = {0};
  payload.version = 1;
  payload.firewall = HDHT_FIREWALL_UNKNOWN;
  if (c->use_relay) {
    // through our relay only: no LAN addresses, so the server tries no shortcut
    payload.has_relay_through = true;
    memcpy(payload.relay_through_public_key, dht->relay, 32);
    randombytes_buf(c->relay_token, 32);
    memcpy(payload.relay_through_token, c->relay_token, 32);
  } else {
    for (int i = 0; i < dht->local_addresses_len && i < HDHT_MAX_ADDRESSES; i++) {
      payload.addresses4[payload.addresses4_len] = dht->local_addresses[i];
      payload.addresses4[payload.addresses4_len++].port = dht->socket.local_port;
    }
  }
  payload.has_udx = true;
  payload.udx_id = stream->local_id;
  payload.has_secret_stream = true;

  uint8_t plain[128];
  int n = hdht_noise_payload_encode(&payload, plain, sizeof(plain));
  hdht_noise_init(&c->noise, true, dht->public_key, dht->secret_key, remote_public_key, HDHT_NS_PEER_HANDSHAKE);
  n = n < 0 ? -1 : hdht_noise_send(&c->noise, plain, (size_t) n, c->msg1, sizeof(c->msg1));
  if (n < 0) {
    finish(c, HDHT_CONNECT_ENOMEM);
    return 0;
  }
  c->msg1_len = (size_t) n;

  c->query = hdht_query(dht, c->target, false, HDHT_CMD_FIND_PEER, NULL, 0, NULL, 0, on_find_peer_reply, on_find_peer_done, c);
  if (c->query == NULL) finish(c, HDHT_CONNECT_ENOMEM);
  return 0;
}

int
hdht_connect (hdht_t *dht, hdht_stream_t *stream, const uint8_t remote_public_key[32], hdht_stream_open_cb on_open, hdht_stream_data_cb on_data, hdht_stream_close_cb on_close, void *data) {
  return hdht__connect(dht, stream, remote_public_key, on_open, on_data, on_close, data, false);
}
