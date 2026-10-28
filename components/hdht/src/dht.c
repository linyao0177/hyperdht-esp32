#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "crypto.h"
#include "dht.h"

#define REQUEST_ID  0x03
#define RESPONSE_ID 0x13

#define DEFAULT_RETRIES     3
#define DEFAULT_TIMEOUT_MS  1000
#define QUERY_RETRIES       2
#define QUERY_CONCURRENCY   10
#define TICK_MS             5000
#define REFRESH_TICKS       60 // ~5 min
#define SPARSE_REFRESH_TICK 12 // ~1 min while the table is small

typedef struct {
  udx_socket_send_t req;
  uint8_t data[];
} send_block_t;

static void
reap_queries (hdht_t *dht);

static void
query_read_more (hdht_query_t *q);

// addresses

void
hdht_addr_to_sockaddr (const hdht_addr_t *a, struct sockaddr_in *out) {
  memset(out, 0, sizeof(*out));
  out->sin_family = AF_INET;
  out->sin_port = htons(a->port);
  memcpy(&out->sin_addr.s_addr, a->ip, 4);
}

void
hdht_addr_from_sockaddr (hdht_addr_t *a, const struct sockaddr *in) {
  memset(a, 0, sizeof(*a));
  if (in->sa_family != AF_INET) return;
  const struct sockaddr_in *s = (const struct sockaddr_in *) in;
  memcpy(a->ip, &s->sin_addr.s_addr, 4);
  a->port = ntohs(s->sin_port);
}

int
hdht_addr_parse (hdht_addr_t *a, const char *host, uint16_t port) {
  unsigned int b[4];
  char tail;
  if (sscanf(host, "%u.%u.%u.%u%c", &b[0], &b[1], &b[2], &b[3], &tail) != 4) return -1;
  for (int i = 0; i < 4; i++) {
    if (b[i] > 255) return -1;
    a->ip[i] = (uint8_t) b[i];
  }
  a->port = port;
  return 0;
}

const char *
hdht_addr_str (const hdht_addr_t *a) {
  static char out[24];
  snprintf(out, sizeof(out), "%u.%u.%u.%u:%u", a->ip[0], a->ip[1], a->ip[2], a->ip[3], a->port);
  return out;
}

static int
xor_compare (const uint8_t target[32], const uint8_t a[32], const uint8_t b[32]) {
  for (int i = 0; i < 32; i++) {
    if (a[i] == b[i]) continue;
    return (int) (target[i] ^ a[i]) - (int) (target[i] ^ b[i]);
  }
  return 0;
}

// routing table

static void
table_add (hdht_t *dht, const hdht_addr_t *addr, const uint8_t id[32]) {
  if (memcmp(id, dht->table_id, 32) == 0) return;

  uint64_t now = uv_now(dht->loop);
  int oldest = 0;

  for (int i = 0; i < dht->table_len; i++) {
    if (memcmp(dht->table[i].id, id, 32) == 0) {
      dht->table[i].seen = now;
      return;
    }
    if (dht->table[i].seen < dht->table[oldest].seen) oldest = i;
  }

  hdht_node_t *slot = dht->table_len < HDHT_TABLE_SIZE ? &dht->table[dht->table_len++] : &dht->table[oldest];
  slot->addr = *addr;
  memcpy(slot->id, id, 32);
  slot->seen = now;
}

static void
table_remove_addr (hdht_t *dht, const hdht_addr_t *addr) {
  for (int i = 0; i < dht->table_len; i++) {
    if (!hdht_addr_eq(&dht->table[i].addr, addr)) continue;
    dht->table[i] = dht->table[--dht->table_len];
    return;
  }
}

// Writes up to max nodes closest to target into out, closest first.
static int
table_closest (hdht_t *dht, const uint8_t target[32], const hdht_node_t **out, int max) {
  int n = 0;
  for (int i = 0; i < dht->table_len; i++) {
    const hdht_node_t *node = &dht->table[i];
    int j = n < max ? n++ : max;
    if (j == max) {
      if (xor_compare(target, node->id, out[max - 1]->id) >= 0) continue;
      j = max - 1;
    }
    while (j > 0 && xor_compare(target, node->id, out[j - 1]->id) < 0) {
      out[j] = out[j - 1];
      j--;
    }
    out[j] = node;
  }
  return n;
}

// Validates a claimed id against the sender address.
static bool
valid_id (const hdht_addr_t *from, const uint8_t id[32]) {
  uint8_t expected[32];
  hdht_node_id(expected, from);
  return memcmp(expected, id, 32) == 0;
}

// sockets

static void
on_send (udx_socket_send_t *req, int status) {
  (void) status;
  free(req->data);
}

int
hdht_socket_send (hdht_socket_t *socket, const hdht_addr_t *to, const uint8_t *data, size_t len, int ttl) {
  if (!socket->bound || socket->closing) return -1;

  send_block_t *b = malloc(sizeof(send_block_t) + len);
  if (b == NULL) return HDHT_ENOMEM;
  memcpy(b->data, data, len);
  b->req.data = b;

  struct sockaddr_in addr;
  hdht_addr_to_sockaddr(to, &addr);
  uv_buf_t buf = uv_buf_init((char *) b->data, (unsigned int) len);

  int err = ttl > 0
              ? udx_socket_send_ttl(&b->req, &socket->udx, &buf, 1, (struct sockaddr *) &addr, ttl, on_send)
              : udx_socket_send(&b->req, &socket->udx, &buf, 1, (struct sockaddr *) &addr, on_send);
  if (err) free(b);
  return err;
}

static void
on_message (hdht_t *dht, hdht_socket_t *socket, const uint8_t *buf, size_t len, const hdht_addr_t *from);

static void
on_udx_recv (udx_socket_t *udx_socket, ssize_t read_len, const uv_buf_t *buf, const struct sockaddr *from) {
  hdht_socket_t *socket = udx_socket->data;
  if (read_len <= 0 || from == NULL || from->sa_family != AF_INET) return;

  hdht_addr_t addr;
  hdht_addr_from_sockaddr(&addr, from);
  if (addr.port == 0) return;

  if (read_len == 1) {
    if (socket->on_probe) socket->on_probe(socket, &addr);
    return;
  }

  on_message(socket->dht, socket, (const uint8_t *) buf->base, (size_t) read_len, &addr);
}

static void
on_udx_close (udx_socket_t *udx_socket) {
  hdht_socket_t *socket = udx_socket->data;
  socket->bound = false;
  if (socket->on_close) socket->on_close(socket);
}

int
hdht_socket_open (hdht_t *dht, hdht_socket_t *socket, uint16_t port) {
  memset(socket, 0, sizeof(*socket));
  socket->dht = dht;

  int err = udx_socket_init(&dht->udx, &socket->udx, on_udx_close);
  if (err) return err;
  socket->udx.data = socket;

  struct sockaddr_in addr;
  uv_ip4_addr("0.0.0.0", port, &addr);
  err = udx_socket_bind(&socket->udx, (const struct sockaddr *) &addr, 0);
  if (err && port != 0) {
    uv_ip4_addr("0.0.0.0", 0, &addr);
    err = udx_socket_bind(&socket->udx, (const struct sockaddr *) &addr, 0);
  }
  if (err == 0) err = udx_socket_recv_start(&socket->udx, on_udx_recv);
  if (err) {
    socket->closing = true;
    udx_socket_close(&socket->udx);
    return err;
  }

  struct sockaddr_storage name;
  int name_len = sizeof(name);
  udx_socket_getsockname(&socket->udx, (struct sockaddr *) &name, &name_len);
  socket->local_port = ntohs(((struct sockaddr_in *) &name)->sin_port);
  socket->bound = true;
  return 0;
}

void
hdht_socket_close (hdht_socket_t *socket, void (*on_close)(hdht_socket_t *socket)) {
  if (socket->closing) return;
  socket->closing = true;
  socket->on_probe = NULL;
  socket->on_close = on_close;

  // requests sent from this socket cannot receive replies any more
  hdht_t *dht = socket->dht;
  for (hdht_request_t *r = dht->requests; r != NULL; r = r->next) {
    if (r->socket == socket) r->socket = &dht->socket;
  }

  udx_socket_close(&socket->udx);
}

// request timer

static void
schedule_request_timer (hdht_t *dht);

static void
request_send_now (hdht_request_t *req) {
  hdht_t *dht = req->dht;
  uint64_t now = uv_now(dht->loop);
  if (req->sent == 0) req->first_sent = now;
  req->sent++;
  req->deadline = now + req->timeout_ms;
  hdht_socket_send(req->socket, &req->to, req->buf, req->len, 0);
}

static void
unlink_request (hdht_request_t *req) {
  hdht_t *dht = req->dht;
  for (hdht_request_t **p = &dht->requests; *p != NULL; p = &(*p)->next) {
    if (*p == req) {
      *p = req->next;
      dht->inflight--;
      return;
    }
  }
}

static void
free_request (hdht_request_t *req) {
  free(req->buf);
  free(req);
}

static void
on_request_timer (uv_timer_t *timer) {
  hdht_t *dht = timer->data;

  // callbacks can add or cancel requests, so rescan after each one
  for (;;) {
    uint64_t now = uv_now(dht->loop);
    hdht_request_t *expired = NULL;

    for (hdht_request_t *r = dht->requests; r != NULL; r = r->next) {
      if (r->deadline <= now) {
        expired = r;
        break;
      }
    }

    if (expired == NULL) break;

    if (expired->sent <= expired->retries) {
      dht->stats.retries++;
      request_send_now(expired);
      continue;
    }

    dht->stats.timeouts++;
    unlink_request(expired);
    table_remove_addr(dht, &expired->to);

    hdht_response_t res;
    memset(&res, 0, sizeof(res));
    res.status = HDHT_ETIMEDOUT;
    res.from = expired->to;
    expired->on_response(expired, &res);
    free_request(expired);
  }

  reap_queries(dht);
  schedule_request_timer(dht);
}

static void
schedule_request_timer (hdht_t *dht) {
  if (dht->destroyed) return;

  if (dht->requests == NULL) {
    uv_timer_stop(&dht->request_timer);
    return;
  }

  uint64_t next = UINT64_MAX;
  for (hdht_request_t *r = dht->requests; r != NULL; r = r->next) {
    if (r->deadline < next) next = r->deadline;
  }

  uint64_t now = uv_now(dht->loop);
  uv_timer_start(&dht->request_timer, on_request_timer, next > now ? next - now : 0, 0);
}

// encoding

static int
encode_request (uint8_t *out, size_t cap, uint16_t tid, const hdht_addr_t *to, bool internal, uint32_t command, const uint8_t *target, const uint8_t *token, const uint8_t *value, size_t value_len, bool has_value) {
  cenc_t e;
  cenc_init(&e, out, cap);
  cenc_u8(&e, REQUEST_ID);
  cenc_u8(&e, (uint8_t) ((token ? 2 : 0) | (internal ? 4 : 0) | (target ? 8 : 0) | (has_value ? 16 : 0)));
  cenc_u16(&e, tid);
  cenc_addr(&e, to);
  if (token) cenc_fixed32(&e, token);
  cenc_uint(&e, command);
  if (target) cenc_fixed32(&e, target);
  if (has_value) cenc_buffer(&e, value, value_len);
  return e.err ? -1 : (int) e.pos;
}

hdht_request_t *
hdht_request (hdht_t *dht, hdht_socket_t *socket, const hdht_addr_t *to, bool internal, uint32_t command, const uint8_t *target, const uint8_t *token, const uint8_t *value, size_t value_len, hdht_response_cb cb, void *data) {
  if (dht->destroyed) return NULL;

  hdht_request_t *req = calloc(1, sizeof(hdht_request_t));
  if (req == NULL) return NULL;

  size_t cap = 1 + 1 + 2 + 6 + 32 + 9 + 32 + 9 + value_len;
  req->buf = malloc(cap);
  if (req->buf == NULL) {
    free(req);
    return NULL;
  }

  req->dht = dht;
  req->socket = socket ? socket : &dht->socket;
  req->to = *to;
  req->tid = dht->next_tid++;
  req->retries = DEFAULT_RETRIES;
  req->timeout_ms = DEFAULT_TIMEOUT_MS;
  req->on_response = cb;
  req->data = data;

  int n = encode_request(req->buf, cap, req->tid, to, internal, command, target, token, value, value_len, value != NULL);
  if (n < 0) {
    free_request(req);
    return NULL;
  }
  req->len = (size_t) n;

  req->next = dht->requests;
  dht->requests = req;
  dht->inflight++;
  dht->stats.requests++;

  request_send_now(req);
  schedule_request_timer(dht);
  return req;
}

void
hdht_request_cancel (hdht_request_t *req) {
  hdht_t *dht = req->dht;
  for (hdht_request_t *r = dht->requests; r != NULL; r = r->next) {
    if (r != req) continue;
    unlink_request(req);
    free_request(req);
    schedule_request_timer(dht);
    return;
  }
}

void
hdht_reply (hdht_t *dht, const hdht_incoming_t *req, hdht_socket_t *socket, const hdht_addr_t *to, uint32_t error, const uint8_t *value, size_t value_len, bool closer_nodes) {
  const hdht_node_t *closest[HDHT_K];
  int closest_len = 0;
  if (closer_nodes && req->has_target) closest_len = table_closest(dht, req->target, closest, HDHT_K);

  size_t cap = 1 + 1 + 2 + 6 + 9 + 6 * HDHT_K + 9 + 9 + value_len;
  uint8_t stack[256];
  uint8_t *buf = cap <= sizeof(stack) ? stack : malloc(cap);
  if (buf == NULL) return;

  cenc_t e;
  cenc_init(&e, buf, cap);
  cenc_u8(&e, RESPONSE_ID);
  cenc_u8(&e, (uint8_t) ((closest_len ? 4 : 0) | (error ? 8 : 0) | (value ? 16 : 0)));
  cenc_u16(&e, req->tid);
  cenc_addr(&e, to);
  if (closest_len) {
    cenc_uint(&e, (uint64_t) closest_len);
    for (int i = 0; i < closest_len; i++) cenc_addr(&e, &closest[i]->addr);
  }
  if (error) cenc_uint(&e, error);
  if (value) cenc_buffer(&e, value, value_len);

  if (!e.err) hdht_socket_send(socket ? socket : req->socket, to, buf, e.pos, 0);
  if (buf != stack) free(buf);
}

void
hdht_relay (hdht_t *dht, const hdht_incoming_t *req, hdht_socket_t *socket, const hdht_addr_t *to, const uint8_t *value, size_t value_len) {
  (void) dht;
  size_t cap = 1 + 1 + 2 + 6 + 9 + 32 + 9 + value_len;
  uint8_t stack[256];
  uint8_t *buf = cap <= sizeof(stack) ? stack : malloc(cap);
  if (buf == NULL) return;

  int n = encode_request(buf, cap, req->tid, to, req->internal, req->command, req->has_target ? req->target : NULL, NULL, value, value_len, value != NULL);
  if (n > 0) hdht_socket_send(socket ? socket : req->socket, to, buf, (size_t) n, 0);
  if (buf != stack) free(buf);
}

// incoming

static void
on_internal_request (hdht_t *dht, const hdht_incoming_t *req) {
  switch (req->command) {
  case HDHT_RPC_PING:
  case HDHT_RPC_DOWN_HINT:
    hdht_reply(dht, req, NULL, &req->from, 0, NULL, 0, false);
    return;

  case HDHT_RPC_PING_NAT: {
    if (req->value == NULL || req->value_len < 2) return;
    hdht_addr_t to = req->from;
    to.port = (uint16_t) (req->value[0] | (req->value[1] << 8));
    if (to.port == 0) return;
    hdht_reply(dht, req, NULL, &to, 0, NULL, 0, false);
    return;
  }

  case HDHT_RPC_FIND_NODE:
    if (!req->has_target) return;
    hdht_reply(dht, req, NULL, &req->from, 0, NULL, 0, true);
    return;

  case HDHT_RPC_DELAYED_PING:
    return; // not supported, the requester times out

  default:
    hdht_reply(dht, req, NULL, &req->from, HDHT_RPC_ERR_UNKNOWN_COMMAND, NULL, 0, req->has_target);
  }
}

static void
on_request_message (hdht_t *dht, hdht_socket_t *socket, cdec_t *d, const hdht_addr_t *from) {
  hdht_incoming_t req;
  memset(&req, 0, sizeof(req));
  req.socket = socket;
  req.from = *from;

  uint32_t flags = cdec_uint32(d);
  req.tid = cdec_u16(d);
  cdec_addr(d, &req.to);
  if (flags & 1) {
    const uint8_t *id = cdec_fixed32(d);
    if (id) {
      req.has_id = valid_id(from, id);
      if (req.has_id) memcpy(req.id, id, 32);
    }
  }
  if (flags & 2) {
    const uint8_t *t = cdec_fixed32(d);
    if (t) {
      req.has_token = true;
      memcpy(req.token, t, 32);
    }
  }
  req.internal = (flags & 4) != 0;
  req.command = cdec_uint32(d);
  if (flags & 8) {
    const uint8_t *t = cdec_fixed32(d);
    if (t) {
      req.has_target = true;
      memcpy(req.target, t, 32);
    }
  }
  if (flags & 16) {
    cenc_bytes_t v = cdec_buffer(d);
    req.value = v.data;
    req.value_len = v.len;
  }
  if (d->err) return;

  if (req.has_id) table_add(dht, from, req.id);

  if (req.internal) {
    on_internal_request(dht, &req);
    return;
  }

  if (dht->on_request == NULL || !dht->on_request(dht, &req)) {
    hdht_reply(dht, &req, NULL, &req.from, HDHT_RPC_ERR_UNKNOWN_COMMAND, NULL, 0, req.has_target);
  }
}

static void
on_response_message (hdht_t *dht, cdec_t *d, const hdht_addr_t *from) {
  hdht_response_t res;
  memset(&res, 0, sizeof(res));
  res.from = *from;

  uint32_t flags = cdec_uint32(d);
  uint16_t tid = cdec_u16(d);
  cdec_addr(d, &res.to);
  if (flags & 1) {
    const uint8_t *id = cdec_fixed32(d);
    if (id && valid_id(from, id)) {
      res.has_id = true;
      memcpy(res.id, id, 32);
    }
  }
  if (flags & 2) {
    const uint8_t *t = cdec_fixed32(d);
    if (t) {
      res.has_token = true;
      memcpy(res.token, t, 32);
    }
  }
  if (flags & 4) {
    uint64_t n = cdec_uint(d);
    if (n > 0x100000) d->err = true;
    for (uint64_t i = 0; i < n && !d->err; i++) {
      hdht_addr_t a;
      cdec_addr(d, &a);
      if (res.closer_len < HDHT_K) res.closer[res.closer_len++] = a;
    }
  }
  if (flags & 8) res.error = cdec_uint32(d);
  if (flags & 16) {
    cenc_bytes_t v = cdec_buffer(d);
    res.value = v.data;
    res.value_len = v.len;
  }
  if (d->err) return;

  hdht_request_t *req = NULL;
  for (hdht_request_t *r = dht->requests; r != NULL; r = r->next) {
    if (r->tid == tid) {
      req = r;
      break;
    }
  }
  if (req == NULL) return;

  unlink_request(req);
  dht->stats.responses++;
  if (res.has_id) table_add(dht, from, res.id);

  res.status = HDHT_OK;
  res.rtt = (uint32_t) (uv_now(dht->loop) - req->first_sent);
  req->on_response(req, &res);
  free_request(req);

  reap_queries(dht);
  schedule_request_timer(dht);
}

static void
on_message (hdht_t *dht, hdht_socket_t *socket, const uint8_t *buf, size_t len, const hdht_addr_t *from) {
  if (dht->destroyed || len < 2) return;
  dht->stats.received++;

  cdec_t d;
  cdec_init(&d, buf, len);
  uint8_t type = cdec_u8(&d);

  if (type == REQUEST_ID) on_request_message(dht, socket, &d, from);
  else if (type == RESPONSE_ID) on_response_message(dht, &d, from);
}

// queries

static bool
query_is_closer (hdht_query_t *q, const uint8_t id[32]) {
  return q->closest_len < HDHT_K || xor_compare(q->target, id, q->closest[q->closest_len - 1].id) < 0;
}

static int
query_seen_index (hdht_query_t *q, const hdht_addr_t *addr) {
  for (int i = 0; i < q->seen_len; i++) {
    if (hdht_addr_eq(&q->seen[i], addr)) return i;
  }
  return -1;
}

// Returns whether the node is closer than the current k-th reply.
static bool
query_add_pending (hdht_query_t *q, const hdht_addr_t *addr, const uint8_t id[32]) {
  bool closer = query_is_closer(q, id);
  if (query_seen_index(q, addr) >= 0) return closer;
  if (!closer) return false;
  if (q->seen_len >= HDHT_QUERY_SEEN_MAX) return false;

  q->seen[q->seen_len++] = *addr;

  if (q->pending_len == HDHT_QUERY_PENDING_MAX) {
    // drop the farthest pending node to make room
    int far = 0;
    for (int i = 1; i < q->pending_len; i++) {
      if (xor_compare(q->target, q->pending[i].id, q->pending[far].id) > 0) far = i;
    }
    if (xor_compare(q->target, id, q->pending[far].id) >= 0) return closer;
    q->pending[far] = q->pending[--q->pending_len];
  }

  hdht_query_peer_t *p = &q->pending[q->pending_len++];
  p->addr = *addr;
  memcpy(p->id, id, 32);
  return closer;
}

static void
query_push_closest (hdht_query_t *q, const hdht_response_t *res) {
  for (int i = 0; i < q->closest_len; i++) {
    if (memcmp(q->closest[i].id, res->id, 32) == 0) return;
  }

  int j = q->closest_len < HDHT_K ? q->closest_len++ : HDHT_K - 1;
  while (j > 0 && xor_compare(q->target, res->id, q->closest[j - 1].id) < 0) {
    q->closest[j] = q->closest[j - 1];
    j--;
  }

  hdht_reply_ref_t *r = &q->closest[j];
  r->from = res->from;
  r->to = res->to;
  memcpy(r->id, res->id, 32);
  r->has_token = res->has_token;
  if (res->has_token) memcpy(r->token, res->token, 32);
}

static void
query_add_from_table (hdht_query_t *q) {
  q->from_table = true;

  const hdht_node_t *closest[HDHT_K];
  int n = table_closest(q->dht, q->target, closest, HDHT_K);
  // add farthest first so the closest are popped first
  for (int i = n - 1; i >= 0; i--) query_add_pending(q, &closest[i]->addr, closest[i]->id);
}

static void
query_add_bootstrap (hdht_query_t *q) {
  hdht_t *dht = q->dht;
  for (int i = dht->bootstrap_len - 1; i >= 0; i--) {
    uint8_t id[32];
    hdht_node_id(id, &dht->bootstrap[i]);
    query_add_pending(q, &dht->bootstrap[i], id);
  }
}

static void
on_query_response (hdht_request_t *req, const hdht_response_t *res) {
  hdht_query_t *q = req->data;
  q->inflight--;
  if (q->destroyed) return;

  if (res->status != HDHT_OK) {
    q->errors++;
    query_read_more(q);
    return;
  }

  if (res->error == 0) q->successes++;
  else q->errors++;

  if (res->error == 0 && res->has_id && query_is_closer(q, res->id)) query_push_closest(q, res);

  for (int i = 0; i < res->closer_len; i++) {
    uint8_t id[32];
    hdht_node_id(id, &res->closer[i]);
    if (memcmp(id, q->dht->table_id, 32) == 0) continue;
    if (!query_add_pending(q, &res->closer[i], id)) break;
  }

  if (res->error == 0 && q->on_reply) q->on_reply(q, res);
  if (q->destroyed) return;

  query_read_more(q);
}

static void
query_visit (hdht_query_t *q, const hdht_query_peer_t *peer) {
  hdht_request_t *req = hdht_request(q->dht, NULL, &peer->addr, q->internal, q->command, q->target, NULL, q->value, q->value_len, on_query_response, q);
  if (req == NULL) {
    q->errors++;
    return;
  }
  req->retries = q->retries;
  q->inflight++;
}

static void
query_read_more (hdht_query_t *q) {
  if (q->destroyed || q->done) return;

  while (q->inflight < q->concurrency && q->pending_len > 0) {
    hdht_query_peer_t next = q->pending[--q->pending_len];
    if (!query_is_closer(q, next.id)) continue;
    query_visit(q, &next);
  }

  if (q->pending_len > 0 || q->inflight > 0) return;

  if (!q->from_table && q->successes < HDHT_K / 4) {
    query_add_from_table(q);
    if (q->pending_len > 0) {
      query_read_more(q);
      return;
    }
  }

  q->done = true;
  if (q->on_done) q->on_done(q, q->closest_len > 0 ? HDHT_OK : HDHT_ETIMEDOUT);
}

hdht_query_t *
hdht_query (hdht_t *dht, const uint8_t target[32], bool internal, uint32_t command, const uint8_t *value, size_t value_len, const hdht_addr_t *nodes, size_t nodes_len, hdht_query_reply_cb on_reply, hdht_query_done_cb on_done, void *data) {
  if (dht->destroyed) return NULL;

  hdht_query_t *q = calloc(1, sizeof(hdht_query_t));
  if (q == NULL) return NULL;

  if (value != NULL) {
    q->value = malloc(value_len ? value_len : 1);
    if (q->value == NULL) {
      free(q);
      return NULL;
    }
    memcpy(q->value, value, value_len);
    q->value_len = value_len;
  }

  q->dht = dht;
  memcpy(q->target, target, 32);
  q->command = command;
  q->internal = internal;
  q->concurrency = QUERY_CONCURRENCY;
  q->retries = QUERY_RETRIES;
  q->on_reply = on_reply;
  q->on_done = on_done;
  q->data = data;

  q->next = dht->queries;
  dht->queries = q;

  if (nodes_len > 0) {
    for (size_t i = nodes_len; i > 0; i--) {
      uint8_t id[32];
      hdht_node_id(id, &nodes[i - 1]);
      query_add_pending(q, &nodes[i - 1], id);
    }
  } else {
    query_add_from_table(q);
    if (q->pending_len < HDHT_K) query_add_bootstrap(q);
  }

  query_read_more(q);
  return q;
}

void
hdht_query_destroy (hdht_query_t *q) {
  if (q->destroyed) return;
  q->destroyed = true;

  hdht_t *dht = q->dht;
  for (hdht_request_t *r = dht->requests; r != NULL;) {
    hdht_request_t *next = r->next;
    if (r->on_response == on_query_response && r->data == q) {
      unlink_request(r);
      free_request(r);
      q->inflight--;
    }
    r = next;
  }
  schedule_request_timer(dht);
}

static void
reap_queries (hdht_t *dht) {
  for (hdht_query_t **p = &dht->queries; *p != NULL;) {
    hdht_query_t *q = *p;
    if ((q->done || q->destroyed) && q->inflight == 0) {
      *p = q->next;
      free(q->value);
      free(q);
    } else {
      p = &q->next;
    }
  }
}

// tick

static void
on_refresh_done (hdht_query_t *q, int status) {
  (void) q;
  (void) status;
}

static void
on_tick (uv_timer_t *timer) {
  hdht_t *dht = timer->data;
  dht->ticks++;

  bool sparse = dht->table_len < HDHT_K / 2;
  if ((sparse && dht->ticks % SPARSE_REFRESH_TICK == 0) || dht->ticks % REFRESH_TICKS == 0) {
    uint8_t target[32];
    randombytes_buf(target, sizeof(target));
    hdht_query_t *q = hdht_query(dht, target, true, HDHT_RPC_FIND_NODE, NULL, 0, NULL, 0, NULL, on_refresh_done, NULL);
    if (q) q->concurrency = 3;
  }

  reap_queries(dht);
}

// lifecycle

int
hdht_dht_init (hdht_t *dht, uv_loop_t *loop, uint16_t port) {
  memset(dht, 0, sizeof(*dht));
  dht->loop = loop;
  dht->next_tid = (uint16_t) randombytes_uniform(65536);
  randombytes_buf(dht->table_id, sizeof(dht->table_id));

  int err = udx_init(loop, &dht->udx, NULL);
  if (err) return err;

  err = hdht_socket_open(dht, &dht->socket, port);
  if (err) return err;

  uv_timer_init(loop, &dht->request_timer);
  dht->request_timer.data = dht;
  uv_timer_init(loop, &dht->tick_timer);
  dht->tick_timer.data = dht;
  uv_timer_start(&dht->tick_timer, on_tick, TICK_MS, TICK_MS);

  return 0;
}

void
hdht_dht_add_bootstrap (hdht_t *dht, const hdht_addr_t *addr) {
  if (dht->bootstrap_len < HDHT_MAX_BOOTSTRAP) dht->bootstrap[dht->bootstrap_len++] = *addr;
}

static void
maybe_destroyed (hdht_t *dht) {
  if (--dht->pending_closes > 0) return;
  if (dht->on_destroyed) dht->on_destroyed(dht);
}

static void
on_timer_close (uv_handle_t *handle) {
  maybe_destroyed(handle->data);
}

static void
on_main_socket_close (hdht_socket_t *socket) {
  maybe_destroyed(socket->dht);
}

void
hdht_dht_destroy (hdht_t *dht, void (*on_destroyed)(hdht_t *dht)) {
  if (dht->destroyed) return;
  dht->destroyed = true;
  dht->on_destroyed = on_destroyed;

  for (hdht_query_t *q = dht->queries; q != NULL; q = q->next) {
    q->destroyed = true;
    q->inflight = 0;
  }

  while (dht->requests != NULL) {
    hdht_request_t *r = dht->requests;
    dht->requests = r->next;
    free_request(r);
  }
  dht->inflight = 0;
  reap_queries(dht);

  dht->pending_closes = 3;
  uv_timer_stop(&dht->request_timer);
  uv_timer_stop(&dht->tick_timer);
  uv_close((uv_handle_t *) &dht->request_timer, on_timer_close);
  uv_close((uv_handle_t *) &dht->tick_timer, on_timer_close);
  hdht_socket_close(&dht->socket, on_main_socket_close);
}
