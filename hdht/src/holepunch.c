#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "holepunch.h"
#include "messages.h"

#define HOLEPUNCH_TTL     5
#define CONSISTENT_TRIES  10
#define CONSISTENT_EVERY  1000
#define RANDOM_TRIES      1750 // ~35 s
#define RANDOM_EVERY      20

enum {
  PUNCH_NONE,
  PUNCH_CONSISTENT,
  PUNCH_RANDOM,
};

static const uint8_t PROBE[1] = {0};

// address classes (npm "bogon")

bool
hdht_ip_is_private (const uint8_t ip[4]) {
  return ip[0] == 10 ||
         (ip[0] == 100 && ip[1] >= 64 && ip[1] <= 127) ||
         ip[0] == 127 ||
         (ip[0] == 169 && ip[1] == 254) ||
         (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) ||
         (ip[0] == 192 && ip[1] == 168);
}

bool
hdht_ip_is_reserved (const uint8_t ip[4]) {
  return ip[0] == 0 ||
         (ip[0] == 192 && ip[1] == 0 && (ip[2] == 0 || ip[2] == 2)) ||
         (ip[0] == 198 && (ip[1] == 18 || ip[1] == 19)) ||
         (ip[0] == 198 && ip[1] == 51 && ip[2] == 100) ||
         (ip[0] == 203 && ip[1] == 0 && ip[2] == 113) ||
         ip[0] >= 224;
}

// NAT analysis

static void
add_sample (hdht_nat_sample_t *samples, uint8_t *len, const uint8_t ip[4], uint16_t port) {
  for (int i = 0; i < *len; i++) {
    hdht_nat_sample_t *s = &samples[i];
    if (s->addr.port != port || memcmp(s->addr.ip, ip, 4) != 0) continue;
    s->hits++;
    // keep sorted by hits, highest first
    for (; i > 0 && samples[i - 1].hits < samples[i].hits; i--) {
      hdht_nat_sample_t tmp = samples[i - 1];
      samples[i - 1] = samples[i];
      samples[i] = tmp;
    }
    return;
  }

  if (*len == HDHT_NAT_SAMPLES) return;
  hdht_nat_sample_t *s = &samples[(*len)++];
  memcpy(s->addr.ip, ip, 4);
  s->addr.port = port;
  s->hits = 1;
}

static void
nat_update (hdht_nat_t *nat) {
  if (nat->sampled >= 3) {
    uint8_t max = nat->full[0].hits;

    if (max >= 3) nat->firewall = HDHT_FIREWALL_CONSISTENT;
    else if (max == 1) nat->firewall = HDHT_FIREWALL_RANDOM;
    else if (nat->host_len == 1 && nat->sampled > 3) nat->firewall = HDHT_FIREWALL_RANDOM;
    else if (nat->host_len > 1 && nat->full_len > 1 && nat->full[1].hits > 1) nat->firewall = HDHT_FIREWALL_CONSISTENT;
    else if (nat->sampled > 4) nat->firewall = HDHT_FIREWALL_RANDOM;
  }

  nat->has_addresses = false;
  nat->addresses_len = 0;

  if (nat->firewall == HDHT_FIREWALL_RANDOM) {
    nat->has_addresses = true;
    nat->addresses[nat->addresses_len++] = nat->host[0].addr;
  } else if (nat->firewall == HDHT_FIREWALL_CONSISTENT) {
    nat->has_addresses = true;
    for (int i = 0; i < nat->full_len; i++) {
      if (nat->full[i].hits >= 2 || nat->addresses_len < 2) nat->addresses[nat->addresses_len++] = nat->full[i].addr;
    }
  }
}

void
hdht_nat_add (hdht_nat_t *nat, const hdht_addr_t *addr, const hdht_addr_t *from) {
  for (int i = 0; i < nat->visited_len; i++) {
    if (hdht_addr_eq(&nat->visited[i], from)) return;
  }
  if (nat->visited_len < HDHT_NAT_SAMPLES) nat->visited[nat->visited_len++] = *from;

  add_sample(nat->host, &nat->host_len, addr->ip, 0);
  add_sample(nat->full, &nat->full_len, addr->ip, addr->port);

  nat->sampled++;
  if (nat->sampled >= 3 && !nat->frozen) nat_update(nat);
}

// sampling

static void
check_analyzed (hdht_puncher_t *p) {
  if (p->analyzed || p->destroyed) return;

  bool consistent = p->nat.firewall == HDHT_FIREWALL_CONSISTENT || p->nat.firewall == HDHT_FIREWALL_OPEN;
  if (!consistent && p->nat.sampled < HDHT_NAT_MIN_SAMPLES && p->sample_pending > 0) return;

  p->analyzed = true;
  if (p->on_analyzed) p->on_analyzed(p);
}

static void
start_sampling (hdht_puncher_t *p);

static void
on_sample (hdht_request_t *req, const hdht_response_t *res) {
  hdht_puncher_t *p = req->data;

  for (int i = 0; i < HDHT_NAT_MIN_SAMPLES; i++) {
    if (p->samples[i] == req) p->samples[i] = NULL;
  }
  p->sample_pending--;

  if (res->status == HDHT_OK) hdht_nat_add(&p->nat, &res->to, &res->from);

  if (p->sample_pending == 0 && p->nat.sampled < HDHT_NAT_MIN_SAMPLES && !p->sample_retried && !p->analyzed) {
    p->sample_retried = true;
    start_sampling(p);
    if (p->sample_pending > 0) return;
  }

  check_analyzed(p);
}

static bool
already_visited (hdht_puncher_t *p, const hdht_addr_t *addr) {
  for (int i = 0; i < p->nat.visited_len; i++) {
    if (hdht_addr_eq(&p->nat.visited[i], addr)) return true;
  }
  for (int i = 0; i < HDHT_NAT_MIN_SAMPLES; i++) {
    if (p->samples[i] && hdht_addr_eq(&p->samples[i]->to, addr)) return true;
  }
  return false;
}

static void
sample_node (hdht_puncher_t *p, const hdht_addr_t *addr) {
  int slot = -1;
  for (int i = 0; i < HDHT_NAT_MIN_SAMPLES; i++) {
    if (p->samples[i] == NULL) {
      slot = i;
      break;
    }
  }
  if (slot < 0 || already_visited(p, addr)) return;

  hdht_request_t *req = hdht_request(p->dht, p->socket, addr, true, HDHT_RPC_PING, NULL, NULL, NULL, 0, on_sample, p);
  if (req == NULL) return;
  req->retries = 0;
  p->samples[slot] = req;
  p->sample_pending++;
}

// Pings recently seen nodes from the puncher socket (nat.js autoSample).
static void
start_sampling (hdht_puncher_t *p) {
  hdht_t *dht = p->dht;
  int want = HDHT_NAT_MIN_SAMPLES - p->nat.sampled - p->sample_pending;

  // most recently seen first
  bool used[HDHT_TABLE_SIZE] = {false};
  int skip = dht->table_len >= 8 ? 5 : 0;
  for (int n = 0; n < dht->table_len && want > 0; n++) {
    int best = -1;
    for (int i = 0; i < dht->table_len; i++) {
      if (used[i]) continue;
      if (best < 0 || dht->table[i].seen > dht->table[best].seen) best = i;
    }
    used[best] = true;
    if (skip > 0) {
      skip--;
      continue;
    }
    int before = p->sample_pending;
    sample_node(p, &dht->table[best].addr);
    if (p->sample_pending > before) want--;
  }

  for (int i = 0; i < dht->bootstrap_len && want > 0; i++) {
    int before = p->sample_pending;
    sample_node(p, &dht->bootstrap[i]);
    if (p->sample_pending > before) want--;
  }
}

// probes

void
hdht_puncher_probe (hdht_puncher_t *p, const hdht_addr_t *to, bool low_ttl) {
  if (p->destroyed || p->socket == NULL) return;
  hdht_socket_send(p->socket, to, PROBE, 1, low_ttl ? HOLEPUNCH_TTL : 0);
}

static void
on_probe (hdht_socket_t *socket, const hdht_addr_t *from) {
  hdht_puncher_t *p = socket->data;
  if (p == NULL || p->destroyed) return;

  if (!p->initiator) {
    hdht_puncher_probe(p, from, false); // echo so the initiator learns the path works
    return;
  }

  if (p->connected) return;
  p->connected = true;
  p->punching = false;
  uv_timer_stop(&p->timer);
  if (p->on_connect) p->on_connect(p, from);
}

static void
give_up (hdht_puncher_t *p) {
  p->punching = false;
  uv_timer_stop(&p->timer);
  if (!p->connected && p->on_abort) p->on_abort(p);
}

static void
on_punch_timer (uv_timer_t *timer) {
  hdht_puncher_t *p = timer->data;
  if (!p->punching || p->destroyed) return;

  p->tries++;

  if (p->punch_mode == PUNCH_CONSISTENT) {
    if (p->tries > CONSISTENT_TRIES) {
      give_up(p);
      return;
    }
    for (int i = 0; i < p->remote_len; i++) {
      // unverified addresses only every 4th round
      if (!p->remote[i].verified && (p->tries & 3) != 0) continue;
      hdht_puncher_probe(p, &p->remote[i].addr, false);
    }
    return;
  }

  if (p->tries > RANDOM_TRIES) {
    give_up(p);
    return;
  }
  hdht_addr_t to = p->random_target;
  to.port = (uint16_t) (1000 + randombytes_uniform(64536));
  hdht_puncher_probe(p, &to, false);
}

static uint32_t
coerce (uint32_t firewall) {
  return firewall == HDHT_FIREWALL_OPEN ? HDHT_FIREWALL_CONSISTENT : firewall;
}

bool
hdht_puncher_punch (hdht_puncher_t *p) {
  if (p->destroyed || p->connected) return false;
  if (p->punching) return true;
  if (p->remote_len == 0) return false;

  uint32_t local = coerce(p->nat.firewall);
  uint32_t remote = coerce(p->remote_firewall);

  const hdht_remote_addr_t *verified = NULL;
  for (int i = 0; i < p->remote_len; i++) {
    if (p->remote[i].verified) {
      verified = &p->remote[i];
      break;
    }
  }

  if (local == HDHT_FIREWALL_CONSISTENT && remote == HDHT_FIREWALL_CONSISTENT) {
    p->punch_mode = PUNCH_CONSISTENT;
  } else if (local == HDHT_FIREWALL_CONSISTENT && remote >= HDHT_FIREWALL_RANDOM && verified) {
    p->punch_mode = PUNCH_RANDOM;
    p->random_target = verified->addr;
  } else {
    return false; // a random local NAT would need many sockets
  }

  p->punching = true;
  p->tries = 0;

  if (p->punch_mode == PUNCH_CONSISTENT) {
    // the responder waits a beat: the initiator's fast-open probe may already be on its way
    uint64_t first = p->initiator ? 0 : CONSISTENT_EVERY;
    uv_timer_start(&p->timer, on_punch_timer, first, CONSISTENT_EVERY);
  } else {
    uv_timer_start(&p->timer, on_punch_timer, 0, RANDOM_EVERY);
  }
  return true;
}

// remote state

void
hdht_puncher_update_remote (hdht_puncher_t *p, bool punching, uint32_t firewall, const hdht_addr_t *addresses, uint8_t addresses_len, const uint8_t *verified_ip) {
  hdht_remote_addr_t next[HDHT_NAT_SAMPLES];
  uint8_t next_len = 0;

  for (int i = 0; i < addresses_len && next_len < HDHT_NAT_SAMPLES; i++) {
    bool verified = verified_ip && memcmp(verified_ip, addresses[i].ip, 4) == 0;
    for (int j = 0; j < p->remote_len && !verified; j++) {
      if (p->remote[j].verified && memcmp(p->remote[j].addr.ip, addresses[i].ip, 4) == 0) verified = true;
    }
    next[next_len].addr = addresses[i];
    next[next_len].verified = verified;
    next_len++;
  }

  memcpy(p->remote, next, sizeof(next));
  p->remote_len = next_len;
  p->remote_firewall = firewall;
  p->remote_punching = punching;
}

void
hdht_puncher_add_sample (hdht_puncher_t *p, const hdht_addr_t *to, const hdht_addr_t *from) {
  hdht_nat_add(&p->nat, to, from);
  check_analyzed(p);
}

bool
hdht_puncher_unstable (hdht_puncher_t *p) {
  uint32_t fw = p->nat.firewall;
  return (p->remote_firewall >= HDHT_FIREWALL_RANDOM && fw >= HDHT_FIREWALL_RANDOM) || fw == HDHT_FIREWALL_UNKNOWN;
}

// lifecycle

hdht_puncher_t *
hdht_puncher_create (hdht_t *dht, bool initiator, uint32_t remote_firewall, void *data) {
  hdht_puncher_t *p = calloc(1, sizeof(hdht_puncher_t));
  if (p == NULL) return NULL;

  p->socket = calloc(1, sizeof(hdht_socket_t));
  if (p->socket == NULL || hdht_socket_open(dht, p->socket, 0) != 0) {
    free(p->socket); // a failed open leaves nothing to close
    free(p);
    return NULL;
  }

  p->dht = dht;
  p->initiator = initiator;
  p->remote_firewall = remote_firewall;
  p->data = data;
  p->socket->data = p;
  p->socket->on_probe = on_probe;

  uv_timer_init(dht->loop, &p->timer);
  p->timer.data = p;

  start_sampling(p);
  if (p->sample_pending == 0) p->analyzed = true; // nothing to sample against
  return p;
}

hdht_socket_t *
hdht_puncher_release_socket (hdht_puncher_t *p) {
  hdht_socket_t *socket = p->socket;
  p->socket = NULL;
  p->socket_released = true;
  socket->data = NULL;
  socket->on_probe = NULL;
  return socket;
}

static void
on_released_socket_close (hdht_socket_t *socket) {
  free(socket);
}

static void
on_timer_close (uv_handle_t *handle) {
  free(handle->data);
}

void
hdht_puncher_destroy (hdht_puncher_t *p) {
  if (p->destroyed) return;
  p->destroyed = true;
  p->punching = false;

  for (int i = 0; i < HDHT_NAT_MIN_SAMPLES; i++) {
    if (p->samples[i]) hdht_request_cancel(p->samples[i]);
    p->samples[i] = NULL;
  }

  if (p->socket) {
    p->socket->data = NULL;
    p->socket->on_probe = NULL;
    hdht_socket_close(p->socket, on_released_socket_close);
    p->socket = NULL;
  }

  uv_timer_stop(&p->timer);
  uv_close((uv_handle_t *) &p->timer, on_timer_close);
}
