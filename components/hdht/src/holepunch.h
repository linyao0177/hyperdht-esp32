// NAT analysis and UDP holepunching (hyperdht/lib/nat.js, holepuncher.js).
//
// Differences from the JS: one socket per puncher (no birthday-paradox
// sockets, so a local RANDOM NAT cannot punch) and no socket re-opening.

#ifndef HDHT_HOLEPUNCH_H
#define HDHT_HOLEPUNCH_H

#include <stdbool.h>
#include <stdint.h>

#include "dht.h"

#define HDHT_NAT_SAMPLES     8
#define HDHT_NAT_MIN_SAMPLES 4

typedef struct {
  hdht_addr_t addr;
  uint8_t hits;
} hdht_nat_sample_t;

typedef struct {
  hdht_nat_sample_t host[HDHT_NAT_SAMPLES]; // port 0
  uint8_t host_len;
  hdht_nat_sample_t full[HDHT_NAT_SAMPLES];
  uint8_t full_len;
  hdht_addr_t visited[HDHT_NAT_SAMPLES];
  uint8_t visited_len;
  uint8_t sampled;
  bool frozen;
  uint32_t firewall;
  bool has_addresses;
  hdht_addr_t addresses[HDHT_NAT_SAMPLES];
  uint8_t addresses_len;
} hdht_nat_t;

typedef struct hdht_puncher_s hdht_puncher_t;

typedef void (*hdht_puncher_cb)(hdht_puncher_t *p);
typedef void (*hdht_puncher_connect_cb)(hdht_puncher_t *p, const hdht_addr_t *from);

typedef struct {
  hdht_addr_t addr;
  bool verified;
} hdht_remote_addr_t;

struct hdht_puncher_s {
  hdht_t *dht;
  hdht_socket_t *socket; // heap allocated; handed to the stream on connect
  bool initiator;

  hdht_nat_t nat;
  bool analyzed;
  uint8_t sample_pending;
  bool sample_retried;
  hdht_request_t *samples[HDHT_NAT_MIN_SAMPLES];

  uint32_t remote_firewall;
  hdht_remote_addr_t remote[HDHT_NAT_SAMPLES];
  uint8_t remote_len;
  bool remote_punching;

  bool punching;
  bool connected;
  bool destroyed;
  uint8_t punch_mode;
  uint32_t tries;
  hdht_addr_t random_target; // verified host for random probing
  uv_timer_t timer;
  bool timer_closed;
  bool socket_released;

  hdht_puncher_cb on_analyzed;      // NAT analysis finished
  hdht_puncher_connect_cb on_connect; // initiator: first probe received
  hdht_puncher_cb on_abort;          // punching gave up
  void *data;
};

// Allocates a puncher with its own socket and starts NAT sampling.
hdht_puncher_t *
hdht_puncher_create (hdht_t *dht, bool initiator, uint32_t remote_firewall, void *data);

// Feeds a NAT sample seen on the puncher socket (reply.to from reply.from).
void
hdht_puncher_add_sample (hdht_puncher_t *p, const hdht_addr_t *to, const hdht_addr_t *from);

void
hdht_puncher_update_remote (hdht_puncher_t *p, bool punching, uint32_t firewall, const hdht_addr_t *addresses, uint8_t addresses_len, const uint8_t *verified_ip);

// true while both sides are unusable for a direct path (unknown, or both random)
bool
hdht_puncher_unstable (hdht_puncher_t *p);

// Sends one probe (low TTL opens a NAT session without reaching the peer).
void
hdht_puncher_probe (hdht_puncher_t *p, const hdht_addr_t *to, bool low_ttl);

// Starts the probe loop. Returns false if this NAT combination cannot punch.
bool
hdht_puncher_punch (hdht_puncher_t *p);

// Gives the socket to the caller (the stream) so destroy does not close it.
hdht_socket_t *
hdht_puncher_release_socket (hdht_puncher_t *p);

// Stops everything and frees the puncher asynchronously. Callbacks stop.
void
hdht_puncher_destroy (hdht_puncher_t *p);

void
hdht_nat_add (hdht_nat_t *nat, const hdht_addr_t *addr, const hdht_addr_t *from);

bool
hdht_ip_is_private (const uint8_t ip[4]);

bool
hdht_ip_is_reserved (const uint8_t ip[4]);

#endif
