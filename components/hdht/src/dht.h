// dht-rpc for an ephemeral, firewalled node: request/response transport,
// a small routing table and iterative queries. See docs/protocol.md.

#ifndef HDHT_DHT_H
#define HDHT_DHT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <udx.h>
#include <uv.h>

#include "cenc.h"

#ifndef HDHT_K
#define HDHT_K 20
#endif

#ifndef HDHT_TABLE_SIZE
#define HDHT_TABLE_SIZE 32
#endif

#ifndef HDHT_MAX_BOOTSTRAP
#define HDHT_MAX_BOOTSTRAP 4
#endif

#define HDHT_QUERY_PENDING_MAX 48
#define HDHT_QUERY_SEEN_MAX    160

enum {
  HDHT_RPC_PING = 0,
  HDHT_RPC_PING_NAT = 1,
  HDHT_RPC_FIND_NODE = 2,
  HDHT_RPC_DOWN_HINT = 3,
  HDHT_RPC_DELAYED_PING = 4,
};

enum {
  HDHT_RPC_ERR_UNKNOWN_COMMAND = 1,
  HDHT_RPC_ERR_INVALID_TOKEN = 2,
};

// request completion status
enum {
  HDHT_OK = 0,
  HDHT_ETIMEDOUT = -1,
  HDHT_EDESTROYED = -2,
  HDHT_ENOMEM = -3,
};

typedef struct hdht_s hdht_t;
typedef struct hdht_socket_s hdht_socket_t;
typedef struct hdht_request_s hdht_request_t;
typedef struct hdht_query_s hdht_query_t;

// Called for 1-byte holepunch probes received on a socket.
typedef void (*hdht_probe_cb)(hdht_socket_t *socket, const hdht_addr_t *from);

struct hdht_socket_s {
  udx_socket_t udx;
  hdht_t *dht;
  bool bound;
  bool closing;
  uint16_t local_port;
  hdht_probe_cb on_probe;
  void *data;
  void (*on_close)(hdht_socket_t *socket);
};

typedef struct {
  int status; // HDHT_OK or a negative HDHT_E* code
  hdht_addr_t from;
  hdht_addr_t to; // our address as seen by the responder
  bool has_id;
  uint8_t id[32];
  bool has_token;
  uint8_t token[32];
  hdht_addr_t closer[HDHT_K];
  uint8_t closer_len;
  uint32_t error;
  const uint8_t *value; // valid only during the callback
  size_t value_len;
  uint32_t rtt;
} hdht_response_t;

typedef void (*hdht_response_cb)(hdht_request_t *req, const hdht_response_t *res);

struct hdht_request_s {
  hdht_t *dht;
  hdht_socket_t *socket;
  hdht_addr_t to;
  uint16_t tid;
  uint8_t *buf;
  size_t len;
  uint8_t sent;
  uint8_t retries;
  uint32_t timeout_ms;
  uint64_t deadline;
  uint64_t first_sent;
  hdht_response_cb on_response;
  void *data;
  hdht_request_t *next;
};

// An incoming request, valid only during the callback.
typedef struct {
  hdht_socket_t *socket;
  hdht_addr_t from;
  hdht_addr_t to;
  bool has_id;
  uint8_t id[32];
  uint16_t tid;
  bool has_token;
  uint8_t token[32];
  bool internal;
  uint32_t command;
  bool has_target;
  uint8_t target[32];
  const uint8_t *value;
  size_t value_len;
} hdht_incoming_t;

// Return true if handled; otherwise UNKNOWN_COMMAND is sent.
typedef bool (*hdht_request_handler)(hdht_t *dht, const hdht_incoming_t *req);

typedef struct {
  hdht_addr_t addr;
  uint8_t id[32];
  uint64_t seen;
} hdht_node_t;

typedef struct {
  hdht_addr_t from;
  hdht_addr_t to;
  uint8_t id[32];
  uint8_t token[32];
  bool has_token;
} hdht_reply_ref_t;

typedef void (*hdht_query_reply_cb)(hdht_query_t *q, const hdht_response_t *res);
typedef void (*hdht_query_done_cb)(hdht_query_t *q, int status);

typedef struct {
  hdht_addr_t addr;
  uint8_t id[32];
} hdht_query_peer_t;

struct hdht_query_s {
  hdht_t *dht;
  uint8_t target[32];
  uint32_t command;
  bool internal;
  uint8_t *value;
  size_t value_len;

  hdht_reply_ref_t closest[HDHT_K];
  uint8_t closest_len;

  hdht_query_peer_t pending[HDHT_QUERY_PENDING_MAX];
  uint8_t pending_len;

  hdht_addr_t seen[HDHT_QUERY_SEEN_MAX];
  uint16_t seen_len;

  uint8_t inflight;
  uint8_t concurrency;
  uint8_t retries;
  uint16_t successes;
  uint16_t errors;
  bool from_table;
  bool done;
  bool destroyed;

  hdht_query_reply_cb on_reply;
  hdht_query_done_cb on_done;
  void *data;
  hdht_query_t *next;
};

struct hdht_s {
  uv_loop_t *loop;
  udx_t udx;
  hdht_socket_t socket; // main socket: requests out, everything in

  uint8_t table_id[32];
  hdht_node_t table[HDHT_TABLE_SIZE];
  uint8_t table_len;

  hdht_addr_t bootstrap[HDHT_MAX_BOOTSTRAP];
  uint8_t bootstrap_len;

  uint16_t next_tid;
  hdht_request_t *requests;
  uint16_t inflight;
  uv_timer_t request_timer;
  uv_timer_t tick_timer;
  uint32_t ticks;

  hdht_query_t *queries;

  hdht_request_handler on_request;
  void *data;

  // HyperDHT layer (hdht.c)
  uint8_t public_key[32];
  uint8_t secret_key[64];
  hdht_addr_t local_addresses[2]; // LAN IPv4s, port filled from the main socket
  uint8_t local_addresses_len;
  struct hdht_server_s *servers;

  bool destroyed;
  int pending_closes;
  void (*on_destroyed)(hdht_t *dht);

  struct {
    uint32_t requests;
    uint32_t responses;
    uint32_t timeouts;
    uint32_t retries;
    uint32_t received;
  } stats;
};

// lifecycle

int
hdht_dht_init (hdht_t *dht, uv_loop_t *loop, uint16_t port);

void
hdht_dht_destroy (hdht_t *dht, void (*on_destroyed)(hdht_t *dht));

void
hdht_dht_add_bootstrap (hdht_t *dht, const hdht_addr_t *addr);

// sockets (in addition to the main one, e.g. for holepunching)

int
hdht_socket_open (hdht_t *dht, hdht_socket_t *socket, uint16_t port);

void
hdht_socket_close (hdht_socket_t *socket, void (*on_close)(hdht_socket_t *socket));

int
hdht_socket_send (hdht_socket_t *socket, const hdht_addr_t *to, const uint8_t *data, size_t len, int ttl);

// requests

// Sends a request; returns NULL on allocation failure (on_response is not called then).
hdht_request_t *
hdht_request (hdht_t *dht, hdht_socket_t *socket, const hdht_addr_t *to, bool internal, uint32_t command, const uint8_t *target, const uint8_t *token, const uint8_t *value, size_t value_len, hdht_response_cb cb, void *data);

// Cancels without calling the callback.
void
hdht_request_cancel (hdht_request_t *req);

void
hdht_reply (hdht_t *dht, const hdht_incoming_t *req, hdht_socket_t *socket, const hdht_addr_t *to, uint32_t error, const uint8_t *value, size_t value_len, bool closer_nodes);

// Forwards a request with the same tid to another address (dht-rpc relay).
void
hdht_relay (hdht_t *dht, const hdht_incoming_t *req, hdht_socket_t *socket, const hdht_addr_t *to, const uint8_t *value, size_t value_len);

// queries

// Seeds from the routing table and bootstrap nodes unless nodes are given.
hdht_query_t *
hdht_query (hdht_t *dht, const uint8_t target[32], bool internal, uint32_t command, const uint8_t *value, size_t value_len, const hdht_addr_t *nodes, size_t nodes_len, hdht_query_reply_cb on_reply, hdht_query_done_cb on_done, void *data);

// Stops issuing requests; on_done is not called afterwards.
void
hdht_query_destroy (hdht_query_t *q);

// helpers

void
hdht_addr_to_sockaddr (const hdht_addr_t *a, struct sockaddr_in *out);

void
hdht_addr_from_sockaddr (hdht_addr_t *a, const struct sockaddr *in);

int
hdht_addr_parse (hdht_addr_t *a, const char *host, uint16_t port);

// "a.b.c.d:port" for logs; returns a static buffer (not reentrant).
const char *
hdht_addr_str (const hdht_addr_t *a);

#endif
