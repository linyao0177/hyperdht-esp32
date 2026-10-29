// hdht: HyperDHT client and server for constrained devices.
//
// Single-threaded: every call and callback runs on the libuv (or uv_esp)
// loop passed to hdht_init. Interoperates with hyperdht 6.x.

#ifndef HDHT_H
#define HDHT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dht.h"
#include "holepunch.h"
#include "messages.h"
#include "noise.h"
#include "stream.h"

typedef struct hdht_connect_s hdht_connect_t;
typedef struct hdht_server_s hdht_server_t;

typedef struct {
  const char *const *bootstrap; // "ip:port" or "ip@name:port"; NULL = public HyperDHT nodes
  size_t bootstrap_len;
  uint16_t port;          // 0 = any
  const uint8_t *seed;    // 32-byte seed for the default key pair; NULL = random
} hdht_opts_t;

typedef void (*hdht_ready_cb)(hdht_t *dht, int status);

int
hdht_init (hdht_t *dht, uv_loop_t *loop, const hdht_opts_t *opts);

// Joins the DHT (FIND_NODE towards our id). cb runs once.
int
hdht_bootstrap (hdht_t *dht, hdht_ready_cb cb);

// Registers a LAN IPv4 address to share with peers on the same network.
void
hdht_add_local_address (hdht_t *dht, const uint8_t ip[4]);

void
hdht_destroy (hdht_t *dht, void (*on_destroyed)(hdht_t *dht));

void
hdht_keypair (uint8_t public_key[32], uint8_t secret_key[64], const uint8_t *seed);

// client

typedef enum {
  HDHT_CONNECT_EPEER_NOT_FOUND = -100,
  HDHT_CONNECT_EHANDSHAKE = -101,
  HDHT_CONNECT_ESERVER_ERROR = -102,
  HDHT_CONNECT_ECANNOT_HOLEPUNCH = -103,
  HDHT_CONNECT_EHOLEPUNCH = -104,
  HDHT_CONNECT_ETIMEOUT = -105,
  HDHT_CONNECT_ENOMEM = -106,
} hdht_connect_error_t;

// Connects to the server announced under remote_public_key. stream is caller
// memory; on_open runs once the encrypted stream is up, on_close always runs
// last (with a negative error if the connection failed).
int
hdht_connect (hdht_t *dht, hdht_stream_t *stream, const uint8_t remote_public_key[32], hdht_stream_open_cb on_open, hdht_stream_data_cb on_data, hdht_stream_close_cb on_close, void *data);

// server

// The server allocates the stream; set on_data/on_close/data here. The stream
// memory is freed by the server after on_close returns.
typedef void (*hdht_connection_cb)(hdht_server_t *server, hdht_stream_t *stream);

#ifndef HDHT_SERVER_MAX_HANDSHAKES
#define HDHT_SERVER_MAX_HANDSHAKES 4
#endif

#ifndef HDHT_SERVER_RELAYS
#define HDHT_SERVER_RELAYS 3
#endif

typedef struct hdht_server_handshake_s hdht_server_handshake_t;

struct hdht_server_s {
  hdht_t *dht;
  uint8_t public_key[32];
  uint8_t secret_key[64];
  uint8_t target[32];

  hdht_relay_info_t relays[HDHT_SERVER_RELAYS]; // nodes holding our announce
  uint8_t relays_len;
  hdht_reply_ref_t announced[HDHT_SERVER_RELAYS];
  uint8_t announced_len;
  hdht_reply_ref_t next_announced[HDHT_SERVER_RELAYS]; // filled during an announce round
  uint8_t next_announced_len;
  hdht_query_t *query;
  uint8_t announcing;   // pending ANNOUNCE requests
  uint8_t pings_pending;
  uint8_t pings_ok;
  uint32_t cycles;
  bool listening;
  bool closing;
  bool refresh;

  hdht_server_handshake_t *handshakes[HDHT_SERVER_MAX_HANDSHAKES];

  uv_timer_t timer;
  hdht_connection_cb on_connection;
  void (*on_listening)(hdht_server_t *server, int status);
  void (*on_closed)(hdht_server_t *server);
  void *data;
  hdht_server_t *next;

  struct {
    uint32_t announces;
    uint32_t handshakes;
    uint32_t connections;
    uint32_t punches;
  } stats;
};

// Announces the key pair and accepts connections. on_listening runs after the
// first announce round.
int
hdht_listen (hdht_t *dht, hdht_server_t *server, const uint8_t public_key[32], const uint8_t secret_key[64], hdht_connection_cb on_connection, void (*on_listening)(hdht_server_t *server, int status), void *data);

// Unannounces and stops accepting. on_closed runs when done.
void
hdht_server_close (hdht_server_t *server, void (*on_closed)(hdht_server_t *server));

// mutable records (mutable.c)
//
// A value of up to HDHT_MUTABLE_MAX_VALUE bytes signed by an Ed25519 key pair
// and stored on the nodes closest to BLAKE2b(public key), the same records as
// hyperdht's mutablePut / mutableGet. Nodes keep them for up to 48 hours, so
// republish periodically; anyone holding a signed record can republish it.
// A higher seq replaces a lower one; reusing a seq with a different value is
// rejected. An operation still running when the DHT is destroyed never calls back.

#ifndef HDHT_MUTABLE_MAX_VALUE
#define HDHT_MUTABLE_MAX_VALUE 1000
#endif

typedef enum {
  HDHT_MUTABLE_ENOT_FOUND = -110,
  HDHT_MUTABLE_ESEQ_REUSED = -111,
  HDHT_MUTABLE_ESEQ_TOO_LOW = -112,
  HDHT_MUTABLE_ETOO_BIG = -113,
} hdht_mutable_error_t;

// status is 0 when at least one node stored the record; stored counts them.
typedef void (*hdht_mutable_put_cb)(hdht_t *dht, int status, unsigned stored, void *data);

// status is 0 with the highest valid seq found, or HDHT_MUTABLE_ENOT_FOUND.
// value is valid only during the callback.
typedef void (*hdht_mutable_get_cb)(hdht_t *dht, int status, uint64_t seq, const uint8_t *value, size_t len, void *data);

int
hdht_mutable_put (hdht_t *dht, const uint8_t public_key[32], const uint8_t secret_key[64], uint64_t seq, const uint8_t *value, size_t len, hdht_mutable_put_cb cb, void *data);

// Returns only records signed by public_key with seq >= min_seq.
int
hdht_mutable_get (hdht_t *dht, const uint8_t public_key[32], uint64_t min_seq, hdht_mutable_get_cb cb, void *data);

bool
hdht_mutable_verify (const uint8_t public_key[32], uint64_t seq, const uint8_t *value, size_t len, const uint8_t signature[64]);

#endif
