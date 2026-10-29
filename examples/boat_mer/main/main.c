// BoAT MER on hyperdht-esp32: one key pair, reachable by DID, paying over HyperDHT.
//
// - BoAT MER creates and keeps the device keys (NVS namespace "boat_mer"). Its
//   Ed25519 key is used unchanged as the HyperDHT key pair, so the device's DID,
//   did:mw:<ed25519 public key>, is also its HyperDHT address.
// - Server: anyone can connect by DID. The device answers with a reading
//   attested by MER (SHA-256 + Ed25519) and ends the stream.
// - Buyer (CONFIG_MER_SELLER_KEY): MER's nanopayment buyer engine runs over a
//   HyperDHT stream instead of BLE GATT. It reads the seller's power, opens a
//   paying stream, validates every slice and signs an EIP-3009 authorization
//   for it on the device. Nothing is settled here; the seller only verifies.
// - Anchoring (CONFIG_MER_ANCHOR_NODES): signed readings go to several open
//   anchor nodes instead of one HashAnchor server; see anchor.c.
// - DID record: the device publishes {"v":1,"did","eth","eth_sig"} as a
//   HyperDHT mutable record under its DID key. eth_sig is an EIP-191 signature
//   of the DID by the device's secp256k1 key, so the record binds the DID and
//   the wallet both ways, and anyone can check it without a registry. Before
//   paying, the buyer reads the seller's record and only accepts slices whose
//   payee is the seller's own wallet.
//
// Wire: each HyperDHT message carries one GATT operation of MER's 0xEE00
// protocol, unchanged:
//   op (1 byte) | characteristic uuid16 (LE) | value
// op 1 = write, 2 = read, 3 = read result (value = status byte + data),
// 4 = notify. tools/host/mer-seller.js is the other end.

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "protocol_examples_common.h"

#include "boat_attest.h"
#include "boat_buyer_nanopay.h"
#include "boat_crypto.h"
#include "hdht.h"
#include "mer.h"

enum {
  OP_WRITE = 1,
  OP_READ = 2,
  OP_READ_RESULT = 3,
  OP_NOTIFY = 4,
};

#define MAX_VALUE 512 // the 0xEE04 proof JSON is ~400 bytes

#define RECORD_REPUBLISH_S 1800 // nodes keep mutable records for up to 48 hours

static uv_loop_t loop;
hdht_t dht;
static hdht_server_t server;
boat_keypair_t kp;

static char record[320]; // our DID record (283 bytes), the same bytes on every boot
static size_t record_len;
static uint64_t record_seq; // 0 until we know the seq stored in the DHT
static bool record_published;
static int64_t record_started;

static uint8_t payee[20]; // the seller's wallet, from its DID record
static uint32_t payee_rejects;

static boat_buyer_ctx_t buyer; // ~33 KB (replay-guard set): must be static
static hdht_stream_t seller;
static uint8_t seller_key[32];
static bool has_seller;
static bool seller_up;   // stream open, engine connected
static bool seller_busy; // connecting or open
static uint32_t ticks_down;
static uint32_t ticks;
static int64_t notify_started;

void
log_heap (const char *at) {
  printf("MER|heap at=%s free=%u min=%u largest=%u stack_free=%u\n", at, (unsigned) heap_caps_get_free_size(MALLOC_CAP_8BIT), (unsigned) heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT), (unsigned) heap_caps_get_largest_free_block(MALLOC_CAP_8BIT), (unsigned) uxTaskGetStackHighWaterMark(NULL));
}

// DID record

// keccak256("\x19Ethereum Signed Message:\n" + len + msg), as personal_sign
static void
eip191_digest (const char *msg, uint8_t out[32]) {
  char buf[128];
  int n = snprintf(buf, sizeof(buf), "\x19"
                                     "Ethereum Signed Message:\n%u%s",
                   (unsigned) strlen(msg), msg);
  boat_keccak256((const uint8_t *) buf, (size_t) n, out);
}

static void
build_record (void) {
  uint8_t digest[32], sig[65];
  eip191_digest(kp.did, digest);
  int64_t t0 = esp_timer_get_time();
  boat_secp256k1_sign(&kp, digest, sig);
  long ms = (long) ((esp_timer_get_time() - t0) / 1000);

  char sig_hex[131];
  boat_bytes_to_hex(sig, 65, sig_hex);
  int n = snprintf(record, sizeof(record), "{\"v\":1,\"did\":\"%s\",\"eth\":\"%s\",\"eth_sig\":\"0x%s\"}", kp.did, kp.eth_addr_hex, sig_hex);
  record_len = n > 0 && (size_t) n < sizeof(record) ? (size_t) n : 0;
  printf("MER|record built len=%u eth_sign_ms=%ld\n", (unsigned) record_len, ms);
}

bool
json_str (const char *json, const char *key, char *out, size_t cap) {
  char pattern[24];
  snprintf(pattern, sizeof(pattern), "\"%s\":\"", key);
  const char *p = strstr(json, pattern);
  if (p == NULL) return false;
  p += strlen(pattern);
  const char *end = strchr(p, '"');
  if (end == NULL || (size_t) (end - p) >= cap) return false;
  memcpy(out, p, end - p);
  out[end - p] = '\0';
  return true;
}

bool
verify_record (const uint8_t public_key[32], const uint8_t *value, size_t len, uint8_t eth[20]) {
  static char json[HDHT_MUTABLE_MAX_VALUE + 1]; // off the loop task's stack
  memcpy(json, value, len);
  json[len] = '\0';

  char did[80], expected[80], eth_hex[48], sig_hex[136];
  char hex[65];
  sodium_bin2hex(hex, sizeof(hex), public_key, 32);
  snprintf(expected, sizeof(expected), "did:mw:%s", hex);
  if (!json_str(json, "did", did, sizeof(did)) || strcmp(did, expected) != 0) return false;
  if (!json_str(json, "eth", eth_hex, sizeof(eth_hex)) || !json_str(json, "eth_sig", sig_hex, sizeof(sig_hex))) return false;

  uint8_t sig[65], claimed[20], recovered[20], digest[32];
  if (boat_hex_to_bytes(eth_hex, claimed, 20) != 20 || boat_hex_to_bytes(sig_hex, sig, 65) != 65) return false;
  eip191_digest(did, digest);
  if (boat_secp256k1_ecrecover(digest, sig, recovered) != BOAT_OK) return false;
  if (memcmp(recovered, claimed, 20) != 0) return false;

  memcpy(eth, claimed, 20);
  return true;
}

static void
resolve_seller (void);

static void
on_record_put (hdht_t *d, int status, unsigned stored, void *data) {
  (void) d;
  (void) data;
  printf("MER|record put status=%d stored=%u seq=%llu ms=%ld\n", status, stored, (unsigned long long) record_seq, (long) ((esp_timer_get_time() - record_started) / 1000));
  if (status == HDHT_MUTABLE_ESEQ_TOO_LOW || status == HDHT_MUTABLE_ESEQ_REUSED) record_seq = 0; // look again next time

  // connect as a buyer once our own record is out, so the seller can check us
  bool first = !record_published;
  record_published = true;
  if (first && has_seller) resolve_seller();
  if (first) anchor_start();
}

static void
on_own_record (hdht_t *d, int status, uint64_t seq, const uint8_t *value, size_t len, void *data) {
  (void) data;
  // republish the stored seq if the record is unchanged, otherwise replace it
  if (status == 0) record_seq = len == record_len && memcmp(value, record, len) == 0 ? seq : seq + 1;
  else record_seq = 1;
  printf("MER|record lookup status=%d seq=%llu ms=%ld\n", status, (unsigned long long) record_seq, (long) ((esp_timer_get_time() - record_started) / 1000));
  if (hdht_mutable_put(d, kp.ed25519_pk, kp.ed25519_sk, record_seq, (const uint8_t *) record, record_len, on_record_put, NULL) != 0) on_record_put(d, HDHT_ENOMEM, 0, NULL);
}

static void
publish_record (void) {
  if (record_len == 0) return;
  record_started = esp_timer_get_time();
  int err = record_seq
              ? hdht_mutable_put(&dht, kp.ed25519_pk, kp.ed25519_sk, record_seq, (const uint8_t *) record, record_len, on_record_put, NULL)
              : hdht_mutable_get(&dht, kp.ed25519_pk, 0, on_own_record, NULL);
  if (err) printf("MER|record publish failed %d\n", err);
}

// server: answer a DID dial with an attested reading

static void
on_peer_close (hdht_stream_t *stream, int error) {
  (void) stream;
  printf("MER|peer closed error=%d\n", error);
}

static void
on_peer_connection (hdht_server_t *s, hdht_stream_t *stream) {
  (void) s;
  char hex[65];
  sodium_bin2hex(hex, sizeof(hex), stream->remote_public_key, 32);
  printf("MER|peer did:mw:%.16s... from %s\n", hex, hdht_addr_str(&stream->remote_addr));
  stream->on_close = on_peer_close;

  unsigned long long uptime = esp_timer_get_time() / 1000000;
  unsigned heap = (unsigned) heap_caps_get_free_size(MALLOC_CAP_8BIT);
  char payload[96];
  snprintf(payload, sizeof(payload), "{\"uptime_s\":%llu,\"free_heap\":%u}", uptime, heap);

  boat_attestation_t att;
  int64_t t0 = esp_timer_get_time();
  boat_err_t err = boat_attest_create(&kp, payload, &att);
  long sign_ms = (long) ((esp_timer_get_time() - t0) / 1000);
  if (err != BOAT_OK) {
    printf("MER|attest failed %d\n", err);
    hdht_stream_end(stream);
    return;
  }

  char hash_hex[65], sig_hex[129];
  sodium_bin2hex(hash_hex, sizeof(hash_hex), att.hash, 32);
  sodium_bin2hex(sig_hex, sizeof(sig_hex), att.signature, 64);

  // the payload again, escaped as a JSON string, so its exact bytes can be hashed
  char msg[640];
  int n = snprintf(msg, sizeof(msg), "{\"did\":\"%s\",\"eth\":\"%s\",\"payload\":\"{\\\"uptime_s\\\":%llu,\\\"free_heap\\\":%u}\",\"hash\":\"%s\",\"sig\":\"%s\",\"timestamp\":%u,\"sign_ms\":%ld}", kp.did, kp.eth_addr_hex, uptime, heap, hash_hex, sig_hex, (unsigned) att.timestamp, sign_ms);
  printf("MER|attest sign_ms=%ld\n", sign_ms);
  hdht_stream_write(stream, (const uint8_t *) msg, n);
  hdht_stream_end(stream);
}

static void
on_listening (hdht_server_t *s, int status) {
  (void) s;
  printf("MER|listening status=%d did=%s\n", status, kp.did);
  log_heap("listening");
}

// buyer: MER's engine over a HyperDHT stream

static int
seller_send (uint8_t op, uint16_t uuid16, const void *value, uint16_t len) {
  if (!seller_up || len > MAX_VALUE) return -1;
  uint8_t msg[3 + MAX_VALUE];
  msg[0] = op;
  msg[1] = uuid16 & 0xff;
  msg[2] = uuid16 >> 8;
  if (len) memcpy(msg + 3, value, len);
  return hdht_stream_write(&seller, msg, 3 + len) == 0 ? 0 : -1;
}

static int
xport_write (void *t, uint16_t uuid16, const void *value, uint16_t len) {
  (void) t;
  return seller_send(OP_WRITE, uuid16, value, len);
}

static int
xport_read (void *t, uint16_t uuid16) {
  (void) t;
  return seller_send(OP_READ, uuid16, NULL, 0);
}

static int
xport_disconnect (void *t) {
  (void) t;
  if (!seller_up) return -1;
  hdht_stream_destroy(&seller, HDHT_STREAM_ECLOSED);
  return 0;
}

static const boat_buyer_transport_t xport = {
  .write_chr = xport_write,
  .read_chr = xport_read,
  .disconnect = xport_disconnect,
  .hard_reset = NULL,
};

static void
on_slice_signed (void *user, uint32_t slice_id, const char *proof, uint16_t len) {
  (void) user;
  (void) proof;
  long ms = (long) ((esp_timer_get_time() - notify_started) / 1000);
  printf("MER|slice id=%u signed_ms=%ld proof_len=%u\n", (unsigned) slice_id, ms, len);
}

static void
on_session (void *user, bool streaming) {
  (void) user;
  printf("MER|session %s\n", streaming ? "open" : "closed");
  log_heap("session");
}

static void
on_buyer_log (void *user, int level, const char *msg) {
  (void) user;
  printf("MER|buyer %s: %s\n", level == 0 ? "error" : level == 1 ? "warn" : "info", msg);
}

static const boat_buyer_callbacks_t buyer_cb = {
  .on_slice_signed = on_slice_signed,
  .on_session = on_session,
  .on_log = on_buyer_log,
};

static void
on_seller_data (hdht_stream_t *s, const uint8_t *data, size_t len) {
  (void) s;
  if (len < 3) return;
  uint16_t uuid16 = data[1] | data[2] << 8;

  switch (data[0]) {
  case OP_NOTIFY:
    // pay only the wallet the seller's DID record names
    if (uuid16 == BOAT_NANO_CHR_SLICE_REQUEST && len - 3 >= sizeof(boat_nano_slice_request_v2_t)) {
      const uint8_t *to = data + 3 + offsetof(boat_nano_slice_request_v2_t, to_address);
      if (memcmp(to, payee, 20) != 0) {
        char got[41], want[41];
        sodium_bin2hex(got, sizeof(got), to, 20);
        sodium_bin2hex(want, sizeof(want), payee, 20);
        printf("MER|payee mismatch to=0x%s record=0x%s rejects=%u: not signing, disconnecting\n", got, want, (unsigned) ++payee_rejects);
        hdht_stream_destroy(&seller, HDHT_STREAM_ECLOSED);
        return;
      }
    }
    notify_started = esp_timer_get_time();
    boat_buyer_on_notify(&buyer, uuid16, data + 3, len - 3);
    break;
  case OP_READ_RESULT:
    if (len < 4) return;
    boat_buyer_on_read_result(&buyer, uuid16, data + 4, len - 4, data[3]);
    break;
  }
}

static void
on_seller_open (hdht_stream_t *s) {
  char hex[65];
  sodium_bin2hex(hex, sizeof(hex), s->remote_public_key, 32);
  printf("MER|seller connected did:mw:%.16s... via %s\n", hex, hdht_addr_str(&s->remote_addr));
  seller_up = true;
  boat_buyer_on_connect(&buyer);
  log_heap("seller_open");
}

static void
on_seller_close (hdht_stream_t *s, int error) {
  (void) s;
  printf("MER|seller closed error=%d\n", error);
  if (seller_up) boat_buyer_on_disconnect(&buyer);
  seller_up = false;
  seller_busy = false;
  ticks_down = 0;
}

static void
connect_seller (void) {
  int err = hdht_connect(&dht, &seller, seller_key, on_seller_open, on_seller_data, on_seller_close, NULL);
  if (err) {
    printf("MER|connect failed %d\n", err);
    seller_busy = false;
  }
}

static int64_t resolve_started;

static void
on_seller_record (hdht_t *d, int status, uint64_t seq, const uint8_t *value, size_t len, void *data) {
  (void) d;
  (void) data;
  long lookup_ms = (long) ((esp_timer_get_time() - resolve_started) / 1000);
  if (status != 0) {
    printf("MER|seller record status=%d lookup_ms=%ld: not connecting\n", status, lookup_ms);
    seller_busy = false;
    ticks_down = 0;
    return;
  }

  int64_t t0 = esp_timer_get_time();
  bool ok = verify_record(seller_key, value, len, payee);
  long verify_ms = (long) ((esp_timer_get_time() - t0) / 1000);
  char hex[41];
  sodium_bin2hex(hex, sizeof(hex), payee, 20);
  printf("MER|seller record seq=%llu valid=%s payee=0x%s lookup_ms=%ld verify_ms=%ld\n", (unsigned long long) seq, ok ? "yes" : "no", ok ? hex : "-", lookup_ms, verify_ms);
  if (!ok) {
    seller_busy = false;
    ticks_down = 0;
    return;
  }
  connect_seller();
}

// look up the seller's DID record (its payee) before every connection
static void
resolve_seller (void) {
  seller_busy = true;
  resolve_started = esp_timer_get_time();
  if (hdht_mutable_get(&dht, seller_key, 0, on_seller_record, NULL) != 0) seller_busy = false;
}

// once a second: the engine's watchdog and power self-drive, reconnects, heap log
static void
on_tick (uv_timer_t *t) {
  (void) t;
  if (seller_up) boat_buyer_tick(&buyer);
  else if (has_seller && record_published && !seller_busy && ++ticks_down >= 5) resolve_seller();

  if (++ticks % 30 == 0) log_heap("tick");
  if (ticks % RECORD_REPUBLISH_S == 0) publish_record();
  anchor_tick(ticks);
}

static void
on_ready (hdht_t *d, int status) {
  printf("MER|bootstrapped status=%d nodes=%u\n", status, d->table_len);
  hdht_listen(d, &server, kp.ed25519_pk, kp.ed25519_sk, on_peer_connection, on_listening, NULL);
  publish_record(); // the buyer starts once it is out
}

static void
hdht_task (void *arg) {
  (void) arg;

  // MER generates the keys on first boot and loads them afterwards
  int64_t t0 = esp_timer_get_time();
  if (boat_crypto_init(&kp) != BOAT_OK) {
    printf("MER|boat_crypto_init failed\n");
    vTaskDelete(NULL);
  }
  printf("MER|identity did=%s eth=%s init_ms=%ld\n", kp.did, kp.eth_addr_hex, (long) ((esp_timer_get_time() - t0) / 1000));

  // the HyperDHT key pair derived from MER's seed (the first 32 bytes of its secret key)
  uint8_t pk[32], sk[64];
  hdht_keypair(pk, sk, kp.ed25519_sk);
  printf("MER|keycheck same_keypair=%s\n", memcmp(pk, kp.ed25519_pk, 32) == 0 && memcmp(sk, kp.ed25519_sk, 64) == 0 ? "yes" : "no");
  sodium_memzero(sk, sizeof(sk));
  build_record();

  has_seller = sodium_hex2bin(seller_key, 32, CONFIG_MER_SELLER_KEY, strlen(CONFIG_MER_SELLER_KEY), NULL, NULL, NULL) == 0 && strlen(CONFIG_MER_SELLER_KEY) == 64;
  if (has_seller) {
    boat_buyer_config_t cfg = {
      .chain_id = CONFIG_MER_CHAIN_ID,
      .domain_name = "GatewayWalletBatched",
      .domain_version = "1",
      .rate_ceiling_micro = 500000,  // $0.50 per kWh
      .session_cap_micro = 1000000,  // $1 per session
      .min_valid_window_secs = 3600, // 1 hour
      .power_start_dw = 50,          // open at >= 5 W
      .power_stop_dw = 30,           // close below 3 W
      .power_start_ticks = 2,
      .power_stop_ticks = 3,
      .tick_ms = 1000,
      .wedge_secs = 15,
    };
    boat_hex_to_bytes(CONFIG_MER_GATEWAY_CONTRACT, cfg.gateway_contract, 20);
    if (boat_buyer_init(&buyer, &kp, &xport, NULL, &cfg, &buyer_cb, NULL) != BOAT_OK) {
      printf("MER|boat_buyer_init failed\n");
      has_seller = false;
    }
    printf("MER|buyer ctx_bytes=%u seller=%.16s...\n", (unsigned) sizeof(buyer), CONFIG_MER_SELLER_KEY);
  }

  uv_loop_init(&loop);

  static const char *bootstrap[] = {CONFIG_MER_BOOTSTRAP};
  hdht_opts_t opts = {
    .seed = kp.ed25519_sk, // outgoing connections authenticate as the DID too
  };
  if (bootstrap[0][0]) {
    opts.bootstrap = bootstrap;
    opts.bootstrap_len = 1;
  }
  if (hdht_init(&dht, &loop, &opts) != 0) {
    printf("MER|hdht_init failed\n");
    vTaskDelete(NULL);
  }

  esp_netif_ip_info_t ip;
  esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
  if (netif && esp_netif_get_ip_info(netif, &ip) == ESP_OK) hdht_add_local_address(&dht, (const uint8_t *) &ip.ip.addr);

  log_heap("start");
  hdht_bootstrap(&dht, on_ready);

  static uv_timer_t tick;
  uv_timer_init(&loop, &tick);
  uv_timer_start(&tick, on_tick, 1000, 1000);

  uv_run(&loop, UV_RUN_DEFAULT);
}

void
app_main (void) {
  esp_err_t err = nvs_flash_init();
  if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    err = nvs_flash_init();
  }
  ESP_ERROR_CHECK(err);
  if (sodium_init() < 0) return;

  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());
  ESP_ERROR_CHECK(example_connect());

  xTaskCreate(hdht_task, "hdht", CONFIG_MER_TASK_STACK, NULL, 5, NULL);
}
