// The device as a remote signer for its owner's wallet app (CONFIG_MER_OWNER_KEY).
//
// The owner connects to the device's DID with the key in CONFIG_MER_OWNER_KEY.
// That stream carries signing requests, one JSON object per message, answered
// with {"id","ok":true,...} or {"id","ok":false,"error"}. Anyone else who
// connects still gets an attested reading (main.c). The secp256k1 key never
// leaves the device; the app (wdk-protocol-boat-evm's BoatDeviceSignerEvm, a
// WDK signer) sends what to sign and gets signatures back.
//
//   {"id":"1","op":"address"}
//     -> {"id":"1","ok":true,"address":"0x..","did":"did:mw:.."}
//   {"id":"2","op":"sign","message":"<text>"}
//     -> EIP-191 personal_sign: {"id":"2","ok":true,"signature":"0x<65 bytes>"}
//   {"id":"3","op":"transfer","chainId":"5042002","token":"0x..","name":"USDC",
//    "version":"2","to":"0x..","value":"1000","validAfter":"0",
//    "validBefore":"1794..","nonce":"0x<32 bytes>"}
//     -> an EIP-3009 TransferWithAuthorization from the device's own address,
//        signed under the token's domain: {"id":"3","ok":true,"signature":".."}
//   {"id":"4","op":"sol_address"}
//     -> the device's Solana key (main/solana.h): {"id":"4","ok":true,"key":"<hex>","did":".."}
//   {"id":"6","op":"mqtt_node","node":"<node key hex, or network name>"}
//     -> the MQTT node (or network) the device publishes to (main/mqtt.c), kept
//        in NVS; the device moves there and names it in its DID record:
//        {"id":"6","ok":true}
//   {"id":"7","op":"post_job","registry":"0x..","chainId":"5042002","role":"2",
//    "quorum":"2","perEpoch":"12","deadline":"<unix s>","spec":"0x<32 bytes>",
//    "pay":"1000000","budget":"200000000","paramsHash":"0x<32 bytes>","nonce":"0"}
//     -> the device's own job request for BoatRegistry.postJobFromDevice
//        (packages/boat-registry): it puts in its own DID, hashes the request as
//        the contract does and signs it (EIP-191), when the budget is within
//        CONFIG_MER_JOB_MAX_BUDGET and the deadline within a day:
//        {"id":"7","ok":true,"signature":"0x..","did":"0x<DID key>"}
//   {"id":"5","op":"sol_transfer","message":"<transaction message, base64>"}
//     -> an Ed25519 signature of the message, when it is a transfer of
//        CONFIG_MER_SOL_MINT out of the device's own token account that
//        someone else pays the fee of: {"id":"5","ok":true,"signature":"<hex>"}
//
// Policy, on the device: only TransferWithAuthorization typed data (no
// transactions, so the device never needs gas), at most
// CONFIG_MER_SIGNER_MAX_VALUE base units per authorization, valid for at most
// seven days. All values are JSON strings, without escapes.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_timer.h"
#include "sodium.h"

#include "boat_crypto.h"
#include "boat_nano.h"
#include "boat_pal.h"
#include "mer.h"
#include "solana.h"

#define MAX_REQUEST 1024 // a Solana transfer message is about 330 bytes of base64
#define MAX_VALIDITY_S (7 * 24 * 3600)

static uint8_t owner[32];
static bool has_owner;
static sol_keypair_t sol;
static uint8_t sol_mint[32];
static bool has_sol_mint;

bool
signer_enabled (void) {
  return has_owner;
}

void
signer_init (void) {
  has_owner = strlen(CONFIG_MER_OWNER_KEY) == 64 &&
              sodium_hex2bin(owner, 32, CONFIG_MER_OWNER_KEY, 64, NULL, NULL, NULL) == 0;
  if (has_owner) printf("MER|signer owner=%.16s... max_value=%d\n", CONFIG_MER_OWNER_KEY, CONFIG_MER_SIGNER_MAX_VALUE);
  sol_derive(&sol, kp.ed25519_sk);
  has_sol_mint = sol_base58_decode(CONFIG_MER_SOL_MINT, sol_mint);
  if (has_owner) {
    char address[45];
    sol_base58_encode(sol.pk, address);
    printf("MER|signer solana=%s mint=%s\n", address, has_sol_mint ? CONFIG_MER_SOL_MINT : "-");
  }
}

bool
signer_is_owner (const uint8_t key[32]) {
  return has_owner && memcmp(key, owner, 32) == 0;
}

static void
reply (hdht_stream_t *s, const char *id, const char *fields) {
  char msg[320];
  int n = snprintf(msg, sizeof(msg), "{\"id\":\"%s\",%s}", id, fields);
  if (n > 0 && (size_t) n < sizeof(msg)) hdht_stream_write(s, (const uint8_t *) msg, n);
}

static void
refuse (hdht_stream_t *s, const char *id, const char *op, const char *why) {
  char f[128];
  snprintf(f, sizeof(f), "\"ok\":false,\"error\":\"%s\"", why);
  printf("MER|signer refused op=%s: %s\n", op, why);
  reply(s, id, f);
}

static bool
hex20 (const char *hex, uint8_t out[20]) {
  return strlen(hex) == 42 && hex[0] == '0' && hex[1] == 'x' && sodium_hex2bin(out, 20, hex + 2, 40, NULL, NULL, NULL) == 0;
}

static void
sig_field (const uint8_t sig[65], char *out, size_t cap) {
  char hex[131];
  boat_bytes_to_hex(sig, 65, hex);
  snprintf(out, cap, "\"ok\":true,\"signature\":\"0x%s\"", hex);
}

static void
op_sign (hdht_stream_t *s, const char *id, const char *req) {
  char message[200], buf[240];
  if (!json_str(req, "message", message, sizeof(message))) { refuse(s, id, "sign", "bad message"); return; }
  int n = snprintf(buf, sizeof(buf), "\x19"
                                     "Ethereum Signed Message:\n%u%s",
                   (unsigned) strlen(message), message);
  uint8_t digest[32], sig[65];
  boat_keccak256((const uint8_t *) buf, (size_t) n, digest);
  int64_t t0 = esp_timer_get_time();
  if (boat_secp256k1_sign(&kp, digest, sig) != BOAT_OK) { refuse(s, id, "sign", "signing failed"); return; }
  char f[180];
  sig_field(sig, f, sizeof(f));
  printf("MER|signer sign len=%u ms=%ld\n", (unsigned) strlen(message), (long) ((esp_timer_get_time() - t0) / 1000));
  reply(s, id, f);
}

static void
op_transfer (hdht_stream_t *s, const char *id, const char *req) {
  char chain[16], token[48], name[32], version[16], to[48], value[24], after[16], before[16], nonce[80];
  if (!json_str(req, "chainId", chain, sizeof(chain)) || !json_str(req, "token", token, sizeof(token)) ||
      !json_str(req, "name", name, sizeof(name)) || !json_str(req, "version", version, sizeof(version)) ||
      !json_str(req, "to", to, sizeof(to)) || !json_str(req, "value", value, sizeof(value)) ||
      !json_str(req, "validAfter", after, sizeof(after)) || !json_str(req, "validBefore", before, sizeof(before)) ||
      !json_str(req, "nonce", nonce, sizeof(nonce))) {
    { refuse(s, id, "transfer", "missing field"); return; }
  }
  uint8_t token_addr[20], to_addr[20];
  boat_nano_slice_t slice = {0};
  if (!hex20(token, token_addr) || !hex20(to, to_addr)) { refuse(s, id, "transfer", "bad address"); return; }
  if (strlen(nonce) != 66 || sodium_hex2bin(slice.nonce, 32, nonce + 2, 64, NULL, NULL, NULL) != 0) { refuse(s, id, "transfer", "bad nonce"); return; }

  char *end;
  unsigned long long amount = strtoull(value, &end, 10);
  if (*end || value[0] == '\0') { refuse(s, id, "transfer", "bad value"); return; }
  if (amount > (unsigned long long) CONFIG_MER_SIGNER_MAX_VALUE) { refuse(s, id, "transfer", "value over the device limit"); return; }
  slice.valid_after = strtoul(after, NULL, 10);
  slice.valid_before = strtoul(before, NULL, 10);
  uint32_t now = boat_pal_time();
  if (now < MER_CLOCK_SET) { refuse(s, id, "transfer", "device clock not set yet"); return; }
  if (slice.valid_before <= now || slice.valid_before - now > MAX_VALIDITY_S) { refuse(s, id, "transfer", "validity out of range"); return; }

  boat_nano_auth_t auth;
  int64_t t0 = esp_timer_get_time();
  if (boat_nano_sign(&kp, to_addr, amount, strtoul(chain, NULL, 10), token_addr, name, version, &slice, &auth) != BOAT_OK) {
    { refuse(s, id, "transfer", "signing failed"); return; }
  }
  uint8_t sig[65];
  memcpy(sig, auth.r, 32);
  memcpy(sig + 32, auth.s, 32);
  sig[64] = auth.v;
  char f[180];
  sig_field(sig, f, sizeof(f));
  printf("MER|signer transfer to=%.10s... value=%llu token=%s/%s chain=%s ms=%ld\n", to, amount, name, version, chain, (long) ((esp_timer_get_time() - t0) / 1000));
  reply(s, id, f);
}

// ABI words: a uint up to 64 bits, right-aligned
static void
word_u64 (uint8_t w[32], uint64_t v) {
  memset(w, 0, 32);
  for (int i = 0; i < 8; i++) w[31 - i] = (uint8_t) (v >> (8 * i));
}

static bool
hex32 (const char *hex, uint8_t out[32]) {
  return strlen(hex) == 66 && hex[0] == '0' && hex[1] == 'x' && sodium_hex2bin(out, 32, hex + 2, 64, NULL, NULL, NULL) == 0;
}

static bool
dec_u64 (const char *s, uint64_t *out) {
  char *end;
  if (s[0] == '\0' || s[0] == '-') return false;
  *out = strtoull(s, &end, 10);
  return *end == '\0';
}

// keccak256(abi.encode("boat-job/1", registry, chainId, did, role, quorum,
// perEpoch, deadline, spec, pay, budget, paramsHash, nonce)): what
// BoatRegistry.jobRequestStatement gives
static void
op_post_job (hdht_stream_t *s, const char *id, const char *req) {
  char registry[48], chain[24], role[8], quorum[8], per_epoch[16], deadline[24], spec[72], pay[24], budget[24], params[72], nonce[24];
  if (!json_str(req, "registry", registry, sizeof(registry)) || !json_str(req, "chainId", chain, sizeof(chain)) ||
      !json_str(req, "role", role, sizeof(role)) || !json_str(req, "quorum", quorum, sizeof(quorum)) ||
      !json_str(req, "perEpoch", per_epoch, sizeof(per_epoch)) || !json_str(req, "deadline", deadline, sizeof(deadline)) ||
      !json_str(req, "spec", spec, sizeof(spec)) || !json_str(req, "pay", pay, sizeof(pay)) ||
      !json_str(req, "budget", budget, sizeof(budget)) || !json_str(req, "paramsHash", params, sizeof(params)) ||
      !json_str(req, "nonce", nonce, sizeof(nonce))) {
    refuse(s, id, "post_job", "missing field");
    return;
  }
  uint8_t reg[20], spec_b[32], params_b[32];
  uint64_t v_chain, v_role, v_quorum, v_per, v_deadline, v_pay, v_budget, v_nonce;
  if (!hex20(registry, reg) || !hex32(spec, spec_b) || !hex32(params, params_b)) { refuse(s, id, "post_job", "bad hex"); return; }
  if (!dec_u64(chain, &v_chain) || !dec_u64(role, &v_role) || !dec_u64(quorum, &v_quorum) || !dec_u64(per_epoch, &v_per) ||
      !dec_u64(deadline, &v_deadline) || !dec_u64(pay, &v_pay) || !dec_u64(budget, &v_budget) || !dec_u64(nonce, &v_nonce)) {
    refuse(s, id, "post_job", "bad number");
    return;
  }
  if (!(v_role == 1 || v_role == 2 || v_role == 4 || v_role == 8) || v_quorum == 0 || v_quorum > 65535 || v_per == 0 || v_per > 0xffffffffu) {
    refuse(s, id, "post_job", "bad terms");
    return;
  }
  if (v_budget > (uint64_t) CONFIG_MER_JOB_MAX_BUDGET || v_pay > v_budget) { refuse(s, id, "post_job", "budget over the device limit"); return; }
  uint32_t now = boat_pal_time();
  if (now < MER_CLOCK_SET) { refuse(s, id, "post_job", "device clock not set yet"); return; }
  if (v_deadline <= now || v_deadline - now > 24 * 3600) { refuse(s, id, "post_job", "deadline out of range"); return; }

  static uint8_t enc[15 * 32];
  memset(enc, 0, sizeof(enc));
  word_u64(enc + 0 * 32, 13 * 32);           // offset of the string
  memcpy(enc + 1 * 32 + 12, reg, 20);         // registry
  word_u64(enc + 2 * 32, v_chain);
  memcpy(enc + 3 * 32, kp.ed25519_pk, 32);    // did: this device, always
  word_u64(enc + 4 * 32, v_role);
  word_u64(enc + 5 * 32, v_quorum);
  word_u64(enc + 6 * 32, v_per);
  word_u64(enc + 7 * 32, v_deadline);
  memcpy(enc + 8 * 32, spec_b, 32);
  word_u64(enc + 9 * 32, v_pay);
  word_u64(enc + 10 * 32, v_budget);
  memcpy(enc + 11 * 32, params_b, 32);
  word_u64(enc + 12 * 32, v_nonce);
  word_u64(enc + 13 * 32, 10);               // "boat-job/1"
  memcpy(enc + 14 * 32, "boat-job/1", 10);
  uint8_t h[32], prefixed[28 + 32], digest[32], sig[65];
  boat_keccak256(enc, sizeof(enc), h);
  memcpy(prefixed, "\x19" "Ethereum Signed Message:\n32", 28);
  memcpy(prefixed + 28, h, 32);
  boat_keccak256(prefixed, sizeof(prefixed), digest);
  int64_t t0 = esp_timer_get_time();
  if (boat_secp256k1_sign(&kp, digest, sig) != BOAT_OK) { refuse(s, id, "post_job", "signing failed"); return; }
  char hex[131], did[65], f[300];
  boat_bytes_to_hex(sig, 65, hex);
  sodium_bin2hex(did, sizeof(did), kp.ed25519_pk, 32);
  snprintf(f, sizeof(f), "\"ok\":true,\"signature\":\"0x%s\",\"did\":\"0x%s\"", hex, did);
  printf("MER|signer post_job role=%llu budget=%llu pay=%llu nonce=%llu ms=%ld\n", (unsigned long long) v_role, (unsigned long long) v_budget, (unsigned long long) v_pay, (unsigned long long) v_nonce, (long) ((esp_timer_get_time() - t0) / 1000));
  reply(s, id, f);
}

static void
op_sol_transfer (hdht_stream_t *s, const char *id, const char *req) {
  static char b64[MAX_REQUEST];
  static uint8_t message[768];
  size_t len;
  if (!has_sol_mint) { refuse(s, id, "sol_transfer", "no Solana mint configured"); return; }
  if (!json_str(req, "message", b64, sizeof(b64)) ||
      sodium_base642bin(message, sizeof(message), b64, strlen(b64), NULL, &len, NULL, sodium_base64_VARIANT_ORIGINAL) != 0) {
    refuse(s, id, "sol_transfer", "bad message");
    return;
  }
  sol_transfer_t t;
  const char *why = sol_check_transfer(message, len, sol.pk, sol_mint, (uint64_t) CONFIG_MER_SIGNER_MAX_VALUE, &t);
  if (why) { refuse(s, id, "sol_transfer", why); return; }
  uint8_t sig[64];
  int64_t t0 = esp_timer_get_time();
  crypto_sign_detached(sig, NULL, message, len, sol.sk);
  char hex[129], f[180], to[45];
  sodium_bin2hex(hex, sizeof(hex), sig, 64);
  snprintf(f, sizeof(f), "\"ok\":true,\"signature\":\"%s\"", hex);
  sol_base58_encode(t.destination, to);
  printf("MER|signer sol_transfer to=%.10s... amount=%llu transfers=%d len=%u ms=%ld\n", to, (unsigned long long) t.amount, t.transfers, (unsigned) len, (long) ((esp_timer_get_time() - t0) / 1000));
  reply(s, id, f);
}

static void
on_owner_data (hdht_stream_t *s, const uint8_t *data, size_t len) {
  static char req[MAX_REQUEST + 1]; // off the hdht task's stack
  char id[16] = "?", op[16];
  if (len > MAX_REQUEST) { refuse(s, id, "?", "request too long"); return; }
  memcpy(req, data, len);
  req[len] = '\0';
  json_str(req, "id", id, sizeof(id));
  if (!json_str(req, "op", op, sizeof(op))) { refuse(s, id, "?", "no op"); return; }

  if (strcmp(op, "address") == 0) {
    char f[200];
    snprintf(f, sizeof(f), "\"ok\":true,\"address\":\"%s\",\"did\":\"%s\"", kp.eth_addr_hex, kp.did);
    reply(s, id, f);
  } else if (strcmp(op, "sign") == 0) {
    op_sign(s, id, req);
  } else if (strcmp(op, "transfer") == 0) {
    op_transfer(s, id, req);
  } else if (strcmp(op, "sol_address") == 0) {
    char f[200], hex[65];
    sodium_bin2hex(hex, sizeof(hex), sol.pk, 32);
    snprintf(f, sizeof(f), "\"ok\":true,\"key\":\"%s\",\"did\":\"%s\"", hex, kp.did);
    reply(s, id, f);
  } else if (strcmp(op, "sol_transfer") == 0) {
    op_sol_transfer(s, id, req);
  } else if (strcmp(op, "post_job") == 0) {
    op_post_job(s, id, req);
  } else if (strcmp(op, "mqtt_node") == 0) {
    char node[80];
    if (!json_str(req, "node", node, sizeof(node)) || node[0] == '\0') { refuse(s, id, "mqtt_node", "bad node"); return; }
    if (!mqtt_set_node(node)) { refuse(s, id, "mqtt_node", "could not set it"); return; }
    printf("MER|signer owner set the MQTT node to %.16s...\n", node);
    reply(s, id, "\"ok\":true");
  } else {
    refuse(s, id, op, "unsupported op");
  }
}

static void
on_owner_close (hdht_stream_t *s, int error) {
  (void) s;
  printf("MER|signer owner disconnected error=%d\n", error);
}

void
signer_serve (hdht_stream_t *stream) {
  printf("MER|signer owner connected from %s\n", hdht_addr_str(&stream->remote_addr));
  stream->on_data = on_owner_data;
  stream->on_close = on_owner_close;
}
