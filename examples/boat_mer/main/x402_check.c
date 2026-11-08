// See x402_check.h.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "boat_crypto.h"

#include "x402_check.h"

// the string value of "key" in [p, end), copied into out
static bool
field (const char *p, const char *end, const char *key, char *out, size_t cap) {
  char pattern[32];
  int n = snprintf(pattern, sizeof(pattern), "\"%s\":\"", key);
  if (n <= 0 || (size_t) n >= sizeof(pattern)) return false;
  for (const char *q = p; q + n <= end; q++) {
    if (memcmp(q, pattern, (size_t) n) != 0) continue;
    const char *v = q + n;
    const char *e = v;
    while (e < end && *e != '"') {
      if (*e == '\\') return false;
      e++;
    }
    if (e >= end || (size_t) (e - v) >= cap) return false;
    memcpy(out, v, (size_t) (e - v));
    out[e - v] = '\0';
    return true;
  }
  return false;
}

static bool
hex_bytes (const char *hex, uint8_t *out, size_t n) {
  if (strlen(hex) != 2 + n * 2 || hex[0] != '0' || (hex[1] != 'x' && hex[1] != 'X')) return false;
  return boat_hex_to_bytes(hex, out, n) == (int) n;
}

// a decimal string that fits in 64 bits
static bool
decimal (const char *s, uint64_t *out) {
  if (*s == '\0' || strlen(s) > 19) return false;
  uint64_t v = 0;
  for (const char *p = s; *p; p++) {
    if (*p < '0' || *p > '9') return false;
    v = v * 10 + (uint64_t) (*p - '0');
  }
  *out = v;
  return true;
}

const char *
x402_parse_payment (const char *json, x402_auth_t *out) {
  memset(out, 0, sizeof(*out));
  // the authorization object, then the signature beside it in "payload"
  const char *a = strstr(json, "\"authorization\":{");
  if (a == NULL) return "no authorization";
  const char *a_end = strchr(a, '}');
  if (a_end == NULL) return "malformed authorization";
  char from[48], to[48], value[24], after[24], before[24], nonce[72], sig[136];
  if (!field(a, a_end, "from", from, sizeof(from)) || !field(a, a_end, "to", to, sizeof(to)) ||
      !field(a, a_end, "value", value, sizeof(value)) || !field(a, a_end, "validAfter", after, sizeof(after)) ||
      !field(a, a_end, "validBefore", before, sizeof(before)) || !field(a, a_end, "nonce", nonce, sizeof(nonce))) {
    return "authorization fields missing";
  }
  const char *p = strstr(json, "\"payload\":{");
  if (p == NULL || !field(p, json + strlen(json), "signature", sig, sizeof(sig))) return "no signature";
  if (!hex_bytes(from, out->from, 20) || !hex_bytes(to, out->to, 20)) return "bad address";
  if (!hex_bytes(nonce, out->nonce, 32)) return "bad nonce";
  if (!hex_bytes(sig, out->signature, 65)) return "bad signature";
  if (!decimal(value, &out->value) || !decimal(after, &out->valid_after) || !decimal(before, &out->valid_before)) return "bad number";
  return NULL;
}

static void
keccak_str (const char *s, uint8_t out[32]) {
  boat_keccak256((const uint8_t *) s, strlen(s), out);
}

static void
word_u64 (uint8_t w[32], uint64_t v) {
  memset(w, 0, 32);
  for (int i = 0; i < 8; i++) w[31 - i] = (uint8_t) (v >> (8 * i));
}

static void
word_addr (uint8_t w[32], const uint8_t a[20]) {
  memset(w, 0, 12);
  memcpy(w + 12, a, 20);
}

void
x402_eip3009_digest (const x402_terms_t *t, const x402_auth_t *a, uint8_t digest[32]) {
  uint8_t buf[7 * 32], domain[32], hash[32];

  keccak_str("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)", buf);
  keccak_str(t->name, buf + 32);
  keccak_str(t->version, buf + 64);
  word_u64(buf + 96, t->chain_id);
  word_addr(buf + 128, t->token);
  boat_keccak256(buf, 5 * 32, domain);

  keccak_str("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)", buf);
  word_addr(buf + 32, a->from);
  word_addr(buf + 64, a->to);
  word_u64(buf + 96, a->value);
  word_u64(buf + 128, a->valid_after);
  word_u64(buf + 160, a->valid_before);
  memcpy(buf + 192, a->nonce, 32);
  boat_keccak256(buf, 7 * 32, hash);

  uint8_t msg[2 + 64] = {0x19, 0x01};
  memcpy(msg + 2, domain, 32);
  memcpy(msg + 34, hash, 32);
  boat_keccak256(msg, sizeof(msg), digest);
}

const char *
x402_check_payment (const x402_terms_t *t, const x402_auth_t *a, uint64_t now) {
  if (memcmp(a->to, t->payee, 20) != 0) return "pays someone else";
  if (a->value < t->price) return "pays less than the price";
  if (a->valid_after > now) return "not valid yet";
  if (a->valid_before <= now + 6) return "expires too soon to settle"; // a block or two
  if (a->valid_before > now + t->max_timeout_s + 600) return "valid for too long";
  uint8_t digest[32], signer[20];
  x402_eip3009_digest(t, a, digest);
  if (boat_secp256k1_ecrecover(digest, a->signature, signer) != BOAT_OK) return "bad signature";
  if (memcmp(signer, a->from, 20) != 0) return "not signed by the payer";
  return NULL;
}
