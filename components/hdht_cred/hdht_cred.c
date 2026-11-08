// Manufacturer credentials, checked by a device. See hdht_cred.h.
//
// The JSON readers here only take what the credential format allows: flat
// string and integer fields, no escapes, and a model of A-Z a-z 0-9 space
// . _ -. Anything else is MALFORMED.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "hdht_cred.h"

const char *
hdht_cred_reason (int result) {
  switch (result) {
  case HDHT_CRED_VALID: return "valid";
  case HDHT_CRED_NO_RECORD: return "no device record";
  case HDHT_CRED_NO_CRED: return "no credential in the device record";
  case HDHT_CRED_MALFORMED: return "credential malformed";
  case HDHT_CRED_OTHER_DEVICE: return "credential for another device";
  case HDHT_CRED_BAD_SIGNATURE: return "credential bad signature";
  case HDHT_CRED_NOT_TRUSTED: return "issuer not trusted";
  case HDHT_CRED_ISSUER_UNKNOWN: return "issuer record not found, cannot check revocation";
  case HDHT_CRED_REVOKED: return "revoked";
  default: return "unknown";
  }
}

// the value of "key" in [p, end): a pointer just past `"key":`, or NULL
static const char *
field (const char *p, const char *end, const char *key) {
  char pattern[24];
  int n = snprintf(pattern, sizeof(pattern), "\"%s\":", key);
  if (n <= 0 || (size_t) n >= sizeof(pattern)) return NULL;
  for (const char *q = p; q + n <= end; q++) {
    if (memcmp(q, pattern, (size_t) n) == 0) return q + n;
  }
  return NULL;
}

// a JSON string with no escapes, copied into out
static bool
string (const char *p, const char *end, const char *key, char *out, size_t cap) {
  const char *v = field(p, end, key);
  if (v == NULL || v >= end || *v != '"') return false;
  v++;
  const char *q = v;
  while (q < end && *q != '"') {
    if (*q == '\\' || (unsigned char) *q < 0x20) return false;
    q++;
  }
  if (q >= end || (size_t) (q - v) >= cap) return false;
  memcpy(out, v, (size_t) (q - v));
  out[q - v] = '\0';
  return true;
}

static bool
did_key (const char *did, uint8_t out[32]) {
  return strlen(did) == 71 && memcmp(did, "did:mw:", 7) == 0 &&
         sodium_hex2bin(out, 32, did + 7, 64, NULL, NULL, NULL) == 0;
}

static bool
model_ok (const char *m) {
  size_t n = strlen(m);
  if (n < 1 || n > 32) return false;
  for (size_t i = 0; i < n; i++) {
    char c = m[i];
    if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == ' ' || c == '.' || c == '_' || c == '-')) return false;
  }
  return true;
}

int
hdht_cred_parse (hdht_cred_t *out, const char *json, size_t len) {
  const char *p = json, *end = json + len;

  // a record carries the credential as "cred": {...}, with no objects inside
  const char *c = field(p, end, "cred");
  if (c != NULL) {
    if (c >= end || *c != '{') return HDHT_CRED_MALFORMED;
    const char *close = memchr(c, '}', (size_t) (end - c));
    if (close == NULL) return HDHT_CRED_MALFORMED;
    p = c;
    end = close + 1;
  } else if (field(p, end, "sig") == NULL) {
    return HDHT_CRED_NO_CRED;
  }

  const char *v = field(p, end, "v");
  if (v == NULL || v + 1 >= end || v[0] != '1' || (v[1] != ',' && v[1] != '}')) return HDHT_CRED_MALFORMED;

  char iss[80], sub[80], sig[136];
  memset(out, 0, sizeof(*out));
  if (!string(p, end, "id", out->id, sizeof(out->id)) || strlen(out->id) != 16 ||
      !string(p, end, "iss", iss, sizeof(iss)) || !string(p, end, "sub", sub, sizeof(sub)) ||
      !string(p, end, "model", out->model, sizeof(out->model)) || !string(p, end, "sig", sig, sizeof(sig))) {
    return HDHT_CRED_MALFORMED;
  }
  uint8_t id[8];
  if (sodium_hex2bin(id, 8, out->id, 16, NULL, NULL, NULL) != 0) return HDHT_CRED_MALFORMED;
  for (int i = 0; i < 16; i++) {
    if (out->id[i] >= 'A' && out->id[i] <= 'F') return HDHT_CRED_MALFORMED; // lower-case hex, as signed
  }
  if (!did_key(iss, out->issuer) || !did_key(sub, out->subject) || !model_ok(out->model)) return HDHT_CRED_MALFORMED;
  if (strlen(sig) != 128 || sodium_hex2bin(out->sig, 64, sig, 128, NULL, NULL, NULL) != 0) return HDHT_CRED_MALFORMED;

  const char *t = field(p, end, "iat");
  if (t == NULL || t >= end || *t < '1' || *t > '9') return HDHT_CRED_MALFORMED; // no sign, no leading zero
  char *after;
  unsigned long long iat = strtoull(t, &after, 10);
  if (after >= end || (*after != ',' && *after != '}') || after - t > 12) return HDHT_CRED_MALFORMED;
  out->iat = iat;
  return 0;
}

int
hdht_cred_check (const hdht_cred_t *cred, const uint8_t device[32]) {
  if (device != NULL && memcmp(cred->subject, device, 32) != 0) return HDHT_CRED_OTHER_DEVICE;
  char iss[65], sub[65], text[192];
  sodium_bin2hex(iss, sizeof(iss), cred->issuer, 32);
  sodium_bin2hex(sub, sizeof(sub), cred->subject, 32);
  int n = snprintf(text, sizeof(text), "hdht-credential/1 %s %s %s %llu %s", cred->id, iss, sub, (unsigned long long) cred->iat, cred->model);
  if (n <= 0 || (size_t) n >= sizeof(text)) return HDHT_CRED_MALFORMED;
  return crypto_sign_verify_detached(cred->sig, (const uint8_t *) text, (size_t) n, cred->issuer) == 0 ? 0 : HDHT_CRED_BAD_SIGNATURE;
}

int
hdht_cred_check_issuer_record (const char *json, size_t len, const uint8_t issuer[32], const char *id) {
  const char *end = json + len;
  char did[80];
  uint8_t key[32];
  if (!string(json, end, "did", did, sizeof(did)) || !did_key(did, key) || memcmp(key, issuer, 32) != 0) return HDHT_CRED_MALFORMED;

  const char *r = field(json, end, "revoked");
  if (r == NULL) return 0;
  if (r >= end || *r != '[') return HDHT_CRED_MALFORMED;
  const char *close = memchr(r, ']', (size_t) (end - r));
  if (close == NULL) return HDHT_CRED_MALFORMED;
  char quoted[20];
  snprintf(quoted, sizeof(quoted), "\"%s\"", id);
  size_t qn = strlen(quoted);
  for (const char *q = r; q + qn <= close; q++) {
    if (memcmp(q, quoted, qn) == 0) return HDHT_CRED_REVOKED;
  }
  return 0;
}

static void
on_issuer_record (hdht_t *dht, int status, uint64_t seq, const uint8_t *value, size_t len, void *data) {
  (void) dht;
  (void) seq;
  hdht_cred_verify_t *v = data;
  if (status != 0) {
    v->cb(v, HDHT_CRED_ISSUER_UNKNOWN, &v->cred);
    return;
  }
  int r = hdht_cred_check_issuer_record((const char *) value, len, v->cred.issuer, v->cred.id);
  v->cb(v, r == HDHT_CRED_MALFORMED ? HDHT_CRED_ISSUER_UNKNOWN : r, &v->cred);
}

static void
on_device_record (hdht_t *dht, int status, uint64_t seq, const uint8_t *value, size_t len, void *data) {
  (void) seq;
  hdht_cred_verify_t *v = data;
  if (status != 0) {
    v->cb(v, HDHT_CRED_NO_RECORD, NULL);
    return;
  }
  int r = hdht_cred_parse(&v->cred, (const char *) value, len);
  if (r == 0) r = hdht_cred_check(&v->cred, v->device);
  if (r != 0) {
    v->cb(v, r, NULL);
    return;
  }
  bool trusted = false;
  for (size_t i = 0; i < v->trusted_len && !trusted; i++) trusted = memcmp(v->trusted[i], v->cred.issuer, 32) == 0;
  if (!trusted) {
    v->cb(v, HDHT_CRED_NOT_TRUSTED, &v->cred);
    return;
  }
  if (hdht_mutable_get(dht, v->cred.issuer, 0, on_issuer_record, v) != 0) v->cb(v, HDHT_CRED_ISSUER_UNKNOWN, &v->cred);
}

int
hdht_cred_verify_device (hdht_cred_verify_t *v, hdht_t *dht, const uint8_t device[32], const uint8_t (*trusted)[32], size_t trusted_len, hdht_cred_verify_cb cb, void *data) {
  memset(v, 0, sizeof(*v));
  v->dht = dht;
  memcpy(v->device, device, 32);
  v->trusted = trusted;
  v->trusted_len = trusted_len;
  v->cb = cb;
  v->data = data;
  return hdht_mutable_get(dht, device, 0, on_device_record, v);
}
