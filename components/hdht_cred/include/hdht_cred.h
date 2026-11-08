// Manufacturer credentials, checked by a device (docs/credentials.md).
//
// A credential is an issuer's Ed25519 signature over
//   "hdht-credential/1 <id> <issuer key hex> <device key hex> <iat> <model>"
// kept as "cred" in the device's DID record. The issuer's own record lists
// revoked credential ids. hdht_cred_verify_device does what
// tools/host/credential.js verifyDevice does, on a device: read the peer's
// record, check its credential, check the issuer is trusted, and check the
// issuer's record does not revoke it.

#ifndef HDHT_CRED_H
#define HDHT_CRED_H

#include <stddef.h>
#include <stdint.h>

#include "hdht.h"

typedef struct {
  char id[17];        // 8 bytes as hex
  uint8_t issuer[32];
  uint8_t subject[32];
  uint64_t iat;
  char model[33];     // 1-32 of A-Z a-z 0-9 space . _ -
  uint8_t sig[64];
} hdht_cred_t;

typedef enum {
  HDHT_CRED_VALID = 0,
  HDHT_CRED_NO_RECORD = -1,      // the device has no record in the DHT
  HDHT_CRED_NO_CRED = -2,        // its record carries no credential
  HDHT_CRED_MALFORMED = -3,
  HDHT_CRED_OTHER_DEVICE = -4,   // the credential is for another key
  HDHT_CRED_BAD_SIGNATURE = -5,
  HDHT_CRED_NOT_TRUSTED = -6,    // signed by an issuer not on the list
  HDHT_CRED_ISSUER_UNKNOWN = -7, // no issuer record: revocation cannot be checked
  HDHT_CRED_REVOKED = -8,
} hdht_cred_result_t;

const char *
hdht_cred_reason (int result);

// Reads a credential from JSON: the credential object itself, or a record
// that carries it as "cred". Returns 0 or HDHT_CRED_NO_CRED / _MALFORMED.
int
hdht_cred_parse (hdht_cred_t *out, const char *json, size_t len);

// Checks the signature, and that the credential is for `device` (NULL: any).
// Returns 0, HDHT_CRED_OTHER_DEVICE or HDHT_CRED_BAD_SIGNATURE.
int
hdht_cred_check (const hdht_cred_t *cred, const uint8_t device[32]);

// Whether an issuer record (JSON) belongs to `issuer` and revokes `id`.
// Returns 0, HDHT_CRED_REVOKED, or HDHT_CRED_MALFORMED for a record that is
// not the issuer's.
int
hdht_cred_check_issuer_record (const char *json, size_t len, const uint8_t issuer[32], const char *id);

typedef struct hdht_cred_verify_s hdht_cred_verify_t;

// result is a hdht_cred_result_t; cred is set from HDHT_CRED_NOT_TRUSTED on.
typedef void (*hdht_cred_verify_cb)(hdht_cred_verify_t *v, int result, const hdht_cred_t *cred);

struct hdht_cred_verify_s {
  hdht_t *dht;
  uint8_t device[32];
  const uint8_t (*trusted)[32];
  size_t trusted_len;
  hdht_cred_t cred;
  hdht_cred_verify_cb cb;
  void *data;
};

// The whole check, on the hdht loop: two record lookups. `trusted` must
// outlive the call. Returns 0 if started; cb is called once.
int
hdht_cred_verify_device (hdht_cred_verify_t *v, hdht_t *dht, const uint8_t device[32], const uint8_t (*trusted)[32], size_t trusted_len, hdht_cred_verify_cb cb, void *data);

#endif
