// Checking an x402 v2 "exact" EVM payment on the device (x402_sell.c): the
// EIP-3009 TransferWithAuthorization in a PAYMENT-SIGNATURE payload, verified
// under the token's EIP-712 domain with the device's own crypto, before the
// device asks a facilitator to settle it. Plain C over MER's keccak and
// ecrecover, so it is tested on the desktop (../test).

#ifndef MER_X402_CHECK_H
#define MER_X402_CHECK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint8_t from[20];
  uint8_t to[20];
  uint64_t value;
  uint64_t valid_after;
  uint64_t valid_before;
  uint8_t nonce[32];
  uint8_t signature[65];
} x402_auth_t;

typedef struct {
  uint32_t chain_id;
  uint8_t token[20];
  const char *name;    // the token's EIP-712 domain
  const char *version;
  uint8_t payee[20];
  uint64_t price;
  uint32_t max_timeout_s; // longest validity the device accepts
} x402_terms_t;

// reads payload.authorization and payload.signature from a decoded
// PAYMENT-SIGNATURE (JSON); NULL when well formed, else why not
const char *
x402_parse_payment (const char *json, x402_auth_t *out);

// the EIP-712 digest of a TransferWithAuthorization under the token's domain
void
x402_eip3009_digest (const x402_terms_t *terms, const x402_auth_t *a, uint8_t digest[32]);

// NULL when the payment pays the terms, signed by its "from", valid at now
const char *
x402_check_payment (const x402_terms_t *terms, const x402_auth_t *a, uint64_t now);

#endif
