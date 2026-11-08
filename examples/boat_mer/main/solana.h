// The device's Solana key, and what it agrees to sign with it.
//
// The key is derived from the DID key, not the DID key itself, so a Solana
// signature can never be taken for one by the DID (HyperDHT handshakes,
// mutable records) or the other way round:
//
//   seed = BLAKE2b-256(key = DID seed, "boat-solana/1"), an Ed25519 key pair
//
// The device signs SPL Token transfers out of its own token accounts and
// nothing else: a transaction message (legacy or v0 without address tables)
// whose fee payer is someone else, in which the device is a read-only signer,
// whose instructions are only Token transferChecked with the device as
// authority, of one mint, to one destination, and ComputeBudget ones. Like
// EIP-3009 on EVM chains, the device needs no SOL: the fee payer pays.
//
// Plain C over libsodium, so it is tested on the desktop (../test).

#ifndef MER_SOLANA_H
#define MER_SOLANA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint8_t pk[32];
  uint8_t sk[64];
} sol_keypair_t;

void
sol_derive (sol_keypair_t *out, const uint8_t did_sk[64]);

// base58 for 32-byte keys; decode returns false unless it is exactly 32 bytes
void
sol_base58_encode (const uint8_t in[32], char out[45]);

bool
sol_base58_decode (const char *in, uint8_t out[32]);

typedef struct {
  uint64_t amount; // the sum of the transfers, in the mint's base units
  uint8_t destination[32];
  uint8_t decimals;
  int transfers;
} sol_transfer_t;

// NULL when the device may sign the message, else why not
const char *
sol_check_transfer (const uint8_t *msg, size_t len, const uint8_t signer[32], const uint8_t mint[32], uint64_t max_amount, sol_transfer_t *out);

#endif
