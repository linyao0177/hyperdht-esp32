// See solana.h.

#include <string.h>

#include "sodium.h"

#include "solana.h"

static const char ALPHABET[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA, the SPL Token program
static const uint8_t TOKEN_PROGRAM[32] = {
  0x06, 0xdd, 0xf6, 0xe1, 0xd7, 0x65, 0xa1, 0x93, 0xd9, 0xcb, 0xe1, 0x46, 0xce, 0xeb, 0x79, 0xac,
  0x1c, 0xb4, 0x85, 0xed, 0x5f, 0x5b, 0x37, 0x91, 0x3a, 0x8c, 0xf5, 0x85, 0x7e, 0xff, 0x00, 0xa9
};
// ComputeBudget111111111111111111111111111111
static const uint8_t COMPUTE_BUDGET_PROGRAM[32] = {
  0x03, 0x06, 0x46, 0x6f, 0xe5, 0x21, 0x17, 0x32, 0xff, 0xec, 0xad, 0xba, 0x72, 0xc3, 0x9b, 0xe7,
  0xbc, 0x8c, 0xe5, 0xbb, 0xc5, 0xf7, 0x12, 0x6b, 0x2c, 0x43, 0x9b, 0x3a, 0x40, 0x00, 0x00, 0x00
};
#define TRANSFER_CHECKED 12

void
sol_derive (sol_keypair_t *out, const uint8_t did_sk[64]) {
  static const char context[] = "boat-solana/1";
  uint8_t seed[32];
  crypto_generichash(seed, sizeof(seed), (const uint8_t *) context, sizeof(context) - 1, did_sk, 32);
  crypto_sign_seed_keypair(out->pk, out->sk, seed);
  sodium_memzero(seed, sizeof(seed));
}

void
sol_base58_encode (const uint8_t in[32], char out[45]) {
  uint8_t digits[45] = {0};
  int len = 0;
  for (int i = 0; i < 32; i++) {
    int carry = in[i];
    for (int j = 0; j < len; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry /= 58;
    }
    while (carry) {
      digits[len++] = carry % 58;
      carry /= 58;
    }
  }
  int n = 0;
  for (int i = 0; i < 32 && in[i] == 0; i++) out[n++] = '1';
  for (int i = len - 1; i >= 0; i--) out[n++] = ALPHABET[digits[i]];
  out[n] = '\0';
}

bool
sol_base58_decode (const char *in, uint8_t out[32]) {
  size_t n = strlen(in);
  if (n == 0 || n > 44) return false;
  uint8_t bytes[33] = {0};
  int len = 0;
  for (size_t i = 0; i < n; i++) {
    const char *p = strchr(ALPHABET, in[i]);
    if (p == NULL || in[i] == '\0') return false;
    int carry = (int) (p - ALPHABET);
    for (int j = 0; j < len; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry) {
      if (len == 33) return false;
      bytes[len++] = carry & 0xff;
      carry >>= 8;
    }
  }
  int zeros = 0;
  while ((size_t) zeros < n && in[zeros] == '1') zeros++;
  if (zeros + len != 32) return false;
  memset(out, 0, 32);
  for (int i = 0; i < len; i++) out[31 - i] = bytes[i];
  return true;
}

typedef struct {
  const uint8_t *p, *end;
} reader_t;

static bool
take (reader_t *r, size_t n, const uint8_t **out) {
  if ((size_t) (r->end - r->p) < n) return false;
  if (out) *out = r->p;
  r->p += n;
  return true;
}

// Solana's compact-u16: 1 to 3 bytes, 7 bits each
static bool
compact_u16 (reader_t *r, unsigned *out) {
  unsigned v = 0;
  for (int i = 0; i < 3; i++) {
    const uint8_t *b;
    if (!take(r, 1, &b)) return false;
    v |= (unsigned) (*b & 0x7f) << (7 * i);
    if (!(*b & 0x80)) {
      if (v > 0xffff) return false;
      *out = v;
      return true;
    }
  }
  return false;
}

const char *
sol_check_transfer (const uint8_t *msg, size_t len, const uint8_t signer[32], const uint8_t mint[32], uint64_t max_amount, sol_transfer_t *out) {
  reader_t r = {msg, msg + len};
  memset(out, 0, sizeof(*out));

  bool v0 = false;
  if (len > 0 && (msg[0] & 0x80)) {
    if ((msg[0] & 0x7f) != 0) return "unsupported message version";
    v0 = true;
    r.p++;
  }
  const uint8_t *header;
  if (!take(&r, 3, &header)) return "truncated header";
  unsigned required = header[0], readonly_signed = header[1], readonly_unsigned = header[2];

  unsigned nkeys;
  const uint8_t *keys;
  if (!compact_u16(&r, &nkeys) || nkeys == 0 || !take(&r, (size_t) nkeys * 32, &keys)) return "truncated accounts";
  if (required == 0 || required > nkeys || readonly_signed >= required || readonly_unsigned > nkeys - required) return "bad header";

  int me = -1;
  for (unsigned i = 0; i < nkeys; i++) {
    if (memcmp(keys + i * 32, signer, 32) == 0) {
      if (me >= 0) return "the device's key appears twice";
      me = (int) i;
    }
  }
  if (me < 0 || (unsigned) me >= required) return "the device is not a signer";
  if (me == 0) return "the device would pay the fee";
  if ((unsigned) me < required - readonly_signed) return "the device's account would be writable";

  if (!take(&r, 32, NULL)) return "truncated blockhash";

  unsigned ninstructions;
  if (!compact_u16(&r, &ninstructions) || ninstructions == 0) return "no instructions";
  for (unsigned k = 0; k < ninstructions; k++) {
    const uint8_t *program;
    unsigned naccounts, ndata;
    const uint8_t *accounts, *data;
    if (!take(&r, 1, &program) || *program >= nkeys) return "bad program index";
    if (!compact_u16(&r, &naccounts) || !take(&r, naccounts, &accounts)) return "truncated instruction";
    if (!compact_u16(&r, &ndata) || !take(&r, ndata, &data)) return "truncated instruction";
    for (unsigned a = 0; a < naccounts; a++) {
      if (accounts[a] >= nkeys) return "bad account index";
    }
    const uint8_t *program_key = keys + *program * 32;

    if (memcmp(program_key, COMPUTE_BUDGET_PROGRAM, 32) == 0) {
      if (naccounts != 0) return "compute budget instruction with accounts";
      continue;
    }
    if (memcmp(program_key, TOKEN_PROGRAM, 32) != 0) return "an instruction of another program";
    if (ndata != 10 || data[0] != TRANSFER_CHECKED || naccounts != 4) return "a token instruction other than transferChecked";
    // accounts: source, mint, destination, authority
    if (accounts[3] != (unsigned) me) return "a transfer the device is not the authority of";
    if (accounts[0] == (unsigned) me || accounts[1] == (unsigned) me || accounts[2] == (unsigned) me) return "the device's key used as a token account";
    if (memcmp(keys + accounts[1] * 32, mint, 32) != 0) return "another mint";
    uint64_t amount = 0;
    for (int i = 7; i >= 0; i--) amount = (amount << 8) | data[1 + i];
    if (out->transfers == 0) {
      memcpy(out->destination, keys + accounts[2] * 32, 32);
      out->decimals = data[9];
    } else if (memcmp(out->destination, keys + accounts[2] * 32, 32) != 0 || out->decimals != data[9]) {
      return "transfers to more than one destination";
    }
    if (amount > max_amount || out->amount > max_amount - amount) return "amount over the device limit";
    out->amount += amount;
    out->transfers++;
  }
  if (out->transfers == 0) return "no transfer";

  if (v0) {
    unsigned ntables;
    if (!compact_u16(&r, &ntables)) return "truncated message";
    if (ntables != 0) return "address table lookups";
  }
  if (r.p != r.end) return "trailing bytes";
  return NULL;
}
