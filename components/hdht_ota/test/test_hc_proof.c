// hc_proof against proofs made by hypercore itself (packages/boat-ota/test/run.js
// writes them): test_hc_proof <vectors file>
//
// The file has lines of hex: "key <hex>", "signer <hex>", "head <expect> <wire>",
// "block <expect> <wire>", where <expect> is "ok" or a reason with '_' for spaces.
// Blocks are checked against the last head that verified.

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "hc_proof.h"

static uint8_t *
unhex (const char *hex, size_t *len) {
  size_t n = strlen(hex) / 2;
  uint8_t *out = malloc(n ? n : 1);
  sodium_hex2bin(out, n, hex, strlen(hex), NULL, len, NULL);
  return out;
}

int
main (int argc, char **argv) {
  if (argc != 2 || sodium_init() < 0) return 2;
  FILE *f = fopen(argv[1], "r");
  if (!f) return 2;
  static char line[1 << 17];
  uint8_t key[32] = {0}, signer[32] = {0};
  static hc_head_t head;
  int passed = 0, failed = 0;
  while (fgets(line, sizeof(line), f)) {
    line[strcspn(line, "\n")] = 0;
    char *kind = strtok(line, " "), *a = strtok(NULL, " "), *b = strtok(NULL, " ");
    if (!kind || !a) continue;
    size_t len;
    if (strcmp(kind, "key") == 0 || strcmp(kind, "signer") == 0) {
      uint8_t *v = unhex(a, &len);
      memcpy(kind[0] == 'k' ? key : signer, v, 32);
      free(v);
      continue;
    }
    for (char *p = a; *p; p++) if (*p == '_') *p = ' ';
    uint8_t *buf = unhex(b, &len);
    const char *why;
    if (strcmp(kind, "head") == 0) {
      hc_head_t h;
      uint64_t latest;
      why = hc_decode_head(buf, len, &h, &latest);
      if (!why) why = hc_verify_head(&h, key, signer);
      if (!why) head = h;
    } else {
      uint64_t index;
      static hc_node_t nodes[HC_MAX_NODES];
      size_t n, dlen;
      const uint8_t *data;
      why = hc_decode_block(buf, len, &index, nodes, &n, &data, &dlen);
      if (!why) why = hc_verify_block(&head, index, data, dlen, nodes, n);
    }
    bool ok = strcmp(a, "ok") == 0 ? why == NULL : (why != NULL && strcmp(why, a) == 0);
    ok ? passed++ : failed++;
    printf("%s %s: expected %s, got %s\n", ok ? "PASS" : "FAIL", kind, a, why ? why : "ok");
    free(buf);
  }
  printf("\n%d of %d passed\n", passed, passed + failed);
  return failed ? 1 : 0;
}
