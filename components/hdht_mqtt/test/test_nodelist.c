// Desktop check of the node list tally against the JS (packages/boat-registry
// test/nodelist-c.js builds and drives it).
//   test_nodelist <trusted> <pick> <page hex | -> <record value hex | ->...
//     -> "<epoch> <votes> <page> <verifier hex,...> <node hex,...>" or "NONE";
//        the page given must be page pick % pages of the agreed list ("BADPAGE" if not)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

#include "hdht_mqtt_nodelist.h"

int
main (int argc, char **argv) {
  if (sodium_init() < 0 || argc < 5) return 2;
  size_t trusted = strtoul(argv[1], NULL, 10);
  unsigned pick = (unsigned) strtoul(argv[2], NULL, 10);
  const char *page_hex = argv[3];
  argv += 2;
  argc -= 2;
  size_t n = (size_t) argc - 2;
  const uint8_t **blobs = calloc(n, sizeof(*blobs));
  size_t *lens = calloc(n, sizeof(*lens));
  for (size_t i = 0; i < n; i++) {
    const char *h = argv[i + 2];
    if (strcmp(h, "-") == 0) continue;
    size_t vlen = strlen(h) / 2;
    uint8_t *value = malloc(vlen + 1);
    sodium_hex2bin(value, vlen, h, strlen(h), NULL, NULL, NULL);
    uint8_t *blob = malloc(1000);
    int len = hdht_mqtt_nodelist_from_record(value, vlen, blob, 1000);
    free(value);
    if (len > 0) {
      blobs[i] = blob;
      lens[i] = (size_t) len;
    } else {
      free(blob);
    }
  }
  hdht_mqtt_nodelist_t l;
  size_t votes = 0;
  if (hdht_mqtt_nodelist_tally(blobs, lens, n, trusted, &l, &votes) != 0) {
    printf("NONE\n");
    return 0;
  }
  if (l.pages_len > 0) {
    size_t plen = strlen(page_hex) / 2;
    uint8_t *page = malloc(plen + 1);
    sodium_hex2bin(page, plen, page_hex, strlen(page_hex), NULL, NULL, NULL);
    if (strcmp(page_hex, "-") == 0 || hdht_mqtt_nodelist_decode_page(page, plen, (uint8_t) (pick % l.pages_len), &l) != 0) {
      printf("BADPAGE\n");
      return 0;
    }
  }
  char hex[65];
  printf("%llu %u %u ", (unsigned long long) l.epoch, (unsigned) votes, (unsigned) l.page);
  for (int i = 0; i < l.verifiers_len; i++) printf("%s%s", i ? "," : "", sodium_bin2hex(hex, sizeof(hex), l.verifiers[i], 32));
  printf(" ");
  for (int i = 0; i < l.nodes_len; i++) printf("%s%s", i ? "," : "", sodium_bin2hex(hex, sizeof(hex), l.nodes[i], 32));
  printf("\n");
  return 0;
}
