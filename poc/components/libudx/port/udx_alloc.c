// Heap accounting for libudx. Each block carries a small header with its
// size. Only touched from the event loop task, so no locking.

#include <stdint.h>
#include <string.h>

#include "udx_alloc.h"

typedef struct {
  size_t size;
  size_t pad; // keep the payload 8-byte aligned on RV32
} udx_alloc_header_t;

static udx_alloc_stats_t stats;

static void
on_alloc (size_t size) {
  stats.current += size;
  stats.allocs++;
  if (stats.current > stats.peak) stats.peak = stats.current;
}

void *
udx_alloc_malloc (size_t size) {
  udx_alloc_header_t *h = malloc(sizeof(*h) + size);
  if (h == NULL) {
    stats.failures++;
    return NULL;
  }
  h->size = size;
  on_alloc(size);
  return h + 1;
}

void *
udx_alloc_calloc (size_t n, size_t size) {
  if (size && n > SIZE_MAX / size) return NULL;
  void *p = udx_alloc_malloc(n * size);
  if (p) memset(p, 0, n * size);
  return p;
}

void *
udx_alloc_realloc (void *ptr, size_t size) {
  if (ptr == NULL) return udx_alloc_malloc(size);

  udx_alloc_header_t *old = (udx_alloc_header_t *) ptr - 1;
  size_t old_size = old->size;

  udx_alloc_header_t *h = realloc(old, sizeof(*h) + size);
  if (h == NULL) {
    stats.failures++;
    return NULL;
  }

  h->size = size;
  stats.current -= old_size;
  on_alloc(size);
  return h + 1;
}

void
udx_alloc_free (void *ptr) {
  if (ptr == NULL) return;
  udx_alloc_header_t *h = (udx_alloc_header_t *) ptr - 1;
  stats.current -= h->size;
  free(h);
}

void
udx_alloc_get_stats (udx_alloc_stats_t *out) {
  *out = stats;
}

void
udx_alloc_reset_peak (void) {
  stats.peak = stats.current;
}
