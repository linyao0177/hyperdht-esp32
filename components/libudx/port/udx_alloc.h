// Force-included into every libudx translation unit so its heap usage can be
// measured separately from the rest of the firmware.

#ifndef UDX_ALLOC_H
#define UDX_ALLOC_H

#include <stddef.h>
#include <stdlib.h>

typedef struct {
  size_t current;   // bytes currently allocated by libudx
  size_t peak;      // high-water mark of `current`
  size_t allocs;    // number of successful allocations
  size_t failures;  // number of failed allocations
} udx_alloc_stats_t;

void *
udx_alloc_malloc (size_t size);

void *
udx_alloc_calloc (size_t n, size_t size);

void *
udx_alloc_realloc (void *ptr, size_t size);

void
udx_alloc_free (void *ptr);

void
udx_alloc_get_stats (udx_alloc_stats_t *out);

void
udx_alloc_reset_peak (void);

#ifdef UDX_ALLOC_TRACK
#define malloc(s)     udx_alloc_malloc(s)
#define calloc(n, s)  udx_alloc_calloc(n, s)
#define realloc(p, s) udx_alloc_realloc(p, s)
#define free(p)       udx_alloc_free(p)
#endif

#endif // UDX_ALLOC_H
