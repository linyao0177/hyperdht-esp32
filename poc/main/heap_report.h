#ifndef POC_HEAP_REPORT_H
#define POC_HEAP_REPORT_H

#include <stddef.h>

typedef struct {
  size_t free;
  size_t min_free;
  size_t largest;
} poc_heap_t;

// Reads the 8-bit capable (internal DRAM) heap.
void
poc_heap_sample (poc_heap_t *out);

// Prints a `POC|heap|<label>|...` line and returns the sample.
poc_heap_t
poc_heap_checkpoint (const char *label);

// Brackets a phase whose lowest free-heap point should be measured.
void
poc_heap_watch_start (void);

// Returns the lowest free heap seen since poc_heap_watch_start().
size_t
poc_heap_watch_stop (void);

#endif
