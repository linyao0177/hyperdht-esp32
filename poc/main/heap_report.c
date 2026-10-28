#include <stdio.h>

#include "esp_heap_caps.h"

#include "heap_report.h"

void
poc_heap_sample (poc_heap_t *out) {
  out->free = heap_caps_get_free_size(MALLOC_CAP_8BIT);
  out->min_free = heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT);
  out->largest = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
}

poc_heap_t
poc_heap_checkpoint (const char *label) {
  poc_heap_t h;
  poc_heap_sample(&h);
  printf("POC|heap|%s|free=%u|min_free=%u|largest_block=%u\n", label, (unsigned) h.free, (unsigned) h.min_free, (unsigned) h.largest);
  return h;
}

void
poc_heap_watch_start (void) {
  heap_caps_monitor_local_minimum_free_size_start();
}

size_t
poc_heap_watch_stop (void) {
  size_t low = heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT);
  heap_caps_monitor_local_minimum_free_size_stop();
  return low;
}
