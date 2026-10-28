#ifndef POC_UDX_ECHO_H
#define POC_UDX_ECHO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint32_t rwnd_max;     // 0 = libudx default
  bool ok;
  const char *error;
  size_t bytes;          // bytes echoed back and verified
  uint32_t elapsed_ms;   // first write to last echoed byte
  uint32_t rtt_min_ms;
  uint32_t srtt_ms;      // smoothed RTT when the run ended
  uint32_t cwnd;         // congestion window (packets) when the run ended
  uint32_t pacing_bytes_per_ms;
  uint32_t packets_tx;
  uint32_t packets_rx;
  uint32_t retransmits;
  uint32_t rto_count;
  size_t heap_before;    // free heap before the run
  size_t heap_low;       // lowest free heap during the run
  size_t heap_after;     // free heap after everything was released
  size_t udx_baseline;   // libudx bytes held after udx_init + bind
  size_t udx_peak;       // libudx peak bytes during the run
  size_t udx_allocs;     // libudx allocation count during the run
  size_t udx_leaked;     // libudx bytes still held after teardown
  size_t udx_alloc_failures;
  size_t app_buffers;    // write buffers owned by the test itself
} poc_echo_result_t;

void
poc_udx_print_sizes (void);

// Runs one echo session against host/echo-server.js. Blocks until done.
void
poc_udx_echo_run (uint32_t rwnd_max, poc_echo_result_t *out);

#endif
