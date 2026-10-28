// UDX echo session against host/echo-server.js.
//
// Handshake over the raw socket: the device sends "hello <id>" until the
// host answers "ready <id>", then both sides connect a UDX stream. The device
// writes CONFIG_POC_ECHO_BYTES of a known pattern and verifies the echo.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_random.h"
#include "sdkconfig.h"
#include "udx.h"
#include "udx_alloc.h"
#include "uv.h"

#include "heap_report.h"
#include "udx_echo.h"

#define HELLO_INTERVAL_MS 500
#define PEER_TIMEOUT_MS   15000
#define RUN_TIMEOUT_MS    120000

typedef struct {
  uv_loop_t loop;
  udx_t udx;
  udx_socket_t socket;
  udx_stream_t stream;
  udx_socket_send_t hello_req;
  uv_timer_t hello_timer;
  uv_timer_t deadline;

  struct sockaddr_in peer;
  uint32_t local_id;
  char hello[32];
  bool hello_in_flight;
  bool stream_open;
  bool finished;

  size_t written;
  size_t received;
  uint32_t writes_in_flight;
  uint64_t started_at;

  poc_echo_result_t *result;
} echo_t;

static inline uint8_t
pattern_at (size_t offset) {
  return (uint8_t) (offset * 31 + (offset >> 8));
}

static void
on_handle_close (uv_handle_t *handle) {
  (void) handle;
}

static void
on_socket_close (udx_socket_t *socket) {
  echo_t *e = socket->data;
  uv_close((uv_handle_t *) &e->hello_timer, on_handle_close);
  uv_close((uv_handle_t *) &e->deadline, on_handle_close);
}

static void
finish (echo_t *e, const char *error) {
  if (e->finished) return;
  e->finished = true;

  e->result->ok = error == NULL;
  e->result->error = error;
  e->result->elapsed_ms = (uint32_t) (uv_now(&e->loop) - e->started_at);

  uv_esp_stats_t st;
  uv_esp_stats_get(&st);
  printf("POC|uvstats|ms=%lu|iterations=%lu|polls=%lu|t0=%lu|t1=%lu|tgt1=%lu|idle=%lu|blocked_ms=%lu"
         "|timer_cbs=%lu|recvs=%lu|sends=%lu|would_block=%lu|send_ms=%lu|recv_cb_ms=%lu|recvfrom_ms=%lu|queued_head_changed=%lu\n",
         (unsigned long) e->result->elapsed_ms, (unsigned long) st.iterations, (unsigned long) st.polls,
         (unsigned long) st.poll_timeout_0, (unsigned long) st.poll_timeout_1, (unsigned long) st.poll_timeout_gt1,
         (unsigned long) st.poll_idle, (unsigned long) (st.poll_blocked_us / 1000), (unsigned long) st.timer_cbs,
         (unsigned long) st.recvs, (unsigned long) st.sends, (unsigned long) st.send_would_block,
         (unsigned long) (st.send_us / 1000), (unsigned long) (st.recv_cb_us / 1000), (unsigned long) (st.recvfrom_us / 1000), (unsigned long) st.queued_head_changed);

  const uv_esp_trace_t *trace;
  int trace_len = uv_esp_trace_get(&trace);
  for (int i = 0; i < trace_len; i++) {
    printf("POC|uvtrace|%d|start_ms=%.1f|blocked_ms=%.1f|sends_before=%u|reads=%u\n", i,
           trace[i].start_us / 1000.0, trace[i].blocked_us / 1000.0, trace[i].sends, trace[i].reads);
  }

  uv_timer_stop(&e->hello_timer);
  uv_timer_stop(&e->deadline);

  if (e->stream_open) {
    udx_stream_t *s = &e->stream;
    e->result->rtt_min_ms = udx_rtt_min(s);
    e->result->srtt_ms = s->srtt;
    e->result->cwnd = s->cwnd;
    e->result->pacing_bytes_per_ms = s->pacing_bytes_per_ms;
    e->result->packets_tx = (uint32_t) s->packets_tx;
    e->result->packets_rx = (uint32_t) s->packets_rx;
    e->result->retransmits = s->retransmit_count;
    e->result->rto_count = s->lifetime_rto_count;
    udx_stream_destroy(&e->stream); // socket closes from on_stream_finalize
  } else {
    udx_socket_close(&e->socket);
  }
}

static void
on_stream_close (udx_stream_t *stream, int status) {
  echo_t *e = stream->data;
  if (status < 0) finish(e, uv_strerror(status));
}

static void
on_stream_finalize (udx_stream_t *stream) {
  echo_t *e = stream->data;
  e->stream_open = false;
  udx_socket_close(&e->socket);
}

static void
pump_writes (echo_t *e);

static void
on_ack (udx_stream_write_t *req, int status, int unordered) {
  (void) unordered;
  echo_t *e = req->data;
  e->writes_in_flight--;
  free(req);

  if (e->finished) return;
  if (status < 0) {
    finish(e, uv_strerror(status));
    return;
  }
  pump_writes(e);
}

static void
pump_writes (echo_t *e) {
  const size_t total = CONFIG_POC_ECHO_BYTES;

  while (e->written < total && e->writes_in_flight < CONFIG_POC_MAX_INFLIGHT_WRITES) {
    size_t len = total - e->written;
    if (len > CONFIG_POC_CHUNK_BYTES) len = CONFIG_POC_CHUNK_BYTES;

    size_t req_size = udx_stream_write_sizeof(1);
    udx_stream_write_t *req = malloc(req_size + len);
    if (req == NULL) {
      finish(e, "out of memory for write");
      return;
    }

    uint8_t *data = (uint8_t *) req + req_size;
    for (size_t i = 0; i < len; i++) data[i] = pattern_at(e->written + i);

    req->data = e;
    uv_buf_t buf = uv_buf_init((char *) data, len);
    int err = udx_stream_write(req, &e->stream, &buf, 1, on_ack);
    if (err < 0) {
      free(req);
      finish(e, uv_strerror(err));
      return;
    }

    e->written += len;
    e->writes_in_flight++;
  }
}

// Logs where the echo diverged and, if the bytes match the pattern at some
// other stream offset, how far they were shifted.
static void
report_mismatch (echo_t *e, const uint8_t *data, size_t len, size_t at) {
  size_t offset = e->received + at;
  size_t probe = len - at < 32 ? len - at : 32;

  long shift = 0;
  bool found = false;
  for (long d = -16384; d <= 16384 && !found; d++) {
    if (d == 0 || (long) offset + d < 0) continue;
    size_t k = 0;
    while (k < probe && data[at + k] == pattern_at(offset + d + k)) k++;
    if (k == probe) {
      shift = d;
      found = true;
    }
  }

  printf("POC|mismatch|offset=%u|chunk_offset=%u|chunk_len=%u|index=%u|expected=%02x|got=%02x|shift=%s%ld|bytes=",
         (unsigned) offset, (unsigned) e->received, (unsigned) len, (unsigned) at,
         pattern_at(offset), data[at], found ? "" : "none:", shift);
  for (size_t k = at; k < len && k < at + 16; k++) printf("%02x", data[k]);
  printf("\n");
}

static void
on_read (udx_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
  echo_t *e = stream->data;
  if (e->finished) return;

  if (nread < 0) {
    finish(e, nread == UV_EOF ? "peer ended early" : uv_strerror(nread));
    return;
  }

  for (ssize_t i = 0; i < nread; i++) {
    if ((uint8_t) buf->base[i] != pattern_at(e->received + i)) {
      report_mismatch(e, (const uint8_t *) buf->base, (size_t) nread, (size_t) i);
      finish(e, "echo mismatch");
      return;
    }
  }

  e->received += nread;
  e->result->bytes = e->received;

  if (e->received == CONFIG_POC_ECHO_BYTES) finish(e, NULL);
}

static void
on_socket_recv (udx_socket_t *socket, ssize_t len, const uv_buf_t *buf, const struct sockaddr *from) {
  echo_t *e = socket->data;
  if (e->stream_open || e->finished || len <= 6) return;

  char msg[32];
  size_t n = (size_t) len < sizeof(msg) - 1 ? (size_t) len : sizeof(msg) - 1;
  memcpy(msg, buf->base, n);
  msg[n] = '\0';

  unsigned long remote_id;
  if (sscanf(msg, "ready %lu", &remote_id) != 1) return;

  int err = udx_stream_init(&e->udx, &e->stream, e->local_id, on_stream_close, on_stream_finalize);
  if (err) {
    finish(e, uv_strerror(err));
    return;
  }
  e->stream.data = e;
  e->stream_open = true;

  if (e->result->rwnd_max) udx_stream_set_rwnd_max(&e->stream, e->result->rwnd_max);

  err = udx_stream_connect(&e->stream, &e->socket, (uint32_t) remote_id, (const struct sockaddr *) &e->peer);
  if (err == 0) err = udx_stream_read_start(&e->stream, on_read);
  if (err) {
    finish(e, uv_strerror(err));
    return;
  }

  uv_timer_stop(&e->hello_timer);
  e->started_at = uv_now(&e->loop);
  uv_esp_stats_reset();
  pump_writes(e);
}

static void
on_hello_sent (udx_socket_send_t *req, int status) {
  (void) status;
  echo_t *e = req->data;
  e->hello_in_flight = false;
}

static void
on_hello_timer (uv_timer_t *timer) {
  echo_t *e = timer->data;
  if (uv_now(&e->loop) - e->started_at > PEER_TIMEOUT_MS) {
    finish(e, "no answer from echo peer");
    return;
  }
  if (e->hello_in_flight) return;

  uv_buf_t buf = uv_buf_init(e->hello, strlen(e->hello));
  e->hello_req.data = e;
  if (udx_socket_send(&e->hello_req, &e->socket, &buf, 1, (const struct sockaddr *) &e->peer, on_hello_sent) == 0) {
    e->hello_in_flight = true;
  }
}

static void
on_deadline (uv_timer_t *timer) {
  finish(timer->data, "run timed out");
}

void
poc_udx_print_sizes (void) {
  printf("POC|udx|sizeof|udx_t=%u|udx_socket_t=%u|udx_stream_t=%u|udx_packet_t=%u|uv_udp_send_t=%u|uv_timer_t=%u\n",
         (unsigned) sizeof(udx_t), (unsigned) sizeof(udx_socket_t), (unsigned) sizeof(udx_stream_t),
         (unsigned) sizeof(udx_packet_t), (unsigned) sizeof(uv_udp_send_t), (unsigned) sizeof(uv_timer_t));
}

void
poc_udx_echo_run (uint32_t rwnd_max, poc_echo_result_t *out) {
  memset(out, 0, sizeof(*out));
  out->rwnd_max = rwnd_max;
  out->app_buffers = CONFIG_POC_MAX_INFLIGHT_WRITES * (udx_stream_write_sizeof(1) + CONFIG_POC_CHUNK_BYTES);

  udx_alloc_stats_t before_stats;
  udx_alloc_get_stats(&before_stats);

  poc_heap_t h;
  poc_heap_sample(&h);
  out->heap_before = h.free;
  poc_heap_watch_start();

  echo_t *e = calloc(1, sizeof(echo_t));
  if (e == NULL) {
    out->error = "out of memory for context";
    poc_heap_watch_stop();
    return;
  }
  e->result = out;
  e->local_id = (esp_random() & 0x7fffffff) | 1;
  snprintf(e->hello, sizeof(e->hello), "hello %lu", (unsigned long) e->local_id);

  if (uv_ip4_addr(CONFIG_POC_PEER_HOST, CONFIG_POC_PEER_PORT, &e->peer) != 0) {
    out->error = "bad CONFIG_POC_PEER_HOST";
    free(e);
    poc_heap_watch_stop();
    return;
  }

  uv_loop_init(&e->loop);
  udx_init(&e->loop, &e->udx, NULL);
  udx_socket_init(&e->udx, &e->socket, on_socket_close);
  e->socket.data = e;

  struct sockaddr_in local;
  uv_ip4_addr("0.0.0.0", CONFIG_POC_LOCAL_PORT, &local);
  int err = udx_socket_bind(&e->socket, (const struct sockaddr *) &local, 0);
  if (err == 0) err = udx_socket_recv_start(&e->socket, on_socket_recv);

  udx_alloc_stats_t s;
  udx_alloc_get_stats(&s);
  out->udx_baseline = s.current - before_stats.current;
  udx_alloc_reset_peak();

  uv_timer_init(&e->loop, &e->hello_timer);
  uv_timer_init(&e->loop, &e->deadline);
  e->hello_timer.data = e;
  e->deadline.data = e;
  e->started_at = uv_now(&e->loop);

  if (err) {
    finish(e, uv_strerror(err));
  } else {
    uv_timer_start(&e->hello_timer, on_hello_timer, 0, HELLO_INTERVAL_MS);
    uv_timer_start(&e->deadline, on_deadline, RUN_TIMEOUT_MS, 0);
  }

  uv_run(&e->loop, UV_RUN_DEFAULT);

  if (!e->finished) finish(e, "loop exited early");
  if (uv_loop_close(&e->loop) != 0 && out->ok) {
    out->ok = false;
    out->error = "loop still busy after run";
  }

  udx_alloc_get_stats(&s);
  out->udx_peak = s.peak - before_stats.current;
  out->udx_allocs = s.allocs - before_stats.allocs;
  out->udx_leaked = s.current - before_stats.current;
  out->udx_alloc_failures = s.failures - before_stats.failures;

  free(e);

  out->heap_low = poc_heap_watch_stop();
  poc_heap_sample(&h);
  out->heap_after = h.free;
}
