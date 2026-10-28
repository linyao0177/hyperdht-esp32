// Minimal libuv-compatible event loop for ESP-IDF. See include/uv.h.
//
// Phases per iteration follow libuv: timers, pending, prepare, poll,
// pending, check, closing. The poll phase uses lwIP select() on the open
// UDP sockets. lwIP reports pbuf exhaustion as ENOMEM rather than making a
// socket unwritable, so queued sends are retried with a 1 ms poll timeout.

#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "uv.h"

#define UV__ACTIVE    0x01
#define UV__CLOSING   0x02
#define UV__CLOSED    0x04
#define UV__RECEIVING 0x08
#define UV__IPV6      0x10

#define UV__MAX_POLL_UDP 16
#define UV__MAX_READS    32

#define uv__data(ptr, type, field) ((type *) ((char *) (ptr) - offsetof(type, field)))

static uv_esp_stats_t uv__stats;
static uv_esp_trace_t uv__trace[UV_ESP_TRACE_LEN];
static int uv__trace_len;
static int64_t uv__trace_epoch;
static uint32_t uv__trace_sends;

void
uv_esp_stats_get (uv_esp_stats_t *out) {
  *out = uv__stats;
}

void
uv_esp_stats_reset (void) {
  memset(&uv__stats, 0, sizeof(uv__stats));
  uv__trace_len = 0;
  uv__trace_sends = 0;
  uv__trace_epoch = esp_timer_get_time();
}

int
uv_esp_trace_get (const uv_esp_trace_t **out) {
  *out = uv__trace;
  return uv__trace_len;
}

_Static_assert(sizeof(uv_buf_t) == sizeof(struct iovec), "uv_buf_t must match struct iovec");
_Static_assert(offsetof(uv_buf_t, base) == offsetof(struct iovec, iov_base), "uv_buf_t must match struct iovec");
_Static_assert(offsetof(uv_buf_t, len) == offsetof(struct iovec, iov_len), "uv_buf_t must match struct iovec");

static inline void
q_init (uv__queue_t *q) {
  q->next = q;
  q->prev = q;
}

static inline bool
q_empty (const uv__queue_t *q) {
  return q->next == q;
}

// Inserts n before pos (at the tail when pos is the list head).
static inline void
q_insert_before (uv__queue_t *pos, uv__queue_t *n) {
  n->next = pos;
  n->prev = pos->prev;
  pos->prev->next = n;
  pos->prev = n;
}

static inline void
q_remove (uv__queue_t *n) {
  n->prev->next = n->next;
  n->next->prev = n->prev;
  q_init(n);
}

static inline void
q_move (uv__queue_t *from, uv__queue_t *to) {
  if (q_empty(from)) {
    q_init(to);
    return;
  }
  to->next = from->next;
  to->prev = from->prev;
  to->next->prev = to;
  to->prev->next = to;
  q_init(from);
}

static inline int
uv__err (int e) {
  return e > 0 ? -e : e;
}

static socklen_t
uv__addr_len (const struct sockaddr *addr) {
  return addr->sa_family == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
}

static void
uv__handle_init (uv_loop_t *loop, uv_handle_t *handle, uv_handle_type type) {
  handle->loop = loop;
  handle->type = type;
  handle->flags = 0;
  handle->close_cb = NULL;
  q_init(&handle->closing_node);
}

// loop

int
uv_loop_init (uv_loop_t *loop) {
  memset(loop, 0, sizeof(*loop));
  q_init(&loop->timers);
  q_init(&loop->prepares);
  q_init(&loop->checks);
  q_init(&loop->udps);
  q_init(&loop->pending);
  q_init(&loop->closing);
  uv_update_time(loop);
  return 0;
}

uint64_t
uv_hrtime (void) {
  return (uint64_t) esp_timer_get_time() * 1000;
}

void
uv_update_time (uv_loop_t *loop) {
  loop->time = (uint64_t) esp_timer_get_time() / 1000;
}

uint64_t
uv_now (const uv_loop_t *loop) {
  return loop->time;
}

void
uv_stop (uv_loop_t *loop) {
  loop->stop_flag = 1;
}

int
uv_loop_alive (const uv_loop_t *loop) {
  if (!q_empty(&loop->timers) || !q_empty(&loop->prepares) || !q_empty(&loop->checks)) return 1;
  if (loop->active_reqs || !q_empty(&loop->closing)) return 1;

  for (uv__queue_t *q = loop->udps.next; q != &loop->udps; q = q->next) {
    uv_udp_t *udp = uv__data(q, uv_udp_t, node);
    if (udp->flags & UV__RECEIVING) return 1;
  }

  return 0;
}

int
uv_loop_close (uv_loop_t *loop) {
  return uv_loop_alive(loop) ? UV_EBUSY : 0;
}

// timers

int
uv_timer_init (uv_loop_t *loop, uv_timer_t *handle) {
  uv__handle_init(loop, (uv_handle_t *) handle, UV_TIMER);
  handle->cb = NULL;
  handle->due = 0;
  handle->repeat = 0;
  handle->start_id = 0;
  q_init(&handle->node);
  return 0;
}

int
uv_timer_stop (uv_timer_t *handle) {
  if (!(handle->flags & UV__ACTIVE)) return 0;
  q_remove(&handle->node);
  handle->flags &= ~UV__ACTIVE;
  return 0;
}

int
uv_timer_start (uv_timer_t *handle, uv_timer_cb cb, uint64_t timeout, uint64_t repeat) {
  if (cb == NULL || (handle->flags & UV__CLOSING)) return UV_EINVAL;

  uv_loop_t *loop = handle->loop;

  uv_timer_stop(handle);

  handle->cb = cb;
  handle->due = loop->time + timeout;
  handle->repeat = repeat;
  handle->start_id = ++loop->timer_counter;

  // Keep the list sorted by due time; equal due times keep start order.
  uv__queue_t *q;
  for (q = loop->timers.next; q != &loop->timers; q = q->next) {
    uv_timer_t *t = uv__data(q, uv_timer_t, node);
    if (handle->due < t->due) break;
  }
  q_insert_before(q, &handle->node);

  handle->flags |= UV__ACTIVE;
  return 0;
}

static void
uv__run_timers (uv_loop_t *loop) {
  // Timers started from a callback in this pass wait for the next one.
  uint64_t limit = loop->timer_counter;

  while (!q_empty(&loop->timers)) {
    uv_timer_t *t = uv__data(loop->timers.next, uv_timer_t, node);
    if (t->due > loop->time || t->start_id > limit) break;

    uv_timer_stop(t);
    if (t->repeat) uv_timer_start(t, t->cb, t->repeat, t->repeat);
    uv__stats.timer_cbs++;
    t->cb(t);
  }
}

static int
uv__next_timeout (const uv_loop_t *loop) {
  if (q_empty(&loop->timers)) return -1;

  const uv_timer_t *t = uv__data(loop->timers.next, uv_timer_t, node);
  if (t->due <= loop->time) return 0;

  uint64_t diff = t->due - loop->time;
  return diff > INT_MAX ? INT_MAX : (int) diff;
}

// prepare / check

#define UV__LIST_HANDLE(name, type, list) \
  int uv_##name##_init (uv_loop_t *loop, uv_##name##_t *handle) { \
    uv__handle_init(loop, (uv_handle_t *) handle, type); \
    handle->cb = NULL; \
    q_init(&handle->node); \
    return 0; \
  } \
  int uv_##name##_start (uv_##name##_t *handle, uv_##name##_cb cb) { \
    if (cb == NULL) return UV_EINVAL; \
    if (handle->flags & UV__ACTIVE) return 0; \
    handle->cb = cb; \
    q_insert_before(&handle->loop->list, &handle->node); \
    handle->flags |= UV__ACTIVE; \
    return 0; \
  } \
  int uv_##name##_stop (uv_##name##_t *handle) { \
    if (!(handle->flags & UV__ACTIVE)) return 0; \
    q_remove(&handle->node); \
    handle->flags &= ~UV__ACTIVE; \
    return 0; \
  } \
  static void uv__run_##name (uv_loop_t *loop) { \
    uv__queue_t q; \
    q_move(&loop->list, &q); \
    while (!q_empty(&q)) { \
      uv__queue_t *n = q.next; \
      q_remove(n); \
      q_insert_before(&loop->list, n); \
      uv_##name##_t *h = uv__data(n, uv_##name##_t, node); \
      h->cb(h); \
    } \
  }

UV__LIST_HANDLE(prepare, UV_PREPARE, prepares)
UV__LIST_HANDLE(check, UV_CHECK, checks)

// requests

static void
uv__req_complete (uv_loop_t *loop, uv_req_t *req) {
  q_insert_before(&loop->pending, &req->pending_node);
}

static void
uv__run_pending (uv_loop_t *loop) {
  while (!q_empty(&loop->pending)) {
    uv__queue_t *n = loop->pending.next;
    q_remove(n);
    loop->active_reqs--;

    uv_req_t *req = uv__data(n, uv_req_t, pending_node);

    if (req->type == UV_UDP_SEND) {
      uv_udp_send_t *send = (uv_udp_send_t *) req;
      if (send->bufs != send->bufsml) free(send->bufs);
      send->bufs = NULL;
      if (send->cb) send->cb(send, send->status);
    } else if (req->type == UV_GETADDRINFO) {
      uv_getaddrinfo_t *gai = (uv_getaddrinfo_t *) req;
      gai->cb(gai, gai->status, gai->addrinfo);
    }
  }
}

// udp

int
uv_udp_init (uv_loop_t *loop, uv_udp_t *handle) {
  uv__handle_init(loop, (uv_handle_t *) handle, UV_UDP);
  handle->fd = -1;
  handle->sndbuf = 0;
  handle->rcvbuf = 0;
  handle->alloc_cb = NULL;
  handle->recv_cb = NULL;
  handle->send_queue_size = 0;
  handle->send_queue_count = 0;
  q_init(&handle->send_queue);
  q_insert_before(&loop->udps, &handle->node);
  return 0;
}

int
uv_udp_bind (uv_udp_t *handle, const struct sockaddr *addr, unsigned int flags) {
  if (handle->fd >= 0) return UV_EINVAL;
  if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6) return UV_EINVAL;

  int fd = socket(addr->sa_family, SOCK_DGRAM, IPPROTO_UDP);
  if (fd < 0) return uv__err(errno);

  int on = 1;
  if (flags & UV_UDP_REUSEADDR) setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
  if (addr->sa_family == AF_INET6 && (flags & UV_UDP_IPV6ONLY)) setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));

  int fl = fcntl(fd, F_GETFL, 0);
  fcntl(fd, F_SETFL, fl | O_NONBLOCK);

  if (bind(fd, addr, uv__addr_len(addr)) != 0) {
    int err = uv__err(errno);
    close(fd);
    return err;
  }

  handle->fd = fd;
  if (addr->sa_family == AF_INET6) handle->flags |= UV__IPV6;
  return 0;
}

int
uv_udp_getsockname (const uv_udp_t *handle, struct sockaddr *name, int *namelen) {
  if (handle->fd < 0) return UV_EBADF;
  socklen_t len = *namelen;
  if (getsockname(handle->fd, name, &len) != 0) return uv__err(errno);
  *namelen = (int) len;
  return 0;
}

int
uv_udp_set_ttl (uv_udp_t *handle, int ttl) {
  if (handle->fd < 0) return UV_EBADF;
  if (ttl < 1 || ttl > 255) return UV_EINVAL;
  // lwIP has no per-socket IPv6 hop limit; keep libudx's asserts happy.
  if (handle->flags & UV__IPV6) return 0;
  if (setsockopt(handle->fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) != 0) return uv__err(errno);
  return 0;
}

int
uv_udp_set_membership (uv_udp_t *handle, const char *multicast_addr, const char *interface_addr, uv_membership membership) {
  return UV_ENOSYS;
}

int
uv_udp_set_source_membership (uv_udp_t *handle, const char *multicast_addr, const char *interface_addr, const char *source_addr, uv_membership membership) {
  return UV_ENOSYS;
}

int
uv_udp_set_multicast_loop (uv_udp_t *handle, int on) {
  return UV_ENOSYS;
}

int
uv_udp_set_multicast_interface (uv_udp_t *handle, const char *interface_addr) {
  return UV_ENOSYS;
}

int
uv_udp_recv_start (uv_udp_t *handle, uv_alloc_cb alloc_cb, uv_udp_recv_cb recv_cb) {
  if (alloc_cb == NULL || recv_cb == NULL) return UV_EINVAL;
  if (handle->fd < 0) return UV_EBADF;
  if (handle->flags & UV__RECEIVING) return UV_EALREADY;
  handle->alloc_cb = alloc_cb;
  handle->recv_cb = recv_cb;
  handle->flags |= UV__RECEIVING | UV__ACTIVE;
  return 0;
}

int
uv_udp_recv_stop (uv_udp_t *handle) {
  handle->flags &= ~(UV__RECEIVING | UV__ACTIVE);
  handle->alloc_cb = NULL;
  handle->recv_cb = NULL;
  return 0;
}

static inline bool
uv__send_would_block (ssize_t r) {
  return r == UV_EAGAIN || r == UV_ENOMEM || r == UV_ENOBUFS;
}

static ssize_t
uv__udp_sendmsg (int fd, const uv_buf_t bufs[], unsigned int nbufs, const struct sockaddr *addr) {
  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_name = (void *) addr;
  msg.msg_namelen = uv__addr_len(addr);
  msg.msg_iov = (struct iovec *) bufs;
  msg.msg_iovlen = nbufs;

  int64_t t = esp_timer_get_time();
  ssize_t r;
  do {
    r = sendmsg(fd, &msg, 0);
  } while (r < 0 && errno == EINTR);
  uv__stats.send_us += esp_timer_get_time() - t;
  uv__trace_sends++;

  r = r < 0 ? uv__err(errno) : r;
  if (uv__send_would_block(r)) uv__stats.send_would_block++;
  else uv__stats.sends++;
  return r;
}

int
uv_udp_try_send (uv_udp_t *handle, const uv_buf_t bufs[], unsigned int nbufs, const struct sockaddr *addr) {
  if (handle->fd < 0) return UV_EBADF;
  if (handle->send_queue_count) return UV_EAGAIN;

  ssize_t r = uv__udp_sendmsg(handle->fd, bufs, nbufs, addr);
  if (uv__send_would_block(r)) return UV_EAGAIN;
  return (int) r;
}

static void
uv__udp_flush (uv_udp_t *handle) {
  while (!q_empty(&handle->send_queue)) {
    uv_udp_send_t *req = uv__data(handle->send_queue.next, uv_udp_send_t, pending_node);

    if (req->nbufs && req->bufs[0].len >= sizeof(req->head) && memcmp(req->head, req->bufs[0].base, sizeof(req->head)) != 0) {
      uv__stats.queued_head_changed++;
      memcpy(req->head, req->bufs[0].base, sizeof(req->head)); // count each send once
    }

    ssize_t r = uv__udp_sendmsg(handle->fd, req->bufs, req->nbufs, (struct sockaddr *) &req->addr);
    if (uv__send_would_block(r)) break;

    q_remove(&req->pending_node);
    handle->send_queue_count--;
    for (unsigned int i = 0; i < req->nbufs; i++) handle->send_queue_size -= req->bufs[i].len;

    req->status = r < 0 ? (int) r : 0;
    uv__req_complete(handle->loop, (uv_req_t *) req);
  }
}

int
uv_udp_send (uv_udp_send_t *req, uv_udp_t *handle, const uv_buf_t bufs[], unsigned int nbufs, const struct sockaddr *addr, uv_udp_send_cb send_cb) {
  if (handle->fd < 0) return UV_EBADF;
  if (handle->flags & UV__CLOSING) return UV_EINVAL;

  req->type = UV_UDP_SEND;
  req->handle = handle;
  req->cb = send_cb;
  req->status = 0;
  req->nbufs = nbufs;
  req->bufs = req->bufsml;

  if (nbufs > UV_UDP_SEND_BUFSML) {
    req->bufs = malloc(nbufs * sizeof(uv_buf_t));
    if (req->bufs == NULL) return UV_ENOMEM;
  }

  memcpy(req->bufs, bufs, nbufs * sizeof(uv_buf_t));
  memcpy(&req->addr, addr, uv__addr_len(addr));
  if (nbufs && bufs[0].len >= sizeof(req->head)) memcpy(req->head, bufs[0].base, sizeof(req->head));

  handle->loop->active_reqs++;
  handle->send_queue_count++;
  for (unsigned int i = 0; i < nbufs; i++) handle->send_queue_size += bufs[i].len;
  q_insert_before(&handle->send_queue, &req->pending_node);

  uv__udp_flush(handle);
  return 0;
}

static void
uv__udp_read (uv_udp_t *handle) {
  for (int i = 0; i < UV__MAX_READS; i++) {
    if ((handle->flags & (UV__RECEIVING | UV__CLOSING)) != UV__RECEIVING) return;

    uv_buf_t buf = {NULL, 0};
    handle->alloc_cb((uv_handle_t *) handle, 65536, &buf);
    if (buf.base == NULL || buf.len == 0) {
      handle->recv_cb(handle, UV_ENOBUFS, &buf, NULL, 0);
      return;
    }

    struct sockaddr_storage peer;
    socklen_t peer_len = sizeof(peer);
    int64_t t = esp_timer_get_time();
    ssize_t n = recvfrom(handle->fd, buf.base, buf.len, 0, (struct sockaddr *) &peer, &peer_len);
    uv__stats.recvfrom_us += esp_timer_get_time() - t;

    if (n < 0) {
      int err = errno;
      handle->recv_cb(handle, (err == EAGAIN || err == EWOULDBLOCK) ? 0 : uv__err(err), &buf, NULL, 0);
      return;
    }

    uv__stats.recvs++;
    t = esp_timer_get_time();
    handle->recv_cb(handle, n, &buf, (struct sockaddr *) &peer, 0);
    uv__stats.recv_cb_us += esp_timer_get_time() - t;
  }
}

static void
uv__io_poll (uv_loop_t *loop, int timeout) {
  uv_udp_t *udps[UV__MAX_POLL_UDP];
  int nudps = 0;
  bool sending = false;

  fd_set rfds;
  FD_ZERO(&rfds);
  int maxfd = -1;

  for (uv__queue_t *q = loop->udps.next; q != &loop->udps && nudps < UV__MAX_POLL_UDP; q = q->next) {
    uv_udp_t *udp = uv__data(q, uv_udp_t, node);
    if (udp->fd < 0) continue;

    udps[nudps++] = udp;
    if (udp->send_queue_count) sending = true;
    if (udp->flags & UV__RECEIVING) {
      FD_SET(udp->fd, &rfds);
      if (udp->fd > maxfd) maxfd = udp->fd;
    }
  }

  if (sending && (timeout < 0 || timeout > 1)) timeout = 1;

  uv__stats.polls++;
  if (timeout == 0) uv__stats.poll_timeout_0++;
  else if (timeout == 1) uv__stats.poll_timeout_1++;
  else uv__stats.poll_timeout_gt1++;
  int64_t poll_start = esp_timer_get_time();

  if (maxfd < 0) {
    if (timeout > 0) vTaskDelay(pdMS_TO_TICKS(timeout) ? pdMS_TO_TICKS(timeout) : 1);
    uv_update_time(loop);
    uv__stats.poll_idle++;
  } else {
    struct timeval tv;
    struct timeval *tvp = NULL;
    if (timeout >= 0) {
      tv.tv_sec = timeout / 1000;
      tv.tv_usec = (timeout % 1000) * 1000;
      tvp = &tv;
    }
    int n = select(maxfd + 1, &rfds, NULL, NULL, tvp);
    uv_update_time(loop);
    if (n <= 0) uv__stats.poll_idle++;
    if (n < 0) FD_ZERO(&rfds);
  }
  int64_t poll_end = esp_timer_get_time();
  uv__stats.poll_blocked_us += poll_end - poll_start;

  uv_esp_trace_t *tr = NULL;
  uint32_t recvs_before = uv__stats.recvs;
  if (uv__trace_len < UV_ESP_TRACE_LEN) {
    tr = &uv__trace[uv__trace_len++];
    tr->start_us = (uint32_t) (poll_start - uv__trace_epoch);
    tr->blocked_us = (uint32_t) (poll_end - poll_start);
    tr->sends = (uint16_t) uv__trace_sends;
  }
  uv__trace_sends = 0;

  for (int i = 0; i < nudps; i++) {
    uv_udp_t *udp = udps[i];
    if (udp->flags & UV__CLOSING) continue;
    if (udp->send_queue_count) uv__udp_flush(udp);
    if (udp->fd >= 0 && FD_ISSET(udp->fd, &rfds)) uv__udp_read(udp);
  }

  if (tr) tr->reads = (uint16_t) (uv__stats.recvs - recvs_before);
}

static void
uv__udp_close (uv_udp_t *handle) {
  uv_udp_recv_stop(handle);

  while (!q_empty(&handle->send_queue)) {
    uv_udp_send_t *req = uv__data(handle->send_queue.next, uv_udp_send_t, pending_node);
    q_remove(&req->pending_node);
    req->status = UV_ECANCELED;
    uv__req_complete(handle->loop, (uv_req_t *) req);
  }
  handle->send_queue_count = 0;
  handle->send_queue_size = 0;

  if (handle->fd >= 0) close(handle->fd);
  handle->fd = -1;
  q_remove(&handle->node);
}

// handles

void
uv_close (uv_handle_t *handle, uv_close_cb close_cb) {
  assert(!(handle->flags & (UV__CLOSING | UV__CLOSED)));

  handle->flags |= UV__CLOSING;
  handle->close_cb = close_cb;

  switch (handle->type) {
  case UV_TIMER:
    uv_timer_stop((uv_timer_t *) handle);
    break;
  case UV_PREPARE:
    uv_prepare_stop((uv_prepare_t *) handle);
    break;
  case UV_CHECK:
    uv_check_stop((uv_check_t *) handle);
    break;
  case UV_UDP:
    uv__udp_close((uv_udp_t *) handle);
    break;
  default:
    break;
  }

  q_insert_before(&handle->loop->closing, &handle->closing_node);
}

static void
uv__run_closing (uv_loop_t *loop) {
  // Cancelled send callbacks must run before the owning handle's close callback.
  uv__run_pending(loop);

  uv__queue_t q;
  q_move(&loop->closing, &q);

  while (!q_empty(&q)) {
    uv__queue_t *n = q.next;
    q_remove(n);

    uv_handle_t *handle = uv__data(n, uv_handle_t, closing_node);
    handle->flags = (handle->flags & ~(UV__CLOSING | UV__ACTIVE)) | UV__CLOSED;
    if (handle->close_cb) handle->close_cb(handle);
  }
}

int
uv_is_active (const uv_handle_t *handle) {
  return (handle->flags & UV__ACTIVE) != 0;
}

int
uv_is_closing (const uv_handle_t *handle) {
  return (handle->flags & (UV__CLOSING | UV__CLOSED)) != 0;
}

int
uv_fileno (const uv_handle_t *handle, uv_os_fd_t *fd) {
  if (handle->type != UV_UDP) return UV_EINVAL;
  int f = ((const uv_udp_t *) handle)->fd;
  if (f < 0) return UV_EBADF;
  *fd = f;
  return 0;
}

// lwIP buffers by pbuf count (CONFIG_LWIP_UDP_RECVMBOX_SIZE), not bytes, so
// libudx's 1 MB SO_RCVBUF request is recorded but not applied.
int
uv_send_buffer_size (uv_handle_t *handle, int *value) {
  if (handle->type != UV_UDP) return UV_EINVAL;
  uv_udp_t *udp = (uv_udp_t *) handle;
  if (*value == 0) *value = udp->sndbuf;
  else udp->sndbuf = *value;
  return 0;
}

int
uv_recv_buffer_size (uv_handle_t *handle, int *value) {
  if (handle->type != UV_UDP) return UV_EINVAL;
  uv_udp_t *udp = (uv_udp_t *) handle;
  if (*value == 0) *value = udp->rcvbuf;
  else udp->rcvbuf = *value;
  return 0;
}

// run

int
uv_run (uv_loop_t *loop, uv_run_mode mode) {
  int r = uv_loop_alive(loop);
  if (!r) uv_update_time(loop);

  while (r != 0 && loop->stop_flag == 0) {
    uv__stats.iterations++;
    uv_update_time(loop);
    uv__run_timers(loop);
    uv__run_pending(loop);
    uv__run_prepare(loop);

    int timeout = 0;
    if (mode != UV_RUN_NOWAIT && q_empty(&loop->pending) && q_empty(&loop->closing) && loop->stop_flag == 0) {
      timeout = uv__next_timeout(loop);
    }

    uv__io_poll(loop, timeout);
    uv__run_pending(loop);
    uv__run_check(loop);
    uv__run_closing(loop);

    if (mode == UV_RUN_ONCE) {
      uv_update_time(loop);
      uv__run_timers(loop);
    }

    r = uv_loop_alive(loop);
    if (mode != UV_RUN_DEFAULT) break;
  }

  loop->stop_flag = 0;
  return r;
}

// dns / interfaces

int
uv_getaddrinfo (uv_loop_t *loop, uv_getaddrinfo_t *req, uv_getaddrinfo_cb cb, const char *node, const char *service, const struct addrinfo *hints) {
  if (cb == NULL) return UV_EINVAL;

  req->type = UV_GETADDRINFO;
  req->loop = loop;
  req->cb = cb;
  req->addrinfo = NULL;

  // Blocks the loop for the DNS round trip; acceptable for bootstrap lookups.
  int r = getaddrinfo(node, service, hints, &req->addrinfo);
  req->status = r == 0 ? 0 : UV_EAI_NONAME;

  loop->active_reqs++;
  uv__req_complete(loop, (uv_req_t *) req);
  return 0;
}

void
uv_freeaddrinfo (struct addrinfo *ai) {
  if (ai) freeaddrinfo(ai);
}

int
uv_interface_addresses (uv_interface_address_t **addresses, int *count) {
  *addresses = NULL;
  *count = 0;
  return UV_ENOSYS;
}

void
uv_free_interface_addresses (uv_interface_address_t *addresses, int count) {
  free(addresses);
}

// misc

uv_buf_t
uv_buf_init (char *base, unsigned int len) {
  uv_buf_t buf = {base, len};
  return buf;
}

const char *
uv_err_name (int err) {
  switch (err) {
  case UV_EAGAIN: return "EAGAIN";
  case UV_ECANCELED: return "ECANCELED";
  case UV_ECONNRESET: return "ECONNRESET";
  case UV_EINVAL: return "EINVAL";
  case UV_ENOMEM: return "ENOMEM";
  case UV_ENOTCONN: return "ENOTCONN";
  case UV_EPIPE: return "EPIPE";
  case UV_ETIMEDOUT: return "ETIMEDOUT";
  case UV_EOF: return "EOF";
  case UV_EAI_NONAME: return "EAI_NONAME";
  default: return "UNKNOWN";
  }
}

const char *
uv_strerror (int err) {
  if (err == UV_EOF) return "end of file";
  if (err == UV_EAI_NONAME) return "unknown node or service";
  return strerror(-err);
}

int
uv_ip4_addr (const char *ip, int port, struct sockaddr_in *addr) {
  memset(addr, 0, sizeof(*addr));
  addr->sin_family = AF_INET;
  addr->sin_port = htons(port);
  return inet_pton(AF_INET, ip, &addr->sin_addr) == 1 ? 0 : UV_EINVAL;
}

int
uv_ip4_name (const struct sockaddr_in *src, char *dst, size_t size) {
  return inet_ntop(AF_INET, &src->sin_addr, dst, size) ? 0 : UV_ENOSPC;
}
