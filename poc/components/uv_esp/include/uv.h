// Minimal libuv-compatible API for ESP-IDF (lwIP sockets + FreeRTOS).
//
// Implements only the subset libudx needs: UDP, timers, prepare/check
// handles, getaddrinfo and a handful of helpers. Single-threaded: a loop
// and all of its handles must be used from one task.

#ifndef UV_ESP_H
#define UV_ESP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "lwip/netdb.h"
#include "lwip/sockets.h"

#define UV_EADDRINUSE   (-EADDRINUSE)
#define UV_EAGAIN       (-EAGAIN)
#define UV_EALREADY     (-EALREADY)
#define UV_EBADF        (-EBADF)
#define UV_EBUSY        (-EBUSY)
#define UV_ECANCELED    (-ECANCELED)
#define UV_ECONNRESET   (-ECONNRESET)
#define UV_EFAULT       (-EFAULT)
#define UV_EINVAL       (-EINVAL)
#define UV_EISCONN      (-EISCONN)
#define UV_EMSGSIZE     (-EMSGSIZE)
#define UV_ENOBUFS      (-ENOBUFS)
#define UV_ENOMEM       (-ENOMEM)
#define UV_ENOSPC       (-ENOSPC)
#define UV_ENOSYS       (-ENOSYS)
#define UV_ENOTCONN     (-ENOTCONN)
#define UV_ENOTSOCK     (-ENOTSOCK)
#define UV_EPIPE        (-EPIPE)
#define UV_ETIMEDOUT    (-ETIMEDOUT)
#define UV_EAI_NONAME   (-3008)
#define UV_EOF          (-4095)

typedef int uv_os_sock_t;
typedef int uv_os_fd_t;

typedef struct {
  char *base;
  size_t len;
} uv_buf_t;

typedef struct uv__queue_s {
  struct uv__queue_s *next;
  struct uv__queue_s *prev;
} uv__queue_t;

typedef enum {
  UV_UNKNOWN_HANDLE = 0,
  UV_TIMER,
  UV_PREPARE,
  UV_CHECK,
  UV_UDP,
} uv_handle_type;

typedef enum {
  UV_UNKNOWN_REQ = 0,
  UV_UDP_SEND,
  UV_GETADDRINFO,
} uv_req_type;

typedef enum {
  UV_RUN_DEFAULT = 0,
  UV_RUN_ONCE,
  UV_RUN_NOWAIT,
} uv_run_mode;

typedef enum {
  UV_LEAVE_GROUP = 0,
  UV_JOIN_GROUP,
} uv_membership;

enum uv_udp_flags {
  UV_UDP_IPV6ONLY = 1,
  UV_UDP_PARTIAL = 2,
  UV_UDP_REUSEADDR = 4,
};

typedef struct uv_loop_s uv_loop_t;
typedef struct uv_handle_s uv_handle_t;
typedef struct uv_timer_s uv_timer_t;
typedef struct uv_prepare_s uv_prepare_t;
typedef struct uv_check_s uv_check_t;
typedef struct uv_udp_s uv_udp_t;
typedef struct uv_req_s uv_req_t;
typedef struct uv_udp_send_s uv_udp_send_t;
typedef struct uv_getaddrinfo_s uv_getaddrinfo_t;

typedef void (*uv_close_cb)(uv_handle_t *handle);
typedef void (*uv_timer_cb)(uv_timer_t *handle);
typedef void (*uv_prepare_cb)(uv_prepare_t *handle);
typedef void (*uv_check_cb)(uv_check_t *handle);
typedef void (*uv_alloc_cb)(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
typedef void (*uv_udp_recv_cb)(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags);
typedef void (*uv_udp_send_cb)(uv_udp_send_t *req, int status);
typedef void (*uv_getaddrinfo_cb)(uv_getaddrinfo_t *req, int status, struct addrinfo *res);

struct uv_loop_s {
  void *data;
  uint64_t time;
  uint64_t timer_counter;
  int stop_flag;
  uv__queue_t timers;   // active timers, sorted by (due, start_id)
  uv__queue_t prepares; // active prepare handles
  uv__queue_t checks;   // active check handles
  uv__queue_t udps;     // open udp handles
  uv__queue_t pending;  // completed requests awaiting their callback
  uv__queue_t closing;  // handles awaiting their close callback
  unsigned int active_reqs;
};

#define UV_HANDLE_FIELDS \
  void *data; \
  uv_loop_t *loop; \
  uv_handle_type type; \
  unsigned int flags; \
  uv_close_cb close_cb; \
  uv__queue_t closing_node;

struct uv_handle_s {
  UV_HANDLE_FIELDS
};

struct uv_timer_s {
  UV_HANDLE_FIELDS
  uv_timer_cb cb;
  uint64_t due;
  uint64_t repeat;
  uint64_t start_id;
  uv__queue_t node;
};

struct uv_prepare_s {
  UV_HANDLE_FIELDS
  uv_prepare_cb cb;
  uv__queue_t node;
};

struct uv_check_s {
  UV_HANDLE_FIELDS
  uv_check_cb cb;
  uv__queue_t node;
};

struct uv_udp_s {
  UV_HANDLE_FIELDS
  int fd;
  int sndbuf;
  int rcvbuf;
  uv_alloc_cb alloc_cb;
  uv_udp_recv_cb recv_cb;
  uv__queue_t node;       // in loop->udps
  uv__queue_t send_queue; // uv_udp_send_t waiting for buffer space
  size_t send_queue_size;
  size_t send_queue_count;
};

#define UV_REQ_FIELDS \
  void *data; \
  uv_req_type type; \
  uv__queue_t pending_node;

struct uv_req_s {
  UV_REQ_FIELDS
};

#define UV_UDP_SEND_BUFSML 4

struct uv_udp_send_s {
  UV_REQ_FIELDS
  uv_udp_t *handle;
  uv_udp_send_cb cb;
  int status;
  unsigned int nbufs;
  uv_buf_t *bufs;
  uv_buf_t bufsml[UV_UDP_SEND_BUFSML];
  struct sockaddr_storage addr;
  uint8_t head[4]; // first bytes of bufs[0] when queued, to catch callers mutating queued data
};

struct uv_getaddrinfo_s {
  UV_REQ_FIELDS
  uv_loop_t *loop;
  uv_getaddrinfo_cb cb;
  int status;
  struct addrinfo *addrinfo;
};

typedef struct {
  char *name;
  char phys_addr[6];
  int is_internal;
  union {
    struct sockaddr_in address4;
    struct sockaddr_in6 address6;
  } address;
  union {
    struct sockaddr_in netmask4;
    struct sockaddr_in6 netmask6;
  } netmask;
} uv_interface_address_t;

// loop

int
uv_loop_init (uv_loop_t *loop);

int
uv_loop_close (uv_loop_t *loop);

int
uv_run (uv_loop_t *loop, uv_run_mode mode);

void
uv_stop (uv_loop_t *loop);

int
uv_loop_alive (const uv_loop_t *loop);

uint64_t
uv_now (const uv_loop_t *loop);

void
uv_update_time (uv_loop_t *loop);

uint64_t
uv_hrtime (void);

// handles

void
uv_close (uv_handle_t *handle, uv_close_cb close_cb);

int
uv_is_active (const uv_handle_t *handle);

int
uv_is_closing (const uv_handle_t *handle);

int
uv_fileno (const uv_handle_t *handle, uv_os_fd_t *fd);

int
uv_send_buffer_size (uv_handle_t *handle, int *value);

int
uv_recv_buffer_size (uv_handle_t *handle, int *value);

// timer

int
uv_timer_init (uv_loop_t *loop, uv_timer_t *handle);

int
uv_timer_start (uv_timer_t *handle, uv_timer_cb cb, uint64_t timeout, uint64_t repeat);

int
uv_timer_stop (uv_timer_t *handle);

// prepare / check

int
uv_prepare_init (uv_loop_t *loop, uv_prepare_t *handle);

int
uv_prepare_start (uv_prepare_t *handle, uv_prepare_cb cb);

int
uv_prepare_stop (uv_prepare_t *handle);

int
uv_check_init (uv_loop_t *loop, uv_check_t *handle);

int
uv_check_start (uv_check_t *handle, uv_check_cb cb);

int
uv_check_stop (uv_check_t *handle);

// udp

int
uv_udp_init (uv_loop_t *loop, uv_udp_t *handle);

int
uv_udp_bind (uv_udp_t *handle, const struct sockaddr *addr, unsigned int flags);

int
uv_udp_getsockname (const uv_udp_t *handle, struct sockaddr *name, int *namelen);

int
uv_udp_set_ttl (uv_udp_t *handle, int ttl);

int
uv_udp_set_membership (uv_udp_t *handle, const char *multicast_addr, const char *interface_addr, uv_membership membership);

int
uv_udp_set_source_membership (uv_udp_t *handle, const char *multicast_addr, const char *interface_addr, const char *source_addr, uv_membership membership);

int
uv_udp_set_multicast_loop (uv_udp_t *handle, int on);

int
uv_udp_set_multicast_interface (uv_udp_t *handle, const char *interface_addr);

int
uv_udp_recv_start (uv_udp_t *handle, uv_alloc_cb alloc_cb, uv_udp_recv_cb recv_cb);

int
uv_udp_recv_stop (uv_udp_t *handle);

int
uv_udp_try_send (uv_udp_t *handle, const uv_buf_t bufs[], unsigned int nbufs, const struct sockaddr *addr);

int
uv_udp_send (uv_udp_send_t *req, uv_udp_t *handle, const uv_buf_t bufs[], unsigned int nbufs, const struct sockaddr *addr, uv_udp_send_cb send_cb);

// dns / interfaces

int
uv_getaddrinfo (uv_loop_t *loop, uv_getaddrinfo_t *req, uv_getaddrinfo_cb cb, const char *node, const char *service, const struct addrinfo *hints);

void
uv_freeaddrinfo (struct addrinfo *ai);

int
uv_interface_addresses (uv_interface_address_t **addresses, int *count);

void
uv_free_interface_addresses (uv_interface_address_t *addresses, int count);

// misc

uv_buf_t
uv_buf_init (char *base, unsigned int len);

const char *
uv_strerror (int err);

const char *
uv_err_name (int err);

int
uv_ip4_addr (const char *ip, int port, struct sockaddr_in *addr);

int
uv_ip4_name (const struct sockaddr_in *src, char *dst, size_t size);

// ESP extension (not libuv): process-wide event loop counters for profiling.

typedef struct {
  uint32_t iterations;
  uint32_t polls;
  uint32_t poll_timeout_0;   // poll called with timeout 0 (work pending)
  uint32_t poll_timeout_1;   // poll called with timeout 1 ms
  uint32_t poll_timeout_gt1; // poll called with timeout > 1 ms or infinite
  uint32_t poll_idle;        // poll returned with nothing readable
  uint64_t poll_blocked_us;  // time spent inside select()/vTaskDelay()
  uint32_t timer_cbs;
  uint32_t recvs;
  uint32_t sends;
  uint32_t send_would_block;
  uint64_t send_us;          // time inside sendmsg()
  uint64_t recv_cb_us;       // time inside recv callbacks (includes nested sends)
  uint64_t recvfrom_us;      // time inside recvfrom()
  uint32_t queued_head_changed; // queued sends whose first bytes changed before they went out
} uv_esp_stats_t;

// Per-poll trace for the first UV_ESP_TRACE_LEN polls after a reset.
#define UV_ESP_TRACE_LEN 48

typedef struct {
  uint32_t start_us;   // poll start, relative to the reset
  uint32_t blocked_us; // time inside select()
  uint16_t reads;      // datagrams read after select() returned
  uint16_t sends;      // datagrams sent since the previous poll
} uv_esp_trace_t;

int
uv_esp_trace_get (const uv_esp_trace_t **out);

void
uv_esp_stats_get (uv_esp_stats_t *out);

void
uv_esp_stats_reset (void);

#ifdef __cplusplus
}
#endif
#endif // UV_ESP_H
