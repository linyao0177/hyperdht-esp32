// ESP-IDF replacement for libudx's src/io_posix.c.
//
// lwIP exposes neither IP_MTU nor IP_MTU_DISCOVER, so link MTU lookup and the
// don't-fragment option are reported as unavailable. libudx then keeps
// probing from UDX_MTU_BASE; probes larger than the path MTU are fragmented
// by lwIP instead of dropped.

#include <sys/socket.h>
#include <uv.h>

#include "../libudx/include/udx.h"
#include "../libudx/src/internal.h"
#include "../libudx/src/io.h"

int
udx__get_socket_ttl (udx_socket_t *socket) {
  uv_os_fd_t fd;
  if (uv_fileno((uv_handle_t *) &socket->uv_udp, &fd) != 0) return -1;

  int ttl;
  socklen_t ttl_opt_size = sizeof(ttl);
  if (getsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, &ttl_opt_size) != 0) return -1;

  return ttl;
}

int
udx__get_link_mtu (const struct sockaddr *addr) {
  UDX_UNUSED(addr);
  return -1;
}

int
udx__udp_set_dontfrag (uv_os_sock_t fd, bool is_ipv6) {
  UDX_UNUSED(fd);
  UDX_UNUSED(is_ipv6);
  return -1;
}
