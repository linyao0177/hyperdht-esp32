# uv_esp

The subset of the [libuv](https://libuv.org) API that libudx and hdht use, implemented for ESP-IDF on lwIP sockets. It was written from scratch for this project (MIT).

| API | Notes |
|---|---|
| Loop | `uv_loop_init`, `uv_run` (DEFAULT/ONCE/NOWAIT), `uv_stop`, `uv_now`, `uv_hrtime`, `uv_loop_close` |
| Timers, prepare, check | As in libuv, including callback ordering |
| UDP | `uv_udp_*` (bind, recv, `try_send`, queued `send`, TTL) via `select()`. lwIP reports buffer exhaustion as `ENOMEM`; it is treated as `EAGAIN` and retried after 1 ms |
| Async | `uv_async_init`/`uv_async_send` via an ESP-IDF VFS eventfd. `uv_async_send` is the only call that is safe from other FreeRTOS tasks |
| DNS | `uv_getaddrinfo` (synchronous lwIP lookup, callback deferred) |
| Not provided | TCP, pipes, files, the thread pool, `uv_interface_addresses` (`UV_ENOSYS`) |

There are also two debugging helpers that are not part of libuv. `uv_esp_stats_get` returns loop counters (polls, time blocked, sends, receives, EAGAINs), and `uv_esp_trace_get` returns a timeline of the first 48 polls. Both were used to find the lwIP receive-queue bottleneck (see `research/phase0/README.md`).
