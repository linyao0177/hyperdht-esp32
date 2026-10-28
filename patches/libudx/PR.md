# Draft PR for holepunchto/libudx

Base: `main` @ `9c9a0e7` (close socket in udx__get_link_mtu if connect() errors. (#331))
Commits: `0001-*.patch`, `0002-*.patch` in this directory (`git am` applies them).

---

**Title:** Fix stream corruption when an RTO hits a queued MTU probe, handle OOM on out-of-order data

## Summary

Two independent fixes in `src/udx.c`. Both were found by running libudx on an ESP32-C3 (lwIP, a small libuv-compatible shim) under memory pressure, where `uv_udp_try_send()` returns `UV_EAGAIN` often because lwIP reports pbuf exhaustion as `ENOMEM`.

### 1. Don't unprobeify an MTU probe that is still queued for send on RTO

When `uv_udp_try_send()` returns `UV_EAGAIN`, `_send_packet()` bumps `ref_count` to 2 and queues the packet with `uv_udp_send()`. Since #227 the probe padding is added at that point: the buffer list handed to libuv includes a padding buffer whose length comes from `header[3]`.

In `udx_rto_timeout()`, the order was:

```c
if (pkt->is_mtu_probe) {
  mtu_unprobeify_packet(pkt, stream); // header[3] = 0
}

if (pkt->ref_count == 2) continue; // packet is already scheduled to transmit, so don't reschedule
```

If the RTO fires while a probe is still sitting in the libuv send queue, `header[3]` is cleared in place, but the queued send still carries the padding. The datagram goes out saying "no padding" with the zero padding still in it, and the receiver delivers those zero bytes as stream data.

The fix moves the `ref_count == 2` check ahead of `mtu_unprobeify_packet()`, which matches `rack_detect_loss()`: it already skips queued packets first. The probe is left alone while it is queued. It is acked or detected lost later through the normal paths.

**Observed:** an echo test streamed 256 KiB from the device to `udx-native`. The peer received 64 extra bytes, all zero, at the point where the stream diverged. Instrumenting the shim to compare the first bytes of each queued send between `uv_udp_send()` and the actual `sendmsg()` showed headers mutated while queued, and only in runs that had an RTO. With the fix, 20 runs at the same memory pressure (many with ≥7 RTOs) showed no corruption and no queued-header mutation.

### 2. Handle allocation failure when buffering out-of-order data

In `process_data_packet()`, the slow path does two allocations:
- It asserts on `calloc()` of a new sack block.
- It `memset()`s the result of `malloc()` for the packet copy without a NULL check.

On an exhausted heap this aborts, or with `NDEBUG` it writes through NULL. We hit the store fault on the device.

The fix drops the packet instead. If a sack block was just created for it, the block is removed and freed, so the packet is not SACKed and the remote retransmits it as for any loss.

## Testing

- `ctest` on macOS (arm64, Debug), run serially: 44/44 pass. `stream-write-read-perf` is disabled as upstream.
  - Note: with `ctest -j4`, several tests fail at `udx_socket_bind` because they share fixed ports (e.g. 8082). This happens independently of this change.
- On ESP32-C3 with free heap squeezed to ~2 KB during transfer: no corruption and no crashes across 20 runs, with ~10 allocation failures in libudx. Normal-memory runs are unchanged.

There's no new regression test for (1). Reproducing it needs a send that is actually deferred: `uv_udp_send()` has to queue the datagram, and an RTO has to fire before it is written. On desktop libuv, `uv_udp_send()` writes immediately when the send queue is empty, so mutating the header afterwards doesn't reach the wire. `UDX_DEBUG_FORCE_SEND_SLOW_PATH` only covers `udx_socket_send()`. A deterministic test would need a debug hook that holds stream data sends in a queue. Happy to add one if you'd like that.
