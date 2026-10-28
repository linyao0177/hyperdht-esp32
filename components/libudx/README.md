# libudx

[holepunchto/libudx](https://github.com/holepunchto/libudx) (reliable, congestion-controlled streams over UDP; Apache-2.0), vendored at `9c9a0e7` in `libudx/` with its own LICENSE and NOTICE.

Two bug fixes are applied to `libudx/src/udx.c`. Both were found under memory pressure on the ESP32-C3 and are described in `libudx/VENDORED.txt`. They are submitted upstream as patches in [`patches/libudx`](../../patches/libudx):
1. A data corruption bug: an RTO rewrote the header of an MTU probe that was still queued for sending.
2. A NULL dereference when buffering out-of-order data with the heap exhausted.

`port/` holds the ESP-IDF glue: `io_esp.c` (in place of `io_posix.c`; lwIP has no MTU discovery) and `udx_alloc.*`, which counts libudx's own heap use separately.
