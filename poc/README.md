# 阶段 0 PoC：ESP32-C3 上的 libsodium 与 libudx

ESP-IDF v5.5.1 工程，目标芯片 ESP32-C3（QFN32 rev v0.4，内置 4MB Flash）。

PoC 验证三件事：
1. libsodium 能否提供 HyperDHT 所需的全部原语，结果是否与桌面端逐字节一致，性能怎样。
2. 官方 libudx（只打了两个 bug 修复补丁）配一个自写的 libuv 适配层能否在 lwIP 上运行，并与官方 `udx-native` 互通。
3. 内置 SRAM 的堆和栈实际占用多少。

## 目录

| 路径 | 内容 |
|---|---|
| `components/uv_esp/` | 自写的最小 libuv 适配层（约 650 行，Apache-2.0 兼容，**没有**用 hyperdht-cpp 的 LGPL 代码）。覆盖 UDP、timer、prepare/check、getaddrinfo |
| `components/libudx/libudx/` | vendor 的 holepunchto/libudx `9c9a0e7`，`src/udx.c` 打了两个 bug 修复补丁，见 `VENDORED.txt` |
| `components/libudx/port/` | `io_esp.c`（替换 io_posix.c），`udx_alloc.*`（单独统计 libudx 自己的堆分配） |
| `main/sodium_check.c` | 原语一致性检查 + 性能测试 |
| `main/sodium_vectors.h` | 用 Mac 上的 libsodium 生成的参考向量（`tools/gen_vectors.c`） |
| `main/udx_echo.c` | 跟 Mac 端做 UDX 回显，并测量堆占用 |
| `host/echo-server.js` | Mac 端 echo 服务（udx-native 1.22.0） |
| `tools/capture.py` | 复位板子并抓取 `POC|` 开头的输出 |

## 运行

```bash
cp sdkconfig.wifi.example sdkconfig.wifi   # 填 2.4G SSID/密码 和 Mac 的局域网 IP
```

```bash
rm -f sdkconfig && idf.py build flash
```

```bash
cd host && npm install && node echo-server.js 9000
```

```bash
python tools/capture.py /dev/cu.usbmodem21101 300
```

## 已测结果（2026-10-27，实板）

### libsodium（板上版本 1.0.21，`espressif/libsodium` 组件）

15 项一致性检查全部通过，包括 Ed25519 签名、`crypto_scalarmult_ed25519_noclamp`（noise-curve-ed 的 DH）、BLAKE2b（带 key 和不带 key）、SHA-512、ChaCha20-Poly1305、XChaCha20-Poly1305、secretbox 和 secretstream。板上输出与 Mac 上 libsodium 1.0.20 逐字节一致。

| 操作 | 每次耗时 | 吞吐 |
|---|---|---|
| Ed25519 seed keypair | 12.6 ms | |
| Ed25519 签名（64B） | 15.0 ms | |
| Ed25519 验签（64B） | 24.1 ms | |
| Ed25519 DH（sha512 + noclamp） | 40.5 ms | |
| BLAKE2b 64B（代码在 Flash） | 1540 µs | 41 KiB/s |
| BLAKE2b 1KiB（代码在 Flash） | 11.4 ms | 88 KiB/s |
| BLAKE2b 64B（`POC_BLAKE2B_IRAM=y`） | 63 µs | 987 KiB/s |
| BLAKE2b 1KiB（`POC_BLAKE2B_IRAM=y`） | 440 µs | 2274 KiB/s |
| SHA-512 1KiB（走 mbedTLS） | 806 µs | 1240 KiB/s |
| ChaCha20-Poly1305 1KiB | 374 µs | 2671 KiB/s |
| secretbox 1KiB | 458 µs | 2184 KiB/s |
| secretstream push 1KiB | 400 µs | 2499 KiB/s |

- **Noise IK 握手估算**：每一端约 1 次生成密钥 + 4 次 DH，算下来约 0.18 s/端，可以接受。
- **BLAKE2b 的问题**：`blake2b_compress_ref` 完全展开后有 21KB，超过了 C3 16KB 的指令 cache，从 Flash 执行时 cache 不断失效，比正常慢约 25 倍。放进 IRAM 能解决，但要占 21KB 内存。更好的做法是换一个按轮次循环实现的 BLAKE2b（代码约 2KB）。
- **栈**：整个测试过程最多用了 5.9KB。

### 内存与 Flash

| 项 | 数值 |
|---|---|
| 启动后可用堆（未开 WiFi） | 267,416 B |
| 固件总大小（含 WiFi、libsodium、libudx） | 1.03 MB（4MB Flash，单 app 分区还剩 33%） |
| libsodium 占 Flash | 152 KB |
| libudx 占 Flash | 25 KB |
| uv_esp 占 Flash | 4 KB |

### UDX 回显（2026-10-28，实板 + Mac 上的 udx-native 1.22.0，同一局域网）

板子通过 2.4G WiFi 连接（WPA2，RSSI -33）。每次运行发送 256KB，每次写 1KB，最多同时有 16 个写请求在途，回显内容逐字节校验。

| 接收窗口 | 结果 | 耗时 | 吞吐 | 最小 RTT | 最低可用堆 | 本次峰值堆占用 | libudx 峰值 | libudx 分配次数 | 泄漏 |
|---|---|---|---|---|---|---|---|---|---|
| 16 KB | 通过 | 1638 ms | 156 KiB/s | 1 ms | 130,848 B | 67,392 B | 29,332 B | 350 | 0 |
| 64 KB | 通过 | 1686 ms | 152 KiB/s | 1 ms | 108,556 B | 89,220 B | 62,352 B | 382 | 0 |
| 默认（4 MB） | 通过 | 1599 ms | 160 KiB/s | 1 ms | 119,908 B | 77,912 B | 43,556 B | 323 | 0 |

- **峰值堆占用**的计算方法是运行前的可用堆减去运行期间的最低可用堆。它包含 libudx、lwIP/WiFi 缓冲区，以及测试程序自己的 17KB 收发缓冲。每次运行结束后可用堆都回到运行前的水平（差值小于 400B，属于 lwIP/WiFi 的波动），libudx 自己的分配全部释放。
- 连上 WiFi 后可用堆是 215,056 B。整个测试中最低可用堆是 108,556 B，满足“剩余大于 60KB”的判断标准。
- 由于测试程序限制了在途数据量（16 × 1KB），接收窗口的大小基本不起作用，三次结果之间的差异主要是时序波动（每种窗口只跑了 1 次）。
- RV32 上的结构体大小：`udx_t` 4168 B，`udx_socket_t` 2344 B，`udx_stream_t` 880 B，`udx_packet_t` 304 B，`uv_udp_send_t` 96 B，`uv_timer_t` 64 B。
- 设备结束时直接调用 `udx_stream_destroy`，所以 Mac 端会看到 “connection reset by peer”，这是预期行为。
- 上表是 lwIP 默认配置下的结果。把 UDP 接收队列调大以后，吞吐翻了一倍多，见下一节。

### 吞吐排查：lwIP UDP 接收队列太小（2026-10-28）

**结论**：lwIP 默认每个 UDP socket 最多排队 6 个包（`CONFIG_LWIP_UDP_RECVMBOX_SIZE=6`）。设备处理一批包要十几到几十毫秒，这期间 Mac 发来的包把队列挤满，多出来的直接被丢掉。Mac 端约 22% 的包需要重传，还会停下来等重传，每次运行累计空等 0.5–1 秒。

现在 `sdkconfig.defaults` 里已经把这个值设成 32。

| 配置（16 个写请求在途，6 次运行） | 吞吐 | Mac 端重传 | 最低可用堆 |
|---|---|---|---|
| lwIP 默认（接收队列 6） | 150–170 KiB/s | 110–119 次（约 22%），6 次快速恢复 | 108.5 KB |
| **接收队列 32（现在的默认）** | **313–365 KiB/s** | 2–3 次 | 108.5 KB |
| 接收队列 32 + `LWIP_IRAM_OPTIMIZATION` + `LWIP_EXTRA_IRAM_OPTIMIZATION` | 382–502 KiB/s | 1–2 次 | 78 KB |

排查过程：
1. **WiFi 省电不是主因**。默认的 `WIFI_PS_MIN_MODEM` 和关闭省电（`WIFI_PS_NONE`）比，吞吐只差约 10%。测试程序现在两种模式各跑一遍，结果行里带 `ps=` 字段。
2. **写端延迟和窗口都不是问题**。把在途写请求从 16 提到 64，吞吐不变；srtt 约 10ms，cwnd 约 20 包，pacing 2–3 MB/s，都远高于实际速率。
3. 给 uv_esp 加了计数器和每次 poll 的时间线（`uv_esp_stats_get`、`uv_esp_trace_get`，输出为 `POC|uvstats` 和 `POC|uvtrace`）。结果显示 1.6s 里事件循环只转了 28 圈，其中有好几次 180–920ms 的空等，期间一个包都没收到。
4. 在 Mac 端 echo 服务里打印 udx-native 的流统计，发现约 535 个包里有 110+ 个是重传，确认是丢包。设备忙的时候，接收队列先满了。

**还剩的瓶颈是 CPU**。现在一次运行 700ms 左右，select 只阻塞了约 100–180ms，其余时间都在处理包：
- `sendmsg` 每次约 0.7ms，开了 lwIP IRAM 优化后降到约 0.3ms，说明主要是 Flash 指令 cache 失效。
- libudx 的收包处理（不算里面的发送）每个包约 0.5ms。

继续优化的方向：
- 把 libudx 的热路径放进 IRAM。
- BBR 里的 `double`/`float` 运算在 C3（没有 FPU）上是软浮点，可以检查是否值得换成定点数。
- 开 lwIP IRAM 优化要少 33KB 堆，等 DHT 部分的内存预算定下来再决定开不开。

### 低内存下的数据损坏：libudx 上游 bug，已修（2026-10-28）

**现象**：可用堆几乎耗尽时，有一次回显校验失败。Mac 多收了 64 字节，设备在出错的位置收到的全是 `00`。

**复现方法**：新增配置项 `CONFIG_POC_HEAP_LEAVE_FREE`。每次运行前先分配一块“压舱”内存，把可用堆压到指定值，运行结束后释放。设成 70000 后，6 次运行里复现了 1 次。
- 设备和 Mac 两端现在都会按数据模式逐字节校验，出错时打印位置和内容（`POC|mismatch` 和 `MISMATCH`）。两端都显示，坏数据是在设备发往 Mac 的方向产生的，内容是全 0。
- 适配层加了一个检测（`queued_head_changed`）：排队时记下包的前 4 字节，真正发送前再比对。出错那次运行检测到 2 个排队中的包在发出前被改了，同时有 `rtos=2`。

**根因**：在 `udx.c` 的 RTO 路径里，下面两步的顺序反了：
1. 先执行 `mtu_unprobeify_packet()`，把 MTU 探测包 header 里的填充长度（`header[3]`）清零。
2. 然后才检查 `pkt->ref_count == 2`，也就是这个包已经在发送队列里了。

如果 `uv_udp_try_send` 返回 EAGAIN，探测包就会排进发送队列，排队的那份带着全 0 的填充段。这时触发 RTO，header 被就地改掉，填充段却还在。包发出去后，对端就把填充当成了流数据。RACK 路径是先检查 `ref_count` 的，所以没有这个问题。

在桌面系统上 `try_send` 很少返回 EAGAIN，所以这个 bug 不容易暴露；而在 C3 上，内存一紧，lwIP 就会返回 ENOMEM。

**顺带修的崩溃**：`process_data_packet` 处理乱序包时，没有检查 calloc/malloc 是否返回 NULL，内存不足时会对 NULL 执行 memset，导致 Store access fault。现在改成分配失败就丢掉这个包，等对端重传。

两处修改都写在 `components/libudx/libudx/VENDORED.txt` 里，适合提交给上游。

**验证**：
- 压到 70KB 跑了 20 次：校验失败 0 次，`queued_head_changed` 始终为 0。其中 14 次触发了 7 次以上 RTO，也就是修复前出问题的条件确实出现了。期间 libudx 一共分配失败约 10 次，没有崩溃。
- 正常内存下跑了 6 次，全部通过，最低可用堆约 109KB。这一轮吞吐是 189–297 KiB/s，比上一轮的 313–365 低，原因没有查，可能是无线环境的波动，也可能和 Mac 端新加的逐字节校验有关。

**仍然存在的问题（数据不会出错，但连接会中断）**：
- 可用堆压到只剩 1–3KB 时，大多数运行以 `Connection timed out` 结束。原因是 WiFi 和 lwIP 收不进包，libudx 连续 7 次 RTO 后放弃。
- 20 次里有 1 次卡了 120s 都没有触发 RTO，原因还没查。
- 有几次运行结束时可用堆比运行前少 9–24KB，但下一次运行开始前又恢复了，看起来是关闭连接时 lwIP/WiFi 缓冲区的暂时占用，不是泄漏。

结论：实际部署时要给网络栈留出足够的堆余量，把 lwIP 返回 ENOMEM 当作异常情况，而不是常态。

### 栈：libudx 需要 16KB 任务栈

一开始给 UDX 任务的栈是 8KB，运行时 `Stack protection fault`。原因是 `udx.c` 的 `_send_packet` 在栈上声明了 `uv_buf_t _bufs[UDX_MAX_COMBINED_WRITES + 2]`，也就是 1474 × 8B，整个栈帧达到 11,648 B。这个数组只在发送 MTU 探测包时才会用到，大小是按“每个字节都是一次单独写”的最坏情况算的。

把任务栈改成 16KB 后测试通过，实际用了 12,944 B。如果要省下这部分内存，可以给上游提一个补丁，把这个数组改成按 `nwbufs` 动态分配，或者用 `#ifndef` 包住这个常量，允许外部改小。改小后栈帧可以降到 1KB 以内。
