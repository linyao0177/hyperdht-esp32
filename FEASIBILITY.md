# Holepunch 移植到 ESP32-C3 可行性调研

调研日期：2026-10-27
参考源码版本：hyperdht 6.34.1、libudx（main）、hyperdht-cpp（2026-10-27 main）

## 1. 结论

| 目标 | 可行性 | 说明 |
|---|---|---|
| 完整 Holepunch 栈（Bare/Pear + Hypercore/Hyperbee/Autobase） | **不可行** | V8 不可能跑；就算换成 Micro QuickJS 也只支持 ES5 子集，现有 npm 模块大量使用 class、async/await、streamx，没法直接运行；Hypercore 还需要持久化存储和 Merkle 树 |
| 在 C3 上原生实现 **HyperDHT 子集**（按公钥连接、打洞、端到端加密流） | **可行，但内存很紧** | 需要用 C 写精简版，限制为 1–2 条并发连接、ephemeral 节点、只做常规打洞加中继兜底。粗估业务堆占用 80–120KB，C3 连上 WiFi 后剩余的可用堆大约在 200KB 量级 |
| 直接把现成的 hyperdht-cpp 搬到 C3 | **风险高** | 作者自己估计要 2–3MB 堆，强制依赖 PSRAM，而 C3 不支持 PSRAM；TODO 里也写着上板运行尚未验证；另外是 LGPL-3.0 |
| 网关架构（C3 用 MQTT、WS 或 BLE 连到 S3/树莓派网关，再由网关接入 Hyperswarm） | **最稳** | 工作量最小，但 C3 本身不是 P2P 节点 |

**建议**：如果业务要求设备本身就是 Hyperswarm 节点（别人能凭公钥直连它），优先考虑换成 **ESP32-S3 + 8MB PSRAM**，直接用 hyperdht-cpp。如果硬件必须是 C3，就走“C 写精简版 HyperDHT 客户端”这条路，先用 1–2 周做内存 PoC 再决定要不要投入。

## 2. Holepunch 协议栈拆解

```
Pear / Bare(JS 运行时, libjs→V8)                  ← C3 不可行
Hypercore / Hyperbee / Autobase / Corestore        ← C3 不建议
Hyperswarm  (topic 发现、连接管理, ~1.3k 行 JS)
Protomux    (流上的多路复用, ~0.9k 行 JS)
SecretStream(Noise IK + XChaCha20-Poly1305, ~0.7k 行 JS)
HyperDHT    (announce/lookup/connect/holepunch/relay, ~5.5k 行 JS)
dht-rpc     (Kademlia、NAT 采样, ~3.7k 行 JS)
libudx      (基于 UDP 的可靠流 + BBR, ~5.6k 行 C, 依赖 libuv)
```

本地统计（不含测试）：真正需要在 C3 上实现的是 libudx 加约 1.2 万行 JS 的协议逻辑，对应的 C 代码量估计在 1 万行左右。

### 2.1 密码学原语（全部来自 libsodium）

- Ed25519：`crypto_sign_*`，`crypto_scalarmult_ed25519_noclamp`（noise-curve-ed 用 Ed25519 做 DH）
- BLAKE2b：`crypto_generichash`，大量使用（节点 ID、topic、token）
- SHA-512：`crypto_hash_sha512`
- XChaCha20-Poly1305 secretstream、ChaCha20-Poly1305 IETF、`crypto_secretbox`

ESP-IDF 组件仓库里有 `espressif/libsodium ^1.0.20`，hyperdht-cpp 就是用的它。**待确认**：这个组件编译时有没有打开 `SODIUM_LIBRARY_MINIMAL`。如果打开了，`crypto_scalarmult_ed25519_noclamp` 会缺失。

C3 的硬件加速只有 SHA-1/224/256、AES、RSA，**帮不上 Ed25519、SHA-512 和 BLAKE2b**，全部要走软件实现。

### 2.2 libudx 对 libuv 的依赖

用到的 libuv API 只有这几类：`uv_udp_*`、`uv_timer_*`、`uv_prepare/check`、`uv_getaddrinfo`、`uv_interface_addresses`。没有用到文件和线程池。hyperdht-cpp 已经写了一个约 2.7k 行的 **libuv-esp32 shim**（基于 lwIP `select()` 和最小堆定时器），可以参考。注意它是 LGPL 许可。

移植中需要注意的点：
- `udx_bbr.c` 用 `double` 计算增益，而 C3 是 RV32IMC，**没有 FPU**，只能软浮点。速率低时问题不大，也可以换成定点数实现或更简单的拥塞控制。
- lwIP 不支持 `IP_MTU_DISCOVER`/`DONTFRAG`，MTU 探测只能关掉，固定用 1200 字节的基础 MTU。

## 3. ESP32-C3 资源约束

| 项 | C3 | 影响 |
|---|---|---|
| CPU | RV32IMC 单核 160MHz，无 FPU | Ed25519 操作预计每次几十毫秒（需实测）；一次 Noise 握手需要多次 DH，预计几百毫秒，可以接受 |
| SRAM | 400KB（其中 16KB 作 cache），**不支持 PSRAM** | 最大约束 |
| Flash | 常见 4MB | 精简实现加 libsodium 预计 1MB 级，放得下 |
| 网络 | 2.4G WiFi 4 + BLE 5 | 吞吐对 IoT 场景足够 |

### 3.1 内存粗估（C 精简实现，1 条连接）

在 64 位主机上量的 libudx 结构体大小：`udx_t` 8.3KB、`udx_socket_t` 2.7KB、`udx_stream_t` 1.4KB、`udx_packet_t` 0.7KB。RV32 上会小一些。

| 模块 | 估算 |
|---|---|
| 路由表（ephemeral，k=10–20） | 10–20KB |
| 查询（findPeer/announce）进行中 | 5–10KB |
| udx 实例 + 1–2 个 socket | ~10KB |
| 每条 UDX 流（发送窗口限制在 16 包） | 20–40KB |
| Noise / SecretStream 状态 | <2KB |
| DHT 任务栈（Ed25519 吃栈） | 12–16KB |
| **合计** | **约 80–120KB** |

C3 连上 WiFi 后剩余的堆大约在 200KB 量级（随 sdkconfig 变化，**必须实测**），所以有余量，但不宽裕。容易出问题的地方是碎片化和 lwIP pbuf 突发占用。

> **阶段 0 实测（2026-10-28，详见 `poc/README.md`）**：连上 WiFi 后可用堆为 215KB。跑 1 条 UDX 回显流（256KB）时，最低可用堆为 108.5KB；libudx 自己的峰值为 29–62KB，没有泄漏。RV32 上的结构体大小为 `udx_t` 4.2KB、`udx_socket_t` 2.3KB、`udx_stream_t` 0.9KB、`udx_packet_t` 0.3KB。需要注意的是，libudx 的 `_send_packet` 在栈上放了一个 11.6KB 的数组，所以跑 libudx 事件循环的任务栈至少要 16KB。吞吐方面，把 lwIP 的 UDP 接收队列从默认的 6 调到 32 以后，局域网回显能到 313–365 KiB/s，不额外占堆；剩下的瓶颈是 CPU（Flash 指令 cache 失效和软浮点）。

相比之下，hyperdht-cpp 在 S3 上的实测数字是“占用约 2–3MB”。它大量使用 `std::function`、`std::vector`、`std::unordered_map`、`std::string`，要压到 C3 上需要大规模重写，不如直接写 C 版本。

## 4. 现有实现

| 项目 | 语言 | 状态 | 与 C3 的关系 |
|---|---|---|---|
| [holepunchto/hyperdht](https://github.com/holepunchto/hyperdht) | JS | 官方参考实现，MIT | 协议权威来源 |
| [holepunchto/libudx](https://github.com/holepunchto/libudx) | C | 官方，Apache-2.0 | **可以直接复用** |
| [jjacke13/hyperdht-cpp](https://github.com/jjacke13/hyperdht-cpp) | C++ | 线协议兼容 hyperdht@6.29.1（官方已到 6.34.1），自报约 93% 行为一致；带 ESP32-S3 示例 | 需要 PSRAM；TODO 写明“ESP32-S3 firmware linking, flashing and an actual board connection”尚未验证；**LGPL-3.0**；它的 `PROTOCOL.md` 适合拿来当协议规格参考 |
| [hyperdht](https://docs.rs/hyperdht/) / [hyperswarm](https://docs.rs/crate/hyperswarm/latest) Rust crate | Rust | 0.1.x，不稳定 | 理论上可以用 esp-idf-svc 跑在 C3 上，但成熟度不够 |
| [holepunchto/libmqjs](https://github.com/holepunchto/libmqjs) | C | 基于 Micro QuickJS 的 libjs 替代实现 | 引擎只支持 ES5 子集，跑不了现有 Holepunch JS 模块 |
| [hyperswarm#89](https://github.com/holepunchto/hyperswarm/issues/89) | — | 社区提的“C 实现给 IoT/ESP32 用”需求 | 官方没有跟进 |

## 5. 功能裁剪建议（C3 精简版）

**保留**
- Bootstrap（`node1-3.hyperdht.org:49737`）、ephemeral 模式（不充当 DHT 路由节点）
- `connect(publicKey)`：findPeer → PEER_HANDSHAKE（Noise IK）→ PEER_HOLEPUNCH → UDX 流 → SecretStream
- `createServer().listen(keyPair)`：announce，每约 5 分钟刷新一次，并处理经 DHT 中继转发过来的握手
- 可选：Protomux、mutable/immutable 存储（成本不高）

**裁剪或降级**
- 生日攻击打洞：JS 版本会开 256 个 socket，在 C3 上做不到。设备在随机型 NAT（CGNAT、4G）后面且对端也受限时，大概率连不上，只能靠 blind-relay 兜底
- BBR 换成定点数实现或更简单的拥塞控制；关闭 MTU 探测；只支持 IPv4
- 不实现 Hypercore 复制

## 6. 主要风险

1. **内存**：最大的不确定性，需要 PoC 实测“WiFi + libsodium + 1 条加密流”时的峰值堆。
2. **协议跟进**：官方 hyperdht 迭代很快（hyperdht-cpp 落后 5 个小版本），自研实现要持续跟进线协议变化。
3. **NAT 穿透率**：嵌入式能开的 socket 数量受限，随机型 NAT 场景下成功率会明显低于桌面端。
4. **功耗**：作为服务端常在线时，需要定期 announce 和 NAT 保活，跟 deep-sleep 冲突。电池设备只适合按需连接的客户端模式。
5. **许可证**：复用 hyperdht-cpp 的代码（包括 libuv shim）意味着 LGPL-3.0。静态链接进闭源固件时，需要提供可重新链接的目标文件；LGPLv3 对消费类设备还有“安装信息”义务。官方的 libudx、SecretStream、Noise 都是 Apache-2.0，hyperdht 和 dht-rpc 是 MIT，自研不受影响。

## 7. 建议路线

**阶段 0：PoC（1–2 周）**
- ESP-IDF 5.5 + `espressif/libsodium`：先验证 `crypto_scalarmult_ed25519_noclamp` 可用，并测出 Ed25519、BLAKE2b、XChaCha20 在 C3 上的耗时
- 移植 libudx 加一个最小 uv shim，跟 PC 上的 udx-native 互通 echo，同时测量堆占用
- 判断标准：WiFi 连上后，跑 1 条 UDX 流时剩余堆是否大于 60KB
- **结果（2026-10-28）：通过**。最差情况下仍剩 108.5KB 可用堆，libsodium 15 项检查与桌面端逐字节一致

**阶段 1：DHT 客户端（4–6 周）**
- compact-encoding、dht-rpc 客户端（ping、find_node、query）、HyperDHT findPeer + connect + SecretStream
- 跟 JS 版 `hyperdht` 服务端互通
- **结果（2026-10-28）：在局域网测试网里实板通过**。实现在 `hdht/`（C，可移植），演示固件在 `firmware/`。板子通过公钥连接防火墙后的 JS 服务端，9/9 成功，每次约 0.5 秒，全部经过打洞；单次连接峰值占用约 25KB 堆，没有泄漏

**阶段 2：服务端与加固（4–6 周）**
- announce/listen、中继握手、holepunch 状态机、blind-relay 兜底、长时间运行的稳定性测试
- **结果（2026-10-28）：在局域网测试网里实板通过，blind-relay 兜底未实现**。JS 客户端通过公钥连板子：局域网直连 5/5，板子作为服务端打洞 10/10，30 分钟长测 52/52（期间重新 announce 6 次，堆没有增长）
- **公网 HyperDHT（2026-10-28）：通过**。板子用公网引导节点入网（3.1 秒），作为客户端 3/3 连上 JS 服务端；作为服务端在公网 announce 后，JS 客户端局域网直连 5/5、强制打洞 5/5（经家用路由器的公网地址回环），没有泄漏
- **跨两个真实 NAT（2026-10-28）：通过**。板子在家用路由器后面（端口一致型 NAT），Mac 连手机热点，运营商 NAT 是随机端口型，只能靠随机端口打洞。板子连 JS 服务端 3/3 成功（12–32 秒）。JS 连板子时，排除 JS 自身的随机打洞限流后 3/4 成功（9–20 秒），有 1 次真实失败。随机端口打洞本身就是概率性的，官方实现也一样

**备选**：如果阶段 0 的内存测试不过关，就改用 ESP32-S3（PSRAM）+ hyperdht-cpp，或者走网关架构。
