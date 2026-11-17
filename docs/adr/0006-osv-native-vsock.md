# ADR-0006：OSv 原生 vsock 的内核和应用边界

状态：Accepted；日期：2026-10-29；需求 OSV-01、SEC-06、QA-02/04。固定 OSv `0e34e4dc2b278b7f64e4169abbf297b7de46fb6b`。

## 决策

新增真正的 virtio device ID 19 驱动，复用该版本的 modern virtio-MMIO/vring/中断框架，提供 listen/connect/accept/recv/send/shutdown/close 的有界 C ABI，先由原生 C 测试应用验证。阶段一不伪装为 Linux AF_VSOCK，也不以 TCP、串口或 Linux guest 替代原生通道。原 Rust executor 继续作为诊断/工具实现；后续 agent 与宿主 RPC 使用此驱动，独立验收后才能晋级生产。

初始交付平台是 x86_64 Firecracker 的 modern MMIO；PCI、热插拔和 snapshot 恢复不宣称通过。profile 禁用 PCI/NIC/ACPI，根盘 ROFS，最小设备为 block、vsock、必要控制台。驱动对 guest 不构成进程权限边界，host jailer/KVM/配额仍是强制边界。

## 队列、内存和流控

- RX/TX/event 三个 virtqueue 由一个 I/O worker 独占操作；应用仅在锁内修改连接状态/有界待发队列。中断只确认/禁用相应队列并唤醒 worker，不做分配或协议解析。
- RX buffer、已发布 TX buffer 和 event buffer 在 device 返回 used descriptor 前一直有效。先消费/finalize used，再回收/repost，不复用 DMA 正在使用的内存。
- 固定帧头 44 字节，小端逐字段编码；最大单包 payload=4096，连接 RX 容量=64 KiB。used 长度、hdr.len、CID/port/type/op/flags 和缓冲区上限先验证后访问。
- 对端 credit 使用 uint32 环绕计数，验证 forward 增量不超过已发送未确认量；本地 TX 预留 credit 后才入队。recv 真正交给应用后才推进 fwd_cnt。REQUEST/UPDATE/SHUTDOWN 等控制包不消耗 payload credit。
- 数据与控制待发空间独立有界，RX/event 不能因 TX 无 descriptor 而阻塞；控制空间耗尽明确失败连接，不无限分配或静默继续无信用发送。
- 最多 32 个活动/待关闭 flow、8 个 listener；backlog、handle 数、待发队列和缓冲区均有上限。所有可等待 C ABI 调用接受 0～300000 ms timeout，0 表示不阻塞；错误返回负 errno。

## 生命周期

每个 flow 绑定 guest CID 和 peer tuple；初始 peer 只支持 Firecracker host CID=2，其他 CID 明确拒绝。清洁关闭发送 SHUTDOWN 并等待 RST，超时发送 RST；在此之前不复用 tuple。peer shutdown 的两方向标志永久累积。transport reset 关闭现存 flow、丢弃尚未发布的旧报文、重新读取 CID；listener 保留，新请求不能恢复旧连接。已发布 TX 必须等 completion 才能释放。

shutdown/destructor 先 reset device 停止 DMA，再唤醒/join worker，最后释放 buffer。MMIO 中断路径在 reset 后不能再触及释放的队列；不将现有驱动框架的 PCI 卸载能力推导为已支持。

## 验收与构建

先设计/自评审，再实现纯 codec/credit 属性测试、OSv 内核编译、指定机器真实 Firecracker transport 测试，最后才接现有 API。必须覆盖 listen/accept、connect、跨 credit 窗口双向数据、拒绝端口、timeout、半关闭/重连、reset、畸形包和队列压力。codec/credit 测试不能代替 DMA、中断或整驱动测试；未执行的项保持未验证。

并发压力用固定上限的 8 个 guest 工作线程分别连接 host；host 在收到全部连接的标识后才放行传输，确认 8 条 flow 真正同时存活，再核对各连接的数据与回执。每条连接和总测试时间有界，失败时关闭连接、终止专属 VM 并检查 cgroup/目录清理。此诊断场景仍不能代替产品 agent/API、长稳、reset 和畸形 virtqueue 帧测试。

补丁与 overlay 存于本仓库，应用前核查固定 commit 和补丁上下文；上游源码、构建产物和子模块放忽略目录。只初始化所需子模块，不为 ROFS 路径下载无关 GUI/OpenZFS；工具链和产物摘要进入证据。无变更不重复完整回归，驱动变更至少重编内核并执行受影响真机集。

依据：[Virtio 1.2 §5.10](https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html)、[Firecracker vsock](https://github.com/firecracker-microvm/firecracker/blob/main/docs/vsock.md)。协议事实依规范，内存/资源上限是本项目的实现选择。
