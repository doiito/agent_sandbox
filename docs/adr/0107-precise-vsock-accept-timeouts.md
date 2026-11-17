# ADR-0107：客体控制监听保留亚毫秒等待，消除零超时忙轮询

状态：Accepted（机制、实际池 CPU 收益及 rc87 完整同包功能验收通过，启动门禁开放）；日期：2026-11-12；需求 LIFE-04、PERF-03、QA-01、BUILD-01。

[定向验收](../../PUBLIC-QUALIFICATION.md#private-evidence)已复现原零超时忙轮询，新空闲等待的本机线程 CPU 明显减少，92 项 guest/clippy、双架构静态编译与 allocator 核验、新 ARM QEMU 7 组/14 项通过。真实 API 与池资源对照尚未作为性能通过登记。

[实际 API 对照](../../PUBLIC-QUALIFICATION.md#private-evidence)532 次请求全部成功；两次 B 的三台原 idle VM 观察均降低 CPU，按实际窗口归一化均值由每 VM 5.2685%→1.2396% 核，下降 76.47%。以此资源收益保留改动，进入新完整候选回归。合并 warm 为 3.339/8.596/31.364→3.299/9.473/18.230ms，p95 回退且仍未达到 8/10ms，不称普遍延迟提升或正式门禁通过。

[rc87 完整功能验收](../../PUBLIC-QUALIFICATION.md#private-evidence)已完成 2039 输入冻结、一次 canonical CI、双架构 bundle/四镜像及 90/75 项离线包、x64 非 root API、ARM 原 59+1 组、指定机原 15 套/516+44 项及同一原 VM 的 6200ms 维护与 warm 只读执行。源码输入未漂移，原失败保留，255 项重复副本核对后回收约 2.47GiB；当前功能基线推进至 rc87。正式性能及原 40 项其余要求保持开放。

## 依据与决策

rc86 `accept_host_vsock_until` 在剩余时间大于零时，将 `remaining.as_millis()` 向下取整后调用 poll。剩余不足 1ms 时 timeout=0，循环在绝对截止前持续读时钟和零超时 poll。该函数被主控制、端口、文件监视及代码服务共用；端口和文件监视分别每 25ms、100ms 截断一次等待，未准备的 pristine VM 同样启动这些监听线程。这是可由精确源码和真实系统调用复现的周期性空闲 CPU 成本，不等同已经证明它解释了原千次长尾。

用 libc ppoll 和 timespec 表示当前正剩余时间，保留原 1s 单次上限、同一绝对截止、原事件与全部 accept/CID2/收发超时检查。sigmask 传 NULL，不修改线程信号屏蔽；Interrupted 后重新计算原截止，不延长租期。[Linux man-pages](https://man7.org/linux/man-pages/man2/poll.2.html)说明 ppoll 在 NULL sigmask 下与 poll 的主要差别为超时精度，事件到达可立即返回。无需新增依赖、修改内核、减少线程或增加固定等待。

原控制协议、绑定、prepare、输入冻结、审计/lease 持久性、配额与后台供给策略保持；正常小结果帧继续使用原 rc86 实现。此变更不把端口/文件功能移出 pristine 启动，也不增加代码语言或网络权限。

## 验证与采用

先完成[自评审](../../PUBLIC-QUALIFICATION.md#private-evidence)。从原与新源码逐字节提取实际 accept/地址/超时函数到私有检查程序；计数 shim 转发真实 poll/ppoll，验证不足 1ms、25ms、100ms 空闲监听不再零超时轮询，另在无 shim 的函数上做有界 ABBA 线程 CPU 对照。保留源码闭包、编译器、输入与原始结果，不将本机微基准解释为真实 API 启动收益。

检查过期截止、错误 FD、非宿主连接拒绝、EINTR 重算与持续活动时的绝对截止。受影响 guest 测试/clippy、x64/aarch64 静态 musl 与实际 mimalloc 检查，新 ARM 无网卡 QEMU 验证该等待和原控制功能。CPU/等待机制成立后，再准备原 rc86 host/精确镜像的同源重编 guest A/B 实际 API 对照，正常 doctor、原配额、供给与七阶段保持；只有实际收益成立才统一完整候选 CI/离线/QEMU/指定机回归。

保持 warm 5/8/10ms、四必要路线和每路千次、一次领取/隔离/恢复/资源长稳及原 40 项需求与发布条件；不合并旧候选或小样本，不因失败重跑直到变绿。原实验材料、实用依赖留在项目内，/tmp 仅作验证缓存。

## 实际 API 与空闲池 CPU 对照

沿用 ADR0106 已完成的同源重编与严格引用控制，改用独立的 accept-timeout 引用类型与新任务 ID；A/B 只改变本函数，原 rc86 host/内核/supervisor/静态 mimalloc 保持。正常 doctor、CPU2–5/NUMA0、原 128MiB/1vCPU 与 100000/100000、max_booting=2/health=1000ms，A1/B1/B2/A2 各 128+5 次原 API。保留完整七阶段、HTTP、等待、paced、RSS/FD 和独立清理；短窗不登记千次门禁。

每组原请求采样完成后，另等待原三台 idle VM 就绪并停止补池启动，最多 10s；不主动扩池、停止健康检查或执行租户任务。读取原 owned_leases 绑定的 VM/PID/start ticks/cgroup cpu.stat，在同一批三台 VM 上做一次 5s 空闲观察，核对前后身份、phase=ready、原 CPU 配额、计数单调与窗口。此阶段在 warm 采样之后，不能改变其样本或 paced 分母；结果单列 VMM/KVM cgroup 总 CPU，不称 guest 有效计算、饱和吞吐或长稳通过。

保留原 signed host 的 90 项及引用 10 项载荷，参考镜像逐文件只差 agent-init；测试签名与 SBOM 必须匹配。私有准备器只适配原 reference hook，规范化只允许确切路径、loopback 临时端口和已验证 image SHA，其余配置差异拒绝。修正上一实验已证明的 tar 内部硬链接问题：本次输入归档直接物化普通文件，先逐成员校验再传输，不放宽远端严格解包器。一次不可变任务持有原验证锁，观察超时只查原 ID，不重放。

## 完整候选回归

采用资源修正后，按[完整候选自评审](../../PUBLIC-QUALIFICATION.md#private-evidence)集中冻结 2026.11.12-rc87 测试签名候选。重新运行原静态 bundle 构建器，为两架构保留实际 C 库、链接映射、编译器和全 Rust 源码来源；用原构建器重建各自基础 rootfs 及完整代码/推理镜像，逐字核对实际 agent/helper。不得只给旧镜像更换元数据或复用旧 guest。

全部来源与文档稳定后冻结输入，完整 canonical CI 一次，再生成保留原全部特性的双架构离线包。x64 严格 0077 安装/非 root API 与 H1/H2/gRPC；ARM 无网卡整包保留原 59 组并新增 accept 4 项的一组；指定机保留原 15 套/516 个命名用例及 44 个 gRPC 用例、6200ms 前台维护跨读超时检查。按原不可变 worker/任务 ID 跟踪，失败保留并只补受影响或未执行阶段；不能通过缩小原用例、重复已通过昂贵全量或变更宿主/配额来通过。

构建与实际资产留在项目，已核验且无引用的重复 staging/install 在验收后清理。全套功能通过后才推进同一新候选正式性能；本批仍不因 CPU 改善开放正式发布，原四路线、千次与 40 项其余未完成要求保持。
