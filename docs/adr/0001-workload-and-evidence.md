# ADR-0001：工作负载分流和证据驱动的 OSv 投资

状态：Accepted；日期：2026-10-29。对应原方案 R3/R6/G2，需求 CAP-01、PERF-01、OSV-01。

## 背景

仓库已有 OSv 固定 Rust 工具和最小 Linux 执行器。OSv 单地址空间和缺少 fork 的限制不能靠 SDK 命名弥补；也不能以 Linux 后端替代 OSv 改造。原方案的密度和延迟假设缺少同口径对照。

## 决策

保留 OSv 作为原生重点优化路径；一般 shell/多进程工作负载使用最小 Linux。客户端显式选择经过认证的 template/backend，不能因失败自动降级。OSv 在驱动、runtime 和隔离验收完成前标记 experimental；现有 `Production` 校验只允许 Linux 是当前限制，不是永久取消 OSv 生产交付。

性能测量必须同时记录：kernel boot、guest handshake、host Run（含 staging 和回收）、HTTP（含认证和 RTT）、失败率、RSS/peak/cgroup 内存、吞吐和容量 headroom。预热、文件定向驱逐和真正冷机分开报告。每个候选绑定源码和 kernel/image/VMM 摘要、硬件、并发、任务和包版本。

OSv 推广门槛：相同任务语义和隔离设置下，关键模板通过兼容/故障矩阵，稳定成功率和资源回收满足门槛，并观察到可重复的延迟或单位成功任务成本优势。原 <20 ms kernel / <100 ms ready / 500 并发保留为实验目标；没有相应机器和负载实测就保持未验证。

## 替代和后果

只做 OSv 会阻塞多进程兼容；只做 Linux 会失去本次 OSv 改造目标；双路径增加维护成本，需共享控制面但分别验收。暂不实现受限 vfork 模拟，不承诺其能够覆盖 shell/pip/npm 的语义。
