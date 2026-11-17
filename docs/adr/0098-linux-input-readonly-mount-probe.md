# ADR-0098：Linux 输入只读挂载的定向诊断

状态：Accepted（诊断完成，未复现毫秒级挂载等待，保留原产品实现）；日期：2026-11-11；需求 FILE-01、LIFE-04、PERF-03、QA-03。

## 依据与决策

rc85 Linux warm 的千次原始报告为 3.676 / 11.610 / 19.756 ms，超过当前 5 / 8 / 10 ms 尾延迟门槛。89 个超过 8 ms 的请求中，68 个最大耗时阶段为 preparation；这仍只是阶段归属，不证明存储、调度、RCU 或分配器的具体原因。OSv 的不同工作负载单独报告，不能据此推导同任务优劣。

Linux pristine prepare 对私有 tmpfs 输入执行 `MS_REMOUNT|MS_RDONLY`，并核对 readonly/nosuid/nodev/noexec。Linux 的 [mount(2) 文档](https://man7.org/linux/man-pages/man2/mount.2.html)说明，增加 `MS_BIND` 可只修改挂载点属性，而不重新配置整个超级块。这提供一个可检验的优化方向；文件系统及实际工作负载的只读约束都必须继续成立。

先冻结一个独立的静态 guest PID1 诊断程序和测试镜像，保留产品 guest、rc85 发行包与通用 benchmark 原字节。使用相同实际内核、Firecracker/jailer、128 MiB / 1 vCPU、CPU 配额及私有 CPU/NUMA 放置，在新夹具运行一台无网卡 VM。每轮建立新的私有 tmpfs、写入相同测试文件，按 ABBA 顺序比较两种 remount；分别计量该调用的 guest 单调时钟和进程 CPU 时间。总计每种 128 个样本，限时、限日志，禁止作为启动 SLO 证据。

每个样本实际验证文件可读、创建/改写均返回 EROFS、执行返回 EACCES，并核对四个 statvfs 属性。诊断只能在 guest PID1 执行；宿主执行立即拒绝。挂载失败或任一属性不满足时整批失败，不退回宽松权限。没有租户程序、网络或共享输入别名。

实施顺序为本决定、[自评审](../../PUBLIC-QUALIFICATION.md#private-evidence)、冻结工具、指定机原四条启动任务结束及清理确认、单次持久诊断任务、独立归档/样本/清理核验。记录原 InvocationID 和全部来源摘要；失败证据保留，不因观察中断重放。

若定向对照支持挂载方式导致额外等待，再修改产品并验证实际空/非空输入、禁止执行、一次准备、失败销毁及双架构 guest。后续用实际 mTLS API 做同负载对照，再集中构建与回归；本诊断不替代千次启动、一般安全、密度、长稳或原需求矩阵。

## 首轮工具初始化失败

原 `rc85-input-mount-probe-r1` 在控制台初始化时重复挂载内核已自动挂载的 devtmpfs，返回 EBUSY；零挂载样本。随后使用通用 poweroff 的尝试在此 `reboot=k` 内核上只停住 vCPU，最终由宿主截止时间清理。原失败、工具源码/ELF/镜像及清理证据全部保留。r2 改为产品已使用的直接打开 `/dev/console`、`RB_AUTOBOOT` 退出方式；不改变两种 remount 调用、256 个样本、ABBA、EROFS/EACCES 或属性检查。使用新工具目录、镜像、任务 ID 和夹具根目录补验。

## 实际结论

r2 完成 256 个样本及全部读取、EROFS/EACCES 和挂载属性检查；原方式最大 7.748 µs，增加 MS_BIND 最大 3.691 µs，均未复现毫秒级等待。Go 测试二进制和被测函数与原 r1 一致，两轮均已独立确认清理。此结果不支持把 remount 作为当前 prepare 长尾的主要解释，也不证明真实完整 agent 负载没有其他交互；保持产品原方式，沿宿主校验、vsock RPC 与调度路径继续定位。详见[验证记录](../../PUBLIC-QUALIFICATION.md#private-evidence)。
