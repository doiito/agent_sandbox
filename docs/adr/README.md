# 架构决策记录

原始需求、设计决策和验收之间的映射见[需求跟踪矩阵](../REQUIREMENTS.zh-CN.md)。Accepted 表示采用该决策，不表示实现完成或生产验收通过。

| ADR | 状态 | 决策 |
|---|---|---|
| [0001](0001-workload-and-evidence.md) | Accepted | 保留 OSv 原生优化路线和最小 Linux 兼容路线，用同口径工作负载证据决定推广 |
| [0002](0002-host-enforced-isolation.md) | Accepted | 一任务一 VM、宿主强制隔离与独立可取消控制通道 |
| [0003](0003-regression-and-release.md) | Accepted | 风险和变更驱动的分层 CI/回归，原始证据绑定候选制品 |
| [0004](0004-capabilities-and-contracts.md) | Accepted | 显式能力协商与版本化产品契约，未实现功能不冒充兼容 |
| [0005](0005-durable-admission-and-supervision.md) | Accepted | 执行前持久审计、运行时有效期、客体后代收尾和 systemd 就绪通知 |
| [0006](0006-osv-native-vsock.md) | Accepted | 固定上游的 OSv 原生 virtio-vsock、C ABI、队列/流控与独立验收 |
| [0007](0007-offline-self-contained-release.md) | Accepted | 离线自包含发布、签名验证和版本化安装 |
| [0008](0008-osv-job-control.md) | Accepted | OSv 原生任务控制、单次签名模块执行与结果通道门禁 |
| [0009](0009-signed-osv-template.md) | Accepted | OSv 模板签名、入口与制品清单绑定 |
| [0010](0010-osv-cross-process-preproduction.md) | Accepted | OSv 生产前跨进程诊断验收及门禁隔离 |
| [0011](0011-capability-discovery.md) | Accepted | 权威能力查询和租户过滤 |
| [0012](0012-explicit-template-selection.md) | Accepted | v2 任务显式绑定后端与签名模板摘要 |
| [0013](0013-offline-activation-rollback.md) | Accepted | 离线版本切换、已安装字节复核及回滚门禁 |
| [0014](0014-cgroup-owned-recovery.md) | Accepted | 专用任务 cgroup 拥有 VMM 生命周期与启动对账 |
| [0015](0015-python-client-contract.md) | Accepted | 零第三方依赖 Python 客户端使用 mTLS 与显式 v2 模板绑定 |
| [0016](0016-node-typescript-client.md) | Accepted | 零 npm 依赖 Node/TypeScript 客户端与 Python 客户端对称 |
| [0017](0017-e2b-pinned-compatibility.md) | Accepted | 固定 E2B 版本、34 项分母和双语言真实行为证据门槛 |
| [0018](0018-linux-guest-session-protocol.md) | Accepted | Linux guest 在同一 VM 内执行多条命令的 v2 协议 |
| [0019](0019-host-owned-sessions.md) | Accepted | launcher 持有 VM、API 持有租户配额的公开 session 生命周期 |
| [0020](0020-dual-language-session-clients.md) | Accepted | 双语言原生 session 客户端和准确能力声明 |
| [0021](0021-confined-session-files.md) | Accepted | guest 内严格限制的 session 工作区文件读写与稳定错误语义 |
| [0022](0022-bounded-session-file-metadata.md) | Accepted | 有界工作区文件列表、元数据与删除，目录 fd 限制及结果绑定 |
| [0023](0023-e2b-compatible-facade.md) | Accepted | 固定 E2B 2.51.0 双语言显式适配层与逐项真机计分门槛 |
| [0024](0024-confined-session-directory-and-e2b-writes.md) | Accepted | 受限目录创建、双语言自动父目录文件写入与有界批量 |
| [0025](0025-osv-native-environment.md) | Accepted | OSv 原生签名模块任务的有界环境变量与向后拒绝的请求扩展 |
| [0026](0026-osv-native-stdin.md) | Accepted | OSv 原生签名模块任务的有界二进制 stdin 与特性门禁 |
| [0027](0027-confined-session-file-info.md) | Accepted | Linux 会话受限文件元数据与 E2B 信息契约 |
| [0028](0028-symlink-and-xattr-file-info.md) | Accepted | 受限文件信息的符号链接、扩展属性与完整 E2B 语义 |
| [0029](0029-pristine-warm-pool-and-startup-gates.md) | Accepted | pristine VM warm pool、快照/冷启动分路径测量与生产门禁 |
| [0030](0030-pristine-guest-preparation.md) | Accepted | pristine guest 一次准备、绑定、输入冻结与降级拒绝 |
| [0031](0031-owned-vm-lifecycle.md) | Accepted | cold 与 warm 共用 VM 实例所有权、唯一销毁和管理器关机收尾 |
| [0032](0032-linux-pristine-pool-runtime.md) | Accepted | Linux pristine pool 的有界调度、一次领取及 job/session 接入 |
| [0033](0033-osv-pristine-job-preparation.md) | Accepted | OSv pristine 探测、单次任务绑定、硬租期和旧协议隔离 |
| [0034](0034-shared-pristine-pool-backends.md) | Accepted | Linux/OSv 共用池生命周期、后端准备与结果适配、能力和签名门禁 |
| [0035](0035-startup-measurement-evidence.md) | Accepted | 公开 API 启动测量、预启动 VM 证据绑定和诊断/生产区分 |
| [0036](0036-atomic-warm-readiness-and-preparation.md) | Accepted | 就绪与单次领取准备合并为一次有界控制握手 |
| [0037](0037-direct-cgroup-membership-verification.md) | Accepted | 直接读取专用 cgroup，识别合法内核 worker 并拒绝额外用户进程 |
| [0038](0038-pinned-osv-python-science-template.md) | Proposed | 固定 Python 科学栈依赖闭包与真实 OSv 语言兼容矩阵 |
| [0039](0039-static-mimalloc-musl-guests.md) | Proposed | 两个 musl Rust guest 的静态 mimalloc、双架构构建和性能证据 |
| [0040](0040-osv-pipe-stat-metadata.md) | Accepted | 匿名管道有效 fstat、不可变共享元数据与 Python 标准流兼容 |
| [0041](0041-osv-task-exit-result-bridge.md) | Accepted | 单任务 VM 的显式 exit 通知与一次完成，保留语言清理和真实退出码 |
| [0042](0042-bounded-osv-rofs-memory-policy.md) | Accepted | 只读科学模板的受控内存缓存策略、同候选对照与签名绑定 |
| [0043](0043-reclaimable-readonly-osv-mappings.md) | Proposed | 驻留测量、只读文件页所有权、TLB 和压力回收边界 |
| [0044](0044-checked-source-python-bytecode.md) | Accepted | 固定解释器的 checked-hash 字节码、保留源码语义与同负载内存验证 |
| [0045](0045-bounded-rofs-block-reads.md) | Accepted | 无缓存 ROFS 的有界连续缓冲、文件完整性与块设备失败状态 |
| [0046](0046-runtime-component-provenance.md) | Accepted | 科学运行库来源、许可证、字节码构建与镜像内部 SBOM |
| [0047](0047-replayable-vulnerability-evidence.md) | Accepted | 漏洞查询计划、原始响应、离线重放与覆盖/时效门禁 |
| [0048](0048-component-impact-evidence.md) | Deferred | 组件影响分析，按用户要求转为增强项 |
| [0049](0049-functional-delivery-and-baseline-security.md) | Accepted | 功能优先、基本安全保留、增强审计可选 |
| [0050](0050-workspace-rename-and-recursive-remove.md) | Accepted | 会话文件/目录重命名、递归删除与双 SDK 工作流 |
| [0051](0051-background-commands-and-streaming-output.md) | Accepted | 后台命令句柄、实时输出、游标重连与取消回收 |
| [0052](0052-bash-and-e2b-command-handles.md) | Accepted | 真实 Bash、guest PID、运行参数与 E2B 命令句柄 |
| [0053](0053-bounded-interactive-command-stdin.md) | Accepted | 有界交互stdin、guest确认与独立观察/取消 |
| [0054](0054-session-info-pagination-and-renewable-ttl.md) | Accepted | 会话信息、租户稳定分页与有界可调整TTL |
| [0055](0055-linux-one-shot-job-execution-inputs.md) | Accepted | Linux一次性任务环境、工作目录与非阻塞固定stdin |
| [0056](0056-mcp-stdio-api-gateway.md) | Accepted | 双版本stdio MCP与共用认证API工具网关 |
| [0057](0057-bounded-authenticated-egress-fetch.md) | Accepted | 认证HTTP egress引擎与API/MCP网络fetch |
| [0081](0081-controlled-remote-inference-and-task-billing.md) | Proposed | 受控远程推理、双后端 guest SDK 与持久任务账单 |
