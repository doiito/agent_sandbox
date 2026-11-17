# ADR-0090：独立的 Linux 工作负载监督入口

状态：Accepted；日期：2026-11-11；需求 BUILD-01、PERF-01、QA-01/02、REL-04。

## 依据

[普通 mimalloc 实测](../../PUBLIC-QUALIFICATION.md#private-evidence)完成 2048 次实际 API 操作，命令 p50/p99 相对 System 增加 9.4%/10.9%。另有独立 1024 次启动诊断，在相同镜像和限额下，16 次 agent 相对 true 的配对耗时中位数为 System −1.96 ms、普通 mimalloc +5.55 ms，正式操作未观察到 CPU 节流。现行每次工作负载都重新执行完整 agent，短生命周期监督进程与 PID1 使用同一个 mimalloc ELF。此证据支持拆开分配生命周期进行验证，尚未证明拆分后的实际收益。

## 决策

Linux guest 增加独立的静态 `/sbin/osv-workload-supervisor`，作为同一 Cargo 包内的二进制，调用现有共享 `workload::dispatch_helper()`。显式使用 Rust System 分配器，避免短生命周期程序携带 mimalloc 初始化与退出成本。PID1、文件/JSON/代码服务及另一个 musl guest 继续使用锁版本 mimalloc。SBOM、构建来源与 allocator 门禁分别声明两个 Linux 程序的身份，不用整个包的 Cargo 特性推断每个 ELF 的分配器。

正式父进程使用固定绝对 helper 路径，保留原 `--workload-supervisor` 参数及 CONTROL/GROUP/语言 FD 协议。工作负载配置、cgroup/subreaper、真实 PID、父死信号、超时、取消、并发任务归属和清理共用既有代码。独立入口在非预期参数、非 root、父进程非 PID1、控制 FD 缺失或协议非法时仍拒绝执行。旧 agent 辅助入口在迁移验证期间保留兼容能力，父进程固定选择新程序，缺失时明确失败，不能静默回退而掩盖未安装产物。

构建入口、基础/科学/Node 等所有 Linux 模板和实际 QEMU 验证 initrd 必须携带同一构建的 helper。发布核验两个架构的静态 ELF、通用 ISA、来源/依赖/许可证、文件权限及镜像逐字绑定。helper 的构建与运行无需额外目标机库或下载，实际程序与来源保存在项目。guest ready 前检查固定 helper 可用，镜像签名和 hash 仍覆盖完整文件系统。

新 musl bundle 使用 `osv-musl-guest-build/v2`，分别绑定两个 mimalloc 程序和 System helper 的摘要、分配器身份及实际链接映射。新代码镜像使用 `osv-linux-code-image/v2`，逐字绑定 helper 与基础镜像并在最终 SBOM 中记录其 System 静态身份。新发布准备拒绝遗漏、错架构、篡改、错误分配器或不匹配的镜像副本；历史 rc82 程序/签名包保留作为基线，SBOM 工具保留 v1 的历史来源读入能力。

## 验证与验收

先完成[自评审](../../PUBLIC-QUALIFICATION.md#private-evidence)，再实现。先做两个架构的离线静态编译、allocator 身份和拒绝入口定向检查，随后验证真实监督的成功/错误/退出码、stdin/输出、并发隔离、超时/取消、脱离会话后代清理、解释器与代码上下文控制 FD。ARM64 使用 QEMU，继续遵守免验 ARM KVM 的用户范围。

使用同源码、同 PID1 分配器和优化设置的旧/新监督路径参考，镜像差异明确限制为父程序路径选择及新增 helper。按前述真实四操作 ABBA 测量完整 API、命令时长、失败率和内存，保留原始失败及各臂波动。除前述布局外不同时改动 mimalloc secure 配置或 CPU 配额，避免混淆收益。参考保持诊断身份，不在验证前替换 rc82 的功能基线。

原 agent 的可执行页可能已由 PID1 启动加载，新增 helper 在 fresh VM 中可能尚无文件页缓存。每个新会话的首条工作负载须单列耗时及 CPU 计数，覆盖首次 helper 加载，随后再报告预热后的正式样本。不能只用稳态测量推断首条命令收益，也不在测量前引入未记录的 helper 预执行。

首轮真实 API ABBA 完成 2048 次正式操作且零失败，稳定命令 p50 降低 6.6%，首条工作负载的 16 个样本/布局尚未改善。下一步将内部监督程序的代码读取纳入 guest 初始化，在声明 ready 前以固定栈缓冲读取，限制文件不超过 4 MiB，不执行 helper 或租户命令。读取成本计入 cold boot，warm 池只接收初始化完成的 VM。此项用于验证首次代码加载的影响，尚未认定首轮差异由缓存单独导致；保留首轮数据，修改后以新输入和固定任务 ID 对照，不用隐藏预热替换首条样本。

代码读取采用独立因素对照，两组均固定独立 System helper、PID1 mimalloc secure=4 和相同限额。私有源码副本仅在 baseline 中移除已标记的代码读取块，primed 使用正式源码，不增加运行时开关。v3 参考明确 baseline/primed、实际路径/分配器及布尔读取状态。每臂 32 个 fresh session、2 轮预热和 4 轮正式四操作，正式分母仍为 2048 次，每种操作每组 256 个样本；首次工作负载增至每组 64 个样本。每会话请求上界 40，原 100 次预算保留。首条样本、全部预热、正式操作、CPU/内存和失败分别保存，仍不替代千次启动门禁。

[独立读取对照结果](../../PUBLIC-QUALIFICATION.md#private-evidence)已完成，128 个新 VM 和 2048 次正式操作零失败。首条探针 CPU 中位数为 baseline 12.670 ms、primed 11.291 ms，完整 API 中位数为 35.818 / 35.658 ms，后者改善较小且与臂间波动接近。保留有界读取进入新候选回归，初始化成本仍须计入 cold boot，不据此关闭整体性能门禁；64 个首条样本的 p99 是组内最大值，不能替代千次启动验收。

收益得到支持后，将两个架构及全部 Linux 模板冻结为一个新候选，按影响策略只运行一次完整 CI、双架构离线安装、ARM QEMU 和指定 x64 KVM 功能回归，覆盖命令、代码/科学运行时、上下文、stdin、流式、SDK/MCP/gRPC、代理/端口和生命周期。失败先定点修复。既有 2/5/10 ms 启动 SLO、同任务性能、资源/一般安全基线、其余原始功能及正式发布条件继续保留。

[rc83 完整候选验收](../../PUBLIC-QUALIFICATION.md#private-evidence)已完成 1909 项输入绑定、宿主完整 CI、双架构离线包、ARM 无网卡 QEMU 58 组及指定机 KVM 原 15 套/516 项加 44 项 gRPC。首轮受限环境的 socket 权限失败保留，8 项定向宿主检查后使用同一冻结输入完成验收。本 ADR 的入口拆分与有界初始化决定接受，整体 mimalloc 收益及原性能/正式发布门禁继续开放。
