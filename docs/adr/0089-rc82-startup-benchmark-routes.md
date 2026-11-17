# ADR-0089 RC82 启动分路径复测

状态 Accepted，2026-11-11。关联 PERF-01、PERF-03、QA-03。沿用 [ADR-0035](0035-startup-measurement-evidence.md) 和 [启动门禁](../contracts/warm-start-gates.json)。

在指定 x64 主机使用通过功能验收的 rc82 签名包，逐后端串行测量 warm 和 cold。Linux warm 首先复用已冻结的公开 mTLS 工具和 128 MiB、1 vCPU shell 工作负载。保留 5 次预热、1000 次正式请求、所有失败以及宿主、签名载荷和阶段数据。Linux warm 与早期样本的版本和宿主状态差异随结果记录。

warm 继续使用从 launcher 认证准入到持久归属提交的 `startup_duration_us`，每个响应通过持久领取事件与请求前观察的唯一 ready VM 关联。cold 使用 `vm_boot_duration_us`，另记全准入和 HTTP 时长。使用有独立 VMM 计时的前台 cold 分配路径，并以 `pool.created`、`pool.claimed`、配置形状及 VM ID 核对。Linux 使用 shell，rc82 包内 OSv science 使用签名 Python 入口及其 512 MiB profile，各自固定 1 vCPU。两套工作负载各自报告，另行验证同任务同限额比较。

指定主机读到已启用 swap，按现有生产 doctor 规则以诊断身份采集并记录就绪检查。沿用现有全局验证锁、独立 systemd 夹具、隔离网络、逐批清理和持久 worker。快照启动、长期稳定性和实际工作负载分配器对照继续保留各自的验收分母。

四路线基线采集完成后，复用 ADR-0035 的有界 launcher 跟踪工具，在同一 rc82 包的新 Linux warm 夹具采集 5 次预热和 8 次正式任务。保持正常 1 秒健康检查，以完整请求的审计窗口关联 lease 提交、guest 控制连接和宿主检查，核对持久写入实际成本。继续采用既有时间与文件上限、数据参数 raw 模式、VMM 不持续跟踪及脱离确认。跟踪数据用于优化归因，正式分位数取前述无跟踪批次。应用修改须在归因和自评审之后进行。
