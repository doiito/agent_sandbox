# CI、E2E 与回归策略

对应 ADR-0003；执行顺序：设计 → 自评审 → 实现 → 定向测试 → 合并 CI → 实机/发布验证。

按 [ADR-0049](adr/0049-functional-delivery-and-baseline-security.md)，功能开发与实际验证优先。基本权限、隔离、配额、取消/回收及签名检查保留；全面 CVE、长期 fuzz、独立安全认证为增强项，不阻塞基本功能交付。以下 L3/L4 涉及这些项目时按增强配置执行，性能和离线安装目标继续独立验收。

| 层级 | 触发/频率 | 覆盖 | 通过标准 |
|---|---|---|---|
| L0 快检 | 修改完成时；只检查受影响模块 | fmt/shell/JSON/文档结构、定向 Go/Rust/Python/Node 客户端测试 | 无格式修改、非零退出即失败 |
| L1 合并 CI | PR/主分支代码变更，一候选一次 | Go test/vet/race、Rust test/clippy、Python/Node 客户端契约测试、固定 E2B 分母完整性审计、静态 release 构建、进程集成 | 所有命令成功，无需 KVM；每候选报告 |
| L2 真机 E2E | 合并候选/手动；backend/guest/kernel/VMM/安全变更强制 | mTLS/API/launcher/jailer/guest、argv/input/限额/取消/隔离/清理 | 每条断言通过且实际 KVM；生产 doctor 不 ready 必须失败 |
| L3 批量回归 | 累计候选；失败修复后受影响集 | OSv/Linux 兼容、资源故障/恢复；fuzz 和深度依赖审计为增强项 | 受影响功能矩阵 + 原始证据；同服务器串行 |
| L4 发布 | RC、VMM/kernel/driver 重大变更 | 发布安装/回滚、性能与长稳；逃逸深测/独立审计为增强项 | 满足当前范围的必须项；未执行等于未通过 |

## 变更影响与重跑规则

- 仅 docs/proposal：检查 Markdown 链接/ADR/需求 ID，L1 Go/Rust 和 KVM 不触发。
- auth/http/tls：定向权限/输入/取消/TLS 测试 + L1；合并候选 L2 认证/拒绝/配额。不得让 fork PR 使用受控 runner。
- SDK/离线包文件清单/SBOM：定向客户端契约、打包/验签/安装与 L1；如服务运行载荷摘要不变，L2 仅重测安装后客户端真机链路和对应架构 QEMU，复用已绑定摘要的旧完整 KVM 结果。
- launcher/manager/lease/backend/guest：L1 + 合并时完整 L2；取消/回收及故障测试不能省略。
- kernel/VMM/OSv 驱动/镜像配方：L2 + L3 兼容/安全 + L4 性能/长稳，重建并重新签名制品。
- 只有候选源码内容、制品、测试版本、配置、工具链和宿主基线完全相同且已有成功证据才能复用昂贵结果。源码未提交时按内容生成摘要，不能只看 HEAD。
- 分段集成远程推理时，先冻结主机核心，再冻结出口/root生命周期，定向验证实际非root生产进程与ARM64协议功能；这些证据不能代替后续guest/签名/公开SDK同候选KVM。变更共享hijack传输时增加原代理进程回归。测试名称筛选需核对实际case集合，排除硬件专项采用精确名称；误排除普通单元项时按同一输入只补该项，不重复已通过的整组。
- guest 推理合约生成检查及 Python/Node 纯组件测试纳入普通 CI。修改 guest 合约或传输后，运行真实 SDK 进程到 root 桥接/TLS 模型的定向链路；ARM 编译或运行时相关变更使用无 NIC QEMU 执行实际 ARM 解释器的同组测试及固定回环调用。只有测试或验证驱动变化时，核对源码差异后复用未变组件的结果；完整候选再集中运行全 CI 和同包 E2E。QEMU 组件及模拟 C ABI 不能替代签名模板、实际 OSv、离线安装或 x64 KVM 验收。
- 快速 CI 可以取消 superseded PR job；真机测试使用跨 CI/手工一致的 flock，运行中的任务不能被下一批杀死。观察 SSH 超时先查原 PID/unit/session，不能盲目启动另一批。
- 长批次使用[ADR-0084](adr/0084-durable-validation-jobs.md)的 `scripts/validation_job.py submit/status`：固定ID、输入摘要和独立systemd单元；相同ID只观察、不重放，worker以O_EXCL领取一次。独立批次锁不占子夹具原锁；日志/期限有界，失联查询错误保持未知，收据落盘后仍等待原管理器确认worker退出。CI执行普通用户的工具定向测试；真实短任务证据见[专项验证](../PUBLIC-QUALIFICATION.md#private-evidence)，它不能代替原KVM/性能/零残留报告。
- OCI导入模板夹具先验证真实已安装CLI、原签名/字节与非root namespace可读性；正式cold/warm额外屏蔽API/launcher的包内原目录，并核对真实VM的kernel/rootfs。保留原混合模板、SDK/MCP、配额及清理断言，不能用同字节导入或namespace探针替代KVM。工具修改只运行新增定向用例；按模板及时回收重复layout，完整批次见[导入夹具记录](../PUBLIC-QUALIFICATION.md#private-evidence)。
- 不把 benchmark 放在每次 quick check；小样本 smoke 只检功能，性能门禁用固定硬件/CPU/NUMA/工作负载的独立批次。
- warm pool：L1 只审计[启动契约](contracts/warm-start-gates.json)及状态机/记账；池/生命周期实现变更触发真实 KVM 的一次领取、污染、配额、健康、模板失效、取消/崩溃/回收集。性能按签名候选批次分别测 warm/snapshot/cold，生产开启前运行 `python3 scripts/check-startup-gates.py --require-target`；无真实证据必须失败，不能以文档完整性检查代替性能通过。详见 [ADR-0029](adr/0029-pristine-warm-pool-and-startup-gates.md)。正式非测试签名的打包也强制执行该检查。两后端必须持有同一 run_root 独占 owner，重启在新身份分配前回收旧实例；功能报告要核对第二 owner 拒绝、PID start ticks/lease/cgroup 与 doctor 对账数量。Linux 专项脚本 `scripts/e2e-warm-pool.py` 覆盖预启动 VM ID、空闲检查预算、job/session、TTL、双租户、只读输入、死亡、断连、API/launcher crash 和停机；独立 helper 测试覆盖内存压力、签名过期、补池退避和并发竞争，不能冒充这些故障已有完整 KVM 证据。
- 启动性能批次独立于功能回归，使用 `scripts/startup_benchmark.py`，OSv 由既有夹具的显式 benchmark 分支调用。工具/统计修改只做 Python 定向、语法和文档/契约检查；运行载荷摘要不变时不重复构建或完整 KVM/QEMU。新候选需要测性能时才采集完整批次；pilot、strace、warmup 与正式样本分别保留，不混算。诊断条件和首批观测边界见 [ADR-0035](adr/0035-startup-measurement-evidence.md)及[千次基线](../PUBLIC-QUALIFICATION.md#private-evidence)。
- syscall 跟踪工具：L0/L1 用真实 strace 的本地子进程哨兵验证 raw 缓冲区不泄露及 exec 脱离，并验证线程交错/FD 复用/看门狗。CI 显式安装 strace，它仅为测试依赖，不进入离线应用运行闭包。附加 launcher 的跟踪仅在新隔离 KVM 夹具手动运行，保留时间/文件上限与格式审计；不能把跟踪分位数用于性能门禁，也不因新工具修改重跑不变应用的全矩阵。
- SBOM schema：L0/L1 的 Python 工具固定于 `deploy/requirements-validation.txt`，wheel/许可证和摘要在项目 `assets/build/python-validation`，CI 离线安装且明确使用 Python 3.12；目标机不依赖这些工具。四种 schema 格式检查器缺失即失败，不能静默跳过可选 IRI/时间校验。官方 CycloneDX 1.5 schema、SPDX/JSF 引用和来源摘要保存在项目 `assets/build/schemas/cyclonedx-1.5` 与 `deploy/schemas/cyclonedx-1.5/lock.json`；验证器禁止网络补取 schema，未知引用、摘要不符和悬空组件引用均失败。
- 漏洞工具：[采集与离线重放](SECURITY-EVIDENCE.zh-CN.md)按实际 SBOM 组件/制品字节和固定 policy 生成计划，联网采集只在依赖变化或证据过期时进行；普通 L1 用模拟原始响应和断网负测试，不每次调用公网数据库。真实易受影响版本正对照、当前候选查询、外部固定摘要和无路由 CLI 重放属于单独批次。库级文件覆盖、版本覆盖、查询完成、源码包匹配及实际二进制影响分别记录；纯工具/CI 依赖修订做定向 CI 和扫描流程 E2E，不重复 KVM/QEMU 全矩阵。
- OSv 池用 `scripts/e2e-osv-warm-pool.py` 验证同签名模板的真实预启动 ID 领取、env/stdin 绑定、能力拒绝、双租户/配额、取消/TTL、死亡、API/launcher crash 和零残留；与 Linux 共用状态机修改时，两后端均需同版功能回归。OSv harness 不解除产品生产门禁，功能微秒样本不计性能通过。
- OSv 跨进程夹具的批量选项默认关闭；仅在候选源码、签名模板或运行时路径变化后手动触发 `--stress-jobs`，并记录精确制品摘要。128 任务的功能批量不替代 L4 的 10k+ 与长稳门禁。

## E2E 证据和当前范围

`TestAPIEndToEndWithHelperBackend` 仅为 helper 进程集成，不能证明 KVM、jailer、mTLS 或 OSv 兼容。L2 脚本必须针对真实生产 API，用 client CA/cert/key 和 token 环境变量，检查 doctor/backend/实际 guest 输出/状态/job ID；清理再由 host 检查 cgroup/目录/进程。宿主采样需显示 VMM 非 root、seccomp=2、CapEff=0、有效 cgroup 限额。

用例至少包括：正确 stdout/stderr/argv；退出 7 的 guest_error；只读 input；root 写拒绝/uid 降权/no_new_privs；默认无 NIC/metadata 禁止；输出 flood 有界；guest timeout；HTTP 取消；无效 bearer/租户 entrypoint/超配额/非法 JSON/路径；连续任务 workspace 不继承；launcher/API crash 恢复；最终零残留。各后端单独记录能力，不能跳过 OSv 缺失项然后给总通过。

OSv 生产门禁未开放期间，`tests/osv-preproduction` 的 API→launcher 真机测试只能作为前置诊断证据；它复用运行时库，但不证明产品 CLI 的生产启动路径。其[故障与并发结果](../PUBLIC-QUALIFICATION.md#private-evidence)按此范围解释。

报告 JSON 包含 suite/version/time、候选内容与二进制摘要、命令退出码、case/pass/fail、host baseline 摘要和 cleanup。原始文件在 results/ 或受控 CI artifacts（默认保留 30 天，RC/发布证据另行归档）；提交去敏摘要和摘要校验值。CI 上传仅选报告，不上传 auth/TLS 文件。自动 CI 未在 GitHub 运行前，报告称“本地执行 CI 同等检查”，不能称云端 CI 绿色。

## 门槛失败的处理

过期证书、启用 swap、未缓解 CPU 漏洞、缺少控制器、错误签名都必须使生产 doctor/ready 失败。可另开明确标记的开发诊断测试验证 KVM 行为，但其结果不计为生产验收。测试 CA 可验证 mTLS，不能代替用户域名有效证书；2026-10-29 用户已明确先做域名证书以外的工作。

后台/流式变更按 [ADR-0051](adr/0051-background-commands-and-streaming-output.md)触发 guest 输出先于退出、取消帧/预读缓冲/静默断连/洪泛和 Go/SSE/SDK 定向检查；冻结一次 L1 后跑实际同包双语言后台工作流及受影响 session/取消/owner 回归。guest/pristine/transport 变化补验真实 warm 流式绑定与取消，不能只凭冷路径和原池用例推断；仅 SDK 适配变更按载荷摘要复用不变的完整池/内核证据，避免高频全矩阵。
