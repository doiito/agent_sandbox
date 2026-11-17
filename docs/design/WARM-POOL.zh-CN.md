# 本项目 pristine VM pool 管理设计

当前 warm 启动门槛为 **p50≤5 ms、p95≤9 ms、p99≤13 ms**，依据[ADR-0114](../adr/0114-warm-start-five-nine-thirteen.md)，由[机器契约](../contracts/warm-start-gates.json)及 `scripts/check-startup-gates.py` 校验。计时包含持久准入与客体准备，每条必要路线至少 1000 个正式样本；历史采样及判定保留原记录。

更新：2026-10-31；关联ADR-0029/0032/0034/0036及[ADR-0037](../adr/0037-direct-cgroup-membership-verification.md)、LIFE-04、PERF-03。[rc42验收](../../PUBLIC-QUALIFICATION.md#private-evidence)通过完整CI、双架构包、ARM64无网卡QEMU28项、Linux job/session池KVM29项、OSv共用池25项/冷路径33项及SDK/API/故障回归。内核worker实时识别并纳入实例预算/清理；两后端各128次任务成功，readiness无>10ms，完整性能与生产门禁未通过。

## 归属与状态

root launcher 中的 `PoolManager` 管理多个固定签名 profile 的队列。`VMInstance` 统一持有 VMM 进程、生命周期 context、jail identity、cgroup、工作目录、lease 和一次性 cleanup；HTTP/API 的 `SessionLease` 只持有一次领取后的租户租期与控制连接。预启动 context 不随创建请求取消；领取后通过独立 timer/取消通道终止实例，不能试图替换已经启动的 `exec.Cmd` context。

| 状态 | 所有者 | 可转移到 | 必须完成的动作 |
|---|---|---|---|
| reserved | PoolManager | booting / destroying | 预留物理实例、内存、CPU/pids 和唯一 jail identity，登记实例 owner；进程启动后持久化 lease |
| booting | PoolManager | ready / destroying | 固定签名 profile 启动；guest pristine 握手；禁止租户执行 |
| ready | PoolManager 的有界队列 | claiming / destroying | 从未接收租户输入；记录单调时钟 idle 截止时间 |
| claiming | 唯一领取事务 | active / destroying | 原子移出队列；持久审计准入；校验存活/剩余寿命/模板；绑定新 ID/nonce/input |
| active | SessionLease 或一次性任务 | destroying | 租户 TTL、API 断连和命令取消直达同一个实例；不回 ready |
| destroying | VMInstance cleanup | destroyed / cleanup_failed | kill、wait、cgroup 空、目录清理、lease 收尾，确认后释放所有预算 |
| cleanup_failed | VMInstance / operator | destroyed | 保留归属与证据，停止新准入；不可先释放预算后继续发 VM |

任何状态仅一个所有者。领取通过互斥状态转移/CAS 同时取得实例与预算标记；转移之后的任意错误由领取方销毁。补池协程不能把已移出的实例重新入队。终态 cleanup 使用 once，进程 watcher、TTL、断连、关机均调用同一路径。

[ADR-0031](../adr/0031-owned-vm-lifecycle.md) 的共用 `vmInstance` 已在 [rc31](../../PUBLIC-QUALIFICATION.md#private-evidence) 接入 cold job/session，覆盖 reserved/booting/active/终态与管理器停止。它持有固定 context 和物理预算，会话只管理租期与 active 预留；启动前登记、staging/销毁互斥、唯一 Wait 和幂等 cleanup 均已验证。rc34 增加 ready/claiming、pool key 和请求归属的持久化，以及调度、领取和后台检查；全部实例仍沿用这一 owner 清理。

## 容量和调度

采用两个不同计数：`active` 限制租户已领取任务；`instances` 限制宿主真实 VM，包括 reserved、booting、ready、claiming、active、destroying。领取 ready VM 只转移已有物理预留，不再次申请物理槽。冷启动须取得物理预留，匹配不到池但预算被 idle VM 占用时，优先淘汰最老的不匹配 idle VM，确认回收后再启动。不能复用现有 `m.sem` 同时代表两种容量，避免池占满后领取死锁。

每个实例预留 `guest_memory + VMM_overhead`，按现有无 swap 的 cgroup 限制执行；所有状态占用真实资源直到退出确认。物理配置使用 `vm_capacity.max_instances/reserved_memory_mib/reserved_vcpus/reserved_pids`；active 上限使用 `limits.max_concurrent`。`warm_pool` 配置 `max_booting/refill_per_second/refill_burst/max_idle_age_ms/checkout_timeout_ms`，每个允许 profile 配置 `min_ready/max_ready`。校验各 profile 最小预留不超过宿主预算，所有值有硬上限。

首个实现批次中，`limits.max_concurrent` 对应 max_active，`vm_capacity.max_instances/reserved_memory_mib/reserved_vcpus/reserved_pids` 对应物理资源预算。普通 job/session 以原子事务同时预留 active 与物理资源；内部独立物理预留和 active 领取接口已通过并发/race 检查，rc34 的预启动只领取物理预留，前台单独领取 active。doctor 返回账本快照，[rc28 双架构与 KVM 验收](../../PUBLIC-QUALIFICATION.md#private-evidence)已通过。rc34 已提供显式启用的 `warm_pool` 配置、补池、健康淘汰与 ready/claiming；默认关闭，正式发行仍受性能和安全门禁约束。

只有管理员配置且已验签的 profile 可建池，用户请求不能创建任意新池键。补池先补各 profile 的 min_ready，再轮转增长目标，有界并发和每 profile 指数退避。目标从 min_ready 开始，匹配命中或 cold fallback 成功后增加至 max_ready，idle 过期时逐步缩回 min_ready。物理预算满时优先回收超出其他 profile 最小数的 idle，避免热 profile 饿死最低预热目标；冷启动前台请求优先于补池。内存压力下缩减 idle，恢复后按速率补足；不通过 zram/swap 隐藏池成本。池空或规格不符时，遵从显式 `on_miss=cold|reject`，记录原因与实际启动路径；队列等待受请求 deadline/租户配额限制。

前台优先由同一个调度器落实，不能只在补池循环里检查一个布尔值：先登记有界前台 demand，再领取或回收 idle，最后为 cold 请求原子预留物理预算。存在等待物理预算的 demand 时暂停对应资源的 refill，直到前台已取得预算、拒绝或取消，避免回收出的槽立刻被补池抢走。active 槽不足时直接拒绝，不能先淘汰 idle。补池只做非阻塞资源预留；不持有 pool 锁等待启动、guest RPC 或 cleanup。多 profile 按 deficit 轮转，单个失败 profile 的退避不阻塞其他队列；`min_ready` 是受预算约束的补足目标，不能阻止前台回收 idle。

池键由管理员不可变 profile 计算摘要，至少覆盖 backend/arch、签名 manifest 摘要、kernel/rootfs/VMM/guest 内容摘要、CPU 兼容配置、内存/vCPU、scratch/input 配置、vsock 协议、网络与 cgroup/安全策略。租户 ID、nonce 和 input 内容不进入可共享池键，它们只在唯一领取事务中绑定。规格必须精确匹配；首版不以大规格 VM 代替小规格请求。首版模板轮换通过停止旧 Manager、保守回收全部旧实例、重新验签和启动新 Manager 完成；不在原队列上修改键，不接管旧 ready VM。

## 领取、输入与租期

API 完成租户鉴权与 active 配额预留后，launcher 在同一受认证连接中领取实例。即时核对签名窗口、模板摘要、backend/arch、规格、网络策略、lease/PID 代次和 cgroup，并用一次精确的新绑定 prepared ACK 确认 guest 当前未用及租期合法。warm 不额外发送前台 ping，cold/boot/background 仍完整探测。VM 启动时的 jail UID/GID 在整个生命周期唯一，领取不改宿主身份；VM ID 与新生成的 job/session ID 分别记录并绑定审计。

Linux guest 增加版本化 pristine→prepared 握手，在首次准备中接收有界输入、冻结只读 input、创建空 workspace、绑定请求 nonce/ID/TTL，然后 ACK；ACK 前不允许工作负载执行。宿主不能修改已挂载 block image 来注入输入。现有 guest 单调时钟最大寿命保持硬界：`idle age + requested TTL + cleanup headroom` 必须小于剩余寿命，否则淘汰；不能让预热 VM 获得无限续期。

[ADR-0030](../adr/0030-pristine-guest-preparation.md) 的 Linux `fc-agent/v3` 已通过 [rc29 真实 KVM 与 ARM64 QEMU 验收](../../PUBLIC-QUALIFICATION.md#private-evidence)，包含准备前拒绝、ID/nonce 绑定、输入冻结、一次 job 和 idle 租期。rc34 已接入公开 job/session pool 领取，并强制 `pristine_revision=2`：旧 v3 guest 不能仅凭协议字符串入池。pristine 健康 ping 不消耗租户的 100 帧预算，自身仍受 6000 次检查和 600 秒硬寿命约束。领取使用 guest 剩余寿命和 owner 原始 deadline 中较早者；宿主 session TTL 从 prepare 前开始，不晚于 guest 的租期边界。

一次性任务准备后仅执行一次并销毁；session 准备后可在同一租户租期内执行多条命令，关闭即销毁。OSv 按 [ADR-0033](../adr/0033-osv-pristine-job-preparation.md) 使用独立 OSP1 准备协议，rc37 已接入共用调度器、资源账本和 owner，诊断中验证预启动实例的实际领取、绑定、隔离、取消与恢复。OSv warm_pool 能力只在配置实际启池时为 true；公开结果协议仍为 osv-agent/v1，session/input-files/workspace 继续拒绝，产品生产准入仍关闭。

共用领取事务生成私有 32 字节 nonce：Linux 使用全部 256 位，OSv adapter 按现有 OSJ1 wire 使用前 128 位；每次重新生成，不能写入 lease/审计/日志。backend 和确切 pristine 协议修订显式进入 pool key。job 在 VM 退出后只允许有界结果 drain，既保留正常退出前的绑定结果，也不让死亡 VM 的控制连接等待整个任务 TTL。warm/cold 依据已绑定 guest 结果保留实际退出码。

## 健康、更新和恢复

健康检查包括进程存活、cgroup/lease 归属、guest pristine 状态和有界 ping。后台检查不替代领取时检查；死亡或响应异常的实例隔离销毁。模板、策略、VMM/kernel/guest、CPU 兼容 profile 或签名窗口变化时，停止相关补池并淘汰 idle，已准入租户任务按原 TTL 收尾。清理失败触发现有 fail-closed。

领取和健康检查必须取得同一个实例互斥归属，禁止并发向 guest 发 ping/prepare。原子移出 ready 后再在锁外检查和准备；检查失败时由领取方销毁，随后按显式 miss 策略处理，不能将可疑实例重新入队。取消与 prepare ACK 同时发生时，只有确认请求仍有效且状态提交成功才可交出句柄，否则销毁；ACK 超时后不得自动重试 prepare。idle age 以单调时钟计算，绝不超过 guest 剩余寿命减去租期和清理余量的硬界。首版用补池速率/并发限制平滑重建，尚未加入过期抖动；是否进一步分散过期由大样本批次评估。

实例继续使用现有 `job-*` 工作目录及专用 cgroup，lease 增加 pool key/state/VM ID/可选租户归属，禁止记录秘密输入。launcher 重启时先保守回收所有旧实例及残留补池，再重新验签和建池；首版不接管旧 ready VM。systemd 停止时先关闭补池入口和新领取，取消/等待 booting，按既有停机策略收尾 active，最后确认全部实例和身份归零。

独占 owner 与启动对账覆盖生产运行时、所有启用的 warm pool，以及签名 jailed 的 OSv 诊断模式。诊断模式不能绕开生命周期保护：先验证规范、root 所有且不可被 group/other 写入的运行目录与祖先，再持有 run_root 独占锁、清理旧 cgroup/目录，最后分配身份与建池；第二 owner 必须在对账前拒绝。doctor 报告持锁状态与对账数量。运行目录和配置文件分别检查末级类型，拒绝符号链接；初始化失败必须关闭锁。rc35 崩溃恢复和 rc36 路径检查的实机失败均保留，不能计为成功样本。

`pool.created/ready/claimed/discarded/refill_failed` 审计关联 VM ID、profile 摘要与请求 ID。doctor 报告 ready/booting/目标、检查/回收中数量、内存压力、补池退避及失败；资源账本和 owner 报告 active、物理预留与清理状态。Prometheus 当前输出 available、ready/booting/目标、命中、未命中/丢弃原因与补池失败计数；每次响应另外记录 `startup_mode/startup_duration_us`。idle age 分布与聚合启动直方图留待性能批次，不把尚未输出的指标宣称已具备。开启池时 doctor 验证预算/profile/签名/初始最小池；运行期间短时缺池作为可观察降级，安全或 cleanup 失败继续阻止准入。

## 验收顺序

1. 状态机与资源账本：并发领取、取消、重复 close、前台优先、容量不超限及无死锁。
2. 真实 KVM：pristine 标志、一次领取、输入冻结、双租户污染/拒绝、TTL、池空/不匹配/死亡、过期模板、补池故障、API/launcher crash、停机零残留。
3. 同候选独立性能批次：从 launcher 接受已鉴权请求到 guest 确认可执行，包含持久准入、健康和准备开销；另列纯 checkout、API/mTLS、排队、解释器初始化和执行耗时。每路径至少 1000 样本，正式发布按 PERF-02。
4. pristine 内存快照单独接入与验证熵、时钟、身份、vsock，不能用 warm 命中结果证明快照恢复。

两后端功能通过不等于全部 LIFE-04/PERF-03 完成：独立大样本、OSv 产品生产准入和安全门禁继续跟踪；用户新增需求不因默认关闭而视为完成。机器门禁明确要求独占 owner 与崩溃对账，功能脚本或单个启动样本均不能替代性能批次。

rc38 新增可选 startup_timing，将原 launcher 起点到可执行分成七个不重叠阶段，重试/淘汰计入累计，逐条总和等于 startup_duration_us。cold miss 另报首次完整 readiness 的 VMM boot，warm 不报旧预启动成本；字段定义与 [ADR-0035](../adr/0035-startup-measurement-evidence.md)一致。[128 次阶段定位](../../PUBLIC-QUALIFICATION.md#private-evidence)表明 readiness 主导长尾，随后[同版 CPU 周期对照](../../PUBLIC-QUALIFICATION.md#private-evidence)的 256 个正式任务全成功，缩短周期未消除长尾，14 个慢样本覆盖窗口内无节流增量；默认值不变。随后[直连 vsock 分段](../../PUBLIC-QUALIFICATION.md#private-evidence) 256 个连续 ping 全成功、p99=1.347ms，未复现领取长尾；正式 API 的检查/调度与通信仍需在原路径定位，不能用直连或定位样本代替生产性能通过。

[正常 API 有限跟踪](../../PUBLIC-QUALIFICATION.md#private-evidence)确认 rc38 每次领取的 ping→prepare 两条连接。[ADR-0036](../adr/0036-atomic-warm-readiness-and-preparation.md) 的原子准备确认已在 rc40 验收：即时宿主归属/签名/保守寿命检查、一次精确 prepare ACK、准备后复核和原有持久提交；启动/cold/background ping 保留。zombie/closed owner 不得领取，只有确定在 prepare payload 尝试前失败且销毁成功才可按原 miss 策略重选；未知 ACK 不能重试。完整本地 CI、双架构/QEMU/KVM 回归及 13 次一次控制连接证明通过。rc39 死亡实例 503 和 rc40 跟踪末行原解析失败分别保留，补充格式审计不覆盖原失败。每后端 128 次诊断的总启动 p50 为 4.145/3.511ms，但 Linux host-only readiness p99 仍为 31.229ms；下一步定位宿主检查/持久化/调度，完整目标不变。

[ADR-0037](../adr/0037-direct-cgroup-membership-verification.md)将即时归属核对改为固定cgroup v2目录FD下的domain类型/成员读取；预期VMM必须直接在组内，其他PID仅接受内核PF_KTHREAD证明，拒绝未知或额外用户进程。一次VM可有VMM及附属内核worker多个宿主PID，均计入原CPU/内存/pids预算，销毁必须确认cgroup清空后才释放预留。rc41的单PID假设导致初池失败并保留，rc42按真实模型通过八项内核反例、两个真实VM正例及完整候选回归。新检查有成本，两后端p50分别4.539/3.705ms；正式目标未达到，不通过删除持久化或跳过当前归属确认降低计时。
