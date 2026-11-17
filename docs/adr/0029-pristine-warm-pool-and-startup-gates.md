# ADR-0029：一次性 pristine VM warm pool 与分路径启动门禁

状态：Accepted；日期：2026-10-30；需求 LIFE-04、PERF-03、SEC-01、SEC-03、REL-04。来源：用户要求参考 exec-sandbox 加入 warm pool 加速及门禁。继承 ADR-0001、0002、0003、0005、0014、0019。

当前 warm 数值由[ADR-0092](0092-warm-start-five-eight-ten.md)替代为 **p50≤5 ms、p95≤8 ms、p99≤10 ms**；下文原数值属于历史决策。

## 现状与参考

当前 `Manager.StartSession` 在请求到达后创建目录、cgroup、VMM 并等待 guest 就绪；一次性任务也为请求启动 VMM。jail identity pool 只分配 UID/GID，不包含预启动 VM。`Snapshots=false`，尚无 warm pool 或内存快照恢复，不能声称具备 1–2 ms warm start。

参考 [exec-sandbox 固定提交](https://github.com/dualeai/exec-sandbox/tree/09738dd7e0976c5fab6560eb1ab915e4b6b426af)的 [WarmVMPool](https://github.com/dualeai/exec-sandbox/blob/09738dd7e0976c5fab6560eb1ab915e4b6b426af/src/exec_sandbox/warm_vm_pool.py)、[scheduler](https://github.com/dualeai/exec-sandbox/blob/09738dd7e0976c5fab6560eb1ab915e4b6b426af/src/exec_sandbox/scheduler.py)与 [README 性能说明](https://github.com/dualeai/exec-sandbox/blob/09738dd7e0976c5fab6560eb1ab915e4b6b426af/README.md)。其预启动池按语言配置，领取时剔除死亡 VM，用后销毁并后台补池；池未命中可走快照或冷启动。README 的池命中、内存快照和冷启动属于不同测量路径，不能互相替代，也不能直接当成本项目性能证据。

## 决策

实现 root launcher 持有的 pristine VM pool，覆盖 Linux 一次性任务和 session 创建，OSv 按后端协议接入并分别验收。池键包含 backend、架构、签名模板原始摘要、VMM/kernel/guest 版本、内存/vCPU、网络策略和运行时 profile。只有完成 guest 健康握手、未接触租户数据的 VM 可进入 ready 队列。领取时原子转移唯一所有权并再次检查存活、签名窗口、池键和 guest readiness；重新绑定随机请求/session ID、nonce、vsock 身份和租期后才允许执行。普通 job 和已结束 session 的 VM 一律销毁，不返回池中。

池由明确 min/max、补池并发/速率、idle age、资源预算控制。预启动、ready、已领取、补池中的 VM 都计入宿主内存/CPU/pids/cgroup 和 jail identity 容量；不能以池为由绕过租户准入、全局槽或生产安全门禁。池空、规格不符、健康失败、签名过期和模板切换的处理必须可观察；未执行请求可选择同模板冷启动，不能静默切换 backend/template。取消、领取中断、API/launcher 崩溃、停机和补池失败均须确定唯一回收责任，已有 lease/cgroup 启动对账覆盖全部池实例。

Linux 预启动 VM 须在独立准备阶段接收并冻结本次只读 input、重置空 workspace，并保留现有 uid/seccomp/限额/无 NIC 语义。不能向已挂载 block image 无同步写入，也不能把已有 session 当作跨租户复用池。OSv 预启动状态必须等待新的有界签名任务请求，生产链路未通过前不开放该后端池。

pristine 内存快照作为独立后续加速路径，必须绑定签名池键、只读制品和兼容 CPU/VMM，恢复后重新注入熵、身份、时钟与 vsock 状态；任何租户执行后的快照不得进入共享基础缓存。它与 LIFE-03 的用户 pause/resume 分别声明能力，但共用恢复安全检查。

## 测量与门禁

管理细节见[本项目 VM pool 设计](../design/WARM-POOL.zh-CN.md)，机器可读契约为 [`warm-start-gates.json`](../contracts/warm-start-gates.json)。性能目标只在真实 KVM、固定 CPU/NUMA/限额/镜像/解释器版本、无排队条件下判定；ARM64 本轮依用户范围先做 QEMU 功能，不把其结果计作 KVM 性能。

- `warm_start_ms`：launcher 接受已鉴权请求，到 pristine VM 完成本次身份/输入绑定并确认可开始执行；包含持久准入、健康检查和领取准备，不能只计 queue.pop。无输入最小任务目标 p50 ≤2 ms、p95 ≤5 ms、p99 ≤10 ms，输入尺寸与解释器 profile 分别列报。
- `snapshot_start_ms`：同一入口经 pristine 内存快照恢复至可执行；目标 p50 ≤100 ms、p95 ≤150 ms、p99 ≤250 ms。
- `cold_boot_ms`：VMM 启动至 guest agent 可用；目标 p50 ≤400 ms、p95 ≤600 ms、p99 ≤1000 ms。解释器初始化、排队、API/mTLS 传输和完整首次执行耗时另列，不能并入或省略后声称达到 400 ms。
- 性能批次每路径至少 1000 个成功样本，另记全部失败/超时/拒绝；发布仍需 PERF-02 的 10k+ 与长稳。报告必须带候选、制品、测试、配置、宿主基线摘要，原始样本和 p50/p95/p99，池命中率、补池耗时、RSS、预留容量、吞吐与失败率。不同路径不混算分位数。
- 安全/功能门禁包括跨租户内存/文件/环境残留、唯一身份、TTL、超额拒绝、池耗尽/不匹配/死亡领取、补池失败、模板过期/切换、取消/崩溃恢复、停机零残留和审计归属；任何一项失败不得开放生产 warm pool。

当前实现及证据为空，门禁 `--require-target` 必须失败。配置和能力声明只在实现、L2 安全功能及性能证据全部通过后开放；不得以文档或 mock 状态机测试标为完成。新增需求是生产交付必须项，默认关闭仅是未完成期间的保护措施。

2026-11-11 用户调整：当前 warm 分位数门槛由[ADR-0092](0092-warm-start-five-eight-ten.md)改为5/8/10ms；本文原数值保留为历史决策，其他计时、样本与隔离/恢复要求保持。
