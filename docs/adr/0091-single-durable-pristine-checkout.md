# ADR-0091：pristine 领取只提交一次持久归属

状态：Accepted（实现及完整功能验收，正式性能仍开放）；日期：2026-11-11；需求 LIFE-04、PERF-03、SEC-01、LIFE-01/02、QA-01/02。

## 依据

[rc82 无跟踪千次采样](../../PUBLIC-QUALIFICATION.md#private-evidence)中，Linux warm 的 selection / ownership 中位数为 0.955 / 1.126 ms，OSv 为 0.895 / 1.089 ms。两阶段分别原子替换 claiming / active lease。独立有界跟踪确认每次领取有两次替换、四次文件/目录 fsync；跟踪耗时仅用于归因。rc83 已完成[完整功能验收](../../PUBLIC-QUALIFICATION.md#private-evidence)，未改变这条宿主链路。

当前 `reconcileRunRootAt` 在独占 run_root 锁后先清除每个实例的专用 cgroup，再移除目录；还清除只有 cgroup、没有目录的实例。恢复从不重新使用任何 ready、claiming 或 active VM，也不根据 lease 中的 PID 直接发信号。缺失 cgroup 且原进程仍活跃时拒绝启动。由此，guest prepare 前的单独 claiming 落盘不是阻止崩溃后复用的必要条件。

## 决策与边界

只调整 ADR-0036 中 claiming 的持久化步骤。原始 booting / ready lease 已在 VM 启动/入池前完成文件与目录 fsync；领取时仍从 ready 队列原子移出并持有 controlMu，在内存记录 request、tenant 和该完整原始持久 lease。磁盘在交付前保持原始 booting / ready 身份，不改写文件格式，不增加恢复 VM 的路径。

prepare 前后均检查：claim 属于当前请求/租户、内存状态为 claiming，持久 lease 的全部字段与记录的原始值一致，PID/start ticks 仍为原进程，实际 cgroup、签名、寿命及取消状态有效。只有这些检查通过、guest 精确 prepared ACK 已确认且代理绑定完成后，才原子写入 active lease，并同步文件与目录、写入 pool.claimed 审计。最终检查取消/死亡和租期后才交付。持久准入、guest 准备和审计仍全部计入原 startup_duration_us 起止；不能提前报告成功。

进程中止于领取、prepare、ACK 或 active 提交附近时，恢复逻辑一律销毁原 VM；磁盘仍为 ready 不能被解释为可复用。在进程内，未知 ACK、提交失败、状态失配或取消均沿用同一 owner 的销毁流程，确认清理后才释放预算。只有明确未开始 prepare payload 写入的传输失败，才继续沿用原有销毁后重选策略。所有其他 warm pool 容量、公平性、补池/淘汰、模板隔离与控制协议不变。

本方案不删除最终持久归属或目录 fsync，也不并发执行 guest 准备与尚未确认的持久提交。claiming 是进程内的中间状态；重启后只有销毁与重新创建，不提供原地接管。这个区别必须在状态检查与故障验收中明确。

## 验证顺序

先完成[自评审](../../PUBLIC-QUALIFICATION.md#private-evidence)。新增检查在旧源码上验证：prepare 期间保留原持久身份，返回前 active 归属已提交；最后提交失败即使 guest ACK 成功也不能交付；恢复不得复用仍标记 ready 的已准备 VM。保留既有 PID/lease/cgroup 篡改、未知 ACK、超时、取消、签名过期、独占 owner、资源与清理失败用例。

实现后先执行受影响宿主包的定向普通/race/vet，以及真实固定进程故障检查。然后在指定机使用同一 rc83 guest 和候选宿主、相同限额与正常持久目录，比较原/新路径；Linux、OSv 分别测量完整领取、阶段、失败率与实际任务，不用微基准代替真实收益。优先诊断样本，收益成立后再做每路径至少 1000 次正式验收及一个冻结候选的完整 CI/离线/QEMU/KVM 回归。

原始 claiming/active 两次持久化版本及其失败/性能证据保留。若收益不足或恢复/一般安全约束不成立，不能以降低门槛接受。2/5/10 ms、cold/snapshot、同任务/资源/长稳和其余 40 项需求继续开放。

2026-11-11 用户后续明确当前 warm 门槛为5/8/10ms，见[ADR-0092](0092-warm-start-five-eight-ten.md)。上述原2/5/10ms保留为设计时历史目标，测量输入与其他验收条件保持。

实现后的普通/race/vet、双架构静态宿主编译和指定机 1024 次真实任务 ABBA 已完成，见[验证结果](../../PUBLIC-QUALIFICATION.md#private-evidence)。每组每路线 256 个正式样本，两后端领取启动延迟均下降；完整 HTTP 未普遍加速。其后[rc85 完整功能验收](../../PUBLIC-QUALIFICATION.md#private-evidence)通过同候选完整 CI、双架构离线/QEMU 与指定机 15 套/516+44 个用例，本实现决定接受。千次正式性能、资源/长稳及原总目标仍开放。
