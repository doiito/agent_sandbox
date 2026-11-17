# ADR-0036：以原子准备确认 warm 领取就绪

状态：Accepted（[rc40 双架构/QEMU/KVM 功能及一次往返验证通过](../../PUBLIC-QUALIFICATION.md#private-evidence)，完整性能门禁未通过；rc39 真机失败保留）；日期：2026-10-31；需求 LIFE-04、PERF-03、SEC-01、LIFE-01/02。继承 ADR-0029、0032、0033、0034、0035。

## 问题与已检查的依据

现有 ready VM 已经通过启动及周期性的 pristine 验证，领取时又发送 ping，再发送 prepare。两个控制请求各新建一条 vsock 连接。CPU 周期对照没有消除长尾，连续 ping 也未复现正常领取的长尾；因此不把以下改动称为已证实的长尾根因修复。它针对两次往返及分离状态检查的明确成本，仍须独立测量。

Linux `pristine::Runtime::dispatch` 仅在 Pristine 状态接受 prepare，在任何输入变更前转入 Poisoned，验证 TTL 与 boot deadline，再冻结输入并绑定新 ID/nonce。已绑定、重复准备、无效输入或不足寿命不能成功返回 pristine-revision-2 的 prepared ACK；宿主 validatePreparedResult 检查精确绑定、修订、状态及剩余租期。OSv osp_control 同样只允许未准备状态，检查 remaining>TTL+5s，再一次绑定；宿主校验 OSP1 精确 ID/nonce、状态、修订、租期以及 ACK/EOF。两份已签名 guest 协议均已有原子“确认未用并绑定”能力，不需要改变 guest 字节或 wire。

## 决策与顺序

warm 领取仍独占实例 controlMu、从 ready 原子移出并持久提交 claiming。随后执行宿主即时检查：原 PID/start ticks、lease/VM ID/pool key、实际 cgroup 归属、签名窗口、规格/策略、实例 context、idle age 和寿命。寿命使用最近一次已验证 pristine 握手的保守 guestDeadline 与 owner 原始 deadline 的较早者；两者都是宿主单调时钟值。启动和后台 health 在发探测前记录 sent，再加 guest 返回 remaining，得到不会晚于 guest 的保守边界。禁止从墙钟、ready 年龄或请求输入重建该边界；缺失/不足即不能领取。

通过宿主检查后，生成新的私有绑定，发送一次原子 prepare。成功的精确 prepared ACK 同时证明该 guest 在准备时未被使用、TTL 合法并已唯一归属本请求，作为前台 guest 就绪确认。它不是用后台健康缓存代替前台确认。prepare 的未知结果、超时、错误绑定/状态、ACK/EOF 失败均只销毁，不重试该 prepare，不将该 VM 放回池，也不在未知提交后静默执行另一台 VM。

rc39 真机的已杀 VM 领取场景返回 503，未通过并保留；单凭该返回不能确定具体死亡时刻。补充边界：即时代次检查还必须拒绝 zombie/dead 状态及已关闭的 owner exited 通道。若 VM 在检查之后退出，只能由 backend 在任何 prepare payload 写入尝试之前，将路径/连接失败标记为“确定未发送准备”；VMM CONNECT 协商不算 prepare。宿主在请求仍有效、原 VM 已确认销毁且实际路径为 warm 时，才可按原 miss 策略重新选择，并生成新 nonce。开始 payload 写入之后的错误一律没有该标记，即使返回写入 0 字节也保守视为未知；cold 准备失败不重复创建。这一区分不允许重试未知 ACK 或已开始的用户执行。

prepare 前记录 leaseStart，宿主租期不能晚于 guest；成功后再次检查原进程/归属、context 与签名窗口，然后按现有顺序持久提交 active lease 和 pool.claimed，最终检查取消/死亡才交付。claiming、active、准入/完成审计及目录 fsync 保持原有持久化语义。任何失败由同一 VM owner 销毁，确认退出/清理后才释放物理和 active 预算；清理失败继续 fail closed。

cold miss 仍需首次 guest readiness，建立有效 guestDeadline 并记录 VMM boot，然后 prepare；启动/background health 的完整 ping 不变。共享池对 Linux job/session 与 OSv 单次模块 job 采取同一事务顺序，后端仅承担既有原子 prepare/ACK 验证。OSv 产品生产准入继续保持原门禁。

## 计时与验收

新候选使用 startup_timing/v2 区分语义：warm readiness 为宿主即时确认，前台 guest 状态/寿命确认随原子 preparation 计入；cold readiness 仍含首次完整探测。七阶段与总耗时继续严格相等，完整 startup_duration_us 起止不变，不将预启动成本算成本次 warm。测量工具同时识别已存档 v1 与新 v2，候选绑定不能混用；不能把 readiness 阶段的重新划分单独称为性能提升。

先完成自评审与单元/race 故障测试：保守 deadline、缺失/过期租期、host lease/PID/cgroup 失配、成功 warm 不额外 ping、prepare 一次且唯一绑定、未知 ACK 不重试、准备后死亡/取消/签名失效、重复领取/清理失败。然后一次新候选完整 L1，以及双架构离线包、ARM64 无网卡 QEMU、同包 Linux job/session 与 OSv 共用池 KVM、取消/崩溃/独占 owner 回归。真实领取窗口应观察仅一次 prepare 控制往返，启动/background ping 仍存在。

最后重新采集同候选无跟踪的启动批次，原 rc38 与失败诊断证据保留。优化量和长尾是否改变由数据决定；完整 2/5/10ms、每路径≥1000 样本、生产宿主基线、安全与长稳门禁不放宽。本 ADR 不宣称目标已达到，也不以默认关闭视作需求完成。
