# ADR-0032：Linux pristine pool 调度与一次领取

状态：Accepted；日期：2026-10-30；需求 LIFE-04、PERF-03、SEC-01、SEC-03、REL-04。继承 ADR-0029～0031。

## 决策

root launcher 增加显式启用的 `warm_pool` 管理员配置，仅支持已签名的 firecracker-linux。profile 固定内存/vCPU 与最小/最大 ready 数，池键绑定当前 manifest、架构、VMM、kernel/rootfs、guest 协议及安全/资源策略；请求只能精确匹配，不创建任意后台池。配置在 Manager 构造时冻结。OSv 仍须单独实现与验收，不能据 Linux 命中证明其已支持。

后台仅预留物理容量，前台先取得 active 预留并登记 demand。一个调度器公平轮转 profile，有界 boot 并发、令牌桶、每 profile 指数退避；初始目标为 min_ready，命中或对应 cold miss 后可增长至 max_ready，idle 淘汰后收缩。各 profile 最小资源合计须可容纳，所有状态占物理预算直到 owner 清理成功。存在前台 demand 时不启动补池，避免回收出的容量被 refill 抢占。

ready VM 必须通过 v3 pristine ping。领取原子移出队列并进入 claiming，随后在锁外持久化归属、核对进程/lease/cgroup、签名窗口及剩余寿命，以新 ID/nonce/input/TTL 执行唯一 prepare；ACK 与 active 归属提交成功且请求仍有效才交出句柄。任何失败由领取方销毁，不回 ready，不自动重试 prepare。健康检查和领取共用实例控制互斥，禁止并发 ping/prepare；请求等待正在进行的检查受 checkout deadline 限制。

池空、不匹配或安全检查淘汰时按显式 `on_miss=cold|reject` 处理。cold fallback 仍使用 pristine v3，记录实际路径。取得物理容量失败时，前台可淘汰最老 idle 或取消未领取的 boot，确认释放后再预留；只有 active VM 占满时及时拒绝。签名失效、模板代际不符、宿主可用内存低于阈值时停止补池并淘汰 idle，已领取任务依原租期收尾；首版模板切换通过停止/重启 Manager 完成。

实例 context 从预启动起固定；session 的宿主租期在发送 prepare 前开始，guest 在接受 prepare 后开始自己的租期，宿主边界更保守。领取同时检查 guest 剩余寿命与 owner 的原始 deadline，job 使用原请求 deadline，二者通过 owner 取消收尾。session 的 run/file/shutdown 均带相同绑定。job 只执行一次，结果后销毁。池停止先关闭调度和领取、取消补池，再由共用 Shutdown 等待所有预留和 owner 归零；lease 记录 VM ID、profile、阶段及领取后的请求/租户归属，不写 input 或 nonce。

pool created/ready/claimed/discarded/refill_failed 事件持久化，失败锁存并拒绝新领取。doctor/指标报告 ready/booting/目标、命中/未命中原因、预留、退避和错误。启动在 min_ready 满足后报告就绪；后台临时缺池作为可观察降级。启动路径和时延单独记录，测量起点在 launcher 持久准入前，包含准备与归属提交，不将纯队列 pop 冒充可执行启动。

## 验收与边界

按设计→自评审→实现→定向/race→CI→签名离线候选→真实 KVM 顺序推进。验证一次领取、双租户隔离、输入只读、物理/active 分离、规格不符、池空、死亡、签名过期、补池失败、前台优先、取消、crash/停止回收。ARM64 使用 QEMU 编译/功能验收。机器性能门禁仍按 ADR-0029 每路径至少 1000 个真实 KVM 样本执行；功能通过和配置启用均不能替代性能通过。
