# ADR-0034：Linux 与 OSv 共用 pristine pool 生命周期

状态：Accepted；日期：2026-10-30；需求 LIFE-04、PERF-03、SEC-01、SEC-06、REL-04。继承 ADR-0029～0033。

## 决策

保留唯一 warmPool 调度器、resourceLedger、vmInstance、lease 和 Shutdown 实现，将 guest 差异收敛为内部 pristine 后端接口：固定启动、协议/修订标识、probe、一次 prepare、绑定 job 执行及结果协议。Linux adapter 使用 fc-agent/v3 revision=2，支持 job/session 和只读输入；OSv adapter 使用 OSP1 revision=1 + OSJ1，仅支持一次签名模块 job。OSv session、输入文件和可写 workspace 仍不支持，不因复用调度器而扩大能力声明。

共同领取事务持有请求 ID 和私有随机 32 字节 nonce。Linux 编码全部 32 字节，OSv 按现有 OSJ1 契约编码前 16 字节，保留 128 位随机强度；各次领取重新生成，不在 lease、日志、指标或审计中保存 nonce。后端 adapter 明确完成编码转换和校验，调度器不处理 JSON 或 OSP1 二进制。pool key 显式加入 backend 与 pristine 协议修订，继续绑定签名 manifest、架构、规格与不可变安全策略，不允许跨后端或旧代队列领取。

OSv pool 仅允许已签名 v2 模板且 `agent_features` 包含 `pristine-v1`；创建 Manager 时拒绝旧模板，初始/后台/领取 probe 再验证 wire revision 和 pristine 状态。配置允许显式选择 OSv 的诊断池，但原有 OSv 产品生产准入门禁保持关闭。普通未启池的 OSJ1 路径继续可用；启池后的 cold miss 也使用 pristine 准备，不静默回退旧执行模式。

进程/lease/PID start ticks/cgroup、签名窗口、剩余寿命、前台 demand、健康互斥、原子领取、一次 prepare、审计、失败保留、取消和 crash 对账均走共用实现。OSv prepare 不运行模块，prepare/归属/audit 提交后才发 OSJ1；结果使用 OSv 的绑定解码，公开协议保持 osv-agent/v1，不能误报 fc-agent/v3。

实机自评审补充：run_root 独占锁与启动对账不能以 `Production` 作为唯一开关。任何启用的 warm pool，以及已签名、jailed 的 OSv 诊断运行时，都必须先独占并对账，再分配新身份；诊断 owner 同样要求 root 和规范、root 所有且不可被 group/other 写入的 run_root 路径。Linux scratch 模板仍只按原生产 Linux 配置构建。此生命周期保护不解除 OSv 的产品生产准入限制。

job 的控制交换使用请求 deadline，VM 退出后只允许有界结果 drain，避免正常结果与 poweroff 竞争，也避免死亡实例等满任务 TTL。guest 返回的成功/失败及退出码为权威，串口和 VMM poweroff 码仅作诊断；warm/cold 的公开顶层退出码应一致。无任务退出码的加载/协议错误保留合成失败码，不能把 runner 失败当作 exit 0。

## 验收

先自评审，新增 adapter/签名拒绝/池键隔离/结果与取消定向测试，再完整 CI。共用状态机变更需同候选 Linux 公开 warm pool、双语言 API/文件和停止/恢复回归，双架构离线构建与 ARM64 QEMU；OSv 用同一签名 pristine 模板验证 API→launcher→预启动 VM 的 ID 领取、双租户状态隔离、唯一身份、冷 miss、健康死亡、并发/限额、取消、TTL、API/launcher crash 和零残留。OSv 生产前 harness 的就绪记录必须在初始最小池 ready 后写入。

功能通过不替代两后端每路径至少 1000 个真实 KVM 样本、性能、安全和长稳门禁；快照单独跟踪。保持既有按变更影响运行回归的策略，不对每次 adapter 局部修改运行完整真机批次。
