# ADR-0005：持久化准入、客体收尾与启动就绪

状态：Accepted；日期：2026-10-29；对应 RV-05/06/08、OBS-02、SEC-05、EXEC-01、OPS-01。

## 设计

审计采用显式 JSONL writer，序列化 append + fsync 并检查 write/short-write/sync 错误，不能通过 slog 的无返回值日志接口证明持久化。每个 launcher 请求生成 host request ID，run 在任何 VM 启动前写入并 fsync `run.admitted`，执行后持久化 `run.completed` 或 `run.rejected`；只记录 tenant、peer UID/PID、request/job ID、state/code、时长，不记录 bearer、argv、输入或输出。任何 I/O 失败将该 writer 标为失效，拒绝后续执行并使 launcher doctor 的 audit 检查失败，修复后须重启。先前已持久准入、尚未完成的任务按原 TTL 收尾，完成日志失败时不返回成功确认。前置事件与完成事件之间发生断电时，操作方据 request ID、lease 和启动对账识别结果未知，不承诺 exactly-once。

完整签名/hash/size/SBOM 在 launcher 启动时校验，保存已认证 manifest 的时间窗口；每次执行准入及 doctor 重新校验该窗口。避免每个任务重新 hash 全部镜像影响吞吐；根目录/制品的 root 只读不可变约束仍必须成立。过期后不接受新任务，已准入任务可按原 TTL 完成。要延长有效期或换制品，必须用新实例重新验证并灰度切换，不能热改存活 manager 的认证快照。

Linux agent 使用单线程、非阻塞 pipe 采集循环，公平处理 stdout/stderr、主进程状态和 deadline；消除阻塞 join。任务主进程结束或超时时终止整个单任务 guest 的用户进程并有界 drain/reap，包含另建 session 的后代。全 guest signal 只能在 agent 确认为 guest PID 1 时执行；host 单元测试只能清理自己创建的 process group。超时、采集/清理错误与正常退出明确区分；最终 VM 强杀仍由宿主硬 deadline 兜底。

launcher 采用 systemd Type=notify/NotifyAccess=main，仅在制品、scratch、socket 和初始审计全部就绪后从主进程发送 READY=1。API 的 Requires/After 因而等待真实就绪；启动失败不发送 ready，受 TimeoutStartSec 约束。独立 CLI 无 NOTIFY_SOCKET 时不发送通知；禁止把 notify 环境透传给 VMM。

启动时检查审计文件以换行结束；short-write 或断电留下不完整尾记录时拒绝启动并保留文件，不能自动截断证据。恢复空间后仍须归档、修复日志并重启才能恢复准入。

## 自评审与验收

- 前置审计失败的测试必须证明 backend.Command 没有被调用，不能只检查客户端报错；short-write、sync 和并发 append 分别注入。
- 完成审计失败允许已执行任务存在，但必须拒绝确认并阻止下一任务；ready 要显示 audit 失效。
- 时间窗口测试使用可控的已认证 manifest 时间值，证明过期/未来窗口在启动后也拒绝新任务，且未调用 backend；原始签名篡改测试继续保留。
- pipe 测试包含大量双流输出、main 提前退出而后台持有 pipe、超时；setsid 后代在真 KVM 验证，不能在 host 测试中调用全局 kill。
- notify 测试检查实际 Unix datagram，真机同时启动两个 unit，禁用自动重启，证明 API 不会因 socket 尚未创建而退出。
- 只跑受影响的定向测试，再对同一候选执行一批完整 CI/真机 E2E；未改 OSv 客体不重复 OSv 基准。

参考：[systemd sd_notify](https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html)。这是工程准入和收尾设计，审计远程不可变归档、OSv vsock、完整产品功能和生产 host 基线依然独立跟踪。
