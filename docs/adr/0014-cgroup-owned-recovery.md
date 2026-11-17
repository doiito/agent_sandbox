# ADR-0014：以专用 cgroup 为权威的 VM 恢复与清理

状态：Accepted；日期：2026-10-29；需求 LIFE-02、SEC-01、SEC-03、QA-02。继承 [ADR-0002](0002-host-enforced-isolation.md) 和 [ADR-0005](0005-durable-admission-and-supervision.md)。

## 背景

生产 launcher 为每个 job 先建专用 cgroup，再启动 jailer。现有重启对账只扫描 `run_root/job-*`，根据持久 lease 的 PID/进程启动 tick 发 `kill(-pid)`。即使 lease 校验成功，检查和发信号之间仍存在 PID 复用竞态；若目录已删但 cgroup 留下，对账也不会发现。正常收尾忽略 cgroup 删除错误，可能在 API 已确认成功后遗留资源。

## 决策

生产 Linux 路径保持“一任务一专用 cgroup”。启动对账在持有全局 `.launcher.lock` 时扫描合法 job 目录和专用 cgroup 父目录的合法 `job-*` 叶子；以叶子的 `cgroup.kill` 终止其成员，等待叶子可删除。缺失或损坏 lease 也可按专用 cgroup 清理；不再把历史 PID 或进程组 ID 用作恢复期的击杀目标。若目录有有效且仍存活的 lease，但叶子缺失，拒绝对账并保留现场，不能猜测性按 PID 发信号。无合法目录的 cgroup 叶子也必须处理；非 job 名称及非目录对象不触碰。

任务正常结束后同样有界清理 cgroup，再清理工作目录。任一清理失败将当前请求作为不确定结果返回错误，锁存 manager 的清理故障并阻止后续准入；doctor 报告不就绪，要求运维对账/重启。lease 写入采用临时文件、文件 fsync、rename、目录 fsync，缩小断电窗口。正式生产始终要求 jailer/cgroup v2；无 cgroup 的诊断路径只在确认没有存活 lease 时删除目录。

launcher 在任务执行中崩溃时，API 与 launcher 之间的 Unix RPC 断开属于服务不可用，调用方收到 HTTP 503；该故障不得伪装成请求参数错误 400。原始取消/超时原因保留在错误链中。

## 自评审

| 风险 | 处理 |
|---|---|
| PID 在核对 lease 后重用，旧进程组 ID 击杀无关任务。 | 恢复期不发送 PID/PGID 信号；仅操作本服务父 cgroup 下经严格 job ID 校验的叶子。 |
| launcher 在 lease 落盘前崩溃。 | cgroup 在进程启动前创建；对账不依赖 lease 存在即可终止叶子成员。 |
| 工作目录先被删，叶子遗漏。 | 独立扫描 cgroup 父目录；按叶子清理并计数。 |
| cgroup 或工作目录清理失败却向客户端确认成功。 | 清理错误改变任务结果并锁存准入/doctor 故障；保留现场供运维处理。 |
| cgroup 叶子名称被伪造导致误清理。 | 只在专用、配置固定的父目录内处理合法 `job-*` ID；非匹配对象保留；真机故障测试必须检查无关进程存活。 |
