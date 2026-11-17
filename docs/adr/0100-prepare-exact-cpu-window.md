# ADR-0100：prepare RPC 的 CPU 配额与调度精确窗口

状态：Accepted（有界诊断，产品优化待实际结果）；日期：2026-11-12；需求 PERF-03、LIFE-04、QA-03。

## 问题与决策

正式千次 Linux warm 的 preparation 尾延迟未达标。挂载微测量未复现毫秒级等待；launcher strace 区分了握手与响应，但对调度影响明显。原 benchmark 的 CPU 前后窗口包含业务执行，不能判定准备期是否发生限流。

在新夹具中使用同一 rc85 原签名 guest/kernel/VMM，使用产品 `newManagerRuntime` 与 `newPristineVMBackend` 取得真实签名功能开关及 scratch 模板，不手写简化后端、不改 guest 或配额。停下本夹具 API/launcher后持有 run_root owner，串行启动 48 个不同无网卡 VM，沿产品驱动执行 pristine ping、一次 prepare、绑定命令和销毁。

按轮换顺序给三组各 16 个 VM，在 ping 后分别等待 0、25、100 ms，再进行 prepare。只将 prepare RPC 放入主计时；其前后同步读取 VM 专属 cgroup 的 cpu.max/cpu.stat 和 VMM 线程 schedstat，不包含随后绑定命令执行。记录实际 ready 后时间、读取窗口、PID/线程身份、样本、CPU/NUMA/权限与 guest 成功结果。保留 100000/100000 的 1 vCPU 配额、128 MiB 和原固定放置，不改宿主全局调度选项。

若宿主未启用详细 schedstats，明确记录限制，不能把零等待计数解释为没有调度等待。CPU 窗口计数也只支持窗口内现象与请求的关联；三组差异不自动等于 warm pool 产品改动的完整收益。诊断绕过公开 API，不登记 SLO；不能在生产中随意增加等待、突发额度或移除资源上限。

先完成[自评审](../../PUBLIC-QUALIFICATION.md#private-evidence)，再通过 Go overlay 编译静态测试，不写入产品文件。单次持久任务持全局验证锁，时间/日志有界；逐 VM 清理和独立宿主检查保留，失败不重放。只有结果指出具体方向后才设计产品修正并集中做同包验证。

## 实际结果

48 台 VM、全部 prepare 和绑定命令成功；三组 prepare 中位数为 0.788/0.810/0.834 ms，全部最大值为 1.895 ms，未复现正式长尾，也没有增加 100 ms 等待的稳定收益。详细 schedstats 未启用，等待数据明确不可用；两次累计限流计数增长不能直接等同于 RPC 停顿时长。不增加固定等待或放宽配额，转向真实 API/完整池的后台供给竞争对照。原任务与清理均独立核对，见[验证记录](../../PUBLIC-QUALIFICATION.md#private-evidence)。
