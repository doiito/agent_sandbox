# ADR-0124：验证专用 Go 协程调度观察

状态：Accepted（观察器资格验证、预定两组业务、独立清理及 133 项完整内核/Go 回复关联通过；统一根因未证明）；日期：2026-11-16；需求 PERF-03、QA-01、REL-02。

## 缺失的证据

rc92 正式 Linux warm p99=14.245ms，仍超过 13ms。原内核跟踪完整识别 VM、Unix 回复与宿主线程，却不能把线程等待等同于处理 prepare 的 Go 协程等待。三个慢例分别出现同线程 R 等待、协程可能迁移、读线程已占用 CPU 的情况，不能据此统一归因为 GC 或 Linux 调度，也不能选择增加资源或重复已否决的 max_booting/短周期干预。

## 决定

先资格验证一个**验证专用**静态 amd64 launcher。使用 Go overlay 编译，保持工作区产品源文件和原 rc92 stage 不变；overlay 只添加有界 `runtime/trace` 捕获，以及 Linux pristine prepare/ping 的常量 region。不记录请求体、job ID、nonce、token、路径参数或用户缓冲。诊断程序和 overlay 来源留在项目 build/validation；它不是发布程序，不能把其测量登记为 rc92 或新候选正式性能。

捕获显式启用才启动，默认关闭。输出使用私有新建 0600 文件，最大 128MiB、180秒，超限、写入失败、定时停止或 trace 解析错误均不得声称完整观察。正常服务退出前停止和刷新；当前 Go trace 实现不传播 writer 错误，因此 writer 自行保留失败状态，独立 JSON 回执必须核对。记录实际 runtime.Version、NumCPU、GOMAXPROCS 及 GC 指标；用常量 trace.Log 事件和两侧 CLOCK_MONOTONIC 读取建立时间对齐区间。

先做真实 Go trace 的小型控制：常量 region、已知协程阻塞/恢复、实际 Linux TID、关闭行为、输出权限、边界与失败传播。必须用本地实际 Go trace 解析器解析，不能只测试正则或伪造事件。overlay 去除插入片段后必须恢复产品原字节，编译前后记录其源摘要。只对观察工具做定向普通/race 检查，不因验证工具添加而重复产品全套 CI。

资格通过后最多执行一次预定未跟踪/跟踪观察，每组 128+5，共 266 个独立任务/VM。两组使用同一验证程序及原 rc92 API、镜像、签名、四物理槽、CPU2–5/NUMA0、100000/100000 配额和正常 doctor。只有 trace 开关不同；新增线程亲和性及祖先 CPU 配额快照两组都采集。测量核心及七阶段计时不改。生产 stage 的 91 项原载荷逐项核对；fixture 明确将 ExecStart 指向验证程序，不能覆盖原签名载荷冒充一致。

跟踪组复用已资格验证的内核/同步观察器和 PID/start ticks/cgroup inode 关联，禁止修改主 trace buffer 或全局 tracing 选项。Go trace 关联具体 G、P、M、Runnable/Waiting/Running 转换和 GC 区间，再与 prepare region、原始响应时间和内核事件对齐；时钟误差、丢失、超限或线程代次不明的窗口均标不确定。若没有捕获可解释慢例，不追加样本追求结果。保留正式失败，先据证据评审单一干预，再做受影响回归和必要正式验收。

指定机执行前必须绑定原包、观察程序、冻结源码和既有合格控制；使用持久任务 ID，断线先观察同一任务。业务完成后独立确认服务、VM、cgroup、追踪实例和测试凭据清理，保留压缩原始数据再回收大副本。原 40 项要求、用户 5/9/13ms、ARM KVM/K8s/域名 TLS 的既有决定保持。

## 自评审与依据

见[实施前自评审](../../PUBLIC-QUALIFICATION.md#private-evidence)。设计依据为项目实际 Go 1.24.2 的 `runtime/trace/trace.go`、`runtime/extern.go` 和 `runtime/os_linux.go`：Start 的后台 reader 忽略 writer 返回值，Stop 等待写完，NumCPU 来自 Linux affinity。代码只据这些本地实现做工具设计，不推断目前实际服务的 GOMAXPROCS 或 GC 暂停；后者须由本批实际数据确认。

实施结果见[Go 运行时观察](../../PUBLIC-QUALIFICATION.md#private-evidence)。两个设置阶段失败均保留；未跟踪 A 成功后只补尚未执行的 B，总计 266 个不同任务/VM，不重放 A。程序放入夹具自有 `/var/lib`，trace 写入既有可写审计目录，停止后移入 results；生产保护保持。B 的真实 Go trace 完整解析，133 个 prepare G 均与原始 live 窗口、Unix 收发线程及 VM/cgroup 代次完整关联；实际 NumCPU/GOMAXPROCS 均为 4。四个 >9ms 慢例的主要等待均在 VM 正文发布前；两例与同 vCPU 节流/R 等待重叠，另两例为 vCPU 调度上下文内耗时。GC 与 Go 队列没有覆盖主要等待，但仍不是统一根因或正式性能通过。后续先评审具体 CPU 放置方案，不追加观察批次或重复已否决控制。
