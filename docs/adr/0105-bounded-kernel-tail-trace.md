# ADR-0105：用独立 tracefs 实例细分剩余启动尾延迟

状态：Accepted（控制、原包采集及请求关联已验证，正式性能未通过）；日期：2026-11-12；需求 PERF-03、QA-03、LIFE-04。

[rc86 千次](../../PUBLIC-QUALIFICATION.md#private-evidence)的 53 个 >8ms 请求中，35 个最大阶段是 preparation、12 个是 admission。前者已使用预连接，后者包括 `run.admitted` 的同步审计及 Manager 准入；仅凭阶段名不能定位等待。此前 ptrace 明显放大延迟、直接 RPC 的 48 次 CPU 窗口未复现尾部，因此下一步用原签名程序上的内核时间线，不修改产品或 guest。

## 诊断方案

指定机 6.1.0-42-amd64 已确认 tracefs 独立实例、mono 时钟、调度/syscall 事件、Unix stream/VFS write 与 CFS 探针符号可用。先用无 VM 的有界控制夹具验证事件字段、Unix send/return、文件 offset/fsync、128 字节 read 和线程归属；再创建独立任务运行原 rc86 同配置 A/B 两组，每组 128+5 次，A 不跟踪、B 跟踪。原准备器、测量器、4 核/NUMA0、配额、补池与正常 doctor 保持；A/B 用于观察跟踪开销，不是新候选性能门禁。

仅在本任务独立 tracefs 实例记录 CPU 2–5 的 sched_switch/wakeup/task_newtask、受长度过滤的 read/write、fsync/close，以及任务唯一命名空间的 Unix sendmsg/VFS write/CFS entry/return 元数据。不得读取用户缓冲区正文、nonce、token、密码或进程参数。记录 fd/count/offset/返回值、时间与 PID，结合原审计中的请求/VM ID、原测量器的 PID/start ticks 和线程 clone 标志关联；不依赖 comm 名称猜测归属。

原审计逐行 byte offset 对应 VFS write 的文件位置，明确定位 run.admitted 和 pool.claimed 的 write/fsync；prepare 以 admitted→claimed 窗口内唯一 launcher Unix 发送及对应 FD 的 128 字节读取关联，并匹配该 VM 进程的 Unix 回复。墙钟/mono 成对校准保留误差界。出现多义性或缺失就标记无法归属，不能编造首字节时间。若同一请求具备足够完整事件，再区分回复产生前等待、宿主读取前等待、调度 runnable/off-CPU 与审计持久等待。

## 边界与清理

只改本实例的时钟/CPU mask/事件与缓冲；四个目标 CPU 各最多 32MiB，其余 CPU 最小缓冲；导出文本硬限 384MiB，跟踪最长 180 秒（主 r1 原为每 CPU 16MiB / 文本 128MiB，按下述实测调整）。实际启停窗口、事件格式、overrun/drop、探针 miss 与全局控制快照入证据。溢出、探针 miss 或关键覆盖不足不记为完整诊断。CFS 只有 rq/生命周期和窗口能完整对应时才可解释，累计 cpu.stat 不能直接等同请求阻塞。

不关闭或清空已有全局跟踪（当前 tracing_on=1），不改 sysctl/配额/TTL/持久性。动态探针使用唯一名字，仅启用在独立实例；结束关闭并删除本实例和本组探针，确认原全局控制/其他探针保持。失败也执行清理，原数据、源码、候选保留。真机服务、VM、cgroup、测试凭据及可证明重复的安装副本继续独立核对。

依据：[Linux 6.1 kprobe 文档](https://www.kernel.org/doc/html/v6.1/trace/kprobetrace.html)、[Linux ftrace 文档](https://www.kernel.org/doc/html/latest/trace/ftrace.html)。接口以本机读取的事件格式和先行控制测试为准；实例共享的 trace_options 不修改。先完成[自评审](../../PUBLIC-QUALIFICATION.md#private-evidence)，再实现和测试工具。本批不运行完整 CI/功能回归、不登记性能通过，原四路线及 40 项范围保持。

## 控制夹具 r1 后的修正

原 `rc86-tail-trace-pilot-r1` 在 Python 文本 append 打开 `kprobe_events` 时以 EINVAL 失败，尚未注册任何探针、未启动 VM。原任务、源码、输入摘要及失败日志保持；事后只读检查确认专属实例/探针不存在，全局 tracing_on=1、nop、local 时钟保持。r1 未持久化完整前置快照，不能据此声称全部全局字段已精确核对。

新 r2 仅修正诊断工具：用 `os.open(O_WRONLY|O_APPEND)` 与单次 `os.write` 发送探针命令，避免 Python FileIO append 的 EOF seek，保留不截断语义；构造时立即持久化全局快照，setup 失败也输出清理后快照，业务归档不再被断言跳过。若全局字段比较仍有变化，保留差异并定位，不写回根实例或放宽检查。主 VM 夹具的服务清理必须在跟踪收尾失败时仍执行。

实现依据：[CPython 3.11 FileIO](https://github.com/python/cpython/blob/v3.11.2/Modules/_io/fileio.c)与 [Linux perf 探针文件操作](https://github.com/torvalds/linux/blob/v6.1/tools/perf/util/probe-file.c)。先编译检查新工具，再运行独立新 ID 的无 VM 控制夹具，成功后才推进原包 API 诊断。

r2 已完成采集和精确清理，81 条事件、零 overrun/drop/miss，完整全局快照一致；业务断言因本机 syscall 文本格式与预期不同而失败。实际格式为 `sys_fsync(fd: 6)` / `sys_fsync -> 0x0`，参数为无前缀十六进制，而不是 `sys_enter_fsync:`。r3 按原 r2 数据修正解析器，保留其失败状态，先离线重验两次文件 offset/fsync、三次 128 字节读取、Unix 384 字节发送和线程 clone，再以新 ID 完整验证控制夹具；不修改 trace_options 或原事件格式。

控制 r3 已完整通过。主诊断 r1 的两组 128+5 次实际 API 均成功，但跟踪窗口 47.709 秒产生约 175 万条事件，三个 CPU 覆盖了旧记录，文本也触达 128MiB 上限，因此原主任务失败，不能作完整归因。五个探针 miss 均为 0，全局快照完全一致，独立事后检查两夹具服务/VM/cgroup/凭据/重复安装副本及专属跟踪资源清理通过。原数据和失败状态保留。

主 r2 保持同候选、同事件/解析器/生命周期、两组各 128+5 次及四核/配额/正常 doctor，仅把实例每目标 CPU 缓冲增至 32MiB、文本上限增至 384MiB，总内核缓冲约 128MiB，占 32GiB 宿主约 0.4%；180 秒上限与零 overrun/drop/miss 要求保持。增量自评审确认不写全局控制、不改变产品内存配额或持久性；旧失败不能被替换。事件关联和清理已由控制 r3 与主 r1 验证，缓冲增量直接在新主任务中检查，不重复产品完整 CI/功能回归。

[实际结果](../../PUBLIC-QUALIFICATION.md#private-evidence)：主 r2 266 次请求全成功、完整采集零 overrun/drop/miss；133/133 跟踪请求关联通过。短前缀分开发送的一例只报告可证明的发布结束边界，原首次未关联结果保留。尾部同时出现回复产生前等待、审计 fsync 和写入前等待，尚未支持统一根因或产品默认值变更。下一步优先复用这些原始数据细分调度，不缩小原性能/功能范围。

## 原数据的跨边界调度与审计分析

先核对原 trace/请求关联/工具摘要，复用 133 个原 VM PID/start ticks 和 clone 归属，在完整 trace 上配对 switch-out/in 后再裁剪请求写入至首段发布结束窗口，覆盖开始于请求之前的未运行区间。comm 仅在进程归属已证明后标记 vCPU 角色；逐线程报告运行、R 状态未运行和其他状态未运行，不把多个线程的时间相加当作关键路径。R 状态仍可能受 CPU 带宽限制，不能直接称为已经可运行但被调度器饿死。

同一审计 inode/FD 的 write/fsync 按 byte offset 和串行窗口匹配，找出每个准入/claim 记录之前的实际记录及 fsync，区分前序持久写与自身 fsync、写入前调度间隔；At 时间校准保留误差界。不从 At→write 差直接推断锁持有者或磁盘耗时。CFS 只报告实际捕获的同 rq 配对与目标 VM 线程上下文，缺失或全局归属未知保持未知。

该步骤仅分析原始文件，不创建 VM，不修改产品/宿主，不重复 CI/KVM。先完成增量自评审，再实现分析器，并用完整分区不重叠/覆盖检查及原始尾部实例验证；证据支持干预时另写产品决策。
