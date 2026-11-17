# ADR-0035：公开 API 的启动测量与诊断证据

状态：Accepted；日期：2026-10-31；需求 PERF-01、PERF-02、PERF-03、LIFE-04、QA-03。继承 ADR-0029、0034。

## 决策

现有完整任务 HTTP 基准不能证明 pristine 启动延迟。新增标准库测量工具，经真实 mTLS API 发起显式后端/签名模板、固定 128 MiB/1 vCPU、无输入的最小任务。warm 指标只取 launcher 的 startup_duration_us，包含持久准入、领取、健康检查、一次准备与归属提交；另记完整 HTTP 耗时和补池等待，不能以客户端耗时或队列弹出时间替代。

每次请求前等待相同 profile ready、active/foreground 为零，保存可领取 VM 的 lease/PID start ticks/UID/GID/seccomp/cgroup；请求后必须以 pool.claimed 审计将 job ID 关联到该预启动 VM，验证 guest 结果与 job ID、退出码、预期输出及用后销毁。跨样本禁止 VM ID 复用。任何 cold miss、HTTP 拒绝、错误结果、超时或未准备好均保留为失败，不能重试未知结果或过滤后计算通过。预热样本与正式样本分开保存，warmup 失败也使批次失败。

原始 JSONL 每样本持久化；最终报告包含全部尝试、最近秩 p50/p95/p99、失败/超时/拒绝/未命中、补池等待、采样观察的 VMM RSS、预算、宿主/亲和性/配置/脚本/候选摘要及清理状态。采样 RSS 与节奏控制后的吞吐注明采样口径，不冒充精确峰值或饱和容量。固定模板内的原生 OSv probe 与 Linux shell 是不同工作负载，分别报告，不推导 Python/JS 解释器性能。

默认要求 production=true、非诊断能力和 doctor ready；仅显式 --diagnostic 可在不达标宿主或 OSv harness 中执行，报告保留失败检查且 release_eligible=false。工具不修改宿主 swap、CPU governor、服务或安全策略，不自动登记机器门禁证据。固定 CPU/NUMA、生产基线、安全用例与完整发布证据缺失时，不因有 1000 样本或某分位数较好而开放生产。

首批采集真实 warm 数据，定位优化方向。cold_boot 的 VMM 启动→guest ready 时间须另行可靠采集；现有 cold startup_duration_us 还包括 staging/准入/prepare，不得重命名为 cold_boot_ms。snapshot 同样独立，缺测量仍未通过。1000 样本不替代 PERF-02 长稳。

## 阶段计时扩展

rc37 千次诊断已证实完整目标未达到；单条 strace 也不足以定位长尾。公开 job/session 的 pristine 领取结果增加可选 startup_timing（osv-startup-timing/v1）：admission_us、selection_us、readiness_us、preparation_us、ownership_us、audit_us、finalize_us 和 total_us。全部使用同一宿主单调时钟，阶段累计而非互相重叠；重试选择、淘汰与等待计入 selection，检查失败的既有 readiness 成本保留。admission 从原 launcher 起点到 acquire 入口，包含原持久准入；prepare 后检查计入 ownership；最终 total 与原 startup_duration_us 相等。转换微秒的舍入余量归入 finalize，各段之和严格等于 total。计时异常时省略细分，不改变任务准入/执行结果。

cold miss 另报可选 vm_boot_duration_us：从既有 command.Start 前的实例启动时刻，到第一次成功验证 guest pristine readiness、PID/lease 和 cgroup 归属。它是宿主保守观察的 VMM 启动→就绪，排除 staging，包含启动后的 lease/检查开销；只记录一次，后台后续健康检查不能覆盖。该值与 selection/readiness 存在时间重叠，不加入七阶段之和；warm 不把原预启动成本报为本次 cold。未取得可靠测量的 legacy cold 或失败准备结果保持缺省。

计时仅增加定长数值，不包含 nonce、输入或时间戳，不改变原协议/RPC/持久化/取消/回收。session 查询返回计时的独立副本，避免新指针暴露内部状态。测量工具应保留完整预启动观察和细分数据，独立校验阶段之和；cold 指标只在对应独立测量字段存在时计算。

## CPU 周期诊断实验

rc38 将长尾定位到 readiness 包围的路径，尚未确定根因。使用同一 rc38 签名包，在新隔离夹具比较 100000/100000 与 10000/10000 微秒的 cpu.max；配额与周期同时变更，维持每 vCPU 一份 CPU，其他预算、协议、持久化和安全检查不变。按 A-B-B-A 顺序各跑 64 个正式样本、每次 5 个 warmup，每份配置独立启动并完全清理后再运行下一份。样本合计每策略 128，属于诊断而非正式性能通过。

准备工具只提供成对、等值的 CPU 周期/配额覆盖，验证后在创建 units/VM 前写入新配置；不热改存活池，既有 immutable pool key 已绑定完整 jailer 策略。观察工具保存实际 cpu.max、请求前 cpu.stat 与有限的 20 ms 存活采样历史，以 VM ID/PID start ticks 关联。节流增量窗口可能包括用户代码和收尾，也可能漏掉最后增量；缺少覆盖时保留未知，不能补零或声称精确归因为 readiness。采样缓存有固定上限。

Linux [CPU 接口文档](https://docs.kernel.org/admin-guide/cgroup-v2.html#cpu-interface-files)定义 cpu.max 的配额/周期及 cpu.stat 节流统计；本实验把周期作为独立干预变量，保持 CPU 份额，结果仍受未固定 CPU/NUMA 与共享宿主噪声影响。不修改发行默认值或宿主全局 swap/governor，不重新编译不变运行载荷，也不因工具修改重跑完整功能矩阵。

## 后续通信诊断计划

周期对照完成后再决定下一实验，先保留方案：在同版独立 Linux pristine 夹具，用有界的有效 ping 分别记录 UDS connect、Firecracker CONNECT 确认、请求写入与 guest 结果读取，保留 PID/start ticks、cgroup 和计数。每次仍验证协议、唯一 job ID、pristine revision、binding 为空及剩余寿命；任何未知结果立即结束，不重试。该直连工具只定位传输，不是公开 API 性能验收。

不得与 launcher 的后台健康检查并发访问同一 guest。若使用直连方案，必须在启动前以已支持的配置拉长诊断夹具健康间隔，并将整批硬截止限制在首次后台检查之前；无法证明没有重叠则批次不合格。该条件或时间窗口不现实则改用既有领取路径的跟踪，不暂停生产守护进程或降低正式健康检查。默认配置、安全检查、租户准入和发布门禁不随诊断改变。

## 正常领取路径的系统调用跟踪

CPU 周期对照未消除长尾，连续直连 ping 也未复现。下一步用同一 rc38 包、新隔离夹具和正常 health 配置，在真实 mTLS API 的 64 个正式任务及 5 个 warmup 期间附加 strace。仅跟踪 launcher 及其线程；跟随新线程但在子进程 exec 时脱离，逐任务保存 VMM TracerPid=0 观察，避免将 VMM 本身置于持续 ptrace 下。原始参数模式用于 read/write/readv/writev/recv/send/getrandom/exec 等涉及数据的系统调用，保留地址与长度，禁止输出缓冲区、nonce、认证或租户数据。

跟踪器使用独立进程会话，180s 看门狗、48 MiB 软停止和 64 MiB RLIMIT_FSIZE 后备上限；任何提前退出/超限、附加失败或不完整样本使诊断批次失败。正常结束只对跟踪器发 SIGINT 并确认脱离，不对服务发信号；最后照既有路径回收夹具。整批继续持全局 flock。将 trace 的 TID/时间/FD、实际 VM 目录及领取审计关联，区分目标 vsock 系统调用与其他 VM/后台线程；不把全进程 syscall 累计当成单请求耗时。

跟踪会改变时序，不得合并进无跟踪分位数或登记性能门禁。此前连续 ping 只证明所测稳态路径快，不能排除 fresh 领取、idle 模式、后台调度或宿主检查。先验证隐私输出、上限、线程/FD 解析与失败留存，再采集；不因诊断工具变化重新构建不变运行载荷。选项含义以 [strace 官方手册](https://github.com/strace/strace/blob/master/doc/strace.1.in)及服务器实际 --help 为准。

## cgroup 归属接口诊断

rc40 在仅含宿主检查的 readiness 中仍有31ms长尾，已采 trace 的一个17.031ms样本中，`/proc/<VM PID>/cgroup` read占13.723ms。Linux stable [v6.1.159 proc_cgroup_show](https://github.com/gregkh/linux/blob/v6.1.159/kernel/cgroup/cgroup.c#L5902)获取cgroup_lock；同文件 cgroup.procs 迭代器与类型读取有不同路径。这只形成竞争假设，尚未证明无跟踪领取的根因。

先做不改应用的内核接口对照：指定服务器全局flock，新建独占诊断cgroup父节点，仅把脚本自己创建的子进程放入专用叶节点。交错读取原 `/proc/PID/cgroup` 与预期叶节点 `cgroup.type`+`cgroup.procs`，每次核对PID代次/确切归属；按A1(静止)-B1(有界创建/销毁)-B2-A2顺序，各1024对、交替接口先后，每对间隔2ms。B只在本父节点下串行创建一个128MiB上限的临时叶，启动并触碰32MiB的自有子进程，退出确认后删除；每秒最多20次，不修改全局控制器、swap或CPU策略。整批45s截止、每个B最多64轮/10s，异常停止并保留失败与清理证据。若读阻塞超过截止，外层60s进程超时终止脚本，信号处理收尾。

原始JSONL保留所有尝试、接口顺序、单调与墙钟区间、PID代次、耗时/失败；未知不能补零。新接口诊断仅接受确切domain叶、完整数字成员且只有预期PID（重复PID可接受），不接受threaded/domain-threaded/空列表/额外PID；它还不是生产实现。清理只终止本脚本持有的进程组，未知PID不杀，无法清理即报告失败。实验没有VM、API、真实租户输入或运行库变更，不能替代KVM/功能/性能门禁；工具只跑针对解析/边界的测试。是否修改生产检查，另经ADR/自评审与完整候选回归决定。

## 验证

先完成本自评审和定向统计/失败留存/绑定拒绝测试，再执行指定服务器独立批次。工具修改只触发 Python 定向与文档/契约审计；运行代码未变时不重建离线包或重跑完整 KVM 功能套件。批次共用既有跨测试 flock，按后端串行，结束回收夹具并核对零残留。
