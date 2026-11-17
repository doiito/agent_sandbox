# ADR-0037：以专用 domain 叶的实时成员验证 VM 归属

状态：Accepted（[rc42完整CI/双架构/QEMU/KVM功能通过](../../PUBLIC-QUALIFICATION.md#private-evidence)，完整性能门禁未通过；rc41失败保留）；日期2026-10-31；需求 LIFE-04、PERF-03、SEC-01。继承ADR-0031/0034/0036。

## 依据与边界

rc40 已将 warm guest 确认合入原子 prepare，宿主 readiness 仍出现约31ms长尾。现有 trace 中一次 `/proc/PID/cgroup` read 为13.723ms。指定服务器[完整接口对照](../../PUBLIC-QUALIFICATION.md#private-evidence)4096对读取表明：两次压力阶段原接口p99为36.614/38.099ms，domain类型+成员接口p99为0.220/0.221ms。原接口76次>10ms，成员接口0次、最大0.628ms；新接口中位数约0.16ms，比原接口约0.09ms更高。该结果定位到可复现的接口长尾，不证明完整API启动已经改善，也没有直接观测内核锁的所有持有者。

Linux stable [v6.1.159 proc_cgroup_show](https://github.com/gregkh/linux/blob/v6.1.159/kernel/cgroup/cgroup.c#L5902)获取cgroup_lock；成员迭代器从专用cgroup列举进程。[内核文档](https://docs.kernel.org/admin-guide/cgroup-v2.html)规定cgroup.procs可能重复PID，且threaded domain根会聚合子树进程，不能只看列表包含PID就认定直接归属。诊断脚本的Python文件读取也不是Go生产实现的时延证明。

## 决策

仅替换 pristine VM 的即时cgroup归属验证方式；boot/cold/background/warm前后均调用同一验证器。预期目录固定为 `/sys/fs/cgroup/<管理员 parent_cgroup>/<合法 VM instance>`。打开目录时拒绝末级符号链接，检查真实文件系统为cgroup v2；后续所有读取通过该目录FD的openat进行，拒绝符号链接、限制读取长度，防止目录切换或普通文件伪装成cgroup。

先读cgroup.type，要求精确domain；再完整读取最多16KiB的cgroup.procs，要求非空、逐行规范正整数，且必须包含原VMM PID。同一PID重复可接受。其他PID须逐个从内核stat证明PF_KTHREAD，普通用户进程、读取未知/格式错误、缺少VMM、截断或非法成员均拒绝；重复worker只验证一次。不能凭comm名称或root UID信任额外进程。最后再次读type仍须domain，避免threaded根的聚合语义冒充直接叶成员。拒绝threaded/domain threaded/domain invalid，不回退旧接口。所有worker继续位于专用cgroup内，计入原CPU/内存/pids预算与退出确认，不能从清理/计费中排除。

PID/start ticks、非zombie状态、owner exited、lease/claim/tenant/profile、签名、保守寿命与prepare精确ACK全部保留，准备后复核与所有持久化保持原顺序。cgroup读取不能单独证明进程代次；原代次检查和唯一准备不可省略。目录/controller由受信任root launcher管理，未向VMM UID委托写权限；该修改不防御任意宿主root破坏，旧路径检查也没有这种承诺。root可变更cgroup类型的TOCTOU仍按同一信任边界处理，普通租户不能制造此变更。

rc41暴露了初版“只有一个宿主进程”的错误假设，真实VM初池成员失配并清理，不能计为KVM通过。已用原已通过rc40包在新隔离夹具实测两个ready VM：各自包含Firecracker及一个kvm-nx-lpage-recovery内核worker，后者stat flags=2129984（含PF_KTHREAD），没有用户可执行文件；两组代次和实际路径均核对。Linux [KVM worker实现](https://github.com/torvalds/linux/blob/v6.1/virt/kvm/kvm_main.c#L5655)会把worker加入创建者cgroup，[PF_KTHREAD定义](https://github.com/torvalds/linux/blob/v6.1/include/linux/sched.h#L1640)是内核标志。原项目moveKVMPITThread也会将PIT内核线程纳入VM预算。修订保留原VM必须直接归属的目标，允许真实内核worker且继续拒绝额外用户进程；不是用名称白名单忽略未知PID。

## 验证顺序

设计→[实施前自评审](../../PUBLIC-QUALIFICATION.md#private-evidence)→实现→定向测试→一次完整候选CI→新签名双架构离线包/ARM64 QEMU→指定x64 Linux/OSv池、SDK/API/取消/崩溃/回收回归。ARM64 KVM按用户范围免验。

定向覆盖domain/重复PID正例，空/额外用户进程/非法/超界/截断PID、threaded/类型切换、符号链接、普通文件系统伪装与FD清理负例；根权限内核测试验证真实迁移、后代归属、threaded domain根的聚合误报与已退出进程拒绝；另用真实预启动VM证明内核worker正例，sleep夹具不能替代。原死亡VM及未知ACK测试不改成较容易的场景。测试中可用临时普通文件验证读界限/解析，但真实cgroup证明须来自服务器内核测试。

候选功能通过后再测同候选无跟踪启动。保留rc40及首轮失败诊断，不用内核接口微基准替代每路径≥1000合格样本、完整2/5/10ms、cold/snapshot/安全/长稳及生产宿主门禁。无新第三方运行依赖，实际资产继续在项目目录。
