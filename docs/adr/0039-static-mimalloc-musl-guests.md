# ADR-0039：musl guest 的静态 mimalloc 构建链

状态：Proposed；日期：2026-10-31；需求 BUILD-01、REL-04、PERF-01、PERF-03、QA-01/04。用户新增要求使用 mimalloc 优化 musl 路径，原双架构离线与 warm 池要求继续保留。

## 实际分配边界

`guest/` 和 `linux-guest/` 的发布目标是 x86_64/aarch64 Linux musl 静态程序，Rust 默认系统堆经过 musl。先为这两个程序设置编译时 Rust 全局 mimalloc 分配器。Go 服务使用 Go 堆；OSv 内核的 malloc 在 core/mempool.cc 中实现，不能把其 musl C ABI 支持误当作 musl malloc。它们的当前分配器在制品说明中分别记录。若后续要移植 OSv 内核 allocator，须验证内核页、TLS、启动和 C/C++ 配对所有权，另作设计和验收。

采用 [mimalloc Rust 绑定](https://github.com/purpleprotocol/mimalloc_rust) `=0.1.52`，底层 `libmimalloc-sys =0.1.49` 由 Cargo.lock 固定。实际下载包的 v3 头文件声明 `MI_MALLOC_VERSION=30302`，即 C 实现 3.3.2，不能按上游最新 release 或 Rust 包版本推断 C 版本。官方 Cargo index 摘要分别为 `2d4139bb28d14ad1facf21d5eb8825051b326e172d216b39f6d31df53cc97862` 和 `6a45a52f43e1c16f667ccfe4dd8c85b7f7c204fd5e3bf46c5b0db9a5c3c0b8e9`；下载已核对。上游构建代码的 secure 模式设置 MI_SECURE=4。

## 决策

1. 使用小型本地共享 allocator crate，由两个 guest 显式引用。musl 发布默认启用 mimalloc，保留显式关闭特性构建的同源码 System 对照，仅用于测量。对照与正式候选的分配器身份必须可辨，不可将 System 对照作为 mimalloc 候选发布。
2. 静态链接 Rust allocator 使用的 mi_*，启用 secure/no_thp，避免额外共享库和目标机安装；malloc/free、C++、Go 与 Rust 各自保留完整配对。上游区分 [静态与动态 override](https://microsoft.github.io/mimalloc/overrides.html)；本决策不使用 LD_PRELOAD 或启用全局 C malloc override。
3. allocator C 实现使用 -O3，保留现有 guest Rust release 参数作为对照控制变量；不同时把应用从 opt-level=z 改成 3 来混淆收益。x64 使用通用指令基线，aarch64 使用 armv8-a，检查 TLS 和 outline atomics，不能把构建机 native CPU 指令带进跨机器包。
4. 源码、锁文件、许可证和必要 C 头文件/sysroot 放项目 assets，Cargo vendor 完整闭包并锁校验值；实际发布二进制和库不依赖 /tmp。编译器/头文件身份与 C 版本单独记录，不把用于编译的 musl 头文件版本声明成 Rust 静态 libc 的版本。目标机安装和运行继续断网、无下载。
5. 构建入口统一为两个目标设置 C 编译器、AR、sysroot 和 Rust linker，verify/rootfs/QEMU/发布走同一配置。构建检查实际 C flags、静态 ELF、正确架构与 allocator 版本；SBOM 记录 Rust 包与 C 实现/源摘要，离线包携带相应许可证。

## 门禁与回归策略

先[自评审](../../PUBLIC-QUALIFICATION.md#private-evidence)，再实现和定向验证。必须证明 Rust 全局分配实际进入 mimalloc：版本与指针归属、不同大小/过对齐/零初始化/扩容/跨线程释放、线程退出回收、失败处理，以及实际 musl agent 的命令/文件/取消/进程退出。历史 [ARM64 musl 上游问题](https://github.com/microsoft/mimalloc/issues/556)要求本项目自己跑 aarch64 QEMU，不能用 x64 通过推断 ARM64 通过；用户免验 ARM64 KVM 的范围不变。

采用同源码、同编译器/优化/安全设置、交替顺序的 System/mimalloc 对照，分配密集基准与真实任务分别测耗时分位、吞吐、RSS/峰值和失败率。微基准收益不能替代完整 API warm SLO。性能目标为分配密集工作负载有可复现收益，真实任务 p99 与内存预算不发生实质回退；若结果不足或回退，门禁保持未通过并继续调优，不能只凭“使用 mimalloc”宣称加速。2/5/10ms、样本量、宿主达标与生产门禁均不放宽。

定向验证与对照先行；构建链和运行修改冻结为一个候选后，仅执行一次完整 CI、双架构离线构建、ARM64 QEMU 与 x64 KVM 的受影响全链路回归。失败后先定点修复，避免每改一个构建参数就重复整套回归。Python/OSv 的退出问题继续独立推进，未通过的矩阵不因引入 allocator 而改绿。

## rc82 真实 API 对照

2026-11-11 使用已验收 rc82 的宿主程序、内核、BusyBox、Bash 及资源策略，比较同一 39 项输入、编译器和 musl libc 生成的 System 与 mimalloc agent。两份独立参考镜像的文件清单仅允许 `/sbin/agent-init` 内容变化，分别绑定 agent、镜像、源码、公开签名与来源摘要。参考 manifest 使用同一诊断签名身份，原 rc82 包保留。验证准备工具只在显式参考参数下选择这些产物，实际 API/launcher 仍验证其签名、有效期、hash、大小和 jailer。参考身份及 release_eligible=false 随报告保存。

在指定机全局验证锁内按 System、mimalloc、mimalloc、System 的 ABBA 顺序串行启动四个隔离夹具。每臂 8 个 fresh session，均为 128 MiB、1 vCPU、无网络、相同宿主 CPU 可用集合及 cgroup 限额。每个会话先运行 2 轮预热，再测 16 轮，固定顺序执行最小 shell 命令、512 KiB 文件写入、完整内容读取校验和 256 项目录列举。每臂每种操作 128 个正式样本，每种分配器合计 256 个样本。每个会话的准备、设置、预热、测量、guest 内存读取和关闭全部计入现有 100 次 guest 请求预算，不增加运行额度。

通过正常 mTLS API 和已安装 Python SDK运行，保存所有尝试、输出/内容摘要、session/VM/模板身份、完整 API 延迟、命令报告时长、guest PID 1 的 VmRSS/VmHWM、宿主 VMM RSS 及存活期间观察的 cgroup memory.peak/OOM 计数。失败或未知结果结束该臂并保留，不自动重放。会话关闭后验证原 VM 退出，再进入下一会话。宿主 CPU/NUMA、swap 和生产 doctor 随臂记录，限额及工作负载在两种分配器间一致。

对每臂及每种分配器分别重算分位数和内存，报告比例、方向一致性和所有失败。256 个样本的尾部统计保留样本量限制，该批不登记为千次启动门禁或完整功能矩阵。实际收益需结合 API、命令和内存判断，原微基准继续保留。此次只有测量工具和诊断镜像变化，复用 rc82 完整 CI、双架构和现有功能基线，先完成参考选择/篡改拒绝定向测试，再运行四臂真实任务。

## 普通 mimalloc 配置的后续对照

上述真实 API ABBA 已完成，secure=4 的命令 p50/p99 和 agent VmHWM 出现回退，512 KiB 文件读取变化很小。用户要求一般安全基线，本轮先增加同源码普通 mimalloc 的诊断参考，直接启用依赖的 mimalloc 特性，验证 feature tree 无 secure、实际 C 配置及指针归属测试。以同编译器、musl 和优化设置重新构建，并记录 C 库与 agent 摘要。默认发布配置的选择取决于后续同口径实际任务结果。

普通配置仍使用固定 C 3.3.2、no_thp 及原 Rust/C 优化设置。先完成离线编译和实际静态 musl allocator 测试，再按前述任务、资源、会话预算和 ABBA 口径验证。宿主隔离、签名准入、持久归属和回收均使用既有 rc82 实现，分配器配置的收益独立记录。

普通配置四臂真实任务完成后，命令耗时仍有回退。源码中的每条命令通过重新执行 `/sbin/agent-init --workload-supervisor` 创建监督进程，agent 的 allocator 初始化先于辅助入口分派。下一步先做相同镜像的启动路径诊断，在普通 System/mimalloc 两组中，分别执行 16 次 `/bin/true` 和 16 次非 PID1 的 `/sbin/agent-init`。后者逐次确认预期拒启码 2，使用固定输出标记，每次 API 命令仍有原超时和资源限制。

诊断沿用 ABBA 四臂、每臂 8 个 fresh session、2 轮预热和 16 轮正式请求，每轮包含上述两种命令，每种分配器每操作 256 个样本。记录完整 API、命令报告时长与操作前后 cpu.stat 计数，在同会话中计算两种路径差值。guest 请求上限收紧到每会话 40 次以内，原 100 次预算继续生效。所有调度波动、节流与失败保留，诊断结果用于判断进程启动路径的贡献，真实任务门禁仍使用先前四操作的完整批次。

两批已完成且零任务失败。普通配置命令仍回退，独立启动诊断支持进程启动存在额外开销，详见[实际结果](../../PUBLIC-QUALIFICATION.md#private-evidence)。后续按 [ADR-0090](0090-separate-workload-supervisor.md) 拆分长生命周期 PID1 和短生命周期监督入口的分配边界，复用既有协议及清理实现，真实收益和正式候选验收继续开放。
