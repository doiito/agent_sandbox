# ADR-0096：rc85 正式启动采样的宿主与放置条件

状态：Accepted（采样流程及正式数据核对，Linux warm 尾延迟未通过）；日期：2026-11-11；需求 PERF-03、QA-03、REL-04。

## 决策

rc85 已通过完整 CI、双架构离线包、x64 非 root API 和 ARM 无网卡 QEMU 58 组，指定机完整 KVM 功能回归进行中。原启动数据因宿主 swap 启用而仅为诊断；本轮按既有生产部署基线，在确认约 27.7 GiB 可用内存后通过独立持久部署任务备份 fstab、关闭唯一约 1 GiB swap，并注释其启动项。操作和独立复查均成功，恢复记录位于服务器 `/var/lib/osv-host-baseline-rc85`。这不是测量工具对门禁的覆盖。

正式采样固定同一 rc85 包、原测量起止、正常 quiet/loglevel=3、1 秒健康检查、1 vCPU 的 100000/100000 CPU 配额和原资源上限。使用四条必要路线：Linux shell warm/cold、OSv Python science warm/cold；两种负载分别报告，不推导同任务比较。

服务器已实际核对 48 个在线逻辑 CPU：CPU 2–5 是 NUMA 节点 0 上四个不同物理核心的线程。采样夹具的 API/launcher 在首次启动前设置 `CPUAffinity=2-5`、`NUMAPolicy=bind`、`NUMAMask=0`；通过 unit 属性、实际 ready VMM 的 CPU 亲和性及 `/proc/PID/numa_maps` 匿名映射策略核验。NUMA 分配策略不等于 Mems_allowed 授权列表，也不要求共享文件页只存在于节点 0。仅约束本夹具，保留实际观察，不更改宿主全局 CPU/NUMA 或其他服务。

测量实现继续复用既有 `startup_benchmark.py` 原字节，只在独立冻结的准备器副本添加 unit 放置条件。pilot 每路线 16 次正式请求加 5 次预热，用于验证新夹具、放置、实际 doctor 就绪及协议；不登记门禁。pilot 成功后以新任务 ID、新根目录运行同脚本每路线 1000 次正式请求加 5 次预热，禁止重放失败任务或混入 pilot 样本。

不传 `--diagnostic`，任何初始或过程 doctor 不就绪、路由不符、未知结果、身份/隔离错误或任务失败均停止该批并保留。样本、候选、宿主、配置、工具、放置与持久 worker 原 InvocationID 一起归档。仅当完整候选功能、一般安全用例和独立数据核对都满足时，才登记 5/8/10 ms warm 与 400/600/1000 ms cold 门禁。

## 验证策略

先完成[自评审](../../PUBLIC-QUALIFICATION.md#private-evidence)，再生成冻结准备器和路线 worker。不修改产品、通用测量工具或已冻结候选；本次工具变化以语法检查、实际四路线 pilot 验证，避免重跑已通过的规范 CI。服务器任务继续串行持有全局验证锁，完整功能回归结束后才开始 pilot。

NUMA 或 doctor 条件不满足时，先调查原失败，不自动退回宽亲和性或诊断模式。启动分位数通过仍不代替同任务性能、资源密度、长稳及其余原需求。

## 首次放置失败与修正

Linux warm pilot-r1 在发任务前被实际 VMM CPU 亲和性检查拒绝，没有性能样本；原任务及归档保留，夹具清理成功。宿主已启用 cpuset 控制器。随后用一个自有 sleep 子进程做独立有界干预：原 affinity=2-5，迁入未限制的 cgroup 后变为 0-47，迁入 cpuset.cpus=2-5 / cpuset.mems=0 的叶节点后保持 2-5；测试子进程与目录均清理。[实际迁组证据](../../PUBLIC-QUALIFICATION.md#private-evidence)

因此仅设置 service CPUAffinity 不能保证 jailer 迁入独立 VM cgroup 后仍保持放置。新 r2 准备器在任何服务/VM 启动前创建本夹具的空 cgroup 父节点，固定其 cpuset.cpus=2-5、cpuset.mems=0，并仅在本父节点启用已由宿主提供的 cpuset 子控制器；原 unit CPUAffinity/NUMAPolicy 保留。检查实际有效父节点与 VMM 掩码，不降低原检查，不热改存活 VM，不改宿主根控制器或其他 cgroup。清理仍移除整个专用父节点。

r1 原四条 pilot/formal 计划不执行或重放；r2 使用新工具目录、新任务 ID/根目录。原 benchmark 字节、计时与样本门槛保持，先重新验证四路线 pilot。

四路线 r2 pilot 已完成，64 次正式请求加 20 次预热全部成功，实际放置与 doctor 均核对，五套原/新目录独立清理通过。Linux warm 有一个 23.538 ms 长尾，正式性能没有登记通过；随后用新 ID 进行千次统计。见[采样记录](../../PUBLIC-QUALIFICATION.md#private-evidence)。

四路线 r2 正式千次统计现已完成并独立核对，共 4020 台唯一 VM（含每路 5 次预热），任务零失败、生产 doctor 均就绪；宿主终态也已独立确认。OSv warm 与两条 cold 路线达到延迟数值阈值，Linux warm 3.676/11.610/19.756 ms 未达 p95/p99，整体门禁保持未通过。按 [ADR-0098](0098-linux-input-readonly-mount-probe.md)对完整分布显示的 preparation 阶段做只读挂载诊断，不修改原样本或放置条件。
