# ADR-0111：补池就绪事件成对持久化

状态：Accepted（实验已完成实际对照，未采用）；日期：2026-11-13；需求 LIFE-04、SEC-03、OBS-01、QA-01、PERF-03、REL-02。

## 依据与决策

[rc87精确观察](../../PUBLIC-QUALIFICATION.md#private-evidence)中，前台pool.claimed记录等待前一后台pool.created fsync，两个实例的等待分别约7.156/14.130ms；不能将其解释为所有长尾。等平均CPU预算的[周期对照](../../PUBLIC-QUALIFICATION.md#private-evidence)未改善完整warm合并p99，继续保留100ms周期。

先验证一个固定大小的事务：成功补池的pool.created与pool.ready两条JSONL记录在探测、持久lease阶段转换之后，在发布到可领取队列之前，以一次完整write和一次fsync提交。保留两个事件、VM/profile身份及原协议；At表示这次成对提交的调用时间，不伪造为更早的boot时间。没有延迟窗口、异步队列、全局请求串行锁或丢弃事件。前台run.admitted、pool.claimed、完成事件及归属lease的持久边界保持。

只为AuditLog提供确切两条事件的AppendPair能力，原AuditRecorder接口兼容；不支持成对提交的recorder顺序Append两条并检查每次错误。探测/lease转换失败时，先持久记录created，再按既有路径销毁并记录discarded/refill_failed，不产生ready事件。boot自身失败仍保持原行为。write、short write、编码或sync失败粘性失效，禁止发布ready及后续新准入，不能以重试恢复成功；已准入任务按原TTL收尾。

## 崩溃、并发与限制

boot完成到成对提交前，VM已有持久进程lease/独占owner和物理预算，但尚不可领取且没有租户准备/执行。此时launcher崩溃依原lease/cgroup对账回收；审计文件尾部不完整继续拒绝启动并保留证据。append的完整write+fsync仍由原mutex串行，Close不能提前关闭fd。取消/停机后即使sync成功也必须经过既有ctx/closed检查，不能发布已取消VM。

这将成功补池的两次审计fsync变成一次；不保证缩短单次fsync、其他持久lease操作或前台长尾。共享文件系统、CPU调度及guest准备问题继续独立跟踪。

## 顺序与验收

先完成[自评审](../../PUBLIC-QUALIFICATION.md#private-evidence)，使用项目内Go overlay隔离两个修改文件及新增测试，当前已验收产品源码/包保持。定向覆盖双事件落盘前不可返回、并发记录完整、write/short/sync/编码失败和粘性失效、真实文件尾部、同步阻塞时ready不可见、补池失败与取消回收、兼容recorder，执行相关包race和双架构编译。

通过后用同源重编译control/experiment宿主二进制、相同原guest与正常doctor做实际API ABBA，保留所有样本及失败，同时核对真实VM补池/领取、持久审计归属及清理。实际launcher崩溃在新提交窗口的KVM恢复必须进入采用前回归。不得以本地helper或fsync计数代替真实KVM/启动性能。

只有实际收益和功能/一般安全性合格才采用并构建新完整候选；采用后执行一次canonical CI、双架构离线安装与ARM无NIC QEMU、指定机受影响及原15套回归和四必要启动路线。实验阶段只运行受影响检查，未变guest/SDK不高频重复完整回归。当前warm5/8/10ms、每路线1000次、18场景和原40项要求不变。

## 对照冻结与本阶段结果

实际API下一批预先固定A1/B1/B2/A2各128正式+5预热，不剔除或重测慢窗口。A为已验收rc87（重编译x64 API/launcher已与原包逐字节一致），B为相同guest/assets的完整测试签名宿主实验包；宿主二进制及相应SBOM/manifest/来源证明变化必须精确列出，其他载荷逐项一致。正常doctor、CPU2–5/NUMA0、128MiB/1vCPU、100000/100000µs、max_booting=2、health=1000ms保持。短窗仅用于选择，采用需要重复方向的完整warm收益且功能/失败不回退，不能仅以fsync计数或局部分位数采用。

共同成功确认边界不代表两条记录在掉电时物理原子；可能留下完整created加不完整ready，或只有完整created。前者保留尾部并拒绝启动，后者由原owner/lease/cgroup对账回收，均不得重用未发布VM。

[组件验证](../../PUBLIC-QUALIFICATION.md#private-evidence)10个新增顶层测试/19条记录、受影响两包396个顶层测试/970条race通过记录、双架构8份静态二进制以及ARM无NIC QEMU 20个顶层测试/38条记录通过；首次沙箱构建拦截单独保留。当前只证明提交边界和成功补池fsync为2→1，尚未执行本批真实API或新窗口KVM崩溃验收，产品未采用。

## 实际对照结论

[四组原任务](../../PUBLIC-QUALIFICATION.md#private-evidence)532次全部成功，B的合并warm=3.378/8.793/12.012ms，A为3.231/7.148/14.070ms。p99下降，但p50/p95及超8/10ms计数回退，不满足完整warm采用条件；**保留原实现，不推进该候选**。因此未为被拒实验追加新窗口KVM崩溃回归；该项仍为以后任何采用的必需门禁。当前产品与原正式性能结论保持，下一步研究物理池余量，不能将短审计间隔单独当因果。
