# ADR-0116：当前候选的池故障场景定向验收

状态：Accepted（设计及分阶段执行，原18场景尚未全部通过）；日期：2026-11-13；需求 LIFE-04、SEC-03、QA-01、QA-02、PERF-03、REL-04。

## 缺口与验收边界

[原候选场景核验](../../PUBLIC-QUALIFICATION.md#private-evidence)显示当前rc87的15套功能回归没有独立Linux/OSv pool故障套件，不能仅凭560个聚合用例填满机器契约的18个case。原独立脚本已有Linux29、OSv25项检查，但Linux固定3槽和UID上限，并直接开guest vsock发送110个ping，与当前预连接控制通道不一致；OSv脚本仍构建旧独立诊断夹具，须先绑定当前候选。

保持原18场景定义，不由不足范围的结果推断True。每个case绑定原始报告/检查名/实际断言、候选摘要、配置及脚本、原任务与清理；分后端记录支持能力。OSv拒绝不支持input_files的事实不能冒充已证明输入只读挂载；未覆盖部分保持开放，不把helper/unit或旧候选当本候选真实KVM。

## 第一步：当前Linux基础池与补池失败

保留原Linux29项检查的执行目的，私有复制到项目验证目录，不改产品或原脚本。使用原rc87签名包及四槽准备器；从已核验配置读取VM/身份/PID边界，完整UID/GID、seccomp/cap、cgroup及代次检查不放宽。以跨越guest五秒空闲窗口的6200ms真实launcher维护、原VM仍pristine且下一领取确为原VM，替代外部抢占预连接通道的110个直接ping；不将其表述为实际发送了110个ping。输入写拒绝、跨租户文件隔离、一次领取销毁、TTL、profile mismatch、死亡领取、取消、API/launcher崩溃和零残留原断言保持。

补池失败另做定向私有cgroup控制：记录原pids.max、当前任务和事件计数，确认API/launcher及验证器不在受限VM子树；短暂将该夹具的VM父cgroup pids.max置0，按已核验PID/start ticks/cgroup的pidfd杀死一台ready VM，观察新补池失败计数及pids事件、未发布假ready。finally恢复原pids.max，再确认正常补池及真实warm执行。该私有故障不修改宿主根cgroup、全局策略或已有VM预算文件，不把资源失败当请求成功。

[内核cgroup文档](https://docs.kernel.org/admin-guide/cgroup-v2.html#pid)说明限制低于现有任务数是允许的，fork/clone增加任务违反限额时返回EAGAIN；不据此假定实际内核已验证，真机仍须核对控制器事件与恢复结果。故障窗口有界；异常先恢复私有设置，再由外层固定夹具清理和独立终态检查。VM信号使用pidfd并核对代次/cgroup，服务信号交给已验证私有unit的systemctl kill，避免对复用PID误发信号。

## 后续缺口与顺序

原pool_exhaustion须验证已配置的on_miss行为与资源账，不能用租户quota拒绝替代池空；独立配置保持可解释的active/物理预算。artifact_expiry需用当前执行文件和实际受信签名、短有效期元数据，在进程加载后真实到期，核对idle退役、新领取拒绝与已准入任务；只替换磁盘文件而未使已加载manifest到期不算过期证明。template_rotation按产品支持的签名代次切换/激活流程验证旧实例不可再领取，不声称尚未提供的热切换。两者应明确记录派生测试元数据的摘要及恢复，不能把篡改签名拒绝当过期或轮转。

先完成[自评审](../../PUBLIC-QUALIFICATION.md#private-evidence)，实现私有适配/故障守卫的定向反例；当前其余三路线正式性能任务结束并导出后，再顺序执行新ID故障任务，不能同时给性能批次施加故障。原29/25分母及新case分别记录，不因适配删除原失败/检查。故障任务最多1200秒、日志8MiB、只提交一次；观察失败查原ID，不重放业务。通过初步基础/补池控制也不自动登记全部18场景。

产品与原benchmark不变，复用原完整CI/E2E，原5/9/13ms、四路线各千次、40项原要求和一般安全范围保持；K8s继续暂缓。实际库、签名资产和依赖保留项目中，清理只针对有证据的重复副本。

## r1失败与r2的死亡前置条件

首轮任务 `rc87-pool-faults-r1`（InvocationID `e61d1c5b3a274911b3a49ab683e1189b`）保留失败终态：29项中已完成18项，发送SIGKILL后立即创建替代任务收到503。原脚本只确认发送信号，没有确认原VM已经退出，不能据此认定请求开始时已有死亡VM。当前产品在准备可能已发送时返回不可用并销毁实例，不允许盲目重发租户输入；r1的503具体经过仍未由原日志证明，不能直接宣告产品没有问题。

修订只给私有测试加前置条件：打开pidfd并核对PID代次和私有cgroup，发SIGKILL后最多等待2秒的POLLIN/POLLHUP退出通知，再执行原死亡领取断言。超时或错误必须失败，不循环重放API请求；保留不同VM、真实执行、原29项目的及后续崩溃检查。补池失败受控杀死同样先确认退出。[Linux pidfd手册](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)说明进程终止会产生可读通知、回收后产生挂断通知；实际106内核结果仍须记录。

修订后的24项本地守卫测试通过后，以新任务 `rc87-pool-faults-r2` 冻结和执行一次。r1原始归档、失败报告和独立清理证明保留，不更改r1终态；r2通过也只证明修订后明确的死亡前置条件，不能替代并发死亡窗口的语义核验。

## 当前候选补证进展

2026-11-14，rc88原Linux29项与真实补池拒绝/退避/恢复已通过；[Linux池空、真实到期、镜像代次激活](../../PUBLIC-QUALIFICATION.md#private-evidence)及[当前生产OSv原25项](../../PUBLIC-QUALIFICATION.md#private-evidence)也均独立核对通过。原失败、源码、计划/InvocationID及清理收据分别保留，没有重放已完成业务或重复不变产品完整CI。

`results/2026-11-14-rc88-pool-case-coverage/receipt.json`给出18项到当前报告/检查名的索引：Linux18、OSv13项有对应检查；OSv的input_readonly、pool_exhaustion、refill_failure、artifact_expiry、template_rotation仍未证明。索引不填充正式gate布尔值，原18定义、后端能力差异及完整资源/性能要求保持。先补实际缺口，再做当前候选集中正式采样。
