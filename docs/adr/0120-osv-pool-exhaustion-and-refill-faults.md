# ADR-0120：当前OSv池空策略与真实补池拒绝/恢复

状态：Accepted（OSv两种池空策略、真实补池拒绝/恢复及独立清理通过）；日期：2026-11-14；需求 LIFE-04、SEC-03、QA-01、QA-02、PERF-03。

## 目标与配置

沿用[当前生产OSv原25项](../../PUBLIC-QUALIFICATION.md#private-evidence)的rc88原包、签名Python模板、生产API/launcher/VMM与四槽身份/PID配置，不重跑原25项、Linux专项或不变产品完整CI。当前18场景索引仍缺OSv pool_exhaustion与refill_failure；本批只补这两个缺口，真实到期、镜像轮换及只读输入继续分别跟踪，不替其登记通过。

建立emptyreject、emptycold、refill三个隔离夹具，顺序共用原全局flock，每组结束独立清理后再建下一组。所有配置在首次服务启动前完成；使用ADR0119已合格的明确OSv四槽开关，仍保留原准备器默认行为及全部宿主/namespace/cgroup检查。签名资产及产品程序不变，1243项输入与原90项载荷前后逐项绑定。

## 真正池空与两个策略

OSv不支持session，因此用两个单次原生Python任务持有最初两个warm VM。单profile为512MiB、1vCPU，min=max=2；refill burst=2/rate=0.1每秒，active/物理/身份上限4，两租户并发上限均4。两个租户A任务sleep12秒后输出不同holder标记，宿主job超时20秒；控制器保留各自唯一HTTP请求连接，不重发请求。

在首次服务启动后7秒内证明：两个原ready VM现为A的active owner；matching profile ready=booting=0；active=instances=2、可用身份2、容量不blocked，租户与active quota仍有余量。第三次由B单次发起同512MiB job，并须在下一补池token前9秒内完成。reject必须429 busy且没有B领取；cold必须新VM以empty miss、同profile实际运行Python并成功。不能用quota满、profile mismatch或第三次请求重试替代池空。

第三次请求后两个原A进程仍存活，再读取各自原HTTP响应，验证原job ID、warm/成功/标记与其owner一致，证明池空处理未杀死已准入任务。读取限制为2MiB并保留原响应，不把等待holder结束的12秒计入第三次请求控制窗或性能。最后确认两owner销毁、active归0；正常补池可以在控制窗之后继续。

## 实际补池拒绝与恢复

refill夹具保留512/768MiB两profile、active2、每租户1，使用已合格的私有VM父cgroup pids.max=0控制。确认API/launcher/验证器不在该子树，记录原限额；pidfd核对代次/cgroup后杀一台small ready VM，并确认实际退出，最多15秒故障窗内核对新补池计数/退避、实际内核fork denial及无假ready，不伤其他原ready VM。

finally恢复原pids.max，等待两个profile恢复原desired且无booting/checking/retiring，再从已知新ready VM执行当前签名Python任务并核对warm、任务/VM/审计。Linux6.1父pids.events可以不增长，继续用精确私有cgroup、boot ID、新VM ID和单调时窗的内核拒绝记录，不用父计数0否定已确认内核故障。

## 验收与边界

先[自评审](../../PUBLIC-QUALIFICATION.md#private-evidence)，执行配置、控制窗、HTTP响应边界/错误、holder绑定及私有路径反例，再新ID单次真机。任何前置条件失败即保留失败，不循环请求直到通过；响应未知不重发。异常先恢复限额并关闭本夹具连接，再用已验证的未启动兼容清理，逐项SHA和无引用后删除重复安装件。原归档、失败和实际依赖保留项目中。

这是功能及故障验收，不新增正式延迟样本；warm仍5/9/13ms，四必要路线各1000正式样本，原18/40项完整范围、普通安全、K8s暂缓及ARM编译/QEMU范围保持。

## 实际结果

任务`rc88-osv-pool-supplement-r1`（InvocationID `82b265b956ca4dd0825699b2c5b8465f`）三个夹具单次通过。reject/cold控制窗分别4.128/4.792秒，第三次请求前active=instances=2、可用身份2、ready=booting=0；两个原warm holder均由原连接返回成功。补池故障持续0.826秒，原pids.max恢复，实际内核拒绝1条、计数0→1且有退避，恢复后新known-ready OSv VM真实执行成功。

原90项载荷前后及1243项程序输入未变，三个夹具独立清理通过。核对收据`results/2026-11-14-rc88-osv-pool-supplement/r1/verified-analysis.json`；详见[验证记录](../../PUBLIC-QUALIFICATION.md#private-evidence)。没有重跑原25项、Linux或完整CI，没有登记正式延迟或剩余case通过。
