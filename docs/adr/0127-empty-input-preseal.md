# ADR-0127：在 pristine ready 前封存空输入

状态：Deferred（用户改为p99≤15ms并要求先发布；实验已归档，产品源码已恢复）；日期：2026-11-17；需求 PERF-03、QA-01、QA-02、QA-05。

## 问题与证据边界

当前Linux warm正式p99为14.245ms，高于13ms。[一次KVM观察](../../PUBLIC-QUALIFICATION.md#private-evidence)的文本超限，方法已停止，不扩限补采。现有记录显示prepare仍有慢例，但不能把vCPU上下文当作guest CPU，也没有证明remount是这些慢例的原因。

源码提供一个独立可审查的优化机会：`initialize_guest`为pristine创建空的可写`/input`；每次prepare无论是否有输入文件，均遍历/设置权限并调用`freeze_input`执行只读remount。正式shell启动工作负载没有输入文件。将已经确定的空输入只读状态前移到boot，能够避免请求阶段重复改变挂载状态；实际端到端收益须验证，不能预先登记性能提升。

## 设计

pristine guest在声明ready及启动请求服务前，将空`/input`目录设为0555，封存为只读、nodev、nosuid、noexec并实际检查挂载标志。初始化失败沿原init_error/拒绝/退役路径处理。legacy启动路径保持原行为。

prepare仍先完成完整绑定/TTL/输入预算校验及输入、workspace为空的检查。若输入为空且原输入挂载的全部保护标志和0555目录权限正确，复用该状态；不执行chmod/remount。若有输入，只有在确认初始完整只读保护状态后才解除只读，保留nodev/nosuid/noexec，完成原文件写入、0444/0555权限和封存验证后才发布Prepared绑定/ACK。写入失败尝试恢复只读，原请求仍失败并退役；失败不能复用VM。`freeze_input`可复用实际验证的完整只读状态，缺任何标志不能走捷径。

不增加可见协议字段、空闲等待、池容量、CPU配额、FD资源或宿主依赖，不改变一次性checkout、原七阶段计时或原5/9/13ms门禁。不关闭guest功能，不减少有输入文件的功能。实际库/构建依赖继续留项目目录。

## 验证和采用

先执行受影响Rust协议/状态/输入单元检查及双架构musl+mimalloc静态编译；以实际无NIC QEMU检查空输入预封存、有输入解除只读后正确封存、写入拒绝/失败退役及原只读输入用例。验证新增代码不依靠本地root测试的跳过结果。指定机只做与此改动有关的真实guest/绑定及故障控制，合格后冻结一次预定A/B/B/A对照，各128+5，不重放已成功批次。

对照保持原签名基线/全部功能、四槽、CPU2–5/NUMA0、100000/100000、正常doctor及七阶段/原始JSON。独立报告warm、HTTP、供给等待、cold boot及失败率；供给/HTTP p99不得比基线汇总恶化超过既有10%资源预算。只有功能通过、目标范围内且可解释的warm收益才推进完整候选及一次正式验收；没有证明收益则恢复原实现并保留实验。小批次不替代千次，当前rc92正式失败不因新设计放行。

## 自评审

见[实施前评审](../../PUBLIC-QUALIFICATION.md#private-evidence)。原40项、普通安全、ARM无网QEMU要求、ARM KVM豁免、K8s和域名TLS暂缓保持。
