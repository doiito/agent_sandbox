# ADR-0126：区分 vCPU 调度上下文与 KVM 驻留区间

状态：Accepted（小型及采集配置资格通过；一次实际API捕获因文本上限拒绝，当前方法停止）；日期：2026-11-17；需求 PERF-03、QA-01、QA-02、QA-05。

## 问题与现有证据

[ADR-0124 的133项完整关联](../../PUBLIC-QUALIFICATION.md#private-evidence)已将主要等待定位在 VM 正文发布前。两个慢例与同 vCPU 的 CFS/R 等待重叠，另两个在 vCPU 调度上下文中约8.388/7.829ms，该值包含宿主工作，不能称作纯 guest CPU。[ADR-0125](0125-vm-cpu-placement.md)唯一532任务ABBA没有证明所需p99收益，已恢复原1355项产品身份和八个双架构控制面程序。不得重复该实验或正式采样直到变绿。

现有原始 trace 没有 KVM entry/exit，无法仅靠重新解析分离上述区间。下一步先验证宿主观察器是否能可靠保留此信息；不改 guest、API/launcher、CPU配额、放置、池资源或七阶段计时。

## 拟定方法与限制

指定机只读[预检](../../PUBLIC-QUALIFICATION.md#private-evidence)确认内核6.1.0-42-amd64提供 `kvm_entry`/`kvm_exit`，字段格式和摘要已记录。entry含vcpu_id、immediate_exit及地址，exit含vcpu_id、reason/isa及地址等；只拟保留vcpu_id、immediate_exit、reason/isa和通用PID/CPU/时间，不读取guest内存、RIP、请求体或参数。

[官方eprobe文档](https://cdn.kernel.org/doc/html/latest/trace/eprobetrace.html)说明可从事件选择字段，但其文档针对6.17；本机6.1的功能存在性和字段类型必须实际验证，不能据文档或一个CONFIG行推断可用。eprobe不保证降低执行开销。只创建唯一自有动态事件及独立trace实例，只在该实例启用；不改全局tracing_on、clock、buffer、CPU或调度设置，不升级宿主内核。

先完成有界解析/反例和小型实际KVM控制，验证entry/exit字段、同TID/同vCPU配对、迁移/代次、主机停留间隙与真实VM执行区间的区分、immediate/失败进入处理、丢失及前后边界。乱序、嵌套entry、缺失exit、重复、跨代次/CPU、未知isa、截断和drop/overrun必须拒绝或明确coverage未知；未知不能记零。以原调度区间作交集，不把entry到exit的全部墙钟直接称作guest CPU，报告保留为“KVM事件驻留区间”，注明事件放置和固件等边界限制。实际资格控制只用明确自有VM，不计业务/性能样本。

观察器及独立清理合格后，再冻结一次当前rc92签名程序的无/有观察对照，每组128+5，共266个不同任务/VM；保留全部现有guest特性、四物理槽、CPU2–5/NUMA0、100000/100000和正常doctor。与已有Unix/CFS/调度关联按VM PID/start ticks、vCPU TID代次、cgroup inode及同一mono时钟汇合。每个目标窗口需有完整边界，未完整覆盖则不作归因；不得仅挑慢样本拼结论。正式千次和发布门禁不因此放行。

在实际资格检查前不提交这266个业务请求；功能不具备、捕获有缺口或扰动过大时停止该方法，保留失败，不能放宽原判据。所有原始结果、程序来源和回收索引留项目；验证副本按已授权规则在终态和引用核查后清理。

## 评审

见[资格验证前自评审](../../PUBLIC-QUALIFICATION.md#private-evidence)。原40项范围、普通安全基线、ARM无网QEMU/ARM KVM豁免、K8s和域名TLS暂缓决定保持。

## 字段能力控制结果

指定机一次持久任务创建了两个自有eprobe及独立实例，实际格式严格只有通用PID/CPU/时间字段和显式vcpu_id、immediate_exit、exit_reason/isa，无RIP/额外payload字段。全程没有启用事件、捕获trace、创建VM或请求API；独立复核自有资源全部删除，全局设置及其他动态事件定义摘要与执行前相同，任务终态、输入未变且未重放。见[能力收据](../../PUBLIC-QUALIFICATION.md#private-evidence)。这只证明本机字段投影可用，不证明区间解析、KVM归因或性能采样已合格；后续前置门槛保持。

后续[小型资格](../../PUBLIC-QUALIFICATION.md#private-evidence)已完成：5个真实裸KVM控制、16对事件及独立计数一致，5段已知宿主间隙全部排除；原读取格式失败只离线修复，VM未重跑。16组本地反例及原后续断言保持，所有设置/解析失败分别保留，曾残留的自有实例已修复并独立确认回收。此结论只覆盖小型观察器资格，不是应用E2E或性能达标。

实际API配置另经20组本地检查、5新VM/18对跨实例控制通过。唯一[266任务业务对照](../../PUBLIC-QUALIFICATION.md#private-evidence)全部业务成功并清理；KVM文本超过256MiB预定上限且未保存，实际区间观察拒绝。不扩大上限补采，当前方法停止。现有完整调度/同步记录支持部分关联，4项所有权边界仍未知；不能从vCPU上下文推断纯guest CPU。原正式p99失败及未完成需求继续开放。
