# ADR-0112：按物理余量验证warm池工作点

状态：Accepted（对照已执行，尚未采用或改变发行默认值）；日期：2026-11-13；需求 LIFE-04、PERF-03、QA-01、OPS-01、REL-02。

## 依据

[审计成对提交对照](../../PUBLIC-QUALIFICATION.md#private-evidence)的p95回退，不采用。原夹具small profile为min1/max2、large为min1/max1、全局active上限2，但物理VM上限3。因此2台small ready+1台large ready+1台active至少需4个物理槽，在3槽夹具中不能同时存在。

同批500/512正式样本的ready审计调用到admission审计调用间隔不足100ms，两个先前已精确关联CFS等待的例子为17.896/17.604ms。该墙钟差不是准确队列年龄或带宽预算年龄；槽位可行性与时间相关只支持做新对照，不证明增加槽位有效。旧rc85的48次直接prepare/ready-age实验无等待收益，原负向记录保留，不引入固定等待。

## 固定变因

重新使用原rc87签名包，两组均不使用被拒的审计overlay。A保持max_instances=3、identity_pool_size=3、reserved_pids=192；B改为4/4/256。三项是同一物理工作点的必要配套：仍每VM64 pids、生命周期唯一身份，不能只加VM槽而卡住身份或PID预算。新UID范围须按原准备器校验，不能复用宿主现有用户/组。

每VM 128MiB/1vCPU的正式工作负载、两个原profile的min/max、active上限2、CPU100000/100000µs、CPU2–5/NUMA0、max_booting=2、health=1000ms、总预留内存6528MiB/12vCPU、原持久审计/归属/TTL/取消与无swap保持。不删large profile，不降低资源限制，不借额外CPU预算，不把一次性benchmark结果当全局默认4台更优。

## 验证与采用

先完成[自评审](../../PUBLIC-QUALIFICATION.md#private-evidence)，在项目验证目录增加准备选项和三个确切字段的规范化；原选项关闭时行为不变。定向拒绝单改max_instances、少配identity/PID、其他资源/profile/安全字段漂移。四组A1/B1/B2/A2各128正式+5预热，正常doctor，原未跟踪benchmark与全部七阶段；原不可变任务提交一次，保留全部样本、失败、拒绝、冷回落和原ID观察。

核对真实VM代次/UID、配额、载荷、容量及最终清理。分别报告warm/七阶段、HTTP、池等待、paced供给、20ms观测RSS峰值和边界实例数；增加一个物理槽的内存/PID成本、CPU竞争导致回退的可能性不得省略。该批单客户端最多一个前台任务，不替代active上限2或更高并发/密度验收；RSS观察也不证明500实例目标。

采用需完整warm p95/p99有重复方向收益、满足当前5/8/10ms选择条件，且无功能/失败退化，供给和资源代价可解释。无收益则保留原工作点并保留证据。通过短窗仍须同配置千次、四必要路线、18场景、资源/长稳及原40项要求；部署指引应按profile和负载说明工作点，不隐式抬高用户的资源上限。当前产品程序未变，实验先做受影响配置与实际API，完整回归仅在采用并形成新候选时做一次。

## 2026-11-13执行结果

[原任务对照](../../PUBLIC-QUALIFICATION.md#private-evidence)532次全部成功，B的warm=3.172/6.586/11.108ms，A为3.325/8.117/11.350ms；paced供给+30.7%，观测RSS峰值+6.51MiB，同时HTTP分位数回退约7–9%。B1/B2的p99方向不一致，合并p99仍超10ms，**暂不采用**。全部原数据保留，不重复完整CI/E2E或挑选B2替换批次。4槽可供残余准入/归属等待的后续诊断，原门禁与发布条件保持。
