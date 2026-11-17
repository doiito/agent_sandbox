# ADR-0115：按新规格正式验收四槽warm工作点

状态：Accepted（四槽warm正式延迟通过；其余路线/场景开放，未采用或登记发布）；日期：2026-11-13；需求 LIFE-04、PERF-03、QA-01、REL-02、REL-04。

## 新规格下的选择理由

用户已通过[ADR-0114](0114-warm-start-five-nine-thirteen.md)把warm门槛改为5/9/13ms。原3槽正式千次为3.299/7.894/13.639ms，新p99仍失败。原两个profile最多需要2个small ready、1个large ready，另有1个active时至少需要4个物理槽；四槽是明确预算的部署工作点，不能描述成无资源成本的代码提速。

[原ABBA](../../PUBLIC-QUALIFICATION.md#private-evidence)保留A1/B1/B2/A2全部结果：4槽合并warm=3.172/6.586/11.108ms，相比3槽3.325/8.117/11.350ms，paced供给约+30.7%、RSS观测峰值+6.51MiB，HTTP部分分位数回退7–9%。旧5/8/10ms下未采用的结论保持。B1 p99=13.975ms且两组方向不一致；[后续未跟踪128样本](../../PUBLIC-QUALIFICATION.md#private-evidence)p99=13.885ms也超新门槛。这里没有声称4槽已通过，只依据槽位可行性、供给收益及新规格，允许首次固定四槽正式千次验收，不再追加小批选择。

## 固定配置与执行

使用原rc87签名包和原benchmark，不采用审计overlay、CPU周期实验、额外等待、追踪或目录FD固定包装器。只把物理max_instances、identity_pool_size、reserved_pids设置为4/4/256；其余归一化配置必须与原3槽基线完全相同。保留两个原profile、active上限2、每VM128MiB/1vCPU/PID64、CPU100000/100000、CPU2–5/NUMA0、max_booting=2、health=1000ms、预留6528MiB/12vCPU及无swap。

按[自评审](../../PUBLIC-QUALIFICATION.md#private-evidence)和原准备器6项反例检查后，冻结一次1000正式+5预热的未跟踪真实API批次，正常production doctor，完整七阶段及HTTP/ready wait/供给/RSS/失败保留；不在测量中修改配置。新不可变任务只提交一次，观察失败继续查原ID，不重放业务。

## 结果处理与回归

评估全部1000正式样本的5/9/13ms、零错误、正常doctor、唯一VM/身份、实际CPU配额/放置、载荷及独立清理。失败时保留全部数据，不能再启动同配置同候选采样直到变绿；需要新的产品/配置因果依据后另行设计。成功也仅证明此指定工作点的Linux warm性能，不能用资源增加掩盖HTTP或资源代价。

正式evidence登记仍须同候选其他三必要路线及18场景/功能和一般发布要求的证据；不自动采纳四槽为全局默认，也不改变原40项需求、cold/snapshot、ARM QEMU或一般安全范围。编译产品和90个payload未变，当前政策只改变冻结清单中一个检查脚本，使用新政策清单精确绑定；复用原完整CI/E2E及已执行的四槽实际功能检查，本阶段只执行受影响准备器检查与正式性能，避免高频全量回归。

四槽千次已完成：原任务1005次全成功，warm=3.058/4.971/9.786ms，最大23.397ms和4个>13ms样本保留，达到新分位数目标。原输入未变并独立回收，见[完整验收记录](../../PUBLIC-QUALIFICATION.md#private-evidence)。按原ADR-0108解除其余三路线的等待：每条固定1000正式+5预热，原同包/benchmark/准备器，原route参数及其CPU/NUMA放置，分别新ID顺序执行；Linux cold、OSv warm/cold使用各自原已定义profile与预算，不冒充OSv/Linux同工作负载比较。warm用5/9/13，cold用400/600/1000，未通过不重采到绿。旧3槽失败和本次4槽结果均保留。
