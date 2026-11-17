# ADR-0104：按最不确定的启动路线推进 rc86 千次验证

状态：Accepted（首路线千次已核对，尾延迟未达标，按顺序继续定位）；日期：2026-11-12；需求 PERF-03、QA-03、REL-04。

预连接已通过 [rc86 完整同包功能验收](../../PUBLIC-QUALIFICATION.md#private-evidence)，[原包 API 对照](../../PUBLIC-QUALIFICATION.md#private-evidence)显示延迟收益，但 B1 的短窗 p99 仍超目标。下一步先对同一签名 rc86 执行 Linux warm **1000 次正式请求及 5 次预热**，完整保留失败与尾部样本，不追加多批挑选最好结果。

继续使用已验证的原测量器、准备器、实际 CPU 2–5/NUMA0、原配额/补池、正常生产 doctor 和计时起止。原包与程序输入保持；本次不再重复完整 CI、双架构包、ARM QEMU 或 15 套功能回归。Linux warm 的 256 次 rc86 实际对照已经证明测量链可用，因此不再增加短 pilot。

若本条必要路线不达 p50≤5/p95≤8/p99≤10ms，先定位它，再推进其余三路线，避免在明确未达标时高频重复四路全量。若达到，则继续同候选 Linux cold、OSv warm/cold 各至少千次及原隔离/恢复/资源/长稳门禁；旧 rc85 的通过不能冒充 rc86 通过，四路线分母不缩小。该执行顺序不代表正式性能门禁已经通过。

先完成[执行自评审](../../PUBLIC-QUALIFICATION.md#private-evidence)，冻结新工具/计划/任务 ID，再观察原任务代次。SSH 观察中断只恢复同一任务，不重放。任务终态后独立关联原始请求、七阶段、唯一 VM/归属、实际载荷、正常 doctor、限额、宿主与清理。

## 实际结果

[Linux warm 正式采样](../../PUBLIC-QUALIFICATION.md#private-evidence)1000+5 次全部成功，1005 个唯一 VM，原输入/任务代次/正常 doctor/实际放置和独立清理通过；warm 为 **3.341/8.281/14.481ms**，p95/p99 未达 8/10ms。53 个 >8ms 请求中 35 个最大阶段为 preparation、12 个为 admission。继续定位真实等待，暂缓其余三条必要路线的千次重测；不把短样本、历史候选或请求成功改写为门禁通过。
