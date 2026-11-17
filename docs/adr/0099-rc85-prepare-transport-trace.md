# ADR-0099：rc85 prepare 宿主与通信路径跟踪

状态：Accepted（定向诊断，整体性能门禁仍未通过）；日期：2026-11-11；需求 PERF-03、QA-03、LIFE-04。

## 依据与决策

rc85 已在就绪宿主完成每路线千次启动，Linux warm preparation 长尾仍未解释。[输入挂载对照](../../PUBLIC-QUALIFICATION.md#private-evidence)中原方式最大仅 7.748 µs，未复现毫秒级等待；不因此修改产品挂载。下一步区分宿主文件/归属校验、Unix/vsock CONNECT 握手、发送准备请求和接收 guest 应答的等待。

复用已经过真实 strace 哨兵及实际 KVM 验证的 `scripts/trace-startup.py`、通用 benchmark 和 r2 固定放置准备器原字节，不改产品、候选、计时定义或安全检查。新夹具安装同一 rc85 签名包并核对全部 90 项载荷，CPU 2–5 / NUMA bind:0、128 MiB / 1 vCPU、原 CPU 配额及 1 秒健康检查保持。先验证实际 ready VMM 的放置，再执行 16 次请求加 5 次预热，正常生产 doctor 必须就绪。

只附加本夹具 launcher；原跟踪工具继续 raw 化 read/write、随机数和 exec 参数缓冲，执行子进程在 exec 时脱离，预启动 VMM 的 TracerPid 必须为 0。时间上限 180 秒、软/硬日志上限 48/64 MiB 及格式审计保持。跟踪本身会改变调度，全部数据明确为诊断，不进入千次性能分母。

以原 request/job/VM ID、audit 时间戳及 FD 生命周期关联每次 CONNECT、请求写入和响应读取；确认单次最终归属提交的两次 fsync、一次 rename。记录完整原始轨迹和必要 audit，不能凭一次 read 等待直接断言 guest、CFS、磁盘或 allocator 根因。现有 CPU 统计窗口涵盖任务执行，不能当作精确启动限流计数。

顺序为本决定、[自评审](../../PUBLIC-QUALIFICATION.md#private-evidence)、冻结工具、一次持久任务、独立分析与宿主清理。原候选功能回归保持有效，不为纯验证工具重复完整 CI、双架构包或 QEMU。失败任务保留原状态；观察中断只查询原 InvocationID，不重放。

## 实际结果

16+5 次全部成功，原工具上限与格式审计、VMM 未被跟踪、最终脱离和独立清理均通过。每次只有两次 lease fsync、一次 rename；响应主要等待在首字节前。跟踪本身将启动中位数放大到 42.710 ms，故不据此断言正式长尾原因，改用未跟踪的 prepare RPC 前后精确窗口继续区分 CPU 配额与调度。见[验证记录](../../PUBLIC-QUALIFICATION.md#private-evidence)。
