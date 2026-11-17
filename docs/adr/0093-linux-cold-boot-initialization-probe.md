# ADR-0093：Linux 冷启动初始化的有界归因

状态：Accepted（有界诊断流程，性能验收仍开放）；日期：2026-11-11；需求 PERF-03、QA-01/03。

## 依据与决策

rc82 的 1000 次 Linux cold 请求中，VMM 启动到第一次验证 pristine ready 的中位数约 690 ms，超过 cold 的 400 ms 中位数门槛，staging 不在该字段内。实际保留内核为 6.18.56+，其内嵌 IKCONFIG 启用了 CONFIG_SERIO_I8042、INPUT_KEYBOARD 等。仅凭配置不能判定它们造成耗时。

先做一个独立、最多 30 秒的真实 KVM 启动诊断。使用 rc83 已验证签名包、原 jailer/限额/静态 guest 与无网卡配置，通过既有后端命令构造和 pristine 协议验证 guest；仅在这一诊断实例中移除 quiet、改为 loglevel=7 并添加 printk.time=1、initcall_debug，记录初始化函数耗时。输出限制 512 KiB，超限或未知执行结果使批次失败，不重放同一工作。rootfs、内核、guest、普通运行参数及生产宿主均不修改。

该诊断绕过公开 API，只用于定位内核或 PID1 之前的等待。日志输出会增加耗时，不作正式启动分位数或发布门禁证据。即使某项 initcall 较慢，也须按其具体代码/硬件依赖设计修正，再以正常日志级别和真实 API 做有界对照。不能直接删驱动、关闭 CPU 防护或把计时起点后移来满足门槛。

Linux [参数文档](https://docs.kernel.org/admin-guide/kernel-parameters.html)和 [i8042 驱动源码](https://github.com/torvalds/linux/blob/master/drivers/input/serio/i8042.c)供解释驱动参数使用；当前上游代码不是已安装内核的精确源码，最终以实际内核配置和启动日志为依据。

## 验证与清理

先完成[自评审](../../PUBLIC-QUALIFICATION.md#private-evidence)，再编译 opt-in KVM 测试和冻结工具/候选摘要。使用单次 durable worker、全局验证锁和独立 fixture；启动前停止本 fixture 的 API/launcher，确认没有池或租户 VM 并发。实际 ping、prepare、绑定命令和输出均须验证；进程回收、测试 cgroup、安装重复副本及临时凭据在 finally 清理。只发送已授权的 SSH/本项目测试操作，不触碰其他服务或全局 swap。

此轮不重建 guest 或完整离线包，不重复完整功能回归。仅当定位结果支持产品改动时，才新增相应设计、定向功能/故障验证和受控性能对照；冻结候选后集中完整 CI、双架构离线/QEMU 与 KVM 回归。

## 实际结果

有界诊断与后续四模式对照完成，见[验证记录](../../PUBLIC-QUALIFICATION.md#private-evidence)。实际内核没有产生预期 initcall 耗时记录；日志时间线显示键盘注册之前约 445 ms 的空档。随后按 [ADR-0094](0094-headless-linux-ps2-probing.md)进行参数干预，详细日志中的键盘注册及其长等待消失；正常日志的单 VM 对照为 699.348→327.133 ms。该流程用于归因，不提供正式性能通过结论。
