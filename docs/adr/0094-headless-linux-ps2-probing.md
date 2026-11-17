# ADR-0094：Firecracker Linux 不探测无用途的键鼠端口

状态：Accepted（实现及完整功能验收，正式性能仍开放）；日期：2026-11-11；需求 PERF-03、ARCH-01、QA-01/03。

## 依据

[ADR-0093](0093-linux-cold-boot-initialization-probe.md)的实际签名 rc83 guest 在真实 KVM 成功完成 pristine ping、prepare 和绑定命令。详细启动日志最长连续空档为 444.867 ms，结束于 `input: AT Raw Set 2 keyboard` 注册；VMM 到已验证就绪约 1.030 秒，含详细串口日志开销。内核没有输出预期的 initcall 耗时记录，故当前证据是消息时间线，尚不能声称具体函数已被计时。[原始诊断分析](../../PUBLIC-QUALIFICATION.md#private-evidence)

本项目 Firecracker Linux 的租户输入通过 vsock/stdin/代码与端口服务传递，不使用 PS/2 键鼠或图形终端。Linux 官方[参数文档](https://docs.kernel.org/admin-guide/kernel-parameters.html)把 i8042.nokbd/noaux 定义为不检查/创建相应端口；[驱动源码](https://github.com/torvalds/linux/blob/master/drivers/input/serio/i8042.c)在创建键盘端口前检查 nokbd。仍须以实际内核和同配置干预确认收益。

## 决策

Firecracker Linux 的固定启动参数追加 `i8042.nokbd=1 i8042.noaux=1`。保留现有串口、panic/reboot、根文件系统只读、随机源、vsock、pristine 和所有代码/代理/端口参数。没有新增可接受任意内核参数的配置入口，不修改内核、guest、签名格式、CPU 防护、配额或宿主全局配置；OSv 与 QEMU 构造路径不变。

先在同一新诊断二进制中作四个独立新 VM 对照：原参数详细日志、新参数详细日志、新参数正常日志、原参数正常日志。baseline 只在本诊断实例移除新增的两个固定参数；其他参数、资源及协议保持。每次均验证实际 ping、一次准备、精确绑定命令结果和进程/cgroup 清理，输出和实例寿命保持有界。详细日志用于验证键盘注册及长空档是否消失，正常日志只判断是否值得继续真实 API 验收，不作为千次门禁证据。

如果启动失败、键鼠等待没有消失或冷启动仍无实质改善，则保持未验收，继续定位。收益成立后，固定宿主源码和工具链生成新的诊断签名宿主包，真实 mTLS API 验证冷/暖及所影响功能，再集中冻结完整 CI、两架构离线包/QEMU 与指定机 KVM 回归。保留原方案和失败数据；不把单 VM 对照或旧候选成绩登记为当前发布通过。

## 自评审与验证状态

[实施前自评审](../../PUBLIC-QUALIFICATION.md#private-evidence)通过，四模式真实 KVM 对照已完成。正常日志的单 VM 就绪观察为 699.348→327.133 ms，详细日志中的键盘注册与长等待消失，7 项受影响后端检查通过，见[验证记录](../../PUBLIC-QUALIFICATION.md#private-evidence)。其后[rc85 完整功能验收](../../PUBLIC-QUALIFICATION.md#private-evidence)通过同候选完整 CI、双架构离线/QEMU 与指定机 15 套/516+44 个用例，本实现决定接受。千次正式性能仍开放。无键鼠是 Firecracker 后端的用途约束；若将来产品加入物理键盘交互，须重新设计该功能与后端适用范围，而不是开放任意启动参数覆盖。
