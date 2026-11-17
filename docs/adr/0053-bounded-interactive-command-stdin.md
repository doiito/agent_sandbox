# ADR-0053：有界交互 stdin、guest 确认与独立控制

状态：Accepted；日期：2026-11-03；需求 EXEC-01/02、API-01/02、REL-04。

## 需求与固定语义

固定 E2B 2.51.0 源码已随 ADR-0052 核对。commands.run 的 stdin=True/true 创建可写 stdin；commands.send_stdin/close_stdin 按实际 guest PID 操作，句柄有同名委托方法。文本 UTF-8 编码、原始字节不改写；close 显式 EOF；输出断连不关闭输入或杀进程。默认 stdin 关闭，自定义用户/PTY 仍独立待实现。原七项命令分母保留，实际双语言同包 KVM 正反例通过后才计入余下两项。

## 设计

Linux session 的后台启动增加 interactive_stdin 布尔字段，旧同步接口拒绝 true，避免无输入控制的挂起。guest 只在 run_stream 显式启用时创建 ChildStdin 非阻塞管道；复用绑定到同一 protocol/job/nonce 的可信 execution 连接传送有序 stdin 控制帧与确认帧，保留 cancel 帧。

每块最多16KiB、每命令最多1MiB输入及256次事务，单命令最多一个未确认事务。host 和 guest 均校验界限。guest 至多保留一块，非阻塞逐步写入并继续排 stdout/stderr、收取消/断连；确认记录实际 written_bytes，成功表示数据已进入子进程管道，不等于应用已消费。EOF 排在已确认数据之后，关闭写端才确认；重复关闭运行进程的已关闭输入可幂等，写已关闭输入明确失败。程序提前关闭/退出时将未完成事务记失败，不能将排队当作已写入。

launcher 提交事务只入有界槽并立即返回票据，不在会话 RPC 循环中等待 guest。POST /v2/sessions/{id}/commands/{command}/stdin 返回202及序号；GET .../stdin/{sequence} 查询所属命令的有界确认记录。状态 pending/delivered/closed/failed，带 session/command/sequence 绑定和 written_bytes；不保存输入正文到历史或审计。最近32条命令各自最多256份小型回执，旧命令历史淘汰规则保留。

双 SDK 的 send/close 提交后观察票据到完成，等待期限只停止当前等待，不重新提交，不取消工作或控制 owner；已知票据可通过原生 API 继续查询。POST 传输失败未取得票据时结果不确定，只能由应用幂等协议或取消命令处理，不能声称可恢复未知票据。请求结果不确定时不自动重试输入。待确认时额外写返回busy，观察与kill可用；session关闭/租期/owner丢失仍销毁VM。guest输入管道一直不读时保留一块至程序结束/取消/租期，不积累队列。

## 验证与回归策略

先[实施前自评审](../../PUBLIC-QUALIFICATION.md#private-evidence)，再分段帧/UTF-8和二进制/EOF/提前关闭/背压时取消的真实子进程测试；Go桥接/控制/租户/票据和双SDK定向测试。冻结后一次完整CI，双架构静态guest与离线包，ARM64无网卡QEMU及同候选x64双SDK KVM、实际warm新路径。保留原后台/输出回归；OSv未改不重复其完整昂贵矩阵。基本安全沿用既有边界，全面深审继续按ADR-0049可选。

## 实际验收

[rc56](../../PUBLIC-QUALIFICATION.md#private-evidence)双架构离线包、一次完整CI、ARM64 QEMU32组、同包双SDK v8 KVM与实际warm新路径9项通过，真实1MiB输入/EOF与背压取消得到验证。新增两项计入19/34，整体门槛和启动性能仍未达成。
