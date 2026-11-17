# ADR-0051：持久命令句柄与有界实时输出

状态：Accepted；日期：2026-11-03；需求 EXEC-01/02、LIFE-01/02、API-01/02、REL-04。

## 决策

会话执行增加后台命令句柄，支持开始、列举、状态/输出续读、等待、取消；HTTP SSE 与双 SDK 逐段输出。命令归属 root launcher 的既有 Session，由会话租期、owner 与 VM 生命周期管理。观察者断连不结束后台命令；显式取消须经 guest 控制通道确认收尾，确认后继续使用原 workspace。API/launcher 控制连接丢失仍销毁 VM。旧同步命令接口兼容。

沿用每 VM 一条执行中命令的资源模型，不新增宿主 shell 或把 guest 文件当可信退出码。guest stdout/stderr 在独立 vsock 控制连接上发有序 base64 事件，结果仍用既有 JobResult，并绑定协议、命令 ID 与 pristine nonce；串口不能注入。legacy session 与 pristine session 均支持；一次性 job 保持原行为。取消在该连接发送固定控制帧，guest PID 1 杀掉并回收全部工作负载后发送终态；传输或确认失败则销毁 VM。

输出受既有字节预算及最多 256 条数据事件限制；超限明确截断并继续排空管道，不阻塞超时和回收。发送超时/连接丢失结束工作负载；launcher 保留有界事件日志，最后 32 条命令可重连，自动淘汰完成的最旧记录，不淘汰运行中的记录。每次查询最多 64 条事件，按游标续读，终态仅一次；重复读取不重复执行。已淘汰/其他租户的句柄返回 404。

SSE 在 API 上按游标读取 launcher 日志并及时 flush，慢客户端有写入截止；观察断连保留后台执行。原生 SDK 的后台句柄提供真实事件迭代与最终状态，显式 kill 与 session close 分开。E2B 适配按固定上游方法核对，只声明已完成并在同包双语言 KVM 验证的操作；交互 stdin、环境/cwd、暂停/恢复及更高并发继续单独补齐，不冒充本批完成。

## 验证顺序

先[自评审](../../PUBLIC-QUALIFICATION.md#private-evidence)，再实现 guest→backend→launcher→API→SDK。定向测试覆盖输出早于退出、stdout/stderr 次序、二进制、洪泛、取消后继续使用、句柄重连/淘汰、重复 kill、租户拒绝、断连和 session 租期。冻结一次候选完整 CI，双架构静态构建/离线包、ARM64 无网卡 QEMU 与 x64 KVM 新功能和受影响生命周期回归；OSv 无变动不重复昂贵全矩阵。基本安全保留，扩展审计按 ADR-0049 可选。

[rc53 实施验证](../../PUBLIC-QUALIFICATION.md#private-evidence)完成一次完整本地 CI、双架构包、ARM64 QEMU 31 组、x64 池/API/session、双 SDK v6 及 warm 新路径五项通过。采集序号不承诺跨管道真实写入顺序；原生后台能力不增加 E2B 计分。
