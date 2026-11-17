# ADR-0030：pristine guest 一次准备协议

状态：Accepted；日期：2026-10-30；需求 LIFE-04、FILE-01、SEC-01、SEC-06、PERF-03。继承 ADR-0018、0029。

## 决策

Linux 预启动 VM 由受信任 host boot arg `agent.pristine=1` 进入独立模式，只接受 `fc-agent/v3`。该模式不能通过 v1/v2 执行租户命令；旧 cold v1/v2 启动方式保持原协议。v3 的状态为 pristine → prepared → 终止，失败进入 poisoned 并关机。准备前仅允许无绑定 ping、shutdown 和一次 prepare；准备后所有请求均携带相同的 24 位小写十六进制 session ID 与 64 位随机十六进制 nonce，响应也须绑定。不能自动重试 prepare，ACK 丢失后销毁实例。

prepare 包括绑定、`mode=job|session`、1–300 秒租期、最多 64 个 input file。路径为 UTF-8 干净相对路径，最多 1024 字节/16 层/每段 255 字节，总路径预算 32 KiB；拒绝重复和文件/父目录冲突，数据总量最多 512 KiB，文件模式只接受 0444，base64 必须规范。host 在领取前校验同一限制，guest 独立复核。

预启动时 `/input` 为新的 4 MiB tmpfs，带 nodev/nosuid/noexec，workspace 是独立空 scratch。初始化仅删除空的 ext4 lost+found，其他已有内容使初始化失败。准备时以目录 FD 和 openat2 不跟随方式写入 root 所有的输入文件；目录设 0555、文件设 0444，再 remount `/input` 为只读并用 statvfs 验证。只在全部成功后设置 prepared 和返回绑定 ACK；失败的半成品不能交给租户。不得修改宿主已挂载的 block image。租期在准备成功时开始，但不得越过从开机计的 600 秒硬寿命及 5 秒回收余量。

job 模式只能执行一次 run，完成即关机；session 模式允许同一绑定内的多条命令/文件操作，关闭即销毁。准备后不允许更改绑定或重建输入。guest 保持 uid/gid 降权、无 NIC、输出/时间边界和整体进程收尾。响应带 guest_state、绑定及剩余租期；host 校验协议、job ID、绑定和预期状态，任何传输/绑定异常使实例不可再使用。

## 验收

先完成自评审；本地测试验证畸形/越界/路径冲突、准备前拒绝、降级拒绝、nonce/ID 绑定、重复准备、截止时间和写入权限。实际 readonly remount 由 ARM64 QEMU 或指定 x64 KVM guest 验证，本地模拟不能证明挂载只读。双架构静态构建后，在隔离 KVM 依次证明 pristine 握手、真实输入只读/noexec、同绑定会话、一次 job、错误绑定及重新准备拒绝，最后执行受影响 CI/回归。该协议通过不等于 pool 调度与性能门禁通过。
