# ADR-0002：宿主强制隔离与可取消的任务链路

状态：Accepted；日期：2026-10-29。对应 R1/R2/R4/R5/R7/R8，需求 SEC-01～SEC-06、LIFE-01～LIFE-03。

## 背景与边界

Guest（包括 agent、输出、日志、自报指标）均属于不可信输入。OSv 应用可破坏 guest 内核，guest syscall 策略/隐藏符号只能减面。Host root、KVM/VMM/固件漏洞不在本层能够完全防御的范围，补丁和安全评审仍属上线工作。

## 决策

每任务全新 VM；只读签名根盘、独立受限 scratch/只读 input、默认无 NIC、无宿主共享目录。jailer 的 chroot/seccomp、任务独立身份和 cgroup v2 CPU/memory/swap/pids/io 为强制边界。公开 API 非 root，仅 root launcher 管理 VM，私有 Unix socket 校验 SO_PEERCRED，mTLS + tenant bearer + 配额控制入口。

取消必须贯穿 HTTP context → LauncherClient 关闭 socket → launcher EOF → Manager 杀死 VMM 进程组 → 回收目录/cgroup → 释放身份/配额。任何阻塞 socket I/O 必须同时受 context 取消和硬 deadline 控制；只有 DialContext 或固定 SetDeadline 不足以实现请求取消。超时、调用方取消和正常失败应可区分。清理失败须有证据，不允许静默宣称零残留。

生产进程的配置文件是决定 `production`、制品公钥、入口策略、launcher socket 与 TLS 的根信任输入。launcher 和 API 在接受 `production=true` 配置前，必须验证配置文件及原始路径的每一级目录均由 root 拥有、不可被组或其他用户写入，且路径不含符号链接。正式 API 启动单元还必须显式要求 `production=true`；若配置被替换成诊断模式，应在监听前拒绝启动，而不是退回进程内 manager。开发诊断命令不使用这个强制开关。

Linux 的结果权威只来自 vsock 交换返回的有界、版本和 job ID 绑定 envelope；串口仅用于诊断，不能因为串口恰好打印合法前缀而接受成功。OSv 当前串口通路保留为诊断基线，原生 vsock 和恶意输出用例通过前不得晋级生产。串口不能挤占 vsock 结果的存储预算，所有来源的输出均受上限约束。

快照/warm pool 默认关闭；不复用运行过用户代码的 guest。未来 pristine 快照须另行验证熵、唯一标识、设备/连接重置、时钟及跨租户无数据残留。网络代理在 host 实施目标 IP、解析/重绑定、redirect、IPv6、DNS/SNI/ECH、协议和审计约束，未实现前仅接受 network=none。

## `network=none` 真机验收设计（2026-10-30 补充）

在隔离的已签名 Linux release fixture 中，先验证已认证能力未广告 egress，再从真实 VM 内检查网络接口、IPv4 路由及 IPv6 路由。明确从 guest 发起对元数据地址、宿主地址和同网段网关的限时 TCP 连接；三者必须均不可达。用受认证 API 提交 `network=proxy` 与 `network=all`，必须在任务准入前返回 400，并保持工作目录和任务 cgroup 为空。测试本身必须确认所用 `busybox nc` applet 存在，避免缺少探测工具造成假阳性。宿主上的 API/launcher 使用 `PrivateNetwork=yes`，以证明结果不依赖服务器出网。若未来增加 host egress proxy，本验收需按显式能力版本调整，不能把当前无 NIC 模式静默放宽。

## 双租户配额真机验收设计（2026-10-30 补充）

在隔离 fixture 中配置两个独立 bearer 租户、全局并发 2、每租户并发 1；A 的 token bucket 使用 burst 3 和低速补充，B 保持高配额。先启动 A 的长任务，再提交 A 第二个任务，必须返回 429；同时启动 B 的任务，必须进入另一台 VM 和不同 jail UID。A、B 完成后 A 第三个任务应成功，第四个因 token 耗尽返回 429；B 后续任务仍应成功。每个阶段检查真实工作目录、VM 进程和 cgroup，并在全部结束后检查零残留。这分别证明并发阈值、速率阈值和租户之间不会共用 token bucket 或身份。

## 取舍和参考

冷启动及每任务 staging 成本高于复用，换取可解释的生命周期和隔离。vsock 的 job ID 仅绑定任务，不证明 guest 计算诚实。参考：[Firecracker production host](https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md)、[vsock](https://github.com/firecracker-microvm/firecracker/blob/main/docs/vsock.md)、[snapshot](https://github.com/firecracker-microvm/firecracker/blob/main/docs/snapshotting/snapshot-support.md)。
