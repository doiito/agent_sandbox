# ADR-0059：Linux guest 代理领用、签名能力和冷/热路径

状态：Accepted（Linux子集已通过[rc66验收](../../PUBLIC-QUALIFICATION.md#private-evidence)）；日期：2026-11-04；需求 NET-01、SEC-02、PERF-03、REL-04、API-02、API-03。

沿用 ADR-0058 已验收的宿主代理核心，接通实际 Linux guest。不是用 host fetch 替代 guest 代理，也不因此关闭 OSv/private/SOCKS/端口预览等原跟踪事项。

## 签名能力与接口

增加 `osv-sandbox-artifacts/v3` Linux profile，显式 backend=firecracker-linux、排序后的有限 agent_features（首项 `vsock-proxy-v1`），不接受 OSv 字段/模块路径，保留 v1 Linux 与 v2 OSv 验证规则。签名摘要仍绑定真实 kernel/rootfs/VMM/jailer/SBOM，manifest 摘要也是池 key。旧模板不会因此自动广告新能力。构建产物与真实 guest 探测都要验证能力，不以配置字段代替实现。

`network=none` 缺省不变。显式 `proxy` 只接受 Linux 新签名能力和固定 egress socket。API 先核对当前租户出网策略及服务支持代理，SDK 检查同一 live capability，未授权/未配置/停服时拒绝，不回退成直接联网。代理只在 root launcher 内以可信 tenant/VM/lease 元数据打开宿主核心入口；guest 不接收租户 Bearer。

MCP 仅使用 live capability 校验参数和公开限额，不持有 launcher 私有 socket 路径。请求参数校验与部署校验分开；API/manager 继续执行完整部署校验和授权。会话网络模式在创建时固定，session exec 不允许悄悄改变它。

## 冷启动、warm 领用与回收

guest 代理在 127.0.0.1:3128 监听，将每个 TCP 连接通过 CID 2、vsock port 5001 转到本 VM 的 `agent.vsock_5001`。无 NIC。仅代理模式提升 lo，命令缺省设置大小写 HTTP_PROXY/HTTPS_PROXY 和空 NO_PROXY，调用方可覆盖环境但不能绕过宿主无 NIC/目标策略。guest 服务并发有界，超时/EOF 关闭两侧，不增添动态库或外部代理程序。

冷启动在已验证模板的 boot args 显式给 `agent.proxy=5001`，launcher 创建本 VM listener 后才开始执行用户命令。session 用自身 session ID 作为 lease；job 用控制面生成的 job ID。warm pristine boot 不含租户网络参数，不创建宿主 listener；prepare 明确携带 network=proxy 后启用 guest loopback，host 完成 claim 验证、创建专属 listener，再向调用方交付。nonce 不进日志，已领用 VM 从不回池。

宿主 listener 由对应 vmInstance 持有，文件权限仅该 Firecracker 的独占 UID，接受连接时验证实际 SO_PEERCRED UID。使用打开的 jail 目录 FD 缩短 Unix 路径，目录 FD 活到 listener 退出。每 VM 转发并发有界；egress 再按全局/租户配额执行。转发不在 launcher 解析或改写用户 HTTP。

Destroy 先取消网络并同步等待所有转发、listener 退出，再移除 VM/cgroup/目录并归还唯一 UID。超时、session TTL/关闭、API EOF、launcher 停止统一回收；续租仍受原 VM 硬期限约束。并发启动与 Destroy 使用原 bootMu，同一 VM 不允许第二次安装网络权限。停掉 egress 后在途连接关闭，后续连接失败且不影响无网 VM/文件工作流。

## 自评审与验证策略

先核对 guest lo ioctl、vsock CLOEXEC/期限、线程与 fd 上限，及 listener 创建/取消/WG 顺序。重点是实际授权、身份和回收，普通安全不扩大成新的全面审计前置。

定向测试后冻结候选，一次完整 CI。重编 musl+mimalloc 双架构 guest 和 rootfs，编译产物/依赖保存在项目；冻结后运行实际 ARM64 QEMU 和 x64 同包 KVM cold/warm job/session。验证 HTTP/HTTPS、拒绝目标/租户、默认 none、跨 VM UID、取消/TTL/续租/服务停止、池补充及零残留。受影响 API/session/SDK/pool 核心矩阵在候选执行一次，失败保留证据并退役夹具，不为纯文档重复运行实机矩阵。

Linux guest 本批的部分通过不能证明 NET-01 整体、全部原目标或原性能/内存门禁完成。发布前继续保留已验收 rc64 回滚包；仅清理确认结束且证据归档的构建/测试副本。
