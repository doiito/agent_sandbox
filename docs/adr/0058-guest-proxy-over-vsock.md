# ADR-0058：由 VM 生命周期管理的 vsock guest 代理

状态：Accepted（分阶段实现）；日期：2026-11-04；需求 NET-01、POOL-01、SEC-02、OBS-01。

## 功能与结构

保持 guest 无 NIC，`network=none` 为缺省。显式 `network=proxy` 的 Linux job/session 使用 guest 的 loopback HTTP 代理，经 virtio-vsock 到 launcher 创建的每 VM Unix listener，再转发到独立的非 root egress 服务。HTTP absolute-form 请求复用 ADR-0057 引擎；HTTPS CONNECT 为端到端 TLS 隧道。无需 TAP、宿主路由、iptables 或系统额外代理程序，不引入发布时依赖。OSv 代理适配、SOCKS/private 网络仍在原 NET-01 跟踪范围，本阶段不能宣称 NET-01 整体完成。

Firecracker [guest 发起 vsock 连接](https://github.com/firecracker-microvm/firecracker/blob/v1.14.0/docs/vsock.md#guest-initiated-connections)映射到 `uds_path_PORT`，不会直接给 guest 宿主网络。guest 的 HTTP_PROXY/HTTPS_PROXY 环境变量用于常见客户端，忽略代理的程序仍无网卡。

## 权限与生命周期

租户身份继续由认证 API 经已有 root launcher 信任边界提供。egress 私有 Unix socket 额外接受内核验证的 UID 0，只能通过显式开启的 `/v1/guest-proxy` 入口，以固定 tenant/VM/lease 身份升级为一次代理连接；非 root 不能凭自报 tenant 使用该入口，root 也不能凭此跳过普通 fetch 的 Bearer 认证。原 API/fetch 入口保持现有认证。

egress 独立加载同一 root 管理的租户策略并实际执行，guest 数据不能更改身份。launcher 只在完成唯一 VM 领用后创建该 VM 的 listener，校验 Firecracker Unix peer UID，并绑定实际 VM owner/lease。pristine warm VM 无租户 listener；已领用 VM 不回池。Destroy 首先取消网络上下文、关闭 listener 和所有转发，再回收物理身份/目录；job 结束、session TTL/显式关闭、API EOF、launcher 退出均走同一路径。不能只关闭监听而遗留 CONNECT 隧道。续租不得超过原 VM 硬期限。

## 一般安全与可解释边界

HTTP 每个请求按 origin、全部 DNS 答案与固定 IP 校验；客户端自行跟随重定向时每条新代理请求重新验证。代理删除逐跳/代理报头，拒绝 upgrade，单连接只处理一个请求，明确 `Connection: close`。不使用环境代理或自动重试。

CONNECT 只允许 `https` 精确 origin 的显式 host:port；在返回 200 前验证目标和 IP，在真正拨号前从实际客户端 ClientHello 校验可见 SNI，使用 Go TLS 解析器，不自己编写 TLS 语法解析器。仅透明转发捕获的原始字节，不代签证书/终止 TLS，不做无法证明客户端行为的预先 TLS 探测。IP literal 目标只接受空 SNI；域名要求可见 SNI 与目标一致。证书验证由客户端承担，代理不能证明加密后的 HTTP Host/path；允许 origin 必须是管理员信任的服务，不能把此设计宣称为 TLS 解密审计。ECH/无匹配可见 SNI、裸 TCP CONNECT 不支持。

沿用独立全局/租户网络并发和速率桶；读取代理报头、ClientHello、请求/响应与隧道均有大小和总期限上限。隧道字节限额包含 TLS 开销。双向转发一侧错误/EOF、超限、取消会关闭两侧并等到转发协程退出后释放名额；不保留无界连接。启动前/拨号前/结束均审计 tenant、VM、lease、origin、IP、状态、字节与时间，不记录凭据、path/query 或 body；审计失效拒绝新连接。

## 验证和门禁

先实现并验证宿主代理核心与真实 HTTP/TLS/Unix 连接，再接 guest loopback、冷启动与 warm 领用路径。核心测试覆盖 HTTP POST/二进制、HTTPS 真 TLS、SNI 不符、DNS 混合答案、非 TLS、端口/私网/metadata、额度、超限、EOF/取消、服务退出及无租户授权入口。后续 guest 必须通过 x64 同包 cold/warm 真 KVM 与 aarch64 QEMU，证明 none 默认隔离、代理可用、身份不可跨租户、TTL/销毁零网络/VM残留；签名 guest 能力和实际服务可用后才广告 network_egress。普通安全不延伸为本轮全面 CVE/fuzz 前置。

完整原始功能、离线双架构、E2B 分母与性能/内存目标保持原门禁；代理核心单测通过不等于 guest 或最终发布验收。
