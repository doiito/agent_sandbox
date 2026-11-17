# ADR-0010：OSv 跨进程预生产验收入口

状态：Accepted；日期：2026-10-29；需求 OSV-01、SEC-06、API-01、QA-02。此决策只定义验收夹具，不开放生产模式。

## 背景

ADR-0008 要求指定 x64 服务器验证 API→launcher→jailer→VM→agent→签名模块。现有 `firecracker-osv` 诊断 API 直接持有 manager，无法验证非 root API 与 root launcher 的进程边界；生产 CLI 则正确拒绝 OSv 后端。ADR-0009 已定义签名 OSv 模板，但诊断配置此前拒绝 `artifact_manifest`。

## 决策

非生产配置只在 `backend=firecracker-osv` 时可选择完整的签名模板声明。manager 使用与生产相同的签名、SBOM、入口及有效期验证；未声明模板的旧诊断仍可运行。生产配置继续只接受 `firecracker-linux`。

在 `tests/osv-preproduction` 提供单一验收二进制，显式选择 `launcher` 或 `api` 角色。启动条件强制非生产 OSv、签名模板、mTLS、租户策略、审计、私有 Unix socket 和指定非 root API UID。root launcher 调用现有 `NewManager`、`ListenLauncher`、`ServeLauncher`；非 root API 调用现有 `LauncherClient`、`LoadAuthenticator`、`LoadServerTLS`、`NewAPIWithAuthenticator`。该二进制不属于离线发布包，不能代替产品 CLI 的生产门禁。

验收机使用独立目录、端口、cgroup 和临时测试证书。两进程均在无路由网络命名空间中运行，完成真实 KVM 的成功、失败、超时、取消、未签名入口、peer UID、审计及资源清理检查。测试密钥不进入正式发行；证据记录精确制品散列和环境限制。

## 评审

风险是测试入口绕过产品 CLI 的 `production=true` 前置条件。将二进制置于 `tests/`、在启动时拒绝 `production=true`、不纳入离线包，并保留配置级 OSv 生产拒绝，可将其限定为验收工具。此工具复用运行时库，但不证明产品 CLI 的 OSv 生产启动路径；该项仍列在 ADR-0008 门禁中。诊断配置本身不具备生产目录所有权及开机恢复保证，压力和独立安全评审仍需单独完成。
