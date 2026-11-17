# ADR-0019：host 持有的 Linux session 生命周期

状态：Accepted；日期：2026-10-30；需求 API-02、LIFE-01、SEC-04。继承 ADR-0017、ADR-0018。

## 背景

rc14 guest 已支持同一 VM 的多条命令，但现有 launcher RPC 每次请求执行一次任务并等待 VM 退出。直接在 launcher 中按 session ID 保存 VM，会在 API 进程崩溃后留下未计入租户并发的 VM；把每条命令交给新 VM 则会丢失文件系统状态。

## 决策

使用独立版本 `osv-sandbox-launcher-session/v1` 的**长期 Unix 控制连接**。API 创建 session 时获取并持续持有一个租户并发槽；launcher 在同一连接上创建并持有一个 VM，同时占用全局并发槽和独立 jail UID/GID。连接关闭、API 进程死亡、launcher 停止、显式删除、guest 意外退出或租期届满时，launcher 终止 VM、等待进程退出、清理 cgroup 和工作目录，再释放资源。保留 `job-*` 形式的 lease，以现有启动对账处理 launcher 崩溃后的孤儿。session ID 由控制面生成不可猜测随机值，所有后续命令必须在原控制连接上携带同一 ID 和租户 ID；HTTP 每次重新认证并绑定 tenant，不允许跨租户查询或执行。

正常关闭由 launcher 在完成回收后应答，API 收到应答才释放租户并发槽。若请求取消或连接损坏使应答丢失，API 立即隐藏 session，并额外保留租户槽 15 秒，覆盖 launcher 的最长优雅/强制回收窗口；launcher 在清理失败时保留全局槽并停止新准入。此时重建 session 可能暂时返回 429，客户端应等待而不是把未知结果重试为命令。

对外使用 `POST /v2/sessions` 创建、`GET /v2/sessions/{id}` 查询、`POST /v2/sessions/{id}/commands` 串行执行、`DELETE /v2/sessions/{id}` 终止。创建必须显式绑定已签名 backend/manifest，Linux backend、`network=none`、内存/CPU、初始只读输入和 1–300 秒租期按现有策略验证；其他 backend 明确拒绝。命令沿用租户 entrypoint 白名单、速率桶、参数和 1–300 秒超时限制。API 请求取消时终止整个 session，因为宿主无法安全判定客体命令是否已经产生副作用；客户端可查询 session 状态，不能透明重试。session 自身持有并发配额，命令执行不重复占用同一并发槽。guest v2 仍有 10 分钟和 100 请求的独立兜底上限。

launcher 在创建、执行、拒绝、关闭时写入持久审计，写入失败时拒绝操作并关闭 session。VMM 仅通过经校验的 vsock 结果回报命令状态；串口不作为完成依据。session 结果不计 E2B 兼容，直到固定 Python 和 JS SDK 的同项真机行为测试均通过。

## 验收

CI：协议严格解析、租户隔离、配额持有和释放、取消、超时、意外断连、错误模板、恶意帧和旧 `/v1`/`/v2/jobs` 回归。x64 真机：mTLS→API→长期 launcher 连接→jailer→同一 KVM VM 多次命令、不同租户 404、超额 429、取消/TTL/崩溃回收、审计完整性与零残留。ARM64 继续按用户确认只做编译与 QEMU 功能验收；正式域名证书与生产宿主基线另行门禁。
