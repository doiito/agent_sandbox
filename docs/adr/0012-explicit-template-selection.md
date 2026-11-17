# ADR-0012：任务请求绑定后端与签名模板

状态：Accepted；日期：2026-10-29；需求 CAP-01、API-01、SEC-05。继承 [ADR-0004](0004-capabilities-and-contracts.md) 和 [ADR-0011](0011-capability-discovery.md)。

## 背景

`GET /v1/capabilities` 已提供实际 backend 与签名 manifest 摘要，但旧 `POST /v1/jobs` 没有显式选择。客户端查询后若服务滚动切换模板，同一请求可能执行到另一份制品。多模板路由尚未实现，不能用默认入口或隐式 fallback 假装已选择目标。

## 决策

保留现有 `/v1/jobs` 兼容契约，新增 `POST /v2/jobs`。v2 请求必须提供非空 `entrypoint`、`backend` 和 64 位小写十六进制 `artifact_manifest_sha256`，其余任务参数沿用 v1。只有通过签名验证的模板才在能力报告中声明 v2 方法。API 先校验字段形状和租户入口授权；root manager 在真正准入前把选择值与当前 backend、已验签 manifest 的**原始字节摘要**逐字节比较，任何不一致返回稳定的 `template_mismatch` / HTTP 409，不启动 VMM。缺字段/非法格式返回 HTTP 400；签名模板过期或不可用返回 HTTP 503。旧 v1 请求不带选择值时保持原行为，但若带了选择值，也必须同时提供且由 manager 校验，不能形成半绑定。

选择字段经过 Unix launcher RPC 原样传输；launcher 将类型化冲突错误回传 API，不能降级为普通参数错误或悄然切换 backend。v2 错误 JSON 在现有 `error` 字段之外增加稳定 `code`；成功响应保留现有任务结果结构。`GET /v1/capabilities` 的 `methods` 只对已签名模板声明 `POST /v2/jobs`。本次只绑定单个当前模板，不实现模板目录、多版本路由或热切换。

## 自评审

| 风险 | 处理 |
|---|---|
| API 查询与启动之间仍可能发生模板切换。 | 比较发生在权威 manager 的任务准入入口；API 不只依赖自身缓存。 |
| 老版本调用方被强制迁移。 | v1 无选择字段保持兼容；新约束仅对 v2 和主动携带选择值的请求生效。 |
| 失败的选择请求耗费 VM 资源或泄露制品路径。 | 在获取并发槽、创建任务目录之前拒绝；外部错误使用固定 code/message，不回显路径。 |
| API/launcher 升级时错误类型丢失。 | RPC 显式传递 `template-mismatch`，客户端映射为类型化错误；进程集成与真机负向测试覆盖。 |
