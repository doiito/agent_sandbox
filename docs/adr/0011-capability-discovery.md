# ADR-0011：可认证的后端能力查询

状态：Accepted；日期：2026-10-29；需求 CAP-01、API-01、LIFE-03、OSV-02。继承 [ADR-0001](0001-workload-and-evidence.md) 的 OSv/Linux 分流和 [ADR-0004](0004-capabilities-and-contracts.md) 的版本化契约。

## 决策

增加需租户 token 鉴权的 `GET /v1/capabilities`，返回 `osv-sandbox-capabilities/v1`。响应明确声明实际 backend、工作负载种类、诊断或生产阶段、guest 结果协议、经签名模板的原始 manifest SHA-256 与协议、租户可用入口、已实现方法和限制。暂不支持的 cwd、文件工作区、网络出口、流式输出及 pause/snapshot/port 能力以 `false` 明示。环境变量仅在 [ADR-0025](0025-osv-native-environment.md) 的 OSv 签名 agent feature 存在时声明，stdin 仅在 [ADR-0026](0026-osv-native-stdin.md) 的签名 feature 存在时声明；其他模板为 `false`。Linux 才声明只读输入文件支持；OSv 只声明固定签名模块执行，不把上游可运行语言的宣传当作已验收模板。

root launcher 是生产配置和已签名模板的权威来源。能力报告由同一个 manager 构造，通过版本化 Unix RPC 返回给非 root API；API 再按已认证租户的入口策略过滤。诊断 API 直接从其 manager 构造。API 不从另一份本地配置推断后端，避免配置漂移。查询失败返回 503，协议不匹配拒绝；未认证返回 401。报告是静态支持范围，实时可用性仍以 `/readyz` 和 `/v1/doctor` 为准。

当前 `/v1/jobs` 保持兼容；[ADR-0012](0012-explicit-template-selection.md) 已定义单模板 `/v2/jobs` 的显式绑定。多模板路由和热切换仍未实现。此能力查询不打开 OSv 生产门禁，也不宣称 SDK/MCP、文件、网络或快照已交付。

## 自评审

| 风险 | 约束 |
|---|---|
| 报告其他租户可用的模块路径。 | API 对报告入口按租户策略求交集；无 token 不返回配置。 |
| API 本地推断与 launcher 实际签名模板不一致。 | 能力通过现有 SO_PEERCRED 保护的 launcher RPC 获取；manifest digest 从已验签的原始字节生成。 |
| 布尔值过度承诺运行时兼容。 | 仅声明代码中存在且已有相应测试的能力；未认证 Python/Node/JVM 模板不列出。 |
| 能力报告被误当作健康探针。 | 契约只描述支持范围，不携带动态 ready；保留独立健康和 doctor 接口。 |
