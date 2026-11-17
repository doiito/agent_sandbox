# ADR-0020：双语言原生 session 客户端与能力声明

状态：Accepted；日期：2026-10-30；需求 API-01、API-02、REL-04。继承 ADR-0011、0012、0015、0016、0019。

## 背景

rc17 已在真实 KVM 验证 `POST/GET/DELETE /v2/sessions` 和 `POST /v2/sessions/{id}/commands`，但能力响应仍只声明一次性任务，离线包内 Python/Node 客户端也无法使用 session。直接把这些原生方法标为 E2B 兼容会混淆方法签名和行为证据；固定 34 项矩阵要求两语言真实服务端用例才计分。

## 决策

仅当签名清单已配置且摘要有效、后端是 `firecracker-linux` 且支持 v2 guest session 时，能力响应声明 `sessions=true`、`persistent_workspace=true`、`session_max_ttl_ms=300000` 和四个现有 HTTP 方法。OSv 后端、无签名模板和其他诊断模式不得冒充该能力。能力字段描述静态支持，不替代生产 doctor；清单过期仍由实际准入拒绝。

Python 标准库客户端和零 npm 依赖的 Node/TypeScript 客户端增加原生 `create_session`/`createSession`、`connect_session`/`connectSession` 和 session 对象的 `info`、`run`、`close`。创建请求显式绑定签名模板；未传模板时先读取经 mTLS 和 bearer 认证的能力并验证入口可用。session ID 在拼接 URL 前严格校验为 24 位小写十六进制；每次操作重新认证，跨租户的 404 原样传播。命令结果必须绑定请求的 session ID，并满足现有 `JobResult` 严格结构；204 删除响应必须为空，重定向和畸形响应拒绝。传输失败或超时不透明重试有副作用的创建/执行/删除。

session 只在当前 API 进程持有状态的租期内可连接；API 重启会终止 session，客户端不提供虚假的恢复承诺。原生客户端方法不等同于固定 E2B 2.51.0 方法；矩阵分子在专用兼容层、Python/TypeScript 同项真实 KVM 正反用例和候选摘要证据齐备前保持原值。

## 验收

CI：Go 能力不夸大测试、双语言请求/响应/畸形输入/跨租户/超时/删除语义测试、TypeScript 类型检查、离线包 SBOM 与签名覆盖。真机：从已安装包导入 Python/Node 客户端，经 mTLS→API→launcher→同一 KVM VM 连续写读工作区，验证重新连接、租户拒绝、删除与零残留。ARM64 按用户确认只做编译和无网络 QEMU 包功能验收。
