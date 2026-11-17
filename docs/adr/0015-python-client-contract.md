# ADR-0015：零第三方依赖 Python 客户端与显式模板绑定

状态：Accepted；日期：2026-10-29；需求 API-01、API-02、REL-04。继承 [ADR-0004](0004-capabilities-and-contracts.md)、[ADR-0011](0011-capability-discovery.md) 与 [ADR-0012](0012-explicit-template-selection.md)。

## 背景

当前服务有 mTLS、bearer、`GET /v1/capabilities`、`GET /v1/doctor` 和 `POST /v2/jobs`，但客户端仍需手写 curl/JSON。离线部署不能要求目标环境在安装时从 PyPI 获取依赖。模板查询与任务提交之间仍可能发生切换，客户端不能用隐式 v1 回退掩盖 409。

## 决策

提供仅用 Python 标准库的同步客户端，明确要求 HTTPS、系统或指定 CA、客户端证书/私钥和 bearer。客户端不提供关闭证书验证的选项，不在异常或日志中打印 token/私钥。每次未指定模板的任务先查询已认证能力，只在报告声明 `POST /v2/jobs`、有效 backend/manifest 摘要且入口属于租户允许列表时提交 v2；明确指定模板时直接提交，manager 仍是最终仲裁。HTTP 409 `template_mismatch` 是类型化错误，不自动重试、不降级到 v1。旧 v1 只通过显式 `run_legacy` 调用。客户端源码随两个架构的离线包作为受 release manifest 签名的文件分发，Linux profile 的 SBOM 同时记录源码摘要；目标端运行仍须预装 Python 3.10+，不需 pip 安装。

请求和响应有本地大小界限，成功任务保留服务器 `state`、`protocol_ok`、guest 结果，不把 HTTP 200 误解为 guest 成功。`doctor` 在 HTTP 503 时仍返回结构化报告；其他非 2xx 响应映射为含状态和稳定 code 的异常。输入文件只接受调用方提供的字节并由客户端 base64 编码，不隐式读本地路径。未实现的流式、持久文件、网络、快照和 E2B 兼容方法不做同名伪实现。

本 ADR 只定义本项目的原生 Python 客户端；E2B 指定版本的方法清单、分母和 ≥80% 行为兼容、TypeScript SDK 分别验收，不能由本客户端推出完成。

## 取舍

标准库减少离线运行依赖，也意味着目前只有同步调用。任务取消依赖 HTTP 连接断开和服务端取消链路；后续若暴露显式取消 API，需另行版本化。每次任务前查询能力增加一次请求，但避免客户端静默选择另一个模板；调用方可带显式模板跳过查询。
