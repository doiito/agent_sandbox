# v2控制API错误契约

通用应用层HTTP错误返回`application/json`，格式由[离线JSON Schema](http-errors-v2.schema.json)约束：`code`是非空字符串，`error`是说明字符串，通用信封仅这两个字段。推理端点已有可选`invocation_id`扩展，使用[OpenAPI中的InferenceAPIErrorResponseOutput](../../api/contracts/openapi.json#components/schemas/InferenceAPIErrorResponseOutput)，不能用通用闭合schema拒绝或删除该身份字段。按`code`与HTTP状态判断，不匹配说明全文。错误码可以增加，客户端必须保留未知码并给出通用失败；不能将未知码当成功或自动重放变更请求。v1保留只有`error`的旧格式，部分既有子系统拒绝也使用code/error，完整端点契约分别描述。

| 条件 | HTTP | code | 行为 |
|---|---:|---|---|
| 未认证 | 401 | unauthorized | 路由判断前拒绝，含不存在路径 |
| 认证配置缺失或服务不可用 | 503 | unavailable | 不准入新任务 |
| 认证通过，无匹配路径 | 404 | not_found | 固定说明，不回显URL |
| 匹配路径不支持该方法 | 405 | method_not_allowed | 标准库的Allow头保留，GET同时允许HEAD |
| 请求JSON无效 | 400 | invalid_json | 不调用backend |
| 选择器/参数无效 | 400 | invalid_request | 不静默选择另一个模板 |
| 策略拒绝 | 403 | forbidden | 不增加执行权限 |
| 模板身份不匹配 | 409 | template_mismatch | 重新获取能力并由调用方决定后续 |
| 配额/并发/速率达到上限 | 429 | busy | 不承诺请求已经执行 |

子系统的既有细分码继续保留，例如`command_not_found`、`code_not_found`、`file_denied`、`stdin_limit`和`watch_cursor`；本表不将其删减为上述通用码。HTTP 200中的`state=failed`等是已接收任务的结果，不能仅由状态码判断业务成功。`/readyz`和`/v1/doctor`的健康报告、preview代理上游响应以及TLS/HTTP解析错误保持各自协议。HEAD在线上无响应body；`/v2`与`/v2/`后代属于v2，`/v20`不属于v2。

通用错误设计和回归见[ADR-0086](../adr/0086-versioned-http-error-envelope.md)，推理扩展及完整OpenAPI见[ADR-0087](../adr/0087-offline-rest-wire-contract.md)。gRPC及整体API-01验收继续跟踪。
