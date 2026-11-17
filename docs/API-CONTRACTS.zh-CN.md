# 离线HTTP接口契约

安装包的`docs/contracts/openapi.json`是OpenAPI 3.1.1文档，随新版构建完整列出源码注册的48个操作（含新增归档三操作，新包尚待验收），涵盖legacy v1、jobs、sessions、命令/SSE/stdin、文件/watch、代码上下文/执行、模板/能力、受控推理/账单、端口和preview控制。开发目录的[canonical文件](../api/contracts/openapi.json)由实际Go wire类型及端点约束生成，逐项核对源码路由/handler。构建拒绝陈旧schema，再把同一字节纳入离线包的签名payload；目标机使用此文件不需要联网或安装schema工具。

生产控制入口同时要求mTLS和租户Bearer；health/ready仅绕过Bearer，不绕过生产TLS握手。schema不是授权书，调用前应查询认证后的模板或session capabilities。签名特性、租户策略、实时服务、剩余寿命和资源上限仍由服务端核验；默认配置不能作为全局限额。GET也支持HEAD，线上HEAD没有响应body。

通用应用错误为`code`/`error`，v1保留旧错误格式。推理端点可能附加`invocation_id`，表示调用方已知的原调用身份；错误和断线均不授权自动重放。健康报告的503仍是报告对象。HTTP 200中的任务`state`不一定成功，调用方须检查任务结果。TLS/HTTP解析错误不属于应用JSON错误信封。

命令事件通过`text/event-stream`发送，`x-sse-events`分别描述output/result/timeout的JSON data；keepalive注释没有JSON。观察期限和断开观察连接不取消任务，按原ID续查。端口POST仅支持HTTP/1.1 `Upgrade: osv-port/1`，101之后按`x-port-tunnel`描述的有界帧协议传输二进制，不能把流当JSON下载；HTTP/2会被拒绝。preview浏览器origin另用TLS/HTTP1代理应用HTTP/WebSocket，应用自己的响应不是控制API schema。

`components.schemas`区分输入和输出，保留实际可选null、base64、RFC3339时间及大整数计费字符串。`InferenceUnits`用十进制字符串表示uint64，客户端不能先转为IEEE754数再计费。`x-max-request-bytes`是编码后body上限，`x-max-utf8-bytes`和`x-max-decoded-bytes`补充UTF-8/base64字节约束；动态限额以capabilities为准。代码事件的自定义JSON编码由闭合union描述，不会丢掉必需的false或空字符串字段。

开发检查：

```sh
go run ./cmd/osv-api-contract --check
python3 -B scripts/check-api-contract.py
```

生成更新用`go run ./cmd/osv-api-contract`。检查器使用项目内固定官方元schema及已有固定Python验证依赖，禁止网络引用获取。SDK、真实服务行为、ARM及指定机KVM仍需各自验收；OpenAPI不代表gRPC已实现，也不代表原性能或整个项目发布门禁已通过。

## 开发与验收状态

实施与结果见[ADR-0087](adr/0087-offline-rest-wire-contract.md)、[自评审](../PUBLIC-QUALIFICATION.md#private-evidence)及[rc81本地验收](../PUBLIC-QUALIFICATION.md#private-evidence)。完整CI及安装器两文件差异补充、双架构完整签名包、实际x64非root读取与API、ARM完整55组、五模板registry及官方Collector通过。[rc81指定机同包原15套/516项](../PUBLIC-QUALIFICATION.md#private-evidence)已通过，当前支持范围完整功能基线推进至rc81；gRPC、其余运行时和原性能/生产等门禁仍开放，rc80旧有效基线继续保留；本节不进入离线包的独立使用说明。
