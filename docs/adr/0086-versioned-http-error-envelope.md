# ADR-0086：版本化HTTP路由错误与错误信封

状态：Accepted（设计；实现与验收分别记录）；日期：2026-11-10；对应API-01、QA-01、QA-03、OBS-01。

## 问题

当前业务处理器使用JSON错误，但ServeMux生成的404/405仍是纯文本。未知路径、已知路径的错误方法与业务拒绝因此具有不同格式；路由拒绝也未显式向已有OTLP观察记录HTTP状态。补齐这部分是统一REST/gRPC契约的一个实施步骤，不表示gRPC或完整请求/响应schema已经实现。

## 决策

版本化控制API的错误信封继续为`{"code":"...","error":"..."}`，用公开Go类型和离线JSON Schema描述，不改为嵌套错误，也不改变已有业务错误码。`code`供程序判断，`error`为可变化的说明；新错误码允许增补，客户端必须能处理未知码。v1继续只返回`error`字段。HTTP 200中的任务失败是任务结果；ready/doctor健康报告和浏览器preview代理响应保持各自契约。

认证保持在路由判断之前，未知路由不绕过Bearer认证。版本边界为`/v2`及`/v2/`子路径，`/v20`不是v2。认证通过后，无匹配路径返回404/`not_found`；方法不匹配返回405/`method_not_allowed`，保留标准库计算的完整`Allow`头（包括GET隐含的HEAD）。不回显路径、query、请求体或凭据。底层HTTP解析、TLS握手和`OPTIONS *`仍由net/http拥有，不将协议层错误冒充应用JSON。

使用ServeMux公开`Handler`接口识别无注册pattern的内部处理器，仅在这种情况下以丢弃body的轻量writer读取内部生成的状态/Allow，再输出JSON。内部重定向仍交给ServeMux；不复制其路由、CONNECT或escaped-path规则。所有实际业务处理器仍经`ServeHTTP`设置Pattern/PathValue，获得原始ResponseWriter，不包裹SSE、Hijacker、101和ResponseController。代价是已注册请求增加一次路由查询；不据此声称性能无影响，原启动/吞吐门禁继续独立验收。

路由拒绝显式调用已有状态观察，OTLP仍只记录有界方法及`unmatched`路由名，不加入原始URL。此处遥测不是root持久审计；OBS-02剩余需求保持。

## 验证与回归

先增加回归并保存旧代码404/405失败，再修复。检查全部注册路由的错误方法与Allow；覆盖v1/v2边界、认证先行、HEAD、CONNECT、path清理重定向、encoded slash、wildcard PathValue及不调用backend。真实mTLS HTTP/1.1与HTTP/2检查线上格式、HEAD无body和未知客户端拒绝；schema用项目内固定jsonschema依赖离线校验并含反例。检查OTLP实际导出状态和敏感哨兵。

通用dispatch影响所有控制路由，因此完成一次受影响Go包race/vet及现有端口/preview/SSE集成，随后双架构静态编译；文档追加只做链接/矩阵检查。新候选冻结时再做一批完整CI、ARM QEMU和指定机同包KVM，不把旧rc80包冒充包含此次修复。原性能、64MiB、其他运行时、gRPC/完整schema和40项总目标不关闭。

依据：[当前Go 1.24.2 ServeMux接口](https://pkg.go.dev/net/http@go1.24.2#ServeMux.Handler)及项目所用`/usr/local/go/src/net/http/server.go`；[JSON Schema 2020-12](https://json-schema.org/draft/2020-12/json-schema-core)。

## ADR0087补充

后续完整路由核对发现推理错误已有可选invocation_id，上一轮通用错误说明遗漏了这个扩展。上面的闭合两字段schema只适用于通用错误，不适用于带调用身份的推理错误；按[ADR0087](0087-offline-rest-wire-contract.md)保留字段并单独建模，原实际writer与旧schema冲突证据保留。部分legacy v1子系统也会返回code/error，完整端点schema声明相应union，不追改原业务行为。
