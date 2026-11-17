# ADR-0087：完整REST线协议与离线OpenAPI契约

状态：Accepted（实现、rc81本地/ARM及指定机同包KVM验收通过）；日期：2026-11-10；对应API-01、QA-01、QA-03、REL-04。

## 背景与范围

API-01仍缺完整请求/响应schema和gRPC。当前控制面有45条注册路由，另有浏览器preview origin。只描述通用错误不足以支持接口实现、客户端和发布审核：推理错误保留可选`invocation_id`，健康报告、SSE和端口101也各有真实协议，不能套入统一JSON响应。ADR0086的两字段schema仅用于通用错误；本ADR纠正其对推理扩展的遗漏，不删除原调用身份或改写原失败证据。

本步交付全部已注册控制路由的OpenAPI 3.1.1离线线协议，包括45条路由的请求/响应、path/query/header、认证、成功/错误状态、body上限及SSE/端口升级说明。浏览器origin透明代理任意上游HTTP/WS，不虚构固定上游body；以已有preview协议单独引用。gRPC仍是后续独立实施，不用OpenAPI代替。

## 决策

canonical文档放`api/contracts/openapi.json`，处于代码CI触发路径，签名离线包携带相同字节。生成器只用于开发/CI，不增加API运行时依赖、反射路径或请求验证开销。生成器使用实际Go wire类型和显式端点语义覆盖；匿名请求/响应外壳改为具名wire类型，序列化字段及既有行为保持。以源码AST逐项核对实际路由/handler与契约清单，缺项、额外项、handler变更或输出陈旧都使检查失败。

请求与响应schema分开：omitempty不是输入required声明；请求required来自实际语义，默认值/可选null按现有解码和规范化处理。响应按实际JSON字段/tag建模，slice/map的nil、指针的null、嵌入字段和RawMessage单独处理；`InferenceUnits`是十进制字符串而非Go底层uint64，时间是RFC3339字符串。遇到未声明的自定义JSON marshaler拒绝生成，不猜测格式。动态签名能力、租户策略、剩余寿命和配置限额仍由服务端检查，schema以capability引用和说明表达，不把默认配置误写成全局协议最大值。

通用错误仍为code/error；推理端点使用明确的扩展错误schema，允许可选invocation_id，认证/路由拒绝仍可用通用错误。保留错误码增补兼容性。SSE声明text/event-stream及output/result/timeout各JSON data schema；端口POST声明仅HTTP/1.1 Upgrade和101后的有界帧协议，不能暗示普通JSON下载或HTTP/2隧道可用。健康/doctor的503报告和legacy v1错误单独声明。

固定官方OpenAPI元schema及许可证在项目assets，使用既有固定jsonschema/referencing依赖离线验证；禁用网络引用获取。所有内部ref必须存在，operationId唯一，path参数齐全，输入/成功响应根对象不能无类型或任意字段兜底。检查类型形状不能代替实际调用证据，须配套真实处理器/进程响应与协议正反例。

## 顺序与回归

先设计/自评审，再记录旧契约对推理扩展的拒绝及缺完整schema的证据；实现具名wire类型、完整生成器/文档、离线验证与签名包携带。契约定向回归覆盖全部路由清单、未知字段、错误格式、nullable/base64/decimal/time、配置动态值和生成漂移；实际HTTP夹具采集请求/响应以schema校验，SSE/101沿用真实协议验证。

本步改变通用wire类型但不重构业务路由/准入，完成一次受影响Go普通/race/vet、两SDK回归、生成检查与双架构编译/ARM定向功能；冻结新候选后集中做完整CI、整包ARM与指定机KVM。文档追加不重跑昂贵测试，原rc80功能基线保留。原性能/64MiB/其他运行时和40项总目标不关闭。

依据：[OpenAPI 3.1.1](https://spec.openapis.org/oas/v3.1.1.html)、[官方3.1元schema](https://spec.openapis.org/oas/3.1/schema/2022-10-07)、[JSON Schema 2020-12](https://json-schema.org/draft/2020-12/json-schema-core)。

## 实施结果

45个操作/74个schema已纳入canonical CI和两架构完整签名包。完整CI通过后，离线安装器仅有两个文件的必要差异，经实际依赖图、普通/race/vet及两架构静态编译完整补充覆盖；其余CI未重复。实际安装发现并修复嵌套目录在umask 0077下不可被非root读取的问题，双架构实际安装后读取通过。rc81完成实际x64 API、ARM定向8组及完整签名包55组、五模板独立registry和官方Collector7次请求验证，见[本轮验收](../../PUBLIC-QUALIFICATION.md#private-evidence)。本地阶段当时尚未执行指定机原15套KVM；该阶段历史收据保持原值，后续结果见下。

[指定机rc81原15套/516个原命名用例](../../PUBLIC-QUALIFICATION.md#private-evidence)现已通过，每套86项payload与原worker/InvocationID绑定，独立宿主复查零残留。当前支持范围完整功能基线推进至rc81，原本地阶段收据不改写；gRPC、其余运行时和原性能/生产等门禁仍开放。
