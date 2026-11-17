# 原生 gRPC 控制接口

`sandbox.control.v1.Control` 在同一控制地址上提供 48 个 RPC（源码增加归档 create/read/delete，原 45 项 ABI 保留；新发布包尚待验收）。生产连接使用 TLS、HTTP/2 和客户端证书。除 `Health` 和 `Readiness` 外，调用需附加 `authorization: Bearer <token>`。REST 与 gRPC 使用同一套身份、租户配额、模板能力与 VM 管理逻辑。浏览器 preview URL 使用独立的 HTTP/WS 地址。

## 离线调用

签名包安装目录的 `docs/contracts` 包含客户端生成所需的 schema。`docs/contracts/api/control/v1/control.proto` 是完整源文件，以 `docs/contracts` 为 proto include 根目录。现有客户端可以直接使用 `docs/contracts/control.descriptor.pb`。下面的示例从安装目录执行，客户端机器需已有 `grpcurl` 和部署方签发的证书。

```bash
grpcurl -cacert "$OSV_CA" -cert "$OSV_CLIENT_CERT" -key "$OSV_CLIENT_KEY" \
  -protoset docs/contracts/control.descriptor.pb \
  "$OSV_CONTROL_ADDRESS" sandbox.control.v1.Control/Health
```

把 `OSV_CONTROL_ADDRESS` 设为与控制证书匹配的 `host:port`。对业务 RPC，通过客户端的调用凭据或 metadata 传入 bearer token。使用 `Capabilities` 和 `SessionCapabilities` 查询实际启用的功能与大小限制。单个 protobuf 入站消息上限为 1 MiB，业务操作仍执行各自的限制。

## 数据与状态

- 生成客户端应使用字段 presence 区分缺省与显式的 `0`、`false` 或空值。列表和 map 通过含 `values` 的容器表示，缺省容器与显式空容器各有含义。整数使用 protobuf 的整数类型。动态 provider JSON 使用 `JsonValue`，其 `number` 分支保存 JSON 数字文本。
- 消息的 `bytes` 字段接收二进制数据。在 `grpcurl` 等 ProtoJSON 工具里，这些字段写作 Base64 文本。文件读取结果的 `data_base64` 是 Base64 字符串，客户端读取后解码一次。
- 错误使用标准 gRPC status，结构化详情为 `sandbox.control.v1.ErrorDetail`。自动化客户端读取 `code`、`http_status` 与可选 `invocation_id`。收到推理 `invocation_id` 时，可用该身份关联查询账单。是否执行过有副作用的操作应以业务状态为准。
- `HostDoctor` 和 `Readiness` 的未就绪诊断可返回结构化响应，客户端同时检查 `ready` 或 `status` 和 `osv-http-status` trailer。`osv-rpc-accepted: 1` 是业务分派前发送的响应头，用于提交 gRPC 传输，实际准入和结果由业务响应表示。

## 命令与端口流

- `StreamSessionCommand` 按顺序返回 `output`、`result` 或 `timeout`。客户端依据序号、结果页和 `next_sequence` 继续观察。取消流结束本次观察，取消后台命令使用 `CancelSessionCommand`。
- `OpenPortTunnel` 的首帧为 `open`，携带 session ID、端口和连接参数。收到 `opened` 后发送 1–16 KiB 的 `data` 帧。发送 `eof` 或关闭客户端发送方向后继续读取，直到收到 `finished` 或 gRPC 错误。取消整条流可取消客户端调用或发送 `cancel` 帧。端口策略、总字节数、空闲及总时限由现有会话策略执行。
