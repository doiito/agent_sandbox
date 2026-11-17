# Native port tunnel v1

状态：HTTP/launcher、[v6签名/就绪](../../PUBLIC-QUALIFICATION.md#private-evidence)、[双SDK/MCP](../../PUBLIC-QUALIFICATION.md#private-evidence)和[预览宿主核心](../../PUBLIC-QUALIFICATION.md#private-evidence)组件已验收；预览SDK/MCP包装、新实际载荷与同包验收尚未完成。当前rc74包不声明此能力。设计见[ADR-0080](../adr/0080-session-port-relay-and-preview.md)，HTTP范围见[HTTP验收](../../PUBLIC-QUALIFICATION.md#private-evidence)。

## 建立连接

`POST /v2/sessions/{id}/ports/{port}/connections/{connection}` 使用当前session的API认证；生产入口同时使用原mTLS要求。`id`和`connection`为24位小写十六进制，port为1..65535的规范十进制，不带前导零。调用者生成connection，ID固定绑定port并在session内保留，重复POST不会重放拨号。内置proxy端口3128始终拒绝。

请求必须为HTTP/1.1，Connection包含upgrade token，Upgrade为`osv-port/1`。body为限制对象：

```json
{"max_bytes":67108864,"timeout_ms":300000,"idle_timeout_ms":300000}
```

三个字段均为正整数。max_bytes每方向独立计量且不超过64MiB；两个时间不超过300000毫秒。实际期限仍受原session限制，不能通过新连接延长VM租期。Content-Length必须明确，为编码后body的实际字节数，范围1..4096；不使用chunked上传。body不接受ID、目标地址或额外字段。

root完成准入并打开guest loopback TCP后回复101，包含以下字段：

```text
Connection: Upgrade
Upgrade: osv-port/1
X-OSV-Session-ID: <original session ID>
X-OSV-Connection-ID: <original connection ID>
X-OSV-Port: <original port>
Cache-Control: no-store
```

客户端应核对状态、Upgrade和三个身份字段。HTTP/2返回426，应为该通道显式选择HTTP/1.1；普通JSON API可以继续使用其现有传输。根TCP为同一VM的IPv4 loopback，不提供宿主地址或DNS选项。

## 数据帧

101后每帧为1字节类型、4字节大端无符号长度、该长度的body。DATA是任意二进制；控制帧和数据可以分片或合并发送，不要求一帧对应一次socket读写。

| 类型 | 发送方向 | body |
| --- | --- | --- |
| 1 DATA | 双向 | 1..16384字节 |
| 2 EOF | 双向 | 长度0，仅结束该方向应用数据 |
| 3 CANCEL | 客户端到服务端 | 长度0，结束当前传输；独立DELETE更适合背压期间取消 |
| 4 FINISHED | 服务端到客户端 | 1..4096字节的连接终态JSON |

EOF仅关闭应用TCP的一侧写方向，反向仍可传输。客户端收到EOF后仍应处理FINISHED；若自己的写方向尚未关闭，仍可写DATA再发送EOF。不要用TLS/底层socket的CloseWrite替代EOF帧。重复EOF、EOF后的DATA、空DATA、越界长度或错误方向的控制帧均终止该通道。

FINISHED的字段为 `id`、`port`、`status`、`sent_bytes`、`received_bytes`、`error`，error为null或固定错误码。status为completed、cancelled或failed；completed要求双方EOF完成且计数相符。sent_bytes是写向应用TCP的字节数，received_bytes是从guest写入转发socket的应用字节数，不含帧头；它们不证明应用或客户端已经消费全部数据。

未收到完整FINISHED的断线为结果未确认，不能当作正常结束。若取消中断了写出一部分的DATA，服务端直接关闭该传输，禁止把终态JSON拼进DATA剩余部分；通过原ID另行查询终态。任何断线均不得自动重放已发送字节。

## 查询与取消

同一路径的GET返回200，DELETE接受取消并返回202：

```json
{"session_id":"aaaaaaaaaaaaaaaaaaaaaaaa","connection":{"id":"bbbbbbbbbbbbbbbbbbbbbbbb","port":8080,"status":"cancelled","sent_bytes":0,"received_bytes":0,"error":"cancelled"}}
```

DELETE可先于POST建立已取消占位，使迟到的POST不再拨号。取消ACK可能仍是cancelling，必须等FINISHED或GET的终态才能确认关闭。GET/DELETE不占用新连接槽或速率令牌；新建端口策略收紧后仍可清理原owned session。

每session最多8条活跃连接、256个ID；租户跨session并发还受独立root策略限制。API断开不能直接返还root额度：根服务先确认guest终态；2秒内无法确认时关闭原VM，Destroy失败仍保留额度并触发清理失败门禁。

101前错误是标准JSON `code`/`error`。常见状态为400非法请求、401认证失败、403策略拒绝、404缺失、409已保留/取消的ID、410会话关闭、429额度/速率限制、501模板不支持、502应用拒绝连接、503不可用、504超时。不存在的子连接使用`port_not_found`，父session缺失使用`not_found`；后者不证明物理VM已经清理。101后只发送帧或关闭连接，不追加HTTP错误页面。

## 服务生命周期

端口始终归原session所有。session关闭、租期到期、API通道关闭或明确取消均触发回收；端口连接不能成为新的VM owner。API在root open前登记pending通道，停机关闭准入、取消pending/live并等待handler结束。嵌入使用NewAPI返回handler的服务器，应调用其 `Shutdown(context.Context) error` 再执行普通HTTP Shutdown；生产sandboxd已接入该顺序并等待结束。原session、root确认及VM清理门禁继续生效。
