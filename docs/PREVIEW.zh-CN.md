# 离线部署的浏览器预览

预览把同一 VM 内的 loopback HTTP/WebSocket 服务转成带授权的 HTTPS 地址。服务运行不下载软件或调用外部网关。管理员需要提前提供本地 DNS 或 hosts 解析、通配 TLS 证书及密钥；离线客户端仍需其 Python 3.10+ 或 Node.js 20+ 解释器。SDK 本身无第三方依赖。

当前 rc74 包不包含端口/预览；只有后续通过整包验收并启用端口能力的候选才支持本页功能。关闭 preview 配置时，既有控制 API 照常使用。签名 Linux v6 模板必须含 port-forward-v1；OSv 和旧模板没有此能力。

## 管理员配置

将以下字段合并到完整生产配置，API 与预览必须使用不同监听器。浏览器入口使用 TLS 1.3、HTTP/1.1，不要求浏览器提供客户端证书；控制 API 继续使用原 mTLS 与 Bearer。

```json
{"preview":{
  "listen":"0.0.0.0:8444",
  "origin_base":"https://preview.internal.example:8444",
  "api_origin":"https://api.internal.example:8443",
  "cert_file":"/etc/osv-sandbox/tls/preview.crt",
  "key_file":"/etc/osv-sandbox/tls/preview.key"
}}
```

为 `*.preview.internal.example` 配置到此主机的解析和匹配的有效证书；浏览器必须信任签发 CA。解析和证书可以完全由内网提供。preview 后缀不能包含控制 API 主机名。生产文件应放在项目部署目录或明确配置的持久目录，密钥不能向其他用户开放，不能放在 `/tmp`。API 与 root launcher 的租户策略都必须包含目标端口和 preview 许可，例如：

```json
{"ports":{"allowed_ports":[{"from":8000,"to":8099}],"max_concurrent":8,"preview":true}}
```

3128 不可转发。API 能力报告的 `features.port_preview` 为 true 后才能创建；不会因增加本配置给旧模板补出端口能力。主进程启动时先绑定两处监听器，任一失败都会回收另一处。

## 应用调用

先通过原有会话命令，在 VM 的 `127.0.0.1:8080` 启动 HTTP 服务。使用已认证的原生 SDK 会话：

```python
grant = session.ports.create_preview(8080, ttl_ms=60000)
url = grant.bootstrap_url  # 给获授权的浏览器打开一次；不要写入日志
metadata = grant.info()    # 不再返回 bootstrap secret
grant.revoke()            # 关闭此 URL 的授权和在途代理请求
```

```javascript
const grant = await session.ports.createPreview(8080, {ttlMs: 60000});
const url = grant.bootstrapURL;
const metadata = await grant.info();
await grant.revoke();
```

MCP 提供 `sandbox.preview.create/info/revoke`。三者参数均为 `session_id`、`preview_id`（24 位小写 hex）和 `port`；create 可加 `ttl_ms`。创建结果直接包含 `bootstrap_url`。授权归 API 会话所有，MCP 退出不会撤销；可从另一个 MCP 进程按同一 ID 查询或撤销。info/revoke 有独立控制槽，不依赖新建模板目录可用。

创建 POST 仅发送一次，网络失败时禁止重放。SDK 异常上的 `preview` 句柄保留已知 ID；也可用 Python `session.ports.preview(8080, preview_id)` 或 Node `session.ports.preview(8080, previewId)` 取得句柄。这些引用只用于 info/revoke，不创建连接或续期。若原创建已成功但响应丢失，GET 也无法恢复 bootstrap secret；应撤销后用新 ID 创建。

## 生命周期与限制

浏览器打开一次性地址后，入口以 Secure、HttpOnly、host-only Cookie 认证并跳转到 `/`。每份授权有独立随机 hostname、Cookie 和来源。HTTP、流式响应、上传及 WebSocket 均经过原生端口通道；目标不能指定为宿主或其他 VM。控制凭据和内部 Cookie 不转发给应用。

TTL 为 1000..300000ms，且不超过创建时会话的剩余租期。会话续租不会延长旧授权。每会话最多 8 份活跃授权、32 个不可重用 ID；每授权最多 16 个在途请求、8 条复用 TCP 连接，请求体最大 8MiB。底层连接每方向 64MiB 总量限制继续生效。

撤销、到期、会话关闭及 API 退出均停止授权并关闭代理传输。DELETE 返回的是授权撤销状态，guest 连接的物理清理仍由端口生命周期管理。普通 HTTP 请求或创建操作结果未知时不自动重放。授权 URL 是访问凭据，请只交给获授权的浏览器；不要记录完整 URL 或 Cookie。
