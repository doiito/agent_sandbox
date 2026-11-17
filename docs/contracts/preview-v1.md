# Authenticated preview v1

状态：宿主API/HTTP/WebSocket核心已完成[组件验收](../../PUBLIC-QUALIFICATION.md#private-evidence)，Python/Node与MCP授权接口及离线手册已完成[组件验收](../../PUBLIC-QUALIFICATION.md#private-evidence)。[rc75离线候选与同包VM功能验收](../../PUBLIC-QUALIFICATION.md#private-evidence)通过，正式发布继续等待原性能及其他门禁。此前rc74不包含端口/预览功能。设计见[ADR-0080](../adr/0080-session-port-relay-and-preview.md)，底层使用[原生端口通道](port-tunnel-v1.md)。

## 配置与来源

生产配置可选preview，缺省关闭：

```json
{
  "preview": {
    "listen": "0.0.0.0:8444",
    "origin_base": "https://preview.example.test:8444",
    "api_origin": "https://api.example.test:8443",
    "cert_file": "/etc/osv-sandbox/tls/preview.crt",
    "key_file": "/etc/osv-sandbox/tls/preview.key"
  }
}
```

这是合并到完整配置的片段。需要该DNS后缀的通配解析，以及有效且覆盖`*.preview.example.test`的证书；listen与API分开，DNS后缀不能包含控制API hostname。生产路径沿用root可信文件检查，密钥不得对其他用户开放。预览使用TLS 1.3、HTTP/1.1，浏览器不携带API客户端证书；控制API继续使用mTLS/Bearer。主进程在开始服务前绑定两个监听器，任一个绑定失败都会回收另一个。

租户需显式允许目标端口并启用ports.preview，例如：

```json
{"ports":{"allowed_ports":[{"from":3000,"to":3099},{"from":8000,"to":8099}],"max_concurrent":8,"preview":true}}
```

API和root launcher独立加载策略，模板必须是具备port-forward-v1的签名Linux v6。3128始终拒绝。只有入口已配置、签名/端口能力及租户策略均允许时，API报告features.port_preview及相应方法；原v4/v5和OSv不隐式获得能力。

## 控制操作

调用者先生成24位小写hex的preview ID：

- POST `/v2/sessions/{sid}/ports/{port}/previews/{preview}`，body仅`{"ttl_ms":300000}`，ttl_ms为1000..300000；成功201。
- GET `/v2/sessions/{sid}/previews/{preview}`，返回200的当前授权元数据。
- DELETE 同一路径，返回200及撤销后的元数据；停止新建策略和速率额度不妨碍查询/撤销。

元数据protocol为`osv-sandbox-preview/v1`，包含id、session_id、port、origin、created_at、expires_at和status。status为active、revoked、expired、session_closed、server_closed。只有创建响应额外包含bootstrap_url，后续GET不重发secret。未知子授权使用preview_not_found，与父session缺失区分。DELETE确认的是URL授权撤销；guest连接的实际清理由原root端口门禁另行确认。

每session最多8份活跃授权和32个不可重用ID，服务最多1024份活跃授权。重复创建返回409，额度429；没有端口能力501，策略拒绝403。创建不会拨号或创建新VM。每份授权另外生成随机hostname，调用者不能选择旧origin。期限取请求TTL和session当前剩余租期的较小值；后续续租不延长这份授权。

创建结果未知时禁止重放POST。用原ID查询/撤销，然后为新授权选择新ID；丢失的bootstrap secret不能恢复。不同授权的hostname、cookie摘要与tenant/session/port绑定均独立。

## 浏览器授权

SDK 的 Python `session.ports.create_preview(port, preview_id=..., ttl_ms=...)` 与 Node `session.ports.createPreview(port, {previewId, ttlMs})` 返回授权句柄。句柄的 created 元数据只在创建成功时包含 bootstrap_url，可通过 bootstrap_url/bootstrapURL 属性取出；info/revoke 不恢复 secret。`session.ports.preview(port, id)` 引用既有授权，不创建或续期。创建错误保留 exception.preview/error.preview；结果未知时不重放 POST，不自动撤销或补建。句柄默认打印只显示 ID/port。

MCP 提供 sandbox.preview.create/info/revoke，参数均为 session_id、preview_id 和 port，create 另外接受 ttl_ms。授权归 API 会话所有，不进入 MCP 本地端口传输表，MCP 断线及 RPC 取消不自动回滚。info/revoke 使用既有独立控制槽，不依赖新建目录；创建仍查 owner 会话实际能力。响应校验协议、ID/SID/port、HTTPS origin、固定状态、纳秒精度期限与创建专用 URL；查询拒绝重发 secret。离线包的 docs/PREVIEW.zh-CN.md 说明配置、内网 DNS/TLS 及调用方法，并由原签名文件清单覆盖。

bootstrap_url使用`/.osv/authorize?token=<256位随机secret>`。正确GET只可使用一次，服务将其换成新的随机`__Host-osv-preview` Cookie，并303跳转到`/`，同时设置no-store和no-referrer。Cookie为Secure、HttpOnly、host-only、Path=/、SameSite=Lax。服务只保存摘要，不记录完整URL、secret或cookie值。`/.osv/`为内部保留路径。

后续应用请求由此Cookie认证；Cookie不能用于另一份授权。非空Origin必须与当前授权origin相同，跨站非安全请求及WebSocket拒绝。内部Cookie、Proxy-Authorization、伪造Forwarded/X-Forwarded/X-OSV头不会到达guest；识别到本服务控制Bearer时移除Authorization，其他普通应用认证可以保留。guest的扩域Set-Cookie、保留Cookie名和跨域授权响应头被过滤；普通host-only应用Cookie可以使用。响应固定no-store、no-referrer和Origin-Agent-Cluster。

每份授权是独立origin；这些规则不改变浏览器的公共后缀规则。控制授权依赖__Host Cookie及每grant摘要，不能把后端Set-Cookie过滤解释为禁止任意页面脚本写父域普通cookie。

## HTTP、WebSocket与退出

应用HTTP根路径及查询保持，目标固定为原VM的loopback端口。请求体最多8MiB，响应逐块传输并flush，不缓存整个响应。原生连接每方向64MiB总量和授权/VM期限继续生效。支持上传与响应同时进行、流式响应及标准WebSocket二进制转发。仅允许WebSocket的101升级，不提供CONNECT或TRACE代理。

HTTP在同一授权内复用连接，最多8条上游连接；每授权最多16个、服务最多256个在途请求。独立HTTP请求可以复用原TCP，不会自动重放一个已发送但结果未知的HTTP请求。应用返回连接错误时使用现有端口错误状态或502；已经开始的响应被截断时关闭传输，不伪装为完整成功。

WebSocket保留两边已缓存的首帧，并按固定缓冲双向转发。任一方向结束、撤销、授权到期、session关闭或API退出都会关闭两边并等待复制结束。撤销还关闭空闲复用连接及未完成的native open；原guest终态/销毁失败继续保留物理额度，不能因为浏览器断开就直接返还。

本地受控CA/解析不等同于nas.deployment.example证书验收；该项按用户决定延期。原性能和内存门槛不因预览功能增加而降低。
