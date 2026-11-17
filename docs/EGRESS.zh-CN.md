# 认证网络 fetch 与 Linux guest 代理

`osv-sandbox-egress` 是可选的非 root 静态服务，提供 API、MCP 和原生 SDK 的受控 HTTP/HTTPS 访问。双架构离线包已包含程序、systemd unit 与无凭据配置，目标机无需安装 Go/Node/Python。业务访问需要目标端点可达；离线安装不要求出网。

`network_fetch` 与 guest 的 `network_egress` 分开声明。网络 fetch 不创建 VM，不改变 guest 网卡/路由。新 Linux v3 签名模板支持显式 `network=proxy`，经 guest loopback/vsock 接到宿主 HTTP/HTTPS 代理，仍无 NIC；`network=none` 保持默认。OSv 代理、SOCKS、通用端口转发/private 网络继续实现，不能据此宣称 NET-01 整体验收完成。

Linux guest代理已通过[rc66同包cold/warm及ARM QEMU验收](../PUBLIC-QUALIFICATION.md#private-evidence)。

远程推理按 [ADR-0081](adr/0081-controlled-remote-inference-and-task-billing.md)继续实施。[共享核心与出口服务](../PUBLIC-QUALIFICATION.md#private-evidence)、[主机HTTP/账单命令](../PUBLIC-QUALIFICATION.md#private-evidence)、[双SDK/MCP](../PUBLIC-QUALIFICATION.md#private-evidence)、[guest组件](../PUBLIC-QUALIFICATION.md#private-evidence)及[v7实际镜像/签名](../PUBLIC-QUALIFICATION.md#private-evidence)已验证；完整新包与实际 guest 冷/暖验收继续进行，尚未正式发布。可选出口配置的 `inference` 对象使用 `ledger_directory` 与 `max_tasks`，缺省不启用；生产状态必须放持久磁盘，例如 `/var/lib/osv-sandbox-egress/inference`，不能放 `/tmp` 或 `/run`。unit 的 StateDirectory 管理持久目录，root 控制 socket 与主 socket 分开；测试调用器不属于目标机运行依赖。

## 受控远程推理

发布者使用 `RELEASE_INFERENCE=1` 选择已嵌入 SDK 的 v7 Linux/OSv 模板，见[离线构建](OFFLINE-RELEASE.zh-CN.md)。管理员在出口配置中启用：

```json
{"guest_proxy": true, "inference": {"ledger_directory": "/var/lib/osv-sandbox-egress/inference", "max_tasks": 4096}}
```

在有权限的租户中，除下文的 `egress` origin/CIDR/请求大小/期限外，再配置固定别名与整数计价，例如：

```json
{
  "inference": {
    "endpoints": [{
      "name": "model",
      "url": "https://api.example.com/v1/infer",
      "credential": {"file": "/var/lib/osv-sandbox-egress/credentials/model", "header": "Authorization", "prefix": "Bearer "},
      "price": {"request_units": "5", "input_byte_units": "2", "output_byte_units": "3"}
    }],
    "max_invocations": 32,
    "budget_units": "10000000"
  }
}
```

凭据文件及其父目录由出口服务账号持有，目录 0700、文件 0600，使用单链接常规文件；管理员在服务启动前创建。文件中只保存凭据值，不能通过 guest 或客户端传入。出口启动时缓存，替换文件后重启出口；端点、价格或限额策略改变时同时更新并重启 API/launcher，旧 launcher 的策略摘要会被拒绝。预算单位是管理员设定的本地 microcredits，按尝试和实际 JSON 正文字节计量，不代表提供方 token 数或实际扣款。

客户端显式创建 `network="proxy"` 的签名 v7 会话/任务。guest Python 可用 `import remote_infer; remote_infer.invoke("model", {"query":"hello"}, invocation_id="0123456789abcdef01234567")` 或 `import sandbox; sandbox.ml.invoke(...)`；Linux Node 使用 `require('/opt/osv/remote-infer.cjs').ml.invoke('model', payload, {invocationId})`。Linux SDK 固定走回环代理，OSv Python 固定走已有 vsock C ABI，均不读取 guest 的 URL、凭据或身份设置。模块导入不联网，可用于 pristine 预热。

主机 Python 使用 `session.ml.invoke(...)` / `session.ml.bill()`，Node 使用 `session.ml.invoke(...)` / `session.ml.bill()`；MCP 为 `sandbox.ml.invoke` / `sandbox.ml.bill`。主机查询历史账单分别使用 `client.get_inference_bill(task_id)` / `client.getInferenceBill(taskId)`。账单金额为规范十进制字符串，调用前应保存已知 invocation ID。超时、取消或传输丢失后按 ID 查账，不能自动重试模型 POST；未知结果保持预算占用。关闭任务后账单继续保留，撤销消费授权不删除本租户历史。

root 使用随包静态程序归档已关闭账单，不需要目标机另装 Python/curl：

```sh
/opt/osv-sandbox/current/bin/osv-sandbox-egress -config /etc/osv-sandbox/egress.production.json bill-export -tenant tenant-a -task 0123456789abcdef01234567 -output /var/lib/osv-sandbox-bills/task.json
/opt/osv-sandbox/current/bin/osv-sandbox-egress bill-verify -archive /var/lib/osv-sandbox-bills/task.json
/opt/osv-sandbox/current/bin/osv-sandbox-egress -config /etc/osv-sandbox/egress.production.json bill-retire -archive /var/lib/osv-sandbox-bills/task.json
```

归档父目录须为 root 私有持久目录。export 不覆盖已有文件，retire 核对并同步同一归档与精确摘要后才回收在线记录；归档继续保留。达到 `max_tasks` 后拒绝新增账单，管理员应归档关闭记录，不能直接删除运行中的 ledger 文件。

## Guest 代理

需要签名 manifest v3 的 `vsock-proxy-v1` 能力；旧 Linux v1/OSv v2 模板不会自动获得权限。使用项目脚本重编 musl+mimalloc guest/rootfs 后，设置 `RELEASE_GUEST_PROXY=1` 生成新模板，构建会核对 source-bound guest、镜像内 agent、静态 HTTP 客户端与固定公共 CA 数据。

管理员在 egress 配置中显式加入 `"guest_proxy":true`，并让 API/launcher 的 `egress_socket` 指向同一私有服务；租户仍须有下述 egress origin/CIDR/额度授权。`capabilities.features.network_egress` 同时受签名模板、租户策略与当前服务支持状态约束；服务停机时新代理 VM 请求失败，不会直接联网。原生 Python/Node SDK 的 job/session `network` 支持 `"proxy"`，MCP exec/session.create 仅对获授权租户提供这一选项。

guest 程序使用 127.0.0.1:3128 的 HTTP 代理，默认设置大小写 HTTP_PROXY/HTTPS_PROXY 和空 NO_PROXY。忽略代理的程序仍无法直接出网。镜像内 `/usr/bin/osv-http` 是静态 Go HTTP/TLS 客户端，例如 `osv-http https://allowed.example/data`；它保留显式代理对 loopback 目标的作用，默认验证证书、不跟随重定向，并限制期限与响应大小。私有 CA 可用 `-cacert /input/private-ca.crt` 明确追加，未提供可信 CA 时请求失败。Go 客户端使用 Go allocator，Rust/musl agent 继续使用 mimalloc；没有新 libc 或包管理器运行依赖。

每台已领用 VM 持有自己的 Unix relay 和独占 UID，pristine 池没有租户网络 listener；job/session 销毁、TTL、控制连接结束会回收所有转发后才归还 UID。HTTPS CONNECT 透明转发 TLS，校验实际 ClientHello 的可见 SNI、目标 origin、全部 DNS 答案与固定拨号 IP；证书由 guest 客户端验证，宿主不能读取加密后的 Host/path。隧道字节限额含 TLS 开销，和 fetch 的应用 body 计数不同。代理连接最长 30 秒，guest/launcher 外层转发有额外有限期限，长连接业务须据此设计。

## 配置

API 与 egress 使用同一个 `osv-sandbox` 服务账号及 root 管理的 `auth.json`。在有权限的租户项中添加：

```json
{
  "egress": {
    "allowed_origins": ["https://api.example.com:443"],
    "max_concurrent": 2,
    "max_request_bytes": 262144,
    "max_response_bytes": 524288,
    "timeout_ms": 10000,
    "max_redirects": 3
  }
}
```

无 `egress` 对象的租户无此权限。origin 精确匹配协议、主机和端口，不接受域名通配；默认 HTTP80/HTTPS443 会规范化为显式端口。缺省允许 origin 的公网目的地址，IPv6 限 global-unicast 范围并排除特殊用途网段。需要企业内网端点时另设 `allowed_cidrs`，例如 `["10.20.0.0/16"]`，它同时收窄所有可拨号地址；仍须匹配 origin。link-local/组播/未指定地址及已识别云 metadata 端点不可授权。除非明确需要，不给租户配置 loopback 或广泛 CIDR。

复制包内 `examples/egress.production.json` 至 `/etc/osv-sandbox/egress.production.json`，由 root 持有且不可被 group/other 写。将随包 `examples/egress-public-roots.crt` 复制到 `/etc/osv-sandbox/egress-public-roots.crt`，保持root持有且不可被group/other写；发布配置已将 `ca_file` 指向该文件，因此无需安装系统证书包或在安装时下载CA。私有 TLS 服务可改为自有root管理的CA文件，不提供跳过TLS验证选项。API 配置增加：

```json
{"egress_socket": "/run/osv-sandbox-egress/egress.sock"}
```

将包内 `systemd/osv-sandbox-egress.service` 安装到 systemd，按现有离线发布手册设置 `/opt/osv-sandbox/current`，启动可选 egress 服务并重启 API 读取配置。unit 自动创建 service-owned 0700 runtime/audit 目录，socket 与日志为 0600。API、egress 的策略若不同或服务不在线，API 不广告 fetch，且请求失败，不能回退为 API/MCP 直接出网。升级/回退前须停止 API、launcher 和 egress 三个服务。

egress 仅监听私有 Unix socket，双方校验对端 UID。独立全局/租户网络并发与 VM active/物理资源分别计数；API 仍使用同一租户速率限制，网络服务再次限制自身速率。可在持有 VM 会话时 fetch，不必释放 VM。服务的 systemd 内存、CPU、线程与文件描述符上限独立设置。

## 调用

使用现有 mTLS 与 Bearer 访问 `POST /v2/net/fetch`：

```json
{
  "url": "https://api.example.com/data",
  "method": "POST",
  "headers": {"Content-Type": "application/json", "Authorization": "Bearer remote-endpoint-token"},
  "body_base64": "e30=",
  "timeout_ms": 10000,
  "follow_redirects": false
}
```

方法支持 GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS。GET/HEAD 不接受请求体；body 使用标准规范 base64。客户端不能覆盖 Host、Content-Length、Connection/Upgrade、代理认证等报头。原 API token 只用于认证服务，远端凭据由调用方明确放在 `headers` 中；日志不保存报头或 body。

成功网络操作返回 HTTP200 的 `osv-sandbox-network-fetch/v1`：`request_id`、最终 `url`、上游 `status`、筛选后 `headers`、`body_base64`、`body_bytes`、`redirects`、请求/累计响应体字节及总时长。远端404/500也是已完成网络操作，SDK返回真实status；MCP用isError提示。策略拒绝403、繁忙/速率429、超时504、上游/DNS/TLS失败502、配置/审计不可用503。未知传输结果不自动重试。

MCP工具为 `sandbox.net.fetch`，只经同一认证 API。Python 为 `client.fetch_network(url, method="POST", body=b"{}", headers=..., timeout_ms=10000)`，返回 `NetworkFetchResult`；Node/TS 为 `client.fetchNetwork(url, {method:"POST", body:Uint8Array, headers, timeoutMs:10000})`，返回有界二进制 `body`。先从 capabilities 的 `network_fetch_policy` 查看权限与限制。

默认不跟随重定向。显式 `follow_redirects:true` 也逐跳检查 origin、DNS 的全部地址、固定实际拨号 IP，并拒绝 HTTPS→HTTP 降级。跨 origin 清除全部调用方报头；301/302 的 POST 与303按HTTP语义转GET，307/308保留方法与body。允许跳数0～5，累计响应体共享512KiB硬上限，总期限最多30秒；业务可能已在前一跳产生副作用，调用方应据此选择是否跟随。

## 审计与退出

审计先持久化 admit/逐次拨号 allow，再发起出站；成功结果前持久化 complete，拒绝/失败也记录，审计错误后停止新出网。日志只含租户、request ID、origin、方法、核准IP、状态、字节和时长，不含 URL path/query、token、body 或敏感报头。字节是应用请求/响应体计数，并非链路流量账单。

HTTP取消、API断连、MCP取消/EOF和服务停止会取消在途请求、关闭上游连接并释放网络槽位。API/MCP不会自动重发有副作用请求。该行为与已交付 VM 会话/后台命令的独立生命周期并存。正式性能、guest代理及其余原始要求继续按需求矩阵验收。

公共CA数据固定为Mozilla 2026-10-20转换版，118份证书，来源和MPL-2.0许可证随签名包分发并进入SBOM；构建先核对上游SHA、来源锁、许可证和证书解析数量。信任数据随发布版本升级，不在离线安装时自动更新。Go程序仍支持显式私有CA；省略ca_file才会使用宿主系统CA，离线发布示例不采用该回退。
