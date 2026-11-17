# MCP stdio 使用

离线包内 `bin/osv-sandbox-mcp` 是静态 Linux 程序，支持 x64/aarch64，无需在目标机安装 Go、Node.js、Python 或 MCP SDK。它通过已部署的 HTTPS API 执行工具；API 与虚拟机仍需按生产部署手册配置。支持 MCP 2026-07-28 的逐请求版本声明及发现，也兼容 2025-11-25 的初始化握手。

复制包内 `examples/mcp.production.json`，填写 API 固定 HTTPS 地址、CA、客户端证书/私钥和当前租户 token 文件路径。配置及凭据由运行 MCP 的用户读取，建议权限 0600。token 放在文件中。API 客户端证书和服务端证书需要在有效期内。

在支持 stdio MCP 的客户端中配置：

```json
{
  "mcpServers": {
    "osv-sandbox": {
      "command": "/opt/osv-sandbox/current/bin/osv-sandbox-mcp",
      "args": ["-config", "/etc/osv-sandbox/mcp.json"]
    }
  }
}
```

也可通过 `OSV_SANDBOX_MCP_CONFIG` 指定配置文件。`-version` 显示实现和支持的协议版本。正常运行时 stdout 仅含逐行 JSON-RPC；诊断写入 stderr。

先调用 `sandbox.capabilities` 或 `sandbox.templates` 查看租户可见入口、真实模板摘要和资源上限。工具列表按当前 API 能力生成，包含执行、会话、工作区文件及后台命令：

| 工具 | 用法 |
|---|---|
| `sandbox.exec` | `entrypoint`、`args`、`environment`、`cwd`、base64 `stdin` 等受限任务输入。可填写当前 `backend`/`artifact_manifest_sha256`，不匹配时失败。传 `session_id` 则在该会话同步执行，不能改变资源或传固定 stdin/input_files。 |
| `sandbox.session.create/get/list/set_timeout/close` | 创建、查看、列举、续期和关闭显式 API 会话。创建结果的 `id` 用作后续 `session_id`。 |
| `sandbox.fs.read/write/list/info/mkdir/rename/remove` | 传 `session_id` 与 `/workspace` 下路径。write/read 的字节使用 base64，rename 另传 `destination`。 |
| `sandbox.fs.artifact.create/read/delete` | 源码新增 Linux v8 会话产物 tar；create 传 path，read 传 artifact_id/offset/length（≤512 KiB）、返回块/归档 SHA256，delete 释放缓存。新包验收待完成，rc90 不含此功能。 |
| `sandbox.commands.start/list/get/wait/cancel` | 在会话内运行后台命令；start 返回 `id`，后续使用 `command_id`。get/wait 只观察已有命令；wait 返回完整有界输出，不推送增量消息。 |
| `sandbox.commands.stdin/stdin_status` | start 时启用 `interactive_stdin`。stdin 传 `data_base64`，可 `close:true` 发送 EOF，返回输入票据；用 `sequence` 查询交付状态，不自动重发。 |
| `sandbox.watch.start/list/poll/stop` | 仅实际会话签名模板提供 `file_watch` 时发布。start 传 `session_id/path` 及可选 recursive/include_entry/timeout_ms；poll/stop 传 watch_id。poll 的 after 确认并释放旧事件，每监听一个消费者，溢出明确终止。 |
| `sandbox.code.context.create/default/list/info/restart/remove` | 仅认证Linux v5代码模板提供。create传调用者已知context_id、显式language，可选cwd（默认/workspace）；default显式language；restart/remove携带generation。返回真实过渡状态，info观察idle/下一代次或code_not_found，ACK不等于完成。 |
| `sandbox.code.execute/poll/cancel` | 传session_id/context_id/generation/execution_id；execute另传code、可选environment和timeout_ms（默认60000，0不限制执行期限、不延长租期）；poll的after默认0，每页最多64事件，非破坏性观察。取消ACK后继续poll确认终态。 |
| `sandbox.net.fetch` | 在 API 已配置 egress 且租户授权时发布；传 `url`、`method`、`headers`、`body_base64`、`follow_redirects`、`timeout_ms`，逐跳受域名/IP/资源限制。响应含上游status与base64 body；上游4xx/5xx用isError提示。 |
| `sandbox.ml.invoke` | 未发布的推理接入入口；仅实际 owner 的签名推理能力、proxy 与租户许可均有效时允许。传 session_id、显式 invocation_id、endpoint 别名、JSON payload 和可选 timeout_ms；不接受 URL/凭据/价格，不自动重发。 |
| `sandbox.ml.bill` | 按 task_id 查询本租户持久账单，包含会话关闭、模板目录失效或撤权后的历史；金额为精确十进制字符串，不触发模型请求。 |

取消 MCP 请求会中断对应在途 API 调用，一次性任务由 API 回收 VM。同步会话 exec 取消可能关闭整个会话；后台命令要用 commands.cancel 明确停止。取消 wait 或关闭 MCP 进程不会自动停止已交付 ID 的后台命令或会话，它们可在新 MCP 进程中继续访问，最终受会话 TTL 和显式 close 控制。创建响应丢失时不会自动重建；可使用 session.list 查找本租户会话，或等待 TTL 回收。

tools/call 的工具参数、权限、容量、任务失败通过 `isError:true` 返回，`structuredContent` 和文本 JSON 内容一致。协议方法/未知工具错误使用 JSON-RPC error。默认最多 4 个在途调用，可配置 1～16；超过限制立即返回错误。单条请求最多 1MiB，API 响应最多 8MiB，输出队列有界，持续不读取 stdout 的客户端会被断开。网关不自动重试写操作。

所有工具使用同一个配置租户，继续受 API 的入口、签名模板、工作区、配额及资源规则约束。网络工具使用[认证 egress 服务](EGRESS.zh-CN.md)，不直接在 MCP 进程中访问远端URL。未启用/未授权/服务不在线时不发布该工具。默认guest网络为none；[rc66](../PUBLIC-QUALIFICATION.md#private-evidence)已验证获授权Linux模板的exec和session.create显式`network=proxy`。会话网络在创建时固定，session exec省略network即可继承；不接受借exec改变模式。网关检查公开参数与live能力，API/launcher执行实际部署与租户授权。


## 多模板目录与选择

新服务的`sandbox.templates`返回全部租户可见的已签名模板、可用状态、入口与能力，执行时同时给出`backend`和`artifact_manifest_sha256`。`sandbox.capabilities`也接受这一选择器。工具schema来自可用模板的并集，实际调用再查询所选模板能力；OSv不能借Linux的proxy/session权限。默认模板不可见或过期时仍可发现其他模板，但exec不自动回退，需要显式选择。旧单模板服务继续使用其实际广告的能力。

session exec及commands.start按已绑定会话查询模板，冲突选择器拒绝。支持范围及候选验证进度见[ADR-0060](adr/0060-multi-template-catalog-and-shared-capacity.md)。

代码工具每次使用会话绑定能力入口，核对实际owner与v5或含代码能力的v6 profile，不借默认模板授权。`sandbox.capabilities`可单独传session_id查看该已领取VM的合同，不能同时传backend/摘要。`sandbox.templates`返回code_runtime/code_languages。模板停止新VM准入时，Available仍false；既有代码会话可继续查询/取消/关闭，不能由此创建新VM。

代码提交和上下文创建使用调用者事先持有的24位hex ID。MCP取消、EOF或响应丢失只结束当前HTTP观察；不重放源码，不自动取消已接受执行或删除上下文。失败结果保留session/context/generation/execution等身份和delivery_unknown，不回显源码/环境；用info/poll/cancel继续处理。代码poll保持原始JSON、MIME及base64，完成状态与最后一页分别判断；淘汰、用户error事件及失败终态明确isError。代码工具不使用watch/普通命令的ACK丢失回滚。

代码工具已完成[本地stdio验证](../PUBLIC-QUALIFICATION.md#private-evidence)与[rc74同包验收](../PUBLIC-QUALIFICATION.md#private-evidence)。新增端口工具尚未进入rc74，不将源码实现视为已发布能力。

## 原生端口通道

签名Linux v6及租户端口策略允许时，工具发现包含`sandbox.ports.open/write/read/close_write/info/cancel/close`。身份字段固定为session_id、connection_id（调用者生成的24位小写hex）和port。open可选max_bytes、timeout_ms、idle_timeout_ms，缺省每方向64MiB和300000毫秒；目标始终为同一VM的IPv4 loopback，不接收宿主地址。

write一次提交1..16384字节的data_base64；read一次消费一帧，返回kind=data/eof/finished，data为data_base64，finished为connection终态。read会消费数据，丢失RPC响应不能通过重试恢复原帧。一个读和一个写可以并行，重复同方向在途操作拒绝，无后台输出队列。close_write发送应用EOF，收到eof后仍可写自己的方向并继续读取finished。close仅关闭本地传输，cleanup_confirmed=false；终态通过info或finished确认。

通道由当前MCP连接拥有，最多8条活跃传输和256个本地ID，ID不重用；总期限从open开始，空闲未读取也会关闭并回收本地槽。MCP进程EOF、输出断线和取消会关闭相关本地传输；guest仍由原session及API/root清理门禁管理，不因MCP连接消失销毁正常owner。RPC取消若中断端口读写会关闭该通道，未完成传输不重放。错误返回已知ID及outcome_uncertain，控制凭据和业务字节不回显。

info/cancel/close另有2个有界控制RPC槽，不受堵塞DATA占满工作槽影响。info/cancel按当前API认证和原ID独立执行，不重新依赖新VM目录或新准入额度，也允许cancel-before-open。已停止新准入的v6模板仍可发现既有VM的端口工具；open实际查询session绑定能力并由root再次准入。取消ACK可能是cancelling，不等于物理清理完成。协议见[端口合同](contracts/port-tunnel-v1.md)；预览和新离线包同包验收继续开放。

## 浏览器预览授权

`sandbox.preview.create/info/revoke` 采用 API 会话拥有的授权，三者参数为 session_id、preview_id（24 位小写 hex）和 port；create 可加 ttl_ms（1000..300000，缺省 300000，受会话剩余租期限制）。创建结果直接包含一次性 bootstrap_url，后续 info 不重发 secret。MCP 退出或 RPC 取消不会自动撤销授权，也不会重建或恢复丢失的 URL。创建不确定时返回原 ID 和 outcome_uncertain，不重放 POST。

info/revoke 与原端口查询/取消共享 2 个独立控制 RPC 槽，并跳过新建目录发现，策略停止新建时仍可清理既有授权。授权期限和 session 关闭负责最终生命周期；revoke 确认授权状态，不宣称 guest 物理连接已清理。工具只在已认证 v6 端口与预览能力可用时发现，实际 create 再查 owner 会话。离线配置见 `PREVIEW.zh-CN.md`。rc74 不含该功能；新离线候选和同包 VM 验收仍开放。
