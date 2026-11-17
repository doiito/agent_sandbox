# Workspace 产物归档详细设计

对应 [ADR-0122](../adr/0122-bounded-workspace-artifacts.md)。实现状态以测试和候选回执为准。

## 公开契约

| 操作 | REST | 结果 |
| --- | --- | --- |
| 创建 | `POST /v2/sessions/{id}/artifacts`，body `path` | session/artifact ID、源路径、tar 字节数、SHA256、用户条目/文件数及载荷字节数 |
| 读取 | `POST /v2/sessions/{id}/artifacts/{artifact_id}/read`，body `offset,length` | 绑定 ID/offset/总长度、canonical base64、块 SHA256、归档 SHA256、EOF |
| 删除 | `DELETE /v2/sessions/{id}/artifacts/{artifact_id}` | 204；释放缓存 FD |

offset 为非负整数、length 为 1..524288，越界明确报错；offset 等于总长度允许空 EOF。ID 使用现有 24 位小写 hex 校验。跨租户/不存在会话或归档均返回 404。所有操作遵循会话 lookup、mTLS、bearer、请求限速与能力校验。创建额度为 2 个，包括正在创建的预留；满额返回明确的 artifact limit，删除后恢复。未签名或不支持模板在 guest 连接前拒绝。

capabilities 增加 `session_artifacts` 和相应 limits。Python/TS native Session 暴露 create/read/download/delete；download 根据已知总长循环，逐块校验绑定、大小、摘要，最后校验整个 tar，不自动解包。MCP `files.artifact.create/read/delete` 使用同一 REST 契约。gRPC 增加三个 unary 方法，块 JSON 仍低于原消息上限；保留原 45 方法 ABI。

## 选择与归档格式

path 必须是 `/workspace` 或现有规范化的后代。文件选择导出 basename；目录选择导出其内容相对于选中目录的路径，空子目录也保留。根空目录生成只有清单的有效 tar。`.osv-artifact-manifest.json` 是根保留成员；与用户成员冲突则拒绝。

宿主清单 schema 为 `osv-workspace-artifact/v1`，包含 source_path 及排序后的条目。每项为 path、type、size，文件额外有 SHA256。用户条目不包括生成的清单。路径是合法 UTF-8 相对 POSIX 路径；无空/点/上级段、反斜线、控制字符、绝对/驱动路径；每段≤255 字节、总路径≤1024、深度≤16、全部路径合计≤65536。树最多 1024 项，单文件及总载荷都受 32 MiB 归档预算约束。

tar 由宿主 `archive/tar` 创建，使用确定性的 PAX 需要项；UID/GID/时间归零，目录 0755，文件 0644 或按源可执行位规范为 0755，去掉特权位/owner/xattrs。清单排在首位，用户成员按相对路径排序。最终总大小含 header、padding、清单及终止块，超过 32 MiB 全部失败。相同源路径、内容、目录结构和可执行属性应产生相同字节与 SHA256。

## Guest 与宿主传输

`fc-artifact/v1` 独立 vsock 5005，不消耗主控制通道的 100 次请求预算。仅新签名模板通过 boot policy 开启；同一 VM 最多一个物理导出 worker，接受/退出遵循既有有界服务模式。预备授权与失效在主控制响应 ACK 之前同步，继承会话软 TTL 和 600 秒硬寿命。one-shot/pristine/poisoned 状态拒绝。

请求包含协议、session ID、export request ID、独立 nonce、准备 binding（如有）、source path。guest 先绑定和验证请求，再进行 FD 相对遍历，逐条输出 `entry`、文件 `data`（最多 64 KiB 原始字节）、`file_end` 和最终 `end`。每帧重复身份、单调 sequence；JSONL 前缀固定 `FC_ARTIFACT_EVENT `，单帧≤128 KiB。宿主要求阶段顺序、唯一排序路径、偏移连续、声明大小精确、累计额度合法及成功终态后 EOF；错误码仅接受固定集合。协议异常、超限、EOF/取消都不能发布部分结果。

guest 拒绝 symlink、硬链接（nlink>1）、特殊文件及跨文件系统。遍历期间保留元数据指纹，读之前/之后以及最终重遍历核对 dev/inode、类型、size、mtime/ctime 和目录集合，发现改变返回 conflict。代码/后台进程可能修改文件系统，接口不承诺原子快照；所有实际返回字节由宿主摘要覆盖。

## 宿主暂存和生命周期

root launcher 在 Session opMu 下执行创建，使用独立 guest service 完成一次有界传输。先把经验证的内容写入私有、立即 unlink 的 content FD，记录范围/摘要；验证成功后生成第二个立即 unlink 的 tar FD。清单因此可置于归档首部，不需要把 32 MiB 文件树放进 Go 内存。完成并计算归档摘要、通过可信审计后才把 tar FD 放入会话缓存；content FD 随即关闭。

缓存最多两个完成/预留项。创建满额时不分配临时文件；因此每会话至多一个已有 tar 加一个 content 和一个正在构建的 tar，暂存约束上界 96 MiB。缓存列表使用独立锁并有 closed 状态；与 Session.Close 竞争时拒绝晚到发布并关闭 FD。read 使用固定范围 ReadAt，delete/Close 并发读返回明确错误；不保存 guest 控制的宿主路径。launcher 崩溃时内核释放已 unlink 的缓存；VM workdir 和 cgroup 继续由原 owner 对账。

创建上下文取请求期限与 session ctx/TTL 的较小值，最大 30 秒。读块不执行 guest 命令；读取过程的 HTTP 断连只终止本次读取。创建时的 guest/协议失联按原 session 失联语义清理；slot/身份释放沿用确认后的 owner 生命周期。审计只记录租户、session/artifact ID、结果、数量/大小，内容与清单文件名不进入公共日志。路径/数据作为归档内容只经认证通道返回。

## 公开接口接入复核（2026-11-16）

root launcher 使用独立的 `osv-sandbox-launcher-artifact/v1` UDS RPC（create/read/delete）接入同一已登记会话，沿用现有 peer UID 检查和 tenant/session owner 索引；请求与响应绑定独立 nonce。创建仍受 Session opMu、30 秒期限和原会话寿命约束。三个操作各用一个连接，读块断连只取消该次缓存读取；不关闭持有 VM 的长期 owner 连接。创建断连按既定传输不确定语义关闭会话，完成但未确认的归档在处理器退出时删除；不重试创建。删除的确认丢失由调用者查询决定，不隐式重放。

MCP 采用现有工具命名空间 `sandbox.fs.artifact.create/read/delete`。REST 的 create/read/delete 分别返回 201/200/204。明确错误为 `artifacts_unsupported`（501）、`artifact_limit`（429）、`artifact_too_large`（413）、`artifact_not_found`（404）、`artifact_range`（416）、`artifact_changed`（409）；文件路径和权限错误沿用已有错误码。Python `create_artifact/read_artifact/download_artifact/delete_artifact` 与 TS 对应 camelCase 方法；下载接收已创建的归档元数据，逐块检查已知总长度、归档摘要绑定和块摘要，再检查整体摘要，返回有界 bytes/Buffer，不自动解包。

接入自评审：独立连接避免缓存读取取消摧毁 VM；响应必须只含所请求结果并验证 owner/nonce/offset/完整性；错租户与旧模板在 guest 前拒绝；201 写出失败删除刚创建项；所有层的总大小/块大小与两项缓存额度一致。新增三项 HTTP/native gRPC 操作，保留原 45 项方法及已发布 protobuf 编号，E2B 分母仍为 34。SDK/MCP 功能接入完成后先做定向集成和契约验收，稳定后才冻结发布候选并集中执行 CI、实包及 KVM/启动门禁。

## 实施与验证批次

1. 类型、额度、归档构建/缓存及单元/FD 竞争测试。
2. guest 遍历/分帧/身份/取消服务与主 ACK 授权，双架构 guest 单元及无 NIC QEMU。
3. root launcher、REST、capabilities/v8、三项 native gRPC、Python/TS 与 MCP，全链路进程测试。
4. 稳定后一次候选 CI/离线包、ARM 实包、同包当前基础矩阵和新增 cold/warm KVM；独立清理。
5. 按产品影响复测正式启动，旧 rc90 证据保持历史含义；随后推进其他未完成需求。

发布前联调复核：基础镜像与 code 子模板都必须透传归档开关并签名 v8；新候选冻结全部产品、SDK、契约及验收源码。实际 KVM 夹具保留原 15 套/516 项、44 项 gRPC 与两项 OSv 输入夹具，再独立增加 cold/warm 归档夹具。归档夹具使用安装包内 Python/Node SDK、现代/旧版 MCP 和三项 typed gRPC，检查 Unicode/二进制、多块与完整 SHA256、确定性、源改变后的缓存不变、单文件/空目录、两项额度、EOF/越界、错租户、链接/FIFO/保留名、tar 开销计入 32 MiB、删除/TTL/owner 回收。功能和清理成功前不登记新启动结果。
