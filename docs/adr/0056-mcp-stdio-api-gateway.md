# ADR-0056：共用认证 API 的双版本 stdio MCP 网关

状态：Accepted；日期：2026-11-03；需求 API-03、API-01/02、CAP-01、EXEC-01、FILE-02、LIFE-01、REL-04。

## 固定协议与实现选择

固定官方[MCP规范](https://modelcontextprotocol.io/specification/2026-07-28)提交 `3c4d91b7e832d9b74338d56eed03403ccc662123`，schema/stdio/versioning/discovery/tools/cancellation及旧版生命周期保存在项目 `assets/contracts/mcp-2026-07-28/`，含来源锁与许可证。

同时支持2026-07-28的每请求_meta/server/discover/resultType/缓存字段，以及2025-11-25 initialize/initialized握手。现代请求不能继承其他请求的版本/能力；旧握手状态只用于旧版请求。只声明tools，不声明未实现的prompts/resources/subscriptions/tasks等扩展。

新增静态Go程序osv-sandbox-mcp，仅stdio JSON-RPC，不新增公网入口。官方Go SDK当前要求Go1.25及HTTP/OAuth等依赖；本项目现有Go链不变，使用标准库实现受限的stdio传输和固定工具集，并用已锁官方两版schema、真实进程/取消和KVM端到端验证。目标机不增加Node/Python/SDK安装要求。

## 权限和工具

通过配置文件读取固定HTTPS origin、CA/mTLS证书与token文件；token不进入命令行或stdout。所有执行/文件/会话请求都访问现有认证版本化API，保留租户、入口、签名模板、资源、路径和TTL规则。不连接root launcher、不执行宿主命令、不把文件工具映射到宿主路径。禁用环境代理和重定向，不提供跳过TLS验证参数。

工具包括capabilities、真实模板列表、一次性/会话exec、显式会话create/get/list/set_timeout/close、工作区fs read/write/list/info/mkdir/rename/remove及后台命令start/list/get/cancel和stdin票据。工具列表根据当前租户API能力确定、顺序固定、零缓存期限；每次调用复核能力，模板变化不默默切后端。所有跨请求状态由API签发的显式session/command ID引用，stdio进程不是会话生命周期。

net.fetch随NET-01的受控egress继续实施；当前不发布不可用网络工具，调用不能回退为宿主HTTP。API-03本批为执行/文件/模板接入，不因此宣称网络功能或整个需求完成。

## 生命周期与边界

单行JSON-RPC帧最多1MiB；并发请求、响应队列和HTTP响应有界。reader持续处理取消，stdout只写协议，stderr只写不含凭据的诊断。无自动重发。notifications/cancelled、EOF/SIGTERM取消在途HTTP，使现有API执行取消/回收；已完成请求与取消的竞争按协议处理。显式已交付session/command可跨MCP进程继续使用，不因stdio断连全部删除。创建资源但响应未交付时，已知新ID用独立短期限补偿清理；未知提交结果不能假称回滚成功，可由租户列表/TTL恢复。

协议方法/未知工具错误为JSON-RPC错误；工具参数和API/guest执行错误在tools/call结果中以isError呈现，同时提供结构化对象与文本JSON。现代响应带resultType和serverInfo；版本错误列出支持版本。工具schema使用固定JSON Schema2020-12，不加载客户端提供的schema或外部ref。

## 验证

先[自评审](../../PUBLIC-QUALIFICATION.md#private-evidence)。定向覆盖两版生命周期/发现、必需_meta、ID/错误/帧/并发、取消/EOF/输出背压、HTTP TLS/代理/重定向和工具映射/租户/边界；用官方schema离线校验真实stdio响应。冻结一次CI，双架构离线包增加MCP程序与手册/SBOM，ARM64 QEMU运行真实协议，x64同包MCP→mTLS API→launcher→KVM验证工具及取消/重连/配额/回收。API/guest/VMM载荷未变时按摘要复用完整原矩阵，只重测MCP与安装链路；性能门禁不变。

本批验收见 [rc62](../../PUBLIC-QUALIFICATION.md#private-evidence)：完整CI、双架构44文件包、ARM64无网卡QEMU35组及同包x64 cold/warm各29项通过。API/guest/VMM/SDK逐项等于rc60，旧完整矩阵按载荷摘要复用。首次CI与验证夹具/探针失败均保留；API-03网络部分和性能/生产目标仍开放。
