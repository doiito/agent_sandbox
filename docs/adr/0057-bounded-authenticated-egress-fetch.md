# ADR-0057：认证 HTTP egress 引擎与网络 fetch 工具

状态：Accepted；日期：2026-11-03；需求 NET-01、API-03/04、SEC-02/04、OBS-01、REL-04。

## 范围与后续 guest 接入

原方案 §6.3.6 要求默认无网卡、显式代理、域名/IP/SNI/端口策略和审计，且 §6.3.9 要求 MCP net.fetch。先交付可供 API/MCP 与后续 guest 代理共同复用的真实 HTTP egress 引擎及认证入口。NET-01 的 guest 代理接入、通用 CONNECT/SOCKS/TAP/private 网络继续跟踪，不能把这个阶段当作全部出网目标完成。guest 仍无NIC，network!=none仍拒绝，capabilities分别报告network_fetch和network_egress。

## 架构

新增静态 osv-sandbox-egress 非root进程，只监听私有 Unix socket；内核 SO_PEERCRED 限定 API UID，继续验证原租户 Bearer 与同一 root 管理的 auth policy。API 新增 POST /v2/net/fetch，固定 Unix 后端，不向调用方提供代理地址或任意主机传输参数；MCP sandbox.net.fetch 仅调用该API。API连接 egress 不依赖环境HTTP代理。egress为可选服务，缺省禁用；停服不影响VM核心功能，网络能力不再广告且fetch不能回退为API直接出网。

认证策略新增可选egress对象：精确http/https origin白名单、可选目的CIDR收窄/明确内网授权、独立有界网络并发与请求/响应大小、总期限和重定向上限。与VM active/物理配额分别记账，fetch不创建VM，也不能占用无限宿主IO；使用租户既有速率token。部署配置和策略以现有root文件信任边界加载，不把客户端参数当成策略。

每跳先校验URL/scheme/host/port/origin，再解析全部IPv4/IPv6地址并验证，出现不允许地址则拒绝；将实际拨号固定到本次核准IP，不再次DNS解析。TLS使用原始主机名验证证书和SNI，生产没有skip-verify；HTTP不接受CONNECT/upgrade/客户端Host或逐跳报头。缺省仅公网地址，私有目标必须由管理员同时授权origin及CIDR；不接受zone ID/用户信息等含混URL。精确origin包含scheme/port，不接受域名后缀通配、跨协议静默放宽。

参考 [Go net/http](https://pkg.go.dev/net/http) 与 [RFC9110重定向语义](https://www.rfc-editor.org/rfc/rfc9110.html)。自动重定向关闭，由引擎逐跳执行策略，默认不跟随；显式跟随也有跳数/累计时间/字节上限。跨origin清除所有调用方报头，防止认证或自定义API key泄漏；HTTPS不能降级HTTP。301/302的POST与303转换GET、去body；307/308按显式跟随语义保留方法和body。无cookie jar、无环境代理、无连接跨请求复用或自动业务重发。

## 功能边界与审计

支持GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS；有界base64请求体及二进制响应体，状态/筛选后报头/最终URL/跳数明确返回，不解释或执行远端内容。API和MCP暴露可区分的策略拒绝、繁忙、超时、DNS/TLS/上游错误；HTTP上游4xx/5xx仍是网络结果，MCP以isError提示。取消/期限/EOF关闭在途HTTP并释放网络槽位；不自动重试不确定的有副作用请求。

持久审计记录租户、请求ID、origin、方法、核准目的IP、状态、字节和时长；不记录token、query/path、请求/响应body或敏感报头。发起出网前审计成功，审计失效后拒绝新出网。systemd给独立进程设置普通资源/权限边界，离线包包含静态程序、unit、无凭据配置和手册，必要文件放项目内。

## 自评审与验证顺序

先[自评审](../../PUBLIC-QUALIFICATION.md#private-evidence)，再实现与定向测试：域名/端口/IPv4/IPv6/混合答案、DNS固定拨号、TLS/SNI、每跳重定向与凭据剥离、请求/响应/报头/并发/时间上限、取消、审计和Unix peer/tenant验证。使用实际临时TLS上游和真实服务进程测试，不依赖外网或商业端点。

冻结一次CI后构建双架构离线包。ARM64无NIC QEMU运行实际安装程序及网络策略/协议功能；x64在隔离测试网络运行包内API/MCP→egress→真实HTTP/TLS上游，并与同包真实KVM job/session/warm工作流共存验收。新增配置/auth/API影响既有控制面，完整核心API/session/SDK/warm矩阵只在该冻结候选执行一次；guest/VMM按载荷摘要复用，不重复构建无变化guest。失败夹具退役，失败证据保留。正式门禁与原始40项范围不变。

离线依赖核对补充：公共TLS信任文件同属必要数据，不能要求目标机另装ca-certificates。随包提供固定Mozilla转换CA、MPL许可证和来源锁，示例配置指向复制后的root管理文件。运行程序不变，只增加发布数据/配置与SBOM；后续候选按完整运行载荷摘要复用同包实机矩阵，并单独验收新增信任文件。

[rc63/rc64验收](../../PUBLIC-QUALIFICATION.md#private-evidence)已完成：完整运行CI、本地真实进程14项、双架构最终51文件包、ARM64 QEMU38组、同包x64 cold/warm网络各28项与核心API/SDK/pool/生命周期回归。公共CA补充后的服务/SDK/VMM载荷逐项等于运行基线，只补发布增量CI、实际最终包安装/信任7项，未重复全回归。四夹具退役且清理约2.24GiB重复副本。guest代理与NET-01整体、原其余目标仍开放。
