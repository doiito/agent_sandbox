# ADR-0081：受控远程推理与任务账单

状态：Proposed；日期：2026-11-07；关联 API-04、NET-01、OBS-01/02、LIFE-01/02、REL-04。遵循用户的功能优先、一般安全、双架构离线安装及及时清理验证产物要求，K8s 不在本轮范围。

## 决定

实现方案 §6.3.9 的完整调用链：guest 中的 `remote_infer`/`sandbox.ml.invoke(endpoint, payload)`、原生双语言客户端与 MCP，复用现有 root 绑定的 vsock 出口和 DNS/IP/TLS 校验，返回与所属任务或会话关联的主机计量账单。Linux 与 OSv 均纳入设计和后续真机范围，不以宿主普通 fetch 包装替代 guest SDK。没有本地 GPU 能力声明。

调用采用有界、单次 JSON POST，返回 JSON。管理员将端点别名绑定到固定 HTTP(S) URL，必须同时满足该租户原有 egress origin/CIDR 策略。客户端不能覆盖 URL、路径、认证头或价格；不跟随重定向，不自动重放未知结果。端点不限定模型厂商或 JSON 业务结构；流式推理不在此 unary 合同内，非 JSON 响应使用可识别错误并保留计量结果。

端点凭据可来自服务管理的持久私有文件，只在出口服务读取，按配置的合法头名及前缀注入。API/guest 的能力发现仅返回别名、有效限额和价格摘要；不返回凭据、私有文件路径、prompt 或模型输出。固定 URL 禁止 userinfo、fragment、含秘密的 query；HTTP 私有服务仍须管理员明确 origin/CIDR 授权。

凭据在出口服务启动时从固定的服务所有私有常规文件读取并缓存在该进程；替换文件后重启服务生效。目录与文件不允许不可信写入，不跟随末级符号链接。凭据头不能改变正文编码、HTTP 帧、租户身份或固定的幂等键。

## 出口与身份

沿用 guest proxy 的 vsock 5001、Linux loopback 3128 与 root peer credential 校验。增加保留的推理 HTTP 路由，只处理专用版本化 JSON 请求。root 为每条连接提供不可由 guest 覆盖的 tenant、物理 VM、lease 和逻辑任务身份；计量一律使用这些身份。Linux session 内的调用计入其会话账单，one-shot 任务计入该任务账单。guest 自报子任务标签不能替代主机身份。

Linux SDK 使用现有 loopback 代理；OSv Python SDK 使用已有 `osv_vsock_connect/send/recv` ABI，不向 VM 注入控制 API 的私钥、证书或 Bearer。网络权限继续要求调用者显式选择受控 proxy 模式及租户推理许可，缺省不开放。OSv 接入现有 root VM 出口桥并新增对应签名能力，旧 profile 不隐式获得权限。主机 SDK 的 session 调用经 launcher 重新确认 owner、绑定及签名能力后进入同一服务，不能只凭 tenant token 编造任务 ID。

采用显式签名 v7 profile 承载 remote-infer-v1 及所需 proxy 能力，与既有 v1..v6 兼容规则一起实施和测试。在 guest、签名、SDK、计量均未接通前不发布 remote inference 能力。

root 在启动时缓存租户许可；签名验证器现已按严格 v7 合同接入 remote-infer-v1/vsock-proxy-v1 双标记、架构和固定 transport、完整 SDK 文件摘要及镜像内 BOM 一致性。实际双架构 Linux、x64 OSv 镜像的签名与官方 BOM schema 已验证；现有 v1..v6 模板不因此获得权限。完整离线包、实际 guest 冷/暖调用与同候选真机验收仍须继续完成。

## 持久化与计量

每次调用提供已知的24位小写hex invocation ID，属于一个主机确认的任务/会话；同一账单内 ID 永不复用。重复调用返回冲突，不重发请求。异常携带 ID，查询可返回状态和计量，不能重新执行模型。每任务调用数有硬上限，任一提供方结果丢失不触发自动补发。

价格使用整数 microcredits：每次获准尝试的固定费用、输入/输出实际正文 UTF-8 字节费用。全部金额在对外 JSON 中使用十进制字符串。它是管理员配置的本地计费口径，不冒充提供方实际扣款；提供方自报 token 数不是主机权威计量。无价格配置时仍记录请求数、字节和耗时，费用为0。

输入计量为主机准备交给 HTTP 尝试的 JSON 正文长度，输出为主机实际读取的正文长度，不包含头、TLS 或其它线缆开销，不承诺提供方实际收到/计费的字节。DNS、拨号或 TLS 建连之前失败的请求不收取尝试费用；HTTP 连接就绪后中断即保守视为可能已执行，保持完整费用保留。完整的非 JSON、错误状态与重定向响应按已观测正文结算并返回本地错误，不泄漏提供方错误正文；超限响应最多多读1字节用于检测，费用封顶到已保留的输出上限。部分响应或未知传输结果不释放预算。

向外发送前，按已知输入和响应上限保留最大费用并持久化。结束后按主机观测字节结算；预算不足不拨号，并行调用不能超花。结果不确定或存储提交未确认时保持保留金额，不把它当作免费失败或成功完成。完成状态与账单持久化后才返回成功数据。

账单状态采用服务拥有的持久目录、单实例锁、每任务受限 JSON 文件、原子替换与文件/目录同步。任务文件包含 tenant/VM/lease/task 绑定、调用 ID、状态、价格、计量和金额，禁止记录 prompt、输出和认证内容。状态提交失败锁存并拒绝后续变更；重启时未完成记录变成结果未知且仍保留预算，不能重放。任务数与单文件大小有硬上限，显式导出关闭账单后才能回收；不静默删除有效账单。运行库和真实状态不能放在 `/tmp`，验证夹具可使用临时目录。

完成写入在 rename 之后报告故障时，当次进程仍拒绝返回成功并停止新消费。重启只依据重新读取并验证的规范文件恢复：文件仍是 reserved 则转 uncertain 并保留预算；若规范文件已经保存完整完成状态，则保留该已知结算，不能凭上一进程收到的存储错误覆写成免费失败。存储恢复不重放模型请求，也不恢复未持久化的模型输出。

任务结束时 root 停止该 VM 的出口、取消/等待所有推理调用，再确认账单关闭。跨进程恢复、重放、预算并发、磁盘满、完成写入失败和关闭中的调用都必须有可验证语义。

## root 与出口服务接入

出口配置新增可选 inference 对象，包含服务所有的持久 ledger_directory 与 max_tasks；缺省关闭，要求 guest_proxy 已显式开启。生产状态放在 `/var/lib/osv-sandbox-egress/inference`，拒绝易失目录、符号链接及内存文件系统；systemd StateDirectory 管理所有权与可写范围。验证配置可使用临时目录，不将它当成生产存储证明。

root 通过内核 UID 0 的专用控制 socket 执行 bind、close、export、retire，控制 socket 位于主出口 socket 同目录的 inference.sock。模型调用走主出口 socket；控制 socket 不接受模型调用、fetch 或 guest upgrade，不能被慢模型占满。普通 API UID 的 Bearer 只可查询本租户的去敏策略和账单，不能创建 grant 或通过任意 task ID 消费模型。公开 API 的推理能力在完整候选通过前仍不声明。

bind 将完整 tenant/task/物理VM/lease 绑定写为空账单，作为持久 grant；模型调用必须已有同一未关闭绑定。rootclose 先阻止新调用，取消/等待该任务所有已进入的调用与账单/审计完成，再持久关闭。close 先于迟到 bind 到达时，保存该绑定的空关闭记录，后到 bind 必须失败；对同一已关闭记录重复 close 可安全确认。不同绑定不能关闭或复用相同 task ID。出口重启保留 grant 与调用ID，并将未完成调用转为 uncertain，不重新执行模型。

guest proxy 的外层身份增加 root 写入的逻辑 task ID 与 remote-infer-v1 授权标记；服务对保留主机 inference.osv.invalid 的 HTTP 请求按此外层绑定处理。guest 内层头和 JSON 不提供身份、URL、凭据或价格。只有新增签名 profile 明确支持 remote-infer-v1 时 root 才赋予标记，旧 profile 不能通过构造保留 URL 获得推理许可。该标记、持久 grant 和租户推理策略须同时有效。

root 在发出 bind 之前，将绑定意图原子写入自己的 VM workdir；ACK 丢失也能恢复关闭。VM 退出先停止 proxy 并加入工作线程，再关闭账单；关闭确认失败保留 workdir 和物理保留量，使现有 cleanup-failed 门禁生效。启动 orphan reconciliation 在终止旧 cgroup 后、删除 workdir 之前确认账单关闭；出口不可用时不删除恢复意图、不允许复用该身份。恢复动作不依赖旧 PID，也不从 guest 文件读取绑定。

root RPC、公开 SDK/API 及静态运维程序现已提供账单导出/核对/回收协议，并完成组件与实际 mTLS/UDS 进程链路验证。完整离线候选仍须验证随包入口和真实 guest 任务关闭；不将测试用 Python 调用器作为目标机运行依赖。

## 公开接口与离线运维

新增 `POST /v2/sessions/{id}/ml/invocations`，正文只有已知 invocation ID、endpoint 别名、JSON payload 及可选 timeout_ms；响应包含逻辑 task_id、调用回执及 JSON data。API 校验自己的会话 owner 与能力，root 另通过独立RPC确认活跃registry、原签名模板、proxy模式、租户模板/推理许可及不可变VM绑定，再调用出口；不占用正在执行shell/code的同步控制锁。请求取消、TTL及VM退出取消调用，回执/账单按已知ID观察，不自动重发。

`GET /v2/ml/bills/{task}` 按Bearer租户查询持久历史，不要求活跃API会话、当前模板可新建或当前仍有推理许可；不存在和其它租户统一404。发现区分 remote_inference 与 inference_billing，前者需要签名v7、network proxy、相同租户端点/价格/限额策略及健康出口，后者来自已配置账单服务，便于撤权后查询。私有UDS状态带编译策略摘要用于API核对，公开发现只给别名/价格/限额，不给凭据路径或端点URL。旧模板不自动获得调用权限。

Python/Node提供session.ml.invoke(endpoint,payload)，可显式传 invocation ID；省略时先在本地生成，结果与异常都保留该ID。历史查询在client级可用。MCP工具使用同一公开API，模型调用必须显式提供已知ID，调用前按实际session owner能力检查。账单金额保持规范十进制字符串，不转为JS浮点金额。

SDK/MCP 实施细则：Python `Session.ml.invoke` 与 Node `Session.ml.invoke` 在有效调用 ID 生成后，用 `InferenceError` 保留 task/调用 ID、原异常及 `delivery_unknown`。该标记表示 POST 已尝试但没有得到经校验的成功结果，不能据此断言账单不存在；通过 `Client.get_inference_bill` / `getInferenceBill` 或 `Session.ml.bill` 查询。格式错误的显式 ID 在本地报配置错误。调用前读取实际 session 能力并核对原模板、v7、proxy/推理许可、别名及限额；不重做新模板 admission，不缓存金额策略。JSON payload 限定为有限、无自定义序列化的 JSON 数据，避免 NaN/Infinity、BigInt、丢失的字段或整数舍入静默改变模型请求。返回回执和账单核对绑定、状态、整数计价、预留/结算/占用总额；金额保持 uint64 范围的规范字符串。Node 支持 AbortSignal，Python 支持独立请求超时；取消后的已知 ID 不重发。

MCP 提供 `sandbox.ml.invoke`（session_id、显式 invocation_id、endpoint、payload）和 `sandbox.ml.bill`（task_id），分别按实际 owner 能力与持久账单服务授权。调用两工具时绕过新模板目录发现，但 HTTP 服务与 root 仍独立鉴权；账单查询不依赖活跃会话，允许撤权后查询。列表按当前能力声明工具，过期模板仍可声明已有 owner 的操作；账单服务能力独立于模板可用性。工具输出丢失或 MCP 取消不产生模型重试或隐式回滚。

同一个静态osv-sandbox-egress程序增加bill-export、bill-verify和bill-retire运维子命令。export按tenant/task经root控制通道取得已关闭规范记录，保存带SHA256的版本化私有归档，不覆盖现有文件。verify可离线验证记录、绑定、金额与摘要；retire再次验证并同步归档文件/目录后，以完整绑定与精确digest请求服务回收，归档继续保留。文件发布采用同目录临时文件同步及排他发布，失败不触发回收。操作要求root，普通daemon仍要求非root；不直接打开正在使用的ledger、不绕过writer锁。

## Guest SDK、外层策略与签名 v7

guest 内提供 Python `import remote_infer` / `import sandbox; sandbox.ml.invoke(...)`，Linux Node 提供固定 `/opt/osv/remote-infer.cjs` 的 `ml.invoke`。OSv 当前科学模板只承诺其已有 Python 运行时；不在本需求中虚构 OSv Node 运行时。Python 模块在 Linux 连接 PID1 固定的 `127.0.0.1:3128` 代理，在 OSv 使用现有全局 `osv_vsock_connect/send/recv/shutdown/close` C ABI 直连 CID 2、port 5001。Node 只使用同一固定回环代理。两端仅请求 `http://inference.osv.invalid/v1/policy|bill|invoke`，不读取环境中的 URL、凭据或 task/tenant；可修改 guest 代码不能改变 root 的授权。

模块导入不访问网络，允许 pristine 预热。首次操作从当前绑定的 bill 取得逻辑 task ID 后固定；每次 invoke 读取去敏策略，固定调用 ID，再提交一次。连接按单请求使用，发送后保持双向可读，不能用写半关闭把请求误判为取消。读写均有绝对期限、头/body 限额、明确 Content-Length 和严格 JSON；超时/断连后保留 ID 并查询账单。OSv 的负 errno 和部分读写按现有 C ABI 处理，不增加新原生库。规范计量/JSON校验从现有主机 SDK 生成项目内 guest 合约文件，生成器 `--check` 防止两端漂移；生成文件随实际镜像清单保留。

root 保存 `guestInferenceGrant{binding, policy_sha256}`，摘要来自该 launcher 启动时独立加载的租户策略，不从出口重新拉取来覆盖。每次外层 upgrade 携带摘要；出口在授权推理前核对当前编译策略。缺失/不规范摘要拒绝，策略变更拒绝且不预留费用；inner guest 头不能补齐或覆盖外层摘要。普通旧 profile 的代理保持原行为，不能申请推理授权。持久 intent/bill 的物理/逻辑绑定不混入可变网络头，关闭及回收继续使用原绑定。

签名 v7 复用完整 artifact/image/SBOM 绑定，并增加显式 guest SDK 文件摘要。Linux v7 必须含代码运行时、`code-contexts-v1`、`vsock-proxy-v1`、`remote-infer-v1`，可继续含已有 watch/port 能力；BusyBox 基础模板不因升级服务而自动成为 v7。OSv v7 保留现有 upstream/module/ROFS 约束，必须含 proxy/inference，保留已有 environment/stdin/pristine 能力。文件位于镜像的固定 Python site-packages 与 Node 路径，清单、来源及 SDK 合约必须实际核对；旧 v1..v6 规则保持兼容。v7 不以一个 feature 字符串代替 SDK 文件或真实镜像证据。

本段先验证共享 guest SDK 和外层授权，再制作实际双架构 Linux 镜像、现有 x64 OSv 镜像与 v7 签名。最终仍须工作区脚本内调用、任务账单、冷/暖独占 owner、服务换策略后拒绝、ARM 真包 QEMU 与 x64 同候选 KVM；普通协议或 C ABI 模拟不关闭 API-04。

## 分段交付和门禁

1. 共享策略、账单存储和有界推理引擎：实际本地 HTTP/TLS、DNS/地址拒绝、凭据过滤、并发预算、重启/故障及取消检查；功能不完整时能力保持关闭。
2. root/出口服务/API、双 SDK 和 MCP：任务身份、已知 ID、计量查询及生命周期；真实 mTLS/UDS 进程链路验证。
3. Linux 与 OSv guest SDK、显式签名和离线文件：实际 PID1/OSv、ARM 编译/QEMU及 x64 同候选真机，包含工作区脚本中的调用和任务账单。ARM KVM 不作为前置。
4. 完整候选冻结后运行一次完整 CI 与受影响 E2E；已通过且输入一致的项复用。失败或新变更再扩大检查，不降低原性能、内存或长稳要求。

API-04 在这条完整链路验收前保持开放；不得用本机 mock 或一次 HTTP 成功宣称已完成方案。增强安全认证不作为本轮前置，现有一般安全边界和审计失败门禁继续保持。
