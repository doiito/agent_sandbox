# ADR-0080：会话端口通道与隔离预览

状态：Accepted；日期：2026-11-06；关联 NET-02、CAP-01、LIFE-01/02、API-01/02/03。继承 ADR-0049 的功能优先与一般安全基线，K8s 不在本轮范围。

## 决定

入站端口使用独立的 `5004` vsock 服务连接同一 VM 的 IPv4 loopback TCP，不添加 NIC，也不打开宿主目标地址选择。支持任意二进制 TCP、独立双向背压、半关闭、取消、额度和终态；HTTP 预览与 WebSocket 使用这条通道。不能用有界 HTTP fetch 冒充端口隧道。普通命令、代码上下文和目录订阅继续使用各自的服务通道。

新签名 Linux profile 只有在 guest、launcher、API 和实际发布载荷完整接入后才能声明端口能力；现有 v4/v5 和 OSv 不隐式获得此能力。PID1 只在显式 `agent.port=5004` 时启动服务。pristine 状态、一次性 job 和未成功握手的 legacy 状态均不能拨号；成功准备的 session 使用原 binding/hard deadline，legacy session 首次有效请求固定 SID。撤权、shutdown、协议毒化和租期结束会关闭连接并等待 worker 回收。

`fc-port/v1` 采用长度前缀 JSON 握手：每连接提供 SID、随机 nonce、prepared binding、目标端口和传输限制，回复逐项回显绑定。后续每帧为类型字节加四字节大端长度。DATA=1（1..16384字节）、EOF=2（长度0）、CANCEL=3（长度0）；guest 单独使用 FINISHED=4 返回实际交付字节计数与固定错误码。EOF 仅关闭对应 TCP 写方向，反向仍可继续；未收到 FINISHED 不能当作已确认的正常结束。TCP socket 在 FINISHED 之前关闭，断线不重放已发送字节。分片或合并的读不能丢弃下一帧。取消若中断了写出一部分的帧，则直接关闭该传输，禁止把 FINISHED 拼入 DATA；通过独立 info 请求确认终态。

guest 同时最多8个数据worker，另保留4个短控制worker，每方向最多64MiB，连接时长最多300秒，空闲时长最多300秒；实际请求与原会话剩余硬窗口取较小值。握手最多4096字节、等待最多2秒，loopback connect 最多250ms。转发缓冲按帧固定上界；慢读、未完成帧、并发额度和停止时都不能无限占用线程或内存。限制必须作为能力返回，宿主还要在拨号前实行租户端口策略与连接额度。

控制请求为 open/cancel/info，使用调用者生成的连接ID。cancel/info独立于正在背压的数据连接；不能把取消排在阻塞的DATA后面。每会话最多保留256个ID记录，cancel可先于open生成取消占位，防止迟到的open拨号；重复open不重放。取消ACK仅表示接受，只有TCP关闭后的终态记录才证明连接已结束。物理worker槽在实际线程回收后归还；原数据连接发生HUP时，即使写向应用的缓冲已满也应立即取消。

宿主通道沿用可信 Unix peer 与原 owning session 校验，独立于命令 opMu，按 SID/backend/签名摘要确认能力。新连接与预览授权不延长 VM 租期或绕过当前租户策略。二进制数据不写审计日志，审计只记录身份、端口、字节数和终态。API 与双 SDK 的通道继续使用显式 DATA/EOF/CANCEL 语义，避免把 TLS 连接的物理半关闭误当作应用 TCP 的半关闭。

预览为独立授权的 HTTPS 入口，每份授权使用独立 hostname/origin，支持应用根路径、HTTP 流与 WebSocket。控制 API 的 Bearer token、客户端认证资料和内部预览 cookie 不传入 guest。初始授权 URL 的 secret 换取 Secure/HttpOnly/host-only cookie 后跳转到应用路径，secret 不留在应用 URL 或访问日志；应用不能覆盖内部 cookie 或给其他预览域设置 cookie。授权与原 tenant/SID/port/期限绑定，可撤销并取消其现有连接。域名和 TLS 由可信配置指定，不能信任请求 Host 生成链接；测试用受控 CA/解析，不将其记为 nas.deployment.example 的域名验收。

原生接口分别提供端口连接、预览授权和撤销；Python/Node SDK 与 MCP 共用认证和额度。固定 E2B 分母保持34，既有28项证据保持；`get_host` 等只有在固定上游语义确实验证后才增加兼容项，不将一个不同的预览 URL 算作 hostname 兼容。

## 推进与回归

### 宿主会话与策略实施约束

租户 auth/v1 增加可选 ports 策略：显式 allowed_ports 的闭区间（最多16个，升序且不重叠）、max_concurrent（1..128）和 preview 开关；缺省不开放端口。3128 为内置 egress proxy，始终不得作为入站端口发布。API 与 launcher 读取相同的可信策略；launcher 按已通过 Unix peer 验证的 tenant ID 查找策略，再校验 owning session。旧模板不受新增端口策略影响；单 token 的旧默认策略不自动开启端口。

每 session 保留最多256个不可重放连接ID，最多8条活跃连接。ID由调用者提供，必须与端口固定绑定；取消可在open之前形成占位，之后的open不能再拨号。成功拨号、取消、连接异常与session关闭共用记录。新连接同时取得租户全局连接槽与session槽；查询和取消不申请新槽，不占命令锁，收紧策略也不能阻止既有连接清理。

连接终态以guest确认TCP关闭为准。正常FINISHED或独立info的有效终态才返还槽；握手/响应丢失不能按失败即无连接处理。数据传输关闭后主动独立cancel/info，最多2秒内确认；无法确认时关闭原VM，只有Destroy成功后才能返还仍未确认的槽。session关闭先中断所有端口传输，然后走原VM清理；Destroy失败保持额度占用并沿用原清理失败门禁。后台清理不得在持锁状态调用Session.Close，避免与正在关闭的会话互等。审计增加连接ID/端口/计数，不记录数据、nonce或认证secret。

launcher单独协议包含SID、tenant、随机nonce、操作和连接ID/端口；open的ACK后复用有界DATA/EOF/FINISHED帧，保留首行后reader内已读取的数据。取消/查询走新连接；所有回复校验原nonce/SID/ID/端口。owner连接断开仍结束整个session，新端口连接不能变成新的session owner。guest协议与签名能力的就绪证明接入完成前，不允许正式profile声明这项能力。

### HTTP 双向通道实施约束

公开路径为 `/v2/sessions/{id}/ports/{port}/connections/{connection}`：POST要求HTTP/1.1、`Connection: Upgrade`及`Upgrade: osv-port/1`，body仅包含max_bytes/timeout_ms/idle_timeout_ms三个限制，必须有明确且不超过4096字节的Content-Length，不使用chunked上传。根服务open成功后才回复101；回显session、连接ID和端口，并保留原HTTP reader中的合并首帧。后续使用相同有界DATA/EOF/CANCEL/FINISHED语义；HTTP/2请求明确拒绝，SDK用HTTP/1.1通道。GET返回绑定session的连接信息，DELETE接受取消并返回202；取消ACK不是已关闭的证明，调用者继续查询终态。

POST复核已准入session的不可变能力及backend/签名摘要，校验当前租户模板/端口策略并消耗请求速率令牌；launcher仍独立复核。GET/DELETE沿用owner和原能力校验，不消耗新建连接额度或速率令牌，不因新建策略收紧阻塞清理。子连接不存在使用port_not_found，与父session缺失区分。不能通过URL或请求提供目标地址、任意端口服务选项或认证信息。

升级连接显式登记在API中，登记覆盖根open尚未完成的窗口。停机先关闭登记入口并取消所有pending/live通道，等待处理结束，再完成普通HTTP Shutdown；正常server退出必须等待这一过程。回收仍由root确认guest终态或原VM销毁，API不能仅以socket关闭返还root额度。双向缓冲按帧固定上界，慢读时写入最多等待2秒，绝对期限和原session关闭均中断等待。仅接受完整终态，不把缺失FINISHED的EOF当作成功；升级以后不向数据流追加HTTP错误响应。

根服务open握手期间独立观察Unix peer的HUP/RDHUP，不读取应用字节；client断开立即取消guest拨号/握手，随后按已知ID确认清理。不能复用会读取一个字节的普通session创建断线探针，否则会消费合并到首行后的DATA。Linux使用有界epoll等待并在握手结束时join观察线程；观察资源创建失败时拒绝新建连接。

### v6 与就绪证明实施约束

v6限定Linux并必须包含port-forward-v1；可独立组合code-contexts-v1、vsock-proxy-v1和workspace-watch-v1，特性排序、去重并拒绝未知值。code-runtime只在包含代码能力时存在且沿用v5固定运行时验证；v1..v5语义不变，OSv不隐式扩展。签名工具仅在显式请求port-forward-v1时选择v6，旧发行配置继续生成原profile。新profile实际发布仍须新载荷及同包验收，不将支持v6的源码等同于已发布候选。

PID1成功回复携带port_service：revision=1、protocol=fc-port/v1、port=5004、target=ipv4_loopback、state=pending/session，以及实际max_connections、max_records、max_frame_bytes、max_bytes和max_duration_ms。监听线程已结束、撤权或期限已过时不报告就绪。pristine探活报告pending，legacy有效ping后及prepare-session的授权ACK报告session；prepare-job完成撤权后不含该字段。Main结果中的binding继续由原v3验证，元数据不重复nonce。

宿主在启用端口的backend的每次ping/prepare回复中严格验证全部字段和预期状态；旧guest缺字段、错误限额、错误状态或成功job仍宣称服务均拒绝。由统一ExchangeSession检查覆盖cold创建、warm探活、prepare及绑定后ping，不通过设置普通ok字段绕过。准备/就绪失败继续使用原VM销毁和池补充路径，不将不完整VM交付给租户。

模板能力发现只在签名v6和实际backend同时启用时报告原生TCP支持及协议/额度；预览另要求独立入口实现/配置及租户preview策略，未配置不声明。API返回租户可用能力时按显式端口策略过滤并复制白名单，不修改已准入session保存的原模板能力，保证策略收紧后仍可查询和取消。SDK/MCP及预览未验收前仍不发布新完整候选。

### SDK 与 MCP 实施约束

Python和Node保持标准库/内置模块零外部依赖，沿用同一origin、TLS 1.3、CA、客户端证书及bearer；端口显式HTTP/1.1升级，不跟随重定向或环境代理。先构造调用者已知ID的连接句柄，再尝试一次open；任何不确定错误携带该句柄，禁止重放POST或DATA。可不打开数据通道直接构造句柄查询/取消，包括cancel-before-open。清理不重新依赖新准入能力发现。

句柄提供一次有界DATA写、显式close_write、一次有界read_frame、独立info/cancel和本地close。read_frame区分data/eof/finished，避免把应用EOF当作完整终态；没有隐式累积全部输出的wait。每方向单一在途操作，读写独立，背压直接传递给调用者，无无界后台队列。连接总期限从open开始计时，并在无人读写时也关闭底层传输；超时或断线保留ID，实际清理通过独立控制请求确认。半关闭只写协议EOF，不调用TLS CloseWrite。FINISHED核验绑定、固定状态/错误及字节计数，完成要求双向EOF和精确计数。

MCP使用同一认证HTTP通道，暴露已知ID的open/write/read/close_write/info/cancel/close工具。每次读写最多一帧，二进制base64，read不消费额外帧；RPC取消不重放字节，写结果不确定时关闭本地数据通道并保留远端ID供查询。持久通道由MCP连接拥有，数量有界，连接结束需关闭并等待清理；不能把单次有界fetch当作端口实现。工具按签名v6能力发现，操作时仍读取原session能力。组合v6不应丢失既有代码客户端能力，v5代码模板行为不变。

验证使用实际TLS/mTLS升级、分片与合并帧、任意二进制、双向EOF顺序、慢读背压、独立取消、总超时、错误绑定/帧/终态和缺失ACK/FINISHED；SDK/MCP组件测试不替代新镜像与同包KVM验收。

### 隔离预览实施约束

配置可选preview，包含独立listen、可信HTTPS origin_base、api_origin及预览TLS证书/密钥。缺省关闭；外部URL只由配置与服务端随机hostname产生，不采信Host/Forwarded。origin_base必须为DNS名称且不包含API hostname，证书必须有效并覆盖其通配子域。预览入口使用TLS 1.3，浏览器不要求API客户端证书；控制API仍保持原mTLS和Bearer。未启动完整入口时不声明预览能力。

控制路径使用调用者事先持有的preview ID：POST /v2/sessions/{id}/ports/{port}/previews/{preview}，body仅ttl_ms；GET/DELETE /v2/sessions/{id}/previews/{preview}。ID在session内最多保留32个、同时最多8份活跃授权，服务最多1024份活跃授权；重复POST拒绝。每次真正创建另外生成随机hostname，不能让调用者选取旧origin。有效期为请求窗口与原session剩余租期的较小值，最多300秒，续租不延长既有预览。响应丢失不重试：可按已知ID查询/撤销再创建新ID；GET不重发bootstrap secret。

每授权的bootstrap URL只使用一次，将256位secret换为同长度随机__Host-osv-preview Cookie并303到应用根路径。Cookie为Secure、HttpOnly、host-only、Path=/、SameSite=Lax，期限不超过授权。服务只保存摘要，不记录secret/完整URL。控制API凭据与内部cookie不得进入guest；应用Cookie的Set-Cookie拒绝Domain扩域和保留名称，内部cookie不能被覆盖。固定Origin-Agent-Cluster及Referrer-Policy，HTTP/WS的非空Origin必须等于本授权origin；不转发应用的跨域授权响应头。普通应用认证可保留，识别到本服务控制Bearer时移除全部Authorization，Proxy-Authorization始终移除。

HTTP与WebSocket复用既有native port帧及root额度。launcher的preview_id只允许在open出现，独立核对root租户preview策略，并写入不含secret的审计。每条连接的总期限受授权和session约束。每grant使用有界HTTP/1连接复用，最多8条上游连接；每grant最多16个、服务最多256个在途请求，不能用无界队列隐藏背压。Go标准Transport处理HTTP上传/响应并行和连接复用，通过请求级trace禁止断线后第二次发送应用请求；相同TCP可以承载后续独立HTTP请求，但不重放一个不确定请求。

HTTP响应流逐块转发并及时flush，不缓存完整正文；请求体上限8MiB，端口每方向总64MiB继续生效。WebSocket保留双方已读入的首帧，双向复制使用固定缓冲并在任一方向结束后关闭并join两方向。撤销、到期、session关闭和API停机同时取消pending/native上游及HTTP/WS前端，关闭空闲复用连接并等待处理结束。DELETE确认授权撤销，不把这一点冒充guest物理清理证明；物理槽仍沿用root终态/销毁门禁。

组件验证覆盖控制身份/策略、一次性URL与Cookie、错误Host/Origin、凭据过滤、HTTP根路径/上传/流、应用Cookie、连接复用、未知结果不重放、WS首帧/双向/慢读、额度和pending/live/idle撤销/期限/session/API退出。测试使用受控CA及本地解析；新候选才进行完整CI、ARM包QEMU和真实x64同包vsock/预览/SIGTERM，仍不声明nas.deployment.example证书验收完成。

先实现和验证 guest TCP 核心及 PID1 授权，随后接入签名能力、launcher/API、隔离预览与双 SDK/MCP，最后生成新的同包候选。分组件做受影响的定向测试；只在完整候选冻结后跑一次完整 CI、ARM 包 QEMU 和 x64 cold/warm/预览与相关旧功能回归。失败或新变更才扩大或重复检查。rc74 包与实际依赖保留；本 ADR 的中间实现不代表 NET-02 已完成，也不改变原性能/64MiB门槛。

实施前自评审见[评审记录](../../PUBLIC-QUALIFICATION.md#private-evidence)。

guest、双架构 PID1 和宿主帧通道的[组件验收](../../PUBLIC-QUALIFICATION.md#private-evidence)已完成；ADR 保持 Proposed，直到剩余完整链路与同包验收完成。

会话、策略和launcher的[组件验收](../../PUBLIC-QUALIFICATION.md#private-evidence)已完成：16组39叶用例/race通过，包级共享路径回归通过；正式v6、就绪证明、API/预览、SDK/MCP和同包验收仍开放。

HTTP端口与停机管理的[组件验收](../../PUBLIC-QUALIFICATION.md#private-evidence)已完成，协议见[port tunnel v1](../contracts/port-tunnel-v1.md)：新HTTP27叶用例、定向及HTTP/main共享回归/race通过。正式v6/就绪证明、SDK/MCP、预览与新同包验收仍开放，ADR继续Proposed。

v6签名、就绪与发现的[组件验收](../../PUBLIC-QUALIFICATION.md#private-evidence)已完成。源码支持显式v6，双架构PID1各9组、实际后端交换/签名/旧特性及定向race回归通过；旧rc74包不变，预览能力未声明，SDK/MCP/预览与新载荷同包验收仍开放，ADR继续Proposed。

双SDK和MCP的[组件验收](../../PUBLIC-QUALIFICATION.md#private-evidence)已完成：Python92、Node71及声明检查通过；端口sandbox与MCP全包共79顶层/233叶race通过，实际mTLS/API/launcher及MCP双协议36个脚本场景通过。SDK无额外运行依赖，MCP额外保留2个清理RPC槽。隔离预览、新载荷与同包验收继续开放，rc74不变，ADR继续Proposed。

隔离预览宿主核心的[组件验收](../../PUBLIC-QUALIFICATION.md#private-evidence)已完成：新增18顶层/20叶，HTTP流、双向上传、二进制WS、配额、root策略/审计和双监听器回收通过；定向race60/207，共享路径一次回归326/613且7项专用环境检查跳过，双架构编译/vet通过。SDK/MCP预览包装、新载荷及真实同包验收仍开放，rc74不变，ADR继续Proposed。

同批追加真实Chromium145的6组Cookie、来源、WS和撤销检查及单项race，通过后新增测试合计19顶层/21叶，最终203输入归档。生产代码未改，未重复共享回归；测试仅信任当前临时证书SPKI，不替代公共域名TLS验收。SDK/MCP预览包装及新同包验收继续开放。

预览授权的[双SDK/MCP与离线手册组件验收](../../PUBLIC-QUALIFICATION.md#private-evidence)已完成：Python98、Node77/类型，MCP42/74与预览17/22 race无跳过，四条真实mTLS/launcher客户端进程路径及离线手册签名安装通过。270输入冻结后复核一致，双架构各5个静态Go程序通过。授权独立于MCP进程，查询/撤销不依赖新建目录。现在进入双架构musl/镜像及新候选重建；同包VM、进程与原性能门禁仍开放，ADR继续Proposed。

[rc75同包功能验收](../../PUBLIC-QUALIFICATION.md#private-evidence)通过：双架构真实helper QEMU共88组、ARM离线包48组及x64七个隔离KVM夹具；端口/预览cold与warm各28项，包括真实vsock、双VM/租户/来源、双SDK/MCP、二进制HTTP/WS和生产API SIGTERM回收。安装后每夹具核对79文件。完整CI507输入通过；三份后续验收脚本修订独立绑定，产品与包保持一致，失败记录保留。该ADR的Linux设计范围完成，原性能/64MiB/长稳与其他需求继续开放。
