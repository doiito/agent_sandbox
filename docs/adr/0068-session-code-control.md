# ADR-0068：会话代码控制、独立RPC与SDK交接

状态：Accepted（guest控制核心双架构30组通过，外部vsock/API/SDK及模板继续推进）；日期：2026-11-05；需求API-02/03、EXEC-01/02、OSV-02、REL-04、QA-02/03。

## 服务和归属

为[代码worker](0067-persistent-code-worker.md)提供独立guest vsock端口5003；主执行、代理5001和watch5002保持各自入口。服务只接受现有host CID校验通过的连接，每次控制操作使用短连接，最多4个物理控制worker和16条actor队列命令；执行本身不占用控制连接。上下文及执行仍属于原session VM、owner和容量账本，不能生成另一套VM计费或复用记录。

guest服务持有Manager，控制线程只持有Client。退出先撤销permission、停止接受连接，再通知Manager停止并join，最后回收控制worker；不得在全局索引锁内等待guest或网络。代码执行、普通同步shell和文件观察可以并存。owner失联、TTL、硬寿命、VM关闭仍由原会话生命周期驱动，代码控制不能续租。

主agent仅在明确的代码模板启动参数下初始化服务，初始化错误使该模板启动失败；普通旧模板不自动启用。按现有main/pristine/watch路径核对，prepare的permission发布必须放在dispatch成功后、write_result之前；循环尾update不能代替这一顺序。legacy仅在确认session入口后授权，one-shot及pristine ping都不能打开租户接口。服务监听/关闭与Manager的实际线程所有权一起实现和验收。

## 消息与验证

guest请求是单行JSON信封，protocol为fc-code/v1，包含session_id、每次RPC的64字符十六进制nonce、可选pristine binding及一个类型化worker request。输入上限128KiB；有界读写与2秒actor调用期限。响应使用FC_CODE_REPLY前缀，回显同一protocol/session/nonce/binding，携带类型化response或有界错误。host同时核对连接所属VM、session、上下文ID/generation、执行ID和事件序号，不接受guest自报的身份扩大权限。

pristine状态下所有租户控制请求均拒绝；prepare成功后必须在发布ACK前把binding及有效期交给代码服务。legacy session沿用现有watch入口的可信host连接及session授权模式，one-shot不启用代码服务。具体生命周期绑定须在实施时与主agent现有路径逐项核对，不能只靠文档宣称已完成。

launcher使用单独的osv-sandbox-launcher-code/v1短RPC，沿用Unix peer credential、tenant/session owner检查、审计和生命周期context。后台执行状态不依赖该短连接的存活。root索引只查找owner句柄并取得生命周期引用，随后释放锁；响应丢失后以已知ID查询，不能重放同一执行。

## 原生API与显式适配

原生接口提供contexts的create/default/list/info/restart/remove及code-executions的submit/info/cancel。create与submit要求调用方提前生成24位hex ID；SDK在发请求前生成并保留ID，确保断线后可查询/清理。create/default/restart可以返回可观察的starting/stopping状态；原生执行提交立即返回，观察请求断开不自动停止后台任务。执行记录分页必须读到next_sequence等于last_sequence且状态已终结；只看到completed状态不能跳过后续页。

固定E2B适配层提供run_code/runCode和五项已核对接口。创建、重启和删除等待真实ready/清理后再返回上游规定的Context或None/void；language/context互斥，默认持久Python；别名由适配层规范化，未支持语言明确拒绝。默认执行期限60秒，0关闭执行计时但不关闭租期；request_timeout只控制请求阶段。原生默认cwd为/workspace，与上游默认路径的差异须公开，不能伪造真实cwd。

E2B同步run_code拥有本次执行的取消责任：超时、调用取消或回调异常时，通过独立控制通道取消已知执行并确认终态；Node逐个await回调。类型化上下文对象保存session绑定，防止同一owner的不同session混用对象。裸字符串ID按当前sandbox作用域解释，不作为授权令牌。MCP经同一认证API提供上下文和代码工具，不建立额外执行路径。

## 签名模板、预启动与离线发布

仅新签名Linux代码模板声明code-contexts-v1及5003入口；旧Linux与OSv模板明确不支持。镜像及清单绑定语言运行时、kernel脚本、TypeScript版本和双架构库闭包，目标机无需下载或系统动态库安装。x64科学运行时的CPU基线检查须覆盖实际所用指令，不能用qemu64的基础指令集冒充兼容。

预热只运行受信任初始化过程，选定预启动语言必须到达验证后的idle/ready才计入池最低水位。领取时先发布会话权限再ACK；任何已执行租户代码的VM均销毁。预启动语言、模板、内存和全局容量由同一池key及账本管理；未预启动语言的首次解释器创建不能算入1–2ms warm成果。快照、64MiB、2/5/10ms及千次性能门槛继续独立跟踪。

## 实施前自评审与门禁

先验证guest服务的pristine/legacy/prepare-ACK授权、身份回显、帧边界、控制并发、关闭和期限，再接launcher/API与两套SDK/MCP。正式worker的双架构功能通过是接入前提；Python空闲期后台async任务等语言语义仍需在代码API契约验收前明确验证，不能用变量持久和单次await替代完整行为证据。

worker核心已按ADR-0067完成双架构验收，空闲async和旧任务输出归属按[ADR-0069](0069-continuous-interpreter-async.md)另行补齐。设计获接受不代表服务、语言兼容、预热或新包已实现；后续验收必须绑定新增入口实际二进制和同一签名模板。

guest实施细节及实施前检查见[服务自评审](../../PUBLIC-QUALIFICATION.md#private-evidence)。Pending允许可信内部预启动而拒绝外部操作，Prepared按固定binding授权，legacy在主入口确认session后首次合法代码RPC锁定session_id；Revoked不可重新授权。控制队列deadline取RPC两秒与实际租期的较小值，actor逐条检查停止信号；服务独立监听循环在租期到期后停止并join Manager，不能依赖主入口再次收到请求才清理。

最终候选冻结后一次完整CI；ARM按用户要求做编译和实际QEMU功能，x64在指定服务器进行同包cold/warm、两SDK、MCP、断网安装、owner/TTL/崩溃回收。source/allocator/runtime/manifest绑定及实际VMM回收证明均须保留。只有同候选真实正反例满足固定矩阵后才能增加E2B分子；原34项分母、28项门槛、完整40项及生产/资源性能条件不改写。

guest控制核心及main处理器已完成[双架构30组实际功能验证](../../PUBLIC-QUALIFICATION.md#private-evidence)。Unix传输注入不能替代真实5003 vsock同包KVM；目前不增加E2B项，不接受公共代码API或新包。初始ready元数据只核对预启动上下文的原generation/当前Idle；租户使用、重启或移除后不用于重新入池。
