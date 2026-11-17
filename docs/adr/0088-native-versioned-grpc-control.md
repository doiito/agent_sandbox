# ADR-0088：版本化原生gRPC控制面

状态：Accepted（设计，尚未宣称gRPC交付）；日期：2026-11-10。对应API-01、API-02、API-03、OBS-01、QA-01、QA-03、REL-04。

## 需求与完整范围

原方案§6.3/§6.4要求REST/gRPC双协议。rc81已具备45个REST操作及完整离线OpenAPI，但没有gRPC服务。保留[rc81完整功能基线](../../PUBLIC-QUALIFICATION.md#private-evidence)，补齐版本化`sandbox.control.v1.Control`的45个对应操作、具名protobuf请求/响应、命令输出服务端流及端口双向流，提供.proto、descriptor和生成客户端。preview浏览器origin继续独立HTTP/WS，不虚构为gRPC上游页面协议。该范围全部实现和验收前，API-01的gRPC部分保持未完成。

## 契约和数值

以已核对实际Go类型/handler的canonical OpenAPI为结构来源，生成具名protobuf message、operation/path/query/body绑定及客户端。保留独立、持久的字段号/类型登记表：新增字段仅分配未用号码，删除字段保留名称/号码；已有号码、wire类型和oneof成员不可静默改变，检查模式不得更新登记表。新增REST操作必须显式进入gRPC映射，遗漏或陈旧生成物使检查失败。

proto3 scalar使用optional；列表/字典使用具名容器message，在需要处区分缺省/null和显式空容器。JSON null对输入scalar按原解码语义归入未设置；显式零、false、空字符串/bytes仍保留presence，特别是代码timeout_ms=0与缺省60000、文件空写入和stdin关闭。整数使用int64/uint64，计量decimal保持完整uint64域；时间保留原UTC字符串。CodeEvent使用具名oneof，各分支保留实际false/空值。任意JSON只在原有provider/MIME动态payload位置使用专用JsonValue联合，其中number为受JSON数字语法约束的字符串，避免double损失大整数精度；固定请求/响应不使用任意JSON外壳兜底。

## 服务和权限

同一个mTLS控制listener按HTTP/2及application/grpc媒体类型分派，REST入口保持既有处理链。gRPC成功调用在进程内适配到同一业务handler，继承同一认证、租户策略、配额、能力、账单、launcher/guest所有权及清理规则，不建立内部TCP代理或第二套VM管理器。转换只作用于gRPC调用，不给REST主路径增加schema反射/验证。protobuf与现有JSON整数映射单独实现，不能直接套用ProtoJSON的int64字符串映射。

gRPC在解码消息/公布未知方法前检查现有Authorization身份；后续公共业务链仍根据可信token构建租户上下文，不接受请求内租户字段。禁止把Authorization、原始路径、源代码、argv、输出和provider数据放入状态说明/标签。HTTP业务错误映射到标准gRPC status，并携带具名ErrorDetail（稳定code/message/http_status及可选invocation_id）；可能已派发的推理身份不得丢失，不能因传输失败诱导自动重放。在业务准入/派发前发送gRPC响应headers使调用提交，验证配置重试策略的客户端也不会因缺少提交标记而透明重放。状态说明和ErrorDetail.message使用稳定公开code摘要，不盲目复制可能包含用户输入的HTTP解析错误文本。doctor/readiness的结构化诊断需保留，204映射具名空成功响应，metrics有具名文本响应。

## 流、背压和退出

命令输出以具名output/result/timeout oneof逐事件发送，游标和最终状态保留，发送同步施加背压；只缓存一个有上限的完整事件，不累计整条SSE。每次实际发送设置有界写期限，发送成功后清除；首消息读取受握手期限约束，流建立后由业务总时间/空闲时间与取消控制，避免全局HTTP ReadTimeout错误截断已建立双向流。断连取消观察，持久session操作沿用原有短RPC结束规则。

端口首个双向消息必须为具名open参数，后续为有界数据/关闭帧，响应保留实际open/data/terminal语义。沿用既有连接ID、租户端口策略、字节/空闲/总时间限制及取消/半关闭。每方向至多一个待处理帧；所有bridge goroutine受明确owner和取消控制。客户端不半关闭、慢消费者、guest EOF、取消、期限和服务关闭必须验证；不能靠无限队列或丢弃流尾来让测试通过。

gRPC停止接收后，在独立有界窗口内排空或取消活动RPC。复用HTTP监听器时，由bridge管理准入、活动调用、首帧读取和response writer生命周期，再停止底层gRPC server。grpc-go的`ServeHTTP`传输调用`GracefulStop`会触发未实现的`Drain`，初次验证已复现。端口、HTTP、gRPC和遥测的退出顺序集中管理，最终已受理任务必须记录后再关闭导出器。验证graceful stop和超时强停均不遗留reader/pipe/VM或阻塞服务器退出。 [初次退出测试](../../PUBLIC-QUALIFICATION.md#private-evidence) · [修复后竞态检查](../../PUBLIC-QUALIFICATION.md#private-evidence)

## 离线依赖与实施顺序

保留现有Go1.24.2构建基线，固定兼容此编译器的grpc-go v1.79.3和其明确依赖；官方v1.85.0要求Go1.26，本轮不把编译器整体升级混入接口功能。完整依赖源、许可证、校验摘要和代码生成器保存在项目，Go vendor支持断网构建校验。新库编译进静态x64/aarch64应用；目标离线安装/运行不需要下载模块、安装protoc或额外共享库。既有REST Python/Node SDK运行闭包保持，原生protobuf客户端使用公开契约。

两架构包在x64构建主机上使用固定protoc与Go插件复核生成物。签名载荷包含`.proto`、编译描述符、使用说明和所链接Go模块的声明文件。模块版本取自目标API ELF的Go build info，逐一匹配vendor版本与许可证，并进入根发布SBOM的API组件。

先自评审并保存当前源码/rc81缺gRPC的负向证据，再完成契约/生成、原生传输、流和退出，按风险定向验证。阶段结果只证明相应组件，不把契约或一条RPC当作全部gRPC交付。功能完成后集中一次完整CI、双架构静态构建、实际非root双协议和ARM QEMU，再冻结新完整签名候选做指定机E2E/原回归及新增gRPC场景；开发中不高频重跑原15套。原40项、性能/64MiB/其他运行时、长稳/生产门禁不关闭，K8s/公网续证继续暂缓。

依据：[官方grpc-go版本依赖](https://github.com/grpc/grpc-go/blob/v1.79.3/go.mod)、[v1.85.0编译器要求](https://github.com/grpc/grpc-go/blob/v1.85.0/go.mod)、[protobuf字段号与演进](https://protobuf.dev/programming-guides/proto3/)、[显式presence](https://protobuf.dev/programming-guides/field_presence/)、[gRPC取消](https://grpc.io/docs/guides/cancellation/)和[流控](https://grpc.io/docs/guides/flow-control/)。
