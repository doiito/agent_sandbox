# ADR-0085：有界 OTLP 指标、日志与 trace

状态：接受，分组件实施。日期：2026-11-09。关联OBS-01、OBS-02、PERF-03、REL-04、QA-01/03；原40项及未完成门禁不变。

## 范围与协议

原方案§3.2 R8、§6.3观测包含OTLP指标，§控制面包含日志/trace。三种信号均保留，不以Prometheus或仅指标替代。采用[官方OTLP/HTTP JSON规范](https://opentelemetry.io/docs/specs/otlp/)的 `/v1/metrics`、`/v1/logs`、`/v1/traces`；lowerCamelCase、64位整数十进制字符串、trace/span ID十六进制、枚举整数。应用使用Go标准库，不增加目标机运行依赖或collector安装要求。collector是管理员选择的独立接收端；项目内固定的官方程序仅用于互操作验收。

## 执行和失效语义

缺省关闭。启用后只有一个后台worker，事件使用有界队列和非阻塞入队；满队列、采样、无效输入和发送失败分别计数。采样/批量/间隔/请求期限/响应上限/批次大小均有明确范围。前台不执行网络、证书读取或重试，不在任务指标锁内发送数据。指标先复制一致快照，再编码/发送，Prometheus同样不跨网络写持有任务计数锁。累计counter/histogram保留进程起始时间，批次截分不改语义；大于signed int64的number值用合法double表示，直方图计数保持uint64精确字符串，不能把遥测当整数账单账本。

collector不可用不阻止任务。JSONL持久root审计的fsync与失败闭锁继续独立，OTLP不成为审计持久化的确认或替代物。三个信号分别核对响应，partial success记录拒绝数且不重试；429/502/503/504和网络失败在总期限内有限指数退避，遵守有界Retry-After；其它4xx/5xx不重试。重复发送仅限遥测批次，不触碰模型调用、任务或文件操作的重放规则。发送结果不确认时不得报告成功。

HTTPS使用系统/显式CA和可选mTLS；Bearer只从权限受限文件读取。明文仅显式loopback IP。拒绝URL凭据、query/fragment、跳转和环境代理；请求和响应大小有界，不打印远端body、错误文字或凭据。密钥/凭据仅启动读取，当前轮换通过正常重启，不宣称热重载。

## 数据与集成

资源只默认给service.name和随机service.instance.id，不自动导出主机名、环境或配置。事件属性有数量和字节上界；API适配器只允许租户ID、静态route/method、合法task ID、backend、归一化state/startup_mode等字段，不导出URL/query、请求/响应body、argv/env、代码、文件内容、stdout/stderr或Provider凭据。host.api、host.launcher.audit、guest.reported来源必须区分；guest自报不能升级为root持久事实。内核/syscall/文件/网络全事件及guest资源采集仍按原范围实现与验收，不能用API完成事件关闭这些缺口。

先实现独立三信号codec/传输、队列/重试/关闭生命周期，再接入API配置、指标快照、逻辑事件与trace。API观测不包裹ResponseWriter，保留原hijack/stream接口。若需root池状态，使用可取消、有截止期的快照调用，不能启动无界RPC或每请求查询。HTTP停收/排空后才做最后flush，超时取消并明确计损，不因收据已生成就宣称worker退出。

## 验收与发布

实施前自评审后做native race/vet、分信号JSON和边界/隐私/重试/部分拒绝/满队列/慢端/取消测试；用固定官方collector独立解码三信号。amd64/aarch64静态编译和ARM函数按影响验证。核心codec/传输组件不能代替API接入或真实任务证据。API接入后执行实际非root进程、mTLS、原流式/代理与端口定向回归；同候选完整CI、离线包和指定机KVM集中执行，不因工具或文档变化高频重建未变guest。性能收益/开销需同条件实测，原2/5/10ms、64MiB、吞吐及长稳门禁保持。
