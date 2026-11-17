# OTLP指标、日志与trace

API内置OTLP/HTTP JSON导出，缺省关闭。离线安装与运行无需安装Collector、OpenTelemetry SDK或动态库；启用导出时，由管理员指定可访问的接收端。离线且无接收端时省略`otlp`配置即可。

## 配置

在API与launcher共用的配置中增加可选对象；只有API创建导出worker，launcher校验配置但不读取导出凭据、不重复发送。示例：

```json
{
  "otlp": {
    "endpoint": "https://collector.example.internal:4318",
    "service_name": "osv-sandbox",
    "signals": ["metrics", "logs", "traces"],
    "interval_ms": 1000,
    "timeout_ms": 5000,
    "queue_capacity": 1024,
    "batch_size": 128,
    "max_batch_bytes": 1048576,
    "trace_sample_permille": 1000,
    "ca_file": "/etc/osv-sandbox/otlp/ca.pem",
    "client_cert_file": "/etc/osv-sandbox/otlp/client.pem",
    "client_key_file": "/etc/osv-sandbox/otlp/client.key"
  }
}
```

接收路径为endpoint基础路径下的`/v1/metrics`、`/v1/logs`、`/v1/traces`。默认使用系统CA，可通过`ca_file`追加信任；客户端证书与私钥须成对配置。不使用mTLS时可省略该对配置；需要Bearer时指定`bearer_token_file`。私钥和token文件必须由root或API用户拥有，权限0600或更严，路径不得包含符号链接；文件仍须能被非root API读取。证书/CA可为可读普通文件。凭据在启动时读取，修改后重启API。

生产接收端使用HTTPS。只有显式`allow_loopback_http: true`才允许数字loopback IP的HTTP，用于同机接收端；不接受URL凭据、query/fragment、跨域重定向或环境代理。默认资源source为`host.api`，API配置不接受其它source。未指定`instance_id`时随机生成实例标识，不自动导出主机名、环境或配置。

范围：interval为100–60000ms，timeout为100–30000ms；queue为1–16384，batch为1–1024且不超过queue；max_batch_bytes为64KiB–4MiB；trace采样为0–1000千分比。省略signals时启用三种信号。采样只作用于trace，日志仍独立导出；被采样的同一请求，其日志和span共享ID。

## 数据含义

- API指标保留进程累计起点，含HTTP请求/认证失败、单次任务完成/拒绝、inflight及duration原始直方图。`jobs_total`针对`POST /v1/jobs`和`POST /v2/jobs`，不将会话代码执行次数混入该计数。
- 请求事件与server span只导出认证租户、注册路由pattern、规范method和验证后的任务ID/backend/模板摘要/state/startup_mode。原始URL/query、header、argv/env、代码、文件、stdout/stderr和错误文字不导出。部分路由提供已知状态码；其它路由只表达handler正常返回，不将其推断为HTTP或任务成功。
- API观察、launcher状态和guest自报分源；当前API接入不伪装root持久审计。池profile包含key及模板/backend，避免同名碰撞。launcher生命周期独立于API，现有快照没有counter起点，因此其累计值按`*_observed` gauge保留原值；池查询失败时`osv_sandbox_warm_pool_snapshot_available=0`，仍保留API指标，不将未知状态当健康。
- 大于signed int64的number值按double表示；int64范围内counter与uint64直方图count/buckets使用精确整数。遥测不能替代精确账单或持久审计账本。

## 失联、计损与退出

前台只做有界入队，不执行Collector网络请求。单worker使用有界队列/批次/响应，Collector慢或失联不阻塞业务；满队列和发送失败会计损。只对429/502/503/504及规定网络失败有限重试，遵守总期限和Retry-After；非空partial warning或实际拒绝不重试。空partialSuccess按无警告/拒绝处理。

认证后的`GET /metrics`提供`osv_sandbox_otlp_*`计数和队列水位，OTLP指标也包含这些计数。`event_drops_total{reason}`区分invalid、queue_full、closed、unencoded；每信号的dropped_records与exported_records分别统计。一个事件可能产生日志和trace，不能将跨信号record数量当作独立业务事件相加。HTTP200或无丢失发送只表示接收端接受，不保证最终后端持久化。

退出先关闭升级连接并排空HTTP，再等待完整外层请求的最终事件，最后在独立最多5秒期限内关闭导出器。等待/导出超时或已知计损会返回错误，并记录无敏感数据的计数及worker是否已停止；重复关闭保留此前的失败。root JSONL审计的fsync和失败闭锁仍独立，OTLP不替代它。嵌入式调用者应在HTTP排空后调用handler的`CloseTelemetry(context.Context)`。

## 开发与验收状态

源码接入与定向验证见[应用记录](../PUBLIC-QUALIFICATION.md#private-evidence)，组件协议验收见[组件记录](../PUBLIC-QUALIFICATION.md#private-evidence)。完整离线候选/指定机KVM仍须在本轮稳定后集中验收；guest资源及syscall/文件/网络全事件、root持久事件导出/轮转/告警和原性能/长稳门禁仍未完成。不能由本地脚本launcher夹具或组件验收关闭原40项需求。
