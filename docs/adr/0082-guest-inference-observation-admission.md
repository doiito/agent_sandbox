# ADR-0082：guest 推理观察与模型配额分离

状态：Proposed；日期：2026-11-07；关联 API-04、NET-01、OBS-01/02、QA-03。

## 实机发现

rc76 完成 896 输入完整 CI、双架构离线包验签与 ARM 真包 50 组 QEMU 检查，但 x64 Linux KVM 在模型超时后立即查账失败。去敏审计记录：模型已持久转 uncertain，旧 proxy 的 deferred release 尚未完成，新 GET 连接因租户 `max_concurrent=1` 被 `egress_busy` 拒绝。guest SDK 正确拒绝普通代理错误帧，不能靠重试模型 POST 或放大夹具配额规避。

现有 root 控制和主机账单 API 有独立通道，guest bill/policy 却在解析保留路由前消耗模型/网络并发，导致在模型占满时无法观察自己的账单。这与 ADR-0081 的可观察账单语义不符。

## 决定

仅对经 root UID、签名 v7 双能力和启动策略摘要核对的 inference upgrade，先使用独立且有界的 transport 入口，读取有界的首个 HTTP 请求，再分配工作配额。入口在全局和租户维度限制连接，保留固定观察余量；每次 upgrade 仍只消费一次租户速率令牌，沿用总期限、头/正文/relay 上限、跟踪和退出加入。

保留 URI 的合法 GET bill/policy 不占模型/网络工作槽，但仍要求完整 root 绑定、租户授权、有效策略、审计与持久状态。POST invoke 必须取得原有全局与租户工作配额，再进入原预算预留、出站和持久结算。v7 上的普通 HTTP/CONNECT 在解析后仍取得同样工作配额。没有 inference grant 的旧 proxy 保留原准入行为。

入口本身不能无限排队，不能让占满工作槽的正常模型吞掉全部观察余量；恶意慢头、无效路由和退出时仍有明确释放。busy 的推理 POST 使用规范 inference JSON/Content-Length 错误响应，保留已知 ID，不拨号、不预留、不重放。root bind/close/export/retire 通道继续独立。

transport 上限为全局工作并发加 16、租户网络工作并发加 4；工作槽满载时仍有对应的观察余量，所有连接继续受速率及期限限制。该固定余量控制额外 FD/缓冲占用，不代表增加模型并发。达到 transport 上限仍返回有界的繁忙拒绝。

SDK、签名合同、guest 镜像及模型/金额格式均不变。修复发生在宿主出口服务，必须生成新双架构候选；不能对已签名 rc76 安装内容打补丁并沿用其验收结论。

## 门禁

先用 `max_concurrent=1`、真实 UDS 与正在等待的模型复现：GET bill/policy 必须即时返回且工作槽保持占用；额外模型和普通代理仍拒绝、没有新增消费。取消、关闭、慢头上限和释放必须覆盖。保留 rc76 失败日志及包摘要。

修复后先定向 race/真实 SDK 进程链路与 ARM 编译/函数回归，再冻结新候选集中完整 CI、实际 ARM 包 QEMU、Linux/OSv cold/warm KVM 及受影响原矩阵。夹具修正按同包摘要复用已通过项，产品变更按影响重新验收。原性能、64 MiB、allocator A/B、长稳及正式发布门禁保持开放。
