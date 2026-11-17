# ADR-0023：固定 E2B 2.51.0 的双语言显式适配层

状态：Accepted；日期：2026-10-30；需求 API-02、FILE-02、LIFE-03、EXEC-02、NET-02。继承 ADR-0017、0019、0020、0021、0022。

## 背景

项目原生 Python/Node 客户端已有同一 VM 的 session 与文件操作，但方法名、结果类型和可用语义与固定的 E2B 2.51.0 公共调用面不同。直接宣称原生客户端兼容会误计 34 项矩阵。固定上游提交、源文件摘要和矩阵见[兼容契约](../contracts/e2b-2.51.0-matrix.json)；本决策仅对该版本生效。

## 决策

在包内已有的零第三方依赖 Python、Node/TypeScript 客户端增加独立 `Sandbox` 适配类，保留原生 `Client`/`Session`。调用方明确传入已配置 mTLS 和 bearer 的原生 `Client`，适配层不得持有跨租户全局默认客户端。`Sandbox.create('firecracker-linux', client=...)` 创建带签名模板选择的同一 VM session；`Sandbox.connect(id, client=...)` 只连接仍在运行的 session；`sandbox_id`/`sandboxId` 暴露同一 ID。创建时拒绝其他模板、网络/快照等无法保证的参数，不静默使用另一模板。每个适配方法由原生 API 执行，不通过 shell 拼接文件路径，也不为每次调用创建新 VM。

第一批实现 `is_running`/`isRunning`、`kill`、`files.read`、`files.exists` 的明确语义：404 表示已终止或文件不存在；认证、权限、传输错误保持错误，不能转换为 `false`。`kill` 成功返回 `true`，已不存在返回 `false`。`files.read` 默认 UTF-8 文本，显式 `bytes` 返回 Python `bytearray`/Node `Uint8Array`；路径仍限 `/workspace`，单文件 512 KiB。`files.exists` 使用 guest `stat` 区分不存在与拒绝。`connect` 对 paused/resumed 的兼容仍不成立，不能计入对应矩阵行；缺少的超时调整、命令控制、丰富文件元数据、代码上下文和端口/URL 能力显式返回 `UnsupportedCapability`，分子保持零直到真实服务端证据落盘。

调用形式旨在迁移常用 E2B 方法，不声称原版 `e2b==2.51.0`/`e2b@2.51.0` 包能直接连接本服务。后续若需要未经修改的原版包，必须另行实现其控制面和 envd 协议、认证与版本协商；本适配层不能被命名为原版包或接管其导入路径。任何计分记录必须列明与固定上游的参数/返回差异，且按 ADR-0017 具备 Python 与 TypeScript 同一候选真实 KVM 正反例证据。

## 验收

先核对固定源码 SHA 和行为，设计失配表并自评审；再做双语言契约/错误测试、包内 SDK 签名/SBOM、同一 KVM session 的跨调用状态与租户边界测试。ARM64 交叉编译和无网卡 QEMU 包验收继续执行，ARM64 KVM 部署按用户确认免验。没有双语言真实服务端证据时，E2B 矩阵保持 0/34。
