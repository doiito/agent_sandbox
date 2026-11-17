# ADR-0017：固定 E2B 版本、行为分母与独立 session 能力

状态：Accepted；日期：2026-10-30；需求 API-02、API-01、FILE-02、EXEC-02、NET-02。继承 ADR-0004、ADR-0015、ADR-0016。

## 背景

原方案 G4 要求 E2B Python/JS SDK 常用调用面兼容率 ≥80%，特别提到 connect、Sandbox、run_code、文件和端口。当前服务是一次性 `/v2/jobs`，Python/Node 客户端均是项目原生 API；没有持久 sandbox ID、跨调用文件系统、代码上下文或端口隧道。把每次 `commands.run` 映射为新 VM 会改变文件、进程、环境和超时状态，不能算 E2B 行为兼容。

## 决策

固定 E2B 官方 monorepo 的 `e2b@2.51.0` / Python `e2b==2.51.0`，提交 `ccaf9fc0ffe6ac39c7ec786af7608ab1de19467b`；同提交的 Code Interpreter Python `2.10.0`、JS `2.8.0`。以该提交源代码定义 34 个逻辑操作，分为生命周期 9、命令 7、文件 10、代码解释器 5、端口/URL 3；Python 与 JS/TS 的重载、异步变体不另计分。完整名单、调用名和预期行为保存在 [`e2b-2.51.0-matrix.json`](../contracts/e2b-2.51.0-matrix.json)。分母锁定为 34；≥80% 需至少 28 项。只在两种语言的同一行为用例均通过、且有真实服务端 E2E 证据时，将一项标为 compatible。方法名、单元 mock、原生 SDK 的一次性近似能力都不计分。未实现操作必须显式返回 unsupported，不得静默创建新 VM 或降级到另一语义。

持久 session 是兼容层的独立能力：版本化创建/连接/终止 API、租户绑定的不可猜测 ID、租期和取消、同一 VM 内多次命令、持久工作区、审计和配额。Linux 与 OSv backend 分别标注能力；一个 backend 不支持时不得替换 backend。先完成 session、文件、命令流，再接 SDK 适配器、代码解释器上下文和端口隧道。端口能力必须继承 host 认证与网络策略。生产 one-shot 路径继续保持当前强隔离语义，调用方显式选择 session。

## 验收与取舍

`scripts/check-e2b-matrix.py` 检查锁定分母、唯一 ID、语言映射和证据结构；`--require-target` 仅在 ≥28 项有双语言真机证据时成功。每项必须覆盖成功、失败、取消/超时和租户边界中适用的情形。矩阵当前 0/34，不能从原生 SDK 验收推出 E2B 兼容。持久 VM 增加资源占用与生命周期风险，须维持 per-tenant 配额、jailer/cgroup、签名模板绑定和显式 TTL；这是达成原方案 G4 的成本，不能通过重新定义“兼容”规避。
