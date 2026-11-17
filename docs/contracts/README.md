# 版本化接口契约

REST OpenAPI 覆盖 45 个注册操作及 74 个 schema，随双架构离线包签名交付。通用错误信封覆盖应用错误、路由 404/405 和认证边界。推理错误另有可选 `invocation_id`。rc81 在指定机通过原有 15 套 KVM 回归，共 516 项。 [OpenAPI](../../api/contracts/openapi.json) · [REST 使用说明](../API-CONTRACTS.zh-CN.md) · [HTTP 错误信封](http-errors-v2.md) · [错误 schema](http-errors-v2.schema.json) · [rc81 验收](../../PUBLIC-QUALIFICATION.md#private-evidence)

`sandbox.control.v1.Control` 提供对应的 45 个 RPC，以及其中的命令输出服务端流和端口双向流。固定工具链复核生成物和独立字段兼容基线。双架构签名包和指定机的 gRPC 验收按 API-01 跟踪。 [Protobuf](../../api/control/v1/control.proto) · [描述符](../../api/control/v1/control.descriptor.pb) · [使用说明](../GRPC.zh-CN.md) · [ADR-0088](../adr/0088-native-versioned-grpc-control.md)

## E2B 固定版本兼容分母

本项目以 E2B 官方 [`e2b@2.51.0`](https://github.com/e2b-dev/E2B/releases/tag/e2b%402.51.0) 的完整提交 [`ccaf9fc0ffe6ac39c7ec786af7608ab1de19467b`](https://github.com/e2b-dev/E2B/tree/ccaf9fc0ffe6ac39c7ec786af7608ab1de19467b) 为源。该提交的 [Python 包](https://github.com/e2b-dev/E2B/blob/ccaf9fc0ffe6ac39c7ec786af7608ab1de19467b/packages/python-sdk/pyproject.toml)和 [JS 包](https://github.com/e2b-dev/E2B/blob/ccaf9fc0ffe6ac39c7ec786af7608ab1de19467b/packages/js-sdk/package.json)均为 2.51.0；同提交 Code Interpreter Python 包为 2.10.0、JS 包为 2.8.0。`e2b-2.51.0-matrix.json` 记录 17 个官方源文件/包清单的 SHA-256 和 34 个逻辑操作。源码核对后，生命周期 9、命令 7、文件 10、代码解释器 5、端口/URL 3 项；重载和异步变体不重复计分。

这份分母覆盖原方案 G4 指定的 connect/Sandbox、run_code、文件、端口和命令调用面，同时纳入这些调用所依赖的创建、终止、超时和状态操作。未计入模板构建、卷、密钥、Git 等其他 E2B 产品面；它们不能据此宣称兼容。若要调整“常用”范围，必须新增 ADR 和矩阵版本，保留旧分母及其结果，避免将难实现的方法从现有分母删除。

计分规则：同一逻辑操作的 Python 和 JS/TS 调用均针对同一候选通过真实服务端行为测试，才计 1 分。每端至少提交成功和失败用例；适用的租户、持久状态、取消、超时与资源回收须在行为用例中核对。证据文件必须位于 `results/e2b-2.51.0/`，包含 `suite=e2b-compat-case/v1`、操作 ID、语言、固定上游提交、候选 SHA-256、`environment=real-kvm`、两个以上通过的用例和 `passed=true`，并由 `e2b-2.51.0-evidence.json` 以 SHA-256 引用，同时核对项目 `dist/` 中候选包的字节摘要。分母 34，≥80% 即至少 28 项。原生一次性 `/v2/jobs` 不满足 E2B 持久 Sandbox 语义；显式双语言适配层已于[rc74代码模板验收](../../PUBLIC-QUALIFICATION.md#private-evidence)达到 **28/34**，2026-11-10[离线审计](../../PUBLIC-QUALIFICATION.md#private-evidence)复核通过；[rc52的12/34](../../PUBLIC-QUALIFICATION.md#private-evidence)保留为历史结果。未覆盖方法仍在原分母中；没有宣称未经修改的官方SDK兼容。这不是 SDK 源码数量或 API 请求成功率。

本地离线审计：

```sh
python3 scripts/check-e2b-matrix.py --output results/e2b-matrix-audit.json
```

若可访问官方 GitHub，可加 `--verify-upstream` 重新下载固定提交的 17 个源文件/包清单并核对 SHA-256、版本及方法存在性。发布门槛用 `--require-target`；当前有28项双语言真实E2E证据，门槛复核通过。此结论不表示原性能、其余功能或整项目发布门禁已通过；不带行为证据的矩阵完整性审计本身只证明分母可靠。

## warm pool 启动与安全门禁

`warm-start-gates.json` 固定 Linux/OSv x64 的 warm/cold 分路径样本、启动分位数和安全故障用例；当前 warm 阈值为 **p50≤5 ms、p95≤9 ms、p99≤13 ms**，见[ADR-0114](../adr/0114-warm-start-five-nine-thirteen.md)。独占 owner、崩溃对账、身份隔离和零残留均必须验证。`scripts/check-startup-gates.py --require-target` 只接受摘要绑定的真实 KVM、生产 doctor 就绪和每路径至少 1000 个成功样本；未执行不通过，QEMU/helper/小样本不能替代。正式非测试离线打包强制调用它，当前仍缺合格性能批次。详见[rc37 功能证据与限制](../../PUBLIC-QUALIFICATION.md#private-evidence)。
