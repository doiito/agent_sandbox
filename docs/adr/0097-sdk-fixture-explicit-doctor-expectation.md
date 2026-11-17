# ADR-0097：SDK 夹具显式声明宿主就绪预期

状态：Accepted；日期：2026-11-11；需求 QA-01/02、API-01、REL-04。

## 原始失败

rc85 完整 CI、两架构离线包、ARM QEMU 58 组、x64 非 root API 和指定机四套冷热推理通过。关闭宿主 swap 后，原 SDK E2E 把 `doctor.ready` 固定断言为 false，导致综合回归在 Python SDK 的首次任务之前失败，错误为“fixture unexpectedly reports production ready”。之前 API 和 session 检查成功；原任务 `rc85-regression-r1` 已终态退出并保留，不能改写为成功。Node SDK 有同一固定 false 假设。

## 决策与自评审

两个 SDK E2E 增加显式 `--expect-doctor-ready`。不传时仍要求 false，保留原未就绪诊断夹具的覆盖；传入时严格要求 true，不能改为接受任意值。Python 的 nsenter 再执行和 Node 的 namespace 再执行均必须传递该标志。报告分别保存预期和实际 ready，既有命名用例与分母不变。实际客户端、API、launcher、guest、离线包和资源配置均不修改。

风险是修正夹具时顺带放宽生产验收。处理是保留两种明确预期、布尔严格比较和全部原用例；新部署只使用 true，不为过门禁重新启用 swap。命令行标志只影响验证预期，不能改变服务响应。

先完成本设计和[自评审](../../PUBLIC-QUALIFICATION.md#private-evidence)，检查修改脚本语法与 namespace 传递，再用同一 rc85 包、新任务 ID 和新 fixture 完成受影响综合回归。复用已成功推理与不受影响的目录/OCI；保留首次失败、相同包摘要和原用例顺序。不因验证脚本两项断言修正重建未变发行包或重跑完整规范 CI；最终收据明确列出候选冻结后的验证工具变更。

同包 regression-r2 七套回归已成功，双 SDK 在 namespace 内实际/预期 doctor.ready 均为 true；独立合并确认 15 套、原 516 个命名用例及 44 个 gRPC 用例完整，原 r1 保持失败。见[rc85 验证记录](../../PUBLIC-QUALIFICATION.md#private-evidence)。
