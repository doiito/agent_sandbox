# ADR-0004：版本化能力和产品契约

状态：Accepted；日期：2026-10-29。对应 R2/R3/R4/R6/R8/R9/R10，需求 API-01～API-04、OSV-02、OBS-01。

## 决策

已有同步 `/v1/jobs` 继续作为一次性任务协议；新增 session/stream/files/template 能力应使用版本化契约，记录 backend、模板 digest、协议版本、大小上限和支持方法。模板切换由调用方显式指定，拒绝未认证模板/不支持能力。

流式 stdout/stderr 必须有来源、序号、累计配额、背压、断连取消和终止事件。文件注入/导出必须限定工作区和总大小，防 symlink/traversal/设备文件/tar 炸弹；输入盘保持 ro/noexec/nodev/nosuid。后台子进程与继承 pipe 的后代不能令 agent join 永久阻塞，任务结束时必须清理 guest 进程，再由 host 完成 VM 销毁。

OSv vsock 驱动单独设计 virtqueue 生命周期、credit、disconnect/reset、内存所有权、帧上限和 fuzz；先基于固定上游版本做驱动验证，再接 agent。Python/Node/JVM 模板按 runtime + 包版本逐一认证，不能沿用上游“可以运行某语言”作为本项目所有依赖的测试结果。

E2B 兼容层明确 SDK 版本和方法列表，Python/TS SDK、MCP server 用契约测试验收；未实现的方法返回可识别 unsupported 错误。MCP 工具不赋予额外网络/宿主权限。OCI 分发、K8s、OTLP、计费和 GPU 外置等保留跟踪，未交付时不得通过静态说明宣称实现。

## 替代与后果

直接模仿方法名不能保证语义，静默 fallback 也无法保留隔离/SLO。显式能力增加客户端处理，但可防止调用方把 OSv 当通用 Linux，并给兼容承诺可测试的分母。
