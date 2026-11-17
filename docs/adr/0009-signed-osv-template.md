# ADR-0009：签名 OSv 模板的后端与模块绑定

状态：Accepted；日期：2026-10-29。对应 OSV-01、OSV-02、SEC-05、QA-02、REL-04。本决策只建立签名模板门禁，不表示 OSv 生产链路已验收。

## 背景

现有 `osv-sandbox-artifacts/v1` 签名 manifest 固定 kernel、rootfs、Firecracker、jailer 和 SBOM 的摘要与大小，但不声明 backend 或镜像内允许执行的模块。Linux 发布包使用 v1。现有 SBOM 工具固定标注 Linux guest、Rust agent 和 BusyBox；把它用于 OSv 会误报模板内容。OSv 诊断镜像目前包含 `/osv-job-agent.so` 与测试模块 `/task-probe.so`，生产配置仍拒绝 OSv。

## 决策

保留 v1 用于现有 Linux 制品，新增 `osv-sandbox-artifacts/v2` 给 OSv。v2 在原有文件摘要、大小和有效期之外，签名绑定 `backend=firecracker-osv`、规范化的 `entrypoints` 列表和固定上游提交。列表必须非空、字典序排序且无重复；每项必须是规范化绝对 `.so` 路径。运行配置的允许入口必须非空且是签名列表的子集，便于运维进一步收紧；未签名入口与 backend 不匹配均 fail closed。v1 manifest 不得用于 OSv，即使文件摘要本身有效。上游提交字段是签名来源声明，不能单凭它证明可复现构建；镜像摘要仍是运行字节的权威。

OSv SBOM 生成器必须明确使用 OSv profile，记录 OSv kernel/rootfs、内置 agent 和模块、API、launcher、Firecracker、jailer 与固定上游提交，不得标注 Linux guest、BusyBox 或与 OSv 无关的 Cargo 依赖。SBOM 由 manifest 摘要绑定。模板构建从固定上游和项目补丁生成最终镜像，真正运行的 kernel/rootfs 保存在项目 `assets/osv-native/`；密钥只作构建侧输入，测试私钥不得进入项目或包。

SBOM 的模块输入同时声明 guest 中的规范化绝对路径和构建文件路径，避免不同目录同名模块发生名称冲突。v2 验证器除校验 SBOM 文件摘要外，还应核对 OSv 提交、签名入口全集、kernel/rootfs 与 Firecracker/jailer 哈希同 manifest 一致；不一致时拒绝候选。

独立验证器从带外可信渠道取得公钥和期望的 kernel/rootfs 摘要，接受显式 backend 与运行入口策略，调用同一签名/文件校验逻辑。包内公钥不能自行证明包可信；验证器不从待验证 manifest 自动生成其期望摘要或入口策略。测试候选与正式发布分开命名和留证。

## 验收与发布门禁

先做 v1 兼容和 v2 正反向测试：签名、过期、后端混用、未签名入口、重复/非规范入口、篡改 SBOM 均拒绝；OSv SBOM 不含 Linux 专属条目。再构建测试签名候选并在指定服务器独立验证，随后接入独立 launcher、mTLS/租户策略和真实 KVM E2E。模板兼容矩阵、长稳与独立安全评审仍是 OSv 生产门禁；这些完成前 `production=true` 继续拒绝 `firecracker-osv`。
