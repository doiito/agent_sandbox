# ADR-0050：会话文件重命名与递归删除

状态：Accepted；日期：2026-11-03；需求 FILE-02、API-01/02、REL-04；顺序遵循 [ADR-0049](0049-functional-delivery-and-baseline-security.md)。

## 功能

在 Linux 会话的既有 `/v2/sessions/{id}/files` 增加 `rename`（path + destination）和 `remove`（递归删除）动作。保留旧 `delete` 的只删普通文件语义。Python/TypeScript 原生 SDK 及固定 E2B 2.51.0 显式适配层同步支持；上游 rename 返回新路径的 EntryInfo，remove 返回空。已保存并验摘要的两份上游源码为行为依据。

rename 使用原子 renameat，支持文件/目录/链接本身及普通覆盖语义；结果绑定源路径和目标路径，返回目标 inode 信息。目标父目录必须存在，移动目录到自身后代或覆盖非空目录失败。两条路径均在 `/workspace` 内，根目录禁止移动。

remove 删除文件、目录树和链接本身；不跟随目录或最后一层符号链接。根目录禁止删除。一次最多访问 4096 个条目、32 层目录；超限返回明确错误，可能已有部分条目删除，调用方可检查/重试。保留路径限制、openat2 及独立 guest 文件系统，避免越界；不增加新的第三方运行依赖。

## 验证与交付

先[自评审](../../PUBLIC-QUALIFICATION.md#private-evidence)。测试实际文件和目录移动、覆盖、元数据保留、嵌套树/链接删除、缺失路径、根/越界拒绝、预算与失败后继续使用会话。两 SDK 检查返回路径/状态，新增真实工作流“写入→重命名→读取/执行→清理”，跨会话边界保留。

组合冻结后一次 CI；x64 指定服务器 KVM 的实际 API/双 SDK 工作流与相关会话回归，aarch64 Linux 离线包编译及 QEMU 功能验证。无 OSv 内核变更时不重跑其独立全矩阵。只有同候选双语言真实用例通过才增加 E2B 兼容计数。

[rc52 实施验收](../../PUBLIC-QUALIFICATION.md#private-evidence)完成双架构 musl/mimalloc 构建、完整本地 CI、ARM64 无网卡 QEMU 30 组及 x64 KVM 池/API/session 和双语言文件工作流。固定 E2B 计分为 12/34，完整功能与发布目标继续跟踪。
