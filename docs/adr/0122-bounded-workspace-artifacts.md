# ADR-0122：有界 workspace 产物归档与分块下载

状态：Accepted（实现与当前候选完整功能验收通过；Linux warm p99 发布门禁继续）；日期：2026-11-16；需求 FILE-02、API-01、API-03、SEC-01、SEC-03、LIFE-01、LIFE-02、OBS-02、QA-01、QA-02、REL-04。

## 问题与目标

原方案 R4 / §6.3.7 要求取回产物，并建议 tar 流减少 vsock 往返。当前 Linux 会话已有二进制读写、目录操作与监听，但单次 read 上限 512 KiB，主 guest 控制通道最多 100 次请求。FILE-02 的归档导出仍未完成。新增功能须支持大于单次 read 的实际文件，保留目录/二进制数据，提供完整性校验，并沿用租户、模板和会话生命周期。

采用[详细设计](../design/WORKSPACE-ARTIFACTS.zh-CN.md)。当前 rc90 功能与启动门禁保持其原证据；新产品候选须在本功能稳定后集中执行 CI、双架构离线、实际 ARM QEMU、当前 x64 KVM 和受影响回归。

## 决定

Linux 新签名模板使用 `workspace-artifacts-v1` 与 artifact manifest v8；显式启用 vsock 5005 的 `fc-artifact/v1` 服务。旧模板保持原能力，OSv session/workspace 仍不支持。服务在会话授权完成后、准备 ACK 发布前同步绑定身份与期限；pristine、one-shot、关闭/失效状态均不可导出。

guest 顺序发送受限文件/目录条目、64 KiB 数据帧和终态。宿主检查协议、session/request nonce、序号、路径、类型、偏移、计数、总大小、终态与 EOF。使用 Go 标准库生成确定性 POSIX tar，首个成员是 `.osv-artifact-manifest.json`，列出用户条目类型、大小与文件 SHA256。归档 SHA256 和总字节数在发布前计算。无新增第三方依赖，无自动解包。

公开接口为 create/read/delete：先创建不可变归档并取得元数据，再按 offset/length 读取最多 512 KiB 的块，最后删除。Python/TS SDK 的下载方法验证每块及完整归档摘要；MCP 使用相同三操作，原生 gRPC 增加三个方法并保留现有 45 个方法及字段编号。E2B 固定兼容分母保持 34，native 新方法独立验收。

每会话最多保留 2 个归档，每个 tar 最多 32 MiB，用户条目最多 1024、相对深度最多 16、路径合计最多 64 KiB。归档计入元数据和 tar 开销，达到上限明确拒绝。暂存文件位于私有 VM workdir，创建后立即 unlink，通过 root launcher 持有的 FD 使用；发布失败、删除、会话 TTL/取消/关闭及 launcher 退出均释放。API 不直接读取宿主文件路径。新导出与会话命令共用有界 opMu，现有归档块读取通过独立缓存锁并支持关闭竞争。

导出拒绝 symlink、hardlink、特殊设备、FIFO/socket、跨文件系统、路径逃逸和保留清单名冲突。guest 通过 FD 相对遍历/打开及前后身份/元数据检查检测普通并发写入；检测到改变则整个导出失败。该能力是检查后的文件集合，不承诺运行中 guest 文件系统的原子快照。发布前完成所有验证，失败不会返回可下载的部分归档。

## 回归与验收

先完成[自评审](../../PUBLIC-QUALIFICATION.md#private-evidence)，再执行定向 Go/Rust/双 SDK/MCP/gRPC 契约检查。重点覆盖大文件多帧、空目录与 Unicode、确定性/摘要、越界/伪造/截断、并发写入、缓存配额与删除重用、错租户、guest/UDS/HTTP 断连、TTL/关闭/launcher 崩溃及 FD/磁盘零残留。

普通 quick check 不运行 KVM 全矩阵。功能稳定后冻结一次新候选，保留原 15 夹具/516 项、44 原生 gRPC、OSv 输入 49 项及各后端池场景的独立分母，再加本功能 cold/warm、大文件、双 SDK/MCP/native gRPC 和清理。产品字节变更按既有规则复测四条正式启动路线；不得复用 rc90 数字为新候选登记。ARM KVM、K8s、过期域名证书以及增强安全范围遵循用户现有决定。

## rc92 当前功能验收

[当前候选](../../PUBLIC-QUALIFICATION.md#private-evidence)已通过完整 CI、双架构离线包、非 root 安装、ARM 无网卡 QEMU 65 组、原 KVM 15 夹具/516 项与 44 原生 gRPC、保留 OSv 只读输入 49 项；新增实际 Linux 基础/code × cold/warm 四夹具通过，全部独立清理。两后端各 18 类池场景及新签名轮转/过期通过。

四路线各 1000+5 全成功；当前 Linux warm 为 3.131/6.012/14.245 ms，p99 未达到 13 ms，其他三路线达标。固定诊断完成并保留原始数据，未重采正式结果或登记当前发布门禁。该功能验收不关闭其余原始 40 项要求，也不声明整体 mimalloc 收益。
