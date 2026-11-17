# ADR-0022：有界会话文件列表、元数据和删除

状态：Accepted；日期：2026-10-30；需求 FILE-02、API-01、API-02。继承 ADR-0021 的租户、路径、故障与签名模板边界。

## 背景

rc19 已在同一 Linux session 内实现工作区文件的读写，但客户端无法按目录发现文件、查询类型/长度或删除文件。把这些操作转成 shell 命令会引入字符串注入，并绕过文件 API 的统一边界。

## 决策

扩展 `POST /v2/sessions/{id}/files` 的 `action`：`list`、`stat`、`delete`。`list`/`stat` 允许路径恰为 `/workspace` 或其下干净路径；`delete` 只允许 `/workspace/<path>` 且只删除普通文件。`list` 返回按字节序排列的直接子项名称，不递归、不跟随链接，最多 256 项、名称总 UTF-8 字节数最多 64 KiB；目录超限返回 413。文件名若不是 UTF-8，整个列表返回有界错误，不返回有损名称。`stat` 返回 `kind=file|directory` 与字节长度（目录为零）；链接、设备和其他类型拒绝。`delete` 成功返回零长度；目标不存在返回 404，目录/链接拒绝。

guest 仍从 `/workspace` 目录 fd 起点，用 `openat2` 的 `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV` 定位目标/父目录。列表通过已打开的目录 fd 遍历；元数据从已打开 fd 获取；删除先验证目标为普通文件，再以受限父目录 fd 调用不带 `AT_REMOVEDIR` 的 `unlinkat`。POSIX 名称删除与预检之间存在竞态：并发恶意修改时可能删除该父目录当前同名文件或链接本身，但不能沿链接越出工作区，也不能删除目录。文件操作继续占用同一 session 互斥、租户速率、审计、租期和故障关闭语义，不自动重试删除。

host 校验 guest 返回的 action/path、列表数量/名称/顺序/总长度、类型和长度；畸形结果关闭 session。Python/Node 原生客户端暴露相应方法，并校验响应绑定。能力声明仍限已认证 Linux session 模板。目录创建、递归删除、批量文件、产物导出和 E2B SDK 适配仍属后续范围。

## 验收

先完成 guest 的有界列表、类型、目录/链接/设备/路径和删除对抗测试，再做 Go 协议与租户测试、双语言客户端契约测试；当前候选如需更新，重新构建双架构测试签名包并以包摘要绑定 ARM64 无网卡 QEMU 与 x64 指定服务器 KVM 证据。ARM64 KVM 部署按用户确认免验。
