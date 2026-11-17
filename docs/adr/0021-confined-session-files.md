# ADR-0021：会话工作区文件操作的客体内限制

状态：Accepted；日期：2026-10-30；需求 FILE-02、API-01、API-02、SEC-06。继承 ADR-0002、0004、0017、0018、0019、0020。

## 背景

原生 session 已能连续执行命令，但文件只能经 shell 间接操作。E2B 固定矩阵的文件操作要求同一 sandbox 内的 read/write/list 等语义；把文件路径交给宿主或 shell 字符串拼接会增加越界、符号链接和注入风险。当前 guest 工作区是独立 VM 内的 `/workspace`，生命周期由 launcher 控制。

## 决策

新增租户认证的 `POST /v2/sessions/{id}/files`，本阶段仅支持 `read` 与 `write`；其他文件操作仍显式 unsupported。请求只接受 `/workspace/<clean relative path>`，不接受 `/tmp`、绝对宿主路径、`.`/`..`、空组件、控制字符或反斜线。单文件/单次请求数据最多 512 KiB，原始字节用严格 base64 编码。文件操作与命令共用 session 的互斥、租期、租户限速、launcher 审计和故障关闭机制；不创建新 VM，不读写宿主工作目录。

guest 使用工作区目录 fd 与 Linux `openat2` 的 `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV` 打开目标或父目录；读仅允许普通文件。写使用同一父目录内排他临时文件、受限权限、完整写入及原子 rename，失败时清除临时文件；已有符号链接不被跟随。guest 返回绑定 job ID、操作、路径和字节数的结果；host 再次校验绑定和 base64/长度后返回客户端。缺失、拒绝、过大、损坏结果分别映射稳定错误；传输不确定时关闭 session，不透明重试写操作。

能力响应仅在已认证 Linux session 模板上声明 `session_files=true` 与文件方法及上限；OSv 不声明。Python/Node 原生 session 客户端暴露 `read_file`/`write_file`、`readFile`/`writeFile`；这些原生方法不直接计入固定 E2B 2.51.0 矩阵。后续仍需 list/stat/delete、批量与产物导出、E2B 适配层及双语言对应真实服务端证据。

## 验收

先做 guest 对抗测试（traversal、符号链接、跨挂载、设备文件、大小、二进制和覆盖原子性），再做 host 协议/租户测试、双语言客户端契约测试。最后从同一测试签名离线包在 x64 KVM 和 ARM64 无网络 QEMU 验证；ARM64 KVM 部署按用户确认免做。只在完整链路与候选摘要绑定时更新验收记录。
