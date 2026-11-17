# ADR-0024：受限会话目录创建与 E2B 文件写入

状态：Accepted；日期：2026-10-30；需求 FILE-02、API-02。继承 ADR-0021～0023。

## 背景

固定 E2B 2.51.0 的 `files.make_dir` 会递归创建父目录，并区分新建与已存在；`files.write`/`write_files` 在父目录不存在时也会创建父目录，返回每个文件的名称、路径和类型。本项目 rc23 原生 `write_file` 只允许已存在父目录，因此不能把相同方法名计为兼容。上游公开源码及版本摘要见固定矩阵。

## 决策

在已认证、租户绑定的 Linux session 文件操作中增加 `mkdir`，路径只可位于干净的 `/workspace/<relative>` 下，最多 1024 UTF-8 字节、16 个分量。guest 从已打开的 workspace fd 逐级使用 `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_XDEV)`；不存在的分量以 `mkdirat` 创建、再重新受限打开，绝不把路径拼接后交给 shell。新目录权限 0700，guest PID 1 在特权状态下将新目录所有权交给 sandbox UID/GID；已有目录不改权限或所有权。结果 `created` 是布尔值，只有最终目录新建时为真；已存在为假。错误、symlink、跨挂载、文件占位和超深路径不得转成 `false`。host 校验 guest action/path/size/created 的完整绑定，畸形成功结果关闭 session。

Python/Node 原生客户端分别增加 `make_dir`/`makeDir`。显式 E2B 适配类实现 `files.make_dir`/`makeDir`、`files.write`、`files.write_files`/`writeFiles`：先验证所有输入，单文件接受 UTF-8 文本或内存字节，批量最多 16 项且总字节数最多 512 KiB；每个写入先创建其父目录，再调用已有原子 `write_file`。返回 E2B 风格 `WriteInfo` 的名称、路径、`file` 类型；可选元数据、用户、流式输入、gzip、请求信号等当前无法保证的语义显式拒绝。批量是顺序执行；若中途失败，已成功的文件保持写入，调用方不得自动重试未知结果。单个文件仍最多 512 KiB。所有调用保持同一个 session ID、租户、TTL、速率与 guest 文件边界。

`files.remove` 的递归目录语义、`files.list/get_info` 的丰富元数据、`rename` 的返回类型均不能由本变更推导为兼容。仅在同一签名候选的双语言真实 KVM 正反例和候选摘要落盘后，才给上述三项矩阵计分。ARM64 交叉编译和无网卡 QEMU 功能需通过，ARM64 KVM 部署按用户范围免验。

## 验收

先做 guest 目录树、文件占位、symlink、路径深度、权限和回归测试，再做 host 协议绑定/租户错误、双语言 SDK 契约及 CI。guest 变更必须重建两架构 rootfs、agent 与签名包，从项目 `assets/offline/` 读取全部真正运行资产；x64 指定服务器完整真实 KVM，ARM64 无网卡 QEMU。根据 ADR-0003，仅重跑受影响的文件/session 用例及必要的发布门禁。
