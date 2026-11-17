# ADR-0028：受限文件信息的符号链接与 E2B 扩展属性

状态：Accepted；日期：2026-10-30；需求 FILE-02、API-02。继承 ADR-0021、0022、0027。

## 背景

rc26 对普通文件和目录返回完整 inode 信息，但省略列表中的符号链接与特殊文件，直接查询链接返回 403。固定 E2B 2.51.0 的 `EntryInfo` 可表示 `file`、`dir`、`symlink`，并报告 `symlinkTarget` 和 `user.e2b.*` 扩展属性。当前行为只是受限子集，不满足固定矩阵中 `files.list/get_info` 的行为定义，不能计分。

## 决策

保留原生 `stat`、读、写、删除对链接的拒绝；新增只读 `info` 文件动作，供显式 E2B 适配层查询 inode 信息。`info` 对 `/workspace` 和受限子路径有效，不解析最终符号链接。`list` 继续返回同一有序名称数组，但 `entry_infos` 为每个仍存在的目录项提供信息；普通文件、目录、符号链接分别标为 `file`、`directory`、`symlink`，其余 inode 标为 `other`，映射到上游未识别类型。链接目标通过已打开的 `O_PATH|O_NOFOLLOW` 链接 FD 读取，只作为文本返回，绝不跟随；读写、删除和原生 `stat` 的拒绝语义不变。

信息项增加可选 `symlink_target` 与 `metadata`。`metadata` 只读取 `user.e2b.*` 扩展属性并剥去前缀；无属性时省略。属性键使用上游 HTTP token 字符集且最多 246 字节，值使用可打印 ASCII，其他值拒绝而不截断。单项最多 16 个属性、16 KiB 属性字节；总信息响应仍受 256 KiB 上限约束。读取扩展属性使用已打开 inode 的 `/proc/self/fd` 路径，目录项被替换也保持原 inode 绑定；不以读取内容的方式打开特殊 inode。ext4 不支持符号链接 inode 的 `user.*` 属性，链接信息省略 metadata，且绝不通过 `/proc/self/fd` 跟随链接目标。宿主须校验类型与 mode、链接目标、属性键值、路径绑定、列表顺序和总量。

`write` 可选带同一格式的 `metadata` 对象。guest 在临时普通文件上先写内容、设置 `user.e2b.*` 属性、同步，再原子替换目标；任一属性失败则删除临时文件且不替换旧文件。原生 SDK 的写入方法可传可选元数据，双语言 E2B 单项/批量写入把已有上游 `metadata` 选项映射到该动作。批量仍按序执行，前项成功在后项失败时可能保留。

Python/Node 适配层把 `symlink` 和未识别类型映射为固定上游类型/空类型，把目标和属性映射为 `EntryInfo`。旧 guest 缺字段时仍返回 `UnsupportedCapability`。只有同一签名候选通过双语言真实 KVM 中普通文件、目录、链接、扩展属性、缺失路径与租户边界的正反例，才能将 `files.list/get_info` 加入固定矩阵。

## 验收

按设计→自评审→实现顺序处理。先验证链接 FD 读取与 xattr 的系统调用边界和竞态；再做 guest、host 伪造结果、双语言 SDK 合约测试。构建双架构离线包，ARM64 无网卡 QEMU 验签安装及功能；指定 x64 服务器隔离安装后用包内 SDK 做真实 KVM 正反例，最后运行受影响 CI 和固定矩阵审计。
