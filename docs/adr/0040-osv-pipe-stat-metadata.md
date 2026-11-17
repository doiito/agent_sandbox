# ADR-0040：OSv 匿名管道的有效 fstat 元数据

状态：Accepted；日期：2026-11-01；需求 OSV-01、OSV-02、EXEC-01、QA-01/02。

2026-11-02：原生 32 项、Python 512MiB 20 项、完整 CI 和受影响冷/warm/协议回归已通过，见 [rc48 验证](../../PUBLIC-QUALIFICATION.md#private-evidence)。64MiB 与生产门禁仍失败或开放。

## 原因与待证实边界

Python 科学栈 rc44 的独立诊断确认 Py_InitializeFromConfig 在 init_sys_streams 抛出 EBADF，尚未执行用户代码。固定 OSv 提交中 pipe_file 继承 special_file::stat，该函数直接返回 EBADF；CPython FileIO 把此错误视为 fd 无效。先以同一旧内核的独立 C 模块验证 pipe/dup/stdio fd 的实际 stat 及 IO，保留修复前失败。正常有效 fd 与错误 fd 应分别按 [fstat](https://man7.org/linux/man-pages/man2/stat.2.html) 返回成功与 EBADF；不能让解释器忽略该异常。

## 决策

1. 仅为单向 POSIX pipe 的 pipe_file 实现 stat，不把所有 special_file 的未知类型伪装成普通文件或管道。共享 pipe_buffer 也用于 socketpair，保持其现有实现和语义。
2. 两个管道端点持有同一份不可变元数据：FIFO 类型、0600 权限、创建者有效 UID/GID、专用匿名设备标识、每个 VM 内单调分配且不回绕的 inode、链接数 1、size/blocks 为 0、块大小 4096，以及创建时间。dup/dup2 继续使用同一个 file，因此身份一致。inode 不暴露内核指针。
3. 匿名管道使用创建时的 atime/mtime/ctime，不在 IO 热路径增加时钟查询或锁。这与本机 Linux 探针以及 [Linux pipe 实现](https://raw.githubusercontent.com/torvalds/linux/master/fs/pipe.c)中匿名管道与有名 FIFO 的区分一致。首次参考探针错误要求每次 IO 更新时间，两个时间断言失败；原结果保留，实施前已据证修订设计。元数据只在构造时写入，stat 直接复制完整快照，无共享可变字段。创建时取 CLOCK_REALTIME；失败则原样返回 errno，不发布缺时间的管道。
4. 管道创建中的共享元数据、buffer、端点与 fd 都由 RAII 管理。元数据分配失败映射 ENOMEM，inode 空间耗尽映射 EOVERFLOW；不向外泄漏 C++ 异常，不改变错误 fd、非阻塞、EOF、EPIPE、ESPIPE、输出捕获或一次任务后销毁约束。
5. 通过固定上游 overlay 的精确上下文应用，修改源码在项目 osv-native，避免只改未跟踪的 upstream 树。独立候选保存旧内核/模板，正式 kernel 和 Python wrapper 不加入诊断日志，不跳过 Py_RunMain/finalization。
6. 原版 guest 同时暴露 isatty 的错误约定：有效非终端返回 0 却不设置 ENOTTY，无效 fd 返回 -1；后者经 CPython PyBool_FromLong 会变成真。按 [isatty](https://man7.org/linux/man-pages/man3/isatty.3.html)补正两条错误分支，保留真实 tty 的识别逻辑。原始 31 项探针在元数据之外的 nonterminal 项也失败，不能忽略该项让修复变绿；增加无效 fd 的独立断言并对旧/新内核运行同一 32 项模块。

## 实施与门禁

先完成[自评审](../../PUBLIC-QUALIFICATION.md#private-evidence)，再运行修复前探针；随后实现和定向测试。原生 C 探针覆盖有效两端、dup/dup2、标准流、跨管道身份、并发 IO/stat、非阻塞/EOF/无效 fd、创建时间一致性和重复创建关闭。Linux 参考只验证探针假设，OSv 真实 guest 的同一模块是兼容证据。

Python 必须经签名 agent、warm VM、mTLS API 完成实际任务与结果回传，保留正常初始化和退出语义；完整科学栈和 64MiB 均按原矩阵执行，不缩减 workload。冻结运行修改后，对新 OSv kernel 候选做一次完整本地 CI 和受影响 OSv 冷/warm/任务协议/资源退出回归。Linux musl/ARM64 rc46 未修改时不重复整套构建/QEMU；出现实际跨路径影响再扩展。性能与生产门禁保持原标准。
