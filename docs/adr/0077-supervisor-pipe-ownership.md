# ADR-0077：监督进程交接管道端点

状态：Accepted；日期：2026-11-06；关联 EXEC-01/02、LIFE-01/02、QA-03，承接 ADR-0065。

rc71 的真实 KVM 旧 SDK 回归发现：`exec 0<&-; printf closed; sleep 30` 已关闭目标命令的 stdin，后续输入仍获得成功 ACK。代码上下文 cold/warm 验收通过，但此回归阻止 rc71 成为新的发布基线。

原因是每任务监督 helper 把自身标准管道继承给目标命令后，仍保留 fd0 的读取端。目标命令关闭 fd0 时，PID1 的写入端看不到 EPIPE。相同的端点所有权问题也适用于 helper 的 stdout/stderr，以及可选的解释器 fd3/fd4。

决定：只在 `Command::spawn` 完成端点交接之后，把 helper 自身的 fd0/1/2 转接到 `/dev/null`，并释放用于继承的解释器 fd3/fd4。实际命令及其后代独占原标准管道，解释器独占其 fd3/fd4；private control fd9、cgroup fd10 保留。交接前的 fd3/fd4 预留仍保持，不能影响 Rust 的 exec-error pipe。转接失败继续走既有监督失败/VM 回收路径，不发送虚假的成功确认。

实施前自评审：不能在 spawn 前关闭管道，不能只修 SDK 错误映射；必须让内核确实报告 EPIPE/EOF。仅关闭 fd0 会留下同类输出端问题；直接关闭标准 fd 又可能被后续文件分配复用，故用可读写的 `/dev/null` 替换。成功与 spawn 失败路径均要释放解释器传输副本。此变更不改变目标的 PID、UID、cgroup、退出状态或端点本身，仍由原私有协议确认清理。

验证顺序：先用实际 guest PID1/QEMU 记录修复前的 stdin 关闭失败；再核对关闭输入时目标仍存活、写入 EPIPE，以及目标关闭 stdout/stderr 后、仍存活时观察到 EOF。双架构普通监督/实际 agent pipeline 和代码服务验证覆盖新交接与解释器私有通道。冻结修复后构建新候选，运行一次完整 CI、ARM 离线包 QEMU，以及 x64 同包代码 cold/warm 和原 stdin/SDK/MCP 回归。现有 rc71 包及失败证据保留；不以其代码专项通过覆盖旧功能回归。

2026-11-06 验收：见[rc74同包验证](../../PUBLIC-QUALIFICATION.md#private-evidence)。双架构实际guest70组、447输入完整CI、ARM离线包QEMU48组及指定服务器五夹具全部通过；本决定已实施。正式发布继续遵循功能、性能和一般安全基线条件，未据此关闭原完整目标。
