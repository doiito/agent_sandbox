# ADR-0031：统一 VM 实例所有权与关机收尾

状态：Accepted；日期：2026-10-30；需求 LIFE-01、LIFE-02、LIFE-04、SEC-03、REL-04。继承 ADR-0014、0019、0029、0030。

## 决策

warm pool 不能接管当前 `Session` 内的进程后替换 `exec.Cmd` 的 context。先抽出 launcher 内部 `vmInstance`，统一持有 VM ID、物理预留、backend、工作目录、cgroup、进程、退出信号和一次销毁操作。cold job 和 session 也必须使用它；会话句柄仅管理租户租期、命令序列化、协议与 active 预留。下一批 pool scheduler 复用同一个实例对象，不再复制启动和清理逻辑。

实例从 reserved 经 booting 进入 active；后续 pristine 分支从 booting 进入 ready，经 claiming 进入 active。任何状态都可进入 destroying，成功后 destroyed，失败后 cleanup_failed。领取后的实例绝不回 ready。实例进程 context 在创建时固定，所属请求取消、租期和管理器停止通过取消它终止实例，不在启动后替换 context。

管理器在启动前登记实例及物理预留。登记与停止互斥：停止后拒绝新实例，已登记而尚在 staging 的实例同样必须取消和回收。启动与销毁的进程创建阶段串行，销毁先取消再等待 staging；不能出现 cleanup 先归还身份、另一个 goroutine 随后启动旧 VMM。`Wait` 仅由一个 watcher 调用；退出先关闭信号，再触发幂等清理，避免 watcher 等待自己。

销毁顺序为取消/kill、确认 Wait、清空并移除 cgroup、移除目录和 lease，全部确认后才释放物理预算及身份。失败保留实例、目录、预算及错误证据，并封闭管理器准入。active 预留在 owner 清理成功后释放，不得以错误路径 defer 无条件归还。进程意外退出和创建者取消都必须通向同一条销毁路径。

launcher 停止时关闭准入、取消全部已登记实例并等待有界并发清理，完成后检查实例注册表和资源账本归零。停止或监听错误应取消所有连接处理器，避免只有正常 SIGTERM 才收尾。关机超时返回失败，仍保留资源归属；不得声称已清理。启动时继续采用专用 cgroup 和 lease 对账，不接管旧进程。

## 验收

先自评审，再实现和定向测试。验证并发 Close/自然退出/超时只有一次回收、staging 取消和 shutdown 竞争不在清理后启动、清理失败保留物理与 active 资源、停止后不能新建，以及普通 job/session 行为保持。L1 CI 后使用签名离线候选在指定服务器运行 API/SDK KVM 基线、容量和 launcher 恢复/停止用例；ARM64 进行静态构建与 QEMU 功能检查。此批次不代表后台补池或 warm 性能完成，原启动门禁继续保留。
