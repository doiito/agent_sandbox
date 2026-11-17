# ADR-0041：OSv 单任务 VM 的显式退出结果桥

状态：Accepted；日期：2026-11-02；需求 OSV-01/02、EXEC-01、LIFE-01/04、QA-01/02。

原生 KVM 49 项、Python 512MiB 20 项、完整 CI 和受影响冷/warm 回归已通过，见 [rc48 验证](../../PUBLIC-QUALIFICATION.md#private-evidence)。64MiB 的完整科学任务超时，整体内存与生产目标未通过。

## 证据

rc47 只替换内核，原 CPython/科学栈和 agent 逐字未改。指定服务器的签名 warm 任务已通过解释器、NumPy/pandas 导入、固定版本、stdlib、NumPy 线性代数、pandas CSV/聚合/合并/时间、线程、UTF-8 argv/环境/二进制 stdin、路径隔离共 10 项。第 11 项 sys.exit(7) 导致结果通道 EOF，后续异常/新解释器/64MiB 尚未执行。

固定 CPython 的 handle_system_exit 调用 Py_Exit；Py_Exit 先执行 Py_FinalizeEx，再调用 exit(status)。实际 OSv 符号表中 exit/_Exit/_exit 指向 runtime.cc 同一入口，直接关闭整个 VM；agent 的应用 main 返回回调收不到这个退出事件。问题也会影响调用 exit 的其他语言，不能通过把 sys.exit 改成 return、跳过 Python 清理或伪造退出码解决。

## 决策

1. 保留 CPython、Py_RunMain、Py_Exit 和正常 Py_FinalizeEx。为已认证、一次任务的 OSv VM 添加通用退出通知桥，由 agent 在执行模块前注册一次，内核 exit 入口先通知后保持既有 VM shutdown。无注册时行为不变；这不是多进程或通用应用复用。
2. 注册 ABI 显式带版本，拒绝空回调/上下文、错误版本和第二次注册。回调与上下文原子发布，无注销或重新武装。绑定只在实际任务执行前安装，未领取 pristine VM 不安装，任务结束仍销毁 VM。
3. main 正常返回与任意任务线程的显式 exit 竞争同一个完成状态：executing → completing → completed。仅一方清理 capture、写结果和等待 ACK；另一方等待完成后退出，不发送第二个结果、不提前关机。完成线程重入 exit 时保留失败关机路径，避免等待自己。
4. capture 的 fd/线程状态提升到 main 生命周期内的上下文，避免退出回调持有已返回函数的栈。内核 run_module 将 main 返回码写入调用线程的局部变量，赢得完成权后才写共享结果，消除与 exit 的数据竞争。回调上下文持续有效直至 VM 关闭。
5. 显式 exit 的回调只排空已经写入管道的数据，不额外 flush 用户 C FILE；Python 已在 Py_Exit 中完成自己的清理/刷新。正常 main 返回保留原 fflush 行为。stdin feeder 与 reader 采用既有 stop/join、50ms 排空和总输出上限；结果继续绑定 ID/nonce、runner 状态和真实整数退出码，ACK 与硬租期不放宽。
6. 完成阶段使用原传输超时与 VM/任务硬期限，等待方不能无限延长期限。关闭 peer/listener、标记 completed 后再沿原关机路径终止。退出回调路径的请求/响应存储不提前释放给仍在返回的模块线程；其生命周期结束于不可复用的 VM 销毁，体积受原请求/输出限额约束。
7. 不把 OSv 现有的 C atexit 空实现称为完整 POSIX exit 兼容，也不把 abort/硬关机冒充普通返回。该桥传递显式 exit 的真实状态；未完成回传、VM crash 和超时继续失败。新增 C ABI 的 kernel 与 agent 通过签名 kernel/rootfs/SBOM 配对，旧 agent 不注册便保持旧行为。

## 验证与回归

先[自评审](../../PUBLIC-QUALIFICATION.md#private-evidence)，再实现/定向验证。注册发布和一次完成分别做并发、重复、版本、重入与截止检查；原生模块覆盖 main 返回、exit/_Exit、后台线程退出与并发竞争、截断/ACK/断连和 VM 清理。Python 仍执行原有全部科学任务，新增 Python atexit 标记验证 sys.exit(7) 已正常清理，再扩展 None/字符串退出；异常结果不得转换成成功。

64MiB 继续运行同一完整科学 workload，单独记录并纳入目标是否达成；仅 512MiB 通过不能把整体内存目标标绿。冻结 kernel+agent 后一次完整 CI、受影响 OSv 冷/warm/控制协议/资源退出回归；Linux rc46 未变化时保留其双架构/QEMU/KVM 证据。生产和完整性能门禁继续开放。
