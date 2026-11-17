# ADR-0066：受监督解释器的独立控制通道

状态：Accepted（设计、实施前自评审及双架构专用管道功能验证通过）；日期：2026-11-05；需求OSV-02、EXEC-01/02、API-02、QA-02/03。

## 决策

[共享工作负载监督](0065-linux-workload-supervision.md)提供真实PID、专属cgroup及subreaper，不改变既有shell入口。新增类型化spawn_kernel，返回同一监督Process及两条独立匿名管道。父端由创建Process的常驻worker持有；helper仅在内部显式kernel角色下转交管道，不接受租户指定fd数字。

两条管道的用户端分别映射为解释器fd3输入/fd4输出，保留现有长度前缀语言协议；stdio保持真实stdin/stdout/stderr。privileged控制socket fd9、cgroup目录fd10不与语言数据混用；新增暂存fd11/12只供helper转交。私有工作负载配置加协议版本及kernel角色，普通spawn不会取得语言控制fd。

helper在构造用户Command前保留fd3/4为CLOEXEC，避免pre_exec覆盖Rust内部exec错误管道；用户child的pre_exec仅清除该两个保留fd的CLOEXEC。helper的9/10/11/12和成员文件均在用户exec时关闭。语言管道传输仍视为不可信租户输出，worker按帧大小/顺序/累积额度解析，不能把语言结果当作privileged监督ACK。

## 所有权与错误

PDEATHSIG绑定创建线程。Process设为不能跨线程迁移，由常驻worker内部创建、监督并完整关闭；请求线程只交换有界命令/结果，不持有Process。该限制也适用于pristine预启动；不能在主线程启动后把Process移入临时worker。

正常中断通过既有pidfd SIGINT，解释器继续存活；不响应时有界stop，等待cgroup/ECHILD及完整ACK后标记上下文failed，必须显式restart。helper/私有协议错误沿用VM不可用/reset，不静默重建。语言通道EOF、错误帧或执行进程退出按上下文失败处理；helper仍负责所有后代回收。上下文创建、会话授权、默认语言、事件及SDK行为仍由ADR-0064后续控制协议定义，本ADR不宣称已完成这些接口。

## 实施前自评审与验证

专用语言管道支持Python同步读和Node事件循环读，父端设非阻塞，写方向与读方向各自独立，避免Node把输入设非阻塞时影响输出。Node使用内置net.Socket包装输入pipe，避免长期占用fs线程池导致UV_THREADPOOL_SIZE=1时用户异步文件操作饥饿；该变化需真实解释器验证。提前占用3/4保证exec失败仍能通过Rust原错误管道返回；只清除明确两fd的CLOEXEC，其他root fd不泄漏。普通命令分支须保持原语义，不因新增角色自动取得fd。

先编译验证不可跨线程的所有权，再在真实guest PID1下用默认生产helper及项目内双架构Python/Node资产实际测试：ready/执行/表达式、状态保留、stdout/stderr与富结果分流、JS/TS await、SIGINT后复用、关闭后代、9/10/11/12未进入用户、fd3/4确实可读写，以及带语言通道的spawn失败。保留既有32组监督基线；新通道冻结后执行受影响core/pipeline及解释器定向QEMU验证，完整候选CI/KVM仍集中到公开代码功能完成后。

实际结果见[独立控制通道验证](../../PUBLIC-QUALIFICATION.md#private-evidence)：新通道双架构34组、受影响普通命令/监督30组通过；native54项、不可迁移编译测试及定向Python唤醒回归通过。Python在selector内等待时仅cancel任务会被系统调用重试阻塞，已改为线程安全调度并写入唤醒管道；真实等待后再发SIGINT的用例覆盖该路径。上述完成范围为共享监督与解释器管道，代码上下文服务/控制面、SDK、MCP和warm交接仍按ADR-0064推进。
