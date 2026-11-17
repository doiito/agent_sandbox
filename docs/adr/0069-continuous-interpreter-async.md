# ADR-0069：解释器空闲异步与输出归属

状态：Accepted（实现及双架构70组QEMU功能验收通过）；日期：2026-11-05；需求EXEC-01/02、API-02、OSV-02、QA-02/03。

## 问题与决策

[worker核心](0067-persistent-code-worker.md)已验证持久变量和单次await，但Python在两次Runner.run之间阻塞读取控制管道，空闲期的asyncio任务不会前进。这不满足正常持久异步解释器语义，必须在公开代码接口前修复；原32组不改写为这项行为的证据。

Python改为单次持续运行的事件循环，使用异步pipe reader读取有界控制帧，每个cell由独立Task执行。后台任务在没有新请求时仍能推进；当前cell的SIGINT仍只取消ACTIVE_TASK，CPU循环继续沿用cell栈内KeyboardInterrupt，不撤销其他正常任务。Manager重启/删除/期限停止仍通过正式监督回收整个上下文及所有后代。

Python入口使用-u，保证普通print及部分写入不必等cell结束才交付；新增真实未结束执行中的输出验证。每个cell使用同一持久user Context运行，但结果接收器进入/退出时单独设置和恢复，使用户ContextVar也能跨cell保存，后台Task则按语言标准继承自己的上下文副本。

display作为稳定函数，Python使用ContextVar、Node使用AsyncLocalStorage选择调用任务的结果接收器。保存display别名后在新cell中调用，输出属于新cell；后台任务继承创建cell的接收器，后续输出仍带原execution_count。这修正R12中“保存旧display即视为错误”的临时策略，不能为了保留旧断言而破坏正常函数别名语义。

worker保持唯一finished终态，不在完成记录后追加迟到事件。已完成cell的result/error帧在验证结构和序数后有界丢弃，不能混入当前cell；将丢弃事件数和字节数纳入上下文可观察元数据，每代至多256个/64KiB，超额停止上下文。未知序数、旧done/状态/ACK及无效结构仍是协议错误。原始stdout/stderr仍是进程流，后台线程/回调输出可能交错，该边界明确公开。

Node的REPL domain错误处理同时核对AsyncLocalStorage中的来源cell。当前执行的普通throw/rejection仍返回当前cell错误；旧后台回调未捕获异常终止整个上下文，当前执行得到上下文故障而不能冒领旧异常为自己的用户代码错误。真实旧实现已复现错误归属，修复后两架构生产worker回归通过。

语言ready帧增加osv-code-kernel/v2协议标识，worker核验协议、语言及固定版本，旧脚本不能仅因解释器版本相同而被当成新协议ready。独立控制pipe、非阻塞父端及已有预算保持；没有增加第三方库。

## 实施前自评审

异步reader不在事件循环中执行阻塞read_exact；完整帧及源码/环境验证先于执行，reader缓冲有界。任务局部结果对象避免把旧任务的富结果误归新执行；后台输出丢弃有额度且可观察，不静默重放或改写已完成记录。display别名从当前调用上下文取结果，不能固定在定义时的cell。

active Task与常驻循环分离，取消后的循环仍可复用，空闲后台任务不会被临时Runner关闭。后台任务本身的异常、用户主动破坏解释器或不可响应代码依旧可使上下文failed，不能把它描述为独立任务安全边界；整个VM仍归一个tenant。协议升级、两语言结果归属和重启后的旧任务清除需实际验证，不能只做静态检查。

## 验证与出口

先用真实Python子进程验证空闲Task在不提交新cell时完成、保存display别名在新cell可用、后台display保留旧计数、当前执行中断不取消无关后台任务；首项须保留旧实现失败。再通过生产worker和默认helper在x64/aarch64 QEMU验证三种语言的别名、空闲后台任务、交错富输出丢弃/额度、代次重启清除和循环CPU/await取消。影响范围内回归核心worker，旧Go/API矩阵不重复；完整语言/服务/API/SDK和发行门禁仍按ADR-0068推进，不增加E2B分子。

上述范围已按R3同28项源码输入、两架构各35组实际QEMU通过，另有Python7项、Rust59项及不可跨线程迁移doctest、固定Node诊断与clippy；失败历史和精确边界见[验证记录](../../PUBLIC-QUALIFICATION.md#private-evidence)。未据此接受完整代码API、新离线包、64MiB或warm性能。
