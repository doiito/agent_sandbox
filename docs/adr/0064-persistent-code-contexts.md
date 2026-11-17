# ADR-0064：受会话生命周期管理的持久代码上下文

状态：Proposed（语言原型、共享Rust监督及常驻worker核心通过，完整语言语义/服务/控制面待实现）；日期：2026-11-04；进展：2026-11-05；需求R3/R6/G4、API-02/03、EXEC-01/02、OSV-02、QA-02/03、REL-04。

## 契约与范围

固定E2B2.51.0提交的code interpreter Python2.10.0/JS2.8.0原始接口已按原矩阵摘要核验，保存在 `assets/contracts/e2b-2.51.0/code-source-lock.json`。五项为run_code、create/list/restart/remove_code_context。执行保留变量、函数、导入和语言状态，结果包括stdout/stderr、执行错误及富结果；language/context互斥。默认语言Python，默认上下文在多次调用间保留。重启只重置选中上下文，删除不影响其他正常上下文。

先实现Python、JavaScript/TypeScript的真实持久进程，由[双架构Linux代码运行时](0063-linux-language-runtime-closure.md)提供。其余语言继续按原矩阵推进，未支持选项明确拒绝，不借其他语言或新进程伪装原上下文。完整固定分母仍34项；只有同包双语言真实正反例通过后才增加对应分子。

## 监督和生命周期设计

一个上下文对应一个独立解释器进程及专属监督器，属于现有tenant session VM。上下文不是租户隔离边界；VM仍是一租户安全边界，工作区在同一session内共享。每session至多4个上下文，进程、执行、事件与结果有明确上限。上下文身份和运行代次由guest监督器管理，root验证session/context/execution ID、nonce和pristine binding，不能让guest自报身份扩大宿主权限。

解释器与监督器使用专用控制fd通信，stdout/stdin与控制协议分离。监督器负责进程组、子进程、输出读取、超时、中断、失联和重启。正常中断尽量保留上下文；不响应中断的解释器在有界宽限期后终止，该上下文明示failed，用户显式restart后恢复；不能静默重建并丢失变量。监督器失陷或无法确认后代回收时停止整个VM，避免把未知进程当作干净状态。另一个正常上下文的重启/删除不得误杀无关上下文。

每工作负载PID namespace原型已证明后代回收，但实施前复核发现重复PID2会破坏现有Bash $$及SDK PID句柄，因此正式路径按[ADR-0065](0065-linux-workload-supervision.md)改用guest内独立cgroup与专属subreaper，保留session PID语义。历史[ARM QEMU原型](../../PUBLIC-QUALIFICATION.md#private-evidence)不改写为该新机制的证据。普通命令与新解释器必须一起迁移：迁移前PID 1的guest-wide kill(-1)/waitpid(-1)会影响其他工作负载，在迁移并验证前不得启用新能力。

随后[共享Rust监督验证](../../PUBLIC-QUALIFICATION.md#private-evidence)完成正式普通命令迁移，PID1全局kill/reap已移除，双架构32组通过。独立代码服务、常驻worker与解释器fd3/4接线、会话/API/SDK及warm交接仍待实现；前一段描述的迁移前阻碍已由该阶段消除。

操作使用独立guest服务与短launcher控制连接，不能被同步shell/另一执行占用。控制操作在执行繁忙时仍能列举、中断、重启或删除。不得持有全局索引锁等待guest、进程或网络。原session owner连接、TTL、硬寿命和全局VM账本保持唯一归属；上下文不增加另一套VM容量。断开或结束执行不延长租期，关闭session/VM停止全部解释器及后代。

pristine代码模板只有可信初始化过程，没有租户代码；预启动解释器必须达到可验证的干净ready状态后才计入该模板池。领取后重新绑定身份并发布权限，ACK前完成交接。已执行用户代码的VM始终销毁，不回池；快照与暂停恢复仍另行实现，1–2ms目标不放宽。

## 执行、输出及适配

原生API采用有界执行记录与可取消观察，真实事件按序号到达；SDK同步run_code拥有本次执行的取消责任，回调异常、调用超时和取消应停止对应执行。原生后台观察与E2B同步调用的差别显式定义，不能意外把观察断线解释为新的执行或重复提交。

语言原型使用fd3输入/fd4输出、4字节大端长度加JSON。帧上限96KiB、代码64KiB、环境64项；每次富结果最多16项/32KiB。Python使用持久命名空间、表达式/富输出及异步执行；Node使用固定22.23.4的REPL和固定TypeScript编译器。同步抛错、await拒绝以及CPU/await中断均已有双架构实际回归。Node错误domain与中断的适配依赖固定REPL实现，升级必须重新验证；async恢复后进入不可中断的原生代码、用户改变信号处理等情况仍依赖监督器有界升级，不能把原型SIGINT成功当作所有任务都能保留状态的保证。

代码源、事件、stdout/stderr、traceback、富结果、嵌套JSON和累计输出均有上限。Python捕获最后表达式及display MIME结果；JS/TS保留顶层声明并支持异步结果。富结果作为数据交付，不在控制面渲染HTML或执行内容。错误包含名称、值及有界traceback，用户代码异常不冒充宿主协议失败；无效控制帧则终止对应监督链。环境及cwd受现有会话规则约束，默认工作区与E2B差异公开。

SDK提供原生上下文与显式E2B适配，Node回调依次await，Python与Node都验证实际模板、上下文绑定和输出终态。MCP经同一认证API发布语言及上下文工具，能力来自实际选中模板。旧模板、OSv与未绑定代码特性的镜像不宣称支持。Runtime版本、kernel脚本及TypeScript编译器由签名镜像/清单绑定。

## 实施出口

监督协议、后代归属和warm初始化先做原型与自评审，再进入控制面和SDK实现；关键开放细节不能靠文档视为已完成。验证至少覆盖状态持久、双上下文隔离、语言切换、重启/删除、rich output、语法与运行错误、异步结果、输出洪泛、超时/断线/回调失败、逃逸进程组、TTL/关闭、跨租户、配额及实际cold/warm。ARM用QEMU实际执行两个语言运行时与监督过程，x64使用最终同包KVM双SDK/MCP及回收证明。源码冻结后一次完整CI，失败按影响重验；不为进度提高兼容分子或改写原40项。

2026-11-05 worker进展：[ADR-0067](0067-persistent-code-worker.md)已完成常驻线程、上下文代次及执行记录、分阶段取消、重启/删除与完整后代清理；同源码双架构32组通过。独立服务、公开控制面及完整语言语义继续按[ADR-0068](0068-session-code-control.md)推进，未增加E2B分子。
