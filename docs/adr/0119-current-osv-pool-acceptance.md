# ADR-0119：当前签名Python模板的OSv池功能验收

状态：Accepted（当前签名生产OSv模板原25项及独立清理通过）；日期：2026-11-13；2026-11-14验收；需求 CAP-01、LIFE-01、LIFE-02、LIFE-04、EXEC-01、QA-01、QA-02、PERF-03。

## 决策

原`e2e-osv-warm-pool.py`的25项覆盖仍有价值，但绑定旧诊断harness、task-probe.so、固定身份及128/256MiB规格。当前rc88已包含签名python-science原生模板和生产systemd启动流程，不能用旧诊断模板补记当前候选通过。本批在私有验证目录适配原25项的意图，保留原用例名称与分母，不改产品或历史脚本。

使用原rc88包、原生产API/launcher/VMM/OSv内核及科学Python镜像，配置在首次加载前完成。原准备器的defer-start改动保持独立且有AST等价检查。显式默认OSv模板后移除其他目录模板，签名摘要、production能力、environment/stdin及OSv结果协议逐项核对；不把Linux后端成功或诊断stage冒充生产OSv。

原small/large两profile分别映射512/768MiB，cold mismatch用640MiB，保持两最小ready水位和单vCPU；物理/身份上限4，active上限2，各租户并发1。保留原资源账本、CPU配额/实际放置、PID/独占owner和mTLS，不要求科学Python在原任务探针的128MiB内运行。所有Python任务只用已签名`/python3.12.so -c`，不换镜像或注入新模块。

## 原25项的当前验证

保留启动最小池先于launcher.ready、真实ready VM绑定、启动分段、用后销毁、独占owner拒绝、两租户状态隔离、warm退出7、cold mismatch退出7及cold就绪时长。环境及二进制stdin由Python实际读回；前一VM写入的临时标记在后一租户新VM中必须不存在。

OSv session与input_files仍按当前能力拒绝，不将拒绝登记为input_readonly证明，原FILE需求及18场景的该缺口保留。验证双租户唯一身份与active容量、第三请求quota拒绝不影响持有者、断连取消不伤另一租户、warm任务超时回收、已确认退出的dead VM不被发放、checkout IO中断连回收。

API SIGKILL只作用于本夹具unit的main进程，核对该active VM退出与idle供给保留；恢复API后进入新的网络namespace。正常launcher停止验证owner锁、run/cgroup及全部原PID代次回收；launcher SIGKILL保留owned lease，再由原生产启动对账并验证新任务。历史名称`diagnostic-runtime-confirms-reconciliation`保留作分母身份，实际断言为production doctor的orphan-reconciliation计数，不再要求diagnostic stage。

VM故障只通过pidfd，在信号前核对PID start ticks和精确私有cgroup；SIGKILL后确认pidfd退出再发送下一个请求。SIGSTOP后的所有存活VM在finally恢复，服务控制限私有unit。HTTP连接单次提交，429 quota观察可以有界重试只读状态，不重放结果未知的请求；接收断连与SIGKILL均保留原任务终态。

## 验证策略与边界

先自评审与纯配置/工作负载/信号边界反例，再同包真机执行一次原25项及独立清理；原包90项前后SHA、1243程序输入、计划/InvocationID和源码/配置均绑定。发生失败保留归档，定位后只补必要未通过范围；验证工具变化不触发不变产品的完整CI、ARM或原15套回归。

本批不是千次延迟、长期稳定、全18场景或发布证明。warm继续5/9/13ms，四必要路线各1000正式样本另行集中验收；K8s暂缓，ARM仍仅编译和无网卡QEMU功能。自评审见[当前OSv池验收](../../PUBLIC-QUALIFICATION.md#private-evidence)。

## r1准备器拒绝与r2定向修正

2026-11-14，r1在准备器参数检查即失败，尚未创建夹具或运行25项。原`--warm-pool-headroom`明确只允许无目录切换的shell夹具，不能与`--template-catalog-probe --osv-default`混用；独立核对原终态、输入未变及无创建目录/清理残留，保留InvocationID `93afb1ad23de4d888741fd61379487f3`。

r2保持4槽、两profile及25项目标，增加只供本私有OSv夹具的`--current-osv-pool-headroom`。该开关同时要求私有OSv路径、tenant-pair、isolate-network、warm-pool、template-catalog-probe与osv-default；拒绝旧shell headroom及其他导入、配额、代理、推理、代码、计时和预算覆盖。仍复用原headroom_overrides的4身份/4实例/256 PID总预算，保留每VM64 PID及原CPU/放置。不放宽原shell开关，也不改产品配置或镜像。

新增参数正反例和剥除显式扩展后的准备器AST等价检查，确认原默认行为未变；原r1源码/日志冻结保留。r2只执行尚未开始的原25项，先要求r1独立清理及Linux三个专项核对收据通过，再用新ID单次投递。

r2已通过，InvocationID `ffd30342101f49df944d5e9bbebbb65e`；原25个名称及顺序逐项保持，实际原生Python环境/二进制stdin、临时文件隔离、warm/cold退出7、pidfd确认死亡、两种服务崩溃/对账及零残留均核对。独立收据为`results/2026-11-13-rc88-osv-pool-current/verified-analysis.json`，仍明确OSv session及只读输入未实现、不登记全部18场景或正式延迟通过。详见[当前OSv池验证](../../PUBLIC-QUALIFICATION.md#private-evidence)。
