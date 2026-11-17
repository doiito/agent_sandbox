# ADR-0072：E2B同步代码执行、回调和取消确认

状态：Accepted（双SDK本地契约和宿主定向测试通过，同包VM待验收）；日期：2026-11-05；承接ADR-0064/0070/0071，需求API-02/03、EXEC-01/02、QA-02/03。

固定四份上游代码契约继续沿assets/contracts/e2b-2.51.0/code-source-lock.json核验，不变更34项分母。两SDK在原生session.code之上实现run_code/runCode及create/list/restart/remove上下文。Context保留id/language/cwd，附带session归属；上下文字符串或手工构造对象先向实际owner查询，运行使用最新快照，但提交遇stale generation不重试。language/context互斥，默认Python；不支持语言及旧模板明确拒绝。

create等待实际idle，restart等待同ID的下一generation实际idle，remove等待get返回code_not_found。原生代码HTTP将guest的not_found映射为code_not_found，以区分原HTTP owner缺失的not_found；会话消失不冒充上下文清理确认。准备总等待40秒，单个RPC默认10秒，可设置请求超时；期限届满明确报错并保留已知ID，不能返回虚假ready。创建ACK丢失时凭已知ID继续观察，无法观察则带context ID报错，不自动重建。

执行默认60秒，0不设执行期限，最大300秒，与会话TTL独立。执行事件按真实序号积累，终态与分页耗尽同时满足才返回；events_evicted、运行时failed/cancelled/timed_out均明确错误。用户代码error事件作为Execution.error返回，不能冒充控制失败。Execution.execution_count目前未由guest对外提供，保持None/undefined，不本地猜计数。

输出用增量UTF-8解码，保留跨帧字符；回调得到OutputMessage(line,timestamp,error)，timestamp为客户端接收时间。富结果把MIME映射成text/html/json等字段，并保留raw和额外MIME；不渲染内容。空文本、false和JSON结构保留。Python回调同步依序调用，拒绝async函数；Node依序await回调，以deadline/AbortSignal中断异步等待，避免后续回调继续交付。两语言均无法安全强行打断用户同步回调占用的本地线程；Python独立定时线程在deadline仍取消guest，函数在回调返回后报告超时，Node guest执行期限独立生效、同步回调返回后检查超时；此边界公开。

提交之前生成执行句柄；已知拒绝4xx不作为未知交付，其他发送/观察失败、回调异常、deadline或显式取消使用独立控制请求停止同一个execution ID。取消等待最多8秒，单RPC最多2秒；接受ACK后继续读实际journal至终态，取消ACK丢失时可重发同一取消，不能重放源码。unknown执行404不证明未来不会执行，依赖guest取消占位阻止迟到提交。

停止确认失败则请求关闭原owner会话，另给最多6秒。由于既有DELETE会话的HTTP确认可能丢失launcher清理ACK，这一步只作为回收请求，不能当作journal终态证明；抛CodeCleanupError并保留original_error和execution句柄，明确清理不确定。成功确认停止后重抛原调用错误。正常完成不额外取消、不销毁持久上下文；上下文中的其他执行不被常规取消影响。

实施前竞态检查：普通命令与代码独立，取消不能复用被执行/回调占用的锁；每次执行的清理最多一条控制流程，主线程与定时线程共同使用锁/Promise，不重复close。SDK准备和执行阶段不能只靠固定sleep判定ready；回调错误即使发生在terminal已生成后也要保留原错误，停止后不重复交付。原生异步观察语义保持不变。

先以两SDK定向正反例验证全部五方法、分页/富结果/错误、CPU/await观察模型、ACK丢失/取消先到、回调失败/超时/清理不确定及生命周期代次；本轮不修改guest，不重跑其32组QEMU。最终新代码模板/SDK/MCP冻结后统一候选CI、指定x64真实vsock/KVM冷/暖与ARM离线/QEMU；本地mock不增加固定E2B分子。

实施结果见[本地验证](../../PUBLIC-QUALIFICATION.md#private-evidence)，其中CPU/await的实际语言行为继续承接已封存guest QEMU；本轮状态API夹具不冒充解释器执行。Python新增16项、全75项；Node新增18项、全58个命名用例；TypeScript正反例及宿主21项代码测试race/vet通过。
