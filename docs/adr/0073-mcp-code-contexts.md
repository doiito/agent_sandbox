# ADR-0073：MCP持久代码上下文与已知ID执行

状态：Accepted（本地Go/race及真实stdio+mTLS/官方schema验证通过，同包VM待验收）；设计日期：2026-11-05；验证：2026-11-06；承接ADR-0056/0060/0070/0072，需求API-03、API-02、EXEC-01/02、CAP-01、QA-02/03。

MCP继续只访问现有mTLS/tenant API，不接launcher、不在宿主执行代码、不增加安装依赖。提供九个原生工具：sandbox.code.context.create/default/list/info/restart/remove和sandbox.code.execute/poll/cancel。它们是异步控制与有界观察，不把E2B同步执行包装成另一套生命周期。

create必须提供context_id/language，可选cwd缺省/workspace；default显式提供language。execute必须提供context_id/generation/execution_id/code，environment缺省{}，timeout_ms缺省60000、允许0、最大300000。poll要求session/context/generation/execution ID及after（缺省0），结果最多64事件；取消也携带同样绑定。所有ID为24位lower hex，generation和编码/源码/环境沿宿主类型验证。输入schema的未知字段拒绝。

代码工具针对既有会话，发现来自认证Linux v5、code_contexts及有效固定runtime profile；新VM工具仍只来自Available=true的模板。按tenant的code_languages发布语言枚举；无允许语言时仅发布观察/清理工具。多模板发现合并工具，调用始终通过[会话绑定能力入口](0074-active-session-capabilities.md)查询owner实际模板及live策略，包括旧单模板路径；不得借默认模板执行，也不缓存运行状态。目录保留不可再准入模板的代码运行时合同，以便活跃会话继续受控使用，不能借此创建新VM。session-info使用独立短launcher连接，不占同步shell控制锁。

执行与restart按实际context info查语言准入；只读及cancel/remove不被新解释器准入限制阻塞。响应共享宿主CodeResponse验证，核对session/context/generation/执行ID、状态、序号、终态、MIME/base64和预算。poll保留原始JSON以避免数值经float64往返。输出文本与structuredContent一致，用户error事件、failed/timed_out/cancelled和淘汰明确isError；completed仍可能有后续页，不能推断分页耗尽。

create/restart/remove/cancel的ACK仍是实际过渡或接受状态，不当作ready或清理完成。执行/上下文ID由调用者事先持有；MCP取消、EOF、响应丢失只终止本次HTTP，不重放源码、不自动删除上下文或取消已接受执行。代码工具不使用普通watch/command创建的ACK丢失回滚，因为那会破坏后台已知ID语义。失败结果附带有界身份字段及是否交付不确定，不回显源码、环境或API诊断；调用者用info/poll/cancel继续处理。显式session.close和原TTL保持最终资源归属。

实施前自评审：索引/能力查询不占全局锁；单次代码控制HTTP限制10秒并受原调用取消约束；无跨MCP进程状态。参数先验证再访问API，选择器始终按会话确认；无允许语言仍可清理既有工作。poll携带context/generation，避免把同session的另一个执行误交付；上下文已删除后仍可查询原执行记录，不额外依赖该context存在。协议错误只报告，API保有owner/VM回收权，不谎称MCP已清理。

先做工具schema/路径与body/绑定/丢ACK/取消/跨模板/原始大JSON的定向Go测试及真实stdio+mTLS/官方schema验证。guest源码未改，不重跑32组QEMU；模板/SDK/MCP冻结后一次完整候选CI，再在指定x64同包KVM cold/warm及ARM离线QEMU实际验证。代码分子的E2B五项仍需双SDK同包证据，MCP本地通过不增加23/34或关闭完整40项。

实施结果见[验证记录](../../PUBLIC-QUALIFICATION.md#private-evidence)：新增10项Go顶层用例，MCP包全30项带race通过；真实进程+mTLS夹具14组及两版官方schema通过，含取消提交后不重放/回滚和跨进程查询/显式取消。x64/aarch64静态ELF编译通过。既有sandbox.capabilities增加session_id绑定查询；不可新准入的代码目录条目仍发布已有会话code工具及session.get/close，不发布session.create/exec。sandbox.templates保留code_runtime/code_languages供发现。
