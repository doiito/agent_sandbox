# ADR-0071：代码上下文的双SDK句柄

状态：Accepted（原生双SDK本地验证通过，E2B适配及实际VM待验收）；日期：2026-11-05；承接ADR-0064/0070，需求API-02/03、EXEC-01/02、QA-02/03。

先接原生Python/Node的session.code接口及类型，再做固定E2B代码解释器适配。客户端继续只用标准库/Node内置模块，正式依赖留在项目；不增加安装依赖。

上下文快照带session_id、id、generation、language、cwd、state及真实PID/错误指标。create/default立即返回实际过渡状态；get/list观察真实状态；restart/remove/execute使用快照的generation，不能自动刷新后重试修改而误操作新的代次。restart返回的过渡快照不代表解释器已经ready。只读和清理仍允许观察原有上下文，即使新的解释器准入策略已经改变。

submit前生成执行ID及绑定句柄，仅发送一次；原生执行与观察独立，不因请求断线自动取消或重放。发送后异常附带execution句柄，调用者可查询/取消已知身份；也可事先传入ID。句柄固定session/context/generation/language，分页核对身份、连续序号、状态、终态和有界输出。完成状态不能跳过后续页，events_evicted显式暴露，不能伪装完整输出。未知取消沿guest有界占位处理。

两SDK按真实选中模板查询能力，只有签名且启用code-contexts-v1的模板支持；language还受tenant发现结果限制。结果MIME保持数据，原生stdout/stderr保留base64，调用者选择文本解码。Python保留JSON整数，Node采用标准JSON.parse的number语义；不声称超出Number安全整数的精确算术。

E2B适配随后承担同步执行的完整责任：language/context互斥，默认Python持久上下文，callbacks顺序交付；用户代码error返回Execution.error，服务失败单独报错。回调抛错、超时或取消必须对已知执行ID发独立取消并确认终态，无法确认时请求关闭原会话并明确报告清理不确定。不能把404未知执行、一次取消ACK或SDK调用结束当作回收完成。默认60秒，0只取消执行期限，不延长会话；request timeout与执行timeout分别有界。真实运行时ready等待及restart/remove完成确认不能用固定sleep冒充状态。

实施前检查：句柄不持全局请求锁，不缓存运行状态；API失败不能覆盖已知ID，绑定错误和分页缺失不能当作用户代码异常；现有SDK旧模板用例应继续明确unsupported。先做本地两SDK原生正反例和类型检查，E2B/MCP/代码模板冻结后统一完整CI与同包实际VM验收。固定兼容分子在此阶段不变。

原生实施记录见[双SDK验证](../../PUBLIC-QUALIFICATION.md#private-evidence)。自动生成的context ID也在创建回包异常时附加到异常，便于get查询，不自动重试。单次code RPC及首次能力查询均使用请求超时（Python秒、Node毫秒，默认10秒），还受Client自身超时上限。E2B同步run_code等五项仍明确unsupported，不能从原生句柄存在推导已兼容。

后续[ADR-0072](0072-e2b-code-lifecycle.md)已实现五项E2B适配并通过本地契约测试；上述原生阶段的unsupported状态为其当时边界。同包真实VM门禁及兼容分子仍未推进。
