# ADR-0070：代码控制的宿主RPC、归属与原生API

状态：Accepted（宿主控制面与取消竞态定向功能验证通过，公开同包VM链路待验收）；日期：2026-11-05；需求API-02/03、EXEC-01/02、CAP-01、REL-04、QA-02/03；承接ADR-0068。

## 通路与生命周期

HTTP使用现有lookupSession权限，launcher经原Unix peer credential检查后处理独立osv-sandbox-launcher-code/v1短连接。launcher从共享owner索引获得原Session引用后释放索引锁，直接转发guest5003的fc-code/v1；不创建新VM、额外租期或容量账本，不占用普通同步shell的opMu。每次guest RPC有独立nonce、session及原pristine binding，宿主验证身份回显及类型化结果。

提交者先生成24字符hex上下文/执行ID。原生提交成功即返回accepted，断线不取消已接受的工作，不自动重放；调用者以已知ID查询或取消。协议损坏、身份或序号错误使Session通过原Close销毁；普通请求超时和连接丢失保留独立会话及执行，明确返回unavailable/取消错误，不能伪报未执行。E2B同步包装稍后承担独立取消确认责任。owner关闭、TTL及崩溃仍沿原会话回收。

实施前竞态检查补充：独立取消可能先于已写入、尚未被guest接受的提交到达；仅not_found不能证明未来不会执行。guest核对context/generation后为未知执行ID生成有界取消占位，保留ID并拒绝后续submit；查询得到cancelled/failure=cancelled_before_submit及唯一finished，**没有started事件**。占位共用原256条执行额度及16条完成内容保留规则，不能无限增长。宿主每Session以同样256条上限保存执行ID到context/generation/language绑定，断线不丢失；回包不得改绑，取消占位可以被独立查询。这个改动不声称未运行的代码曾启动。

代码语言入口仍受原模板及tenant的entrypoint允许列表约束，Python映射/opt/python/bin/python3.12，JS/TS映射/opt/node/bin/node；清理和只读查询继续由session owner权限决定。上下文语言按不可复用ID缓存，避免每次执行增加探测；不把缓存当作执行状态或generation真相。

## 资源与错误

contexts提供POST create、POST default、GET list、GET info、POST restart、DELETE remove；code-executions提供POST submit、GET info/page、DELETE cancel。create/execute要求已知ID，执行携带context_id/generation，restart/remove/cancel携带generation；原生过渡状态立即返回，SDK等待真实ready/清理。默认执行60秒，显式0不设执行期限，最大300秒，均不延长租期。

所有guest/launcher结果限制在256KiB，事件分页最多64项，验证上下文/执行绑定、唯一ID、generation、状态、事件序号、MIME/二进制和终态位置。完成状态与分页耗尽分别检查，不能因status完成跳过余页；已淘汰内容明确标识。宿主附加session_id，拒绝guest自报其他会话身份。错误分为未支持、请求无效、找不到、冲突/旧代次、忙/额度、会话关闭、传输不可用及协议损坏，不能把用户代码error事件当成协议故障。

## 签名能力

Linux v5清单必须包含code-contexts-v1，并签名绑定架构、固定Python/Node/TypeScript版本、kernel v2协议、两个脚本摘要、运行时完整inventory摘要、预启动语言和最低CPU特性。可并存watch/proxy已有能力。旧协议拒绝额外代码profile，旧Linux/OSv不宣称代码能力。新Manager按清单启用启动参数，校验本机CPU/架构；初次cold/pristine/prepared握手核对真实code ready及预启动语言，使用后不据此重新入池。

## 实施前自评审与验收

索引锁不跨网络等待；连接取消只关闭该RPC，不能撤销原会话owner连接。异步操作不使用watch的“ACK丢失即停止新资源”补偿，因为已知ID是查询/去重边界；必需审计写入失败则关闭会话停止工作，日志不包含源码或环境值。所有代码入口重复核对owner/session，ID不是授权令牌。

先做真实Unix转发/HTTP/归属/取消与伪造回包的定向测试，加签名profile与capability正反例；本轮不逐次重跑完整guest矩阵。新代码模板/两SDK/MCP冻结后一次完整CI，再做指定x64服务器同包真实vsock/KVM cold/warm、跨owner/会话、断线/超时/回收及ARM离线/QEMU。仅控制面测试不增加固定E2B项，不代表新发行或完整40项完成。

实施结果见[验证记录](../../PUBLIC-QUALIFICATION.md#private-evidence)：宿主包完整race与vet通过；新增20个顶层用例涵盖上述通路。取消占位涉及guest行为变更，因此重跑同33输入双架构实际QEMU，各16组共32组通过；正式vsock及最终发布包仍待验证。
