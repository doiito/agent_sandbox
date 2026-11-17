# ADR-0054：会话信息、稳定分页与有界可调整 TTL

状态：Accepted；日期：2026-11-03；需求 LIFE-01/02/03、API-01/02、REL-04。

## 固定契约

核对固定 E2B 2.51.0 的生命周期源码与现有四个 SHA；另保存同提交的模型/分页来源。list 返回有 has_next/next_items（Node hasNext/nextItems）的分页器，仅见当前租户会话，按创建时间全局排序；get_info 返回同一 ID、模板、资源和起止时间；set_timeout 从现在重设剩余 TTL，可延长或缩短，但不能复活已过期会话。本项目仍为显式 facade，不运行 envd；兼容信息里的 envd_version/envdVersion 如实提供实际 fc-agent 协议标识，不伪造上游版本。

## 决策

新增 GET /v2/sessions 的租户列表、原生客户端分页及显式 E2B 适配；分页先冻结有界 ID 集合及创建时间排序，后续页仍核对当前所有权、存活和最新信息，跳过已销毁/过期项，新建项不混入旧分页。游标绑定租户与快照，最多128份快照/每租户8份/30秒；页大小1..100，asc/desc在全结果排序。无效/过期/其他租户游标明确拒绝。暂停会话、元数据筛选等未支持选项不伪造结果。

信息由 launcher 当前 VM owner 确认，补真实 memory_mib/vcpus/guest_protocol 及 max_expires_at。GET和短元数据RPC在本地控制连接占用时有界等待，不因后台观察误报 busy；旧同步长RPC占用仍可明确busy，不能将错误转为不存在。

TTL 分两层：租户软期限可重设，每次1..300秒；VM owner和guest的不可延长寿命上限仍不超过现有600秒。运维可用session_max_lifetime_ms进一步限制（0默认600秒、允许1..600秒）；验收专用夹具设60秒，以实际检验超硬窗口拒绝而不等待数分钟。cold VM用独立固定上限上下文；soft期限用可重置的单调时钟timer，不能把可撤销旧context替换成失控VM。warm领取保留经过host/guest确认的剩余窗口，session prepare使用该窗口减10秒守护余量（含guest要求的5秒及控制传输余量）作为guest硬租期，job模式仍最多300秒；host软期限初值仍是用户请求。续期只改软期限，不能重置VM出生时间或签名身份、超越owner/guest寿命，超过max_expires_at明确拒绝。正在运行的流式命令可因续期继续跨过原软期限，执行自身timeout不变；缩短/到期仍取消执行并销毁VM。

API与root各自以锁保护timer/期限/closed状态，处理已触发旧timer与续期并发；root为权威，成功返回后API才更新缓存和本地timer，任何一层已开始退役则拒绝复活。API/launcher owner丢失仍销毁VM，配额/池一次领取策略不变。

## 验证

先[自评审](../../PUBLIC-QUALIFICATION.md#private-evidence)，再root/API timer竞态、分页/所有权、双SDK契约与实际子进程/guest边界测试。冻结一次CI，双架构离线包/ARM64无网卡QEMU、x64同包双SDK真实延长与缩短、到期后台回收/配额恢复及warm路径。三个E2B操作仅在双语言同候选正反例完成后计分。OSv未改不重复完整昂贵矩阵，普通安全基线与原性能门禁继续保留。

实施与双架构/实际KVM结果见[rc58验收](../../PUBLIC-QUALIFICATION.md#private-evidence)。三项新增E2B方法具同包双语言正反例，矩阵22/34；完整生态和性能目标仍开放。
