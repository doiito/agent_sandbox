# OTLP应用接入顺序

日期：2026-11-09。依据[ADR-0085](../adr/0085-bounded-otlp-observability.md)及[实施前评审](../../PUBLIC-QUALIFICATION.md#private-evidence)。独立三信号组件已进入验收，应用接入仍未完成；不关闭OBS-01、OBS-02或原40项范围。

先修复当前Prometheus慢读者持有任务计数锁的问题：在短锁内复制jobs、原始直方图buckets和duration，锁外排序及输出。慢writer阻塞在jobs头部时，并发recordJob仍必须完成；用同一反例先确认旧行为失败，再核对修复。返回的快照拥有自己的map/数组，记录累计指标的起点和采集时间，后续OTLP复用同一份快照。

后续配置增加可选`otlp`对象，缺省关闭，配置校验不联网、不打开凭据；只有API构造阶段创建worker，root launcher不因共享配置再次导出。资源来源固定host.api，单次事件分别保留host.api、host.launcher、host.launcher.audit与guest.reported，不替换持久审计。暴露明确的无效/满队列/已关闭/未编码丢失原因及各信号的发送结果。

请求适配不包裹ResponseWriter，保留hijack/flush。只从已认证租户、静态mux pattern、规范method和经过验证的任务结果填充属性；不读取raw URL/query、body、argv、输出或凭据。未拿到可信状态码时不标HTTP成功；正常handler返回与任务成功分别表达。需要逐任务结果时使用请求context中的明确观测槽，不能从响应字节推断。OTLP回调只取内存快照；池状态调用增加可取消context并保持3秒上限，失败时报告快照不可用，不将未知池状态标为健康或把已有API指标整批丢弃。

既有Shutdown继续先关闭升级连接，再排空HTTP。增加单独的CloseTelemetry，在HTTP排空后使用独立有界期限最后flush；超时或强制关闭必须保留错误，不能声称无损退出。嵌入式调用和监听失败也需关闭worker。

按影响验证：快照锁修复做native race、vet、ARM静态编译及无NIC QEMU；应用接入做配置、脱敏/来源、Collector失联/满队列、最终flush顺序和原流式/端口定向回归，再执行实际非root API进程与官方Collector互操作。完整候选CI、双架构离线包及指定机KVM在接入完成后集中进行；本次不重建未变化的guest，不宣称性能收益或完成原启动/容量/长稳门禁。
