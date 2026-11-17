# ADR-0074：活跃会话绑定的能力查询

状态：Accepted（宿主及双SDK本地验证通过，MCP使用该入口继续实施）；设计日期：2026-11-05；验证：2026-11-06；需求API-02/03、CAP-01、LIFE-01，支撑ADR-0073。

现有CapabilitiesFor及模板目录把artifactAvailability作为新任务/VM准入条件；签名到期后仍在租期内的VM，其代码控制入口实际按原owner/TTL继续工作。让SDK/MCP为查询或取消先通过该新准入接口，会意外阻断活跃工作。需要会话绑定的能力入口，不绕过创建VM的有效期校验。

新增GET /v2/sessions/{id}/capabilities，沿原lookupSession验证owner、TTL、launcher状态，并使用独立session-info确认实际ID/backend/签名摘要。创建会话时保存已认证模板能力的深拷贝；响应为原capability report附加session_id，再按当前tenant入口策略过滤。该信息说明原已领取VM的能力，不保证新VM可准入；签名/源码/运行时由创建时的证明和不可变绑定保证。新POST sessions/jobs与原CapabilitiesFor的有效期规则不变。

SDK代码发现改用该入口，校验session/backend/digest及v5 runtime profile，再缓存不变运行时语义；所有操作仍由实际API/launcher授权。MCP每次从owner会话入口查询live capability，避免依赖默认模板或额外同步shell控制。MCP发现针对既有会话的代码工具可使用目录中的已认证代码profile，即使该模板停止新VM准入；目录明确保留Available=false，不能因此重新发布新VM工具。当前tenant允许语言为空时仍可观察/清理。

实施前自评审：不能只用API缓存声称会话仍存活，必须经独立owner info；能力保存深拷贝，响应过滤不得改变其他会话或原模板。endpoint跨tenant返回404；launcher失联或身份变化失败并关闭API会话。source/signature到期不延长TTL，不恢复已关闭会话，不新增容量。目录不可用条目只保留代码会话所需的认证profile/语言/limits，不宣称新VM/one-shot等准入。

定向验证owner、SID/backend/digest变化、失联/过期、深拷贝、当前语言策略、过期模板仍能控制原会话而不能创建新VM；双SDK错误会话/模板能力拒绝及旧模板回归。guest无改动，仍承接32组QEMU，不重复完整矩阵。候选冻结后统一CI与双架构同包验收，完整40项及23/34计数不变。

验证见[记录](../../PUBLIC-QUALIFICATION.md#private-evidence)：五项新增Go顶层用例及相关Session/Code/DirectoryWatch/TemplateCatalog带race通过；双SDK各新增2项、Python全77/Node全60及TypeScript正反例通过，vet通过。MCP九项代码工具仍待实现与测试，当前发行仍rc70。
