# ADR-0060：多签名模板目录、显式路由与共享容量

状态：Accepted（rc68 基础功能验收通过）；日期：2026-11-04；需求 CAP-01、OSV-01/02、API-01/02/03、REL-04、PERF-03。

## 问题与范围

rc66服务只有一个当前模板。OSv科学模板和Linux进程模板只能分开运行；SDK显式选择与MCP仍假定默认模板，多个独立manager还会重复计算UID/内存预算。原方案要求多运行时模板、共用控制面与warm调度，本批实现这一基础，不把单模板列表视作多模板完成。

在现有配置增加有界静态`templates`目录（默认模板加至多15项）。每项有稳定ID、backend、artifact_root、kernel/image、签名manifest、入口、可选Linux磁盘配置与默认资源，以及该模板的warm profiles。宿主VMM/jailer、run_root、cgroup parent、并发/内存/CPU/pids/UID预算、安全和审计政策仍由顶层配置统一管理。全部签名和实际资产在启动时核验，不接受运行请求携带宿主路径或动态替换模板。模板目录允许受验证的Linux与OSv；不支持的架构/未安装模板明确拒绝。

## 发现、选择与权限

`GET /v2/templates`返回真实配置、当前可用且经租户入口/模板权限过滤的目录与能力。`GET /v1/capabilities`保留默认模板语义，显式backend和artifact_manifest_sha256查询只返回对应模板。名称用于发现，执行仍绑定backend与签名摘要，避免别名变化触发错误路由。未知/部分/过期选择拒绝；不会切回默认backend。目录里不可用项用有限原因码表示，不暴露服务器路径。

默认模板对租户隐藏时，缺省能力响应只保留无模板身份的全局发现/网络fetch能力；不自动选中其他模板。MCP在默认不可用时仍可读取目录，工具schema来自可用模板的并集，每次执行再查询所选能力。会话命令检查其已绑定模板，拒绝与显式selector冲突。签名job结果回显实际模板ID与摘要，SDK对新响应核对绑定并保留旧响应兼容。

`/v1/jobs`旧请求缺少选择器时使用默认模板；显式选择沿用严格验证。`/v2/jobs`、session创建、SDK与MCP按相同selector路由，session后续操作绑定创建时的manager。代理/环境/stdin/session等能力必须取所选模板，不能借默认Linux能力授权OSv。可选租户`allowed_templates`按backend/摘要限制；省略保留现有入口政策，空列表禁止所有模板。租户总并发/速率由现有API政策跨模板共享。

OSv纳入非root API/root launcher的正式代码路径，保留生产签名、路径信任、每VM独占UID、资源、审计和控制连接回收；不借诊断入口绕过这些机制。生产host readiness的既有失败仍真实报告，不把代码支持等同当前服务器生产ready。

## 共用VM与池管理

一个run_root锁、一次全局孤儿回收、一个物理/active资源账本和一个VM生命周期登记。子模板manager仅持有不可变模板政策与后端，所有VM注册在同一owner，stop/shutdown覆盖全部后端。清理失败锁住同一共享账本，UID只有实际销毁完成后才能归还。

每个模板保持现有签名/架构/配置/profile池key，禁止跨模板checkout或已使用VM回池。池策略的最大booting、refill速率/burst和前台优先规则为全局值；按模板轮转补充，先满足各模板最低水位，再增长热profile。全部最低水位的实例/内存/CPU/pids之和在启动前检查；不能分别通过后在运行期才发现无法满足。前台冷miss可回收其他模板闲置pristine/取消尚未领用的boot，不能销毁已领用任务；不在持有两个pool mutex时等待清理。状态/指标带模板身份，物理容量不把同一全局快照重复相加。

## 自评审与验证

实施前检查：递归配置与deep copy；单次锁/回收与构造失败；共享关闭和ledger锁次序；跨池前台优先/最低水位/有界并发；选中能力与租户过滤；OSv生产参数、审计和断连；旧单模板行为。

先做纯Go配置/路由/资源与真实launcher进程测试、双SDK与MCP定向测试；冻结候选后一次完整CI。双架构离线主包保持现有Linux默认，x64构建可显式加入已锁定OSv科学模板（kernel/rootfs/module、独立签名manifest/SBOM、来源与许可证），主SBOM引用子BOM，外层发布签名覆盖所有文件。缺少对应架构资产时显式拒绝，不自动降级；目标机不下载依赖。实际最终ARM QEMU验证目录、安装与现有功能；x64同候选在隔离网络中同时运行Linux与真实OSv模板，验证cold/warm、租户总配额、池资源/独占身份、取消/停止及零残留，并执行一次受影响的原矩阵。仅验证脚本或文档变化按摘要复用已证明部分；产品变更另冻结新候选。

多模板本身不证明新增运行时兼容、E2B分子、完整性能/内存或域名TLS。原40需求、普通安全基线和用户的ARM KVM免验、离线安装及项目内依赖要求保持。

实施与失败/补验结果见[rc68 验收](../../PUBLIC-QUALIFICATION.md#private-evidence)。真实混合 cold/warm、OSv 默认、全局容量及双 SDK/MCP 路由通过；父科学模板的定时等待缺口按 ADR-0061 修复后使用新内核候选，未绕过原 sleep 用例。
