# 验证记录与复现方法

2026-11-11 [监督路径真实API ABBA](../PUBLIC-QUALIFICATION.md#private-evidence)在指定机完成32个fresh session、2048次正式操作且零失败，固定PID1 mimalloc secure=4。独立监督的稳定命令p50/p99降低6.56%/1.01%，首条工作负载p50增加2.39%，读取p99波动完整保留，整体性能门禁未通过。后续有界代码读取仅修改initialize函数，双架构各19组及1次真实崩溃重启通过；ARM编译权限失败未启动VM，原记录保留，获准访问离线容器后在新r4通过。新代码的实际API性能及候选验收待完成，当前基线仍为rc82。

2026-11-11 [独立监督程序接线](../PUBLIC-QUALIFICATION.md#private-evidence)完成正式父进程、双架构基础/代码镜像、QEMU及发布/SBOM接线。两架构各71组功能检查和1次真实崩溃重启通过，10套通过夹具的实际helper逐字匹配新bundle。两份旧kernel验证器的异步SIGINT失败保留，按当前帧协议修正后独立r2通过。构建正反向门禁16/14项和SBOM检查通过，旧/新路径同源码agent已准备；实际API性能、新候选CI/离线包及KVM回归尚待执行，当前基线仍为rc82。

2026-11-11 [普通 mimalloc 实测](../PUBLIC-QUALIFICATION.md#private-evidence)完成2048次真实API操作和独立1024次启动路径诊断，均零任务失败。普通配置命令p50/p99仍增加9.4%/10.9%，guest VmHWM中位数为7.43MiB，整体收益继续开放。8个夹具清理后回收指定机约217MiB和本地约34MiB测试副本，实际参考与源码保留。随后[独立监督入口](../PUBLIC-QUALIFICATION.md#private-evidence)按设计、自评审顺序完成双架构静态编译、逐ELF分配器核验及x64四项拒绝入口检查；父进程/镜像接线、实际VM和性能回归尚待完成，当前功能基线仍为rc82。

2026-11-05 [共享Rust工作负载监督](../PUBLIC-QUALIFICATION.md#private-evidence)接入正式命令路径，保留真实PID，独立cgroup/subreaper回收setsid后代并支持命令共存。双架构32组QEMU实际监督/pipeline/fatal reset、native54项及clippy通过；修复已结束进程误判超时，原始失败保留。归档后清理19份验证目录约189.33MiB，真实依赖及回滚保留。完整代码上下文/API/SDK/warm与新候选CI、KVM继续开放，E2B仍23/34。

2026-11-05 [Linux代码运行时与解释器原型](../PUBLIC-QUALIFICATION.md#private-evidence)完成双架构闭包和普通用户实际Python/科学库/Node/npm/TypeScript运行。相同kernel源码的本地与ARM无NIC QEMU验证状态、富结果、异步、错误及CPU/await中断后的复用；namespace原型验证setsid后代回收和另一工作负载存活。结果封存于项目；正式Rust监督/API/SDK/MCP/warm/发布验收尚待完成，E2B仍23/34，64MiB及性能条件继续开放。

最新 [rc70 目录事件订阅](../PUBLIC-QUALIFICATION.md#private-evidence)完成真实inotify、独立guest/launcher通道、双SDK与MCP；cold/warm Python各24、Node各19，MCP各33项通过。完整CI418输入、双架构65/51文件、ARM无NIC QEMU48组、六份x64同包夹具通过。46份同候选报告将E2B增至23/34，28项门槛仍未达到；原40项、64MiB、性能/生产继续开放。rc69真实线程回收缺陷已修复；rc70两处验收脚本补记及失败记录保留。选定验证副本约8.02GiB已清理，真实资产与回滚保留。

最新 [rc68 多模板与 OSv 定时等待](../PUBLIC-QUALIFICATION.md#private-evidence)完成同一控制面的真实 Linux/OSv 签名目录、共享容量/补池及租户选择；修复 Python sleep，生产 API 原科学功能20项通过。完整 CI、双架构65/51文件包、ARM64无 NIC QEMU45组、混合 cold/warm/OSv默认26/26/24项及原核心矩阵通过。七套通过夹具、结束的失败夹具和串口预检退役，清理副本并保留真实项目依赖及rc66/rc64回滚。44份同包 E2B 报告仍22/34；完整功能、64MiB、性能/生产条件继续开放。验证脚本修正和初始失败独立留档，包及产品源码保持冻结。

[rc66 Linux guest代理](../PUBLIC-QUALIFICATION.md#private-evidence)接通实际guest/vsock/per-VM relay与非root egress，修复MCP误用部署校验；其32/33项cold/warm代理、池29与SDK/MCP/生命周期矩阵在rc68同包再次通过。NET-01其余网络模式继续开放。

最新 [guest代理宿主核心](../PUBLIC-QUALIFICATION.md#private-evidence)完成HTTP/HTTPS CONNECT、root launcher身份与非root egress链路，双架构静态编译、ARM64无网卡QEMU20组、实际非root进程8项及Go回归/race通过。该阶段的guest/vsock接线与VM生命周期后来由rc66完成；当时离线包保持rc64。NET-01其余模式与原完整目标仍开放。

最新 [rc63/rc64网络fetch与离线信任文件](../PUBLIC-QUALIFICATION.md#private-evidence)完成公共egress引擎/API/MCP/双SDK、真实TLS/IPv6/重定向/取消/审计与公共CA闭包。最终双架构51文件、ARM64无NIC QEMU38组、x64cold/warm网络各28及核心API/SDK/pool/生命周期矩阵通过；公共CA发布增量仅改变数据/安装器/SBOM，服务与SDK逐项相同后复用运行基线，另验实际最终包信任/模板7项。四夹具退役、清理约2.24GiB重复副本，真实依赖保留项目。E2B同候选rc63仍22/34，guest代理与原完整功能/性能目标继续开放。

最新 [rc62 MCP stdio](../PUBLIC-QUALIFICATION.md#private-evidence)完成双版本协议与共用认证API的执行/文件/模板、会话/后台命令和输入票据。完整CI、双架构各44文件包、ARM64无网卡QEMU35组、同包x64 cold/warm各29项通过；原API/guest/VMM/SDK载荷摘要等于rc60，完整既有矩阵按摘要复用。网络工具未发布，E2B索引仍绑定rc60的22/34，性能/生产门禁不变。5份测试夹具退役并清理约1.45GiB重复副本，实际依赖保留于项目。

此前 [rc60 Linux一次性job输入](../PUBLIC-QUALIFICATION.md#private-evidence)完成environment/cwd/16KiB固定stdin及客户端实际启动模式。完整CI、双架构各41文件离线包、ARM64无网卡QEMU33组、x64双SDK cold/warm各23项、基础API/session/生命周期及warm会话13项通过；独立同包池29项校验后复用。E2B仍22/34，性能门禁和其余原始功能继续跟踪。

此前 [rc58 会话信息、分页与 TTL](../PUBLIC-QUALIFICATION.md#private-evidence)完成真实资源信息、租户稳定分页及有界延期/缩短。完整CI、双架构各41文件离线包、ARM64无网卡QEMU32组、x64池29/API28/session26、双SDK生命周期各26项及实际warm补验13项通过；E2B为22/34，距28项仍差6项，性能门禁继续保留。

此前 [rc56 交互stdin](../PUBLIC-QUALIFICATION.md#private-evidence)完成有界写入、显式EOF、guest确认与独立观察/取消。完整CI、双架构各41文件离线包、ARM64无网卡QEMU32组、同包x64双SDK v8及实际warm新路径9项通过；真实1MiB输入/超限、背压超时后查询和取消复用验证通过。E2B为19/34，原始其余功能和性能目标继续跟踪。

此前 [rc55 Bash 与 E2B 命令](../PUBLIC-QUALIFICATION.md#private-evidence)完成真实 guest PID、env/cwd、run/list/connect/kill 与缓存 wait、UTF-8 回调、观察超时后重连。双架构离线包各41文件、完整CI、ARM64无网卡QEMU32组、x64池29/API28/session26、双SDK v7及实际warm新路径7项通过。固定E2B增至17/34；交互stdin、OSv流式、其余原功能和性能目标继续跟踪。

此前 [rc53 后台命令与实时输出](../PUBLIC-QUALIFICATION.md#private-evidence)完成 Linux session 句柄、SSE、游标重连、取消后复用与有界历史。一次完整本地 CI、双架构离线包、ARM64 QEMU31组、x64池29/API28/session26、包内双SDK v6及warm新路径5项通过；QEMU夹具执行位原失败保留。E2B仍12/34，OSv流式、交互stdin/env/cwd与性能等原缺口继续跟踪。

此前 [rc52 文件整理与功能验收](../PUBLIC-QUALIFICATION.md#private-evidence)补齐文件/目录/链接重命名和有界递归删除；双架构离线包、完整本地 CI、ARM64 无网卡 QEMU 30 组及指定 x64 KVM warm 29/API 28/session 26 与包内双 SDK 工作流通过，固定 E2B 由 10/34 增至 12/34。按用户要求功能优先，全面 CVE/长期 fuzz/独立安全认证转为增强项；基本权限/隔离/资源/签名与性能目标继续保留。

此前[漏洞证据与发布隔离检查](../PUBLIC-QUALIFICATION.md#private-evidence)完成真实正对照、rc51 的 18/18 查询、定向 CI 21 项和无路由 CLI E2E 六项。13 条源码包级匹配尚待实际二进制影响审核，另有 13 项覆盖缺口，严格门禁失败；修复 clean 工作树测试开关的发布标记绕过及 schema 可选格式检查缺失，签名业务载荷不变。

最新 [rc51 来源与完整文件级 SBOM](../PUBLIC-QUALIFICATION.md#private-evidence)把固定解释器的字节码语义核验接入常规构建，覆盖最终镜像 2,775 个文件/链接及 30 个运行时描述，官方 schema 离线验证通过。一次完整本地 CI、真实 KVM 的 128MiB 原 20 项功能、1,111 项缓存契约与两条大读取完整性路径通过；64MiB 完整科学任务仍 guest OOM/超时，组件版本与扫描覆盖明确不完整。四份夹具归档后退役，实际依赖和已签名候选保存在项目。

此前 [rc50 有界 ROFS 大读取](../PUBLIC-QUALIFICATION.md#private-evidence)修复固定 Firecracker 描述符布局与无缓存大读取的不兼容，原生协议/退出 49 项、池 25 项、冷 API 33 项及 Python 128MiB 功能 20 项通过，64MiB 仍 OOM。修复、复现和失败门禁均保留。

此前 [rc49 签名 ROFS 内存策略](../PUBLIC-QUALIFICATION.md#private-evidence)保持原 kernel/agent/科学栈不变，经完整 CI 和真实 API 验证在 128MiB 通过原 20 项 Python 功能，旧原生模板池 25 项/冷路径 33 项兼容通过。64MiB 完整科学任务仍超时；缓存关闭在一对诊断中少约 37.35MiB，但增加读取调用，不能称普遍提速。小页实验未采纳，八份本轮夹具退役，生产和完整性能门禁仍开放。[磁盘清理](../PUBLIC-QUALIFICATION.md#private-evidence)释放约 9.14GiB，当前包与实际依赖摘要不变。

最新 [rc48 OSv 管道与退出桥验证](../PUBLIC-QUALIFICATION.md#private-evidence)完成真实 pipe 32 项、原生协议/退出 49 项、签名池 25 项、冷路径 API 33 项及一次完整 CI。512MiB Python 科学栈的 20 项功能用例全部通过，含正常 finalization、atexit、CLI 与真实非零退出；64MiB 完整科学任务超时，总体内存目标仍失败。成功与失败报告均保留，测试进程/cgroup/凭据已核对退役，生产和完整性能门禁未通过。

此前 [rc46 静态 mimalloc 双架构离线验收](../PUBLIC-QUALIFICATION.md#private-evidence)完成项目内依赖/许可证/SBOM、双架构构建及重编逐字一致、ARM64 实际离线包 QEMU 29 组、x64 KVM warm 29 项/API 28 项/session 26 项及 14 台 VMM 资源隔离观察。两个测试服务和临时凭据已退役，实际安装文件摘要与本地包一致。混合分配/跨线程释放微基准改善，小块分配回退；完整性能和生产门禁仍未通过。

此前[rc42实时归属与回归](../PUBLIC-QUALIFICATION.md#private-evidence)通过完整本地CI、双架构离线包、ARM64 QEMU28项、Linux池29项、OSv池25项/冷路径33项及同包SDK/API/故障回归。合法KVM内核worker被实时识别并纳入原资源/退出预算，额外用户进程拒绝。每后端128次无跟踪任务成功，Linux/OSv总启动p50=4.539/3.705ms、p99=6.341/5.347ms；两后端readiness均无>10ms，完整性能门禁继续失败。十一份夹具和观察过的VM/worker原代次退役已核对，rc41失败保留。

[4096对cgroup接口诊断](../PUBLIC-QUALIFICATION.md#private-evidence)原读取76次>10ms、成员接口0次；[rc41候选](../PUBLIC-QUALIFICATION.md#private-evidence)完整CI/QEMU通过但实机初池因错误排斥内核worker失败。修订rc42已完成验收，初版失败和原始诊断均保留；相较rc40两后端中位数增加，没有宣称所有分位数更快。

此前 [rc38 启动阶段与回归](../PUBLIC-QUALIFICATION.md#private-evidence)建立七阶段与 cold 首次就绪计时，保留同口径总启动和旧 v1 阶段原始证据。

随后完成[同版 CPU 周期 A-B-B-A](../PUBLIC-QUALIFICATION.md#private-evidence)：256 正式任务全成功，100ms/10ms 两策略各 128 样本，readiness p99=34.493/33.670ms；14 个慢样本在覆盖窗口内未观察到 CPU 节流增量。缩短周期没有消除长尾，默认值保持不变；13 项采样工具测试与清理核对通过，首轮异常批次独立保留，生产门禁仍未通过。

[Linux 直连 vsock 分段](../PUBLIC-QUALIFICATION.md#private-evidence)的 256 个连续 ping 全成功，受控串行窗口内总传输 p99=1.347ms、最大 1.360ms，未复现领取长尾；它不包含完整启动成本。新增工具与原测量合计 19 项测试通过，八份夹具零残留，下一步回到正常 API 领取路径定位，生产门禁保持未通过。

[正常 API 有限跟踪](../PUBLIC-QUALIFICATION.md#private-evidence) 8 正式+5 warmup 全成功且完整覆盖，确认旧 ping→prepare 两条控制连接；首轮 64 任务虽全成功，仍因 trace 上限/采样异常保持失败。26 项工具测试与十份夹具清理通过。[ADR-0036](adr/0036-atomic-warm-readiness-and-preparation.md) 已在 rc40 完成功能验收，停止尾行补充解析后工具回归增至 28 项，完整性能目标未达到。

[rc37 功能基线](../PUBLIC-QUALIFICATION.md#private-evidence)完成共用 pristine warm pool：指定 x64 KVM Linux 公开 job/session 池 26/26、OSv 诊断池 23/23，独占 owner 与崩溃对账通过；同包双 SDK、job API 28/28、session API 26/26、停止/崩溃恢复和宿主隔离回归通过，OSv 冷路径 33/33。双架构离线包及 ARM64 无网卡 QEMU 25/25 通过。OSv 产品生产准入和真实大样本启动门禁仍未通过，功能结果不能宣称 1–2 ms 目标达成。

新增 [rc37 两后端千次 warm 启动诊断](../PUBLIC-QUALIFICATION.md#private-evidence)：各 1000 正式样本均成功、无 cold miss，Linux p50/p95/p99 为 4.939/23.762/41.929 ms，OSv 为 3.717/4.609/5.203 ms。两边均未达到完整 2/5/10 ms 目标；宿主/亲和性/OSv 生产准入等条件未通过，不登记为生产性能证据。启动、完整 HTTP、等待补池分别列报，原始 JSONL/候选/源码/宿主/清理绑定与 CDF 已保留。

OSv [pristine 准备协议 r2](../PUBLIC-QUALIFICATION.md#private-evidence)的 17 项真实 KVM 协议测试是 guest 基线；rc37 在此之上接入共用调度器和生命周期。运行时发现并修复诊断 owner 未锁定/对账、运行目录类型检查错误，失败候选与清理证据均保留。共用 owner 历史基线见[rc31](../PUBLIC-QUALIFICATION.md#private-evidence)，Linux 准备协议见[rc29](../PUBLIC-QUALIFICATION.md#private-evidence)。

> 当前目标的逐项状态见[需求矩阵](REQUIREMENTS.zh-CN.md)；实际执行见[首轮记录](../PUBLIC-QUALIFICATION.md#private-evidence)、[第二轮记录](../PUBLIC-QUALIFICATION.md#private-evidence)、[配置根信任验收](../PUBLIC-QUALIFICATION.md#private-evidence)、[离线发布验收](../PUBLIC-QUALIFICATION.md#private-evidence)、[rc5 离线包增量验收](../PUBLIC-QUALIFICATION.md#private-evidence)、[rc6 双架构离线包验收](../PUBLIC-QUALIFICATION.md#private-evidence)、[OSv guest 并发验收](../PUBLIC-QUALIFICATION.md#private-evidence)、[镜像模块真机验证](../PUBLIC-QUALIFICATION.md#private-evidence)、[OSv 产品通道诊断验收](../PUBLIC-QUALIFICATION.md#private-evidence)、[OSv 参数边界及畸形帧真机验收](../PUBLIC-QUALIFICATION.md#private-evidence)、[签名 OSv 模板候选验收](../PUBLIC-QUALIFICATION.md#private-evidence)、[OSv 跨进程 KVM 验收](../PUBLIC-QUALIFICATION.md#private-evidence)、[故障与并发验收](../PUBLIC-QUALIFICATION.md#private-evidence)、[能力契约验收](../PUBLIC-QUALIFICATION.md#private-evidence)和[v2 显式模板绑定验收](../PUBLIC-QUALIFICATION.md#private-evidence)。下文 2026-08 数据为历史记录，不能代替当前候选的 CI、兼容、长稳或生产验收证据。

文件信息基线的双架构验签、ARM64 无网卡 QEMU 18/18、指定服务器隔离安装及包内双语言真实 KVM 链接/扩展属性文件信息正反例见[rc27 验收](../PUBLIC-QUALIFICATION.md#private-evidence)；固定 E2B 2.51.0 显式适配层为 10/34。包内可解析手册和配置示例基线见[rc23 定向验收](../PUBLIC-QUALIFICATION.md#private-evidence)，原生 session 文件读写/列表/元数据/删除基线见[rc20 验收](../PUBLIC-QUALIFICATION.md#private-evidence)。公开 session API 基线见[rc17 验收](../PUBLIC-QUALIFICATION.md#private-evidence)，真实 launcher 崩溃恢复见[rc11 验收](../PUBLIC-QUALIFICATION.md#private-evidence)，专用 cgroup 恢复见[rc10 验收](../PUBLIC-QUALIFICATION.md#private-evidence)，切换回滚见[rc9 定向验收](../PUBLIC-QUALIFICATION.md#private-evidence)。

OSv 原生签名模块的有界环境变量在指定服务器完成[跨进程 24/24、guest 帧 28/28 与公开 API 定向验收](../PUBLIC-QUALIFICATION.md#private-evidence)。此能力仍在 OSv 诊断范围，生产门禁未开放。
OSv 原生签名模块的有界二进制 stdin 完成[跨进程 33/33、guest 帧 37/37 与公开 API 定向验收](../PUBLIC-QUALIFICATION.md#private-evidence)；空输入在 API→launcher 传输中保留，OSv 生产门禁仍关闭。

rc12 将[零第三方依赖 Python 客户端纳入双架构离线包](../PUBLIC-QUALIFICATION.md#private-evidence)，已完成 ARM64 QEMU 和 x64 指定服务器的安装后 SDK 真机验收。
rc13 将[零 npm 依赖的 Node.js / TypeScript 客户端纳入双架构离线包](../PUBLIC-QUALIFICATION.md#private-evidence)，已完成类型编译、ARM64 QEMU 和 x64 指定服务器的安装后 SDK 真机验收。
同一 rc13 候选完成[Linux `network=none` 真机隔离验收](../PUBLIC-QUALIFICATION.md#private-evidence)，覆盖 guest 接口/路由、元数据/宿主/网关不可达与非 `none` API 拒绝。
同一 rc13 候选还完成[双租户并发、速率及身份隔离真机验收](../PUBLIC-QUALIFICATION.md#private-evidence)，并在完整用例后清理了独立测试环境。
生态兼容方面已建立[E2B 2.51.0 固定方法分母与门槛](../PUBLIC-QUALIFICATION.md#private-evidence)：34 项中当前真实行为兼容证据为 22，发布目标门槛仍关闭。

rc11 真机资源限额故障注入见[CPU/pids](../PUBLIC-QUALIFICATION.md#private-evidence)、[memory/swap](../PUBLIC-QUALIFICATION.md#private-evidence)、[IO 写入](../PUBLIC-QUALIFICATION.md#private-evidence)、[IO 读取](../PUBLIC-QUALIFICATION.md#private-evidence)和[双租户并发 OOM](../PUBLIC-QUALIFICATION.md#private-evidence)。

## 1. 验证结论

2026-08-26 已在指定 Debian 12 裸机完成 QEMU/Firecracker/OSv 真实 KVM 基线；2026-08-27 在同一机器完成 Firecracker + 最小 Linux 的生产链路验收：

- QEMU microvm + KVM：同一 OSv/Rust 客体启动、任务协议、只读盘和禁网验证通过；
- Firecracker + KVM：功能、冷启动、RSS、吞吐和 host 攻击面 profile 通过；
- Firecracker + jailer + KVM：Go API 完整链路通过，实际 UID/GID、capability、seccomp、chroot cleanup 与 cgroup memory 上限均验证；
- 100/50/100/128 次四组正式基准全部零失败；详细数字见 [特性与性能实测](METRICS.zh-CN.md)。
- TLS 1.3 mTLS、非 root API/root launcher、签名 manifest/SBOM、唯一 jail UID、CPU/memory/swap/pids/io cgroup、只读 input disk 和 hardened systemd unit 实机通过；
- 生产 API c=1 12/12 与 c=4 24/24 零失败，p50 分别 922.554/956.271 ms，吞吐 1.085/4.020 jobs/s；
- API crash 会取消运行 VM；launcher SIGKILL 后自动重启并 reconciliation=1，最终进程、workdir、cgroup 全部零残留。

验收未使用任何公网域名或既有证书；mTLS 使用临时测试 CA，测试私钥在验收后删除。

## 2. 环境与供应链

| 项目 | 实测值 |
|---|---|
| Host | 隔离的 x86_64 KVM 裸机；可识别硬件信息不入库 |
| OS / kernel | Debian 12 / Linux 6.1 系列 |
| CPU / RAM | 满足并发基准容量；具体机器指纹不入库 |
| KVM | 硬件虚拟化开启；`/dev/kvm` 仅授权给运行服务的组 |
| cgroup | unified cgroup v2 |
| QEMU | 7.2.22，Debian security build |
| Firecracker / jailer | 官方 release 1.16.1；release tar SHA-256 和包内 `SHA256SUMS` 均校验 |
| OSv | `v0.57.0-398-g0e34e4dc` |

最终产物在全部测试后重新计算，摘要未变化：

```text
loader-stripped.elf  e3496ebbbc7d3a87166fc136c8e9e251c704cdd262ed6c6f13cf140470c3b916
usr.img (qcow2)      6f035beb0336c2a16a8a9047a77904ebcacd3a18a5ecf161640902770a8b0cdf
osv-agent.raw        9ff043979975c55f5a7c5b1b7fdb2e5e2fc2b1e2db84325da5f9cb76aaea88fb
```

raw image 的 logical size 为 512 MiB，但保持稀疏；QEMU 和 Firecracker 使用相同 kernel 和同一客体文件内容，只因磁盘格式要求分别使用 qcow2/raw。

## 3. 代码验证

本地最终执行：

```bash
GOCACHE=/tmp/osv-sandbox-go-cache GOTMPDIR=/tmp \
  go test ./cmd/... ./internal/...
GOCACHE=/tmp/osv-sandbox-go-cache GOTMPDIR=/tmp \
  go vet ./cmd/... ./internal/...
cargo test --manifest-path guest/Cargo.toml --locked
cargo build --manifest-path guest/Cargo.toml --locked --release \
  --target x86_64-unknown-linux-musl
```

Go tests 覆盖 artifact hash/path confinement、参数引用、QEMU hardening、jailer 文件 staging/cgroup argv、严格 API、job ID 协议绑定、预期 VMM 非零 shutdown、输出限制和 timeout kill。Rust tests 为 2/2，通过 JSON escaping 与 job ID 行为；release 为静态 musl executor。

## 4. 远端功能与隔离验证

### 4.1 两个 KVM 后端

`cmd/osv-bench` 直接调用生产 backend 的参数/配置生成逻辑，避免 benchmark 与 daemon 启动路径漂移。等价 smoke 命令：

```bash
/opt/osv-sandbox/osv-bench \
  -backend both -iterations 1 -warmup 0 -concurrency 1 \
  -operation isolation-probe -include-output \
  -output /var/tmp/osv-sandbox-results/isolation.json
```

两个后端都返回匹配的 `OSV_AGENT_RESULT`，其中 `root_write_blocked`、`metadata_connect_blocked`、`loopback_connect_blocked` 全为 `true`。原始结果可能包含宿主信息，因此只作为发布流水线制品保存，不提交源码仓库。

Firecracker 的 one-shot guest 通过 I/O poweroff 后，有时以 `MicroVMStopped ... GenericError` 和 VMM exit 1 退出。控制面只有在未超时且收到 protocol、job ID、`ok` 均合法的 envelope 时才把它归一为成功；缺失或错误 envelope 仍为失败。对应回归测试已经加入。

### 4.2 jailer 完整 API

生产示例配置启用：

```json
"jailer": {
  "path": "/usr/local/bin/jailer",
  "uid": 65534,
  "gid": 65534,
  "cgroup_version": 2,
  "memory_overhead_mib": 128,
  "no_file_limit": 128
}
```

root 启动 daemon 后，doctor 四项（artifact、hypervisor、KVM、jailer）全部 `ready=true`。经 loopback API 提交 `isolation-probe`，状态 `succeeded`、`protocol_ok=true`、耗时 125 ms。

在 5 秒 `hold` 任务运行期间从 host 实测：

```text
Uid/Gid        65534 / 65534（real/effective/saved/fs 全部一致）
Threads        2
CapEff         0000000000000000
Seccomp        2
cgroup         /firecracker/<job-id>
memory.max     268435456
```

任务后 `/opt/osv-sandbox/run` 无子项，未发现残留 osv-sandboxd/Firecracker/QEMU 进程。`--new-pid-ns` 的 jailer 手工 smoke 会让同步父进程提前返回，因此当前 manager 明确不启用该选项；需要 PID namespace 时应先实现 supervisor/pidfile wait。

## 5. 性能复现

正式命令的核心参数如下；完整原始报告保存了 host、options、每个 sample 和 summary：

```bash
# warm c=1, n=100
/opt/osv-sandbox/osv-bench -backend both -iterations 100 -warmup 10 \
  -concurrency 1 -operation probe \
  -output /var/tmp/osv-sandbox-results/warm-c1-n100.json

# 定向驱逐 artifact cache，c=1, n=50
/opt/osv-sandbox/osv-bench -backend both -iterations 50 -warmup 0 \
  -concurrency 1 -operation probe -evict-artifacts \
  -output /var/tmp/osv-sandbox-results/cold-artifact-c1-n50.json

# warm 并发扩展
/opt/osv-sandbox/osv-bench -backend both -iterations 100 -warmup 8 \
  -concurrency 8 -operation probe \
  -output /var/tmp/osv-sandbox-results/warm-c8-n100.json
/opt/osv-sandbox/osv-bench -backend both -iterations 128 -warmup 8 \
  -concurrency 32 -operation probe \
  -output /var/tmp/osv-sandbox-results/warm-c32-n128.json
```

不要把 `-evict-artifacts` 称为“物理冷机”：它只针对 kernel/image file descriptor 请求 `POSIX_FADV_DONTNEED`，没有重启 host，也不能保证驱逐块设备或 hypervisor 内部的所有 cache。

## 6. 攻击面复现与局限

二进制/linkage、`/proc` maps/FD/thread/RSS、Seccomp、CapEff 均由 host 采集。另用 `strace -f -c` 对一次最小 `echo` 启动做 syscall 汇总。Tracer 会改变时序，故 syscall 汇总只用于攻击面枚举，不进入冷启动统计；原始采集文件不提交源码仓库。

已有代码与功能证据尚未覆盖全部生产要求，完成状态以[需求矩阵](REQUIREMENTS.zh-CN.md)为准。原始 benchmark 与结构化验收证据因包含宿主运行信息而由发布流水线留存，不进入 Git。组织上线前仍需补齐 KVM/Firecracker CVE 周期扫描、10k+ 长样本、CPU pinning/NUMA、24h/7d soak、OOM/串口/vsock flood、parser fuzz、密钥轮换和远程不可变审计。

- [2026-11-07 rc75端口/预览同包功能验收](../PUBLIC-QUALIFICATION.md#private-evidence)：完整CI、双架构真实helper、ARM离线包及x64七夹具通过；原性能和其他发布门禁继续开放。
- [验收产物回收](ARTIFACT-RETENTION.zh-CN.md)：及时清理已证明无用的中间、失败及重复产物，保留实际依赖与必要证据。
- [2026-11-07 推理主机接口与账单命令](../PUBLIC-QUALIFICATION.md#private-evidence)：主机处理器/root RPC、离线运维、生产出口进程及ARM64组件验收通过；guest、双SDK/MCP、签名和同包部署继续实施。
- [2026-11-07 推理双SDK/MCP](../PUBLIC-QUALIFICATION.md#private-evidence)：双SDK、MCP、25组实际mTLS组件链路与ARM64对应功能检查通过；真实guest、签名及同包部署继续实施。
- [2026-11-07 Guest 推理组件](../PUBLIC-QUALIFICATION.md#private-evidence)：固定guest SDK、root策略摘要、35组实际进程桥接/TLS链路及实际ARM解释器函数通过；生产签名镜像、OSv实际调用与同包部署仍待完成。
