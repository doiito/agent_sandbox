# x64 / aarch64 Linux 离线发布

2026-11-17 GitHub 发布新增[隐私门禁](adr/0129-github-publication-privacy.md)：所有源码、文档、包内元数据、二进制和附件必须排除运维身份、凭据、本机路径和业务数据。旧草稿与新建引用已撤下，旧包未上传；正在构建路径匿名化的新 guest 与候选，公开侧仅保留脱敏摘要。

2026-11-17用户要求先发布，当前warm目标按[ADR0128](adr/0128-warm-p99-fifteen-release.md)更新为5/9/15ms。rc92原千次数据满足新阈值，但旧包缺少现行构建身份，仍需按下述候选绑定流程生成、验收并正式签名；以下历史候选状态不代表本轮发行已经完成。

最新[rc74代码模板与监督清理](../PUBLIC-QUALIFICATION.md#private-evidence)已通过双架构78/64文件离线包、70组实际guest QEMU、完整CI、ARM离线包48组及x64同包五夹具。固定E2B28/34门槛达到；当前为测试签名功能基线，正式发布仍按功能、性能和一般安全准则验收。K8s暂缓，运行依赖保存在项目中。

目录事件订阅已由[rc70 目录事件订阅](../PUBLIC-QUALIFICATION.md#private-evidence)完成：签名Linux v4、双架构65/51文件、完整CI及ARM QEMU48组、x64同包cold/warm双SDK监听/MCP与既有矩阵通过。构建显式设置 `RELEASE_FILE_WATCH=1`，proxy仍由 `RELEASE_GUEST_PROXY=1` 独立声明；真实依赖位于项目。E2B23/34，完整目标继续开放。

最新 [rc63/rc64网络fetch与离线信任文件](../PUBLIC-QUALIFICATION.md#private-evidence)完成公共egress引擎/API/MCP/双SDK、真实TLS/IPv6/重定向/取消/审计与公共CA闭包。最终双架构51文件、ARM64无NIC QEMU38组、x64cold/warm网络各28及核心API/SDK/pool/生命周期矩阵通过；公共CA发布增量仅改变数据/安装器/SBOM，服务与SDK逐项相同后复用运行基线，另验实际最终包信任/模板7项。四夹具退役、清理约2.24GiB重复副本，真实依赖保留项目。E2B同候选rc63仍22/34，guest代理与原完整功能/性能目标继续开放。

最新 [rc62 MCP stdio](../PUBLIC-QUALIFICATION.md#private-evidence)完成双版本协议与共用认证API的执行/文件/模板、会话/后台命令和输入票据。完整CI、双架构各44文件包、ARM64无网卡QEMU35组、同包x64 cold/warm各29项通过；原API/guest/VMM/SDK载荷摘要等于rc60，完整既有矩阵按摘要复用。网络工具未发布，E2B索引仍绑定rc60的22/34，性能/生产门禁不变。5份测试夹具退役并清理约1.45GiB重复副本，实际依赖保留于项目。

此前 [rc60 Linux一次性job输入](../PUBLIC-QUALIFICATION.md#private-evidence)完成environment/cwd/16KiB固定stdin及客户端实际启动模式。完整CI、双架构各41文件离线包、ARM64无网卡QEMU33组、x64双SDK cold/warm各23项、基础API/session/生命周期及warm会话13项通过；独立同包池29项校验后复用。E2B仍22/34，性能门禁和其余原始功能继续跟踪。

此前 [rc58 会话信息、分页与 TTL](../PUBLIC-QUALIFICATION.md#private-evidence)完成真实资源信息、租户稳定分页及有界延期/缩短。完整CI、双架构各41文件离线包、ARM64无网卡QEMU32组、x64池29/API28/session26、双SDK生命周期各26项及实际warm补验13项通过；E2B为22/34，距28项仍差6项，性能门禁继续保留。

此前 [rc56 交互stdin](../PUBLIC-QUALIFICATION.md#private-evidence)完成有界写入、显式EOF、guest确认与独立观察/取消。完整CI、双架构各41文件离线包、ARM64无网卡QEMU32组、同包x64双SDK v8及实际warm新路径9项通过；真实1MiB输入/超限、背压超时后查询和取消复用验证通过。E2B为19/34，原始其余功能和性能目标继续跟踪。

此前 [rc55 Bash 与 E2B 命令](../PUBLIC-QUALIFICATION.md#private-evidence)完成真实 guest PID、env/cwd、run/list/connect/kill 与缓存 wait、UTF-8 回调、观察超时后重连。双架构离线包各41文件、完整CI、ARM64无网卡QEMU32组、x64池29/API28/session26、双SDK v7及实际warm新路径7项通过。固定E2B增至17/34；交互stdin、OSv流式、其余原功能和性能目标继续跟踪。

rc53 增加 Linux session 后台命令与真实 SSE 输出，包含双架构独立离线包及对应 `osv-offline-release-rc53-linux-{amd64,arm64}` 安装器；完整本地 CI、ARM64 QEMU31组、x64双SDK与warm路径实际验收见[记录及摘要](../PUBLIC-QUALIFICATION.md#private-evidence)。

rc52 的双架构离线包补齐会话重命名和递归删除，ARM64 无网卡 QEMU 30 组、x64 KVM 池/API/session 和双 SDK 实际流程通过；见[验收与包摘要](../PUBLIC-QUALIFICATION.md#private-evidence)。安全配置默认 baseline，完整扫描为显式 extended 增强项；测试签名安装范围及独立性能门禁保留。本批对应的独立安装器为 `dist/osv-offline-release-rc52-linux-amd64` 与 `dist/osv-offline-release-rc52-linux-arm64`，应与 rc52 包及公钥配对使用。

本项目提供按架构分开的签名 tar 包。目标机器安装和运行服务时不需要联网、包管理器、容器、Go/Rust 工具链；必须预先具备匹配架构的 Linux、KVM、cgroup v2、systemd 和足够资源。包内另附零第三方运行依赖的 Python 与 Node/TypeScript 客户端；使用各客户端的机器须分别预装 Python 3.10+ 或 Node.js 20+，不需要 pip/npm 下载。应用服务器本身不依赖 Python 或 Node.js。aarch64 本轮按用户要求以交叉编译及 QEMU 功能验收，不把 QEMU 结果写成 ARM64 KVM 真机结果。域名 TLS 验收等待有效证书。

## 项目内制品与构建

`RELEASE_INFERENCE=1` 显式附带 v7 guest 推理模板，要求同时设置 `RELEASE_GUEST_PROXY=1`、`RELEASE_LINUX_CODE=1`，并以 `RELEASE_LINUX_CODE_ASSETS` 选择含完整 SDK 的封存镜像。附带 OSv 时还须明确设置 `RELEASE_OSV_PYTHON_ASSETS`，选择同样含 SDK 的 x64 镜像。当前资产位于 `assets/runtimes/linux-code/images/inference-v7-r2/linux-{amd64,arm64}` 和 `assets/osv-native/python-3.12-science/candidates/inference-v7-r2`，构建会核对来源、实际文件清单、SDK 摘要、签名和 BOM；旧资产不能只靠开关升级。基础 shell 模板不因此获得推理权限。此项已完成[签名与实际镜像验证](../PUBLIC-QUALIFICATION.md#private-evidence)，完整新包和实际 guest 冷/暖验收继续进行，尚未正式发布。

`RELEASE_LINUX_CODE=1` 附带独立的 `linux-code` v5 模板，适用于 amd64 与 arm64。同时必须设置 `RELEASE_LINUX_CODE_ASSETS`，选择项目内与当前 guest 构建匹配的已封存镜像，例如 `assets/runtimes/linux-code/images/rc74/linux-{amd64,arm64}`；不隐式复用某个旧候选。模板内含 CPython、NumPy/pandas、Node.js、TypeScript、pip/npm 及 ELF 库闭包，目标机无需下载；解释器在 VM 内运行，服务和 MCP 仍为静态程序。代码模板默认 1024 MiB、1 vCPU，Python 在 VM ready 前预热；warm reservation 由管理员按模板、内存和 CPU 规格配置。默认 shell 保留，客户端可从目录显式选择代码模板；管理员也可将代码模板设为默认。原有性能和 64 MiB 门禁保留。构建方式和边界见 [ADR-0075](adr/0075-linux-code-offline-template.md)，当前候选状态见[验证记录](../PUBLIC-QUALIFICATION.md#private-evidence)。

真正随包运行的第三方二进制、内核、rootfs 和 `mkfs.ext4` 库闭包存于 [`assets/offline/`](../assets/offline/README.md)，分别按架构保存，并各有 `SHA256SUMS`。`scripts/build-offline-release.sh` 默认从这些目录读取，检查摘要、内核架构和 rootfs 中的 agent，再交叉编译静态 Go 程序、生成 SBOM 和双层签名。构建环境可联网；断网从源码重建不在本轮需求内。

rc12 将项目内的 [Python 客户端](../sdk/python/README.md)复制到包内 `sdk/python/osv_sandbox_client.py`，其路径、权限、大小和 SHA-256 受 release manifest 签名约束；Linux profile 的 SBOM 同时记录该源码的摘要。包内 `docs/PYTHON-SDK.md` 提供调用方法。客户端凭据、Python 解释器均不在包内；服务本身仍无需 Python 运行。

rc13 增加 [Node.js / TypeScript 客户端](../sdk/node/README.md)的 `sdk/node/index.js`、`index.d.ts` 和 `package.json`，及包内 `docs/NODE-SDK.md`。三个客户端文件受 release manifest 签名约束；Linux SBOM 记录可执行源码和类型声明摘要。Node.js 只在使用该客户端的机器上需要。

rc14 更新双架构 Linux guest rootfs，加入内部多命令 `fc-agent/v2` 协议；对外 session API 仍待完成，原有 `/v2/jobs` 继续使用一次性 `fc-agent/v1`。变更后的运行制品和摘要已保存在项目 `assets/offline/`，见[rc14 验收](../PUBLIC-QUALIFICATION.md#private-evidence)。

rc17 增加对外 Linux session 创建、查询、命令和删除接口；正常删除等待 launcher 回收确认，失联时保留租户配额 15 秒。双架构包、ARM64 QEMU、指定服务器的断网安装与真实 KVM 验收见[rc17 验收](../PUBLIC-QUALIFICATION.md#private-evidence)。

rc19 增加 Linux session 的 `/workspace` 文件读写和双语言客户端方法；单次最多 512 KiB。实际 rootfs 构建所需的两架构静态 BusyBox 已保存在项目 `assets/offline/`，不依赖 `/tmp` 中的构建资产。双架构包、ARM64 无网卡 QEMU 13/13 和 x64 指定服务器从包内 SDK 发起的 KVM 验收见[rc19 验收](../PUBLIC-QUALIFICATION.md#private-evidence)。

rc20 增加有界目录列表、普通文件/目录元数据及普通文件删除；双架构包、ARM64 无网卡 QEMU 15/15 和指定服务器 x64 双语言 KVM 验收见[rc20 验收](../PUBLIC-QUALIFICATION.md#private-evidence)。

rc21 修正包内生产手册；与 rc20 已签名逐文件比较证明运行载荷相同。rc21 在 ARM64 QEMU 15/15，x64 指定服务器验签并隔离安装；x64 KVM 功能沿用同载荷 rc20 证据，见[rc21 定向验收](../PUBLIC-QUALIFICATION.md#private-evidence)。

rc22 增加固定 E2B 2.51.0 的显式双语言适配层；同一 x64 签名包在指定服务器隔离安装后完成 Python/Node 真实 KVM 正反例，固定矩阵为 5/34。ARM64 包在无网卡 QEMU 15/15，通过验签、安装和包内 SDK 检查。两架构与 rc21 的已签名逐文件比较证明运行载荷相同；见[rc22 验收](../PUBLIC-QUALIFICATION.md#private-evidence)。

rc23 让包内生产手册的本地链接全部可解析，并将两份无秘密 JSON 配置示例纳入签名包。与 rc22 的逐文件比较证明运行载荷和 SDK 相同；ARM64 无网卡 QEMU 15/15，x64 指定服务器验签后隔离安装，见[rc23 定向验收](../PUBLIC-QUALIFICATION.md#private-evidence)。

rc25 增加受限目录创建与显式 E2B 适配层的单项/批量写入；双架构包内 SDK 与项目源码一致，ARM64 无网卡 QEMU 16/16，x64 指定服务器隔离安装后双语言真实 KVM 正反例通过。固定矩阵为 8/34。rc24→rc25 逐文件比较显示运行载荷和 SDK 相同，变化为手册修订与签名元数据；见[rc25 验收](../PUBLIC-QUALIFICATION.md#private-evidence)。

rc26 增加受限普通文件/目录完整信息及双语言显式 E2B `files.list/get_info` 默认选项子集。双架构测试签名包已验签，ARM64 无网卡 QEMU 16/16，x64 指定服务器隔离安装后包内双语言 SDK、真实 KVM 子集正反例及宿主隔离检查通过。上游符号链接信息语义尚未实现，固定矩阵仍为 8/34；见[rc26 验收](../PUBLIC-QUALIFICATION.md#private-evidence)。

rc27 补齐符号链接信息、特殊 inode 类型及 `user.e2b.*` 扩展属性；包内双语言 SDK 的元数据写入和信息读回通过指定服务器真实 KVM。ARM64 无网卡 QEMU 在 ext4 测试目录通过 18 项；固定 E2B 矩阵为 10/34，见[rc27 验收](../PUBLIC-QUALIFICATION.md#private-evidence)。

rc28 将 cold job/session 接入 active/物理资源分离的统一账本，增加 `vm_capacity` 管理员预算与 doctor 使用量；清理失败保留资源并封闭准入。双架构测试包、ARM64 无网卡 QEMU 19 项和指定 x64 KVM 基线/共享预算验收通过。预启动池仍待实现，见[rc28 验收](../PUBLIC-QUALIFICATION.md#private-evidence)。

rc29 增加 Linux pristine guest 一次准备协议，7 组真实 x64 KVM 协议用例、同包双语言/API 基线和 ARM64 无网卡 QEMU 21 项通过；准备前不可执行，输入冻结为只读，租期/绑定异常销毁。协议还未接入 pool 调度，启动时延门禁保持未通过，见[rc29 验收](../PUBLIC-QUALIFICATION.md#private-evidence)。

rc31 将 job/session 接入共用 VM owner，验证 staging/停止竞争、唯一 Wait/清理、失败保留与启动对账；并修复 launcher 失联后 GET 会话仍返回缓存 running 的问题。ARM64 QEMU 23 项、指定服务器 SDK/API、双 VM 停止/崩溃/容量及 OSv 诊断回归通过。后台补池和领取仍待实现，见[rc31 验收](../PUBLIC-QUALIFICATION.md#private-evidence)。

rc34 接入 Linux pristine warm pool：按签名规格有界预热、独立物理/active 记账、唯一准备和领取、前台优先、健康与到期淘汰。指定服务器 warm pool 23 项、同包双 SDK/API/隔离及停止/崩溃回归通过，ARM64 无网卡 QEMU 25 项通过；OSv 池和大样本性能仍待完成，见[rc34 验收](../PUBLIC-QUALIFICATION.md#private-evidence)。实际运行资产保存在项目目录，未增加第三方运行依赖。

rc37 将 Linux 与 OSv pristine pool 接入同一资源账本/owner/调度器，修复诊断运行时的独占与崩溃对账，验证 Linux 池 26 项及 OSv 诊断池 23 项；同包 SDK/API/故障回归、双架构离线包和 ARM64 无网卡 QEMU 25 项通过，见[rc37 验收](../PUBLIC-QUALIFICATION.md#private-evidence)。OSv 产品生产准入和大样本性能门禁仍未通过，实际运行资产继续存于项目目录。

rc38 增加宿主七阶段与 pristine cold 首次就绪计时；双架构离线包、ARM64 QEMU 25 项、指定服务器 Linux 池 29 项/OSv 诊断池 25 项及同包 SDK/API/故障回归通过，见[rc38 验收](../PUBLIC-QUALIFICATION.md#private-evidence)。每后端 128 次阶段定位用于诊断，未替代性能门禁；无新增第三方运行依赖。

rc40 采用一次原子 prepare 确认 warm 领取就绪，保留宿主身份复核和持久化，补充死亡实例与发送前错误边界；完整 CI、双架构包、ARM64 无网卡 QEMU 27 项及指定服务器 Linux/OSv 池、SDK/API/故障回归通过，见[rc40 验收](../PUBLIC-QUALIFICATION.md#private-evidence)。13 次跟踪独立确认各一次前台控制连接；每后端 128 次无跟踪任务全成功，完整性能门禁仍未通过。rc39 真机失败和 rc40 跟踪原解析失败保留，补充审计通过；运行依赖仍全部在项目目录。

rc42修订实时cgroup归属，接受经内核标志证明的合法KVM worker并继续拒绝额外用户进程；完整CI、双架构离线包、ARM64无网卡QEMU28项及指定服务器全套功能回归通过，见[rc42验收](../PUBLIC-QUALIFICATION.md#private-evidence)。十一份夹具与观察过的VM/worker代次退役已核对，rc41失败保留，完整性能门禁未通过；实际运行依赖仍在项目目录。

构建侧需从可信渠道提供两套不同用途的 Ed25519 私钥：release PEM 私钥和现有 artifact manifest 的 base64 私钥。私钥、mTLS 证书、租户策略不进入包。例子：

```bash
RELEASE_ARCH=amd64 \
RELEASE_VERSION=2026.10.29-rc9 \
RELEASE_VALID_UNTIL=2027-04-01T00:00:00Z \
RELEASE_OUTPUT=dist/osv-sandbox-2026.10.29-rc9-linux-amd64.tar \
RELEASE_PRIVATE_KEY=/secure/release.private.pem \
ARTIFACT_PRIVATE_KEY=/secure/artifact.private \
RELEASE_SECURITY_SNAPSHOT=/project/evidence/snapshot \
RELEASE_SECURITY_SNAPSHOT_SHA256='替换为审核流水线固定的64位SHA256' \
bash scripts/build-offline-release.sh
```

把 `RELEASE_ARCH` 换成 `arm64` 即可构建另一架构。正式构建要求 Git 工作树干净，并强制通过 `scripts/check-startup-gates.py --require-target`；当前按[ADR0128](adr/0128-warm-p99-fifteen-release.md)的5/9/15ms及具体候选身份验收；缺当前候选的证据仍拒绝。按用户 2026-11-03 调整，安全配置默认 `RELEASE_SECURITY_PROFILE=baseline`，保留基本隔离、认证、配额、路径和签名要求；包内 `docs/security-profile.json` 记录实际配置。全面扫描属于增强项，显式设置 `RELEASE_SECURITY_PROFILE=extended` 时才要求[安全快照离线重放](SECURITY-EVIDENCE.zh-CN.md)。增强模式从同一实际运行载荷的测试候选采集安全快照；计划独立于 SBOM UUID/时间，制品或组件字节变化则拒绝复用。测试版本须显式设置 `RELEASE_ALLOW_DIRTY_TEST=1`，无论工作树是否干净都要求输出以 `.test-signed.tar` 结尾，修订字段附加 `-dirty-test` 以触发受限安装规则，不能作为正式来源/验收证明。发布者应在隔离环境保管私钥；不要用仓库内或测试用私钥签正式版本。`scripts/build-offline-mkfs.sh` 可从 Debian 12 包构建对应架构的 `mkfs.ext4` 和七个运行库，`scripts/build-firecracker-linux-rootfs.sh` 可构建 guest rootfs。项目内已保存本轮生成的运行制品。

## 目标机离线安装

将对应架构的 tar、**独立取得并固定摘要的静态** `osv-offline-release` 验证器、release 公钥传到目标机。发布包内同名验证器和同目录公钥不能自行证明可信；正式环境须通过可信渠道固定它们的摘要/公钥。先用 `verify` 校验签名、有效期、目标架构、每个文件摘要和归档结构，再安装：

```bash
./osv-offline-release-linux-amd64 verify \
  -archive osv-sandbox-2026.10.29-rc9-linux-amd64.tar \
  -public-key release.public.pem
sudo ./osv-offline-release-linux-amd64 install \
  -archive osv-sandbox-2026.10.29-rc9-linux-amd64.tar \
  -public-key release.public.pem \
  -root /opt/osv-sandbox/releases
```

ARM64 上使用 arm64 验证器和包。安装器先完整验证，随后在同一文件系统的临时目录写入并 `fsync`，最后原子提交为 `/opt/osv-sandbox/releases/<版本>-linux-<架构>`；已存在的版本不会被覆盖。它不会自动启用或启动生产服务。

准备运行时，管理员先停止两个生产 unit、完成在途任务和审计收尾，保留签名 tar 与带外公钥，再运行：

```bash
sudo ./osv-offline-release-linux-amd64 switch \
  -archive osv-sandbox-2026.10.29-rc9-linux-amd64.tar \
  -public-key release.public.pem \
  -root /opt/osv-sandbox
```

`switch` 使用默认的 `/var/lib/osv-sandbox/run` 与 `/sys/fs/cgroup/osv-sandbox` 检查 launcher 锁及 `job-*` 残留，确认生产 API/launcher 均 inactive，重新校验签名包和已安装的全部文件，再原子更新 `current` 相对链接。缺签名 tar、已安装文件变化或服务/任务仍在运行时拒绝。回滚时对保留的**旧版签名 tar**运行同一命令；不删除任一版本目录。含 `-dirty-test` 的验证候选默认拒绝切换，只有 `osv-offline-validation-*` 隔离根配合 `-allow-test-candidate` 才可演练。命令不自动启动服务。

包内 `config/config.production.json.template` 是无秘密的有效 JSON，路径以 `/opt/osv-sandbox/current` 为基准；复制到 `/etc/osv-sandbox/config.production.json`。包内两个 `systemd/` unit 复制到 `/etc/systemd/system/`。宿主用 `systemd-sysusers` 建立独立的 `osv-sandbox` API 用户，配置 `/etc/osv-sandbox/launcher.env` 中的 `SANDBOX_API_UID` 和 `SANDBOX_API_GID`，并从可信渠道提供 artifact 公钥、租户策略及有效 mTLS 文件。`/etc/osv-sandbox` 须允许 API 用户读取配置和所需密钥；launcher/root 单独管理 `/var/lib/osv-sandbox/run` 与 `/var/log/osv-sandbox`。完成 `systemctl daemon-reload`、生产 doctor 和审计检查后才启动服务。正式激活/回滚必须继续满足证书、宿主与发布门禁。

目标机不会调用宿主 `mkfs.ext4`：配置通过包内 glibc loader 和库目录运行包内 `mkfs.ext4`。本轮 x64 本地和 ARM64 QEMU 均实际格式化了 ext4。宿主系统本身的 KVM、systemd、cgroup 和用户管理能力属于显式基线，不包含在发布包中。

## 当前验收状态

| 项目 | 状态 |
|---|---|
| x64、ARM64 静态 Go 编译与 ELF 架构/依赖闭包 | rc42 测试候选构建与安装检查通过；运行依赖保存在项目 `assets/offline/` |
| 双架构签名归档校验、原子版本安装和负向安全测试 | 已通过本地测试 |
| ARM64 QEMU 中真实包签名验证、安装、包内 SDK 摘要、mkfs 格式化及 agent 协议/边界功能 | rc42 在 `-nic none` 下 28/28；ARM64 KVM 按用户范围免验 |
| x64 本地真实包安装、Firecracker/jailer 启动版本检查、包内 mkfs 格式化 | 先前候选已通过；rc42 在指定服务器复核真包摘要并隔离安装 |
| x64 指定服务器离线包隔离安装及 API→launcher→VM→guest 验收 | rc42 已验签隔离安装；双语言从已安装包读取 SDK，KVM 文件读写/列表/元数据/删除/目录创建、E2B 显式适配层十项兼容正反例测试通过。Linux warm pool 专项 29/29；同版 OSv 诊断池 25/25及冷路径33/33，job API 28/28、session API 26/26；宿主隔离检查观察 14 个受限 VM，四份夹具零残留；swap 使 production doctor 未就绪 |
| x64 离线版本切换与回滚 | rc9 包内静态工具在无路由隔离目录 10/10 通过；正式生产流量切换仍待发布门禁 |
| ARM64 Firecracker/KVM 真机验收 | 用户批准本轮不执行 |
| 域名 TLS 验收 | 证书已过期，等待有效证书 |

当前 `dist/` 的 rc42 包使用临时测试签名密钥，仅作候选验证，不应作为正式生产发行。正式发行需使用受控私钥重签并保留验收结果；签名有效期由各包清单决定，过期后验签将拒绝。

详细命令、候选摘要与原始证据见[rc42实时归属与双架构验收](../PUBLIC-QUALIFICATION.md#private-evidence)、[rc31 VM owner 与双架构验收](../PUBLIC-QUALIFICATION.md#private-evidence)、[rc29 准备协议与双架构验收](../PUBLIC-QUALIFICATION.md#private-evidence)、[rc28 双架构与资源账本验收](../PUBLIC-QUALIFICATION.md#private-evidence)、[rc25 双架构与写入验收](../PUBLIC-QUALIFICATION.md#private-evidence)、[rc23 包内手册验收](../PUBLIC-QUALIFICATION.md#private-evidence)、[rc22 E2B 适配层验收](../PUBLIC-QUALIFICATION.md#private-evidence)、[rc20 双语言文件 KVM](../PUBLIC-QUALIFICATION.md#private-evidence)、[rc17 公开 session API](../PUBLIC-QUALIFICATION.md#private-evidence)、[rc11 崩溃恢复](../PUBLIC-QUALIFICATION.md#private-evidence)和[切换/回滚验收](../PUBLIC-QUALIFICATION.md#private-evidence)。


## 可选的x64 OSv科学模板

`RELEASE_OSV_PYTHON=1`在Linux主包中附带项目内锁定的OSv Python科学模板及其kernel/rootfs/modules、独立签名manifest/SBOM、来源与许可证文件。主SBOM用摘要引用子BOM；外层发布签名覆盖全部载荷。构建默认从`assets/osv-native/python-3.12-science/candidates/clock-sleep-r1`读取真实依赖，`RELEASE_OSV_PYTHON_ASSETS`可指定项目内相同类型的锁定资产。该候选保留rc51科学库/ROFS，内核补齐[单调时钟等待](adr/0061-osv-monotonic-clock-sleep.md)。目标机安装和运行无需下载或重建这些依赖。当前科学模板仅有amd64资产，arm64构建显式拒绝该选项。

包内config模板自动包含科学模板描述，`templates/python-science/template.json`给出相同配置片段。默认Linux入口不变；管理员按[生产手册](PRODUCTION.zh-CN.md)配置身份、路径和租户入口后启动。[rc68](../PUBLIC-QUALIFICATION.md#private-evidence)已完成双架构包、ARM QEMU、x64同包混合cold/warm与原科学20项功能验收；包仍为测试签名，正式签名、生产基线和原性能/内存门槛继续跟踪。验收后的结论记录在仓库中，已冻结包内手册不因文档更新而重签。

## 当前候选的正式发布门禁

按 [ADR-0123](adr/0123-current-candidate-release-gate.md)，正式构建必须同时指定已通过四路线启动门禁的 x64 候选，以及目标架构已验收候选；两者须属于同一源码、Go 版本和候选版本/提交。ARM 仍独立做编译与无网卡 QEMU 功能验收，未要求 ARM KVM。示例环境变量使用实际绝对路径：

```bash
export RELEASE_STARTUP_CANDIDATE='/项目路径/dist/已验收-amd64.test-signed.tar'
export RELEASE_VALIDATED_CANDIDATE='/项目路径/dist/已验收-目标架构.test-signed.tar'
export RELEASE_CANDIDATE_PUBLIC_KEY='/项目路径/密钥目录/候选-release.public.pem'
```

候选公钥由操作者带外提供；不是从归档中取得。目标为 amd64 时，两个候选必须是同一归档字节。已有旧包若没有版本化构建身份，不能补写元数据后直接复用验收；需按当前流程准备并验收新候选。rc92原数据按新15ms阈值达标，但旧包缺少现行版本化构建身份，因此仍不能直接指定该旧包完成正式发布。

builder 为新的测试候选固定 `SOURCE_DATE_EPOCH`，正式重建自动沿用目标候选的原值。相同源码/Go 工具链、artifact 签名密钥、功能开关和有效期参数生成相同 SBOM、清单及签名；错误或不同的显式 epoch 会拒绝。外层发布签名密钥与版本号可以变更，但实际载荷的所有文件、权限、大小和 SHA256 都必须与目标候选完全一致，包括签名、SDK、文档和配置。固定时间不续期已过期 artifact。

前置检查会验签候选、绑定指定启动证据并核对公共源码身份；打包前再次核对候选与全部新 stage 文件。packer 在写任何归档头之前比较参考载荷清单，并保留写出时逐文件哈希复核；变化或任何失败都会删除未完成的归档。该检查不替代完整 CI、两架构功能、一般安全和其余发布验收，也不把小样本诊断作为正式千次结果。
