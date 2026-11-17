# ADR-0075：双架构 Linux 代码模板离线发布

状态：Accepted；日期：2026-11-06；关联 ADR-0067～0074、REL-04、API-02/03、CAP-01、LIFE-04。

代码 worker、宿主入口、双 SDK 和 MCP 已分别完成本地验证。下一步把它们接入实际可安装的发布载荷，并用同一候选验收。新增 `linux-code` 目录模板，默认 shell 和现有 OSv 科学模板保留独立镜像与签名。amd64、arm64 均使用项目内已封存的 glibc 解释器闭包；Rust agent 仍为静态 musl 加 mimalloc。离线安装和运行不需要宿主 Python、Node、容器或包管理器。

镜像构建从当前源码绑定的基础 guest 镜像提取骨架，叠加封存运行时、两份内核脚本、运行时 inventory 和固定版本 profile，生成只读 ext4。输出及真实依赖位于项目 assets，临时提取树仅用于构建和验证，完成后删除。构建和发布阶段都提取实际 ext4，再比较完整文件/模式/链接清单及运行时闭包；不能只校验外部 inventory。运行时原有 Debian CA 文件覆盖骨架的 Mozilla CA，作为明确记录的唯一允许文件覆盖；代码模板 SBOM 按实际 Debian 运行时记录 CA，默认 shell 继续使用原有 CA。

代码模板使用 v5 manifest，绑定架构、CPython/Node/TypeScript 固定版本、最小 CPU 特性、运行时 inventory 和两份脚本摘要，默认预热 Python。child CycloneDX BOM 包含解释器来源、Debian 运行包版本、许可证及完整镜像文件清单；主 BOM 以摘要引用该独立模板 BOM。外层发布签名覆盖镜像、manifest、BOM、来源、清单与配置。普通隔离、身份、容量、路径和签名检查保留；不在本阶段追加增强扫描。

模板初始默认 1024 MiB、1 vCPU；这是待实际验收的功能配置，不是 64 MiB 达标声明。模板不自动申请 warm reservation：管理员可以给它独立配置与资源形状相符的 warm_profiles，沿用项目原有跨模板总账、单租用、失败销毁及补池管理；实际候选验证需覆盖代码 cold/warm 与清理。不能把原 shell 的 warm VM 转作代码 VM，也不能凭启动速度注释关闭性能门禁。

实施前自评审：运行时库存约 367 MiB，应根据实际文件量计算 ext4 大小并留元数据空间；不能沿用 64 MiB 根盘。不能把 glibc 解释器标为 mimalloc；不能由宿主绝对软链接泄漏文件；基础文件只允许明确的 CA 覆盖。发布配置须收集所有模板而非只写科学模板；父 BOM 只接受已有 OSv v2 或代码 Linux v5，并验证 profile。旧默认路径、安装和回滚流程需回归。QEMU 功能证据、实际 vsock/KVM 证据及性能证据分别记录。

门禁：双架构当前源码绑定的 agent；镜像实际文件及 ELF 闭包核验；BOM schema 和签名/配置验证；候选冻结后统一 CI；x64 指定服务器断网同包 SDK/MCP 与 cold/warm；arm64 离线包 QEMU 编译及功能验收。用户已豁免 arm64 KVM，其他功能及原 40 项需求、性能目标和正式发布门禁不因本 ADR 自动完成。

2026-11-06 验收：见[rc74同包验证](../../PUBLIC-QUALIFICATION.md#private-evidence)。双架构实际guest70组、447输入完整CI、ARM离线包QEMU48组及指定服务器五夹具全部通过；本决定已实施。正式发布继续遵循功能、性能和一般安全基线条件，未据此关闭原完整目标。
