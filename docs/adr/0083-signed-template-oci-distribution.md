# ADR-0083：签名模板的 OCI 分发与离线导入

状态：接受；指定机导入模板cold/warm待验收。关联 OPS-02、SEC-05、REL-04、QA-01/03。K8s 按 ADR-0076 暂缓。

2026-11-09：[本地 layout 首阶段](../../PUBLIC-QUALIFICATION.md#private-evidence)已完成实现、110 项 native race、ARM 静态编译/30 项无网卡 QEMU 及五套真实签名模板 CLI 往返和官方 schema 验证。registry、发行包集成与同候选 KVM 仍待完成，需求保持开放。

## 问题

现有完整离线发行包与 root launcher 已验证模板签名、有效期、镜像和 SBOM，但还不能通过标准 OCI registry 单独分发签名模板。离线安装要求保留；不能让 registry、tag、OCI descriptor 或随包公钥代替原有 Ed25519 信任链，也不能在拉取时直接改动运行中模板。

## 决定

采用 [OCI Image 1.1.0 的 artifact manifest](https://github.com/opencontainers/image-spec/blob/v1.1.0/manifest.md)及[OCI Distribution 1.1.0](https://github.com/opencontainers/distribution-spec/blob/v1.1.0/spec.md)。提供零运行时第三方依赖的 Go 管理工具与内部库，支持 export/import 本地 OCI layout，以及 registry push/pull。完整发行包继续作为独立离线安装通路。

模板 artifact 使用 `application/vnd.osv-sandbox.template.v1`，OCI manifest mediaType 为标准 `application/vnd.oci.image.manifest.v1+json`。自定义 config 只含版本、架构、backend 和原签名 manifest 摘要；五个 layer 分别承载原签名 manifest、原签名、SBOM、kernel、rootfs 的原始字节。layer role、mediaType、title 必须唯一且与签名内容匹配，不执行 tar 解包、宿主钩子或随包命令。许可证/构建来源仍由原发行资产保留，后续分发扩展不得冒充受现有签名覆盖。

- digest 为小写 SHA256，大小同时核对。import/pull 要求外部明确传入 OCI manifest digest、期望架构和 backend、带外公钥及受信 Firecracker/jailer；OSv 还要求显式模块 allowlist。不从传输包选择信任锚，不静默回退 backend/tag/架构。
- 提取原有签名元数据核验为共用函数，保留原生产验签语义。先核对签名、有效期、profile、架构和 descriptor 与签名的大小/摘要关系，再复制或下载大镜像；最终复用完整生产验证器核对实际镜像、SBOM 与受信宿主二进制。旧 v1/v6 不含架构声明时，由签名的 Firecracker/jailer 摘要和实际 ELF 架构共同约束。
- metadata 上限 1 MiB，签名/公钥各 4 KiB，config 16 KiB，SBOM 64 MiB，kernel 512 MiB，rootfs 16 GiB；五个 blob 的总量有界。传输流核对声明大小并多读一字节拒绝超长，拒绝外部 URLs、内联 data、路径穿越、重复 role、路径冲突与符号链接。大文件流式处理，内存不随镜像大小增长。
- 在目标同一父目录创建私有 staging。所有校验成功后同步文件/目录，使用目标专用非阻塞锁、检查目标不存在并原子发布，随后同步父目录；失败和取消清理自有 staging。已有目标保持不变。管理目标的父目录属于可信管理员；不把此 CLI 当作多租户任意文件写接口。导入不切换服务配置、默认模板或现有 VM。
- registry 默认 HTTPS、系统/显式 CA 校验，可选 mTLS 和从权限受限文件读取凭据。凭据不进入 URL、日志或 OCI 内容。按 digest 拉取；发布可给 tag，但回显不可变 digest。按标准 POST→PUT 上传 blob、最后提交 manifest；使用 HEAD 去重。跳转/上传 Location 保持显式受信 origin，禁止隐式携带凭据到其他域名。不同 origin 的对象存储需要后续显式策略，不自动放宽。网络错误保留可识别结果，不把观察断连当作远端发布成功。registry 整体互操作在独立实现上验证。

## 实施与验收顺序

1. 设计和自评审后实现签名元数据复用、本地 OCI layout 导出/导入及 CLI；本地负向/并发/取消、真实离线候选的两架构五模板字节核对及 ARM 编译/QEMU。此步不能关闭 OPS-02。
2. 接入 registry push/pull、TLS/认证、取消/故障、独立 registry 互操作和 OCI 官方 schema 离线验证。验收真实模板的 registry→离线 layout→导入→生产验证器链路。
3. 纳入双架构完整发行包、CI 和对应文档；新候选的指定服务器真实模板 cold/warm、既有模板/SDK/推理回归按影响执行。原性能、64 MiB、一般安全与完整交付门禁不变。

纯工具/传输测试不高频重跑 guest 构建与全部 KVM；共用生产验签函数改动要运行 artifact/profile/catalog 定向 race 回归，最终候选再集中完整 CI、ARM 包与受影响 KVM。原始失败和输入绑定保留，结束的重复 OCI layout/展开根目录按引用检查后回收。

## 限制

OCI digest 只约束传输内容，原签名与有效期仍决定准入；不承诺通用容器运行、不实现 K8s、不声称完成原性能或正式发布。状态随实际证据更新，设计存在不等于交付。

## Registry 实施约束（2026-11-09，先于传输代码）

传输命令为 push/pull；二者都显式绑定 repository、OCI digest 和原模板验证参数。push 的可选 reference 可以是 tag 或相同 digest，pull 只接受 digest。repository/tag 按 Distribution 1.1.0 的语法和长度验证。成功 push 必须在 manifest 提交后按 digest 读回原始 manifest；提交后断连或无法读回明确返回“发布结果未确认”与已知 digest，不当作成功。

凭据文件为权限 0600 的有界 JSON，只允许 Basic username/password 或预先获得的 Bearer token 二选一；不隐式发现或访问第三方 token realm。该轮不实现 OAuth token broker。TLS 使用系统/显式 CA，可选 mTLS，不能关闭证书校验；显式明文开关仅供 loopback IP 测试。请求/错误不记录凭据、远端响应 body 或含 upload state 的 URL。只有同 origin 的 GET/HEAD 跳转允许跟随；upload Location 也必须同 origin，保留原 query 字节后追加 digest，拒绝 URL userinfo/fragment。跨 origin 存储跳转返回明确拒绝，不能自动扩大信任范围。

push 在联网前核对所有 blob 的大小/摘要并复用完整生产验签，再 HEAD 去重、POST→PUT 单 blob 流式上传、最后提交 manifest。上传时再次计算字节摘要；已完成的 blob 可在人工重试时复用，不自动重放未知结果的请求。本轮不实现单 blob Range/PATCH 断点续传。源布局属于可信管理员控制的本地存储，不能允许其他不受信用户在推送时改写。验证 view 优先使用同文件系统的私有硬链接，不复制镜像；只读/跨文件系统布局可显式选工作目录，必要时复制并在结束时回收。

pull 在目标同父目录私有 staging 中先获取有界 OCI manifest/config/原签名元数据，完成原签名/架构/descriptor 交叉校验后才获取 SBOM/kernel/rootfs；最终完整验签后原子发布 OCI layout。每个响应检查长度、摘要、可选 Docker-Content-Digest，禁止隐式内容解压；取消/失败不发布半包，不切换活动模板。TLS 握手、响应头、请求总期限和并发连接数有界。原本地布局负例继续回归，网络增加真实 HTTP/TLS、Basic/Bearer/mTLS、重定向泄露、慢响应/取消、未确认提交及独立 registry 互操作。

2026-11-09：[registry 阶段](../../PUBLIC-QUALIFICATION.md#private-evidence)已完成 65 项 native race/同集合 ARM QEMU，以及独立 Distribution 3.1.2 的双架构五模板实际 TLS/mTLS/Basic 流程。下一阶段将静态 CLI 和独立可读手册纳入两架构完整包，root Linux BOM 记录实际 CLI 字节摘要；不把独立 registry 测试程序、凭据或私钥打包。新文件只增加到签名载荷 allowlist，不加入旧格式的全局 required 集合，保留已有签名包的验证/回滚能力。新包仍需要匹配的带外可信 bootstrap，不能让旧 verifier 静默接受未知载荷。ARM 完整包需补充已安装 CLI 的实际离线模板流程，显式 workspace 与 imported-template 真机验收继续跟踪。

## 导入模板实机夹具（先于夹具实现）

rc78完整CI、双架构包及ARM51组已通过，见[发行记录](../../PUBLIC-QUALIFICATION.md#private-evidence)。下一步只扩展验收工具，不改变两个签名包。新catalog夹具使用**已安装CLI**顺序export/import原Linux和OSv模板，逐文件核对五份原字节和外部信任锚，将生产配置的artifact_root指向导入目录，保留原模板ID、签名摘要、策略、容量和cold/warm参数。OSv允许模块来自既有可信配置，不从OCI内容重新授信。

为证明生产服务确实使用导入产物，两个服务通过InaccessiblePaths屏蔽原包的模板目录，原始发行包在服务之外仍可逐项校验。原catalog E2E额外核对两个进程的实际挂载视图、导入签名及真实VM的kernel/rootfs摘要与只读drive；继承原Linux/OSv混合、双租户、SDK/MCP、配额/超时/清理断言。真实KVM通过前不关闭OPS-02。

export的临时layout放在夹具私有目录，每模板import和字节核对后，归档小元数据并检查宿主引用再回收layout；活跃导入目录保留到服务结束。失败保留诊断，不覆盖已有目录。先做配置/路径负例、实际rc78 CLI与namespace屏蔽的本地功能验证；指定机恢复认证后在固定ID的独立验收任务中执行cold/warm和原回归。只修改夹具时不重建未变应用，也不重复原完整CI/ARM/性能矩阵。

本阶段已通过[七项定向、rc78实际两模板CLI与非root namespace](../../PUBLIC-QUALIFICATION.md#private-evidence)；当前传输包精确重建和四份计划本地验证通过。保留原13套，新增OCI cold/warm两套；指定机尚未执行，不关闭OPS-02。
