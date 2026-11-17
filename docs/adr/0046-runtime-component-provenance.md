# ADR-0046：科学运行时的组件来源、许可证与完整 SBOM

状态：Accepted；日期：2026-11-02；需求 OSV-02、REL-04、QA-04/05。

## 问题

rc50 科学模板已可运行，但外层 SBOM 主要绑定 kernel、镜像和模块；镜像内的 Python 包、15 个系统共享库和 vendored 原生库没有完整的来源关系。stdlib/轮子的许可证已保留，复制进镜像的系统共享库却尚无对应的包版权文件。字节码实验还没有接入常规构建，清单的初始缓存裁剪规则也需与最终加入的缓存区分。

## 设计

1. 从固定 source lock、已验字节的 wheel/CPython 源、实际构建容器的 dpkg/ldconfig 和运行时文件摘要采集来源。不以文件名猜系统包版本；必须核对安装库与被复制库的 SHA256、构建 image ID 和原 build-provenance 的包版本。未知的 bundled 库版本明确标记，不能当作 CVE 零命中。
2. 保留完整的 CPython/轮子许可证；为系统库加入实际包 copyright 及其引用的 common-licenses 文本，逐项记录摘要。对 CPython 自带 expat、mpdecimal 和 wheel vendored 库记录可核实版本/来源及边界；不把 ELF DT_NEEDED 当作所有静态组件的证明。
3. 生成组件、文件归属、源归属、原生依赖边的机器可读记录；每个实际文件须有归属或显式的未解析原因。字节码归属与对应源码相同，生成和核验显式 optimize=0/checked-hash，不删断言或文档。常规构建串联这些步骤后再封存清单。
4. 新清单版本区分 initial_cleanup_excluded_directories 与 final_excluded_directories；旧版清单继续仅按原契约验字节。最终 pyc、来源记录、许可证均纳入完整文件清单和签名 ROFS，SBOM 本身放在镜像外以避免自引用。
5. 依照 [CycloneDX 1.5 schema](https://github.com/CycloneDX/specification/blob/1.5/schema/bom-1.5.schema.json)，在既有 osv-rootfs 组件下嵌套内部包/文件，使用唯一引用和明确依赖。保持运行时现有顶层组件白名单、镜像摘要与完整 SBOM 签名校验，不放宽为任意顶层条目。官方 schema 及引用依赖固定在项目中，离线验证时禁止远端 schema 获取。
6. 漏洞扫描是独立结果，须记录数据库时间、包版本、发行版修订、覆盖和未解析项；不能用完整文件清单、无扫描结果或不支持的生态系统来关闭 QA-04。正式发布不得将 partial coverage 宣称完整。
7. 真实依赖、库、许可证、schema 与固定来源资料存入项目目录；目标机离线安装运行不增加 Python/pip/包管理器依赖。Linux ARM64 原离线包边界不变，不宣称新增 ARM64 OSv 科学模板。
8. 组件导出必须独立读取最终 raw/ROFS，逐文件核对源树清单，并覆盖 image skeleton 加入的基础文件；不可仅把某个源目录称作完整镜像。只读解析器检查分区、计数、目录循环、路径和数据范围，不解包到宿主路径。Python 业务镜像通过显式构建选项不带入仅供 native 协议验证的 task-probe，native 诊断镜像保留原行为。

## 实施与验证

先做[自评审](../../PUBLIC-QUALIFICATION.md#private-evidence)，再实施。负测试覆盖错库字节、错包版本、漏文件、重复归属、越界/符号链接、无许可证、错误字节码语义与错误 SBOM 归属。用官方 schema 作离线结构验证，检查依赖引用和镜像/清单绑定。将字节码、来源、许可证和 SBOM 合并为一个镜像候选，冻结后一次 CI 及受影响的完整 Python/缓存/大读取和 64MiB 门禁；不重复无改动的 native 或 Linux/QEMU 矩阵。

[rc51 验证](../../PUBLIC-QUALIFICATION.md#private-evidence) 已覆盖实际镜像 2,775 个文件/链接、30 个运行时描述和离线官方 schema，一次完整 CI 及受影响 KVM 通过功能/缓存/读取检查。采用上述来源与覆盖策略；libgfortran/libquadmath 确切源码版本、额外静态来源、漏洞扫描和 64MiB 仍明确未完成，不能据此关闭 QA-04 或生产门禁。
