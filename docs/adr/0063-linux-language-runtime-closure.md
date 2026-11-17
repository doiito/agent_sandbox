# ADR-0063：Linux代码运行时的双架构离线闭包

状态：Accepted（双架构构建与独立运行时功能通过，正式代码模板/API及发布包验收待完成）；日期：2026-11-04；进展：2026-11-05；需求OSV-02、CAP-01、API-02、REL-04、BUILD-01、QA-02。

## 目标

继续交付原R3/R6/G4的真实代码解释器。现有Linux模板提供Bash，OSv科学模板提供一次性Python；新增Linux Python/Node运行时支持持久代码上下文，同时保留两条现有路径。原多语言矩阵、64MiB和性能要求保持，不以新增Linux模板代替OSv验收。

## 资产与构建

Python固定3.12.16，复用项目已验证的CPython源归档与摘要；常用科学依赖继续锁NumPy2.5.4、pandas3.1.0及其直接运行依赖。Node固定官方22.23.4，x64和arm64分别使用官方Linux资产及固定版本SHASUMS256。TypeScript沿用项目固定5.9.3。版本和来源写入新资产锁，不能跟随latest漂移。下载属于构建准备，目标机安装/运行不联网。

新增项目内构建目录和最终资产目录，不修改rc70及OSv既有资产。Python在固定构建镜像内编译，arm64采用交叉编译并记录构建Python、编译器、配置参数和包版本。最终包含pip及预装科学依赖，Node包含npm；来源归档、wheel、许可证、运行库及清单均留项目。目标环境不需要Docker、pip/npm安装或编译器。

Rust agent继续使用既有静态musl+mimalloc构建。Python/Node在独立进程中使用自身C运行库和分配器，不跨分配器传递所有权；不通过全局LD_PRELOAD替换分配器，也不以使用mimalloc直接宣称端到端收益。

动态运行时在guest镜像内携带自身loader与递归DT_NEEDED闭包。x64和arm64分别校验ELF架构、解释器路径、依赖解析、符号版本和实际运行版本。解析基于目标构建环境与目标架构库，不能误用宿主库满足arm64依赖。复制后对每个实际文件/链接封存SHA及来源，拒绝逃逸链接和不完整闭包。

新增不可变代码模板，按真实模板发布语言/版本能力；现有最小Linux模板及OSv模板不自动取得新能力。默认小镜像和旧签名行为保留。代码模板需要更大的镜像空间，构建参数显式、有界；不将镜像大小当作运行内存，也不改变64MiB尚未通过的结论。

## 验证与门禁

先定向验证下载摘要、目标ELF和缺库失败，再构建资产、执行实际版本/标准库/NumPy/pandas/Node/npm/TypeScript及普通文件/子进程任务。arm64在现有无NIC QEMU内实际执行；原ARM KVM免验继续生效。x64使用指定服务器的新隔离夹具验证最终安装包、cold/warm实际模板及零残留。

运行时与后续[代码上下文](0064-persistent-code-contexts.md)共同冻结后执行一次完整CI与受影响矩阵。构建中不高频重跑已验收rc70，错误修复按影响范围重验。构建完成、设计、单元测试、宿主运行均不能代替最终guest与同候选E2E。实施前复核见[记录](../../PUBLIC-QUALIFICATION.md#private-evidence)。

双架构实际结果及初始失败见[运行时与解释器原型验证](../../PUBLIC-QUALIFICATION.md#private-evidence)：x64普通用户独立根目录和aarch64无NIC QEMU均执行Python/科学库/Node/npm/TypeScript，实际库、loader、证书及版本均来自项目封存目录。ARM验证使用1536MiB，不能登记为64MiB或ARM KVM通过。rc70当前离线包仍是已验收发布基线，新运行时尚未随新候选安装。
