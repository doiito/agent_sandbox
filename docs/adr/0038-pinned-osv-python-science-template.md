# ADR-0038：固定依赖闭包的 OSv Python 科学栈模板

状态：Proposed（先验证真实 OSv 兼容性）；日期：2026-10-31；需求 OSV-02、CAP-01、LIFE-04、REL-04、QA-04。继承 ADR-0009/0034，不关闭其他语言或生产门禁。

## 问题与依据

原方案 §6.3.4 要求 Python 3.12 与 numpy/pandas。现有 OSv 模板只有原生诊断模块，不能证明该能力。固定上游的 python3x 配方复制构建宿主的 Python，并假定旧版 libpython 的 m 后缀；直接使用会把构建机状态带进发布。

选用 [CPython 3.12.16 安全修订](https://www.python.org/downloads/release/python-31216/)、NumPy 2.5.4、[pandas 3.1.0](https://pandas.pydata.org/docs/whatsnew/v3.1.0.html)，以及它们在 Python 3.12/Linux 上的必要依赖 python-dateutil 2.9.0.post0、six 1.17.0。版本元数据和 wheel 摘要来自各项目的 PyPI JSON 接口；实际源码还须匹配 Python 官方 SHA-256。选版本不等于完成 CVE 扫描或 OSv 兼容验收。

## 决策

1. 增加独立的 python-3.12-science 模板目录、固定 URL/版本/SHA-256 锁文件。下载只在显式准备阶段进行，已存在文件必须验证，不静默换版本。真正需要的源包、wheel、运行库、解释器、清单和镜像都存放在项目 assets 下；构建中间件在 build 下。安装运行不使用 pip、网络或宿主 Python。
2. 使用项目已有 OSv 构建镜像的独立派生镜像构建共享 CPython；记录实际镜像 ID、编译参数与开发库版本。OSv 上游提交、vsock agent、无网卡、只读 ROFS 和一次任务后销毁保持原契约。新模板输出到独立资产目录，不能覆盖 rc42 的基础模板和离线包。
3. `/python3.12.so` 是唯一业务入口，通过现有 OSJ1 argv/env/stdin 通道启动真实解释器。解释器固定 home，忽略 PYTHON* 路径覆盖和用户 site，不写字节码；保留程序读取显式环境变量的能力。OpenBLAS/OMP 线程固定为 1，符合一核模板的资源预算。无 shell 拼接、宿主执行或 Linux 后端替代。
4. stdlib、扩展模块、wheel 和传递共享库构成闭包。逐个 ELF 读取 DT_NEEDED，区分 OSv 本身提供的 libc 等 ABI 和需要随镜像带入的库；未解析依赖失败。记录来源、版本、逐文件摘要和裁剪规则，保留许可证。裁剪仅排除测试/缓存/构建头文件，不删减验收任务以迁就内存目标。内置清单连同完整 rootfs 受镜像摘要绑定；签名模板的模块与 SBOM 继续按 ADR-0009 验证。完整运行库级 SBOM 扩展须单独实现和验证，不能把仅绑定 rootfs 当成已经完成 QA-04。
5. 使用独立测试签名模板与已有池管理器验证。池身份绑定签名模板/镜像和资源 profile，模板更新不能命中旧实例；执行过的 VM 不回池。预启动 agent ready 只证明 VM 控制面就绪，尚未预初始化 Python 或 numpy/pandas，解释器首任务成本另测，不能计入 1–2ms 的宣传。后续预初始化须在真实兼容性证明后设计独立 readiness 条件。

## 验证和拒绝条件

先做[实施前自评审](../../PUBLIC-QUALIFICATION.md#private-evidence)，再构建、核对版本/库闭包/清单与真实 KVM 执行。任务至少包含版本、argv/env/二进制 stdin、stdout/stderr/退出码、异常、线程、hashlib/zlib/ssl/ctypes、numpy 数组/矩阵分解和 pandas CSV/groupby/merge/时间运算。逐层保留失败串口和镜像摘要，出现缺失 ABI 时不能改为宿主运行来声称通过。

分别测 64MiB 与实际工作 profile 的结果和峰值内存；64MiB 不足须明确记录。OSv 当前仅有 x64 原生通路，新模板不能宣称 ARM64 OSv 已支持；原有 Linux ARM64 离线包/QEMU验收继续有效。解释器运行验证、池/回收验收、正式签名发布是不同阶段。全套候选 CI/L2 在实际运行修改合并冻结后执行一次；只改构建工具时按影响做定向验证，不重复生成 rc42。
