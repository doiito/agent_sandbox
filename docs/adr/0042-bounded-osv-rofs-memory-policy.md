# ADR-0042：OSv 只读模板的可控内存缓存策略

状态：Accepted；日期：2026-11-02；需求 OSV-02、SEC-03/05、PERF-01、QA-01/02。

签名缓存策略经完整 CI、128MiB 的 20 项 Python API/warm 功能、旧模板池 25 项/冷 API 33 项及篡改/旧验证器边界通过，见 [rc49 验证](../../PUBLIC-QUALIFICATION.md#private-evidence)。64MiB 完整科学任务仍失败，小页实验未采纳，完整性能和生产门禁未通过。

## 证据与问题

rc48 的固定 Python/NumPy/pandas 在 512MiB 通过 20 项完整功能；64MiB 完整任务、pandas 单独导入和 128MiB 完整任务超时。sysinfo 阶段采样从约 25MiB 上升到 pandas 导入后的 120MiB，含缓存，不能据此推断真实语言堆或最低 RAM。

固定上游 `fs/rofs/rofs_cache.cc` 有独立的全局 inode/段缓存：普通 read 和文件映射都可创建段，段与 file_cache 常驻，无 shrinker/容量淘汰。通用 pagecache 中的 borrowed-page 包装不拥有这些内存。原方案 §3 关于页缓存回收的描述不能直接用于这个 ROFS 缓存。上游已有 `--disable_rofs_cache`，关闭 ROFS 段缓存和借用页映射，保留只读文件读取和通用私有文件映射路径。

## 决策与验证顺序

1. 先用同一个 rc48 kernel/rootfs/agent/固定科学任务做缓存启用/关闭的真实 KVM 对照。记录实际启动选项、物理 guest RAM、cgroup、身份、原始结果与 sysinfo；完整工作量和原 30 秒期限不变。独立诊断启动策略不冒充现有签名模板的新能力。
2. 若证实明显减少内存并使完整任务通过，采用明确的模板内存策略：由签名 manifest 声明，launcher 固定生成对应 boot option；API 不接受租户自定义 kernel 参数。默认与旧 manifest 保持兼容，不能仅替换 rootfs 后隐式改变策略。
3. 单次任务、只读模板优先避免永久 guest 文件副本；宿主只读镜像 page cache 继续由宿主统一管理。不立即对 borrowed-page 添加自制 LRU，以免释放仍映射的段。后续有界缓存必须验证页映射引用、COW、TLB、并发与回收锁序。
4. 不删减科学库、换版本、跳过导入/finalization 或把 RAM 目标改大。64MiB 仍执行原完整 workload；若对照不能达标，保持失败并继续定位真实语言堆、栈与其他回收问题。
5. 同时观察读取量、首任务耗时与重复访问行为。缓存关闭可能增加 virtio I/O；功能达标不等于性能通过，也不证明语言初始化已经在 warm pool 中摊销。原 2/5/10ms 与其他性能门禁保持不变。

## 第一轮对照后的设计补充

同镜像 KVM 对照中，关闭缓存使完整任务阶段用量从约 122MiB 降到 85MiB，但两种 64MiB 路径都超时。因此不把缓存开关作为已经达标的产品策略。另一个独立因素是普通匿名 VMA 首次 fault 可自动分配 2MiB 页，稀疏 BSS/匿名区可能放大驻留内存。

增加可显式启用的 `--sandbox-small-pages`：只为此后新建的普通匿名映射设置既有 mmap_small，沿用原 4KiB fault/populate 路径；不重写页分配器、不改变文件/COW 映射，不降低权限或清零保证。MAP_HUGETLB 明确请求保留，已有 MADV_HUGEPAGE/NOHUGEPAGE 行为保留；VMA 分割复制原 flags，mremap 新建部分仍应用当前默认策略。开关默认关闭、启动期只启用一次，以原子状态发布给其他线程；不将 tenant payload 放进启动参数。

先验证普通稀疏 mmap 的实际物理增量、数据/清零/munmap 和显式大页/advise，再在相同科学栈上对照；只有工作量完整且结果真实才可能关闭 64MiB 功能目标。若有效，后续由签名模板同时绑定 ROFS/匿名页策略，不能给旧模板隐式启用。此补充仍不承诺降低 Python 必需堆。

## 第二轮后的取舍

小页实验通过真实稀疏映射与大页/advise 检查，但科学任务各阶段占用未降低，64MiB 仍失败。因此不采纳该内核修改：实验 kernel、完整源码和结果独立保留，生产 overlay/内核源码恢复 rc48，12 个已验收运行时源码摘要逐一相符。

原版 rc48 的无缓存完整科学任务与阶段探针在 128MiB 均成功。接入可选签名字段 `osv_rofs_cache="disabled"`，仅 OSv v2 允许；缺省保留旧行为，未知值和 Linux 使用拒绝。Manager 只从已验签清单构造 backend，cold/pristine 使用同一固定 boot option，租户不能提供该字段或任意 kernel 参数。旧运行时遇到新字段应拒绝，不静默使用其他策略。API 完整功能矩阵改为显式选择 128/512MiB 测试 profile，64MiB 完整工作量和总体失败判定保留。

128MiB 下的诊断不是最终 64MiB 门禁，也不是生产性能/长稳证据。后续继续追踪可回收只读映射和真实语言内存，不以切换分配器、小页合成微基准或更大 RAM 替代原目标。

## 自评审与回归

实施前见[自评审](../../PUBLIC-QUALIFICATION.md#private-evidence)。先做窄范围对照，再实现签名策略、反例与启动参数检查。冻结后一次 CI 与受影响 OSv 冷/warm/协议/完整 Python 回归。Linux rc46、ARM64 QEMU 不因测试工具或文档变更重复回归。原失败、原候选与依赖闭包保留，全部真实库和产物继续在项目目录。
