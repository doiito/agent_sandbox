# ADR-0045：无缓存 ROFS 的有界块读取与失败状态

状态：Accepted（有界读取与失败状态；不关闭 64MiB 或生产门禁）；日期：2026-11-02；需求 OSV-02、REL-02、SEC-03、QA-01/02/05。

## 发现

checked-hash 字节码实验在 128MiB 通过完整 20 项真实 API 功能，但 64MiB 科学任务返回 pandas 源码含空字节，VMM 同时报告 InvalidDataLength。不能将其简单标为 MemoryError。固定 OSv 的 rofs_read_without_cache 对整次请求 malloc；malloc_large 在大请求或碎片化时可转为 VMA 映射，virt_to_phys 将其逐页展开为多个数据描述符。

固定 [Firecracker v1.16.1 Request::parse](https://github.com/firecracker-microvm/firecracker/blob/v1.16.1/src/vmm/src/devices/virtio/block/virtio/request.rs) 仅取一个 data_desc，紧接的描述符作为 status_desc，且 data_len 须为 512 的倍数。OSv malloc 的页内头部可使首段不对齐，且多个数据段会使状态地址解析错误。OSv blk::make_request 当前把请求状态初始化为成功，不能作为设备必定写入状态的假设。

## 顺序与方案

1. 先以固定 libpython 文件的已知 SHA256，在 cached/uncached 128MiB 下执行跨 2MiB 边界的大读取，独立复现；不依赖 pandas 或内存耗尽解释现象。原镜像、版本与失败报告保留。
2. 无缓存 ROFS 改用最大 32KiB、物理连续、页对齐的 bounce buffer，分块读取并立即复制到 uio。单次 buffer 生命周期有界，不恢复永久缓存；分配使用 `block=false`，分配失败返回 ENOMEM，IO 失败返回原错误，不把未读或部分数据当作成功。固定 OSv 分配器仍可能等待 emergency 最低水位，不能将该参数宣传为完全无等待；不新增占用 emergency reserve 的绕过策略，既有外部任务期限继续有效。
3. 检查读量、offset、块边界与尾部；EOF/零长不分配，不越过请求或文件尾；分块错误保留已经完成的 uio 进度，由既有 VFS 规则决定部分读取。避免用文件长度直接决定临时物理连续分配大小。
4. virtio-blk 状态初值为 IOERR，只有设备真正写入 OK 才成功；此为防御措施，不能代替正确数据描述符。先保留通用设备的合法 SG 能力，不将整个驱动限制成仅单段。
5. 修改通过项目 overlay 应用；不覆盖上游 checkout 的其他更改，不恢复旧的错误 virt_to_phys 单段假设。缓存策略仍由签名模板控制，租户不能注入启动参数。
6. 验证大读取内容、任意偏移/短尾、ENOMEM/IO 错误、清理和只读语义，再运行完整科学负载和既有 64MiB 原门禁。文件完整性修复不等于 64MiB 能容纳全部科学栈。

实施前[自评审](../../PUBLIC-QUALIFICATION.md#private-evidence)。内核候选冻结后一次 CI 与受影响的真实协议、cold/warm、完整语言回归；不因工具变化重复旧 Linux/QEMU 验收。

## 实施证据

[rc50 验证](../../PUBLIC-QUALIFICATION.md#private-evidence)记录旧内核 cached 大读取通过/uncached 超时、新内核两路径内容哈希均正确，ASan/UBSan 边界与故障测试、完整 CI，以及真实 KVM 协议/退出 49、warm pool 25、冷 API 33 和 Python 128MiB 功能 20 项通过。原始 64MiB 科学任务现在明确记录 guest allocator 耗尽，仍在原期限内由宿主终止，内存门禁保持失败。
