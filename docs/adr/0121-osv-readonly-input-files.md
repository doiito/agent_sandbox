# ADR-0121：OSv单次任务的有界只读输入

状态：Accepted（rc90 只读输入完整功能、双架构离线及四路线启动门禁已通过；完整原始发布目标继续跟踪）；日期：2026-11-14；需求 FILE-01、CAP-01、EXEC-01、LIFE-04、SEC-01、QA-01、QA-02、PERF-03、REL-04。

## 用户要求与兼容边界

用户于2026-11-14明确选择“补齐OSv只读输入”。因此本次发布须实现当前OSv job的input_files，而不是把unsupported拒绝计为input_readonly通过。[ADR0034](0034-shared-pristine-pool-backends.md)的旧OSv模板能力边界仍用于兼容，新的受信签名模板才启用新功能；OSv session、可写workspace或无签名模块不因此开放。

目标与Linux公开JobRequest一致：相对路径映射到`/input/<path>`，最多64文件、总数据512KiB、总路径32KiB、单路径1024字节、段长255字节及最多16层；只允许数据文件0444。拒绝绝对/空/点/点点/反斜杠路径、NUL/控制字符、无效UTF-8、重复文件和文件/父目录冲突，不接受用户symlink或宿主共享路径。每任务fresh VM，一次prepare并用后销毁。

## 受信能力与OSP2

新增签名`input-files-v1`，要求同时有`pristine-v1`并绑定实际新kernel、agent与SBOM。没有该特性的旧OSv模板继续input_files=false并在执行前拒绝文件；新host兼容OSP1，旧host拒绝未知签名特性。当前v7的guest_inference及其他原特性继续完整保留，不以新功能删除推理、stdin、environment或ROFS cache策略。

新模板使用显式`--pristine-inputs-v1`启动模式，探测/准备均为OSP2 revision2；旧`--pristine-v1`保持OSP1 revision1的固定52字节语义。pool key继续绑定签名摘要、后端及实际协议修订，不混发旧队列。公开执行结果仍是osv-agent/v1，后续OSJ1的ID/nonce绑定不变。

OSP2 ping保持52字节、ttl=0且无输入。prepare为原52字节binding/ttl头、u16文件数/u16零保留位，再顺序编码每文件u16路径字节数/u16零保留位/u32数据字节数、UTF-8路径字节及原始数据。无额外JSON/base64放大；最大557624字节，旧OSJ1执行帧上限不扩大。新模式仅在未prepare状态允许该较大prepare帧，其他状态或magic/版本混用拒绝并终止VM。

host复用公共路径/预算验证，guest在分配及挂载前独立验证全部边界、UTF-8、路径和冲突。C解码器只返回有界视图，不把跨wire指针当地址；本地agent→kernel ABI另用只在guest地址空间内有效的明确版本结构。

## 原子准备与只读文件系统

新ROFS镜像预置空`/input`挂载点。pristine阶段没有租户输入；OSP2 prepare在任何模块执行之前，构建VM私有的RAMFS输入树，复制数据并以MNT_RDONLY发布到`/input`，文件0444、目录0555。不能只靠chmod声称只读。

内核新增明确版本的input mount C ABI，复用ramfs节点与数据段，仅为该有界输入导入路径在挂载发布前创建目录/文件；普通ramfs行为不变。所有校验在构建前完成，构建失败回收尚未发布节点；数据由RAMFS自己持有，不保留准备帧内存指针。空文件集也挂载空的只读输入树。源数据不挂宿主目录、不把文件插入全局共享guest镜像，也不允许新进程改动其他VM。

当前固定OSv VFS的`vn_access(VWRITE)`会对MNT_RDONLY返回EROFS，创建/元数据操作也检查挂载标志；普通sys_mount拒绝重复挂载，ramfs不支持unmount。实现仍须通过实际guest的open/truncate/rename/delete/chmod/link等反例确认，源码存在不算已验收。共享地址空间的OSv不是guest内多租户安全边界，隔离继续由fresh VM/VMM/jailer承担；不会以该功能声称解决任意原生代码改写guest内核的问题。

只有输入树完整只读发布后才提交prepared状态并发送绑定ACK；ACK中的剩余期限按实际准备耗时重新计算。任何解码/挂载/期限/ACK失败均拒绝并销毁VM，失去ACK后不重发prepare或用户模块。输入传输与挂载计入已有preparation/startup分段，不能移到启动计时之后隐藏成本。

新模板在warm、启池cold miss以及完全未启warm pool的cold三条路径都必须准备输入。不能只让pool.acquire支持后就声明通用InputFiles能力：当前无池OSv直接OSJ1执行路径也须复用实际pristine准备/绑定/清理及计时逻辑，新模板始终进入对应OSP2模式，不借内部虚假池或隐式开启后台预热绕过配置。旧模板的无池冷启动语义保持。三条路径分别设置定向回归并核对公开startup_mode、active/物理资源账及零残留。

## 验证与构建顺序

先完成[实施前自评审](../../PUBLIC-QUALIFICATION.md#private-evidence)，再用Go/C定向反例验证wire及准备状态。包括最大/空/二进制输入、预算溢出、截断/保留位/版本、UTF-8、路径及祖先冲突、失去ACK、旧模板拒绝与新能力声明。内核只读语义必须用实际OSv QEMU/KVM验证，native stub不能替代挂载证据。

当前rc88的池空/真实补池故障先取回并独立归档，签名到期与镜像轮换继续补证，保留产品改动前的可解释基线。随后产品协议、agent、内核、模板、API能力、签名/打包及回归守卫集中形成新候选，跑一次完整canonical CI、双架构离线包、ARM编译/QEMU及指定机回归；不对每个局部文件修改重复整套。

新候选须分别证明OSP1旧能力兼容和OSP2的新默认模板：cold/warm实际读取最大/嵌套/空文件，写/截断/元数据与跨挂载改动拒绝，真实模块不得执行数据文件；两租户输入、取消、TTL与崩溃零残留。原15套、池生命周期覆盖及新用例分母分别保持，不能把旧输入拒绝断言悄悄改名为新只读证明。稳定后才集中四必要路线各千次正式性能，warm仍5/9/13ms；OSv内核不新增ARM KVM要求，K8s仍暂缓。

实际库、源码、镜像和签名依赖存项目中；只能在SHA及无引用检查后清理已证明无用的中间件/重复安装副本。新功能与其验收完成前，不标记FILE-01的OSv分支或完整发布通过。

## 输入解码器定向起步

首个可独立验证组件位于项目`build/validation/osv-inputs-codec-r1/`，尚未接入产品。C解码器不分配文件数据、不修改FSM或文件系统，校验成功才返回完整视图数量；失败时数量保持0。Python独立生成wire向量，10项检查覆盖精确/超限预算、UTF-8/C1、重复/祖先、全部截断、保留位与溢出，并在UBSan下通过。收据`results/2026-11-14-osv-inputs-codec-r1/receipt.json`明确未证明实际只读挂载、Go/guest接入或发布；后续按同字节组件集成并补齐这些证据。

## 首轮真实挂载发现与修复边界

实际kernel/agent和Go三路由已进入实现。106首轮KVM组件任务`osv-input-mount-kvm-r1`（InvocationID `c34e4277d024494085d96efad8bdfa43`）验证了64文件、512KiB、嵌套中文/1024字节路径以及源buffer释放后的逐字节读取，但任务失败，原始记录保存在`results/2026-11-14-osv-input-mount-kvm/r1/`。本地相同内核QEMU/TCG因没有可用时钟源、未进入模块而失败，不能算挂载证据。

KVM发现原OSv `sys_truncate`缺少MNT_RDONLY检查；`chown`所有权桩无条件成功；`sys_link`在只读检查失败时释放未初始化的newdp导致内核崩溃。这些均须修复而非放宽断言：路径truncate在调用VOP前拒绝只读；chown/lchown/fchown验证实际目标挂载或fd，只读返回EROFS，保留可写文件系统的既有无uid/gid语义；硬链接失败只释放已取得的dentry。修复后使用新任务身份重验，原失败不可覆盖或重放。组件验证仍不等同于OSP2真实RPC、签名新模板、完整CI/双架构离线或发布验收。

## rc90 验收结果

[当前验收](../../PUBLIC-QUALIFICATION.md#private-evidence)保留 cold/warm 两输入夹具 49 项、21 个唯一 job/VM，以及原 15 夹具/516 项、44 原生 gRPC、完整 CI、x64 非 root 安装和 ARM 无网卡 QEMU 62 组。完全无池 cold、启池 profile miss 和实际预启动 warm、16 类写/元数据操作拒绝及隔离/取消/超时清理通过。两个后端各 18 类池场景、[四条正式启动路线](../../PUBLIC-QUALIFICATION.md#private-evidence)及机器门禁已核验；OSv session 仍不支持，整体 mimalloc 收益和其余原目标未由本分支关闭。
