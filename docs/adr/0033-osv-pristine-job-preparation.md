# ADR-0033：OSv pristine 任务准备与一次执行

状态：Accepted；日期：2026-10-30；需求 LIFE-04、PERF-03、OSV-01、SEC-01、SEC-06。继承 ADR-0029～0032。

## 决策

OSv 的单地址空间模块不能在任务结束后恢复成干净状态。预热实例只能在执行任何租户模块前共享，领取后只执行一次并销毁。采用共用 owner/容量/调度器，后端各自实现 pristine probe、prepare 和执行；不复制一套 OSv 资源账本或补池循环，不声称 OSv 已支持 Linux session/workspace。

OSv agent 新增显式启动参数 `--pristine-v1`；无参数保留既有一次 OSJ1 任务路径，未知参数拒绝。新模板签名特性为 `pristine-v1`，与运行时 OSP1 revision=1 双重校验；旧 agent 即使可连 vsock，也不能进入新池。新模板继续使用已固定提交的 OSv、签名只读模块列表和无 NIC profile。

固定 Firecracker 会追加 `pci=off root=/dev/vda ro`，OSv 将它们作为应用尾参传入；agent 只移除这一组完整、顺序一致的尾参，再严格校验自身模式参数。不同尾参、未知标志或版本均拒绝，不忽略任意额外参数。

OSP1 为有界二进制控制协议，独立 magic，不扩展旧 OSJ1 的含义。请求固定 52 字节：magic 4、操作 1、flags/reserved 3（全零）、24 字节小写 hex ID、16 字节 nonce、little-endian TTL 4。操作为 ping=1、prepare=3；ping TTL 必须为 0，prepare TTL 为 1000～300000 ms。响应固定 64 字节：同一 ID/nonce、pong=2/prepared=4、revision=1、state（0 pristine/1 prepared）、剩余寿命、status=0。所有保留位、长度、操作、绑定、状态与寿命均严格校验。nonce 沿用 OSJ1 的 128 位随机挑战；不降低既有 OSv 的绑定强度。

pristine 状态接受最多 6000 次 ping，各连接一次交换；prepare 只接受一次，先提交不可变任务 ID/nonce 和租期，再发送 prepared ACK。每个响应沿用有界 `0xa5` 确认与 EOF 收尾，防止 OSv transport 提前关闭丢失响应。prepared 状态只允许下一条 OSJ1 任务，其 ID/nonce 必须与 prepare 一致；失败、重复 prepare、无准备执行、错误绑定或畸形帧均终止实例，不降级、不重试 prepare。执行原有 argv/env/stdin/结果与截断契约，结果确认后整机退出，绝不回池。

guest 使用单调时钟：从 pristine main 起最多存活 600 秒，prepare 要求剩余寿命大于 TTL+5 秒；接受后固定租期。独立 watchdog 在 boot/准备/模块执行/响应阶段均生效，期限到达整机 poweroff，不尝试在线程/模块内取消任务。宿主仍以固定 owner deadline、请求 deadline 和归属清理为权威；guest 时钟不可用即拒绝。各次 accept/read/write 的等待也受剩余寿命和单次传输上限约束。

## 验收与集成顺序

先自评审、实现和定向测试 C 状态机/Go wire codec，再以新签名模板做真实 KVM 的探测、超过 100 次 ping、一次准备、绑定拒绝、旧模式、TTL/硬界和 argv/env/stdin/结果回归。guest 准备协议通过后再接入共用 pool；其准入必须同时满足 signed feature、wire revision、进程/lease/cgroup、模板和寿命检查。最终按同候选运行完整 pool 故障集、CI 和既有后端回归。

每路径至少 1000 样本的真实 KVM 性能与安全门禁继续保留；协议或功能通过不能证明 OSv pool 已启用或 1–2 ms 已达成。OSv 产品生产准入继续受现有总门禁约束。
