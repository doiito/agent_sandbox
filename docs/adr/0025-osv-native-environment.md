# ADR-0025：OSv 原生任务的有界环境变量

状态：Accepted；日期：2026-10-30；需求 EXEC-01、API-01、OSV-01。继承 ADR-0002、0008、0009、0011。

## 背景

当前 OSv 原生控制通道只传模块路径和 argv，`environment` 明示为不可用。签名模块中的 Python、Node 和 native 应用需要任务级配置；若改用 boot args 或宿主进程环境，会扩大秘密暴露面并破坏任务身份绑定。OSv 的应用和 agent 共享进程环境，但每台 VM 只执行一个任务，任务结束即关机，因此可以在模块加载前设置环境而不跨任务复用。

## 决策

`RunRequest.environment` 是最多 32 项的字符串映射，名称限 ASCII `[A-Za-z_][A-Za-z0-9_]*`、最多 64 字节；拒绝 `LD_`、`OSV_` 前缀。值最多 1024 字节且不得含 NUL；名称和值合计不超过 8192 字节。仅 `firecracker-osv` 的一次性签名模块任务支持该字段，其他 backend 非空环境在准入阶段拒绝。OSv v2 签名 manifest 的可选 `agent_features=["environment"]` 把此能力与镜像、agent 模块和 SBOM 一起绑定；旧 manifest 和无签名诊断配置不声明、也不接受环境输入。HTTP、SDK 和能力报告只能声称已实现且已签名声明的范围，审计和错误不得记录环境值。

保持 `OSJ1` 长度帧、job ID、nonce、上限和结果 ACK/EOF 语义。请求 flags 的 bit0 表示环境扩展；未设置时旧帧字节不变。设置时 argv 后附 `env_count:u16` 及按名称字节序严格递增的 `name_len:u16,value_len:u16,name,value`。host 先验证再排序编码，guest 再验证长度、名称、前缀、顺序、NUL 和总预算。未知 flag 或尾随字节拒绝，旧 guest 对新 flag 拒绝，不会把扩展误作参数。guest 在模块执行前逐项 `setenv`；任何失败不运行模块，返回明确非零 runner status。VM 独占与 poweroff 保证任务后无环境残留。

此决策不声称工作目录、stdin、任意未签名模块、OSv 生产准入或未修改 E2B SDK 已就绪。OSv 生产 gate 保持关闭，直到完整运行时兼容、长期稳定与安全评审完成。

## 验收

先审查协议扩展和资源预算，再做 host 解析/准入及 guest 畸形帧定向测试；构建项目目录中的 OSv kernel、raw image 和模块。指定服务器做真实 Firecracker/KVM 的正确值、空值、非法名称、过界、旧帧回归、租户/模板约束及零残留检查。代码变更触发 L1 CI 和 OSv 受影响 L2，不重复无关 Linux 完整回归。
