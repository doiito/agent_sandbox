# ADR-0026：OSv 原生任务的有界二进制 stdin

状态：Accepted；日期：2026-10-30；需求 EXEC-01、API-01、OSV-01。继承 ADR-0008、0009、0011、0025。

## 背景

签名 OSv 模块任务已支持 argv 和有界环境变量，但无法接收 stdin。将输入放进 argv 或环境会破坏二进制语义，也增加意外泄露到日志和进程参数的机会。OSv agent 与模块共享进程的标准描述符，每台 VM 只执行一个任务；可以在模块运行期间临时绑定一个内存中的输入流，并在发送结果前恢复 agent 描述符。

## 决策

`RunRequest.stdin` 为可选的 base64 编码 JSON 字节字段，最大 16 KiB；缺失与显式空字节串不同，后者向模块交付立即 EOF。仅一次性 `firecracker-osv` 签名模块任务支持；非 OSv backend 在准入阶段拒绝非空输入。OSv v2 签名 manifest 的 `agent_features` 必须包含 `stdin` 才接受和声明该能力。特性列表仅允许已实现名称，按字节序严格递增且不重复；旧 manifest 仍有效，但不获得新能力。能力报告声明 `stdin=true` 和 `max_stdin_bytes=16384` 仅在签名声明存在时成立。

`OSJ1` 请求 flag bit1 标记 stdin；旧帧与环境 bit0 语义保持不变。环境块之后追加 `stdin_length:u16` 和原始字节，包括长度零。host 在 VM 分配前检查上限并编码；guest 检查长度与剩余帧精确一致，拒绝未知 flag、截断和尾随字节。旧 guest 因未知 flag 拒绝扩展帧。

guest 使用内存 pipe 作为 stdin，非阻塞 feeder 线程发送，发送完关闭写端提供 EOF；feeder 线程单独阻塞 SIGPIPE，使模块提前关闭 stdin 时写入只返回 EPIPE；模块结束时停止 feeder 并恢复 fd 0。此方式避免预填管道容量造成死锁。host 仍负责超时与 VM 强杀；后台模块线程不保留跨任务状态，因为 VM 结果后关机。审计、错误和报告不得包含输入内容。

此决策不声称 cwd、持续交互 stdin、流式输出、OSv 生产准入或任意未签名模块已就绪。

## 验收

先检查能力/协议/资源边界和 fd 恢复设计，再做 host 准入、签名特性、旧帧回归与 guest 畸形帧测试。指定服务器使用新签名模板运行真实 KVM：空输入、含 NUL 二进制、16 KiB 边界、超限前置拒绝、模块不读取时无死锁、后续 VM 不继承、零残留。运行受影响 CI 和 OSv 定向 E2E；无关 Linux 大回归不重复。
