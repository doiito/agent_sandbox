# ADR-0052：真实 Bash、guest PID 与 E2B 命令句柄

状态：Accepted；日期：2026-11-03；需求 EXEC-01/02、API-01/02、REL-04。

## 固定语义

已下载并核对固定 E2B 2.51.0 提交的四份命令/句柄源码，与现有矩阵 SHA-256 一致。上游以 `/bin/bash -l -c` 执行命令；list 只列运行进程，pid 为实际 guest PID；非零退出的 wait 抛出携带 stdout/stderr/exit_code/error 的专用异常；disconnect 不杀进程，可按 pid connect。Python timeout（秒）和 Node timeoutMs 限制观察连接，不等于进程执行期限。

## 本批决策

离线 guest 包含两架构真实静态 GNU Bash，源、版本、构建来源、许可证、二进制与所需库保存在项目中，不引入目标机下载。构建先验证 C 交叉链接输入，编译后查架构/动态解释器并实际执行；不以 BusyBox sh 冒充 Bash。租户必须获准 `/bin/bash`，新默认示例与隔离验收夹具显式列入。

执行器在可信控制连接上发送绑定 protocol/job_id/nonce 的 started 帧，报告实际子进程 PID，先于 stdout/stderr。opaque 命令 ID 继续作为底层控制身份；适配层按所属 session 的运行记录解析 pid，不向宿主 PID 发信号。句柄创建等待 started 或明确启动失败；退出后保留同一句柄结果，重复 wait 不重复回调或执行。

Linux session 增加有界 env/cwd：最多 32 项/8KiB 环境、每值 1KiB，校验名称、UTF-8 与 NUL；环境仅用于子进程，不修改 PID 1。cwd 为 guest 内绝对路径，限 1024 字节且无控制字符，实际 chdir 在降权后执行；默认 `/workspace`，缺目录或权限不足明确启动失败。原执行/租期/输出资源限制保留。

双语言显式适配层本批补齐 commands.run/list/connect/kill 与 command_handle.wait。回调使用增量 UTF-8 解码，支持 foreground/background、成功与非零退出、输出观察超时后重连；观察 timeout 独立于既有服务端执行上限与 session TTL，timeout=0 不增加观察期限。自定义用户、PTY、交互 stdin 仍显式未支持，并在下一批扩展，原七项命令分母保留。只有同候选双语言真实 KVM 行为完成才增加这五项计分。

## 验证与回归

先[自评审](../../PUBLIC-QUALIFICATION.md#private-evidence)，再 native/guest/SDK 定向测试，冻结一次完整 CI，双架构离线包、ARM64 QEMU 及 x64 同包双 SDK E2E；真实 warm 路径补验 started 绑定与取消。测试 Bash 数组/参数展开、真实 PID、运行列表、env/cwd、非零异常字段、回调、断连/重连与观察超时不杀进程，另核对基本权限和零残留。OSv 未改不重复其昂贵全矩阵，全面安全深审按 ADR-0049 可选。

## 验收

[rc55 双架构、QEMU 与 x64 KVM](../../PUBLIC-QUALIFICATION.md#private-evidence)通过；首次 rc54 集成失败与修复保留。新增五项有同候选双语言真机证据，固定矩阵17/34；交互 stdin 两项与其余原需求仍待实现，启动性能门禁未达标。
