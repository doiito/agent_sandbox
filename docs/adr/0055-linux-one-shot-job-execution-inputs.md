# ADR-0055：Linux 一次性任务的环境、工作目录与固定 stdin

状态：Accepted；日期：2026-11-03；需求 EXEC-01、API-01/02、LIFE-01、LIFE-04、REL-04。

## 缺口与决策

Linux session 已支持 env/cwd 和交互输入，但一次性 job 仍在准入层拒绝 env/stdin，且没有 cwd。补齐真实一次性任务执行契约，冷路径 fc-agent/v1 和 pristine warm job v3 均在领取/绑定后传输同样的执行载荷；不把租户环境、stdin、cwd放进预启动池或内核命令行，不改 OSv 的签名特性和协议。

`environment` 复用 Linux session 的32项、名称64字节、值1024字节、总8KiB、UTF-8/NUL约束；执行清空继承环境，默认 PATH/HOME/LANG后应用租户值。OSv继续使用现有保留前缀与签名agent feature准入。`cwd` 为实际guest绝对路径、最多1024字节且无控制字符，省略仍为/workspace；child降权后chdir，目录不存在/无权限明确返回guest执行错误，不自动建目录或替换路径。

`stdin` 保持现有 job API 的base64字节字段和16KiB有界载荷，省略为/dev/null，显式空输入创建管道并关闭以产生EOF。数据通过真正的stdin管道进入child，父端非阻塞推进并与stdout/stderr排空、deadline和子进程回收共用监督循环；全部写入即关闭，无读者/提前关闭按程序自身退出结果处理，不强制程序消费全部数据，也不重放输入。不能在spawn后阻塞write_all，也不增加线程或目标机依赖。固定stdin与交互stdin互斥，非执行操作拒绝固定输入。

Python/Node原生JobRequest新增cwd，按能力准入；环境通用schema允许Linux正常变量，OSv保留前缀由已选backend明确检查。无能力或不支持的backend不能静默忽略字段。公开capabilities声明Linux的environment/working_directory/stdin及上限；本批不冒充新增E2B方法分子。原生JobResult同时保留服务端实际startup_mode/startupMode，缺失时不伪造默认模式，以便客户端核对真实warm领取。

## 验证与回归

先[自评审](../../PUBLIC-QUALIFICATION.md#private-evidence)，再定向验证：Go准入/JSON空输入/冷warm执行线上的字段与绑定，Rust真实管道4KiB容量/16KiB输入/双向输出/EOF/提前关闭/超时，双SDK类型和能力负例。冻结一次完整CI，再构建项目内双架构mimalloc guest/rootfs及离线包，ARM64无网卡QEMU与x64实际KVM同包双语言冷/warm正反例。保留已有基础取消/清理回归；OSv载荷和代码未改，复用既有OSv矩阵。只有实际通过后才把需求状态改为已验收；性能门禁仍独立。

实施与验证见[rc60验收](../../PUBLIC-QUALIFICATION.md#private-evidence)：完整CI、双架构离线包、ARM64 QEMU33、真实x64同包cold/warm双SDK各23项、基础/生命周期及warm会话补验通过。E2B仍22/34，性能与完整项目目标继续开放。
