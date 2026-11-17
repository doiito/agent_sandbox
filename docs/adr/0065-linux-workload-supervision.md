# ADR-0065：保留guest PID语义的工作负载监督

状态：Accepted（共享Rust监督和正式命令定向验证通过，完整上下文/发布链继续实施）；日期：2026-11-05；需求EXEC-01/02、CAP-01、OSV-02、API-02、QA-02/03。

## 决策及原因

[ADR-0064](0064-persistent-code-contexts.md)的每工作负载PID namespace原型证明了后代回收，但正式路径不采用该PID划分：现有命令PID必须等于Bash的$$，并能在同一session历史中区分commands.connect/kill/stdin句柄。每个namespace重复出现PID2会破坏这个已验收契约，不能以修改测试断言或SDK伪造PID解决。

正式监督采用guest内每工作负载cgroup v2及独立可信subreaper进程。解释器/shell保留session VM的PID空间及共享workspace；subreaper在root身份设置PR_SET_CHILD_SUBREAPER后启动一个普通用户入口。fork/setsid/多层后台后代留在该cgroup并由该subreaper收养。正常完成或取消通过cgroup.kill停止整组，再waitpid直到ECHILD，最后确认cgroup为空、helper被收集并移除cgroup。PID1不对并存工作负载执行kill(-1)/waitpid(-1)。

这仍以tenant VM为安全边界，不创建新租户边界，不修改宿主全局cgroup或系统策略。当前x64实际kernel为6.18.56+且有cgroup.kill符号，ARM QEMU kernel也须实际验证挂载/kill能力；不能由符号检查替代运行证据，不满足时明确不可用。

## 生命周期与协议

guest启动时将cgroup v2挂到root拥有的/run目录，权限禁止普通用户迁移。每次root创建唯一工作负载目录并打开目录fd，以专用fd交给同一静态agent二进制的helper模式。root helper使用固定干净环境；argv/env/cwd通过有界私有控制socket传递，只对降权后的入口应用租户环境。helper将入口在exec前加入cgroup、setsid、设置既有rlimit/no_new_privs及UID/GID；控制fd和cgroup fd均CLOEXEC，不传给用户入口。

父进程负责原stdin/stdout/stderr与外部连接、超时/取消。helper只在独立控制socket上报告真实入口PID、spawn失败、最终原始wait状态或监督错误，不向用户stdout插入协议。父进程在started前不发布用户输出；控制读写非阻塞并计入原执行截止时间。退出码来自入口进程，不能用helper的0退出码替代用户失败。

取消只发送一次stop。helper写cgroup.kill并在有界清理时间内收集全部归属子进程，返回完整清理ACK；父进程必须看到ACK、helper成功退出及空cgroup后才能复用session。pidfd用于helper失败后的精确终止，不能在wait后对可能复用的数字PID反复kill。控制协议错误、helper失联、未知后代或清理超时将VM标为不可用，不能静默转回全guest清理后声称其他上下文正常。helper的父进程死亡同样触发整组回收。

专属解释器后续复用这套监督原语，单次代码SIGINT与整个上下文stop分别处理。pristine绑定、TTL、物理VM账本和用后销毁规则保持；预启动成本计入真实模板池ready，不能降低既有性能目标。

PDEATHSIG绑定创建线程。上下文的常驻worker必须创建并拥有Process直到clean，不能在短请求线程创建后迁移；代码上下文实施时应在接口上限制这种错误用法。当前普通命令由guest PID1主线程持有。父/owner崩溃整链路仍须最终同包KVM生命周期验证。

## 实施前自评审

PID namespace方案因现有SDK PID契约被否决，历史原型证据保留。cgroup负责追踪全部活后代，subreaper以ECHILD证明归属收集结束，无全局reaper抢占其他Child状态；helper在工作负载cgroup之外，cgroup.kill不会杀掉自己的可信回收器。控制通道与租户stdio分离，用户环境不影响root helper，非root不能自行启动可信helper或迁移cgroup。保留stdin背压、超时、流式PID/顺序和非零退出的既有行为，不为简化实现缩小原功能。

先实现共享Rust监督模块并在ARM无NIC QEMU实际执行：真实不同PID/$$、普通用户/env/cwd、双工作负载并存、fork/setsid后代、非零退出、超时/取消、输出及stdin、父进程退出、helper异常、空组与ECHILD。随后迁移生产普通命令，再接代码上下文服务。对应定向测试通过后，在完整功能冻结的新候选上集中CI、双架构离线包、ARM QEMU及x64 cold/warm KVM回归；本ADR或单独helper测试不等于新API/发布验收。

[双架构R10结果](../../PUBLIC-QUALIFICATION.md#private-evidence)完成32组共享监督/实际命令pipeline/真实fatal reset，native54项及clippy通过。修复已结束命令误判超时，保留初始失败。正式代码上下文服务、owner/TTL/KVM及新离线候选继续开放。
