# ADR-0008：OSv 原生任务控制与模块执行

状态：Accepted；日期：2026-10-29；需求 OSV-01、EXEC-01、SEC-06、API-01、QA-02。此决策定义产品路径，不表示实现或生产验收已经完成。

## 背景与边界

现有 OSv `firecracker` backend 把命令放进 boot args，并从串口识别结果；原生 vsock 驱动目前只由独立诊断模块使用。上游 OSv 可加载镜像内 ELF 模块，但 OSv 无 `fork()`；文件描述符表是全局的，加载模块可能留下线程、FD 和状态。`run_and_join` 在后台线程仍属该 application 时会等它们全部结束，即使模块主函数早已返回。单地址空间的 guest 代码可修改 agent，因此 guest 结果是任务数据而非宿主授权凭据。生产强边界仍是签名镜像、每任务全新 Firecracker VM、jailer/cgroup、无默认 NIC、宿主准入/审计和期限到达时的宿主强杀。

## 决策

建立独立 `firecracker-osv` backend，与旧串口诊断 backend 显式区分。OSv 镜像 boot args 只启动固定 agent；请求的 entrypoint、argv、job ID 和限制经 Firecracker host CID 2 到 guest CID 的 vsock 传入，不写入 boot args 或串口。entrypoint 必须是已签名模板中的规范化绝对模块路径，并同时通过租户入口策略。每台 VM 只接受一个任务，不在同一 VM 中重试或执行第二个任务。

host 通过该 job 独有的 jailer root 中的 UDS 建立 `CONNECT 5000`，连接路径用已打开目录的 `/proc/self/fd` 避免 Unix socket 路径长度及目录替换问题。单连接只交换一份请求和一份结果；取消/超时立即关闭连接并由 manager 杀死整台 VM。任何串口内容只作为有界诊断，不能成为结果或权限依据。

协议 `osv-job/v1` 使用固定字节序的长度帧，拒绝未知版本、类型、重复字段、额外字节、非规范 job ID、超长路径/参数/结果。请求上限 64 KiB，包含随机 job ID、独立随机 nonce、entrypoint、argv、guest deadline 和输出上限；结果必须回显 job ID 和 nonce，给出退出码、stdout/stderr 长度、截断位及明确错误类型。host 将已验证的一份结果映射为现有 `osv-agent/v1` JSON envelope，再由 manager 的任务身份检查接收。nonce 绑定同一连接的请求/响应，不把它说成抵御已失陷 guest 的认证密钥。解析失败、EOF、重复结果或期限超时均 fail closed。

v1 帧均以 4 字节小端 payload 长度开始。payload 的前 8 字节为 ASCII `OSJ1`、type（请求 1／结果 2）、flags、两字节零保留位；接着为 24 字节小写十六进制 job ID 和 16 字节 nonce。请求后续为 `timeout_ms:u32`、`max_capture:u32`、`path_len:u16`、`argc:u16`、path 字节及逐项 `arg_len:u16 + arg`；`argc` 不含 argv[0]。结果后续为 `runner_status:i32`、`exit_code:i32`、`stdout_len:u32`、`stderr_len:u32` 和两个原始字节串。结果 flags 仅允许 stdout/stderr 截断两位。host 完整校验结果后回写单字节 `0xA5`，guest 才关闭发送方向并关机；host 必须看到 EOF，防止把首帧后额外数据当作成功。`max_capture` 是 stdout+stderr 的合计原始字节上限，host 以 API 输出预算预留最坏 JSON 转义空间后下发。

参数边界统一为最多 64 个用户参数，加载 ABI 中连同模块路径 `argv[0]` 最多 65 项；所有 argv 字符串的原始字节数（含模块路径，不含结尾 NUL）合计最多 32768。API 准入、host 帧编码、guest 解析与模块加载包装须用相同边界，超限在准入或解析阶段拒绝，不能在 guest 执行阶段才表现为模块失败。真机边界用例应验证 64 项请求成功及 65 项请求拒绝；畸形帧测试覆盖 header、身份、长度、参数数量与尾随字节。

agent 通过 `osv::application::run` 的 `post_main` 回调接收主函数退出码；安全加载包装在回调触发后返回，不等待后台线程。应用实例由 OSv registry 保持到整台 VM 关机，不在后台线程仍可能执行其代码时卸载模块。输出捕获须先验证全局 FD 重定向不会阻塞 agent/vsock 控制通道：读取线程持续排空 stdout/stderr，分别设置容量和总上限，达到上限仍排空但不继续累积；不得以等待管道 EOF 作为唯一完成条件。主函数返回后应快速发送一次结果并关机；若模块留下线程、FD 或破坏 agent，宿主 TTL 直接杀 VM，不复用 guest。运行任意用户上传 ELF、开放共享目录或启用宿主网络均不属于首轮契约；Python/Node/JVM 模板必须各自经签名制品和真实兼容矩阵准入。

上游现成的 C 导出 `osv_run_app` 可用于固定路径的可行性测试，但其实现对模块加载失败使用 `assert`。产品 agent 必须改用捕获加载异常的安全包装，不允许把未验证请求路径直接传给此函数。固定镜像内模块的参数和退出码真机验证只证明加载能力，不等于上述产品协议或输出收尾完成。

## 门禁与证据

顺序为：固定上游/API/FD 语义核查，协议和后端自评审，host/guest parser 负向测试，构建真实 OSv agent 镜像，指定服务器 API→launcher→jailer→VM→agent→签名模块 E2E，覆盖正常/非零退出、argv、输出洪泛、后代持有 FD、guest 崩溃、取消、超时、重放/错误 job ID、manifest 过期、无 NIC 与清理。随后做压力、模板兼容与独立安全评审。未完成这些门禁时生产配置仍应拒绝 `firecracker-osv`，不能以诊断 vsock 测试宣称产品 agent 就绪。

依据：本仓库固定 OSv 上游 `include/osv/app.hh`、`include/osv/run.hh`、`fs/vfs/kern_descrip.cc` 与 [ADR-0006](0006-osv-native-vsock.md) 的真实传输结果。
