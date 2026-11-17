# 特性与性能实测

## 1. 已实现特性

| 类别 | 指标/行为 | 状态 |
|---|---|---|
| 隔离粒度 | 每个请求一个 OSv microVM | QEMU+KVM、Firecracker+KVM 均实机通过 |
| 生产封装 | root launcher + 非 root API、Firecracker jailer、唯一 UID/GID、每任务 chroot | 实机通过 |
| 网络 | 默认且仅允许 `none` | 强制并实测不可达 |
| 根文件系统 | OSv ROFS，VMM block device read-only | 强制并实测写入失败 |
| 入口点 | 默认仅 `/agent`，精确 allowlist | 强制 |
| 资源 | vCPU、RAM、timeout、并发、输出上限 | cgroup v2 cpu/memory/swap/pids/io、rlimit、租户 rate/concurrency 均强制 |
| 供应链 | Ed25519 manifest、SBOM、kernel/rootfs/Firecracker/jailer hash/size、root path trust | 强制；篡改单测和远端签名启动通过 |
| 结果完整性 | `osv-agent/v1` + 控制面生成的 96-bit job ID | 强制并实测 |
| API | TLS 1.3 mTLS、hashed bearer、租户 RBAC、严格 schema 与 timeout | 已实现并实机拒绝无证书/错误 token/越权入口 |
| 回收 | process group、systemd cgroup、durable lease、启动对账 | API/launcher crash 注入后进程、workdir、cgroup 均为零残留 |
| 可观测性 | JSON log、root fsync audit、Prometheus、doctor、benchmark | 已实现并实机通过 |
| 可选OTLP源码接入 | API指标、日志、server span及有界队列/计损/退出 | [33项native/同名ARM及实际非root API/官方Collector通过](../PUBLIC-QUALIFICATION.md#private-evidence)；新完整离线候选与指定机KVM待验收，不替代原性能门禁 |

## 2. 测试环境与口径

基准在隔离的 x86_64 KVM 裸机上执行；可识别硬件型号、CPU/RAM 组合和宿主标识不进入源码仓库。软件基线为 Debian 12、Linux 6.1 系列、QEMU 7.2.22、Firecracker/jailer 1.16.1；客体为 OSv `v0.57.0-398-g0e34e4dc`、128 MiB、1 vCPU、同一个只读 Rust executor 镜像。

主要口径：

- `result latency`：VMM `Start()` 到读到匹配 job ID 的有效 guest envelope；这是本文的“冷启动到可用结果”。
- `process latency`：VMM `Start()` 到进程完全退出，包含 Firecracker guest shutdown 尾部。
- warm：先预热再测，宿主页缓存自然保留。
- artifact-cache-evicted：每次任务前对 kernel 和对应 image 调用 `fadvise(DONTNEED)`；它不是重启物理机、清空全部 Linux cache 的绝对冷机测试。
- RSS：1 ms 轮询 `/proc/<pid>/status` 的 `VmRSS`，是 VMM 进程 RSS，不等同于 guest 配置内存，也不含控制面。
- 每组 QEMU 与 Firecracker 是顺序运行，未做 CPU pinning/NUMA pinning；数据适合本机选型，不应直接成为其他硬件的 SLO。

原始样本与环境字段可能包含宿主指纹，作为受控发布流水线制品留存，不提交 Git；仓库只保留下述去标识化汇总。

## 3. 冷启动、RSS 与吞吐

### 并发 1，warm，100 次

| 指标 | QEMU microvm + KVM | Firecracker + KVM | Firecracker 差异 |
|---|---:|---:|---:|
| 成功率 | 100/100 | 100/100 | 相同 |
| result p50 | 107.620 ms | 27.204 ms | 降低 74.7%，约 3.96× 快 |
| result p99 | 136.190 ms | 77.746 ms | 降低 42.9% |
| process p50 | 183.642 ms | 95.863 ms | 降低 47.8% |
| process p99 | 227.760 ms | 171.579 ms | 降低 24.7% |
| VMM RSS p50 | 62,444 KiB | 24,984 KiB | 降低 60.0%，约为 QEMU 的 40% |
| 吞吐 | 5.50 jobs/s | 9.23 jobs/s | 提高 67.7% |

OSv 自身串口报告的 boot 时间约为 6.4–9.0 ms。它只覆盖客体内启动，不包含进程创建、VMM 初始化、artifact 打开、结果读取和 VMM 退出，所以不能拿它替代端到端 `result latency`。

### 并发 1，artifact cache eviction，50 次

| 指标 | QEMU microvm + KVM | Firecracker + KVM |
|---|---:|---:|
| 成功率 | 50/50 | 50/50 |
| result p50 / p99 | 110.835 / 143.008 ms | 29.837 / 82.071 ms |
| process p50 / p99 | 190.474 / 234.330 ms | 101.916 / 189.823 ms |
| RSS p50 / p99 | 62,508 / 64,828 KiB | 24,984 / 24,992 KiB |
| 吞吐 | 5.28 jobs/s | 8.33 jobs/s |

### 并发扩展，warm

| 并发与样本 | 后端 | 成功 | 吞吐 jobs/s | result p50 | result p99 | RSS p99 |
|---|---|---:|---:|---:|---:|---:|
| c=8, n=100 | QEMU | 100 | 39.31 | 93.481 ms | 148.432 ms | 64,556 KiB |
| c=8, n=100 | Firecracker | 100 | 57.07 | 27.369 ms | 51.068 ms | 24,988 KiB |
| c=32, n=128 | QEMU | 128 | 97.02 | 150.706 ms | 256.231 ms | 63,392 KiB |
| c=32, n=128 | Firecracker | 128 | 146.00 | 53.559 ms | 117.131 ms | 24,988 KiB |

在 c=8 和 c=32 时，Firecracker 吞吐分别高 45.2% 和 50.5%，result p99 分别低 65.6% 和 54.3%。本机因此明确选择 Firecracker+jailer 为生产主路径，QEMU 保留为兼容、诊断和差异回归后端。

## 4. 攻击面实测

| 观察项 | QEMU 7.2.22 | Firecracker 1.16.1（直接 VMM） |
|---|---:|---:|
| 主二进制大小 | 18,397,984 B | 3,527,456 B |
| 链接方式 | 动态；`ldd` 输出 51 行 | static PIE |
| peak threads | 4–5 | 2 |
| peak memory mappings | 342–343 | 27–29 |
| peak FDs | 17 | 23 |
| 观察到的 seccomp mode | 2 | 2 |
| `CapEff` | 0 | 0 |
| `strace -f -c` syscall 种类 | 49 | 39 |
| 单次 profile syscall 总数 | 2,806 | 1,553 |

syscall 数量受启动路径、日志和 tracer 干扰，只用于描述本次最小设备模型的相对 host 接触面，不能证明没有 VMM 漏洞。原始 syscall 文件不提交源码仓库。

jailer 运行中另外从宿主 `/proc` 和 cgroup v2 实测：Firecracker 的 real/effective/saved/fs UID/GID 均为 65534，`CapEff=0`、`Seccomp=2`、2 线程，cgroup 路径为 `/firecracker/<job-id>`，`memory.max=268435456`（128 MiB guest + 128 MiB VMM overhead）。每任务 jail 在结束后被清理。

客体 `isolation-probe` 在 QEMU、直接 Firecracker 和 jailer Firecracker 上均观察到：

- `/sandbox-write-probe` 创建失败；
- `169.254.169.254:80` 与 `127.0.0.1:9` 连接失败；
- `/dev` 只有 `console`、`null`、`random`、`urandom`、`vblk0`、`vblk0.1`；
- 无网卡、无 host directory share，基础镜像测试后 SHA-256 不变。

## 5. 上游参考与生产门槛

OSv 上游把项目定义为运行单个 Linux 应用的 unikernel，并明确支持 QEMU/KVM、Firecracker 及 Rust；其 README 中约 3–5 ms 的 ROFS/microvm 数字是不同环境的客体启动参考，不能替代上述端到端实测：<https://github.com/cloudius-systems/osv>。Firecracker 官方生产文档要求使用 jailer 或同等严格约束：<https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md>。

代码层生产门槛已经实现：CPU/pids/I/O cgroup、特权 launcher 拆分、签名/SBOM、租户认证审计和基础故障注入均完成。组织上线仍需 10k+ 固定 CPU/NUMA 基准、24h/7d soak、逃逸漏洞响应演练、串口/vsock flood/fuzz、密钥轮换、远程不可变审计和容量灰度；这些是环境与运营验收，不能由单次开发验证替代。

## 6. Firecracker + 最小 Linux 路径

为支持 shell、`fork/exec` 和通用 coding agent，项目新增了不依赖 OSv 的 `firecracker-linux` backend。2026-08-26 direct/jailer 基线为：256 MiB guest、每任务 256 MiB scratch，串行 30/30 成功、API p50 939.396 ms、吞吐 1.052 jobs/s；并发 8 时 64/64 成功、p99 1,747.977 ms、吞吐 7.357 jobs/s。运行中单 VMM 时点 RSS 为 70,092 KiB。

2026-08-27 又在相同裸机验证完整生产链路：TLS 1.3 mTLS、非 root API、root launcher、签名 manifest/SBOM、唯一 jail identity、全 cgroup 限制、只读 input disk、reflink scratch 与 hardened systemd unit。结果如下：

| 样本 | 成功 | HTTP p50 | HTTP p90 | HTTP p99/max | 吞吐 |
|---|---:|---:|---:|---:|---:|
| c=1, n=12 | 12/12 | 922.554 ms | 947.440 ms | 957.270 ms | 1.085 jobs/s |
| c=4, n=24 | 24/24 | 956.271 ms | 1044.546 ms | 1112.737 ms | 4.020 jobs/s |

现场并发 VM 使用不同 UID 200003/200004。1 vCPU/256 MiB guest 的 VMM RSS 为 70,088 KiB，cgroup `memory.current=70,463,488`；2 vCPU/512 MiB 为 74,184 KiB 和 75,120,640。两者都观测到 `memory.swap.max=0`、`pids.max=64` 与 `io.max="8:0 rbps=104857600 wbps=52428800"`。API 进程终止会通过 RPC EOF 立即取消 VM；强杀 launcher 后 systemd 自动重启，lease reconciliation=1，进程、workdir、cgroup 均零残留。

这组数据包含完整 Linux 启动、artifact staging、命令和关机，且没有 snapshot，不能与前面的 OSv direct-mode 数据作纯 VMM 对照。生产实现已把每任务 scratch mkfs 优化为可信模板 clone，因此新数据比旧链路更稳定。原始生产样本不提交源码仓库；完整部署见 [生产手册](PRODUCTION.zh-CN.md)。
