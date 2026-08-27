# Firecracker + 最小 Linux AI Agent Sandbox

## 1. 选型结论

直接使用 Firecracker + Linux 适合需要 shell、`fork/exec`、多个命令和标准 Linux 工具的通用 AI Agent。OSv 路径仍适合单个预编译执行器，启动和常驻内存更小，但它不提供通用 Linux 多进程及多用户语义。两条路径共用 Go 控制面，互不替代：

| 路径 | 主要用途 | 兼容性 | 本机实测冷启动 |
|---|---|---|---:|
| Firecracker + OSv | 单进程、预链接工具 | 较窄 | result p50 27.2 ms（128 MiB、direct 基线） |
| Firecracker + 最小 Linux | shell/coding agent、任意 allowlist executable | 标准 Linux syscall/process | API p50 937.9 ms（256 MiB、jailer、含 scratch） |
| QEMU microvm + OSv | 兼容和差异诊断 | OSv 单进程 | result p50 107.6 ms（128 MiB） |

这里的 “Firecracker” 和 “KVM” 不是互斥选项：Firecracker 与 QEMU 都通过 `/dev/kvm` 使用 KVM；真正比较的是精简 VMM 与通用 QEMU 设备模型。上述三组口径和配置不同，不能把数值解释为纯 VMM 开销。

本文件保留 backend 原理与 2026-08-26 基线；当前双进程、签名制品、mTLS、全 cgroup 和故障恢复部署见 [生产手册](PRODUCTION.zh-CN.md)。

## 2. 已实现架构

```text
Agent Orchestrator
        │ HTTPS + TLS 1.3 mTLS + tenant bearer
        ▼
非 root Go osv-sandboxd
  ├─ 严格 schema、entrypoint allowlist、并发/CPU/RAM/timeout/output 策略
  ├─ tenant RBAC/rate/concurrency、metrics
  └─ private Unix RPC + SO_PEERCRED
        ▼
root-only launcher
  ├─ Ed25519 manifest/SBOM + root-owned path trust
  ├─ 每任务 jail root、只读 rootfs/input、clone scratch
  ├─ Firecracker jailer：唯一 UID/GID、cgroup v2、rlimit
  └─ durable lease、fsync audit、host-side virtio-vsock
        │ fc-agent/v1（argv 不进入 kernel cmdline）
        ▼
Firecracker + KVM，每请求一个 microVM
  ├─ vmlinux 6.18.44
  ├─ 64 MiB Debian 12/BusyBox ext4，作为只读 /dev/vda
  ├─ 每任务可写 /dev/vdb，挂载到 /workspace
  └─ Rust static PIE /sbin/agent-init（PID 1）
       ├─ mount、vsock accept、请求校验
       ├─ child setsid + UID/GID 10000 + no_new_privs + rlimits
       ├─ 并发读取 stdout/stderr，强制总输出预算
       ├─ deadline 后 kill 整个客体进程组
       └─ FC_AGENT_RESULT JSON，随后触发一次性 VM 退出
```

实现入口：

- Go backend：[`internal/sandbox/backend_linux.go`](../internal/sandbox/backend_linux.go)
- 生命周期和结果校验：[`internal/sandbox/manager.go`](../internal/sandbox/manager.go)
- Rust PID 1：[`linux-guest/src/main.rs`](../linux-guest/src/main.rs)
- rootfs 构建：[`deploy/linux-guest-rootfs.Dockerfile`](../deploy/linux-guest-rootfs.Dockerfile)
- 配置样例：[`examples/config.firecracker-linux.json`](../examples/config.firecracker-linux.json)
- API benchmark：[`cmd/linux-api-bench/main.go`](../cmd/linux-api-bench/main.go)

## 3. 生命周期与协议

1. launcher 启动时验证签名 manifest、SBOM、全部制品/VMM hash/size 和 root-owned 路径；doctor 另检查 KVM、swap、cgroup controller、CPU vulnerability、mTLS 与 tenant policy。
2. 每个请求获得并发令牌和控制面生成的 96-bit job ID，调用者不能伪造结果绑定 ID。
3. launcher 创建 0700 job 目录，以 reflink/sparse fallback staging kernel/rootfs，clone 可信 scratch template，并可离线构建只读 input ext4；没有 TAP、virtio-net、host directory share 或 Firecracker API socket。
4. jailer 完成 chroot、cgroup 和降权后，以 `--no-api --config-file /config.json` 启动 Firecracker。
5. Rust PID 1 监听固定 vsock port。Go 端发送单行 JSON：`protocol`、`job_id`、`argv[]`、剩余 deadline 和客体输出上限。
6. 客体只接受 1–65 个 argv、单参数最多 4096 bytes、总参数最多 32 KiB、最大 300 s timeout。命令以 argv API 启动，控制面没有 shell 拼接；只有明确 allowlist `/bin/sh` 时调用者才拥有 shell 语义。
7. 子进程在 `/workspace` 以 UID/GID 10000 运行，环境被清空重建，stdin 为 `/dev/null`，设置 `no_new_privs` 及 core/nofile/nproc/fsize rlimit。
8. 控制面仅接受 `protocol=fc-agent/v1` 且 job ID 精确匹配的 envelope。客体 timeout、非零退出、协议错误与 VMM 错误分别映射为不同状态。
9. VMM 退出、API 断开或 deadline 后，launcher 终止进程组并删除 job/cgroup；异常崩溃由持久 lease 在启动时安全对账。基础 rootfs 永不作为可写盘挂载。

## 4. 构建与部署

前置条件为 x86_64 Linux、KVM、Docker、Rust musl target、Go 1.23+、`e2fsprogs`、Firecracker 和同版本 jailer。Firecracker 官方文档要求生产使用 jailer 或等价约束，并建议为生产内核和 rootfs 建立自己的受控构建链，而不是永久依赖演示 artifact：

- <https://github.com/firecracker-microvm/firecracker/blob/main/docs/rootfs-and-kernel-setup.md>
- <https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md>

构建最小 rootfs 和获取官方 CI 内核：

```bash
rustup target add x86_64-unknown-linux-musl
./scripts/build-firecracker-linux-rootfs.sh
./scripts/fetch-firecracker-ci-kernel.sh
sha256sum build/linux-agent-rootfs.ext4 build/vmlinux-firecracker
```

验证所用内核来源固定为：

```text
https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/20260826-761f88fbb951-0/x86_64/vmlinux-6.18.44
SHA-256 435466ec838656f59e464ce941e7fe9f3697d5da6a73c5e5dad60dae5ad93ceb
```

CI artifact 适合复现本报告；生产必须使用受控源码构建、CycloneDX SBOM 和离线 Ed25519 签名，并按 [生产手册](PRODUCTION.zh-CN.md)部署两个 systemd 服务。禁止用开发配置让网络 API 以 root 运行。

## 5. 安全特性与边界

| 风险 | 已实施措施 | 尚需生产增强 |
|---|---|---|
| VMM/guest 逃逸 | 每任务 KVM VM；Firecracker 1.16.1；精简设备；jailer chroot/降权/seccomp | CVE SLA、内核/VMM 自动轮换、逃逸演练 |
| artifact 篡改 | Ed25519 manifest、SBOM、VMM/kernel/rootfs hash/size、root path trust、rootfs block 只读 | 发布账户隔离、可选 dm-verity、CVE SLA |
| 宿主文件访问 | 无共享目录；只读 input ext4；独立 scratch | 大对象通道与输出盘离线验证/擦除 |
| 网络外泄 | 配置只接受 `network=none`；VM 无网卡 | 如需出网，独立 netns/TAP + 认证 egress proxy，不直接 NAT |
| 命令注入 | argv JSON/vsock；全局+租户 entrypoint allowlist；参数/总长度限制 | 协议持续 fuzz |
| 资源 DoS | CPU/memory/swap/pids/io cgroup；rlimit；tenant rate/concurrency；guest rlimits | 多节点容量与 PSI 自动隔离 |
| 残留 | systemd cgroup、进程组、deadline、durable lease、启动 orphan reconciliation | 周期性故障演练 |

Firecracker 官方设计把 KVM、jailer 和默认 seccomp 过滤器作为纵深防御的一部分，但 microVM 仍不是“绝对安全”：<https://github.com/firecracker-microvm/firecracker/blob/main/docs/design.md>。当前 rootfs 内的 BusyBox shell 是刻意提供给不可信任务的客体能力；安全边界是 microVM，不是客体 UID 10000 本身。

## 6. 2026-08-26 裸机验证

环境为隔离的 x86_64 KVM 裸机、Debian 12、Linux 6.1 系列和 Firecracker/jailer 1.16.1；可识别硬件信息不进入仓库。请求为 256 MiB、1 vCPU、256 MiB scratch、jailer、无 snapshot。原始采集文件由受控发布流水线留存，Git 仅保存去标识化汇总。

| 项目 | 结果 |
|---|---:|
| doctor | artifacts/Firecracker/KVM/jailer/mkfs 全部通过 |
| `/bin/echo` 完整冷启动 | 782 ms；guest command 8 ms |
| 串行，30 jobs（最终二进制） | 30/30；p50 939.396 ms；p90 994.934 ms；p99 1,048.222 ms；1.052 jobs/s |
| 并发 8，64 jobs（最终二进制） | 64/64；p50 1,007.041 ms；p90 1,564.810 ms；p99 1,747.977 ms；7.357 jobs/s |
| 运行中 VMM RSS | 70,092 KiB（单次时点样本，不是 guest memory 上限） |
| VMM 进程属性 | UID/GID 65534；2 threads；`CapEff=0`；`Seccomp=2` |
| cgroup | `memory.current=70,471,680`；`memory.max=402,653,184` bytes |
| 客体身份 | `uid=10000(agent) gid=10000(agent)` |
| 文件隔离 | `/workspace` 可写；只读根目录写入失败 |
| 网络隔离 | metadata 地址返回 `Network is unreachable` |
| 2 s timeout | `timed_out`；guest 进程组退出 137；端到端 1,870 ms |
| 输出洪泛 | 200,000 bytes 输入被截为 174,080 bytes；协议仍有效 |

当前约 0.8–1.0 s 的主要代价是完整 Linux 冷启动。生产实现已加入 artifact reflink/sparse fallback 和 scratch template clone；它仍不是 Firecracker snapshot 指标。

同配置第二组并发 8 样本得到 7.624 jobs/s、p99 1,151.546 ms，说明未固定 CPU/NUMA 的短样本尾延迟存在明显抖动；当前容量规划应采用较保守的最终组结果，并在 10k+ 固定拓扑测试后再设 SLO。

下一阶段是固定 CPU/NUMA 后测 10k jobs、24h/7d soak、p99.9 与 page-cache cold/warm。默认不复用 snapshot：Firecracker 官方明确警告同一 snapshot 多次恢复会复制 entropy/唯一标识；没有经过验证的强唯一性重建机制时不应启用。

## 7. 当前非目标

- 未实现网络 egress、文件上传下载、持久 volume、GPU、OCI 镜像或包管理器动态安装。
- 未实现 snapshot/VM pool，因此当前指标不能满足几十毫秒级 coding-agent 启动 SLO；这是默认安全决策。
- 代码级生产隔离已经实现；互联网高价值场景仍需完成组织级 soak、fuzz、CVE/密钥 SLA 和安全评审。
- 当前只有 x86_64 构建和实测；aarch64 需要对应 kernel、musl target 与裸机回归。
