# Agent Sandbox

这是一个 Go 控制面 + Rust 客体执行器的 AI Agent microVM sandbox。项目保留两条明确分工的客体路径：生产主路径使用 Firecracker + 最小 Linux，服务需要 shell、`fork/exec` 和标准 Linux 语义的通用 Agent；OSv unikernel 路径服务极低延迟的单进程预编译工具。两者都以“每任务一个 KVM microVM”作为安全边界。

当前仓库已经实现生产代码路径与部署加固，但“可直接承载任意互联网恶意负载”仍需要使用方完成固定硬件长稳压测、持续 CVE/SBOM 治理、密钥轮换、逃逸演练及独立安全评审，详见[生产手册](docs/PRODUCTION.zh-CN.md)。

当前实现提供：

- QEMU `microvm` 和 Firecracker 两个启动后端；
- root-only Firecracker launcher 与非 root HTTPS API 的进程拆分，Unix `SO_PEERCRED` 绑定；
- Firecracker jailer：每任务 chroot、唯一 UID/GID、默认 seccomp、精确 capability/systemd hardening；
- 固定入口点、CPU/内存/并发/超时/输出上限；
- 默认完全禁网、ROFS 根镜像、无共享宿主目录；
- 内核和镜像路径约束及 SHA-256 校验；
- QEMU 设备裁剪与 `-sandbox` 加固；
- cgroup v2 CPU/memory/swap/pids/I/O 硬限制与 KVM PIT thread 归组；
- TLS 1.3 mTLS、租户 bearer hash/RBAC/rate/concurrency、Prometheus 与 fsync audit；
- Ed25519 签名 artifact manifest、有效期、SBOM、VMM/kernel/rootfs hash/size；
- durable lease、启动孤儿对账、进程组强制终止与 workdir/cgroup 回收；
- `osv-agent/v1` 任务 ID 绑定的结构化结果协议；
- `firecracker-linux` backend、virtio-vsock `fc-agent/v1`、只读 Linux rootfs/输入 ext4、每任务 reflink scratch；
- Linux Rust PID 1：客体 UID/GID 降权、`no_new_privs`、rlimit、进程组 timeout 和并发输出截断；
- host doctor、Go/Rust 单元测试、mock 集成测试和真实 KVM benchmark 工具。

重要边界：OSv 不提供传统 Linux 多进程模型，`fork()`/`vfork()` 是 stub，且客体内没有多用户权限边界。因此它适合运行“单个、预构建、将工具链接进进程”的 Agent executor，不适合直接运行依赖 shell、包管理器及任意子进程的通用 coding agent。安全边界来自 KVM/Firecracker，而不是 OSv 客体内部。

详细材料：

- [架构与安全设计](docs/DESIGN.zh-CN.md)
- [特性与性能指标](docs/METRICS.zh-CN.md)
- [验证方法与生产验收步骤](docs/VALIDATION.zh-CN.md)
- [Firecracker + 最小 Linux 方案、部署与实测](docs/FIRECRACKER-LINUX.zh-CN.md)
- [完整生产部署、安全与运维手册](docs/PRODUCTION.zh-CN.md)

## 推荐路径

| 工作负载 | 后端 | 说明 |
|---|---|---|
| 通用 coding agent、shell、多进程工具 | `firecracker-linux` | 生产默认；Firecracker+jailer+最小 Linux+vsock |
| 单个预链接执行器 | `firecracker` + OSv | 更低启动开销，但不支持通用多进程 Linux 语义 |
| 兼容性与差异诊断 | `qemu` + OSv | 设备面更大，不作为通用 Agent 的生产默认 |

Firecracker 和 KVM 不是二选一：Firecracker 是使用 `/dev/kvm` 的精简 VMM；无 KVM 时不能获得这里设计的硬件虚拟化安全边界。

## 快速验证

无需 KVM 即可验证控制面、Rust 协议和命令生成：

```bash
./scripts/verify.sh
```

构建通用 Linux Agent 客体：

```bash
./scripts/build-firecracker-linux-rootfs.sh
./scripts/fetch-firecracker-ci-kernel.sh
```

脚本会执行 Go test/vet、两个 Rust crate 的测试与 release build，以及 JSON、shell、systemd 和安全配置检查。生成物全部位于已忽略的 `build/` 或 Cargo `target/`。

开发配置只用于本机功能验证；承载不可信任务时必须使用 [生产手册](docs/PRODUCTION.zh-CN.md)中的签名制品、mTLS、租户策略及双进程 systemd 部署。API 进程以静态非 root 用户运行，只有不监听 TCP 的 launcher 持有 jailer/KVM 所需权限。

通用 Linux 客体构建完成后，以 [生产配置模板](examples/config.production.json)为起点，生成 SBOM 和签名 manifest，再安装两个 systemd unit：

```bash
sudo ./deploy/install-production.sh
sudo ./scripts/production-preflight.sh
```

安装脚本不会自动启用服务；只有证书、tenant auth policy、签名制品和 doctor 全部就绪后才能接入流量。

生成 OSv ROFS 镜像需要 64 位 Linux、完整上游源码和构建依赖。`osv-upstream/` 是本地依赖目录，不提交本仓库：

```bash
git clone https://github.com/cloudius-systems/osv.git osv-upstream
git -C osv-upstream checkout 0e34e4dc2b278b7f64e4169abbf297b7de46fb6b
git -C osv-upstream submodule update --init --recursive
./osv-upstream/scripts/setup.py
./scripts/build-osv-agent-image.sh
```

脚本输出 `loader-stripped.elf`、`usr.img` 及其 SHA-256。复制 [QEMU 配置示例](examples/config.qemu.json)，填写产物路径和哈希后运行：

```bash
export OSV_SANDBOX_TOKEN='replace-with-a-long-random-token'
go build -trimpath -o osv-sandboxd ./cmd/osv-sandboxd
./osv-sandboxd -config config.json -doctor
./osv-sandboxd -config config.json
```

提交同步任务：

```bash
curl -sS http://127.0.0.1:8080/v1/jobs \
  -H "Authorization: Bearer $OSV_SANDBOX_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"entrypoint":"/agent","args":["echo","hello"],"memory_mib":128,"vcpus":1,"timeout_ms":30000}'
```

真实 KVM 节点可用同一生产 backend 逻辑比较 QEMU 与 Firecracker：

```bash
go build -trimpath -o osv-bench ./cmd/osv-bench
./osv-bench -backend both -iterations 100 -warmup 10 -concurrency 1 \
  -operation probe -output results.json
```

去标识化实测汇总见 [特性与性能指标](docs/METRICS.zh-CN.md)。原始 benchmark、宿主环境和验证日志可能包含机器指纹，作为受控流水线制品留存，不提交 Git。生产 unit 位于 [launcher service](deploy/systemd/osv-sandbox-launcher.service) 与 [API service](deploy/systemd/osv-sandboxd-production.service)；旧 direct-mode unit 只用于开发和回归。

## 上游基线

研究和实现基于 `cloudius-systems/osv` 提交 `0e34e4dc2b278b7f64e4169abbf297b7de46fb6b`。上游源码按需克隆到已忽略的 `osv-upstream/`；本项目控制面和客体代码与其隔离，便于更新和审计。

## License

[BSD 3-Clause](LICENSE)
