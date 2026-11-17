# Agent Sandbox

2026.11.17：Linux x64 / aarch64 离线安装运行版本。发布范围、门禁结果和隐私说明见 [公开验收摘要](PUBLIC-QUALIFICATION.md)；机器可读结果见 [RELEASE-QUALIFICATION.json](RELEASE-QUALIFICATION.json)。

Go 控制面配合 Rust 客体执行器。Firecracker + 最小 Linux 提供通用 Agent 所需的 shell、fork/exec 和标准 Linux 语义；OSv 提供单进程工具执行路径。每个一次性任务或 session 使用独立 KVM microVM。

本版真实 KVM warm 启动 p50/p95/p99：Linux 3.057/6.377/12.531 ms；OSv 2.396/3.419/3.928 ms。每条路线 1000 个正式样本，warm 门槛 5/9/15 ms。完整 HTTP 和补池可用性分别计时。

本轮覆盖一般安全基线、双架构离线包、x64 真实 KVM 功能和 aarch64 无网络 QEMU。aarch64 KVM、K8s、自定义域名 TLS 和离线源码重建不属于本轮验收范围。

GitHub 源码和附件经过[隐私门禁](docs/adr/0129-github-publication-privacy.md)：排除服务器操作身份、凭据、私有目录、业务数据与原始验收日志。
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
- 已认证的 `GET /v1/capabilities` 和显式绑定后端/签名模板的 `POST /v2/jobs`；
- 租户可见的 `GET /v2/templates`、按签名摘要查询能力与实际模板结果绑定；Linux/OSv 共用控制面和资源预算；
- Linux `POST /v2/sessions` 与命令/文件读写、列表、元数据、删除及会话查询/关闭接口：同一 VM 连续执行、租户配额持有、租期与断连回收；
- Ed25519 签名 artifact manifest、有效期、SBOM、VMM/kernel/rootfs hash/size；
- durable lease、启动孤儿对账、进程组强制终止与 workdir/cgroup 回收；
- `osv-agent/v1` 任务 ID 绑定的结构化结果协议；
- `firecracker-linux` backend、virtio-vsock `fc-agent/v1`、只读 Linux rootfs/输入 ext4、每任务 reflink scratch；
- Linux Rust PID 1：客体 UID/GID 降权、`no_new_privs`、rlimit、工作负载专属cgroup/subreaper、timeout和并发输出截断；
- host doctor、Go/Rust 单元测试、mock 集成测试和真实 KVM benchmark 工具。
- x64 与 aarch64 分架构、签名校验的离线发布包；运行制品保存在项目内 `assets/offline/`。
- 共用 pristine warm VM pool：按签名规格预启动、一次领取后销毁、物理/active 分账、前台优先、有界补池、独占 owner 与崩溃对账；[rc68](PUBLIC-QUALIFICATION.md#private-evidence)补齐全局最低水位/公平补池、跨模板供给回收与 OSv 正式代码通路。当前 warm 目标按用户要求调整为 [5/9/13 ms](docs/adr/0114-warm-start-five-nine-thirteen.md)；完整性能、正式签名与宿主生产就绪门槛继续跟踪。
- 零第三方依赖的 [Python 客户端](sdk/python/README.md)，随双架构离线包签名分发，默认绑定 v2 签名模板。
- 零 npm 运行依赖的 [Node.js / TypeScript 客户端](sdk/node/README.md)，同样随双架构包签名分发。
- 静态 [MCP stdio 网关](docs/MCP.zh-CN.md)，支持2026-07-28和2025-11-25，经同一认证API提供执行、文件、模板、会话和后台命令工具，随双架构离线包分发。
- 可选的[认证HTTP egress服务](docs/EGRESS.zh-CN.md)，提供API/MCP/双SDK网络fetch及授权的Linux guest代理，精确origin/IP规则、固定DNS拨号、重定向与独立资源/审计，随包提供CA。

重要边界：OSv 不提供传统 Linux 多进程模型，`fork()`/`vfork()` 是 stub，且客体内没有多用户权限边界。因此它适合运行“单个、预构建、将工具链接进进程”的 Agent executor，不适合直接运行依赖 shell、包管理器及任意子进程的通用 coding agent。安全边界来自 KVM/Firecracker，而不是 OSv 客体内部。

详细材料：

- [原方案评估与优化基线](docs/ASSESSMENT.zh-CN.md)
- [架构决策 ADR](docs/adr/README.md)与[需求跟踪矩阵](docs/REQUIREMENTS.zh-CN.md)
- [CI、E2E 与分层回归策略](docs/TEST-STRATEGY.zh-CN.md)
- [架构与安全设计](docs/DESIGN.zh-CN.md)
- [特性与性能指标](docs/METRICS.zh-CN.md)
- [验证方法与生产验收步骤](docs/VALIDATION.zh-CN.md)
- [Firecracker + 最小 Linux 方案、部署与实测](docs/FIRECRACKER-LINUX.zh-CN.md)
- [完整生产部署、安全与运维手册](docs/PRODUCTION.zh-CN.md)
- [x64 / aarch64 Linux 离线发布与验收](docs/OFFLINE-RELEASE.zh-CN.md)
- [原生 gRPC 控制接口](docs/GRPC.zh-CN.md)

## 推荐路径

| 工作负载 | 后端 | 说明 |
|---|---|---|
| 通用 coding agent、shell、多进程工具 | `firecracker-linux` | 生产默认；Firecracker+jailer+最小 Linux+vsock |
| 签名的 OSv 原生模块 | `firecracker-osv` | 独立 vsock 任务协议；当前完成诊断真机验收，生产门禁仍关闭 |
| 兼容性与差异诊断 | `qemu` + OSv | 设备面更大，不作为通用 Agent 的生产默认 |

Firecracker 和 KVM 不是二选一：Firecracker 是使用 `/dev/kvm` 的精简 VMM；无 KVM 时不能获得这里设计的硬件虚拟化安全边界。

## 快速验证

无需 KVM 即可验证控制面、Rust 协议和命令生成：

```bash
python3 -m venv build/tools/python-validation
build/tools/python-validation/bin/python3 -m pip install --no-index --require-hashes \
  --find-links assets/build/python-validation -r deploy/requirements-validation.txt
source build/tools/python-validation/bin/activate
./scripts/verify.sh
```

上述固定 Python 工具仅用于构建/CI，不增加目标机的离线运行依赖；项目内 wheel 覆盖 Linux x64/aarch64 的 CPython 3.10、3.11、3.12。安全查询、离线重放与正式构建要求见[漏洞证据说明](docs/SECURITY-EVIDENCE.zh-CN.md)。

OSv 原生 virtio-vsock 目前处于独立验收阶段。固定上游提交 `0e34e4dc2b278b7f64e4169abbf297b7de46fb6b` 放在忽略目录 `osv-upstream/`，所需子模块为 musl、kbuild、ACPICA 和 apps。构建器由 `deploy/osv-native-builder.Dockerfile` 生成；离线构建与真机结果见 [原生 vsock 验收](PUBLIC-QUALIFICATION.md#private-evidence)：

```bash
bash scripts/test-osv-vsock-protocol.sh
bash scripts/build-osv-native-vsock-test.sh
```

`/vsock-test.so` 是早期驱动夹具；后续已构建原生任务 agent，并完成 API→launcher→KVM 的签名模板诊断验收。transport reset、持续压力和 OSv 生产门禁仍在[需求矩阵](docs/REQUIREMENTS.zh-CN.md)中跟踪。

构建通用 Linux Agent 客体：

```bash
./scripts/build-firecracker-linux-rootfs.sh
./scripts/fetch-firecracker-ci-kernel.sh
```

默认 `ci` 模式执行 Go test/vet/race、两个 Rust crate 的 test/clippy/release build、Python/Node 客户端契约测试，以及 JSON、shell 和文档结构检查；`quick` 模式省略 race、静态分析和构建。完整基准不放在开发快检中。systemd/宿主安全配置由 production-preflight 和真机验收分别验证，不能以快检替代。生成物位于已忽略的 Cargo target 或临时缓存目录。

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

查询当前租户可见的后端与能力：

```bash
curl -sS http://127.0.0.1:8080/v1/capabilities \
  -H "Authorization: Bearer $OSV_SANDBOX_TOKEN"
```

能力报告是支持范围，实时可用性仍由 `/readyz` 和 `/v1/doctor` 判定。

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

[审计成对提交实际对照](PUBLIC-QUALIFICATION.md#private-evidence)532次请求全部成功，但warm p95回退，不采用该实验，当前产品保持rc87。[物理余量对照](PUBLIC-QUALIFICATION.md#private-evidence)532次全成功，4槽改善p95/供给，但按当时规格和预定采用标准仍不采用；按[目录同步观察设计](docs/adr/0113-owned-directory-sync-observation.md)继续定位准入/归属等待，正式门禁保持。
