# Firecracker AI Agent Sandbox 生产部署

## 1. 生产形态与结论

通用 AI Agent sandbox 的生产主路径是 `Firecracker + KVM + 最小 Linux`，不使用 OSv。OSv 路径仍保留给预编译、单进程、无需 `fork/exec` 的极低延迟工具；需要 shell、子进程、标准 Linux 文件权限和通用 CLI 的 coding agent 使用本路径。

生产进程被拆成两个信任域：

```text
Agent/Orchestrator
  │ HTTPS, TLS 1.3, required client certificate, bearer tenant identity
  ▼
osv-sandboxd (static non-root user)
  ├─ strict JSON and request limits
  ├─ tenant RBAC, token bucket and concurrency quota
  ├─ Prometheus metrics and structured log
  └─ private Unix RPC; SO_PEERCRED-bound UID
  ▼
osv-sandbox-launcher (root, no TCP/IP socket)
  ├─ signed manifest/SBOM and root-owned path verification
  ├─ durable lease, orphan reconciliation and append-only audit
  ├─ Firecracker jailer, unique UID/GID and cgroup v2
  └─ immutable root/input disks plus disposable scratch disk
  ▼
one Firecracker microVM per request
  └─ Rust PID 1 -> drops to guest uid/gid -> fork/exec allowlisted argv
```

root launcher 不解析公网协议、不保存 bearer 明文、不监听 TCP；API 用户不能打开 `/dev/kvm`、修改 cgroup、读取服务端私钥或访问制品目录。Unix socket 为 API UID 所有、`0600`，launcher 再用 `SO_PEERCRED` 校验连接进程的真实 UID。

## 2. 已强制的生产安全属性

| 层 | 强制属性 |
|---|---|
| Host | KVM 可用；cgroup v2 的 cpu/io/memory/pids controller；swap 必须关闭；CPU 漏洞报告不得为 Vulnerable/Unknown |
| API | 非 root；TLS 1.3；双向证书；SHA-256 bearer 映射租户；entrypoint RBAC；rate/burst/并发配额；1 MiB body 上限 |
| Launcher | root-only；唯一实例 `flock`；Unix peer credential；2 MiB RPC 上限；客户端断开即取消 VM |
| Supply chain | Ed25519 签名 manifest；有效期；kernel/rootfs/Firecracker/jailer/SBOM 的 hash 与 size；路径/父目录 root-owned 且不可被 group/other 写 |
| VM | 每任务唯一 jail UID/GID、chroot、mount namespace、Firecracker 默认 seccomp、无 capability、默认无网卡 |
| cgroup | `cpu.max`、`memory.max`、`memory.swap.max=0`、`memory.oom.group=1`、`pids.max`、`io.max`；KVM PIT thread 迁入同一 cgroup |
| Filesystem | rootfs 只读；input 独立 ext4 且 guest 以 ro,nodev,nosuid,noexec 挂载；scratch 独立、限额、任务后销毁；无 host directory share |
| Guest | Rust PID 1；固定协议/job ID；guest uid/gid 降权；`no_new_privs`；进程组 timeout；stdout/stderr 总量截断 |
| Recovery | VMM process group；API EOF cancellation；systemd `KillMode=control-group`；PID start-time lease；launcher 启动对账；workdir/cgroup 回收 |
| Audit | root `O_APPEND` JSONL，每请求 fsync；不记录 token、输入内容和完整任务输出；Prometheus 指标需要认证 |

当前网络策略是 fail-closed：配置只接受 `network=none`，Firecracker 配置中没有 NIC。需要访问模型服务时，优先让宿主编排层完成调用。若未来增加 egress，必须使用每 VM netns/TAP、认证代理及 L7 allowlist，不能直接给 microVM 做公网 NAT。

## 3. Host 基线

生产节点应为独占或可信工作负载节点，并执行：

```bash
sudo ./deploy/install-production.sh
sudo ./scripts/production-preflight.sh
```

必须满足：

- `/dev/kvm` 可读写，Firecracker 与 jailer 来自同一固定 release；
- unified cgroup v2 提供 `cpu io memory pids`；
- 禁用 swap；如组织策略必须使用 swap，应采用宿主级加密且完成风险评审，当前 doctor 仍会拒绝 ready；
- host kernel、CPU microcode、Firecracker、jailer 和 guest kernel 纳入补丁 SLA；
- `/var/lib/osv-sandbox/artifacts`、`/var/lib/osv-sandbox/run`、`/var/log/osv-sandbox` 及全部父目录为 root 所有且不可被非 root 写；
- identity pool 的 UID/GID 区间未分配给宿主账户，并且 `identity_pool_size >= max_concurrent`；
- 生产证书私钥和 auth policy 由 secret manager 原子发布，不放进仓库。

安装脚本只安装程序、目录和 systemd unit，不会在制品、签名、证书和租户策略尚未就绪时启用服务。

## 4. 构建、SBOM 与离线签名

构建并验证控制面和两个 Rust 客体：

```bash
GOCACHE=/tmp/osv-sandbox-go-cache GOTMPDIR=/tmp ./scripts/verify.sh
./scripts/build-firecracker-linux-rootfs.sh
./scripts/fetch-firecracker-ci-kernel.sh
```

生成 CycloneDX 1.5 SBOM：

```bash
go build -buildvcs=false -trimpath -o build/osv-sbom ./cmd/osv-sbom
build/osv-sbom \
  -kernel build/vmlinux-firecracker \
  -rootfs build/linux-agent-rootfs.ext4 \
  -agent linux-guest/target/x86_64-unknown-linux-musl/release/agent-init \
  -api build/osv-sandboxd -launcher build/osv-sandbox-launcher \
  -firecracker /usr/local/bin/firecracker -jailer /usr/local/bin/jailer \
  -output build/sbom.cdx.json
```

签名私钥只能存在于离线发布环境或 HSM；运行节点只部署 public key：

```bash
build/osv-artifact-manifest -generate-key-prefix /secure/offline/osv-artifacts
build/osv-artifact-manifest \
  -artifact-root build -kernel vmlinux-firecracker \
  -image linux-agent-rootfs.ext4 -sbom sbom.cdx.json \
  -firecracker /usr/local/bin/firecracker -jailer /usr/local/bin/jailer \
  -private-key /secure/offline/osv-artifacts.private \
  -valid-for 720h -output build/manifest.json
```

部署 `manifest.json`、`manifest.json.sig`、SBOM、kernel 和 rootfs 为 root:root `0444`。配置内 hash 仍保留，形成“配置 hash + 签名清单”的双重约束。manifest 过期、签名错误、大小/hash 不匹配、VMM 二进制变化或 SBOM 被替换都会阻止 launcher 启动。

## 5. 租户身份与 mTLS

复制 [auth policy 示例](../examples/auth.production.json)，为每个租户生成独立随机 bearer，仅把 SHA-256 写入 policy：

```bash
token=$(openssl rand -hex 32)
printf '%s' "$token" | sha256sum
```

明文 token 进入 secret manager，不能写日志、配置或命令历史。每个租户配置独立 entrypoint allowlist、requests/s、burst 和最大并发。全局 allowlist 与租户 allowlist 同时生效。

TLS 文件为：

```text
/etc/osv-sandbox/tls/server.crt     root:osv-sandbox 0644
/etc/osv-sandbox/tls/server.key     root:osv-sandbox 0640
/etc/osv-sandbox/tls/client-ca.crt  root:osv-sandbox 0644
```

服务端只接受 TLS 1.3，并要求客户端证书由指定 client CA 验证。公网部署仍建议前置具备连接限额、DDoS 防护和证书自动轮换的 L4/L7 gateway；gateway 到 daemon 的链路继续保留 mTLS。

## 6. 配置与启动

以 [生产配置示例](../examples/config.production.json) 为模板，至少替换制品 hash、签名 public key、证书、租户策略、监听地址和容量参数。`max_concurrent` 必须按内存容量计算：

```text
host_reserved + max_concurrent × (guest_memory + VMM_overhead + scratch_cache_budget) < host_memory
```

推荐保留 20% 以上 host headroom，并在固定 CPU/NUMA 后用压力测试确定实际值。启动顺序：

```bash
sudo systemctl start osv-sandbox-launcher.service
sudo systemctl start osv-sandboxd.service
curl --cacert ca.crt --cert client.crt --key client.key \
  -H "Authorization: Bearer $SANDBOX_TOKEN" \
  https://sandbox.example/v1/doctor
sudo systemctl enable osv-sandbox-launcher.service osv-sandboxd.service
```

只有 doctor 全部通过后才能 enable/接入流量。`/healthz` 仅表示进程存活，`/readyz` 执行完整 production doctor；生产 TLS 层会先要求客户端证书。`/v1/doctor` 和 `/metrics` 还需要 bearer。

提交带输入盘的任务：

```bash
curl --cacert ca.crt --cert client.crt --key client.key \
  -H "Authorization: Bearer $SANDBOX_TOKEN" \
  -H 'Content-Type: application/json' \
  https://sandbox.example/v1/jobs \
  -d '{"entrypoint":"/bin/cat","args":["/input/prompt.txt"],"input_files":[{"path":"prompt.txt","data":"aGVsbG8K","mode":292}]}'
```

`data` 是 base64；最多 64 个文件、总计 512 KiB，路径必须为干净相对路径，模式只允许十进制 `292`（八进制 `0444`）。当前小输入盘由 launcher 离线生成；大对象应进入独立对象存储通道，而不是扩大 JSON body。

## 7. 性能策略

每个请求仍创建新的 microVM，不跨租户复用 guest。优化来自：

- rootfs/kernel staging 优先 `FICLONE`，不支持时使用 sparse copy，再回退 full copy；
- launcher 启动时只创建一次可信 ext4 scratch template，每任务 reflink/clone；
- 无 Firecracker API round-trip，使用 `--no-api --config-file`；
- vsock 传 argv/result，避免把不可信参数放入 kernel cmdline；
- 容量由 cgroup 和 identity pool 预先界定。

默认不启用通用 snapshot restore。Firecracker 官方说明，同一 snapshot 多次恢复会复制 guest entropy 和唯一标识；除非 guest 有经过验证的强唯一性重建机制，否则这在安全上不可接受。snapshot 还要求内存/state 文件不可变、磁盘路径一致，并会重置既有 vsock 连接。生产默认选择每任务冷启动换取明确隔离语义。

在隔离的 x86_64 KVM 裸机上完成了 mTLS + 非 root API + root launcher + jailer + 最小 Linux 验收；可识别的硬件配置不进入仓库：

| 场景 | 成功 | HTTP p50/p99 | server p50 范围 | 吞吐 |
|---|---:|---:|---:|---:|
| c=1, n=12 | 12/12 | 922.554/957.270 ms | 0.76–0.81 s | 1.085 jobs/s |
| c=4, n=24 | 24/24 | 956.271/1112.737 ms | 0.73–0.91 s | 4.020 jobs/s |

1 vCPU/256 MiB VM 的现场 RSS 为约 68.4 MiB，2 vCPU/512 MiB 为约 72.4 MiB。以上每次都是新 VM，但 host page cache 已预热；它不是物理机重启后的绝对冷机 SLO。原始样本可能包含宿主信息，因此不提交源码仓库。

## 8. 监控、告警与运维

至少采集：任务 state/tenant、inflight、HTTP/auth failure、端到端直方图、launcher restart、doctor ready、host PSI、cgroup memory.events/pids.events/io.stat、KVM/Firecracker kernel log。推荐告警：

- ready 连续失败或 manifest 临近过期；
- launcher/API restart、orphan reconciliation 非零；
- p99 超 SLO、busy/429 或 guest protocol error 激增；
- cgroup OOM、pids max、I/O throttle 持续命中；
- audit fsync/磁盘空间失败；
- host swap 被重新启用或 CPU vulnerability 状态变化。

升级采用不可变制品和分批节点轮换：先离线签名，新节点 doctor/smoke/基准通过，再接流量。不要原地覆盖正在运行节点上的 Firecracker、jailer、kernel 或 rootfs，因为 launcher 会把二进制 hash 纳入签名验证。

故障恢复顺序：停止入口流量，检查 doctor 与两个 unit；launcher 重启会持有独占 run-root lock，读取 lease 中 PID、进程启动 tick 和 instance ID，确认匹配后才 kill，随后删除 workdir 与 cgroup。不可直接按进程名批量 kill，也不可手工删除仍有进程的 cgroup。

## 9. 安全边界与上线门槛

microVM 显著缩小攻击面，但不是“绝对安全”。它不防御恶意 root 管理员、宿主 kernel/KVM/CPU firmware 漏洞，也不替代秘密最小化。高价值生产上线还应完成组织侧工作：

- 10k+ 固定 CPU/NUMA 基准与 24h/7d soak；
- hypervisor escape、guest kernel exploit、OOM、I/O flood、串口/vsock flood、磁盘满和证书/manifest 过期演练；
- Go JSON/RPC/result parser 与 Rust guest protocol fuzz；
- CVE/SBOM 扫描、补丁 SLA、密钥轮换、审计日志远程不可变归档；
- 多节点调度、容量 headroom、灰度与回滚；
- 由安全团队根据数据敏感度确认残余风险。

上游生产要求与本设计依据见 Firecracker [production host setup](https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md)、[jailer](https://github.com/firecracker-microvm/firecracker/blob/main/docs/jailer.md)、[seccomp](https://github.com/firecracker-microvm/firecracker/blob/main/docs/seccomp.md) 和 [snapshot support](https://github.com/firecracker-microvm/firecracker/blob/main/docs/snapshotting/snapshot-support.md)。
