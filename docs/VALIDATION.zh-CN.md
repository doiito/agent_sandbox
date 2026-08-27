# 验证记录与复现方法

## 1. 验证结论

2026-08-26 已在指定 Debian 12 裸机完成 QEMU/Firecracker/OSv 真实 KVM 基线；2026-08-27 在同一机器完成 Firecracker + 最小 Linux 的生产链路验收：

- QEMU microvm + KVM：同一 OSv/Rust 客体启动、任务协议、只读盘和禁网验证通过；
- Firecracker + KVM：功能、冷启动、RSS、吞吐和 host 攻击面 profile 通过；
- Firecracker + jailer + KVM：Go API 完整链路通过，实际 UID/GID、capability、seccomp、chroot cleanup 与 cgroup memory 上限均验证；
- 100/50/100/128 次四组正式基准全部零失败；详细数字见 [特性与性能实测](METRICS.zh-CN.md)。
- TLS 1.3 mTLS、非 root API/root launcher、签名 manifest/SBOM、唯一 jail UID、CPU/memory/swap/pids/io cgroup、只读 input disk 和 hardened systemd unit 实机通过；
- 生产 API c=1 12/12 与 c=4 24/24 零失败，p50 分别 922.554/956.271 ms，吞吐 1.085/4.020 jobs/s；
- API crash 会取消运行 VM；launcher SIGKILL 后自动重启并 reconciliation=1，最终进程、workdir、cgroup 全部零残留。

验收未使用任何公网域名或既有证书；mTLS 使用临时测试 CA，测试私钥在验收后删除。

## 2. 环境与供应链

| 项目 | 实测值 |
|---|---|
| Host | 隔离的 x86_64 KVM 裸机；可识别硬件信息不入库 |
| OS / kernel | Debian 12 / Linux 6.1 系列 |
| CPU / RAM | 满足并发基准容量；具体机器指纹不入库 |
| KVM | 硬件虚拟化开启；`/dev/kvm` 仅授权给运行服务的组 |
| cgroup | unified cgroup v2 |
| QEMU | 7.2.22，Debian security build |
| Firecracker / jailer | 官方 release 1.16.1；release tar SHA-256 和包内 `SHA256SUMS` 均校验 |
| OSv | `v0.57.0-398-g0e34e4dc` |

最终产物在全部测试后重新计算，摘要未变化：

```text
loader-stripped.elf  e3496ebbbc7d3a87166fc136c8e9e251c704cdd262ed6c6f13cf140470c3b916
usr.img (qcow2)      6f035beb0336c2a16a8a9047a77904ebcacd3a18a5ecf161640902770a8b0cdf
osv-agent.raw        9ff043979975c55f5a7c5b1b7fdb2e5e2fc2b1e2db84325da5f9cb76aaea88fb
```

raw image 的 logical size 为 512 MiB，但保持稀疏；QEMU 和 Firecracker 使用相同 kernel 和同一客体文件内容，只因磁盘格式要求分别使用 qcow2/raw。

## 3. 代码验证

本地最终执行：

```bash
GOCACHE=/tmp/osv-sandbox-go-cache GOTMPDIR=/tmp \
  go test ./cmd/... ./internal/...
GOCACHE=/tmp/osv-sandbox-go-cache GOTMPDIR=/tmp \
  go vet ./cmd/... ./internal/...
cargo test --manifest-path guest/Cargo.toml --locked
cargo build --manifest-path guest/Cargo.toml --locked --release \
  --target x86_64-unknown-linux-musl
```

Go tests 覆盖 artifact hash/path confinement、参数引用、QEMU hardening、jailer 文件 staging/cgroup argv、严格 API、job ID 协议绑定、预期 VMM 非零 shutdown、输出限制和 timeout kill。Rust tests 为 2/2，通过 JSON escaping 与 job ID 行为；release 为静态 musl executor。

## 4. 远端功能与隔离验证

### 4.1 两个 KVM 后端

`cmd/osv-bench` 直接调用生产 backend 的参数/配置生成逻辑，避免 benchmark 与 daemon 启动路径漂移。等价 smoke 命令：

```bash
/opt/osv-sandbox/osv-bench \
  -backend both -iterations 1 -warmup 0 -concurrency 1 \
  -operation isolation-probe -include-output \
  -output /var/tmp/osv-sandbox-results/isolation.json
```

两个后端都返回匹配的 `OSV_AGENT_RESULT`，其中 `root_write_blocked`、`metadata_connect_blocked`、`loopback_connect_blocked` 全为 `true`。原始结果可能包含宿主信息，因此只作为发布流水线制品保存，不提交源码仓库。

Firecracker 的 one-shot guest 通过 I/O poweroff 后，有时以 `MicroVMStopped ... GenericError` 和 VMM exit 1 退出。控制面只有在未超时且收到 protocol、job ID、`ok` 均合法的 envelope 时才把它归一为成功；缺失或错误 envelope 仍为失败。对应回归测试已经加入。

### 4.2 jailer 完整 API

生产示例配置启用：

```json
"jailer": {
  "path": "/usr/local/bin/jailer",
  "uid": 65534,
  "gid": 65534,
  "cgroup_version": 2,
  "memory_overhead_mib": 128,
  "no_file_limit": 128
}
```

root 启动 daemon 后，doctor 四项（artifact、hypervisor、KVM、jailer）全部 `ready=true`。经 loopback API 提交 `isolation-probe`，状态 `succeeded`、`protocol_ok=true`、耗时 125 ms。

在 5 秒 `hold` 任务运行期间从 host 实测：

```text
Uid/Gid        65534 / 65534（real/effective/saved/fs 全部一致）
Threads        2
CapEff         0000000000000000
Seccomp        2
cgroup         /firecracker/<job-id>
memory.max     268435456
```

任务后 `/opt/osv-sandbox/run` 无子项，未发现残留 osv-sandboxd/Firecracker/QEMU 进程。`--new-pid-ns` 的 jailer 手工 smoke 会让同步父进程提前返回，因此当前 manager 明确不启用该选项；需要 PID namespace 时应先实现 supervisor/pidfile wait。

## 5. 性能复现

正式命令的核心参数如下；完整原始报告保存了 host、options、每个 sample 和 summary：

```bash
# warm c=1, n=100
/opt/osv-sandbox/osv-bench -backend both -iterations 100 -warmup 10 \
  -concurrency 1 -operation probe \
  -output /var/tmp/osv-sandbox-results/warm-c1-n100.json

# 定向驱逐 artifact cache，c=1, n=50
/opt/osv-sandbox/osv-bench -backend both -iterations 50 -warmup 0 \
  -concurrency 1 -operation probe -evict-artifacts \
  -output /var/tmp/osv-sandbox-results/cold-artifact-c1-n50.json

# warm 并发扩展
/opt/osv-sandbox/osv-bench -backend both -iterations 100 -warmup 8 \
  -concurrency 8 -operation probe \
  -output /var/tmp/osv-sandbox-results/warm-c8-n100.json
/opt/osv-sandbox/osv-bench -backend both -iterations 128 -warmup 8 \
  -concurrency 32 -operation probe \
  -output /var/tmp/osv-sandbox-results/warm-c32-n128.json
```

不要把 `-evict-artifacts` 称为“物理冷机”：它只针对 kernel/image file descriptor 请求 `POSIX_FADV_DONTNEED`，没有重启 host，也不能保证驱逐块设备或 hypervisor 内部的所有 cache。

## 6. 攻击面复现与局限

二进制/linkage、`/proc` maps/FD/thread/RSS、Seccomp、CapEff 均由 host 采集。另用 `strace -f -c` 对一次最小 `echo` 启动做 syscall 汇总。Tracer 会改变时序，故 syscall 汇总只用于攻击面枚举，不进入冷启动统计；原始采集文件不提交源码仓库。

代码级生产项已经补齐。原始 benchmark 与结构化验收证据因包含宿主运行信息而由发布流水线留存，不进入 Git。组织上线前仍需补齐 KVM/Firecracker CVE 周期扫描、10k+ 长样本、CPU pinning/NUMA、24h/7d soak、OOM/串口/vsock flood、parser fuzz、密钥轮换和远程不可变审计。
