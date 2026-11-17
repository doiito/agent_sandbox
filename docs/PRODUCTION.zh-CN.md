# Firecracker AI Agent Sandbox 生产部署

当前可靠性行为采用 [ADR-0005](adr/0005-durable-admission-and-supervision.md)：launcher 发送 systemd READY 后 API 才启动；准入前和完成后分别持久审计；审计 I/O 失败后停止新任务，恢复空间也不会清除失败状态。审计结构为 `osv-sandbox-audit/v1`，采集端需按 protocol/event 解析，历史日志保留原状。发现半条尾记录时启动拒绝，先归档并修复日志再重启，不能直接截断丢弃证据。准入无完成的 request ID 属结果未知，不自动重试。

已认证 manifest 过期后停止新准入，已有任务按原 TTL 收尾；制品或有效期更新使用重新校验的新实例，禁止热覆盖现有实例的制品。Linux agent 在任务主进程结束后清理其后台/setsid 后代，输出采集与收尾有界。最新验证范围见[第二轮记录](../PUBLIC-QUALIFICATION.md#private-evidence)，不能据此跳过 host 基线和完整发布门禁。

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

root launcher 不解析公网协议、不保存 bearer 明文、不监听 TCP；API 用户不能打开 `/dev/kvm`、修改 cgroup、读取服务端私钥或访问制品目录。Unix socket 为 API UID 所有、`0600`，launcher 再用 `SO_PEERCRED` 校验连接进程的真实 UID。两个进程读取 `production=true` 配置时均验证配置文件和原始路径逐级为 root 所有、非组/其他用户可写且没有符号链接；正式 API unit 传 `-require-production`，配置被切为诊断模式会在监听前拒绝启动。

## 2. 已强制的生产安全属性

| 层 | 强制属性 |
|---|---|
| Host | KVM 可用；cgroup v2 的 cpu/io/memory/pids controller；swap 必须关闭；CPU 漏洞报告不得为 Vulnerable/Unknown |
| API | 非 root；TLS 1.3；双向证书；SHA-256 bearer 映射租户；entrypoint RBAC；rate/burst/并发配额；1 MiB body 上限 |
| Launcher | root-only；唯一实例 `flock`；Unix peer credential；2 MiB RPC 上限；客户端断开即取消 VM |
| Supply chain | Ed25519 签名 manifest；有效期；kernel/rootfs/Firecracker/jailer/SBOM 的 hash 与 size；配置和制品路径/父目录 root-owned 且不可被 group/other 写，生产配置路径无符号链接 |
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
- identity pool 的 UID/GID 区间未分配给宿主账户，并且 `identity_pool_size >= vm_capacity.max_instances`；
- 生产证书私钥和 auth policy 由 secret manager 原子发布，不放进仓库。

安装脚本只安装程序、目录和 systemd unit，不会在制品、签名、证书和租户策略尚未就绪时启用服务。

`limits.max_concurrent` 限制已领取任务，`vm_capacity` 限制真实 VM 资源预留：`max_instances`、`reserved_memory_mib`、`reserved_vcpus`、`reserved_pids`。内存按每实例 guest 配额加 `jailer.memory_overhead_mib` 计费，pids 按每实例 `jailer.pids_max` 预留；job/session 共用账本，超额在启动 VMM 前返回 429 busy。未配置时按最大实例数与现有限额生成默认上限，管理员应根据宿主容量配置实际预算。doctor 的 `vm_capacity` 返回当前使用量；确认清理后才归还资源，清理失败保留预留并拒绝后续准入。pristine 池也使用此账本：空闲实例计物理资源，领取时才占 active。

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

客户端可用同一 mTLS 与 bearer 请求 `GET /v1/capabilities`，确认 `backend=firecracker-linux`、`stage=production`、签名 manifest 摘要、租户可用入口及支持的限制。Linux 签名模板还会声明 `session_files` 与单文件上限。能力响应描述静态支持范围；它不代替 doctor/ready，也不表示 OSv、网络出口、快照或全部文件操作已在生产开放。

OSv 模板在受信 v2/v7 manifest 明示 `environment` 特性时声明 `features.environment=true`，并接受有界任务级 `environment` 映射；旧模板或无签名配置拒绝非空环境。能力由所选签名模板决定，具体限制通过 capabilities 查询。该字段最初的真机范围见 [ADR-0025](adr/0025-osv-native-environment.md) 和[OSv 环境验收](../PUBLIC-QUALIFICATION.md#private-evidence)。

同一 OSv 模板在签名 `agent_features` 包含 `stdin` 时才声明 `features.stdin=true` 和 16 KiB 上限，接受一次性二进制 stdin，包括显式空输入；未声明的模板在 VM 前拒绝。见 [ADR-0026](adr/0026-osv-native-stdin.md) 和[stdin 真机验收](../PUBLIC-QUALIFICATION.md#private-evidence)。OSv 不提供 Linux session 的交互式 stdin。

开发中的 OSv 只读输入按 [ADR-0121](adr/0121-osv-readonly-input-files.md)启用：只有同时签名 `input-files-v1` 和 `pristine-v1` 的新模板声明 `features.input_files=true`。单次任务的相对路径映射到 `/input/<path>`，最多64文件、512KiB数据，文件模式0444；旧模板继续拒绝非空文件输入。warm、池未命中 cold 和关闭池的 cold 使用同一输入限制；不支持 OSv session 或可写工作区。组件验收不代替新发布包的完整验收。

需要将任务绑定到查询时看到的模板时，使用 `POST /v2/jobs`，显式提交能力响应中的 `backend`、`artifact_manifest_sha256` 和租户允许的 `entrypoint`。例如：

```json
{"backend":"firecracker-linux","artifact_manifest_sha256":"<capabilities 返回的 64 位摘要>","entrypoint":"/bin/sh","args":["-c","printf selected"]}
```

manager 在实际准入前复核选择值；模板已切换时返回 HTTP 409、`code=template_mismatch`，不启动 VM。缺少或非法选择字段返回 HTTP 400、`code=invalid_request`。旧 `/v1/jobs` 保持兼容，未携带选择字段时不提供这个模板绑定保证。

同一租户需要在一台 Linux VM 中连续执行命令时，先用 `POST /v2/sessions` 创建 session：

```json
{"backend":"firecracker-linux","artifact_manifest_sha256":"<capabilities 返回的 64 位摘要>","network":"none","ttl_ms":60000}
```

响应中的 `id` 用于 `GET /v2/sessions/{id}`、`POST /v2/sessions/{id}/commands` 和 `DELETE /v2/sessions/{id}`。命令请求示例：`{"entrypoint":"/bin/sh","args":["-c","printf hello > /workspace/hello"],"timeout_ms":10000}`；后续命令可读取同一 `/workspace`。创建时也可提供只读 `input_files`、`memory_mib` 和 `vcpus`。租期为 1–300 秒，默认 300 秒；只支持已签名的 `firecracker-linux` 模板和 `network=none`。每个 session 占用一个租户并发槽和一个独立 jail 身份，正常关闭在 VM 回收应答后释放租户槽；应答丢失时额外保留 15 秒以覆盖回收窗口。命令仍逐次检查租户入口白名单及速率。跨租户访问返回 404。HTTP 请求取消、API/launcher 连接断开、显式删除或租期届满会终止整台 VM；客户端应将中断命令视为结果未知，不应自动重试有副作用的操作。session API 的验收见 [ADR-0019](adr/0019-host-owned-sessions.md)；E2B 兼容性尚未声明。

`GET /v2/sessions/{id}` 同步确认 launcher 的会话仍可用；连接失效后返回 404，不返回缓存的 running 状态。控制通道正在执行其他操作时返回 429，可稍后重试状态查询。

同一 session 可向 `POST /v2/sessions/{id}/files` 发送 `{"action":"write","path":"/workspace/data.bin","data_base64":"AP8="}`，或发送 `{"action":"read","path":"/workspace/data.bin"}` 读取结果中的 `data_base64`。普通文件读写最多 512 KiB，写操作在 guest 内同目录原子替换。`{"action":"mkdir","path":"/workspace/deep/dir"}` 最多逐级创建 16 层目录，返回 `created=true|false`；`{"action":"list","path":"/workspace"}` 返回排序后的直接子项名称，最多 256 个名称；`stat` 返回 `kind=file|directory` 和 `size`，`delete` 仅删除普通文件。所有操作拒绝路径遍历、符号链接跟随及跨租户访问；结果未知时不要自动重试写入或删除。`{"action":"rename","path":"/workspace/old","destination":"/workspace/new"}` 移动文件、目录或链接本身并返回目标信息；`{"action":"remove","path":"/workspace/tree"}` 有界递归删除，不跟随链接，最多 4096 项/32 层，超限可能部分完成。目标父目录须存在，根目录不可移动或删除；产物导出仍待实现。双语言显式 E2B 适配层提供按顺序执行的有界批量写入，失败时可能部分成功。接口设计见 [ADR-0021](adr/0021-confined-session-files.md)、[ADR-0022](adr/0022-bounded-session-file-metadata.md)及[ADR-0024](adr/0024-confined-session-directory-and-e2b-writes.md)。

包内双语言客户端还提供固定 E2B 2.51.0 的显式 `Sandbox` 适配类，调用方须传入已配置 mTLS/bearer 的原生 `Client`。它实现运行态创建/连接、运行状态、终止、有界文件读取、存在性判断、目录创建、单项/批量写入和单层文件信息查询。`info` 动作及适配层可报告链接目标文本和 `user.e2b.*` 属性，写入支持有界 metadata；查询不跟随链接。其余方法显式报不支持。固定矩阵的分子只随同一签名包的双语言真实 KVM 证据更新，rc52 为 12/34；详见 [ADR-0028](adr/0028-symlink-and-xattr-file-info.md)及[rc27 验收](../PUBLIC-QUALIFICATION.md#private-evidence)。

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

`warm_pool` 为 root launcher 的显式配置，使用受信签名的 Linux 或 OSv 模板；OSv 必须声明 `pristine-v1`，只支持一次性 job，其只读输入另须 `input-files-v1`。Linux session 仍仅用于 Linux 模板。以下对象合并到完整生产配置；`vm_capacity` 必须容纳所有 min_ready 的 guest+VMM 内存、vCPU/pids，且 `identity_pool_size` 至少等于物理实例上限。它们和租户 active 并发分别计数。关闭池时不会启动补池 worker 或预留空闲 VM；新 OSv 输入模板仍会为每个实际请求执行准备及一次性绑定。

```json
{
  "warm_pool": {
    "enabled": true,
    "on_miss": "cold",
    "max_booting": 2,
    "refill_per_second": 2,
    "refill_burst": 2,
    "max_idle_age_ms": 120000,
    "health_interval_ms": 1000,
    "check_timeout_ms": 500,
    "boot_timeout_ms": 10000,
    "checkout_timeout_ms": 10000,
    "startup_timeout_ms": 30000,
    "min_available_memory_mib": 128,
    "profiles": [
      {"name": "small", "memory_mib": 128, "vcpus": 1, "min_ready": 1, "max_ready": 2}
    ]
  }
}
```

启动先满足 min_ready，再报告 systemd 就绪；命中或对应规格的 cold miss 后按需求增长到 max_ready，空闲到期后收缩。前台领取先占 active 配额并优先取得容量，补池受并发、令牌桶、退避和宿主可用内存阈值限制。规格必须精确匹配；`on_miss=reject` 在缺池或不匹配时返回 busy，`cold` 可确认回收 idle/未领取 boot 后启动新 VM。池只保存从未接收租户输入的 pristine VM，prepare 后不回池，用完销毁。健康 ping 与租户请求分别有上限，预热不消耗会话执行预算；host 要求 `pristine_revision=2` 证明。

开启池后的 job/session 创建响应记录 `startup_mode` 和 `startup_duration_us`，包含 launcher 持久准入、健康、prepare 和归属提交。doctor 的 `warm_pool` 与指标报告 ready/booting/目标、命中/未命中、退避、淘汰和失败。短时缺池为可观察降级；审计、签名或清理故障阻止新领取。模板变更通过停止并重启 launcher，旧 idle 不接管。

warm 领取在持久 claiming 后即时复核 lease/PID/start ticks、请求/租户、cgroup、签名/规格及已验证的保守寿命，然后以一次原子 prepare 的精确新绑定 ACK 确认当前 guest 就绪。准备后再次复核归属，按原顺序持久提交 active 和领取审计；准备结果未知只销毁、不重试或回池。退出/zombie 的进程不能作为可领取实例；仅 backend 确认任何 prepare payload 写入前已失败时，且旧 VM 已销毁、请求仍有效，warm 才可按 miss 策略重新选择。写入尝试后的错误和未知 ACK/EOF 均不换 VM 重试。准备或持久化期间请求租期已耗尽时不交付句柄。启动、cold 与后台健康检查继续完整 ping，后台缓存不能独自交出 VM。详见 [ADR-0036](adr/0036-atomic-warm-readiness-and-preparation.md)。

cgroup归属实时核对预期专用叶节点：目录须来自cgroup v2，前后类型均为domain，完整成员列表必须含原VMM PID，其他成员仅接受经内核PF_KTHREAD标志确认的worker；拒绝额外用户进程、threaded聚合根、缺成员和格式/读取错误。内核worker仍计入原资源预算并随VM清理。PID代次、活状态和lease归属仍单独核对，prepare后再次复核。该检查不使用后台缓存代替当前归属，详见[ADR-0037](adr/0037-direct-cgroup-membership-verification.md)。

pristine 路径另可返回 `startup_timing`（schema=osv-startup-timing/v2）：`admission_us`、`selection_us`、`readiness_us`、`preparation_us`、`ownership_us`、`audit_us`、`finalize_us` 七阶段之和严格等于 `total_us` 与 `startup_duration_us`；失败候选检查和重选时间也保留。v2 warm 的 readiness 是即时宿主归属/寿命确认，当前 guest 状态证明计入原子 preparation；cold 仍含首次探测。历史 v1 warm readiness 另含 ping，两版不能按该单段直接比较；总启动起止不变。cold miss 的 `vm_boot_duration_us` 独立表示 VMM 启动到首次完整验证就绪，排除 staging，不能与七阶段相加；warm 不返回此前预启动成本，缺失表示未测量。阶段和 cold 指标不等于性能门禁通过。

warm/cold job 的顶层 `exit_code` 保留已绑定 guest 的实际非零退出码；例如模块或进程退出 7 时返回 `guest_error`/7。未产生任务退出码或报告 exit 0 的加载失败仍返回非零合成失败码。VM poweroff 的宿主退出状态不能覆盖已验证的 guest 结果；VM 死亡后只允许有界结果读取，不等待完整任务 TTL。

上述配置可用于隔离候选验证；正式发行仍须通过 `python3 scripts/check-startup-gates.py --require-target`。无真实 KVM 安全及性能证据时该命令失败，正式构建亦拒绝；测试签名候选不据此宣称达到 1–2 ms。

每个一次性任务或 session 创建独立 microVM；session 内的命令可复用该 VM，不跨租户复用 guest。优化来自：

- rootfs/kernel staging 优先 `FICLONE`，不支持时使用 sparse copy，再回退 full copy；
- launcher 启动时只创建一次可信 ext4 scratch template，每任务 reflink/clone；
- 无 Firecracker API round-trip，使用 `--no-api --config-file`；
- vsock 传 argv/result，避免把不可信参数放入 kernel cmdline；
- 容量由 cgroup 和 identity pool 预先界定。

默认不启用通用 snapshot restore。Firecracker 官方说明，同一 snapshot 多次恢复会复制 guest entropy 和唯一标识；除非 guest 有经过验证的强唯一性重建机制，否则这在安全上不可接受。snapshot 还要求内存/state 文件不可变、磁盘路径一致，并会重置既有 vsock 连接。未开启 warm pool 时使用每任务冷启动；开启后只领取 pristine VM，任务或 session 结束即销毁。

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

离线版本切换使用 `osv-offline-release switch`：保留原签名 tar 与带外公钥，先停止两个生产 unit、完成任务/审计收尾，再由命令复验已安装字节和空闲锁/目录/cgroup，原子更新 `/opt/osv-sandbox/current`。回滚用旧版 tar 执行相同流程；命令不会启动服务或替代 doctor、有效证书和正式发布审核。具体参数见[离线发布手册](OFFLINE-RELEASE.zh-CN.md)。

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


## 后台命令与输出观察

`POST /v2/sessions/{id}/commands/start` 使用与旧同步命令相同的 entrypoint/args/timeout_ms，返回 202 及命令 ID。`GET /v2/sessions/{id}/commands` 返回带 session_id 的最近 32 条记录；`GET /v2/sessions/{id}/commands/{command}?after=N` 返回最多 64 条有序数据事件与 next_sequence，complete 时带可信终态。`GET .../{command}/events?after=N` 通过 SSE 及时返回 output 事件，含 sequence/stream/data_base64；result 事件含终态和同一 session/命令绑定。首次 after=0，重连用已消费序号。

`DELETE /v2/sessions/{id}/commands/{command}` 返回 killed 是否首次接受取消；取消经执行连接发给 guest，guest 完成全工作负载回收后才释放执行位置和发布终态。等待终态后可继续用原 workspace。观察者断连不会取消后台工作；session close、TTL 或丢失 API/launcher 控制连接仍销毁 VM。一个会话同时执行一条命令，执行/文件操作并发拒绝 busy；只读观察、取消仍可用。输出受既有字节预算（最多 64 KiB）与最多 256 条数据事件限制，超限显式截断；完成记录超过 32 条时淘汰最旧记录，其他租户与已淘汰句柄返回 404。两语言原生 SDK 提供开始、连接、列举、events、wait 和 kill；Linux session 新增 environment/cwd；最多32项/8KiB、值1KiB，cwd 为 guest 绝对路径且在降权后 chdir。双 SDK 显式 E2B 适配层增加 Bash run/list/connect/kill 与缓存 wait，真实 guest PID、UTF-8 回调及非零专用异常。SSE 可带 timeout_ms，观察超时只断观察，不杀进程；E2B Python timeout 为秒、Node timeoutMs 为毫秒，0 不增加观察期限，但执行上限/租期保留。交互 stdin 现可由后台启动 interactive_stdin=true 显式启用；POST .../{command}/stdin 返回202票据，GET .../{command}/stdin/{sequence} 查询guest写入确认（pending/delivered/closed/failed）。每块16KiB、每命令1MiB/256次、一次一份pending；关闭输入显式EOF，输入背压不阻塞观察/取消。默认关闭，旧同步run拒绝true。输入正文不入审计，SDK不自动重发结果不确定的写入；详见 [ADR-0053](adr/0053-bounded-interactive-command-stdin.md)。真实静态 GNU Bash 与完整源归档/许可证随离线包交付，详见 [ADR-0052](adr/0052-bash-and-e2b-command-handles.md)和双 SDK 用法。


## 会话信息、分页与可调整TTL

`GET /v2/sessions` 支持limit=1..100、order=asc/desc及cursor，只见当前租户。分页冻结ID/全局创建顺序，后续页复核当前存活与信息，不混入新建项；30秒过期、每租户8份/总128份快照。游标失效或越租户明确拒绝。`GET /v2/sessions/{id}` 由launcher owner确认，含真实memory_mib/vcpus/guest_protocol、当前expires_at与固定max_expires_at。

`POST /v2/sessions/{id}/timeout` 的ttl_ms从现在重设剩余期限，范围1000..300000；可延长或缩短，但不能跨过max_expires_at或复活已过期会话。`session_max_lifetime_ms` 控制不可延长的VM寿命（0默认600000，允许1000..600000），warm模式同时受原始host/guest已验证剩余寿命及守护余量限制。API/root软timer与固定VM上下文分离；到期销毁活跃执行并释放资源，命令自身timeout不随租期扩展。信息/延期在控制连接短暂占用时有界等待，旧同步长RPC仍可能busy。设计见 [ADR-0054](adr/0054-session-info-pagination-and-renewable-ttl.md)。


## Linux 一次性任务执行输入

Linux `/v1/jobs` 与签名模板 `/v2/jobs` 均支持有界 `environment`、guest绝对路径 `cwd` 和 base64 `stdin`；cold与pristine warm绑定后执行均传递相同字段。环境32项/8KiB、每值1KiB；cwd最多1024字节、默认/workspace，在child降权后切换，失败不回退。stdin最多16KiB，省略/dev/null、显式空输入为管道EOF，非阻塞监督同时处理输出与超时；程序可以不消费全部输入。交互stdin仍由独立session后台接口提供。能力分别为environment/working_directory/stdin，OSv仍按签名特性和保留变量规则准入且不支持cwd。用法见包内Python/Node手册及[ADR-0055](adr/0055-linux-one-shot-job-execution-inputs.md)；不把功能验收作为性能通过证据。


Linux签名v3模板可显式启用受控guest HTTP/HTTPS代理，默认仍无NIC/none，部署条件与SDK/MCP用法见[egress手册](EGRESS.zh-CN.md)。[rc66](../PUBLIC-QUALIFICATION.md#private-evidence)已完成双架构离线、ARM QEMU及x64同包cold/warm/核心矩阵功能验收，完整生产/性能和域名证书条件继续按各自门禁跟踪。


## 多签名模板目录

顶层配置保持默认模板，可添加最多15项`templates`；每项包含`id`、`backend`、`artifact_root`、`kernel`、`image`、`artifact_manifest`、`allowed_entrypoints`，以及可选`defaults`、`linux_guest`和`warm_profiles`。x64科学模板构建选项会生成对应配置片段，迁移部署路径时须同步调整其artifact_root和公钥路径。所有模板启动时逐项验签并核对同一宿主VMM/jailer，不接受请求提供宿主路径。

`GET /v2/templates`提供真实租户目录，`GET /v1/capabilities?backend=...&artifact_manifest_sha256=...`提供所选能力。名称用于发现，任务按backend和签名摘要绑定。默认模板隐藏时只保留无模板身份的全局发现/fetch能力。租户`allowed_templates`可指定允许的backend/摘要列表；省略或null沿用全部已配置模板的入口政策，空数组禁止所有模板。Python入口还需加入该租户的allowed_entrypoints。所有模板共用同一租户并发/速率、VM容量、独占UID与生命周期登记。

开启warm_pool后，各附加模板的`warm_profiles`沿用顶层补充速率、burst和booting上限。全体最低水位之和必须容纳于同一vm_capacity；状态profile含模板ID/backend/摘要，附加profile名称带模板前缀。前台需求可回收其他模板的未领用pristine供给，已使用VM始终销毁。OSv正式代码路径保留签名、mTLS、审计和资源检查，host readiness继续独立报告。设计与候选验证见[ADR-0060](adr/0060-multi-template-catalog-and-shared-capacity.md)。
