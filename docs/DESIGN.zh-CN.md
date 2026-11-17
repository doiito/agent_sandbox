# Go 控制面 + Rust OSv 客体设计

本文件描述 OSv 单进程路径。通用 coding agent 的当前生产架构已采用 `Firecracker + 最小 Linux`、root launcher/非 root API 双进程，见 [生产手册](PRODUCTION.zh-CN.md)。

## 1. 结论与适用范围

OSv 是面向单应用的 Linux ABI 兼容 unikernel，可以把应用与最小 OS 组合成 microVM 镜像，并运行在 QEMU/KVM、Firecracker 等 hypervisor 上。官方说明其目标是单个 Linux 应用、微服务和 serverless 工作负载，并支持 Go、Rust、JVM、Python 等运行时：<https://github.com/cloudius-systems/osv>、<https://osv.io/>。

本方案把它定位为 AI 系统中的“受限工具/推理任务执行单元”，而不是一台缩小版 Linux：

- 适合：预编译 Rust Agent、单进程推理插件、解析器、转换器、规则引擎、嵌入式 WASM runtime，以及可以链接为 Rust crate 的工具。
- 不适合：需要 `bash`、`fork/exec`、动态安装软件、多个守护进程或完整 POSIX 用户权限语义的通用 coding agent。

后一类工作负载已由独立的 [Firecracker + 最小 Linux 路径](FIRECRACKER-LINUX.zh-CN.md)实现；它复用 Go 控制面，但用 virtio-vsock 把 argv 交给 Linux Rust PID 1，不再把任务塞进 OSv kernel cmdline。

该判断也由固定上游提交中的实现直接支持：`runtime.cc` 中 `fork()`/`vfork()` 返回失败；`libc/user.cc` 明确说明 OSv 不支持不同用户，UID/GID 恒为 0。OSv 内部因此不是权限隔离边界，真正边界必须是硬件虚拟化。

## 2. 目标与非目标

目标：

1. 每个不可信任务拥有独立 microVM 生命周期和内存空间。
2. 默认无网络、根盘只读、无宿主目录共享。
3. 请求不能注入 hypervisor 参数或任意 OSv 入口点。
4. 对 CPU、内存、并发数、执行时间和输出量建立硬限制。
5. 内核、镜像和任务结果均能确定来源并审计。
6. 控制面不依赖 shell 拼接，崩溃或超时后能回收整棵 VMM 进程树。

非目标：

- 防御恶意宿主机管理员或已被攻陷的 hypervisor/CPU firmware；
- 在同一个 OSv VM 内隔离多个互不信任的 Agent；
- 在 MVP 中提供任意公网访问、持久化状态或热迁移；
- 声称达到容器/Kata/gVisor 的 Linux 应用兼容面。

## 3. 总体架构

```text
Agent Orchestrator
        │ HTTPS / mTLS（部署层终止）
        ▼
Go osv-sandboxd
  ├─ 认证、schema/策略校验、配额、审计
  ├─ SHA-256 固定的 kernel + ROFS image
  ├─ QEMU microvm backend（开发/兼容）
  └─ Firecracker backend（生产首选）
        │ KVM + virtio block + serial
        ▼
每任务一个 microVM
  OSv kernel + ROFS
        │
        └─ Rust /agent（唯一入口、单进程、in-process tools）
               └─ OSV_AGENT_RESULT { osv-agent/v1 envelope }
```

语言边界：

- Go 控制面负责 I/O 密集型编排：HTTP、并发令牌、deadline、VMM 生命周期、审计和 host preflight。
- Rust 客体负责内存安全、资源可预测的任务执行；工具通过 trait/crate 链接进入同一进程，不依赖 `fork/exec`。
- 两者只通过不可变启动参数、串口输出和版本化 JSON envelope 耦合。

## 4. 任务生命周期

1. API 只接受严格 JSON；未知字段、额外 JSON 值和超过 1 MiB 的 body 被拒绝。
2. 控制面应用默认值并检查 `/agent` allowlist、参数数量/长度、OSv 1024-byte cmdline 预算、CPU/内存/timeout/network 策略。
3. 从 CSPRNG 生成 96-bit job ID，控制面将其作为内部参数注入，调用方不能决定结果绑定 ID。
4. 仅从 `artifact_root` 内解析真实路径；拒绝 symlink/path escape，启动时校验 kernel 和 image SHA-256。
5. 获取并发令牌，为该任务创建 0700 临时目录，生成 VMM argv/config；整个过程不经过 shell。
6. 启动新的进程组，并配置 parent-death signal。超时或请求取消时向整个 VMM 进程组发送 `SIGKILL`。
7. microVM 使用固定 `/agent` 入口。Rust executor 回传带 protocol 和 job ID 的单行 JSON。
8. 控制面只接受 `protocol=osv-agent/v1`、job ID 相同且明确包含 `ok` 的结果。VMM 退出 0 但缺少 envelope 时为 `protocol_error`；合法 envelope 的 `ok=false` 为 `guest_error`。
9. 输出达到上限后继续消费但停止保存，避免 pipe 阻塞与宿主内存膨胀；任务结束后删除临时目录并释放令牌。

## 5. 隔离层与控制措施

| 风险 | 当前强制措施 | 生产增强 |
|---|---|---|
| 客体内核/应用逃逸 | 每任务 KVM microVM；不与其他任务共享 OSv 地址空间 | 固定已修复的 VMM/OSv 版本，漏洞扫描和分批轮换 |
| QEMU 设备攻击面 | `microvm`、`-nodefaults`、无 PCI、仅 virtio-blk/serial、QEMU sandbox | 生产优先 Firecracker 的精简设备模型 |
| 文件系统篡改 | ROFS 基础镜像、block device read-only、artifact 哈希固定 | dm-verity/签名清单、只读 mount、独立 artifact 发布账户 |
| 路径/参数注入 | realpath confinement、entrypoint allowlist、argv 调用、OSv 特殊字符引用 | fuzz command encoder 和配置解析器 |
| 数据外泄 | `network=none` 是唯一已实现策略，无 host directory share | 独立 TAP/netns + L7 egress proxy + 域名/IP/端口 allowlist |
| 资源耗尽 | vCPU/timeout/output/concurrency 限额；jailer 模式设置 cgroup v2 `memory.max` | 增加 CPU、pids、I/O controller 和租户 rate limiter |
| VMM 残留 | 独立 process group、Pdeathsig、timeout kill、临时目录回收 | 外部 reaper 对账、租约和 orphan 扫描 |
| API 滥用 | loopback 默认监听、Bearer constant-time compare、body/header/time limits | mTLS、短期 workload identity、RBAC、全链路审计 |

Firecracker 后端有两种明确区分的模式：直接模式只用于可比性能基线；配置 `jailer` 后，每任务创建独立 chroot、把已验哈希的 kernel/ROFS 副本放入 jail、降权到专用 UID/GID，并设置 cgroup v2 `memory.max` 和 `RLIMIT_NOFILE`。Firecracker 官方生产指南要求使用 jailer 或至少同等严格的约束：<https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md>。

本实现为了让 launcher 可靠等待 VMM、执行 deadline 和清理目录，没有使用 `--daemonize` 或 `--new-pid-ns`。网络 API 已拆为静态非 root 用户，只有不监听 TCP 的 launcher 以 root 完成 chroot/cgroup/UID drop，并通过 Unix `SO_PEERCRED` 只接受该 API UID。

## 6. 文件与网络模型

MVP 不把调用方目录通过 Virtio-FS 直接暴露给客体，因为这会增加共享文件系统实现和宿主文件权限的攻击面。推荐的生产数据路径是：

1. 控制面验证输入大小和内容摘要；
2. 离线生成每任务只读 input block image；
3. 以第二个 virtio block device 挂入 OSv；
4. 输出优先走串口协议；大对象写入独立、限额的 scratch block device；
5. VM 结束后由宿主离线读取并校验结果，随后销毁 scratch。

OSv 官方支持 ROFS、RAMFS、ZFS、Virtio-FS 以及通过 `libext` 挂载 ext2/3/4；对于无状态任务，官方也建议考虑 ROFS：<https://github.com/cloudius-systems/osv#filesystems>。

网络仍保持 fail-closed。若 Rust Agent 需要调用模型服务，推荐让模型编排留在宿主侧；客体只执行工具。确需客体出网时，再加入独立 netns/TAP 和认证 egress proxy，禁止直接 NAT 到公网，且 DNS 解析结果也必须受策略约束。

## 7. Rust 客体协议与扩展

`guest/` 是无第三方 crate 的协议参考实现，构建目标为 `x86_64-unknown-linux-musl` 静态 PIE。当前内置：

- `probe`：客体 readiness 和协议闭环；
- `echo`：验证参数编码、Unicode/JSON 和串口结果提取；
- `isolation-probe`：检查根目录写保护、metadata/loopback 不可达以及 `/dev` 枚举；
- `hold`：仅用于 timeout、进程属性和 cgroup 验证，最长 5 秒；
- 未知操作：返回结构化错误和 exit code 64。

生产 Agent 应保持同一 envelope，并把实际工具实现为同进程 Rust 模块，例如：

```rust
trait Tool {
    fn name(&self) -> &'static str;
    fn run(&self, input: &[u8], budget: &Budget) -> Result<Vec<u8>, ToolError>;
}
```

WASM 是扩充“不可信插件”兼容面的候选，但 runtime 本身仍位于 OSv VM 内；需要独立配置 fuel、linear-memory 和 hostcall allowlist。不能因为使用 WASM 就取消 microVM 边界。

## 8. 镜像供应链

- OSv upstream 固定到提交 `0e34e4dc2b278b7f64e4169abbf297b7de46fb6b`，更新必须经过源码 diff、构建和 KVM 回归。
- Rust 使用 `Cargo.lock`、`--locked`、musl 静态构建、LTO、`panic=abort` 和 strip。
- `osv-module/agent-sandbox/module.py` 仅把指定 executor 映射为 `/agent`。
- `scripts/build-osv-agent-image.sh` 强制 `fs=rofs`，最终输出 kernel/image 哈希。
- 部署配置必须填写 64 位 SHA-256；不存在跳过哈希校验的开发开关。

## 9. 生产状态

双进程拆权、CPU/memory/swap/pids/io cgroup、签名 manifest/SBOM、输入/scratch block 生命周期、tenant RBAC/rate、审计、指标与 crash reconciliation 已在通用 Linux 主路径实现。OSv 路径保留作受控预构建工具的性能选项；组织上线仍需固定 CI 裸机的长时间 soak、fuzz、CVE/密钥 SLA、跨 NUMA 容量与逃逸响应演练，详见 [生产手册](PRODUCTION.zh-CN.md)。
