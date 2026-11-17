# ADR-0106：合并 Linux 控制结果帧的客体写入

状态：Not adopted（定向功能通过，实际 API 未证明收益，已恢复原实现）；日期：2026-11-12；需求 PERF-03、QA-01、BUILD-01。

[实际 API ABBA](../../PUBLIC-QUALIFICATION.md#private-evidence)完成 532 个唯一任务和 VM、零请求失败。每函数 256 个正式样本，原函数 warm 为 3.301/7.167/9.205ms，合并函数为 3.346/8.720/20.300ms，未证明实际加速。保留实验源码、双架构 ELF、引用资产与全部证据，工作源码精确恢复 rc86 的 1241 项原程序输入；不推进本实验的新完整候选。以下为原设计与执行要求，不代表当前采用了该实现。

## 依据与决策

原 rc86 的 Linux `write_result` 对未缓冲 `File` 使用 `writeln!(writer, "{RESULT_PREFIX}{encoded}")`，帧头、JSON 和换行分别调用底层 write。[原签名包时间线](../../PUBLIC-QUALIFICATION.md#private-evidence)第 105 个正式请求实际观察到 16 字节前缀、392 字节正文及最后 1 字节分开发送。该模式给每次 ping/prepare/普通结果增加 guest/virtio/VMM 写入机会，合并它是明确的固定成本优化；尚不能称作剩余尾延迟的统一根因或 SLO 修复。

在单个临时 Vec 中构造原帧头，直接用同一 serde_json serializer 写入 JSON，再加原换行，完成序列化后才调用一次 `write_all` 并保留原 flush。正常小结果减少为一次底层 write；短写仍由 write_all 重试，不承诺所有大帧在内核中只调用一次。避免 encoded String 与整帧的双份同时分配，不修改 mimalloc/System 分配边界或新增依赖。

原 wire 字节、字段与版本、绑定、帧长度限制、host 128 字节 reader、取消/超时与不确定发送后销毁保持。序列化失败不发送部分帧；写入失败保持原 host 不确定结果处理，不重试整个 RPC 或重新执行 VM。不合并不同请求，不改变流式事件、OSv 或独立代码/端口协议。

## 验证与回归顺序

先完成[自评审](../../PUBLIC-QUALIFICATION.md#private-evidence)。用可注入 Writer 的定向测试在旧格式化实现中复现三次 write，再验证小帧单写、原 wire 字节、中文/转义/大结果、Interrupted/短写、BrokenPipe/WriteZero 后不继续输出及 flush 行为。测试 Writer 的泛化只用于同一内部函数，生产仍传入 File。

修正后运行受影响 Linux guest 单元/协议测试及 clippy，锁依赖离线构建 x64/aarch64 musl 静态程序；实际 ARM QEMU 验证新编译功能。新 guest 的实际 KVM/原 API A-B-B-A 对照先验证是否有收益；没有证据时不得称 p95/p99 达标或替换正式功能基线。收益成立后才集中构建新的完整双架构候选、一次完整 CI/离线/QEMU/指定机回归，避免为每个微调重跑全矩阵。

正式 warm 目标保持 5/8/10ms、四必要路线与千次/隔离/恢复/资源长稳要求保持；原 40 项范围及发布条件不缩小。并行的原 trace 离线跨边界分析继续保留：R 状态不等同具备 CPU 带宽资格，审计 At→write 不能直接解释为锁或磁盘时间。

[定向验证已完成](../../PUBLIC-QUALIFICATION.md#private-evidence)：旧实现 3 次写入复现，新 4 项及受影响 guest 92 项、clippy 通过；双架构静态 ELF 与原 mimalloc 源锁核对，新 ARM 测试二进制无网卡 QEMU 7 组/14 项通过。原冗余测试转换的 clippy 失败保留。随后真实 API 对照未证明收益，恢复原实现；完整新候选回归的采用前提未成立。

## 同宿主真实 API 对照

以原 rc86 签名包作宿主/内核/辅助程序基线；原 rootfs 必须匹配包内 SHA-256。在同一私有源码路径、同一 Cargo target/cache、锁依赖与工具链顺序重编 A（原函数）和 B（合并函数），保存每份实际源码归档和构建事件；比较生产源码只能有 write_result 差异，测试模块差异不进入 release ELF。此重编控制 A 不冒充原发行 ELF，是否字节相同单独记录。

两份 rootfs 均只替换 `/sbin/agent-init`；逐文件内容/模式与符号链接清单必须证明 A/B 仅该路径不同，并核对原 supervisor/内核保持。每份使用同一新建测试密钥签名 manifest 与准确 SBOM/来源记录，标记 diagnostic=true/release_eligible=false；测试私钥不保留。引用资产及实际静态库证据保存项目目录。

私有准备器仅把已存在的 reference hook 指向本帧对照校验器，保持其余 rc86 指定机准备与 CPU/NUMA 放置逻辑字节不变；不修改通用脚本或宿主程序。校验器限制引用清单、基线包/内核/辅助程序/特性、镜像/ELF/签名绑定，在启动前复制至本夹具。配置规范化只允许确切夹具/发行路径、loopback 临时端口和已经与引用 manifest 核对的镜像 SHA，不忽略其他字段。

原 startup_benchmark、placement、wait-pool 保持，正常 mTLS API 与生产 doctor、CPU2–5/NUMA0、128MiB/1vCPU、100000/100000 CPU quota/period、max_booting=2/health=1000ms。A1/B1/B2/A2 四独立代次，各 128 正式+5 预热，共 532 个任务；核对实际引用/host 载荷、七阶段、唯一 VM、失败/超时/拒绝/冷回落、paced 供给、RSS/FD 边界及批前批后 pool 状态。该样本量不是正式千次门禁，不以短窗使发布变绿。

任务使用原不可变 worker/输入/InvocationID 和验证 flock；观察中断只查同一 ID，不重放业务。四组逐组停止并独立清理服务/VM/cgroup/凭据与已验证重复安装/引用副本，原始结果与失败保留。先完成增量自评审和引用校验正反例，再提交原任务；收益及资源结论成立后才统一完整新候选 CI/离线/QEMU/KVM 验收。
