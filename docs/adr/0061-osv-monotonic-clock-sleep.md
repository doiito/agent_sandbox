# ADR-0061：OSv 单调时钟定时等待

状态：Accepted（rc68 功能验收通过）；日期：2026-11-04；需求 OSV-02、CAP-01、QA-02/03、REL-04。

## 实机发现

多模板 rc67 冷路径中，Python `time.sleep(5)` 在约 0.8 秒内以 `OSError: [Errno 95] Not supported` 结束。独立新夹具复现 0.1 秒和 5 秒调用均失败，`time.monotonic()` 与 `time.time()` 成功。固定 CPython 源码使用 `clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, ...)`，现有 OSv `libc/time.cc` 只支持 CLOCK_REALTIME 相对等待。保留初次失败及三项真实返回，不把它视为 warm pool 配额问题，也不更换用例绕过它。

## 决定

在固定上游 overlay 补齐 CLOCK_MONOTONIC 与 CLOCK_REALTIME 的相对和绝对等待。绝对时间已过直接返回；合法等待实际进入 OSv 调度器；非法 timespec/flags 拒绝，返回正 errno 值且不把 clock_nanosleep 改成 nanosleep 的返回约定。使用宽整数计算防止秒转纳秒或绝对时间差溢出；有界等待片段避免调度器期限相加溢出，并使绝对墙钟等待重新观察墙钟。保留现有不可中断调度/有限 signal 支持，不声明完整 POSIX signal、CPU 时钟或暂停恢复兼容。

修复不修改业务代码或 CPython 缓存，不重编未改变的 Python/NumPy/pandas/ROFS。生成新的项目内科学模板候选，保存新 kernel、上游/overlay/工具链来源和父资产摘要；原 rc51 资产与 rc66 回滚包保持可追溯。新离线包重新签名、绑定 SBOM 与实际 kernel。rc67 作为失败候选保留证据，不标本批验收通过。

## 验证

先验证真实修复函数的边界、相对/绝对时间和等待行为，再编译固定 OSv kernel。最终 x64 KVM 同包验证 Python sleep、C ABI 时间等待、Linux/OSv 混合并发、超时、cold/warm 与切换默认模板，执行受影响核心矩阵；最终双架构离线包与 ARM QEMU 按现有门禁执行。ARM 不额外声称具备 OSv 科学模板或 KVM 证据。实施前自评审见[记录](../../PUBLIC-QUALIFICATION.md#private-evidence)。

返回约定与绝对期限依据 [Linux man-pages 项目文档](https://man7.org/linux/man-pages/man2/clock_nanosleep.2.html)。原 40 项需求、功能优先与一般安全、E2B 和性能/内存门槛保持。

[rc68](../../PUBLIC-QUALIFICATION.md#private-evidence)完成实际新内核的 Python/C ABI、三组混合模板、原科学功能20项和受影响核心验收；科学功能使用512MiB，不声明64MiB目标或完整信号兼容通过。
