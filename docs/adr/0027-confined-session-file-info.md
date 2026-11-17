# ADR-0027：Linux 会话文件元数据与 E2B 信息契约

状态：Accepted；日期：2026-10-30；需求 FILE-02、API-01、API-02。继承 ADR-0021、0022、0024。

## 背景

Linux 会话已提供受限 `list/stat`，但只返回名称、类型与大小。固定 E2B 2.51.0 的 `files.list/get_info` 还要求路径、权限位、权限字符串、属主、属组和修改时间；缺项时 SDK 明确拒绝。用宿主猜测这些字段会把 guest 的实际文件属性和租户身份混淆。

## 决策

保留现有原生 `list/stat` 字段，guest 在同一结果中可选增加 `info`（stat）或 `entry_infos`（list）。每个信息项包含 `name,path,type,size,mode,permissions,owner,group,modified_time_ms`。`mode` 是 Linux `st_mode`，权限字符串由低 9 位及 setuid/setgid/sticky 位生成；`modified_time_ms` 是 Unix 毫秒。普通文件与目录可报告，符号链接、设备和 FIFO 不跟随、不报告信息项。原生 list 的旧名称数组仍保留；E2B list 仅返回有完整信息的普通文件和目录。`metadata` 与 `symlink_target` 对未支持对象保持空。

guest 仍使用 `openat2`/目录描述符与 `O_NOFOLLOW`，list 每项在已打开的目录描述符下再次打开并获取属性；路径规范化、最多 256 名称及 64 KiB 名称预算沿用。信息项总体响应限制为 256 KiB，超限报错，不截断。发生并发删除时跳过已经不存在的目录项；其他打开错误使操作失败。host 严格校验信息项的路径、名称、排序、类型与 `st_mode` 一致性、权限字符串、大小、时间范围和与原生列表/统计字段的绑定，错误时关闭会话并拒绝响应。SDK 只有在看到完整且经 host 校验的字段时映射 E2B `EntryInfo`；旧镜像或旧 server 缺字段时返回 `UnsupportedCapability`。

Python/Node 显式 E2B 适配层先只支持默认单层目录和默认用户/超时选项。`files.list/get_info` 的双语言真实 KVM 正反例通过后才进入固定 34 项兼容矩阵分子。此决策不承诺用户定义 xattr、符号链接目标或递归深度选项。

## 验收

先做 guest 路径、类型、权限、时间和竞态审查；再做 host 伪造响应负例和 SDK 契约测试。构建双架构离线候选，ARM64 无网卡 QEMU 安装与功能检查；x64 指定服务器验签隔离安装后，用包内 Python/Node SDK 在真实 KVM 验证元数据、租户隔离、符号链接拒绝及清理。最后做受影响 CI 与矩阵审计。
