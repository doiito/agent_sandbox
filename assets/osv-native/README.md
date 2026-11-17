# OSv 原生任务镜像（amd64 验证候选）

`linux-amd64/kernel.elf` 与 `linux-amd64/rootfs.raw` 是固定 OSv 提交 `0e34e4dc2b278b7f64e4169abbf297b7de46fb6b`、项目内安全加载补丁及 `osv-job-agent.so` 构建出的真实运行资源。模块构建产物另存于 `linux-amd64/modules/`，供 SBOM 记录与模板核对；`scripts/build-osv-native-agent.sh` 构建成功后更新项目内文件及 `SHA256SUMS`。

该镜像随只读 rootfs 内置 `/osv-job-agent.so` 和 `/task-probe.so`。后者只用于真机协议/输出验收，不能代表 Python、Node 或 JVM 生产模板。测试签名 v2 模板候选在项目 `dist/osv-native-template-r2-linux-amd64-test/`，原始证据见[模板验收](../../docs/validation/2026-10-29-osv-template-r1.md)。生产配置仍拒绝 `firecracker-osv`，因为完整 API→launcher、模板兼容及独立安全评审尚未完成。现有双架构离线 Linux 发布包见 `assets/offline/`，不依赖本目录。

当前项目运行资产加入显式 `--pristine-v1` 模式和 OSP1 revision=1 的有界 ping/一次 prepare；新签名候选为 `dist/osv-native-template-pristine-r2-linux-amd64-test/`。pristine 状态从未运行租户模块，准备后仅允许同一 ID/nonce 的一次 OSJ1 任务；用后整机退出，guest 另有 boot/租期 watchdog，宿主 owner 仍为资源与安全权威。固定 Firecracker 追加的尾参只按完整序列识别，其他未知参数继续拒绝。此阶段完成准备协议的定向验收，共用 OSv pool 调度尚未接入，不代表生产启用或启动性能门禁通过。
