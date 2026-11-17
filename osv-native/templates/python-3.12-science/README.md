# OSv Python 3.12 科学栈兼容性候选

此目录固定 CPython 3.12.16、NumPy 2.5.4、pandas 3.1.0、python-dateutil 2.9.0.post0 和 six 1.17.0 的源文件摘要。设计与边界见 [ADR-0038](../../../docs/adr/0038-pinned-osv-python-science-template.md)。候选只覆盖 x64 OSv；原有 ARM64 Linux 离线发布和 QEMU 验收独立保留。

准备阶段允许下载和安装编译依赖；编译运行时使用 `--network none`。目标机运行模板不需要 pip、Python 或任何宿主科学库。实际依赖保存在项目 `assets/osv-native/python-3.12-science/`，构建中间件保存在 `build/python-3.12-science/`，均不依赖 /tmp。

```bash
python3 scripts/fetch-python-science.py --fetch
docker build --network host -t osv-sandbox-python-science-builder:ubuntu22.04 - \
  < deploy/osv-python-science-builder.Dockerfile
bash scripts/build-osv-python-science.sh
```

构建要求新的 rootfs 和中间目录；不会覆盖基础 OSv 模板。镜像大小 384MiB 是磁盘容量，不能拿它当 guest RAM 要求。运行内存 512MiB 的候选验收和原方案 64MiB 目标分别记录。

`runtime-inventory.json` 记录逐文件摘要、ELF DT_NEEDED 闭包、OSv 提供的 soname、源包摘要和裁剪规则；其副本内置于只读镜像。`build-provenance.json` 记录编译镜像 ID、编译器、开发包版本和构建输入摘要。许可证保留 CPython LICENSE 与 wheel 内许可证；完整运行库 SBOM、系统库许可证归集与 CVE 门禁仍需完善，不能将兼容性候选直接用作正式发布。

通过 `OSV_TEMPLATE_TEST_PROFILE=python-3.12-science` 调用 `scripts/build-osv-template-candidate.sh` 生成独立 `*-test` 测试签名模板。该脚本要求显式测试密钥输入；正式密钥、测试私钥均不得放入发布物。候选沿用现有签名 v2、唯一允许入口 `/python3.12.so`、mTLS 和一次任务后销毁的池管理。

当前预启动的是 guest agent，解释器和科学库在领取后的任务中初始化。VM warm-start、解释器首任务耗时、64MiB 与生产门禁分别验收，不能相互替代。

[rc48 实机结果](../../../docs/validation/2026-11-02-osv-pipe-and-exit.md)：512MiB 的 20 项完整功能用例通过，保留正常 Python 清理与真实退出码；64MiB 的完整科学任务超时，整体内存目标仍未通过。rc48 使用独立候选目录，本文构建的初版资产和失败报告均保留。

[rc49 签名缓存策略](../../../docs/validation/2026-11-02-rofs-memory-rc49.md)将同一完整 20 项功能验证到 128MiB，64MiB 目标仍失败。构建测试模板可显式设置 `OSV_TEMPLATE_TEST_ROFS_CACHE=disabled`，策略写入签名 manifest；要求支持该字段的新管理端，旧端会拒绝。该选项保留初版默认，不能把原资产的复制直接当作 rc49。
