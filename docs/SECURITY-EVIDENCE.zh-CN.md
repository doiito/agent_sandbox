# 漏洞证据与发布门禁

对应 [ADR-0047](adr/0047-replayable-vulnerability-evidence.md)。工具查询的是公开 OSV 漏洞资料，与本项目的 OSv guest 是两个概念。目标机离线安装运行不需要扫描器、Python 工具或联网；以下步骤在构建/审核机执行。

2026-11-03 用户调整后，本文扫描流程属于可选增强项，见 [ADR-0049](adr/0049-functional-delivery-and-baseline-security.md)。默认 `RELEASE_SECURITY_PROFILE=baseline` 保留基本隔离、认证、路径、资源和签名校验，不要求完整 CVE 快照；包内 `docs/security-profile.json` 记录实际配置。已有匹配与覆盖缺口继续保留，baseline 不代表漏洞审核已完成。

## 采集与重放

```bash
python3 scripts/vulnerability_evidence.py plan --sbom /project/candidate/artifacts/sbom.cdx.json \
  --output /project/evidence/query-plan.json
python3 scripts/vulnerability_evidence.py fetch --sbom /project/candidate/artifacts/sbom.cdx.json \
  --snapshot /project/evidence/snapshot
```

snapshot 必须是新目录。采集只将公开包名/版本或提交发送给固定的官方 API；网络错误、响应超过 32MiB、分页不完整均记录失败，不当作零匹配。保存命令输出中的 `snapshot_sha256` 到审核流水线的可信记录中；仅从待验证目录临时重算摘要不能证明它未被整体改写。

```bash
python3 scripts/vulnerability_evidence.py replay --sbom /project/candidate/artifacts/sbom.cdx.json \
  --snapshot /project/evidence/snapshot --snapshot-sha256 '<外部固定的摘要>' \
  --output /project/evidence/report.json
```

重放不联网，重新核对计划、全部原始响应、分页和时间。证据有效窗为 24 小时；报告记录每页实际取得时间及 advisory 的 modified，不声称 API 提供全局数据库修订。报告输出路径也必须是新文件。

query_count 是去重查询数，不是完整软件覆盖分母。报告逐项区分查询、未知身份/版本、自己的代码、容器及来源/补丁缺口。`queried_no_matches` 仅表示数据库在本次查询没有匹配，不证明未索引组件安全。Ubuntu 使用已验证的源码包和完整源码版本，不去掉 epoch 或 Ubuntu 修订号。

活跃的源码包匹配还要审核是否涉及实际打包的二进制/代码，以及修复版本和补丁；它们不自动等于可利用漏洞。首版没有忽略清单或未经证据支持的可达性豁免。任何未处置匹配、查询错误或覆盖缺口都会使 replay 退出 1；输入/绑定错误也不能通过。

## 构建与依赖

设置 `RELEASE_SECURITY_PROFILE=extended` 的正式 `scripts/build-offline-release.sh` 要求 `RELEASE_SECURITY_SNAPSHOT` 与 `RELEASE_SECURITY_SNAPSHOT_SHA256`，在签名/打包前对实际新 SBOM 重放，生成将随发布包签名覆盖的 `docs/vulnerability-report.json`。同一软件/制品字节仅改变 SBOM UUID 或生成时间可复用有效快照；任一组件身份、归属、依赖或制品摘要变化都要求重新采集。baseline 不执行这个扩展门禁；其他发布和性能要求独立保留。

`RELEASE_ALLOW_DIRTY_TEST=1` 始终强制 `.test-signed.tar` 包名和 `-dirty-test` 标记，即使 Git 工作树干净；已有 switch 规则仍要求隔离验证根和显式测试许可。低层 pack CLI 仅提供封装/签名，不是完整生产验收器，不能用绕开正式构建脚本的方式声明生产门禁通过。

schema 验证依赖固定于 `deploy/requirements-validation.txt`，wheel、元数据、SHA256 和许可证保存在 `assets/build/python-validation`。按 README 建立项目内虚拟环境后可离线安装；CI 明确使用 Python 3.12。实际验证了 x64 Python 3.11/3.12，其他已保存 wheel 不冒充执行证据。

验证器要求官方 schema 使用的 `date-time`、`idn-email`、`iri-reference`、`uri` 四种格式检查器全部可用；缺任一种失败，避免可选依赖缺失时静默跳过验证。包和依赖闭包、生产基线继续跟踪；全面 CVE/静态来源深审、fuzz 与独立安全认证按[需求矩阵](REQUIREMENTS.zh-CN.md)列为增强项。
