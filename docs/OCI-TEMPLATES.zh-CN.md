# 签名模板 OCI 工具

`osv-template-oci` 支持本地 OCI layout 的 export/import，以及私有 registry 的 push/pull。程序为对应架构的静态 Go 文件；目标机无需安装 Go、Python、Docker 或 registry 服务。export/import 可以完全断网运行。官方 schema 检查及独立 registry 是构建验收依赖，不是目标机依赖。

每个 layout 对应一套架构/backend 的签名模板。artifact 目录包含原始 `manifest.json`、`manifest.json.sig`、`sbom.cdx.json`，以及 manifest 指定的 kernel/rootfs。传输保持这五份文件的原始字节；不打包宿主钩子，也不从包内选择信任公钥。许可证和构建来源仍保留在原发行资产中。

## 本地导出与断网导入

目标父目录须存在，目标目录须不存在。以已安装工具和 Linux 模板为例：

```sh
/opt/osv-sandbox/current/bin/osv-template-oci export \
  -source /srv/templates/linux-code/artifacts \
  -destination /srv/oci/linux-code-amd64 \
  -architecture amd64 -backend firecracker-linux \
  -public-key /etc/osv-sandbox/artifact.public \
  -firecracker /opt/osv-sandbox/current/bin/firecracker \
  -jailer /opt/osv-sandbox/current/bin/jailer
```

stdout 输出 descriptor JSON。通过受信渠道保存完整 `sha256:...` digest；接收方显式传入该值：

```sh
/opt/osv-sandbox/current/bin/osv-template-oci import \
  -source /srv/oci/linux-code-amd64 \
  -digest 'sha256:<受信渠道确认的完整OCI-manifest摘要>' \
  -destination /srv/templates/imported-linux-code-amd64 \
  -architecture amd64 -backend firecracker-linux \
  -public-key /etc/osv-sandbox/artifact.public \
  -firecracker /opt/osv-sandbox/current/bin/firecracker \
  -jailer /opt/osv-sandbox/current/bin/jailer
```

替换示例摘要后执行。模板公钥是 base64 Ed25519 公钥，与完整发行包使用的 PEM 公钥不同，须单独获得且不能由 group/other 写入。ARM 使用 `-architecture arm64` 和匹配的 ARM Firecracker/jailer。OSv 使用 `-backend firecracker-osv`，并按受信策略重复传入 `-entrypoint /模块路径`，例如 `/python3.12.so`。

## Registry 推送与拉取

registry 默认 HTTPS，验证系统或显式提供的 CA。可选 `-registry-client-cert` / `-registry-client-key` 启用 mTLS。认证文件权限须为 0600，JSON 二选一：

```json
{"username":"registry-user","password":"<密码>"}
```

```json
{"token":"<预先获得的Bearer-token>"}
```

凭据不能放在 URL 中；工具不自动访问第三方 token realm。推送仍使用本地 layout 的已知 digest，reference 可选 tag；省略时使用相同 digest：

```sh
/opt/osv-sandbox/current/bin/osv-template-oci push \
  -source /srv/oci/linux-code-amd64 \
  -digest 'sha256:<完整OCI-manifest摘要>' -reference release-amd64 \
  -registry-url https://registry.example:5000 -repository sandbox/linux-code \
  -registry-ca /etc/osv-sandbox/registry-ca.crt \
  -registry-auth /etc/osv-sandbox/registry-auth.json \
  -architecture amd64 -backend firecracker-linux \
  -public-key /etc/osv-sandbox/artifact.public \
  -firecracker /opt/osv-sandbox/current/bin/firecracker \
  -jailer /opt/osv-sandbox/current/bin/jailer
```

拉取只接受 digest，先生成新 OCI layout，再显式 import：

```sh
/opt/osv-sandbox/current/bin/osv-template-oci pull \
  -destination /srv/oci/downloaded-linux-code-amd64 \
  -digest 'sha256:<完整OCI-manifest摘要>' \
  -registry-url https://registry.example:5000 -repository sandbox/linux-code \
  -registry-ca /etc/osv-sandbox/registry-ca.crt \
  -registry-auth /etc/osv-sandbox/registry-auth.json \
  -architecture amd64 -backend firecracker-linux \
  -public-key /etc/osv-sandbox/artifact.public \
  -firecracker /opt/osv-sandbox/current/bin/firecracker \
  -jailer /opt/osv-sandbox/current/bin/jailer
```

推送前完整验签、上传时再次计算摘要，已有 blob 通过 HEAD 复用；提交后按 digest 读回确认。若报“publication unconfirmed”，使用原 digest 检查远端内容，不能当作发布成功。当前不做单 blob 断点续传；已完成 blob 可在重新执行时复用。源 layout 应由可信管理员控制，推送时不能让其他用户改写。`-work-dir` 可选择私有验证工作目录；同文件系统优先使用临时硬链接，跨文件系统可能复制大镜像。`-registry-timeout` 为单个请求的期限，默认 30m，Ctrl-C/SIGTERM 取消整个操作。

只跟随同 origin 的只读跳转；跨 origin 对象存储和写请求跳转明确拒绝。无法通过关闭证书校验来绕过 TLS；`-allow-loopback-http` 仅允许 loopback IP 上的本地测试服务。

## 文件发布与接入

导入/拉取先认证有界元数据，再处理大镜像；最后复用生产验证器核对实际镜像、SBOM 和宿主二进制。私有 staging 位于目标同父目录，全部校验并同步后才原子发布；已有目标拒绝，竞争操作返回 busy/已存在。目标旁保留的小型 `.oci.lock` 用于互斥，进程退出不会持续占锁，不应在其他操作运行时删除。

目标父目录由可信管理员控制。工具只发布只读 guest 文件，不切换运行中配置、默认模板或 VM。接入 root launcher 仍经过原生产配置、权限和准入流程。完整发行升级使用与新包匹配、经带外摘要核对的 bootstrap；旧 verifier 对未知载荷的拒绝不应被绕过。

## 开发与验收状态

设计见 [ADR-0083](adr/0083-signed-template-oci-distribution.md)。[本地布局](../PUBLIC-QUALIFICATION.md#private-evidence)及 [registry 互操作](../PUBLIC-QUALIFICATION.md#private-evidence)完成组件验证；[rc78](../PUBLIC-QUALIFICATION.md#private-evidence)完整双架构包、已安装CLI及ARM51组功能已通过，指定机同候选KVM仍待验收。此前 rc77 不包含该工具。开发程序保存在项目 `build/validation/template-oci-registry`，目标发行手册只包含本节之前的运行说明。
