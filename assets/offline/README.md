# 离线发布的项目内运行制品

本目录保存发布包真正依赖的两套架构制品。`linux-amd64/` 与 `linux-arm64/` 各含 Firecracker、jailer、`mkfs.ext4`、其七个动态加载器/库文件、guest kernel、guest rootfs、`agent-init` 和重建 rootfs 所需的静态 BusyBox。BusyBox 从已验收 rootfs 中提取，按目标架构核对为静态 ELF，摘要收入 `SHA256SUMS`。这些文件不是 `/tmp` 验证缓存；重新打包默认从此目录读取，并先核对各目录的 `SHA256SUMS`。

| 架构 | Firecracker 来源 | guest kernel 来源 | rootfs 来源 | mkfs 来源 |
|---|---|---|---|---|
| amd64 | 官方 v1.16.1 x86_64 发布包，压缩包 SHA-256 `382a02a869e4d6d5cb14c40577f9545e8458021ea8b0b2d3fc10ec14d9c242e6` | Firecracker CI `firecracker-ci/20261028-84df49062576-0/x86_64/vmlinux-6.18.56` | 本项目 x86_64 Linux guest 构建产物 | Debian 12 `e2fsprogs` 与运行库闭包 |
| arm64 | 官方 v1.16.1 aarch64 发布包，压缩包 SHA-256 `8d0e69f6d6f9a1724551f607f18504052c16c1828ee3d4d7b6e6c73380871e0e` | Firecracker CI `firecracker-ci/20261028-84df49062576-0/aarch64/vmlinux-6.18.56` | 本项目 aarch64 Linux guest 与 Debian 12 arm64 静态 BusyBox 构建产物 | Debian 12 `e2fsprogs` 与运行库闭包 |

Firecracker 压缩包来自镜像站，已与 GitHub 官方发布 API 给出的 SHA-256 一致后才提取。发布包的静态 Go 程序由 `scripts/build-offline-release.sh` 在打包时按目标架构编译；`scripts/build-firecracker-linux-rootfs.sh` 默认使用本目录的 BusyBox 重建 guest rootfs。发布签名私钥、租户策略、mTLS 私钥和证书不进入这里。二进制资源较大，克隆或转存仓库时需连同此目录一起保留，并运行 `sha256sum -c SHA256SUMS`。
