# ADR-0016：零 npm 依赖的 Node.js / TypeScript 原生客户端

状态：Accepted；日期：2026-10-30；需求 API-02、REL-04。继承 ADR-0012 和 ADR-0015。

## 决策

离线包同时提供可直接执行的 Node.js ESM、独立 `.d.ts` 类型声明与本地 `package.json`。客户端需要目标端已有 Node.js 20+，运行时只使用 `node:https` 与 `node:fs`，无 npm 下载或第三方运行库。应用服务器的安装、运行不依赖 Node.js。与 Python 客户端保持同一原生 API 契约：HTTPS、mTLS、bearer、能力发现、签名 v2 模板绑定、显式 v1、输入文件与类型化 409。禁止隐式降级、重定向、代理和关闭 TLS 校验。发布 manifest 覆盖三个文件，Linux SBOM 记录可执行源码及类型声明的摘要。

Node.js 客户端只解决原生 API 的 TypeScript 调用路径。E2B 固定版本方法矩阵与行为兼容率须单独验收，不能用 `.d.ts` 存在推断完成。

## 验收

本地 Node 单元契约测试、离线包签名和文件摘要、ARM64 QEMU 包验证，以及 x64 安装包的真实 mTLS API→launcher→KVM 任务。TypeScript 编译检查需要可用的 `tsc`；无编译器环境时不能宣称该项通过。
