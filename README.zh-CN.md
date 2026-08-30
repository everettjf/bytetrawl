# ByteTrawl

[English](README.md) · **简体中文** · [日本語](README.ja.md) · [Português (Brasil)](README.pt-BR.md) · [Español](README.es.md) · [Deutsch](README.de.md)

[![macOS](https://img.shields.io/badge/macOS-13%2B-d69b51?style=flat-square)](#系统要求)
[![许可证](https://img.shields.io/badge/license-Apache--2.0-d7d3c6?style=flat-square)](LICENSE)

ByteTrawl 是一个使用 Rust 编写的跨平台软件制品安全静态分诊、比较与发布审计工作台。它把应用、目录、发布包与单个文件统一建模为 Artifact，在不运行目标程序的情况下检查其结构、元数据、签名、依赖以及 PE、Mach-O 和 ELF 二进制内容。

最新桌面能力包括 Size Lab 与交互式 treemap、熵 Area Chart/热力图与 Hex 跳转、Canvas 依赖节点图、签名/Provisioning 时间线、IPA 架构/隐私矩阵、Findings 严重度筛选、可保存的面板显隐与拖拽宽度、高对比模式，以及本地 SVG 报告和窗口截图导出。

英文 [README](README.md#detailed-support-matrix) 是能力清单的规范源，并包含最新、最详细的逐项支持矩阵。安装最新版请使用下方 Homebrew 命令，发布文件见 [GitHub Releases](https://github.com/everettjf/homebrew-tap/releases)。

## 截图

[![ByteTrawl 正在检查 GrapeCompare.app](docs/assets/screenshots/overview.jpg)](https://xnu.app/bytetrawl/#gallery)

[在线图库](https://xnu.app/bytetrawl/#gallery) 会动态展示应用结构、Mach-O 信息、依赖解析、字符串提取和有界 Hex 查看。

## 安装

```sh
brew tap everettjf/tap
brew install --cask bytetrawl
brew install bytetrawl-cli
```

```sh
bytetrawl-cli --version
```

macOS 应用经过 Developer ID 签名和 Apple 公证，并附带公证票据。发布前会执行严格签名验证、公证票据验证和 Gatekeeper 评估。

## 主要能力

| 类别 | 当前支持 |
|---|---|
| macOS 与 iOS | `.app`、bundle、framework、插件、Mach-O/Universal Mach-O、DMG、flat PKG/XAR；IPA 身份、体积、嵌入目标、架构、本地化、隐私清单、描述字段、Provisioning Profile、entitlements 和发布 findings |
| Android | APK Manifest、包/版本/SDK、权限、导出组件、deep link、DEX 统计、ABI/native library、签名线索与发布 findings |
| Windows | PE/COFF 的头、节、导入导出、符号、依赖和 Authenticode 元数据；APPX/MSIX 身份、capabilities、应用入口、block map 与签名状态 |
| Linux | ELF 的头、架构、解释器、节、段、重定位、符号、依赖与 findings；DEB control、依赖、payload、安装尺寸、维护脚本与特权文件审计 |
| 容器与数据 | ZIP、tar/tar.gz、ar、DMG、ISO、JSON、XML、plist、SQLite、图片和文本；7z、RAR 与独立压缩流目前为类型识别级别 |
| 通用分析 | Artifact Tree、元数据、headers、slices、sections、segments、imports、exports、symbols、relocations、依赖图、字符串、按需 Hex、hash、熵、签名和 findings |
| 比较 | 基于 SHA-256 的精确内容身份；新增、删除、修改、移动、体积增长、重复文件，以及 IPA 隐私/签名/entitlement 变化 |
| 报告与 CI | JSON、Markdown、独立 HTML、SARIF；共享发布策略、severity gate、稳定退出码、原子输出与取消 |

详细能力、支持层级和明确边界见[英文完整支持矩阵](README.md#detailed-support-matrix)。报告格式见[版本化 schema](docs/report-schema.md)，自动化测试范围见[测试矩阵](docs/testing.md)。

## 桌面工作流

- 使用原生 macOS 菜单打开文件、文件夹、workspace 和新窗口。
- 文件、应用、包、workspace 或目录可直接拖到窗口中央。
- Artifact Tree、主内容区和 Details 区域可以调整大小；大型表格采用虚拟渲染。
- **External Tools…** 优先显示已安装且兼容的工具，未安装工具不会堆满 Details 面板。
- Workspace 保存路径、当前视图、书签、笔记和缓存分析结果。

快捷键：`⌘N` 新窗口、`⌘O` 打开文件、`⇧⌘O` 打开文件夹、`⌥⌘O` 打开 workspace、`⌘S` 保存、`⌘F` 搜索。

## CLI 示例

```sh
bytetrawl-cli inspect ./SomeApp.app --pretty
bytetrawl-cli inspect ./MyApp.ipa --depth deep --format sarif --output bytetrawl.sarif
bytetrawl-cli inspect ./package --hash sha256 --strings --entropy
```

`lightweight`、`standard` 和 `deep` 控制分析深度。退出码区分致命错误（`1`）、策略或 finding 失败（`2`）、取消（`4`）以及可用但不完整的报告（`5`）。

## 系统要求与构建

- Apple 芯片 Mac（`arm64`）
- macOS 13 Ventura 或更高版本
- 使用上述命令安装时需要 Homebrew

```sh
cargo run -p bytetrawl
```

核心分析层不依赖 GPUI，可在 macOS 上静态检查 Windows PE 和 Linux ELF。Windows 与 Linux 原生打包和 UI 验证尚在规划中。

## 安全边界

ByteTrawl 是只读静态分析工具：不会执行导入程序、挂载镜像、安装软件包、自动解包、反编译、调试进程或修改字节。目录发现不跟随符号链接；解析输入、递归深度、文件数、字符串、重定位、归档成员和外部命令输出都有显式限制。启发式 finding 是调查线索，不是恶意软件结论。

## 自动化质量保障

除完整 Rust workspace 测试、Clippy、Rust 1.88 最低版本、CLI/报告契约和 macOS App 构建启动测试外，ByteTrawl 还用 16 个经过长度与 SHA-256 固定的公开真实制品回归 IPA、APK、APPX/MSIX、有效及破坏签名的 macOS App、公证 PKG、DMG、ISO、PE、ELF、DEB、RPM 和异常 APPX。发布流程还会实际通过 Homebrew 安装 App 与 CLI，并验证 Developer ID 签名、Apple 公证、stapler、Gatekeeper 和 Formula 自测。详见[自动化测试矩阵](docs/testing.md)。

## 规划与文档

- [产品战略与路线图](docs/product-strategy.md)
- [现状与竞品分析](docs/product-analysis-roadmap.md)
- [IPAView 融合计划](docs/ipa-convergence-plan.md)
- [自动化测试矩阵](docs/testing.md)
- [GitHub Pages](https://xnu.app/bytetrawl/)

英文 README 是规范源；本地化页面在版本、安装方式或能力发生变化时同步更新。
