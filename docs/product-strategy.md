# ByteTrawl 产品战略与完整路线图

> 产品定位：**跨平台软件制品的安全静态分诊、比较与发布审计工作台**  
> 状态：产品主规划  
> 日期：2026-08-27

> 实施状态：1.1–1.5 的核心闭环已经落地，包括安全虚拟归档成员、IPA/IPAView
> 兼容审计、精确比较、统一策略与四种报告格式，以及 APK、APPX/MSIX、DEB 发布
> 审计。更深的平台格式扩展（MSI、RPM、Snap/Flatpak、AAB 拆分语义等）和 2.0
> 扩展 API 仍按下文路线演进，不属于当前已完成声明。实现证据见
> [report-schema.md](report-schema.md)。

## 1. 产品定义

ByteTrawl 面向已经构建完成、即将安装、准备发布或需要调查的软件制品。用户把一个应用、安装包、二进制、归档、磁盘镜像或目录交给 ByteTrawl，在不运行目标程序、不安装软件、默认不挂载镜像、不无界解压内容的前提下，快速获得以下答案：

1. **它是什么？** 格式、平台、架构、版本、身份和入口点。
2. **里面有什么？** 文件、组件、框架、插件、扩展、资源和嵌套制品。
3. **它依赖什么？** 系统库、内嵌库、缺失依赖和跨组件关系。
4. **它是否可信？** 签名、公证、证书、provisioning、entitlements、权限和安全特征。
5. **哪里值得关注？** 高熵、异常路径、错误架构、弱发布配置、危险权限、调试信息和格式异常。
6. **与上一版有什么变化？** 文件、体积、依赖、签名、权限、隐私声明和 findings 的增删变化。
7. **能否发布？** 是否满足团队定义的大小、架构、签名、隐私、安全和依赖门禁。
8. **下一步怎么分析？** 导出证据报告，或把选中节点交给专业反编译器、Hex 工具和平台工具。

### 一句话承诺

> 在运行、安装或发布一个软件制品之前，先用 ByteTrawl 看清它。

### 产品类别

ByteTrawl 不是单一格式查看器，也不是完整逆向工程平台。它位于三类工具之间：

```text
Finder / Quick Look / 文件管理器
                ↓
      ByteTrawl：识别、盘点、审计、比较、报告
                ↓
IDA / Ghidra / Binary Ninja / Hopper / ImHex / jadx / 平台工具
```

ByteTrawl 的价值是降低“第一轮理解软件制品”的成本，并把结果转化为可比较、可分享、可自动化的发布证据。

## 2. 产品原则

### 2.1 静态优先

- 默认不执行导入的程序、脚本或安装器。
- 默认不挂载未知磁盘镜像。
- 默认不完整解压归档；优先使用虚拟成员树和有界读取。
- 动态分析只通过用户明确触发的外部工具完成。

### 2.2 本地优先

- 默认所有分析在本机完成。
- 不上传用户制品、签名、证书、profile、字符串或报告。
- 将来如增加在线漏洞、信誉或 AI 服务，必须独立授权、明确展示发送内容，并提供完整离线模式。

### 2.3 证据优先

- 每个重要结论都应指向文件、archive member、字段、section、offset、证书或命令输出。
- Findings 是“带证据的检查结果”，不是笼统的恶意判断。
- 明确区分事实、规则判断、启发式推断、未知和分析失败。

### 2.4 快速渐进

- 打开后先显示结构和轻量 Summary。
- Hash、entropy、strings、完整依赖图、签名验证和规则包按需或按策略运行。
- 大制品使用虚拟化、缓存、取消、上限和增量计算。

### 2.5 跨格式统一，平台语义深化

- PE、Mach-O、ELF、IPA、APK、PKG 等共享 Artifact、Evidence、Finding、Compare 和 Report 模型。
- 平台差异通过独立 analyzer pack 表达，不把所有格式硬塞进一个巨型解析器。
- UI 先展示跨平台共同概念，再允许用户进入平台专项细节。

### 2.6 只读核心，专业工具协作

- ByteTrawl 近期不做 binary patching、完整反编译器或 debugger。
- 外部工具集成是一等能力，不是临时按钮。
- Handoff 应携带文件、member、offset、architecture 和 workspace 上下文。

## 3. 目标用户

### 3.1 发布与客户端工程师

典型问题：

- 为什么这个版本大了 80 MB？
- 是否误带 simulator architecture、debug symbols 或重复 framework？
- 签名、provisioning、entitlements、隐私声明和最低系统版本正确吗？
- 与已发布版本相比，是否新增权限、依赖或不安全配置？

核心价值：发布前审计、版本比较、体积归因、CI 门禁。

### 3.2 安全工程师和轻量逆向用户

典型问题：

- 这个陌生 App/安装包里包含哪些 executable、script、daemon 或 extension？
- 它由谁签名、是否公证、依赖哪些库、暴露哪些符号和字符串？
- 哪些异常值得交给 IDA、Ghidra、Hopper 或沙箱继续分析？

核心价值：安全的第一轮 triage、证据定位、专业工具 handoff。

### 3.3 跨平台开发者与支持工程师

典型问题：

- Windows/Linux 二进制的架构和依赖是否正确？
- 为什么用户环境缺库或无法启动？
- 安装包里实际装了什么？

核心价值：在一台机器上统一检查不同平台制品，快速排障。

### 3.4 高级用户与软件采购人员

典型问题：

- 安装前能否知道软件来自谁、要安装哪些内容、申请哪些权限？
- 新版本相较旧版本是否增加后台组件或隐私能力？

核心价值：低门槛可信摘要和版本变化说明。

### 用户优先级

第一优先级是发布/客户端工程师和安全工程师。高级用户界面可以更友好，但不能以牺牲证据准确性和专业深度为代价。

## 4. 核心用户工作流

### 4.1 导入制品

入口：

- 拖入文件或文件夹。
- File → Open File / Open Folder / Open Recent。
- 命令行参数和 Finder Open With。
- CLI `inspect`、`compare` 和未来的 `audit`。
- Workspace 恢复历史分析。

导入后立即记录 source identity：绝对路径、大小、修改时间、可选 SHA-256、容器/member locator 和分析时间。

### 4.2 识别与盘点

先做 magic/structure detection，再参考扩展名。输出：

- Artifact kind 和 file format。
- 目标平台、架构、位数、端序。
- 逻辑组件树和容器成员树。
- 身份、版本、入口点和主要 executable。
- compressed、uncompressed、installed 和 mapped size 等不同尺寸语义。

### 4.3 静态审计

审计层组合以下信号：

- 格式结构和 header。
- 组件、依赖和解析路径。
- 签名、证书、公证、provisioning 和 entitlements。
- privacy manifest、usage descriptions、manifest capabilities。
- sections、segments、imports、exports、symbols、relocations、strings、entropy。
- archive path/link/size/compression 风险。
- 平台发布规则和团队规则。

### 4.4 与基线比较

比较优先按语义而非纯字节：

- 文件 added/removed/changed/moved。
- 体积变化和 top regressions。
- 组件、架构、依赖、imports/exports 变化。
- 签名 identity、证书、profile、entitlements、permissions 和 privacy 变化。
- 新增、解决和保持的 findings。
- 必要时下钻到结构 diff 或 byte diff。

### 4.5 决策与报告

输出层：

- UI Summary。
- 版本化 JSON。
- Markdown/HTML 人类可读报告。
- SARIF 安全/CI 结果。
- CycloneDX/SPDX（有足够 provenance 时）。
- 可重复执行的 command/configuration 摘要。

报告必须说明 partial、cancelled、resource limited、unsupported 和 external verification 状态。

### 4.6 深度工具 Handoff

根据选中对象推荐已安装工具：

- Native binary → Hopper、IDA、Binary Ninja、Ghidra、Cutter/radare2。
- Android DEX/APK → jadx、Android Studio。
- 通用字节/未知格式 → ImHex、010 Editor、Synalyze It!。
- 平台命令 → codesign、otool、nm、readelf、objdump、dumpbin、Sigcheck 等。

未安装工具不应占据主要 UI；菜单可显示用途和安装提示。

## 5. 支持对象与能力层级

对外宣传统一使用四级支持标签：

| 等级 | 定义 | 示例 |
|---|---|---|
| Deep | 有稳定语义模型、结构解析、专项视图、findings 和测试样本 | PE、Mach-O/Fat Mach-O、ELF；完成后的 IPA |
| Structured | 可安全枚举结构和元数据，但未覆盖全部平台语义 | ZIP、tar、ar、XAR/PKG、DMG、ISO |
| Identified | 可可靠识别并显示通用信息，尚无成员级或语义级解析 | 当前 7z、RAR、gzip stream |
| Generic | 作为未知文件提供 Hex、search、strings/hash/entropy 等通用能力 | Unknown binary |

不再只用“支持/不支持”二元表述，避免把扩展名归类误解为完整支持。

### 目标平台包

1. **Apple Pack**：Mach-O、Universal Mach-O、`.app`、`.framework`、`.appex`、IPA、PKG、DMG、provisioning、entitlements、privacy、notarization。
2. **Windows Pack**：PE、DLL/SYS、Authenticode、resources、manifest、CLR/.NET、APPX/MSIX、MSI。
3. **Linux Pack**：ELF、`.so`、ar、DEB、RPM、AppImage、Snap/Flatpak metadata。
4. **Android Pack**：APK/AAB/APKS/XAPK、Manifest、DEX summary、resources、signing、permissions/privacy。
5. **Generic Container Pack**：ZIP、tar、gzip、7z、RAR、ISO 和结构化 archive member。

平台包是能力组织方式，不意味着做成必须联网下载的插件。第一阶段可以继续静态编译。

## 6. 六大产品支柱

### 6.1 Artifact Explorer

目标：任何制品都能形成可导航的逻辑树。

能力：

- 文件系统节点和 archive member 统一展示。
- 应用、可执行文件、框架、库、插件、extension、资源、metadata、script、package 和 image 分类。
- Virtualized tree、breadcrumb、过滤、搜索和证据跳转。
- 文本、plist、JSON/XML、图片和 Hex 安全预览。
- Recent Artifacts、Bookmarks、Notes、Workspace。

### 6.2 Format & Platform Intelligence

目标：从“字节是什么”提升到“平台怎样理解这些字节”。

能力：

- PE/Mach-O/ELF headers、sections、segments、imports、exports、symbols、relocations 和 slices。
- App/package identity、targets、architectures、minimum OS、capabilities 和 install metadata。
- Container entry、compression、filesystem/volume 和 payload semantics。
- Strings 与 section/virtual address 映射。
- 未来的 typed structure/template 支持。

### 6.3 Trust & Security Audit

目标：解释制品的信任状态和发布风险，不做黑箱“安全/恶意”结论。

能力：

- Code signature、certificate chain、timestamp、Team/Publisher identity。
- Apple notarization、Hardened Runtime、resource seal、provisioning、entitlements。
- Windows Authenticode、manifest/security features。
- Android signing schemes、permissions/exported components。
- Archive traversal、symlink、setuid/script/install target 风险。
- Rules、severity、confidence、evidence、remediation、suppression。

### 6.4 Compare & Size Intelligence

目标：回答“新版本变了什么，为什么”。

能力：

- Artifact structure diff。
- compressed/uncompressed/installed/mapped size 模型。
- Treemap、类型 breakdown、top growth、duplicate resources。
- architecture、dependency、signature、permission、privacy 和 finding diff。
- Baseline 和 budget。

### 6.5 Reports & Release Gates

目标：让桌面分析进入发布流程。

能力：

- UI 与 CLI 共用 analyzer、规则和 report schema。
- JSON、Markdown、HTML、SARIF；谨慎生成 SBOM。
- `--fail-on`、size budget、forbidden change、required rule 等策略。
- deterministic output、schema version、atomic write 和 reproducible config。
- CI 示例：GitHub Actions、通用 shell、未来其他 CI。

### 6.6 Tool Ecosystem

目标：ByteTrawl 成为分析入口和上下文协调器。

能力：

- Installed tool discovery、format compatibility 和推荐排序。
- Launch 与 bounded capture 两类行为。
- 传递 member/offset/architecture/context。
- 后期开放 analyzer、rule pack、reporter 和 tool adapter 扩展点。

## 7. 信息架构与交互

当前大量横向 tabs 随格式增加会失控。目标信息架构按用户问题组织：

### 一级导航

1. **Summary**：Identity、关键体积、Trust、Findings、主要变化。
2. **Contents**：Artifact/member tree、Preview、Metadata、Files。
3. **Platform**：Targets、Manifest/Plist、Privacy、Signing、Install 等平台专项内容。
4. **Binary**：Overview、Slices、Headers、Segments、Sections、Relocations、Imports、Exports、Symbols、Strings、Hex。
5. **Relationships**：Dependencies、Dependency Graph、embedded component relationships。
6. **Compare**：Contents、Size、Binary、Trust、Privacy、Findings diff。
7. **Report**：运行状态、规则、导出和 CI configuration。

### 布局

- 左侧：Artifact/Member Tree，可调整宽度。
- 中间：当前一级导航和主内容。
- 右侧：上下文 Details、Evidence、Actions、Notes。
- 顶部：全局 Search、当前 Artifact identity、分析状态。
- 底部：进度、partial/error/resource limit 和安全模式状态。

### 渐进披露

- 普通用户首先看到结论和解释。
- 专业用户可下钻原始字段、offset 和 command output。
- “No finding”不表述为“安全”，应表述为“当前启用规则未发现问题”。

## 8. 核心技术架构

### 8.1 分层

```text
Input & Source Layer
  Filesystem / Archive Member / Disk Image Member / Future Remote Artifact
                         ↓
Detection & Artifact Layer
  Magic / Logical Tree / Identity / Source Provenance
                         ↓
Format Analyzers
  PE / Mach-O / ELF / Archive / Metadata / Image / Database
                         ↓
Platform Analyzers
  Apple / iOS / Windows / Linux / Android
                         ↓
Evidence & Rule Engine
  Facts → Evidence → Findings → Suppression / Policy
                         ↓
Compare & Report
  Snapshot / Baseline / Diff / JSON / HTML / SARIF / CLI
                         ↓
GPUI Desktop & Tool Integrations
```

### 8.2 Artifact Source

必须从“每个节点都有真实 `PathBuf`”演进为：

- `Filesystem`
- `ArchiveMember`
- `DiskImageMember`（后续）
- 可选 `MaterializedTemporary`，仅显式动作使用

统一的 bounded reader 提供 prefix/range/all-with-limit，不允许 analyzer 绕过限制直接无界读取。

### 8.3 Facts、Evidence 与 Findings

建议把 analyzer 输出分成三层：

- **Fact**：解析得到的客观字段，如 Team ID、section flags、entry path。
- **Evidence**：Fact 的来源定位，如 plist key、archive member、file offset。
- **Finding**：规则对 Facts 的判断，包含 rule ID、severity、confidence、description、remediation 和 evidence references。

这样 compare 可以比较 Facts，报告可以追踪 Evidence，规则可以迭代而不改 parser。

### 8.4 Snapshot 与缓存

Snapshot 必须包含：

- schema/analyzer version。
- source identity 和可选 content hash。
- 启用的 analysis depth/rules/configuration。
- facts、findings、errors、partial/cancelled。
- 缓存有效性条件。

Compare 只重算变化节点；规则变化时可尽量复用 facts 重跑 findings。

### 8.5 Crate 方向

- `bytetrawl-core`：Artifact、Source、Fact、Evidence、Finding、Snapshot、Compare contract。
- `bytetrawl-format`：PE/Mach-O/ELF 与基础 magic。
- `bytetrawl-container`：ZIP/tar/ar/XAR/DMG/ISO 和 virtual members，可从 analysis 中拆出。
- `bytetrawl-apple`：macOS bundle、signature/notarization、PKG/DMG 语义。
- `bytetrawl-ios`：IPA、mobileprovision、privacy、embedded targets。
- 后续 `bytetrawl-windows`、`bytetrawl-linux`、`bytetrawl-android`。
- `bytetrawl-rules`：规则执行、policy、suppression。
- `bytetrawl-report`：schema、diff、JSON/HTML/SARIF。
- UI、CLI 和 tools 继续独立。

无需一次完成拆分；每次只在新能力确实需要边界时迁移。

## 9. 安全模型

ByteTrawl 分析的输入默认不可信。

### 必须保持的约束

- 不执行 imported code。
- 不运行 installer scripts。
- 不自动启动外部工具。
- 不跟随 filesystem/archive symlink。
- path normalization 防止 archive traversal。
- file count、depth、parse bytes、entry count、expanded bytes、compression ratio、strings、rows、subprocess output 和时间均有上限。
- 每个昂贵任务支持 cancellation。
- Parser panic 不得导致整个 workspace 丢失。
- 临时物化内容使用隔离随机目录、严格尺寸上限、quarantine 和生命周期清理。
- 外部命令参数不得经过 shell 拼接。

### 工程保障

- 每个 parser 都有 malformed fixtures 和 fuzz target。
- 维护 adversarial corpus：zip slip、zip bomb、重复 entries、错误 size/CRC、深层 XML/plist、截断 binary、overlapping sections、循环/逃逸路径。
- 报告明确显示未分析、跳过、失败和受限内容。
- 发布制品继续强制 Developer ID 签名、Apple notarization、ticket staple、codesign/stapler/spctl 验证。

## 10. 完整版本路线图

版本号表示产品里程碑，不承诺固定日期。建议以 2–6 周为一个可交付阶段，避免长期大分支。

### 1.1 — Safe Artifact Foundation

目标：让容器内成员成为一等 Artifact，建立后续平台分析的安全基础。

范围：

- `ArtifactSource` 与 bounded `ArtifactReader`。
- ZIP/tar/ar/XAR virtual member tree。
- 文本、plist、JSON/XML、图片和 Hex 安全预览。
- 统一 Evidence Link，可从 finding/search 跳到 member/offset/key。
- Recent Artifacts。
- Snapshot schema 增加 generator/configuration/partial/errors。
- Archive adversarial corpus 和 fuzzing 基线。

完成标准：不解压即可浏览包；危险路径不能写出；10 万 entries 可虚拟化；取消有效；旧文件系统 Artifact 行为不回归。

### 1.2 — Apple & IPA Audit

目标：完整覆盖 IPAView，并把 Apple 发布审计融入统一工作台。

范围：

- IPA Payload/main app、identity、installed size、frameworks、extensions、localizations。
- 主程序及 embedded targets 的 Mach-O 分析。
- mobileprovision、Team/Application ID、expiration、entitlements。
- UsageDescriptions、PrivacyInfo.xcprivacy presence。
- IPAView 现有 findings 和兼容 JSON。
- macOS bundle identity/components/entitlements/signature/notarization 深化。
- PKG Distribution/PackageInfo/Scripts/Payload/BOM 摘要。

详细等价和迁移门槛见 [ByteTrawl × IPAView 功能收敛规划](ipa-convergence-plan.md)。

完成标准：IPAView parity matrix 全通过；共享 golden fixtures 一致；20 个合法样本核心字段一致；ByteTrawl 可以承担 IPAView 的主要用户任务，但 IPAView 仍保留迁移期。

### 1.3 — Compare & Size

目标：从静态查看器升级为版本决策工具。

范围：

- 两个文件、应用、包或 workspace snapshot 比较。
- added/removed/changed/moved 文件。
- compressed/uncompressed/installed/mapped size 和目录聚合。
- Treemap、type breakdown、top growth、duplicates。
- architectures、dependencies、signature、entitlements、privacy 和 findings diff。
- Baseline、size budgets 和“只看新增问题”。
- CLI `compare OLD NEW`。

完成标准：可以用一份结果解释主要体积变化和发布安全变化；未变化内容通过缓存跳过；大制品比较可取消。

### 1.4 — Evidence, Rules & Reports

目标：建立可靠、可配置、可进入 CI 的审计系统。

范围：

- 稳定 rule ID、severity、confidence、remediation、references。
- Rule profile、enable/disable、severity override、suppression reason/expiry。
- Markdown/HTML 报告、SARIF、改进版 JSON。
- CLI policies：required/forbidden changes、size、signature、architecture、privacy。
- Deterministic output 和 schema migration 文档。
- 可选 YARA 本地集成，清晰标记 pattern match。

完成标准：同一配置在 GUI/CLI 得到一致结果；报告中所有高优先级 findings 都有证据；GitHub Actions 示例可以阻止发布回归。

### 1.5 — Platform Packs

目标：把统一模型扩展到 Windows、Linux 和 Android 的发布语义。

按需求依次交付，而非同时开发：

**Windows**

- PE resources/version/manifest、TLS、exception/debug/load config、CLR metadata。
- APPX/MSIX manifest、capabilities、publisher/signature、members。
- MSI tables、custom actions 和 install impact。

**Linux**

- ELF notes/build-id/versioned symbols/RPATH/RUNPATH/glibc baseline。
- DEB control/data、RPM headers/payload、AppImage、Snap/Flatpak metadata。

**Android**

- APK/AAB/APKS/XAPK members。
- AndroidManifest、permissions/components/exported/deep links。
- DEX counts、resources summary、signing schemes。
- 代码反编译交给 jadx。

完成标准：每个平台至少有一个“发布审计”完整工作流，而不只是增加格式识别。

### 2.0 — Extensible Artifact Workbench

目标：稳定扩展接口与团队级工作流。

候选范围：

- Analyzer、rule pack、reporter、tool adapter 扩展 API。
- Kaitai Struct 或兼容结构模板的只读集成。
- Workspace/report bundle 分享与 redaction。
- 团队 policy 配置版本化。
- 可选离线 SBOM/OSV/Trivy 工作流。
- Windows/Linux 原生桌面发布达到正式支持。

2.0 不以“功能更多”为标准，而以 schema、extension 和跨平台兼容性稳定为标准。

## 11. 明确不做或后置

### 近期不做

- 完整 native decompiler。
- Debugger 和动态 instrumentation。
- Binary patching、re-signing、sideloading 或安装功能。
- 自动执行安装脚本或样本。
- 云端上传和病毒评分。
- 自建漏洞数据库。
- 为了格式数量而添加没有语义和测试的扩展名识别。

### 可以通过集成满足

- 反编译与 CFG → IDA/Ghidra/Binary Ninja/Hopper/Cutter/jadx。
- 高级 Hex/template/edit → ImHex/010 Editor/Synalyze It!。
- 漏洞数据库 → OSV-Scanner/Trivy。
- Malware pattern → YARA。
- 动态分析 → 用户选择的 sandbox/debugger。

## 12. 优先级方法

每个候选能力按以下权重评分：

- 用户任务频率：25%
- 发布/安全决策价值：20%
- 与定位的差异化：20%
- 复用现有 Artifact 架构：15%
- 证据可靠性和可测试性：10%
- 实现与维护成本反向分：10%

### 当前排序

| 能力 | 优先级 |
|---|---:|
| Archive member tree + bounded reader | P0 |
| Evidence links 和稳定 snapshot/report contract | P0 |
| IPAView parity / Apple release audit | P0 |
| Artifact Compare | P0 |
| Size attribution / treemap | P0/P1 |
| Explainable rules 和 HTML/SARIF | P1 |
| PKG install impact | P1 |
| Windows/Linux/Android platform packs | P1/P2，按用户需求 |
| YARA/SBOM/OSV integration | P2 |
| Kaitai/typed structures | P2 |
| 内置小范围 disassembly preview | P3 |
| Decompiler/debugger/patching | 非近期目标 |

## 13. 成功指标

### 产品指标

- 首次导入到 Summary 可用的 P50/P95。
- Artifact 打开成功率、partial 比例、unsupported 分类和 parser error 率。
- 用户从 root 到 evidence 的时间和点击数。
- Compare 后能被明确归因的体积变化比例。
- 新增权限/签名/依赖变化被发现的比例。
- 报告导出率、baseline 使用率、CLI/CI 使用率。
- External tool handoff 率和目标工具分布。
- Finding 有用率、suppression 率和误报反馈。

### 近期工程 SLO

- 普通 `.app`/IPA 在 2 秒内出现可用轻量树和 Summary；深度任务可继续后台运行。
- 10 万节点保持可滚动、可搜索且不一次实例化全部 UI 行。
- 500 MiB binary 的 Hex 打开不整文件复制到 UI 内存。
- 归档和 parser 限制触发时提供明确 partial report，而不是卡死或崩溃。
- Compare 对未变化文件使用 source identity/hash cache。

### 质量门槛

- 新 parser 必须有正常、截断、恶意和资源上限测试。
- 新 rule 必须有 positive/negative fixture、证据断言和说明文档。
- 新 report schema 必须有 snapshot test 和 migration note。
- 发布前通过 workspace tests、格式检查、真实制品 smoke test、Homebrew audit/install test。
- macOS release 必须签名、公证、staple 并通过 Gatekeeper。

## 14. 发布与分发策略

### 渠道

- Homebrew Cask：macOS 主渠道。
- GitHub Release：签名、公证、stapled App 和 CLI artifacts。
- GitHub Pages：产品定位、支持矩阵、截图、报告示例和 release verification。
- CLI Formula：开发者和 CI 用户。

### Release 内容

每次 release notes 必须包含：

- 新增的 Deep/Structured/Identified 支持等级。
- 新规则和可能的行为变化。
- Report schema 变化。
- 已知限制和 partial cases。
- 测试、签名、公证和安装验证。

### 版本兼容

- Report/schema 使用独立整数版本，不完全绑定 App semver。
- Workspace 迁移向前兼容；不支持时给出可理解错误，不覆盖原文件。
- Rule ID 一经发布保持稳定，重命名通过 alias/migration。

## 15. 生态与商业化方向

当前优先验证产品任务，不急于用复杂收费结构限制采用。

### 可持续方向

- 免费核心：本地单制品查看、基础审计、通用 CLI。
- 专业能力候选：Compare history、团队 policies、高级报告、CI baselines、平台专项规则包。
- 团队能力候选：共享 policy、报告签名、集中 baseline、审计历史；必须保持制品不上云的部署选项。

任何商业化都不应破坏：本地分析、报告可导出、基本格式查看、安全限制和用户对自己数据的控制。

## 16. 风险与控制

| 风险 | 控制策略 |
|---|---|
| 功能范围扩张成不完整 IDA | 坚持“分诊/比较/发布审计”，深度代码分析用 handoff |
| 格式多但支持浅 | 公开四级支持矩阵，每个 Deep 格式要求语义、findings 和 fixtures |
| 恶意输入攻击 parser | bounded reader、fuzzing、adversarial corpus、取消与 partial report |
| Findings 误导用户 | evidence/confidence/remediation；禁止“无 findings = 安全”措辞 |
| 报告 schema 快速失控 | versioned DTO、snapshot tests、migration notes |
| GUI 与 CLI 结果不一致 | 共用 analyzer、rules、snapshot 和 report crates |
| 平台专项代码污染 core | 独立 platform analyzer packs |
| 云功能损害隐私定位 | local-first、显式 opt-in、展示发送内容、offline mode |
| IPAView 迁移造成能力倒退 | golden fixtures、双实现对照、真实样本和维护迁移期 |

## 17. 执行治理

### 每个里程碑必须有

- 用户问题和成功标准。
- 支持层级变化。
- 数据模型/schema 变化。
- 安全边界和资源限制。
- fixtures、tests 和 benchmark。
- UI、CLI、报告三端影响。
- 文档、截图、release note 和迁移说明。

### 每个功能的 Definition of Done

1. 正常输入可用。
2. malformed/敌意输入安全失败。
3. 可取消、有限制、错误可见。
4. GUI 与 CLI 共享结果。
5. 重要结论有 Evidence。
6. 报告可序列化且 snapshot 稳定。
7. 文档明确支持等级和限制。
8. 对真实制品完成 smoke test。

### 规划维护

- 本文档是 ByteTrawl 产品方向的主来源。
- [现状分析与竞品研究](product-analysis-roadmap.md) 作为决策依据和历史研究。
- [IPAView 功能收敛规划](ipa-convergence-plan.md) 作为 Apple/IPA 专项执行计划。
- 每个重要版本发布后复查路线图，完成项移入 release notes，未完成项重新排序，避免无限累积。

## 18. 立即执行的下一步

第一批工作不从新增规则或 UI 页面开始，而从可复用基础开始：

1. 为 `ArtifactSource` 和 bounded `ArtifactReader` 写 RFC/接口与测试。
2. 引入 ZIP virtual member nodes，保留现有中央目录风险检测。
3. 建立 Evidence locator，支持 filesystem path、archive member、plist key、file offset。
4. 导入 IPAView golden fixtures 和 JSON snapshots。
5. 在新 `bytetrawl-ios` 中完成 IPA detection、Payload/main app 和 identity。
6. 把结果接入现有 Artifact Tree、Metadata 和 CLI report。

完成这六项后，再进入 IPA provisioning/privacy 规则和 UI 产品化。这样同一基础也能服务 APK、APPX/MSIX、PKG、DEB/RPM 和未来 Compare。
