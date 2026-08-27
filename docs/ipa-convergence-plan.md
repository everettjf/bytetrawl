# ByteTrawl × IPAView 功能收敛规划

> 目标：让 ByteTrawl 完整覆盖并最终超越 IPAView 的 IPA 查看与发布审计能力，同时保持 ByteTrawl 的静态、只读、安全和跨格式架构。

## 决策摘要

IPAView 暂时继续维护，ByteTrawl 不立即取代它。迁移采用“测试先行、双实现对照、达到验收线后再停止 IPAView 独立发布”的方式。

建议最终形态：

- IPA 成为 ByteTrawl 的一等 Artifact，而不只是 ZIP 扩展名。
- IPA 专属能力放入独立的 iOS analyzer；通用 ZIP、Mach-O、plist、signature、strings、hash、entropy 和 dependency 能力继续复用 ByteTrawl 现有模块。
- 默认不完整解压 IPA。成员树、plist、provisioning 和 Mach-O 通过有界 Archive Member reader 按需读取；只有用户明确交给外部工具时，才把单个成员安全地物化到隔离临时目录。
- IPAView 的 JSON 报告字段在迁移期保持兼容，同时增加 `schema_version`、分析器版本、输入 hash、partial/errors 和 embedded targets。
- IPAView 的历史代码作为行为基线，不直接把 SwiftUI 或 ZIPFoundation UI 架构搬进 GPUI。

## 1. 必须达到的 IPAView 功能等价线

ByteTrawl 只有满足以下全部条件，才可以宣称完整替代 IPAView：

| 能力 | 等价验收标准 |
|---|---|
| 打开 IPA | 文件选择、拖拽、启动参数和最近打开都能识别 `.ipa`；错误 IPA 给出 Payload/App/Info.plist 等明确原因 |
| IPA 成员树 | 展示 ZIP → Payload → 主 `.app` → Frameworks/PlugIns/资源；无需用户手动解压 |
| App Identity | 自动给出名称、Bundle ID、marketing version、build、minimum OS、executable |
| 文件和安装尺寸 | 每个文件提供 path、uncompressed/installed bytes；报告提供总 installed size；目录可聚合 |
| Frameworks | 自动枚举主 App 内嵌 `.framework`，并可进入其 Mach-O/Info.plist |
| Extensions | 自动枚举 `.appex`，显示 identity、executable、architecture、entitlements 和 privacy metadata |
| Localizations | 汇总 `.lproj`，去重并按 locale 展示 |
| Mach-O Architectures | 自动定位主 executable，解析 thin/fat slices；至少与 IPAView 的 i386/arm/x86_64/arm64/arm64_32 结果一致 |
| Provisioning | 解析 `embedded.mobileprovision` 的 Team ID、Application ID、ExpirationDate 和 Entitlements |
| Privacy Usage | 汇总 `NS*UsageDescription` 的 key/value |
| Privacy Manifest | 检查 App 与 embedded SDK/extension 中 `PrivacyInfo.xcprivacy` 的存在性 |
| Findings | 覆盖 IPAView 现有 7 类规则及相同严重程度语义 |
| JSON Export | 可导出 IPA 专属 JSON；日期为 ISO-8601，键稳定且文档化 |
| Recent Files | 提供最近 IPA/Artifact 入口，文件失效时可移除或标记不可用 |
| 文件浏览 | 可搜索、选择和预览 IPA 内成员，并从 findings 跳转到证据节点 |

IPAView 当前规则必须原样覆盖：

- `missing-bundle-id`
- `missing-version`
- `missing-privacy-manifest`
- `missing-executable`
- `simulator-architecture`
- `missing-provisioning-profile`
- `weak-NS*UsageDescription`

迁移到 ByteTrawl 后建议使用带命名空间的稳定 ID，例如 `ios.ipa.missing-bundle-id`。兼容 JSON 中可以同时保留旧 `code`。

## 2. 架构规划

### 2.1 先解决 Archive Member，不直接完整解压

ByteTrawl 当前节点以 `PathBuf` 指向物理文件。IPA 的真正内容位于 ZIP entry 中，因此先引入数据源抽象：

```text
ArtifactSource
├── Filesystem(PathBuf)
└── ArchiveMember
    ├── container: PathBuf
    ├── member_path: normalized relative path
    ├── compressed_size
    ├── uncompressed_size
    ├── crc32
    └── entry_index
```

所有 parser 不应直接假设 `std::fs::File`，而应逐步依赖有界的 `ArtifactReader`：

- `read_prefix(limit)`
- `read_range(offset, length)`
- `read_all(max_bytes)`
- `materialize_to_quarantine(max_bytes)`，仅显式外部工具动作可用

安全条件：

- member path 必须规范化并拒绝绝对路径、`..`、NUL 和目录逃逸。
- 不跟随 archive symlink。
- 同时限制 entry 数、单 entry 展开尺寸、总声明尺寸、压缩比和实际读取字节。
- CRC/size 不一致形成 partial/error，不静默继续。
- 取消操作必须中断 inflate 和递归分析。
- 临时文件使用随机隔离目录，完成后清理，并带 quarantine 属性后再交给外部 GUI。

### 2.2 独立 iOS 语义层

建议新增 `bytetrawl-ios` crate，而不是把 IPA 规则堆入通用 ZIP analyzer：

```text
crates/bytetrawl-ios/
├── ipa.rs              # Payload 与主 App 定位
├── bundle.rs           # Info.plist 与 embedded targets
├── mobileprovision.rs  # CMS/plist 与 entitlements
├── privacy.rs          # UsageDescription / PrivacyInfo
├── size.rs             # compressed/uncompressed/installed 聚合
├── rules.rs            # IPA findings
└── report.rs           # versioned IPA report DTO
```

通用能力继续由现有模块提供：

- ZIP 中央目录与危险路径：`bytetrawl-analysis`
- Mach-O/fat slices/signature blob：`bytetrawl-format`
- 通用 Artifact、Finding、Evidence：`bytetrawl-core`
- GUI/虚拟树：`bytetrawl-ui`
- JSON/CI：`bytetrawl-cli`

### 2.3 报告模型

第一版 `IpaAuditReportV1` 应完整覆盖 IPAView 的 `IPAAuditReport`：

- metadata
- total_bytes
- files
- frameworks
- extensions
- localizations
- privacy_usage_descriptions
- has_privacy_manifest
- architectures
- signing
- findings

同时增加：

- `schema_version`
- `generator`
- `source.sha256`
- `compressed_bytes`
- `targets[]`（主 App、extensions、watch apps、framework executables）
- `partial`
- `errors[]`
- 每条 finding 的 `evidence[]`

不要只保留一个全局 `has_privacy_manifest`：兼容字段继续存在，但新模型应记录 manifest 属于哪个 target/SDK。

## 3. 分阶段实施

### Phase 0 — 行为契约与回归样本（2–3 天）

在写 ByteTrawl IPA analyzer 前，先固定 IPAView 行为：

1. 从 IPAView 的 4 个现有测试扩展成共享 golden fixtures。
2. 保存 IPAView 当前 JSON 作为兼容快照。
3. 最少覆盖：正常 IPA、无 Payload、无 `.app`、无 Info.plist、binary plist、thin arm64、fat arm64+x86_64、无 profile、有 profile、无 privacy manifest、多个 appex/framework/localization。
4. 增加敌意 ZIP：zip slip、symlink、超高压缩比、重复 entry、CRC 错误、超大 plist、嵌套过深。

验收：fixtures 不包含第三方商业 IPA；IPAView Core 与未来 ByteTrawl analyzer 可读取同一组测试输入和预期 JSON。

### Phase 1 — IPA 一等识别与安全成员树（5–7 天）

1. 对 ZIP entry 建立虚拟 `ArtifactNode`/`ArtifactSource`。
2. 检查 `Payload/*.app/Info.plist` 后把 ZIP 重新分类为 iOS IPA；不能只看 `.ipa` 扩展名。
3. 自动定位主 App，生成 Payload、App、Frameworks、PlugIns、Resources 节点。
4. 成员节点支持 Metadata、Hex、Strings 和安全预览。
5. 进度、取消、错误和 resource-limit 状态进入现有状态栏。

验收：拖入 IPA 后无需解压即可浏览；恶意路径永远不会写出 archive；10k entries 的 UI 保持虚拟化。

### Phase 2 — IPAView 核心审计等价（5–7 天）

1. 解析主 App Info.plist，生成 identity。
2. 计算逐文件和目录 installed size。
3. 枚举 frameworks、appex 和 localizations。
4. 自动把主 executable 交给现有 Mach-O analyzer。
5. 解析 mobileprovision、Team/Application ID、expiration 和 entitlements。
6. 汇总 UsageDescriptions，检查 Privacy Manifest。
7. 实现 IPAView 现有规则与 JSON 兼容导出。

验收：共享 fixture 上，兼容字段和 IPAView golden JSON 语义一致；规则集合与 severity 一致；ByteTrawl CLI 可输出 IPA report。

### Phase 3 — ByteTrawl UI 产品化（5–7 天）

建议给 IPA 使用稳定的信息架构，而不是再增加十几个顶层 tab：

- **Summary**：图标、identity、installed/compressed size、architectures、targets、finding counts。
- **Contents**：成员树、文件/目录尺寸、preview。
- **Targets**：主 App、extensions、frameworks、watch app。
- **Privacy**：UsageDescriptions、Privacy Manifests、entitlements。
- **Signing**：provisioning、application/team ID、expiration、Mach-O signature/FairPlay。
- **Findings**：规则、解释、证据跳转。
- 原有 Binary/Strings/Hex/Dependencies 视图作为选中 Mach-O 成员的深度视图。

同时增加 File → Open Recent，统一 IPA 与其他 Artifact 最近记录。

验收：IPAView 的 Overview/Findings/Files 用户任务全部能在 ByteTrawl 内完成，且每条 finding 可跳转到 target/plist/member/Mach-O slice。

### Phase 4 — 超越 IPAView（1–2 个版本，按价值排序）

1. **递归 embedded target 审计**：每个 appex、watch app、framework 分别解析 identity、architecture、signature、privacy 和 size。
2. **Privacy Manifest 内容解析**：Required Reason APIs、collected data、tracking domains，而不只是 presence boolean。
3. **签名与加密**：比较 provisioning entitlements 与 executable entitlements；识别 `LC_ENCRYPTION_INFO(_64)`/FairPlay cryptid；检查 profile 过期和 application ID 不匹配。
4. **体积分析**：compressed vs installed、目录 treemap、top files、重复资源、无用 simulator slice、未 strip binary。
5. **IPA Compare**：两个版本的 files、targets、size、architectures、entitlements、privacy、signing 与 findings 差异。
6. **发布门禁**：CLI size budgets、禁止新增 entitlement、禁止 simulator slice、必须有 privacy manifest、SARIF/Markdown/HTML。
7. **SDK 识别**：基于 framework/bundle/signature 的本地规则；必须显示 confidence 和 evidence。

## 4. 迁移与停用 IPAView 的门槛

不要以“代码写完”为停用依据。必须同时满足：

1. 功能等价表全部通过。
2. 共享测试和恶意 ZIP 安全测试全部通过。
3. 至少 20 个合法自有/开源 IPA 样本对照，核心字段一致率 100%；差异均有明确兼容说明。
4. ByteTrawl 对同一 IPA 的打开时间和内存不显著劣于 IPAView，并且取消立即生效。
5. IPA JSON schema 有文档、版本和迁移说明。
6. ByteTrawl 的签名、公证、staple、Gatekeeper、Homebrew 安装验证全部通过。
7. IPAView README 标记迁移路径，并至少保留一个兼容维护版本；不立即删除仓库和历史 release。

满足后：

- IPAView 进入 maintenance-only。
- IPAView 首页和 README 指向 ByteTrawl。
- Homebrew Cask 可保留一段迁移期，然后 deprecate，而不是直接移除。
- ByteTrawl release notes 明确列出 IPAView parity matrix。

## 5. 建议的版本安排

| ByteTrawl 版本 | 范围 | 是否可替代 IPAView |
|---|---|---|
| 1.1 | Archive Member 数据源、IPA 识别、Payload/App 成员树 | 否 |
| 1.2 | IPAView identity/size/framework/extension/localization/Mach-O parity | 仍不完全 |
| 1.3 | Provisioning/privacy/findings/兼容 JSON/UI/Recent Files | 候选 |
| 1.4 | Embedded targets、privacy manifest 内容、签名一致性、FairPlay | 是，能力超过 IPAView |
| 1.5 | IPA Compare、size treemap、CI gates、HTML/SARIF | 明显超过 |

如果希望更快收敛，也可把 1.1–1.3 合并为一个 4–6 周的 `IPA parity` 里程碑，但代码顺序仍应保持 Phase 0 → Archive Source → Semantic Analyzer → UI。

## 6. 第一批工程任务

按依赖顺序建议建立以下任务：

1. `test(ipa): import IPAView golden fixtures and report snapshots`
2. `core: add ArtifactSource and bounded ArtifactReader`
3. `analysis(zip): expose safe virtual archive member nodes`
4. `ios(ipa): detect Payload app and parse bundle identity`
5. `ios(ipa): enumerate targets, frameworks and localizations`
6. `ios(ipa): reuse Mach-O analyzer for archive members`
7. `ios(signing): parse embedded mobile provisioning profiles`
8. `ios(privacy): collect usage descriptions and privacy manifests`
9. `ios(rules): port IPAView audit findings with evidence`
10. `cli: emit versioned IPA audit JSON`
11. `ui: add IPA Summary/Targets/Privacy/Signing presentation`
12. `ui: add unified recent Artifacts`

第一批实现完成前，不修改 IPAView 的发布状态。
