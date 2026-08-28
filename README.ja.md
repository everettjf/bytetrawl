# ByteTrawl

[English](README.md) · [简体中文](README.zh-CN.md) · **日本語** · [Português (Brasil)](README.pt-BR.md) · [Español](README.es.md) · [Deutsch](README.de.md)

[![macOS](https://img.shields.io/badge/macOS-13%2B-d69b51?style=flat-square)](#動作要件)
[![License](https://img.shields.io/badge/license-Apache--2.0-d7d3c6?style=flat-square)](LICENSE)

ByteTrawl は Rust で実装された、クロスプラットフォームのソフトウェア成果物向け静的トリアージ・比較・リリース監査ワークベンチです。アプリ、ディレクトリ、パッケージ、単体ファイルを Artifact として統一的に扱い、対象を実行せずに構造、メタデータ、署名、依存関係、PE／Mach-O／ELF を検査します。

最新かつ詳細な項目別一覧は、正規版である英語の[サポートマトリクス](README.md#detailed-support-matrix)を参照してください。最新版は下記の Homebrew コマンド、または [GitHub Releases](https://github.com/everettjf/homebrew-tap/releases)から入手できます。

## スクリーンショット

[![GrapeCompare.app を検査する ByteTrawl](docs/assets/screenshots/overview.jpg)](https://xnu.app/bytetrawl/#gallery)

[ライブギャラリー](https://xnu.app/bytetrawl/#gallery)では、アプリ構造、Mach-O、依存関係、抽出文字列、範囲限定 Hex ビューを切り替えて確認できます。

## Homebrew でインストール

```sh
brew tap everettjf/tap
brew install --cask bytetrawl
brew install bytetrawl-cli
```

macOS アプリは Developer ID で署名され、Apple の公証とチケットの stapling が完了しています。リリース成果物は厳格な署名検証、公証チケット検証、Gatekeeper 評価を通過します。

## 主な対応範囲

| 分野 | 対応内容 |
|---|---|
| macOS / iOS | `.app`、bundle、framework、plug-in、Mach-O/Fat Mach-O、DMG、flat PKG/XAR。IPA の識別情報、サイズ、組み込みターゲット、アーキテクチャ、ローカライズ、Privacy Manifest、provisioning、entitlements、release findings |
| Android | APK Manifest、package/version/SDK、permissions、exported components、deep links、DEX 統計、ABI/native libraries、署名指標、release findings |
| Windows | PE/COFF headers、sections、imports/exports、symbols、dependencies、Authenticode metadata。APPX/MSIX identity、capabilities、entry points、block map、signature state |
| Linux | ELF headers、architecture、interpreter、sections/segments、relocations、symbols、dependencies、findings。DEB control、dependencies、payload、installed size、maintainer scripts、privileged files |
| コンテナ / データ | ZIP、tar/tar.gz、ar、DMG、ISO、JSON、XML、plist、SQLite、画像、テキスト。7z、RAR、単体圧縮ストリームは現在識別レベル |
| 共通分析 | Artifact Tree、metadata、headers、slices、sections、segments、imports、exports、symbols、relocations、dependency graph、strings、オンデマンド Hex、hash、entropy、signature、findings |
| 比較 / CI | SHA-256 による追加・削除・変更・移動・増加・重複の比較。JSON、Markdown、HTML、SARIF、release policies、severity gates、安定した終了コード |

全項目と対応レベルは[英語版の詳細マトリクス](README.md#detailed-support-matrix)、レポート仕様は[versioned schema](docs/report-schema.md)、自動テスト範囲は[testing matrix](docs/testing.md)にあります。

## デスクトップ操作

- macOS ネイティブメニューから file、folder、workspace、新規 window を開けます。
- file、app、package、workspace、directory をウィンドウ中央へドラッグ＆ドロップできます。
- Artifact Tree、中央ビュー、Details はリサイズ可能で、大規模な表は virtual rendering されます。
- **External Tools…** はインストール済みで互換性のあるツールを優先します。
- Workspace は path、view、bookmarks、notes、cached results を保持します。

ショートカット：`⌘N` 新規ウィンドウ、`⌘O` ファイル、`⇧⌘O` フォルダ、`⌥⌘O` workspace、`⌘S` 保存、`⌘F` 検索。

## CLI

```sh
bytetrawl-cli inspect ./SomeApp.app --pretty
bytetrawl-cli inspect ./MyApp.ipa --depth deep --format sarif --output bytetrawl.sarif
bytetrawl-cli inspect ./package --hash sha256 --strings --entropy
```

解析深度は `lightweight`、`standard`、`deep`。終了コードは fatal error（`1`）、policy/finding failure（`2`）、cancel（`4`）、利用可能な partial report（`5`）を区別します。

## 動作要件

- Apple silicon Mac（`arm64`）
- macOS 13 Ventura 以降
- 上記インストールには Homebrew

コア解析層は GPUI に依存せず、macOS 上で Windows PE と Linux ELF を静的解析できます。Windows / Linux ネイティブ UI と配布パッケージは今後の対象です。

## 安全境界

ByteTrawl は読み取り専用の静的ツールです。取り込んだプログラムの実行、イメージのマウント、パッケージのインストール、自動展開、逆コンパイル、デバッグ、バイト変更は行いません。シンボリックリンクを追跡せず、入力、再帰、ファイル数、文字列、archive members、外部コマンド出力には明示的な上限があります。ヒューリスティックな finding は調査の手掛かりであり、マルウェア判定ではありません。

## 自動品質保証

Rust workspace 全体、Clippy、Rust 1.88 の MSRV、CLI/レポート契約、macOS App の build/launch に加え、長さと SHA-256 を固定した 16 個の公開実物 artifact で IPA、APK、APPX/MSIX、正常・破損署名 macOS App、notarized PKG、DMG、ISO、PE、ELF、DEB、RPM、異常 APPX を回帰検証します。Release では Homebrew 経由で App と CLI を実際に導入し、Developer ID、Apple notarization、stapler、Gatekeeper、Formula test まで確認します。詳細は[自動テストマトリクス](docs/testing.md)を参照してください。

## ドキュメント

[製品戦略](docs/product-strategy.md) · [現状・競合分析](docs/product-analysis-roadmap.md) · [IPAView 統合計画](docs/ipa-convergence-plan.md) · [テストマトリクス](docs/testing.md) · [Web サイト](https://xnu.app/bytetrawl/)

英語 README が正規版です。バージョン、インストール方法、主要機能の変更時には翻訳版も同期します。
