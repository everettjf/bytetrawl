# ByteTrawl

[English](README.md) · [简体中文](README.zh-CN.md) · [日本語](README.ja.md) · [Português (Brasil)](README.pt-BR.md) · [Español](README.es.md) · **Deutsch**

[![macOS](https://img.shields.io/badge/macOS-13%2B-d69b51?style=flat-square)](#voraussetzungen)
[![Lizenz](https://img.shields.io/badge/license-Apache--2.0-d7d3c6?style=flat-square)](LICENSE)

ByteTrawl ist eine in Rust geschriebene, plattformübergreifende Workbench zur sicheren statischen Triage, zum Vergleich und zum Release-Audit von Software-Artefakten. Anwendungen, Verzeichnisse, Pakete und einzelne Dateien werden als Artifacts modelliert, damit Struktur, Metadaten, Signaturen, Abhängigkeiten sowie PE-, Mach-O- und ELF-Binärdateien untersucht werden können, ohne den Inhalt auszuführen.

Die Desktop-App bietet Size Lab und interaktive Treemaps, Entropie-Flächendiagramm und Heatmap mit Hex-Navigation, einen Canvas-Abhängigkeitsgraphen, Signatur-/Provisioning-Zeitachsen, IPA-Architektur-/Datenschutzmatrix, Findings-Filter, gespeicherte Panelbreiten, hohen Kontrast sowie lokalen SVG- und Fensterbildexport.

Die englische [README](README.md#detailed-support-matrix) ist die maßgebliche Quelle und enthält die aktuelle, vollständige Support-Matrix. Die neueste Version lässt sich mit den folgenden Homebrew-Befehlen installieren oder über [GitHub Releases](https://github.com/everettjf/homebrew-tap/releases) beziehen.

## Screenshots

[![ByteTrawl untersucht GrapeCompare.app](docs/assets/screenshots/overview.jpg)](https://xnu.app/bytetrawl/#gallery)

Die [Live-Galerie](https://xnu.app/bytetrawl/#gallery) wechselt zwischen Anwendungsstruktur, Mach-O-Details, Abhängigkeiten, extrahierten Strings und begrenzter Hex-Ansicht.

## Installation mit Homebrew

```sh
brew tap everettjf/tap
brew install --cask bytetrawl
brew install bytetrawl-cli
```

Die macOS-App ist mit einer Developer ID signiert, von Apple notarisiert und mit dem Notarisierungsticket versehen. Jedes Release besteht strikte Signaturprüfung, Ticketvalidierung und Gatekeeper-Bewertung.

## Wichtigste Fähigkeiten

| Bereich | Aktuelle Unterstützung |
|---|---|
| macOS und iOS | `.app`, Bundles, Frameworks, Plug-ins, Universal Mach-O, DMG und PKG/XAR; IPA-Audit für Identität, Größe, eingebettete Targets, Architekturen, Lokalisierungen, Datenschutz, Provisioning, Entitlements und Findings |
| Android | APK Manifest, Paket/Version/SDK, Berechtigungen, exportierte Komponenten, Deep Links, DEX-Statistiken, ABIs, native Bibliotheken, Signaturindikatoren und Findings |
| Windows | PE/COFF-Header, Sections, Imports/Exports, Symbole, Abhängigkeiten und Authenticode-Metadaten; APPX/MSIX-Identität, Capabilities, Entry Points, Block Map und Signaturstatus |
| Linux | ELF-Header, Architektur, Interpreter, Sections, Segments, Relocations, Symbole, Abhängigkeiten und Findings; DEB Control, Payload, installierte Größe, Maintainer-Skripte und privilegierte Dateien |
| Container und Daten | ZIP, tar/tar.gz, ar, DMG, ISO, JSON, XML, plist, SQLite, Bilder und Text; 7z, RAR und einzelne komprimierte Streams derzeit auf Identifikationsebene |
| Allgemeine Analyse | Artifact Tree, Metadata, Headers, Slices, Sections, Segments, Imports, Exports, Symbols, Relocations, Dependency Graph, Strings, bedarfsgesteuertes Hex, Hashes, Entropie, Signatur und Findings |
| Vergleich und CI | Exakte SHA-256-Identität; hinzugefügte, entfernte, geänderte und verschobene Dateien, Wachstum und Duplikate; JSON, Markdown, HTML, SARIF, Policies, Severity Gates und stabile Exit-Codes |

Alle Einzelheiten stehen in der [englischen Support-Matrix](README.md#detailed-support-matrix), im [versionierten Report-Schema](docs/report-schema.md) und in der [automatisierten Testmatrix](docs/testing.md).

## Desktop-Workflow

- Native macOS-Menüs öffnen Dateien, Ordner, Workspaces und neue Fenster.
- Dateien, Apps, Pakete, Workspaces oder Verzeichnisse können in die Fenstermitte gezogen werden.
- Artifact Tree, Inhalt und Details sind skalierbar; große Tabellen werden virtualisiert gerendert.
- **External Tools…** priorisiert installierte, kompatible Integrationen.
- Workspaces bewahren Pfad, Ansicht, Lesezeichen, Notizen und Analyse-Cache.

Kurzbefehle: `⌘N` neues Fenster, `⌘O` Datei, `⇧⌘O` Ordner, `⌥⌘O` Workspace, `⌘S` speichern und `⌘F` suchen.

## CLI

```sh
bytetrawl-cli inspect ./SomeApp.app --pretty
bytetrawl-cli inspect ./MyApp.ipa --depth deep --format sarif --output bytetrawl.sarif
bytetrawl-cli inspect ./package --hash sha256 --strings --entropy
```

Analysetiefen sind `lightweight`, `standard` und `deep`. Exit-Codes unterscheiden fatale Fehler (`1`), Policy-/Finding-Fehler (`2`), Abbruch (`4`) und nutzbare Teilberichte (`5`).

## Voraussetzungen

- Mac mit Apple silicon (`arm64`)
- macOS 13 Ventura oder neuer
- Homebrew für die obigen Befehle

Der Kern ist unabhängig von GPUI und untersucht Windows PE und Linux ELF statisch unter macOS. Native Windows-/Linux-Pakete und UI-Validierung folgen später.

## Sicherheitsgrenzen

ByteTrawl arbeitet statisch und schreibgeschützt. Es führt importierte Programme nicht aus, mountet keine Images, installiert keine Pakete, extrahiert Archive nicht automatisch, dekompiliert und debuggt nicht und verändert keine Bytes. Symbolischen Links wird nicht gefolgt; Eingaben, Rekursion, Dateizahl, Strings, Archiveinträge und Befehlsausgaben sind explizit begrenzt. Heuristische Findings sind Hinweise, keine Malware-Urteile.

## Automatisierte Qualitätssicherung

Neben dem vollständigen Rust-Workspace, Clippy, Rust 1.88 als MSRV, CLI-/Report-Verträgen und macOS-App-Build/Launch prüft ein öffentlicher Korpus aus 16 nach Länge und SHA-256 fixierten realen Artefakten IPA, APK, APPX/MSIX, gültig und absichtlich beschädigt signierte macOS-Apps, notarisiertes PKG, DMG, ISO, PE, ELF, DEB, RPM und fehlerhafte APPX-Pakete. Jeder Release installiert App und CLI außerdem real über Homebrew und validiert Developer ID, Apple-Notarisierung, Stapler, Gatekeeper und den Formula-Test. Details enthält die [Testmatrix](docs/testing.md).

## Dokumentation

[Produktstrategie](docs/product-strategy.md) · [Produkt- und Wettbewerbsanalyse](docs/product-analysis-roadmap.md) · [IPAView-Plan](docs/ipa-convergence-plan.md) · [Testmatrix](docs/testing.md) · [Website](https://xnu.app/bytetrawl/)

Die englische README ist maßgeblich; Übersetzungen werden bei Änderungen an Version, Installation oder Hauptfunktionen synchronisiert.
