# Automated testing matrix

ByteTrawl uses `scripts/verify.sh` as its local and CI quality gate. GitHub Actions runs the same
command on every push and pull request, then builds and launches a real macOS application bundle.

| Area | Automated coverage |
|---|---|
| Artifact model and workspace persistence | Unit tests and backward-compatible serialization |
| PE, Mach-O, Universal Mach-O, ELF | Magic, headers, malformed offsets, target-specific fixtures |
| Archives and untrusted input | Traversal, symlinks, depth/size/ratio limits, CRC corruption, cancellation |
| IPA | Identity, targets, architectures, privacy, provisioning, findings, 20-case IPAView matrix |
| Android APK | Text/binary manifest, permissions, components, DEX, resources, native code, signing |
| APPX/MSIX | Manifest, identity, applications, capabilities, signature and block-map indicators |
| Debian DEB | Control/data archives, dependencies, sizes, scripts, setuid/setgid modes |
| Comparison | Content hashes, add/remove/modify/move, growth, directory/type totals, duplicates |
| Policies and reports | Profiles, overrides, suppression/expiry, exit codes, JSON/Markdown/HTML/SARIF |
| CLI | Process-level stdout/stderr, output files, comparison and policy failure behavior |
| Desktop app | Full compile plus real `.app` assembly, signature structure, version and launch smoke test |
| macOS release | Script-enforced Developer ID signing, notarization, staple, final ZIP re-verification |
| Packaging | Info.plist and Homebrew Cask/Formula syntax; release-time strict audit/install test |

## Deliberate boundary

The semantic engines, CLI behavior, package reports, policies, serialization, app assembly, and app
startup are automated. Native GPUI mouse/keyboard interaction, drag-and-drop coordinates, visual
layout, and macOS system dialogs still require release-time UI smoke testing because GPUI does not
currently expose a stable end-to-end accessibility test harness. These checks must not be described
as automated until such a harness exists.

Apple notarization and Homebrew online installation are automated by the release procedure rather
than ordinary pull-request CI because they require protected credentials and external services.

## Real-world public artifact corpus

In addition to deterministic synthetic fixtures, a scheduled and manually dispatchable workflow
downloads pinned open-source IPA, APK, MSIX, DMG, PE, ELF, DEB, and RPM artifacts. Every download has a
fixed byte length and SHA-256 digest, and every report is checked with format-appropriate semantic
assertions. The manifest, provenance, licenses, coverage model, and local commands are documented in
[the real-world corpus README](../tests/real-world-corpus/README.md).

This corpus is deliberately separate from pull-request CI. External hosting availability must not
make ordinary development flaky, and its roughly 40 MB download should not be repeated on every
commit. The scheduled job caches verified payloads, never executes or installs them, and uploads the
generated JSON reports for regression diagnosis.
