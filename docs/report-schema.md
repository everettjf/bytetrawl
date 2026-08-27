# ByteTrawl report and policy schema

ByteTrawl emits deterministic, versioned reports. Additive fields may appear within a schema
version; consumers should ignore unknown fields. A removed field or changed meaning requires a
new major schema version.

## Inspection report v1

The top-level JSON fields are `schema_version`, `generator`, `artifact`, `files`, `findings`,
`policy_violations`, and `run`. Optional platform reports are `ipa`,
`ipa_view_compatibility`, `android`, `windows_package`, and `linux_package`.

`run.partial` means the report is usable but one or more bounded analyses failed. `run.errors`
identifies each failed stage. `run.cancelled` is distinct from partial completion. CLI exit codes
are documented in the README.

## Comparison report v1.1

Comparison reports contain exact SHA-256-backed `files`, `moved_files`, `directory_deltas`,
`type_deltas`, `duplicate_groups`, and `largest_growth`. When both inputs are IPAs, `ipa` adds
identity, architecture, target, localization, privacy, signing, entitlement, and finding changes.

## Platform report v1

- IPA: identity, compressed and installed sizes, files, targets, frameworks, extensions,
  localizations, architectures, privacy declarations, provisioning, entitlements, findings, and
  the IPAView-compatible projection.
- Android APK: manifest identity, SDK levels, application flags, permissions, components, deep
  links, DEX counts, resources, native libraries, signing indicators, and findings.
- APPX/MSIX: package identity, target families, capabilities, applications, executable members,
  block-map/signature presence, and findings.
- Debian package: control identity, dependencies, installed size, files and modes, maintainer
  scripts, and findings.

## Release policy v1

Policies are JSON objects with `schema_version: "1.0"`. Profiles are `balanced`, `strict`, and
`store_release`. Explicit `fail_on_severity` overrides the profile threshold. Rule configuration
supports `enabled_rules`, `disabled_rules`, `severity_overrides`, and `suppressions`; each
suppression requires a reason and may provide an RFC 3339 `expires_at` timestamp. Expired
suppressions do not apply.

See [`examples/policies/store-release.json`](../examples/policies/store-release.json) for all
cross-platform gates and [`examples/github-actions/bytetrawl-audit.yml`](../examples/github-actions/bytetrawl-audit.yml)
for CI integration.

## Compatibility

The IPAView projection is camelCase and governed by the shared contract in
`tests/fixtures/ipa/ipaview-contract.json`. Its golden matrix uses 20 deterministic, legally owned
synthetic IPA variants. Report ordering is stable so JSON can be reviewed and diffed in CI.
