//! Deterministic file, size, and iOS release-audit comparisons.

use bytetrawl_analysis::{ArtifactReader, CancellationToken};
use bytetrawl_core::{ArtifactNode, ArtifactSource, Result};
use bytetrawl_ios::IpaAuditReportV1;
use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Added,
    Removed,
    Modified,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileChange {
    pub kind: ChangeKind,
    pub path: PathBuf,
    pub before_bytes: Option<u64>,
    pub after_bytes: Option<u64>,
    pub delta_bytes: i128,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValueChange {
    pub field: String,
    pub before: Option<String>,
    pub after: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SetChanges {
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IpaChanges {
    pub identity: Vec<ValueChange>,
    pub architectures: SetChanges,
    pub targets: SetChanges,
    pub localizations: SetChanges,
    pub privacy_usage_keys: SetChanges,
    pub privacy_manifest_values: SetChanges,
    pub signing: Vec<ValueChange>,
    pub entitlements: Vec<ValueChange>,
    pub findings: SetChanges,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompareReportV1 {
    pub schema_version: String,
    pub generator: String,
    pub before: PathBuf,
    pub after: PathBuf,
    pub before_bytes: u64,
    pub after_bytes: u64,
    pub delta_bytes: i128,
    pub files: Vec<FileChange>,
    pub largest_growth: Vec<FileChange>,
    pub ipa: Option<IpaChanges>,
}

pub fn compare_artifacts(
    before: &ArtifactNode,
    after: &ArtifactNode,
    before_ipa: Option<&IpaAuditReportV1>,
    after_ipa: Option<&IpaAuditReportV1>,
    cancel: &CancellationToken,
) -> Result<CompareReportV1> {
    let before_files = file_snapshots(before, cancel)?;
    let after_files = file_snapshots(after, cancel)?;
    let before_bytes = before_files.values().map(|file| file.size).sum();
    let after_bytes = after_files.values().map(|file| file.size).sum();
    let paths = before_files
        .keys()
        .chain(after_files.keys())
        .cloned()
        .collect::<IndexSet<_>>();
    let mut files = paths
        .into_iter()
        .filter_map(|path| {
            let old = before_files.get(&path);
            let new = after_files.get(&path);
            if old == new {
                return None;
            }
            Some(FileChange {
                kind: match (old, new) {
                    (None, Some(_)) => ChangeKind::Added,
                    (Some(_), None) => ChangeKind::Removed,
                    _ => ChangeKind::Modified,
                },
                path,
                before_bytes: old.map(|file| file.size),
                after_bytes: new.map(|file| file.size),
                delta_bytes: new.map_or(0, |file| file.size) as i128
                    - old.map_or(0, |file| file.size) as i128,
            })
        })
        .collect::<Vec<_>>();
    files.sort_by(|left, right| left.path.cmp(&right.path));
    let mut largest_growth = files
        .iter()
        .filter(|change| change.delta_bytes > 0)
        .cloned()
        .collect::<Vec<_>>();
    largest_growth.sort_by(|left, right| right.delta_bytes.cmp(&left.delta_bytes));
    largest_growth.truncate(50);
    Ok(CompareReportV1 {
        schema_version: "1.0".into(),
        generator: format!("ByteTrawl/{}", env!("CARGO_PKG_VERSION")),
        before: before.path.clone(),
        after: after.path.clone(),
        before_bytes,
        after_bytes,
        delta_bytes: after_bytes as i128 - before_bytes as i128,
        files,
        largest_growth,
        ipa: before_ipa
            .zip(after_ipa)
            .map(|(before, after)| compare_ipa(before, after)),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileSnapshot {
    size: u64,
    sha256: String,
}

fn file_snapshots(
    root: &ArtifactNode,
    cancel: &CancellationToken,
) -> Result<IndexMap<PathBuf, FileSnapshot>> {
    let mut snapshots = IndexMap::new();
    for node in root.files() {
        cancel.check()?;
        let Some(path) = logical_path(root, node) else {
            continue;
        };
        let reader = ArtifactReader::open(node)?;
        let mut hasher = Sha256::new();
        let mut offset = 0u64;
        while offset < reader.len() {
            cancel.check()?;
            let bytes = reader.read_range(offset, 1024 * 1024)?;
            if bytes.is_empty() {
                break;
            }
            hasher.update(&bytes);
            offset = offset.saturating_add(bytes.len() as u64);
        }
        snapshots.insert(
            path,
            FileSnapshot {
                size: reader.len(),
                sha256: hex::encode(hasher.finalize()),
            },
        );
    }
    Ok(snapshots)
}

fn logical_path(root: &ArtifactNode, node: &ArtifactNode) -> Option<PathBuf> {
    match node.source.as_ref() {
        Some(ArtifactSource::ArchiveMember { member_path, .. }) => Some(member_path.clone()),
        _ => node
            .path
            .strip_prefix(&root.path)
            .ok()
            .map(Path::to_path_buf),
    }
}

fn set_changes(
    before: impl IntoIterator<Item = String>,
    after: impl IntoIterator<Item = String>,
) -> SetChanges {
    let before = before.into_iter().collect::<IndexSet<_>>();
    let after = after.into_iter().collect::<IndexSet<_>>();
    let mut added = after.difference(&before).cloned().collect::<Vec<_>>();
    let mut removed = before.difference(&after).cloned().collect::<Vec<_>>();
    added.sort();
    removed.sort();
    SetChanges { added, removed }
}

fn value_change(field: &str, before: Option<String>, after: Option<String>) -> Option<ValueChange> {
    (before != after).then(|| ValueChange {
        field: field.into(),
        before,
        after,
    })
}

fn compare_ipa(before: &IpaAuditReportV1, after: &IpaAuditReportV1) -> IpaChanges {
    let mut identity = Vec::new();
    for change in [
        value_change(
            "name",
            before.metadata.name.clone(),
            after.metadata.name.clone(),
        ),
        value_change(
            "bundle_identifier",
            before.metadata.bundle_identifier.clone(),
            after.metadata.bundle_identifier.clone(),
        ),
        value_change(
            "version",
            before.metadata.version.clone(),
            after.metadata.version.clone(),
        ),
        value_change(
            "build",
            before.metadata.build.clone(),
            after.metadata.build.clone(),
        ),
        value_change(
            "minimum_os_version",
            before.metadata.minimum_os_version.clone(),
            after.metadata.minimum_os_version.clone(),
        ),
    ]
    .into_iter()
    .flatten()
    {
        identity.push(change);
    }
    let before_entitlements = before.signing.as_ref().map(|signing| &signing.entitlements);
    let after_entitlements = after.signing.as_ref().map(|signing| &signing.entitlements);
    let entitlement_keys = before_entitlements
        .into_iter()
        .flat_map(|values| values.keys())
        .chain(
            after_entitlements
                .into_iter()
                .flat_map(|values| values.keys()),
        )
        .cloned()
        .collect::<IndexSet<_>>();
    let entitlements = entitlement_keys
        .into_iter()
        .filter_map(|key| {
            value_change(
                &key,
                before_entitlements
                    .and_then(|values| values.get(&key))
                    .cloned(),
                after_entitlements
                    .and_then(|values| values.get(&key))
                    .cloned(),
            )
        })
        .collect();
    let signing = [
        value_change(
            "team_identifier",
            before
                .signing
                .as_ref()
                .and_then(|value| value.team_id.clone()),
            after
                .signing
                .as_ref()
                .and_then(|value| value.team_id.clone()),
        ),
        value_change(
            "application_identifier",
            before
                .signing
                .as_ref()
                .and_then(|value| value.application_identifier.clone()),
            after
                .signing
                .as_ref()
                .and_then(|value| value.application_identifier.clone()),
        ),
        value_change(
            "expiration",
            before
                .signing
                .as_ref()
                .and_then(|value| value.expiration)
                .map(|value| value.to_rfc3339()),
            after
                .signing
                .as_ref()
                .and_then(|value| value.expiration)
                .map(|value| value.to_rfc3339()),
        ),
    ]
    .into_iter()
    .flatten()
    .collect();
    IpaChanges {
        identity,
        architectures: set_changes(before.architectures.clone(), after.architectures.clone()),
        targets: set_changes(
            before
                .targets
                .iter()
                .map(|target| target.path.display().to_string()),
            after
                .targets
                .iter()
                .map(|target| target.path.display().to_string()),
        ),
        localizations: set_changes(before.localizations.clone(), after.localizations.clone()),
        privacy_usage_keys: set_changes(
            before.privacy_usage_descriptions.keys().cloned(),
            after.privacy_usage_descriptions.keys().cloned(),
        ),
        privacy_manifest_values: set_changes(privacy_values(before), privacy_values(after)),
        signing,
        entitlements,
        findings: set_changes(
            before
                .findings
                .iter()
                .map(|finding| finding.rule_id.clone()),
            after.findings.iter().map(|finding| finding.rule_id.clone()),
        ),
    }
}

fn privacy_values(report: &IpaAuditReportV1) -> Vec<String> {
    let mut values = Vec::new();
    for manifest in &report.privacy_manifests {
        values.push(format!("tracking={}", manifest.tracking));
        values.extend(
            manifest
                .tracking_domains
                .iter()
                .map(|value| format!("tracking-domain:{value}")),
        );
        values.extend(
            manifest
                .collected_data_types
                .iter()
                .map(|value| format!("collected-data:{value}")),
        );
        for (category, reasons) in &manifest.accessed_api_categories {
            for reason in reasons {
                values.push(format!("required-reason:{category}:{reason}"));
            }
        }
    }
    values
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytetrawl_analysis::open_artifact;

    #[test]
    fn reports_added_removed_modified_and_largest_growth() {
        let temporary = tempfile::tempdir().expect("create comparison fixture");
        let before_path = temporary.path().join("before");
        let after_path = temporary.path().join("after");
        std::fs::create_dir(&before_path).expect("create baseline");
        std::fs::create_dir(&after_path).expect("create candidate");
        std::fs::write(before_path.join("a"), vec![b'a'; 10]).expect("write baseline a");
        std::fs::write(before_path.join("gone"), vec![b'g'; 5]).expect("write removed file");
        std::fs::write(after_path.join("a"), vec![b'a'; 30]).expect("write candidate a");
        std::fs::write(after_path.join("new"), vec![b'n'; 7]).expect("write added file");
        std::fs::write(before_path.join("same-size"), b"before").expect("write baseline content");
        std::fs::write(after_path.join("same-size"), b"after!").expect("write candidate content");
        let cancellation = CancellationToken::default();
        let before = open_artifact(&before_path, &cancellation).expect("open baseline");
        let after = open_artifact(&after_path, &cancellation).expect("open candidate");
        let report = compare_artifacts(&before, &after, None, None, &cancellation)
            .expect("compare artifacts");
        assert_eq!(report.delta_bytes, 22);
        assert_eq!(report.files.len(), 4);
        assert_eq!(report.largest_growth[0].path, PathBuf::from("a"));
        assert_eq!(report.largest_growth[0].delta_bytes, 20);
        assert!(
            report
                .files
                .iter()
                .any(|change| change.path == PathBuf::from("same-size")
                    && change.kind == ChangeKind::Modified
                    && change.delta_bytes == 0)
        );
    }
}
