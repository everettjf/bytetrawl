//! Deterministic file, size, and iOS release-audit comparisons.

use bytetrawl_core::{ArtifactNode, ArtifactSource};
use bytetrawl_ios::IpaAuditReportV1;
use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};
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
) -> CompareReportV1 {
    let before_files = file_sizes(before);
    let after_files = file_sizes(after);
    let before_bytes = before_files.values().copied().sum();
    let after_bytes = after_files.values().copied().sum();
    let paths = before_files
        .keys()
        .chain(after_files.keys())
        .cloned()
        .collect::<IndexSet<_>>();
    let mut files = paths
        .into_iter()
        .filter_map(|path| {
            let old = before_files.get(&path).copied();
            let new = after_files.get(&path).copied();
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
                before_bytes: old,
                after_bytes: new,
                delta_bytes: new.unwrap_or(0) as i128 - old.unwrap_or(0) as i128,
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
    CompareReportV1 {
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
    }
}

fn file_sizes(root: &ArtifactNode) -> IndexMap<PathBuf, u64> {
    root.files()
        .filter_map(|node| logical_path(root, node).map(|path| (path, node.size)))
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;
    use bytetrawl_core::ArtifactKind;

    #[test]
    fn reports_added_removed_modified_and_largest_growth() {
        let mut before =
            ArtifactNode::new("before", PathBuf::from("/before"), ArtifactKind::Directory);
        before.children.push(file("a", "/before/a", 10));
        before.children.push(file("gone", "/before/gone", 5));
        let mut after =
            ArtifactNode::new("after", PathBuf::from("/after"), ArtifactKind::Directory);
        after.children.push(file("a", "/after/a", 30));
        after.children.push(file("new", "/after/new", 7));
        let report = compare_artifacts(&before, &after, None, None);
        assert_eq!(report.delta_bytes, 22);
        assert_eq!(report.files.len(), 3);
        assert_eq!(report.largest_growth[0].path, PathBuf::from("a"));
        assert_eq!(report.largest_growth[0].delta_bytes, 20);
    }

    fn file(name: &str, path: &str, size: u64) -> ArtifactNode {
        let mut node = ArtifactNode::new(name, PathBuf::from(path), ArtifactKind::Resource);
        node.size = size;
        node.source = None;
        node
    }
}
