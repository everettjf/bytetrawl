//! Static, extraction-free inspection of Apple iOS IPA artifacts.

use bytetrawl_analysis::{ArtifactReader, CancellationToken};
use bytetrawl_core::{
    ArtifactKind, ArtifactNode, ArtifactSource, ByteTrawlError, Result, Severity,
};
use bytetrawl_format::{AnalysisInput, BinaryAnalyzer, MAX_PARSE_BYTES, UnifiedBinaryAnalyzer};
use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use plist::Value;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const MAX_PLIST_BYTES: u64 = 32 * 1024 * 1024;
const MAX_PROFILE_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IpaSource {
    pub path: PathBuf,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct IpaMetadata {
    pub name: Option<String>,
    pub bundle_identifier: Option<String>,
    pub version: Option<String>,
    pub build: Option<String>,
    pub minimum_os_version: Option<String>,
    pub executable: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IpaFile {
    pub path: PathBuf,
    pub compressed_bytes: u64,
    pub installed_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IpaTarget {
    pub kind: String,
    pub path: PathBuf,
    pub metadata: IpaMetadata,
    pub architectures: Vec<String>,
    pub has_privacy_manifest: bool,
    pub privacy_manifest: Option<PrivacyManifest>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PrivacyManifest {
    pub path: PathBuf,
    pub tracking: bool,
    pub tracking_domains: Vec<String>,
    pub collected_data_types: Vec<String>,
    pub accessed_api_categories: IndexMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct IpaSigning {
    pub team_id: Option<String>,
    pub application_identifier: Option<String>,
    pub expiration: Option<DateTime<Utc>>,
    pub entitlements: IndexMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IpaEvidence {
    pub path: PathBuf,
    pub field: Option<String>,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IpaFinding {
    pub code: String,
    pub rule_id: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub evidence: Vec<IpaEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IpaAuditReportV1 {
    pub schema_version: String,
    pub generator: String,
    pub source: IpaSource,
    pub metadata: IpaMetadata,
    pub total_bytes: u64,
    pub compressed_bytes: u64,
    pub files: Vec<IpaFile>,
    pub frameworks: Vec<String>,
    pub extensions: Vec<String>,
    pub localizations: Vec<String>,
    pub privacy_usage_descriptions: IndexMap<String, String>,
    pub has_privacy_manifest: bool,
    pub privacy_manifests: Vec<PrivacyManifest>,
    pub architectures: Vec<String>,
    pub signing: Option<IpaSigning>,
    pub findings: Vec<IpaFinding>,
    pub targets: Vec<IpaTarget>,
    pub partial: bool,
    pub errors: Vec<String>,
}

pub fn audit_ipa(artifact: &ArtifactNode, cancel: &CancellationToken) -> Result<IpaAuditReportV1> {
    cancel.check()?;
    let source_path = artifact.path.clone();
    let source_sha256 = hash_source(&source_path, cancel)?;
    let nodes = flatten_nodes(artifact);
    let main_app = find_main_app(artifact).ok_or_else(|| {
        ByteTrawlError::Malformed("IPA has no Payload/*.app bundle with Info.plist".into())
    })?;
    let main_prefix = member_path(main_app).ok_or_else(|| {
        ByteTrawlError::Malformed("IPA application is not backed by an archive member".into())
    })?;
    let info_node = child_named(main_app, "Info.plist")
        .ok_or_else(|| ByteTrawlError::Malformed("main app has no Info.plist".into()))?;
    let info = read_plist(info_node)?;
    let metadata = metadata_from_plist(&info);

    let mut files = Vec::new();
    let mut compressed_bytes = 0u64;
    let mut total_bytes = 0u64;
    let mut frameworks = Vec::new();
    let mut extensions = Vec::new();
    let mut localizations = Vec::new();
    let mut errors = Vec::new();

    for node in &nodes {
        cancel.check()?;
        let Some(path) = member_path(node) else {
            continue;
        };
        if node.is_file() {
            let (compressed, installed) = source_sizes(node);
            compressed_bytes = compressed_bytes.saturating_add(compressed);
            total_bytes = total_bytes.saturating_add(installed);
            files.push(IpaFile {
                path: path.clone(),
                compressed_bytes: compressed,
                installed_bytes: installed,
            });
        }
        if node.kind == ArtifactKind::Framework {
            frameworks.push(relative_to(&path, &main_prefix));
        } else if node
            .path
            .extension()
            .is_some_and(|extension| extension == "appex")
        {
            extensions.push(relative_to(&path, &main_prefix));
        }
        if node
            .path
            .extension()
            .is_some_and(|extension| extension == "lproj")
            && let Some(locale) = node.path.file_stem().and_then(|value| value.to_str())
        {
            localizations.push(locale.to_owned());
        }
    }
    frameworks.sort();
    frameworks.dedup();
    extensions.sort();
    extensions.dedup();
    localizations.sort();
    localizations.dedup();
    files.sort_by(|left, right| left.path.cmp(&right.path));

    let architectures = metadata
        .executable
        .as_deref()
        .and_then(|name| child_named(main_app, name))
        .map(|node| architectures_for(node, &mut errors))
        .unwrap_or_default();
    let privacy_usage_descriptions = usage_descriptions(&info);
    let has_privacy_manifest = subtree_contains(main_app, "PrivacyInfo.xcprivacy");
    let signing = child_named(main_app, "embedded.mobileprovision")
        .map(parse_mobileprovision)
        .transpose()
        .map_err(|error| ByteTrawlError::Malformed(format!("mobile provisioning: {error}")))?;
    let targets = collect_targets(main_app, &metadata, &architectures, &mut errors, cancel)?;
    let privacy_manifests = targets
        .iter()
        .filter_map(|target| target.privacy_manifest.clone())
        .collect();
    let mut report = IpaAuditReportV1 {
        schema_version: "1.0".into(),
        generator: format!("ByteTrawl/{}", env!("CARGO_PKG_VERSION")),
        source: IpaSource {
            path: source_path,
            sha256: source_sha256,
        },
        metadata,
        total_bytes,
        compressed_bytes,
        files,
        frameworks,
        extensions,
        localizations,
        privacy_usage_descriptions,
        has_privacy_manifest,
        privacy_manifests,
        architectures,
        signing,
        findings: Vec::new(),
        targets,
        partial: !errors.is_empty(),
        errors,
    };
    report.findings = evaluate_rules(&report, &main_prefix);
    Ok(report)
}

fn hash_source(path: &Path, cancel: &CancellationToken) -> Result<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).map_err(|source| ByteTrawlError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 1024 * 1024];
    loop {
        cancel.check()?;
        let read = file
            .read(&mut buffer)
            .map_err(|source| ByteTrawlError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn flatten_nodes(root: &ArtifactNode) -> Vec<&ArtifactNode> {
    fn visit<'a>(node: &'a ArtifactNode, nodes: &mut Vec<&'a ArtifactNode>) {
        nodes.push(node);
        for child in &node.children {
            visit(child, nodes);
        }
    }
    let mut nodes = Vec::new();
    visit(root, &mut nodes);
    nodes
}

fn find_main_app(root: &ArtifactNode) -> Option<&ArtifactNode> {
    root.children
        .iter()
        .find(|node| node.name == "Payload")?
        .children
        .iter()
        .find(|node| {
            node.kind == ArtifactKind::Application && child_named(node, "Info.plist").is_some()
        })
}

fn child_named<'a>(node: &'a ArtifactNode, name: &str) -> Option<&'a ArtifactNode> {
    node.children.iter().find(|child| child.name == name)
}

fn member_path(node: &ArtifactNode) -> Option<PathBuf> {
    match node.source.as_ref()? {
        ArtifactSource::ArchiveMember { member_path, .. } => Some(member_path.clone()),
        ArtifactSource::Filesystem { .. } => None,
    }
}

fn source_sizes(node: &ArtifactNode) -> (u64, u64) {
    match node.source.as_ref() {
        Some(ArtifactSource::ArchiveMember {
            compressed_size,
            uncompressed_size,
            ..
        }) => (*compressed_size, *uncompressed_size),
        _ => (node.size, node.size),
    }
}

fn relative_to(path: &Path, prefix: &Path) -> String {
    path.strip_prefix(prefix)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

fn read_plist(node: &ArtifactNode) -> Result<Value> {
    let bytes = ArtifactReader::open(node)?.read_all(MAX_PLIST_BYTES)?;
    Value::from_reader(std::io::Cursor::new(bytes))
        .map_err(|error| ByteTrawlError::Malformed(format!("plist: {error}")))
}

fn string(dict: &plist::Dictionary, key: &str) -> Option<String> {
    dict.get(key)?.as_string().map(ToOwned::to_owned)
}

fn metadata_from_plist(value: &Value) -> IpaMetadata {
    let Some(dict) = value.as_dictionary() else {
        return IpaMetadata::default();
    };
    IpaMetadata {
        name: string(dict, "CFBundleDisplayName").or_else(|| string(dict, "CFBundleName")),
        bundle_identifier: string(dict, "CFBundleIdentifier"),
        version: string(dict, "CFBundleShortVersionString"),
        build: string(dict, "CFBundleVersion"),
        minimum_os_version: string(dict, "MinimumOSVersion"),
        executable: string(dict, "CFBundleExecutable"),
    }
}

fn usage_descriptions(value: &Value) -> IndexMap<String, String> {
    let mut descriptions = IndexMap::new();
    if let Some(dict) = value.as_dictionary() {
        for (key, value) in dict {
            if key.starts_with("NS")
                && key.ends_with("UsageDescription")
                && let Some(text) = value.as_string()
            {
                descriptions.insert(key.clone(), text.to_owned());
            }
        }
    }
    descriptions.sort_keys();
    descriptions
}

fn subtree_contains(node: &ArtifactNode, name: &str) -> bool {
    node.name == name
        || node
            .children
            .iter()
            .any(|child| subtree_contains(child, name))
}

fn architectures_for(node: &ArtifactNode, errors: &mut Vec<String>) -> Vec<String> {
    let result = (|| {
        let bytes = ArtifactReader::open(node)?.read_all(MAX_PARSE_BYTES)?;
        let path = member_path(node).unwrap_or_else(|| node.path.clone());
        let analysis = UnifiedBinaryAnalyzer.analyze(&AnalysisInput {
            path: &path,
            bytes: &bytes,
        })?;
        let mut values = if analysis.slices.is_empty() {
            vec![analysis.architecture]
        } else {
            analysis
                .slices
                .into_iter()
                .map(|slice| slice.architecture)
                .collect()
        };
        values.retain(|value| !value.is_empty());
        values.sort();
        values.dedup();
        Result::<Vec<String>>::Ok(values)
    })();
    match result {
        Ok(values) => values,
        Err(error) => {
            errors.push(format!("{}: {error}", node.path.display()));
            Vec::new()
        }
    }
}

fn collect_targets(
    main_app: &ArtifactNode,
    main_metadata: &IpaMetadata,
    main_architectures: &[String],
    errors: &mut Vec<String>,
    cancel: &CancellationToken,
) -> Result<Vec<IpaTarget>> {
    let mut bundles = vec![("application", main_app)];
    for node in flatten_nodes(main_app) {
        if node
            .path
            .extension()
            .is_some_and(|extension| extension == "appex")
        {
            bundles.push(("extension", node));
        } else if node.kind == ArtifactKind::Framework {
            bundles.push(("framework", node));
        }
    }
    let mut targets = Vec::new();
    for (kind, bundle) in bundles {
        cancel.check()?;
        let (metadata, architectures) = if std::ptr::eq(bundle, main_app) {
            (main_metadata.clone(), main_architectures.to_vec())
        } else if let Some(info) = child_named(bundle, "Info.plist") {
            match read_plist(info) {
                Ok(value) => {
                    let metadata = metadata_from_plist(&value);
                    let architectures = metadata
                        .executable
                        .as_deref()
                        .and_then(|name| child_named(bundle, name))
                        .map(|node| architectures_for(node, errors))
                        .unwrap_or_default();
                    (metadata, architectures)
                }
                Err(error) => {
                    errors.push(format!("{}: {error}", info.path.display()));
                    (IpaMetadata::default(), Vec::new())
                }
            }
        } else {
            (IpaMetadata::default(), Vec::new())
        };
        targets.push(IpaTarget {
            kind: kind.into(),
            path: member_path(bundle).unwrap_or_else(|| bundle.path.clone()),
            metadata,
            architectures,
            has_privacy_manifest: subtree_contains(bundle, "PrivacyInfo.xcprivacy"),
            privacy_manifest: find_named(bundle, "PrivacyInfo.xcprivacy")
                .map(parse_privacy_manifest)
                .transpose()?,
        });
    }
    Ok(targets)
}

fn find_named<'a>(node: &'a ArtifactNode, name: &str) -> Option<&'a ArtifactNode> {
    if node.name == name {
        return Some(node);
    }
    node.children
        .iter()
        .find_map(|child| find_named(child, name))
}

fn parse_privacy_manifest(node: &ArtifactNode) -> Result<PrivacyManifest> {
    let value = read_plist(node)?;
    let dict = value.as_dictionary().ok_or_else(|| {
        ByteTrawlError::Malformed("PrivacyInfo.xcprivacy root is not a dictionary".into())
    })?;
    let mut tracking_domains = string_array(dict.get("NSPrivacyTrackingDomains"));
    let mut collected_data_types = dict
        .get("NSPrivacyCollectedDataTypes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_dictionary)
        .filter_map(|entry| string(entry, "NSPrivacyCollectedDataType"))
        .collect::<Vec<_>>();
    let mut accessed_api_categories = IndexMap::new();
    if let Some(entries) = dict
        .get("NSPrivacyAccessedAPITypes")
        .and_then(Value::as_array)
    {
        for entry in entries.iter().filter_map(Value::as_dictionary) {
            if let Some(category) = string(entry, "NSPrivacyAccessedAPIType") {
                let mut reasons = string_array(entry.get("NSPrivacyAccessedAPITypeReasons"));
                reasons.sort();
                reasons.dedup();
                accessed_api_categories.insert(category, reasons);
            }
        }
    }
    tracking_domains.sort();
    tracking_domains.dedup();
    collected_data_types.sort();
    collected_data_types.dedup();
    accessed_api_categories.sort_keys();
    Ok(PrivacyManifest {
        path: member_path(node).unwrap_or_else(|| node.path.clone()),
        tracking: dict
            .get("NSPrivacyTracking")
            .and_then(Value::as_boolean)
            .unwrap_or(false),
        tracking_domains,
        collected_data_types,
        accessed_api_categories,
    })
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_string)
        .map(ToOwned::to_owned)
        .collect()
}

fn parse_mobileprovision(node: &ArtifactNode) -> Result<IpaSigning> {
    let bytes = ArtifactReader::open(node)?.read_all(MAX_PROFILE_BYTES)?;
    let xml_start = bytes
        .windows(5)
        .position(|window| window == b"<?xml")
        .ok_or_else(|| ByteTrawlError::Malformed("profile does not contain an XML plist".into()))?;
    let close = b"</plist>";
    let relative_end = bytes[xml_start..]
        .windows(close.len())
        .position(|window| window == close)
        .ok_or_else(|| ByteTrawlError::Malformed("profile plist is truncated".into()))?;
    let end = xml_start + relative_end + close.len();
    let value = Value::from_reader(std::io::Cursor::new(&bytes[xml_start..end]))
        .map_err(|error| ByteTrawlError::Malformed(format!("profile plist: {error}")))?;
    let dict = value.as_dictionary().ok_or_else(|| {
        ByteTrawlError::Malformed("profile plist root is not a dictionary".into())
    })?;
    let entitlement_dict = dict.get("Entitlements").and_then(Value::as_dictionary);
    let mut entitlements = IndexMap::new();
    if let Some(values) = entitlement_dict {
        for (key, value) in values {
            entitlements.insert(key.clone(), plist_scalar(value));
        }
    }
    let team_id = dict
        .get("TeamIdentifier")
        .and_then(Value::as_array)
        .and_then(|values| values.first())
        .and_then(Value::as_string)
        .map(ToOwned::to_owned)
        .or_else(|| {
            entitlement_dict
                .and_then(|values| string(values, "com.apple.developer.team-identifier"))
        });
    let application_identifier =
        entitlement_dict.and_then(|values| string(values, "application-identifier"));
    let expiration = dict
        .get("ExpirationDate")
        .and_then(Value::as_date)
        .map(|date| DateTime::<Utc>::from(std::time::SystemTime::from(date)));
    Ok(IpaSigning {
        team_id,
        application_identifier,
        expiration,
        entitlements,
    })
}

fn plist_scalar(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Boolean(value) => value.to_string(),
        Value::Integer(value) => value.to_string(),
        Value::Real(value) => value.to_string(),
        Value::Date(value) => value.to_xml_format(),
        Value::Data(value) => format!("<{} bytes>", value.len()),
        Value::Array(value) => value
            .iter()
            .map(plist_scalar)
            .collect::<Vec<_>>()
            .join(", "),
        Value::Dictionary(_) => "<dictionary>".into(),
        _ => "<value>".into(),
    }
}

fn evidence(path: &Path, field: Option<&str>, value: Option<&str>) -> Vec<IpaEvidence> {
    vec![IpaEvidence {
        path: path.to_path_buf(),
        field: field.map(ToOwned::to_owned),
        value: value.map(ToOwned::to_owned),
    }]
}

fn finding(
    code: &str,
    severity: Severity,
    title: &str,
    description: &str,
    evidence: Vec<IpaEvidence>,
) -> IpaFinding {
    IpaFinding {
        code: code.into(),
        rule_id: format!("ios.ipa.{code}"),
        severity,
        title: title.into(),
        description: description.into(),
        evidence,
    }
}

fn evaluate_rules(report: &IpaAuditReportV1, app_path: &Path) -> Vec<IpaFinding> {
    let info = app_path.join("Info.plist");
    let mut findings = Vec::new();
    if report
        .metadata
        .bundle_identifier
        .as_deref()
        .unwrap_or("")
        .is_empty()
    {
        findings.push(finding(
            "missing-bundle-id",
            Severity::High,
            "Missing bundle identifier",
            "CFBundleIdentifier is absent or empty.",
            evidence(&info, Some("CFBundleIdentifier"), None),
        ));
    }
    if report.metadata.version.as_deref().unwrap_or("").is_empty() {
        findings.push(finding(
            "missing-version",
            Severity::Medium,
            "Missing marketing version",
            "CFBundleShortVersionString is absent or empty.",
            evidence(&info, Some("CFBundleShortVersionString"), None),
        ));
    }
    if !report.has_privacy_manifest {
        findings.push(finding(
            "missing-privacy-manifest",
            Severity::Medium,
            "Missing privacy manifest",
            "The application bundle has no PrivacyInfo.xcprivacy.",
            evidence(app_path, None, None),
        ));
    }
    if report
        .metadata
        .executable
        .as_deref()
        .unwrap_or("")
        .is_empty()
    {
        findings.push(finding(
            "missing-executable",
            Severity::High,
            "Missing executable declaration",
            "CFBundleExecutable is absent or empty.",
            evidence(&info, Some("CFBundleExecutable"), None),
        ));
    }
    for architecture in &report.architectures {
        if matches!(architecture.as_str(), "i386" | "x86" | "x86_64") {
            findings.push(finding(
                "simulator-architecture",
                Severity::High,
                "Simulator architecture in IPA",
                "A simulator architecture is present in the main executable.",
                evidence(app_path, Some("architecture"), Some(architecture)),
            ));
        }
    }
    if report.signing.is_none() {
        findings.push(finding(
            "missing-provisioning-profile",
            Severity::Medium,
            "Missing provisioning profile",
            "The application has no embedded.mobileprovision.",
            evidence(app_path, None, None),
        ));
    }
    if let Some(signing) = report.signing.as_ref() {
        if let Some(expiration) = signing.expiration
            && expiration < Utc::now()
        {
            let expiration = expiration.to_rfc3339();
            findings.push(finding(
                "expired-provisioning-profile",
                Severity::High,
                "Expired provisioning profile",
                "The embedded provisioning profile has expired.",
                evidence(app_path, Some("ExpirationDate"), Some(&expiration)),
            ));
        }
        if let (Some(application_identifier), Some(bundle_identifier)) = (
            signing.application_identifier.as_deref(),
            report.metadata.bundle_identifier.as_deref(),
        ) && !application_identifier.ends_with(bundle_identifier)
        {
            findings.push(finding(
                "application-id-mismatch",
                Severity::High,
                "Provisioning Application ID mismatch",
                "The provisioning application-identifier does not match CFBundleIdentifier.",
                evidence(
                    app_path,
                    Some("application-identifier"),
                    Some(application_identifier),
                ),
            ));
        }
    }
    for (key, value) in &report.privacy_usage_descriptions {
        if value.trim().chars().count() < 10 {
            findings.push(finding(
                "weak-NS*UsageDescription",
                Severity::Low,
                "Weak privacy usage description",
                "The usage description is too short to clearly explain the purpose.",
                evidence(&info, Some(key), Some(value)),
            ));
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytetrawl_analysis::open_artifact;
    use std::io::Write;

    fn add_file(writer: &mut zip::ZipWriter<std::fs::File>, path: &str, bytes: &[u8]) {
        writer
            .start_file(path, zip::write::SimpleFileOptions::default())
            .expect("start fixture member");
        writer.write_all(bytes).expect("write fixture member");
    }

    fn plist(body: &str) -> Vec<u8> {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0"><dict>{body}</dict></plist>"#
        )
        .into_bytes()
    }

    #[test]
    fn audits_identity_targets_sizes_privacy_signing_and_compatibility_rules() {
        let temporary = tempfile::tempdir().expect("create fixture directory");
        let ipa = temporary.path().join("Fixture.ipa");
        let file = std::fs::File::create(&ipa).expect("create IPA fixture");
        let mut writer = zip::ZipWriter::new(file);
        let info = plist(
            "<key>CFBundleDisplayName</key><string>Fixture</string>\
             <key>CFBundleIdentifier</key><string>app.xnu.fixture</string>\
             <key>CFBundleShortVersionString</key><string>2.3</string>\
             <key>CFBundleVersion</key><string>42</string>\
             <key>MinimumOSVersion</key><string>17.0</string>\
             <key>CFBundleExecutable</key><string>Fixture</string>\
             <key>NSCameraUsageDescription</key><string>Camera</string>",
        );
        add_file(&mut writer, "Payload/Fixture.app/Info.plist", &info);
        let executable = std::fs::read(std::env::current_exe().expect("current executable"))
            .expect("read Mach-O fixture");
        add_file(&mut writer, "Payload/Fixture.app/Fixture", &executable);
        add_file(
            &mut writer,
            "Payload/Fixture.app/PrivacyInfo.xcprivacy",
            &plist(
                "<key>NSPrivacyTracking</key><true/>\
                 <key>NSPrivacyTrackingDomains</key><array><string>tracker.example</string></array>\
                 <key>NSPrivacyCollectedDataTypes</key><array><dict>\
                 <key>NSPrivacyCollectedDataType</key><string>NSPrivacyCollectedDataTypeEmailAddress</string>\
                 </dict></array>\
                 <key>NSPrivacyAccessedAPITypes</key><array><dict>\
                 <key>NSPrivacyAccessedAPIType</key><string>NSPrivacyAccessedAPICategoryFileTimestamp</string>\
                 <key>NSPrivacyAccessedAPITypeReasons</key><array><string>C617.1</string></array>\
                 </dict></array>",
            ),
        );
        add_file(
            &mut writer,
            "Payload/Fixture.app/en.lproj/Localizable.strings",
            b"fixture",
        );
        add_file(
            &mut writer,
            "Payload/Fixture.app/Frameworks/Kit.framework/Info.plist",
            &plist("<key>CFBundleExecutable</key><string>Kit</string>"),
        );
        add_file(
            &mut writer,
            "Payload/Fixture.app/PlugIns/Share.appex/Info.plist",
            &plist("<key>CFBundleIdentifier</key><string>app.xnu.fixture.share</string>"),
        );
        let profile = plist(
            "<key>TeamIdentifier</key><array><string>TEAM123</string></array>\
             <key>ExpirationDate</key><date>2030-01-02T03:04:05Z</date>\
             <key>Entitlements</key><dict>\
             <key>application-identifier</key><string>TEAM123.app.xnu.fixture</string>\
             <key>com.apple.developer.team-identifier</key><string>TEAM123</string>\
             </dict>",
        );
        let mut cms_like_profile = b"CMS-prefix".to_vec();
        cms_like_profile.extend(profile);
        cms_like_profile.extend(b"CMS-suffix");
        add_file(
            &mut writer,
            "Payload/Fixture.app/embedded.mobileprovision",
            &cms_like_profile,
        );
        writer.finish().expect("finish IPA fixture");

        let artifact = open_artifact(&ipa, &CancellationToken::default()).expect("open IPA");
        let report = audit_ipa(&artifact, &CancellationToken::default()).expect("audit IPA");
        assert_eq!(report.schema_version, "1.0");
        assert_eq!(
            report.metadata.bundle_identifier.as_deref(),
            Some("app.xnu.fixture")
        );
        assert_eq!(report.metadata.version.as_deref(), Some("2.3"));
        assert!(report.total_bytes > 0);
        assert!(report.compressed_bytes > 0);
        assert_eq!(report.localizations, ["en"]);
        assert!(
            report
                .frameworks
                .iter()
                .any(|path| path.ends_with("Kit.framework"))
        );
        assert!(
            report
                .extensions
                .iter()
                .any(|path| path.ends_with("Share.appex"))
        );
        assert!(report.has_privacy_manifest);
        assert_eq!(report.privacy_manifests.len(), 1);
        assert!(report.privacy_manifests[0].tracking);
        assert_eq!(
            report.privacy_manifests[0].tracking_domains,
            ["tracker.example"]
        );
        assert_eq!(report.targets.len(), 3);
        assert_eq!(
            report
                .signing
                .as_ref()
                .and_then(|value| value.team_id.as_deref()),
            Some("TEAM123")
        );
        assert_eq!(
            report
                .signing
                .as_ref()
                .and_then(|value| value.application_identifier.as_deref()),
            Some("TEAM123.app.xnu.fixture")
        );
        assert_eq!(
            report
                .signing
                .as_ref()
                .and_then(|value| value.expiration)
                .map(|value| value.to_rfc3339()),
            Some("2030-01-02T03:04:05+00:00".into())
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "weak-NS*UsageDescription")
        );
        assert!(
            !report
                .findings
                .iter()
                .any(|finding| finding.code == "missing-privacy-manifest")
        );
        assert!(!report.partial, "unexpected errors: {:?}", report.errors);
        assert_eq!(report.source.sha256.len(), 64);
        serde_json::to_string_pretty(&report).expect("serialize stable report");
    }

    #[test]
    fn emits_all_missing_release_audit_findings() {
        let temporary = tempfile::tempdir().expect("create fixture directory");
        let ipa = temporary.path().join("Missing.ipa");
        let file = std::fs::File::create(&ipa).expect("create IPA fixture");
        let mut writer = zip::ZipWriter::new(file);
        add_file(&mut writer, "Payload/Missing.app/Info.plist", &plist(""));
        writer.finish().expect("finish IPA fixture");
        let artifact = open_artifact(&ipa, &CancellationToken::default()).expect("open IPA");
        let report = audit_ipa(&artifact, &CancellationToken::default()).expect("audit IPA");
        let codes: Vec<_> = report
            .findings
            .iter()
            .map(|finding| finding.code.as_str())
            .collect();
        for expected in [
            "missing-bundle-id",
            "missing-version",
            "missing-privacy-manifest",
            "missing-executable",
            "missing-provisioning-profile",
        ] {
            assert!(
                codes.contains(&expected),
                "missing finding {expected}: {codes:?}"
            );
        }
    }
}
