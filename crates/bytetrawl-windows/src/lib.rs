//! Static APPX/MSIX release-package inspection.

use bytetrawl_analysis::{ArtifactReader, CancellationToken};
use bytetrawl_core::{ArtifactNode, ArtifactSource, ByteTrawlError, Result, Severity};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const MAX_MANIFEST_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct WindowsPackageIdentity {
    pub name: Option<String>,
    pub publisher: Option<String>,
    pub version: Option<String>,
    pub processor_architecture: Option<String>,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TargetDeviceFamily {
    pub name: String,
    pub minimum_version: Option<String>,
    pub maximum_version_tested: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsApplication {
    pub id: String,
    pub executable: Option<String>,
    pub entry_point: Option<String>,
    pub runtime_behavior: Option<String>,
    pub trust_level: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsFinding {
    pub rule_id: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub evidence_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsPackageReportV1 {
    pub schema_version: String,
    pub generator: String,
    pub source: PathBuf,
    pub identity: WindowsPackageIdentity,
    pub target_device_families: Vec<TargetDeviceFamily>,
    pub capabilities: Vec<String>,
    pub restricted_capabilities: Vec<String>,
    pub applications: Vec<WindowsApplication>,
    pub executable_members: Vec<PathBuf>,
    pub signature_present: bool,
    pub block_map_present: bool,
    pub findings: Vec<WindowsFinding>,
}

pub fn is_msix(artifact: &ArtifactNode) -> bool {
    find_member(artifact, "AppxManifest.xml").is_some()
}

pub fn audit_msix(
    artifact: &ArtifactNode,
    cancel: &CancellationToken,
) -> Result<WindowsPackageReportV1> {
    let manifest_node = find_member(artifact, "AppxManifest.xml").ok_or_else(|| {
        ByteTrawlError::Malformed("APPX/MSIX package has no AppxManifest.xml".into())
    })?;
    let parsed =
        parse_manifest(&ArtifactReader::open(manifest_node)?.read_all(MAX_MANIFEST_BYTES)?)?;
    let mut executable_members = Vec::new();
    let mut signature_present = false;
    let mut block_map_present = false;
    for node in artifact.files() {
        cancel.check()?;
        let Some(path) = member_path(node) else {
            continue;
        };
        let lower = path.to_string_lossy().to_ascii_lowercase();
        if lower.ends_with(".exe") || lower.ends_with(".dll") || lower.ends_with(".winmd") {
            executable_members.push(path.clone());
        }
        signature_present |= lower == "appxsignature.p7x";
        block_map_present |= lower == "appxblockmap.xml";
    }
    executable_members.sort();
    let mut report = WindowsPackageReportV1 {
        schema_version: "1.0".into(),
        generator: format!("ByteTrawl/{}", env!("CARGO_PKG_VERSION")),
        source: artifact.path.clone(),
        identity: parsed.identity,
        target_device_families: parsed.target_device_families,
        capabilities: parsed.capabilities,
        restricted_capabilities: parsed.restricted_capabilities,
        applications: parsed.applications,
        executable_members,
        signature_present,
        block_map_present,
        findings: Vec::new(),
    };
    report.findings = evaluate_findings(&report);
    Ok(report)
}

#[derive(Default)]
struct ParsedManifest {
    identity: WindowsPackageIdentity,
    target_device_families: Vec<TargetDeviceFamily>,
    capabilities: Vec<String>,
    restricted_capabilities: Vec<String>,
    applications: Vec<WindowsApplication>,
}

fn parse_manifest(bytes: &[u8]) -> Result<ParsedManifest> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| ByteTrawlError::Malformed(format!("AppxManifest UTF-8: {error}")))?;
    let mut reader = quick_xml::Reader::from_str(text);
    reader.config_mut().trim_text(true);
    let mut parsed = ParsedManifest::default();
    let mut elements = Vec::new();
    loop {
        match reader.read_event() {
            Ok(quick_xml::events::Event::Start(event))
            | Ok(quick_xml::events::Event::Empty(event)) => {
                let qualified = String::from_utf8_lossy(event.name().as_ref()).into_owned();
                let local = qualified
                    .rsplit(':')
                    .next()
                    .unwrap_or(&qualified)
                    .to_owned();
                let attributes = event
                    .attributes()
                    .filter_map(|attribute| attribute.ok())
                    .map(|attribute| {
                        let qualified = String::from_utf8_lossy(attribute.key.as_ref());
                        let key = qualified
                            .rsplit(':')
                            .next()
                            .unwrap_or(&qualified)
                            .to_owned();
                        let value = attribute
                            .decode_and_unescape_value(reader.decoder())
                            .map(|value| value.into_owned())
                            .unwrap_or_default();
                        (key, value)
                    })
                    .collect::<IndexMap<_, _>>();
                match local.as_str() {
                    "Identity" => {
                        parsed.identity.name = attributes.get("Name").cloned();
                        parsed.identity.publisher = attributes.get("Publisher").cloned();
                        parsed.identity.version = attributes.get("Version").cloned();
                        parsed.identity.processor_architecture =
                            attributes.get("ProcessorArchitecture").cloned();
                    }
                    "TargetDeviceFamily" => {
                        parsed.target_device_families.push(TargetDeviceFamily {
                            name: attributes.get("Name").cloned().unwrap_or_default(),
                            minimum_version: attributes.get("MinVersion").cloned(),
                            maximum_version_tested: attributes.get("MaxVersionTested").cloned(),
                        })
                    }
                    "Capability" | "DeviceCapability" | "CustomCapability" => {
                        if let Some(name) = attributes.get("Name") {
                            if qualified.starts_with("rescap:") {
                                parsed.restricted_capabilities.push(name.clone());
                            } else {
                                parsed.capabilities.push(name.clone());
                            }
                        }
                    }
                    "Application" => parsed.applications.push(WindowsApplication {
                        id: attributes.get("Id").cloned().unwrap_or_default(),
                        executable: attributes.get("Executable").cloned(),
                        entry_point: attributes.get("EntryPoint").cloned(),
                        runtime_behavior: attributes.get("RuntimeBehavior").cloned(),
                        trust_level: attributes.get("TrustLevel").cloned(),
                    }),
                    _ => {}
                }
                if !event.is_empty() {
                    elements.push(local);
                }
            }
            Ok(quick_xml::events::Event::Text(value)) => {
                if elements
                    .last()
                    .is_some_and(|element| element == "DisplayName")
                {
                    parsed.identity.display_name = Some(
                        value
                            .decode()
                            .map_err(|error| ByteTrawlError::Malformed(error.to_string()))?
                            .into_owned(),
                    );
                }
            }
            Ok(quick_xml::events::Event::End(_)) => {
                elements.pop();
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Err(error) => {
                return Err(ByteTrawlError::Malformed(format!(
                    "AppxManifest.xml: {error}"
                )));
            }
            _ => {}
        }
    }
    for values in [
        &mut parsed.capabilities,
        &mut parsed.restricted_capabilities,
    ] {
        values.sort();
        values.dedup();
    }
    parsed
        .target_device_families
        .sort_by(|a, b| a.name.cmp(&b.name));
    parsed.applications.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(parsed)
}

fn evaluate_findings(report: &WindowsPackageReportV1) -> Vec<WindowsFinding> {
    let manifest = PathBuf::from("AppxManifest.xml");
    let mut findings = Vec::new();
    let mut push = |rule: &str, severity, title: &str, description: String, path: PathBuf| {
        findings.push(WindowsFinding {
            rule_id: format!("windows.msix.{rule}"),
            severity,
            title: title.into(),
            description,
            evidence_path: path,
        });
    };
    if report
        .identity
        .name
        .as_deref()
        .unwrap_or_default()
        .is_empty()
        || report
            .identity
            .publisher
            .as_deref()
            .unwrap_or_default()
            .is_empty()
        || report
            .identity
            .version
            .as_deref()
            .unwrap_or_default()
            .is_empty()
    {
        push(
            "incomplete-identity",
            Severity::High,
            "Incomplete package identity",
            "Name, Publisher, and Version are required in the package Identity.".into(),
            manifest.clone(),
        );
    }
    if !report.signature_present {
        push(
            "missing-signature",
            Severity::High,
            "Package signature is missing",
            "AppxSignature.p7x was not found.".into(),
            PathBuf::from("AppxSignature.p7x"),
        );
    }
    if !report.block_map_present {
        push(
            "missing-block-map",
            Severity::High,
            "Package block map is missing",
            "AppxBlockMap.xml was not found.".into(),
            PathBuf::from("AppxBlockMap.xml"),
        );
    }
    for capability in &report.restricted_capabilities {
        push(
            "restricted-capability",
            Severity::Medium,
            "Restricted capability declared",
            format!("Restricted capability {capability} requires explicit review."),
            manifest.clone(),
        );
    }
    for application in &report.applications {
        if application.executable.is_none() && application.entry_point.is_none() {
            push(
                "missing-entry-point",
                Severity::High,
                "Application entry point is missing",
                format!(
                    "Application {} has neither Executable nor EntryPoint.",
                    application.id
                ),
                manifest.clone(),
            );
        }
    }
    findings.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));
    findings
}

fn member_path(node: &ArtifactNode) -> Option<PathBuf> {
    match node.source.as_ref()? {
        ArtifactSource::ArchiveMember { member_path, .. } => Some(member_path.clone()),
        _ => None,
    }
}

fn find_member<'a>(node: &'a ArtifactNode, name: &str) -> Option<&'a ArtifactNode> {
    if member_path(node).is_some_and(|path| path == Path::new(name)) {
        return Some(node);
    }
    node.children
        .iter()
        .find_map(|child| find_member(child, name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytetrawl_analysis::open_artifact;
    use std::io::Write;

    #[test]
    fn audits_msix_manifest_capabilities_apps_and_trust_files() {
        let temporary = tempfile::tempdir().expect("create MSIX fixture directory");
        let msix = temporary.path().join("fixture.msix");
        let file = std::fs::File::create(&msix).expect("create MSIX fixture");
        let mut writer = zip::ZipWriter::new(file);
        let manifest = br#"<?xml version="1.0" encoding="utf-8"?>
        <Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10" xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities">
          <Identity Name="app.xnu.fixture" Publisher="CN=XNU" Version="2.3.4.5" ProcessorArchitecture="x64"/>
          <Properties><DisplayName>Fixture</DisplayName></Properties>
          <Dependencies><TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.19041.0" MaxVersionTested="10.0.26100.0"/></Dependencies>
          <Capabilities><Capability Name="internetClient"/><rescap:Capability Name="runFullTrust"/></Capabilities>
          <Applications><Application Id="App" Executable="Fixture.exe" EntryPoint="Windows.FullTrustApplication"/></Applications>
        </Package>"#;
        for (path, bytes) in [
            ("AppxManifest.xml", manifest.as_slice()),
            ("AppxBlockMap.xml", b"block".as_slice()),
            ("AppxSignature.p7x", b"signature".as_slice()),
            ("Fixture.exe", b"MZ".as_slice()),
        ] {
            writer
                .start_file(path, zip::write::SimpleFileOptions::default())
                .expect("start member");
            writer.write_all(bytes).expect("write member");
        }
        writer.finish().expect("finish fixture");
        let cancellation = CancellationToken::default();
        let artifact = open_artifact(&msix, &cancellation).expect("open MSIX");
        let report = audit_msix(&artifact, &cancellation).expect("audit MSIX");
        assert_eq!(report.identity.name.as_deref(), Some("app.xnu.fixture"));
        assert_eq!(report.identity.display_name.as_deref(), Some("Fixture"));
        assert_eq!(report.capabilities, ["internetClient"]);
        assert_eq!(report.restricted_capabilities, ["runFullTrust"]);
        assert!(report.signature_present && report.block_map_present);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.rule_id == "windows.msix.restricted-capability")
        );
    }
}
