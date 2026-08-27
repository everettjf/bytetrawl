//! Static, extraction-free Android APK release inspection.

use bytetrawl_analysis::{ArtifactReader, CancellationToken};
use bytetrawl_core::{ArtifactNode, ArtifactSource, ByteTrawlError, Result, Severity};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const MAX_MANIFEST_BYTES: u64 = 32 * 1024 * 1024;
const MAX_DEX_HEADER_BYTES: usize = 112;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AndroidIdentity {
    pub package: Option<String>,
    pub version_name: Option<String>,
    pub version_code: Option<String>,
    pub min_sdk: Option<String>,
    pub target_sdk: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AndroidApplicationFlags {
    pub debuggable: Option<bool>,
    pub allow_backup: Option<bool>,
    pub uses_cleartext_traffic: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AndroidComponent {
    pub kind: String,
    pub name: String,
    pub exported: Option<bool>,
    pub permission: Option<String>,
    pub actions: Vec<String>,
    pub categories: Vec<String>,
    pub deep_links: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DexSummary {
    pub path: PathBuf,
    pub strings: u32,
    pub types: u32,
    pub prototypes: u32,
    pub fields: u32,
    pub methods: u32,
    pub classes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AndroidFinding {
    pub rule_id: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub evidence_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AndroidAuditReportV1 {
    pub schema_version: String,
    pub generator: String,
    pub source: PathBuf,
    pub identity: AndroidIdentity,
    pub application: AndroidApplicationFlags,
    pub permissions: Vec<String>,
    pub components: Vec<AndroidComponent>,
    pub dex: Vec<DexSummary>,
    pub resources_arsc_bytes: Option<u64>,
    pub native_libraries: Vec<PathBuf>,
    pub signing_schemes: Vec<String>,
    pub findings: Vec<AndroidFinding>,
    pub partial: bool,
    pub errors: Vec<String>,
}

pub fn is_apk(artifact: &ArtifactNode) -> bool {
    find_member(artifact, "AndroidManifest.xml").is_some()
        && artifact.files().any(|node| {
            member_path(node).is_some_and(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        name == "classes.dex"
                            || (name.starts_with("classes") && name.ends_with(".dex"))
                    })
            })
        })
}

pub fn audit_apk(
    artifact: &ArtifactNode,
    cancel: &CancellationToken,
) -> Result<AndroidAuditReportV1> {
    cancel.check()?;
    if !is_apk(artifact) {
        return Err(ByteTrawlError::Malformed(
            "archive is not an Android APK".into(),
        ));
    }
    let manifest_node = find_member(artifact, "AndroidManifest.xml")
        .ok_or_else(|| ByteTrawlError::Malformed("AndroidManifest.xml is missing".into()))?;
    let manifest_bytes = ArtifactReader::open(manifest_node)?.read_all(MAX_MANIFEST_BYTES)?;
    let manifest = parse_manifest(&manifest_bytes)?;
    let mut dex = Vec::new();
    let mut native_libraries = Vec::new();
    let mut resources_arsc_bytes = None;
    let mut has_v1_signature = false;
    for node in artifact.files() {
        cancel.check()?;
        let Some(path) = member_path(node) else {
            continue;
        };
        let text = path.to_string_lossy();
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if file_name.ends_with(".dex") && file_name.starts_with("classes") {
            let header = ArtifactReader::open(node)?.read_prefix(MAX_DEX_HEADER_BYTES)?;
            dex.push(parse_dex_header(path.clone(), &header)?);
        } else if text.starts_with("lib/") && file_name.ends_with(".so") {
            native_libraries.push(path.clone());
        } else if path == PathBuf::from("resources.arsc") {
            resources_arsc_bytes = Some(node.size);
        } else if text.starts_with("META-INF/")
            && matches!(
                path.extension().and_then(|extension| extension.to_str()),
                Some("RSA" | "DSA" | "EC")
            )
        {
            has_v1_signature = true;
        }
    }
    dex.sort_by(|left, right| left.path.cmp(&right.path));
    native_libraries.sort();
    let mut signing_schemes = Vec::new();
    if has_v1_signature {
        signing_schemes.push("v1 (JAR)".into());
    }
    if apk_signing_block_present(&artifact.path)? {
        signing_schemes.push("v2/v3/v4 signing block present".into());
    }
    let mut report = AndroidAuditReportV1 {
        schema_version: "1.0".into(),
        generator: format!("ByteTrawl/{}", env!("CARGO_PKG_VERSION")),
        source: artifact.path.clone(),
        identity: manifest.identity,
        application: manifest.application,
        permissions: manifest.permissions,
        components: manifest.components,
        dex,
        resources_arsc_bytes,
        native_libraries,
        signing_schemes,
        findings: Vec::new(),
        partial: false,
        errors: Vec::new(),
    };
    report.findings = evaluate_findings(&report);
    Ok(report)
}

#[derive(Default)]
struct ParsedManifest {
    identity: AndroidIdentity,
    application: AndroidApplicationFlags,
    permissions: Vec<String>,
    components: Vec<AndroidComponent>,
}

fn parse_manifest(bytes: &[u8]) -> Result<ParsedManifest> {
    if bytes.starts_with(b"<") || bytes.starts_with(b"<?xml") {
        parse_text_manifest(bytes)
    } else {
        parse_binary_manifest(bytes)
    }
}

fn parse_text_manifest(bytes: &[u8]) -> Result<ParsedManifest> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| ByteTrawlError::Malformed(format!("manifest UTF-8: {error}")))?;
    let mut reader = quick_xml::Reader::from_str(text);
    reader.config_mut().trim_text(true);
    let mut parsed = ParsedManifest::default();
    let mut component: Option<AndroidComponent> = None;
    loop {
        match reader.read_event() {
            Ok(quick_xml::events::Event::Start(event))
            | Ok(quick_xml::events::Event::Empty(event)) => {
                let tag = String::from_utf8_lossy(event.name().as_ref()).into_owned();
                let attributes = event
                    .attributes()
                    .filter_map(|attribute| attribute.ok())
                    .map(|attribute| {
                        (
                            String::from_utf8_lossy(attribute.key.as_ref()).into_owned(),
                            attribute
                                .decode_and_unescape_value(reader.decoder())
                                .map(|value| value.into_owned())
                                .unwrap_or_default(),
                        )
                    })
                    .collect::<IndexMap<_, _>>();
                apply_manifest_element(&tag, &attributes, &mut parsed, &mut component);
                if event.is_empty()
                    && is_component_tag(&tag)
                    && let Some(component) = component.take()
                {
                    parsed.components.push(component);
                }
            }
            Ok(quick_xml::events::Event::End(event)) => {
                let tag = String::from_utf8_lossy(event.name().as_ref()).into_owned();
                if is_component_tag(&tag)
                    && let Some(component) = component.take()
                {
                    parsed.components.push(component);
                }
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Err(error) => {
                return Err(ByteTrawlError::Malformed(format!(
                    "AndroidManifest.xml: {error}"
                )));
            }
            _ => {}
        }
    }
    normalize_manifest(&mut parsed);
    Ok(parsed)
}

fn parse_binary_manifest(bytes: &[u8]) -> Result<ParsedManifest> {
    if read_u16(bytes, 0)? != 0x0003 {
        return Err(ByteTrawlError::Malformed(
            "AndroidManifest.xml is neither text nor binary XML".into(),
        ));
    }
    let file_header_size = read_u16(bytes, 2)? as usize;
    let file_size = read_u32(bytes, 4)? as usize;
    if file_header_size < 8 || file_size > bytes.len() {
        return Err(ByteTrawlError::Malformed(
            "binary Android XML header is invalid".into(),
        ));
    }
    let mut strings = Vec::new();
    let mut parsed = ParsedManifest::default();
    let mut component: Option<AndroidComponent> = None;
    let mut offset = file_header_size;
    while offset < file_size {
        let chunk_type = read_u16(bytes, offset)?;
        let header_size = read_u16(bytes, offset + 2)? as usize;
        let chunk_size = read_u32(bytes, offset + 4)? as usize;
        if header_size < 8 || chunk_size < header_size || offset + chunk_size > file_size {
            return Err(ByteTrawlError::Malformed(
                "binary Android XML chunk bounds are invalid".into(),
            ));
        }
        match chunk_type {
            0x0001 => strings = parse_string_pool(bytes, offset, header_size, chunk_size)?,
            0x0102 => {
                if strings.is_empty() || header_size < 16 || chunk_size < 36 {
                    return Err(ByteTrawlError::Malformed(
                        "binary Android XML start element is invalid".into(),
                    ));
                }
                let name = pool_string(&strings, read_u32(bytes, offset + 20)?)?;
                let attribute_start = read_u16(bytes, offset + 24)? as usize;
                let attribute_size = read_u16(bytes, offset + 26)? as usize;
                let attribute_count = read_u16(bytes, offset + 28)? as usize;
                if attribute_size < 20 {
                    return Err(ByteTrawlError::Malformed(
                        "binary Android XML attribute size is invalid".into(),
                    ));
                }
                let attributes_offset = offset + 16 + attribute_start;
                let attributes_end = attributes_offset
                    .checked_add(attribute_size.saturating_mul(attribute_count))
                    .ok_or_else(|| {
                        ByteTrawlError::Malformed("binary XML attribute bounds overflow".into())
                    })?;
                if attributes_end > offset + chunk_size {
                    return Err(ByteTrawlError::Malformed(
                        "binary Android XML attributes exceed their chunk".into(),
                    ));
                }
                let mut attributes = IndexMap::new();
                for index in 0..attribute_count {
                    let attribute = attributes_offset + index * attribute_size;
                    let key = pool_string(&strings, read_u32(bytes, attribute + 4)?)?;
                    let raw_value = read_u32(bytes, attribute + 8)?;
                    let value = if raw_value != u32::MAX {
                        pool_string(&strings, raw_value)?
                    } else {
                        typed_attribute_value(bytes, attribute, &strings)?
                    };
                    attributes.insert(key, value);
                }
                apply_manifest_element(&name, &attributes, &mut parsed, &mut component);
            }
            0x0103 => {
                let name = pool_string(&strings, read_u32(bytes, offset + 20)?)?;
                if is_component_tag(&name)
                    && let Some(component) = component.take()
                {
                    parsed.components.push(component);
                }
            }
            _ => {}
        }
        offset += chunk_size;
    }
    normalize_manifest(&mut parsed);
    Ok(parsed)
}

fn parse_string_pool(
    bytes: &[u8],
    offset: usize,
    header_size: usize,
    chunk_size: usize,
) -> Result<Vec<String>> {
    if header_size < 28 {
        return Err(ByteTrawlError::Malformed(
            "Android string pool header is truncated".into(),
        ));
    }
    let count = read_u32(bytes, offset + 8)? as usize;
    if count > 1_000_000 {
        return Err(ByteTrawlError::Limit(
            "Android string pool exceeds one million strings".into(),
        ));
    }
    let flags = read_u32(bytes, offset + 16)?;
    let strings_start = read_u32(bytes, offset + 20)? as usize;
    let offsets_start = offset + header_size;
    let strings_base = offset + strings_start;
    if offsets_start + count.saturating_mul(4) > offset + chunk_size
        || strings_base > offset + chunk_size
    {
        return Err(ByteTrawlError::Malformed(
            "Android string pool bounds are invalid".into(),
        ));
    }
    let utf8 = flags & 0x100 != 0;
    let mut strings = Vec::with_capacity(count);
    for index in 0..count {
        let relative = read_u32(bytes, offsets_start + index * 4)? as usize;
        let start = strings_base
            .checked_add(relative)
            .ok_or_else(|| ByteTrawlError::Malformed("Android string offset overflows".into()))?;
        if start >= offset + chunk_size {
            return Err(ByteTrawlError::Malformed(
                "Android string points outside its pool".into(),
            ));
        }
        strings.push(if utf8 {
            parse_utf8_pool_string(bytes, start, offset + chunk_size)?
        } else {
            parse_utf16_pool_string(bytes, start, offset + chunk_size)?
        });
    }
    Ok(strings)
}

fn parse_utf8_pool_string(bytes: &[u8], start: usize, end: usize) -> Result<String> {
    let (_, cursor) = decode_length8(bytes, start, end)?;
    let (byte_length, cursor) = decode_length8(bytes, cursor, end)?;
    let string_end = cursor
        .checked_add(byte_length)
        .ok_or_else(|| ByteTrawlError::Malformed("Android UTF-8 string length overflows".into()))?;
    let value = bytes
        .get(cursor..string_end)
        .ok_or_else(|| ByteTrawlError::Malformed("Android UTF-8 string is truncated".into()))?;
    std::str::from_utf8(value)
        .map(ToOwned::to_owned)
        .map_err(|error| ByteTrawlError::Malformed(format!("Android UTF-8 string: {error}")))
}

fn decode_length8(bytes: &[u8], start: usize, end: usize) -> Result<(usize, usize)> {
    let first = *bytes.get(start).filter(|_| start < end).ok_or_else(|| {
        ByteTrawlError::Malformed("Android UTF-8 string length is truncated".into())
    })?;
    if first & 0x80 == 0 {
        Ok((first as usize, start + 1))
    } else {
        let second = *bytes
            .get(start + 1)
            .filter(|_| start + 1 < end)
            .ok_or_else(|| {
                ByteTrawlError::Malformed("Android UTF-8 string length is truncated".into())
            })?;
        Ok((
            (((first & 0x7f) as usize) << 8) | second as usize,
            start + 2,
        ))
    }
}

fn parse_utf16_pool_string(bytes: &[u8], start: usize, end: usize) -> Result<String> {
    let first = read_u16_bounded(bytes, start, end)?;
    let (units, cursor) = if first & 0x8000 == 0 {
        (first as usize, start + 2)
    } else {
        let second = read_u16_bounded(bytes, start + 2, end)?;
        (
            (((first & 0x7fff) as usize) << 16) | second as usize,
            start + 4,
        )
    };
    let byte_length = units.checked_mul(2).ok_or_else(|| {
        ByteTrawlError::Malformed("Android UTF-16 string length overflows".into())
    })?;
    let slice = bytes
        .get(cursor..cursor + byte_length)
        .ok_or_else(|| ByteTrawlError::Malformed("Android UTF-16 string is truncated".into()))?;
    let words = slice
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
    String::from_utf16(&words.collect::<Vec<_>>())
        .map_err(|error| ByteTrawlError::Malformed(format!("Android UTF-16 string: {error}")))
}

fn typed_attribute_value(bytes: &[u8], offset: usize, strings: &[String]) -> Result<String> {
    let value_type = *bytes
        .get(offset + 15)
        .ok_or_else(|| ByteTrawlError::Malformed("Android typed attribute is truncated".into()))?;
    let data = read_u32(bytes, offset + 16)?;
    match value_type {
        0x03 => pool_string(strings, data),
        0x10 => Ok(data.to_string()),
        0x11 => Ok(format!("0x{data:x}")),
        0x12 => Ok((data != 0).to_string()),
        0x01 => Ok(format!("@0x{data:08x}")),
        _ => Ok(format!("0x{data:x}")),
    }
}

fn pool_string(strings: &[String], index: u32) -> Result<String> {
    strings
        .get(index as usize)
        .cloned()
        .ok_or_else(|| ByteTrawlError::Malformed("Android XML string index is invalid".into()))
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| ByteTrawlError::Malformed("binary Android XML is truncated".into()))?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u16_bounded(bytes: &[u8], offset: usize, end: usize) -> Result<u16> {
    if offset + 2 > end {
        return Err(ByteTrawlError::Malformed(
            "binary Android XML string is truncated".into(),
        ));
    }
    read_u16(bytes, offset)
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| ByteTrawlError::Malformed("binary Android XML is truncated".into()))?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn apply_manifest_element(
    tag: &str,
    attributes: &IndexMap<String, String>,
    parsed: &mut ParsedManifest,
    current: &mut Option<AndroidComponent>,
) {
    let attribute = |name: &str| {
        attributes
            .get(name)
            .or_else(|| attributes.get(&format!("android:{name}")))
            .cloned()
    };
    match tag {
        "manifest" => {
            parsed.identity.package = attribute("package");
            parsed.identity.version_name = attribute("versionName");
            parsed.identity.version_code = attribute("versionCode");
        }
        "uses-sdk" => {
            parsed.identity.min_sdk = attribute("minSdkVersion");
            parsed.identity.target_sdk = attribute("targetSdkVersion");
        }
        "uses-permission" | "uses-permission-sdk-23" => {
            if let Some(permission) = attribute("name") {
                parsed.permissions.push(permission);
            }
        }
        "application" => {
            parsed.application.debuggable = attribute("debuggable").and_then(parse_bool);
            parsed.application.allow_backup = attribute("allowBackup").and_then(parse_bool);
            parsed.application.uses_cleartext_traffic =
                attribute("usesCleartextTraffic").and_then(parse_bool);
        }
        tag if is_component_tag(tag) => {
            *current = Some(AndroidComponent {
                kind: tag.into(),
                name: attribute("name").unwrap_or_default(),
                exported: attribute("exported").and_then(parse_bool),
                permission: attribute("permission"),
                actions: Vec::new(),
                categories: Vec::new(),
                deep_links: Vec::new(),
            });
        }
        "action" => {
            if let (Some(component), Some(name)) = (current.as_mut(), attribute("name")) {
                component.actions.push(name);
            }
        }
        "category" => {
            if let (Some(component), Some(name)) = (current.as_mut(), attribute("name")) {
                component.categories.push(name);
            }
        }
        "data" => {
            if let Some(component) = current.as_mut() {
                let scheme = attribute("scheme").unwrap_or_default();
                let host = attribute("host").unwrap_or_default();
                let path = attribute("pathPrefix")
                    .or_else(|| attribute("path"))
                    .unwrap_or_default();
                if !scheme.is_empty() || !host.is_empty() || !path.is_empty() {
                    component
                        .deep_links
                        .push(format!("{scheme}://{host}{path}"));
                }
            }
        }
        _ => {}
    }
}

fn normalize_manifest(parsed: &mut ParsedManifest) {
    parsed.permissions.sort();
    parsed.permissions.dedup();
    for component in &mut parsed.components {
        for values in [
            &mut component.actions,
            &mut component.categories,
            &mut component.deep_links,
        ] {
            values.sort();
            values.dedup();
        }
    }
    parsed
        .components
        .sort_by(|left, right| left.kind.cmp(&right.kind).then(left.name.cmp(&right.name)));
}

fn parse_bool(value: String) -> Option<bool> {
    match value.as_str() {
        "true" | "1" => Some(true),
        "false" | "0" => Some(false),
        _ => None,
    }
}

fn is_component_tag(tag: &str) -> bool {
    matches!(
        tag,
        "activity" | "activity-alias" | "service" | "receiver" | "provider"
    )
}

fn parse_dex_header(path: PathBuf, bytes: &[u8]) -> Result<DexSummary> {
    if bytes.len() < MAX_DEX_HEADER_BYTES || !bytes.starts_with(b"dex\n") {
        return Err(ByteTrawlError::Malformed(format!(
            "{} has an invalid DEX header",
            path.display()
        )));
    }
    let value = |offset: usize| {
        u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ])
    };
    Ok(DexSummary {
        path,
        strings: value(56),
        types: value(64),
        prototypes: value(72),
        fields: value(80),
        methods: value(88),
        classes: value(96),
    })
}

fn apk_signing_block_present(path: &std::path::Path) -> Result<bool> {
    use std::io::{Read, Seek, SeekFrom};
    const WINDOW: u64 = 16 * 1024 * 1024;
    let mut file = std::fs::File::open(path).map_err(|source| ByteTrawlError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let length = file
        .metadata()
        .map_err(|source| ByteTrawlError::Io {
            path: path.to_path_buf(),
            source,
        })?
        .len();
    let start = length.saturating_sub(WINDOW);
    file.seek(SeekFrom::Start(start))
        .map_err(|source| ByteTrawlError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|source| ByteTrawlError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(bytes
        .windows(b"APK Sig Block 42".len())
        .any(|window| window == b"APK Sig Block 42"))
}

fn evaluate_findings(report: &AndroidAuditReportV1) -> Vec<AndroidFinding> {
    let manifest = PathBuf::from("AndroidManifest.xml");
    let mut findings = Vec::new();
    let mut push = |rule: &str, severity, title: &str, description: String| {
        findings.push(AndroidFinding {
            rule_id: format!("android.apk.{rule}"),
            severity,
            title: title.into(),
            description,
            evidence_path: manifest.clone(),
        });
    };
    if report
        .identity
        .package
        .as_deref()
        .unwrap_or_default()
        .is_empty()
    {
        push(
            "missing-package",
            Severity::High,
            "Missing package name",
            "The manifest package attribute is absent or empty.".into(),
        );
    }
    if report.application.debuggable == Some(true) {
        push(
            "debuggable",
            Severity::High,
            "Debuggable release application",
            "android:debuggable is enabled.".into(),
        );
    }
    if report.application.allow_backup != Some(false) {
        push(
            "backup-enabled",
            Severity::Medium,
            "Application backup is not disabled",
            "Set android:allowBackup explicitly according to the release threat model.".into(),
        );
    }
    if report.application.uses_cleartext_traffic == Some(true) {
        push(
            "cleartext-traffic",
            Severity::High,
            "Cleartext traffic allowed",
            "android:usesCleartextTraffic is enabled.".into(),
        );
    }
    for component in &report.components {
        let inferred_exported = component.exported == Some(true)
            || (component.exported.is_none() && !component.actions.is_empty());
        if inferred_exported && component.permission.is_none() {
            push(
                "unprotected-exported-component",
                Severity::High,
                "Exported component has no permission",
                format!(
                    "{} {} is exported without an enforcing permission.",
                    component.kind, component.name
                ),
            );
        }
    }
    if report.signing_schemes.is_empty() {
        push(
            "signature-not-detected",
            Severity::Medium,
            "APK signature not detected",
            "No v1 signature entry or APK signing block was detected.".into(),
        );
    }
    findings.sort_by(|left, right| left.rule_id.cmp(&right.rule_id));
    findings
}

fn member_path(node: &ArtifactNode) -> Option<PathBuf> {
    match node.source.as_ref()? {
        ArtifactSource::ArchiveMember { member_path, .. } => Some(member_path.clone()),
        _ => None,
    }
}

fn find_member<'a>(node: &'a ArtifactNode, name: &str) -> Option<&'a ArtifactNode> {
    if member_path(node).is_some_and(|path| path == PathBuf::from(name)) {
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

    fn dex_header() -> Vec<u8> {
        let mut bytes = vec![0u8; MAX_DEX_HEADER_BYTES];
        bytes[..8].copy_from_slice(b"dex\n035\0");
        for (offset, value) in [
            (56, 11u32),
            (64, 12),
            (72, 13),
            (80, 14),
            (88, 15),
            (96, 16),
        ] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        bytes
    }

    fn push_u16(bytes: &mut Vec<u8>, value: u16) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u32(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn binary_manifest_fixture() -> Vec<u8> {
        let strings = [
            "manifest",
            "package",
            "app.xnu.binary",
            "versionName",
            "3.0",
            "uses-sdk",
            "targetSdkVersion",
            "35",
            "application",
            "debuggable",
            "true",
            "activity",
            "name",
            ".MainActivity",
            "exported",
            "action",
            "android.intent.action.VIEW",
        ];
        let mut encoded = Vec::new();
        let mut offsets = Vec::new();
        for value in strings {
            offsets.push(encoded.len() as u32);
            encoded.push(value.chars().count() as u8);
            encoded.push(value.len() as u8);
            encoded.extend_from_slice(value.as_bytes());
            encoded.push(0);
        }
        while encoded.len() % 4 != 0 {
            encoded.push(0);
        }
        let pool_size = 28 + offsets.len() * 4 + encoded.len();
        let mut pool = Vec::new();
        push_u16(&mut pool, 0x0001);
        push_u16(&mut pool, 28);
        push_u32(&mut pool, pool_size as u32);
        push_u32(&mut pool, offsets.len() as u32);
        push_u32(&mut pool, 0);
        push_u32(&mut pool, 0x100);
        push_u32(&mut pool, (28 + offsets.len() * 4) as u32);
        push_u32(&mut pool, 0);
        for offset in offsets {
            push_u32(&mut pool, offset);
        }
        pool.extend(encoded);

        fn start(name: u32, attributes: &[(u32, u32)]) -> Vec<u8> {
            let mut chunk = Vec::new();
            push_u16(&mut chunk, 0x0102);
            push_u16(&mut chunk, 16);
            push_u32(&mut chunk, (36 + attributes.len() * 20) as u32);
            push_u32(&mut chunk, 1);
            push_u32(&mut chunk, u32::MAX);
            push_u32(&mut chunk, u32::MAX);
            push_u32(&mut chunk, name);
            push_u16(&mut chunk, 20);
            push_u16(&mut chunk, 20);
            push_u16(&mut chunk, attributes.len() as u16);
            push_u16(&mut chunk, 0);
            push_u16(&mut chunk, 0);
            push_u16(&mut chunk, 0);
            for (key, value) in attributes {
                push_u32(&mut chunk, u32::MAX);
                push_u32(&mut chunk, *key);
                push_u32(&mut chunk, *value);
                push_u16(&mut chunk, 8);
                chunk.push(0);
                chunk.push(0x03);
                push_u32(&mut chunk, *value);
            }
            chunk
        }
        fn end(name: u32) -> Vec<u8> {
            let mut chunk = Vec::new();
            push_u16(&mut chunk, 0x0103);
            push_u16(&mut chunk, 16);
            push_u32(&mut chunk, 24);
            push_u32(&mut chunk, 1);
            push_u32(&mut chunk, u32::MAX);
            push_u32(&mut chunk, u32::MAX);
            push_u32(&mut chunk, name);
            chunk
        }
        let chunks = [
            start(0, &[(1, 2), (3, 4)]),
            start(5, &[(6, 7)]),
            end(5),
            start(8, &[(9, 10)]),
            start(11, &[(12, 13), (14, 10)]),
            start(15, &[(12, 16)]),
            end(15),
            end(11),
            end(8),
            end(0),
        ];
        let total = 8 + pool.len() + chunks.iter().map(Vec::len).sum::<usize>();
        let mut xml = Vec::new();
        push_u16(&mut xml, 0x0003);
        push_u16(&mut xml, 8);
        push_u32(&mut xml, total as u32);
        xml.extend(pool);
        for chunk in chunks {
            xml.extend(chunk);
        }
        xml
    }

    #[test]
    fn parses_binary_android_xml_manifest() {
        let parsed = parse_manifest(&binary_manifest_fixture()).expect("parse binary manifest");
        assert_eq!(parsed.identity.package.as_deref(), Some("app.xnu.binary"));
        assert_eq!(parsed.identity.version_name.as_deref(), Some("3.0"));
        assert_eq!(parsed.identity.target_sdk.as_deref(), Some("35"));
        assert_eq!(parsed.application.debuggable, Some(true));
        assert_eq!(parsed.components.len(), 1);
        assert_eq!(parsed.components[0].name, ".MainActivity");
        assert_eq!(parsed.components[0].actions, ["android.intent.action.VIEW"]);
    }

    #[test]
    fn audits_manifest_components_dex_resources_native_code_and_signing() {
        let temporary = tempfile::tempdir().expect("create APK fixture directory");
        let apk = temporary.path().join("fixture.apk");
        let file = std::fs::File::create(&apk).expect("create APK fixture");
        let mut writer = zip::ZipWriter::new(file);
        let manifest = br#"<?xml version="1.0" encoding="utf-8"?>
        <manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="app.xnu.fixture" android:versionName="2.0" android:versionCode="42">
          <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="35"/>
          <uses-permission android:name="android.permission.CAMERA"/>
          <application android:debuggable="true" android:allowBackup="false" android:usesCleartextTraffic="true">
            <activity android:name=".MainActivity" android:exported="true">
              <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:scheme="https" android:host="xnu.app" android:pathPrefix="/open"/>
              </intent-filter>
            </activity>
          </application>
        </manifest>"#;
        for (path, bytes) in [
            ("AndroidManifest.xml", manifest.as_slice()),
            ("classes.dex", dex_header().as_slice()),
            ("resources.arsc", b"resources".as_slice()),
            ("lib/arm64-v8a/libfixture.so", b"elf".as_slice()),
            ("META-INF/FIXTURE.RSA", b"signature".as_slice()),
        ] {
            writer
                .start_file(path, zip::write::SimpleFileOptions::default())
                .expect("start APK member");
            writer.write_all(bytes).expect("write APK member");
        }
        writer.finish().expect("finish APK fixture");
        let cancellation = CancellationToken::default();
        let artifact = open_artifact(&apk, &cancellation).expect("open APK");
        assert_eq!(
            artifact
                .properties
                .get("Package Format")
                .map(String::as_str),
            Some("Android APK")
        );
        let report = audit_apk(&artifact, &cancellation).expect("audit APK");
        assert_eq!(report.identity.package.as_deref(), Some("app.xnu.fixture"));
        assert_eq!(report.identity.target_sdk.as_deref(), Some("35"));
        assert_eq!(report.permissions, ["android.permission.CAMERA"]);
        assert_eq!(report.components.len(), 1);
        assert_eq!(report.components[0].deep_links, ["https://xnu.app/open"]);
        assert_eq!(report.dex[0].methods, 15);
        assert_eq!(report.dex[0].classes, 16);
        assert_eq!(report.native_libraries.len(), 1);
        assert_eq!(report.signing_schemes, ["v1 (JAR)"]);
        for expected in [
            "android.apk.cleartext-traffic",
            "android.apk.debuggable",
            "android.apk.unprotected-exported-component",
        ] {
            assert!(
                report
                    .findings
                    .iter()
                    .any(|finding| finding.rule_id == expected),
                "missing finding {expected}"
            );
        }
    }
}
