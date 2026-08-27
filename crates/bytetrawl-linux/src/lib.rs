//! Static Debian package release inspection.

use bytetrawl_core::{ByteTrawlError, Result, Severity};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::{
    io::Read,
    path::{Path, PathBuf},
};

const MAX_MEMBER_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_CONTROL_BYTES: usize = 16 * 1024 * 1024;
const MAX_ENTRIES: usize = 500_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct DebianIdentity {
    pub package: Option<String>,
    pub version: Option<String>,
    pub architecture: Option<String>,
    pub maintainer: Option<String>,
    pub section: Option<String>,
    pub priority: Option<String>,
    pub description: Option<String>,
    pub depends: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebianFile {
    pub path: PathBuf,
    pub size: u64,
    pub mode: u32,
    pub is_directory: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LinuxFinding {
    pub rule_id: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub evidence_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebianReportV1 {
    pub schema_version: String,
    pub generator: String,
    pub source: PathBuf,
    pub identity: DebianIdentity,
    pub installed_bytes: u64,
    pub files: Vec<DebianFile>,
    pub top_files: Vec<DebianFile>,
    pub maintainer_scripts: Vec<String>,
    pub control_fields: IndexMap<String, String>,
    pub findings: Vec<LinuxFinding>,
}

pub fn is_deb(path: &Path) -> bool {
    read_ar_members(path, false)
        .ok()
        .is_some_and(|members| members.iter().any(|member| member.name == "debian-binary"))
}

pub fn audit_deb(path: &Path) -> Result<DebianReportV1> {
    let members = read_ar_members(path, true)?;
    if !members.iter().any(|member| member.name == "debian-binary") {
        return Err(ByteTrawlError::Malformed(
            "ar archive is not a Debian package".into(),
        ));
    }
    let control_member = members
        .iter()
        .find(|member| member.name.starts_with("control.tar"))
        .ok_or_else(|| ByteTrawlError::Malformed("Debian control archive is missing".into()))?;
    let data_member = members
        .iter()
        .find(|member| member.name.starts_with("data.tar"))
        .ok_or_else(|| ByteTrawlError::Malformed("Debian data archive is missing".into()))?;
    let control_entries = read_tar_entries(&control_member.name, &control_member.data, true)?;
    let data_entries = read_tar_entries(&data_member.name, &data_member.data, false)?;
    let control_text = control_entries
        .iter()
        .find(|entry| entry.path == Path::new("control") || entry.path == Path::new("./control"))
        .and_then(|entry| entry.contents.as_deref())
        .ok_or_else(|| ByteTrawlError::Malformed("Debian control file is missing".into()))?;
    let control_text = std::str::from_utf8(control_text)
        .map_err(|error| ByteTrawlError::Malformed(format!("Debian control UTF-8: {error}")))?;
    let control_fields = parse_control(control_text);
    let depends = control_fields
        .get("Depends")
        .map(|value| {
            value
                .split(',')
                .map(|dependency| dependency.trim().to_owned())
                .filter(|value| !value.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let identity = DebianIdentity {
        package: control_fields.get("Package").cloned(),
        version: control_fields.get("Version").cloned(),
        architecture: control_fields.get("Architecture").cloned(),
        maintainer: control_fields.get("Maintainer").cloned(),
        section: control_fields.get("Section").cloned(),
        priority: control_fields.get("Priority").cloned(),
        description: control_fields.get("Description").cloned(),
        depends,
    };
    let maintainer_scripts = control_entries
        .iter()
        .filter_map(|entry| {
            let name = entry.path.file_name()?.to_str()?;
            matches!(name, "preinst" | "postinst" | "prerm" | "postrm" | "config")
                .then(|| name.to_owned())
        })
        .collect::<Vec<_>>();
    let mut files = data_entries
        .into_iter()
        .map(|entry| DebianFile {
            path: entry.path,
            size: entry.size,
            mode: entry.mode,
            is_directory: entry.is_directory,
        })
        .collect::<Vec<_>>();
    files.sort_by(|a, b| a.path.cmp(&b.path));
    let installed_bytes = files
        .iter()
        .filter(|file| !file.is_directory)
        .map(|file| file.size)
        .sum();
    let mut top_files = files
        .iter()
        .filter(|file| !file.is_directory)
        .cloned()
        .collect::<Vec<_>>();
    top_files.sort_by(|a, b| b.size.cmp(&a.size).then(a.path.cmp(&b.path)));
    top_files.truncate(50);
    let mut report = DebianReportV1 {
        schema_version: "1.0".into(),
        generator: format!("ByteTrawl/{}", env!("CARGO_PKG_VERSION")),
        source: path.to_path_buf(),
        identity,
        installed_bytes,
        files,
        top_files,
        maintainer_scripts,
        control_fields,
        findings: Vec::new(),
    };
    report.findings = evaluate_findings(&report);
    Ok(report)
}

struct ArMember {
    name: String,
    data: Vec<u8>,
}

fn read_ar_members(path: &Path, retain_data: bool) -> Result<Vec<ArMember>> {
    let bytes = std::fs::read(path).map_err(|source| ByteTrawlError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !bytes.starts_with(b"!<arch>\n") {
        return Err(ByteTrawlError::Malformed("invalid ar header".into()));
    }
    let mut offset = 8usize;
    let mut members = Vec::new();
    while offset < bytes.len() {
        if members.len() >= 100_000 {
            return Err(ByteTrawlError::Limit(
                "ar member count exceeds 100000".into(),
            ));
        }
        let header = bytes
            .get(offset..offset + 60)
            .ok_or_else(|| ByteTrawlError::Malformed("truncated ar member header".into()))?;
        if &header[58..60] != b"`\n" {
            return Err(ByteTrawlError::Malformed(
                "invalid ar member trailer".into(),
            ));
        }
        let raw_name = std::str::from_utf8(&header[..16])
            .map_err(|error| ByteTrawlError::Malformed(error.to_string()))?
            .trim();
        let size = std::str::from_utf8(&header[48..58])
            .ok()
            .and_then(|value| value.trim().parse::<usize>().ok())
            .ok_or_else(|| ByteTrawlError::Malformed("invalid ar member size".into()))?;
        if size as u64 > MAX_MEMBER_BYTES {
            return Err(ByteTrawlError::Limit("ar member exceeds 2 GiB".into()));
        }
        let mut data_start = offset + 60;
        let mut data_size = size;
        let name = if let Some(length) = raw_name
            .strip_prefix("#1/")
            .and_then(|value| value.parse::<usize>().ok())
        {
            let name_bytes = bytes
                .get(data_start..data_start + length)
                .ok_or_else(|| ByteTrawlError::Malformed("truncated BSD ar name".into()))?;
            data_start += length;
            data_size = data_size.saturating_sub(length);
            String::from_utf8_lossy(name_bytes).into_owned()
        } else {
            raw_name.trim_end_matches('/').to_owned()
        };
        let data = bytes
            .get(data_start..data_start + data_size)
            .ok_or_else(|| ByteTrawlError::Malformed("truncated ar member".into()))?;
        members.push(ArMember {
            name,
            data: if retain_data {
                data.to_vec()
            } else {
                Vec::new()
            },
        });
        offset = offset + 60 + size + (size % 2);
    }
    Ok(members)
}

struct TarEntry {
    path: PathBuf,
    size: u64,
    mode: u32,
    is_directory: bool,
    contents: Option<Vec<u8>>,
}

fn read_tar_entries(name: &str, bytes: &[u8], retain_small_files: bool) -> Result<Vec<TarEntry>> {
    let reader: Box<dyn Read> = if name.ends_with(".gz") {
        Box::new(flate2::read::GzDecoder::new(bytes))
    } else if name.ends_with(".xz") {
        Box::new(xz2::read::XzDecoder::new(bytes))
    } else if name.ends_with(".zst") || name.ends_with(".zstd") {
        Box::new(
            zstd::stream::read::Decoder::new(bytes)
                .map_err(|error| ByteTrawlError::Malformed(format!("zstd: {error}")))?,
        )
    } else {
        Box::new(bytes)
    };
    let mut archive = tar::Archive::new(reader);
    let mut results = Vec::new();
    for entry in archive
        .entries()
        .map_err(|error| ByteTrawlError::Malformed(format!("tar: {error}")))?
    {
        if results.len() >= MAX_ENTRIES {
            return Err(ByteTrawlError::Limit(
                "tar entry count exceeds limit".into(),
            ));
        }
        let mut entry =
            entry.map_err(|error| ByteTrawlError::Malformed(format!("tar entry: {error}")))?;
        let path = entry
            .path()
            .map_err(|error| ByteTrawlError::Malformed(format!("tar path: {error}")))?
            .into_owned();
        if path.is_absolute()
            || path
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(ByteTrawlError::Malformed(format!(
                "unsafe tar path {}",
                path.display()
            )));
        }
        let size = entry.size();
        let mode = entry.header().mode().unwrap_or(0);
        let is_directory = entry.header().entry_type().is_dir();
        let contents = if retain_small_files && !is_directory && size <= MAX_CONTROL_BYTES as u64 {
            let mut contents = Vec::with_capacity(size as usize);
            entry
                .read_to_end(&mut contents)
                .map_err(|error| ByteTrawlError::Malformed(format!("tar content: {error}")))?;
            Some(contents)
        } else {
            None
        };
        results.push(TarEntry {
            path,
            size,
            mode,
            is_directory,
            contents,
        });
    }
    Ok(results)
}

fn parse_control(text: &str) -> IndexMap<String, String> {
    let mut fields = IndexMap::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(key) = current.as_ref() {
                fields.entry(key.clone()).and_modify(|value: &mut String| {
                    value.push('\n');
                    value.push_str(line.trim());
                });
            }
        } else if let Some((key, value)) = line.split_once(':') {
            let key = key.trim().to_owned();
            fields.insert(key.clone(), value.trim().to_owned());
            current = Some(key);
        } else if line.is_empty() {
            break;
        }
    }
    fields
}

fn evaluate_findings(report: &DebianReportV1) -> Vec<LinuxFinding> {
    let mut findings = Vec::new();
    let mut push =
        |rule: &str, severity, title: &str, description: String, evidence_path: PathBuf| {
            findings.push(LinuxFinding {
                rule_id: format!("linux.deb.{rule}"),
                severity,
                title: title.into(),
                description,
                evidence_path,
            })
        };
    if report
        .identity
        .package
        .as_deref()
        .unwrap_or_default()
        .is_empty()
        || report
            .identity
            .version
            .as_deref()
            .unwrap_or_default()
            .is_empty()
        || report
            .identity
            .architecture
            .as_deref()
            .unwrap_or_default()
            .is_empty()
    {
        push(
            "incomplete-identity",
            Severity::High,
            "Incomplete Debian package identity",
            "Package, Version, and Architecture are required.".into(),
            PathBuf::from("control"),
        );
    }
    if report
        .identity
        .maintainer
        .as_deref()
        .unwrap_or_default()
        .is_empty()
    {
        push(
            "missing-maintainer",
            Severity::Medium,
            "Maintainer is missing",
            "The Debian control file has no Maintainer field.".into(),
            PathBuf::from("control"),
        );
    }
    for script in &report.maintainer_scripts {
        push(
            "maintainer-script",
            Severity::Info,
            "Maintainer script present",
            format!("Review the {script} installation script."),
            PathBuf::from(script),
        );
    }
    for file in &report.files {
        if !file.is_directory && file.mode & 0o6000 != 0 {
            push(
                "privileged-file-mode",
                Severity::High,
                "Setuid or setgid file",
                format!("{} has mode {:o}.", file.path.display(), file.mode),
                file.path.clone(),
            );
        }
    }
    findings.sort_by(|a, b| {
        a.rule_id
            .cmp(&b.rule_id)
            .then(a.evidence_path.cmp(&b.evidence_path))
    });
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};

    fn tar_gz(entries: &[(&str, &[u8], u32)]) -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = tar::Builder::new(encoder);
        for (path, bytes, mode) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(*mode);
            header.set_cksum();
            builder
                .append_data(&mut header, path, *bytes)
                .expect("append tar entry");
        }
        builder
            .into_inner()
            .expect("finish tar")
            .finish()
            .expect("finish gzip")
    }

    fn write_ar_member(output: &mut Vec<u8>, name: &str, bytes: &[u8]) {
        let header = format!(
            "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
            format!("{name}/"),
            0,
            0,
            0,
            0o100644,
            bytes.len()
        );
        assert_eq!(header.len(), 60);
        output.extend_from_slice(header.as_bytes());
        output.extend_from_slice(bytes);
        if !bytes.len().is_multiple_of(2) {
            output.push(b'\n');
        }
    }

    #[test]
    fn audits_debian_control_payload_sizes_scripts_and_modes() {
        let control = b"Package: fixture\nVersion: 1.2.3\nArchitecture: amd64\nMaintainer: XNU <xnu@example.com>\nDepends: libc6 (>= 2.31), zlib1g\nDescription: Fixture package\n";
        let control_tar = tar_gz(&[
            ("./control", control, 0o644),
            ("./postinst", b"#!/bin/sh\n", 0o755),
        ]);
        let data_tar = tar_gz(&[
            ("./usr/bin/fixture", b"ELF fixture", 0o4755),
            ("./usr/share/doc/fixture/readme", b"readme", 0o644),
        ]);
        let mut deb = b"!<arch>\n".to_vec();
        write_ar_member(&mut deb, "debian-binary", b"2.0\n");
        write_ar_member(&mut deb, "control.tar.gz", &control_tar);
        write_ar_member(&mut deb, "data.tar.gz", &data_tar);
        let temporary = tempfile::tempdir().expect("create DEB fixture directory");
        let path = temporary.path().join("fixture.deb");
        std::fs::write(&path, deb).expect("write DEB fixture");
        assert!(is_deb(&path));
        let report = audit_deb(&path).expect("audit DEB");
        assert_eq!(report.identity.package.as_deref(), Some("fixture"));
        assert_eq!(report.identity.depends.len(), 2);
        assert_eq!(report.maintainer_scripts, ["postinst"]);
        assert_eq!(report.installed_bytes, 17);
        assert_eq!(report.top_files[0].path, PathBuf::from("usr/bin/fixture"));
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.rule_id == "linux.deb.maintainer-script")
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.rule_id == "linux.deb.privileged-file-mode")
        );
    }
}
