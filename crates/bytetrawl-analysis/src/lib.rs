use bytetrawl_core::*;
use bytetrawl_format::{analyze_binary, detect_format};
use bytetrawl_signature::{
    HostSignatureProvider, SignatureProvider, inspect_host_signature_with_cancel,
};
use chrono::{DateTime, Utc};
use md5::Md5;
use memmap2::MmapOptions;
use parking_lot::RwLock;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::SystemTime,
};
use walkdir::WalkDir;

const MAX_FILES: usize = 200_000;
const MAX_DEPTH: usize = 64;
const HEADER_BYTES: usize = 64 * 1024;
const MAX_STRUCTURED_METADATA_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ARCHIVE_MEMBER_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);
impl CancellationToken {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }
    pub fn check(&self) -> Result<()> {
        if self.0.load(Ordering::Relaxed) {
            Err(ByteTrawlError::Cancelled)
        } else {
            Ok(())
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

pub struct ArtifactReader {
    source: ArtifactSource,
    length: u64,
}

impl ArtifactReader {
    pub fn open(node: &ArtifactNode) -> Result<Self> {
        let source = node
            .source
            .clone()
            .unwrap_or_else(|| ArtifactSource::Filesystem {
                path: node.path.clone(),
            });
        let length = match &source {
            ArtifactSource::Filesystem { path } => std::fs::metadata(path)
                .map_err(|source| ByteTrawlError::Io {
                    path: path.clone(),
                    source,
                })?
                .len(),
            ArtifactSource::ArchiveMember {
                uncompressed_size, ..
            } => *uncompressed_size,
        };
        Ok(Self { source, length })
    }

    pub fn len(&self) -> u64 {
        self.length
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    pub fn read_prefix(&self, limit: usize) -> Result<Vec<u8>> {
        self.read_range(0, limit)
    }

    pub fn read_all(&self, maximum_bytes: u64) -> Result<Vec<u8>> {
        if self.length > maximum_bytes {
            return Err(ByteTrawlError::Limit(format!(
                "artifact source exceeds {maximum_bytes} bytes"
            )));
        }
        self.read_range(0, self.length as usize)
    }

    pub fn read_range(&self, offset: u64, length: usize) -> Result<Vec<u8>> {
        let available = self.length.saturating_sub(offset);
        let requested = length.min(available.min(usize::MAX as u64) as usize);
        match &self.source {
            ArtifactSource::Filesystem { path } => {
                let mut file = File::open(path).map_err(|source| ByteTrawlError::Io {
                    path: path.clone(),
                    source,
                })?;
                file.seek(SeekFrom::Start(offset))
                    .map_err(|source| ByteTrawlError::Io {
                        path: path.clone(),
                        source,
                    })?;
                let mut bytes = vec![0; requested];
                file.read_exact(&mut bytes)
                    .map_err(|source| ByteTrawlError::Io {
                        path: path.clone(),
                        source,
                    })?;
                Ok(bytes)
            }
            ArtifactSource::ArchiveMember {
                container,
                member_path,
                entry_index,
                is_directory,
                ..
            } => {
                if *is_directory {
                    return Err(ByteTrawlError::Malformed(
                        "cannot read bytes from an archive directory".into(),
                    ));
                }
                let file = File::open(container).map_err(|source| ByteTrawlError::Io {
                    path: container.clone(),
                    source,
                })?;
                let mut archive = zip::ZipArchive::new(file)
                    .map_err(|error| ByteTrawlError::Malformed(format!("ZIP: {error}")))?;
                let mut entry = archive.by_index(*entry_index).map_err(|error| {
                    ByteTrawlError::Malformed(format!("ZIP entry {entry_index}: {error}"))
                })?;
                let enclosed = entry.enclosed_name().ok_or_else(|| {
                    ByteTrawlError::Malformed("archive member path is unsafe".into())
                })?;
                if enclosed != *member_path {
                    return Err(ByteTrawlError::Malformed(
                        "archive member index no longer matches its path".into(),
                    ));
                }
                if offset > 0 {
                    std::io::copy(&mut entry.by_ref().take(offset), &mut std::io::sink()).map_err(
                        |source| ByteTrawlError::Io {
                            path: container.clone(),
                            source,
                        },
                    )?;
                }
                let mut bytes = Vec::with_capacity(requested);
                entry
                    .take(requested as u64)
                    .read_to_end(&mut bytes)
                    .map_err(|source| ByteTrawlError::Io {
                        path: container.clone(),
                        source,
                    })?;
                if bytes.len() != requested {
                    return Err(ByteTrawlError::Malformed(format!(
                        "archive member ended after {} of {requested} requested bytes",
                        bytes.len()
                    )));
                }
                Ok(bytes)
            }
        }
    }
}

pub fn open_artifact(path: &Path, cancel: &CancellationToken) -> Result<ArtifactNode> {
    let metadata = std::fs::symlink_metadata(path).map_err(|source| ByteTrawlError::Io {
        path: path.into(),
        source,
    })?;
    if metadata.is_dir() {
        discover_directory(path, cancel)
    } else {
        let mut root = build_file_node(path)?;
        if root.format == Some(FileFormat::Zip) {
            populate_zip_members(&mut root, cancel)?;
        }
        Ok(root)
    }
}

fn populate_zip_members(root: &mut ArtifactNode, cancel: &CancellationToken) -> Result<()> {
    let file = File::open(&root.path).map_err(|source| ByteTrawlError::Io {
        path: root.path.clone(),
        source,
    })?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|error| ByteTrawlError::Malformed(format!("ZIP: {error}")))?;
    if archive.len() > MAX_FILES {
        return Err(ByteTrawlError::Limit(format!(
            "ZIP contains more than {MAX_FILES} entries"
        )));
    }

    let mut ipa_info_plist_found = false;
    for entry_index in 0..archive.len() {
        cancel.check()?;
        let entry = archive.by_index(entry_index).map_err(|error| {
            ByteTrawlError::Malformed(format!("ZIP entry {entry_index}: {error}"))
        })?;
        let Some(member_path) = entry.enclosed_name() else {
            continue;
        };
        if member_path.components().count().saturating_sub(1) > MAX_DEPTH {
            return Err(ByteTrawlError::Limit(format!(
                "archive member depth exceeds {MAX_DEPTH}"
            )));
        }
        if entry.size() > MAX_ARCHIVE_MEMBER_BYTES {
            return Err(ByteTrawlError::Limit(format!(
                "archive member {} exceeds {MAX_ARCHIVE_MEMBER_BYTES} bytes",
                member_path.display()
            )));
        }
        let source = ArtifactSource::ArchiveMember {
            container: root.path.clone(),
            member_path: member_path.clone(),
            entry_index,
            compressed_size: entry.compressed_size(),
            uncompressed_size: entry.size(),
            crc32: entry.crc32(),
            is_directory: entry.is_dir(),
        };
        if is_ipa_info_plist(&member_path) {
            ipa_info_plist_found = true;
        }
        insert_archive_member(root, &member_path, source)?;
    }
    if ipa_info_plist_found {
        root.kind = ArtifactKind::Package;
        root.properties
            .insert("Package Format".into(), "Apple iOS IPA".into());
        root.properties.insert(
            "Inspection Mode".into(),
            "Virtual archive members; ByteTrawl did not extract this IPA.".into(),
        );
    }
    root.properties
        .insert("Archive Members".into(), archive.len().to_string());
    Ok(())
}

fn is_ipa_info_plist(path: &Path) -> bool {
    let parts = path
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>();
    parts.len() == 3
        && parts[0] == "Payload"
        && parts[1].to_ascii_lowercase().ends_with(".app")
        && parts[2] == "Info.plist"
}

fn insert_archive_member(
    root: &mut ArtifactNode,
    member_path: &Path,
    source: ArtifactSource,
) -> Result<()> {
    let components = member_path.components().collect::<Vec<_>>();
    if components.is_empty() {
        return Ok(());
    }
    let container_path = root.path.clone();
    let mut current = root;
    for (component_index, component) in components.iter().enumerate() {
        let name = component.as_os_str().to_string_lossy().into_owned();
        let is_last = component_index + 1 == components.len();
        if let Some(existing_index) = current.children.iter().position(|node| node.name == name) {
            current = &mut current.children[existing_index];
            if is_last {
                current.source = Some(source.clone());
                apply_archive_source_metadata(current, &source);
            }
            continue;
        }
        let partial_path =
            components[..=component_index]
                .iter()
                .fold(PathBuf::new(), |mut path, component| {
                    path.push(component.as_os_str());
                    path
                });
        let display_path = PathBuf::from(format!(
            "{}!/{}",
            container_path.display(),
            partial_path.display()
        ));
        let mut node = if is_last {
            let kind = archive_member_kind(&name, source.is_dir());
            let mut node = ArtifactNode::new(name, display_path, kind);
            node.source = Some(source.clone());
            apply_archive_source_metadata(&mut node, &source);
            node
        } else {
            let kind = archive_member_kind(&name, true);
            let mut node = ArtifactNode::new(name, display_path, kind);
            node.source = Some(ArtifactSource::ArchiveMember {
                container: container_path.clone(),
                member_path: partial_path,
                entry_index: 0,
                compressed_size: 0,
                uncompressed_size: 0,
                crc32: 0,
                is_directory: true,
            });
            node
        };
        if node.is_dir() {
            node.properties
                .insert("Archive Directory".into(), "true".into());
        }
        current.children.push(node);
        let inserted_index = current.children.len().saturating_sub(1);
        current = &mut current.children[inserted_index];
    }
    Ok(())
}

fn apply_archive_source_metadata(node: &mut ArtifactNode, source: &ArtifactSource) {
    if let ArtifactSource::ArchiveMember {
        member_path,
        compressed_size,
        uncompressed_size,
        crc32,
        ..
    } = source
    {
        node.size = *uncompressed_size;
        node.properties
            .insert("Archive Member".into(), member_path.display().to_string());
        node.properties
            .insert("Compressed Size".into(), compressed_size.to_string());
        node.properties
            .insert("Uncompressed Size".into(), uncompressed_size.to_string());
        node.properties
            .insert("CRC32".into(), format!("{crc32:08x}"));
    }
}

fn archive_member_kind(name: &str, is_directory: bool) -> ArtifactKind {
    if is_directory {
        let extension = Path::new(name)
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        return match extension.as_str() {
            "app" => ArtifactKind::Application,
            "framework" => ArtifactKind::Framework,
            "appex" | "plugin" => ArtifactKind::Plugin,
            "bundle" => ArtifactKind::Bundle,
            _ => ArtifactKind::Directory,
        };
    }
    let extension = Path::new(name)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    match extension.as_str() {
        "plist" | "json" | "xml" | "xcprivacy" | "mobileprovision" => ArtifactKind::Metadata,
        "dylib" | "so" => ArtifactKind::DynamicLibrary,
        "a" | "lib" => ArtifactKind::StaticLibrary,
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "txt" | "strings" => ArtifactKind::Resource,
        _ => ArtifactKind::Unknown,
    }
}

fn discover_directory(path: &Path, cancel: &CancellationToken) -> Result<ArtifactNode> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("Artifact");
    let root_kind = classify_directory(path);
    let mut root = ArtifactNode::new(name, path.to_path_buf(), root_kind);
    let mut count = 0usize;
    for entry in WalkDir::new(path)
        .min_depth(1)
        .max_depth(MAX_DEPTH)
        .follow_links(false)
        .sort_by_file_name()
    {
        cancel.check()?;
        let entry = entry.map_err(|e| ByteTrawlError::Malformed(e.to_string()))?;
        count += 1;
        if count > MAX_FILES {
            return Err(ByteTrawlError::Limit(format!(
                "artifact contains more than {MAX_FILES} entries"
            )));
        }
        if entry.file_type().is_symlink() {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(path)
            .map_err(|e| ByteTrawlError::Malformed(e.to_string()))?;
        insert_path(&mut root, relative, entry.path())?;
    }
    classify_dependencies(&mut root);
    if root.kind == ArtifactKind::Directory
        && root
            .files()
            .any(|node| node.kind == ArtifactKind::Executable)
    {
        root.kind = ArtifactKind::Application;
        root.properties.insert(
            "Application inference".into(),
            "Directory contains one or more executable artifacts".into(),
        );
    }
    logicalize_artifact_tree(&mut root);
    Ok(root)
}

fn logicalize_artifact_tree(root: &mut ArtifactNode) {
    const GROUPS: &[(&str, ArtifactKind)] = &[
        ("Executables", ArtifactKind::Executable),
        ("Frameworks", ArtifactKind::Framework),
        ("Dynamic Libraries", ArtifactKind::DynamicLibrary),
        ("Static Libraries", ArtifactKind::StaticLibrary),
        ("Plugins", ArtifactKind::Plugin),
        ("Resources", ArtifactKind::Resource),
        ("Metadata", ArtifactKind::Metadata),
        ("Archives", ArtifactKind::Archive),
        ("Packages", ArtifactKind::Package),
        ("Disk Images", ArtifactKind::DiskImage),
        ("Other Files", ArtifactKind::Unknown),
    ];

    fn collect(node: &ArtifactNode, buckets: &mut HashMap<ArtifactKind, Vec<ArtifactNode>>) {
        if node.is_dir() && matches!(node.kind, ArtifactKind::Framework | ArtifactKind::Plugin) {
            buckets.entry(node.kind).or_default().push(node.clone());
            return;
        }
        if node.is_file() {
            buckets.entry(node.kind).or_default().push(node.clone());
            return;
        }
        for child in &node.children {
            collect(child, buckets);
        }
    }

    let mut buckets = HashMap::<ArtifactKind, Vec<ArtifactNode>>::new();
    for child in &root.children {
        collect(child, &mut buckets);
    }
    let mut logical = Vec::new();
    for (label, kind) in GROUPS {
        let Some(mut children) = buckets.remove(kind) else {
            continue;
        };
        children.sort_by(|left, right| left.name.cmp(&right.name).then(left.path.cmp(&right.path)));
        let mut group = ArtifactNode::new(*label, root.path.clone(), ArtifactKind::Group);
        group.size = children.iter().map(|node| node.size).sum();
        group
            .properties
            .insert("Logical Group".into(), (*label).into());
        group.children = children;
        logical.push(group);
    }
    // Future ArtifactKind variants remain visible instead of being silently lost.
    for (_, mut children) in buckets {
        logical.append(&mut children);
    }
    root.children = logical;
}

fn insert_path(root: &mut ArtifactNode, relative: &Path, absolute: &Path) -> Result<()> {
    let mut current = root;
    let parts: Vec<_> = relative.components().collect();
    for (i, part) in parts.iter().enumerate() {
        let name = part.as_os_str().to_string_lossy().to_string();
        let is_last = i + 1 == parts.len();
        if let Some(index) = current.children.iter().position(|n| n.name == name) {
            current = &mut current.children[index];
            continue;
        }
        let target = if is_last {
            absolute.to_path_buf()
        } else {
            current.path.join(&name)
        };
        let node = if is_last && target.is_file() {
            build_file_node(&target)?
        } else {
            let kind = classify_directory(&target);
            ArtifactNode::new(name.clone(), target, kind)
        };
        current.children.push(node);
        let index = current.children.len() - 1;
        current = &mut current.children[index];
    }
    Ok(())
}

fn build_file_node(path: &Path) -> Result<ArtifactNode> {
    let meta = std::fs::metadata(path).map_err(|source| ByteTrawlError::Io {
        path: path.into(),
        source,
    })?;
    let mut file = File::open(path).map_err(|source| ByteTrawlError::Io {
        path: path.into(),
        source,
    })?;
    let mut header = vec![0; HEADER_BYTES.min(meta.len() as usize)];
    file.read_exact(&mut header)
        .map_err(|source| ByteTrawlError::Io {
            path: path.into(),
            source,
        })?;
    let mut format = detect_format(&header);
    if matches!(format, FileFormat::UnknownBinary)
        && meta.len() >= udif::format::KOLY_SIZE as u64
        && udif::check_dmg(path)
    {
        format = FileFormat::DiskImage;
    }
    let kind = classify_file(path, format);
    let mut node = ArtifactNode::new(
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("<non-utf8>"),
        path.into(),
        kind,
    );
    node.format = Some(format);
    node.size = meta.len();
    node.modified = meta.modified().ok().map(DateTime::<Utc>::from);
    Ok(node)
}

fn classify_directory(path: &Path) -> ArtifactKind {
    let extension = path
        .extension()
        .and_then(|x| x.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let contents = path.join("Contents");
    let has_bundle_metadata = contents.join("Info.plist").is_file()
        || path.join("Resources/Info.plist").is_file()
        || path.join("Info.plist").is_file();
    let has_macos_executables = contents.join("MacOS").is_dir();
    let framework_binary = path
        .file_stem()
        .is_some_and(|name| path.join(name).is_file());
    let has_framework_layout = path.join("Versions").is_dir()
        || path.join("Headers").is_dir()
        || path.join("Modules").is_dir()
        || framework_binary;

    match extension.as_str() {
        "app" if has_bundle_metadata && has_macos_executables => ArtifactKind::Application,
        "framework" if has_bundle_metadata || has_framework_layout => ArtifactKind::Framework,
        "plugin" | "appex" if has_bundle_metadata => ArtifactKind::Plugin,
        "bundle" if has_bundle_metadata => ArtifactKind::Bundle,
        _ if has_bundle_metadata && has_macos_executables => ArtifactKind::Application,
        _ => ArtifactKind::Directory,
    }
}
fn classify_file(path: &Path, format: FileFormat) -> ArtifactKind {
    let ext = path
        .extension()
        .and_then(|x| x.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match format {
        FileFormat::Pe => {
            if matches!(ext.as_str(), "dll" | "sys") {
                ArtifactKind::DynamicLibrary
            } else {
                ArtifactKind::Executable
            }
        }
        FileFormat::MachO | FileFormat::FatMachO => {
            if matches!(ext.as_str(), "dylib" | "so") {
                ArtifactKind::DynamicLibrary
            } else {
                ArtifactKind::Executable
            }
        }
        FileFormat::Elf => {
            if ext == "so"
                || path
                    .file_name()
                    .and_then(|x| x.to_str())
                    .is_some_and(|x| x.contains(".so."))
            {
                ArtifactKind::DynamicLibrary
            } else {
                ArtifactKind::Executable
            }
        }
        FileFormat::Archive => {
            if matches!(ext.as_str(), "a" | "lib") || format_is_ar(path) {
                ArtifactKind::StaticLibrary
            } else if matches!(ext.as_str(), "pkg" | "mpkg") {
                ArtifactKind::Package
            } else {
                ArtifactKind::Archive
            }
        }
        FileFormat::Zip => {
            if matches!(ext.as_str(), "ipa" | "apk" | "xapk" | "appx" | "msix") {
                ArtifactKind::Package
            } else {
                ArtifactKind::Archive
            }
        }
        FileFormat::Json | FileFormat::Xml | FileFormat::Plist => ArtifactKind::Metadata,
        FileFormat::Image | FileFormat::Text => ArtifactKind::Resource,
        FileFormat::DiskImage => ArtifactKind::DiskImage,
        _ if matches!(ext.as_str(), "pkg" | "mpkg" | "msi" | "deb" | "rpm") => {
            ArtifactKind::Package
        }
        _ => ArtifactKind::Unknown,
    }
}

fn format_is_ar(path: &Path) -> bool {
    read_prefix(path, 8).is_ok_and(|bytes| bytes == b"!<arch>\n")
}

fn classify_dependencies(root: &mut ArtifactNode) {
    fn visit(node: &mut ArtifactNode, bundled: &HashSet<String>) {
        if let Ok(Some(mut a)) = analyze_node(node) {
            node.kind = match a.headers.get("Binary kind").map(String::as_str) {
                Some("Dynamic library") => ArtifactKind::DynamicLibrary,
                Some("Plugin bundle") => ArtifactKind::Plugin,
                Some("Executable" | "Executable (position independent)") => {
                    ArtifactKind::Executable
                }
                _ => node.kind,
            };
            for dep in &mut a.dependencies {
                dep.status = if bundled.contains(
                    dep.name
                        .rsplit('/')
                        .next()
                        .unwrap_or(&dep.name)
                        .to_ascii_lowercase()
                        .as_str(),
                ) {
                    DependencyStatus::Bundled
                } else if is_system_dependency(&dep.name) {
                    DependencyStatus::System
                } else {
                    DependencyStatus::Unknown
                };
            }
            node.properties
                .insert("Dependencies".into(), a.dependencies.len().to_string());
        }
        for child in &mut node.children {
            visit(child, bundled);
        }
    }
    let names: HashSet<String> = root.files().map(|n| n.name.to_ascii_lowercase()).collect();
    visit(root, &names);
}
fn is_system_dependency(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.starts_with("/usr/lib/")
        || n.starts_with("/system/library/")
        || n.starts_with("api-ms-win-")
        || n.starts_with("ext-ms-win-")
        || n.starts_with("linux-vdso")
        || n.starts_with("ld-linux")
        || n.starts_with("ld-musl")
        || matches!(
            n.as_str(),
            "kernel32.dll"
                | "user32.dll"
                | "ntdll.dll"
                | "advapi32.dll"
                | "bcrypt.dll"
                | "combase.dll"
                | "crypt32.dll"
                | "gdi32.dll"
                | "ole32.dll"
                | "oleaut32.dll"
                | "rpcrt4.dll"
                | "secur32.dll"
                | "shell32.dll"
                | "shlwapi.dll"
                | "ucrtbase.dll"
                | "ws2_32.dll"
                | "libc.so.6"
                | "libm.so.6"
                | "libdl.so.2"
                | "libpthread.so.0"
                | "librt.so.1"
        )
}

pub fn resolve_dependencies(analysis: &mut BinaryAnalysis, artifact: &ArtifactNode) {
    for slice in &mut analysis.slice_analyses {
        resolve_dependencies(slice, artifact);
    }
    analysis.findings.retain(|finding| {
        !(finding.category == FindingCategory::Dependency
            && finding.title.starts_with("Missing dependency:"))
    });
    let bundled: HashMap<String, PathBuf> = artifact
        .files()
        .map(|node| (node.name.to_ascii_lowercase(), node.path.clone()))
        .collect();
    for dependency in &mut analysis.dependencies {
        let basename = dependency
            .name
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(&dependency.name)
            .to_ascii_lowercase();
        dependency.status = if let Some(path) = bundled.get(&basename) {
            dependency.path = Some(path.clone());
            DependencyStatus::Bundled
        } else if is_system_dependency(&dependency.name) {
            if dependency.name.starts_with('/') {
                dependency.path = Some(PathBuf::from(&dependency.name));
            }
            DependencyStatus::System
        } else if dependency.name.starts_with("@rpath/")
            || dependency.name.starts_with("@loader_path/")
            || dependency.name.starts_with("@executable_path/")
            || dependency.name.contains('/')
            || dependency.name.contains('\\')
            || (matches!(analysis.platform, Some(BinaryPlatform::Windows))
                && dependency.name.to_ascii_lowercase().ends_with(".dll"))
        {
            DependencyStatus::Missing
        } else {
            DependencyStatus::Unknown
        };
    }
    for dependency in analysis
        .dependencies
        .iter()
        .filter(|dependency| matches!(dependency.status, DependencyStatus::Missing))
    {
        analysis.findings.push(Finding {
            severity: Severity::Medium,
            category: FindingCategory::Dependency,
            title: format!("Missing dependency: {}", dependency.name),
            description: "A path-based dependency could not be resolved inside the imported artifact or as a known system dependency.".into(),
            evidence: vec![Evidence {
                label: "Library".into(),
                value: dependency.name.clone(),
                offset: None,
                locator: None,
            }],
        });
    }
}

pub fn build_dependency_graph(
    artifact: &ArtifactNode,
    cancel: &CancellationToken,
) -> Result<DependencyGraph> {
    let files: Vec<_> = artifact.files().collect();
    let path_to_id: HashMap<_, _> = files
        .iter()
        .map(|node| (node.path.clone(), node.id))
        .collect();
    let mut graph = DependencyGraph {
        nodes: files
            .iter()
            .map(|node| DependencyGraphNode {
                artifact_id: node.id,
                name: node.name.clone(),
                path: node.path.clone(),
                format: node.format,
            })
            .collect(),
        edges: Vec::new(),
    };
    for node in files {
        cancel.check()?;
        let Some(mut analysis) = (match analyze_node(node) {
            Ok(analysis) => analysis,
            Err(_) => continue,
        }) else {
            continue;
        };
        resolve_dependencies(&mut analysis, artifact);
        for binary in std::iter::once(&analysis).chain(&analysis.slice_analyses) {
            for dependency in &binary.dependencies {
                graph.edges.push(DependencyGraphEdge {
                    source: node.id,
                    source_architecture: (!binary.architecture.is_empty())
                        .then(|| binary.architecture.clone()),
                    target: dependency
                        .path
                        .as_ref()
                        .and_then(|path| path_to_id.get(path))
                        .copied(),
                    requested: dependency.name.clone(),
                    resolved_path: dependency.path.clone(),
                    status: dependency.status.clone(),
                });
            }
        }
    }
    Ok(graph)
}

pub fn analyze_node(node: &ArtifactNode) -> Result<Option<BinaryAnalysis>> {
    let detected_format = if node.format.is_some() {
        node.format
    } else {
        Some(detect_format(
            &ArtifactReader::open(node)?.read_prefix(HEADER_BYTES)?,
        ))
    };
    if !matches!(
        detected_format,
        Some(FileFormat::Pe | FileFormat::MachO | FileFormat::FatMachO | FileFormat::Elf)
    ) {
        return Ok(None);
    }
    let mut analysis = match node.source.as_ref() {
        Some(ArtifactSource::ArchiveMember { .. }) => {
            let bytes = ArtifactReader::open(node)?.read_all(bytetrawl_format::MAX_PARSE_BYTES)?;
            analyze_binary(&bytes)?
        }
        _ => {
            let file = File::open(&node.path).map_err(|source| ByteTrawlError::Io {
                path: node.path.clone(),
                source,
            })?;
            let map =
                unsafe { MmapOptions::new().map(&file) }.map_err(|source| ByteTrawlError::Io {
                    path: node.path.clone(),
                    source,
                })?;
            analyze_binary(&map)?
        }
    };
    for slice in &mut analysis.slice_analyses {
        add_findings(slice);
    }
    add_findings(&mut analysis);
    Ok(Some(analysis))
}

pub fn inspect_metadata(node: &ArtifactNode) -> Result<indexmap::IndexMap<String, String>> {
    let mut metadata = indexmap::IndexMap::new();
    if matches!(node.source, Some(ArtifactSource::ArchiveMember { .. })) {
        return inspect_archive_member_metadata(node);
    }
    match node.format {
        Some(FileFormat::Plist) => {
            ensure_structured_metadata_size(node)?;
            let value = plist::Value::from_file(&node.path)
                .map_err(|e| ByteTrawlError::Malformed(format!("plist: {e}")))?;
            flatten_plist("", &value, &mut metadata, 0);
        }
        Some(FileFormat::Json) => {
            ensure_structured_metadata_size(node)?;
            let file = File::open(&node.path).map_err(|source| ByteTrawlError::Io {
                path: node.path.clone(),
                source,
            })?;
            let value: serde_json::Value = serde_json::from_reader(file)
                .map_err(|e| ByteTrawlError::Malformed(format!("JSON: {e}")))?;
            flatten_json("", &value, &mut metadata, 0);
        }
        Some(FileFormat::Xml) => {
            ensure_structured_metadata_size(node)?;
            let text =
                std::fs::read_to_string(&node.path).map_err(|source| ByteTrawlError::Io {
                    path: node.path.clone(),
                    source,
                })?;
            let mut reader = quick_xml::Reader::from_str(&text);
            reader.config_mut().trim_text(true);
            let mut stack = Vec::new();
            let mut count = 0usize;
            loop {
                match reader.read_event() {
                    Ok(quick_xml::events::Event::Start(event)) => {
                        if stack.len() >= 64 {
                            return Err(ByteTrawlError::Limit("XML nesting exceeds 64".into()));
                        }
                        stack.push(String::from_utf8_lossy(event.name().as_ref()).into_owned());
                    }
                    Ok(quick_xml::events::Event::Text(text)) if count < 10_000 => {
                        let value = text
                            .decode()
                            .map_err(|e| ByteTrawlError::Malformed(e.to_string()))?;
                        if !value.trim().is_empty() {
                            metadata
                                .insert(stack.join("."), value.trim().chars().take(4096).collect());
                            count += 1;
                        }
                    }
                    Ok(quick_xml::events::Event::End(_)) => {
                        stack.pop();
                    }
                    Ok(quick_xml::events::Event::Eof) => break,
                    Err(e) => return Err(ByteTrawlError::Malformed(format!("XML: {e}"))),
                    _ => {}
                }
            }
        }
        Some(FileFormat::Text) if node.path.extension().is_some_and(|e| e == "desktop") => {
            ensure_structured_metadata_size(node)?;
            let text =
                std::fs::read_to_string(&node.path).map_err(|source| ByteTrawlError::Io {
                    path: node.path.clone(),
                    source,
                })?;
            for line in text.lines().take(20_000) {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
                    continue;
                }
                if let Some((key, value)) = line.split_once('=') {
                    metadata.insert(key.trim().into(), value.trim().into());
                }
            }
        }
        Some(FileFormat::Zip) => inspect_zip_metadata(&node.path, &mut metadata)?,
        Some(FileFormat::Archive) => inspect_archive_metadata(node, &mut metadata)?,
        Some(FileFormat::Image) => inspect_image_metadata(&node.path, &mut metadata)?,
        Some(FileFormat::Sqlite) => inspect_sqlite_metadata(&node.path, &mut metadata)?,
        Some(FileFormat::DiskImage) => inspect_disk_image_metadata(node, &mut metadata)?,
        _ => {}
    }
    Ok(metadata)
}

fn inspect_archive_member_metadata(
    node: &ArtifactNode,
) -> Result<indexmap::IndexMap<String, String>> {
    ensure_structured_metadata_size(node)?;
    let reader = ArtifactReader::open(node)?;
    let prefix = reader.read_prefix(HEADER_BYTES)?;
    let format = node.format.unwrap_or_else(|| detect_format(&prefix));
    let mut metadata = indexmap::IndexMap::new();
    match format {
        FileFormat::Plist => {
            let bytes = reader.read_all(MAX_STRUCTURED_METADATA_BYTES)?;
            let value = plist::Value::from_reader(std::io::Cursor::new(bytes))
                .map_err(|error| ByteTrawlError::Malformed(format!("plist: {error}")))?;
            flatten_plist("", &value, &mut metadata, 0);
        }
        FileFormat::Json => {
            let bytes = reader.read_all(MAX_STRUCTURED_METADATA_BYTES)?;
            let value: serde_json::Value = serde_json::from_slice(&bytes)
                .map_err(|error| ByteTrawlError::Malformed(format!("JSON: {error}")))?;
            flatten_json("", &value, &mut metadata, 0);
        }
        FileFormat::Xml => {
            let bytes = reader.read_all(MAX_STRUCTURED_METADATA_BYTES)?;
            let text = std::str::from_utf8(&bytes)
                .map_err(|error| ByteTrawlError::Malformed(format!("XML UTF-8: {error}")))?;
            inspect_xml_text(text, &mut metadata)?;
        }
        FileFormat::Sqlite if prefix.len() >= 100 => {
            inspect_sqlite_header(&prefix[..100], &mut metadata)?;
        }
        _ => {}
    }
    metadata.insert(
        "Source".into(),
        "Virtual archive member; no extraction performed".into(),
    );
    Ok(metadata)
}

fn inspect_xml_text(text: &str, metadata: &mut indexmap::IndexMap<String, String>) -> Result<()> {
    let mut reader = quick_xml::Reader::from_str(text);
    reader.config_mut().trim_text(true);
    let mut stack = Vec::new();
    let mut count = 0usize;
    loop {
        match reader.read_event() {
            Ok(quick_xml::events::Event::Start(event)) => {
                if stack.len() >= 64 {
                    return Err(ByteTrawlError::Limit("XML nesting exceeds 64".into()));
                }
                stack.push(String::from_utf8_lossy(event.name().as_ref()).into_owned());
            }
            Ok(quick_xml::events::Event::Text(text)) if count < 10_000 => {
                let value = text
                    .decode()
                    .map_err(|error| ByteTrawlError::Malformed(error.to_string()))?;
                if !value.trim().is_empty() {
                    metadata.insert(stack.join("."), value.trim().chars().take(4096).collect());
                    count += 1;
                }
            }
            Ok(quick_xml::events::Event::End(_)) => {
                stack.pop();
            }
            Ok(quick_xml::events::Event::Eof) => return Ok(()),
            Err(error) => return Err(ByteTrawlError::Malformed(format!("XML: {error}"))),
            _ => {}
        }
    }
}

fn ensure_structured_metadata_size(node: &ArtifactNode) -> Result<()> {
    if node.size > MAX_STRUCTURED_METADATA_BYTES {
        return Err(ByteTrawlError::Limit(format!(
            "structured metadata exceeds {} MiB",
            MAX_STRUCTURED_METADATA_BYTES / (1024 * 1024)
        )));
    }
    Ok(())
}

fn read_prefix(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let file = File::open(path).map_err(|source| ByteTrawlError::Io {
        path: path.into(),
        source,
    })?;
    let mut bytes = Vec::with_capacity(limit);
    file.take(limit as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| ByteTrawlError::Io {
            path: path.into(),
            source,
        })?;
    Ok(bytes)
}

fn inspect_image_metadata(
    path: &Path,
    metadata: &mut indexmap::IndexMap<String, String>,
) -> Result<()> {
    let header = read_prefix(path, 1024 * 1024)?;
    let image_type = imagesize::image_type(&header)
        .map_err(|error| ByteTrawlError::Malformed(format!("image type: {error}")))?;
    let dimensions = imagesize::size(path)
        .map_err(|error| ByteTrawlError::Malformed(format!("image dimensions: {error}")))?;
    metadata.insert("Image Format".into(), format!("{image_type:?}"));
    metadata.insert("Width".into(), dimensions.width.to_string());
    metadata.insert("Height".into(), dimensions.height.to_string());
    metadata.insert(
        "Pixels".into(),
        (dimensions.width as u64 * dimensions.height as u64).to_string(),
    );
    Ok(())
}

fn inspect_sqlite_metadata(
    path: &Path,
    metadata: &mut indexmap::IndexMap<String, String>,
) -> Result<()> {
    let bytes = read_prefix(path, 100)?;
    inspect_sqlite_header(&bytes, metadata)
}

fn inspect_sqlite_header(
    bytes: &[u8],
    metadata: &mut indexmap::IndexMap<String, String>,
) -> Result<()> {
    if bytes.len() < 100 || !bytes.starts_with(b"SQLite format 3\0") {
        return Err(ByteTrawlError::Malformed("truncated SQLite header".into()));
    }
    let page_size = u16::from_be_bytes([bytes[16], bytes[17]]);
    metadata.insert("Database Format".into(), "SQLite 3".into());
    metadata.insert(
        "Page Size".into(),
        if page_size == 1 {
            65_536
        } else {
            page_size as u32
        }
        .to_string(),
    );
    metadata.insert("Write Version".into(), bytes[18].to_string());
    metadata.insert("Read Version".into(), bytes[19].to_string());
    metadata.insert(
        "Schema Format".into(),
        u32::from_be_bytes([bytes[44], bytes[45], bytes[46], bytes[47]]).to_string(),
    );
    metadata.insert(
        "Text Encoding".into(),
        match u32::from_be_bytes([bytes[56], bytes[57], bytes[58], bytes[59]]) {
            1 => "UTF-8",
            2 => "UTF-16le",
            3 => "UTF-16be",
            _ => "Unknown",
        }
        .into(),
    );
    Ok(())
}

fn inspect_disk_image_metadata(
    node: &ArtifactNode,
    metadata: &mut indexmap::IndexMap<String, String>,
) -> Result<()> {
    if udif::check_dmg(&node.path) {
        return inspect_dmg_metadata(node, metadata);
    }
    inspect_iso_metadata(node, metadata)
}

fn inspect_dmg_metadata(
    node: &ArtifactNode,
    metadata: &mut indexmap::IndexMap<String, String>,
) -> Result<()> {
    const MAX_DMG_PLIST_BYTES: u64 = 64 * 1024 * 1024;
    const MAX_DMG_PARTITIONS: usize = 200_000;

    let mut file = File::open(&node.path).map_err(|source| ByteTrawlError::Io {
        path: node.path.clone(),
        source,
    })?;
    let koly = udif::KolyHeader::read(&mut file)
        .map_err(|error| ByteTrawlError::Malformed(format!("DMG trailer: {error}")))?;
    if koly.plist_length > MAX_DMG_PLIST_BYTES {
        return Err(ByteTrawlError::Limit(format!(
            "DMG plist exceeds {MAX_DMG_PLIST_BYTES} bytes"
        )));
    }
    for (label, offset, length) in [
        ("data fork", koly.data_fork_offset, koly.data_fork_length),
        (
            "resource fork",
            koly.rsrc_fork_offset,
            koly.rsrc_fork_length,
        ),
        ("plist", koly.plist_offset, koly.plist_length),
    ] {
        if offset.checked_add(length).is_none_or(|end| end > node.size) {
            return Err(ByteTrawlError::Malformed(format!(
                "DMG {label} range exceeds the container"
            )));
        }
    }

    let archive = udif::DmgArchive::open(&node.path)
        .map_err(|error| ByteTrawlError::Malformed(format!("DMG: {error}")))?;
    let stats = archive.stats();
    let compression = archive.compression_info();
    let partitions = archive.partitions();
    if partitions.len() > MAX_DMG_PARTITIONS {
        return Err(ByteTrawlError::Limit(format!(
            "DMG contains more than {MAX_DMG_PARTITIONS} partitions"
        )));
    }
    metadata.insert("Disk Image Format".into(), "Apple UDIF / DMG".into());
    metadata.insert("UDIF Version".into(), stats.version.to_string());
    metadata.insert("Sector Count".into(), stats.sector_count.to_string());
    metadata.insert("Partition Count".into(), stats.partition_count.to_string());
    metadata.insert(
        "Data Fork Length".into(),
        stats.data_fork_length.to_string(),
    );
    metadata.insert(
        "Total Compressed Bytes".into(),
        stats.total_compressed.to_string(),
    );
    metadata.insert(
        "Total Uncompressed Bytes".into(),
        stats.total_uncompressed.to_string(),
    );
    metadata.insert(
        "Compression Ratio".into(),
        format!("{:.4}", stats.compression_ratio()),
    );
    metadata.insert(
        "Compression Blocks".into(),
        format!(
            "raw={} zlib={} bzip2={} lzfse={} xz={} adc={} zero={}",
            compression.raw_blocks,
            compression.zlib_blocks,
            compression.bzip2_blocks,
            compression.lzfse_blocks,
            compression.xz_blocks,
            compression.adc_blocks,
            compression.zero_fill_blocks
        ),
    );
    for (index, partition) in partitions.into_iter().take(10_000).enumerate() {
        metadata.insert(
            format!("Partition {index:05}"),
            format!(
                "{} · id={} · {:?} · {} sectors · {} → {} bytes",
                partition.name,
                partition.id,
                partition.partition_type,
                partition.sectors,
                partition.compressed_size,
                partition.size
            ),
        );
    }
    metadata.insert(
        "Inspection Mode".into(),
        "Static container metadata only; ByteTrawl did not mount or extract this image.".into(),
    );
    Ok(())
}

fn inspect_iso_metadata(
    node: &ArtifactNode,
    metadata: &mut indexmap::IndexMap<String, String>,
) -> Result<()> {
    let mut file = File::open(&node.path).map_err(|source| ByteTrawlError::Io {
        path: node.path.clone(),
        source,
    })?;
    file.seek(SeekFrom::Start(16 * 2048))
        .map_err(|source| ByteTrawlError::Io {
            path: node.path.clone(),
            source,
        })?;
    let mut descriptor = [0u8; 2048];
    file.read_exact(&mut descriptor)
        .map_err(|source| ByteTrawlError::Io {
            path: node.path.clone(),
            source,
        })?;
    if &descriptor[1..6] != b"CD001" {
        return Err(ByteTrawlError::Malformed(
            "disk image lacks a valid ISO 9660 volume descriptor".into(),
        ));
    }
    let volume_id = String::from_utf8_lossy(&descriptor[40..72])
        .trim_end_matches([' ', '\0'])
        .to_owned();
    let sectors = u32::from_le_bytes(descriptor[80..84].try_into().unwrap_or([0; 4]));
    let block_size = u16::from_le_bytes(descriptor[128..130].try_into().unwrap_or([0; 2]));
    metadata.insert("Disk Image Format".into(), "ISO 9660".into());
    metadata.insert("Volume Descriptor Type".into(), descriptor[0].to_string());
    metadata.insert("Volume Identifier".into(), volume_id);
    metadata.insert("Volume Sectors".into(), sectors.to_string());
    metadata.insert("Logical Block Size".into(), block_size.to_string());
    metadata.insert(
        "Inspection Mode".into(),
        "Static volume metadata only; ByteTrawl did not mount this image.".into(),
    );
    Ok(())
}

fn inspect_archive_metadata(
    node: &ArtifactNode,
    metadata: &mut indexmap::IndexMap<String, String>,
) -> Result<()> {
    let prefix = read_prefix(&node.path, 512)?;
    if prefix.starts_with(b"!<arch>\n") {
        inspect_ar_metadata(node, metadata)
    } else if prefix.starts_with(b"xar!") {
        inspect_xar_metadata(node, metadata)
    } else if prefix.get(257..262).is_some_and(|magic| magic == b"ustar") {
        let file = File::open(&node.path).map_err(|source| ByteTrawlError::Io {
            path: node.path.clone(),
            source,
        })?;
        inspect_tar_reader(file, "Tar", metadata)
    } else if prefix.starts_with(b"\x1f\x8b")
        && node
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                let name = name.to_ascii_lowercase();
                name.ends_with(".tar.gz") || name.ends_with(".tgz")
            })
    {
        let file = File::open(&node.path).map_err(|source| ByteTrawlError::Io {
            path: node.path.clone(),
            source,
        })?;
        inspect_tar_reader(
            flate2::read::GzDecoder::new(file),
            "Gzip-compressed Tar",
            metadata,
        )
    } else {
        metadata.insert(
            "Archive Format".into(),
            archive_format_label(&prefix).into(),
        );
        metadata.insert(
            "Inspection Mode".into(),
            "Static container identification only; ByteTrawl did not extract this archive.".into(),
        );
        Ok(())
    }
}

fn archive_format_label(prefix: &[u8]) -> &'static str {
    if prefix.starts_with(b"7z\xbc\xaf\x27\x1c") {
        "7-Zip"
    } else if prefix.starts_with(b"Rar!\x1a\x07") {
        "RAR"
    } else if prefix.starts_with(b"\x1f\x8b") {
        "Gzip stream"
    } else {
        "Recognized archive"
    }
}

fn inspect_ar_metadata(
    node: &ArtifactNode,
    metadata: &mut indexmap::IndexMap<String, String>,
) -> Result<()> {
    const MAX_AR_BYTES: u64 = 512 * 1024 * 1024;
    const MAX_ARCHIVE_ENTRIES: usize = 200_000;
    if node.size > MAX_AR_BYTES {
        return Err(ByteTrawlError::Limit(format!(
            "ar archive exceeds {MAX_AR_BYTES} bytes"
        )));
    }
    let file = File::open(&node.path).map_err(|source| ByteTrawlError::Io {
        path: node.path.clone(),
        source,
    })?;
    // SAFETY: this is a read-only mapping of a stable file descriptor owned for the map lifetime.
    let map = unsafe { MmapOptions::new().map(&file) }.map_err(|source| ByteTrawlError::Io {
        path: node.path.clone(),
        source,
    })?;
    let archive = goblin::archive::Archive::parse(&map)
        .map_err(|error| ByteTrawlError::Malformed(format!("ar: {error}")))?;
    if archive.len() > MAX_ARCHIVE_ENTRIES {
        return Err(ByteTrawlError::Limit(format!(
            "ar contains more than {MAX_ARCHIVE_ENTRIES} members"
        )));
    }
    let mut total = 0u64;
    for index in 0..archive.len() {
        let Some(member) = archive.get_at(index) else {
            continue;
        };
        total = total.saturating_add(member.size() as u64);
        if index < 10_000 {
            metadata.insert(
                format!("Member {index:05}"),
                format!(
                    "{} · {} bytes · file offset 0x{:x}",
                    member.extended_name(),
                    member.size(),
                    member.offset
                ),
            );
        }
    }
    metadata.shift_insert(0, "Archive Format".into(), "Unix / COFF ar".into());
    metadata.shift_insert(1, "Member Count".into(), archive.len().to_string());
    metadata.shift_insert(2, "Member Bytes".into(), total.to_string());
    metadata.insert(
        "Inspection Mode".into(),
        "Static member table only; ByteTrawl did not extract this archive.".into(),
    );
    Ok(())
}

fn inspect_tar_reader(
    reader: impl Read,
    label: &str,
    metadata: &mut indexmap::IndexMap<String, String>,
) -> Result<()> {
    const MAX_ARCHIVE_ENTRIES: usize = 200_000;
    const MAX_DECLARED_BYTES: u64 = 64 * 1024 * 1024 * 1024;
    let mut archive = tar::Archive::new(reader);
    let entries = archive
        .entries()
        .map_err(|error| ByteTrawlError::Malformed(format!("tar: {error}")))?;
    let mut count = 0usize;
    let mut total = 0u64;
    let mut unsafe_paths = 0usize;
    let mut links = 0usize;
    for entry in entries {
        let entry = entry.map_err(|error| ByteTrawlError::Malformed(format!("tar: {error}")))?;
        count += 1;
        if count > MAX_ARCHIVE_ENTRIES {
            return Err(ByteTrawlError::Limit(format!(
                "tar contains more than {MAX_ARCHIVE_ENTRIES} entries"
            )));
        }
        let size = entry.size();
        total = total.saturating_add(size);
        if total > MAX_DECLARED_BYTES {
            return Err(ByteTrawlError::Limit(format!(
                "tar declares more than {MAX_DECLARED_BYTES} bytes"
            )));
        }
        let path = entry
            .path()
            .map_err(|error| ByteTrawlError::Malformed(format!("tar path: {error}")))?;
        let safe = !path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        });
        if !safe {
            unsafe_paths += 1;
        }
        let is_link =
            entry.header().entry_type().is_symlink() || entry.header().entry_type().is_hard_link();
        if is_link {
            links += 1;
        }
        if count <= 10_000 {
            metadata.insert(
                format!("Entry {:05}", count - 1),
                format!(
                    "{} · {:?} · {} bytes{}{}",
                    path.display(),
                    entry.header().entry_type(),
                    size,
                    if safe { "" } else { " · UNSAFE PATH" },
                    if is_link { " · LINK" } else { "" }
                ),
            );
        }
    }
    metadata.shift_insert(0, "Archive Format".into(), label.into());
    metadata.shift_insert(1, "Entry Count".into(), count.to_string());
    metadata.shift_insert(2, "Declared Bytes".into(), total.to_string());
    metadata.shift_insert(3, "Unsafe Paths".into(), unsafe_paths.to_string());
    metadata.shift_insert(4, "Links".into(), links.to_string());
    metadata.insert(
        "Static Safety Assessment".into(),
        if unsafe_paths > 0 || links > 0 {
            "Review required before extraction; ByteTrawl did not extract this archive."
        } else {
            "No obvious extraction hazard in the entry table; ByteTrawl did not extract this archive."
        }
        .into(),
    );
    Ok(())
}

fn inspect_xar_metadata(
    node: &ArtifactNode,
    metadata: &mut indexmap::IndexMap<String, String>,
) -> Result<()> {
    const MAX_XAR_TOC_BYTES: u64 = 64 * 1024 * 1024;
    const MAX_ARCHIVE_ENTRIES: usize = 200_000;
    let header = read_prefix(&node.path, 28)?;
    if header.len() != 28 || &header[..4] != b"xar!" {
        return Err(ByteTrawlError::Malformed("truncated XAR header".into()));
    }
    let header_size = u16::from_be_bytes([header[4], header[5]]) as u64;
    let compressed = u64::from_be_bytes(header[8..16].try_into().unwrap_or([0; 8]));
    let uncompressed = u64::from_be_bytes(header[16..24].try_into().unwrap_or([0; 8]));
    if header_size < 28
        || compressed > MAX_XAR_TOC_BYTES
        || uncompressed > MAX_XAR_TOC_BYTES
        || header_size
            .checked_add(compressed)
            .is_none_or(|end| end > node.size)
    {
        return Err(ByteTrawlError::Limit(
            "XAR table of contents has unsafe size or range".into(),
        ));
    }
    let file = File::open(&node.path).map_err(|source| ByteTrawlError::Io {
        path: node.path.clone(),
        source,
    })?;
    let reader = apple_xar::reader::XarReader::new(file)
        .map_err(|error| ByteTrawlError::Malformed(format!("XAR: {error}")))?;
    let files = reader
        .files()
        .map_err(|error| ByteTrawlError::Malformed(format!("XAR TOC: {error}")))?;
    if files.len() > MAX_ARCHIVE_ENTRIES {
        return Err(ByteTrawlError::Limit(format!(
            "XAR contains more than {MAX_ARCHIVE_ENTRIES} entries"
        )));
    }
    let mut total = 0u64;
    let mut unsafe_paths = 0usize;
    let mut links = 0usize;
    for (index, (path, file)) in files.iter().enumerate() {
        total = total.saturating_add(file.size.unwrap_or(0));
        let path_value = Path::new(path);
        let safe = !path_value.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        });
        if !safe {
            unsafe_paths += 1;
        }
        let is_link = matches!(
            file.file_type,
            apple_xar::table_of_contents::FileType::Link
                | apple_xar::table_of_contents::FileType::HardLink
        );
        if is_link {
            links += 1;
        }
        if index < 10_000 {
            metadata.insert(
                format!("Entry {index:05}"),
                format!(
                    "{} · {:?} · {} bytes{}{}",
                    path,
                    file.file_type,
                    file.size.unwrap_or(0),
                    if safe { "" } else { " · UNSAFE PATH" },
                    if is_link { " · LINK" } else { "" }
                ),
            );
        }
    }
    let xar_header = reader.header();
    metadata.shift_insert(0, "Archive Format".into(), "Apple XAR / flat PKG".into());
    metadata.shift_insert(1, "XAR Version".into(), xar_header.version.to_string());
    metadata.shift_insert(
        2,
        "TOC Checksum".into(),
        apple_xar::format::XarChecksum::from(xar_header.checksum_algorithm_id).to_string(),
    );
    metadata.shift_insert(3, "Entry Count".into(), files.len().to_string());
    metadata.shift_insert(4, "Declared Bytes".into(), total.to_string());
    metadata.shift_insert(5, "Unsafe Paths".into(), unsafe_paths.to_string());
    metadata.shift_insert(6, "Links".into(), links.to_string());
    metadata.shift_insert(
        7,
        "Embedded Signatures".into(),
        reader.table_of_contents().signatures().len().to_string(),
    );
    metadata.insert(
        "Inspection Mode".into(),
        "Static XAR table of contents only; ByteTrawl did not run Installer or extract the package."
            .into(),
    );
    Ok(())
}

fn inspect_zip_metadata(
    path: &Path,
    metadata: &mut indexmap::IndexMap<String, String>,
) -> Result<()> {
    const MAX_ZIP_ENTRIES: usize = 200_000;
    const MAX_LISTED_ENTRIES: usize = 10_000;
    const SUSPICIOUS_TOTAL_SIZE: u64 = 16 * 1024 * 1024 * 1024;

    let file = File::open(path).map_err(|source| ByteTrawlError::Io {
        path: path.into(),
        source,
    })?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|error| ByteTrawlError::Malformed(format!("ZIP: {error}")))?;
    if archive.len() > MAX_ZIP_ENTRIES {
        return Err(ByteTrawlError::Limit(format!(
            "ZIP contains more than {MAX_ZIP_ENTRIES} entries"
        )));
    }
    let mut compressed = 0u64;
    let mut uncompressed = 0u64;
    let mut unsafe_paths = 0usize;
    let mut symlinks = 0usize;
    for index in 0..archive.len() {
        let entry = archive
            .by_index_raw(index)
            .map_err(|error| ByteTrawlError::Malformed(format!("ZIP entry {index}: {error}")))?;
        compressed = compressed.saturating_add(entry.compressed_size());
        uncompressed = uncompressed.saturating_add(entry.size());
        let safe = entry.enclosed_name().is_some();
        if !safe {
            unsafe_paths += 1;
        }
        let symlink = entry
            .unix_mode()
            .is_some_and(|mode| mode & 0o170000 == 0o120000);
        if symlink {
            symlinks += 1;
        }
        if index < MAX_LISTED_ENTRIES {
            metadata.insert(
                format!("Entry {index:05}"),
                format!(
                    "{} · {} → {} bytes{}{}",
                    entry.name(),
                    entry.compressed_size(),
                    entry.size(),
                    if safe { "" } else { " · UNSAFE PATH" },
                    if symlink { " · SYMLINK" } else { "" }
                ),
            );
        }
    }
    let ratio = if compressed == 0 {
        if uncompressed == 0 {
            0.0
        } else {
            f64::INFINITY
        }
    } else {
        uncompressed as f64 / compressed as f64
    };
    metadata.shift_insert(0, "Entry Count".into(), archive.len().to_string());
    metadata.shift_insert(1, "Compressed Size".into(), compressed.to_string());
    metadata.shift_insert(2, "Uncompressed Size".into(), uncompressed.to_string());
    metadata.shift_insert(3, "Expansion Ratio".into(), format!("{ratio:.2}×"));
    metadata.shift_insert(4, "Unsafe Paths".into(), unsafe_paths.to_string());
    metadata.shift_insert(5, "Symbolic Links".into(), symlinks.to_string());
    metadata.shift_insert(
        6,
        "Static Safety Assessment".into(),
        if unsafe_paths > 0
            || symlinks > 0
            || uncompressed > SUSPICIOUS_TOTAL_SIZE
            || ratio > 1_000.0
        {
            "Review required before extraction; ByteTrawl did not extract this archive."
        } else {
            "No obvious extraction hazard in the central directory; ByteTrawl did not extract this archive."
        }
        .into(),
    );
    Ok(())
}

pub fn inspect_signature(path: &Path) -> Option<SignatureInfo> {
    HostSignatureProvider.inspect(path)
}

pub fn inspect_signature_cancellable(
    path: &Path,
    cancel: &CancellationToken,
) -> Result<Option<SignatureInfo>> {
    let result = inspect_host_signature_with_cancel(path, &|| cancel.is_cancelled());
    cancel.check()?;
    Ok(result)
}

fn flatten_plist(
    prefix: &str,
    value: &plist::Value,
    out: &mut indexmap::IndexMap<String, String>,
    depth: usize,
) {
    if depth > 32 || out.len() >= 20_000 {
        return;
    }
    match value {
        plist::Value::Dictionary(items) => {
            for (key, value) in items {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                flatten_plist(&path, value, out, depth + 1);
            }
        }
        plist::Value::Array(items) => {
            for (index, value) in items.iter().enumerate() {
                flatten_plist(&format!("{prefix}[{index}]"), value, out, depth + 1);
            }
        }
        _ => {
            out.insert(prefix.into(), plist_scalar(value));
        }
    }
}

fn plist_scalar(value: &plist::Value) -> String {
    match value {
        plist::Value::Boolean(v) => v.to_string(),
        plist::Value::Data(v) => format!("<{} bytes>", v.len()),
        plist::Value::Date(v) => format!("{v:?}"),
        plist::Value::Integer(v) => format!("{v:?}"),
        plist::Value::Real(v) => v.to_string(),
        plist::Value::String(v) => v.clone(),
        plist::Value::Uid(v) => format!("{v:?}"),
        _ => String::new(),
    }
}

fn flatten_json(
    prefix: &str,
    value: &serde_json::Value,
    out: &mut indexmap::IndexMap<String, String>,
    depth: usize,
) {
    if depth > 32 || out.len() >= 20_000 {
        return;
    }
    match value {
        serde_json::Value::Object(items) => {
            for (key, value) in items {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                flatten_json(&path, value, out, depth + 1);
            }
        }
        serde_json::Value::Array(items) => {
            for (index, value) in items.iter().enumerate() {
                flatten_json(&format!("{prefix}[{index}]"), value, out, depth + 1);
            }
        }
        _ => {
            out.insert(prefix.into(), value.to_string());
        }
    }
}

fn enrich_section_entropy(
    bytes: &[u8],
    analysis: &mut BinaryAnalysis,
    cancel: &CancellationToken,
) -> Result<()> {
    for section in &mut analysis.sections {
        cancel.check()?;
        let start = section.offset as usize;
        let end = start.saturating_add(section.size as usize).min(bytes.len());
        if start < end {
            section.entropy = Some(entropy(&bytes[start..end]));
        }
    }
    Ok(())
}

pub fn enrich_analysis_entropy(
    path: &Path,
    analysis: &mut BinaryAnalysis,
    cancel: &CancellationToken,
) -> Result<()> {
    let file = File::open(path).map_err(|source| ByteTrawlError::Io {
        path: path.into(),
        source,
    })?;
    let map = unsafe { MmapOptions::new().map(&file) }.map_err(|source| ByteTrawlError::Io {
        path: path.into(),
        source,
    })?;
    enrich_section_entropy(&map, analysis, cancel)?;
    analysis
        .findings
        .retain(|finding| finding.category != FindingCategory::Entropy);
    add_entropy_findings(analysis);
    for slice in &mut analysis.slice_analyses {
        enrich_section_entropy(&map, slice, cancel)?;
        slice
            .findings
            .retain(|finding| finding.category != FindingCategory::Entropy);
        add_entropy_findings(slice);
    }
    Ok(())
}

fn add_entropy_findings(a: &mut BinaryAnalysis) {
    for section in &a.sections {
        if section.entropy.is_some_and(|entropy| entropy > 7.4) {
            a.findings.push(Finding {
                severity: Severity::Info,
                category: FindingCategory::Entropy,
                title: format!("High entropy in {}", section.name),
                description: "High entropy can indicate compressed, packed, or encrypted-looking data; it is an indicator, not a security conclusion.".into(),
                evidence: vec![Evidence {
                    label: "Entropy".into(),
                    value: format!(
                        "{:.3} bits/byte",
                        section.entropy.unwrap_or_default()
                    ),
                    offset: Some(section.offset),
                    locator: None,
                }],
            });
        }
    }
}

fn add_signature_findings(a: &mut BinaryAnalysis) {
    if a.signature
        .as_ref()
        .is_some_and(|s| matches!(s.status, SignatureStatus::Unsigned))
    {
        a.findings.push(Finding {
            severity: Severity::Info,
            category: FindingCategory::Signature,
            title: "Unsigned executable".into(),
            description: "No host-verifiable code signature was found. Unsigned does not by itself imply malicious behavior.".into(),
            evidence: vec![],
        });
    }
    if a.signature
        .as_ref()
        .is_some_and(|signature| matches!(signature.status, SignatureStatus::Invalid))
    {
        a.findings.push(Finding {
            severity: Severity::High,
            category: FindingCategory::Signature,
            title: "Invalid code signature".into(),
            description: "The host cryptographic signature verifier rejected this code object."
                .into(),
            evidence: vec![],
        });
    }
    if matches!(a.platform, Some(BinaryPlatform::MacOs))
        && a.signature.as_ref().is_some_and(|signature| {
            matches!(
                signature.status,
                SignatureStatus::Valid | SignatureStatus::AdHoc
            ) && !signature.platform.contains_key("Hardened Runtime")
        })
    {
        a.findings.push(Finding {
            severity: Severity::Low,
            category: FindingCategory::Signature,
            title: "Hardened Runtime not detected".into(),
            description: "The host signature inspection did not report a Hardened Runtime version."
                .into(),
            evidence: vec![],
        });
    }
}

pub fn apply_signature_analysis(analysis: &mut BinaryAnalysis, signature: &SignatureInfo) {
    analysis.signature = Some(signature.clone());
    analysis
        .findings
        .retain(|finding| finding.category != FindingCategory::Signature);
    add_signature_findings(analysis);
    for slice in &mut analysis.slice_analyses {
        apply_signature_analysis(slice, signature);
    }
}

fn add_findings(a: &mut BinaryAnalysis) {
    add_signature_findings(a);
    for s in &a.sections {
        let permissions = s.flags.split_whitespace().next().unwrap_or_default();
        if permissions.contains('W') && permissions.contains('X') {
            a.findings.push(Finding {
                severity: Severity::High,
                category: FindingCategory::MemorySafety,
                title: format!("Writable and executable section: {}", s.name),
                description: "This section is mapped writable and executable, weakening write-xor-execute protections.".into(),
                evidence: vec![Evidence {
                    label: "Permissions".into(),
                    value: permissions.into(),
                    offset: Some(s.offset),
                    locator: None,
                }],
            });
        }
    }
    add_entropy_findings(a);
    if a.metadata.contains_key("PDB path") || !a.symbols.is_empty() {
        a.findings.push(Finding {
            severity: Severity::Info,
            category: FindingCategory::DebugInfo,
            title: "Debug symbols present".into(),
            description:
                "Symbol or debug metadata is present and may reveal implementation details.".into(),
            evidence: vec![],
        });
    }
    if a.metadata
        .get("RPATH")
        .is_some_and(|paths| paths.split([';', ':']).any(|path| path.starts_with('/')))
    {
        a.findings.push(Finding {
            severity: Severity::Low,
            category: FindingCategory::PathSecurity,
            title: "Absolute RPATH".into(),
            description: "The binary contains an absolute runtime library search path.".into(),
            evidence: vec![],
        });
    }
    if a.metadata
        .get("GNU Stack")
        .is_some_and(|value| value == "Executable")
    {
        a.findings.push(Finding {
            severity: Severity::High,
            category: FindingCategory::MemorySafety,
            title: "Executable ELF stack".into(),
            description: "The GNU_STACK program header requests an executable process stack. This weakens a common exploit mitigation.".into(),
            evidence: vec![],
        });
    }
    if matches!(a.platform, Some(BinaryPlatform::Windows)) {
        for (key, severity, title) in [
            ("ASLR", Severity::Medium, "ASLR compatibility disabled"),
            (
                "DEP / NX compatible",
                Severity::High,
                "DEP/NX compatibility disabled",
            ),
        ] {
            if a.metadata.get(key).is_some_and(|value| value == "Disabled") {
                a.findings.push(Finding {
                    severity,
                    category: FindingCategory::MemorySafety,
                    title: title.into(),
                    description: format!("The PE optional header does not advertise {key}."),
                    evidence: vec![],
                });
            }
        }
    }
}

pub fn entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for b in bytes {
        counts[*b as usize] += 1;
    }
    let len = bytes.len() as f64;
    counts
        .into_iter()
        .filter(|c| *c > 0)
        .map(|c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[derive(Debug, Clone, Copy)]
pub struct HashOptions {
    pub sha256: bool,
    pub sha1: bool,
    pub md5: bool,
}
impl Default for HashOptions {
    fn default() -> Self {
        Self {
            sha256: true,
            sha1: false,
            md5: false,
        }
    }
}
pub fn hash_file(
    path: &Path,
    options: HashOptions,
    cancel: &CancellationToken,
) -> Result<FileSummary> {
    let mut file = File::open(path).map_err(|source| ByteTrawlError::Io {
        path: path.into(),
        source,
    })?;
    let size = file
        .metadata()
        .map_err(|source| ByteTrawlError::Io {
            path: path.into(),
            source,
        })?
        .len();
    let mut h256 = Sha256::new();
    let mut h1 = Sha1::new();
    let mut h5 = Md5::new();
    let mut buf = vec![0u8; 1024 * 1024];
    let mut counts = [0u64; 256];
    let mut total = 0u64;
    loop {
        cancel.check()?;
        let n = file.read(&mut buf).map_err(|source| ByteTrawlError::Io {
            path: path.into(),
            source,
        })?;
        if n == 0 {
            break;
        }
        for b in &buf[..n] {
            counts[*b as usize] += 1
        }
        total += n as u64;
        if options.sha256 {
            h256.update(&buf[..n])
        }
        if options.sha1 {
            h1.update(&buf[..n])
        }
        if options.md5 {
            h5.update(&buf[..n])
        }
    }
    let ent = if total == 0 {
        0.0
    } else {
        counts
            .into_iter()
            .filter(|c| *c > 0)
            .map(|c| {
                let p = c as f64 / total as f64;
                -p * p.log2()
            })
            .sum()
    };
    Ok(FileSummary {
        size,
        sha256: options.sha256.then(|| hex::encode(h256.finalize())),
        sha1: options.sha1.then(|| hex::encode(h1.finalize())),
        md5: options.md5.then(|| hex::encode(h5.finalize())),
        entropy: Some(ent),
        analysis: None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringEncoding {
    Ascii,
    Utf8,
    Utf16Le,
    Utf16Be,
}
#[derive(Debug, Clone)]
pub struct ExtractedString {
    pub offset: u64,
    pub encoding: StringEncoding,
    pub value: String,
    pub section: Option<String>,
    pub virtual_address: Option<u64>,
}
pub fn extract_strings(bytes: &[u8], minimum: usize, limit: usize) -> Vec<ExtractedString> {
    extract_strings_inner(bytes, minimum, limit, None).unwrap_or_default()
}

fn extract_strings_inner(
    bytes: &[u8],
    minimum: usize,
    limit: usize,
    cancel: Option<&CancellationToken>,
) -> Result<Vec<ExtractedString>> {
    let min = minimum.max(2);
    let mut out = Vec::new();
    let mut start = 0;
    while start < bytes.len() && out.len() < limit {
        if start & 0x000f_ffff == 0
            && let Some(cancel) = cancel
        {
            cancel.check()?;
        }
        while start < bytes.len() && !is_ascii(bytes[start]) {
            start += 1
        }
        let mut end = start;
        while end < bytes.len() && is_ascii(bytes[end]) {
            end += 1
        }
        if end - start >= min {
            out.push(ExtractedString {
                offset: start as u64,
                encoding: StringEncoding::Ascii,
                value: String::from_utf8_lossy(&bytes[start..end]).into(),
                section: None,
                virtual_address: None,
            });
        }
        start = end.saturating_add(1);
    }
    let mut cursor = 0usize;
    while cursor < bytes.len() && out.len() < limit {
        if cursor & 0x000f_ffff == 0
            && let Some(cancel) = cancel
        {
            cancel.check()?;
        }
        let (valid_len, skip) = match std::str::from_utf8(&bytes[cursor..]) {
            Ok(text) => (text.len(), 0),
            Err(error) => (error.valid_up_to(), error.error_len().unwrap_or(1)),
        };
        if valid_len > 0 {
            let text = String::from_utf8_lossy(&bytes[cursor..cursor + valid_len]);
            let mut run_start = 0usize;
            for (index, character) in text
                .char_indices()
                .chain(std::iter::once((text.len(), '\0')))
            {
                if character.is_control() {
                    let value = &text[run_start..index];
                    if value.chars().count() >= min && !value.is_ascii() {
                        out.push(ExtractedString {
                            offset: (cursor + run_start) as u64,
                            encoding: StringEncoding::Utf8,
                            value: value.into(),
                            section: None,
                            virtual_address: None,
                        });
                        if out.len() >= limit {
                            break;
                        }
                    }
                    run_start = index + character.len_utf8();
                }
            }
        }
        cursor = cursor.saturating_add(valid_len).saturating_add(skip.max(1));
    }
    for endian in [StringEncoding::Utf16Le, StringEncoding::Utf16Be] {
        let mut i = 0;
        while i + 1 < bytes.len() && out.len() < limit {
            if i & 0x000f_ffff == 0
                && let Some(cancel) = cancel
            {
                cancel.check()?;
            }
            let begin = i;
            let mut units = Vec::new();
            while i + 1 < bytes.len() {
                let u = match endian {
                    StringEncoding::Utf16Le => u16::from_le_bytes([bytes[i], bytes[i + 1]]),
                    _ => u16::from_be_bytes([bytes[i], bytes[i + 1]]),
                };
                if !(0x20..=0x7e).contains(&u) {
                    break;
                }
                units.push(u);
                i += 2;
            }
            if units.len() >= min
                && let Ok(value) = String::from_utf16(&units)
            {
                out.push(ExtractedString {
                    offset: begin as u64,
                    encoding: endian,
                    value,
                    section: None,
                    virtual_address: None,
                });
            }
            i = begin.saturating_add(2);
        }
    }
    out.sort_by_key(|s| s.offset);
    Ok(out)
}

pub fn annotate_string_locations(strings: &mut [ExtractedString], analysis: &BinaryAnalysis) {
    let mut sections: Vec<_> = analysis
        .sections
        .iter()
        .filter(|section| section.size > 0)
        .collect();
    sections.sort_by_key(|section| section.offset);
    for string in strings {
        if let Some(section) = sections.iter().find(|section| {
            string.offset >= section.offset
                && string.offset < section.offset.saturating_add(section.size)
        }) {
            string.section = Some(section.name.clone());
            string.virtual_address = Some(
                section
                    .address
                    .saturating_add(string.offset.saturating_sub(section.offset)),
            );
        }
    }
}

pub fn extract_strings_file(
    path: &Path,
    minimum: usize,
    limit: usize,
) -> Result<Vec<ExtractedString>> {
    let file = File::open(path).map_err(|source| ByteTrawlError::Io {
        path: path.into(),
        source,
    })?;
    let map = unsafe { MmapOptions::new().map(&file) }.map_err(|source| ByteTrawlError::Io {
        path: path.into(),
        source,
    })?;
    extract_strings_inner(&map, minimum, limit, None)
}

pub fn extract_strings_file_cancellable(
    path: &Path,
    minimum: usize,
    limit: usize,
    cancel: &CancellationToken,
) -> Result<Vec<ExtractedString>> {
    cancel.check()?;
    let file = File::open(path).map_err(|source| ByteTrawlError::Io {
        path: path.into(),
        source,
    })?;
    let map = unsafe { MmapOptions::new().map(&file) }.map_err(|source| ByteTrawlError::Io {
        path: path.into(),
        source,
    })?;
    extract_strings_inner(&map, minimum, limit, Some(cancel))
}

pub fn extract_strings_node_cancellable(
    node: &ArtifactNode,
    minimum: usize,
    limit: usize,
    cancel: &CancellationToken,
) -> Result<Vec<ExtractedString>> {
    cancel.check()?;
    match node.source.as_ref() {
        Some(ArtifactSource::ArchiveMember { .. }) => {
            let bytes = ArtifactReader::open(node)?.read_all(MAX_ARCHIVE_MEMBER_BYTES)?;
            cancel.check()?;
            extract_strings_inner(&bytes, minimum, limit, Some(cancel))
        }
        _ => extract_strings_file_cancellable(&node.path, minimum, limit, cancel),
    }
}

pub fn search_file(
    path: &Path,
    needle: &[u8],
    start: u64,
    cancel: &CancellationToken,
) -> Result<Option<u64>> {
    if needle.is_empty() {
        return Ok(None);
    }
    let mut file = File::open(path).map_err(|source| ByteTrawlError::Io {
        path: path.into(),
        source,
    })?;
    file.seek(SeekFrom::Start(start))
        .map_err(|source| ByteTrawlError::Io {
            path: path.into(),
            source,
        })?;
    let chunk_size = 1024 * 1024;
    let mut buffer = vec![0u8; chunk_size + needle.len().saturating_sub(1)];
    let mut carried = 0usize;
    let mut absolute = start;
    loop {
        cancel.check()?;
        let read = file
            .read(&mut buffer[carried..])
            .map_err(|source| ByteTrawlError::Io {
                path: path.into(),
                source,
            })?;
        let available = carried + read;
        if let Some(position) = buffer[..available]
            .windows(needle.len())
            .position(|window| window == needle)
        {
            return Ok(Some(
                absolute.saturating_sub(carried as u64) + position as u64,
            ));
        }
        if read == 0 {
            return Ok(None);
        }
        let keep = needle.len().saturating_sub(1).min(available);
        buffer.copy_within(available - keep..available, 0);
        absolute += read as u64;
        carried = keep;
    }
}

pub fn search_node(
    node: &ArtifactNode,
    needle: &[u8],
    start: u64,
    cancel: &CancellationToken,
) -> Result<Option<u64>> {
    if needle.is_empty() {
        return Ok(None);
    }
    match node.source.as_ref() {
        Some(ArtifactSource::ArchiveMember { .. }) => {
            cancel.check()?;
            let reader = ArtifactReader::open(node)?;
            if start >= reader.len() {
                return Ok(None);
            }
            let bytes = reader.read_all(MAX_ARCHIVE_MEMBER_BYTES)?;
            cancel.check()?;
            Ok(bytes[start as usize..]
                .windows(needle.len())
                .position(|window| window == needle)
                .map(|position| start + position as u64))
        }
        _ => search_file(&node.path, needle, start, cancel),
    }
}

#[derive(Debug, Clone)]
pub struct SearchHit {
    pub node_id: uuid::Uuid,
    pub path: PathBuf,
    pub category: &'static str,
    pub value: String,
    pub detail: String,
}

pub fn global_search(
    artifact: &ArtifactNode,
    query: &str,
    cancel: &CancellationToken,
    limit: usize,
) -> Result<Vec<SearchHit>> {
    global_search_impl(artifact, query, cancel, limit, None)
}

pub fn global_search_cached(
    artifact: &ArtifactNode,
    query: &str,
    cancel: &CancellationToken,
    limit: usize,
    cache: &AnalysisCache,
) -> Result<Vec<SearchHit>> {
    global_search_impl(artifact, query, cancel, limit, Some(cache))
}

fn global_search_impl(
    artifact: &ArtifactNode,
    query: &str,
    cancel: &CancellationToken,
    limit: usize,
    cache: Option<&AnalysisCache>,
) -> Result<Vec<SearchHit>> {
    let needle = query.trim().to_lowercase();
    if needle.is_empty() {
        return Ok(Vec::new());
    }
    let mut hits = Vec::new();
    for node in artifact.files() {
        cancel.check()?;
        push_hit(
            &mut hits,
            limit,
            node,
            "Filename",
            &node.name,
            &node.path.display().to_string(),
            &needle,
        );
        push_hit(
            &mut hits,
            limit,
            node,
            "Path",
            &node.path.display().to_string(),
            "",
            &needle,
        );
        if hits.len() >= limit {
            break;
        }
        let cached = cache.and_then(|cache| cache.get(&node.path));
        let parsed = cached
            .as_ref()
            .and_then(|summary| summary.analysis.clone())
            .map(Some)
            .unwrap_or_else(|| analyze_node(node).unwrap_or(None));
        if let Some(mut analysis) = parsed {
            resolve_dependencies(&mut analysis, artifact);
            if cached.is_none()
                && let Some(cache) = cache
            {
                let _ = cache.insert(
                    &node.path,
                    FileSummary {
                        size: node.size,
                        sha256: None,
                        sha1: None,
                        md5: None,
                        entropy: None,
                        analysis: Some(analysis.clone()),
                    },
                );
            }
            for dependency in &analysis.dependencies {
                push_hit(
                    &mut hits,
                    limit,
                    node,
                    "Dependency",
                    &dependency.name,
                    &format!("{:?}", dependency.status),
                    &needle,
                );
            }
            for symbol in analysis
                .imports
                .iter()
                .chain(&analysis.exports)
                .chain(&analysis.symbols)
            {
                push_hit(
                    &mut hits,
                    limit,
                    node,
                    "Symbol",
                    &symbol.name,
                    symbol.library.as_deref().unwrap_or(""),
                    &needle,
                );
            }
            for (key, value) in &analysis.metadata {
                push_hit(&mut hits, limit, node, "Metadata", value, key, &needle);
            }
            for finding in &analysis.findings {
                push_hit(
                    &mut hits,
                    limit,
                    node,
                    "Finding",
                    &finding.title,
                    &finding.description,
                    &needle,
                );
            }
        }
        if let Ok(metadata) = inspect_metadata(node) {
            for (key, value) in metadata {
                push_hit(&mut hits, limit, node, "Metadata", &value, &key, &needle);
            }
        }
        if node.size <= 128 * 1024 * 1024
            && let Ok(strings) = extract_strings_node_cancellable(node, 4, 10_000, cancel)
        {
            for string in strings {
                push_hit(
                    &mut hits,
                    limit,
                    node,
                    "String",
                    &string.value,
                    &format!("0x{:x} {:?}", string.offset, string.encoding),
                    &needle,
                );
            }
        }
        if hits.len() >= limit {
            break;
        }
    }
    Ok(hits)
}

fn push_hit(
    hits: &mut Vec<SearchHit>,
    limit: usize,
    node: &ArtifactNode,
    category: &'static str,
    value: &str,
    detail: &str,
    needle: &str,
) {
    if hits.len() < limit
        && (value.to_lowercase().contains(needle) || detail.to_lowercase().contains(needle))
    {
        hits.push(SearchHit {
            node_id: node.id,
            path: node.path.clone(),
            category,
            value: value.chars().take(4096).collect(),
            detail: detail.chars().take(4096).collect(),
        });
    }
}
fn is_ascii(b: u8) -> bool {
    (0x20..=0x7e).contains(&b) || b == b'\t'
}

pub struct HexReader {
    reader: ArtifactReader,
}
impl HexReader {
    pub fn open(path: &Path) -> Result<Self> {
        let node = ArtifactNode::new(
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("artifact"),
            path.to_path_buf(),
            ArtifactKind::Unknown,
        );
        Self::open_node(&node)
    }
    pub fn open_node(node: &ArtifactNode) -> Result<Self> {
        Ok(Self {
            reader: ArtifactReader::open(node)?,
        })
    }
    pub fn len(&self) -> u64 {
        self.reader.len()
    }
    pub fn is_empty(&self) -> bool {
        self.reader.is_empty()
    }
    pub fn read_chunk(&mut self, offset: u64, length: usize) -> Result<Vec<u8>> {
        self.reader.read_range(offset, length)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    path: PathBuf,
    size: u64,
    modified: Option<SystemTime>,
}
#[derive(Default, Clone)]
pub struct AnalysisCache(Arc<RwLock<HashMap<CacheKey, Arc<FileSummary>>>>);
impl AnalysisCache {
    fn key(path: &Path) -> std::io::Result<CacheKey> {
        let m = std::fs::metadata(path)?;
        Ok(CacheKey {
            path: path.into(),
            size: m.len(),
            modified: m.modified().ok(),
        })
    }
    pub fn get(&self, path: &Path) -> Option<Arc<FileSummary>> {
        Self::key(path)
            .ok()
            .and_then(|k| self.0.read().get(&k).cloned())
    }
    pub fn insert(&self, path: &Path, value: FileSummary) -> std::io::Result<Arc<FileSummary>> {
        let key = Self::key(path)?;
        let value = Arc::new(value);
        let mut cache = self.0.write();
        cache.retain(|existing, _| existing.path != key.path);
        cache.insert(key, value.clone());
        Ok(value)
    }
    pub fn clear(&self) {
        self.0.write().clear();
    }

    pub fn snapshots_for_artifact(
        &self,
        artifact: &ArtifactNode,
    ) -> indexmap::IndexMap<String, AnalysisSnapshot> {
        artifact
            .files()
            .filter_map(|node| {
                self.get(&node.path).map(|summary| {
                    (
                        node.path.display().to_string(),
                        AnalysisSnapshot {
                            size: node.size,
                            modified: node.modified,
                            summary: (*summary).clone(),
                        },
                    )
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write, process::Command};
    #[test]
    fn entropy_bounds() {
        assert_eq!(entropy(&[]), 0.0);
        assert_eq!(entropy(&[7; 100]), 0.0);
        assert!((entropy(&(0u8..=255).collect::<Vec<_>>()) - 8.0).abs() < 0.0001);
    }

    #[test]
    fn section_entropy_is_lazy_and_computed_on_demand() {
        let path = std::env::current_exe().expect("current executable");
        let node = build_file_node(&path).expect("build executable node");
        let mut analysis = analyze_node(&node)
            .expect("lightweight analysis")
            .expect("binary analysis");
        assert!(
            analysis
                .sections
                .iter()
                .chain(
                    analysis
                        .slice_analyses
                        .iter()
                        .flat_map(|slice| slice.sections.iter())
                )
                .all(|section| section.entropy.is_none())
        );
        enrich_analysis_entropy(&path, &mut analysis, &CancellationToken::default())
            .expect("on-demand section entropy");
        assert!(
            analysis
                .sections
                .iter()
                .chain(
                    analysis
                        .slice_analyses
                        .iter()
                        .flat_map(|slice| slice.sections.iter())
                )
                .any(|section| section.entropy.is_some())
        );
    }

    #[test]
    fn deep_signature_results_replace_static_signature_findings() {
        let mut analysis = BinaryAnalysis {
            platform: Some(BinaryPlatform::MacOs),
            signature: Some(SignatureInfo {
                status: SignatureStatus::Unsigned,
                signer: None,
                identifier: None,
                team_id: None,
                timestamp: None,
                platform: indexmap::IndexMap::new(),
            }),
            ..Default::default()
        };
        add_findings(&mut analysis);
        assert!(
            analysis
                .findings
                .iter()
                .any(|finding| finding.title == "Unsigned executable")
        );
        let invalid = SignatureInfo {
            status: SignatureStatus::Invalid,
            signer: None,
            identifier: None,
            team_id: None,
            timestamp: None,
            platform: indexmap::IndexMap::new(),
        };
        apply_signature_analysis(&mut analysis, &invalid);
        assert!(
            !analysis
                .findings
                .iter()
                .any(|finding| finding.title == "Unsigned executable")
        );
        assert_eq!(
            analysis
                .findings
                .iter()
                .filter(|finding| finding.title == "Invalid code signature")
                .count(),
            1
        );
    }
    #[test]
    fn analysis_cache_is_reused_and_invalidated_by_file_identity() {
        let source = std::env::current_exe().expect("current executable");
        let path = std::env::temp_dir().join(format!("bytetrawl-cache-{}", uuid::Uuid::new_v4()));
        std::fs::copy(source, &path).expect("copy cache fixture");
        let node = build_file_node(&path).expect("build cache fixture node");
        let cache = AnalysisCache::default();
        let _hits = global_search_cached(
            &node,
            "definitely-not-present",
            &CancellationToken::default(),
            100,
            &cache,
        )
        .expect("cached search");
        assert!(
            cache
                .get(&path)
                .and_then(|summary| summary.analysis.clone())
                .is_some(),
            "binary analysis should be cached during global search"
        );

        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open cache fixture for mutation");
        file.write_all(&[0]).expect("mutate cache fixture");
        assert!(
            cache.get(&path).is_none(),
            "changed size must invalidate cache"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn workspace_snapshots_include_every_cached_artifact_file() {
        let root = std::env::temp_dir().join(format!(
            "bytetrawl-workspace-cache-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&root).expect("create cache artifact");
        for name in ["first.bin", "second.bin"] {
            std::fs::write(root.join(name), name).expect("write cache artifact file");
        }
        let artifact = open_artifact(&root, &CancellationToken::default()).expect("open artifact");
        let cache = AnalysisCache::default();
        for node in artifact.files() {
            cache
                .insert(
                    &node.path,
                    FileSummary {
                        size: node.size,
                        sha256: None,
                        sha1: None,
                        md5: None,
                        entropy: None,
                        analysis: None,
                    },
                )
                .expect("cache artifact file");
        }
        assert_eq!(cache.snapshots_for_artifact(&artifact).len(), 2);
        let _ = std::fs::remove_dir_all(root);
    }
    #[test]
    fn strings_have_offsets() {
        let s = extract_strings(b"\0hello world\0x", 4, 10);
        assert_eq!(s[0].offset, 1);
        assert_eq!(s[0].value, "hello world");
    }
    #[test]
    fn extracts_non_ascii_utf8() {
        let strings = extract_strings("prefix\0你好世界\0".as_bytes(), 4, 10);
        assert!(
            strings
                .iter()
                .any(|item| item.encoding == StringEncoding::Utf8 && item.value == "你好世界")
        );
    }
    #[test]
    fn strings_are_mapped_to_section_and_virtual_address() {
        let mut strings = extract_strings(b"xxxx\0hello", 5, 10);
        let analysis = BinaryAnalysis {
            sections: vec![SectionInfo {
                name: ".data".into(),
                address: 0x2000,
                offset: 5,
                size: 5,
                flags: "RW-".into(),
                entropy: None,
            }],
            ..Default::default()
        };
        annotate_string_locations(&mut strings, &analysis);
        let hello = strings
            .iter()
            .find(|string| string.value.contains("hello"))
            .expect("string");
        assert_eq!(hello.section.as_deref(), Some(".data"));
        assert_eq!(hello.virtual_address, Some(0x2000));
    }
    #[test]
    fn searches_across_chunk_boundary() {
        let path = std::env::temp_dir().join(format!("bytetrawl-search-{}", uuid::Uuid::new_v4()));
        let mut data = vec![b'x'; 1024 * 1024 - 2];
        data.extend_from_slice(b"needle");
        std::fs::write(&path, data).expect("write search fixture");
        let found =
            search_file(&path, b"needle", 0, &CancellationToken::default()).expect("search");
        assert_eq!(found, Some((1024 * 1024 - 2) as u64));
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn cancelled_string_scan_stops() {
        let path = std::env::temp_dir().join(format!("bytetrawl-strings-{}", uuid::Uuid::new_v4()));
        std::fs::write(&path, vec![b'A'; 2 * 1024 * 1024]).expect("write strings fixture");
        let cancel = CancellationToken::default();
        cancel.cancel();
        let result = extract_strings_file_cancellable(&path, 4, 10_000, &cancel);
        assert!(matches!(result, Err(ByteTrawlError::Cancelled)));
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn directory_becomes_a_logical_artifact_tree() {
        let root = std::env::temp_dir().join(format!("bytetrawl-tree-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).expect("create artifact fixture");
        let mut pe_header = vec![0u8; 0x84];
        pe_header[..2].copy_from_slice(b"MZ");
        pe_header[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe_header[0x80..0x84].copy_from_slice(b"PE\0\0");
        std::fs::write(root.join("app.exe"), &pe_header).expect("write executable fixture");
        std::fs::write(root.join("helper.dll"), &pe_header).expect("write library fixture");
        std::fs::write(root.join("config.json"), b"{\"name\":\"fixture\"}")
            .expect("write metadata fixture");
        let artifact = open_artifact(&root, &CancellationToken::default()).expect("open artifact");
        assert_eq!(artifact.kind, ArtifactKind::Application);
        let groups: HashSet<_> = artifact
            .children
            .iter()
            .map(|node| node.name.as_str())
            .collect();
        assert!(groups.contains("Executables"));
        assert!(groups.contains("Dynamic Libraries"));
        assert!(groups.contains("Metadata"));
        assert!(
            artifact
                .children
                .iter()
                .all(|node| node.kind == ArtifactKind::Group)
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn bundle_kinds_require_structure_and_can_be_inferred_without_extensions() {
        let root =
            std::env::temp_dir().join(format!("bytetrawl-bundle-kind-{}", uuid::Uuid::new_v4()));
        let fake = root.join("Fake.app");
        let structural = root.join("NoExtension");
        std::fs::create_dir_all(&fake).expect("create fake app directory");
        std::fs::create_dir_all(structural.join("Contents/MacOS"))
            .expect("create structural app layout");
        std::fs::write(structural.join("Contents/Info.plist"), b"bplist00")
            .expect("write structural app metadata");

        assert_eq!(classify_directory(&fake), ArtifactKind::Directory);
        assert_eq!(classify_directory(&structural), ArtifactKind::Application);
        let _ = std::fs::remove_dir_all(root);
    }
    #[cfg(unix)]
    #[test]
    fn directory_discovery_does_not_follow_symbolic_links() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "bytetrawl-symlink-artifact-{}",
            uuid::Uuid::new_v4()
        ));
        let outside =
            std::env::temp_dir().join(format!("bytetrawl-symlink-target-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("create artifact directory");
        std::fs::write(&outside, b"outside artifact").expect("write outside target");
        let link = root.join("untrusted-link");
        symlink(&outside, &link).expect("create symbolic link");

        let artifact = open_artifact(&root, &CancellationToken::default())
            .expect("discover artifact containing symlink");
        assert!(
            artifact.files().all(|node| node.path != link),
            "symbolic links must not enter the logical Artifact Tree"
        );
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_file(outside);
    }
    #[test]
    fn dependency_graph_survives_a_malformed_binary() {
        let root = std::env::temp_dir().join(format!("bytetrawl-graph-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).expect("create graph fixture");
        std::fs::write(root.join("broken.exe"), b"MZtruncated").expect("write malformed binary");
        let artifact = open_artifact(&root, &CancellationToken::default())
            .expect("discover malformed artifact");
        let graph = build_dependency_graph(&artifact, &CancellationToken::default())
            .expect("build partial graph");
        assert!(graph.nodes.iter().any(|node| node.name == "broken.exe"));
        assert!(graph.edges.is_empty());
        let _ = std::fs::remove_dir_all(root);
    }
    #[test]
    fn bundled_dependencies_resolve_to_artifact_nodes_idempotently() {
        let root_path = PathBuf::from("/fixture");
        let mut artifact = ArtifactNode::new("fixture", root_path.clone(), ArtifactKind::Directory);
        let library = ArtifactNode::new(
            "helper.dll",
            root_path.join("helper.dll"),
            ArtifactKind::DynamicLibrary,
        );
        artifact.children.push(library.clone());
        let mut analysis = BinaryAnalysis {
            dependencies: vec![Dependency {
                name: "helper.dll".into(),
                path: None,
                status: DependencyStatus::Unknown,
            }],
            ..Default::default()
        };
        resolve_dependencies(&mut analysis, &artifact);
        resolve_dependencies(&mut analysis, &artifact);
        assert!(matches!(
            analysis.dependencies[0].status,
            DependencyStatus::Bundled
        ));
        assert_eq!(analysis.dependencies[0].path.as_ref(), Some(&library.path));
        assert!(analysis.findings.is_empty());
    }

    #[test]
    fn dependency_resolution_uses_target_platform_semantics() {
        let artifact = ArtifactNode::new(
            "portable",
            PathBuf::from("/artifact"),
            ArtifactKind::Application,
        );
        let mut windows = BinaryAnalysis {
            platform: Some(BinaryPlatform::Windows),
            dependencies: vec![
                Dependency {
                    name: "KERNEL32.dll".into(),
                    path: None,
                    status: DependencyStatus::Unknown,
                },
                Dependency {
                    name: "not-bundled.dll".into(),
                    path: None,
                    status: DependencyStatus::Unknown,
                },
            ],
            ..Default::default()
        };
        resolve_dependencies(&mut windows, &artifact);
        assert!(matches!(
            windows.dependencies[0].status,
            DependencyStatus::System
        ));
        assert!(matches!(
            windows.dependencies[1].status,
            DependencyStatus::Missing
        ));
        assert!(
            windows
                .findings
                .iter()
                .any(|finding| { finding.title == "Missing dependency: not-bundled.dll" })
        );

        let mut linux = BinaryAnalysis {
            platform: Some(BinaryPlatform::Linux),
            dependencies: vec![Dependency {
                name: "libtarget-specific.so.1".into(),
                path: None,
                status: DependencyStatus::Unknown,
            }],
            ..Default::default()
        };
        resolve_dependencies(&mut linux, &artifact);
        assert!(matches!(
            linux.dependencies[0].status,
            DependencyStatus::Unknown
        ));
    }
    #[test]
    fn zip_listing_flags_traversal_without_extracting() {
        let path = std::env::temp_dir().join(format!("bytetrawl-zip-{}.zip", uuid::Uuid::new_v4()));
        let escaped_name = format!("bytetrawl-escape-{}.txt", uuid::Uuid::new_v4());
        let escaped_path = path.with_file_name(&escaped_name);
        let file = File::create(&path).expect("create zip fixture");
        let mut writer = zip::ZipWriter::new(file);
        writer
            .start_file(
                format!("../{escaped_name}"),
                zip::write::SimpleFileOptions::default(),
            )
            .expect("start zip entry");
        writer.write_all(b"not extracted").expect("write zip entry");
        writer.finish().expect("finish zip fixture");
        let node = build_file_node(&path).expect("build zip node");
        let metadata = inspect_metadata(&node).expect("inspect zip");
        assert_eq!(metadata.get("Unsafe Paths").map(String::as_str), Some("1"));
        assert!(!escaped_path.exists());
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn zip_bomb_indicator_is_detected_from_central_directory_only() {
        let path = std::env::temp_dir().join(format!(
            "bytetrawl-compression-ratio-{}.zip",
            uuid::Uuid::new_v4()
        ));
        let file = File::create(&path).expect("create compressed fixture");
        let mut writer = zip::ZipWriter::new(file);
        writer
            .start_file(
                "repeated.bin",
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated),
            )
            .expect("start compressed entry");
        writer
            .write_all(&vec![0u8; 4 * 1024 * 1024])
            .expect("write repeated bytes");
        writer.finish().expect("finish compressed fixture");

        let node = build_file_node(&path).expect("build compressed ZIP node");
        let metadata = inspect_metadata(&node).expect("inspect compressed ZIP");
        assert!(
            metadata
                .get("Static Safety Assessment")
                .is_some_and(|assessment| assessment.contains("Review required")),
            "high expansion ratio should require review: {metadata:?}"
        );
        assert_eq!(
            metadata.get("Uncompressed Size").map(String::as_str),
            Some("4194304")
        );
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn reads_bounded_image_and_sqlite_headers() {
        let png_path =
            std::env::temp_dir().join(format!("bytetrawl-image-{}.png", uuid::Uuid::new_v4()));
        let mut png = vec![0u8; 24];
        png[..8].copy_from_slice(b"\x89PNG\r\n\x1a\n");
        png[16..20].copy_from_slice(&640u32.to_be_bytes());
        png[20..24].copy_from_slice(&480u32.to_be_bytes());
        std::fs::write(&png_path, png).expect("write PNG fixture");
        let png_node = build_file_node(&png_path).expect("build PNG node");
        let png_metadata = inspect_metadata(&png_node).expect("inspect PNG");
        assert_eq!(png_metadata.get("Width").map(String::as_str), Some("640"));
        assert_eq!(png_metadata.get("Height").map(String::as_str), Some("480"));

        let sqlite_path =
            std::env::temp_dir().join(format!("bytetrawl-db-{}.sqlite", uuid::Uuid::new_v4()));
        let mut sqlite = vec![0u8; 100];
        sqlite[..16].copy_from_slice(b"SQLite format 3\0");
        sqlite[16..18].copy_from_slice(&4096u16.to_be_bytes());
        sqlite[56..60].copy_from_slice(&1u32.to_be_bytes());
        std::fs::write(&sqlite_path, sqlite).expect("write SQLite fixture");
        let sqlite_node = build_file_node(&sqlite_path).expect("build SQLite node");
        let sqlite_metadata = inspect_metadata(&sqlite_node).expect("inspect SQLite");
        assert_eq!(
            sqlite_metadata.get("Page Size").map(String::as_str),
            Some("4096")
        );
        assert_eq!(
            sqlite_metadata.get("Text Encoding").map(String::as_str),
            Some("UTF-8")
        );
        let _ = std::fs::remove_file(png_path);
        let _ = std::fs::remove_file(sqlite_path);
    }
    #[test]
    fn disk_images_are_identified_by_structure_and_inspected_without_mounting() {
        let dmg_path = std::env::temp_dir().join(format!(
            "bytetrawl-dmg-no-extension-{}",
            uuid::Uuid::new_v4()
        ));
        udif::DmgBuilder::new()
            .add_partition("Apple_HFS", vec![0x5a; 16 * 1024])
            .build(&dmg_path)
            .expect("build DMG fixture");
        let dmg_node = build_file_node(&dmg_path).expect("identify DMG fixture");
        assert_eq!(dmg_node.kind, ArtifactKind::DiskImage);
        assert_eq!(dmg_node.format, Some(FileFormat::DiskImage));
        let dmg_metadata = inspect_metadata(&dmg_node).expect("inspect DMG fixture");
        assert_eq!(
            dmg_metadata.get("Disk Image Format").map(String::as_str),
            Some("Apple UDIF / DMG")
        );
        assert_eq!(
            dmg_metadata.get("Partition Count").map(String::as_str),
            Some("1")
        );
        assert!(
            dmg_metadata
                .get("Inspection Mode")
                .is_some_and(|mode| mode.contains("did not mount or extract"))
        );

        let iso_path = std::env::temp_dir().join(format!(
            "bytetrawl-iso-no-extension-{}",
            uuid::Uuid::new_v4()
        ));
        let mut iso = vec![0u8; 18 * 2048];
        let descriptor = &mut iso[16 * 2048..17 * 2048];
        descriptor[0] = 1;
        descriptor[1..6].copy_from_slice(b"CD001");
        descriptor[6] = 1;
        descriptor[40..56].copy_from_slice(b"BYTETRAWL TEST  ");
        descriptor[80..84].copy_from_slice(&18u32.to_le_bytes());
        descriptor[128..130].copy_from_slice(&2048u16.to_le_bytes());
        std::fs::write(&iso_path, iso).expect("write ISO fixture");
        let iso_node = build_file_node(&iso_path).expect("identify ISO fixture");
        assert_eq!(iso_node.kind, ArtifactKind::DiskImage);
        assert_eq!(iso_node.format, Some(FileFormat::DiskImage));
        let iso_metadata = inspect_metadata(&iso_node).expect("inspect ISO fixture");
        assert_eq!(
            iso_metadata.get("Disk Image Format").map(String::as_str),
            Some("ISO 9660")
        );

        let _ = std::fs::remove_file(dmg_path);
        let _ = std::fs::remove_file(iso_path);
    }
    #[test]
    fn ar_and_tar_member_tables_are_inspected_without_extraction() {
        let ar_path = std::env::temp_dir().join(format!("bytetrawl-{}.a", uuid::Uuid::new_v4()));
        let payload = b"object bytes";
        let mut ar = b"!<arch>\n".to_vec();
        let header = format!(
            "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
            "member.o/",
            "0",
            "0",
            "0",
            "100644",
            payload.len()
        );
        assert_eq!(header.len(), 60);
        ar.extend_from_slice(header.as_bytes());
        ar.extend_from_slice(payload);
        if !ar.len().is_multiple_of(2) {
            ar.push(b'\n');
        }
        std::fs::write(&ar_path, ar).expect("write ar fixture");
        let ar_node = build_file_node(&ar_path).expect("identify ar fixture");
        assert_eq!(ar_node.kind, ArtifactKind::StaticLibrary);
        let ar_metadata = inspect_metadata(&ar_node).expect("inspect ar fixture");
        assert_eq!(
            ar_metadata.get("Member Count").map(String::as_str),
            Some("1")
        );
        assert!(ar_metadata.values().any(|value| value.contains("member.o")));

        let tar_path = std::env::temp_dir().join(format!("bytetrawl-{}.tar", uuid::Uuid::new_v4()));
        let file = File::create(&tar_path).expect("create tar fixture");
        let mut builder = tar::Builder::new(file);
        let mut tar_header = tar::Header::new_gnu();
        tar_header.set_size(payload.len() as u64);
        tar_header.set_mode(0o644);
        tar_header.set_cksum();
        builder
            .append_data(&mut tar_header, "folder/member.bin", payload.as_slice())
            .expect("append tar member");
        builder.finish().expect("finish tar fixture");
        drop(builder);
        let tar_node = build_file_node(&tar_path).expect("identify tar fixture");
        let tar_metadata = inspect_metadata(&tar_node).expect("inspect tar fixture");
        assert_eq!(
            tar_metadata.get("Entry Count").map(String::as_str),
            Some("1")
        );
        assert!(
            tar_metadata
                .values()
                .any(|value| value.contains("folder/member.bin"))
        );

        let _ = std::fs::remove_file(ar_path);
        let _ = std::fs::remove_file(tar_path);
    }
    #[test]
    fn xar_toc_limits_are_checked_before_third_party_parsing() {
        let path = std::env::temp_dir().join(format!("bytetrawl-{}.pkg", uuid::Uuid::new_v4()));
        let mut header = Vec::with_capacity(28);
        header.extend_from_slice(b"xar!");
        header.extend_from_slice(&28u16.to_be_bytes());
        header.extend_from_slice(&1u16.to_be_bytes());
        header.extend_from_slice(&0u64.to_be_bytes());
        header.extend_from_slice(&u64::MAX.to_be_bytes());
        header.extend_from_slice(&1u32.to_be_bytes());
        std::fs::write(&path, header).expect("write hostile XAR fixture");
        let node = build_file_node(&path).expect("identify hostile XAR fixture");
        assert_eq!(node.kind, ArtifactKind::Package);
        assert!(matches!(
            inspect_metadata(&node),
            Err(ByteTrawlError::Limit(_))
        ));
        let _ = std::fs::remove_file(path);
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn real_xar_package_table_is_listed_when_system_xar_is_available() {
        let xar = Path::new("/usr/bin/xar");
        if !xar.is_file() {
            return;
        }
        let root =
            std::env::temp_dir().join(format!("bytetrawl-xar-source-{}", uuid::Uuid::new_v4()));
        let package =
            std::env::temp_dir().join(format!("bytetrawl-xar-{}.pkg", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("create XAR source");
        std::fs::write(
            root.join("PackageInfo"),
            b"<pkg-info identifier=\"dev.bytetrawl.test\"/>",
        )
        .expect("write XAR member");
        let status = Command::new(xar)
            .current_dir(&root)
            .args(["-cf"])
            .arg(&package)
            .arg("PackageInfo")
            .status()
            .expect("run system xar");
        assert!(status.success());
        let node = build_file_node(&package).expect("identify XAR package");
        let metadata = inspect_metadata(&node).expect("inspect XAR package");
        assert_eq!(
            metadata.get("Archive Format").map(String::as_str),
            Some("Apple XAR / flat PKG")
        );
        assert!(metadata.values().any(|value| value.contains("PackageInfo")));
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_file(package);
    }
    #[test]
    fn rejects_oversized_structured_metadata_before_parsing() {
        let path =
            std::env::temp_dir().join(format!("bytetrawl-large-{}.json", uuid::Uuid::new_v4()));
        let file = File::create(&path).expect("create sparse metadata fixture");
        file.set_len(MAX_STRUCTURED_METADATA_BYTES + 1)
            .expect("size sparse metadata fixture");
        let mut node = ArtifactNode::new("large.json", path.clone(), ArtifactKind::Metadata);
        node.format = Some(FileFormat::Json);
        node.size = MAX_STRUCTURED_METADATA_BYTES + 1;
        assert!(matches!(
            inspect_metadata(&node),
            Err(ByteTrawlError::Limit(_))
        ));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn ipa_zip_opens_as_a_virtual_member_tree_without_extraction() {
        let path =
            std::env::temp_dir().join(format!("bytetrawl-virtual-{}.ipa", uuid::Uuid::new_v4()));
        let file = File::create(&path).expect("create IPA fixture");
        let mut writer = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        writer
            .start_file("Payload/Example.app/Info.plist", options)
            .expect("start Info.plist entry");
        writer
            .write_all(
                br#"<?xml version="1.0" encoding="UTF-8"?>
                <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
                <plist version="1.0"><dict>
                <key>CFBundleIdentifier</key><string>app.xnu.ByteTrawlFixture</string>
                <key>CFBundleExecutable</key><string>Example</string>
                </dict></plist>"#,
            )
            .expect("write Info.plist entry");
        writer
            .start_file("Payload/Example.app/Example", options)
            .expect("start executable entry");
        writer
            .write_all(b"virtual-member-bytes")
            .expect("write executable entry");
        writer
            .start_file("../escape", options)
            .expect("start unsafe entry");
        writer.write_all(b"unsafe").expect("write unsafe entry");
        writer.finish().expect("finish IPA fixture");

        let artifact =
            open_artifact(&path, &CancellationToken::default()).expect("open virtual IPA artifact");
        assert_eq!(
            artifact
                .properties
                .get("Package Format")
                .map(String::as_str),
            Some("Apple iOS IPA")
        );
        let payload = artifact
            .children
            .iter()
            .find(|node| node.name == "Payload")
            .expect("Payload virtual directory");
        let app = payload
            .children
            .iter()
            .find(|node| node.name == "Example.app")
            .expect("application virtual directory");
        assert_eq!(app.kind, ArtifactKind::Application);
        let executable = app
            .children
            .iter()
            .find(|node| node.name == "Example")
            .expect("virtual executable member");
        assert!(executable.is_file());
        assert!(artifact.children.iter().all(|node| node.name != "escape"));

        let info_plist = app
            .children
            .iter()
            .find(|node| node.name == "Info.plist")
            .expect("virtual Info.plist member");
        let metadata = inspect_metadata(info_plist).expect("inspect virtual plist metadata");
        assert_eq!(
            metadata.get("CFBundleIdentifier").map(String::as_str),
            Some("app.xnu.ByteTrawlFixture")
        );
        assert_eq!(
            metadata.get("Source").map(String::as_str),
            Some("Virtual archive member; no extraction performed")
        );

        let reader = ArtifactReader::open(executable).expect("open archive member reader");
        assert_eq!(reader.len(), 20);
        assert_eq!(
            reader.read_prefix(7).expect("read member prefix"),
            b"virtual"
        );
        assert_eq!(
            reader.read_range(8, 6).expect("read member range"),
            b"member"
        );
        assert!(matches!(reader.read_all(8), Err(ByteTrawlError::Limit(_))));
        assert_eq!(
            search_node(executable, b"member", 0, &CancellationToken::default())
                .expect("search virtual member"),
            Some(8)
        );
        let strings =
            extract_strings_node_cancellable(executable, 4, 10, &CancellationToken::default())
                .expect("extract strings from virtual member");
        assert!(
            strings
                .iter()
                .any(|string| string.value == "virtual-member-bytes")
        );
        let mut hex = HexReader::open_node(executable).expect("open virtual member hex reader");
        assert_eq!(
            hex.read_chunk(8, 6).expect("read virtual member hex chunk"),
            b"member"
        );

        std::fs::remove_file(path).expect("remove IPA fixture");
    }

    #[test]
    fn cancelled_zip_discovery_stops_before_member_enumeration() {
        let path =
            std::env::temp_dir().join(format!("bytetrawl-cancel-{}.zip", uuid::Uuid::new_v4()));
        let file = File::create(&path).expect("create ZIP fixture");
        let mut writer = zip::ZipWriter::new(file);
        writer
            .start_file("member.txt", zip::write::SimpleFileOptions::default())
            .expect("start ZIP member");
        writer.write_all(b"content").expect("write ZIP member");
        writer.finish().expect("finish ZIP fixture");
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        assert!(matches!(
            open_artifact(&path, &cancellation),
            Err(ByteTrawlError::Cancelled)
        ));
        std::fs::remove_file(path).expect("remove ZIP fixture");
    }
}
