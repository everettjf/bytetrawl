//! Host-independent domain model for ByteTrawl.

use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Group,
    Application,
    Directory,
    Bundle,
    Executable,
    DynamicLibrary,
    StaticLibrary,
    Framework,
    Plugin,
    Resource,
    Metadata,
    Package,
    Archive,
    DiskImage,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileFormat {
    Pe,
    MachO,
    FatMachO,
    Elf,
    Archive,
    Zip,
    Json,
    Xml,
    Plist,
    Sqlite,
    Image,
    DiskImage,
    Text,
    UnknownBinary,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ArtifactSource {
    Filesystem {
        path: PathBuf,
    },
    ArchiveMember {
        container: PathBuf,
        member_path: PathBuf,
        entry_index: usize,
        compressed_size: u64,
        uncompressed_size: u64,
        crc32: u32,
        is_directory: bool,
    },
}

impl ArtifactSource {
    pub fn is_file(&self) -> bool {
        match self {
            Self::Filesystem { path } => path.is_file(),
            Self::ArchiveMember { is_directory, .. } => !is_directory,
        }
    }

    pub fn is_dir(&self) -> bool {
        match self {
            Self::Filesystem { path } => path.is_dir(),
            Self::ArchiveMember { is_directory, .. } => *is_directory,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinaryPlatform {
    Windows,
    MacOs,
    Linux,
    Unix,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactNode {
    pub id: Uuid,
    pub name: String,
    pub path: PathBuf,
    #[serde(default)]
    pub source: Option<ArtifactSource>,
    pub kind: ArtifactKind,
    pub format: Option<FileFormat>,
    pub size: u64,
    pub modified: Option<DateTime<Utc>>,
    pub children: Vec<ArtifactNode>,
    pub properties: IndexMap<String, String>,
}

impl ArtifactNode {
    pub fn new(name: impl Into<String>, path: PathBuf, kind: ArtifactKind) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            source: Some(ArtifactSource::Filesystem { path: path.clone() }),
            path,
            kind,
            format: None,
            size: 0,
            modified: None,
            children: Vec::new(),
            properties: IndexMap::new(),
        }
    }
    pub fn find(&self, id: Uuid) -> Option<&Self> {
        if self.id == id {
            return Some(self);
        }
        self.children.iter().find_map(|child| child.find(id))
    }
    pub fn files(&self) -> impl Iterator<Item = &ArtifactNode> {
        let mut nodes = Vec::new();
        self.collect_files(&mut nodes);
        nodes.into_iter()
    }
    pub fn is_file(&self) -> bool {
        match self.source.as_ref() {
            Some(ArtifactSource::ArchiveMember { is_directory, .. }) => !is_directory,
            Some(ArtifactSource::Filesystem { path }) => !path.is_dir(),
            None => !self.path.is_dir(),
        }
    }
    pub fn is_dir(&self) -> bool {
        self.source
            .as_ref()
            .map(ArtifactSource::is_dir)
            .unwrap_or_else(|| self.path.is_dir())
    }
    fn collect_files<'a>(&'a self, out: &mut Vec<&'a ArtifactNode>) {
        if self.is_file() {
            out.push(self);
        }
        for child in &self.children {
            child.collect_files(out);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingCategory {
    Signature,
    Dependency,
    MemorySafety,
    Entropy,
    DebugInfo,
    PathSecurity,
    Metadata,
    Format,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub label: String,
    pub value: String,
    pub offset: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locator: Option<EvidenceLocator>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EvidenceLocator {
    File {
        path: PathBuf,
        offset: Option<u64>,
        length: Option<u64>,
    },
    ArchiveMember {
        container: PathBuf,
        member_path: PathBuf,
        offset: Option<u64>,
        length: Option<u64>,
    },
    StructuredField {
        source: PathBuf,
        field: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub category: FindingCategory,
    pub title: String,
    pub description: String,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DependencyStatus {
    Bundled,
    System,
    Missing,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    pub name: String,
    pub path: Option<PathBuf>,
    pub status: DependencyStatus,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DependencyGraph {
    pub nodes: Vec<DependencyGraphNode>,
    pub edges: Vec<DependencyGraphEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyGraphNode {
    pub artifact_id: Uuid,
    pub name: String,
    pub path: PathBuf,
    pub format: Option<FileFormat>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyGraphEdge {
    pub source: Uuid,
    pub source_architecture: Option<String>,
    pub target: Option<Uuid>,
    pub requested: String,
    pub resolved_path: Option<PathBuf>,
    pub status: DependencyStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    pub name: String,
    pub address: u64,
    pub offset: u64,
    pub size: u64,
    pub flags: String,
    pub entropy: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentInfo {
    pub name: String,
    pub address: u64,
    pub virtual_size: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub protections: String,
    pub section_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolInfo {
    pub name: String,
    pub address: Option<u64>,
    pub library: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SliceInfo {
    pub architecture: String,
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelocationInfo {
    pub offset: u64,
    pub relocation_type: String,
    pub symbol: Option<String>,
    pub addend: Option<i64>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignatureStatus {
    Valid,
    Invalid,
    Unsigned,
    AdHoc,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureInfo {
    pub status: SignatureStatus,
    pub signer: Option<String>,
    pub identifier: Option<String>,
    pub team_id: Option<String>,
    pub timestamp: Option<String>,
    pub platform: IndexMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BinaryAnalysis {
    pub format: Option<FileFormat>,
    pub platform: Option<BinaryPlatform>,
    pub architecture: String,
    pub bits: Option<u8>,
    pub endianness: Option<String>,
    pub entry_point: Option<u64>,
    pub image_base: Option<u64>,
    pub interpreter: Option<String>,
    pub sections: Vec<SectionInfo>,
    pub segments: Vec<SegmentInfo>,
    pub imports: Vec<SymbolInfo>,
    pub exports: Vec<SymbolInfo>,
    pub symbols: Vec<SymbolInfo>,
    pub dependencies: Vec<Dependency>,
    pub slices: Vec<SliceInfo>,
    pub slice_analyses: Vec<BinaryAnalysis>,
    pub relocations: Vec<RelocationInfo>,
    pub headers: IndexMap<String, String>,
    pub metadata: IndexMap<String, String>,
    pub signature: Option<SignatureInfo>,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSummary {
    pub size: u64,
    pub sha256: Option<String>,
    pub sha1: Option<String>,
    pub md5: Option<String>,
    pub entropy: Option<f64>,
    pub analysis: Option<BinaryAnalysis>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisSnapshot {
    pub size: u64,
    pub modified: Option<DateTime<Utc>>,
    pub summary: FileSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workspace {
    pub version: u32,
    pub artifact_path: PathBuf,
    pub bookmarks: Vec<PathBuf>,
    pub notes: IndexMap<String, String>,
    pub selected_path: Option<PathBuf>,
    #[serde(default)]
    pub selected_view: Option<String>,
    #[serde(default)]
    pub tool_configuration: IndexMap<String, String>,
    /// Cached analysis snapshots keyed by their artifact-relative or absolute path.
    /// Consumers must revalidate size and modification time before reuse.
    #[serde(default)]
    pub analysis_results: IndexMap<String, AnalysisSnapshot>,
}

impl Workspace {
    pub fn new(path: PathBuf) -> Self {
        Self {
            version: 1,
            artifact_path: path,
            bookmarks: vec![],
            notes: IndexMap::new(),
            selected_path: None,
            selected_view: None,
            tool_configuration: IndexMap::new(),
            analysis_results: IndexMap::new(),
        }
    }
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let file = std::fs::File::open(path).map_err(|source| ByteTrawlError::Io {
            path: path.into(),
            source,
        })?;
        let workspace: Self = serde_json::from_reader(file)
            .map_err(|error| ByteTrawlError::Malformed(format!("workspace: {error}")))?;
        if workspace.version != 1 {
            return Err(ByteTrawlError::Malformed(format!(
                "unsupported workspace version {}",
                workspace.version
            )));
        }
        Ok(workspace)
    }
    pub fn save(&self, path: &std::path::Path) -> Result<()> {
        let temporary = path.with_extension("bytetrawl-workspace.tmp");
        let file = std::fs::File::create(&temporary).map_err(|source| ByteTrawlError::Io {
            path: temporary.clone(),
            source,
        })?;
        serde_json::to_writer_pretty(file, self)
            .map_err(|error| ByteTrawlError::Malformed(format!("workspace: {error}")))?;
        std::fs::rename(&temporary, path).map_err(|source| ByteTrawlError::Io {
            path: path.into(),
            source,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ByteTrawlError {
    #[error("I/O error while inspecting {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("unsupported or malformed input: {0}")]
    Malformed(String),
    #[error("resource limit exceeded: {0}")]
    Limit(String),
    #[error("analysis cancelled")]
    Cancelled,
}

pub type Result<T> = std::result::Result<T, ByteTrawlError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_round_trip() {
        let path =
            std::env::temp_dir().join(format!("bytetrawl-{}.bytetrawl-workspace", Uuid::new_v4()));
        let mut workspace = Workspace::new(PathBuf::from("/tmp/sample.app"));
        workspace
            .bookmarks
            .push(PathBuf::from("Contents/MacOS/sample"));
        workspace.notes.insert("root".into(), "reviewed".into());
        workspace.analysis_results.insert(
            "/tmp/sample.app/Contents/MacOS/sample".into(),
            AnalysisSnapshot {
                size: 42,
                modified: None,
                summary: FileSummary {
                    size: 42,
                    sha256: Some("abc".into()),
                    sha1: None,
                    md5: None,
                    entropy: Some(1.5),
                    analysis: None,
                },
            },
        );
        workspace.save(&path).expect("save test workspace");
        let loaded = Workspace::load(&path).expect("load test workspace");
        assert_eq!(loaded.artifact_path, workspace.artifact_path);
        assert_eq!(loaded.bookmarks, workspace.bookmarks);
        assert_eq!(loaded.analysis_results.len(), 1);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn artifact_source_and_evidence_locator_round_trip() {
        let mut node = ArtifactNode::new(
            "Info.plist",
            PathBuf::from("sample.ipa!/Payload/Sample.app/Info.plist"),
            ArtifactKind::Metadata,
        );
        node.source = Some(ArtifactSource::ArchiveMember {
            container: PathBuf::from("sample.ipa"),
            member_path: PathBuf::from("Payload/Sample.app/Info.plist"),
            entry_index: 7,
            compressed_size: 128,
            uncompressed_size: 256,
            crc32: 0x1234_abcd,
            is_directory: false,
        });
        let encoded = serde_json::to_vec(&node).expect("serialize archive member node");
        let decoded: ArtifactNode =
            serde_json::from_slice(&encoded).expect("deserialize archive member node");
        assert_eq!(decoded.source, node.source);
        assert!(decoded.is_file());

        let evidence = Evidence {
            label: "Bundle identifier".into(),
            value: "com.example.sample".into(),
            offset: None,
            locator: Some(EvidenceLocator::StructuredField {
                source: node.path.clone(),
                field: "CFBundleIdentifier".into(),
            }),
        };
        let encoded = serde_json::to_vec(&evidence).expect("serialize evidence locator");
        let decoded: Evidence =
            serde_json::from_slice(&encoded).expect("deserialize evidence locator");
        assert_eq!(decoded.locator, evidence.locator);
    }

    #[test]
    fn artifact_nodes_from_older_snapshots_default_to_filesystem_compatibility() {
        let node = ArtifactNode::new(
            "legacy.bin",
            PathBuf::from("/tmp/legacy.bin"),
            ArtifactKind::Unknown,
        );
        let mut value = serde_json::to_value(node).expect("serialize legacy node fixture");
        value
            .as_object_mut()
            .expect("artifact node is a JSON object")
            .remove("source");
        let decoded: ArtifactNode =
            serde_json::from_value(value).expect("deserialize legacy artifact node");
        assert!(decoded.source.is_none());
        assert_eq!(decoded.path, PathBuf::from("/tmp/legacy.bin"));
    }
}
