#![recursion_limit = "512"]

use bytetrawl::file_search::{FileSearchMode, parse_search_bytes};
use bytetrawl_analysis::{
    AnalysisCache, CancellationToken, ExtractedString, HashOptions, HexReader, SearchHit,
    analyze_node, annotate_string_locations, apply_signature_analysis, build_dependency_graph,
    enrich_analysis_entropy, extract_strings_file_cancellable, global_search_cached, hash_file,
    inspect_metadata, inspect_signature_cancellable, open_artifact, resolve_dependencies,
    search_file,
};
use bytetrawl_core::{
    ArtifactKind, ArtifactNode, BinaryAnalysis, BinaryPlatform, DependencyGraph, FileSummary,
    Severity, SignatureInfo, Workspace,
};
use bytetrawl_tools::{ToolAvailability, ToolRegistry};
use gpui::prelude::FluentBuilder;
use gpui::*;
use gpui_component::{
    Disableable, Root, Sizable, StyledExt, Theme, ThemeMode,
    button::Button,
    input::{Copy, Cut, Input, InputEvent, InputState, Paste, Redo, SelectAll, Undo},
};
use std::{path::PathBuf, sync::Arc};

mod theme;

use theme::{
    ACCENT, BACKGROUND as BG, BORDER, DESTRUCTIVE, DESTRUCTIVE_ACTIVE, DESTRUCTIVE_HOVER, HIGH,
    PANEL, PANEL_RAISED as PANEL_2, PRIMARY as GREEN, PRIMARY_ACTIVE, PRIMARY_HOVER, SELECTION,
    TEXT, TEXT_MUTED as MUTED, WARNING,
};

actions!(
    bytetrawl,
    [
        OpenFile,
        OpenArtifact,
        OpenWorkspace,
        SaveWorkspace,
        FocusSearch,
        Quit
    ]
);

#[derive(Clone, Copy, PartialEq, Eq)]
enum InspectorTab {
    Search,
    Slices,
    Overview,
    Headers,
    Sections,
    Segments,
    Relocations,
    Imports,
    Exports,
    Symbols,
    Dependencies,
    DependencyGraph,
    Strings,
    Hex,
    Signature,
    Metadata,
    Findings,
}

impl InspectorTab {
    fn label(self) -> &'static str {
        match self {
            Self::Search => "Search",
            Self::Slices => "Slices",
            Self::Overview => "Overview",
            Self::Headers => "Headers",
            Self::Sections => "Sections",
            Self::Segments => "Segments",
            Self::Relocations => "Relocations",
            Self::Imports => "Imports",
            Self::Exports => "Exports",
            Self::Symbols => "Symbols",
            Self::Dependencies => "Dependencies",
            Self::DependencyGraph => "Dependency Graph",
            Self::Strings => "Strings",
            Self::Hex => "Hex",
            Self::Signature => "Signature",
            Self::Metadata => "Metadata",
            Self::Findings => "Findings",
        }
    }
    fn from_label(label: &str) -> Option<Self> {
        [
            Self::Search,
            Self::Slices,
            Self::Overview,
            Self::Headers,
            Self::Sections,
            Self::Segments,
            Self::Relocations,
            Self::Imports,
            Self::Exports,
            Self::Symbols,
            Self::Dependencies,
            Self::DependencyGraph,
            Self::Strings,
            Self::Hex,
            Self::Signature,
            Self::Metadata,
            Self::Findings,
        ]
        .into_iter()
        .find(|tab| tab.label() == label)
    }
}

struct ByteTrawlApp {
    artifact: Option<Arc<ArtifactNode>>,
    selected: Option<uuid::Uuid>,
    expanded_nodes: std::collections::HashSet<uuid::Uuid>,
    analysis: Option<Arc<BinaryAnalysis>>,
    active_slice: Option<usize>,
    summary: Option<Arc<FileSummary>>,
    metadata: Arc<indexmap::IndexMap<String, String>>,
    container_signature: Option<SignatureInfo>,
    signature_loaded: bool,
    strings: Arc<Vec<ExtractedString>>,
    strings_loaded: bool,
    string_minimum: usize,
    search_hits: Arc<Vec<SearchHit>>,
    dependency_graph: Arc<DependencyGraph>,
    dependency_graph_loaded: bool,
    hex_offset: u64,
    hex_selection: Option<(u64, u64)>,
    search_input: Entity<InputState>,
    note_input: Entity<InputState>,
    query: SharedString,
    file_search_mode: FileSearchMode,
    note_draft: SharedString,
    bookmarks: Vec<PathBuf>,
    notes: indexmap::IndexMap<String, String>,
    pending_workspace: Option<Workspace>,
    restore_tab: Option<InspectorTab>,
    _subscriptions: Vec<Subscription>,
    cancellation: CancellationToken,
    cache: AnalysisCache,
    tools: Arc<ToolRegistry>,
    tool_output: Option<(SharedString, SharedString)>,
    tab: InspectorTab,
    loading: bool,
    task_generation: u64,
    status: SharedString,
    error: Option<SharedString>,
}

impl ByteTrawlApp {
    fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let search_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Search artifact, symbols, strings, or enter hex bytes…")
        });
        let note_input = cx.new(|cx| {
            InputState::new(window, cx).placeholder("Add or replace note for selected node…")
        });
        let search_subscription = cx.subscribe(&search_input, |this, input, event, cx| {
            if matches!(event, InputEvent::Change) {
                this.query = input.read(cx).value();
                cx.notify();
            }
        });
        let note_subscription = cx.subscribe(&note_input, |this, input, event, cx| {
            if matches!(event, InputEvent::Change) {
                this.note_draft = input.read(cx).value();
                cx.notify();
            }
        });
        Self {
            artifact: None,
            selected: None,
            expanded_nodes: std::collections::HashSet::new(),
            analysis: None,
            active_slice: None,
            summary: None,
            metadata: Arc::default(),
            container_signature: None,
            signature_loaded: false,
            strings: Arc::default(),
            strings_loaded: false,
            string_minimum: 4,
            search_hits: Arc::default(),
            dependency_graph: Arc::default(),
            dependency_graph_loaded: false,
            hex_offset: 0,
            hex_selection: None,
            search_input,
            note_input,
            query: "".into(),
            file_search_mode: FileSearchMode::Text,
            note_draft: "".into(),
            bookmarks: Vec::new(),
            notes: indexmap::IndexMap::new(),
            pending_workspace: None,
            restore_tab: None,
            _subscriptions: vec![search_subscription, note_subscription],
            cancellation: CancellationToken::default(),
            cache: AnalysisCache::default(),
            tools: Arc::new(ToolRegistry::standard()),
            tool_output: None,
            tab: InspectorTab::Overview,
            loading: false,
            task_generation: 0,
            status: "Ready — static inspection only".into(),
            error: None,
        }
    }
    fn choose(&mut self, folder: bool, cx: &mut Context<Self>) {
        let path = if folder {
            rfd::FileDialog::new().pick_folder()
        } else {
            rfd::FileDialog::new().pick_file()
        };
        if let Some(path) = path {
            self.load(path, cx)
        }
    }
    fn save_workspace(&mut self, cx: &mut Context<Self>) {
        let Some(root) = self.artifact.as_ref() else {
            return;
        };
        let Some(path) = rfd::FileDialog::new()
            .add_filter("ByteTrawl Workspace", &["bytetrawl-workspace"])
            .set_file_name("analysis.bytetrawl-workspace")
            .save_file()
        else {
            return;
        };
        let mut workspace = Workspace::new(root.path.clone());
        workspace.selected_path = self.selected_node().map(|node| node.path.clone());
        workspace.selected_view = Some(self.tab.label().into());
        workspace.bookmarks = self.bookmarks.clone();
        workspace.notes = self.notes.clone();
        workspace.analysis_results = self.cache.snapshots_for_artifact(root);
        match workspace.save(&path) {
            Ok(()) => self.status = format!("Workspace saved to {}", path.display()).into(),
            Err(error) => self.error = Some(error.to_string().into()),
        }
        cx.notify();
    }
    fn open_workspace(&mut self, cx: &mut Context<Self>) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("ByteTrawl Workspace", &["bytetrawl-workspace"])
            .pick_file()
        else {
            return;
        };
        self.load_workspace(path, cx);
    }
    fn load_workspace(&mut self, path: PathBuf, cx: &mut Context<Self>) {
        match Workspace::load(&path) {
            Ok(workspace) => {
                let artifact_path = workspace.artifact_path.clone();
                self.pending_workspace = Some(workspace);
                self.load(artifact_path, cx)
            }
            Err(error) => {
                self.error = Some(error.to_string().into());
                cx.notify();
            }
        }
    }
    fn load_dropped_path(&mut self, path: PathBuf, cx: &mut Context<Self>) {
        if path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("bytetrawl-workspace"))
        {
            self.load_workspace(path, cx);
        } else {
            self.load(path, cx);
        }
    }
    fn load(&mut self, path: PathBuf, cx: &mut Context<Self>) {
        self.cancellation.cancel();
        self.cancellation = CancellationToken::default();
        self.task_generation = self.task_generation.wrapping_add(1);
        let generation = self.task_generation;
        let cancellation = self.cancellation.clone();
        self.loading = true;
        self.error = None;
        self.status = format!("Discovering {}…", path.display()).into();
        cx.notify();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn(async move {
                    let root = open_artifact(&path, &cancellation)?;
                    let metadata = root
                        .files()
                        .find(|node| node.name.eq_ignore_ascii_case("Info.plist"))
                        .map(inspect_metadata)
                        .transpose()?
                        .unwrap_or_default();
                    Ok::<_, bytetrawl_core::ByteTrawlError>((root, metadata))
                })
                .await;
            this.update(cx, |this, cx| {
                if this.task_generation != generation {
                    return;
                }
                this.loading = false;
                match result {
                    Ok((root, metadata)) => {
                        this.expanded_nodes.clear();
                        this.expanded_nodes.insert(root.id);
                        this.expanded_nodes.extend(
                            root.children
                                .iter()
                                .filter(|node| node.kind == ArtifactKind::Group)
                                .map(|node| node.id),
                        );
                        let mut id = root.id;
                        if let Some(workspace) = this.pending_workspace.take() {
                            if let Some(selected_path) = workspace.selected_path.as_ref()
                                && let Some(selected) = find_by_path(&root, selected_path)
                            {
                                id = selected.id;
                            }
                            this.bookmarks = workspace.bookmarks;
                            this.notes = workspace.notes;
                            for (path, snapshot) in workspace.analysis_results {
                                let path = PathBuf::from(path);
                                if path.starts_with(&root.path)
                                    && find_by_path(&root, &path).is_some_and(|node| {
                                        node.size == snapshot.size
                                            && node.modified == snapshot.modified
                                    })
                                {
                                    let _ = this.cache.insert(&path, snapshot.summary);
                                }
                            }
                            this.restore_tab = workspace
                                .selected_view
                                .as_deref()
                                .and_then(InspectorTab::from_label);
                        }
                        this.artifact = Some(Arc::new(root));
                        this.selected = Some(id);
                        this.analysis = None;
                        this.summary = None;
                        this.metadata = Arc::new(metadata);
                        this.container_signature = None;
                        this.signature_loaded = false;
                        this.strings = Arc::default();
                        this.strings_loaded = false;
                        this.dependency_graph = Arc::default();
                        this.dependency_graph_loaded = false;
                        this.status = "Artifact ready".into();
                        let should_analyze = this
                            .artifact
                            .as_ref()
                            .and_then(|artifact| artifact.find(id))
                            .is_some_and(|node| node.path.is_file());
                        if should_analyze {
                            this.select(id, cx);
                        } else if let Some(tab) = this.restore_tab.take()
                            && this.tabs().contains(&tab)
                        {
                            this.set_tab(tab, cx);
                        }
                    }
                    Err(e) => {
                        this.error = Some(e.to_string().into());
                        this.status = "Open failed".into();
                    }
                }
                cx.notify()
            })?;
            anyhow::Ok(())
        })
        .detach();
    }
    fn select(&mut self, id: uuid::Uuid, cx: &mut Context<Self>) {
        self.cancellation.cancel();
        self.cancellation = CancellationToken::default();
        self.task_generation = self.task_generation.wrapping_add(1);
        let generation = self.task_generation;
        let cancellation = self.cancellation.clone();
        self.selected = Some(id);
        self.analysis = None;
        self.active_slice = None;
        self.summary = None;
        self.metadata = Arc::default();
        self.container_signature = None;
        self.signature_loaded = false;
        self.strings = Arc::default();
        self.strings_loaded = false;
        self.hex_offset = 0;
        self.hex_selection = None;
        self.tab = InspectorTab::Overview;
        let node = self.artifact.as_ref().and_then(|r| r.find(id)).cloned();
        let artifact = self.artifact.clone();
        let cache = self.cache.clone();
        let Some(node) = node else {
            cx.notify();
            return;
        };
        if node.path.is_dir() {
            self.status = "Container selected".into();
            cx.notify();
            return;
        }
        self.loading = true;
        self.status = format!("Analyzing {}…", node.name).into();
        cx.notify();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn(async move {
                    let cached = cache.get(&node.path);
                    let mut analysis = if let Some(cached) = &cached {
                        cached.analysis.clone()
                    } else {
                        analyze_node(&node)?
                    };
                    if let (Some(analysis), Some(artifact)) = (&mut analysis, artifact.as_deref()) {
                        resolve_dependencies(analysis, artifact);
                    }
                    let metadata = inspect_metadata(&node)?;
                    cancellation.check()?;
                    let mut summary = if let Some(cached) = cached {
                        (*cached).clone()
                    } else {
                        FileSummary {
                            size: node.size,
                            sha256: None,
                            sha1: None,
                            md5: None,
                            entropy: None,
                            analysis: None,
                        }
                    };
                    summary.analysis = analysis.clone();
                    let _ = cache.insert(&node.path, summary.clone());
                    Ok::<_, bytetrawl_core::ByteTrawlError>((analysis, summary, metadata))
                })
                .await;
            this.update(cx, |this, cx| {
                if this.task_generation != generation {
                    return;
                }
                this.loading = false;
                match result {
                    Ok((a, s, metadata)) => {
                        this.analysis = a.map(Arc::new);
                        this.summary = Some(Arc::new(s));
                        this.metadata = Arc::new(metadata);
                        this.status = "Analysis complete".into();
                        if let Some(tab) = this.restore_tab.take()
                            && this.tabs().contains(&tab)
                        {
                            this.set_tab(tab, cx);
                        }
                    }
                    Err(e) => {
                        this.error = Some(e.to_string().into());
                        this.status = "Analysis incomplete".into();
                    }
                }
                cx.notify()
            })?;
            anyhow::Ok(())
        })
        .detach();
    }
    fn set_tab(&mut self, tab: InspectorTab, cx: &mut Context<Self>) {
        self.tab = tab;
        if tab == InspectorTab::Strings && !self.strings_loaded {
            self.load_strings(cx);
        } else if tab == InspectorTab::DependencyGraph && !self.dependency_graph_loaded {
            self.load_dependency_graph(cx);
        } else if tab == InspectorTab::Signature
            && self.should_run_host_signature()
            && !self.signature_loaded
        {
            self.load_host_signature(cx);
        } else {
            cx.notify();
        }
    }

    fn should_run_host_signature(&self) -> bool {
        self.current_analysis()
            .is_some_and(|analysis| analysis.platform == Some(BinaryPlatform::MacOs))
            || self.selected_node().is_some_and(|node| {
                matches!(
                    node.kind,
                    ArtifactKind::Application
                        | ArtifactKind::Bundle
                        | ArtifactKind::Framework
                        | ArtifactKind::Plugin
                )
            })
    }

    fn load_host_signature(&mut self, cx: &mut Context<Self>) {
        let Some(path) = self.selected_node().map(|node| node.path.clone()) else {
            return;
        };
        self.cancellation.cancel();
        self.cancellation = CancellationToken::default();
        let cancellation = self.cancellation.clone();
        self.task_generation = self.task_generation.wrapping_add(1);
        let generation = self.task_generation;
        self.loading = true;
        self.status = "Verifying code signature and Gatekeeper assessment…".into();
        cx.notify();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn(
                    async move { inspect_signature_cancellable(&path, &cancellation) },
                )
                .await;
            this.update(cx, |this, cx| {
                if this.task_generation != generation {
                    return;
                }
                this.loading = false;
                match result {
                    Ok(signature) => {
                        this.signature_loaded = true;
                        if let (Some(analysis), Some(signature)) =
                            (this.analysis.as_deref(), signature.as_ref())
                        {
                            let mut analysis = analysis.clone();
                            apply_signature_analysis(&mut analysis, signature);
                            this.analysis = Some(Arc::new(analysis));
                        }
                        this.container_signature = signature;
                        this.status = "Deep signature verification complete".into();
                    }
                    Err(error) => {
                        this.error = Some(error.to_string().into());
                        this.status = "Signature verification incomplete".into();
                    }
                }
                cx.notify();
            })?;
            anyhow::Ok(())
        })
        .detach();
    }
    fn load_dependency_graph(&mut self, cx: &mut Context<Self>) {
        let Some(artifact) = self.artifact.clone() else {
            return;
        };
        self.cancellation.cancel();
        self.cancellation = CancellationToken::default();
        self.task_generation = self.task_generation.wrapping_add(1);
        let generation = self.task_generation;
        let cancellation = self.cancellation.clone();
        self.loading = true;
        self.status = "Building Artifact dependency graph…".into();
        cx.notify();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn(async move { build_dependency_graph(&artifact, &cancellation) })
                .await;
            this.update(cx, |this, cx| {
                if this.task_generation != generation {
                    return;
                }
                this.loading = false;
                match result {
                    Ok(graph) => {
                        let edges = graph.edges.len();
                        this.dependency_graph = Arc::new(graph);
                        this.dependency_graph_loaded = true;
                        this.status = format!("Dependency graph ready · {edges} edges").into();
                    }
                    Err(error) => {
                        this.error = Some(error.to_string().into());
                        this.status = "Dependency graph incomplete".into();
                    }
                }
                cx.notify();
            })?;
            anyhow::Ok(())
        })
        .detach();
    }
    fn load_strings(&mut self, cx: &mut Context<Self>) {
        let Some(node) = self
            .selected_node()
            .filter(|node| node.path.is_file())
            .cloned()
        else {
            return;
        };
        self.cancellation.cancel();
        self.cancellation = CancellationToken::default();
        self.task_generation = self.task_generation.wrapping_add(1);
        let generation = self.task_generation;
        let cancellation = self.cancellation.clone();
        let analysis = self.analysis.clone();
        self.loading = true;
        self.status = format!("Extracting strings from {}…", node.name).into();
        cx.notify();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn(async move {
                    let mut strings =
                        extract_strings_file_cancellable(&node.path, 2, 100_000, &cancellation)?;
                    if let Some(analysis) = analysis.as_deref() {
                        if analysis.slice_analyses.is_empty() {
                            annotate_string_locations(&mut strings, analysis);
                        } else {
                            for slice in &analysis.slice_analyses {
                                annotate_string_locations(&mut strings, slice);
                            }
                        }
                    }
                    Ok::<_, bytetrawl_core::ByteTrawlError>(strings)
                })
                .await;
            this.update(cx, |this, cx| {
                if this.task_generation != generation {
                    return;
                }
                this.loading = false;
                match result {
                    Ok(strings) => {
                        let count = strings.len();
                        this.strings = Arc::new(strings);
                        this.strings_loaded = true;
                        this.status = format!("{count} strings extracted").into();
                    }
                    Err(error) => {
                        this.error = Some(error.to_string().into());
                        this.status = "String extraction incomplete".into();
                    }
                }
                cx.notify();
            })?;
            anyhow::Ok(())
        })
        .detach();
    }
    fn find_next(&mut self, cx: &mut Context<Self>) {
        let Some(node) = self.selected_node().cloned() else {
            return;
        };
        if !node.path.is_file() || self.query.is_empty() {
            return;
        }
        self.cancellation.cancel();
        self.cancellation = CancellationToken::default();
        self.task_generation = self.task_generation.wrapping_add(1);
        let generation = self.task_generation;
        let cancellation = self.cancellation.clone();
        let needle = match parse_search_bytes(&self.query, self.file_search_mode) {
            Ok(needle) if !needle.is_empty() => needle,
            Ok(_) => return,
            Err(message) => {
                self.error = Some(message.into());
                cx.notify();
                return;
            }
        };
        let needle_len = needle.len() as u64;
        let start = self.hex_offset.saturating_add(1);
        self.loading = true;
        self.status = "Searching file…".into();
        cx.notify();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn(
                    async move { search_file(&node.path, &needle, start, &cancellation) },
                )
                .await;
            this.update(cx, |this, cx| {
                if this.task_generation != generation {
                    return;
                }
                this.loading = false;
                match result {
                    Ok(Some(offset)) => {
                        this.hex_offset = offset;
                        this.hex_selection = Some((offset, offset.saturating_add(needle_len)));
                        this.tab = InspectorTab::Hex;
                        this.status = format!("Match at 0x{offset:x}").into();
                    }
                    Ok(None) => this.status = "No further match".into(),
                    Err(error) => this.error = Some(error.to_string().into()),
                }
                cx.notify();
            })?;
            anyhow::Ok(())
        })
        .detach();
    }
    fn cancel_current_task(&mut self, cx: &mut Context<Self>) {
        if !self.loading {
            return;
        }
        self.cancellation.cancel();
        self.task_generation = self.task_generation.wrapping_add(1);
        self.loading = false;
        self.status = "Analysis cancelled".into();
        cx.notify();
    }
    fn search_all(&mut self, cx: &mut Context<Self>) {
        let Some(artifact) = self.artifact.clone() else {
            return;
        };
        if self.query.trim().is_empty() {
            return;
        }
        self.cancellation.cancel();
        self.cancellation = CancellationToken::default();
        self.task_generation = self.task_generation.wrapping_add(1);
        let generation = self.task_generation;
        let cancellation = self.cancellation.clone();
        let cache = self.cache.clone();
        let query = self.query.to_string();
        self.loading = true;
        self.status = "Searching entire artifact…".into();
        cx.notify();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn(async move {
                    global_search_cached(&artifact, &query, &cancellation, 20_000, &cache)
                })
                .await;
            this.update(cx, |this, cx| {
                if this.task_generation != generation {
                    return;
                }
                this.loading = false;
                match result {
                    Ok(hits) => {
                        let count = hits.len();
                        this.search_hits = Arc::new(hits);
                        this.tab = InspectorTab::Search;
                        this.status = format!("{count} search results").into();
                    }
                    Err(error) => this.error = Some(error.to_string().into()),
                }
                cx.notify();
            })?;
            anyhow::Ok(())
        })
        .detach();
    }
    fn jump_to_offset(&mut self, cx: &mut Context<Self>) {
        let query = self.query.trim();
        let parsed = query
            .strip_prefix("0x")
            .or_else(|| query.strip_prefix("0X"))
            .and_then(|value| u64::from_str_radix(value, 16).ok())
            .or_else(|| query.parse::<u64>().ok());
        if let Some(offset) = parsed {
            self.hex_offset = offset;
            self.tab = InspectorTab::Hex;
            self.status = format!("Jumped to 0x{offset:x}").into();
        } else {
            self.error = Some("Enter an offset as decimal or 0x-prefixed hexadecimal".into());
        }
        cx.notify();
    }
    fn copy_hex_chunk(&mut self, cx: &mut Context<Self>) {
        let Some(node) = self.selected_node() else {
            return;
        };
        let (offset, length) = self
            .hex_selection
            .map(|(start, end)| {
                (
                    start,
                    end.saturating_sub(start).min(16 * 1024 * 1024) as usize,
                )
            })
            .unwrap_or((self.hex_offset, 4096));
        let bytes = match HexReader::open(&node.path)
            .and_then(|mut reader| reader.read_chunk(offset, length))
        {
            Ok(bytes) => bytes,
            Err(error) => {
                self.error = Some(format!("Could not read hex data: {error}").into());
                self.status = "Hex copy failed".into();
                cx.notify();
                return;
            }
        };
        let text = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        cx.write_to_clipboard(ClipboardItem::new_string(text));
        self.status = if self.hex_selection.is_some() {
            format!("Copied {} selected bytes", bytes.len()).into()
        } else {
            format!("Copied {} bytes from current chunk", bytes.len()).into()
        };
        cx.notify();
    }
    fn compute_all_hashes(&mut self, cx: &mut Context<Self>) {
        let Some(node) = self
            .selected_node()
            .filter(|node| node.path.is_file())
            .cloned()
        else {
            return;
        };
        self.cancellation.cancel();
        self.cancellation = CancellationToken::default();
        self.task_generation = self.task_generation.wrapping_add(1);
        let generation = self.task_generation;
        let cancellation = self.cancellation.clone();
        let analysis = self.analysis.as_deref().cloned();
        let cache = self.cache.clone();
        self.loading = true;
        self.status = "Computing hashes and whole-file/section entropy…".into();
        cx.notify();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn(async move {
                    let mut summary = hash_file(
                        &node.path,
                        HashOptions {
                            sha256: true,
                            sha1: true,
                            md5: true,
                        },
                        &cancellation,
                    )?;
                    summary.analysis = analysis;
                    if let Some(analysis) = &mut summary.analysis {
                        enrich_analysis_entropy(&node.path, analysis, &cancellation)?;
                    }
                    let _ = cache.insert(&node.path, summary.clone());
                    Ok::<_, bytetrawl_core::ByteTrawlError>(summary)
                })
                .await;
            this.update(cx, |this, cx| {
                if this.task_generation != generation {
                    return;
                }
                this.loading = false;
                match result {
                    Ok(summary) => {
                        this.analysis = summary.analysis.clone().map(Arc::new);
                        this.summary = Some(Arc::new(summary));
                        this.status = "Hashes and entropy analysis complete".into();
                    }
                    Err(error) => this.error = Some(error.to_string().into()),
                }
                cx.notify();
            })?;
            anyhow::Ok(())
        })
        .detach();
    }
    fn select_hex_byte(&mut self, offset: u64, cx: &mut Context<Self>) {
        self.hex_selection = Some(match self.hex_selection {
            Some((start, end)) if end == start + 1 && start != offset => {
                (start.min(offset), start.max(offset).saturating_add(1))
            }
            _ => (offset, offset.saturating_add(1)),
        });
        if let Some((start, end)) = self.hex_selection {
            self.status = format!("Selected 0x{start:x}..0x{end:x}").into();
        }
        cx.notify();
    }
    fn selected_node(&self) -> Option<&ArtifactNode> {
        let id = self.selected?;
        self.artifact.as_ref()?.find(id)
    }
    fn activate_tree_node(&mut self, id: uuid::Uuid, cx: &mut Context<Self>) {
        let expandable = self
            .artifact
            .as_ref()
            .and_then(|artifact| artifact.find(id))
            .is_some_and(|node| !node.children.is_empty());
        if expandable && !self.expanded_nodes.remove(&id) {
            self.expanded_nodes.insert(id);
        }
        self.select(id, cx);
    }
    fn current_analysis(&self) -> Option<&BinaryAnalysis> {
        let analysis = self.analysis.as_deref()?;
        self.active_slice
            .and_then(|index| analysis.slice_analyses.get(index))
            .or(Some(analysis))
    }
    fn add_bookmark(&mut self, cx: &mut Context<Self>) {
        let Some(path) = self.selected_node().map(|node| node.path.clone()) else {
            return;
        };
        if !self.bookmarks.contains(&path) {
            self.bookmarks.push(path);
        }
        self.status = "Bookmark added".into();
        cx.notify();
    }
    fn save_note(&mut self, cx: &mut Context<Self>) {
        let Some(path) = self
            .selected_node()
            .map(|node| node.path.display().to_string())
        else {
            return;
        };
        if self.note_draft.trim().is_empty() {
            self.notes.shift_remove(&path);
        } else {
            self.notes.insert(path, self.note_draft.to_string());
        }
        self.status = "Node note saved".into();
        cx.notify();
    }
    fn tabs(&self) -> Vec<InspectorTab> {
        let binary = self.analysis.is_some();
        let mut tabs = Vec::new();
        if !self.search_hits.is_empty() || self.tab == InspectorTab::Search {
            tabs.push(InspectorTab::Search);
        }
        tabs.push(InspectorTab::Overview);
        if self.artifact.is_some() {
            tabs.push(InspectorTab::DependencyGraph);
        }
        if binary {
            if self
                .analysis
                .as_ref()
                .is_some_and(|analysis| !analysis.slice_analyses.is_empty())
            {
                tabs.push(InspectorTab::Slices);
            }
            if let Some(analysis) = self.current_analysis() {
                if !analysis.headers.is_empty() {
                    tabs.push(InspectorTab::Headers);
                }
                for (available, tab) in [
                    (!analysis.segments.is_empty(), InspectorTab::Segments),
                    (!analysis.sections.is_empty(), InspectorTab::Sections),
                    (!analysis.relocations.is_empty(), InspectorTab::Relocations),
                    (!analysis.imports.is_empty(), InspectorTab::Imports),
                    (!analysis.exports.is_empty(), InspectorTab::Exports),
                    (!analysis.symbols.is_empty(), InspectorTab::Symbols),
                    (
                        !analysis.dependencies.is_empty(),
                        InspectorTab::Dependencies,
                    ),
                ] {
                    if available {
                        tabs.push(tab);
                    }
                }
                tabs.extend([InspectorTab::Strings, InspectorTab::Hex]);
                if analysis.signature.is_some() || self.container_signature.is_some() {
                    tabs.push(InspectorTab::Signature);
                }
                if !analysis.metadata.is_empty() || !self.metadata.is_empty() {
                    tabs.push(InspectorTab::Metadata);
                }
                if !analysis.findings.is_empty() {
                    tabs.push(InspectorTab::Findings);
                }
            }
        } else if self.selected_node().is_some_and(|n| n.path.is_file()) {
            tabs.push(InspectorTab::Hex);
            if !self.metadata.is_empty() {
                tabs.push(InspectorTab::Metadata);
            }
        } else if self.selected_node().is_some() {
            if !self.metadata.is_empty() {
                tabs.push(InspectorTab::Metadata);
            }
            if self.should_run_host_signature() || self.container_signature.is_some() {
                tabs.push(InspectorTab::Signature);
            }
        }
        tabs
    }
    fn render_sidebar(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let query = self.query.to_lowercase();
        let rows = Arc::new(
            self.artifact
                .as_ref()
                .map(|root| {
                    let mut out = Vec::new();
                    flatten(root, 0, &self.expanded_nodes, !query.is_empty(), &mut out);
                    out
                })
                .unwrap_or_default()
                .into_iter()
                .filter(|(_, _, name, _, _, _)| {
                    query.is_empty() || name.to_lowercase().contains(&query)
                })
                .collect::<Vec<_>>(),
        );
        let row_count = rows.len();
        div()
            .id("artifact-tree-panel")
            .w(px(300.))
            .h_full()
            .flex_shrink_0()
            .bg(rgb(PANEL))
            .border_r_1()
            .border_color(rgb(BORDER))
            .overflow_hidden()
            .child(section_header("ARTIFACT TREE"))
            .child(
                uniform_list(
                    "artifact-tree-rows",
                    row_count,
                    cx.processor(move |this, range: std::ops::Range<usize>, _, cx| {
                        range
                            .filter_map(|index| rows.get(index))
                            .map(|(id, depth, name, kind, expandable, expanded)| {
                                let id = *id;
                                let depth = *depth;
                                let kind = *kind;
                                let expandable = *expandable;
                                let expanded = *expanded;
                                let active = this.selected == Some(id);
                                div()
                                    .id(SharedString::from(format!("node-{id}")))
                                    .h(px(28.))
                                    .flex()
                                    .items_center()
                                    .pl(px(12. + depth as f32 * 16.))
                                    .pr_2()
                                    .gap_2()
                                    .cursor_pointer()
                                    .when(active, |d| d.bg(rgb(SELECTION)))
                                    .hover(|d| d.bg(rgb(PANEL_2)))
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.activate_tree_node(id, cx)
                                    }))
                                    .child(div().w(px(12.)).text_color(rgb(MUTED)).child(
                                        if expandable {
                                            if expanded { "▾" } else { "▸" }
                                        } else {
                                            ""
                                        },
                                    ))
                                    .child(
                                        div()
                                            .w(px(14.))
                                            .text_color(rgb(if active { ACCENT } else { MUTED }))
                                            .child(kind_icon(kind)),
                                    )
                                    .child(
                                        div()
                                            .text_sm()
                                            .text_color(rgb(if active { TEXT } else { MUTED }))
                                            .overflow_hidden()
                                            .whitespace_nowrap()
                                            .child(name.clone()),
                                    )
                            })
                            .collect::<Vec<_>>()
                    }),
                )
                .id("tree-scroll")
                .flex_1()
                .h_full(),
            )
    }
    fn select_path(&mut self, path: &std::path::Path, cx: &mut Context<Self>) {
        if let Some(id) = self
            .artifact
            .as_ref()
            .and_then(|root| find_by_path(root, path))
            .map(|node| node.id)
        {
            self.select(id, cx);
        }
    }
    fn render_details(&self, cx: &mut Context<Self>) -> AnyElement {
        if self.selected_node().is_none() {
            return div()
                .id("details-empty")
                .w(px(300.))
                .h_full()
                .flex_shrink_0()
                .bg(rgb(PANEL))
                .border_l_1()
                .border_color(rgb(BORDER))
                .child(section_header("DETAILS"))
                .child(
                    div()
                        .p_4()
                        .text_xs()
                        .text_color(rgb(MUTED))
                        .child("Select an Artifact node to inspect properties and actions."),
                )
                .into_any_element();
        }
        let selected_path = self
            .selected_node()
            .map(|node| node.path.display().to_string());
        let existing_note = selected_path
            .as_ref()
            .and_then(|path| self.notes.get(path))
            .cloned();
        let tool_items: Vec<_> = self
            .selected_node()
            .into_iter()
            .flat_map(|node| {
                self.tools
                    .iter()
                    .filter(move |tool| tool.supports(node))
                    .map(|tool| {
                        (
                            tool.id(),
                            tool.display_name(),
                            matches!(tool.detect(), ToolAvailability::Available(_)),
                        )
                    })
            })
            .collect();
        let selected_values = self
            .selected_node()
            .map(|node| {
                let mut values = vec![
                    ("Kind".into(), format!("{:?}", node.kind)),
                    (
                        "Format".into(),
                        node.format
                            .map(|format| format!("{format:?}"))
                            .unwrap_or_else(|| "Container".into()),
                    ),
                    ("Size".into(), format_size(node.size)),
                    ("Path".into(), node.path.display().to_string()),
                ];
                values.extend(
                    node.properties
                        .iter()
                        .map(|(key, value)| (key.clone(), value.clone())),
                );
                if !self.metadata.is_empty() {
                    values.push(("Metadata fields".into(), self.metadata.len().to_string()));
                    for key in [
                        "CFBundleIdentifier",
                        "CFBundleShortVersionString",
                        "Company Name",
                        "Product Name",
                        "Name",
                    ] {
                        if let Some(value) = self.metadata.get(key) {
                            values.push((key.into(), value.clone()));
                        }
                    }
                }
                if let Some(analysis) = self.current_analysis() {
                    for severity in [
                        Severity::Critical,
                        Severity::High,
                        Severity::Medium,
                        Severity::Low,
                        Severity::Info,
                    ] {
                        let count = analysis
                            .findings
                            .iter()
                            .filter(|finding| finding.severity == severity)
                            .count();
                        if count > 0 {
                            values.push((format!("{severity:?} findings"), count.to_string()));
                        }
                    }
                }
                values
            })
            .unwrap_or_default();
        div()
            .id("details-scroll")
            .w(px(300.))
            .h_full()
            .flex_shrink_0()
            .bg(rgb(PANEL))
            .border_l_1()
            .border_color(rgb(BORDER))
            .flex()
            .flex_col()
            .overflow_y_scroll()
            .child(section_header("DETAILS"))
            .child(kv_panel("Selected Node", selected_values))
            .child(
                div()
                    .id("node-details")
                    .p_3()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(
                        Button::new("bookmark-selected")
                            .label("Add Bookmark")
                            .on_click(cx.listener(|this, _, _, cx| this.add_bookmark(cx))),
                    )
                    .child(div().text_xs().text_color(rgb(MUTED)).child("NODE NOTE"))
                    .when_some(existing_note, |d, note| {
                        d.child(
                            div()
                                .p_2()
                                .rounded_md()
                                .bg(rgb(PANEL_2))
                                .text_sm()
                                .text_color(rgb(TEXT))
                                .child(note),
                        )
                    })
                    .child(
                        div()
                            .h(px(72.))
                            .child(Input::new(&self.note_input).h_full()),
                    )
                    .child(
                        Button::new("save-node-note")
                            .label("Save Note")
                            .on_click(cx.listener(|this, _, _, cx| this.save_note(cx))),
                    )
                    .child(
                        Button::new("compute-all-hashes")
                            .label("Compute hashes + entropy")
                            .disabled(!self.selected_node().is_some_and(|node| node.path.is_file()))
                            .on_click(cx.listener(|this, _, _, cx| this.compute_all_hashes(cx))),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(rgb(MUTED))
                            .child("SHA-1 and MD5 are provided for identification only."),
                    ),
            )
            .child(section_header("BOOKMARKS"))
            .child(
                div()
                    .id("bookmarks-scroll")
                    .children(self.bookmarks.iter().enumerate().map(|(index, path)| {
                        let target = path.clone();
                        div()
                            .id(SharedString::from(format!("bookmark-{index}")))
                            .px_3()
                            .py_2()
                            .cursor_pointer()
                            .hover(|d| d.bg(rgb(PANEL_2)))
                            .on_click(
                                cx.listener(move |this, _, _, cx| this.select_path(&target, cx)),
                            )
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(rgb(TEXT))
                                    .child(path.display().to_string()),
                            )
                    })),
            )
            .child(section_header("EXTERNAL TOOLS · EXPLICIT LAUNCH"))
            .child(
                div()
                    .id("external-tools-scroll")
                    .p_3()
                    .max_h(px(360.))
                    .overflow_scroll()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .children(tool_items.into_iter().map(|(id, name, available)| {
                        Button::new(SharedString::from(format!("tool-{id}")))
                            .label(if available {
                                format!("Open in {name}")
                            } else {
                                format!("{name} · not installed")
                            })
                            .disabled(!available)
                            .on_click(cx.listener(move |this, _, _, cx| this.launch_tool(id, cx)))
                    })),
            )
            .when_some(self.tool_output.clone(), |details, (title, output)| {
                details.child(section_header("TOOL OUTPUT")).child(
                    div()
                        .id("tool-output-scroll")
                        .p_3()
                        .max_h(px(360.))
                        .overflow_scroll()
                        .text_xs()
                        .font_family("Menlo")
                        .text_color(rgb(TEXT))
                        .child(div().mb_2().font_semibold().child(title))
                        .child(output),
                )
            })
            .into_any_element()
    }

    fn launch_tool(&mut self, id: &str, cx: &mut Context<Self>) {
        let Some(node) = self.selected_node().cloned() else {
            return;
        };
        let tools = self.tools.clone();
        let Some(name) = tools.get(id).map(|tool| tool.display_name()) else {
            return;
        };
        let id = id.to_string();
        self.cancellation.cancel();
        self.cancellation = CancellationToken::default();
        let cancellation = self.cancellation.clone();
        self.loading = true;
        self.status = format!("Running {name}…").into();
        cx.notify();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn(async move {
                    let tool = tools.get(&id).ok_or_else(|| {
                        bytetrawl_core::ByteTrawlError::Malformed("tool disappeared".into())
                    })?;
                    if let Some(output) =
                        tool.capture_controlled(&node, std::time::Duration::from_secs(60), &|| {
                            cancellation.check().is_err()
                        })?
                    {
                        Ok::<_, bytetrawl_core::ByteTrawlError>((tool.display_name(), Some(output)))
                    } else {
                        tool.launch(&node)?;
                        Ok((tool.display_name(), None))
                    }
                })
                .await;
            this.update(cx, |this, cx| {
                this.loading = false;
                match result {
                    Ok((name, Some(output))) => {
                        let mut text = output.stdout;
                        if !output.stderr.is_empty() {
                            text.push_str("\n--- stderr ---\n");
                            text.push_str(&output.stderr);
                        }
                        if output.truncated {
                            text.push_str("\n… output truncated at 16 MiB …");
                        }
                        if output.timed_out {
                            text.push_str("\n… tool terminated after the 60 second limit …");
                        }
                        if output.cancelled {
                            text.push_str("\n… tool cancelled …");
                        }
                        this.tool_output = Some((name.into(), text.into()));
                        this.status = format!(
                            "{name} finished {}",
                            if output.success {
                                "successfully"
                            } else {
                                "with errors"
                            }
                        )
                        .into();
                    }
                    Ok((name, None)) => this.status = format!("Launched {name}").into(),
                    Err(error) => this.error = Some(error.to_string().into()),
                }
                cx.notify();
            })?;
            anyhow::Ok(())
        })
        .detach();
    }
    fn render_main(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let tabs = self.tabs();
        div()
            .flex_1()
            .h_full()
            .min_w_0()
            .flex()
            .flex_col()
            .bg(rgb(BG))
            .border_2()
            .border_color(rgb(BG))
            .drag_over::<ExternalPaths>(|style, _, _, _| {
                style.bg(rgba(0x9bd26720)).border_color(rgb(GREEN))
            })
            .on_drop(cx.listener(|this, paths: &ExternalPaths, _, cx| {
                if let Some(path) = paths.paths().first() {
                    this.load_dropped_path(path.clone(), cx);
                }
            }))
            .child(
                div()
                    .id("inspector-tabs-scroll")
                    .h(px(40.))
                    .flex()
                    .items_end()
                    .px_4()
                    .gap_1()
                    .bg(rgb(PANEL))
                    .border_b_1()
                    .border_color(rgb(BORDER))
                    .overflow_x_scroll()
                    .children(tabs.into_iter().map(|tab| {
                        let active = self.tab == tab;
                        div()
                            .id(SharedString::from(format!("tab-{}", tab.label())))
                            .px_3()
                            .h(px(39.))
                            .flex()
                            .items_center()
                            .cursor_pointer()
                            .text_sm()
                            .text_color(rgb(if active { TEXT } else { MUTED }))
                            .when(active, |d| d.border_b_2().border_color(rgb(ACCENT)))
                            .on_click(cx.listener(move |this, _, _, cx| this.set_tab(tab, cx)))
                            .child(tab.label())
                    })),
            )
            .child(
                div()
                    .id("inspector-scroll")
                    .flex_1()
                    .min_h_0()
                    .flex()
                    .flex_col()
                    .overflow_y_scroll()
                    .p_5()
                    .child(
                        div()
                            .flex_1()
                            .min_h_0()
                            .flex()
                            .flex_col()
                            .child(self.render_tab(cx)),
                    ),
            )
    }
    fn render_tab(&self, cx: &mut Context<Self>) -> AnyElement {
        let Some(node) = self.selected_node() else {
            return empty_state().into_any_element();
        };
        match self.tab {
            InspectorTab::Search => self.render_search(cx).into_any_element(),
            InspectorTab::Slices => self.render_slices(cx).into_any_element(),
            InspectorTab::Overview => self.render_overview(node).into_any_element(),
            InspectorTab::Headers => kv_panel(
                "Headers",
                self.current_analysis()
                    .map(|a| {
                        a.headers
                            .iter()
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect()
                    })
                    .unwrap_or_default(),
            )
            .into_any_element(),
            InspectorTab::Sections => table_panel(
                "Sections",
                &["Name", "Address", "Offset", "Size", "Flags", "Entropy"],
                self.current_analysis()
                    .map(|a| {
                        a.sections
                            .iter()
                            .map(|s| {
                                vec![
                                    s.name.clone(),
                                    fmt_addr(s.address),
                                    fmt_addr(s.offset),
                                    format_size(s.size),
                                    s.flags.clone(),
                                    s.entropy.map(|e| format!("{e:.3}")).unwrap_or_default(),
                                ]
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
                cx,
            )
            .into_any_element(),
            InspectorTab::Segments => table_panel(
                "Segments",
                &[
                    "Name",
                    "VM address",
                    "VM size",
                    "File offset",
                    "File size",
                    "Protections",
                    "Sections",
                ],
                self.current_analysis()
                    .map(|analysis| {
                        analysis
                            .segments
                            .iter()
                            .map(|segment| {
                                vec![
                                    segment.name.clone(),
                                    fmt_addr(segment.address),
                                    format_size(segment.virtual_size),
                                    fmt_addr(segment.file_offset),
                                    format_size(segment.file_size),
                                    segment.protections.clone(),
                                    segment.section_count.to_string(),
                                ]
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
                cx,
            )
            .into_any_element(),
            InspectorTab::Relocations => table_panel(
                "Relocations",
                &["Offset", "Type", "Symbol", "Addend", "Source"],
                self.current_analysis()
                    .map(|analysis| {
                        analysis
                            .relocations
                            .iter()
                            .map(|relocation| {
                                vec![
                                    fmt_addr(relocation.offset),
                                    relocation.relocation_type.clone(),
                                    relocation.symbol.clone().unwrap_or_default(),
                                    relocation
                                        .addend
                                        .map(|addend| addend.to_string())
                                        .unwrap_or_default(),
                                    relocation.source.clone(),
                                ]
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
                cx,
            )
            .into_any_element(),
            InspectorTab::Imports => symbol_table(
                "Imports",
                self.current_analysis()
                    .map(|a| a.imports.as_slice())
                    .unwrap_or(&[]),
                &self.query,
                cx,
            )
            .into_any_element(),
            InspectorTab::Exports => symbol_table(
                "Exports",
                self.current_analysis()
                    .map(|a| a.exports.as_slice())
                    .unwrap_or(&[]),
                &self.query,
                cx,
            )
            .into_any_element(),
            InspectorTab::Symbols => symbol_table(
                "Symbols",
                self.current_analysis()
                    .map(|a| a.symbols.as_slice())
                    .unwrap_or(&[]),
                &self.query,
                cx,
            )
            .into_any_element(),
            InspectorTab::Dependencies => table_panel(
                "Dependencies",
                &["Library", "Resolution", "Resolved path"],
                self.current_analysis()
                    .map(|a| {
                        let query = self.query.to_lowercase();
                        a.dependencies
                            .iter()
                            .filter(|dependency| {
                                query.is_empty() || dependency.name.to_lowercase().contains(&query)
                            })
                            .map(|d| {
                                vec![
                                    d.name.clone(),
                                    format!("{:?}", d.status),
                                    d.path
                                        .as_ref()
                                        .map(|path| path.display().to_string())
                                        .unwrap_or_default(),
                                ]
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
                cx,
            )
            .into_any_element(),
            InspectorTab::DependencyGraph => self.render_dependency_graph(cx).into_any_element(),
            InspectorTab::Metadata => {
                kv_panel("Metadata", self.combined_metadata()).into_any_element()
            }
            InspectorTab::Findings => self.render_findings().into_any_element(),
            InspectorTab::Hex => self.render_hex(node, cx).into_any_element(),
            InspectorTab::Strings => self.render_strings(cx).into_any_element(),
            InspectorTab::Signature => self.render_signature().into_any_element(),
        }
    }
    fn render_search(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let hits = Arc::new(self.search_hits.clone());
        let hit_count = hits.len();
        div()
            .flex()
            .flex_col()
            .gap_3()
            .child(panel_title(format!(
                "Global Search · {} results",
                self.search_hits.len()
            )))
            .child(
                div()
                    .rounded_md()
                    .border_1()
                    .border_color(rgb(BORDER))
                    .bg(rgb(PANEL))
                    .child(
                        uniform_list(
                            "global-search-results",
                            hit_count,
                            cx.processor(move |_this, range: std::ops::Range<usize>, _, cx| {
                                range
                                    .filter_map(|index| hits.get(index).map(|hit| (index, hit)))
                                    .map(|(index, hit)| {
                                        let node_id = hit.node_id;
                                        div()
                                            .id(SharedString::from(format!("search-hit-{index}")))
                                            .h(px(48.))
                                            .flex()
                                            .items_center()
                                            .border_b_1()
                                            .border_color(rgb(BORDER))
                                            .cursor_pointer()
                                            .hover(|d| d.bg(rgb(PANEL_2)))
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                this.select(node_id, cx)
                                            }))
                                            .child(
                                                div()
                                                    .w(px(110.))
                                                    .px_3()
                                                    .text_xs()
                                                    .text_color(rgb(ACCENT))
                                                    .child(hit.category),
                                            )
                                            .child(
                                                div()
                                                    .flex_1()
                                                    .min_w_0()
                                                    .px_2()
                                                    .child(
                                                        div()
                                                            .text_sm()
                                                            .text_color(rgb(TEXT))
                                                            .child(hit.value.clone()),
                                                    )
                                                    .child(
                                                        div()
                                                            .text_xs()
                                                            .text_color(rgb(MUTED))
                                                            .child(format!(
                                                                "{}  {}",
                                                                hit.path.display(),
                                                                hit.detail
                                                            )),
                                                    ),
                                            )
                                    })
                                    .collect::<Vec<_>>()
                            }),
                        )
                        .h(px(640.)),
                    ),
            )
    }
    fn render_slices(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let slices = self
            .analysis
            .as_ref()
            .map(|analysis| analysis.slices.as_slice())
            .unwrap_or(&[]);
        div()
            .flex()
            .flex_col()
            .gap_3()
            .child(panel_title("Universal Mach-O Slices"))
            .children(slices.iter().enumerate().map(|(index, slice)| {
                let analysis = self
                    .analysis
                    .as_ref()
                    .and_then(|analysis| analysis.slice_analyses.get(index));
                let active = self.active_slice == Some(index);
                div()
                    .id(SharedString::from(format!("slice-{index}")))
                    .p_4()
                    .rounded_md()
                    .border_1()
                    .border_color(rgb(if active { ACCENT } else { BORDER }))
                    .bg(rgb(PANEL))
                    .cursor_pointer()
                    .hover(|item| item.bg(rgb(PANEL_2)))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.active_slice = Some(index);
                        this.tab = InspectorTab::Overview;
                        this.status = format!("Inspecting universal slice {index}").into();
                        cx.notify();
                    }))
                    .child(
                        div()
                            .font_semibold()
                            .text_color(rgb(TEXT))
                            .child(slice.architecture.clone()),
                    )
                    .child(div().mt_1().text_sm().text_color(rgb(MUTED)).child(format!(
                        "File range 0x{:x}..0x{:x} · {} sections · {} dependencies",
                        slice.offset,
                        slice.offset.saturating_add(slice.size),
                        analysis.map_or(0, |analysis| analysis.sections.len()),
                        analysis.map_or(0, |analysis| analysis.dependencies.len())
                    )))
            }))
    }
    fn combined_metadata(&self) -> Vec<(String, String)> {
        let query = self.query.to_lowercase();
        self.current_analysis()
            .into_iter()
            .flat_map(|a| a.metadata.iter())
            .chain(self.metadata.iter())
            .filter(|(k, v)| {
                query.is_empty()
                    || k.to_lowercase().contains(&query)
                    || v.to_lowercase().contains(&query)
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
    fn render_strings(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let query = self.query.to_lowercase();
        let rows = self
            .strings
            .iter()
            .filter(|s| {
                s.value.chars().count() >= self.string_minimum
                    && (query.is_empty() || s.value.to_lowercase().contains(&query))
            })
            .map(|s| {
                vec![
                    fmt_addr(s.offset),
                    s.virtual_address.map(fmt_addr).unwrap_or_default(),
                    s.section.clone().unwrap_or_default(),
                    format!("{:?}", s.encoding),
                    s.value.clone(),
                ]
            })
            .collect();
        div()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(panel_title(format!(
                        "Strings · minimum length {}",
                        self.string_minimum
                    )))
                    .child(div().flex_1())
                    .child(
                        Button::new("strings-min-less")
                            .label("−")
                            .disabled(self.string_minimum <= 2)
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.string_minimum = this.string_minimum.saturating_sub(1).max(2);
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new("strings-min-more")
                            .label("+")
                            .disabled(self.string_minimum >= 64)
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.string_minimum = (this.string_minimum + 1).min(64);
                                cx.notify();
                            })),
                    ),
            )
            .child(table_panel(
                "Extracted Strings",
                &[
                    "File offset",
                    "Virtual address",
                    "Section",
                    "Encoding",
                    "Value",
                ],
                rows,
                cx,
            ))
    }
    fn render_dependency_graph(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let names: std::collections::HashMap<_, _> = self
            .dependency_graph
            .nodes
            .iter()
            .map(|node| (node.artifact_id, node.name.clone()))
            .collect();
        let query = self.query.to_lowercase();
        let rows = self
            .dependency_graph
            .edges
            .iter()
            .filter_map(|edge| {
                let source = names
                    .get(&edge.source)
                    .cloned()
                    .unwrap_or_else(|| edge.source.to_string());
                let target = edge
                    .target
                    .and_then(|id| names.get(&id).cloned())
                    .or_else(|| {
                        edge.resolved_path
                            .as_ref()
                            .map(|path| path.display().to_string())
                    })
                    .unwrap_or_default();
                let searchable = format!("{source} {} {target}", edge.requested).to_lowercase();
                (query.is_empty() || searchable.contains(&query)).then(|| {
                    vec![
                        source,
                        edge.source_architecture.clone().unwrap_or_default(),
                        edge.requested.clone(),
                        format!("{:?}", edge.status),
                        target,
                    ]
                })
            })
            .collect();
        table_panel(
            "Artifact Dependency Graph",
            &["Source", "Architecture", "Requested", "Status", "Target"],
            rows,
            cx,
        )
    }
    fn render_signature(&self) -> impl IntoElement {
        let values = self
            .container_signature
            .as_ref()
            .or_else(|| {
                self.current_analysis()
                    .and_then(|a| a.signature.as_ref())
                    .or_else(|| self.analysis.as_ref().and_then(|a| a.signature.as_ref()))
            })
            .map(|signature| {
                let mut values = vec![("Status".into(), format!("{:?}", signature.status))];
                for (key, value) in [
                    ("Signer", &signature.signer),
                    ("Identifier", &signature.identifier),
                    ("Team ID", &signature.team_id),
                    ("Timestamp", &signature.timestamp),
                ] {
                    if let Some(value) = value {
                        values.push((key.into(), value.clone()));
                    }
                }
                values.extend(
                    signature
                        .platform
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone())),
                );
                values
            })
            .unwrap_or_else(|| vec![("Status".into(), "No host signature result".into())]);
        kv_panel("Digital Signature", values)
    }
    fn render_overview(&self, node: &ArtifactNode) -> impl IntoElement {
        let a = self.current_analysis();
        let mut values = vec![
            ("Type".into(), format!("{:?}", node.kind)),
            (
                "Format".into(),
                node.format
                    .map(|f| format!("{f:?}"))
                    .unwrap_or_else(|| "Container".into()),
            ),
            ("Path".into(), node.path.display().to_string()),
            ("Size".into(), format_size(node.size)),
        ];
        if let Some(a) = a {
            values.extend([
                ("Architecture".into(), a.architecture.clone()),
                (
                    "Bits".into(),
                    a.bits.map(|x| x.to_string()).unwrap_or_default(),
                ),
                (
                    "Entry point".into(),
                    a.entry_point.map(fmt_addr).unwrap_or_default(),
                ),
                ("Dependencies".into(), a.dependencies.len().to_string()),
                (
                    "Imports / Exports".into(),
                    format!("{} / {}", a.imports.len(), a.exports.len()),
                ),
            ]);
            if let Some(compiler) = a.metadata.get("Compiler hint") {
                values.push(("Compiler hint".into(), compiler.clone()));
            }
            if let Some(signature) = a.signature.as_ref() {
                values.push(("Signature".into(), format!("{:?}", signature.status)));
            }
        }
        if let Some(s) = self.summary.as_deref() {
            values.push(("SHA-256".into(), s.sha256.clone().unwrap_or_default()));
            if let Some(sha1) = &s.sha1 {
                values.push(("SHA-1 (identification only)".into(), sha1.clone()));
            }
            if let Some(md5) = &s.md5 {
                values.push(("MD5 (identification only)".into(), md5.clone()));
            }
            values.push((
                "Whole-file entropy".into(),
                s.entropy
                    .map(|e| format!("{e:.3} bits/byte (indicator only)"))
                    .unwrap_or_default(),
            ));
        }
        if self
            .summary
            .as_ref()
            .is_none_or(|summary| summary.sha256.is_none())
            && node.path.is_file()
        {
            values.push((
                "SHA-256 / entropy".into(),
                "Not computed — use “Compute hashes + entropy”".into(),
            ));
        }
        div()
            .flex()
            .flex_col()
            .gap_4()
            .child(
                div()
                    .text_2xl()
                    .font_semibold()
                    .text_color(rgb(TEXT))
                    .child(node.name.clone()),
            )
            .child(kv_panel("Overview", values))
    }
    fn render_findings(&self) -> impl IntoElement {
        let findings = self
            .current_analysis()
            .map(|a| a.findings.as_slice())
            .unwrap_or(&[]);
        div()
            .flex()
            .flex_col()
            .gap_3()
            .child(panel_title("Inspection Findings"))
            .children(findings.iter().map(|f| {
                let color = match f.severity {
                    Severity::Info => ACCENT,
                    Severity::Low => GREEN,
                    Severity::Medium => WARNING,
                    Severity::High => HIGH,
                    Severity::Critical => DESTRUCTIVE,
                };
                div()
                    .p_4()
                    .rounded_md()
                    .bg(rgb(PANEL))
                    .border_1()
                    .border_color(rgb(BORDER))
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            .child(
                                div()
                                    .text_color(rgb(color))
                                    .font_semibold()
                                    .child(format!("{:?}", f.severity)),
                            )
                            .child(
                                div()
                                    .text_color(rgb(TEXT))
                                    .font_semibold()
                                    .child(f.title.clone()),
                            ),
                    )
                    .child(
                        div()
                            .mt_2()
                            .text_sm()
                            .text_color(rgb(MUTED))
                            .child(f.description.clone()),
                    )
                    .when(!f.evidence.is_empty(), |card| {
                        card.child(
                            div()
                                .mt_3()
                                .pt_3()
                                .border_t_1()
                                .border_color(rgb(BORDER))
                                .flex()
                                .flex_col()
                                .gap_1()
                                .children(f.evidence.iter().map(|evidence| {
                                    div()
                                        .flex()
                                        .gap_2()
                                        .text_xs()
                                        .child(
                                            div()
                                                .w(px(140.))
                                                .text_color(rgb(MUTED))
                                                .child(evidence.label.clone()),
                                        )
                                        .child(div().text_color(rgb(TEXT)).child(
                                            match evidence.offset {
                                                Some(offset) => format!(
                                                    "{} · offset 0x{offset:x}",
                                                    evidence.value
                                                ),
                                                None => evidence.value.clone(),
                                            },
                                        ))
                                })),
                        )
                    })
            }))
            .when(findings.is_empty(), |d| {
                d.child(info_panel(
                    "No findings",
                    "No inspection findings were produced by the lightweight analysis.",
                ))
            })
    }
    fn render_hex(&self, node: &ArtifactNode, cx: &mut Context<Self>) -> AnyElement {
        let offset = self.hex_offset.saturating_sub(self.hex_offset % 16);
        let preview = match HexReader::open(&node.path)
            .and_then(|mut reader| reader.read_chunk(offset, 4096))
        {
            Ok(preview) => preview,
            Err(error) => {
                return info_panel(
                    "Hex data unavailable",
                    format!("Could not read {}: {error}", node.path.display()),
                )
                .into_any_element();
            }
        };
        let rows = preview.chunks(16).enumerate().map(|(i, c)| {
            let row_offset = offset + (i * 16) as u64;
            let ascii = c
                .iter()
                .map(|b| {
                    if (0x20..=0x7e).contains(b) {
                        *b as char
                    } else {
                        '.'
                    }
                })
                .collect::<String>();
            div()
                .flex()
                .font_family("Menlo")
                .text_sm()
                .child(
                    div()
                        .w(px(90.))
                        .text_color(rgb(MUTED))
                        .child(format!("{:08x}", offset as usize + i * 16)),
                )
                .child(div().w(px(410.)).flex().children(c.iter().enumerate().map(
                    |(column, byte)| {
                        let byte_offset = row_offset + column as u64;
                        let selected = self
                            .hex_selection
                            .is_some_and(|(start, end)| byte_offset >= start && byte_offset < end);
                        div()
                            .id(SharedString::from(format!("hex-{byte_offset:x}")))
                            .w(px(24.))
                            .text_color(rgb(TEXT))
                            .cursor_pointer()
                            .when(selected, |d| d.bg(rgb(SELECTION)))
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.select_hex_byte(byte_offset, cx)
                            }))
                            .child(format!("{byte:02x}"))
                    },
                )))
                .child(div().text_color(rgb(GREEN)).child(ascii))
        });
        div()
            .flex()
            .flex_col()
            .gap_3()
            .child(panel_title(format!("Hex · 0x{offset:x} · 4 KiB chunk")))
            .child(div().p_4().rounded_md().bg(rgb(PANEL)).children(rows))
            .into_any_element()
    }
}

impl Render for ByteTrawlApp {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .size_full()
            .flex()
            .flex_col()
            .bg(rgb(BG))
            .text_color(rgb(TEXT))
            .on_action(cx.listener(|this, _: &OpenFile, _, cx| this.choose(false, cx)))
            .on_action(cx.listener(|this, _: &OpenArtifact, _, cx| this.choose(true, cx)))
            .on_action(cx.listener(|this, _: &OpenWorkspace, _, cx| this.open_workspace(cx)))
            .on_action(cx.listener(|this, _: &SaveWorkspace, _, cx| this.save_workspace(cx)))
            .on_action(cx.listener(|this, _: &FocusSearch, window, cx| {
                this.search_input.focus_handle(cx).focus(window)
            }))
            .child(
                div()
                    .h(px(36.))
                    .flex()
                    .flex_col()
                    .bg(rgb(PANEL))
                    .border_b_1()
                    .border_color(rgb(BORDER))
                    .child(
                        div()
                            .h(px(36.))
                            .flex()
                            .items_center()
                            .px_3()
                            .gap_1()
                            .bg(rgb(PANEL_2))
                            .border_t_1()
                            .border_color(rgb(BORDER))
                            .child(
                                div()
                                    .h(px(26.))
                                    .flex_1()
                                    .min_w(px(240.))
                                    .child(Input::new(&self.search_input).xsmall()),
                            )
                            .child(
                                Button::new("search-all")
                                    .label("Search Artifact")
                                    .xsmall()
                                    .compact()
                                    .on_click(cx.listener(|this, _, _, cx| this.search_all(cx))),
                            )
                            .child(
                                Button::new("search-mode-text")
                                    .label(if self.file_search_mode == FileSearchMode::Text {
                                        "Text ✓"
                                    } else {
                                        "Text"
                                    })
                                    .xsmall()
                                    .compact()
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.file_search_mode = FileSearchMode::Text;
                                        cx.notify();
                                    })),
                            )
                            .child(
                                Button::new("search-mode-bytes")
                                    .label(if self.file_search_mode == FileSearchMode::Bytes {
                                        "Bytes ✓"
                                    } else {
                                        "Bytes"
                                    })
                                    .xsmall()
                                    .compact()
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.file_search_mode = FileSearchMode::Bytes;
                                        cx.notify();
                                    })),
                            )
                            .child(
                                Button::new("find-next")
                                    .label("Find Next")
                                    .xsmall()
                                    .compact()
                                    .on_click(cx.listener(|this, _, _, cx| this.find_next(cx))),
                            )
                            .child(
                                Button::new("jump-offset")
                                    .label("Jump Offset")
                                    .xsmall()
                                    .compact()
                                    .on_click(
                                        cx.listener(|this, _, _, cx| this.jump_to_offset(cx)),
                                    ),
                            )
                            .child(
                                Button::new("copy-hex")
                                    .label("Copy Hex")
                                    .xsmall()
                                    .compact()
                                    .on_click(
                                        cx.listener(|this, _, _, cx| this.copy_hex_chunk(cx)),
                                    ),
                            )
                            .when(self.loading, |toolbar| {
                                toolbar
                                    .child(
                                        div()
                                            .ml_1()
                                            .text_xs()
                                            .text_color(rgb(ACCENT))
                                            .child("● Analyzing"),
                                    )
                                    .child(
                                        Button::new("cancel-task")
                                            .label("Cancel")
                                            .xsmall()
                                            .compact()
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.cancel_current_task(cx)
                                            })),
                                    )
                            }),
                    ),
            )
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .flex()
                    .child(self.render_sidebar(cx))
                    .child(self.render_main(cx))
                    .child(self.render_details(cx)),
            )
            .child(
                div()
                    .h(px(28.))
                    .flex()
                    .items_center()
                    .px_3()
                    .gap_3()
                    .bg(rgb(PANEL_2))
                    .border_t_1()
                    .border_color(rgb(BORDER))
                    .text_xs()
                    .text_color(rgb(MUTED))
                    .child(self.status.clone())
                    .when_some(self.error.clone(), |d, e| {
                        d.child(div().text_color(rgb(DESTRUCTIVE)).child(e))
                    }),
            )
    }
}

fn flatten(
    node: &ArtifactNode,
    depth: usize,
    expanded: &std::collections::HashSet<uuid::Uuid>,
    force_expand: bool,
    out: &mut Vec<(uuid::Uuid, usize, String, ArtifactKind, bool, bool)>,
) {
    out.push((
        node.id,
        depth,
        node.name.clone(),
        node.kind,
        !node.children.is_empty(),
        force_expand || expanded.contains(&node.id),
    ));
    if force_expand || expanded.contains(&node.id) {
        for child in &node.children {
            flatten(child, depth + 1, expanded, force_expand, out)
        }
    }
}
fn find_by_path<'a>(node: &'a ArtifactNode, path: &std::path::Path) -> Option<&'a ArtifactNode> {
    if node.path == path {
        return Some(node);
    }
    node.children
        .iter()
        .find_map(|child| find_by_path(child, path))
}
fn kind_icon(kind: ArtifactKind) -> &'static str {
    match kind {
        ArtifactKind::Group => "▾",
        ArtifactKind::Application => "◆",
        ArtifactKind::Directory | ArtifactKind::Bundle => "▸",
        ArtifactKind::Executable => "▶",
        ArtifactKind::DynamicLibrary | ArtifactKind::StaticLibrary | ArtifactKind::Framework => "⬡",
        ArtifactKind::Metadata => "≡",
        ArtifactKind::Resource => "◫",
        _ => "·",
    }
}
fn section_header(text: &'static str) -> impl IntoElement {
    div()
        .h(px(38.))
        .flex()
        .items_center()
        .px_3()
        .text_xs()
        .font_semibold()
        .text_color(rgb(MUTED))
        .child(text)
}
fn panel_title(text: impl Into<SharedString>) -> impl IntoElement {
    div()
        .text_lg()
        .font_semibold()
        .text_color(rgb(TEXT))
        .child(text.into())
}
fn kv_panel(title: &'static str, values: Vec<(String, String)>) -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .gap_3()
        .child(panel_title(title))
        .child(
            div()
                .rounded_md()
                .border_1()
                .border_color(rgb(BORDER))
                .bg(rgb(PANEL))
                .children(values.into_iter().map(|(k, v)| {
                    div()
                        .min_h(px(38.))
                        .flex()
                        .items_center()
                        .border_b_1()
                        .border_color(rgb(BORDER))
                        .child(
                            div()
                                .w(px(210.))
                                .px_3()
                                .text_sm()
                                .text_color(rgb(MUTED))
                                .child(k),
                        )
                        .child(
                            div()
                                .flex_1()
                                .px_3()
                                .text_sm()
                                .text_color(rgb(TEXT))
                                .child(v),
                        )
                })),
        )
}
fn table_panel(
    title: &'static str,
    headers: &'static [&'static str],
    rows: Vec<Vec<String>>,
    cx: &mut Context<ByteTrawlApp>,
) -> impl IntoElement {
    const MAX_RENDERED_ROWS: usize = 20_000;
    let total = rows.len();
    let truncated = total > MAX_RENDERED_ROWS;
    let visible_count = total.min(MAX_RENDERED_ROWS);
    let list_rows = Arc::new(rows);
    div()
        .flex_1()
        .min_h(px(160.))
        .flex()
        .flex_col()
        .gap_3()
        .child(panel_title(title))
        .when(truncated, |panel| {
            panel.child(
                div()
                    .text_xs()
                    .text_color(rgb(WARNING))
                    .child(format!(
                        "Showing the first {MAX_RENDERED_ROWS} of {total} rows; use search to narrow the result."
                    )),
            )
        })
        .child(
            div()
                .flex_1()
                .min_h_0()
                .flex()
                .flex_col()
                .rounded_md()
                .border_1()
                .border_color(rgb(BORDER))
                .bg(rgb(PANEL))
                .child(
                    div()
                        .h(px(34.))
                        .flex()
                        .bg(rgb(PANEL_2))
                        .children(headers.iter().map(|h| {
                            div()
                                .flex_1()
                                .px_2()
                                .flex()
                                .items_center()
                                .text_xs()
                                .font_semibold()
                                .text_color(rgb(MUTED))
                                .child(*h)
                        })),
                )
                .child(
                    uniform_list(
                        SharedString::from(format!("table-{title}")),
                        visible_count,
                        cx.processor(move |_this, range: std::ops::Range<usize>, _, _| {
                            range
                                .filter_map(|index| list_rows.get(index))
                                .map(|row| {
                                    div()
                                        .h(px(32.))
                                        .flex()
                                        .border_t_1()
                                        .border_color(rgb(BORDER))
                                        .children(row.iter().cloned().map(|value| {
                                            div()
                                                .flex_1()
                                                .min_w_0()
                                                .px_2()
                                                .flex()
                                                .items_center()
                                                .text_xs()
                                                .text_color(rgb(TEXT))
                                                .overflow_hidden()
                                                .child(value)
                                        }))
                                })
                                .collect::<Vec<_>>()
                        }),
                    )
                    .flex_1()
                    .min_h(px(96.)),
                ),
        )
}
fn symbol_table(
    title: &'static str,
    symbols: &[bytetrawl_core::SymbolInfo],
    query: &str,
    cx: &mut Context<ByteTrawlApp>,
) -> impl IntoElement {
    let query = query.to_lowercase();
    table_panel(
        title,
        &["Name", "Address", "Library"],
        symbols
            .iter()
            .filter(|symbol| {
                query.is_empty()
                    || symbol.name.to_lowercase().contains(&query)
                    || symbol
                        .library
                        .as_ref()
                        .is_some_and(|library| library.to_lowercase().contains(&query))
            })
            .map(|s| {
                vec![
                    s.name.clone(),
                    s.address.map(fmt_addr).unwrap_or_default(),
                    s.library.clone().unwrap_or_default(),
                ]
            })
            .collect(),
        cx,
    )
}
fn info_panel(title: &'static str, text: impl Into<SharedString>) -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .gap_3()
        .child(panel_title(title))
        .child(
            div()
                .p_4()
                .rounded_md()
                .bg(rgb(PANEL))
                .border_1()
                .border_color(rgb(BORDER))
                .text_sm()
                .text_color(rgb(MUTED))
                .child(text.into()),
        )
}
fn empty_state() -> impl IntoElement {
    div()
        .size_full()
        .flex()
        .flex_col()
        .items_center()
        .justify_center()
        .gap_2()
        .text_color(rgb(MUTED))
        .child(
            div()
                .text_base()
                .font_medium()
                .text_color(rgb(TEXT))
                .child("Drop a file or folder here to inspect"),
        )
        .child(
            div()
                .text_sm()
                .child("Applications, packages, binaries, and ByteTrawl workspaces are supported"),
        )
}
fn fmt_addr(v: u64) -> String {
    format!("0x{v:016x}")
}
fn format_size(v: u64) -> String {
    if v >= 1 << 30 {
        format!("{:.2} GB", v as f64 / (1u64 << 30) as f64)
    } else if v >= 1 << 20 {
        format!("{:.2} MB", v as f64 / (1u64 << 20) as f64)
    } else if v >= 1 << 10 {
        format!("{:.1} KB", v as f64 / 1024.)
    } else {
        format!("{v} B")
    }
}

fn configure_component_theme(cx: &mut App) {
    Theme::change(ThemeMode::Dark, None, cx);
    let theme = Theme::global_mut(cx);
    let background = rgb(BG).into();
    let panel = rgb(PANEL).into();
    let raised = rgb(PANEL_2).into();
    let border = rgb(BORDER).into();
    let text = rgb(TEXT).into();
    let muted = rgb(MUTED).into();
    let primary = rgb(GREEN).into();
    let selection = rgb(SELECTION).into();
    let danger = rgb(DESTRUCTIVE).into();
    theme.mode = ThemeMode::Dark;
    theme.background = background;
    theme.foreground = text;
    theme.border = border;
    theme.input = border;
    theme.primary = primary;
    theme.primary_hover = rgb(PRIMARY_HOVER).into();
    theme.primary_active = rgb(PRIMARY_ACTIVE).into();
    theme.primary_foreground = background;
    theme.secondary = raised;
    theme.secondary_hover = rgb(SELECTION).into();
    theme.secondary_active = border;
    theme.secondary_foreground = text;
    theme.accent = raised;
    theme.accent_foreground = text;
    theme.muted = raised;
    theme.muted_foreground = muted;
    theme.selection = selection;
    theme.ring = primary;
    theme.caret = primary;
    theme.link = primary;
    theme.link_hover = rgb(PRIMARY_HOVER).into();
    theme.link_active = rgb(PRIMARY_ACTIVE).into();
    theme.danger = danger;
    theme.danger_hover = rgb(DESTRUCTIVE_HOVER).into();
    theme.danger_active = rgb(DESTRUCTIVE_ACTIVE).into();
    theme.danger_foreground = background;
    theme.popover = panel;
    theme.popover_foreground = text;
    theme.list = panel;
    theme.list_even = background;
    theme.list_head = raised;
    theme.list_hover = raised;
    theme.list_active = selection;
    theme.list_active_border = primary;
    theme.table = panel;
    theme.table_even = background;
    theme.table_head = raised;
    theme.table_head_foreground = muted;
    theme.table_hover = raised;
    theme.table_active = selection;
    theme.table_active_border = primary;
    theme.table_row_border = border;
    theme.sidebar = panel;
    theme.sidebar_foreground = text;
    theme.sidebar_border = border;
    theme.sidebar_accent = raised;
    theme.sidebar_accent_foreground = text;
    theme.sidebar_primary = primary;
    theme.sidebar_primary_foreground = background;
    theme.title_bar = background;
    theme.title_bar_border = border;
    theme.scrollbar = background;
    theme.scrollbar_thumb = border;
    theme.scrollbar_thumb_hover = muted;
    theme.radius = px(2.4);
    theme.radius_lg = px(3.2);
}

fn quit(_: &Quit, cx: &mut App) {
    cx.quit();
}

fn main() {
    Application::new().run(|cx| {
        gpui_component::init(cx);
        configure_component_theme(cx);
        cx.activate(true);
        cx.on_action(quit);
        cx.bind_keys([
            KeyBinding::new("cmd-o", OpenFile, None),
            KeyBinding::new("cmd-shift-o", OpenArtifact, None),
            KeyBinding::new("cmd-alt-o", OpenWorkspace, None),
            KeyBinding::new("cmd-s", SaveWorkspace, None),
            KeyBinding::new("cmd-f", FocusSearch, None),
        ]);
        cx.set_menus(vec![
            Menu {
                name: "ByteTrawl".into(),
                items: vec![
                    MenuItem::os_submenu("Services", SystemMenuType::Services),
                    MenuItem::separator(),
                    MenuItem::action("Quit ByteTrawl", Quit),
                ],
            },
            Menu {
                name: "File".into(),
                items: vec![
                    MenuItem::action("Open File…", OpenFile),
                    MenuItem::action("Open Folder…", OpenArtifact),
                    MenuItem::action("Open Workspace…", OpenWorkspace),
                    MenuItem::separator(),
                    MenuItem::action("Save Workspace…", SaveWorkspace),
                ],
            },
            Menu {
                name: "Edit".into(),
                items: vec![
                    MenuItem::os_action("Undo", Undo, OsAction::Undo),
                    MenuItem::os_action("Redo", Redo, OsAction::Redo),
                    MenuItem::separator(),
                    MenuItem::os_action("Cut", Cut, OsAction::Cut),
                    MenuItem::os_action("Copy", Copy, OsAction::Copy),
                    MenuItem::os_action("Paste", Paste, OsAction::Paste),
                    MenuItem::os_action("Select All", SelectAll, OsAction::SelectAll),
                ],
            },
            Menu {
                name: "View".into(),
                items: vec![MenuItem::action("Focus Search", FocusSearch)],
            },
        ]);
        cx.spawn(async move |cx| {
            cx.open_window(
                WindowOptions {
                    window_bounds: Some(WindowBounds::Windowed(Bounds {
                        origin: point(px(80.), px(60.)),
                        size: size(px(1440.), px(900.)),
                    })),
                    titlebar: Some(TitlebarOptions {
                        title: Some("ByteTrawl".into()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                |window, cx| {
                    let view = cx.new(|cx| ByteTrawlApp::new(window, cx));
                    cx.new(|cx| Root::new(view, window, cx))
                },
            )?;
            anyhow::Ok(())
        })
        .detach()
    })
}
