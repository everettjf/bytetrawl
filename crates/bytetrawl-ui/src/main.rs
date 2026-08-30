#![recursion_limit = "512"]

use bytetrawl::file_search::{FileSearchMode, parse_search_bytes};
use bytetrawl_analysis::{
    AnalysisCache, ArtifactReader, CancellationToken, ExtractedString, HashOptions, HexReader,
    SearchHit, analyze_node, annotate_string_locations, apply_signature_analysis,
    build_dependency_graph, enrich_analysis_entropy, entropy, extract_strings_node_cancellable,
    global_search_cached, hash_file, inspect_metadata, inspect_signature_cancellable,
    open_artifact, resolve_dependencies, search_node,
};
use bytetrawl_android::{AndroidAuditReportV1, audit_apk, is_apk};
use bytetrawl_compare::{ChangeKind, CompareReportV1, compare_artifacts};
use bytetrawl_core::{
    ArtifactKind, ArtifactNode, BinaryAnalysis, BinaryPlatform, DependencyGraph, FileSummary,
    Finding, Severity, SignatureInfo, Workspace,
};
use bytetrawl_ios::{IpaAuditReportV1, audit_ipa};
use bytetrawl_linux::{DebianReportV1, audit_deb, is_deb};
use bytetrawl_policy::{
    PolicyViolation, ReleasePolicyV1, evaluate_android, evaluate_compare, evaluate_ipa,
    evaluate_linux, evaluate_windows,
};
use bytetrawl_tools::{ToolAvailability, ToolBehavior, ToolRegistry};
use bytetrawl_windows::{WindowsPackageReportV1, audit_msix, is_msix};
use gpui::prelude::FluentBuilder;
use gpui::*;
use gpui_component::{
    Disableable, Root, Sizable, StyledExt, Theme, ThemeMode,
    badge::Badge,
    button::{Button, ButtonVariants as _},
    chart::{AreaChart, BarChart, PieChart},
    input::{Copy, Cut, Input, InputEvent, InputState, Paste, Redo, SelectAll, Undo},
    menu::{DropdownMenu as _, PopupMenuItem},
    progress::Progress,
    resizable::{h_resizable, resizable_panel},
    tab::{Tab, TabBar},
};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
struct ChartDatum {
    label: String,
    value: f64,
    bytes: u64,
    color: u32,
}

#[derive(Clone)]
struct TreemapItem {
    id: Option<uuid::Uuid>,
    label: String,
    bytes: u64,
    delta: Option<i128>,
    color: u32,
    x: f32,
    y: f32,
    width: f32,
    height: f32,
}

#[derive(Clone)]
struct EntropySample {
    label: String,
    offset: u64,
    entropy: f64,
}

const CHART_COLORS: [u32; 8] = [
    GREEN, ACCENT, 0x6fa7c8, 0xb58ad6, HIGH, 0x72b5a4, 0xc5ad68, 0x8b9bb4,
];
use std::{
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
};

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
        OpenPolicy,
        CompareArtifacts,
        CompareFolders,
        NewWindow,
        ToggleSidebar,
        ToggleInspector,
        LayoutStandard,
        LayoutFocus,
        LayoutAnalysis,
        ToggleHighContrast,
        ExportVisualReport,
        SaveWorkspace,
        FocusSearch,
        Quit
    ]
);

#[derive(Clone, PartialEq, Action)]
#[action(namespace = bytetrawl, no_json)]
struct OpenRecent {
    path: PathBuf,
}

#[derive(Default)]
struct WindowViews(std::collections::HashMap<WindowId, WeakEntity<ByteTrawlApp>>);

impl Global for WindowViews {}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
struct UiPreferences {
    show_sidebar: bool,
    show_inspector: bool,
    high_contrast: bool,
}

impl Default for UiPreferences {
    fn default() -> Self {
        Self {
            show_sidebar: true,
            show_inspector: true,
            high_contrast: false,
        }
    }
}

static STARTUP_PATH: OnceLock<Mutex<Option<PathBuf>>> = OnceLock::new();

fn take_startup_path() -> Option<PathBuf> {
    STARTUP_PATH
        .get_or_init(|| {
            let path = std::env::args_os().nth(1).map(PathBuf::from);
            Mutex::new(path.filter(|path| path.exists()))
        })
        .lock()
        .ok()?
        .take()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InspectorTab {
    Search,
    Compare,
    AndroidSummary,
    AndroidComponents,
    AndroidFindings,
    WindowsSummary,
    WindowsApplications,
    WindowsFindings,
    LinuxSummary,
    LinuxFiles,
    LinuxFindings,
    Policy,
    IpaSummary,
    IpaTargets,
    IpaPrivacy,
    IpaSigning,
    IpaFindings,
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
    SizeLab,
    Entropy,
}

impl InspectorTab {
    fn label(self) -> &'static str {
        match self {
            Self::Search => "Search",
            Self::Compare => "Compare",
            Self::AndroidSummary => "Android Summary",
            Self::AndroidComponents => "Components",
            Self::AndroidFindings => "Android Findings",
            Self::WindowsSummary => "Windows Summary",
            Self::WindowsApplications => "Applications",
            Self::WindowsFindings => "Windows Findings",
            Self::LinuxSummary => "Linux Summary",
            Self::LinuxFiles => "Installed Files",
            Self::LinuxFindings => "Linux Findings",
            Self::Policy => "Policy",
            Self::IpaSummary => "Summary",
            Self::IpaTargets => "Targets",
            Self::IpaPrivacy => "Privacy",
            Self::IpaSigning => "Signing",
            Self::IpaFindings => "Findings",
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
            Self::SizeLab => "Size Lab",
            Self::Entropy => "Entropy",
        }
    }
    fn from_label(label: &str) -> Option<Self> {
        [
            Self::Search,
            Self::Compare,
            Self::AndroidSummary,
            Self::AndroidComponents,
            Self::AndroidFindings,
            Self::WindowsSummary,
            Self::WindowsApplications,
            Self::WindowsFindings,
            Self::LinuxSummary,
            Self::LinuxFiles,
            Self::LinuxFindings,
            Self::Policy,
            Self::IpaSummary,
            Self::IpaTargets,
            Self::IpaPrivacy,
            Self::IpaSigning,
            Self::IpaFindings,
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
            Self::SizeLab,
            Self::Entropy,
        ]
        .into_iter()
        .find(|tab| tab.label() == label)
    }
}

struct ByteTrawlApp {
    focus_handle: FocusHandle,
    artifact: Option<Arc<ArtifactNode>>,
    ipa_report: Option<Arc<IpaAuditReportV1>>,
    comparison: Option<Arc<CompareReportV1>>,
    android_report: Option<Arc<AndroidAuditReportV1>>,
    windows_report: Option<Arc<WindowsPackageReportV1>>,
    linux_report: Option<Arc<DebianReportV1>>,
    policy: Option<Arc<ReleasePolicyV1>>,
    policy_path: Option<PathBuf>,
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
    entropy_profile: Arc<Vec<EntropySample>>,
    entropy_loaded: bool,
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
    show_sidebar: bool,
    show_inspector: bool,
    finding_filter: Option<Severity>,
    high_contrast: bool,
}

impl ByteTrawlApp {
    fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let preferences = load_ui_preferences();
        let focus_handle = cx.focus_handle();
        focus_handle.focus(window);
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
            focus_handle,
            artifact: None,
            ipa_report: None,
            comparison: None,
            android_report: None,
            windows_report: None,
            linux_report: None,
            policy: None,
            policy_path: None,
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
            entropy_profile: Arc::default(),
            entropy_loaded: false,
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
            show_sidebar: preferences.show_sidebar,
            show_inspector: preferences.show_inspector,
            finding_filter: None,
            high_contrast: preferences.high_contrast,
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
    fn choose_comparison(&mut self, folders: bool, cx: &mut Context<Self>) {
        let baseline_dialog = rfd::FileDialog::new().set_title("Choose baseline artifact");
        let Some(before) = (if folders {
            baseline_dialog.pick_folder()
        } else {
            baseline_dialog.pick_file()
        }) else {
            return;
        };
        let candidate_dialog = rfd::FileDialog::new().set_title("Choose candidate artifact");
        let Some(after) = (if folders {
            candidate_dialog.pick_folder()
        } else {
            candidate_dialog.pick_file()
        }) else {
            return;
        };
        self.cancellation.cancel();
        self.cancellation = CancellationToken::default();
        self.task_generation = self.task_generation.wrapping_add(1);
        let generation = self.task_generation;
        let cancellation = self.cancellation.clone();
        self.loading = true;
        self.error = None;
        self.status = "Comparing baseline and candidate…".into();
        cx.notify();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn(async move {
                    let baseline = open_artifact(&before, &cancellation)?;
                    let candidate = open_artifact(&after, &cancellation)?;
                    let baseline_ipa = baseline
                        .properties
                        .get("Package Format")
                        .is_some_and(|format| format == "Apple iOS IPA")
                        .then(|| audit_ipa(&baseline, &cancellation))
                        .transpose()?;
                    let candidate_ipa = candidate
                        .properties
                        .get("Package Format")
                        .is_some_and(|format| format == "Apple iOS IPA")
                        .then(|| audit_ipa(&candidate, &cancellation))
                        .transpose()?;
                    compare_artifacts(
                        &baseline,
                        &candidate,
                        baseline_ipa.as_ref(),
                        candidate_ipa.as_ref(),
                        &cancellation,
                    )
                })
                .await;
            this.update(cx, |this, cx| {
                if this.task_generation != generation {
                    return;
                }
                this.loading = false;
                match result {
                    Ok(report) => {
                        this.comparison = Some(Arc::new(report));
                        this.tab = InspectorTab::Compare;
                        this.status = "Comparison ready".into();
                    }
                    Err(error) => {
                        this.error = Some(error.to_string().into());
                        this.status = "Comparison failed".into();
                    }
                }
                cx.notify();
            })?;
            anyhow::Ok(())
        })
        .detach();
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
    fn open_policy(&mut self, cx: &mut Context<Self>) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("ByteTrawl Policy", &["json"])
            .pick_file()
        else {
            return;
        };
        match std::fs::read(&path)
            .map_err(|error| error.to_string())
            .and_then(|bytes| serde_json::from_slice(&bytes).map_err(|error| error.to_string()))
        {
            Ok(policy) => {
                self.policy = Some(Arc::new(policy));
                self.policy_path = Some(path.clone());
                self.tab = InspectorTab::Policy;
                self.status = format!("Policy loaded from {}", path.display()).into();
            }
            Err(error) => self.error = Some(format!("Could not load policy: {error}").into()),
        }
        cx.notify();
    }
    fn policy_violations(&self) -> Vec<PolicyViolation> {
        let Some(policy) = self.policy.as_deref() else {
            return Vec::new();
        };
        let mut violations = Vec::new();
        if let Some(report) = self.comparison.as_deref() {
            violations.extend(evaluate_compare(policy, report));
        }
        if let Some(report) = self.ipa_report.as_deref() {
            violations.extend(evaluate_ipa(policy, report));
        }
        if let Some(report) = self.android_report.as_deref() {
            violations.extend(evaluate_android(policy, report));
        }
        if let Some(report) = self.windows_report.as_deref() {
            violations.extend(evaluate_windows(policy, report));
        }
        if let Some(report) = self.linux_report.as_deref() {
            violations.extend(evaluate_linux(policy, report));
        }
        violations.sort_by(|left, right| left.rule_id.cmp(&right.rule_id));
        violations.dedup();
        violations
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
                    let ipa_report = root
                        .properties
                        .get("Package Format")
                        .is_some_and(|format| format == "Apple iOS IPA")
                        .then(|| audit_ipa(&root, &cancellation))
                        .transpose()?;
                    let android_report = is_apk(&root)
                        .then(|| audit_apk(&root, &cancellation))
                        .transpose()?;
                    let windows_report = is_msix(&root)
                        .then(|| audit_msix(&root, &cancellation))
                        .transpose()?;
                    let linux_report = is_deb(&root.path)
                        .then(|| audit_deb(&root.path))
                        .transpose()?;
                    Ok::<_, bytetrawl_core::ByteTrawlError>((
                        root,
                        metadata,
                        ipa_report,
                        android_report,
                        windows_report,
                        linux_report,
                    ))
                })
                .await;
            this.update(cx, |this, cx| {
                if this.task_generation != generation {
                    return;
                }
                this.loading = false;
                match result {
                    Ok((
                        root,
                        metadata,
                        ipa_report,
                        android_report,
                        windows_report,
                        linux_report,
                    )) => {
                        let opened_path = root.path.clone();
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
                        this.ipa_report = ipa_report.map(Arc::new);
                        this.android_report = android_report.map(Arc::new);
                        this.windows_report = windows_report.map(Arc::new);
                        this.linux_report = linux_report.map(Arc::new);
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
                        if let Err(error) = record_recent_artifact(&opened_path) {
                            this.error =
                                Some(format!("Could not update recent artifacts: {error}").into());
                        }
                        install_menus(cx);
                        if this.ipa_report.is_some()
                            && id == this.artifact.as_ref().map_or(id, |root| root.id)
                        {
                            this.tab = InspectorTab::IpaSummary;
                        } else if this.android_report.is_some()
                            && id == this.artifact.as_ref().map_or(id, |root| root.id)
                        {
                            this.tab = InspectorTab::AndroidSummary;
                        } else if this.windows_report.is_some()
                            && id == this.artifact.as_ref().map_or(id, |root| root.id)
                        {
                            this.tab = InspectorTab::WindowsSummary;
                        } else if this.linux_report.is_some()
                            && id == this.artifact.as_ref().map_or(id, |root| root.id)
                        {
                            this.tab = InspectorTab::LinuxSummary;
                        }
                        let should_analyze = this
                            .artifact
                            .as_ref()
                            .and_then(|artifact| artifact.find(id))
                            .is_some_and(ArtifactNode::is_file);
                        if should_analyze {
                            this.select(id, cx);
                        } else if let Some(tab) = this.restore_tab.take()
                            && this.tabs().contains(&tab)
                        {
                            this.set_tab(tab, cx);
                        }
                    }
                    Err(e) => {
                        this.ipa_report = None;
                        this.android_report = None;
                        this.windows_report = None;
                        this.linux_report = None;
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
        self.entropy_profile = Arc::default();
        self.entropy_loaded = false;
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
        if node.is_dir() {
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
        } else if tab == InspectorTab::Entropy && !self.entropy_loaded {
            self.load_entropy_profile(cx);
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
        self.selected_node().is_some_and(|node| {
            matches!(
                node.source,
                Some(bytetrawl_core::ArtifactSource::Filesystem { .. })
            ) && (self
                .current_analysis()
                .is_some_and(|analysis| analysis.platform == Some(BinaryPlatform::MacOs))
                || {
                    matches!(
                        node.kind,
                        ArtifactKind::Application
                            | ArtifactKind::Bundle
                            | ArtifactKind::Framework
                            | ArtifactKind::Plugin
                    )
                })
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
        let Some(node) = self.selected_node().filter(|node| node.is_file()).cloned() else {
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
                        extract_strings_node_cancellable(&node, 2, 100_000, &cancellation)?;
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
    fn load_entropy_profile(&mut self, cx: &mut Context<Self>) {
        let Some(node) = self.selected_node().filter(|node| node.is_file()).cloned() else {
            return;
        };
        self.cancellation.cancel();
        self.cancellation = CancellationToken::default();
        self.task_generation = self.task_generation.wrapping_add(1);
        let generation = self.task_generation;
        let cancellation = self.cancellation.clone();
        self.loading = true;
        self.status = format!("Sampling entropy across {}…", node.name).into();
        cx.notify();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn(async move { sample_entropy_profile(&node, &cancellation) })
                .await;
            this.update(cx, |this, cx| {
                if this.task_generation != generation {
                    return;
                }
                this.loading = false;
                match result {
                    Ok(samples) => {
                        let count = samples.len();
                        this.entropy_profile = Arc::new(samples);
                        this.entropy_loaded = true;
                        this.status = format!("Entropy profile ready · {count} samples").into();
                    }
                    Err(error) => {
                        this.error = Some(error.to_string().into());
                        this.status = "Entropy profile incomplete".into();
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
        if !node.is_file() || self.query.is_empty() {
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
                .background_spawn(async move { search_node(&node, &needle, start, &cancellation) })
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
        let bytes = match HexReader::open_node(node)
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
        let Some(node) = self.selected_node().filter(|node| node.is_file()).cloned() else {
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
    fn navigate_to_evidence(&mut self, path: &std::path::Path, cx: &mut Context<Self>) {
        let Some(root) = self.artifact.as_deref() else {
            return;
        };
        let mut ancestors = Vec::new();
        let Some(id) = find_archive_member_with_ancestors(root, path, &mut ancestors) else {
            self.error = Some(format!("Evidence node is unavailable: {}", path.display()).into());
            cx.notify();
            return;
        };
        self.expanded_nodes.extend(ancestors);
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
        if self.comparison.is_some() {
            tabs.push(InspectorTab::Compare);
        }
        if self.policy.is_some() {
            tabs.push(InspectorTab::Policy);
        }
        let ipa_root_selected = self.ipa_report.is_some()
            && self.selected_node().is_some_and(|node| {
                self.artifact
                    .as_ref()
                    .is_some_and(|artifact| artifact.id == node.id)
            });
        if ipa_root_selected {
            tabs.extend([
                InspectorTab::IpaSummary,
                InspectorTab::IpaTargets,
                InspectorTab::IpaPrivacy,
                InspectorTab::IpaSigning,
                InspectorTab::IpaFindings,
                InspectorTab::DependencyGraph,
            ]);
            return tabs;
        }
        let android_root_selected = self.android_report.is_some()
            && self.selected_node().is_some_and(|node| {
                self.artifact
                    .as_ref()
                    .is_some_and(|artifact| artifact.id == node.id)
            });
        if android_root_selected {
            tabs.extend([
                InspectorTab::AndroidSummary,
                InspectorTab::AndroidComponents,
                InspectorTab::AndroidFindings,
                InspectorTab::DependencyGraph,
            ]);
            return tabs;
        }
        let windows_root_selected = self.windows_report.is_some()
            && self.selected_node().is_some_and(|node| {
                self.artifact
                    .as_ref()
                    .is_some_and(|artifact| artifact.id == node.id)
            });
        if windows_root_selected {
            tabs.extend([
                InspectorTab::WindowsSummary,
                InspectorTab::WindowsApplications,
                InspectorTab::WindowsFindings,
                InspectorTab::DependencyGraph,
            ]);
            return tabs;
        }
        let linux_root_selected = self.linux_report.is_some()
            && self.selected_node().is_some_and(|node| {
                self.artifact
                    .as_ref()
                    .is_some_and(|artifact| artifact.id == node.id)
            });
        if linux_root_selected {
            tabs.extend([
                InspectorTab::LinuxSummary,
                InspectorTab::LinuxFiles,
                InspectorTab::LinuxFindings,
                InspectorTab::DependencyGraph,
            ]);
            return tabs;
        }
        tabs.push(InspectorTab::Overview);
        if self.artifact.is_some() {
            tabs.push(InspectorTab::SizeLab);
        }
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
                tabs.push(InspectorTab::Entropy);
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
        } else if self.selected_node().is_some_and(ArtifactNode::is_file) {
            tabs.push(InspectorTab::Hex);
            tabs.push(InspectorTab::Entropy);
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
            .w_full()
            .h_full()
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
                .w_full()
                .h_full()
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
                            tool.behavior(),
                            matches!(tool.detect(), ToolAvailability::Available(_)),
                        )
                    })
            })
            .collect();
        let available_tools: Vec<_> = tool_items
            .iter()
            .filter(|(_, _, _, available)| *available)
            .map(|(id, name, behavior, _)| (*id, *name, *behavior))
            .collect();
        let unavailable_tool_count = tool_items.len().saturating_sub(available_tools.len());
        let available_tool_count = available_tools.len();
        let tool_menu_view = cx.entity();
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
            .w_full()
            .h_full()
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
                            .disabled(!self.selected_node().is_some_and(ArtifactNode::is_file))
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
            .child(section_header("EXTERNAL TOOLS"))
            .child(
                div()
                    .id("external-tools")
                    .p_3()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(
                        Button::new("external-tools-menu")
                            .label(if available_tool_count == 0 {
                                "No compatible tools installed".to_string()
                            } else {
                                format!("External Tools…  {available_tool_count}")
                            })
                            .disabled(available_tool_count == 0)
                            .dropdown_menu(move |menu, window, _| {
                                let menu = available_tools.iter().fold(
                                    menu.min_w(230.),
                                    |menu, (id, name, behavior)| {
                                        let id = *id;
                                        let label = match behavior {
                                            ToolBehavior::Launch => format!("Open in {name}"),
                                            ToolBehavior::Capture => format!("Run {name}"),
                                        };
                                        menu.item(PopupMenuItem::new(label).on_click(
                                            window.listener_for(
                                                &tool_menu_view,
                                                move |this, _, _, cx| this.launch_tool(id, cx),
                                            ),
                                        ))
                                    },
                                );
                                menu.when(unavailable_tool_count > 0, |menu| {
                                    menu.separator().item(PopupMenuItem::label(format!(
                                        "{unavailable_tool_count} compatible tools not installed"
                                    )))
                                })
                            }),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(rgb(MUTED))
                            .child(if available_tool_count == 0 {
                                format!(
                                    "{unavailable_tool_count} compatible integrations detected; install one to enable this menu."
                                )
                            } else {
                                "Only compatible installed tools are shown.".to_string()
                            }),
                    ),
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

    fn save_ui_preferences(&self) {
        let _ = store_ui_preferences(&UiPreferences {
            show_sidebar: self.show_sidebar,
            show_inspector: self.show_inspector,
            high_contrast: self.high_contrast,
        });
    }

    fn apply_layout(&mut self, sidebar: bool, inspector: bool, cx: &mut Context<Self>) {
        self.show_sidebar = sidebar;
        self.show_inspector = inspector;
        self.save_ui_preferences();
        self.status = match (sidebar, inspector) {
            (true, true) => "Standard workbench layout",
            (false, false) => "Focus layout",
            (true, false) => "Analysis layout",
            (false, true) => "Inspector layout",
        }
        .into();
        cx.notify();
    }

    fn export_visual_report(&mut self, cx: &mut Context<Self>) {
        let Some(root) = self.artifact.as_deref() else {
            self.error = Some("Open an artifact before exporting a visual report.".into());
            cx.notify();
            return;
        };
        let destination = rfd::FileDialog::new()
            .set_title("Export ByteTrawl Visual Report")
            .set_file_name("bytetrawl-visual-report.svg")
            .add_filter("Scalable Vector Graphic", &["svg"])
            .save_file();
        let Some(destination) = destination else {
            return;
        };
        let findings = self
            .current_analysis()
            .map(|analysis| analysis.findings.as_slice())
            .unwrap_or(&[]);
        let report = visual_report_svg(root, findings);
        match std::fs::write(&destination, report) {
            Ok(()) => {
                self.status = format!("Visual report exported · {}", destination.display()).into()
            }
            Err(error) => self.error = Some(format!("Could not export report: {error}").into()),
        }
        cx.notify();
    }
    fn render_main(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let tabs = self.tabs();
        let selected_tab = tabs.iter().position(|tab| *tab == self.tab).unwrap_or(0);
        let tab_view = cx.entity();
        let tabs_for_click = tabs.clone();
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
                    .items_center()
                    .px_3()
                    .bg(rgb(PANEL))
                    .border_b_1()
                    .border_color(rgb(BORDER))
                    .overflow_x_scroll()
                    .child(
                        TabBar::new("inspector-tabs")
                            .underline()
                            .menu(true)
                            .small()
                            .selected_index(selected_tab)
                            .children(tabs.iter().map(|tab| {
                                let finding_count = match tab {
                                    InspectorTab::Findings => self
                                        .current_analysis()
                                        .map(|analysis| analysis.findings.len())
                                        .unwrap_or(0),
                                    InspectorTab::IpaFindings => self
                                        .ipa_report
                                        .as_ref()
                                        .map(|report| report.findings.len())
                                        .unwrap_or(0),
                                    InspectorTab::AndroidFindings => self
                                        .android_report
                                        .as_ref()
                                        .map(|report| report.findings.len())
                                        .unwrap_or(0),
                                    InspectorTab::WindowsFindings => self
                                        .windows_report
                                        .as_ref()
                                        .map(|report| report.findings.len())
                                        .unwrap_or(0),
                                    InspectorTab::LinuxFindings => self
                                        .linux_report
                                        .as_ref()
                                        .map(|report| report.findings.len())
                                        .unwrap_or(0),
                                    _ => 0,
                                };
                                Tab::new().label(tab.label()).suffix(
                                    Badge::new().count(finding_count).color(rgb(DESTRUCTIVE)),
                                )
                            }))
                            .on_click(move |index, _, cx| {
                                if let Some(tab) = tabs_for_click.get(*index).copied() {
                                    tab_view.update(cx, |this, cx| this.set_tab(tab, cx));
                                }
                            }),
                    ),
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
        if self.tab == InspectorTab::Compare {
            return self.render_comparison(cx).into_any_element();
        }
        let Some(node) = self.selected_node() else {
            return empty_state().into_any_element();
        };
        match self.tab {
            InspectorTab::Search => self.render_search(cx).into_any_element(),
            InspectorTab::Compare => empty_state().into_any_element(),
            InspectorTab::AndroidSummary => self.render_android_summary().into_any_element(),
            InspectorTab::AndroidComponents => {
                self.render_android_components(cx).into_any_element()
            }
            InspectorTab::AndroidFindings => self.render_android_findings(cx).into_any_element(),
            InspectorTab::WindowsSummary => self.render_windows_summary().into_any_element(),
            InspectorTab::WindowsApplications => {
                self.render_windows_applications(cx).into_any_element()
            }
            InspectorTab::WindowsFindings => self.render_windows_findings(cx).into_any_element(),
            InspectorTab::LinuxSummary => self.render_linux_summary().into_any_element(),
            InspectorTab::LinuxFiles => self.render_linux_files(cx).into_any_element(),
            InspectorTab::LinuxFindings => self.render_linux_findings().into_any_element(),
            InspectorTab::Policy => self.render_policy().into_any_element(),
            InspectorTab::IpaSummary => self.render_ipa_summary().into_any_element(),
            InspectorTab::IpaTargets => self.render_ipa_targets(cx).into_any_element(),
            InspectorTab::IpaPrivacy => self.render_ipa_privacy().into_any_element(),
            InspectorTab::IpaSigning => self.render_ipa_signing().into_any_element(),
            InspectorTab::IpaFindings => self.render_ipa_findings(cx).into_any_element(),
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
            InspectorTab::Findings => self.render_findings(cx).into_any_element(),
            InspectorTab::SizeLab => self.render_size_lab(cx).into_any_element(),
            InspectorTab::Hex => self.render_hex(node, cx).into_any_element(),
            InspectorTab::Strings => self.render_strings(cx).into_any_element(),
            InspectorTab::Signature => self.render_signature().into_any_element(),
            InspectorTab::Entropy => self.render_entropy(cx).into_any_element(),
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
        let relations = self
            .dependency_graph
            .edges
            .iter()
            .take(24)
            .map(|edge| {
                let source = names
                    .get(&edge.source)
                    .cloned()
                    .unwrap_or_else(|| "Artifact".into());
                let target = edge
                    .target
                    .and_then(|id| names.get(&id).cloned())
                    .unwrap_or_else(|| edge.requested.clone());
                let color = match edge.status {
                    bytetrawl_core::DependencyStatus::Bundled => GREEN,
                    bytetrawl_core::DependencyStatus::System => ACCENT,
                    bytetrawl_core::DependencyStatus::Missing => DESTRUCTIVE,
                    bytetrawl_core::DependencyStatus::Unknown => WARNING,
                };
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(
                        div()
                            .w(px(180.))
                            .p_2()
                            .rounded_md()
                            .bg(rgb(PANEL_2))
                            .text_color(rgb(TEXT))
                            .truncate()
                            .child(source),
                    )
                    .child(div().text_color(rgb(color)).font_semibold().child("────▶"))
                    .child(
                        div()
                            .flex_1()
                            .p_2()
                            .rounded_md()
                            .border_1()
                            .border_color(rgb(color))
                            .text_color(rgb(TEXT))
                            .truncate()
                            .child(target),
                    )
            })
            .collect::<Vec<_>>();
        div()
            .flex()
            .flex_col()
            .gap_4()
            .child(panel_title(format!(
                "Dependency Map · {} nodes · {} edges",
                self.dependency_graph.nodes.len(),
                self.dependency_graph.edges.len()
            )))
            .child(
                div()
                    .p_4()
                    .rounded_lg()
                    .border_1()
                    .border_color(rgb(BORDER))
                    .bg(rgb(PANEL))
                    .flex()
                    .flex_col()
                    .gap_2()
                    .children(relations),
            )
            .child(table_panel(
                "Dependency Table",
                &["Source", "Architecture", "Requested", "Status", "Target"],
                rows,
                cx,
            ))
    }
    fn render_entropy(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let samples = self.entropy_profile.as_ref().clone();
        let chart_data = samples
            .iter()
            .map(|sample| ChartDatum {
                label: sample.label.clone(),
                value: sample.entropy,
                bytes: sample.offset,
                color: GREEN,
            })
            .collect::<Vec<_>>();
        let cells = samples
            .into_iter()
            .enumerate()
            .map(|(index, sample)| {
                let color = entropy_color(sample.entropy);
                div()
                    .id(("entropy-cell", index))
                    .w(px(34.))
                    .h(px(34.))
                    .rounded_sm()
                    .bg(rgb(color))
                    .border_1()
                    .border_color(rgb(BORDER))
                    .cursor_pointer()
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.hex_offset = sample.offset;
                        this.tab = InspectorTab::Hex;
                        this.status = format!("Entropy sample at 0x{:x}", sample.offset).into();
                        cx.notify();
                    }))
            })
            .collect::<Vec<_>>();
        div().flex().flex_col().gap_4()
            .child(panel_title("Entropy Profile"))
            .child(div().p_4().rounded_lg().border_1().border_color(rgb(BORDER)).bg(rgb(PANEL)).h(px(260.)).child(
                AreaChart::new(chart_data).x(|item| item.label.clone()).y(|item| item.value)
                    .stroke(rgb(GREEN)).fill(rgba(0x43e86b33))
            ))
            .child(info_panel("Block heatmap", "Each cell is a distributed 64 KiB sample. Brighter orange cells approach 8 bits/byte and can indicate compression or encryption. Click a cell to inspect its bytes."))
            .child(div().flex().flex_wrap().gap_1().children(cells))
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
        let identity = values
            .iter()
            .any(|(key, value)| key == "Signer" && !value.is_empty());
        let timestamp = values
            .iter()
            .any(|(key, value)| key == "Timestamp" && !value.is_empty());
        let trust_status = values
            .first()
            .map(|value| value.1.clone())
            .unwrap_or_else(|| "Unknown".into());
        div()
            .flex()
            .flex_col()
            .gap_4()
            .child(panel_title("Signature Trust Path"))
            .child(
                div()
                    .flex()
                    .gap_2()
                    .child(metric_card("1 · PARSED", "✓", "Signature envelope", GREEN))
                    .child(metric_card(
                        "2 · IDENTITY",
                        if identity { "✓" } else { "—" },
                        "Signer identity",
                        if identity { GREEN } else { WARNING },
                    ))
                    .child(metric_card(
                        "3 · TIMESTAMP",
                        if timestamp { "✓" } else { "—" },
                        "Trusted timestamp",
                        if timestamp { GREEN } else { WARNING },
                    ))
                    .child(metric_card(
                        "4 · TRUST",
                        trust_status,
                        "Host verification",
                        ACCENT,
                    )),
            )
            .child(kv_panel("Digital Signature", values))
    }
    fn render_comparison(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let Some(report) = self.comparison.as_deref() else {
            return empty_state().into_any_element();
        };
        let mut summary = vec![
            ("Baseline".into(), report.before.display().to_string()),
            ("Candidate".into(), report.after.display().to_string()),
            ("Baseline size".into(), format_size(report.before_bytes)),
            ("Candidate size".into(), format_size(report.after_bytes)),
            ("Size delta".into(), format_signed_size(report.delta_bytes)),
            ("Changed files".into(), report.files.len().to_string()),
            ("Moved files".into(), report.moved_files.len().to_string()),
            (
                "Duplicate groups".into(),
                report.duplicate_groups.len().to_string(),
            ),
        ];
        let reclaimable_bytes = report
            .duplicate_groups
            .iter()
            .map(|group| group.reclaimable_bytes)
            .sum::<u64>();
        let type_chart = report
            .type_deltas
            .iter()
            .filter(|item| item.delta_bytes != 0)
            .map(|item| ChartDatum {
                label: truncate_chart_label(&item.file_type, 14),
                value: item.delta_bytes as f64,
                bytes: item.delta_bytes.unsigned_abs().min(u64::MAX as u128) as u64,
                color: if item.delta_bytes > 0 { HIGH } else { GREEN },
            })
            .collect::<Vec<_>>();
        let growth_chart = report
            .largest_growth
            .iter()
            .take(10)
            .map(|change| ChartDatum {
                label: truncate_chart_label(
                    &change
                        .path
                        .file_name()
                        .map(|name| name.to_string_lossy())
                        .unwrap_or_else(|| change.path.to_string_lossy()),
                    14,
                ),
                value: change.delta_bytes as f64,
                bytes: change.delta_bytes.unsigned_abs().min(u64::MAX as u128) as u64,
                color: HIGH,
            })
            .collect::<Vec<_>>();
        let diff_treemap = comparison_treemap(report, 48);
        if let Some(ipa) = report.ipa.as_ref() {
            for change in &ipa.identity {
                summary.push((
                    format!("IPA · {}", change.field),
                    format!(
                        "{} → {}",
                        change.before.as_deref().unwrap_or("—"),
                        change.after.as_deref().unwrap_or("—")
                    ),
                ));
            }
            for (label, changes) in [
                ("Architectures", &ipa.architectures),
                ("Targets", &ipa.targets),
                ("Localizations", &ipa.localizations),
                ("Privacy usage keys", &ipa.privacy_usage_keys),
                ("Privacy manifest", &ipa.privacy_manifest_values),
                ("Findings", &ipa.findings),
            ] {
                if !changes.added.is_empty() || !changes.removed.is_empty() {
                    summary.push((
                        format!("IPA · {label}"),
                        format!(
                            "+ [{}] · − [{}]",
                            changes.added.join(", "),
                            changes.removed.join(", ")
                        ),
                    ));
                }
            }
            for change in &ipa.entitlements {
                summary.push((
                    format!("Entitlement · {}", change.field),
                    format!(
                        "{} → {}",
                        change.before.as_deref().unwrap_or("—"),
                        change.after.as_deref().unwrap_or("—")
                    ),
                ));
            }
            for change in &ipa.signing {
                summary.push((
                    format!("Signing · {}", change.field),
                    format!(
                        "{} → {}",
                        change.before.as_deref().unwrap_or("—"),
                        change.after.as_deref().unwrap_or("—")
                    ),
                ));
            }
        }
        let rows = report
            .files
            .iter()
            .map(|change| {
                vec![
                    format!("{:?}", change.kind),
                    change.path.display().to_string(),
                    change
                        .before_bytes
                        .map(format_size)
                        .unwrap_or_else(|| "—".into()),
                    change
                        .after_bytes
                        .map(format_size)
                        .unwrap_or_else(|| "—".into()),
                    format_signed_size(change.delta_bytes),
                ]
            })
            .collect();
        let moved_rows = report
            .moved_files
            .iter()
            .map(|item| {
                vec![
                    item.before_path.display().to_string(),
                    item.after_path.display().to_string(),
                    format_size(item.bytes),
                ]
            })
            .collect();
        let directory_rows = report
            .directory_deltas
            .iter()
            .take(50)
            .map(|item| {
                vec![
                    item.path.display().to_string(),
                    format_size(item.before_bytes),
                    format_size(item.after_bytes),
                    format_signed_size(item.delta_bytes),
                ]
            })
            .collect();
        let duplicate_rows = report
            .duplicate_groups
            .iter()
            .map(|item| {
                vec![
                    item.paths
                        .iter()
                        .map(|path| path.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", "),
                    format_size(item.bytes_each),
                    format_size(item.reclaimable_bytes),
                ]
            })
            .collect();
        let type_rows = report
            .type_deltas
            .iter()
            .map(|item| {
                vec![
                    item.file_type.clone(),
                    format_size(item.before_bytes),
                    format_size(item.after_bytes),
                    format_signed_size(item.delta_bytes),
                ]
            })
            .collect();
        div()
            .flex_1()
            .min_h_0()
            .flex()
            .flex_col()
            .gap_5()
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_3()
                    .child(metric_card(
                        "BASELINE",
                        format_size(report.before_bytes),
                        "Previous artifact",
                        0x6fa7c8,
                    ))
                    .child(metric_card(
                        "CANDIDATE",
                        format_size(report.after_bytes),
                        "Current artifact",
                        GREEN,
                    ))
                    .child(metric_card(
                        "DELTA",
                        format_signed_size(report.delta_bytes),
                        "Net size change",
                        if report.delta_bytes > 0 { HIGH } else { GREEN },
                    ))
                    .child(metric_card(
                        "CHANGED",
                        report.files.len().to_string(),
                        "File changes",
                        ACCENT,
                    ))
                    .child(metric_card(
                        "RECLAIMABLE",
                        format_size(reclaimable_bytes),
                        "Duplicate bytes",
                        0xb58ad6,
                    )),
            )
            .child(comparison_waterfall(report))
            .when(!type_chart.is_empty(), |comparison| {
                comparison.child(bar_chart_card(
                    "Size delta by file type",
                    type_chart,
                    "delta",
                ))
            })
            .when(!growth_chart.is_empty(), |comparison| {
                comparison.child(bar_chart_card("Top growth", growth_chart, "delta"))
            })
            .when(!diff_treemap.is_empty(), |comparison| {
                comparison.child(self.render_treemap_panel(
                    "Changed-file treemap",
                    diff_treemap,
                    cx,
                ))
            })
            .child(kv_panel("Artifact Comparison", summary))
            .child(table_panel(
                "Contents & Size Changes",
                &["Change", "Path", "Before", "After", "Delta"],
                rows,
                cx,
            ))
            .child(table_panel(
                "Moved Files",
                &["Before", "After", "Size"],
                moved_rows,
                cx,
            ))
            .child(table_panel(
                "Directory Size Changes",
                &["Directory", "Before", "After", "Delta"],
                directory_rows,
                cx,
            ))
            .child(table_panel(
                "Size by File Type",
                &["Type", "Before", "After", "Delta"],
                type_rows,
                cx,
            ))
            .child(table_panel(
                "Candidate Duplicate Files",
                &["Paths", "Each", "Reclaimable"],
                duplicate_rows,
                cx,
            ))
            .into_any_element()
    }
    fn render_android_summary(&self) -> impl IntoElement {
        let Some(report) = self.android_report.as_deref() else {
            return empty_state().into_any_element();
        };
        let total_methods: u64 = report.dex.iter().map(|dex| dex.methods as u64).sum();
        let total_classes: u64 = report.dex.iter().map(|dex| dex.classes as u64).sum();
        let severity_data =
            severity_chart_data(report.findings.iter().map(|finding| finding.severity));
        let values = vec![
            (
                "Package".into(),
                report
                    .identity
                    .package
                    .clone()
                    .unwrap_or_else(|| "—".into()),
            ),
            (
                "Version / Code".into(),
                format!(
                    "{} / {}",
                    report.identity.version_name.as_deref().unwrap_or("—"),
                    report.identity.version_code.as_deref().unwrap_or("—")
                ),
            ),
            (
                "Min / Target SDK".into(),
                format!(
                    "{} / {}",
                    report.identity.min_sdk.as_deref().unwrap_or("—"),
                    report.identity.target_sdk.as_deref().unwrap_or("—")
                ),
            ),
            ("Permissions".into(), report.permissions.len().to_string()),
            ("Components".into(), report.components.len().to_string()),
            ("DEX files".into(), report.dex.len().to_string()),
            ("DEX methods".into(), total_methods.to_string()),
            ("DEX classes".into(), total_classes.to_string()),
            (
                "Native libraries".into(),
                report.native_libraries.len().to_string(),
            ),
            (
                "resources.arsc".into(),
                report
                    .resources_arsc_bytes
                    .map(format_size)
                    .unwrap_or_else(|| "Missing".into()),
            ),
            (
                "Signing".into(),
                if report.signing_schemes.is_empty() {
                    "Not detected".into()
                } else {
                    report.signing_schemes.join(", ")
                },
            ),
            ("Findings".into(), report.findings.len().to_string()),
        ];
        div()
            .flex()
            .flex_col()
            .gap_4()
            .child(panel_title("Android Release Audit"))
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_3()
                    .child(metric_card(
                        "PERMISSIONS",
                        report.permissions.len().to_string(),
                        "Declared access",
                        WARNING,
                    ))
                    .child(metric_card(
                        "COMPONENTS",
                        report.components.len().to_string(),
                        "Activities & services",
                        ACCENT,
                    ))
                    .child(metric_card(
                        "DEX METHODS",
                        total_methods.to_string(),
                        "Across all DEX files",
                        0x6fa7c8,
                    ))
                    .child(metric_card(
                        "NATIVE LIBS",
                        report.native_libraries.len().to_string(),
                        "Packaged ABIs",
                        0xb58ad6,
                    ))
                    .child(metric_card(
                        "FINDINGS",
                        report.findings.len().to_string(),
                        "Release audit",
                        if report.findings.is_empty() {
                            GREEN
                        } else {
                            HIGH
                        },
                    )),
            )
            .when(!severity_data.is_empty(), |summary| {
                summary.child(bar_chart_card(
                    "Android finding severity",
                    severity_data,
                    "findings",
                ))
            })
            .child(kv_panel("Package details", values))
            .into_any_element()
    }
    fn render_android_components(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let rows = self
            .android_report
            .as_deref()
            .map(|report| {
                report
                    .components
                    .iter()
                    .map(|component| {
                        vec![
                            component.kind.clone(),
                            component.name.clone(),
                            component
                                .exported
                                .map(|value| value.to_string())
                                .unwrap_or_else(|| "Inferred".into()),
                            component.permission.clone().unwrap_or_default(),
                            component.actions.join(", "),
                            component.deep_links.join(", "),
                        ]
                    })
                    .collect()
            })
            .unwrap_or_default();
        table_panel(
            "Android Components",
            &[
                "Kind",
                "Name",
                "Exported",
                "Permission",
                "Actions",
                "Deep links",
            ],
            rows,
            cx,
        )
    }
    fn render_android_findings(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let findings = self
            .android_report
            .as_deref()
            .map(|report| report.findings.clone())
            .unwrap_or_default();
        div()
            .flex()
            .flex_col()
            .gap_3()
            .child(panel_title("Android Release Findings"))
            .when(findings.is_empty(), |panel| {
                panel.child(info_panel(
                    "Status",
                    "No Android release findings were produced.",
                ))
            })
            .children(findings.into_iter().map(|finding| {
                let evidence = finding.evidence_path.clone();
                div()
                    .id(SharedString::from(format!(
                        "android-finding-{}",
                        finding.rule_id
                    )))
                    .p_3()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .rounded_md()
                    .border_1()
                    .border_color(rgb(BORDER))
                    .bg(rgb(PANEL))
                    .cursor_pointer()
                    .hover(|style| style.bg(rgb(PANEL_2)))
                    .on_click(
                        cx.listener(move |this, _, _, cx| this.navigate_to_evidence(&evidence, cx)),
                    )
                    .child(
                        div()
                            .font_semibold()
                            .text_color(rgb(TEXT))
                            .child(finding.title),
                    )
                    .child(div().text_xs().text_color(rgb(MUTED)).child(format!(
                        "{:?} · {} · {}",
                        finding.severity,
                        finding.rule_id,
                        finding.evidence_path.display()
                    )))
                    .child(
                        div()
                            .text_sm()
                            .text_color(rgb(MUTED))
                            .child(finding.description),
                    )
            }))
            .into_any_element()
    }
    fn render_windows_summary(&self) -> impl IntoElement {
        let Some(report) = self.windows_report.as_deref() else {
            return empty_state().into_any_element();
        };
        let severity_data =
            severity_chart_data(report.findings.iter().map(|finding| finding.severity));
        let values = vec![
            (
                "Name".into(),
                report.identity.name.clone().unwrap_or_default(),
            ),
            (
                "Display name".into(),
                report.identity.display_name.clone().unwrap_or_default(),
            ),
            (
                "Publisher".into(),
                report.identity.publisher.clone().unwrap_or_default(),
            ),
            (
                "Version".into(),
                report.identity.version.clone().unwrap_or_default(),
            ),
            (
                "Architecture".into(),
                report
                    .identity
                    .processor_architecture
                    .clone()
                    .unwrap_or_default(),
            ),
            (
                "Target families".into(),
                report
                    .target_device_families
                    .iter()
                    .map(|family| family.name.clone())
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
            ("Capabilities".into(), report.capabilities.join(", ")),
            (
                "Restricted capabilities".into(),
                report.restricted_capabilities.join(", "),
            ),
            ("Applications".into(), report.applications.len().to_string()),
            (
                "Executable members".into(),
                report.executable_members.len().to_string(),
            ),
            ("Signature".into(), report.signature_present.to_string()),
            ("Block map".into(), report.block_map_present.to_string()),
            ("Findings".into(), report.findings.len().to_string()),
        ];
        div()
            .flex()
            .flex_col()
            .gap_4()
            .child(panel_title("Windows Package Release Audit"))
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_3()
                    .child(metric_card(
                        "APPLICATIONS",
                        report.applications.len().to_string(),
                        "Declared entries",
                        GREEN,
                    ))
                    .child(metric_card(
                        "EXECUTABLES",
                        report.executable_members.len().to_string(),
                        "PE members",
                        ACCENT,
                    ))
                    .child(metric_card(
                        "CAPABILITIES",
                        report.capabilities.len().to_string(),
                        "Requested access",
                        WARNING,
                    ))
                    .child(metric_card(
                        "SIGNATURE",
                        if report.signature_present {
                            "Present"
                        } else {
                            "Missing"
                        },
                        "Package trust",
                        if report.signature_present {
                            GREEN
                        } else {
                            DESTRUCTIVE
                        },
                    ))
                    .child(metric_card(
                        "FINDINGS",
                        report.findings.len().to_string(),
                        "Release audit",
                        if report.findings.is_empty() {
                            GREEN
                        } else {
                            HIGH
                        },
                    )),
            )
            .when(!severity_data.is_empty(), |summary| {
                summary.child(bar_chart_card(
                    "Windows finding severity",
                    severity_data,
                    "findings",
                ))
            })
            .child(kv_panel("Package details", values))
            .into_any_element()
    }
    fn render_windows_applications(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let rows = self
            .windows_report
            .as_deref()
            .map(|report| {
                report
                    .applications
                    .iter()
                    .map(|application| {
                        vec![
                            application.id.clone(),
                            application.executable.clone().unwrap_or_default(),
                            application.entry_point.clone().unwrap_or_default(),
                            application.runtime_behavior.clone().unwrap_or_default(),
                            application.trust_level.clone().unwrap_or_default(),
                        ]
                    })
                    .collect()
            })
            .unwrap_or_default();
        table_panel(
            "Windows Applications",
            &["ID", "Executable", "Entry point", "Runtime", "Trust"],
            rows,
            cx,
        )
    }
    fn render_windows_findings(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let findings = self
            .windows_report
            .as_deref()
            .map(|report| report.findings.clone())
            .unwrap_or_default();
        div()
            .flex()
            .flex_col()
            .gap_3()
            .child(panel_title("Windows Package Findings"))
            .when(findings.is_empty(), |panel| {
                panel.child(info_panel(
                    "Status",
                    "No Windows package findings were produced.",
                ))
            })
            .children(findings.into_iter().map(|finding| {
                let evidence = finding.evidence_path.clone();
                div()
                    .id(SharedString::from(format!(
                        "windows-finding-{}",
                        finding.rule_id
                    )))
                    .p_3()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .rounded_md()
                    .border_1()
                    .border_color(rgb(BORDER))
                    .bg(rgb(PANEL))
                    .cursor_pointer()
                    .hover(|style| style.bg(rgb(PANEL_2)))
                    .on_click(
                        cx.listener(move |this, _, _, cx| this.navigate_to_evidence(&evidence, cx)),
                    )
                    .child(
                        div()
                            .font_semibold()
                            .text_color(rgb(TEXT))
                            .child(finding.title),
                    )
                    .child(div().text_xs().text_color(rgb(MUTED)).child(format!(
                        "{:?} · {} · {}",
                        finding.severity,
                        finding.rule_id,
                        finding.evidence_path.display()
                    )))
                    .child(
                        div()
                            .text_sm()
                            .text_color(rgb(MUTED))
                            .child(finding.description),
                    )
            }))
            .into_any_element()
    }
    fn render_linux_summary(&self) -> impl IntoElement {
        let Some(report) = self.linux_report.as_deref() else {
            return empty_state().into_any_element();
        };
        let severity_data =
            severity_chart_data(report.findings.iter().map(|finding| finding.severity));
        let values = vec![
            (
                "Package".into(),
                report.identity.package.clone().unwrap_or_default(),
            ),
            (
                "Version".into(),
                report.identity.version.clone().unwrap_or_default(),
            ),
            (
                "Architecture".into(),
                report.identity.architecture.clone().unwrap_or_default(),
            ),
            (
                "Maintainer".into(),
                report.identity.maintainer.clone().unwrap_or_default(),
            ),
            ("Dependencies".into(), report.identity.depends.join(", ")),
            ("Installed bytes".into(), report.installed_bytes.to_string()),
            ("Files".into(), report.files.len().to_string()),
            (
                "Maintainer scripts".into(),
                report.maintainer_scripts.join(", "),
            ),
            ("Findings".into(), report.findings.len().to_string()),
        ];
        div()
            .flex()
            .flex_col()
            .gap_4()
            .child(panel_title("Debian Package Release Audit"))
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_3()
                    .child(metric_card(
                        "INSTALLED",
                        format_size(report.installed_bytes),
                        "Payload size",
                        GREEN,
                    ))
                    .child(metric_card(
                        "FILES",
                        report.files.len().to_string(),
                        "Installed entries",
                        ACCENT,
                    ))
                    .child(metric_card(
                        "DEPENDENCIES",
                        report.identity.depends.len().to_string(),
                        "Package requirements",
                        0x6fa7c8,
                    ))
                    .child(metric_card(
                        "SCRIPTS",
                        report.maintainer_scripts.len().to_string(),
                        "Maintainer hooks",
                        WARNING,
                    ))
                    .child(metric_card(
                        "FINDINGS",
                        report.findings.len().to_string(),
                        "Release audit",
                        if report.findings.is_empty() {
                            GREEN
                        } else {
                            HIGH
                        },
                    )),
            )
            .when(!severity_data.is_empty(), |summary| {
                summary.child(bar_chart_card(
                    "Linux finding severity",
                    severity_data,
                    "findings",
                ))
            })
            .child(kv_panel("Package details", values))
            .into_any_element()
    }
    fn render_linux_files(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let rows = self
            .linux_report
            .as_deref()
            .map(|report| {
                report
                    .top_files
                    .iter()
                    .map(|file| {
                        vec![
                            file.path.display().to_string(),
                            file.size.to_string(),
                            format!("{:o}", file.mode),
                        ]
                    })
                    .collect()
            })
            .unwrap_or_default();
        table_panel(
            "Largest Installed Files",
            &["Path", "Bytes", "Mode"],
            rows,
            cx,
        )
    }
    fn render_linux_findings(&self) -> impl IntoElement {
        let findings = self
            .linux_report
            .as_deref()
            .map(|report| report.findings.clone())
            .unwrap_or_default();
        div()
            .flex()
            .flex_col()
            .gap_3()
            .child(panel_title("Linux Package Findings"))
            .when(findings.is_empty(), |panel| {
                panel.child(info_panel(
                    "Status",
                    "No Linux package findings were produced.",
                ))
            })
            .children(findings.into_iter().enumerate().map(|(index, finding)| {
                div()
                    .id(SharedString::from(format!("linux-finding-{index}")))
                    .p_3()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .rounded_md()
                    .border_1()
                    .border_color(rgb(BORDER))
                    .bg(rgb(PANEL))
                    .child(
                        div()
                            .font_semibold()
                            .text_color(rgb(TEXT))
                            .child(finding.title),
                    )
                    .child(div().text_xs().text_color(rgb(MUTED)).child(format!(
                        "{:?} · {} · {}",
                        finding.severity,
                        finding.rule_id,
                        finding.evidence_path.display()
                    )))
                    .child(
                        div()
                            .text_sm()
                            .text_color(rgb(MUTED))
                            .child(finding.description),
                    )
            }))
            .into_any_element()
    }
    fn render_ipa_summary(&self) -> impl IntoElement {
        let Some(report) = self.ipa_report.as_deref() else {
            return empty_state().into_any_element();
        };
        let severity_data =
            severity_chart_data(report.findings.iter().map(|finding| finding.severity));
        let mut values = vec![
            (
                "Application".into(),
                report.metadata.name.clone().unwrap_or_else(|| "—".into()),
            ),
            (
                "Bundle ID".into(),
                report
                    .metadata
                    .bundle_identifier
                    .clone()
                    .unwrap_or_else(|| "—".into()),
            ),
            (
                "Version / Build".into(),
                format!(
                    "{} / {}",
                    report.metadata.version.as_deref().unwrap_or("—"),
                    report.metadata.build.as_deref().unwrap_or("—")
                ),
            ),
            (
                "Minimum iOS".into(),
                report
                    .metadata
                    .minimum_os_version
                    .clone()
                    .unwrap_or_else(|| "—".into()),
            ),
            ("Architectures".into(), report.architectures.join(", ")),
            ("Installed size".into(), format_size(report.total_bytes)),
            (
                "Compressed members".into(),
                format_size(report.compressed_bytes),
            ),
            ("Files".into(), report.files.len().to_string()),
            ("Embedded targets".into(), report.targets.len().to_string()),
            (
                "Privacy manifest".into(),
                if report.has_privacy_manifest {
                    "Present"
                } else {
                    "Missing"
                }
                .into(),
            ),
            ("Findings".into(), report.findings.len().to_string()),
            (
                "Report state".into(),
                if report.partial {
                    "Partial"
                } else {
                    "Complete"
                }
                .into(),
            ),
            ("Input SHA-256".into(), report.source.sha256.clone()),
        ];
        if !report.errors.is_empty() {
            values.push(("Partial errors".into(), report.errors.join(" · ")));
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
                    .child("iOS Release Audit"),
            )
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_3()
                    .child(metric_card(
                        "INSTALLED",
                        format_size(report.total_bytes),
                        "Expanded payload",
                        GREEN,
                    ))
                    .child(metric_card(
                        "FILES",
                        report.files.len().to_string(),
                        "IPA members",
                        ACCENT,
                    ))
                    .child(metric_card(
                        "TARGETS",
                        report.targets.len().to_string(),
                        "Apps & extensions",
                        0x6fa7c8,
                    ))
                    .child(metric_card(
                        "PRIVACY",
                        if report.has_privacy_manifest {
                            "Ready"
                        } else {
                            "Missing"
                        },
                        "Privacy manifest",
                        if report.has_privacy_manifest {
                            GREEN
                        } else {
                            WARNING
                        },
                    ))
                    .child(metric_card(
                        "FINDINGS",
                        report.findings.len().to_string(),
                        "Release audit",
                        if report.findings.is_empty() {
                            GREEN
                        } else {
                            HIGH
                        },
                    )),
            )
            .when(!severity_data.is_empty(), |summary| {
                summary.child(bar_chart_card(
                    "iOS finding severity",
                    severity_data,
                    "findings",
                ))
            })
            .child(kv_panel("Application", values))
            .into_any_element()
    }
    fn render_ipa_targets(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let matrix =
            self.ipa_report.as_deref().map(|report| {
                let mut architectures = report
                    .targets
                    .iter()
                    .flat_map(|target| target.architectures.iter().cloned())
                    .collect::<Vec<_>>();
                architectures.sort();
                architectures.dedup();
                let rows = report
                    .targets
                    .iter()
                    .map(|target| {
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(
                                div().w(px(220.)).truncate().text_color(rgb(TEXT)).child(
                                    target
                                        .metadata
                                        .bundle_identifier
                                        .clone()
                                        .unwrap_or_else(|| target.path.display().to_string()),
                                ),
                            )
                            .children(architectures.iter().map(|architecture| {
                                let present = target.architectures.contains(architecture);
                                div()
                                    .w(px(88.))
                                    .text_center()
                                    .rounded_sm()
                                    .bg(rgb(if present { SELECTION } else { PANEL_2 }))
                                    .text_color(rgb(if present { GREEN } else { MUTED }))
                                    .child(if present { "✓" } else { "—" })
                            }))
                            .child(
                                div()
                                    .w(px(88.))
                                    .text_center()
                                    .rounded_sm()
                                    .bg(rgb(if target.has_privacy_manifest {
                                        SELECTION
                                    } else {
                                        PANEL_2
                                    }))
                                    .text_color(rgb(if target.has_privacy_manifest {
                                        GREEN
                                    } else {
                                        WARNING
                                    }))
                                    .child(if target.has_privacy_manifest {
                                        "✓"
                                    } else {
                                        "—"
                                    }),
                            )
                    })
                    .collect::<Vec<_>>();
                div()
                    .p_4()
                    .rounded_lg()
                    .border_1()
                    .border_color(rgb(BORDER))
                    .bg(rgb(PANEL))
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            .text_xs()
                            .font_semibold()
                            .text_color(rgb(MUTED))
                            .child(div().w(px(220.)).child("TARGET"))
                            .children(architectures.into_iter().map(|architecture| {
                                div().w(px(88.)).text_center().child(architecture)
                            }))
                            .child(div().w(px(88.)).text_center().child("PRIVACY")),
                    )
                    .children(rows)
            });
        let rows = self
            .ipa_report
            .as_deref()
            .map(|report| {
                report
                    .targets
                    .iter()
                    .map(|target| {
                        vec![
                            target.kind.clone(),
                            target
                                .metadata
                                .bundle_identifier
                                .clone()
                                .unwrap_or_default(),
                            target.architectures.join(", "),
                            if target.has_privacy_manifest {
                                "Yes"
                            } else {
                                "No"
                            }
                            .into(),
                            target.path.display().to_string(),
                        ]
                    })
                    .collect()
            })
            .unwrap_or_default();
        div()
            .flex()
            .flex_col()
            .gap_4()
            .child(panel_title("Architecture & Privacy Matrix"))
            .children(matrix)
            .child(table_panel(
                "Embedded Targets",
                &["Kind", "Bundle ID", "Architectures", "Privacy", "Path"],
                rows,
                cx,
            ))
    }
    fn render_ipa_privacy(&self) -> impl IntoElement {
        let Some(report) = self.ipa_report.as_deref() else {
            return empty_state().into_any_element();
        };
        let mut values = vec![(
            "App PrivacyInfo.xcprivacy".into(),
            if report.has_privacy_manifest {
                "Present"
            } else {
                "Missing"
            }
            .into(),
        )];
        values.extend(
            report
                .privacy_usage_descriptions
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        );
        for manifest in &report.privacy_manifests {
            let prefix = manifest.path.display();
            values.push((
                format!("{prefix} · Tracking"),
                manifest.tracking.to_string(),
            ));
            if !manifest.tracking_domains.is_empty() {
                values.push((
                    format!("{prefix} · Tracking domains"),
                    manifest.tracking_domains.join(", "),
                ));
            }
            if !manifest.collected_data_types.is_empty() {
                values.push((
                    format!("{prefix} · Collected data"),
                    manifest.collected_data_types.join(", "),
                ));
            }
            for (category, reasons) in &manifest.accessed_api_categories {
                values.push((format!("{prefix} · {category}"), reasons.join(", ")));
            }
        }
        kv_panel("Privacy Declarations", values).into_any_element()
    }
    fn render_ipa_signing(&self) -> impl IntoElement {
        let Some(report) = self.ipa_report.as_deref() else {
            return empty_state().into_any_element();
        };
        let Some(signing) = report.signing.as_ref() else {
            return kv_panel(
                "Provisioning",
                vec![(
                    "Status".into(),
                    "embedded.mobileprovision is missing".into(),
                )],
            )
            .into_any_element();
        };
        let mut values = vec![
            (
                "Team ID".into(),
                signing.team_id.clone().unwrap_or_else(|| "—".into()),
            ),
            (
                "Application ID".into(),
                signing
                    .application_identifier
                    .clone()
                    .unwrap_or_else(|| "—".into()),
            ),
            (
                "Expiration".into(),
                signing
                    .expiration
                    .map(|value| value.to_rfc3339())
                    .unwrap_or_else(|| "—".into()),
            ),
        ];
        values.extend(
            signing
                .entitlements
                .iter()
                .map(|(key, value)| (format!("Entitlement · {key}"), value.clone())),
        );
        let has_team = signing.team_id.is_some();
        let has_app = signing.application_identifier.is_some();
        let has_expiration = signing.expiration.is_some();
        div()
            .flex()
            .flex_col()
            .gap_4()
            .child(panel_title("Provisioning Timeline"))
            .child(
                div()
                    .flex()
                    .gap_2()
                    .child(metric_card("1 · PROFILE", "✓", "Decoded", GREEN))
                    .child(metric_card(
                        "2 · TEAM",
                        if has_team { "✓" } else { "—" },
                        "Identity",
                        if has_team { GREEN } else { WARNING },
                    ))
                    .child(metric_card(
                        "3 · APP ID",
                        if has_app { "✓" } else { "—" },
                        "Entitlement",
                        if has_app { GREEN } else { WARNING },
                    ))
                    .child(metric_card(
                        "4 · EXPIRY",
                        if has_expiration { "✓" } else { "—" },
                        signing
                            .expiration
                            .map(|value| value.format("%Y-%m-%d").to_string())
                            .unwrap_or_else(|| "Unknown".into()),
                        if has_expiration { ACCENT } else { WARNING },
                    )),
            )
            .child(kv_panel("Provisioning & Entitlements", values))
            .into_any_element()
    }
    fn render_ipa_findings(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let findings = self
            .ipa_report
            .as_deref()
            .map(|report| {
                report
                    .findings
                    .iter()
                    .map(|finding| {
                        (
                            finding.severity,
                            finding.rule_id.clone(),
                            finding.title.clone(),
                            finding.description.clone(),
                            finding.evidence.first().map(|item| item.path.clone()),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        div()
            .flex()
            .flex_col()
            .gap_3()
            .child(panel_title("IPA Release Findings"))
            .when(findings.is_empty(), |panel| {
                panel.child(info_panel(
                    "Status",
                    "No IPA release findings were produced.",
                ))
            })
            .children(findings.into_iter().map(
                |(severity, rule_id, title, description, evidence)| {
                    let evidence_for_click = evidence.clone();
                    div()
                        .id(SharedString::from(format!("ipa-finding-{rule_id}")))
                        .p_3()
                        .flex()
                        .flex_col()
                        .gap_2()
                        .rounded_md()
                        .border_1()
                        .border_color(rgb(BORDER))
                        .bg(rgb(PANEL))
                        .when(evidence.is_some(), |card| {
                            card.cursor_pointer()
                                .hover(|style| style.bg(rgb(PANEL_2)))
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    if let Some(path) = evidence_for_click.as_deref() {
                                        this.navigate_to_evidence(path, cx);
                                    }
                                }))
                        })
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap_3()
                                .child(
                                    div()
                                        .text_xs()
                                        .font_semibold()
                                        .text_color(rgb(match severity {
                                            Severity::Critical | Severity::High => DESTRUCTIVE,
                                            Severity::Medium => WARNING,
                                            _ => MUTED,
                                        }))
                                        .child(format!("{severity:?}")),
                                )
                                .child(div().font_semibold().text_color(rgb(TEXT)).child(title))
                                .child(div().text_xs().text_color(rgb(MUTED)).child(rule_id)),
                        )
                        .child(div().text_sm().text_color(rgb(MUTED)).child(description))
                        .when_some(evidence, |card, path| {
                            card.child(
                                div()
                                    .text_xs()
                                    .text_color(rgb(ACCENT))
                                    .child(format!("Open evidence · {}", path.display())),
                            )
                        })
                },
            ))
    }
    fn render_policy(&self) -> impl IntoElement {
        let violations = self.policy_violations();
        let source = self
            .policy_path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "No policy loaded".into());
        div()
            .flex()
            .flex_col()
            .gap_3()
            .child(kv_panel(
                "Release Policy",
                vec![
                    ("Source".into(), source),
                    ("Violations".into(), violations.len().to_string()),
                ],
            ))
            .when(violations.is_empty(), |panel| {
                panel.child(info_panel(
                    "Status",
                    "The loaded policy has no violations for the current report.",
                ))
            })
            .children(
                violations
                    .into_iter()
                    .enumerate()
                    .map(|(index, violation)| {
                        div()
                            .id(SharedString::from(format!("policy-violation-{index}")))
                            .p_3()
                            .flex()
                            .flex_col()
                            .gap_2()
                            .rounded_md()
                            .border_1()
                            .border_color(rgb(BORDER))
                            .bg(rgb(PANEL))
                            .child(
                                div()
                                    .font_semibold()
                                    .text_color(rgb(match violation.severity {
                                        Severity::Critical | Severity::High => DESTRUCTIVE,
                                        Severity::Medium => WARNING,
                                        _ => MUTED,
                                    }))
                                    .child(format!(
                                        "{:?} · {}",
                                        violation.severity, violation.rule_id
                                    )),
                            )
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(rgb(MUTED))
                                    .child(violation.message),
                            )
                    }),
            )
            .into_any_element()
    }
    fn render_size_lab(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let Some(root) = self.artifact.as_deref() else {
            return empty_state().into_any_element();
        };
        let files = root.files().collect::<Vec<_>>();
        let total_bytes = files.iter().map(|node| node.size).sum::<u64>();
        let treemap = artifact_treemap(root, 48);
        let types = artifact_type_breakdown(root);
        let largest = artifact_top_files(root, 12);
        div()
            .flex()
            .flex_col()
            .gap_5()
            .child(
                div()
                    .flex()
                    .items_end()
                    .justify_between()
                    .child(
                        div().child(panel_title("Size Lab")).child(
                            div()
                                .mt_1()
                                .text_sm()
                                .text_color(rgb(MUTED))
                                .child("Explore where artifact size is concentrated."),
                        ),
                    )
                    .child(
                        div()
                            .text_sm()
                            .font_semibold()
                            .text_color(rgb(GREEN))
                            .child(format!(
                                "{} · {} files",
                                format_size(total_bytes),
                                files.len()
                            )),
                    ),
            )
            .child(self.render_treemap_panel("Artifact treemap", treemap, cx))
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_4()
                    .when(!types.is_empty(), |charts| {
                        charts.child(donut_chart_card("Size by file type", types))
                    })
                    .when(!largest.is_empty(), |charts| {
                        charts.child(bar_chart_card("Largest files", largest, "size"))
                    }),
            )
            .into_any_element()
    }

    fn render_treemap_panel(
        &self,
        title: &'static str,
        items: Vec<TreemapItem>,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        div()
            .p_4()
            .rounded_lg()
            .border_1()
            .border_color(rgb(BORDER))
            .bg(rgb(PANEL))
            .child(panel_title(title))
            .child(
                div()
                    .mt_3()
                    .relative()
                    .w_full()
                    .h(px(430.))
                    .overflow_hidden()
                    .rounded_lg()
                    .bg(rgb(BG))
                    .children(items.into_iter().enumerate().map(|(index, item)| {
                        let id = item.id;
                        let label = item.label.clone();
                        let detail = item
                            .delta
                            .map(format_signed_size)
                            .unwrap_or_else(|| format_size(item.bytes));
                        div()
                            .id(SharedString::from(format!("treemap-item-{index}")))
                            .absolute()
                            .left(relative(item.x))
                            .top(relative(item.y))
                            .w(relative(item.width))
                            .h(relative(item.height))
                            .p_2()
                            .border_1()
                            .border_color(rgb(BG))
                            .bg(rgb(item.color))
                            .overflow_hidden()
                            .cursor_pointer()
                            .hover(|style| style.opacity(0.84))
                            .when_some(id, |tile, id| {
                                tile.on_click(cx.listener(move |this, _, _, cx| {
                                    this.activate_tree_node(id, cx)
                                }))
                            })
                            .child(
                                div()
                                    .text_xs()
                                    .font_semibold()
                                    .text_color(rgb(BG))
                                    .overflow_hidden()
                                    .whitespace_nowrap()
                                    .child(label),
                            )
                            .child(div().mt_1().text_xs().text_color(rgb(BG)).child(detail))
                    })),
            )
    }

    fn render_overview(&self, node: &ArtifactNode) -> impl IntoElement {
        let a = self.current_analysis();
        let files = node.files().collect::<Vec<_>>();
        let total_file_bytes = files.iter().map(|file| file.size).sum::<u64>();
        let type_breakdown = artifact_type_breakdown(node);
        let top_files = artifact_top_files(node, 8);
        let finding_data = finding_severity_data(
            a.map(|analysis| analysis.findings.as_slice())
                .unwrap_or_default(),
        );
        let executable_count = files
            .iter()
            .filter(|file| {
                matches!(
                    file.kind,
                    ArtifactKind::Executable
                        | ArtifactKind::DynamicLibrary
                        | ArtifactKind::StaticLibrary
                        | ArtifactKind::Framework
                )
            })
            .count();
        let dependency_count = a.map(|analysis| analysis.dependencies.len()).unwrap_or(0);
        let high_findings = a
            .map(|analysis| {
                analysis
                    .findings
                    .iter()
                    .filter(|finding| {
                        matches!(finding.severity, Severity::Critical | Severity::High)
                    })
                    .count()
            })
            .unwrap_or(0);
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
        if let Some(report) = self.ipa_report.as_deref()
            && self
                .artifact
                .as_ref()
                .is_some_and(|artifact| artifact.id == node.id)
        {
            values.extend([
                (
                    "Bundle ID".into(),
                    report
                        .metadata
                        .bundle_identifier
                        .clone()
                        .unwrap_or_default(),
                ),
                (
                    "Version / Build".into(),
                    format!(
                        "{} / {}",
                        report.metadata.version.as_deref().unwrap_or("—"),
                        report.metadata.build.as_deref().unwrap_or("—")
                    ),
                ),
                (
                    "Installed / Compressed".into(),
                    format!(
                        "{} / {}",
                        format_size(report.total_bytes),
                        format_size(report.compressed_bytes)
                    ),
                ),
                ("Architectures".into(), report.architectures.join(", ")),
                ("Embedded targets".into(), report.targets.len().to_string()),
                ("IPA findings".into(), report.findings.len().to_string()),
            ]);
        }
        if self
            .summary
            .as_ref()
            .is_none_or(|summary| summary.sha256.is_none())
            && node.is_file()
        {
            values.push((
                "SHA-256 / entropy".into(),
                "Not computed — use “Compute hashes + entropy”".into(),
            ));
        }
        div()
            .flex()
            .flex_col()
            .gap_5()
            .child(
                div()
                    .text_2xl()
                    .font_semibold()
                    .text_color(rgb(TEXT))
                    .child(node.name.clone()),
            )
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_3()
                    .child(metric_card(
                        "TOTAL SIZE",
                        format_size(total_file_bytes),
                        "On-disk contents",
                        GREEN,
                    ))
                    .child(metric_card(
                        "FILES",
                        files.len().to_string(),
                        "Discovered members",
                        ACCENT,
                    ))
                    .child(metric_card(
                        "BINARIES",
                        executable_count.to_string(),
                        "Executables & libraries",
                        0x6fa7c8,
                    ))
                    .child(metric_card(
                        "DEPENDENCIES",
                        dependency_count.to_string(),
                        "Linked requirements",
                        0xb58ad6,
                    ))
                    .child(metric_card(
                        "HIGH RISK",
                        high_findings.to_string(),
                        "Critical & high findings",
                        if high_findings > 0 {
                            DESTRUCTIVE
                        } else {
                            GREEN
                        },
                    )),
            )
            .when(!type_breakdown.is_empty(), |dashboard| {
                dashboard.child(
                    div()
                        .flex()
                        .flex_wrap()
                        .gap_4()
                        .child(donut_chart_card("File type distribution", type_breakdown))
                        .when(!top_files.is_empty(), |charts| {
                            charts.child(bar_chart_card("Largest files", top_files, "size"))
                        })
                        .when(!finding_data.is_empty(), |charts| {
                            charts.child(bar_chart_card(
                                "Finding severity",
                                finding_data,
                                "findings",
                            ))
                        }),
                )
            })
            .child(kv_panel("Overview", values))
    }
    fn render_findings(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let findings = self
            .current_analysis()
            .map(|a| a.findings.as_slice())
            .unwrap_or(&[]);
        let filters = [
            None,
            Some(Severity::Critical),
            Some(Severity::High),
            Some(Severity::Medium),
            Some(Severity::Low),
            Some(Severity::Info),
        ]
        .into_iter()
        .enumerate()
        .map(|(index, filter)| {
            let selected = self.finding_filter == filter;
            let label = filter
                .map(|severity| format!("{severity:?}"))
                .unwrap_or_else(|| "All".into());
            div()
                .id(("finding-filter", index))
                .px_3()
                .py_1()
                .rounded_full()
                .cursor_pointer()
                .border_1()
                .border_color(rgb(if selected { GREEN } else { BORDER }))
                .bg(rgb(if selected { SELECTION } else { PANEL }))
                .text_sm()
                .text_color(rgb(if selected { GREEN } else { MUTED }))
                .child(label)
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.finding_filter = filter;
                    cx.notify();
                }))
        })
        .collect::<Vec<_>>();
        let visible = findings
            .iter()
            .filter(|finding| {
                self.finding_filter
                    .is_none_or(|severity| finding.severity == severity)
            })
            .collect::<Vec<_>>();
        div()
            .flex()
            .flex_col()
            .gap_3()
            .child(panel_title("Inspection Findings"))
            .child(div().flex().flex_wrap().gap_2().children(filters))
            .children(visible.iter().map(|f| {
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
            .when(visible.is_empty(), |d| {
                d.child(info_panel(
                    "No findings",
                    "No inspection findings were produced by the lightweight analysis.",
                ))
            })
    }
    fn render_hex(&self, node: &ArtifactNode, cx: &mut Context<Self>) -> AnyElement {
        let offset = self.hex_offset.saturating_sub(self.hex_offset % 16);
        let preview = match HexReader::open_node(node)
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
        let workspace_background = if self.high_contrast { 0x000000 } else { BG };
        let workspace_text = if self.high_contrast { 0xffffff } else { TEXT };
        div()
            .size_full()
            .track_focus(&self.focus_handle)
            .flex()
            .flex_col()
            .bg(rgb(workspace_background))
            .text_color(rgb(workspace_text))
            .on_action(cx.listener(|this, _: &OpenFile, _, cx| this.choose(false, cx)))
            .on_action(cx.listener(|this, _: &OpenArtifact, _, cx| this.choose(true, cx)))
            .on_action(cx.listener(|this, _: &OpenWorkspace, _, cx| this.open_workspace(cx)))
            .on_action(cx.listener(|this, _: &OpenPolicy, _, cx| this.open_policy(cx)))
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
                                    .primary()
                                    .xsmall()
                                    .compact()
                                    .tooltip("Search the entire artifact (Return)")
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
                                    .tooltip("Interpret the query as text")
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
                                    .tooltip("Interpret the query as hexadecimal bytes")
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
                                    .ghost()
                                    .tooltip("Select the next search result")
                                    .on_click(cx.listener(|this, _, _, cx| this.find_next(cx))),
                            )
                            .child(
                                Button::new("jump-offset")
                                    .label("Jump Offset")
                                    .xsmall()
                                    .compact()
                                    .ghost()
                                    .tooltip("Jump to a hexadecimal file offset")
                                    .on_click(
                                        cx.listener(|this, _, _, cx| this.jump_to_offset(cx)),
                                    ),
                            )
                            .child(
                                Button::new("copy-hex")
                                    .label("Copy Hex")
                                    .xsmall()
                                    .compact()
                                    .ghost()
                                    .tooltip("Copy the visible hexadecimal chunk")
                                    .on_click(
                                        cx.listener(|this, _, _, cx| this.copy_hex_chunk(cx)),
                                    ),
                            )
                            .when(self.loading, |toolbar| {
                                toolbar
                                    .child(
                                        div()
                                            .ml_1()
                                            .w(px(92.))
                                            .child(Progress::new().value(62.).bg(rgb(GREEN))),
                                    )
                                    .child(
                                        div().text_xs().text_color(rgb(ACCENT)).child("Analyzing…"),
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
                h_resizable("workspace-panels")
                    .child(
                        resizable_panel()
                            .visible(self.show_sidebar)
                            .size(px(280.))
                            .size_range(px(180.)..px(520.))
                            .child(self.render_sidebar(cx)),
                    )
                    .child(
                        resizable_panel()
                            .size_range(px(420.)..Pixels::MAX)
                            .child(self.render_main(cx)),
                    )
                    .child(
                        resizable_panel()
                            .visible(self.show_inspector)
                            .size(px(320.))
                            .size_range(px(240.)..px(560.))
                            .child(self.render_details(cx)),
                    ),
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
fn find_archive_member_with_ancestors(
    node: &ArtifactNode,
    member_path: &std::path::Path,
    ancestors: &mut Vec<uuid::Uuid>,
) -> Option<uuid::Uuid> {
    if matches!(
        node.source.as_ref(),
        Some(bytetrawl_core::ArtifactSource::ArchiveMember { member_path: path, .. })
            if path == member_path
    ) {
        return Some(node.id);
    }
    for child in &node.children {
        if let Some(id) = find_archive_member_with_ancestors(child, member_path, ancestors) {
            ancestors.push(node.id);
            return Some(id);
        }
    }
    None
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
fn format_signed_size(value: i128) -> String {
    let sign = if value > 0 {
        "+"
    } else if value < 0 {
        "−"
    } else {
        ""
    };
    let magnitude = value.unsigned_abs().min(u64::MAX as u128) as u64;
    format!("{sign}{}", format_size(magnitude))
}

fn sample_entropy_profile(
    node: &ArtifactNode,
    cancellation: &CancellationToken,
) -> bytetrawl_core::Result<Vec<EntropySample>> {
    let reader = ArtifactReader::open(node)?;
    let length = reader.len();
    if length == 0 {
        return Ok(Vec::new());
    }
    const SAMPLE_BYTES: usize = 64 * 1024;
    const MAX_SAMPLES: u64 = 128;
    let count = length.div_ceil(SAMPLE_BYTES as u64).clamp(1, MAX_SAMPLES);
    let stride = length.div_ceil(count);
    let mut samples = Vec::with_capacity(count as usize);
    for index in 0..count {
        cancellation.check()?;
        let offset = index.saturating_mul(stride).min(length.saturating_sub(1));
        let bytes = reader.read_range_cancellable(offset, SAMPLE_BYTES, cancellation)?;
        samples.push(EntropySample {
            label: format!("{:x}", offset),
            offset,
            entropy: entropy(&bytes),
        });
    }
    Ok(samples)
}

fn entropy_color(value: f64) -> u32 {
    if value >= 7.5 {
        DESTRUCTIVE
    } else if value >= 6.5 {
        HIGH
    } else if value >= 5.0 {
        WARNING
    } else if value >= 2.5 {
        GREEN
    } else {
        ACCENT
    }
}

fn metric_card(
    label: impl Into<SharedString>,
    value: impl Into<SharedString>,
    detail: impl Into<SharedString>,
    color: u32,
) -> impl IntoElement {
    div()
        .min_w(px(154.))
        .flex_1()
        .p_4()
        .rounded_lg()
        .border_1()
        .border_color(rgb(BORDER))
        .bg(rgb(PANEL))
        .child(
            div()
                .text_xs()
                .font_semibold()
                .text_color(rgb(color))
                .child(label.into()),
        )
        .child(
            div()
                .mt_2()
                .text_2xl()
                .font_semibold()
                .text_color(rgb(TEXT))
                .child(value.into()),
        )
        .child(
            div()
                .mt_1()
                .text_xs()
                .text_color(rgb(MUTED))
                .child(detail.into()),
        )
}

fn artifact_type_breakdown(root: &ArtifactNode) -> Vec<ChartDatum> {
    let mut totals = std::collections::BTreeMap::<String, u64>::new();
    for node in root.files() {
        let label = match node.kind {
            ArtifactKind::Executable => "Executables",
            ArtifactKind::DynamicLibrary | ArtifactKind::StaticLibrary => "Libraries",
            ArtifactKind::Framework => "Frameworks",
            ArtifactKind::Resource => "Resources",
            ArtifactKind::Metadata => "Metadata",
            ArtifactKind::Archive | ArtifactKind::Package => "Archives",
            ArtifactKind::DiskImage => "Images",
            _ => match node.format {
                Some(bytetrawl_core::FileFormat::Image) => "Images",
                Some(bytetrawl_core::FileFormat::Text) => "Text",
                Some(bytetrawl_core::FileFormat::Json)
                | Some(bytetrawl_core::FileFormat::Xml)
                | Some(bytetrawl_core::FileFormat::Plist) => "Metadata",
                _ => "Other",
            },
        };
        *totals.entry(label.into()).or_default() += node.size;
    }
    let mut values = totals.into_iter().collect::<Vec<_>>();
    values.sort_by_key(|value| std::cmp::Reverse(value.1));
    values
        .into_iter()
        .enumerate()
        .map(|(index, (label, bytes))| ChartDatum {
            label,
            value: bytes as f64,
            bytes,
            color: CHART_COLORS[index % CHART_COLORS.len()],
        })
        .collect()
}

fn artifact_top_files(root: &ArtifactNode, limit: usize) -> Vec<ChartDatum> {
    let mut files = root
        .files()
        .map(|node| (node.name.clone(), node.size))
        .collect::<Vec<_>>();
    files.sort_by_key(|file| std::cmp::Reverse(file.1));
    files
        .into_iter()
        .take(limit)
        .enumerate()
        .map(|(index, (name, bytes))| ChartDatum {
            label: truncate_chart_label(&name, 16),
            value: bytes as f64,
            bytes,
            color: CHART_COLORS[index % CHART_COLORS.len()],
        })
        .collect()
}

fn artifact_treemap(root: &ArtifactNode, limit: usize) -> Vec<TreemapItem> {
    let mut files = root
        .files()
        .filter(|node| node.size > 0)
        .map(|node| (node.id, node.name.clone(), node.size, node.kind))
        .collect::<Vec<_>>();
    files.sort_by_key(|file| std::cmp::Reverse(file.2));
    let mut items = files
        .into_iter()
        .take(limit)
        .enumerate()
        .map(|(index, (id, label, bytes, kind))| TreemapItem {
            id: Some(id),
            label,
            bytes,
            delta: None,
            color: artifact_kind_color(kind, index),
            x: 0.,
            y: 0.,
            width: 1.,
            height: 1.,
        })
        .collect::<Vec<_>>();
    layout_treemap(&mut items, 0., 0., 1., 1., 0);
    items
}

fn artifact_kind_color(kind: ArtifactKind, index: usize) -> u32 {
    match kind {
        ArtifactKind::Executable => GREEN,
        ArtifactKind::DynamicLibrary | ArtifactKind::StaticLibrary | ArtifactKind::Framework => {
            0x6fa7c8
        }
        ArtifactKind::Resource => ACCENT,
        ArtifactKind::Metadata => 0xb58ad6,
        ArtifactKind::Archive | ArtifactKind::Package => HIGH,
        _ => CHART_COLORS[index % CHART_COLORS.len()],
    }
}

fn layout_treemap(
    items: &mut [TreemapItem],
    x: f32,
    y: f32,
    width: f32,
    height: f32,
    depth: usize,
) {
    if items.is_empty() {
        return;
    }
    if items.len() == 1 {
        items[0].x = x;
        items[0].y = y;
        items[0].width = width;
        items[0].height = height;
        return;
    }
    let total = items.iter().map(|item| item.bytes.max(1)).sum::<u64>();
    let target = total / 2;
    let mut subtotal = 0u64;
    let mut split = 1usize;
    for (index, item) in items.iter().enumerate().take(items.len() - 1) {
        subtotal = subtotal.saturating_add(item.bytes.max(1));
        split = index + 1;
        if subtotal >= target {
            break;
        }
    }
    let ratio = (subtotal as f32 / total as f32).clamp(0.08, 0.92);
    let (left, right) = items.split_at_mut(split);
    if (width >= height) ^ (depth % 2 == 1 && width / height < 1.35) {
        let left_width = width * ratio;
        layout_treemap(left, x, y, left_width, height, depth + 1);
        layout_treemap(
            right,
            x + left_width,
            y,
            width - left_width,
            height,
            depth + 1,
        );
    } else {
        let top_height = height * ratio;
        layout_treemap(left, x, y, width, top_height, depth + 1);
        layout_treemap(
            right,
            x,
            y + top_height,
            width,
            height - top_height,
            depth + 1,
        );
    }
}

fn comparison_treemap(report: &CompareReportV1, limit: usize) -> Vec<TreemapItem> {
    let mut changes = report.files.iter().collect::<Vec<_>>();
    changes.sort_by_key(|change| std::cmp::Reverse(change.delta_bytes.unsigned_abs()));
    let mut items = changes
        .into_iter()
        .filter(|change| change.delta_bytes != 0)
        .take(limit)
        .map(|change| TreemapItem {
            id: None,
            label: change
                .path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| change.path.display().to_string()),
            bytes: change.delta_bytes.unsigned_abs().min(u64::MAX as u128) as u64,
            delta: Some(change.delta_bytes),
            color: match change.kind {
                ChangeKind::Added => HIGH,
                ChangeKind::Removed => GREEN,
                ChangeKind::Modified if change.delta_bytes > 0 => WARNING,
                ChangeKind::Modified => 0x6fa7c8,
            },
            x: 0.,
            y: 0.,
            width: 1.,
            height: 1.,
        })
        .collect::<Vec<_>>();
    layout_treemap(&mut items, 0., 0., 1., 1., 0);
    items
}

fn comparison_waterfall(report: &CompareReportV1) -> impl IntoElement {
    let added = report
        .files
        .iter()
        .filter(|change| change.delta_bytes > 0)
        .map(|change| change.delta_bytes)
        .sum::<i128>();
    let removed = report
        .files
        .iter()
        .filter(|change| change.delta_bytes < 0)
        .map(|change| change.delta_bytes)
        .sum::<i128>();
    div()
        .p_4()
        .rounded_lg()
        .border_1()
        .border_color(rgb(BORDER))
        .bg(rgb(PANEL))
        .child(panel_title("Size waterfall"))
        .child(
            div()
                .mt_4()
                .flex()
                .items_center()
                .justify_between()
                .gap_2()
                .child(waterfall_step(
                    "Baseline",
                    format_size(report.before_bytes),
                    0x6fa7c8,
                ))
                .child(waterfall_arrow())
                .child(waterfall_step("Growth", format_signed_size(added), HIGH))
                .child(waterfall_arrow())
                .child(waterfall_step(
                    "Reduction",
                    format_signed_size(removed),
                    GREEN,
                ))
                .child(waterfall_arrow())
                .child(waterfall_step(
                    "Candidate",
                    format_size(report.after_bytes),
                    ACCENT,
                )),
        )
}

fn waterfall_step(label: &'static str, value: String, color: u32) -> impl IntoElement {
    div()
        .flex_1()
        .min_w(px(120.))
        .p_3()
        .rounded_lg()
        .border_1()
        .border_color(rgb(color))
        .bg(rgb(BG))
        .child(div().text_xs().text_color(rgb(MUTED)).child(label))
        .child(
            div()
                .mt_1()
                .text_lg()
                .font_semibold()
                .text_color(rgb(color))
                .child(value),
        )
}

fn waterfall_arrow() -> impl IntoElement {
    div().text_lg().text_color(rgb(MUTED)).child("→")
}

fn finding_severity_data(findings: &[bytetrawl_core::Finding]) -> Vec<ChartDatum> {
    severity_chart_data(findings.iter().map(|finding| finding.severity))
}

fn severity_chart_data(severities: impl IntoIterator<Item = Severity>) -> Vec<ChartDatum> {
    let severities = severities.into_iter().collect::<Vec<_>>();
    [
        (Severity::Critical, "Critical", DESTRUCTIVE),
        (Severity::High, "High", HIGH),
        (Severity::Medium, "Medium", WARNING),
        (Severity::Low, "Low", GREEN),
        (Severity::Info, "Info", ACCENT),
    ]
    .into_iter()
    .filter_map(|(severity, label, color)| {
        let count = severities
            .iter()
            .filter(|value| **value == severity)
            .count();
        (count > 0).then(|| ChartDatum {
            label: label.into(),
            value: count as f64,
            bytes: 0,
            color,
        })
    })
    .collect()
}

fn truncate_chart_label(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let prefix = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() {
        format!("{prefix}…")
    } else {
        prefix
    }
}

fn donut_chart_card(title: &'static str, data: Vec<ChartDatum>) -> impl IntoElement {
    let chart_data = data.clone();
    div()
        .min_w(px(360.))
        .flex_1()
        .p_4()
        .rounded_lg()
        .border_1()
        .border_color(rgb(BORDER))
        .bg(rgb(PANEL))
        .child(panel_title(title))
        .child(
            div()
                .mt_3()
                .flex()
                .items_center()
                .gap_4()
                .child(
                    div().w(px(210.)).h(px(190.)).child(
                        PieChart::new(chart_data)
                            .value(|datum| datum.value as f32)
                            .inner_radius(58.)
                            .pad_angle(0.018)
                            .color(|datum| rgb(datum.color)),
                    ),
                )
                .child(
                    div()
                        .flex_1()
                        .flex()
                        .flex_col()
                        .gap_2()
                        .children(data.into_iter().map(|datum| {
                            div()
                                .flex()
                                .items_center()
                                .gap_2()
                                .child(div().size(px(8.)).rounded_full().bg(rgb(datum.color)))
                                .child(
                                    div()
                                        .flex_1()
                                        .text_xs()
                                        .text_color(rgb(MUTED))
                                        .child(datum.label),
                                )
                                .child(
                                    div()
                                        .text_xs()
                                        .font_semibold()
                                        .text_color(rgb(TEXT))
                                        .child(format_size(datum.bytes)),
                                )
                        })),
                ),
        )
}

fn bar_chart_card(
    title: &'static str,
    data: Vec<ChartDatum>,
    unit: &'static str,
) -> impl IntoElement {
    div()
        .min_w(px(420.))
        .flex_1()
        .p_4()
        .rounded_lg()
        .border_1()
        .border_color(rgb(BORDER))
        .bg(rgb(PANEL))
        .child(panel_title(title))
        .child(
            div().mt_3().h(px(220.)).child(
                BarChart::new(data)
                    .x(|datum| datum.label.clone())
                    .y(|datum| datum.value)
                    .fill(|datum| rgb(datum.color))
                    .label(move |datum| {
                        if unit == "size" {
                            format_size(datum.bytes)
                        } else if unit == "delta" {
                            format_signed_size(datum.value as i128)
                        } else {
                            format!("{:.0}", datum.value)
                        }
                    }),
            ),
        )
}

fn configure_component_theme(cx: &mut App) {
    configure_component_theme_mode(load_ui_preferences().high_contrast, cx);
}

fn configure_component_theme_mode(high_contrast: bool, cx: &mut App) {
    Theme::change(ThemeMode::Dark, None, cx);
    let theme = Theme::global_mut(cx);
    let background = rgb(if high_contrast { 0x000000 } else { BG }).into();
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
    theme.radius = px(7.);
    theme.radius_lg = px(11.);
    theme.progress_bar = primary;
    theme.success = primary;
    theme.warning = rgb(WARNING).into();
    theme.info = rgb(ACCENT).into();
    theme.chart_1 = primary;
    theme.chart_2 = rgb(ACCENT).into();
    theme.chart_3 = rgb(HIGH).into();
    theme.chart_4 = rgb(0x6fa7c8).into();
    theme.chart_5 = rgb(0xb58ad6).into();
}

fn quit(_: &Quit, cx: &mut App) {
    cx.quit();
}

fn active_bytetrawl_view(cx: &App) -> Option<Entity<ByteTrawlApp>> {
    let window_id = cx.active_window()?.window_id();
    cx.global::<WindowViews>().0.get(&window_id)?.upgrade()
}

fn open_file_from_menu(_: &OpenFile, cx: &mut App) {
    if let Some(view) = active_bytetrawl_view(cx) {
        view.update(cx, |this, cx| this.choose(false, cx));
    }
}

fn open_artifact_from_menu(_: &OpenArtifact, cx: &mut App) {
    if let Some(view) = active_bytetrawl_view(cx) {
        view.update(cx, |this, cx| this.choose(true, cx));
    }
}

fn open_workspace_from_menu(_: &OpenWorkspace, cx: &mut App) {
    if let Some(view) = active_bytetrawl_view(cx) {
        view.update(cx, |this, cx| this.open_workspace(cx));
    }
}

fn open_policy_from_menu(_: &OpenPolicy, cx: &mut App) {
    if let Some(view) = active_bytetrawl_view(cx) {
        view.update(cx, |this, cx| this.open_policy(cx));
    }
}

fn compare_artifacts_from_menu(_: &CompareArtifacts, cx: &mut App) {
    if let Some(view) = active_bytetrawl_view(cx) {
        view.update(cx, |this, cx| this.choose_comparison(false, cx));
    }
}

fn compare_folders_from_menu(_: &CompareFolders, cx: &mut App) {
    if let Some(view) = active_bytetrawl_view(cx) {
        view.update(cx, |this, cx| this.choose_comparison(true, cx));
    }
}

fn save_workspace_from_menu(_: &SaveWorkspace, cx: &mut App) {
    if let Some(view) = active_bytetrawl_view(cx) {
        view.update(cx, |this, cx| this.save_workspace(cx));
    }
}

fn toggle_sidebar(_: &ToggleSidebar, cx: &mut App) {
    if let Some(view) = active_bytetrawl_view(cx) {
        view.update(cx, |this, cx| {
            this.show_sidebar = !this.show_sidebar;
            this.save_ui_preferences();
            cx.notify();
        });
    }
}

fn toggle_inspector(_: &ToggleInspector, cx: &mut App) {
    if let Some(view) = active_bytetrawl_view(cx) {
        view.update(cx, |this, cx| {
            this.show_inspector = !this.show_inspector;
            this.save_ui_preferences();
            cx.notify();
        });
    }
}

fn layout_standard(_: &LayoutStandard, cx: &mut App) {
    if let Some(view) = active_bytetrawl_view(cx) {
        view.update(cx, |this, cx| this.apply_layout(true, true, cx));
    }
}

fn layout_focus(_: &LayoutFocus, cx: &mut App) {
    if let Some(view) = active_bytetrawl_view(cx) {
        view.update(cx, |this, cx| this.apply_layout(false, false, cx));
    }
}

fn layout_analysis(_: &LayoutAnalysis, cx: &mut App) {
    if let Some(view) = active_bytetrawl_view(cx) {
        view.update(cx, |this, cx| this.apply_layout(true, false, cx));
    }
}

fn toggle_high_contrast(_: &ToggleHighContrast, cx: &mut App) {
    if let Some(view) = active_bytetrawl_view(cx) {
        let enabled = view.update(cx, |this, cx| {
            this.high_contrast = !this.high_contrast;
            this.save_ui_preferences();
            cx.notify();
            this.high_contrast
        });
        configure_component_theme_mode(enabled, cx);
        cx.refresh_windows();
    }
}

fn export_visual_report(_: &ExportVisualReport, cx: &mut App) {
    if let Some(view) = active_bytetrawl_view(cx) {
        view.update(cx, |this, cx| this.export_visual_report(cx));
    }
}

fn open_recent_from_menu(action: &OpenRecent, cx: &mut App) {
    if let Some(view) = active_bytetrawl_view(cx) {
        let path = action.path.clone();
        view.update(cx, |this, cx| {
            if path.exists() {
                this.load(path, cx);
            } else {
                this.error = Some("The recent artifact no longer exists.".into());
                cx.notify();
            }
        });
    }
}

fn recent_artifacts_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join("Library/Application Support/ByteTrawl/recent-artifacts.json"))
}

fn ui_preferences_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join("Library/Application Support/ByteTrawl/ui-preferences.json"))
}

fn load_ui_preferences() -> UiPreferences {
    ui_preferences_path()
        .and_then(|path| std::fs::read(path).ok())
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn store_ui_preferences(preferences: &UiPreferences) -> std::io::Result<()> {
    let Some(destination) = ui_preferences_path() else {
        return Ok(());
    };
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(preferences).map_err(std::io::Error::other)?;
    let temporary = destination.with_extension("json.tmp");
    std::fs::write(&temporary, bytes)?;
    std::fs::rename(temporary, destination)
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn visual_report_svg(root: &ArtifactNode, findings: &[Finding]) -> String {
    let mut types = artifact_type_breakdown(root);
    types.truncate(8);
    let total = types.iter().map(|item| item.bytes).sum::<u64>().max(1);
    let high = findings
        .iter()
        .filter(|finding| matches!(finding.severity, Severity::Critical | Severity::High))
        .count();
    let files = root.files().count();
    let mut svg = format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="760" viewBox="0 0 1200 760"><rect width="1200" height="760" rx="32" fill="#0e0d0b"/><text x="64" y="76" fill="#9acf68" font-family="-apple-system, sans-serif" font-size="18" font-weight="700">BYTETRAWL VISUAL AUDIT</text><text x="64" y="122" fill="#d7d3c6" font-family="-apple-system, sans-serif" font-size="34" font-weight="700">{}</text><text x="64" y="154" fill="#978f7d" font-family="-apple-system, sans-serif" font-size="15">Static report · safe to share · generated locally</text>"##,
        xml_escape(&root.name)
    );
    for (index, (label, value, detail, color)) in [
        (
            "SIZE",
            format_size(root.size),
            "Artifact bytes".to_string(),
            "#9acf68",
        ),
        (
            "FILES",
            files.to_string(),
            "Discovered members".to_string(),
            "#6fa7c8",
        ),
        (
            "FINDINGS",
            findings.len().to_string(),
            "Inspection results".to_string(),
            "#d69b51",
        ),
        (
            "HIGH RISK",
            high.to_string(),
            "Critical & high".to_string(),
            "#d86d5f",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let x = 64 + index * 272;
        svg.push_str(&format!(r##"<rect x="{x}" y="190" width="248" height="126" rx="14" fill="#141310" stroke="#25231e"/><text x="{}" y="222" fill="{color}" font-family="-apple-system, sans-serif" font-size="12" font-weight="700">{label}</text><text x="{}" y="266" fill="#d7d3c6" font-family="-apple-system, sans-serif" font-size="28" font-weight="700">{}</text><text x="{}" y="294" fill="#978f7d" font-family="-apple-system, sans-serif" font-size="13">{detail}</text>"##, x + 20, x + 20, xml_escape(&value), x + 20));
    }
    svg.push_str(r##"<text x="64" y="374" fill="#d7d3c6" font-family="-apple-system, sans-serif" font-size="20" font-weight="700">Composition</text>"##);
    for (index, item) in types.iter().enumerate() {
        let y = 410 + index * 38;
        let width = ((item.bytes as f64 / total as f64) * 700.0).max(3.0);
        svg.push_str(&format!(r##"<text x="64" y="{}" fill="#978f7d" font-family="-apple-system, sans-serif" font-size="13">{}</text><rect x="230" y="{}" width="700" height="16" rx="8" fill="#1c1b17"/><rect x="230" y="{}" width="{width:.1}" height="16" rx="8" fill="#{:06x}"/><text x="950" y="{}" fill="#d7d3c6" font-family="-apple-system, sans-serif" font-size="13">{}</text>"##, y, xml_escape(&item.label), y - 13, y - 13, item.color, y, format_size(item.bytes)));
    }
    svg.push_str(r##"<text x="64" y="724" fill="#978f7d" font-family="-apple-system, sans-serif" font-size="12">ByteTrawl · cross-platform software artifact security triage, comparison, and release audit</text></svg>"##);
    svg
}

fn recent_artifacts() -> Vec<PathBuf> {
    let Some(path) = recent_artifacts_path() else {
        return Vec::new();
    };
    std::fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Vec<PathBuf>>(&bytes).ok())
        .unwrap_or_default()
        .into_iter()
        .take(10)
        .collect()
}

fn record_recent_artifact(path: &std::path::Path) -> std::io::Result<()> {
    let Some(destination) = recent_artifacts_path() else {
        return Ok(());
    };
    let mut paths = recent_artifacts();
    paths.retain(|recent| recent != path);
    paths.insert(0, path.to_path_buf());
    paths.truncate(10);
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec(&paths).map_err(std::io::Error::other)?;
    let temporary = destination.with_extension("json.tmp");
    std::fs::write(&temporary, bytes)?;
    std::fs::rename(temporary, destination)
}

fn install_menus(cx: &mut App) {
    let recent_items = recent_artifacts()
        .into_iter()
        .map(|path| {
            let label = path.display().to_string();
            MenuItem::action(label, OpenRecent { path })
        })
        .collect::<Vec<_>>();
    let recent_menu = MenuItem::submenu(Menu {
        name: "Open Recent".into(),
        items: recent_items,
    });
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
                MenuItem::action("New Window", NewWindow),
                MenuItem::separator(),
                MenuItem::action("Open File…", OpenFile),
                MenuItem::action("Open Folder…", OpenArtifact),
                recent_menu,
                MenuItem::action("Open Workspace…", OpenWorkspace),
                MenuItem::action("Open Release Policy…", OpenPolicy),
                MenuItem::separator(),
                MenuItem::action("Compare Artifacts…", CompareArtifacts),
                MenuItem::action("Compare Folders…", CompareFolders),
                MenuItem::separator(),
                MenuItem::action("Save Workspace…", SaveWorkspace),
                MenuItem::action("Export Visual Report…", ExportVisualReport),
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
            items: vec![
                MenuItem::action("Focus Search", FocusSearch),
                MenuItem::separator(),
                MenuItem::action("Toggle Artifact Tree", ToggleSidebar),
                MenuItem::action("Toggle Inspector", ToggleInspector),
                MenuItem::separator(),
                MenuItem::action("Standard Layout", LayoutStandard),
                MenuItem::action("Focus Layout", LayoutFocus),
                MenuItem::action("Analysis Layout", LayoutAnalysis),
                MenuItem::separator(),
                MenuItem::action("Toggle High Contrast", ToggleHighContrast),
            ],
        },
        Menu {
            name: "Window".into(),
            items: vec![],
        },
    ]);
}

fn open_bytetrawl_window(cx: &mut App) {
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
                if let Some(path) = take_startup_path() {
                    view.update(cx, |this, cx| this.load(path, cx));
                }
                cx.global_mut::<WindowViews>()
                    .0
                    .insert(window.window_handle().window_id(), view.downgrade());
                cx.new(|cx| Root::new(view, window, cx))
            },
        )?;
        anyhow::Ok(())
    })
    .detach();
}

fn new_window(_: &NewWindow, cx: &mut App) {
    open_bytetrawl_window(cx);
}

fn main() {
    Application::new().run(|cx| {
        gpui_component::init(cx);
        configure_component_theme(cx);
        cx.set_global(WindowViews::default());
        cx.activate(true);
        cx.on_action(quit);
        cx.on_action(new_window);
        cx.on_action(open_file_from_menu);
        cx.on_action(open_artifact_from_menu);
        cx.on_action(open_workspace_from_menu);
        cx.on_action(open_policy_from_menu);
        cx.on_action(compare_artifacts_from_menu);
        cx.on_action(compare_folders_from_menu);
        cx.on_action(save_workspace_from_menu);
        cx.on_action(toggle_sidebar);
        cx.on_action(toggle_inspector);
        cx.on_action(layout_standard);
        cx.on_action(layout_focus);
        cx.on_action(layout_analysis);
        cx.on_action(toggle_high_contrast);
        cx.on_action(export_visual_report);
        cx.on_action(open_recent_from_menu);
        cx.bind_keys([
            KeyBinding::new("cmd-n", NewWindow, None),
            KeyBinding::new("cmd-o", OpenFile, None),
            KeyBinding::new("cmd-shift-o", OpenArtifact, None),
            KeyBinding::new("cmd-alt-o", OpenWorkspace, None),
            KeyBinding::new("cmd-alt-p", OpenPolicy, None),
            KeyBinding::new("cmd-shift-c", CompareArtifacts, None),
            KeyBinding::new("cmd-s", SaveWorkspace, None),
            KeyBinding::new("cmd-f", FocusSearch, None),
            KeyBinding::new("cmd-shift-1", ToggleSidebar, None),
            KeyBinding::new("cmd-shift-2", ToggleInspector, None),
            KeyBinding::new("cmd-shift-0", LayoutStandard, None),
            KeyBinding::new("cmd-shift-f", LayoutFocus, None),
        ]);
        install_menus(cx);
        open_bytetrawl_window(cx);
    })
}
