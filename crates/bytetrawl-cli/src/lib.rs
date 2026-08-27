use bytetrawl_analysis::{
    CancellationToken, HashOptions, analyze_node, annotate_string_locations,
    apply_signature_analysis, build_dependency_graph, enrich_analysis_entropy,
    extract_strings_node_cancellable, hash_node, inspect_metadata, inspect_signature_cancellable,
    open_artifact, resolve_dependencies,
};
use bytetrawl_android::{AndroidAuditReportV1, audit_apk, is_apk};
use bytetrawl_compare::{CompareReportV1, compare_artifacts};
use bytetrawl_core::{
    ArtifactKind, ArtifactNode, BinaryAnalysis, DependencyGraph, FileSummary, Finding, Severity,
    SignatureInfo,
};
use bytetrawl_ios::{IpaAuditReportV1, IpaViewCompatibleReport, audit_ipa, ipa_view_compatible};
use bytetrawl_linux::{DebianReportV1, audit_deb, is_deb};
use bytetrawl_policy::{
    PolicyViolation, ReleasePolicyV1, evaluate_android, evaluate_compare, evaluate_generic,
    evaluate_ipa, evaluate_linux, evaluate_windows,
};
use bytetrawl_windows::{WindowsPackageReportV1, audit_msix, is_msix};
use chrono::{DateTime, Utc};
use clap::{Args, Parser, Subcommand, ValueEnum};
use indexmap::IndexMap;
use serde::Serialize;
use std::{
    io::{self, BufWriter, Write},
    path::{Path, PathBuf},
    time::Instant,
};

pub const REPORT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Parser)]
#[command(
    name = "bytetrawl-cli",
    version,
    about = "Static application, package, and binary inspection"
)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Inspect a file, application, package, or directory and emit JSON.
    Inspect(InspectArgs),
    /// Compare two artifacts and emit deterministic file, size, and IPA semantic differences.
    Compare(CompareArgs),
}

#[derive(Debug, Clone, Args)]
pub struct CompareArgs {
    /// Baseline artifact path.
    pub before: PathBuf,
    /// Candidate artifact path.
    pub after: PathBuf,
    /// Write JSON to this file instead of stdout.
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    /// Pretty-print JSON output.
    #[arg(long)]
    pub pretty: bool,
    /// Exit with status 2 when installed-size growth exceeds this many bytes.
    #[arg(long)]
    pub max_growth_bytes: Option<i128>,
    /// Versioned JSON release policy.
    #[arg(long)]
    pub policy: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct InspectArgs {
    /// Artifact path to inspect.
    pub path: PathBuf,

    /// Write JSON to this file instead of stdout.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Pretty-print JSON output.
    #[arg(long)]
    pub pretty: bool,

    /// Accepted for explicitness; JSON is the stable default output format.
    #[arg(long)]
    pub json: bool,
    /// Report format.
    #[arg(long, value_enum, default_value_t = ReportFormat::Json)]
    pub format: ReportFormat,

    /// Analysis depth. Deep enables SHA-256, entropy, strings, signatures, and graph building.
    #[arg(long, value_enum, default_value_t = AnalysisDepth::Standard)]
    pub depth: AnalysisDepth,

    /// Identification hashes to compute (comma-separated).
    #[arg(long = "hash", value_enum, value_delimiter = ',')]
    pub hashes: Vec<HashAlgorithm>,

    /// Extract strings from every regular file.
    #[arg(long)]
    pub strings: bool,

    /// Compute whole-file and binary-section entropy.
    #[arg(long)]
    pub entropy: bool,

    /// Run host signature verification where supported.
    #[arg(long)]
    pub signature: bool,

    /// Build the complete Artifact dependency graph.
    #[arg(long)]
    pub dependencies: bool,

    /// Minimum extracted string length.
    #[arg(long, default_value_t = 4, value_parser = parse_min_string_length)]
    pub min_string_length: usize,

    /// Maximum strings retained per file.
    #[arg(long, default_value_t = 10_000, value_parser = parse_max_strings)]
    pub max_strings: usize,

    /// Exit with status 2 if this severity or higher is found.
    #[arg(long, value_enum)]
    pub fail_on: Option<SeverityThreshold>,
    /// Versioned JSON release policy.
    #[arg(long)]
    pub policy: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AnalysisDepth {
    Lightweight,
    Standard,
    Deep,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum HashAlgorithm {
    Sha256,
    Sha1,
    Md5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SeverityThreshold {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReportFormat {
    Json,
    Markdown,
    Html,
    Sarif,
}

fn parse_bounded_usize(value: &str, minimum: usize, maximum: usize) -> Result<usize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| format!("expected an integer from {minimum} to {maximum}"))?;
    if (minimum..=maximum).contains(&parsed) {
        Ok(parsed)
    } else {
        Err(format!("expected a value from {minimum} to {maximum}"))
    }
}

fn parse_min_string_length(value: &str) -> Result<usize, String> {
    parse_bounded_usize(value, 2, 1024)
}

fn parse_max_strings(value: &str) -> Result<usize, String> {
    parse_bounded_usize(value, 1, 1_000_000)
}

#[derive(Debug, Serialize)]
pub struct InspectionReport {
    pub schema_version: u32,
    pub generator: GeneratorInfo,
    pub artifact: ArtifactNode,
    pub artifact_signature: Option<SignatureInfo>,
    pub files: Vec<FileReport>,
    pub dependency_graph: Option<DependencyGraph>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipa: Option<IpaAuditReportV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipa_view_compatibility: Option<IpaViewCompatibleReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub android: Option<AndroidAuditReportV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub windows_package: Option<WindowsPackageReportV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linux_package: Option<DebianReportV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_violations: Vec<PolicyViolation>,
    pub findings: Vec<ReportFinding>,
    pub run: RunInfo,
}

#[derive(Debug, Serialize)]
pub struct GeneratorInfo {
    pub name: &'static str,
    pub version: &'static str,
}

#[derive(Debug, Serialize)]
pub struct FileReport {
    pub artifact_id: uuid::Uuid,
    pub path: PathBuf,
    pub kind: ArtifactKind,
    pub size: u64,
    pub summary: FileSummary,
    pub analysis: Option<BinaryAnalysis>,
    pub metadata: IndexMap<String, String>,
    pub strings: Option<Vec<ReportString>>,
    pub errors: Vec<ReportError>,
}

#[derive(Debug, Serialize)]
pub struct ReportString {
    pub offset: u64,
    pub encoding: String,
    pub value: String,
    pub section: Option<String>,
    pub virtual_address: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct ReportFinding {
    pub path: PathBuf,
    #[serde(flatten)]
    pub finding: Finding,
}

#[derive(Debug, Serialize)]
pub struct ReportError {
    pub stage: &'static str,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct RunInfo {
    pub started_at: DateTime<Utc>,
    pub duration_ms: u128,
    pub partial: bool,
    pub cancelled: bool,
    pub errors: Vec<ReportError>,
}

pub fn run() -> u8 {
    let cli = Cli::parse();
    match cli.command {
        Command::Inspect(args) => run_inspect(args),
        Command::Compare(args) => run_compare(args),
    }
}

fn run_compare(args: CompareArgs) -> u8 {
    let cancellation = CancellationToken::default();
    match compare(&args, &cancellation) {
        Ok(report) => {
            let policy = args.policy.as_deref().map(load_policy).transpose();
            let policy = match policy {
                Ok(policy) => policy,
                Err(error) => {
                    eprintln!("bytetrawl-cli: {error}");
                    return 1;
                }
            };
            let policy_violations = policy
                .as_ref()
                .map(|policy| evaluate_compare(policy, &report))
                .unwrap_or_default();
            let failed = !policy_violations.is_empty()
                || args
                    .max_growth_bytes
                    .is_some_and(|maximum| report.delta_bytes > maximum);
            let output = CompareOutput {
                report: &report,
                policy_violations: &policy_violations,
            };
            if let Err(error) = write_json(&output, args.output.as_deref(), args.pretty) {
                eprintln!("bytetrawl-cli: {error}");
                return 1;
            }
            if failed { 2 } else { 0 }
        }
        Err(error) => {
            eprintln!("bytetrawl-cli: {error}");
            1
        }
    }
}

#[derive(Serialize)]
struct CompareOutput<'a> {
    #[serde(flatten)]
    report: &'a CompareReportV1,
    #[serde(skip_serializing_if = "slice_is_empty")]
    policy_violations: &'a [PolicyViolation],
}

fn slice_is_empty<T>(values: &[T]) -> bool {
    values.is_empty()
}

fn load_policy(path: &Path) -> bytetrawl_core::Result<ReleasePolicyV1> {
    let bytes = std::fs::read(path).map_err(|source| bytetrawl_core::ByteTrawlError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_slice(&bytes)
        .map_err(|error| bytetrawl_core::ByteTrawlError::Malformed(format!("policy: {error}")))
}

pub fn compare(
    args: &CompareArgs,
    cancellation: &CancellationToken,
) -> bytetrawl_core::Result<CompareReportV1> {
    let before = open_artifact(&args.before, cancellation)?;
    let after = open_artifact(&args.after, cancellation)?;
    let before_ipa = is_ipa(&before)
        .then(|| audit_ipa(&before, cancellation))
        .transpose()?;
    let after_ipa = is_ipa(&after)
        .then(|| audit_ipa(&after, cancellation))
        .transpose()?;
    compare_artifacts(
        &before,
        &after,
        before_ipa.as_ref(),
        after_ipa.as_ref(),
        cancellation,
    )
}

fn is_ipa(artifact: &ArtifactNode) -> bool {
    artifact
        .properties
        .get("Package Format")
        .is_some_and(|format| format == "Apple iOS IPA")
}

fn run_inspect(args: InspectArgs) -> u8 {
    let cancellation = CancellationToken::default();
    let signal_token = cancellation.clone();
    if let Err(error) = ctrlc::set_handler(move || signal_token.cancel()) {
        eprintln!("warning: could not install Ctrl-C handler: {error}");
    }
    match inspect(&args, &cancellation) {
        Ok(report) => {
            let fail_on = args
                .fail_on
                .is_some_and(|threshold| report_reaches_threshold(&report, threshold))
                || !report.policy_violations.is_empty();
            let cancelled = report.run.cancelled;
            let partial = report.run.partial;
            if let Err(error) =
                write_report(&report, args.output.as_deref(), args.pretty, args.format)
            {
                eprintln!("bytetrawl-cli: {error}");
                return 1;
            }
            if cancelled {
                4
            } else if fail_on {
                2
            } else if partial {
                5
            } else {
                0
            }
        }
        Err(error) => {
            eprintln!("bytetrawl-cli: {error}");
            if cancellation.is_cancelled() { 4 } else { 1 }
        }
    }
}

pub fn inspect(
    args: &InspectArgs,
    cancellation: &CancellationToken,
) -> bytetrawl_core::Result<InspectionReport> {
    let started_at = Utc::now();
    let started = Instant::now();
    let artifact = open_artifact(&args.path, cancellation)?;
    let deep = args.depth == AnalysisDepth::Deep;
    let parse_files = args.depth != AnalysisDepth::Lightweight;
    let want_entropy = args.entropy || deep;
    let want_strings = args.strings || deep;
    let want_signature = args.signature || deep;
    let want_graph = args.dependencies || deep;
    let hashes = if deep && args.hashes.is_empty() {
        vec![HashAlgorithm::Sha256]
    } else {
        args.hashes.clone()
    };
    let hash_options = HashOptions {
        sha256: hashes.contains(&HashAlgorithm::Sha256),
        sha1: hashes.contains(&HashAlgorithm::Sha1),
        md5: hashes.contains(&HashAlgorithm::Md5),
    };

    let mut files = Vec::new();
    let mut findings = Vec::new();
    let mut run_errors = Vec::new();
    for node in artifact.files() {
        if cancellation.check().is_err() {
            break;
        }
        let mut errors = Vec::new();
        let mut analysis = if parse_files {
            match analyze_node(node) {
                Ok(analysis) => analysis,
                Err(error) => {
                    errors.push(ReportError {
                        stage: "binary_analysis",
                        message: error.to_string(),
                    });
                    None
                }
            }
        } else {
            None
        };
        if let Some(analysis) = &mut analysis {
            resolve_dependencies(analysis, &artifact);
            if want_entropy
                && !matches!(
                    node.source,
                    Some(bytetrawl_core::ArtifactSource::ArchiveMember { .. })
                )
                && let Err(error) = enrich_analysis_entropy(&node.path, analysis, cancellation)
            {
                errors.push(ReportError {
                    stage: "section_entropy",
                    message: error.to_string(),
                });
            }
            if want_signature
                && matches!(
                    analysis.platform,
                    Some(bytetrawl_core::BinaryPlatform::MacOs)
                )
                && matches!(
                    node.source,
                    Some(bytetrawl_core::ArtifactSource::Filesystem { .. })
                )
            {
                match inspect_signature_cancellable(&node.path, cancellation) {
                    Ok(Some(signature)) => apply_signature_analysis(analysis, &signature),
                    Ok(None) => {}
                    Err(error) => errors.push(ReportError {
                        stage: "signature",
                        message: error.to_string(),
                    }),
                }
            }
            findings.extend(
                analysis
                    .findings
                    .iter()
                    .cloned()
                    .map(|finding| ReportFinding {
                        path: node.path.clone(),
                        finding,
                    }),
            );
        }

        let metadata = if parse_files {
            match inspect_metadata(node) {
                Ok(metadata) => metadata,
                Err(error) => {
                    errors.push(ReportError {
                        stage: "metadata",
                        message: error.to_string(),
                    });
                    IndexMap::new()
                }
            }
        } else {
            IndexMap::new()
        };

        let mut summary = FileSummary {
            size: node.size,
            sha256: None,
            sha1: None,
            md5: None,
            entropy: None,
            analysis: None,
        };
        if want_entropy || !hashes.is_empty() {
            match hash_node(node, hash_options, cancellation) {
                Ok(result) => summary = result,
                Err(error) => errors.push(ReportError {
                    stage: "hash_entropy",
                    message: error.to_string(),
                }),
            }
        }

        let strings = if want_strings {
            match extract_strings_node_cancellable(
                node,
                args.min_string_length,
                args.max_strings,
                cancellation,
            ) {
                Ok(mut strings) => {
                    if let Some(analysis) = analysis.as_ref() {
                        if analysis.slice_analyses.is_empty() {
                            annotate_string_locations(&mut strings, analysis);
                        } else {
                            for slice in &analysis.slice_analyses {
                                annotate_string_locations(&mut strings, slice);
                            }
                        }
                    }
                    Some(
                        strings
                            .into_iter()
                            .map(|string| ReportString {
                                offset: string.offset,
                                encoding: format!("{:?}", string.encoding),
                                value: string.value,
                                section: string.section,
                                virtual_address: string.virtual_address,
                            })
                            .collect(),
                    )
                }
                Err(error) => {
                    errors.push(ReportError {
                        stage: "strings",
                        message: error.to_string(),
                    });
                    None
                }
            }
        } else {
            None
        };
        files.push(FileReport {
            artifact_id: node.id,
            path: node.path.clone(),
            kind: node.kind,
            size: node.size,
            summary,
            analysis,
            metadata,
            strings,
            errors,
        });
    }

    let dependency_graph = if want_graph && !cancellation.is_cancelled() {
        match build_dependency_graph(&artifact, cancellation) {
            Ok(graph) => Some(graph),
            Err(error) => {
                run_errors.push(ReportError {
                    stage: "dependency_graph",
                    message: error.to_string(),
                });
                None
            }
        }
    } else {
        None
    };
    let artifact_signature = if want_signature
        && !cancellation.is_cancelled()
        && matches!(
            artifact.kind,
            ArtifactKind::Application
                | ArtifactKind::Bundle
                | ArtifactKind::Framework
                | ArtifactKind::Plugin
        ) {
        inspect_signature_cancellable(&artifact.path, cancellation).unwrap_or_else(|error| {
            run_errors.push(ReportError {
                stage: "artifact_signature",
                message: error.to_string(),
            });
            None
        })
    } else {
        None
    };
    let ipa = if artifact
        .properties
        .get("Package Format")
        .is_some_and(|format| format == "Apple iOS IPA")
    {
        match audit_ipa(&artifact, cancellation) {
            Ok(report) => Some(report),
            Err(error) => {
                run_errors.push(ReportError {
                    stage: "ipa_audit",
                    message: error.to_string(),
                });
                None
            }
        }
    } else {
        None
    };
    let ipa_view_compatibility = ipa.as_ref().map(ipa_view_compatible);
    let android = if is_apk(&artifact) {
        match audit_apk(&artifact, cancellation) {
            Ok(report) => Some(report),
            Err(error) => {
                run_errors.push(ReportError {
                    stage: "android_audit",
                    message: error.to_string(),
                });
                None
            }
        }
    } else {
        None
    };
    let windows_package = if is_msix(&artifact) {
        match audit_msix(&artifact, cancellation) {
            Ok(report) => Some(report),
            Err(error) => {
                run_errors.push(ReportError {
                    stage: "windows_package_audit",
                    message: error.to_string(),
                });
                None
            }
        }
    } else {
        None
    };
    let linux_package = if is_deb(&artifact.path) {
        match audit_deb(&artifact.path) {
            Ok(report) => Some(report),
            Err(error) => {
                run_errors.push(ReportError {
                    stage: "linux_package_audit",
                    message: error.to_string(),
                });
                None
            }
        }
    } else {
        None
    };
    let policy = args.policy.as_deref().map(load_policy).transpose()?;
    let mut policy_violations = Vec::new();
    if let Some(policy) = policy.as_ref()
        && ipa.is_none()
        && android.is_none()
        && windows_package.is_none()
        && linux_package.is_none()
    {
        let generic_findings = findings
            .iter()
            .map(|finding| finding.finding.clone())
            .collect::<Vec<_>>();
        policy_violations.extend(evaluate_generic(
            policy,
            files.iter().map(|file| file.size).sum(),
            &generic_findings,
        ));
    }
    if let (Some(policy), Some(ipa)) = (policy.as_ref(), ipa.as_ref()) {
        policy_violations.extend(evaluate_ipa(policy, ipa));
    }
    if let (Some(policy), Some(android)) = (policy.as_ref(), android.as_ref()) {
        policy_violations.extend(evaluate_android(policy, android));
    }
    if let (Some(policy), Some(windows)) = (policy.as_ref(), windows_package.as_ref()) {
        policy_violations.extend(evaluate_windows(policy, windows));
    }
    if let (Some(policy), Some(linux)) = (policy.as_ref(), linux_package.as_ref()) {
        policy_violations.extend(evaluate_linux(policy, linux));
    }
    let partial = !run_errors.is_empty()
        || files.iter().any(|file| !file.errors.is_empty())
        || ipa.as_ref().is_some_and(|report| report.partial)
        || android.as_ref().is_some_and(|report| report.partial);
    Ok(InspectionReport {
        schema_version: REPORT_SCHEMA_VERSION,
        generator: GeneratorInfo {
            name: "ByteTrawl",
            version: env!("CARGO_PKG_VERSION"),
        },
        artifact,
        artifact_signature,
        files,
        dependency_graph,
        ipa,
        ipa_view_compatibility,
        android,
        windows_package,
        linux_package,
        policy_violations,
        findings,
        run: RunInfo {
            started_at,
            duration_ms: started.elapsed().as_millis(),
            partial,
            cancelled: cancellation.is_cancelled(),
            errors: run_errors,
        },
    })
}

fn write_report(
    report: &InspectionReport,
    output: Option<&Path>,
    pretty: bool,
    format: ReportFormat,
) -> io::Result<()> {
    match format {
        ReportFormat::Json => write_json(report, output, pretty),
        ReportFormat::Markdown => write_bytes(&render_markdown(report), output),
        ReportFormat::Html => write_bytes(&render_html(report), output),
        ReportFormat::Sarif => write_json(&render_sarif(report), output, pretty),
    }
}

fn write_bytes(contents: &str, output: Option<&Path>) -> io::Result<()> {
    match output {
        Some(path) => std::fs::write(path, contents),
        None => {
            let mut stdout = io::stdout().lock();
            stdout.write_all(contents.as_bytes())?;
            stdout.write_all(b"\n")
        }
    }
}

fn all_report_findings(report: &InspectionReport) -> Vec<(Severity, String, String)> {
    let mut findings = report
        .findings
        .iter()
        .map(|item| {
            (
                item.finding.severity,
                item.finding.title.clone(),
                item.path.display().to_string(),
            )
        })
        .collect::<Vec<_>>();
    if let Some(ipa) = report.ipa.as_ref() {
        findings.extend(ipa.findings.iter().map(|item| {
            (
                item.severity,
                item.title.clone(),
                item.evidence
                    .first()
                    .map(|evidence| evidence.path.display().to_string())
                    .unwrap_or_default(),
            )
        }));
    }
    if let Some(android) = report.android.as_ref() {
        findings.extend(android.findings.iter().map(|item| {
            (
                item.severity,
                item.title.clone(),
                item.evidence_path.display().to_string(),
            )
        }));
    }
    if let Some(windows) = report.windows_package.as_ref() {
        findings.extend(windows.findings.iter().map(|item| {
            (
                item.severity,
                item.title.clone(),
                item.evidence_path.display().to_string(),
            )
        }));
    }
    if let Some(linux) = report.linux_package.as_ref() {
        findings.extend(linux.findings.iter().map(|item| {
            (
                item.severity,
                item.title.clone(),
                item.evidence_path.display().to_string(),
            )
        }));
    }
    findings
}

fn render_markdown(report: &InspectionReport) -> String {
    let mut output = format!(
        "# ByteTrawl inspection\n\n- Artifact: `{}`\n- Files: {}\n- Partial: {}\n",
        report.artifact.path.display(),
        report.files.len(),
        report.run.partial
    );
    if let Some(ipa) = report.ipa.as_ref() {
        output.push_str(&format!(
            "- Bundle ID: `{}`\n- Version: `{}` (`{}`)\n- Installed size: {} bytes\n",
            ipa.metadata.bundle_identifier.as_deref().unwrap_or(""),
            ipa.metadata.version.as_deref().unwrap_or(""),
            ipa.metadata.build.as_deref().unwrap_or(""),
            ipa.total_bytes
        ));
    }
    output.push_str("\n## Findings\n\n| Severity | Finding | Evidence |\n|---|---|---|\n");
    for (severity, title, evidence) in all_report_findings(report) {
        output.push_str(&format!(
            "| {severity:?} | {} | `{}` |\n",
            title.replace('|', "\\|"),
            evidence.replace('|', "\\|")
        ));
    }
    output
}

fn render_html(report: &InspectionReport) -> String {
    let rows = all_report_findings(report)
        .into_iter()
        .map(|(severity, title, evidence)| {
            format!(
                "<tr><td>{severity:?}</td><td>{}</td><td><code>{}</code></td></tr>",
                html_escape(&title),
                html_escape(&evidence)
            )
        })
        .collect::<String>();
    format!(
        "<!doctype html><meta charset=\"utf-8\"><title>ByteTrawl inspection</title><style>body{{font:15px system-ui;max-width:1100px;margin:40px auto;color:#d7d3c6;background:#0d0c0a}}table{{width:100%;border-collapse:collapse}}td,th{{padding:9px;border:1px solid #302d26;text-align:left}}h1{{color:#9bd568}}</style><h1>ByteTrawl inspection</h1><p><code>{}</code></p><table><thead><tr><th>Severity</th><th>Finding</th><th>Evidence</th></tr></thead><tbody>{rows}</tbody></table>",
        html_escape(&report.artifact.path.display().to_string())
    )
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn render_sarif(report: &InspectionReport) -> serde_json::Value {
    let results = all_report_findings(report)
        .into_iter()
        .map(|(severity, title, evidence)| {
            serde_json::json!({
                "level": match severity { Severity::Critical | Severity::High => "error", Severity::Medium => "warning", _ => "note" },
                "message": { "text": title },
                "locations": [{ "physicalLocation": { "artifactLocation": { "uri": evidence } } }]
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{ "tool": { "driver": { "name": "ByteTrawl", "version": env!("CARGO_PKG_VERSION") } }, "results": results }]
    })
}

fn write_json(report: &impl Serialize, output: Option<&Path>, pretty: bool) -> io::Result<()> {
    match output {
        Some(path) => {
            let parent = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
            if pretty {
                serde_json::to_writer_pretty(&mut temporary, report)?;
            } else {
                serde_json::to_writer(&mut temporary, report)?;
            }
            temporary.write_all(b"\n")?;
            temporary.as_file().sync_all()?;
            temporary.persist(path).map_err(|error| error.error)?;
            Ok(())
        }
        None => {
            let stdout = io::stdout().lock();
            let mut writer = BufWriter::new(stdout);
            if pretty {
                serde_json::to_writer_pretty(&mut writer, report)?;
            } else {
                serde_json::to_writer(&mut writer, report)?;
            }
            writer.write_all(b"\n")
        }
    }
}

fn report_reaches_threshold(report: &InspectionReport, threshold: SeverityThreshold) -> bool {
    let threshold = threshold_rank(threshold);
    report
        .findings
        .iter()
        .any(|finding| severity_rank(finding.finding.severity) >= threshold)
        || report.ipa.as_ref().is_some_and(|ipa| {
            ipa.findings
                .iter()
                .any(|finding| severity_rank(finding.severity) >= threshold)
        })
        || report.android.as_ref().is_some_and(|android| {
            android
                .findings
                .iter()
                .any(|finding| severity_rank(finding.severity) >= threshold)
        })
        || report.windows_package.as_ref().is_some_and(|windows| {
            windows
                .findings
                .iter()
                .any(|finding| severity_rank(finding.severity) >= threshold)
        })
}

fn threshold_rank(severity: SeverityThreshold) -> u8 {
    match severity {
        SeverityThreshold::Info => 0,
        SeverityThreshold::Low => 1,
        SeverityThreshold::Medium => 2,
        SeverityThreshold::High => 3,
        SeverityThreshold::Critical => 4,
    }
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(path: PathBuf) -> InspectArgs {
        InspectArgs {
            path,
            output: None,
            pretty: false,
            json: true,
            format: ReportFormat::Json,
            depth: AnalysisDepth::Standard,
            hashes: vec![],
            strings: false,
            entropy: false,
            signature: false,
            dependencies: false,
            min_string_length: 4,
            max_strings: 100,
            fail_on: None,
            policy: None,
        }
    }

    #[test]
    fn standard_report_is_versioned_and_serializable() {
        let root = std::env::temp_dir().join(format!("bytetrawl-cli-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).expect("create CLI fixture");
        std::fs::write(root.join("metadata.json"), br#"{"name":"fixture"}"#)
            .expect("write CLI fixture");
        let report = inspect(&arguments(root.clone()), &CancellationToken::default())
            .expect("inspect CLI fixture");
        assert_eq!(report.schema_version, 1);
        assert_eq!(report.files.len(), 1);
        let json = serde_json::to_value(&report).expect("serialize report");
        assert_eq!(json["generator"]["name"], "ByteTrawl");
        assert_eq!(json["files"][0]["metadata"]["name"], "\"fixture\"");
        assert!(render_markdown(&report).starts_with("# ByteTrawl inspection"));
        assert!(render_html(&report).contains("<!doctype html>"));
        assert_eq!(render_sarif(&report)["version"], "2.1.0");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn deep_defaults_to_sha256_and_expensive_analyses() {
        let path = std::env::temp_dir().join(format!("bytetrawl-cli-{}", uuid::Uuid::new_v4()));
        std::fs::write(&path, b"hello from ByteTrawl CLI").expect("write CLI fixture");
        let mut args = arguments(path.clone());
        args.depth = AnalysisDepth::Deep;
        let report = inspect(&args, &CancellationToken::default()).expect("deep CLI inspection");
        assert!(report.files[0].summary.sha256.is_some());
        assert!(report.files[0].summary.entropy.is_some());
        assert!(report.files[0].strings.is_some());
        let _ = std::fs::remove_file(path);
    }
}
