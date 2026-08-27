//! Versioned, deterministic release policies for local and CI evaluation.

use bytetrawl_android::AndroidAuditReportV1;
use bytetrawl_compare::CompareReportV1;
use bytetrawl_core::{Finding, Severity};
use bytetrawl_ios::IpaAuditReportV1;
use bytetrawl_linux::DebianReportV1;
use bytetrawl_windows::WindowsPackageReportV1;
use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleasePolicyV1 {
    #[serde(default = "schema_version")]
    pub schema_version: String,
    pub max_artifact_bytes: Option<u64>,
    pub max_growth_bytes: Option<i128>,
    #[serde(default)]
    pub require_privacy_manifest: bool,
    #[serde(default)]
    pub forbidden_architectures: Vec<String>,
    #[serde(default)]
    pub forbidden_entitlements: Vec<String>,
    pub fail_on_severity: Option<Severity>,
    #[serde(default)]
    pub forbidden_android_permissions: Vec<String>,
    pub max_android_dex_methods: Option<u64>,
    #[serde(default)]
    pub require_android_signature: bool,
    #[serde(default)]
    pub forbidden_windows_capabilities: Vec<String>,
    #[serde(default)]
    pub require_windows_package_signature: bool,
    pub max_linux_installed_bytes: Option<u64>,
    #[serde(default)]
    pub forbidden_linux_maintainer_scripts: Vec<String>,
    #[serde(default)]
    pub forbid_privileged_linux_files: bool,
    pub profile: Option<PolicyProfile>,
    #[serde(default)]
    pub enabled_rules: Vec<String>,
    #[serde(default)]
    pub disabled_rules: Vec<String>,
    #[serde(default)]
    pub severity_overrides: IndexMap<String, Severity>,
    #[serde(default)]
    pub suppressions: Vec<RuleSuppression>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyProfile {
    Balanced,
    Strict,
    StoreRelease,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleSuppression {
    pub rule_id: String,
    pub reason: String,
    pub expires_at: Option<DateTime<Utc>>,
}

fn schema_version() -> String {
    "1.0".into()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyViolation {
    pub rule_id: String,
    pub severity: Severity,
    pub message: String,
}

pub fn evaluate_generic(
    policy: &ReleasePolicyV1,
    artifact_bytes: u64,
    findings: &[Finding],
) -> Vec<PolicyViolation> {
    let mut violations = Vec::new();
    if policy
        .max_artifact_bytes
        .is_some_and(|maximum| artifact_bytes > maximum)
    {
        violations.push(PolicyViolation {
            rule_id: "policy.max-artifact-bytes".into(),
            severity: Severity::High,
            message: format!("artifact size {artifact_bytes} exceeds policy maximum"),
        });
    }
    if let Some(minimum) = finding_threshold(policy) {
        violations.extend(
            findings
                .iter()
                .filter(|finding| severity_rank(finding.severity) >= severity_rank(minimum))
                .map(|finding| PolicyViolation {
                    rule_id: format!(
                        "analysis.{}",
                        finding.title.to_ascii_lowercase().replace(' ', "-")
                    ),
                    severity: finding.severity,
                    message: finding.title.clone(),
                }),
        );
    }
    finalize(policy, violations)
}

pub fn evaluate_ipa(policy: &ReleasePolicyV1, report: &IpaAuditReportV1) -> Vec<PolicyViolation> {
    let mut violations = Vec::new();
    if policy
        .max_artifact_bytes
        .is_some_and(|maximum| report.total_bytes > maximum)
    {
        violations.push(PolicyViolation {
            rule_id: "policy.max-artifact-bytes".into(),
            severity: Severity::High,
            message: format!(
                "installed size {} exceeds policy maximum {}",
                report.total_bytes,
                policy.max_artifact_bytes.unwrap_or_default()
            ),
        });
    }
    if policy.require_privacy_manifest && !report.has_privacy_manifest {
        violations.push(PolicyViolation {
            rule_id: "policy.require-privacy-manifest".into(),
            severity: Severity::High,
            message: "PrivacyInfo.xcprivacy is required".into(),
        });
    }
    for architecture in &report.architectures {
        if policy.forbidden_architectures.contains(architecture) {
            violations.push(PolicyViolation {
                rule_id: "policy.forbidden-architecture".into(),
                severity: Severity::High,
                message: format!("architecture {architecture} is forbidden"),
            });
        }
    }
    if let Some(signing) = report.signing.as_ref() {
        for entitlement in &policy.forbidden_entitlements {
            if signing.entitlements.contains_key(entitlement) {
                violations.push(PolicyViolation {
                    rule_id: "policy.forbidden-entitlement".into(),
                    severity: Severity::High,
                    message: format!("entitlement {entitlement} is forbidden"),
                });
            }
        }
    }
    if let Some(minimum) = finding_threshold(policy) {
        violations.extend(
            report
                .findings
                .iter()
                .filter(|finding| severity_rank(finding.severity) >= severity_rank(minimum))
                .map(|finding| PolicyViolation {
                    rule_id: finding.rule_id.clone(),
                    severity: finding.severity,
                    message: finding.title.clone(),
                }),
        );
    }
    finalize(policy, violations)
}

pub fn evaluate_compare(
    policy: &ReleasePolicyV1,
    report: &CompareReportV1,
) -> Vec<PolicyViolation> {
    let mut violations = Vec::new();
    if policy
        .max_artifact_bytes
        .is_some_and(|maximum| report.after_bytes > maximum)
    {
        violations.push(PolicyViolation {
            rule_id: "policy.max-artifact-bytes".into(),
            severity: Severity::High,
            message: format!(
                "candidate size {} exceeds policy maximum",
                report.after_bytes
            ),
        });
    }
    if policy
        .max_growth_bytes
        .is_some_and(|maximum| report.delta_bytes > maximum)
    {
        violations.push(PolicyViolation {
            rule_id: "policy.max-growth-bytes".into(),
            severity: Severity::High,
            message: format!("size growth {} exceeds policy maximum", report.delta_bytes),
        });
    }
    finalize(policy, violations)
}

pub fn evaluate_android(
    policy: &ReleasePolicyV1,
    report: &AndroidAuditReportV1,
) -> Vec<PolicyViolation> {
    let mut violations = Vec::new();
    for permission in &policy.forbidden_android_permissions {
        if report.permissions.contains(permission) {
            violations.push(PolicyViolation {
                rule_id: "policy.forbidden-android-permission".into(),
                severity: Severity::High,
                message: format!("Android permission {permission} is forbidden"),
            });
        }
    }
    let methods = report.dex.iter().map(|dex| dex.methods as u64).sum::<u64>();
    if policy
        .max_android_dex_methods
        .is_some_and(|maximum| methods > maximum)
    {
        violations.push(PolicyViolation {
            rule_id: "policy.max-android-dex-methods".into(),
            severity: Severity::High,
            message: format!("DEX method count {methods} exceeds policy maximum"),
        });
    }
    if policy.require_android_signature && report.signing_schemes.is_empty() {
        violations.push(PolicyViolation {
            rule_id: "policy.require-android-signature".into(),
            severity: Severity::High,
            message: "An APK signature is required".into(),
        });
    }
    if let Some(minimum) = finding_threshold(policy) {
        violations.extend(
            report
                .findings
                .iter()
                .filter(|finding| severity_rank(finding.severity) >= severity_rank(minimum))
                .map(|finding| PolicyViolation {
                    rule_id: finding.rule_id.clone(),
                    severity: finding.severity,
                    message: finding.title.clone(),
                }),
        );
    }
    finalize(policy, violations)
}

pub fn evaluate_windows(
    policy: &ReleasePolicyV1,
    report: &WindowsPackageReportV1,
) -> Vec<PolicyViolation> {
    let mut violations = Vec::new();
    for capability in &policy.forbidden_windows_capabilities {
        if report.capabilities.contains(capability)
            || report.restricted_capabilities.contains(capability)
        {
            violations.push(PolicyViolation {
                rule_id: "policy.forbidden-windows-capability".into(),
                severity: Severity::High,
                message: format!("Windows capability {capability} is forbidden"),
            });
        }
    }
    if policy.require_windows_package_signature && !report.signature_present {
        violations.push(PolicyViolation {
            rule_id: "policy.require-windows-package-signature".into(),
            severity: Severity::High,
            message: "An APPX/MSIX package signature is required".into(),
        });
    }
    if let Some(minimum) = finding_threshold(policy) {
        violations.extend(
            report
                .findings
                .iter()
                .filter(|finding| severity_rank(finding.severity) >= severity_rank(minimum))
                .map(|finding| PolicyViolation {
                    rule_id: finding.rule_id.clone(),
                    severity: finding.severity,
                    message: finding.title.clone(),
                }),
        );
    }
    finalize(policy, violations)
}

pub fn evaluate_linux(policy: &ReleasePolicyV1, report: &DebianReportV1) -> Vec<PolicyViolation> {
    let mut violations = Vec::new();
    if policy
        .max_linux_installed_bytes
        .is_some_and(|maximum| report.installed_bytes > maximum)
    {
        violations.push(PolicyViolation {
            rule_id: "policy.max-linux-installed-bytes".into(),
            severity: Severity::High,
            message: format!(
                "Linux installed size {} exceeds policy maximum",
                report.installed_bytes
            ),
        });
    }
    for script in &report.maintainer_scripts {
        if policy.forbidden_linux_maintainer_scripts.contains(script) {
            violations.push(PolicyViolation {
                rule_id: "policy.forbidden-linux-maintainer-script".into(),
                severity: Severity::High,
                message: format!("Linux maintainer script {script} is forbidden"),
            });
        }
    }
    if policy.forbid_privileged_linux_files {
        violations.extend(
            report
                .files
                .iter()
                .filter(|file| !file.is_directory && file.mode & 0o6000 != 0)
                .map(|file| PolicyViolation {
                    rule_id: "policy.forbid-privileged-linux-files".into(),
                    severity: Severity::High,
                    message: format!("{} has mode {:o}", file.path.display(), file.mode),
                }),
        );
    }
    if let Some(minimum) = finding_threshold(policy) {
        violations.extend(
            report
                .findings
                .iter()
                .filter(|finding| severity_rank(finding.severity) >= severity_rank(minimum))
                .map(|finding| PolicyViolation {
                    rule_id: finding.rule_id.clone(),
                    severity: finding.severity,
                    message: finding.title.clone(),
                }),
        );
    }
    finalize(policy, violations)
}

fn finalize(
    policy: &ReleasePolicyV1,
    mut violations: Vec<PolicyViolation>,
) -> Vec<PolicyViolation> {
    let now = Utc::now();
    violations.retain(|violation| {
        if policy.disabled_rules.contains(&violation.rule_id) {
            return false;
        }
        if !policy.enabled_rules.is_empty() && !policy.enabled_rules.contains(&violation.rule_id) {
            return false;
        }
        !policy.suppressions.iter().any(|suppression| {
            suppression.rule_id == violation.rule_id
                && suppression
                    .expires_at
                    .is_none_or(|expiration| expiration > now)
        })
    });
    for violation in &mut violations {
        if let Some(severity) = policy.severity_overrides.get(&violation.rule_id) {
            violation.severity = *severity;
        }
    }
    violations.sort_by(|left, right| {
        left.rule_id
            .cmp(&right.rule_id)
            .then(left.message.cmp(&right.message))
    });
    violations.dedup();
    violations
}

fn finding_threshold(policy: &ReleasePolicyV1) -> Option<Severity> {
    policy.fail_on_severity.or(match policy.profile {
        Some(PolicyProfile::Balanced) => Some(Severity::High),
        Some(PolicyProfile::Strict) => Some(Severity::Low),
        Some(PolicyProfile::StoreRelease) => Some(Severity::Medium),
        None => None,
    })
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

    #[test]
    fn policy_deserializes_with_version_and_defaults() {
        let policy: ReleasePolicyV1 = serde_json::from_str(
            r#"{"max_artifact_bytes":100,"max_growth_bytes":10,"require_privacy_manifest":true,"forbidden_architectures":["x86_64"],"forbidden_entitlements":[],"fail_on_severity":"High"}"#,
        )
        .expect("parse policy");
        assert_eq!(policy.schema_version, "1.0");
        assert_eq!(policy.fail_on_severity, Some(Severity::High));
    }

    #[test]
    fn rule_controls_override_and_suppress_deterministically() {
        let policy: ReleasePolicyV1 = serde_json::from_str(
            r#"{
                "profile":"strict",
                "max_artifact_bytes":null,
                "max_growth_bytes":null,
                "fail_on_severity":null,
                "disabled_rules":["rule.disabled"],
                "severity_overrides":{"rule.override":"Critical"},
                "suppressions":[{
                    "rule_id":"rule.suppressed",
                    "reason":"accepted until next review",
                    "expires_at":"2999-01-01T00:00:00Z"
                }]
            }"#,
        )
        .expect("parse controlled policy");
        let violations = finalize(
            &policy,
            vec![
                PolicyViolation {
                    rule_id: "rule.disabled".into(),
                    severity: Severity::High,
                    message: "disabled".into(),
                },
                PolicyViolation {
                    rule_id: "rule.suppressed".into(),
                    severity: Severity::High,
                    message: "suppressed".into(),
                },
                PolicyViolation {
                    rule_id: "rule.override".into(),
                    severity: Severity::Low,
                    message: "override".into(),
                },
            ],
        );
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].rule_id, "rule.override");
        assert_eq!(violations[0].severity, Severity::Critical);
    }
}
