//! Versioned, deterministic release policies for local and CI evaluation.

use bytetrawl_android::AndroidAuditReportV1;
use bytetrawl_compare::CompareReportV1;
use bytetrawl_core::Severity;
use bytetrawl_ios::IpaAuditReportV1;
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
    if let Some(minimum) = policy.fail_on_severity {
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
    violations.sort_by(|left, right| {
        left.rule_id
            .cmp(&right.rule_id)
            .then(left.message.cmp(&right.message))
    });
    violations.dedup();
    violations
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
    violations
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
    if let Some(minimum) = policy.fail_on_severity {
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
    violations.sort_by(|left, right| {
        left.rule_id
            .cmp(&right.rule_id)
            .then(left.message.cmp(&right.message))
    });
    violations.dedup();
    violations
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
}
