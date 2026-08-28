use std::process::Command;

#[test]
fn stdout_contains_only_machine_readable_json() {
    let directory = tempfile::tempdir().expect("create CLI fixture directory");
    let artifact = directory.path().join("artifact.json");
    std::fs::write(&artifact, br#"{"name":"fixture"}"#).expect("write CLI fixture");
    let output = Command::new(env!("CARGO_BIN_EXE_bytetrawl-cli"))
        .args([
            "inspect",
            artifact.to_str().expect("UTF-8 fixture path"),
            "--json",
        ])
        .output()
        .expect("run CLI");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse stdout JSON");
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["run"]["partial"], false);
}

#[test]
fn output_file_is_complete_and_pretty_printed() {
    let directory = tempfile::tempdir().expect("create CLI fixture directory");
    let artifact = directory.path().join("artifact.txt");
    let report = directory.path().join("report.json");
    std::fs::write(&artifact, b"ByteTrawl integration fixture").expect("write CLI fixture");
    let status = Command::new(env!("CARGO_BIN_EXE_bytetrawl-cli"))
        .args([
            "inspect",
            artifact.to_str().expect("UTF-8 fixture path"),
            "--pretty",
            "--hash",
            "sha256",
            "--output",
            report.to_str().expect("UTF-8 report path"),
        ])
        .status()
        .expect("run CLI");
    assert!(status.success());
    let bytes = std::fs::read(&report).expect("read report");
    assert!(bytes.ends_with(b"\n"));
    assert!(bytes.windows(2).any(|window| window == b"\n "));
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("parse report JSON");
    assert!(value["files"][0]["summary"]["sha256"].is_string());
}

#[test]
fn every_report_format_is_emitted_by_the_cli() {
    let directory = tempfile::tempdir().expect("create report fixture directory");
    let artifact = directory.path().join("artifact.txt");
    std::fs::write(&artifact, b"report formats").expect("write report fixture");
    for (format, marker) in [
        ("json", "\"schema_version\""),
        ("markdown", "# ByteTrawl inspection"),
        ("html", "<!doctype html>"),
        ("sarif", "\"2.1.0\""),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_bytetrawl-cli"))
            .args([
                "inspect",
                artifact.to_str().expect("UTF-8 artifact path"),
                "--format",
                format,
            ])
            .output()
            .expect("run report format");
        assert!(
            output.status.success(),
            "{format}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains(marker),
            "missing {format} marker"
        );
    }
}

#[test]
fn compare_and_policy_failures_have_stable_exit_codes() {
    let directory = tempfile::tempdir().expect("create compare fixture directory");
    let before = directory.path().join("before");
    let after = directory.path().join("after");
    std::fs::create_dir(&before).expect("create baseline");
    std::fs::create_dir(&after).expect("create candidate");
    std::fs::write(before.join("payload"), b"a").expect("write baseline");
    std::fs::write(after.join("payload"), vec![b'a'; 32]).expect("write candidate");
    let policy = directory.path().join("policy.json");
    std::fs::write(&policy, br#"{"schema_version":"1.0","max_growth_bytes":1}"#)
        .expect("write comparison policy");
    let output = Command::new(env!("CARGO_BIN_EXE_bytetrawl-cli"))
        .args([
            "compare",
            before.to_str().expect("UTF-8 baseline path"),
            after.to_str().expect("UTF-8 candidate path"),
            "--policy",
            policy.to_str().expect("UTF-8 policy path"),
        ])
        .output()
        .expect("run policy comparison");
    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse comparison JSON");
    assert_eq!(report["delta_bytes"], 31);
    assert_eq!(
        report["policy_violations"][0]["rule_id"],
        "policy.max-growth-bytes"
    );
}
