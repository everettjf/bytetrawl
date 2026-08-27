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
