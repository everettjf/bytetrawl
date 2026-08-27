//! Signature inspection providers. Host verification is isolated from format parsing.

use bytetrawl_core::{SignatureInfo, SignatureStatus};
use indexmap::IndexMap;
use std::{
    io::Read,
    path::Path,
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};
use wait_timeout::ChildExt;

const SIGNATURE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_SIGNATURE_OUTPUT: u64 = 4 * 1024 * 1024;

struct BoundedOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    timed_out: bool,
    cancelled: bool,
    truncated: bool,
}

fn run_bounded(command: &mut Command, cancelled: &dyn Fn() -> bool) -> Option<BoundedOutput> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let stdout = child.stdout.take()?;
    let stderr = child.stderr.take()?;
    let read_stream = |mut stream: Box<dyn Read + Send>| {
        let mut bytes = Vec::new();
        let _ = stream
            .by_ref()
            .take(MAX_SIGNATURE_OUTPUT + 1)
            .read_to_end(&mut bytes);
        let truncated = bytes.len() as u64 > MAX_SIGNATURE_OUTPUT;
        bytes.truncate(MAX_SIGNATURE_OUTPUT as usize);
        (bytes, truncated)
    };
    let stdout_reader = thread::spawn(move || read_stream(Box::new(stdout)));
    let stderr_reader = thread::spawn(move || read_stream(Box::new(stderr)));
    let started = Instant::now();
    let (timed_out, was_cancelled) = loop {
        if cancelled() {
            let _ = child.kill();
            break (false, true);
        }
        if started.elapsed() >= SIGNATURE_TIMEOUT {
            let _ = child.kill();
            break (true, false);
        }
        if child
            .wait_timeout(Duration::from_millis(100))
            .ok()?
            .is_some()
        {
            break (false, false);
        }
    };
    let status = child.wait().ok()?;
    let (stdout, stdout_truncated) = stdout_reader.join().ok()?;
    let (stderr, stderr_truncated) = stderr_reader.join().ok()?;
    Some(BoundedOutput {
        status,
        stdout,
        stderr,
        timed_out,
        cancelled: was_cancelled,
        truncated: stdout_truncated || stderr_truncated,
    })
}

pub trait SignatureProvider: Send + Sync {
    fn inspect(&self, path: &Path) -> Option<SignatureInfo>;
}

pub struct HostSignatureProvider;

impl SignatureProvider for HostSignatureProvider {
    fn inspect(&self, path: &Path) -> Option<SignatureInfo> {
        inspect_host_signature_with_cancel(path, &|| false)
    }
}

#[cfg(target_os = "macos")]
pub fn inspect_host_signature_with_cancel(
    path: &Path,
    cancelled: &dyn Fn() -> bool,
) -> Option<SignatureInfo> {
    let mut details_command = Command::new("/usr/bin/codesign");
    details_command
        .args(["-d", "--verbose=4", "--entitlements", ":-"])
        .arg(path);
    let details = run_bounded(&mut details_command, cancelled)?;
    let mut combined = String::from_utf8_lossy(&details.stderr).into_owned();
    combined.push_str(&String::from_utf8_lossy(&details.stdout));
    if combined.contains("code object is not signed at all")
        || (combined.trim().is_empty() && !details.status.success())
    {
        return Some(unsigned());
    }
    let mut verification_command = Command::new("/usr/bin/codesign");
    verification_command
        .args(["--verify", "--deep", "--strict", "--verbose=4"])
        .arg(path);
    let verification = run_bounded(&mut verification_command, cancelled);
    let mut platform = IndexMap::new();
    if details.timed_out {
        platform.insert(
            "Signature Detail Timeout".into(),
            "Exceeded 30 seconds".into(),
        );
    }
    if details.cancelled {
        return None;
    }
    if details.truncated {
        platform.insert(
            "Signature Detail Output".into(),
            "Truncated at 4 MiB per stream".into(),
        );
    }
    let mut identifier = None;
    let mut team_id = None;
    let mut signer = None;
    let mut timestamp = None;
    for line in combined.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key.trim() {
            "Identifier" => identifier = Some(value.trim().to_owned()),
            "TeamIdentifier" => team_id = Some(value.trim().to_owned()),
            "Authority" if signer.is_none() => signer = Some(value.trim().to_owned()),
            "Timestamp" => timestamp = Some(value.trim().to_owned()),
            "Runtime Version" => {
                platform.insert("Hardened Runtime".into(), value.trim().into());
            }
            "Flags" => {
                platform.insert("Code flags".into(), value.trim().into());
            }
            "CDHash" | "Hash choices" | "Page size" | "Platform identifier" => {
                platform.insert(key.trim().into(), value.trim().into());
            }
            "Executable Segment flags" | "CMSDigest" | "CMSDigestType" => {
                platform.insert(key.trim().into(), value.trim().into());
            }
            _ => {}
        }
    }
    if let Some(start) = combined.find("<?xml") {
        platform.insert("Entitlements".into(), combined[start..].trim().to_owned());
    }
    let adhoc = combined.contains("Signature=adhoc") || combined.contains("flags=0x2(adhoc)");
    let verified = verification
        .as_ref()
        .is_some_and(|verification| verification.status.success());
    platform.insert(
        "Cryptographic Verification".into(),
        if verified { "Passed" } else { "Failed" }.into(),
    );
    if let Some(verification) = verification {
        let message = String::from_utf8_lossy(&verification.stderr);
        if !message.trim().is_empty() {
            platform.insert(
                "Verification Detail".into(),
                message.trim().chars().take(4096).collect(),
            );
        }
        if verification.timed_out {
            platform.insert("Verification Timeout".into(), "Exceeded 30 seconds".into());
        }
        if verification.cancelled {
            return None;
        }
        if verification.truncated {
            platform.insert(
                "Verification Output".into(),
                "Truncated at 4 MiB per stream".into(),
            );
        }
    }
    let mut assessment_command = Command::new("/usr/sbin/spctl");
    assessment_command
        .args(["--assess", "--type", "execute", "--verbose=4"])
        .arg(path);
    if let Some(assessment) = run_bounded(&mut assessment_command, cancelled) {
        let mut message = String::from_utf8_lossy(&assessment.stderr).into_owned();
        message.push_str(&String::from_utf8_lossy(&assessment.stdout));
        platform.insert(
            "Gatekeeper / Notarization Assessment".into(),
            format!(
                "{}{}{}",
                if assessment.status.success() {
                    "Accepted"
                } else {
                    "Rejected"
                },
                if message.trim().is_empty() {
                    ""
                } else {
                    " · "
                },
                message.trim().chars().take(4096).collect::<String>()
            ),
        );
        if assessment.timed_out {
            platform.insert("Gatekeeper Timeout".into(), "Exceeded 30 seconds".into());
        }
        if assessment.cancelled {
            return None;
        }
        if assessment.truncated {
            platform.insert(
                "Gatekeeper Output".into(),
                "Truncated at 4 MiB per stream".into(),
            );
        }
    }
    Some(SignatureInfo {
        status: if adhoc {
            SignatureStatus::AdHoc
        } else if verified {
            SignatureStatus::Valid
        } else {
            SignatureStatus::Invalid
        },
        signer,
        identifier,
        team_id,
        timestamp,
        platform,
    })
}

#[cfg(not(target_os = "macos"))]
pub fn inspect_host_signature_with_cancel(
    _path: &Path,
    _cancelled: &dyn Fn() -> bool,
) -> Option<SignatureInfo> {
    None
}

fn unsigned() -> SignatureInfo {
    SignatureInfo {
        status: SignatureStatus::Unsigned,
        signer: None,
        identifier: None,
        team_id: None,
        timestamp: None,
        platform: IndexMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    #[test]
    fn bounded_signature_process_is_actually_cancelled() {
        let started = Instant::now();
        let mut command = Command::new("/bin/sleep");
        command.arg("10");
        let output = run_bounded(&mut command, &|| true).expect("run cancellable process");
        assert!(output.cancelled);
        assert!(started.elapsed() < Duration::from_secs(2));
    }
    #[test]
    fn missing_file_does_not_panic() {
        let result = HostSignatureProvider.inspect(Path::new("/definitely/not/a/file"));
        #[cfg(target_os = "macos")]
        assert!(result.is_some());
        #[cfg(not(target_os = "macos"))]
        assert!(result.is_none());
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn ad_hoc_signed_macho_is_identified() {
        let source = std::env::current_exe().expect("locate signature test executable");
        let target =
            std::env::temp_dir().join(format!("bytetrawl-signature-{}", std::process::id()));
        std::fs::copy(source, &target).expect("copy signature fixture");
        let signed = Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-"])
            .arg(&target)
            .status()
            .expect("run codesign");
        assert!(signed.success());
        let signature = HostSignatureProvider
            .inspect(&target)
            .expect("inspect ad-hoc signature");
        assert!(matches!(
            signature.status,
            SignatureStatus::AdHoc | SignatureStatus::Valid
        ));
        assert_eq!(
            signature.platform.get("Cryptographic Verification"),
            Some(&"Passed".to_string())
        );
        let _ = std::fs::remove_file(target);
    }
}
