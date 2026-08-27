use bytetrawl_core::{ArtifactNode, ByteTrawlError, FileFormat, Result};
use std::{
    collections::BTreeMap,
    io::Read,
    path::PathBuf,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use wait_timeout::ChildExt;

const MAX_CAPTURE_BYTES: u64 = 16 * 1024 * 1024;
pub const DEFAULT_CAPTURE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub enum ToolAvailability {
    Available(PathBuf),
    Unavailable,
}
#[derive(Debug, Clone)]
pub struct ToolOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    pub timed_out: bool,
    pub cancelled: bool,
}
pub trait ExternalTool: Send + Sync {
    fn id(&self) -> &'static str;
    fn display_name(&self) -> &'static str;
    fn detect(&self) -> ToolAvailability;
    fn supports(&self, artifact: &ArtifactNode) -> bool {
        artifact.path.is_file()
    }
    /// Launches only after an explicit UI action.
    fn launch(&self, artifact: &ArtifactNode) -> Result<()>;
    fn capture(&self, _artifact: &ArtifactNode) -> Result<Option<ToolOutput>> {
        Ok(None)
    }
    fn capture_controlled(
        &self,
        artifact: &ArtifactNode,
        _timeout: Duration,
        _is_cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<Option<ToolOutput>> {
        self.capture(artifact)
    }
}

pub struct CommandTool {
    id: &'static str,
    name: &'static str,
    candidates: &'static [&'static str],
    args: &'static [&'static str],
    formats: Option<&'static [FileFormat]>,
    capture: bool,
}
impl CommandTool {
    pub const fn new(
        id: &'static str,
        name: &'static str,
        candidates: &'static [&'static str],
        args: &'static [&'static str],
    ) -> Self {
        Self {
            id,
            name,
            candidates,
            args,
            formats: None,
            capture: false,
        }
    }
    pub const fn with_formats(mut self, formats: &'static [FileFormat]) -> Self {
        self.formats = Some(formats);
        self
    }
    pub const fn with_capture(mut self) -> Self {
        self.capture = true;
        self
    }
}
impl ExternalTool for CommandTool {
    fn id(&self) -> &'static str {
        self.id
    }
    fn display_name(&self) -> &'static str {
        self.name
    }
    fn detect(&self) -> ToolAvailability {
        self.candidates
            .iter()
            .find_map(|candidate| find_command(candidate))
            .map(ToolAvailability::Available)
            .unwrap_or(ToolAvailability::Unavailable)
    }
    fn supports(&self, artifact: &ArtifactNode) -> bool {
        artifact.path.is_file()
            && self
                .formats
                .is_none_or(|formats| artifact.format.is_some_and(|f| formats.contains(&f)))
    }
    fn launch(&self, artifact: &ArtifactNode) -> Result<()> {
        let ToolAvailability::Available(exe) = self.detect() else {
            return Err(ByteTrawlError::Malformed(format!(
                "{} is not installed",
                self.name
            )));
        };
        Command::new(exe)
            .args(self.args)
            .arg(&artifact.path)
            .stdin(Stdio::null())
            .spawn()
            .map_err(|source| ByteTrawlError::Io {
                path: artifact.path.clone(),
                source,
            })?;
        Ok(())
    }
    fn capture(&self, artifact: &ArtifactNode) -> Result<Option<ToolOutput>> {
        self.capture_controlled(artifact, DEFAULT_CAPTURE_TIMEOUT, &|| false)
    }
    fn capture_controlled(
        &self,
        artifact: &ArtifactNode,
        timeout: Duration,
        is_cancelled: &(dyn Fn() -> bool + Sync),
    ) -> Result<Option<ToolOutput>> {
        if !self.capture {
            return Ok(None);
        }
        let ToolAvailability::Available(exe) = self.detect() else {
            return Err(ByteTrawlError::Malformed(format!(
                "{} is not installed",
                self.name
            )));
        };
        let mut child = Command::new(exe)
            .args(self.args)
            .arg(&artifact.path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| ByteTrawlError::Io {
                path: artifact.path.clone(),
                source,
            })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            ByteTrawlError::Malformed(format!("{} stdout pipe unavailable", self.name))
        })?;
        let stderr = child.stderr.take().ok_or_else(|| {
            ByteTrawlError::Malformed(format!("{} stderr pipe unavailable", self.name))
        })?;
        let stdout_thread = thread::spawn(move || read_capped(stdout));
        let stderr_thread = thread::spawn(move || read_capped(stderr));
        let started = Instant::now();
        let mut timed_out = false;
        let mut cancelled = false;
        let status = loop {
            if is_cancelled() {
                cancelled = true;
                terminate_child(&mut child, &artifact.path)?;
                break child.wait().map_err(|source| ByteTrawlError::Io {
                    path: artifact.path.clone(),
                    source,
                })?;
            }
            let remaining = timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                timed_out = true;
                terminate_child(&mut child, &artifact.path)?;
                break child.wait().map_err(|source| ByteTrawlError::Io {
                    path: artifact.path.clone(),
                    source,
                })?;
            }
            let interval = remaining.min(Duration::from_millis(100));
            if let Some(status) =
                child
                    .wait_timeout(interval)
                    .map_err(|source| ByteTrawlError::Io {
                        path: artifact.path.clone(),
                        source,
                    })?
            {
                break status;
            }
        };
        let (stdout, stdout_truncated) = stdout_thread
            .join()
            .map_err(|_| ByteTrawlError::Malformed("stdout reader panicked".into()))?
            .map_err(|source| ByteTrawlError::Io {
                path: artifact.path.clone(),
                source,
            })?;
        let (stderr, stderr_truncated) = stderr_thread
            .join()
            .map_err(|_| ByteTrawlError::Malformed("stderr reader panicked".into()))?
            .map_err(|source| ByteTrawlError::Io {
                path: artifact.path.clone(),
                source,
            })?;
        Ok(Some(ToolOutput {
            success: status.success(),
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            truncated: stdout_truncated || stderr_truncated,
            timed_out,
            cancelled,
        }))
    }
}

fn terminate_child(child: &mut std::process::Child, path: &std::path::Path) -> Result<()> {
    child
        .kill()
        .or_else(|error| {
            if error.kind() == std::io::ErrorKind::InvalidInput {
                Ok(())
            } else {
                Err(error)
            }
        })
        .map_err(|source| ByteTrawlError::Io {
            path: path.to_path_buf(),
            source,
        })
}

fn read_capped(reader: impl Read) -> std::io::Result<(Vec<u8>, bool)> {
    let mut bytes = Vec::new();
    reader.take(MAX_CAPTURE_BYTES + 1).read_to_end(&mut bytes)?;
    let truncated = bytes.len() as u64 > MAX_CAPTURE_BYTES;
    bytes.truncate(MAX_CAPTURE_BYTES as usize);
    Ok((bytes, truncated))
}
fn find_command(name: &str) -> Option<PathBuf> {
    if name.contains('/') {
        let p = PathBuf::from(name);
        return p.is_file().then_some(p);
    }
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|p| p.join(name))
            .find(|p| p.is_file())
    })
}

#[derive(Default)]
pub struct ToolRegistry {
    tools: BTreeMap<&'static str, Box<dyn ExternalTool>>,
}
impl ToolRegistry {
    pub fn standard() -> Self {
        let mut r = Self::default();
        r.register(
            CommandTool::new("otool", "otool", &["/usr/bin/otool", "otool"], &["-L"])
                .with_formats(&[FileFormat::MachO, FileFormat::FatMachO])
                .with_capture(),
        );
        r.register(
            CommandTool::new(
                "codesign",
                "codesign",
                &["/usr/bin/codesign", "codesign"],
                &["-dvvv"],
            )
            .with_formats(&[FileFormat::MachO, FileFormat::FatMachO])
            .with_capture(),
        );
        r.register(CommandTool::new("ghidra", "Ghidra", &["ghidraRun"], &[]));
        r.register(CommandTool::new(
            "ida",
            "IDA",
            &[
                "/Applications/IDA Professional 9.2.app/Contents/MacOS/ida64",
                "/Applications/IDA Professional 9.2.app/Contents/MacOS/ida",
                "/Applications/IDA Professional 9.1.app/Contents/MacOS/ida64",
                "/Applications/IDA Professional 9.1.app/Contents/MacOS/ida",
                "/Applications/IDA Professional 9.0.app/Contents/MacOS/ida64",
                "/Applications/IDA Professional 9.0.app/Contents/MacOS/ida",
                "ida64",
                "ida",
            ],
            &[],
        ));
        r.register(CommandTool::new(
            "binary-ninja",
            "Binary Ninja",
            &[
                "/Applications/Binary Ninja.app/Contents/MacOS/binaryninja",
                "binaryninja",
            ],
            &[],
        ));
        r.register(CommandTool::new(
            "hopper",
            "Hopper",
            &[
                "/Applications/Hopper Disassembler v4.app/Contents/MacOS/hopper",
                "/Applications/Hopper Disassembler.app/Contents/MacOS/hopper",
                "hopper",
            ],
            &[],
        ));
        r.register(CommandTool::new(
            "radare2",
            "radare2",
            &["r2", "radare2"],
            &[],
        ));
        r.register(CommandTool::new("cutter", "Cutter", &["cutter"], &[]));
        r.register(
            CommandTool::new("readelf", "readelf", &["readelf", "eu-readelf"], &["-a"])
                .with_formats(&[FileFormat::Elf])
                .with_capture(),
        );
        r.register(
            CommandTool::new("objdump", "objdump", &["objdump", "llvm-objdump"], &["-x"])
                .with_formats(&[FileFormat::Pe, FileFormat::Elf, FileFormat::MachO])
                .with_capture(),
        );
        r.register(
            CommandTool::new("dumpbin", "dumpbin", &["dumpbin.exe", "dumpbin"], &["/all"])
                .with_formats(&[FileFormat::Pe])
                .with_capture(),
        );
        r.register(
            CommandTool::new(
                "sigcheck",
                "Sigcheck",
                &["sigcheck64.exe", "sigcheck.exe", "sigcheck"],
                &["-a", "-h", "-i", "-nobanner"],
            )
            .with_formats(&[FileFormat::Pe])
            .with_capture(),
        );
        r.register(
            CommandTool::new("nm", "nm", &["nm", "llvm-nm"], &[])
                .with_formats(&[
                    FileFormat::Pe,
                    FileFormat::Elf,
                    FileFormat::MachO,
                    FileFormat::FatMachO,
                    FileFormat::Archive,
                ])
                .with_capture(),
        );
        r.register(CommandTool::new("strings", "strings", &["strings"], &[]).with_capture());
        r
    }
    pub fn register(&mut self, tool: impl ExternalTool + 'static) {
        self.tools.insert(tool.id(), Box::new(tool));
    }
    pub fn iter(&self) -> impl Iterator<Item = &dyn ExternalTool> {
        self.tools.values().map(Box::as_ref)
    }
    pub fn get(&self, id: &str) -> Option<&dyn ExternalTool> {
        self.tools.get(id).map(Box::as_ref)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registry_is_extensible() {
        let r = ToolRegistry::standard();
        assert!(r.get("otool").is_some());
        for id in [
            "ghidra",
            "ida",
            "binary-ninja",
            "hopper",
            "dumpbin",
            "sigcheck",
        ] {
            assert!(r.get(id).is_some(), "missing standard tool {id}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn captured_tool_is_terminated_at_time_limit() {
        let artifact = ArtifactNode::new(
            "artifact",
            std::env::current_exe().expect("current executable"),
            bytetrawl_core::ArtifactKind::Executable,
        );
        let tool = CommandTool::new(
            "slow-test",
            "slow test",
            &["/bin/sh"],
            &["-c", "exec sleep 10"],
        )
        .with_capture();
        let started = Instant::now();
        let output = tool
            .capture_controlled(&artifact, Duration::from_millis(30), &|| false)
            .expect("capture")
            .expect("output");
        assert!(output.timed_out);
        assert!(!output.cancelled);
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
