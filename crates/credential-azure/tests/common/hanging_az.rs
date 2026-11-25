//! A script in place of `az` that never finishes: it starts a child that
//! waits five minutes, records the child's pid in `child.pid`, and waits for
//! it. On Unix it records its own pid in `az.pid` first. Ending the script
//! alone leaves the child running.
//!
//! The script's directory holds nothing else, so it can go first on `PATH`.
//! Dropping a [`HangingAz`] kills any process it recorded that is still
//! running, so a failed test leaves none behind.

use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use runbooks_credential_azure::host::Host;
use tempfile::TempDir;

/// How long the script may take to start its child and say so.
const START: Duration = Duration::from_secs(30);

/// How long ended processes may take to go, reaped by whoever started them.
pub(crate) const GONE: Duration = Duration::from_secs(5);

const POLL: Duration = Duration::from_millis(50);

#[cfg(not(windows))]
const SCRIPT: (&str, &str) = (
    "az",
    "#!/bin/sh\n\
echo $$ > \"$FAKE_AZ_RESPONSES/az.pid\"\n\
sleep 300 &\n\
echo $! > \"$FAKE_AZ_RESPONSES/child.pid\"\n\
wait\n",
);

/// The Azure CLI on Windows is `az.cmd`, which `cmd.exe` runs. Its child is
/// a PowerShell that records its own pid and sleeps. It calls .NET only, no
/// cmdlet, so it loads no module.
#[cfg(windows)]
const SCRIPT: (&str, &str) = (
    "az.cmd",
    "@echo off\r\n\
\"%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoProfile -NonInteractive -Command \"[IO.File]::WriteAllText($env:FAKE_AZ_RESPONSES + '\\child.pid', [string]$PID); [Threading.Thread]::Sleep(300000)\"\r\n",
);

/// The variables that name the home directory, and on Windows the
/// application data in it.
const HOME_VARS: &[&str] = if cfg!(windows) {
    &["USERPROFILE", "APPDATA", "LOCALAPPDATA"]
} else {
    &["HOME"]
};

/// The pid files the script writes, the child's last.
const PID_FILES: [&str; 2] = ["az.pid", "child.pid"];

pub(crate) struct HangingAz {
    /// Holds the script, and the pids it records.
    script: TempDir,
    /// The home directory every run gets, so none reads the real one.
    home: TempDir,
}

impl HangingAz {
    pub(crate) fn new() -> Result<Self, Box<dyn Error>> {
        Self::with_script(SCRIPT.1)
    }

    /// `contents` in place of the script, which records its pids the same
    /// way.
    pub(crate) fn with_script(contents: &str) -> Result<Self, Box<dyn Error>> {
        let script = tempfile::tempdir()?;
        let program = script.path().join(SCRIPT.0);
        fs::write(&program, contents)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&program, fs::Permissions::from_mode(0o755))?;
        }
        Ok(Self {
            script,
            home: tempfile::tempdir()?,
        })
    }

    pub(crate) fn program(&self) -> PathBuf {
        self.script.path().join(SCRIPT.0)
    }

    /// The test process's environment without its `az` config variables,
    /// with a home of its own and where the script records its pids.
    pub(crate) fn env(&self) -> Vec<(OsString, OsString)> {
        let mut env: Vec<_> = Host::new(std::env::vars_os(), cfg!(windows))
            .az_env()
            .into_iter()
            .filter(|(name, _)| !HOME_VARS.iter().any(|home| name.eq_ignore_ascii_case(home)))
            .collect();
        env.extend(
            HOME_VARS
                .iter()
                .map(|home| ((*home).into(), self.home.path().into())),
        );
        env.push(("FAKE_AZ_RESPONSES".into(), self.script.path().into()));
        env
    }

    /// The pids the script recorded, once it has started its child.
    pub(crate) async fn started(&self) -> Result<Vec<u32>, Box<dyn Error>> {
        tokio::time::timeout(START, self.recorded_soon())
            .await
            .map_err(|_elapsed| {
                format!("the script did not start its child within {START:?}").into()
            })
    }

    async fn recorded_soon(&self) -> Vec<u32> {
        loop {
            if let Some(pids) = self.recorded() {
                return pids;
            }
            tokio::time::sleep(POLL).await;
        }
    }

    /// Every pid recorded so far, or `None` until the child's is.
    fn recorded(&self) -> Option<Vec<u32>> {
        let read = |file: &str| {
            fs::read_to_string(self.script.path().join(file))
                .ok()
                .and_then(|pid| pid.trim().parse::<u32>().ok())
        };
        read("child.pid")?;
        Some(PID_FILES.iter().filter_map(|file| read(file)).collect())
    }

    /// Waits up to [`GONE`] for every pid in `pids` to end, and returns
    /// those still running.
    pub(crate) async fn still_running(pids: &[u32]) -> Vec<u32> {
        let mut running = pids.to_vec();
        for _ in 0..GONE.as_millis() / POLL.as_millis() {
            running.retain(|pid| alive(*pid));
            if running.is_empty() {
                break;
            }
            tokio::time::sleep(POLL).await;
        }
        running
    }
}

impl Drop for HangingAz {
    fn drop(&mut self) {
        for pid in self.recorded().unwrap_or_default() {
            if alive(pid) {
                kill(pid);
            }
        }
    }
}

#[cfg(unix)]
fn alive(pid: u32) -> bool {
    Command::new("/bin/kill")
        .args(["-0", &pid.to_string()])
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(unix)]
fn kill(pid: u32) {
    // A process that cannot be killed is reported by the test's assertion.
    let _left = Command::new("/bin/kill")
        .args(["-KILL", &pid.to_string()])
        .stderr(Stdio::null())
        .status();
}

#[cfg(windows)]
fn system32(program: &str) -> PathBuf {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    PathBuf::from(root).join("System32").join(program)
}

#[cfg(windows)]
fn alive(pid: u32) -> bool {
    Command::new(system32("tasklist.exe"))
        .args(["/FI", &format!("PID eq {pid}"), "/NH"])
        .stderr(Stdio::null())
        .output()
        .is_ok_and(|listed| {
            let pid = pid.to_string();
            listed
                .stdout
                .split(u8::is_ascii_whitespace)
                .any(|word| word == pid.as_bytes())
        })
}

#[cfg(windows)]
fn kill(pid: u32) {
    // A process that cannot be killed is reported by the test's assertion.
    let _left = Command::new(system32("taskkill.exe"))
        .args(["/F", "/PID", &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}
