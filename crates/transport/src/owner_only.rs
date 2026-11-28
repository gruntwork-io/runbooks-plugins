//! Paths only the user who runs the plugin, and the system's root, can use.
//! On Unix a plugin sets the mode as it creates the path. On Windows
//! [`OwnerOnly::Icacls`] replaces the path's access list just after.

use std::ffi::{OsStr, OsString};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// How long `whoami.exe` or `icacls.exe` may take.
const TOOL_WAIT: Duration = Duration::from_secs(10);

/// How often a running tool is checked on.
const POLL: Duration = Duration::from_millis(10);

/// What a path is, which decides its access list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathKind {
    /// What is created in a folder later inherits its access list.
    Folder,
    /// A file.
    File,
}

/// How a platform keeps a new path to its owner.
#[derive(Clone, Debug)]
pub enum OwnerOnly {
    /// Unix: the mode the plugin creates the path with.
    Mode,
    /// Windows: `icacls.exe` gives the user full control and stops
    /// inheritance. No one keeps an entry but the user, SYSTEM and
    /// Administrators, as root can read a 0700 path.
    Icacls {
        /// `%SystemRoot%`, whose `System32` holds `whoami.exe` and
        /// `icacls.exe`. Neither is looked for on `PATH`.
        system_root: Option<PathBuf>,
        /// How long each may take.
        wait: Duration,
    },
}

impl OwnerOnly {
    /// The Windows way, with the value of `SystemRoot`.
    #[must_use]
    pub fn icacls(system_root: Option<&OsStr>) -> Self {
        Self::Icacls {
            system_root: system_root.map(PathBuf::from),
            wait: TOOL_WAIT,
        }
    }

    /// Leaves `path` to the user who runs the plugin. For [`Self::Mode`] the
    /// plugin did that when it created the path.
    ///
    /// # Errors
    ///
    /// When `SystemRoot` is unset, or `whoami.exe` or `icacls.exe` fails.
    pub fn restrict(&self, path: &Path, kind: PathKind) -> Result<(), OwnerOnlyError> {
        let Self::Icacls { system_root, wait } = self else {
            return Ok(());
        };
        let system32 = system_root
            .as_ref()
            .ok_or(OwnerOnlyError::NoSystemRoot)?
            .join("System32");
        let whoami = run(&system32.join("whoami.exe"), &["/user".into()], *wait)?;
        let sid = sid(&whoami).ok_or(OwnerOnlyError::NoSid)?;
        let rights = match kind {
            PathKind::Folder => "(OI)(CI)F",
            PathKind::File => "F",
        };
        let args = [
            path.as_os_str().to_owned(),
            "/inheritance:r".into(),
            "/grant:r".into(),
            format!("*{sid}:{rights}").into(),
        ];
        run(&system32.join("icacls.exe"), &args, *wait).map(drop)
    }
}

/// Runs `program` with `args` for at most `wait`, and returns what it
/// printed once it has exited with success: no more than the pipe holds.
fn run(program: &Path, args: &[OsString], wait: Duration) -> Result<Vec<u8>, OwnerOnlyError> {
    let start = |error| OwnerOnlyError::Start {
        program: program.to_owned(),
        error,
    };
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(start)?;
    let deadline = Instant::now() + wait;
    let status = loop {
        if let Some(status) = child.try_wait().map_err(start)? {
            break status;
        }
        if Instant::now() >= deadline {
            // It is reported as timed out whether or not the kill works.
            let _killed: io::Result<ExitStatus> = child.kill().and_then(|()| child.wait());
            return Err(OwnerOnlyError::TimedOut {
                program: program.to_owned(),
                wait,
            });
        }
        thread::sleep(POLL);
    };
    if !status.success() {
        return Err(OwnerOnlyError::Failed {
            program: program.to_owned(),
            status,
        });
    }
    let mut output = Vec::new();
    if let Some(mut stdout) = child.stdout.take() {
        stdout.read_to_end(&mut output).map_err(start)?;
    }
    Ok(output)
}

/// The SID in the table `whoami /user` prints: the one word shaped like
/// one. The headings are in the system's language; the SID is not.
fn sid(output: &[u8]) -> Option<String> {
    let mut sids = output
        .split(u8::is_ascii_whitespace)
        .filter(|word| is_sid(word));
    let sid = sids.next()?;
    let only = sids.next().is_none();
    only.then(|| String::from_utf8_lossy(sid).into_owned())
}

fn is_sid(word: &[u8]) -> bool {
    word.strip_prefix(b"S-1-").is_some_and(|numbers| {
        !numbers.is_empty()
            && numbers
                .iter()
                .all(|byte| byte.is_ascii_digit() || *byte == b'-')
    })
}

/// Why a path could not be left to its owner.
#[derive(Debug, thiserror::Error)]
pub enum OwnerOnlyError {
    /// `SystemRoot` is unset.
    #[error("SystemRoot is not set, so icacls.exe can't be found")]
    NoSystemRoot,
    /// A tool could not be started, waited for or read.
    #[error("{} could not be run: {error}", .program.display())]
    Start {
        /// The tool.
        program: PathBuf,
        /// Why.
        error: io::Error,
    },
    /// A tool ran past its wait, and was killed.
    #[error("{} did not finish within {wait:?}", .program.display())]
    TimedOut {
        /// The tool.
        program: PathBuf,
        /// How long it had.
        wait: Duration,
    },
    /// A tool exited with failure.
    #[error("{} failed: {status}", .program.display())]
    Failed {
        /// The tool.
        program: PathBuf,
        /// How it exited.
        status: ExitStatus,
    },
    /// `whoami.exe` printed no SID.
    #[error("whoami.exe /user printed no SID")]
    NoSid,
}

#[cfg(test)]
mod tests {
    use super::sid;

    /// What `whoami /user` prints on a German system.
    const TABLE: &str = "\r\nBENUTZERINFORMATIONEN\r\n---------------------\r\n\r\nBenutzername SID\r\n============ =============================================\r\nhost\\user    S-1-5-21-1004336348-1177238915-682003330-1001\r\n";

    #[test]
    fn the_sid_is_the_one_word_in_whoamis_table_shaped_like_one() {
        let sid_of = |output: &str| sid(output.as_bytes());
        assert_eq!(
            sid_of(TABLE).as_deref(),
            Some("S-1-5-21-1004336348-1177238915-682003330-1001")
        );
        for output in [
            "",
            "Benutzername SID\r\nhost\\user S-1-\r\n",
            "Benutzername SID\r\nhost\\user S-1-5-x\r\n",
            "host\\user S-1-5-21-1 S-1-5-21-2\r\n",
        ] {
            assert_eq!(sid_of(output), None, "{output:?}");
        }
    }
}
