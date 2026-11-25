//! Ending a child process and every process it started. Killing `az` alone
//! leaves what it started running.
//!
//! On Unix the child leads a process group of its own, and `/bin/kill`
//! signals the group. On Windows `taskkill /T /F` ends the child and its
//! descendants. Both run by absolute path: `PATH` comes from the app.
//!
//! The child is reaped only after the last signal. Until then its pid, which
//! is the group's id, cannot be given to another process.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::thread;
use std::time::Duration;

use tokio::process::{Child, Command};

/// How often a `kill` or `taskkill` run is checked for its exit, and how
/// many times: 5 seconds in all.
const KILLER_POLL: Duration = Duration::from_millis(5);
const KILLER_POLLS: u32 = 1000;

const KILL: &str = "/bin/kill";

/// How a [`ProcessTree`] is ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Killer {
    /// Signal the child's process group with `/bin/kill`, on Unix.
    ProcessGroup,
    /// End the child and its descendants with this `taskkill.exe`, on
    /// Windows.
    Taskkill(PathBuf),
    /// End the child alone: Windows without `SystemRoot`, where there is no
    /// `taskkill.exe` to trust.
    ChildOnly,
}

/// A child process and every process it starts, ended together when the
/// tree is dropped.
///
/// A tree that is dropped is killed at once. A cancelled call is dropped,
/// and the app cancels a sign-in by closing the plugin's input, after which
/// the plugin exits: a signal left for later would never be sent.
#[derive(Debug)]
pub struct ProcessTree {
    child: Child,
    killer: Killer,
}

impl ProcessTree {
    /// Spawns `command`, leading a process group of its own when `killer`
    /// signals groups.
    ///
    /// # Errors
    ///
    /// Spawning's.
    pub fn spawn(command: &mut Command, killer: Killer) -> io::Result<Self> {
        #[cfg(unix)]
        if killer == Killer::ProcessGroup {
            command.process_group(0);
        }
        let child = command.spawn()?;
        Ok(Self { child, killer })
    }

    /// The child, for its pipes and its exit. Wait for it only once its
    /// output has closed: a process it started may still hold that output,
    /// and once the child is reaped its group is no longer signalled.
    pub const fn child(&mut self) -> &mut Child {
        &mut self.child
    }

    fn kill(&mut self, pid: u32) {
        match &self.killer {
            Killer::ProcessGroup => {
                if let Err(failed) = run_killer(Path::new(KILL), &kill_args(pid)) {
                    crate::log(format_args!("ending what az started: kill {failed}"));
                }
            }
            Killer::Taskkill(program) => {
                if let Err(failed) = run_killer(program, &taskkill_args(pid)) {
                    crate::log(format_args!("ending what az started: taskkill {failed}"));
                }
            }
            Killer::ChildOnly => {}
        }
        // The child itself, when its tree could not be ended.
        if let Err(error) = self.child.start_kill() {
            crate::log(format_args!("killing az: {}", error.kind()));
        }
    }
}

impl Drop for ProcessTree {
    fn drop(&mut self) {
        if let Some(pid) = self.child.id() {
            self.kill(pid);
        }
    }
}

/// `kill`'s arguments to kill process group `pid`.
fn kill_args(pid: u32) -> [String; 3] {
    ["-KILL".to_owned(), "--".to_owned(), format!("-{pid}")]
}

/// `taskkill`'s arguments to end process `pid` and its descendants.
fn taskkill_args(pid: u32) -> [String; 4] {
    [
        "/T".to_owned(),
        "/F".to_owned(),
        "/PID".to_owned(),
        pid.to_string(),
    ]
}

/// Why `kill` or `taskkill` did not run to its end. It names no value.
#[derive(Debug, PartialEq, Eq)]
enum KillerFailed {
    Start(io::ErrorKind),
    Wait(io::ErrorKind),
    TimedOut,
}

impl fmt::Display for KillerFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start(kind) => write!(f, "could not start: {kind}"),
            Self::Wait(kind) => write!(f, "could not be waited for: {kind}"),
            Self::TimedOut => write!(
                f,
                "did not finish within {} seconds",
                (KILLER_POLL * KILLER_POLLS).as_secs()
            ),
        }
    }
}

/// Runs `program` and waits for it, up to 5 seconds. Its exit status and
/// output are dropped: `kill` fails for a group that has already ended,
/// which is how a stop usually ends.
fn run_killer(program: &Path, args: &[String]) -> Result<(), KillerFailed> {
    let mut killer = std::process::Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| KillerFailed::Start(error.kind()))?;
    for _ in 0..KILLER_POLLS {
        match killer.try_wait() {
            Ok(Some(_status)) => return Ok(()),
            Ok(None) => thread::sleep(KILLER_POLL),
            Err(error) => return Err(KillerFailed::Wait(error.kind())),
        }
    }
    // Left unreaped if it does not end at once: the system is stuck.
    match killer.kill().and_then(|()| killer.try_wait()) {
        Ok(_) | Err(_) => Err(KillerFailed::TimedOut),
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::{KillerFailed, kill_args, run_killer, taskkill_args};

    #[test]
    fn kill_signals_the_group_and_taskkill_ends_the_tree() {
        assert_eq!(kill_args(4242), ["-KILL", "--", "-4242"]);
        assert_eq!(taskkill_args(4242), ["/T", "/F", "/PID", "4242"]);
    }

    #[test]
    fn a_killer_that_cannot_start_says_why_without_its_path() -> Result<(), String> {
        let temp = tempfile::tempdir().map_err(|error| error.to_string())?;
        let missing = temp.path().join("SECRET-NOT-THERE").join("kill");
        let failed = run_killer(&missing, &[])
            .err()
            .ok_or("a killer that is not there ran")?;
        assert_eq!(failed, KillerFailed::Start(io::ErrorKind::NotFound));
        let shown = failed.to_string();
        assert_eq!(shown, "could not start: entity not found");
        assert!(!shown.contains("SECRET"), "{shown}");
        Ok(())
    }

    #[test]
    fn a_killer_failure_names_no_value() {
        assert_eq!(
            KillerFailed::Wait(io::ErrorKind::Interrupted).to_string(),
            "could not be waited for: operation interrupted"
        );
        assert_eq!(
            KillerFailed::TimedOut.to_string(),
            "did not finish within 5 seconds"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_killer_that_runs_is_waited_for() {
        let program = std::path::Path::new(super::KILL);
        let this_process = std::process::id().to_string();
        assert_eq!(
            run_killer(program, &["-0".to_owned(), this_process]),
            Ok(())
        );
    }
}
