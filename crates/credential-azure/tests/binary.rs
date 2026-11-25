//! The binary as the app starts it.

use std::error::Error;
use std::io::Write;
use std::process::{Command, Stdio};

/// The app closes the plugin's output and error streams; the plugin's
/// answer cannot be written, and nor can why it stopped.
#[test]
fn a_failure_it_cannot_report_still_exits_with_failure() -> Result<(), Box<dyn Error>> {
    let mut plugin = Command::new(env!("CARGO_BIN_EXE_runbooks-credential-azure"))
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    drop(plugin.stdout.take());
    drop(plugin.stderr.take());
    let mut stdin = plugin.stdin.take().ok_or("the plugin has no input")?;
    stdin.write_all(b"not a request\n")?;
    drop(stdin);
    assert_eq!(plugin.wait()?.code(), Some(1));
    Ok(())
}
