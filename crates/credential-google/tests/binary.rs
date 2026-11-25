//! Runs the plugin's binary as the app does.

use std::error::Error;
use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn an_error_standard_error_cannot_take_still_exits_with_failure() -> Result<(), Box<dyn Error>> {
    let mut plugin = Command::new(env!("CARGO_BIN_EXE_runbooks-credential-google"))
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    // With no reader on either, writing the answer fails, and then so does
    // reporting that.
    drop(plugin.stdout.take());
    drop(plugin.stderr.take());
    let mut stdin = plugin.stdin.take().ok_or("the plugin has no stdin")?;
    stdin.write_all(b"not json\n")?;
    drop(stdin);
    assert_eq!(plugin.wait()?.code(), Some(1));
    Ok(())
}
