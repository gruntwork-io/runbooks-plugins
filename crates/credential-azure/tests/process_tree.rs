//! An `az` call that is cancelled or stopped ends `az` and every process it
//! started, on every OS CI runs.

#[path = "common/hanging_az.rs"]
mod hanging_az;

use std::error::Error;
use std::process::Stdio;
use std::time::Duration;

use runbooks_credential_azure::az::{Az, AzCli, AzDir, Interactive};
use runbooks_credential_azure::host::Host;
use runbooks_credential_azure::process_tree::{Killer, ProcessTree};
use tokio::process::Command;
use tokio::sync::oneshot;

use hanging_az::HangingAz;

type TestResult = Result<(), Box<dyn Error>>;

/// How `main` ends `az` and what it started, on this OS.
fn killer() -> Killer {
    Host::new(std::env::vars_os(), cfg!(windows)).tree_killer()
}

/// Starts a login with `hanging` in place of `az`, and drops it, as a
/// cancelled call's future is, once the script has started its child.
async fn cancel_login(hanging: &HangingAz) -> TestResult {
    let config = tempfile::tempdir()?;
    let az = AzCli::new(Some(hanging.program()), hanging.env(), killer());
    let dir = AzDir {
        config: config.path().to_owned(),
        extensions: None,
    };
    let (sender, _receiver) = oneshot::channel();
    let pids = tokio::select! {
        ended = az.login(&dir, Interactive::Browser, None, sender) => {
            return Err(format!("the login ended on its own: {ended:?}").into());
        }
        pids = hanging.started() => pids?,
    };
    let running = HangingAz::still_running(&pids).await;
    assert!(
        running.is_empty(),
        "{running:?} of {pids:?} outlived the cancelled login by {:?}",
        hanging_az::GONE
    );
    Ok(())
}

#[tokio::test]
async fn a_cancelled_az_call_ends_az_and_what_it_started() -> TestResult {
    cancel_login(&HangingAz::new()?).await
}

/// What `az` started still holds its output, so the call waits for it.
#[cfg(unix)]
#[tokio::test]
async fn a_cancelled_az_call_ends_what_az_started_after_az_has_exited() -> TestResult {
    cancel_login(&HangingAz::with_script(
        "#!/bin/sh\n\
echo $$ > \"$FAKE_AZ_RESPONSES/az.pid\"\n\
sleep 300 &\n\
echo $! > \"$FAKE_AZ_RESPONSES/child.pid\"\n",
    )?)
    .await
}

/// Starts `hanging` as a tree, and returns it once the script has started
/// its child, with every pid it recorded and its own.
async fn start(hanging: &HangingAz) -> Result<(ProcessTree, Vec<u32>), Box<dyn Error>> {
    let mut command = Command::new(hanging.program());
    command
        .env_clear()
        .envs(hanging.env())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut tree = ProcessTree::spawn(&mut command, killer())?;
    let mut pids = hanging.started().await?;
    pids.push(tree.child().id().ok_or("the script has already exited")?);
    Ok((tree, pids))
}

#[tokio::test]
async fn stopping_a_tree_ends_az_and_what_it_started_and_reaps_az() -> TestResult {
    let hanging = HangingAz::new()?;
    let (mut tree, pids) = start(&hanging).await?;
    tree.stop(Duration::from_millis(100)).await;
    assert_eq!(tree.child().id(), None, "az was not reaped");
    let running = HangingAz::still_running(&pids).await;
    assert!(
        running.is_empty(),
        "{running:?} of {pids:?} outlived the stop"
    );
    Ok(())
}

/// `az` that handles `SIGTERM` and keeps waiting, and a child that ignores
/// it.
#[cfg(unix)]
#[tokio::test]
async fn stopping_a_tree_sends_sigterm_then_sigkill_after_the_grace() -> TestResult {
    let hanging = HangingAz::with_script(
        "#!/bin/sh\n\
trap 'echo > \"$FAKE_AZ_RESPONSES/term\"' TERM\n\
(trap '' TERM; exec sleep 300) &\n\
echo $! > \"$FAKE_AZ_RESPONSES/child.pid\"\n\
wait\n\
wait\n",
    )?;
    let (mut tree, pids) = start(&hanging).await?;
    tree.stop(Duration::from_millis(500)).await;
    let running = HangingAz::still_running(&pids).await;
    assert!(
        running.is_empty(),
        "{running:?} of {pids:?} outlived the stop"
    );
    assert!(
        hanging.program().with_file_name("term").exists(),
        "az was not sent SIGTERM first"
    );
    Ok(())
}

/// `az` that ends on `SIGTERM`, and a child that ignores it: the group is
/// killed all the same.
#[cfg(unix)]
#[tokio::test]
async fn stopping_a_tree_kills_what_ignores_sigterm_after_az_has_ended() -> TestResult {
    let hanging = HangingAz::with_script(
        "#!/bin/sh\n\
(trap '' TERM; exec sleep 300) &\n\
echo $! > \"$FAKE_AZ_RESPONSES/child.pid\"\n\
wait\n",
    )?;
    let (mut tree, pids) = start(&hanging).await?;
    tree.stop(Duration::from_millis(500)).await;
    let running = HangingAz::still_running(&pids).await;
    assert!(
        running.is_empty(),
        "{running:?} of {pids:?} outlived the stop"
    );
    Ok(())
}
