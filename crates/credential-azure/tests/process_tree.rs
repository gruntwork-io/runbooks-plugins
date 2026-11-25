//! An `az` call that is cancelled ends `az` and every process it started,
//! on every OS CI runs.

#[path = "common/hanging_az.rs"]
mod hanging_az;

use std::error::Error;

use runbooks_credential_azure::az::{Az, AzCli, AzDir, Interactive};
use runbooks_credential_azure::host::Host;
use runbooks_credential_azure::process_tree::Killer;
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
