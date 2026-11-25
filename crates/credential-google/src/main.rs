//! Serves the Google credential plugin on standard input and output.

use std::collections::HashMap;
use std::fmt::Display;
use std::io::{self, Write};
use std::process::ExitCode;

use runbooks_credential_google::{GooglePlugin, Host, HttpApi, RustlsCrypto};
use runbooks_plugin_transport::serve_stdio;
use time::OffsetDateTime;

/// An `Err` is a failure standard error could not take.
fn main() -> io::Result<ExitCode> {
    // The only read of the process environment. A variable that isn't UTF-8
    // can't be a Google credential.
    let env: HashMap<String, String> = std::env::vars_os()
        .filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?)))
        .collect();
    let host = Host {
        env,
        now: OffsetDateTime::now_utc,
    };
    let plugin = GooglePlugin::new(host, Box::new(HttpApi::new), RustlsCrypto);

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => return fail(format_args!("starting the runtime: {error}")),
    };
    let served = runtime.block_on(serve_stdio(plugin));
    // Standard input's read runs on a blocking thread that can't be
    // cancelled, so the process exits without waiting for it.
    runtime.shutdown_background();
    match served {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(error) => fail(error),
    }
}

/// Writes `error` to standard error.
fn fail(error: impl Display) -> io::Result<ExitCode> {
    writeln!(io::stderr().lock(), "runbooks-credential-google: {error}")?;
    Ok(ExitCode::FAILURE)
}
