//! Serves the Azure credential plugin on standard input and output.

use std::fmt::Display;
use std::io::{self, Write};
use std::process::ExitCode;

use runbooks_credential_azure::host::Host;
use runbooks_credential_azure::{AzurePlugin, InstalledAz};
use runbooks_plugin_transport::serve_stdio;

fn main() -> ExitCode {
    let host = Host::new(std::env::vars_os(), cfg!(windows));
    let az = InstalledAz::new(host.find_program("az"), host.az_env());
    let plugin = AzurePlugin::new(host, az);

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => return failed(format_args!("starting the async runtime: {error}")),
    };
    let served = runtime.block_on(serve_stdio(plugin));
    // Standard input's read runs on a blocking thread that cannot be
    // cancelled, so waiting for the runtime to stop could wait forever.
    runtime.shutdown_background();
    match served {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => failed(error),
    }
}

/// Writes why the plugin stopped to standard error, and fails.
fn failed(why: impl Display) -> ExitCode {
    match writeln!(io::stderr().lock(), "runbooks-credential-azure: {why}") {
        // When standard error cannot be written either, the exit code is
        // all that is left to say the plugin failed.
        Ok(()) | Err(_) => ExitCode::FAILURE,
    }
}
