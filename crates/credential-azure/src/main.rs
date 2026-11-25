//! Serves the Azure credential plugin on standard input and output.

use std::process::ExitCode;

use runbooks_credential_azure::host::Host;
use runbooks_credential_azure::{AzurePlugin, InstalledAz};
use runbooks_plugin_transport::serve_stdio;

fn main() -> ExitCode {
    let host = Host::new(std::env::vars_os(), cfg!(windows));
    let az = InstalledAz::new(host.find_program("az"), host.az_env());
    let plugin = AzurePlugin::new(host.local_login(), az);

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("runbooks-credential-azure: starting the async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    let served = runtime.block_on(serve_stdio(plugin));
    // Standard input's read runs on a blocking thread that cannot be
    // cancelled, so waiting for the runtime to stop could wait forever.
    runtime.shutdown_background();
    match served {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("runbooks-credential-azure: {error}");
            ExitCode::FAILURE
        }
    }
}
