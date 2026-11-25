//! `runbooks-credential-aws`: the AWS credential plugin, speaking the Runbooks
//! credential protocol on standard input and output.

use std::collections::HashMap;
use std::process::ExitCode;

use runbooks_credential_aws::{AwsPlugin, Environment, SdkAws, SystemClock};
use runbooks_plugin_transport::serve_stdio;

fn main() -> ExitCode {
    // The only read of the process environment. Variables that are not
    // UTF-8 cannot hold anything the plugin reads.
    let env: HashMap<String, String> = std::env::vars_os()
        .filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?)))
        .collect();
    let plugin = AwsPlugin::new(SdkAws::new(), SystemClock, Environment::new(env));

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("runbooks-credential-aws: starting the async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    let served = runtime.block_on(serve_stdio(plugin));
    // Standard input's blocking read cannot be cancelled, so waiting for the
    // runtime to shut down could hang: let the process exit take it.
    runtime.shutdown_background();
    match served {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("runbooks-credential-aws: {error}");
            ExitCode::FAILURE
        }
    }
}
