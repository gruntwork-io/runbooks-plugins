//! `runbooks-credential-azure`: the credential plugin for Runbooks'
//! `AzureAuth` block. It signs in through the Azure CLI, lets the person
//! choose a tenant and subscription, checks required roles, and hands a run
//! the variables that `az`, `azurerm`, `azuread` and `azapi` read.
//!
//! `main` reads the process environment once into a [`host::Host`], finds
//! `az`, and serves [`AzurePlugin`] on standard input and output. Every
//! `az` call goes through [`az::Az`], so tests run the plugin without it.

pub mod az;
mod choose;
pub mod claims;
mod describe;
pub mod host;
pub mod ids;
mod params;
mod plugin;
mod roles;
mod session;
mod state_dir;

use std::ffi::OsString;
use std::path::PathBuf;

pub use plugin::{AzurePlugin, Connect, Network};
use runbooks_plugin_transport::PluginError;

/// The `az` `main` found on `PATH`, if any, run with the host's environment.
#[derive(Clone, Debug)]
pub struct InstalledAz {
    program: Option<PathBuf>,
    env: Vec<(OsString, OsString)>,
}

impl InstalledAz {
    pub fn new(program: Option<PathBuf>, env: Vec<(OsString, OsString)>) -> Self {
        Self { program, env }
    }
}

impl Connect for InstalledAz {
    type Az = az::AzCli;

    /// `az` reads its CA bundle and proxy from the variables Python's
    /// `requests` reads.
    fn connect(&self, network: &Network) -> Result<az::AzCli, PluginError> {
        let mut env = self.env.clone();
        if let Some(bundle) = &network.ca_bundle_file {
            env.push(("REQUESTS_CA_BUNDLE".into(), bundle.into()));
        }
        if let Some(proxy) = &network.proxy {
            env.push(("HTTPS_PROXY".into(), proxy.into()));
            env.push(("HTTP_PROXY".into(), proxy.into()));
        }
        Ok(az::AzCli::new(self.program.clone(), env))
    }
}
