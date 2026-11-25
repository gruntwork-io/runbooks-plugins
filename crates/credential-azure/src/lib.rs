//! `runbooks-credential-azure`: the credential plugin for Runbooks'
//! `AzureAuth` block. It signs in through the Azure CLI (a person, or a
//! service principal with a secret or a certificate), lets the person
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
pub mod service_principal;
mod session;
mod state_dir;

use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;

pub use plugin::{AzurePlugin, Connect, Network};
use runbooks_plugin_transport::PluginError;

/// The `az` `main` found on `PATH`, if any, run with the host's environment.
#[derive(Clone)]
pub struct InstalledAz {
    program: Option<PathBuf>,
    env: Vec<(OsString, OsString)>,
}

/// The environment's names only: its values may hold the person's secrets.
impl fmt::Debug for InstalledAz {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InstalledAz")
            .field("program", &self.program)
            .field(
                "env",
                &self.env.iter().map(|(name, _)| name).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl InstalledAz {
    /// `program`, if `main` found one, run with `env`.
    #[must_use]
    pub const fn new(program: Option<PathBuf>, env: Vec<(OsString, OsString)>) -> Self {
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::InstalledAz;
    use crate::az::AzCli;

    /// Both name the environment's variables and never show their values.
    #[test]
    fn debug_shows_the_environments_names_but_not_its_values() {
        let program = Some(PathBuf::from("/usr/bin/az"));
        let env = vec![("ARM_CLIENT_SECRET".into(), "hunter2".into())];
        let shown = [
            format!("{:?}", InstalledAz::new(program.clone(), env.clone())),
            format!("{:?}", AzCli::new(program, env)),
        ];
        for (shown, name) in shown.iter().zip(["InstalledAz", "AzCli"]) {
            assert_eq!(
                *shown,
                format!(r#"{name} {{ program: Some("/usr/bin/az"), env: ["ARM_CLIENT_SECRET"] }}"#)
            );
        }
    }
}
