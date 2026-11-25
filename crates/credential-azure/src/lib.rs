//! `runbooks-credential-azure`: the credential plugin for Runbooks'
//! AzureAuth block.
//!
//! Every `az` call goes through [`az::Az`]; [`az::AzCli`] is the one place
//! that runs the Azure CLI. [`host::Host`] is the process environment, read
//! once, and finds `az` on it.

pub mod az;
pub mod claims;
pub mod host;
pub mod ids;
