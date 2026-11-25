//! `runbooks-credential-azure`: the credential plugin for Runbooks'
//! AzureAuth block.
//!
//! [`host::Host`] is the process environment, read once. [`ids`] and
//! [`claims`] are the Azure values the plugin checks before it uses them.

pub mod claims;
pub mod host;
pub mod ids;
