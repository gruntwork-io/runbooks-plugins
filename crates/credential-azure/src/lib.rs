//! `runbooks-credential-azure`: the credential plugin for Runbooks'
//! `AzureAuth` block.
//!
//! Every `az` call goes through [`az::Az`]; [`az::AzCli`] is the one place
//! that runs the Azure CLI. [`host::Host`] is the process environment, read
//! once, and finds `az` on it.
//!
//! [`choose`] applies a block's pins to what a sign-in can see, [`roles`]
//! words its role requirements, and [`state_dir`] keeps each sign-in's
//! `az` config directory under the block's state directory.

pub mod az;
pub mod choose;
pub mod claims;
pub mod host;
pub mod ids;
pub mod roles;
pub mod state_dir;
