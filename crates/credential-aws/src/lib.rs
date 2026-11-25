//! The Runbooks credential plugin for AWS, behind the `AwsAuth` block.
//!
//! [`Aws`] is everything the plugin asks AWS; [`SdkAws`] asks it with the
//! AWS SDK for Rust.

mod aws;
mod identity;
mod region;
mod secret;

pub use aws::{Aws, AwsCredentials, AwsError, AwsErrorKind, CallerIdentity, SdkAws, Service};
pub use identity::{AccountId, InvalidAccountId};
pub use region::{InvalidRegion, Region};
pub use secret::Secret;
