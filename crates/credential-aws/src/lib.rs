//! The Runbooks credential plugin for AWS, behind the `AwsAuth` block.
//!
//! - **Detection** reads `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
//!   `AWS_SESSION_TOKEN`, `AWS_REGION` (then `AWS_DEFAULT_REGION`) and
//!   `AWS_CREDENTIAL_EXPIRATION` from the environment, under a prefix when
//!   the source has one, or the same names from an earlier block's outputs.
//! - Every credential is checked with STS GetCallerIdentity, in the home
//!   region of its region's partition, before it is used.
//! - **Pins** are keyed by level: `account` (`ssoAccountId`) and `role`
//!   (`ssoRoleName`). A credential that does not match fails with
//!   `pinMismatch`.
//! - **A run gets** `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
//!   `AWS_SESSION_TOKEN` and `AWS_REGION`, as env and as outputs.
//!
//! [`AwsPlugin`] answers the protocol; [`Aws`] is everything it asks AWS.

mod aws;
mod detect;
mod error;
mod identity;
mod methods;
mod plugin;
mod region;
mod secret;

pub use aws::{Aws, AwsCredentials, AwsError, AwsErrorKind, CallerIdentity, SdkAws, Service};
pub use detect::Environment;
pub use identity::{AccountId, InvalidAccountId};
pub use plugin::{AwsPlugin, Clock, SystemClock};
pub use region::{InvalidRegion, Region};
pub use secret::Secret;
