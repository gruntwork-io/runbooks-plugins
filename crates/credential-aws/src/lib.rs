//! The Runbooks credential plugin for AWS, behind the `AwsAuth` block.
//!
//! - **Settings**: `defaultRegion`, the run's region when the credential
//!   and the sign-in's Default Region field name none (us-east-1 when
//!   unset). Any other setting is refused.
//! - **Network**: every AWS call trusts `caBundleFile`'s certificates
//!   beside the platform's roots and goes through `proxy`. Without a
//!   `proxy`, calls go direct: the environment's proxy variables are the
//!   app's to pass.
//! - **Detection** reads `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
//!   `AWS_SESSION_TOKEN`, `AWS_REGION` (then `AWS_DEFAULT_REGION`) and
//!   `AWS_CREDENTIAL_EXPIRATION` from the environment, under a prefix when
//!   the source has one, or the same names from an earlier block's outputs.
//! - **Sign-in methods**: `credentials`, an access key with its secret and an
//!   optional session token; `sso`, IAM Identity Center's device
//!   authorization, approved in the browser, then an account and a role;
//!   `profile`, a profile from the shared AWS files with static keys or a
//!   role to assume, found where `AWS_CONFIG_FILE`,
//!   `AWS_SHARED_CREDENTIALS_FILE` and `HOME` in the plugin's environment say.
//!   `configure` lists the profiles with keys or a role, sorted, as the
//!   field's choices; signing in with a profile it did not list is refused.
//! - Every credential is checked with STS `GetCallerIdentity`, in the home
//!   region of its region's partition, before it is used. Then Account
//!   `GetRegionOptStatus` says whether the account has enabled the run's
//!   region: if not, the identity warns. A check that fails warns of nothing.
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
mod profile;
mod region;
mod secret;
mod settings;
mod sso;
#[cfg(test)]
#[path = "../tests/support/tls.rs"]
mod test_tls;

pub use aws::{
    AssumeRole, Aws, AwsCredentials, AwsError, AwsErrorKind, CallerIdentity, DeviceAuthorization,
    Network, NetworkError, SdkAws, Service, SsoAccount, SsoToken, TokenPoll,
};
pub use detect::Environment;
pub use identity::{AccountId, InvalidAccountId};
pub use plugin::{AwsPlugin, Clock, Connect, SystemClock};
pub use region::{InvalidRegion, Region};
pub use secret::Secret;
