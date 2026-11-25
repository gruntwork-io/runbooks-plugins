//! The AWS boundary: every call to an AWS service goes through [`Aws`], in
//! domain types. [`SdkAws`] is the real one, built on the AWS SDK for Rust;
//! tests fake the trait.

mod profile_file;
mod sdk;

use std::fmt;
use std::future::Future;
use std::time::Duration;

use time::OffsetDateTime;

use crate::identity::AccountId;
use crate::region::Region;
use crate::secret::Secret;

pub use profile_file::{PROFILE_FILE_VARIABLES, ProfileSettings, Profiles, read_profiles};
pub use sdk::SdkAws;

/// Keys that sign AWS requests.
#[derive(Clone, Debug)]
pub struct AwsCredentials {
    /// Not a secret: AWS shows it in logs and the console.
    pub access_key_id: String,
    /// The key that signs each request.
    pub secret_access_key: Secret,
    /// The token temporary keys come with. `None` for long-term keys.
    pub session_token: Option<Secret>,
    /// When temporary keys stop working. `None` for keys that don't expire,
    /// or whose expiry isn't known.
    pub expires_at: Option<OffsetDateTime>,
}

/// Who a set of keys belongs to, from STS `GetCallerIdentity`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallerIdentity {
    /// The account the keys belong to.
    pub account: AccountId,
    /// The ARN of the user or role the keys belong to.
    pub arn: String,
    /// The account's IAM alias, when IAM lists one to these keys.
    pub alias: Option<String>,
}

/// An STS AssumeRole request, as a profile's `role_arn` and its settings make it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssumeRole {
    pub role_arn: String,
    pub session_name: String,
    pub external_id: Option<String>,
    /// AWS's default, an hour, when `None`.
    pub duration: Option<Duration>,
}

/// An IAM Identity Center device authorization the person has yet to approve.
#[derive(Clone, Debug)]
pub struct DeviceAuthorization {
    /// The client SSO-OIDC `RegisterClient` registered.
    pub client_id: String,
    /// That client's secret.
    pub client_secret: Secret,
    /// Whoever holds it gets the token once the person approves.
    pub device_code: Secret,
    /// What the person checks in the browser. Not a secret: it is shown.
    pub user_code: String,
    /// The page to approve on, with the code filled in when AWS gives one.
    pub verification_url: String,
    /// How long the person has to approve.
    pub expires_in: Duration,
    /// How long to wait between polls.
    pub interval: Duration,
}

/// One poll of a device authorization.
#[derive(Clone, Debug)]
pub enum TokenPoll {
    /// Not approved yet.
    Pending,
    /// Not approved yet, and polling too often.
    SlowDown,
    /// Approved: the token it gave.
    Approved(SsoToken),
}

/// An IAM Identity Center access token: it lists accounts and roles and gets
/// a role's keys.
#[derive(Clone, Debug)]
pub struct SsoToken {
    /// What each SSO call sends.
    pub access_token: Secret,
    /// How long it lasts from when AWS issued it, if AWS says.
    pub expires_in: Option<Duration>,
}

/// An account IAM Identity Center gives the person.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SsoAccount {
    /// The account's id.
    pub id: AccountId,
    /// The account's name in AWS Organizations, else its id.
    pub name: String,
}

/// The AWS calls the plugin makes.
///
/// Every method sends the request to the region it is given; choosing that
/// region is the caller's decision. The IAM Identity Center calls go to the
/// region it runs in, where the device authorization was started.
pub trait Aws: Send + Sync + 'static {
    /// STS `GetCallerIdentity`, then IAM `ListAccountAliases` for the alias. A
    /// failure to read the alias is not an error: most roles may not list it.
    fn caller_identity(
        &self,
        credentials: &AwsCredentials,
        region: &Region,
    ) -> impl Future<Output = Result<CallerIdentity, AwsError>> + Send;

    /// STS AssumeRole, signed with `credentials`: the role's temporary keys.
    fn assume_role(
        &self,
        credentials: &AwsCredentials,
        request: &AssumeRole,
        region: &Region,
    ) -> impl Future<Output = Result<AwsCredentials, AwsError>> + Send;

    /// SSO-OIDC `RegisterClient`, then `StartDeviceAuthorization` for the access
    /// portal at `start_url`.
    fn start_device_authorization(
        &self,
        start_url: &str,
        region: &Region,
    ) -> impl Future<Output = Result<DeviceAuthorization, AwsError>> + Send;

    /// SSO-OIDC `CreateToken`: whether the person has approved yet.
    fn create_token(
        &self,
        device: &DeviceAuthorization,
        region: &Region,
    ) -> impl Future<Output = Result<TokenPoll, AwsError>> + Send;

    /// SSO `ListAccounts`, every page.
    fn sso_accounts(
        &self,
        token: &SsoToken,
        region: &Region,
    ) -> impl Future<Output = Result<Vec<SsoAccount>, AwsError>> + Send;

    /// SSO `ListAccountRoles`, every page: the role names.
    fn sso_roles(
        &self,
        token: &SsoToken,
        account: &AccountId,
        region: &Region,
    ) -> impl Future<Output = Result<Vec<String>, AwsError>> + Send;

    /// SSO `GetRoleCredentials`: temporary keys for `role` in `account`.
    fn role_credentials(
        &self,
        token: &SsoToken,
        account: &AccountId,
        role: &str,
        region: &Region,
    ) -> impl Future<Output = Result<AwsCredentials, AwsError>> + Send;
}

/// The AWS service a call went to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Service {
    /// AWS Security Token Service.
    Sts,
    /// AWS Identity and Access Management.
    Iam,
    /// IAM Identity Center's sign-in: SSO-OIDC.
    SsoOidc,
    /// IAM Identity Center's accounts, roles and role keys: SSO.
    Sso,
}

impl fmt::Display for Service {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Sts => "STS",
            Self::Iam => "IAM",
            Self::SsoOidc => "SSO OIDC",
            Self::Sso => "SSO",
        })
    }
}

/// Why an AWS call failed, as the plugin acts on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AwsErrorKind {
    /// AWS refused the keys or the token: unknown key, bad signature, access denied.
    Refused,
    /// The keys or the token have expired.
    Expired,
    /// AWS has no such thing for these keys or this token: an account or a
    /// role IAM Identity Center does not give the person.
    NotFound,
    /// AWS answered that it failed or is throttling. Trying again later may work.
    Unavailable,
    /// The request did not reach AWS, or no answer came back.
    Network,
    /// The call did not finish within its time limit.
    TimedOut,
    /// The TLS handshake failed: often a proxy that inspects TLS, with a CA
    /// the plugin does not trust.
    Tls,
    /// AWS answered in a way the plugin does not handle.
    Unexpected,
}

/// A failed AWS call. `detail` is AWS's error code and message, or what went
/// wrong on the way. It never holds a request, so never a key or a token.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{service}: {detail}")]
pub struct AwsError {
    /// The service the call went to.
    pub service: Service,
    /// Why the call failed.
    pub kind: AwsErrorKind,
    /// For a person to read.
    pub detail: String,
}

impl AwsError {
    /// A failed call to `service`.
    pub fn new(service: Service, kind: AwsErrorKind, detail: impl Into<String>) -> Self {
        Self {
            service,
            kind,
            detail: detail.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AwsError, AwsErrorKind, Service};

    #[test]
    fn an_error_names_its_service() {
        assert_eq!(
            AwsError::new(Service::Iam, AwsErrorKind::Refused, "AccessDenied").to_string(),
            "IAM: AccessDenied"
        );
        assert_eq!(Service::Sts.to_string(), "STS");
    }
}
