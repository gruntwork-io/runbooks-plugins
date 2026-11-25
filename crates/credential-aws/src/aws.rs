//! The AWS boundary: every call to an AWS service goes through [`Aws`], in
//! domain types. [`SdkAws`] is the real one, built on the AWS SDK for Rust;
//! tests fake the trait.

mod sdk;

use std::fmt;
use std::future::Future;

use time::OffsetDateTime;

use crate::identity::AccountId;
use crate::region::Region;
use crate::secret::Secret;

pub use sdk::SdkAws;

/// Keys that sign AWS requests.
#[derive(Clone, Debug)]
pub struct AwsCredentials {
    /// Not a secret: AWS shows it in logs and the console.
    pub access_key_id: String,
    pub secret_access_key: Secret,
    pub session_token: Option<Secret>,
    /// When temporary keys stop working. `None` for keys that don't expire,
    /// or whose expiry isn't known.
    pub expires_at: Option<OffsetDateTime>,
}

/// Who a set of keys belongs to, from STS GetCallerIdentity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallerIdentity {
    pub account: AccountId,
    pub arn: String,
    /// The account's IAM alias, when IAM lists one to these keys.
    pub alias: Option<String>,
}

/// The AWS calls the plugin makes. Every method sends the request to the
/// region it is given; choosing that region is the caller's decision.
pub trait Aws: Send + Sync + 'static {
    /// STS GetCallerIdentity, then IAM ListAccountAliases for the alias. A
    /// failure to read the alias is not an error: most roles may not list it.
    fn caller_identity(
        &self,
        credentials: &AwsCredentials,
        region: &Region,
    ) -> impl Future<Output = Result<CallerIdentity, AwsError>> + Send;
}

/// The AWS service a call went to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Service {
    Sts,
    Iam,
}

impl fmt::Display for Service {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Sts => "STS",
            Self::Iam => "IAM",
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
    /// AWS answered that it failed or is throttling. Trying again later may work.
    Unavailable,
    /// The request did not reach AWS, or no answer came back.
    Network,
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
    pub service: Service,
    pub kind: AwsErrorKind,
    pub detail: String,
}

impl AwsError {
    pub fn new(service: Service, kind: AwsErrorKind, detail: impl Into<String>) -> Self {
        Self {
            service,
            kind,
            detail: detail.into(),
        }
    }
}
