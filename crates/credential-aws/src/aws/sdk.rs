//! [`Aws`] on the AWS SDK for Rust. The only module that names an SDK type.

use std::error::Error as StdError;
use std::io;
use std::time::{Duration, SystemTime};

use aws_sdk_sts::config::timeout::TimeoutConfig;
use aws_sdk_sts::config::{BehaviorVersion, Credentials, Region as SdkRegion};
use aws_sdk_sts::error::{ProvideErrorMetadata, SdkError};

use super::{Aws, AwsCredentials, AwsError, AwsErrorKind, CallerIdentity, Service};
use crate::identity::AccountId;
use crate::region::Region;

/// The longest one AWS call may take, the SDK's retries included.
const CALL_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The name the SDK gives the keys the plugin hands it.
const PROVIDER_NAME: &str = "runbooks";

/// Calls AWS with the SDK's default HTTPS client: rustls, the platform's
/// trusted roots, and `HTTPS_PROXY` / `NO_PROXY` from the environment.
#[derive(Debug, Default)]
pub struct SdkAws;

impl SdkAws {
    /// Holds nothing: each call builds its SDK client from its keys and region.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Aws for SdkAws {
    async fn caller_identity(
        &self,
        credentials: &AwsCredentials,
        region: &Region,
    ) -> Result<CallerIdentity, AwsError> {
        let sts = aws_sdk_sts::Client::from_conf(
            aws_sdk_sts::Config::builder()
                .behavior_version(BehaviorVersion::latest())
                .region(sdk_region(region))
                .credentials_provider(sdk_credentials(credentials))
                .timeout_config(timeouts())
                .build(),
        );
        let answer = sts
            .get_caller_identity()
            .send()
            .await
            .map_err(|error| classify(Service::Sts, &error))?;
        let unexpected = |what: &str| {
            AwsError::new(
                Service::Sts,
                AwsErrorKind::Unexpected,
                format!("GetCallerIdentity answered without {what}"),
            )
        };
        let arn = answer.arn().ok_or_else(|| unexpected("an Arn"))?;
        let account = answer
            .account()
            .and_then(|account| AccountId::parse(account).ok())
            .ok_or_else(|| unexpected("a 12-digit Account"))?;

        let iam = aws_sdk_iam::Client::from_conf(
            aws_sdk_iam::Config::builder()
                .behavior_version(BehaviorVersion::latest())
                .region(sdk_region(region))
                .credentials_provider(sdk_credentials(credentials))
                .timeout_config(timeouts())
                .build(),
        );
        // The alias only names the account on the identity card. Keys that
        // may not call iam:ListAccountAliases still sign in.
        let alias = iam
            .list_account_aliases()
            .send()
            .await
            .ok()
            .and_then(|aliases| aliases.account_aliases().first().cloned());

        Ok(CallerIdentity {
            account,
            arn: arn.to_owned(),
            alias,
        })
    }
}

fn sdk_region(region: &Region) -> SdkRegion {
    SdkRegion::new(region.as_str().to_owned())
}

fn sdk_credentials(credentials: &AwsCredentials) -> Credentials {
    Credentials::new(
        credentials.access_key_id.clone(),
        credentials.secret_access_key.expose().to_owned(),
        credentials
            .session_token
            .as_ref()
            .map(|token| token.expose().to_owned()),
        credentials.expires_at.map(SystemTime::from),
        PROVIDER_NAME,
    )
}

fn timeouts() -> TimeoutConfig {
    TimeoutConfig::builder()
        .operation_timeout(CALL_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        .build()
}

/// Reads an SDK error into the kind the plugin acts on. AWS's error codes are
/// an open set: one this does not name is `Unavailable` for a 5xx answer and
/// `Unexpected` otherwise.
fn classify<E>(service: Service, error: &SdkError<E>) -> AwsError
where
    E: ProvideErrorMetadata + StdError + 'static,
{
    let (kind, detail) = match error {
        SdkError::ServiceError(_) => {
            let code = error.code().unwrap_or("an unnamed error");
            let server_error = error
                .raw_response()
                .is_some_and(|response| response.status().is_server_error());
            let detail = match error.message() {
                Some(message) if !message.is_empty() => format!("{code}: {message}"),
                _ => code.to_owned(),
            };
            (kind_of_code(code, server_error), detail)
        }
        SdkError::TimeoutError(_) => (
            AwsErrorKind::TimedOut,
            format!("no answer within {} seconds", CALL_TIMEOUT.as_secs()),
        ),
        SdkError::DispatchFailure(failure) if failure.is_timeout() => {
            (AwsErrorKind::TimedOut, chain(error))
        }
        SdkError::DispatchFailure(_) if is_tls_failure(error) => (AwsErrorKind::Tls, chain(error)),
        SdkError::DispatchFailure(_) => (AwsErrorKind::Network, chain(error)),
        SdkError::ResponseError(_) | SdkError::ConstructionFailure(_) => {
            (AwsErrorKind::Unexpected, chain(error))
        }
        // SdkError is #[non_exhaustive]: a variant added after this was
        // written. What its text holds is unvetted and may be AWS's answer,
        // so say only that the SDK failed.
        _ => (
            AwsErrorKind::Unexpected,
            "the AWS SDK failed in a way this plugin does not know".to_owned(),
        ),
    };
    AwsError::new(service, kind, detail)
}

fn kind_of_code(code: &str, server_error: bool) -> AwsErrorKind {
    match code {
        "InvalidClientTokenId"
        | "SignatureDoesNotMatch"
        | "IncompleteSignature"
        | "AccessDenied"
        | "AccessDeniedException"
        | "UnrecognizedClientException" => AwsErrorKind::Refused,
        "ExpiredToken" | "ExpiredTokenException" | "RequestExpired" => AwsErrorKind::Expired,
        "Throttling" | "ThrottlingException" | "TooManyRequestsException" => {
            AwsErrorKind::Unavailable
        }
        _ if server_error => AwsErrorKind::Unavailable,
        _ => AwsErrorKind::Unexpected,
    }
}

/// rustls reports a failed handshake, an untrusted certificate among them,
/// as an `io::Error` of kind `InvalidData` somewhere in the error's sources.
fn is_tls_failure(error: &(dyn StdError + 'static)) -> bool {
    let mut next = Some(error);
    while let Some(current) = next {
        if current
            .downcast_ref::<io::Error>()
            .is_some_and(|io| io.kind() == io::ErrorKind::InvalidData)
        {
            return true;
        }
        next = current.source();
    }
    false
}

/// The error and each of its sources, joined. The SDK's own `Display` names
/// only the outermost ("dispatch failure").
fn chain(error: &(dyn StdError + 'static)) -> String {
    let mut text = error.to_string();
    let mut next = error.source();
    while let Some(current) = next {
        text.push_str(": ");
        text.push_str(&current.to_string());
        next = current.source();
    }
    text
}
