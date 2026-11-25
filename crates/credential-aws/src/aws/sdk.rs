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

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::io;

    use aws_sdk_sts::config::http::HttpResponse;
    use aws_sdk_sts::error::{ConnectorError, ErrorMetadata, SdkError};
    use aws_sdk_sts::operation::get_caller_identity::GetCallerIdentityError;

    use super::classify;
    use crate::aws::{AwsError, AwsErrorKind, Service};

    type TestResult = Result<(), Box<dyn Error>>;
    type StsError = SdkError<GetCallerIdentityError>;

    /// What STS answering `status` with `code` and `message` reads as.
    fn answered(
        status: u16,
        code: &str,
        message: Option<&str>,
    ) -> Result<AwsError, Box<dyn Error>> {
        let mut metadata = ErrorMetadata::builder().code(code);
        if let Some(message) = message {
            metadata = metadata.message(message);
        }
        let error = StsError::service_error(
            GetCallerIdentityError::generic(metadata.build()),
            HttpResponse::new(status.try_into()?, "".into()),
        );
        Ok(classify(Service::Sts, &error))
    }

    fn dispatch(error: ConnectorError) -> AwsError {
        classify(Service::Sts, &StsError::dispatch_failure(error))
    }

    #[test]
    fn aws_error_codes_are_read_into_kinds() -> TestResult {
        for (status, code, kind) in [
            (403, "InvalidClientTokenId", AwsErrorKind::Refused),
            (403, "SignatureDoesNotMatch", AwsErrorKind::Refused),
            (403, "AccessDenied", AwsErrorKind::Refused),
            (400, "ExpiredToken", AwsErrorKind::Expired),
            (400, "RequestExpired", AwsErrorKind::Expired),
            (400, "Throttling", AwsErrorKind::Unavailable),
            (503, "ServiceUnavailable", AwsErrorKind::Unavailable),
            (400, "SomeNewError", AwsErrorKind::Unexpected),
        ] {
            assert_eq!(answered(status, code, None)?.kind, kind, "{status} {code}");
        }
        Ok(())
    }

    #[test]
    fn an_answered_error_shows_its_code_and_a_message_it_has() -> TestResult {
        let error = answered(
            403,
            "InvalidClientTokenId",
            Some("The security token included in the request is invalid."),
        )?;
        assert_eq!(
            error.to_string(),
            "STS: InvalidClientTokenId: The security token included in the request is invalid."
        );
        assert_eq!(
            answered(403, "AccessDenied", Some(""))?.detail,
            "AccessDenied"
        );
        assert_eq!(answered(403, "AccessDenied", None)?.detail, "AccessDenied");
        Ok(())
    }

    #[test]
    fn a_call_that_ran_out_of_time_timed_out() {
        let error = classify(Service::Iam, &StsError::timeout_error("operation timeout"));
        assert_eq!(
            (error.service, error.kind, error.detail.as_str()),
            (
                Service::Iam,
                AwsErrorKind::TimedOut,
                "no answer within 30 seconds"
            )
        );
        let error = dispatch(ConnectorError::timeout("connect timeout".into()));
        assert_eq!(error.kind, AwsErrorKind::TimedOut, "{error}");
    }

    /// The request never reached AWS: a TLS handshake that failed, or a
    /// connection that did. The detail names every cause.
    #[test]
    fn a_request_that_never_reached_aws_says_why() {
        let untrusted = io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid peer certificate: UnknownIssuer",
        );
        let error = dispatch(ConnectorError::io(Box::new(untrusted)));
        assert_eq!(error.kind, AwsErrorKind::Tls, "{error}");
        assert!(
            error
                .detail
                .ends_with(": invalid peer certificate: UnknownIssuer"),
            "{error}"
        );

        let refused = io::Error::new(io::ErrorKind::ConnectionRefused, "connection refused");
        let error = dispatch(ConnectorError::io(Box::new(refused)));
        assert_eq!(error.kind, AwsErrorKind::Network, "{error}");
        assert!(error.detail.starts_with("dispatch failure: "), "{error}");
        assert!(error.detail.ends_with(": connection refused"), "{error}");
    }

    #[test]
    fn an_answer_or_a_request_the_sdk_could_not_handle_is_unexpected() -> TestResult {
        let error = classify(
            Service::Sts,
            &StsError::response_error(
                "the answer is not XML",
                HttpResponse::new(200.try_into()?, "".into()),
            ),
        );
        assert_eq!(error.kind, AwsErrorKind::Unexpected);
        assert!(error.detail.ends_with(": the answer is not XML"), "{error}");
        let error = classify(Service::Sts, &StsError::construction_failure("no region"));
        assert_eq!(error.kind, AwsErrorKind::Unexpected);
        assert!(error.detail.ends_with(": no region"), "{error}");
        Ok(())
    }
}
