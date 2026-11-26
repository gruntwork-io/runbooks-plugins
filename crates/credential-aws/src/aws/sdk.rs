//! [`Aws`] on the AWS SDK for Rust. The only module that names an SDK type.

use std::error::Error as StdError;
use std::fmt;
use std::io;
use std::time::{Duration, SystemTime};

use aws_sdk_account::types::RegionOptStatus;
use aws_sdk_ssooidc::operation::create_token::CreateTokenError;
use aws_sdk_sts::config::timeout::TimeoutConfig;
use aws_sdk_sts::config::{BehaviorVersion, Credentials, Region as SdkRegion};
use aws_sdk_sts::error::{ProvideErrorMetadata, SdkError};
use aws_smithy_http_client::proxy::ProxyConfig;
use aws_smithy_http_client::tls::rustls_provider::CryptoMode;
use aws_smithy_http_client::tls::{self, TlsContext, TrustStore};
use aws_smithy_http_client::{Builder, ConnectorBuilder};
use aws_types::SdkConfig;
use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use time::OffsetDateTime;

use super::{
    AssumeRole, Aws, AwsCredentials, AwsError, AwsErrorKind, CallerIdentity, DeviceAuthorization,
    Network, NetworkError, Service, SsoAccount, SsoToken, TokenPoll,
};
use crate::identity::AccountId;
use crate::region::Region;
use crate::secret::Secret;

/// The longest one AWS call may take, the SDK's retries included.
const CALL_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The name the SDK gives the keys the plugin hands it.
const PROVIDER_NAME: &str = "runbooks";

/// What IAM Identity Center shows the person for the device authorization,
/// as Runbooks main registered it.
const CLIENT_NAME: &str = "gruntwork-runbooks";
const CLIENT_TYPE: &str = "public";
const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// RFC 8628's defaults, for an answer that gives no expiry or interval.
const DEFAULT_EXPIRES_IN: Duration = Duration::from_secs(600);
const DEFAULT_INTERVAL: Duration = Duration::from_secs(5);

/// A guard against a listing that never ends: far more accounts or roles
/// than anyone is given.
const MAX_PAGES: usize = 1000;

/// Calls AWS with the SDK's HTTPS client, built for the [`Network`].
///
/// That is rustls with aws-lc-rs, trusting the platform's roots and the
/// network's CA bundle, through the network's proxy or none. The
/// environment's proxy variables are the app's to pass as `proxy`.
#[derive(Clone)]
pub struct SdkAws {
    /// Where the IAM Identity Center and Account calls go in place of AWS's
    /// endpoint for their region. Only this module's tests set one: a
    /// loopback server.
    endpoint: Option<String>,
    /// The most pages a listing may take: [`MAX_PAGES`], or fewer in this
    /// module's tests.
    max_pages: usize,
    /// What every client is built from: the HTTPS client, the timeouts and
    /// the SDK's behaviour version.
    shared: SdkConfig,
}

impl fmt::Debug for SdkAws {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SdkAws")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

impl SdkAws {
    /// Calls AWS's own endpoints through `network`: each call builds its SDK
    /// client from its keys and region.
    ///
    /// # Errors
    ///
    /// [`NetworkError`] for a CA bundle without a certificate or with one
    /// that does not parse, or a proxy that is not an http or https URL.
    pub fn new(network: &Network) -> Result<Self, NetworkError> {
        let mut roots = TrustStore::default();
        if let Some(pem) = &network.ca_bundle {
            check_bundle(pem)?;
            roots = roots.with_pem_certificate(pem.clone());
        }
        let tls_context = TlsContext::builder()
            .with_trust_store(roots)
            .build()
            .map_err(|_unusable| NetworkError::BadCertificate)?;
        let proxy = match &network.proxy {
            Some(url) => ProxyConfig::all(url.as_str()).map_err(|_invalid| NetworkError::Proxy)?,
            None => ProxyConfig::disabled(),
        };
        // As the SDK builds its default client, with this trust and proxy.
        let http = Builder::new().build_with_connector_fn(move |settings, components| {
            let mut connector = ConnectorBuilder::default()
                .tls_provider(tls::Provider::Rustls(CryptoMode::AwsLc))
                .tls_context(tls_context.clone())
                .proxy_config(proxy.clone());
            connector.set_connector_settings(settings.cloned());
            if let Some(components) = components {
                connector.set_sleep_impl(components.sleep_impl());
            }
            connector.build()
        });
        Ok(Self {
            endpoint: None,
            max_pages: MAX_PAGES,
            shared: SdkConfig::builder()
                .behavior_version(BehaviorVersion::latest())
                .timeout_config(timeouts())
                .http_client(http)
                .build(),
        })
    }

    fn oidc_client(&self, region: &Region) -> aws_sdk_ssooidc::Client {
        let mut config =
            aws_sdk_ssooidc::config::Builder::from(&self.shared).region(sdk_region(region));
        config.set_endpoint_url(self.endpoint.clone());
        aws_sdk_ssooidc::Client::from_conf(config.build())
    }

    fn sso_client(&self, region: &Region) -> aws_sdk_sso::Client {
        let mut config =
            aws_sdk_sso::config::Builder::from(&self.shared).region(sdk_region(region));
        config.set_endpoint_url(self.endpoint.clone());
        aws_sdk_sso::Client::from_conf(config.build())
    }

    fn sts_client(&self, credentials: &AwsCredentials, region: &Region) -> aws_sdk_sts::Client {
        aws_sdk_sts::Client::from_conf(
            aws_sdk_sts::config::Builder::from(&self.shared)
                .region(sdk_region(region))
                .credentials_provider(sdk_credentials(credentials))
                .build(),
        )
    }
}

/// Checks `pem` as the HTTPS client reads it, since a PEM block that does
/// not parse, or a certificate rustls refuses, would panic there.
fn check_bundle(pem: &[u8]) -> Result<(), NetworkError> {
    let certificates = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_unreadable| NetworkError::BadCertificate)?;
    if certificates.is_empty() {
        return Err(NetworkError::NoCertificate);
    }
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots
            .add(certificate)
            .map_err(|_refused| NetworkError::BadCertificate)?;
    }
    Ok(())
}

impl Aws for SdkAws {
    async fn caller_identity(
        &self,
        credentials: &AwsCredentials,
        region: &Region,
    ) -> Result<CallerIdentity, AwsError> {
        let sts = self.sts_client(credentials, region);
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
            aws_sdk_iam::config::Builder::from(&self.shared)
                .region(sdk_region(region))
                .credentials_provider(sdk_credentials(credentials))
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

    async fn assume_role(
        &self,
        credentials: &AwsCredentials,
        request: &AssumeRole,
        region: &Region,
    ) -> Result<AwsCredentials, AwsError> {
        let sts = self.sts_client(credentials, region);
        let duration = request
            .duration
            .map(|duration| i32::try_from(duration.as_secs()).unwrap_or(i32::MAX));
        let answer = sts
            .assume_role()
            .role_arn(&request.role_arn)
            .role_session_name(&request.session_name)
            .set_external_id(request.external_id.clone())
            .set_duration_seconds(duration)
            .send()
            .await
            .map_err(|error| classify(Service::Sts, &error))?;
        let keys = answer.credentials().ok_or_else(|| {
            AwsError::new(
                Service::Sts,
                AwsErrorKind::Unexpected,
                "AssumeRole answered without Credentials",
            )
        })?;
        let expiration = keys.expiration();
        Ok(AwsCredentials {
            access_key_id: keys.access_key_id().to_owned(),
            secret_access_key: Secret::new(keys.secret_access_key()),
            session_token: Some(Secret::new(keys.session_token())),
            expires_at: OffsetDateTime::from_unix_timestamp(expiration.secs()).ok(),
        })
    }

    async fn start_device_authorization(
        &self,
        start_url: &str,
        region: &Region,
    ) -> Result<DeviceAuthorization, AwsError> {
        let oidc = self.oidc_client(region);
        let client = oidc
            .register_client()
            .client_name(CLIENT_NAME)
            .client_type(CLIENT_TYPE)
            .send()
            .await
            .map_err(|error| classify(Service::SsoOidc, &error))?;
        let missing = |operation: &str, what: &str| {
            AwsError::new(
                Service::SsoOidc,
                AwsErrorKind::Unexpected,
                format!("{operation} answered without {what}"),
            )
        };
        let client_id = client
            .client_id()
            .ok_or_else(|| missing("RegisterClient", "a clientId"))?;
        let client_secret = client
            .client_secret()
            .ok_or_else(|| missing("RegisterClient", "a clientSecret"))?;
        let device = oidc
            .start_device_authorization()
            .client_id(client_id)
            .client_secret(client_secret)
            .start_url(start_url)
            .send()
            .await
            .map_err(|error| classify(Service::SsoOidc, &error))?;
        let verification_url = device
            .verification_uri_complete()
            .or_else(|| device.verification_uri())
            .ok_or_else(|| missing("StartDeviceAuthorization", "a verificationUri"))?;
        Ok(DeviceAuthorization {
            client_id: client_id.to_owned(),
            client_secret: Secret::new(client_secret),
            device_code: Secret::new(
                device
                    .device_code()
                    .ok_or_else(|| missing("StartDeviceAuthorization", "a deviceCode"))?,
            ),
            user_code: device
                .user_code()
                .ok_or_else(|| missing("StartDeviceAuthorization", "a userCode"))?
                .to_owned(),
            verification_url: verification_url.to_owned(),
            expires_in: seconds(device.expires_in()).unwrap_or(DEFAULT_EXPIRES_IN),
            interval: seconds(device.interval()).unwrap_or(DEFAULT_INTERVAL),
        })
    }

    async fn create_token(
        &self,
        device: &DeviceAuthorization,
        region: &Region,
    ) -> Result<TokenPoll, AwsError> {
        let answer = self
            .oidc_client(region)
            .create_token()
            .client_id(&device.client_id)
            .client_secret(device.client_secret.expose())
            .grant_type(DEVICE_CODE_GRANT)
            .device_code(device.device_code.expose())
            .send()
            .await;
        let token = match answer {
            Ok(token) => token,
            Err(error) => {
                let service_error = error.as_service_error();
                if service_error.is_some_and(CreateTokenError::is_authorization_pending_exception) {
                    return Ok(TokenPoll::Pending);
                }
                if service_error.is_some_and(CreateTokenError::is_slow_down_exception) {
                    return Ok(TokenPoll::SlowDown);
                }
                return Err(classify(Service::SsoOidc, &error));
            }
        };
        let access_token = token.access_token().ok_or_else(|| {
            AwsError::new(
                Service::SsoOidc,
                AwsErrorKind::Unexpected,
                "CreateToken answered without an accessToken",
            )
        })?;
        Ok(TokenPoll::Approved(SsoToken {
            access_token: Secret::new(access_token),
            expires_in: seconds(token.expires_in()),
        }))
    }

    async fn sso_accounts(
        &self,
        token: &SsoToken,
        region: &Region,
    ) -> Result<Vec<SsoAccount>, AwsError> {
        let sso = self.sso_client(region);
        let mut accounts = Vec::new();
        let mut next_token = None;
        for _page in 0..self.max_pages {
            let page = sso
                .list_accounts()
                .access_token(token.access_token.expose())
                .set_next_token(next_token)
                .send()
                .await
                .map_err(|error| classify(Service::Sso, &error))?;
            accounts.extend(page.account_list().iter().filter_map(|account| {
                let id = AccountId::parse(account.account_id()?).ok()?;
                let name = account
                    .account_name()
                    .filter(|name| !name.is_empty())
                    .map_or_else(|| id.to_string(), str::to_owned);
                Some(SsoAccount { id, name })
            }));
            next_token = page.next_token().map(str::to_owned);
            if next_token.is_none() {
                return Ok(accounts);
            }
        }
        Err(too_many_pages("ListAccounts", self.max_pages))
    }

    async fn sso_roles(
        &self,
        token: &SsoToken,
        account: &AccountId,
        region: &Region,
    ) -> Result<Vec<String>, AwsError> {
        let sso = self.sso_client(region);
        let mut roles = Vec::new();
        let mut next_token = None;
        for _page in 0..self.max_pages {
            let page = sso
                .list_account_roles()
                .access_token(token.access_token.expose())
                .account_id(account.as_str())
                .set_next_token(next_token)
                .send()
                .await
                .map_err(|error| classify(Service::Sso, &error))?;
            roles.extend(
                page.role_list()
                    .iter()
                    .filter_map(|role| role.role_name())
                    .filter(|name| !name.is_empty())
                    .map(str::to_owned),
            );
            next_token = page.next_token().map(str::to_owned);
            if next_token.is_none() {
                return Ok(roles);
            }
        }
        Err(too_many_pages("ListAccountRoles", self.max_pages))
    }

    async fn role_credentials(
        &self,
        token: &SsoToken,
        account: &AccountId,
        role: &str,
        region: &Region,
    ) -> Result<AwsCredentials, AwsError> {
        let answer = self
            .sso_client(region)
            .get_role_credentials()
            .access_token(token.access_token.expose())
            .account_id(account.as_str())
            .role_name(role)
            .send()
            .await
            .map_err(|error| classify(Service::Sso, &error))?;
        let missing = |what: &str| {
            AwsError::new(
                Service::Sso,
                AwsErrorKind::Unexpected,
                format!("GetRoleCredentials answered without {what}"),
            )
        };
        let keys = answer
            .role_credentials()
            .ok_or_else(|| missing("roleCredentials"))?;
        Ok(AwsCredentials {
            access_key_id: keys
                .access_key_id()
                .ok_or_else(|| missing("an accessKeyId"))?
                .to_owned(),
            secret_access_key: Secret::new(
                keys.secret_access_key()
                    .ok_or_else(|| missing("a secretAccessKey"))?,
            ),
            session_token: keys.session_token().map(Secret::new),
            // Milliseconds since the epoch; 0 when AWS gives none.
            expires_at: (keys.expiration() > 0)
                .then(|| {
                    OffsetDateTime::from_unix_timestamp_nanos(
                        i128::from(keys.expiration()) * 1_000_000,
                    )
                    .ok()
                })
                .flatten(),
        })
    }

    async fn region_enabled(
        &self,
        credentials: &AwsCredentials,
        target: &Region,
        region: &Region,
    ) -> Result<bool, AwsError> {
        let mut config = aws_sdk_account::config::Builder::from(&self.shared)
            .region(sdk_region(region))
            .credentials_provider(sdk_credentials(credentials));
        config.set_endpoint_url(self.endpoint.clone());
        let answer = aws_sdk_account::Client::from_conf(config.build())
            .get_region_opt_status()
            .region_name(target.as_str())
            .send()
            .await
            .map_err(|error| classify(Service::Account, &error))?;
        let status = answer.region_opt_status().ok_or_else(|| {
            AwsError::new(
                Service::Account,
                AwsErrorKind::Unexpected,
                "GetRegionOptStatus answered without a RegionOptStatus",
            )
        })?;
        Ok(matches!(
            status,
            RegionOptStatus::Enabled | RegionOptStatus::EnabledByDefault
        ))
    }
}

/// A positive count of seconds, as SSO-OIDC gives lifetimes and intervals.
fn seconds(value: i32) -> Option<Duration> {
    u64::try_from(value)
        .ok()
        .filter(|seconds| *seconds > 0)
        .map(Duration::from_secs)
}

fn too_many_pages(operation: &str, max_pages: usize) -> AwsError {
    AwsError::new(
        Service::Sso,
        AwsErrorKind::Unexpected,
        format!("{operation} kept paging past {max_pages} pages"),
    )
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
        // The answer may hold keys or a token: say only that it was unreadable.
        SdkError::ResponseError(_) => (
            AwsErrorKind::Unexpected,
            "AWS's answer could not be read".to_owned(),
        ),
        SdkError::ConstructionFailure(_) => (AwsErrorKind::Unexpected, chain(error)),
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
        | "UnrecognizedClientException"
        | "ForbiddenException" => AwsErrorKind::Refused,
        // SSO answers UnauthorizedException for an access token that has
        // expired or been revoked.
        "ExpiredToken" | "ExpiredTokenException" | "RequestExpired" | "UnauthorizedException" => {
            AwsErrorKind::Expired
        }
        "ResourceNotFoundException" => AwsErrorKind::NotFound,
        "Throttling" | "ThrottlingException" | "TooManyRequestsException" => {
            AwsErrorKind::Unavailable
        }
        _ if server_error => AwsErrorKind::Unavailable,
        _ => AwsErrorKind::Unexpected,
    }
}

/// rustls reports a failed handshake, an untrusted certificate among them,
/// as an `io::Error` of kind `InvalidData`, which hyper-rustls wraps in
/// another `io::Error`. An `io::Error`'s `source` skips its payload, so the
/// payload is looked at instead.
fn is_tls_failure(error: &(dyn StdError + 'static)) -> bool {
    let mut next = Some(error);
    while let Some(current) = next {
        next = match current.downcast_ref::<io::Error>() {
            Some(io) if io.kind() == io::ErrorKind::InvalidData => return true,
            Some(io) => io
                .get_ref()
                .map_or_else(|| current.source(), |payload| Some(payload)),
            None => current.source(),
        };
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
    use std::io::{self, BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex, OnceLock, PoisonError};
    use std::thread;
    use std::time::Duration;

    use aws_sdk_sso::operation::get_role_credentials::GetRoleCredentialsError;
    use aws_sdk_sts::config::http::HttpResponse;
    use aws_sdk_sts::error::{ConnectorError, ErrorMetadata, SdkError};
    use aws_sdk_sts::operation::get_caller_identity::GetCallerIdentityError;
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::{ServerConfig, ServerConnection, StreamOwned};
    use time::OffsetDateTime;

    use super::{SdkAws, classify, seconds};
    use crate::aws::{
        Aws, AwsCredentials, AwsError, AwsErrorKind, Network, NetworkError, Service, SsoAccount,
        SsoToken,
    };
    use crate::identity::AccountId;
    use crate::region::Region;
    use crate::secret::Secret;
    use crate::test_tls::make_certificates;

    type TestResult = Result<(), Box<dyn Error>>;
    type StsError = SdkError<GetCallerIdentityError>;
    type SsoError = SdkError<GetRoleCredentialsError>;

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
        // As hyper-rustls hands it on, under an I/O error of another kind.
        let wrapped = io::Error::other(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid peer certificate: UnknownIssuer",
        ));
        let error = dispatch(ConnectorError::io(Box::new(wrapped)));
        assert_eq!(error.kind, AwsErrorKind::Tls, "{error}");

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
        assert_eq!(error.detail, "AWS's answer could not be read", "{error}");
        let error = classify(Service::Sts, &StsError::construction_failure("no region"));
        assert_eq!(error.kind, AwsErrorKind::Unexpected);
        assert!(error.detail.ends_with(": no region"), "{error}");
        Ok(())
    }

    const ACCESS_TOKEN: &str = "test-sso-access-token";

    /// What a fake answers for a request's target and body.
    type Answer = fn(&str, &str) -> String;

    /// [`SdkAws`] calling IAM Identity Center and Account on a loopback port,
    /// where each request, on a connection of its own, gets what `answer`
    /// gives. The server keeps each target it was sent, with its SSO token or
    /// what it was signed for.
    struct FakeSso {
        aws: SdkAws,
        requests: Arc<Mutex<Vec<String>>>,
    }

    impl FakeSso {
        fn start(answer: Answer) -> Result<Self, Box<dyn Error>> {
            Self::serving(answer, None, &Network::default())
        }

        /// Serves HTTPS with the test certificate for 127.0.0.1, which only
        /// the test CA signs, to an [`SdkAws`] reaching it through `network`.
        fn start_tls(answer: Answer, network: &Network) -> Result<Self, Box<dyn Error>> {
            Self::serving(answer, Some(tls_server()?), network)
        }

        fn serving(
            answer: Answer,
            tls: Option<Arc<ServerConfig>>,
            network: &Network,
        ) -> Result<Self, Box<dyn Error>> {
            let listener = TcpListener::bind("127.0.0.1:0")?;
            let scheme = if tls.is_some() { "https" } else { "http" };
            let endpoint = format!("{scheme}://{}", listener.local_addr()?);
            let requests = Arc::new(Mutex::new(Vec::new()));
            let seen = Arc::clone(&requests);
            thread::spawn(move || serve(&listener, answer, tls.as_ref(), &seen));
            Ok(Self {
                aws: SdkAws {
                    endpoint: Some(endpoint),
                    ..SdkAws::new(network)?
                },
                requests,
            })
        }

        fn requests(&self) -> Vec<String> {
            self.requests
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }
    }

    /// Answers each connection to `listener` in turn. A connection that
    /// fails fails only its own call.
    fn serve(
        listener: &TcpListener,
        answer: Answer,
        tls: Option<&Arc<ServerConfig>>,
        seen: &Mutex<Vec<String>>,
    ) {
        for stream in listener.incoming() {
            let _served: io::Result<()> = stream.and_then(|stream| match tls {
                Some(config) => {
                    let connection =
                        ServerConnection::new(Arc::clone(config)).map_err(io::Error::other)?;
                    let mut tls = StreamOwned::new(connection, stream);
                    reply(&mut tls, answer, seen)?;
                    tls.conn.send_close_notify();
                    tls.flush()
                }
                None => reply(stream, answer, seen),
            });
        }
    }

    fn reply(
        stream: impl Read + Write,
        answer: Answer,
        seen: &Mutex<Vec<String>>,
    ) -> io::Result<()> {
        let mut reader = BufReader::new(stream);
        let mut request_line = String::new();
        reader.read_line(&mut request_line)?;
        let mut headers = Vec::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line)?;
            let line = line.trim_end().to_owned();
            if line.is_empty() {
                break;
            }
            headers.push(line);
        }
        let header = |name: &str| {
            headers.iter().find_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.eq_ignore_ascii_case(name)
                    .then(|| value.trim().to_owned())
            })
        };
        let length = header("content-length")
            .and_then(|length| length.parse().ok())
            .unwrap_or(0);
        let mut body = vec![0; length];
        reader.read_exact(&mut body)?;
        let target = request_line.split(' ').nth(1).unwrap_or_default();
        let token = header("x-amz-sso_bearer_token")
            .or_else(|| header("authorization").and_then(|value| signed_for(&value)))
            .unwrap_or_default();
        seen.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(format!("{target} with {token}"));
        let answer = answer(target, &String::from_utf8_lossy(&body));
        let stream = reader.get_mut();
        stream.write_all(answer.as_bytes())?;
        stream.flush()
    }

    /// The key, service and region an `Authorization` header signed for.
    fn signed_for(authorization: &str) -> Option<String> {
        let scope = authorization
            .split("Credential=")
            .nth(1)?
            .split(',')
            .next()?;
        match scope.split('/').collect::<Vec<_>>().as_slice() {
            [key, _date, region, service, _request] => {
                Some(format!("{key} for {service} in {region}"))
            }
            _ => None,
        }
    }

    /// An HTTP answer with a JSON body, and AWS's error type for an error.
    fn json(status: u16, error_type: Option<&str>, body: &str) -> String {
        let error =
            error_type.map_or_else(String::new, |kind| format!("x-amzn-errortype: {kind}\r\n"));
        format!(
            "HTTP/1.1 {status} Fake\r\ncontent-type: application/json\r\n{error}content-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    /// IAM Identity Center's answers: two pages of accounts and of roles,
    /// a role's keys with and without an expiry, and its refusals.
    fn iam_identity_center(target: &str, _body: &str) -> String {
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        let second_page = query.contains("next_token=more");
        let role = |name: &str| query.contains(&format!("role_name={name}"));
        match path {
            "/assignment/accounts" if second_page => json(
                200,
                None,
                r#"{"accountList":[{"accountId":"210987654321","accountName":""},{"accountId":"not-an-account","accountName":"Bad"}]}"#,
            ),
            "/assignment/accounts" => json(
                200,
                None,
                r#"{"accountList":[{"accountId":"123456789012","accountName":"Production"}],"nextToken":"more"}"#,
            ),
            "/assignment/roles" if second_page => {
                json(200, None, r#"{"roleList":[{"roleName":"admin"}]}"#)
            }
            "/assignment/roles" => json(
                200,
                None,
                r#"{"roleList":[{"roleName":"deploy","accountId":"123456789012"},{"roleName":""}],"nextToken":"more"}"#,
            ),
            "/federation/credentials" if role("deploy") => json(
                200,
                None,
                r#"{"roleCredentials":{"accessKeyId":"ASIASSO","secretAccessKey":"test-sdk-role-secret","sessionToken":"test-sdk-role-token","expiration":1767225600000}}"#,
            ),
            "/federation/credentials" if role("lasting") => json(
                200,
                None,
                r#"{"roleCredentials":{"accessKeyId":"ASIASSO","secretAccessKey":"test-sdk-role-secret","expiration":0}}"#,
            ),
            "/federation/credentials" if role("forbidden") => json(
                403,
                Some("ForbiddenException"),
                r#"{"message":"No access"}"#,
            ),
            "/federation/credentials" if role("revoked") => json(
                401,
                Some("UnauthorizedException"),
                r#"{"message":"Session token not found or invalid"}"#,
            ),
            "/federation/credentials" if role("gone") => json(
                404,
                Some("ResourceNotFoundException"),
                r#"{"message":"Could not find account"}"#,
            ),
            _ => json(400, Some("InvalidRequestException"), "{}"),
        }
    }

    fn token() -> SsoToken {
        SsoToken {
            access_token: Secret::new(ACCESS_TOKEN),
            expires_in: None,
        }
    }

    fn production() -> Result<AccountId, Box<dyn Error>> {
        Ok(AccountId::parse("123456789012")?)
    }

    /// Every page is listed, with the token. An account with an empty name
    /// goes by its id, and one whose id is not an account id is left out.
    #[tokio::test]
    async fn the_accounts_are_every_pages_by_name_or_else_id() -> TestResult {
        let sso = FakeSso::start(iam_identity_center)?;
        let accounts = sso
            .aws
            .sso_accounts(&token(), &Region::parse("eu-west-1")?)
            .await?;
        assert_eq!(
            accounts,
            [
                SsoAccount {
                    id: production()?,
                    name: "Production".to_owned(),
                },
                SsoAccount {
                    id: AccountId::parse("210987654321")?,
                    name: "210987654321".to_owned(),
                },
            ]
        );
        let requests = sso.requests();
        assert_eq!(requests.len(), 2, "{requests:?}");
        assert!(
            requests
                .iter()
                .all(|request| request.starts_with("/assignment/accounts")
                    && request.ends_with(&format!(" with {ACCESS_TOKEN}"))),
            "{requests:?}"
        );
        Ok(())
    }

    /// Listings whose every page says there is another.
    fn endless(target: &str, _body: &str) -> String {
        let list = if target.starts_with("/assignment/roles") {
            "roleList"
        } else {
            "accountList"
        };
        json(200, None, &format!(r#"{{"{list}":[],"nextToken":"more"}}"#))
    }

    #[tokio::test]
    async fn a_listing_that_never_ends_stops_at_the_page_cap_and_names_it() -> TestResult {
        let mut sso = FakeSso::start(endless)?;
        sso.aws.max_pages = 3;
        let region = Region::parse("eu-west-1")?;
        let accounts = sso.aws.sso_accounts(&token(), &region).await.err();
        let roles = sso
            .aws
            .sso_roles(&token(), &production()?, &region)
            .await
            .err();
        for (error, operation) in [(accounts, "ListAccounts"), (roles, "ListAccountRoles")] {
            let error = error.ok_or(operation)?;
            assert_eq!(
                (error.service, error.kind, error.detail),
                (
                    Service::Sso,
                    AwsErrorKind::Unexpected,
                    format!("{operation} kept paging past 3 pages")
                ),
            );
        }
        assert_eq!(sso.requests().len(), 6);
        Ok(())
    }

    /// Every page's roles, without the ones with an empty name.
    #[tokio::test]
    async fn the_roles_are_every_pages_named_ones() -> TestResult {
        let sso = FakeSso::start(iam_identity_center)?;
        let roles = sso
            .aws
            .sso_roles(&token(), &production()?, &Region::parse("eu-west-1")?)
            .await?;
        assert_eq!(roles, ["deploy", "admin"]);
        let requests = sso.requests();
        assert!(
            requests
                .iter()
                .all(|request| request.contains("account_id=123456789012")),
            "{requests:?}"
        );
        Ok(())
    }

    /// A role's keys expire when AWS says, in milliseconds since the epoch,
    /// and never when it says 0.
    #[tokio::test]
    async fn a_roles_keys_expire_at_the_millisecond_aws_gives() -> TestResult {
        let sso = FakeSso::start(iam_identity_center)?;
        let region = Region::parse("eu-west-1")?;
        let keys = sso
            .aws
            .role_credentials(&token(), &production()?, "deploy", &region)
            .await?;
        assert_eq!(keys.access_key_id, "ASIASSO");
        assert_eq!(keys.secret_access_key.expose(), "test-sdk-role-secret");
        assert_eq!(
            keys.session_token.as_ref().map(Secret::expose),
            Some("test-sdk-role-token")
        );
        assert_eq!(
            keys.expires_at,
            Some(OffsetDateTime::from_unix_timestamp(1_767_225_600)?)
        );

        let keys = sso
            .aws
            .role_credentials(&token(), &production()?, "lasting", &region)
            .await?;
        assert_eq!(keys.expires_at, None);
        assert!(keys.session_token.is_none());
        Ok(())
    }

    /// IAM Identity Center's refusals: a role the person may not use, a
    /// token it no longer takes, and an account or role it does not know.
    #[tokio::test]
    async fn iam_identity_centers_refusals_are_read_into_kinds() -> TestResult {
        let sso = FakeSso::start(iam_identity_center)?;
        let region = Region::parse("eu-west-1")?;
        for (role, kind, detail) in [
            (
                "forbidden",
                AwsErrorKind::Refused,
                "ForbiddenException: No access",
            ),
            (
                "revoked",
                AwsErrorKind::Expired,
                "UnauthorizedException: Session token not found or invalid",
            ),
            (
                "gone",
                AwsErrorKind::NotFound,
                "ResourceNotFoundException: Could not find account",
            ),
        ] {
            let error = sso
                .aws
                .role_credentials(&token(), &production()?, role, &region)
                .await
                .err()
                .ok_or("IAM Identity Center gave keys")?;
            assert_eq!(
                (error.service, error.kind, error.detail.as_str()),
                (Service::Sso, kind, detail),
                "{role}"
            );
        }
        Ok(())
    }

    /// Account's `GetRegionOptStatus` answers, by the region the body asks
    /// about: each status AWS has, one it may add, none, and a refusal.
    fn account(target: &str, body: &str) -> String {
        let status = |status: &str| {
            json(
                200,
                None,
                &format!(r#"{{"RegionName":"x","RegionOptStatus":"{status}"}}"#),
            )
        };
        let asked = |region: &str| body.contains(&format!(r#""RegionName":"{region}""#));
        match target {
            "/getRegionOptStatus" if asked("us-east-1") => status("ENABLED_BY_DEFAULT"),
            "/getRegionOptStatus" if asked("ap-east-1") => status("ENABLED"),
            "/getRegionOptStatus" if asked("me-south-1") => status("DISABLED"),
            "/getRegionOptStatus" if asked("af-south-1") => status("ENABLING"),
            "/getRegionOptStatus" if asked("eu-south-2") => status("DISABLING"),
            "/getRegionOptStatus" if asked("il-central-1") => status("PAUSED"),
            "/getRegionOptStatus" if asked("ca-west-1") => json(200, None, "{}"),
            "/getRegionOptStatus" if asked("mx-central-1") => json(
                403,
                Some("AccessDeniedException"),
                r#"{"message":"not authorized to perform account:GetRegionOptStatus"}"#,
            ),
            _ => json(400, Some("ValidationException"), "{}"),
        }
    }

    /// Only `ENABLED` and `ENABLED_BY_DEFAULT` are enabled. An answer without a
    /// status, and a refusal, are errors. Each request is signed with the
    /// keys for the region it is sent to.
    #[tokio::test]
    async fn a_regions_status_is_read_from_accounts_answer() -> TestResult {
        let account = FakeSso::start(account)?;
        let keys = AwsCredentials {
            access_key_id: "AKIATEST".to_owned(),
            secret_access_key: Secret::new("test-secret-access-key"),
            session_token: None,
            expires_at: None,
        };
        let home = Region::parse("us-east-1")?;
        let asked = [
            "us-east-1",
            "ap-east-1",
            "me-south-1",
            "af-south-1",
            "eu-south-2",
            "il-central-1",
            "ca-west-1",
            "mx-central-1",
        ];
        let mut answers = Vec::new();
        for region in asked {
            let answer = account
                .aws
                .region_enabled(&keys, &Region::parse(region)?, &home)
                .await;
            answers.push(answer.map_err(|error| (error.service, error.kind)));
        }
        let refused = (Service::Account, AwsErrorKind::Refused);
        let unexpected = (Service::Account, AwsErrorKind::Unexpected);
        assert_eq!(
            answers,
            [
                Ok(true),
                Ok(true),
                Ok(false),
                Ok(false),
                Ok(false),
                Ok(false),
                Err(unexpected),
                Err(refused),
            ]
        );
        assert_eq!(
            account.requests(),
            vec!["/getRegionOptStatus with AKIATEST for account in us-east-1"; asked.len()]
        );
        Ok(())
    }

    /// A test CA no platform trusts, and the certificate it signs for
    /// localhost and 127.0.0.1 with its key, in PEM.
    struct Certificates {
        ca: Vec<u8>,
        localhost: Vec<u8>,
        localhost_key: Vec<u8>,
    }

    /// The test certificates, made with `openssl` once for these tests.
    fn certificates() -> Result<&'static Certificates, Box<dyn Error>> {
        static MADE: OnceLock<Result<Certificates, String>> = OnceLock::new();
        let made = MADE.get_or_init(|| {
            let make = || -> Result<Certificates, Box<dyn Error>> {
                let dir = tempfile::tempdir()?;
                make_certificates(dir.path())?;
                Ok(Certificates {
                    ca: std::fs::read(dir.path().join("ca.pem"))?,
                    localhost: std::fs::read(dir.path().join("localhost.pem"))?,
                    localhost_key: std::fs::read(dir.path().join("localhost-key.pem"))?,
                })
            };
            make().map_err(|error| error.to_string())
        });
        made.as_ref().map_err(|error| error.clone().into())
    }

    /// The keys a test signs with. A proxy must never see them.
    const PROXY_MUST_NOT_SEE: &str = "test-secret-the-proxy-must-not-see";

    fn tls_server() -> Result<Arc<ServerConfig>, Box<dyn Error>> {
        let certificates = certificates()?;
        let chain = CertificateDer::pem_slice_iter(&certificates.localhost)
            .collect::<Result<Vec<_>, _>>()?;
        let key = PrivateKeyDer::from_pem_slice(&certificates.localhost_key)?;
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(chain, key)?;
        Ok(Arc::new(config))
    }

    fn signing_keys() -> AwsCredentials {
        AwsCredentials {
            access_key_id: "AKIATEST".to_owned(),
            secret_access_key: Secret::new(PROXY_MUST_NOT_SEE),
            session_token: Some(Secret::new(PROXY_MUST_NOT_SEE)),
            expires_at: None,
        }
    }

    /// The CA bundle is trusted beside the platform's roots, which alone do
    /// not trust the test CA.
    #[tokio::test]
    async fn https_to_a_server_only_the_ca_bundle_trusts() -> TestResult {
        let home = Region::parse("us-east-1")?;
        let target = Region::parse("ap-east-1")?;
        let bundle = Network {
            ca_bundle: Some(certificates()?.ca.clone()),
            proxy: None,
        };
        let trusted = FakeSso::start_tls(account, &bundle)?;
        let enabled = trusted
            .aws
            .region_enabled(&signing_keys(), &target, &home)
            .await?;
        assert!(enabled);
        assert_eq!(
            trusted.requests(),
            ["/getRegionOptStatus with AKIATEST for account in us-east-1"]
        );

        // A TLS failure, which the plugin answers with a hint to give
        // Runbooks the CA certificate.
        let untrusted = FakeSso::start_tls(account, &Network::default())?;
        let refused = untrusted
            .aws
            .region_enabled(&signing_keys(), &target, &home)
            .await
            .err()
            .map(|error| (error.service, error.kind, error.detail));
        let (service, kind, detail) = refused.ok_or("trusted without the bundle")?;
        assert_eq!((service, kind), (Service::Account, AwsErrorKind::Tls));
        assert!(detail.ends_with("UnknownIssuer"), "{detail}");
        assert_eq!(untrusted.requests(), Vec::<String>::new());
        Ok(())
    }

    /// A proxy on a loopback port that refuses every tunnel, and the request
    /// head of each. No call through it leaves the machine.
    fn refusing_proxy() -> io::Result<(String, Arc<Mutex<Vec<String>>>)> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let heads = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&heads);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let _refused: io::Result<()> = stream.and_then(|stream| refuse(&stream, &seen));
            }
        });
        Ok((
            format!("http://proxy-user:test-proxy-password@{address}"),
            heads,
        ))
    }

    fn refuse(stream: &TcpStream, seen: &Mutex<Vec<String>>) -> io::Result<()> {
        let mut reader = BufReader::new(stream);
        let mut head = Vec::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line)?;
            let line = line.trim_end();
            if line.is_empty() {
                break;
            }
            head.push(line.to_owned());
        }
        seen.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(head.join("\n"));
        let mut stream = reader.into_inner();
        stream
            .write_all(b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
    }

    /// Every service the plugin calls tunnels through the proxy to AWS's
    /// own endpoint, with the proxy's credentials and never the keys or a
    /// token. A refusal is a network error.
    #[tokio::test]
    async fn every_call_tunnels_through_the_proxy_which_never_sees_a_key() -> TestResult {
        let (proxy, heads) = refusing_proxy()?;
        let aws = SdkAws::new(&Network {
            ca_bundle: None,
            proxy: Some(proxy),
        })?;
        let keys = signing_keys();
        let token = SsoToken {
            access_token: Secret::new(PROXY_MUST_NOT_SEE),
            expires_in: None,
        };
        let region = Region::parse("eu-west-1")?;
        let account = production()?;
        let failures = [
            aws.caller_identity(&keys, &region).await.err(),
            aws.start_device_authorization("https://my-org.awsapps.com/start", &region)
                .await
                .err(),
            aws.sso_accounts(&token, &region).await.err(),
            aws.region_enabled(&keys, &region, &region).await.err(),
        ];
        let kinds: Vec<_> = failures
            .iter()
            .map(|failure| failure.as_ref().map(|error| (error.service, error.kind)))
            .collect();
        assert_eq!(
            kinds,
            [
                Some((Service::Sts, AwsErrorKind::Network)),
                Some((Service::SsoOidc, AwsErrorKind::Network)),
                Some((Service::Sso, AwsErrorKind::Network)),
                Some((Service::Account, AwsErrorKind::Network)),
            ]
        );
        let heads = heads.lock().unwrap_or_else(PoisonError::into_inner).clone();
        let mut hosts: Vec<&str> = heads
            .iter()
            .filter_map(|head| head.lines().next()?.split(' ').nth(1))
            .collect();
        hosts.dedup();
        assert_eq!(
            hosts,
            [
                "sts.eu-west-1.amazonaws.com:443",
                "oidc.eu-west-1.amazonaws.com:443",
                "portal.sso.eu-west-1.amazonaws.com:443",
                // Account has one endpoint for the partition.
                "account.us-east-1.amazonaws.com:443",
            ]
        );
        for head in &heads {
            assert!(head.starts_with("CONNECT "), "{head}");
            assert!(head.contains("Proxy-Authorization: Basic "), "{head}");
            assert!(!head.contains(PROXY_MUST_NOT_SEE), "{head}");
            assert!(
                !head.to_lowercase().contains("authorization: aws4"),
                "{head}"
            );
            assert!(!head.contains(account.as_str()), "{head}");
        }
        Ok(())
    }

    /// The client is built only from a bundle it can read, which it would
    /// otherwise panic on, and a proxy URL, which no error shows.
    #[test]
    fn a_bundle_without_a_good_certificate_and_a_bad_proxy_are_refused() -> TestResult {
        let bundle = |pem: &str| Network {
            ca_bundle: Some(pem.as_bytes().to_vec()),
            proxy: None,
        };
        let refused = |network: &Network| SdkAws::new(network).err();
        assert_eq!(
            refused(&bundle("not a certificate")),
            Some(NetworkError::NoCertificate)
        );
        // Not base64, then base64 that is not a certificate.
        for pem in [
            "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        ] {
            assert_eq!(refused(&bundle(pem)), Some(NetworkError::BadCertificate));
        }
        // A good certificate among other text is enough.
        let mixed = format!(
            "a comment\n{}",
            String::from_utf8_lossy(&certificates()?.ca)
        );
        assert_eq!(refused(&bundle(&mixed)), None);

        for proxy in [
            "proxy.example.com:8080",
            "socks5://proxy.example.com:1080",
            "http://user:test-proxy-password@[::1",
        ] {
            let network = Network {
                ca_bundle: None,
                proxy: Some(proxy.to_owned()),
            };
            assert_eq!(refused(&network), Some(NetworkError::Proxy), "{proxy}");
        }
        let network = Network {
            ca_bundle: Some(b"12345".to_vec()),
            proxy: Some("https://user:test-proxy-password@proxy.example.com".to_owned()),
        };
        assert_eq!(
            format!("{network:?}"),
            r#"Network { ca_bundle: Some(5), proxy: Some("<set>") }"#
        );
        let aws = SdkAws::new(&Network {
            ca_bundle: None,
            ..network
        })?;
        assert_eq!(format!("{aws:?}"), "SdkAws { endpoint: None, .. }");
        Ok(())
    }

    /// An answer the SDK could not read may hold keys or a token, so none of
    /// it is shown. A request it could not build says why.
    #[test]
    fn an_unreadable_answer_is_never_shown_and_an_unbuilt_request_says_why() -> TestResult {
        let unreadable = SsoError::response_error(
            r#"expected '}' after {"secretAccessKey":"test-sdk-role-secret""#,
            HttpResponse::new(200.try_into()?, "".into()),
        );
        let error = classify(Service::Sso, &unreadable);
        assert_eq!(
            (error.kind, error.detail.as_str()),
            (AwsErrorKind::Unexpected, "AWS's answer could not be read")
        );
        let unbuilt = SsoError::construction_failure("no account id");
        let error = classify(Service::Sso, &unbuilt);
        assert_eq!(error.kind, AwsErrorKind::Unexpected);
        assert!(error.detail.ends_with(": no account id"), "{error}");
        Ok(())
    }

    /// SSO-OIDC's lifetimes and intervals: a positive count of seconds. 0 or
    /// less is none, so RFC 8628's default applies.
    #[test]
    fn only_a_positive_count_of_seconds_is_a_duration() {
        assert_eq!(seconds(600), Some(Duration::from_secs(600)));
        assert_eq!(seconds(1), Some(Duration::from_secs(1)));
        assert_eq!(seconds(0), None);
        assert_eq!(seconds(-5), None);
    }
}
