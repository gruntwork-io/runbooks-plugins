//! Google credentials: the documents a person or a detection source supplies,
//! and turning one into an access token.

use runbooks_plugin_protocol::credential::ErrorKind;
use runbooks_plugin_transport::PluginError;
use serde_json::{Map, Value};

use crate::Secret;
use crate::api::{ApiError, GoogleApi, OAuthError, TOKEN_URL, TokenRequest};
use crate::crypto::{self, CryptoError, JwtClaims};

pub(crate) const CLOUD_PLATFORM_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";
/// The largest credentials document read. Google's are about 2 KB.
pub(crate) const MAX_DOCUMENT_BYTES: usize = 64 * 1024;
/// How long a service account's assertion asks its token to last.
const ASSERTION_SECONDS: i64 = 3600;

/// A credential the plugin can get access tokens from.
#[derive(Clone, Debug)]
pub(crate) enum Credential {
    Document(Document),
    /// A bare access token from the environment. Nothing can refresh it.
    AccessToken(Secret),
}

/// A credentials document, with its text kept as written: the file a run
/// reads is the document that was validated.
#[derive(Clone, Debug)]
pub(crate) struct Document {
    pub(crate) text: Secret,
    pub(crate) kind: DocumentKind,
}

#[derive(Clone, Debug)]
pub(crate) enum DocumentKind {
    ServiceAccount {
        client_email: String,
        private_key: Secret,
        project_id: Option<String>,
    },
    AuthorizedUser {
        client_id: String,
        client_secret: Secret,
        refresh_token: Secret,
        quota_project_id: Option<String>,
    },
}

/// How the credential was obtained, as `GOOGLE_AUTH_TYPE` names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CredentialType {
    ServiceAccount,
    AuthorizedUser,
    AccessToken,
}

impl CredentialType {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::ServiceAccount => "service_account",
            Self::AuthorizedUser => "authorized_user",
            Self::AccessToken => "access_token",
        }
    }

    /// A service account's tokens are minted for cloud-platform alone, so
    /// they are exempt from the `scopes` requirement.
    pub(crate) const fn is_service_account(self) -> bool {
        match self {
            Self::ServiceAccount => true,
            Self::AuthorizedUser | Self::AccessToken => false,
        }
    }
}

impl Credential {
    pub(crate) const fn credential_type(&self) -> CredentialType {
        match self {
            Self::AccessToken(_) => CredentialType::AccessToken,
            Self::Document(document) => match document.kind {
                DocumentKind::ServiceAccount { .. } => CredentialType::ServiceAccount,
                DocumentKind::AuthorizedUser { .. } => CredentialType::AuthorizedUser,
            },
        }
    }

    /// The project the credential names itself, if any.
    pub(crate) fn own_project(&self) -> Option<String> {
        match self {
            Self::AccessToken(_) => None,
            Self::Document(document) => match &document.kind {
                DocumentKind::ServiceAccount { project_id, .. } => project_id.clone(),
                DocumentKind::AuthorizedUser {
                    quota_project_id, ..
                } => quota_project_id.clone(),
            },
        }
    }

    /// The email the document names, for a token granted without the email scope.
    pub(crate) fn own_email(&self) -> Option<String> {
        match self {
            Self::Document(Document {
                kind: DocumentKind::ServiceAccount { client_email, .. },
                ..
            }) => Some(client_email.clone()),
            Self::Document(_) | Self::AccessToken(_) => None,
        }
    }
}

/// Why a credentials document can't be used. Never quotes the document.
#[derive(Debug, thiserror::Error)]
pub(crate) enum DocumentError {
    #[error("is not JSON")]
    NotJson,
    #[error("is not a JSON object")]
    NotObject,
    #[error(
        "has no \"type\": expected a Google credentials document such as a service account key"
    )]
    NoType,
    #[error(
        "has type {0}, which this plugin can't use: expected service_account or authorized_user"
    )]
    UnsupportedType(String),
    #[error("has type {0}: expected a service account key, of type service_account")]
    NotServiceAccountKey(String),
    #[error("is missing {0}")]
    Missing(&'static str),
}

/// Parses a service account key: a credentials document of type `service_account`.
pub(crate) fn parse_service_account_key(text: String) -> Result<Document, DocumentError> {
    match parse_document(text) {
        Ok(Document {
            kind: DocumentKind::AuthorizedUser { .. },
            ..
        }) => Err(DocumentError::NotServiceAccountKey(type_name(
            CredentialType::AuthorizedUser.name(),
        ))),
        Err(DocumentError::UnsupportedType(other)) => {
            Err(DocumentError::NotServiceAccountKey(other))
        }
        parsed => parsed,
    }
}

/// Parses a credentials document. The text is held as a secret from here on.
pub(crate) fn parse_document(text: String) -> Result<Document, DocumentError> {
    // serde's message can quote the text, so only the kind of failure is kept.
    let value: Value = serde_json::from_str(&text).map_err(|_syntax| DocumentError::NotJson)?;
    let Value::Object(fields) = value else {
        return Err(DocumentError::NotObject);
    };
    let kind = match string(&fields, "type").as_deref() {
        None => return Err(DocumentError::NoType),
        Some("service_account") => DocumentKind::ServiceAccount {
            client_email: required(&fields, "client_email")?,
            private_key: Secret::new(required(&fields, "private_key")?),
            project_id: string(&fields, "project_id"),
        },
        Some("authorized_user") => DocumentKind::AuthorizedUser {
            client_id: required(&fields, "client_id")?,
            client_secret: Secret::new(required(&fields, "client_secret")?),
            refresh_token: Secret::new(required(&fields, "refresh_token")?),
            quota_project_id: string(&fields, "quota_project_id"),
        },
        Some(other) => return Err(DocumentError::UnsupportedType(type_name(other))),
    };
    Ok(Document {
        text: Secret::new(text),
        kind,
    })
}

/// A non-empty string field, trimmed.
fn string(fields: &Map<String, Value>, name: &str) -> Option<String> {
    fields
        .get(name)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn required(fields: &Map<String, Value>, name: &'static str) -> Result<String, DocumentError> {
    string(fields, name).ok_or(DocumentError::Missing(name))
}

/// A `type` value fit to repeat: a document's type is a short identifier,
/// and anything else may be pasted material.
fn type_name(value: &str) -> String {
    let plain = value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_');
    if plain {
        format!("{value:?}")
    } else {
        "an unrecognized value".to_owned()
    }
}

/// What the person sees when a credential is refused: the fix depends on
/// where the credential came from.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Origin {
    /// Application Default Credentials, which gcloud refreshes.
    Adc,
    ServiceAccountKey,
    AccessToken,
}

impl Origin {
    pub(crate) const fn of(credential: &Credential) -> Self {
        match credential.credential_type() {
            CredentialType::ServiceAccount => Self::ServiceAccountKey,
            CredentialType::AuthorizedUser => Self::Adc,
            CredentialType::AccessToken => Self::AccessToken,
        }
    }
}

/// An access token for `credential`, minted fresh unless it is one.
pub(crate) async fn access_token<A: GoogleApi>(
    api: &A,
    now_unix: i64,
    credential: &Credential,
) -> Result<Secret, PluginError> {
    let request = match credential {
        Credential::AccessToken(token) => return Ok(token.clone()),
        Credential::Document(document) => match &document.kind {
            DocumentKind::ServiceAccount {
                client_email,
                private_key,
                ..
            } => {
                let claims = JwtClaims {
                    issuer: client_email.clone(),
                    scope: CLOUD_PLATFORM_SCOPE.to_owned(),
                    audience: TOKEN_URL.to_owned(),
                    issued_at: now_unix,
                    expires_at: now_unix + ASSERTION_SECONDS,
                };
                let assertion =
                    crypto::sign_jwt(&claims, private_key).map_err(|error| crypto_error(&error))?;
                TokenRequest::JwtBearer { assertion }
            }
            DocumentKind::AuthorizedUser {
                client_id,
                client_secret,
                refresh_token,
                ..
            } => TokenRequest::Refresh {
                client_id: client_id.clone(),
                client_secret: client_secret.clone(),
                refresh_token: refresh_token.clone(),
            },
        },
    };
    let token = api
        .token(request)
        .await
        .map_err(|error| api_error(&error, Origin::of(credential)))?;
    Ok(token.access_token)
}

pub(crate) fn crypto_error(error: &CryptoError) -> PluginError {
    match error {
        CryptoError::Failed(_) => PluginError::new(ErrorKind::Internal, error.to_string()),
        CryptoError::InvalidKey => PluginError::new(
            ErrorKind::InvalidParams,
            "The service account key's private_key is not a PKCS #8 RSA key in PEM. Download a new JSON key.",
        ),
    }
}

/// The one place a failed Google call becomes an error kind and the copy a
/// person acts on.
pub(crate) fn api_error(error: &ApiError, origin: Origin) -> PluginError {
    const RELOGIN: &str = "Run `gcloud auth application-default login` to refresh them.";
    let (kind, message) = match (error, origin) {
        (ApiError::Refused(OAuthError::ReauthRequired), Origin::Adc) => (
            ErrorKind::Expired,
            format!("Your Application Default Credentials need reauthentication. {RELOGIN}"),
        ),
        (ApiError::Refused(OAuthError::ReauthRequired), _) => (
            ErrorKind::Expired,
            "This credential needs reauthentication before it can be used.".to_owned(),
        ),
        (ApiError::Refused(OAuthError::InvalidGrant), Origin::Adc) => (
            ErrorKind::Expired,
            format!("Your Application Default Credentials have expired or been revoked. {RELOGIN}"),
        ),
        (ApiError::Refused(OAuthError::InvalidGrant), Origin::ServiceAccountKey) => (
            ErrorKind::Expired,
            "This service account key has been disabled, deleted, or revoked. Generate a new key, or check that the service account still exists.".to_owned(),
        ),
        (
            ApiError::Refused(OAuthError::InvalidGrant | OAuthError::InvalidToken),
            Origin::AccessToken,
        )
        | (ApiError::Refused(OAuthError::InvalidToken), _) => (
            ErrorKind::Expired,
            "This access token has expired or been revoked.".to_owned(),
        ),
        (ApiError::Refused(OAuthError::InvalidClient), _) => (
            ErrorKind::AccessDenied,
            "The OAuth client is not valid for this credential. Check the block's OAuth client, or the GOOGLE_OAUTH_CLIENT_* variables.".to_owned(),
        ),
        (ApiError::Refused(OAuthError::InvalidScope), _) => (
            ErrorKind::AccessDenied,
            "Google refused the scopes this credential asked for.".to_owned(),
        ),
        (ApiError::Refused(OAuthError::Unknown), _) => (
            ErrorKind::AccessDenied,
            "Google refused this credential.".to_owned(),
        ),
        (ApiError::Status { status: 401, .. }, _) => (
            ErrorKind::Expired,
            "Google no longer accepts this credential. Sign in again.".to_owned(),
        ),
        (ApiError::Status { status: 403, .. }, _) => (
            ErrorKind::AccessDenied,
            "Google refused this request for the signed-in identity.".to_owned(),
        ),
        (ApiError::Status { status, .. }, _) => (
            ErrorKind::Network,
            format!("Google answered HTTP {status}. Try again."),
        ),
        (ApiError::Connect | ApiError::TooLarge | ApiError::Malformed, _) => (
            ErrorKind::Network,
            format!("{error}. Check your network connection or proxy settings."),
        ),
        (ApiError::Tls, _) => (
            ErrorKind::TlsError,
            format!("{error}. If a proxy inspects TLS, give Runbooks its CA bundle."),
        ),
        (ApiError::TimedOut, _) => (ErrorKind::TimedOut, format!("{error}. Try again.")),
    };
    PluginError::new(kind, message)
}

/// Whether a failed `projects.get` says the identity can't see the project,
/// rather than that the API couldn't answer: a disabled API, a scope-limited
/// token or a 5xx must not stop a runbook whose commands would work.
pub(crate) fn denies_project(error: &ApiError) -> bool {
    const INCONCLUSIVE: [&str; 6] = [
        "RESOURCE_EXHAUSTED",
        "UNAVAILABLE",
        "INTERNAL",
        "DEADLINE_EXCEEDED",
        "ABORTED",
        "UNAUTHENTICATED",
    ];
    let ApiError::Status {
        status,
        rpc_status,
        reasons,
    } = error
    else {
        return false;
    };
    let rpc = rpc_status.as_deref();
    if rpc.is_some_and(|code| INCONCLUSIVE.contains(&code)) {
        return false;
    }
    match status {
        404 => true,
        // A disabled API, a scope-limited token and a refused quota project
        // all arrive as 403, told apart by their ErrorInfo reason.
        403 => {
            matches!(rpc, None | Some("PERMISSION_DENIED"))
                && reasons
                    .iter()
                    .all(|reason| reason == "IAM_PERMISSION_DENIED")
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{DocumentError, DocumentKind, denies_project, parse_document};
    use crate::api::ApiError;

    #[test]
    fn a_document_error_never_quotes_the_document() {
        let pasted = r#"{"type": "-----BEGIN PRIVATE KEY----- hunter2", "private_key": "x"}"#;
        let error = parse_document(pasted.to_owned()).err();
        let message = error.map_or_default(|e| e.to_string());
        assert!(message.contains("an unrecognized value"), "{message}");
        assert!(!message.contains("hunter2"), "{message}");

        let error = parse_document("{\"type\": \"service_account\", hunter2".to_owned()).err();
        assert!(matches!(error, Some(DocumentError::NotJson)), "{error:?}");
    }

    #[test]
    fn a_service_account_key_needs_its_email_and_key() {
        let error = parse_document(r#"{"type":"service_account","private_key":"k"}"#.to_owned());
        assert!(matches!(error, Err(DocumentError::Missing("client_email"))));
        let key = parse_document(
            r#"{"type":"service_account","client_email":"a@p.iam.gserviceaccount.com","private_key":"k","project_id":" p "}"#.to_owned(),
        );
        assert!(matches!(
            key.map(|document| document.kind),
            Ok(DocumentKind::ServiceAccount { project_id: Some(ref id), .. }) if id == "p"
        ));
    }

    fn status(status: u16, rpc: Option<&str>, reasons: &[&str]) -> ApiError {
        ApiError::Status {
            status,
            rpc_status: rpc.map(str::to_owned),
            reasons: reasons.iter().map(|reason| (*reason).to_owned()).collect(),
        }
    }

    #[test]
    fn only_a_missing_or_iam_denied_project_is_denied() {
        assert!(denies_project(&status(404, Some("NOT_FOUND"), &[])));
        assert!(denies_project(&status(403, Some("PERMISSION_DENIED"), &[])));
        assert!(denies_project(&status(
            403,
            Some("PERMISSION_DENIED"),
            &["IAM_PERMISSION_DENIED"]
        )));
        assert!(!denies_project(&status(
            403,
            Some("PERMISSION_DENIED"),
            &["SERVICE_DISABLED"]
        )));
        assert!(!denies_project(&status(403, Some("UNAUTHENTICATED"), &[])));
        assert!(!denies_project(&status(503, Some("UNAVAILABLE"), &[])));
        assert!(!denies_project(&ApiError::Connect));
    }
}
