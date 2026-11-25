//! Google's APIs: the OAuth token and tokeninfo endpoints, and Cloud Resource
//! Manager. [`GoogleApi`] is the only way the plugin reaches the network, and
//! [`HttpApi`] is the real one. Nothing outside this module names `reqwest`.

use std::future::Future;
use std::io;
use std::time::Duration;

use reqwest::{Client, Response, StatusCode, Url, header};
use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::Secret;

/// Where every token request goes. A credentials document's own `token_uri`
/// is never used, so a pasted document cannot send a signed assertion or a
/// refresh token anywhere else.
pub const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const TOKEN_INFO_URL: &str = "https://oauth2.googleapis.com/tokeninfo";
const PROJECTS_URL: &str = "https://cloudresourcemanager.googleapis.com/v3/projects";

/// Each call's whole deadline, from connecting to the end of the body.
pub const TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// The largest answer read. Google's are a few kilobytes; a page of 1000
/// projects is about 300.
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// A request to the token endpoint.
#[derive(Clone, Debug)]
pub enum TokenRequest {
    /// An `authorized_user` credential's refresh token.
    Refresh {
        /// The OAuth client's ID.
        client_id: String,
        /// The OAuth client's secret.
        client_secret: Secret,
        /// The refresh token.
        refresh_token: Secret,
    },
    /// A service account's signed JWT assertion.
    JwtBearer {
        /// The compact JWS.
        assertion: Secret,
    },
    /// The code Google's redirect brought back from a browser sign-in, with
    /// its PKCE verifier.
    AuthorizationCode {
        client_id: String,
        client_secret: Secret,
        code: Secret,
        code_verifier: Secret,
        redirect_uri: String,
    },
}

/// What the token endpoint grants.
#[derive(Clone, Debug)]
pub struct Token {
    /// The access token.
    pub access_token: Secret,
    /// Only an authorization code's exchange returns one.
    pub refresh_token: Option<Secret>,
}

/// What tokeninfo says about an access token.
#[derive(Clone, Debug, Default)]
pub struct TokenInfo {
    /// Absent when the token was granted without the email scope.
    pub email: Option<String>,
    /// The `sub` claim.
    pub subject: Option<String>,
    /// The scopes granted.
    pub scopes: Vec<String>,
    /// Seconds since the Unix epoch.
    pub expires_at: Option<i64>,
}

/// A Cloud Resource Manager project.
#[derive(Clone, Debug)]
pub struct Project {
    /// The project ID.
    pub id: String,
    /// Absent when empty.
    pub display_name: Option<String>,
    /// `ACTIVE`, `DELETE_REQUESTED`, or absent.
    pub state: Option<String>,
}

/// One page of [`GoogleApi::search_projects`].
#[derive(Clone, Debug, Default)]
pub struct ProjectPage {
    /// The page's projects.
    pub projects: Vec<Project>,
    /// The next page's token, absent on the last page.
    pub next_page_token: Option<String>,
}

/// Why a call failed. Carries nothing the remote wrote beyond codes, so it
/// can never repeat a secret.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// The token or tokeninfo endpoint refused the credential.
    #[error("Google refused the credential ({0})")]
    Refused(OAuthError),
    /// Another API answered with an error status.
    #[error("Google answered HTTP {status}")]
    Status {
        /// The HTTP status code.
        status: u16,
        /// The google.rpc code name, such as `PERMISSION_DENIED`.
        rpc_status: Option<String>,
        /// Every `ErrorInfo` reason in the error's details.
        reasons: Vec<String>,
    },
    /// The connection failed.
    #[error("could not connect to Google")]
    Connect,
    /// The TLS handshake failed.
    #[error("the TLS handshake with Google failed")]
    Tls,
    /// No answer within [`TIMEOUT`].
    #[error("Google did not answer within {} seconds", TIMEOUT.as_secs())]
    TimedOut,
    /// The answer is larger than [`MAX_RESPONSE_BYTES`].
    #[error("Google's answer is larger than {MAX_RESPONSE_BYTES} bytes")]
    TooLarge,
    /// The answer is not the JSON expected.
    #[error("Google's answer is not the JSON expected")]
    Malformed,
}

/// The OAuth `error` codes the plugin acts on. Google can send others.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum OAuthError {
    /// `invalid_grant`.
    #[error("invalid_grant")]
    InvalidGrant,
    /// `invalid_grant` with `error_subtype` `invalid_rapt`: an organization's
    /// reauthentication policy wants the person back.
    #[error("invalid_rapt")]
    ReauthRequired,
    /// `invalid_client` or `unauthorized_client`.
    #[error("invalid_client")]
    InvalidClient,
    /// `invalid_scope`.
    #[error("invalid_scope")]
    InvalidScope,
    /// `invalid_token`.
    #[error("invalid_token")]
    InvalidToken,
    /// Any other code.
    #[error("another error")]
    Unknown,
}

impl OAuthError {
    fn parse(error: &str, subtype: Option<&str>) -> Self {
        match (error, subtype) {
            ("invalid_grant", Some("invalid_rapt")) => Self::ReauthRequired,
            ("invalid_grant", _) => Self::InvalidGrant,
            ("invalid_client" | "unauthorized_client", _) => Self::InvalidClient,
            ("invalid_scope", _) => Self::InvalidScope,
            ("invalid_token", _) => Self::InvalidToken,
            _ => Self::Unknown,
        }
    }
}

/// Google's APIs, as the plugin uses them.
pub trait GoogleApi: Send + Sync + 'static {
    /// Exchanges `request` at [`TOKEN_URL`] for an access token.
    fn token(&self, request: TokenRequest) -> impl Future<Output = Result<Token, ApiError>> + Send;

    /// What tokeninfo says about `access_token`.
    fn token_info(
        &self,
        access_token: &Secret,
    ) -> impl Future<Output = Result<TokenInfo, ApiError>> + Send;

    /// One page of the projects the token can see.
    fn search_projects(
        &self,
        access_token: &Secret,
        page_token: Option<&str>,
        page_size: u32,
    ) -> impl Future<Output = Result<ProjectPage, ApiError>> + Send;

    /// The project with ID `project_id`.
    fn get_project(
        &self,
        access_token: &Secret,
        project_id: &str,
    ) -> impl Future<Output = Result<Project, ApiError>> + Send;
}

/// How the plugin reaches Google, from `configure`.
#[derive(Clone, Debug, Default)]
pub struct Network {
    /// Extra trusted roots, in PEM, read from `caBundleFile`.
    pub ca_bundle: Option<Vec<u8>>,
    /// The `proxy` URL. It can hold a password, so no error repeats it.
    pub proxy: Option<String>,
}

/// Why [`HttpApi::new`] refused a [`Network`].
#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    /// The CA bundle holds no PEM certificate.
    #[error("holds no PEM certificate")]
    CaBundle,
    /// The proxy is not a proxy URL.
    #[error("is not a proxy URL")]
    Proxy,
    /// The HTTP client could not be built.
    #[error("the HTTP client could not be built")]
    Client,
}

/// [`GoogleApi`] over HTTPS.
#[derive(Clone, Debug)]
pub struct HttpApi {
    client: Client,
}

impl HttpApi {
    /// # Errors
    ///
    /// [`NetworkError`] if the CA bundle or the proxy can't be used.
    pub fn new(network: &Network) -> Result<Self, NetworkError> {
        // The environment's proxy variables are the app's to pass as `proxy`.
        let mut builder = Client::builder()
            .timeout(TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy();
        if let Some(pem) = &network.ca_bundle {
            let certs = reqwest::Certificate::from_pem_bundle(pem)
                .map_err(|_unreadable| NetworkError::CaBundle)?;
            if certs.is_empty() {
                return Err(NetworkError::CaBundle);
            }
            builder = builder.tls_certs_merge(certs);
        }
        if let Some(proxy) = &network.proxy {
            let proxy = reqwest::Proxy::all(proxy).map_err(|_invalid| NetworkError::Proxy)?;
            builder = builder.proxy(proxy);
        }
        let client = builder.build().map_err(|_failed| NetworkError::Client)?;
        Ok(Self { client })
    }
}

impl GoogleApi for HttpApi {
    async fn token(&self, request: TokenRequest) -> Result<Token, ApiError> {
        let body = match &request {
            TokenRequest::Refresh {
                client_id,
                client_secret,
                refresh_token,
            } => form(&[
                ("grant_type", "refresh_token"),
                ("client_id", client_id),
                ("client_secret", client_secret.expose()),
                ("refresh_token", refresh_token.expose()),
            ]),
            TokenRequest::JwtBearer { assertion } => form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", assertion.expose()),
            ]),
            TokenRequest::AuthorizationCode {
                client_id,
                client_secret,
                code,
                code_verifier,
                redirect_uri,
            } => form(&[
                ("grant_type", "authorization_code"),
                ("code", code.expose()),
                ("client_id", client_id),
                ("client_secret", client_secret.expose()),
                ("redirect_uri", redirect_uri),
                ("code_verifier", code_verifier.expose()),
            ]),
        }?;
        let response = self
            .client
            .post(TOKEN_URL)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .map_err(|error| classify(&error))?;
        let token: TokenBody = parse(response).await?;
        Ok(Token {
            access_token: token.access_token,
            refresh_token: token.refresh_token,
        })
    }

    async fn token_info(&self, access_token: &Secret) -> Result<TokenInfo, ApiError> {
        // A POST with the token as a bearer, as Google's own library does, so
        // the token is never in a URL.
        let response = self
            .client
            .post(TOKEN_INFO_URL)
            .bearer_auth(access_token.expose())
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .send()
            .await
            .map_err(|error| classify(&error))?;
        let info: TokenInfoBody = parse(response).await?;
        Ok(TokenInfo {
            email: info.email,
            subject: info.sub,
            scopes: info
                .scope
                .unwrap_or_default()
                .split_whitespace()
                .map(str::to_owned)
                .collect(),
            expires_at: info.exp.and_then(Seconds::get),
        })
    }

    async fn search_projects(
        &self,
        access_token: &Secret,
        page_token: Option<&str>,
        page_size: u32,
    ) -> Result<ProjectPage, ApiError> {
        let mut url = projects_url(":search")?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("pageSize", &page_size.to_string());
            if let Some(token) = page_token {
                query.append_pair("pageToken", token);
            }
        }
        let response = self
            .client
            .get(url)
            .bearer_auth(access_token.expose())
            .send()
            .await
            .map_err(|error| classify(&error))?;
        let page: SearchBody = parse(response).await?;
        Ok(ProjectPage {
            projects: page
                .projects
                .into_iter()
                .filter_map(ProjectBody::into_project)
                .collect(),
            next_page_token: page.next_page_token.filter(|token| !token.is_empty()),
        })
    }

    async fn get_project(
        &self,
        access_token: &Secret,
        project_id: &str,
    ) -> Result<Project, ApiError> {
        let mut url = projects_url("")?;
        url.path_segments_mut()
            .map_err(|()| ApiError::Malformed)?
            .pop_if_empty()
            .push(project_id);
        let response = self
            .client
            .get(url)
            .bearer_auth(access_token.expose())
            .send()
            .await
            .map_err(|error| classify(&error))?;
        let project: ProjectBody = parse(response).await?;
        project.into_project().ok_or(ApiError::Malformed)
    }
}

fn projects_url(suffix: &str) -> Result<Url, ApiError> {
    Url::parse(&format!("{PROJECTS_URL}{suffix}")).map_err(|_bad| ApiError::Malformed)
}

/// An `application/x-www-form-urlencoded` body, encoded by `url`'s own
/// serializer so nothing here escapes by hand.
fn form(pairs: &[(&str, &str)]) -> Result<String, ApiError> {
    let mut scratch = Url::parse("http://form.invalid/").map_err(|_bad| ApiError::Malformed)?;
    scratch.query_pairs_mut().extend_pairs(pairs);
    Ok(scratch.query().unwrap_or_default().to_owned())
}

fn classify(error: &reqwest::Error) -> ApiError {
    if error.is_timeout() {
        return ApiError::TimedOut;
    }
    // rustls reports a failed handshake through tokio-rustls as an
    // `InvalidData` I/O error; nothing else on the connect path does.
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(current) = source {
        if current
            .downcast_ref::<io::Error>()
            .is_some_and(|io| io.kind() == io::ErrorKind::InvalidData)
        {
            return ApiError::Tls;
        }
        source = current.source();
    }
    ApiError::Connect
}

/// The response's JSON if its status is a success, or its error as typed
/// fields. The body is read up to [`MAX_RESPONSE_BYTES`].
async fn parse<T: DeserializeOwned>(mut response: Response) -> Result<T, ApiError> {
    let status = response.status();
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| classify(&error))? {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(ApiError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    if status.is_success() {
        // serde's message can quote the body, which may hold a token.
        return serde_json::from_slice(&body).map_err(|_mismatch| ApiError::Malformed);
    }
    Err(error_from(status, &body))
}

fn error_from(status: StatusCode, body: &[u8]) -> ApiError {
    match serde_json::from_slice::<ErrorBody>(body) {
        Ok(ErrorBody {
            error: ErrorField::OAuth(code),
            error_subtype,
        }) => ApiError::Refused(OAuthError::parse(&code, error_subtype.as_deref())),
        Ok(ErrorBody {
            error: ErrorField::Rpc(rpc),
            ..
        }) => ApiError::Status {
            status: status.as_u16(),
            rpc_status: rpc.status,
            reasons: rpc
                .details
                .into_iter()
                .filter(|detail| {
                    detail
                        .kind
                        .as_deref()
                        .is_some_and(|kind| kind.ends_with("google.rpc.ErrorInfo"))
                })
                .filter_map(|detail| detail.reason.filter(|reason| !reason.is_empty()))
                .collect(),
        },
        Err(_) => ApiError::Status {
            status: status.as_u16(),
            rpc_status: None,
            reasons: Vec::new(),
        },
    }
}

#[derive(Deserialize)]
struct TokenBody {
    access_token: Secret,
    #[serde(default)]
    refresh_token: Option<Secret>,
}

#[derive(Deserialize)]
struct TokenInfoBody {
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    exp: Option<Seconds>,
}

/// tokeninfo writes numbers as strings.
#[derive(Deserialize)]
#[serde(untagged)]
enum Seconds {
    Number(i64),
    Text(String),
}

impl Seconds {
    fn get(self) -> Option<i64> {
        match self {
            Self::Number(seconds) => Some(seconds),
            Self::Text(text) => text.parse().ok(),
        }
    }
}

#[derive(Deserialize)]
struct SearchBody {
    #[serde(default)]
    projects: Vec<ProjectBody>,
    #[serde(default, rename = "nextPageToken")]
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
struct ProjectBody {
    #[serde(default, rename = "projectId")]
    project_id: Option<String>,
    #[serde(default, rename = "displayName")]
    display_name: Option<String>,
    #[serde(default)]
    state: Option<String>,
}

impl ProjectBody {
    fn into_project(self) -> Option<Project> {
        Some(Project {
            id: self.project_id.filter(|id| !id.is_empty())?,
            display_name: self.display_name.filter(|name| !name.is_empty()),
            state: self.state,
        })
    }
}

#[derive(Deserialize)]
struct ErrorBody {
    error: ErrorField,
    #[serde(default)]
    error_subtype: Option<String>,
}

/// The token endpoints write `"error": "invalid_grant"`; every other API
/// writes a google.rpc.Status object.
#[derive(Deserialize)]
#[serde(untagged)]
enum ErrorField {
    OAuth(String),
    Rpc(RpcStatus),
}

#[derive(Deserialize)]
struct RpcStatus {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    details: Vec<ErrorDetail>,
}

#[derive(Deserialize)]
struct ErrorDetail {
    #[serde(default, rename = "@type")]
    kind: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    use super::{
        ApiError, GoogleApi, HttpApi, Network, NetworkError, OAuthError, StatusCode, error_from,
        form,
    };
    use crate::Secret;

    type TestResult = Result<(), Box<dyn Error>>;

    const TOKEN: &str = "ya29.a-token-the-proxy-must-not-see";

    /// A proxy on a loopback port that refuses the one tunnel it is asked
    /// for, and the request head it got. The client reaches it as the
    /// network's proxy, so no test call leaves the machine.
    async fn refusing_proxy()
    -> Result<(Network, JoinHandle<std::io::Result<String>>), Box<dyn Error>> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let network = Network {
            ca_bundle: None,
            proxy: Some(format!("http://{}", listener.local_addr()?)),
        };
        Ok((network, tokio::spawn(refuse_tunnel(listener))))
    }

    async fn refuse_tunnel(listener: TcpListener) -> std::io::Result<String> {
        let (stream, _peer) = listener.accept().await?;
        let (read, mut write) = stream.into_split();
        let mut lines = BufReader::new(read).lines();
        let mut head = Vec::new();
        while let Some(line) = lines.next_line().await?
            && !line.is_empty()
        {
            head.push(line);
        }
        write
            .write_all(b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\n\r\n")
            .await?;
        Ok(head.join("\n"))
    }

    #[tokio::test]
    async fn token_info_goes_to_googles_oauth_host_and_a_refused_tunnel_is_an_error() -> TestResult
    {
        let (network, head) = refusing_proxy().await?;
        let answer = HttpApi::new(&network)?
            .token_info(&Secret::new(TOKEN))
            .await;
        assert!(matches!(answer, Err(ApiError::Connect)), "{answer:?}");
        let head = head.await??;
        assert!(
            head.starts_with("CONNECT oauth2.googleapis.com:443 "),
            "{head}"
        );
        assert!(!head.contains(TOKEN), "the proxy saw the token: {head}");
        Ok(())
    }

    #[tokio::test]
    async fn search_projects_goes_to_resource_manager_and_a_refused_tunnel_is_an_error()
    -> TestResult {
        let (network, head) = refusing_proxy().await?;
        let answer = HttpApi::new(&network)?
            .search_projects(&Secret::new(TOKEN), Some("next"), 500)
            .await;
        assert!(matches!(answer, Err(ApiError::Connect)), "{answer:?}");
        let head = head.await??;
        assert!(
            head.starts_with("CONNECT cloudresourcemanager.googleapis.com:443 "),
            "{head}"
        );
        assert!(!head.contains(TOKEN), "the proxy saw the token: {head}");
        Ok(())
    }

    #[test]
    fn a_form_body_is_percent_encoded() -> TestResult {
        assert_eq!(
            form(&[("assertion", "a.b+c/d="), ("grant_type", "x y")])?,
            "assertion=a.b%2Bc%2Fd%3D&grant_type=x+y"
        );
        Ok(())
    }

    #[test]
    fn an_oauth_error_is_read_by_its_code() {
        let body = br#"{"error":"invalid_grant","error_description":"Bad Request","error_subtype":"invalid_rapt"}"#;
        assert!(matches!(
            error_from(StatusCode::BAD_REQUEST, body),
            ApiError::Refused(OAuthError::ReauthRequired)
        ));
    }

    #[test]
    fn an_rpc_error_keeps_its_status_and_error_info_reasons() -> TestResult {
        let body = br#"{"error":{"code":403,"status":"PERMISSION_DENIED","details":[
            {"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"SERVICE_DISABLED"},
            {"@type":"type.googleapis.com/google.rpc.Help","reason":"ignored"}]}}"#;
        let ApiError::Status {
            status,
            rpc_status,
            reasons,
        } = error_from(StatusCode::FORBIDDEN, body)
        else {
            return Err("expected a status error".into());
        };
        assert_eq!(status, 403);
        assert_eq!(rpc_status.as_deref(), Some("PERMISSION_DENIED"));
        assert_eq!(reasons, ["SERVICE_DISABLED"]);
        Ok(())
    }

    // The real adapter, without the network: what it refuses to build.
    #[test]
    fn the_client_refuses_a_ca_bundle_without_certificates_and_a_bad_proxy() -> TestResult {
        let no_pem = Network {
            ca_bundle: Some(b"not a certificate".to_vec()),
            proxy: None,
        };
        assert!(matches!(HttpApi::new(&no_pem), Err(NetworkError::CaBundle)));
        let bad_proxy = Network {
            ca_bundle: None,
            proxy: Some("http://user:hunter2@[::1".to_owned()),
        };
        let error = HttpApi::new(&bad_proxy).err();
        assert!(matches!(error, Some(NetworkError::Proxy)), "{error:?}");
        HttpApi::new(&Network::default())?;
        Ok(())
    }
}
