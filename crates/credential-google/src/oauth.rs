//! Google sign-in in the browser: the loopback redirect of RFC 8252 with
//! PKCE, the flow `gcloud auth application-default login` runs, ending in an
//! `authorized_user` document that refreshes itself.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use reqwest::Url;
use runbooks_plugin_protocol::credential::ErrorKind;
use runbooks_plugin_transport::{PluginError, Prompts};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::time::{Instant, sleep, timeout, timeout_at};

use crate::Secret;
use crate::api::{ApiError, GoogleApi, OAuthError, Token, TokenRequest};
use crate::credential::{
    CLOUD_PLATFORM_SCOPE, Document, Origin, api_error, crypto_error, parse_document,
};
use crate::crypto;
use crate::files::{self, ReadError};
use crate::session::invalid_params;

pub(crate) const AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
/// The one path the listener answers.
const CALLBACK_PATH: &str = "/oauth2callback";
/// How long the person has to finish signing in, as the app allowed.
pub(crate) const SIGN_IN_WINDOW: Duration = Duration::from_mins(5);
/// How long one connection may take to send its request.
const REQUEST_WINDOW: Duration = Duration::from_secs(10);
const MAX_REQUEST_HEAD_BYTES: usize = 16 * 1024;
/// Connections served at once; more are closed unanswered.
const MAX_CONNECTIONS: usize = 16;
const MAX_CLIENT_FILE_BYTES: usize = 64 * 1024;

/// What sign-in asks for when the block requires no scopes, as the app did.
pub(crate) const DEFAULT_SCOPES: [&str; 3] = [
    CLOUD_PLATFORM_SCOPE,
    "https://www.googleapis.com/auth/userinfo.email",
    "openid",
];

const CLIENT_FILE_VAR: &str = "GOOGLE_OAUTH_CLIENT_CREDENTIALS";
const CLIENT_ID_VAR: &str = "GOOGLE_OAUTH_CLIENT_ID";
const CLIENT_SECRET_VAR: &str = "GOOGLE_OAUTH_CLIENT_SECRET";
const NO_CLIENT: &str = "Google sign-in needs a Desktop app OAuth client, and this build has none. Give the block's clientId and clientSecret, or clientFile, or set GOOGLE_OAUTH_CLIENT_CREDENTIALS to the client's JSON file.";
const MISSING_SECRET: &str = "Google issues a client secret with every Desktop app client, and a credential signed in without it can't be refreshed.";

/// A Desktop app OAuth client.
#[derive(Clone, Debug)]
pub(crate) struct Client {
    pub(crate) id: String,
    pub(crate) secret: Secret,
}

/// The `oauth` method's client fields.
#[derive(Debug, Default)]
pub(crate) struct ClientFields {
    pub(crate) id: Option<String>,
    pub(crate) secret: Option<Secret>,
    pub(crate) file: Option<String>,
}

/// The OAuth client: the fields' id and secret or client file, else the file
/// `GOOGLE_OAUTH_CLIENT_CREDENTIALS` names, else `GOOGLE_OAUTH_CLIENT_ID` and
/// `GOOGLE_OAUTH_CLIENT_SECRET`. No build carries a client of its own.
///
/// # Errors
///
/// Kind `invalidParams` for no client, half of one, or a client file that
/// can't be read or used.
pub(crate) async fn resolve_client(
    fields: ClientFields,
    env: &HashMap<String, String>,
) -> Result<Client, PluginError> {
    let var = |name: &str| {
        env.get(name)
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
    };
    match fields {
        ClientFields {
            file: Some(_),
            id,
            secret,
        } if id.is_some() || secret.is_some() => Err(invalid_params(
            "Give clientId and clientSecret, or clientFile, not both.",
        )),
        ClientFields {
            id: Some(id),
            secret: Some(secret),
            ..
        } => Ok(Client { id, secret }),
        ClientFields {
            id: Some(_),
            secret: None,
            ..
        } => Err(invalid_params(format!(
            "clientId was given without clientSecret. {MISSING_SECRET}"
        ))),
        ClientFields {
            id: None,
            secret: Some(_),
            ..
        } => Err(invalid_params("clientSecret was given without clientId.")),
        ClientFields {
            file: Some(file), ..
        } => read_client_file(&file, "clientFile", env).await,
        ClientFields {
            id: None,
            secret: None,
            file: None,
        } => {
            if let Some(file) = var(CLIENT_FILE_VAR) {
                return read_client_file(file, CLIENT_FILE_VAR, env).await;
            }
            match (var(CLIENT_ID_VAR), var(CLIENT_SECRET_VAR)) {
                (Some(id), Some(secret)) => Ok(Client {
                    id: id.to_owned(),
                    secret: Secret::new(secret),
                }),
                (Some(_), None) => Err(invalid_params(format!(
                    "{CLIENT_ID_VAR} is set without {CLIENT_SECRET_VAR}. {MISSING_SECRET}"
                ))),
                (None, _) => Err(invalid_params(NO_CLIENT)),
            }
        }
    }
}

/// Reads a client JSON file as Google Cloud Console downloads it. A leading
/// `~` is the home directory in `env`.
async fn read_client_file(
    path: &str,
    what: &str,
    env: &HashMap<String, String>,
) -> Result<Client, PluginError> {
    let path = expand_home(path.trim(), env).ok_or_else(|| {
        invalid_params(format!(
            "{what} starts with ~, but no home directory is set to expand it"
        ))
    })?;
    if !path.is_absolute() {
        return Err(invalid_params(format!(
            "{what} must be an absolute path, not {}",
            path.display()
        )));
    }
    let text = files::read_text(&path, MAX_CLIENT_FILE_BYTES)
        .await
        .map_err(|error: ReadError| {
            invalid_params(format!("{what} {}: the file {error}", path.display()))
        })?;
    parse_client(&text).map_err(|problem| {
        invalid_params(format!(
            "{what} {} {problem}. Download a Desktop app client's JSON from the Google Cloud console.",
            path.display()
        ))
    })
}

fn expand_home(path: &str, env: &HashMap<String, String>) -> Option<PathBuf> {
    let rest = match path {
        "~" => "",
        _ => match path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")) {
            Some(rest) => rest,
            None => return Some(PathBuf::from(path)),
        },
    };
    let home = ["HOME", "USERPROFILE"]
        .iter()
        .find_map(|name| env.get(*name).filter(|home| !home.trim().is_empty()))?;
    Some(PathBuf::from(home).join(rest))
}

/// The client in a client JSON file. Its problems never quote it.
fn parse_client(text: &str) -> Result<Client, &'static str> {
    let value: Value = serde_json::from_str(text).map_err(|_syntax| "is not JSON")?;
    let Value::Object(file) = value else {
        return Err("is not a JSON object");
    };
    let installed = match (file.get("installed"), file.contains_key("web")) {
        (Some(Value::Object(installed)), _) => installed,
        (None, true) => {
            return Err("is a Web application client; sign-in needs a Desktop app client");
        }
        (_, _) => return Err("has no \"installed\" client"),
    };
    let field = |name: &str| {
        installed
            .get(name)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    };
    let id = field("client_id").ok_or("is missing installed.client_id")?;
    let secret = field("client_secret").ok_or("is missing installed.client_secret")?;
    Ok(Client {
        id: id.to_owned(),
        secret: Secret::new(secret),
    })
}

/// Signs in through the person's browser and returns the `authorized_user`
/// document Google's answer makes.
///
/// # Errors
///
/// `timedOut` if no sign-in arrives in [`SIGN_IN_WINDOW`], `cancelled` if the
/// person declines, and the token exchange's failure as an error kind.
pub(crate) async fn sign_in<A: GoogleApi>(
    api: &A,
    client: &Client,
    scopes: &[String],
    prompts: &Prompts,
) -> Result<Document, PluginError> {
    let secrets = crypto::flow_secrets().map_err(|error| crypto_error(&error))?;
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(|error| listener_error(&error))?;
    let port = listener
        .local_addr()
        .map_err(|error| listener_error(&error))?
        .port();
    // 127.0.0.1, not localhost, which may resolve to ::1.
    let host = format!("127.0.0.1:{port}");
    let redirect_uri = format!("http://{host}{CALLBACK_PATH}");
    let mut url = Url::parse(AUTH_URL).map_err(|error| {
        PluginError::new(
            ErrorKind::Internal,
            format!("Google's sign-in URL doesn't parse: {error}"),
        )
    })?;
    url.query_pairs_mut()
        .append_pair("client_id", &client.id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("scope", &scopes.join(" "))
        // offline and consent are what make Google return a refresh token.
        .append_pair("access_type", "offline")
        .append_pair("prompt", "consent")
        .append_pair("code_challenge", &secrets.challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", &secrets.state);

    let deadline = Instant::now() + SIGN_IN_WINDOW;
    let mut callbacks = Callbacks::listen(listener, host);
    prompts.open_url(url.as_str(), None).await?;
    loop {
        let Some(callback) = callbacks.next(deadline).await else {
            return Err(PluginError::new(
                ErrorKind::TimedOut,
                "The Google sign-in window closed after 5 minutes. Sign in again.",
            ));
        };
        let state = callback.param("state").unwrap_or_default();
        if !crypto::same(state.as_bytes(), secrets.state.as_bytes()) {
            // Only a request that knows the state may end the sign-in.
            callback.respond(Page::BadRequest).await;
            continue;
        }
        if let Some(error) = callback.param("error") {
            let refused = if error == "access_denied" {
                PluginError::new(ErrorKind::Cancelled, "Google sign-in was declined.")
            } else {
                PluginError::new(
                    ErrorKind::AccessDenied,
                    format!("Google refused the sign-in ({}).", error_code(error)),
                )
            };
            callback.respond(Page::NotSignedIn).await;
            return Err(refused);
        }
        let Some(code) = callback.param("code").map(Secret::new) else {
            callback.respond(Page::BadRequest).await;
            return Err(PluginError::new(
                ErrorKind::AccessDenied,
                "Google's redirect carried no authorization code. Sign in again.",
            ));
        };
        let exchanged = api
            .token(TokenRequest::AuthorizationCode {
                client_id: client.id.clone(),
                client_secret: client.secret.clone(),
                code,
                code_verifier: secrets.verifier.clone(),
                redirect_uri: redirect_uri.clone(),
            })
            .await;
        let document = match exchanged {
            Ok(Token {
                refresh_token: Some(refresh_token),
                ..
            }) => authorized_user(client, &refresh_token),
            Ok(Token {
                refresh_token: None,
                ..
            }) => Err(PluginError::new(
                ErrorKind::AccessDenied,
                "Google returned no refresh token. Remove Runbooks' access at https://myaccount.google.com/permissions and sign in again.",
            )),
            Err(ApiError::Refused(OAuthError::InvalidGrant)) => Err(PluginError::new(
                ErrorKind::Expired,
                "Google's sign-in code expired before it could be used. Sign in again.",
            )),
            Err(error) => Err(api_error(&error, Origin::Adc)),
        };
        callback
            .respond(if document.is_ok() {
                Page::SignedIn
            } else {
                Page::NotSignedIn
            })
            .await;
        return document;
    }
}

fn listener_error(error: &std::io::Error) -> PluginError {
    PluginError::new(
        ErrorKind::Internal,
        format!("Google sign-in could not listen on 127.0.0.1 for its redirect: {error}"),
    )
}

/// An OAuth error code is a lower case identifier; anything else isn't echoed.
fn error_code(code: &str) -> &str {
    let identifier = code.len() <= 64
        && code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_');
    if identifier { code } else { "an unknown error" }
}

fn authorized_user(client: &Client, refresh_token: &Secret) -> Result<Document, PluginError> {
    let document = json!({
        "type": "authorized_user",
        "client_id": client.id,
        "client_secret": client.secret.expose(),
        "refresh_token": refresh_token.expose(),
    });
    parse_document(document.to_string()).map_err(|error| {
        PluginError::new(
            ErrorKind::Internal,
            format!("The signed-in credential {error}"),
        )
    })
}

/// The pages the browser is shown. None carries anything from the request.
#[derive(Clone, Copy)]
enum Page {
    SignedIn,
    NotSignedIn,
    BadRequest,
    NotFound,
}

impl Page {
    const fn status(self) -> &'static str {
        match self {
            Self::SignedIn | Self::NotSignedIn => "200 OK",
            Self::BadRequest => "400 Bad Request",
            Self::NotFound => "404 Not Found",
        }
    }

    const fn body(self) -> &'static str {
        match self {
            Self::SignedIn => {
                "<!doctype html><meta charset=utf-8><title>Signed in</title><p>You're signed in to Google Cloud. You can close this tab and return to Runbooks."
            }
            Self::NotSignedIn => {
                "<!doctype html><meta charset=utf-8><title>Not signed in</title><p>Google sign-in did not finish. Return to Runbooks to see why."
            }
            Self::BadRequest | Self::NotFound => {
                "<!doctype html><meta charset=utf-8><title>Not found</title><p>There is nothing here."
            }
        }
    }
}

/// A request that looks like Google's redirect, with its query, waiting for
/// its page.
struct Callback {
    params: Vec<(String, String)>,
    stream: TcpStream,
}

impl Callback {
    fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    async fn respond(mut self, page: Page) {
        respond(&mut self.stream, page).await;
    }
}

/// The listener's connections, each served on its own task.
struct Callbacks {
    received: mpsc::Receiver<Callback>,
    /// Dropping it stops the listener and every connection it serves.
    _listener: JoinSet<()>,
}

impl Callbacks {
    fn listen(listener: TcpListener, host: String) -> Self {
        let (send, received) = mpsc::channel(MAX_CONNECTIONS);
        let mut tasks = JoinSet::new();
        // A block, as the set's type can't name `!` on stable Rust.
        tasks.spawn(async move {
            accept(listener, host, send).await;
        });
        Self {
            received,
            _listener: tasks,
        }
    }

    async fn next(&mut self, deadline: Instant) -> Option<Callback> {
        timeout_at(deadline, self.received.recv())
            .await
            .ok()
            .flatten()
    }
}

async fn accept(listener: TcpListener, host: String, send: mpsc::Sender<Callback>) -> ! {
    let mut connections = JoinSet::new();
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _peer)) => stream,
            Err(_accept_failed) => {
                // Out of file descriptors, say: let some close.
                sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        while connections.try_join_next().is_some() {}
        if connections.len() < MAX_CONNECTIONS {
            connections.spawn(connection(stream, host.clone(), send.clone()));
        }
    }
}

async fn connection(mut stream: TcpStream, host: String, send: mpsc::Sender<Callback>) {
    let Ok(Some(head)) = timeout(REQUEST_WINDOW, read_head(&mut stream)).await else {
        return;
    };
    match callback_params(&head, &host) {
        Ok(params) => {
            // The sign-in has ended if no one is receiving.
            let _ended = send.send(Callback { params, stream }).await;
        }
        Err(page) => respond(&mut stream, page).await,
    }
}

/// The request line and headers, without the blank line that ends them.
async fn read_head(stream: &mut TcpStream) -> Option<String> {
    let mut head = Vec::new();
    let mut chunk = [0_u8; 2048];
    loop {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        head.extend_from_slice(chunk.get(..read)?);
        if let Some(end) = head.windows(4).position(|window| window == b"\r\n\r\n") {
            head.truncate(end);
            return String::from_utf8(head).ok();
        }
        if head.len() > MAX_REQUEST_HEAD_BYTES {
            return None;
        }
    }
}

/// The query of a request that could be Google's redirect arriving in the
/// person's browser, or the page that refuses it.
///
/// Any page the person has open can send requests to a loopback port, so
/// only a top-level GET navigation to the published host and path gets
/// through: a DNS-rebound request carries another host, and an `<img>` or
/// `fetch` probe sends other `Sec-Fetch-*` values. Those headers are checked
/// only when present, so an older browser can still sign in.
fn callback_params(head: &str, host: &str) -> Result<Vec<(String, String)>, Page> {
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Page::BadRequest);
    };
    if !version.starts_with("HTTP/1.") {
        return Err(Page::BadRequest);
    }
    if method != "GET" {
        return Err(Page::NotFound);
    }
    let (mut hosts, mut dests, mut modes) = (Vec::new(), Vec::new(), Vec::new());
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(Page::BadRequest);
        };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "host" => hosts.push(value),
            "sec-fetch-dest" => dests.push(value),
            "sec-fetch-mode" => modes.push(value),
            _ => {}
        }
    }
    let plausible = matches!(hosts.as_slice(), [only] if only.eq_ignore_ascii_case(host))
        && matches!(dests.as_slice(), [] | ["document"])
        && matches!(modes.as_slice(), [] | ["navigate"]);
    if !plausible {
        return Err(Page::NotFound);
    }
    // An absolute-form target carries its own host, which must match too.
    let base = Url::parse(&format!("http://{host}/")).map_err(|_bad| Page::BadRequest)?;
    let url = base.join(target).map_err(|_bad| Page::BadRequest)?;
    let same_origin =
        url.scheme() == "http" && url.host_str() == base.host_str() && url.port() == base.port();
    if !same_origin || url.path() != CALLBACK_PATH {
        return Err(Page::NotFound);
    }
    Ok(url.query_pairs().into_owned().collect())
}

async fn respond(stream: &mut TcpStream, page: Page) {
    let body = page.body();
    let response = format!(
        "HTTP/1.1 {}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nContent-Security-Policy: default-src 'none'\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n{body}",
        page.status(),
        body.len()
    );
    // The browser may be gone; the sign-in's outcome doesn't depend on it.
    let _unsent = timeout(REQUEST_WINDOW, async {
        stream.write_all(response.as_bytes()).await?;
        stream.shutdown().await
    })
    .await;
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::error::Error;
    use std::path::PathBuf;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::{sleep, timeout};

    use super::{
        Callbacks, MAX_CONNECTIONS, Page, callback_params, error_code, expand_home, parse_client,
        read_client_file, read_head,
    };

    type TestResult = Result<(), Box<dyn Error>>;

    const HOST: &str = "127.0.0.1:4567";
    /// Well under the listener's 10-second request window.
    const WAIT: Duration = Duration::from_secs(5);

    fn head(lines: &[&str]) -> String {
        lines.join("\r\n")
    }

    #[test]
    fn a_browser_navigation_to_the_callback_gets_through() {
        let params = callback_params(
            &head(&[
                "GET /oauth2callback?state=s&code=4%2F0abc HTTP/1.1",
                "Host: 127.0.0.1:4567",
                "Sec-Fetch-Dest: document",
                "Sec-Fetch-Mode: navigate",
            ]),
            HOST,
        );
        assert_eq!(
            params.ok(),
            Some(vec![
                ("state".to_owned(), "s".to_owned()),
                ("code".to_owned(), "4/0abc".to_owned())
            ])
        );
        let curl = head(&[
            "GET /oauth2callback?code=c HTTP/1.0",
            "host: 127.0.0.1:4567",
        ]);
        assert!(callback_params(&curl, HOST).is_ok(), "no fetch metadata");
    }

    #[test]
    fn probes_and_rebinding_are_refused() {
        for (lines, page) in [
            (
                vec!["POST /oauth2callback HTTP/1.1", "Host: 127.0.0.1:4567"],
                Page::NotFound,
            ),
            (
                vec!["GET /oauth2callback HTTP/1.1", "Host: evil.example:4567"],
                Page::NotFound,
            ),
            (vec!["GET /oauth2callback HTTP/1.1"], Page::NotFound),
            (
                vec![
                    "GET /oauth2callback HTTP/1.1",
                    "Host: 127.0.0.1:4567",
                    "Host: 127.0.0.1:4567",
                ],
                Page::NotFound,
            ),
            (
                vec![
                    "GET /oauth2callback HTTP/1.1",
                    "Host: 127.0.0.1:4567",
                    "Sec-Fetch-Dest: image",
                ],
                Page::NotFound,
            ),
            (
                vec![
                    "GET /oauth2callback HTTP/1.1",
                    "Host: 127.0.0.1:4567",
                    "Sec-Fetch-Mode: no-cors",
                ],
                Page::NotFound,
            ),
            (
                vec!["GET /favicon.ico HTTP/1.1", "Host: 127.0.0.1:4567"],
                Page::NotFound,
            ),
            (
                vec![
                    "GET http://evil.example/oauth2callback HTTP/1.1",
                    "Host: 127.0.0.1:4567",
                ],
                Page::NotFound,
            ),
            (
                vec![
                    "GET //evil.example/oauth2callback HTTP/1.1",
                    "Host: 127.0.0.1:4567",
                ],
                Page::NotFound,
            ),
            (
                vec![
                    "GET http://evil.example:4567/oauth2callback HTTP/1.1",
                    "Host: 127.0.0.1:4567",
                ],
                Page::NotFound,
            ),
            (
                vec!["GET /oauth2callback", "Host: 127.0.0.1:4567"],
                Page::BadRequest,
            ),
            (
                vec!["GET /oauth2callback HTTP/1.1", "not a header"],
                Page::BadRequest,
            ),
        ] {
            let refused = callback_params(&head(&lines), HOST).err();
            assert!(
                matches!(
                    (refused, page),
                    (Some(Page::NotFound), Page::NotFound)
                        | (Some(Page::BadRequest), Page::BadRequest)
                ),
                "{lines:?}"
            );
        }
        let absolute = head(&[
            "GET http://127.0.0.1:4567/oauth2callback?code=c HTTP/1.1",
            "Host: 127.0.0.1:4567",
        ]);
        assert!(callback_params(&absolute, HOST).is_ok());
    }

    #[test]
    fn a_client_file_is_a_desktop_client_with_its_secret() {
        let client = parse_client(r#"{"installed":{"client_id":"id.apps","client_secret":"s"}}"#);
        assert_eq!(
            client.map(|client| client.id).ok(),
            Some("id.apps".to_owned())
        );
        for (text, problem) in [
            ("{", "is not JSON"),
            ("[]", "is not a JSON object"),
            (
                r#"{"web":{"client_id":"a"}}"#,
                "is a Web application client; sign-in needs a Desktop app client",
            ),
            (
                r#"{"installed":{"client_id":"a"}}"#,
                "is missing installed.client_secret",
            ),
            (
                r#"{"installed":{"client_secret":"a"}}"#,
                "is missing installed.client_id",
            ),
            ("{}", "has no \"installed\" client"),
        ] {
            assert_eq!(parse_client(text).err(), Some(problem), "{text}");
        }
    }

    #[test]
    fn a_tilde_is_the_home_directory_given() {
        let env: HashMap<String, String> = [("HOME".to_owned(), "/home/a".to_owned())].into();
        assert_eq!(
            expand_home("~/client.json", &env),
            Some(PathBuf::from("/home/a").join("client.json"))
        );
        assert_eq!(expand_home("~", &env), Some(PathBuf::from("/home/a")));
        assert_eq!(
            expand_home("/etc/client.json", &HashMap::new()),
            Some(PathBuf::from("/etc/client.json"))
        );
        assert_eq!(expand_home("~/client.json", &HashMap::new()), None);
        assert_eq!(
            expand_home("~user/client.json", &env),
            Some(PathBuf::from("~user/client.json"))
        );
    }

    #[test]
    fn only_an_oauth_error_code_is_echoed() {
        assert_eq!(error_code("invalid_scope"), "invalid_scope");
        assert_eq!(error_code("<script>"), "an unknown error");
    }

    /// A client JSON file may be 64 KiB, whitespace and all; one byte more
    /// is refused.
    #[tokio::test]
    async fn a_client_file_may_be_as_large_as_64_kib() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("client.json");
        let client = r#"{"installed":{"client_id":"id.apps","client_secret":"s"}}"#;
        let mut text = client.to_owned();
        text.push_str(&" ".repeat(64 * 1024 - client.len()));
        std::fs::write(&path, &text)?;
        let path_text = path.to_str().ok_or("the path is not UTF-8")?;
        let read = read_client_file(path_text, "clientFile", &HashMap::new()).await;
        assert_eq!(
            read.map(|client| client.id).ok(),
            Some("id.apps".to_owned())
        );

        text.push(' ');
        std::fs::write(&path, &text)?;
        let refused = read_client_file(path_text, "clientFile", &HashMap::new())
            .await
            .err()
            .ok_or("a file over 64 KiB was read")?;
        assert!(
            refused.message().contains("is larger than 65536 bytes"),
            "{}",
            refused.message()
        );
        Ok(())
    }

    /// Both ends of one loopback connection: the browser's and the
    /// listener's.
    async fn connection() -> std::io::Result<(TcpStream, TcpStream)> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let browser = TcpStream::connect(listener.local_addr()?).await?;
        let (served, _peer) = listener.accept().await?;
        Ok((browser, served))
    }

    /// A request head may be 16 KiB, even when its end arrives in a later
    /// read; one byte more is dropped without waiting for the end.
    #[tokio::test]
    async fn a_request_head_may_be_as_long_as_16_kib() -> TestResult {
        let (mut browser, mut served) = connection().await?;
        let reading = tokio::spawn(async move { read_head(&mut served).await });
        browser.write_all(&vec![b'a'; 16 * 1024]).await?;
        // Long enough for the listener to read all of it before the end.
        sleep(Duration::from_millis(100)).await;
        browser.write_all(b"\r\n\r\n").await?;
        let head = timeout(WAIT, reading).await??;
        assert_eq!(head.map(|head| head.len()), Some(16 * 1024));

        let (mut browser, mut served) = connection().await?;
        let reading = tokio::spawn(async move { read_head(&mut served).await });
        browser.write_all(&vec![b'a'; 16 * 1024 + 1]).await?;
        assert_eq!(timeout(WAIT, reading).await??, None);
        Ok(())
    }

    /// With [`MAX_CONNECTIONS`] open, the next connection is closed at once
    /// rather than held for its request.
    #[tokio::test]
    async fn a_connection_past_the_limit_is_closed_unanswered() -> TestResult {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let address = listener.local_addr()?;
        let _callbacks = Callbacks::listen(listener, address.to_string());
        let mut open = Vec::new();
        for _ in 0..MAX_CONNECTIONS {
            open.push(TcpStream::connect(address).await?);
        }
        let mut extra = TcpStream::connect(address).await?;
        let read = timeout(WAIT, extra.read(&mut [0_u8; 1])).await?;
        assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");

        // A connection within the limit is still served.
        let first = open.first_mut().ok_or("no connection")?;
        let request = format!("GET /favicon.ico HTTP/1.1\r\nHost: {address}\r\n\r\n");
        first.write_all(request.as_bytes()).await?;
        let mut answer = String::new();
        timeout(WAIT, first.read_to_string(&mut answer)).await??;
        assert!(answer.starts_with("HTTP/1.1 404"), "{answer}");
        Ok(())
    }
}
