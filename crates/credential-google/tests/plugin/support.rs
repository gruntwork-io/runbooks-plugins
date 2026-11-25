//! The app's side of the pipe, and a fake Google, for the plugin's tests.

use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::future::{self, Future};
use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonschema::{Draft, Registry, Validator};
use reqwest::Url;
use runbooks_credential_google::{
    ApiError, GoogleApi, GooglePlugin, Host, OAuthError, Project, ProjectPage, Secret, Token,
    TokenInfo, TokenRequest,
};
use runbooks_plugin_protocol::PROTOCOL_VERSION;
use runbooks_plugin_transport::{ServeError, serve};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tokio::io::{
    AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, DuplexStream, Lines, duplex,
};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::timeout;

pub(crate) type TestResult<T = ()> = Result<T, Box<dyn Error>>;

pub(crate) const WAIT: Duration = Duration::from_secs(10);
const SCHEMAS: [&str; 2] = ["base.schema.json", "credential.schema.json"];
const ROOT: &str = "json-schema:///";

/// The fixed clock every test runs at: 2027-01-15T08:00:00Z.
pub(crate) const NOW: i64 = 1_800_000_000;

pub(crate) fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(NOW).unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

fn validator(schema: &Value) -> TestResult<Validator> {
    let mut registry = Registry::new();
    for file in SCHEMAS {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../schema")
            .join(file);
        let contents: Value = serde_json::from_str(&fs::read_to_string(path)?)?;
        registry = registry.add(format!("{ROOT}{file}"), contents)?;
    }
    let registry = registry.prepare()?;
    Ok(jsonschema::options()
        .with_draft(Draft::Draft202012)
        .with_registry(&registry)
        .should_validate_formats(true)
        .build(schema)?)
}

pub(crate) fn assert_valid(def: &str, value: &Value) -> TestResult {
    validator(&json!({ "$ref": format!("{ROOT}credential.schema.json#/$defs/{def}") }))?
        .validate(value)
        .map_err(|e| format!("{def}: {e} in {value}"))?;
    Ok(())
}

/// The member of `value` at JSON Pointer `pointer`, or `null` if there is none.
pub(crate) fn at(value: &Value, pointer: &str) -> Value {
    value.pointer(pointer).cloned().unwrap_or(Value::Null)
}

/// A token for the fake to hand out, and what tokeninfo says about it.
#[derive(Clone)]
pub(crate) struct Grant {
    pub access_token: &'static str,
    pub email: Option<&'static str>,
    pub scopes: &'static [&'static str],
    pub expires_at: Option<i64>,
}

#[derive(Default)]
struct GoogleState {
    /// What the token endpoint answers, by refresh token, or `"jwt"` for any
    /// service account assertion.
    tokens: HashMap<String, Result<Grant, OAuthError>>,
    /// What exchanging an authorization code answers: its refresh token.
    codes: HashMap<String, Result<Option<&'static str>, OAuthError>>,
    projects: Vec<Project>,
    /// What `projects.get` answers when it isn't one of `projects`.
    denied: Vec<String>,
    token_requests: Vec<TokenRequest>,
    page_sizes: Vec<u32>,
}

/// Google, in memory.
#[derive(Clone, Default)]
pub(crate) struct Google(Arc<Mutex<GoogleState>>);

impl Google {
    fn with<T>(&self, f: impl FnOnce(&mut GoogleState) -> T) -> T {
        f(&mut self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }

    pub(crate) fn grant(&self, refresh_token: &str, grant: Result<Grant, OAuthError>) -> &Self {
        self.with(|state| state.tokens.insert(refresh_token.to_owned(), grant));
        self
    }

    pub(crate) fn code(
        &self,
        code: &str,
        refresh_token: Result<Option<&'static str>, OAuthError>,
    ) -> &Self {
        self.with(|state| state.codes.insert(code.to_owned(), refresh_token));
        self
    }

    pub(crate) fn project(&self, id: &str, name: &str, state: Option<&str>) -> &Self {
        self.with(|google| {
            google.projects.push(Project {
                id: id.to_owned(),
                display_name: Some(name.to_owned()),
                state: state.map(str::to_owned),
            });
        });
        self
    }

    pub(crate) fn deny(&self, project: &str) -> &Self {
        self.with(|state| state.denied.push(project.to_owned()));
        self
    }

    pub(crate) fn token_requests(&self) -> Vec<TokenRequest> {
        self.with(|state| state.token_requests.clone())
    }

    pub(crate) fn page_sizes(&self) -> Vec<u32> {
        self.with(|state| state.page_sizes.clone())
    }

    fn grant_for(&self, access_token: &Secret) -> Option<Grant> {
        self.with(|state| {
            state
                .tokens
                .values()
                .filter_map(|grant| grant.as_ref().ok())
                .find(|grant| grant.access_token == access_token.expose())
                .cloned()
        })
    }

    fn search_page(
        &self,
        access_token: &Secret,
        page_token: Option<&str>,
        page_size: u32,
    ) -> Result<ProjectPage, ApiError> {
        self.grant_for(access_token)
            .ok_or(ApiError::Refused(OAuthError::InvalidToken))?;
        let start: usize = page_token
            .map_or(Ok(0), str::parse)
            .map_err(|_not_a_number| ApiError::Malformed)?;
        let size = usize::try_from(page_size).map_err(|_too_big| ApiError::Malformed)?;
        self.with(|state| {
            state.page_sizes.push(page_size);
            let end = (start + size).min(state.projects.len());
            Ok(ProjectPage {
                projects: state.projects.get(start..end).unwrap_or_default().to_vec(),
                next_page_token: (end < state.projects.len()).then(|| end.to_string()),
            })
        })
    }

    fn find_project(&self, access_token: &Secret, project_id: &str) -> Result<Project, ApiError> {
        self.grant_for(access_token)
            .ok_or(ApiError::Refused(OAuthError::InvalidToken))?;
        self.with(|state| {
            if let Some(project) = state
                .projects
                .iter()
                .find(|project| project.id == project_id)
            {
                return Ok(project.clone());
            }
            let denied = state.denied.iter().any(|id| id == project_id);
            Err(ApiError::Status {
                status: if denied { 403 } else { 503 },
                rpc_status: Some(
                    if denied {
                        "PERMISSION_DENIED"
                    } else {
                        "UNAVAILABLE"
                    }
                    .to_owned(),
                ),
                reasons: Vec::new(),
            })
        })
    }
}

impl GoogleApi for Google {
    fn token(&self, request: TokenRequest) -> impl Future<Output = Result<Token, ApiError>> + Send {
        let key = match &request {
            TokenRequest::Refresh { refresh_token, .. } => refresh_token.expose().to_owned(),
            TokenRequest::JwtBearer { .. } => "jwt".to_owned(),
            TokenRequest::AuthorizationCode { code, .. } => {
                let exchanged = self.with(|state| {
                    state.token_requests.push(request.clone());
                    state.codes.get(code.expose()).copied()
                });
                return future::ready(match exchanged {
                    Some(Ok(refresh_token)) => Ok(Token {
                        access_token: Secret::new("ya29.from-code"),
                        refresh_token: refresh_token.map(Secret::new),
                    }),
                    Some(Err(error)) => Err(ApiError::Refused(error)),
                    None => Err(ApiError::Refused(OAuthError::InvalidGrant)),
                });
            }
        };
        let answer = self.with(|state| {
            state.token_requests.push(request);
            state.tokens.get(&key).cloned()
        });
        future::ready(match answer {
            Some(Ok(grant)) => Ok(Token {
                access_token: Secret::new(grant.access_token),
                refresh_token: None,
            }),
            Some(Err(error)) => Err(ApiError::Refused(error)),
            None => Err(ApiError::Refused(OAuthError::InvalidGrant)),
        })
    }

    fn token_info(
        &self,
        access_token: &Secret,
    ) -> impl Future<Output = Result<TokenInfo, ApiError>> + Send {
        future::ready(
            self.grant_for(access_token)
                .ok_or(ApiError::Refused(OAuthError::InvalidToken))
                .map(|grant| TokenInfo {
                    email: grant.email.map(str::to_owned),
                    subject: Some("1234567890".to_owned()),
                    scopes: grant
                        .scopes
                        .iter()
                        .map(|scope| (*scope).to_owned())
                        .collect(),
                    expires_at: grant.expires_at,
                }),
        )
    }

    fn search_projects(
        &self,
        access_token: &Secret,
        page_token: Option<&str>,
        page_size: u32,
    ) -> impl Future<Output = Result<ProjectPage, ApiError>> + Send {
        future::ready(self.search_page(access_token, page_token, page_size))
    }

    fn get_project(
        &self,
        access_token: &Secret,
        project_id: &str,
    ) -> impl Future<Output = Result<Project, ApiError>> + Send {
        future::ready(self.find_project(access_token, project_id))
    }
}

/// Runs `openssl` in `dir` with `args` and `input` on standard input. Its
/// seed file, if it keeps one, goes in `dir` too.
fn openssl(dir: &Path, args: &[&str], input: &[u8]) -> TestResult<Output> {
    let mut child = Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .env("HOME", dir)
        .env("RANDFILE", dir.join("rnd"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("openssl has no stdin")?
        .write_all(input)?;
    Ok(child.wait_with_output()?)
}

/// What `openssl` writes to standard output, if it succeeds.
pub(crate) fn openssl_output(dir: &Path, args: &[&str], input: &[u8]) -> TestResult<Vec<u8>> {
    let output = openssl(dir, args, input)?;
    if !output.status.success() {
        return Err(format!(
            "openssl {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(output.stdout)
}

/// A new key from `openssl genpkey`, in PKCS #8 PEM.
fn new_key(algorithm: &[&str]) -> TestResult<String> {
    let dir = tempfile::tempdir()?;
    let pem = openssl_output(dir.path(), &[&["genpkey"], algorithm].concat(), b"")?;
    Ok(String::from_utf8(pem)?)
}

/// A new 2048-bit RSA key, as Google issues.
pub(crate) fn rsa_key() -> TestResult<String> {
    new_key(&["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"])
}

/// A new P-256 key.
pub(crate) fn ec_key() -> TestResult<String> {
    new_key(&["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"])
}

/// Whether openssl finds `signature` an RS256 signature of `message` by the
/// public half of `private_key`.
pub(crate) fn verifies(private_key: &str, message: &[u8], signature: &[u8]) -> TestResult<bool> {
    let dir = tempfile::tempdir()?;
    let public_key = dir.path().join("public.pem");
    let signature_file = dir.path().join("signature");
    fs::write(
        &public_key,
        openssl_output(dir.path(), &["pkey", "-pubout"], private_key.as_bytes())?,
    )?;
    fs::write(&signature_file, signature)?;
    let verify = [
        "dgst",
        "-sha256",
        "-verify",
        public_key.to_str().ok_or("a temp dir is UTF-8")?,
        "-signature",
        signature_file.to_str().ok_or("a temp dir is UTF-8")?,
    ];
    Ok(openssl(dir.path(), &verify, message)?.status.success())
}

/// The S256 PKCE challenge of `verifier`, by openssl.
pub(crate) fn s256(verifier: &str) -> TestResult<String> {
    let dir = tempfile::tempdir()?;
    let digest = openssl_output(
        dir.path(),
        &["dgst", "-sha256", "-binary"],
        verifier.as_bytes(),
    )?;
    Ok(URL_SAFE_NO_PAD.encode(digest))
}

/// The plugin's host: the process environment `env`, and the fixed clock.
pub(crate) fn host(env: &[(&str, &str)]) -> Host {
    Host {
        env: env
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect(),
        now,
    }
}

/// The app: it writes the plugin's input and reads every line it writes.
pub(crate) struct App {
    stdin: Option<DuplexStream>,
    stdout: Lines<BufReader<DuplexStream>>,
    serve: JoinHandle<Result<(), ServeError>>,
    message: Validator,
    next_id: u64,
    /// Every line the plugin wrote, with the method of the request it answered.
    pub transcript: Vec<(String, String)>,
}

impl App {
    pub(crate) fn start(env: &[(&str, &str)], google: &Google) -> TestResult<Self> {
        let google = google.clone();
        Self::serving(GooglePlugin::new(
            host(env),
            Box::new(move |_network| Ok(google.clone())),
        ))
    }

    /// Serves `plugin`, whichever Google it reaches.
    pub(crate) fn serving<A: GoogleApi>(plugin: GooglePlugin<A>) -> TestResult<Self> {
        let (stdin, plugin_stdin) = duplex(1024 * 1024);
        let (plugin_stdout, stdout) = duplex(1024 * 1024);
        let message = json!({ "oneOf": [
            { "$ref": format!("{ROOT}base.schema.json#/$defs/resultResponse") },
            { "$ref": format!("{ROOT}base.schema.json#/$defs/errorResponse") },
            { "$ref": format!("{ROOT}base.schema.json#/$defs/notification") },
        ]});
        Ok(Self {
            stdin: Some(stdin),
            stdout: BufReader::new(stdout).lines(),
            serve: tokio::spawn(serve(plugin, plugin_stdin, plugin_stdout)),
            message: validator(&message)?,
            next_id: 0,
            transcript: Vec::new(),
        })
    }

    /// Sends one request and returns its response, after any notifications.
    pub(crate) async fn call(&mut self, method: &str, params: Value) -> TestResult<Value> {
        let id = self.send(method, params).await?;
        self.response(method, id, WAIT).await
    }

    /// Sends one request and returns its id.
    pub(crate) async fn send(&mut self, method: &str, params: Value) -> TestResult<u64> {
        self.next_id += 1;
        let id = self.next_id;
        let request = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let stdin = self.stdin.as_mut().ok_or("the plugin's input is closed")?;
        stdin.write_all(format!("{request}\n").as_bytes()).await?;
        Ok(id)
    }

    /// The next line the plugin writes, recorded as written for `method`.
    pub(crate) async fn next_message(&mut self, method: &str, wait: Duration) -> TestResult<Value> {
        let line = timeout(wait, self.stdout.next_line())
            .await??
            .ok_or("the plugin's output ended")?;
        let message: Value = serde_json::from_str(&line)?;
        self.message
            .validate(&message)
            .map_err(|e| format!("{line}: {e}"))?;
        self.transcript.push((method.to_owned(), line));
        Ok(message)
    }

    /// The response to request `id`, after any notifications.
    pub(crate) async fn response(
        &mut self,
        method: &str,
        id: u64,
        wait: Duration,
    ) -> TestResult<Value> {
        loop {
            let message = self.next_message(method, wait).await?;
            if at(&message, "/id") == id {
                return Ok(message);
            }
        }
    }

    /// Calls `method` and returns its result, valid for `def`.
    pub(crate) async fn ok(&mut self, method: &str, def: &str, params: Value) -> TestResult<Value> {
        let response = self.call(method, params).await?;
        let result = response
            .get("result")
            .cloned()
            .ok_or_else(|| format!("{method} failed: {response}"))?;
        assert_valid(def, &result)?;
        Ok(result)
    }

    /// Calls `method` and returns its error, asserting its kind.
    pub(crate) async fn error(
        &mut self,
        method: &str,
        params: Value,
        kind: &str,
    ) -> TestResult<Value> {
        let response = self.call(method, params).await?;
        let error = response
            .get("error")
            .cloned()
            .ok_or_else(|| format!("{method} succeeded: {response}"))?;
        assert_eq!(at(&error, "/data/kind"), kind, "{response}");
        Ok(error)
    }

    pub(crate) async fn configure(&mut self, state_dir: &Path) -> TestResult<Value> {
        let params = json!({
            "protocolVersion": PROTOCOL_VERSION,
            "caller": "runbooks/0.31.0",
            "stateDir": state_dir.to_str().ok_or("a temp dir is UTF-8")?,
        });
        self.ok("configure", "configureResult", params).await
    }

    /// Configures the plugin with the block's `settings`.
    pub(crate) async fn configure_with(
        &mut self,
        state_dir: &Path,
        settings: &Value,
    ) -> TestResult {
        let params = configure_params(state_dir, settings)?;
        self.ok("configure", "configureResult", params).await?;
        Ok(())
    }

    pub(crate) async fn close(mut self) -> TestResult<Vec<(String, String)>> {
        self.stdin = None;
        timeout(WAIT, self.serve).await???;
        Ok(self.transcript)
    }
}

/// `configure`'s params, with the block's `settings`.
pub(crate) fn configure_params(state_dir: &Path, settings: &Value) -> TestResult<Value> {
    Ok(json!({
        "protocolVersion": PROTOCOL_VERSION,
        "caller": "runbooks/0.31.0",
        "stateDir": state_dir.to_str().ok_or("a temp dir is UTF-8")?,
        "settings": settings,
    }))
}

/// The value of `name` in an env result, and whether it is sensitive.
pub(crate) fn env_value<'a>(result: &'a Value, name: &str) -> Option<(&'a str, bool, &'a Value)> {
    result["values"]
        .as_array()?
        .iter()
        .find(|value| value["name"] == name)
        .and_then(|value| {
            Some((
                value["value"].as_str()?,
                value["sensitive"].as_bool()?,
                &value["to"],
            ))
        })
}

// Fixtures. No value here is a real credential.

pub(crate) const SA_EMAIL: &str = "deployer@sandbox-1234.iam.gserviceaccount.com";

/// A service account key holding `private_key`, from [`rsa_key`]. Its
/// `token_uri` points elsewhere; the plugin must ignore it.
pub(crate) fn sa_key(private_key: &str) -> String {
    json!({
        "type": "service_account",
        "project_id": "sandbox-1234",
        "private_key_id": "0",
        "private_key": private_key,
        "client_email": SA_EMAIL,
        "client_id": "1",
        "token_uri": "https://token.example.invalid/",
    })
    .to_string()
}

pub(crate) const USER_EMAIL: &str = "someone@example.com";
pub(crate) const USER_REFRESH_TOKEN: &str = "SENTINEL-REFRESH-TOKEN";
pub(crate) const USER_CLIENT_SECRET: &str = "SENTINEL-CLIENT-SECRET";
/// What `gcloud auth application-default login` writes.
pub(crate) const USER_ADC: &str = r#"{"type":"authorized_user","client_id":"client.apps.googleusercontent.com","client_secret":"SENTINEL-CLIENT-SECRET","refresh_token":"SENTINEL-REFRESH-TOKEN","quota_project_id":"quota-5678"}"#;

pub(crate) const CLOUD_PLATFORM: &str = "https://www.googleapis.com/auth/cloud-platform";
pub(crate) const BARE_TOKEN: &str = "ya29.SENTINEL-BARE-TOKEN";

/// A Google that knows the fixtures' credentials and two projects.
pub(crate) fn google() -> Google {
    let google = Google::default();
    google
        .grant(
            "jwt",
            Ok(Grant {
                access_token: "ya29.service-account",
                email: Some(SA_EMAIL),
                scopes: &[CLOUD_PLATFORM],
                expires_at: Some(NOW + 3600),
            }),
        )
        .grant(
            USER_REFRESH_TOKEN,
            Ok(Grant {
                access_token: "ya29.user",
                email: Some(USER_EMAIL),
                scopes: &[
                    CLOUD_PLATFORM,
                    "https://www.googleapis.com/auth/userinfo.email",
                    "openid",
                ],
                expires_at: Some(NOW + 3600),
            }),
        )
        .grant(
            "bare",
            Ok(Grant {
                access_token: BARE_TOKEN,
                email: Some(USER_EMAIL),
                scopes: &[CLOUD_PLATFORM],
                expires_at: Some(NOW + 1800),
            }),
        )
        .project("sandbox-1234", "Sandbox", Some("ACTIVE"))
        .project("quota-5678", "Quota", None);
    google
}

pub(crate) fn sign_in(method: &str, fields: &Value) -> Value {
    json!({"method": method, "fields": fields, "pins": {}, "requirements": []})
}

pub(crate) fn detect(sources: &Value) -> Value {
    json!({"sources": sources, "pins": {}, "requirements": []})
}

/// A gcloud configuration directory at `dir/gcloud`: configurations `dev`
/// (active, with a project, region and zone) and `default`, and `adc` as
/// its Application Default Credentials file if given.
pub(crate) fn gcloud_root(dir: &Path, adc: Option<&str>) -> TestResult<String> {
    let root = dir.join("gcloud");
    let configurations = root.join("configurations");
    fs::create_dir_all(&configurations)?;
    fs::write(
        configurations.join("config_dev"),
        "[core]\naccount = someone@example.com\nproject = sandbox-1234\n\n[compute]\nregion = europe-west1\nzone = europe-west1-b\n",
    )?;
    fs::write(
        configurations.join("config_default"),
        "[core]\nproject = quota-5678\n",
    )?;
    fs::write(root.join("active_config"), "dev\n")?;
    if let Some(adc) = adc {
        fs::write(root.join("application_default_credentials.json"), adc)?;
    }
    Ok(root
        .to_str()
        .ok_or("the temporary directory isn't UTF-8")?
        .to_owned())
}

pub(crate) const OAUTH_CLIENT_ID: &str = "client.apps.googleusercontent.com";

/// Starts an `oauth` sign-in and returns its request id and the URL the
/// person is asked to open.
pub(crate) async fn start_oauth(app: &mut App, params: Value) -> TestResult<(u64, Url)> {
    let id = app.send("signIn", params).await?;
    let prompt = app.next_message("signIn", WAIT).await?;
    assert_eq!(at(&prompt, "/method"), "signIn.prompt", "{prompt}");
    assert_eq!(at(&prompt, "/params/kind"), "openUrl", "{prompt}");
    assert_eq!(at(&prompt, "/params/request"), id, "{prompt}");
    let url = prompt
        .pointer("/params/url")
        .and_then(Value::as_str)
        .ok_or("no url")?;
    Ok((id, Url::parse(url)?))
}

/// The value of the query parameter `name`.
pub(crate) fn query(url: &Url, name: &str) -> Option<String> {
    url.query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}

/// The person's browser, sent back to the redirect URI in the sign-in URL
/// with `query`, as Google's redirect does. Returns the plugin's response.
pub(crate) async fn redirect(sign_in_url: &Url, query_string: &str) -> TestResult<String> {
    let redirect_uri = query(sign_in_url, "redirect_uri").ok_or("no redirect_uri")?;
    let redirect_uri = Url::parse(&redirect_uri)?;
    let host = format!(
        "{}:{}",
        redirect_uri.host_str().ok_or("no host")?,
        redirect_uri.port().ok_or("no port")?
    );
    let path = format!("{}?{query_string}", redirect_uri.path());
    request(
        &host,
        &format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\n\r\n"),
    )
    .await
}

/// Sends `head` to `host` and returns what comes back.
pub(crate) async fn request(host: &str, head: &str) -> TestResult<String> {
    let mut stream = TcpStream::connect(host).await?;
    stream.write_all(head.as_bytes()).await?;
    let mut response = String::new();
    timeout(WAIT, stream.read_to_string(&mut response)).await??;
    Ok(response)
}
