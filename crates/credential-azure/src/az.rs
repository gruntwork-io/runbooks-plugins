//! The one owner of the Azure CLI. The plugin asks [`Az`] in Azure's terms;
//! [`AzCli`] answers by running `az` as a child process with the sign-in's
//! own config directory, and turns its output into those terms.

use std::collections::{BTreeSet, VecDeque};
use std::ffi::OsString;
use std::fmt;
use std::future::Future;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use runbooks_plugin_protocol::credential::ErrorKind;
use runbooks_plugin_transport::PluginError;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::oneshot;

use crate::claims::{Principal, principal_of_token};
use crate::ids::{ObjectId, SubscriptionId, TenantId, TenantRef};
use crate::process_tree::{Killer, ProcessTree, STOP_GRACE};
use crate::service_principal::{Credential, Secret, ServicePrincipal};

/// Where the error for a missing `az` sends the person to install it.
pub const AZ_INSTALL_URL: &str = "https://learn.microsoft.com/cli/azure/install-azure-cli";

/// How long one `az` call that needs no person may take.
pub const AZ_TIMEOUT: Duration = Duration::from_secs(60);

/// How long an interactive `az login` may wait for the person.
pub const LOGIN_TIMEOUT: Duration = Duration::from_mins(15);

/// The most `az` may print to standard output: `az account list` for a
/// large directory is a few hundred kilobytes.
const MAX_STDOUT_BYTES: usize = 16 * 1024 * 1024;

/// How much of `az`'s standard error is kept to explain a failure: its last
/// lines, up to this many bytes. The rest is read and dropped.
const MAX_STDERR_BYTES: usize = 64 * 1024;

/// Settings for every `az` the plugin runs: no prompts for a new login
/// experience, no colour, no telemetry, no survey, only errors on stderr.
const QUIET: [(&str, &str); 5] = [
    ("AZURE_CORE_LOGIN_EXPERIENCE_V2", "off"),
    ("AZURE_CORE_NO_COLOR", "true"),
    ("AZURE_CORE_ONLY_SHOW_ERRORS", "true"),
    ("AZURE_CORE_COLLECT_TELEMETRY", "false"),
    ("AZURE_CORE_SURVEY_MESSAGE", "false"),
];

const TENANTS_URL: &str = "https://management.azure.com/tenants?api-version=2022-12-01";

/// The config directory one sign-in's `az` runs with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AzDir {
    /// `AZURE_CONFIG_DIR`.
    pub config: PathBuf,
    /// `AZURE_EXTENSION_DIR`. `None` leaves `az` its default, a
    /// `cliextensions` directory inside `config`.
    pub extensions: Option<PathBuf>,
}

/// How an `az login` with a person signs them in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interactive {
    /// `az login`, which opens a browser.
    Browser,
    /// `az login --use-device-code`.
    DeviceCode,
}

/// Which subscription list [`Az::accounts`] reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Listing {
    /// The one `az` saved when it signed in.
    Saved,
    /// Fetched again from Azure first (`--refresh`). `az` keeps an
    /// account's saved list when fetching it fails.
    Refreshed,
}

/// Where the person enters a device code, and the code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceCode {
    /// The page to open.
    pub url: String,
    /// The code to enter there.
    pub code: String,
}

/// A subscription, as `az account list` has it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Subscription {
    /// Its id.
    pub id: SubscriptionId,
    /// Its name, or its id when `az` gives none.
    pub name: String,
    /// The tenant it belongs to.
    pub tenant_id: TenantId,
}

/// What a login can use, as `az account list --all` has it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Accounts {
    /// Enabled subscriptions.
    pub subscriptions: Vec<Subscription>,
    /// Every tenant the login holds, including those with no subscription.
    pub tenants: Vec<TenantId>,
}

/// A tenant the login can see.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tenant {
    /// Its id.
    pub id: TenantId,
    /// Its display name, or else its default domain.
    pub name: Option<String>,
}

/// The Azure CLI, in Azure's terms. Every call names the config directory
/// of the sign-in it is about. Dropping a call's future stops its `az`.
pub trait Az: Send + Sync + 'static {
    /// # Errors
    ///
    /// `toolMissing` when there is no `az` to run: the error every other
    /// call answers.
    fn installed(&self) -> Result<(), PluginError>;

    /// Signs in to `dir`. A device code is sent on `device_code` as soon as
    /// `az` prints it.
    fn login(
        &self,
        dir: &AzDir,
        how: Interactive,
        tenant: Option<&TenantRef>,
        device_code: oneshot::Sender<DeviceCode>,
    ) -> impl Future<Output = Result<(), PluginError>> + Send;

    /// Signs `principal` in to `dir`, with no person involved.
    fn login_service_principal(
        &self,
        dir: &AzDir,
        principal: &ServicePrincipal,
    ) -> impl Future<Output = Result<(), PluginError>> + Send;

    /// Who `dir` is signed in as, in `tenant` or in its default tenant.
    fn principal(
        &self,
        dir: &AzDir,
        tenant: Option<&TenantRef>,
    ) -> impl Future<Output = Result<Principal, PluginError>> + Send;

    /// The subscriptions and tenants `dir`'s login can use, from `listing`.
    fn accounts(
        &self,
        dir: &AzDir,
        listing: Listing,
    ) -> impl Future<Output = Result<Accounts, PluginError>> + Send;

    /// Every tenant the login can see, including those it is a guest in.
    fn tenants(&self, dir: &AzDir)
    -> impl Future<Output = Result<Vec<Tenant>, PluginError>> + Send;

    /// Makes `subscription` the default for a bare `az` in `dir`.
    fn set_subscription(
        &self,
        dir: &AzDir,
        subscription: &SubscriptionId,
    ) -> impl Future<Output = Result<(), PluginError>> + Send;

    /// The names, in lower case, of the roles `principal` holds at `scope`:
    /// assigned there or above it, to it or to one of its groups.
    fn role_names(
        &self,
        dir: &AzDir,
        scope: &str,
        principal: &ObjectId,
    ) -> impl Future<Output = Result<BTreeSet<String>, PluginError>> + Send;
}

/// [`Az`] by running the Azure CLI.
#[derive(Clone)]
pub struct AzCli {
    /// `None` when `main` found no `az` on `PATH`.
    program: Option<PathBuf>,
    env: Vec<(OsString, OsString)>,
    killer: Killer,
}

/// The environment's names only: its values may hold the person's secrets.
impl fmt::Debug for AzCli {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AzCli")
            .field("program", &self.program)
            .field(
                "env",
                &self.env.iter().map(|(name, _)| name).collect::<Vec<_>>(),
            )
            .field("killer", &self.killer)
            .finish()
    }
}

impl AzCli {
    /// Runs `program` with exactly `env`, plus the sign-in's config
    /// directory and settings that keep `az` quiet. `killer` ends a call's
    /// `az`, and what it started, when the call times out or is dropped.
    #[must_use]
    pub const fn new(
        program: Option<PathBuf>,
        env: Vec<(OsString, OsString)>,
        killer: Killer,
    ) -> Self {
        Self {
            program,
            env,
            killer,
        }
    }

    async fn run(
        &self,
        dir: &AzDir,
        command: &str,
        args: &[&str],
        timeout: Duration,
        input: Option<&Secret>,
        mut on_stderr_line: impl FnMut(&str) + Send,
    ) -> Result<Vec<u8>, PluginError> {
        let Some(program) = &self.program else {
            return Err(az_missing());
        };
        let mut child = Command::new(program);
        child
            .args(args)
            .arg("--only-show-errors")
            .env_clear()
            .envs(self.env.iter().map(|(key, value)| (key, value)))
            .envs(QUIET)
            .env("AZURE_CONFIG_DIR", &dir.config)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(extensions) = &dir.extensions {
            child.env("AZURE_EXTENSION_DIR", extensions);
        }
        let mut tree = ProcessTree::spawn(&mut child, self.killer.clone()).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                az_missing()
            } else {
                PluginError::new(
                    ErrorKind::Internal,
                    format!("could not start {}: {error}", program.display()),
                )
            }
        })?;
        let child = tree.child();
        let (stdin, stdout, stderr) =
            (child.stdin.take(), child.stdout.take(), child.stderr.take());
        let write = async {
            if let (Some(mut stdin), Some(input)) = (stdin, input) {
                // An az that exits without reading it says why on stderr.
                let _unread = stdin.write_all(input.expose().as_bytes()).await;
                // Dropping stdin closes it: az reads to the end.
            }
        };
        let finished = tokio::time::timeout(timeout, async {
            let ((), stdout, stderr) = tokio::join!(
                write,
                read_capped(stdout),
                read_stderr(stderr, &mut on_stderr_line)
            );
            // Reaped once its output has closed: until then, a process az
            // left holding that output is still in the group a stop ends.
            (stdout, stderr, tree.child().wait().await)
        })
        .await;
        let Ok((stdout, stderr, status)) = finished else {
            tree.stop(STOP_GRACE).await;
            return Err(PluginError::new(
                ErrorKind::TimedOut,
                format!(
                    "{command} did not finish within {} seconds",
                    timeout.as_secs()
                ),
            ));
        };
        let read_failed = |error: std::io::Error| {
            PluginError::new(
                ErrorKind::Internal,
                format!("reading the output of {command}: {error}"),
            )
        };
        let (stdout, stderr, status) = (
            stdout.map_err(read_failed)?,
            stderr.map_err(read_failed)?,
            status.map_err(read_failed)?,
        );
        if !status.success() {
            let stderr: Vec<String> = match input {
                Some(secret) => stderr.iter().map(|line| secret.redact(line)).collect(),
                None => stderr,
            };
            return Err(failure(command, &stderr));
        }
        stdout.ok_or_else(|| {
            PluginError::new(
                ErrorKind::Internal,
                format!("{command} printed more than {MAX_STDOUT_BYTES} bytes"),
            )
        })
    }

    async fn run_json<T: DeserializeOwned>(
        &self,
        dir: &AzDir,
        command: &str,
        args: &[&str],
    ) -> Result<T, PluginError> {
        let mut args = args.to_vec();
        args.extend(["-o", "json"]);
        let stdout = self
            .run(dir, command, &args, AZ_TIMEOUT, None, |_| ())
            .await?;
        // serde's message can quote what it refused, which may be a token.
        serde_json::from_slice(&stdout).map_err(|_refused| {
            PluginError::new(
                ErrorKind::Internal,
                format!("{command} printed something other than the JSON it documents"),
            )
        })
    }
}

impl Az for AzCli {
    fn installed(&self) -> Result<(), PluginError> {
        self.program.as_ref().map(drop).ok_or_else(az_missing)
    }

    async fn login(
        &self,
        dir: &AzDir,
        how: Interactive,
        tenant: Option<&TenantRef>,
        device_code: oneshot::Sender<DeviceCode>,
    ) -> Result<(), PluginError> {
        let mut args = vec!["login", "--allow-no-subscriptions", "-o", "none"];
        if how == Interactive::DeviceCode {
            args.push("--use-device-code");
        }
        if let Some(tenant) = tenant {
            args.extend(["--tenant", tenant.as_str()]);
        }
        let mut device_code = Some(device_code);
        self.run(dir, "az login", &args, LOGIN_TIMEOUT, None, |line| {
            if let Some(code) = parse_device_code(line)
                && let Some(sender) = device_code.take()
            {
                // The receiver is gone only if the sign-in was cancelled.
                let _cancelled = sender.send(code);
            }
        })
        .await
        .map(drop)
    }

    /// The secret goes on standard input (`--password=@-`), never in the
    /// arguments, where other processes can read it.
    async fn login_service_principal(
        &self,
        dir: &AzDir,
        principal: &ServicePrincipal,
    ) -> Result<(), PluginError> {
        let mut args = vec![
            "login",
            "--service-principal",
            "--username",
            principal.client_id.as_str(),
            "--tenant",
            principal.tenant.as_str(),
            "--allow-no-subscriptions",
            "-o",
            "none",
        ];
        let command = "az login --service-principal";
        match &principal.credential {
            Credential::Secret(secret) => {
                args.push("--password=@-");
                self.run(dir, command, &args, AZ_TIMEOUT, Some(secret), |_| ())
                    .await
            }
            Credential::Certificate(path) => {
                let path = path.to_str().ok_or_else(|| {
                    PluginError::new(
                        ErrorKind::InvalidParams,
                        "the certificate's path is not valid Unicode",
                    )
                })?;
                args.extend(["--certificate", path]);
                self.run(dir, command, &args, AZ_TIMEOUT, None, |_| ())
                    .await
            }
        }
        .map(drop)
    }

    async fn principal(
        &self,
        dir: &AzDir,
        tenant: Option<&TenantRef>,
    ) -> Result<Principal, PluginError> {
        #[derive(Deserialize)]
        struct Token {
            #[serde(rename = "accessToken")]
            access_token: String,
        }
        let mut args = vec!["account", "get-access-token"];
        if let Some(tenant) = tenant {
            args.extend(["--tenant", tenant.as_str()]);
        }
        let token: Token = self
            .run_json(dir, "az account get-access-token", &args)
            .await
            .map_err(|error| match tenant {
                Some(tenant) if error.kind() != ErrorKind::ToolMissing => PluginError::new(
                    error.kind(),
                    format!(
                        "az could not get a token for tenant {tenant} without signing in again ({}). Sign in with that tenant ID.",
                        error.message()
                    ),
                ),
                _ => error,
            })?;
        principal_of_token(&token.access_token).ok_or_else(|| {
            PluginError::new(
                ErrorKind::Internal,
                "the Azure CLI's token does not say who is signed in",
            )
        })
    }

    async fn accounts(&self, dir: &AzDir, listing: Listing) -> Result<Accounts, PluginError> {
        let args: &[&str] = match listing {
            Listing::Saved => &["account", "list", "--all"],
            Listing::Refreshed => &["account", "list", "--all", "--refresh"],
        };
        let raw: Vec<RawAccount> = self.run_json(dir, "az account list", args).await?;
        Ok(accounts_of(raw))
    }

    async fn tenants(&self, dir: &AzDir) -> Result<Vec<Tenant>, PluginError> {
        #[derive(Deserialize)]
        struct Page {
            #[serde(default)]
            value: Vec<RawTenant>,
        }
        #[derive(Deserialize)]
        struct RawTenant {
            #[serde(rename = "tenantId")]
            tenant_id: Option<String>,
            #[serde(rename = "displayName")]
            display_name: Option<String>,
            #[serde(rename = "defaultDomain")]
            default_domain: Option<String>,
        }
        let page: Page = self
            .run_json(
                dir,
                "az rest /tenants",
                &["rest", "--method", "get", "--url", TENANTS_URL],
            )
            .await?;
        Ok(page
            .value
            .into_iter()
            .filter_map(|raw| {
                Some(Tenant {
                    id: TenantId::parse(raw.tenant_id.as_deref()?)?,
                    name: raw
                        .display_name
                        .filter(|name| !name.is_empty())
                        .or(raw.default_domain),
                })
            })
            .collect())
    }

    async fn set_subscription(
        &self,
        dir: &AzDir,
        subscription: &SubscriptionId,
    ) -> Result<(), PluginError> {
        let args = [
            "account",
            "set",
            "--subscription",
            subscription.as_str(),
            "-o",
            "none",
        ];
        self.run(dir, "az account set", &args, AZ_TIMEOUT, None, |_| ())
            .await
            .map(drop)
    }

    async fn role_names(
        &self,
        dir: &AzDir,
        scope: &str,
        principal: &ObjectId,
    ) -> Result<BTreeSet<String>, PluginError> {
        #[derive(Deserialize)]
        struct Assignment {
            #[serde(rename = "roleDefinitionName")]
            role_definition_name: Option<String>,
        }
        let args = [
            "role",
            "assignment",
            "list",
            "--assignee-object-id",
            principal.as_str(),
            "--scope",
            scope,
            "--include-inherited",
            "--include-groups",
            "--fill-principal-name",
            "false",
        ];
        let assignments: Vec<Assignment> =
            self.run_json(dir, "az role assignment list", &args).await?;
        Ok(assignments
            .into_iter()
            .filter_map(|a| a.role_definition_name)
            .map(|name| name.to_lowercase())
            .collect())
    }
}

fn az_missing() -> PluginError {
    PluginError::tool_missing(
        "az",
        AZ_INSTALL_URL,
        format!(
            "The Azure CLI (az) isn't installed, or isn't on your PATH. Install it from {AZ_INSTALL_URL}, then try again."
        ),
    )
}

#[derive(Deserialize)]
struct RawAccount {
    id: Option<String>,
    name: Option<String>,
    #[serde(rename = "tenantId")]
    tenant_id: Option<String>,
    state: Option<String>,
}

/// `az login --allow-no-subscriptions` lists a tenant with no subscription
/// as an account whose id is the tenant's, named like this.
const TENANT_LEVEL_NAME: &str = "N/A(tenant level account)";

fn accounts_of(raw: Vec<RawAccount>) -> Accounts {
    let mut accounts = Accounts::default();
    for account in raw {
        let Some(tenant_id) = account.tenant_id.as_deref().and_then(TenantId::parse) else {
            continue;
        };
        if !accounts.tenants.contains(&tenant_id) {
            accounts.tenants.push(tenant_id.clone());
        }
        let tenant_level = account.name.as_deref() == Some(TENANT_LEVEL_NAME)
            || account.id.as_deref() == Some(tenant_id.as_str());
        let Some(id) = account.id.as_deref().and_then(SubscriptionId::parse) else {
            continue;
        };
        if tenant_level || account.state.as_deref() == Some("Disabled") {
            continue;
        }
        accounts.subscriptions.push(Subscription {
            name: account.name.unwrap_or_else(|| id.to_string()),
            id,
            tenant_id,
        });
    }
    accounts
}

/// MSAL's device code line: "To sign in, use a web browser to open the page
/// <https://microsoft.com/devicelogin> and enter the code ABCD1234E to
/// authenticate."
fn parse_device_code(line: &str) -> Option<DeviceCode> {
    let words: Vec<&str> = line.split_whitespace().collect();
    let url = words
        .iter()
        .find(|word| word.starts_with("https://"))?
        .trim_end_matches(['.', ',', ';', ':']);
    let code = words
        .windows(2)
        .find(|pair| pair.first().is_some_and(|w| w.eq_ignore_ascii_case("code")))
        .and_then(|pair| pair.get(1))
        .filter(|code| {
            code.len() >= 6
                && code
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-')
        })?;
    Some(DeviceCode {
        url: url.to_owned(),
        code: (*code).to_owned(),
    })
}

/// A failed `az` as an error kind the app acts on. `az` has no error codes,
/// so its standard error is the only evidence; text that matches nothing is
/// `internal`.
fn failure(command: &str, stderr: &[String]) -> PluginError {
    let text = stderr.join("\n").to_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|needle| text.contains(needle));
    let (kind, hint) = if has(&["certificate_verify_failed", "sslerror", "ssl: "]) {
        (
            ErrorKind::TlsError,
            " Azure's certificate could not be verified: if your network inspects TLS, set Runbooks' custom CA.",
        )
    } else if has(&[
        "max retries exceeded",
        "failed to establish a new connection",
        "name or service not known",
        "nodename nor servname",
        "temporary failure in name resolution",
        "getaddrinfo",
        "connectionerror",
    ]) {
        (
            ErrorKind::Network,
            " Azure could not be reached: check the network connection and any proxy, then try again.",
        )
    } else if has(&["aadsts7000222"]) {
        (
            ErrorKind::Expired,
            " The service principal's client secret has expired: create a new one.",
        )
    } else if has(&["aadsts700082", "aadsts70043", "refresh token has expired"]) {
        (
            ErrorKind::Expired,
            " The Azure CLI sign-in has expired: sign in again.",
        )
    } else if has(&[
        "aadsts50076",
        "aadsts50079",
        "aadsts50158",
        "aadsts53003",
        // A wrong secret or certificate, an app or tenant that isn't there.
        "aadsts7000215",
        "aadsts700027",
        "aadsts700016",
        "aadsts90002",
        "authorizationfailed",
        "does not have authorization",
    ]) {
        (ErrorKind::AccessDenied, "")
    } else if has(&["user canceled", "user cancelled", "canceled by the user"]) {
        (ErrorKind::Cancelled, "")
    } else if has(&["az login", "not logged in", "no subscription found"]) {
        (ErrorKind::NotSignedIn, " Sign in again.")
    } else {
        (ErrorKind::Internal, "")
    };
    PluginError::new(
        kind,
        format!(
            "{command} failed: {}.{hint}",
            error_line(stderr).trim_end_matches('.')
        ),
    )
}

/// The line that says what went wrong: `az`'s `ERROR:` line, else the first
/// `<name> ERROR` line of a wrapper such as a mise shim, else the last line
/// that is not a warning.
fn error_line(stderr: &[String]) -> &str {
    let mut lines = stderr
        .iter()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty());
    if let Some(error) = lines.clone().find_map(|line| line.strip_prefix("ERROR:")) {
        return error.trim();
    }
    if let Some(error) = lines.clone().find(|line| is_wrapper_error(line)) {
        return error;
    }
    lines
        .rfind(|line| !line.starts_with("WARNING:") && !line.contains("Warning:"))
        .unwrap_or("az exited with an error")
}

/// `<name> ERROR <text>`, where `<name>` is ASCII letters, digits, `_` or `-`.
fn is_wrapper_error(line: &str) -> bool {
    line.split_once(' ').is_some_and(|(name, rest)| {
        name.bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
            && rest.starts_with("ERROR ")
    })
}

/// All of `stream`, or `None` once it is longer than [`MAX_STDOUT_BYTES`].
/// The rest is still read, so `az` never blocks on a full pipe.
async fn read_capped(stream: Option<impl AsyncRead + Unpin>) -> std::io::Result<Option<Vec<u8>>> {
    let Some(mut stream) = stream else {
        return Ok(Some(Vec::new()));
    };
    let mut out = Vec::new();
    let mut overflowed = false;
    let mut chunk = [0_u8; 8192];
    loop {
        let read = stream.read(&mut chunk).await?;
        let Some(bytes) = chunk.get(..read).filter(|bytes| !bytes.is_empty()) else {
            return Ok((!overflowed).then_some(out));
        };
        if out.len() + bytes.len() > MAX_STDOUT_BYTES {
            overflowed = true;
            out = Vec::new();
        } else if !overflowed {
            out.extend_from_slice(bytes);
        }
    }
}

/// Reads `stream` to its end, calling `on_line` for each line, and keeps
/// its last lines up to [`MAX_STDERR_BYTES`].
async fn read_stderr(
    stream: Option<impl AsyncRead + Unpin>,
    on_line: &mut (impl FnMut(&str) + Send),
) -> std::io::Result<Vec<String>> {
    let mut tail = Tail::default();
    let Some(mut stream) = stream else {
        return Ok(Vec::new());
    };
    let mut line = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let read = stream.read(&mut chunk).await?;
        let Some(bytes) = chunk.get(..read).filter(|bytes| !bytes.is_empty()) else {
            break;
        };
        for &byte in bytes {
            if byte == b'\n' {
                tail.push(&std::mem::take(&mut line), on_line);
            } else if line.len() < MAX_STDERR_BYTES {
                line.push(byte);
            }
        }
    }
    if !line.is_empty() {
        tail.push(&line, on_line);
    }
    Ok(tail.lines.into())
}

/// The last lines of a stream, up to [`MAX_STDERR_BYTES`].
#[derive(Default)]
struct Tail {
    lines: VecDeque<String>,
    bytes: usize,
}

impl Tail {
    fn push(&mut self, line: &[u8], on_line: &mut impl FnMut(&str)) {
        let line = String::from_utf8_lossy(line)
            .trim_end_matches('\r')
            .to_owned();
        on_line(&line);
        self.bytes += line.len();
        self.lines.push_back(line);
        while self.bytes > MAX_STDERR_BYTES {
            match self.lines.pop_front() {
                Some(dropped) => self.bytes -= dropped.len(),
                None => break,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use runbooks_plugin_protocol::credential::ErrorKind;
    use serde_json::json;

    use super::{
        DeviceCode, RawAccount, Tail, TenantId, accounts_of, failure, parse_device_code,
        read_capped, read_stderr,
    };

    #[test]
    fn reads_msals_device_code_line() {
        let line = "To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code ABCD1234E to authenticate.";
        assert_eq!(
            parse_device_code(line),
            Some(DeviceCode {
                url: "https://microsoft.com/devicelogin".to_owned(),
                code: "ABCD1234E".to_owned()
            })
        );
        assert_eq!(parse_device_code("WARNING: Retrieving tenants"), None);
        assert_eq!(
            parse_device_code("open https://example.com/ and enter the code abc"),
            None
        );
        let code = |line: &str| parse_device_code(line).map(|device| device.code);
        assert_eq!(
            code("open https://example.com/ and enter the code ABCD-1234"),
            Some("ABCD-1234".to_owned())
        );
        for short_or_lower in ["ABC12", "abcd1234"] {
            assert_eq!(
                code(&format!(
                    "open https://example.com/ and enter the code {short_or_lower}"
                )),
                None,
                "{short_or_lower}"
            );
        }
    }

    fn stderr(lines: &[&str]) -> Vec<String> {
        lines.iter().map(|line| (*line).to_owned()).collect()
    }

    #[test]
    fn a_failure_is_classified_by_what_az_printed() {
        for (lines, kind) in [
            (
                vec!["ERROR: Please run 'az login' to setup account."],
                ErrorKind::NotSignedIn,
            ),
            (
                vec!["ERROR: AADSTS700082: The refresh token has expired due to inactivity."],
                ErrorKind::Expired,
            ),
            (
                vec![
                    "ERROR: AADSTS50076: Due to a configuration change made by your administrator, you must use multi-factor authentication.",
                    "Run the command below to authenticate interactively: az login --tenant x",
                ],
                ErrorKind::AccessDenied,
            ),
            (
                vec![
                    "ERROR: HTTPSConnectionPool(host='login.microsoftonline.com', port=443): Max retries exceeded with url: /x (Caused by NewConnectionError('Failed to establish a new connection'))",
                ],
                ErrorKind::Network,
            ),
            (
                vec![
                    "ERROR: HTTPSConnectionPool: Max retries exceeded (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED]')))",
                ],
                ErrorKind::TlsError,
            ),
            (
                vec![
                    "ERROR: AADSTS7000215: Invalid client secret provided. Ensure the secret being sent in the request is the client secret value.",
                ],
                ErrorKind::AccessDenied,
            ),
            (
                vec![
                    "ERROR: AADSTS7000222: The provided client secret keys for app 'x' are expired.",
                ],
                ErrorKind::Expired,
            ),
            (
                vec!["ERROR: The subscription of 'x' doesn't exist in cloud 'AzureCloud'."],
                ErrorKind::Internal,
            ),
        ] {
            let error = failure("az account set", &stderr(&lines));
            assert_eq!(error.kind(), kind, "{lines:?}");
            assert!(
                error.message().starts_with("az account set failed: "),
                "{}",
                error.message()
            );
        }
    }

    #[test]
    fn the_error_line_wins_over_warnings() {
        let error = failure(
            "az login",
            &stderr(&[
                "WARNING: A web browser has been opened",
                "ERROR: Something broke.",
                "WARNING: later",
            ]),
        );
        assert_eq!(error.message(), "az login failed: Something broke.");
        let error = failure("az login", &stderr(&["WARNING: only a warning"]));
        assert_eq!(error.message(), "az login failed: az exited with an error.");
        // Without an ERROR: line, the last line that is no Python warning.
        let error = failure(
            "az login",
            &stderr(&[
                "The token is not valid",
                "/opt/az/lib/python3.12/site-packages/x.py:1: UserWarning: deprecated",
            ]),
        );
        assert_eq!(error.message(), "az login failed: The token is not valid.");
    }

    #[test]
    fn a_wrappers_first_error_wins_over_its_closing_hint() {
        let error = failure(
            "az login",
            &stderr(&[
                "mise ERROR No version is set for shim: az",
                "Set a global default version with one of the following:",
                "mise use -g azure-cli@2.85.0",
                "mise ERROR Run with --verbose or MISE_VERBOSE=1 for more information",
            ]),
        );
        assert_eq!(
            error.message(),
            "az login failed: mise ERROR No version is set for shim: az."
        );
    }

    #[test]
    fn a_wrappers_error_is_named_by_letters_digits_underscores_or_hyphens() {
        let error = failure(
            "az account list",
            &stderr(&[
                "WARNING: ERROR details are in the log file",
                "az_wrap-2 ERROR No az installed",
                "Subscription not found.",
            ]),
        );
        assert_eq!(
            error.message(),
            "az account list failed: az_wrap-2 ERROR No az installed."
        );
    }

    #[test]
    fn accounts_skip_disabled_and_tenant_level_entries_but_keep_their_tenants()
    -> Result<(), serde_json::Error> {
        let tenant = "72f988bf-86f1-41af-91ab-2d7cd011db47";
        let guest = "f8cdef31-a31e-4b4a-93e4-5f571e91255a";
        let raw: Vec<RawAccount> = serde_json::from_value(json!([
            {"id": "11111111-1111-1111-1111-111111111111", "name": "Prod", "tenantId": tenant, "state": "Enabled"},
            {"id": "22222222-2222-2222-2222-222222222222", "name": "Old", "tenantId": tenant, "state": "Disabled"},
            {"id": guest, "name": "N/A(tenant level account)", "tenantId": guest, "state": "Enabled"},
            {"id": guest, "name": "Fabrikam", "tenantId": guest, "state": "Enabled"},
            {"id": "33333333-3333-3333-3333-333333333333", "tenantId": "not-a-guid"},
        ]))?;
        let accounts = accounts_of(raw);
        let names: Vec<&str> = accounts
            .subscriptions
            .iter()
            .map(|s| s.name.as_str())
            .collect();
        assert_eq!(names, ["Prod"]);
        let tenants: Vec<&str> = accounts.tenants.iter().map(TenantId::as_str).collect();
        assert_eq!(tenants, [tenant, guest]);
        Ok(())
    }

    /// `az`'s standard output may be 16 MiB. One byte more and none of it is
    /// kept, though all of it is read.
    #[tokio::test]
    async fn standard_output_may_be_16_mib() -> std::io::Result<()> {
        let most = vec![b'a'; 16 * 1024 * 1024];
        let read = read_capped(Some(most.as_slice())).await?;
        assert_eq!(read.map(|out| out.len()), Some(16 * 1024 * 1024));
        let over = vec![b'a'; 16 * 1024 * 1024 + 1];
        let read = read_capped(Some(over.as_slice())).await?;
        assert_eq!(read.map(|out| out.len()), None);
        assert_eq!(read_capped(None::<&[u8]>).await?, Some(Vec::new()));
        Ok(())
    }

    /// Each line of standard error reaches `on_line` as it is read, without
    /// its `\r`, a last line without a newline too. A line is cut at 64 KiB.
    #[tokio::test]
    async fn standard_error_is_read_line_by_line_and_a_line_is_cut_at_64_kib() -> std::io::Result<()>
    {
        let mut input = b"WARNING: one\r\ntwo\n".to_vec();
        input.extend(vec![b'x'; 64 * 1024 + 10]);
        input.extend(b"\nlast");
        let mut seen = Vec::new();
        let kept = read_stderr(Some(input.as_slice()), &mut |line: &str| {
            seen.push(line.len());
        })
        .await?;
        assert_eq!(seen, [12, 3, 64 * 1024, 4]);
        assert_eq!(kept, ["last"], "only the last line fits beside the cut one");
        Ok(())
    }

    fn push(tail: &mut Tail, byte: u8, len: usize) {
        tail.push(&vec![byte; len], &mut |_line: &str| {});
    }

    /// The first byte of each line the tail keeps.
    fn kept(tail: &Tail) -> String {
        tail.lines
            .iter()
            .filter_map(|line| line.chars().next())
            .collect()
    }

    /// The tail keeps the last lines that fit in 64 KiB, dropping the
    /// oldest first.
    #[test]
    fn the_tail_keeps_the_last_64_kib_of_lines() {
        let half = 32 * 1024;
        let mut tail = Tail::default();
        push(&mut tail, b'a', half);
        push(&mut tail, b'b', half);
        assert_eq!(kept(&tail), "ab", "exactly 64 KiB fits");
        push(&mut tail, b'c', 1);
        assert_eq!(kept(&tail), "bc");
        push(&mut tail, b'd', half);
        assert_eq!(kept(&tail), "cd");
    }
}
