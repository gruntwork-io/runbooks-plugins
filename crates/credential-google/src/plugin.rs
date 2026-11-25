use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use runbooks_plugin_protocol::PROTOCOL_VERSION;
use runbooks_plugin_protocol::credential::{
    ConfigureParams, ConfigureResult, ConfigureResultCloud, DetectParams, DetectResult, EnvResult,
    ErrorKind, Field, Level, LevelChosen, Method, RequirementKind, SelectParams, SelectResult,
    SignInParams, SignInResult, SignOutResult, Source, Target, TargetsParams, TargetsResult,
};
use runbooks_plugin_transport::{CredentialPlugin, PluginError, Prompts};
use serde_json::Map;
use time::OffsetDateTime;

use crate::Secret;
use crate::api::{GoogleApi, Network, NetworkError};
use crate::credential::{Credential, MAX_DOCUMENT_BYTES, Origin, api_error, parse_document};
use crate::crypto::Crypto;
use crate::files::{self, CREDENTIALS_FILE, ReadError};
use crate::session::{self, Candidate, Constraints, PROJECT, Prover, Session, invalid_params};
use crate::sources::{self, FoundVars, Prefix, VarCredential};

/// The most projects `targets` lists, as the app did.
pub const MAX_PROJECTS: usize = 500;
/// The largest page asked for.
const PAGE_SIZE: usize = 1000;
const MAX_CA_BUNDLE_BYTES: usize = 1024 * 1024;

const SERVICE_ACCOUNT: &str = "service_account";

/// What `main` found in the process: its environment, read once, and the
/// clock. The plugin reads no other global state.
#[derive(Clone, Debug)]
pub struct Host {
    pub env: HashMap<String, String>,
    pub now: fn() -> OffsetDateTime,
}

/// Builds the API client once `configure` says how to reach Google.
pub type Connect<A> = Box<dyn Fn(&Network) -> Result<A, NetworkError> + Send + Sync>;

/// The Google credential plugin, for one block.
pub struct GooglePlugin<A, C> {
    host: Host,
    connect: Connect<A>,
    crypto: C,
    state: Mutex<State<A>>,
}

struct State<A> {
    configured: Option<Configured<A>>,
    session: Option<Session>,
    /// Display names from the last `targets`, so `select` can name a project.
    project_names: HashMap<String, String>,
}

struct Configured<A> {
    api: Arc<A>,
    state_dir: PathBuf,
}

impl<A: GoogleApi, C: Crypto> GooglePlugin<A, C> {
    pub fn new(host: Host, connect: Connect<A>, crypto: C) -> Self {
        Self {
            host,
            connect,
            crypto,
            state: Mutex::new(State {
                configured: None,
                session: None,
                project_names: HashMap::new(),
            }),
        }
    }

    /// No section holding the lock panics or awaits, so a poisoned lock
    /// still holds a whole state.
    fn state(&self) -> MutexGuard<'_, State<A>> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn configured(&self) -> Result<(Arc<A>, PathBuf), PluginError> {
        let state = self.state();
        let configured = state.configured.as_ref().ok_or_else(|| {
            PluginError::new(ErrorKind::NotConfigured, "configure has not succeeded")
        })?;
        Ok((Arc::clone(&configured.api), configured.state_dir.clone()))
    }

    fn session(&self) -> Result<Session, PluginError> {
        self.state()
            .session
            .clone()
            .ok_or_else(|| PluginError::new(ErrorKind::NotSignedIn, "Sign in first."))
    }

    fn prover<'a>(&'a self, api: &'a A) -> Prover<'a, A, C> {
        Prover {
            api,
            crypto: &self.crypto,
            now: (self.host.now)(),
        }
    }

    /// Proves `candidate` and makes it the block's credential.
    async fn sign_in_with(
        &self,
        candidate: Candidate,
        constraints: &Constraints,
    ) -> Result<Session, PluginError> {
        let (api, _) = self.configured()?;
        let session = self.prover(&api).prove(candidate, constraints).await?;
        self.state().session = Some(session.clone());
        Ok(session)
    }

    async fn sign_in_service_account(
        &self,
        fields: HashMap<String, String>,
        constraints: &Constraints,
    ) -> Result<Session, PluginError> {
        let mut fields =
            MethodFields::new(SERVICE_ACCOUNT, fields, &["key", "keyFile", "project"])?;
        let key = fields.take("key").map(Secret::new);
        let key_file = fields.take("keyFile");
        let project = fields.take("project");
        let document = match (key, key_file) {
            (Some(key), None) => parse_document(key.expose().to_owned())
                .map_err(|error| invalid_params(format!("The key field {error}")))?,
            (None, Some(path)) => {
                let path = PathBuf::from(path);
                if !path.is_absolute() {
                    return Err(invalid_params(format!(
                        "keyFile must be an absolute path, not {}",
                        path.display()
                    )));
                }
                read_document(&path, "keyFile").await?
            }
            (Some(_), Some(_)) => {
                return Err(invalid_params("Give key or keyFile, not both."));
            }
            (None, None) => {
                return Err(invalid_params(
                    "service_account needs key (the key's JSON) or keyFile (the key file's path).",
                ));
            }
        };
        let candidate = Candidate {
            credential: Credential::Document(document),
            method: SERVICE_ACCOUNT.to_owned(),
            project,
            region: None,
            zone: None,
            configuration: None,
        };
        self.sign_in_with(candidate, constraints).await
    }
}

/// The candidate in variables an `env` or `values` source found.
async fn candidate_from_vars(found: FoundVars, source: &str) -> Result<Candidate, PluginError> {
    let credential = match found.credential {
        VarCredential::Token(token) => Credential::AccessToken(token),
        VarCredential::Json(text) => Credential::Document(
            parse_document(text.expose().to_owned())
                .map_err(|error| invalid_params(format!("{} {error}", found.var)))?,
        ),
        VarCredential::Path(path) => {
            Credential::Document(read_document(Path::new(&path), &found.var).await?)
        }
    };
    Ok(Candidate {
        credential,
        method: source.to_owned(),
        project: found.project,
        region: found.region,
        zone: found.zone,
        configuration: None,
    })
}

/// A method's fields, refused if any is unknown. An empty field is absent.
struct MethodFields(HashMap<String, String>);

impl MethodFields {
    fn new(
        method: &str,
        fields: HashMap<String, String>,
        known: &[&str],
    ) -> Result<Self, PluginError> {
        // A name that isn't an identifier could be pasted material.
        let mut unknown: Vec<&str> = fields
            .keys()
            .map(String::as_str)
            .filter(|name| !known.contains(name))
            .map(|name| {
                let identifier = name.len() <= 64
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
                if identifier {
                    name
                } else {
                    "(a name that is not an identifier)"
                }
            })
            .collect();
        if !unknown.is_empty() {
            unknown.sort_unstable();
            return Err(invalid_params(format!(
                "{method} has no field {}; its fields are {}",
                unknown.join(", "),
                known.join(", ")
            )));
        }
        Ok(Self(fields))
    }

    fn take(&mut self, name: &str) -> Option<String> {
        self.0
            .remove(name)
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    }
}

/// Reads and parses the credentials document at `path`, which `what` names.
async fn read_document(
    path: &Path,
    what: &str,
) -> Result<crate::credential::Document, PluginError> {
    let text = files::read_text(path, MAX_DOCUMENT_BYTES)
        .await
        .map_err(|error| {
            let kind = match error {
                ReadError::NotFound => ErrorKind::NotSignedIn,
                ReadError::TooLarge(_) | ReadError::NotText | ReadError::Io(_) => {
                    ErrorKind::InvalidParams
                }
            };
            PluginError::new(kind, format!("{what} {}: the file {error}", path.display()))
        })?;
    parse_document(text)
        .map_err(|error| invalid_params(format!("{what} {} {error}", path.display())))
}

fn methods() -> Vec<Method> {
    let field = |name: &str, label: &str, secret: bool| Field {
        label: label.to_owned(),
        name: name.to_owned(),
        required: false,
        secret,
    };
    vec![Method {
        fields: vec![
            field("key", "Service account key (JSON)", true),
            field("keyFile", "Key file", false),
            field("project", "Project ID", false),
        ],
        label: "Service Account Key".to_owned(),
        name: SERVICE_ACCOUNT.to_owned(),
    }]
}

/// A detection source, checked before any is read.
enum Lookup {
    Vars {
        vars: HashMap<String, String>,
        prefix: Prefix,
        name: &'static str,
    },
}

impl<A: GoogleApi, C: Crypto> CredentialPlugin for GooglePlugin<A, C> {
    async fn configure(&self, params: ConfigureParams) -> Result<ConfigureResult, PluginError> {
        let state_dir = PathBuf::from(&params.state_dir);
        if !state_dir.is_absolute() {
            return Err(invalid_params(format!(
                "stateDir must be an absolute path, not {}",
                params.state_dir
            )));
        }
        files::create_private_dir(&state_dir)
            .await
            .map_err(|error| {
                PluginError::new(
                    ErrorKind::Internal,
                    format!(
                        "stateDir {} could not be created: {error}",
                        state_dir.display()
                    ),
                )
            })?;
        let ca_bundle = match &params.ca_bundle_file {
            None => None,
            Some(path) => Some(
                files::read_text(Path::new(path), MAX_CA_BUNDLE_BYTES)
                    .await
                    .map_err(|error| invalid_params(format!("caBundleFile {path} {error}")))?
                    .into_bytes(),
            ),
        };
        let network = Network {
            ca_bundle,
            proxy: params.proxy.clone(),
        };
        let api = (self.connect)(&network).map_err(|error| match error {
            NetworkError::CaBundle => invalid_params(format!(
                "caBundleFile {} {error}",
                params.ca_bundle_file.as_deref().unwrap_or_default()
            )),
            NetworkError::Proxy => invalid_params(format!("proxy {error}")),
            NetworkError::Client => PluginError::new(ErrorKind::TlsError, error.to_string()),
        })?;
        self.state().configured = Some(Configured {
            api: Arc::new(api),
            state_dir,
        });
        Ok(ConfigureResult {
            cloud: Some(ConfigureResultCloud::Gcp),
            driver_version: env!("CARGO_PKG_VERSION").to_owned(),
            levels: vec![Level {
                chosen: LevelChosen::AfterSignIn,
                label: "Project".to_owned(),
                name: PROJECT.to_owned(),
            }],
            methods: methods(),
            names: session::names(),
            protocol_version: PROTOCOL_VERSION.to_owned(),
            requirements: vec![RequirementKind::Scopes],
            sources: Vec::new(),
        })
    }

    async fn detect(&self, params: DetectParams) -> Result<DetectResult, PluginError> {
        let constraints = Constraints::parse(&params.pins, &params.requirements)?;
        let mut lookups = Vec::new();
        let mut problems = Vec::new();
        for source in params.sources {
            match source {
                Source::Env { prefix } => match Prefix::parse(prefix) {
                    Ok(prefix) => lookups.push(Lookup::Vars {
                        vars: self.host.env.clone(),
                        prefix,
                        name: "env",
                    }),
                    Err(prefix) => problems.push(format!(
                        "env prefix {prefix:?} must match ^[A-Z][A-Z0-9_]*_$"
                    )),
                },
                Source::Values { values } => lookups.push(Lookup::Vars {
                    vars: values,
                    prefix: Prefix::default(),
                    name: "values",
                }),
                Source::Named { name } => problems.push(format!(
                    "this plugin has no detection source named {name:?}"
                )),
            }
        }
        if !problems.is_empty() {
            return Err(invalid_params(problems.join("; ")));
        }

        // A credential that fails is skipped for the next source, as the app
        // did; one that lacks a required scope stops the search.
        let mut failures: Vec<PluginError> = Vec::new();
        for lookup in lookups {
            let Lookup::Vars { vars, prefix, name } = lookup;
            let Some(found) = sources::find(&vars, &prefix) else {
                continue;
            };
            let proved = match candidate_from_vars(found, name).await {
                Ok(candidate) => self.sign_in_with(candidate, &constraints).await,
                Err(error) => Err(error),
            };
            match proved {
                Ok(session) => return Ok(DetectResult::found(session.identity(), name)),
                Err(error) if error.kind() == ErrorKind::RequirementNotMet => return Err(error),
                Err(error) => failures.push(error),
            }
        }
        match failures.first() {
            None => Ok(DetectResult::not_found()),
            Some(first) => {
                let messages: Vec<&str> = failures.iter().map(PluginError::message).collect();
                Err(PluginError::new(
                    first.kind(),
                    format!(
                        "Credentials were found but can't be used: {}",
                        messages.join("; ")
                    ),
                ))
            }
        }
    }

    async fn sign_in(
        &self,
        params: SignInParams,
        _prompts: Prompts,
    ) -> Result<SignInResult, PluginError> {
        let constraints = Constraints::parse(&params.pins, &params.requirements)?;
        let session = match params.method.as_str() {
            SERVICE_ACCOUNT => {
                self.sign_in_service_account(params.fields, &constraints)
                    .await?
            }
            other => {
                return Err(invalid_params(format!(
                    "this plugin has no sign-in method {other:?}; its methods are {SERVICE_ACCOUNT}"
                )));
            }
        };
        Ok(SignInResult(session.identity()))
    }

    async fn targets(&self, params: TargetsParams) -> Result<TargetsResult, PluginError> {
        if params.level != PROJECT {
            return Err(invalid_params(format!(
                "targets has level {:?}; this plugin's only level is \"project\"",
                params.level
            )));
        }
        let (api, _) = self.configured()?;
        let session = self.session()?;
        let origin = Origin::of(&session.credential);
        let token = self.prover(&api).token(&session.credential).await?;
        let mut targets = Vec::new();
        let mut page_token = None;
        loop {
            let size = (MAX_PROJECTS - targets.len()).min(PAGE_SIZE);
            let page = api
                .search_projects(
                    &token,
                    page_token.as_deref(),
                    u32::try_from(size).unwrap_or(1),
                )
                .await
                .map_err(|error| api_error(error, origin))?;
            // Projects pending deletion are listed too; gcloud hides them.
            for project in page.projects {
                if project
                    .state
                    .as_deref()
                    .is_none_or(|state| state == "ACTIVE")
                {
                    targets.push(Target {
                        name: project.display_name.unwrap_or_else(|| project.id.clone()),
                        id: project.id,
                    });
                }
            }
            page_token = page.next_page_token;
            if page_token.is_none() || targets.len() >= MAX_PROJECTS {
                break;
            }
        }
        targets.truncate(MAX_PROJECTS);
        self.state().project_names = targets
            .iter()
            .map(|target| (target.id.clone(), target.name.clone()))
            .collect();
        Ok(TargetsResult { targets })
    }

    async fn select(&self, params: SelectParams) -> Result<SelectResult, PluginError> {
        let mut targets = params.targets;
        let project = targets.remove(PROJECT);
        if let Some(level) = targets.keys().next() {
            return Err(invalid_params(format!(
                "targets has level {level:?}; this plugin's only level is \"project\""
            )));
        }
        let Some(project) = project.filter(|project| !project.is_empty()) else {
            return Err(invalid_params("select needs targets.project"));
        };
        let mut state = self.state();
        let names = state.project_names.get(&project).cloned();
        let session = state
            .session
            .as_mut()
            .ok_or_else(|| PluginError::new(ErrorKind::NotSignedIn, "Sign in first."))?;
        if let Some(pinned) = session
            .pinned_project
            .as_ref()
            .filter(|pinned| **pinned != project)
        {
            return Err(PluginError::new(
                ErrorKind::PinMismatch,
                format!("The block pins project {pinned}, so {project} can't be selected."),
            ));
        }
        session.project = Some(Target {
            name: names.unwrap_or_else(|| project.clone()),
            id: project,
        });
        Ok(SelectResult(session.identity()))
    }

    async fn env(&self) -> Result<EnvResult, PluginError> {
        let (_, state_dir) = self.configured()?;
        let session = self.session()?;
        let file = match &session.credential {
            Credential::AccessToken(_) => None,
            Credential::Document(document) => {
                let path = files::write_private(
                    &state_dir,
                    CREDENTIALS_FILE,
                    document.text.expose().as_bytes(),
                )
                .await
                .map_err(|error| {
                    PluginError::new(
                        ErrorKind::Internal,
                        format!(
                            "The credentials file could not be written under stateDir: {error}"
                        ),
                    )
                })?;
                Some(path.to_string_lossy().into_owned())
            }
        };
        Ok(EnvResult {
            expires_at: session.expires_at.map(Into::into),
            values: session.env_values(file.as_deref()),
        })
    }

    async fn sign_out(&self) -> Result<SignOutResult, PluginError> {
        let state_dir = {
            let mut state = self.state();
            state.session = None;
            state.project_names.clear();
            state
                .configured
                .as_ref()
                .map(|configured| configured.state_dir.clone())
        };
        if let Some(state_dir) = state_dir {
            files::remove(&state_dir, CREDENTIALS_FILE)
                .await
                .map_err(|error| {
                    PluginError::new(
                        ErrorKind::Internal,
                        format!(
                            "The credentials file under stateDir could not be deleted: {error}"
                        ),
                    )
                })?;
        }
        Ok(SignOutResult(Map::new()))
    }
}
