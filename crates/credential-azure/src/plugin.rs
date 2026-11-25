//! The credential protocol's methods for Azure.
//!
//! - Each sign-in gets its own `az` config directory under the block's state
//!   directory. A detected login is a copy of the person's own, so neither
//!   the block nor a script it runs changes `~/.azure`.
//! - `detect` and `signIn` both leave the plugin signed in: the credential
//!   they return is the one `targets`, `select` and `env` then use. One that
//!   replaces another deletes the other's directory.
//! - `env` calls nothing: `az` refreshes its own tokens during the run.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::future::{self, Future};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::OnceLock;

use runbooks_plugin_protocol::credential::{
    ConfigureParams, ConfigureResult, DetectParams, DetectResult, EnvResult, ErrorKind,
    SelectParams, SelectResult, SignInParams, SignInResult, SignOutResult, Source, TargetsParams,
    TargetsResult,
};
use runbooks_plugin_transport::{CredentialPlugin, PluginError, Prompts};
use serde_json::Map;
use tokio::sync::{Mutex, oneshot};

use crate::az::{Az, AzDir, Interactive};
use crate::choose::{self, Pins, Resolution, TenantPin};
use crate::claims::Principal;
use crate::describe::{self, CLI_SOURCE, SUBSCRIPTION_LEVEL, TENANT_LEVEL};
use crate::host::LocalLogin;
use crate::ids::{SubscriptionId, TenantId, TenantRef};
use crate::params::{self, Constraints};
use crate::roles::{self, MissingRole, RoleRequirement};
use crate::session::{Chosen, Session, SignInMethod, Stage};
use crate::state_dir::StateDir;

/// The app's network settings from `configure`.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Network {
    /// The CA bundle `configure` gave, for `az` to trust.
    pub ca_bundle_file: Option<PathBuf>,
    /// May carry a proxy password, so `Debug` does not show it.
    pub proxy: Option<String>,
}

impl fmt::Debug for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Network")
            .field("ca_bundle_file", &self.ca_bundle_file)
            .field("proxy", &self.proxy.as_ref().map(|_| "<set>"))
            .finish()
    }
}

/// Builds the plugin's clients once `configure` has given the network
/// settings they need.
pub trait Connect: Send + Sync + 'static {
    /// The [`Az`] the plugin's calls go through.
    type Az: Az;

    /// # Errors
    ///
    /// A [`PluginError`] `configure` answers with.
    fn connect(&self, network: &Network) -> Result<Self::Az, PluginError>;
}

/// The Azure credential plugin. One process serves one block.
pub struct AzurePlugin<C: Connect> {
    local: LocalLogin,
    connect: C,
    configured: OnceLock<Configured<C::Az>>,
    /// The block's sign-in. Every call but the interactive part of `signIn`
    /// holds it, so calls change it one at a time.
    session: Mutex<Option<Session>>,
}

/// Shows only whether `configure` has succeeded: the session is behind an
/// async lock.
impl<C: Connect> fmt::Debug for AzurePlugin<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AzurePlugin")
            .field("configured", &self.configured.get().is_some())
            .finish_non_exhaustive()
    }
}

struct Configured<A> {
    az: A,
    state: StateDir,
    network: Network,
}

impl<C: Connect> AzurePlugin<C> {
    /// `local` is the person's own `az` login, which the `cli` source copies.
    pub fn new(local: LocalLogin, connect: C) -> Self {
        Self {
            local,
            connect,
            configured: OnceLock::new(),
            session: Mutex::new(None),
        }
    }

    fn configured(&self) -> Result<&Configured<C::Az>, PluginError> {
        self.configured.get().ok_or_else(|| {
            PluginError::new(ErrorKind::NotConfigured, "configure has not succeeded")
        })
    }

    /// `configure`, which awaits nothing.
    fn configure_now(&self, params: ConfigureParams) -> Result<ConfigureResult, PluginError> {
        let state_dir = PathBuf::from(&params.state_dir);
        if !state_dir.is_absolute() {
            return Err(PluginError::new(
                ErrorKind::InvalidParams,
                format!(
                    "configure: stateDir must be an absolute path, not {:?}",
                    params.state_dir
                ),
            ));
        }
        let network = Network {
            ca_bundle_file: params.ca_bundle_file.map(PathBuf::from),
            proxy: params.proxy,
        };
        if let Some(configured) = self.configured.get() {
            return if configured.state.path() == state_dir && configured.network == network {
                Ok(describe::configure_result())
            } else {
                Err(PluginError::new(
                    ErrorKind::InvalidParams,
                    "configure: this plugin is already configured with another stateDir or network: start a new process for another block",
                ))
            };
        }
        let az = self.connect.connect(&network)?;
        // Two configures at once both reach here; the second one's clients
        // are dropped and it answers as the first did.
        let _first = self.configured.set(Configured {
            az,
            state: StateDir::new(state_dir),
            network,
        });
        Ok(describe::configure_result())
    }

    /// Makes `session` the block's sign-in, deleting the directory of the
    /// one it replaces.
    async fn install(&self, state: &StateDir, session: Session) -> Result<(), PluginError> {
        let old = self.session.lock().await.replace(session);
        match old {
            Some(old) => state.remove(&old.dir.config).await,
            None => Ok(()),
        }
    }

    async fn detect_cli(
        &self,
        configured: &Configured<C::Az>,
        constraints: &Constraints,
    ) -> Result<Option<Session>, PluginError> {
        let Some(from) = &self.local.config_dir else {
            return Ok(None);
        };
        let Some(config) = configured.state.copy_login(from).await? else {
            return Ok(None);
        };
        let extensions = match &self.local.extension_dir {
            Some(dir) if tokio::fs::try_exists(dir).await.unwrap_or(false) => Some(dir.clone()),
            Some(_) | None => None,
        };
        let dir = AzDir { config, extensions };
        match establish(&configured.az, SignInMethod::Cli, dir.clone(), constraints).await {
            Ok(session) => Ok(Some(session)),
            Err(error) => {
                configured.state.remove(&dir.config).await?;
                match error.kind() {
                    // Nothing here the block can use as it is.
                    ErrorKind::NotSignedIn
                    | ErrorKind::Expired
                    | ErrorKind::PinMismatch
                    | ErrorKind::ToolMissing => Ok(None),
                    ErrorKind::NotConfigured
                    | ErrorKind::UnsupportedProtocolVersion
                    | ErrorKind::InvalidParams
                    | ErrorKind::RequirementNotMet
                    | ErrorKind::AccessDenied
                    | ErrorKind::Cancelled
                    | ErrorKind::TimedOut
                    | ErrorKind::Network
                    | ErrorKind::TlsError
                    | ErrorKind::Internal => Err(error),
                }
            }
        }
    }
}

/// Reads what a fresh sign-in in `dir` can see, and chooses what the pins
/// and the login leave no choice about.
async fn establish<A: Az>(
    az: &A,
    method: SignInMethod,
    dir: AzDir,
    constraints: &Constraints,
) -> Result<Session, PluginError> {
    let home = az.principal(&dir, None).await?;
    let tenant = match &constraints.tenant {
        None => None,
        Some(TenantRef::Id(id)) => Some(TenantPin {
            id: id.clone(),
            written: id.to_string(),
        }),
        Some(domain @ TenantRef::Domain(written)) => Some(TenantPin {
            id: az.principal(&dir, Some(domain)).await?.tenant_id,
            written: written.clone(),
        }),
    };
    let accounts = az.accounts(&dir).await?;
    // Azure's tenant list adds only names and tenants with no subscription:
    // the sign-in works without it, as it does today, and logs why.
    let listed = az.tenants(&dir).await.unwrap_or_else(|error| {
        log(format_args!(
            "signing in without Azure's tenant list: {error}"
        ));
        Vec::new()
    });
    let tenants = choose::visible_tenants(listed, &accounts, &home.tenant_id);
    let pins = Pins {
        tenant,
        subscription: constraints.subscription.clone(),
    };
    let resolution = choose::resolve(&tenants, &accounts.subscriptions, &pins)?;
    let mut session = Session {
        method,
        dir,
        home,
        tenants,
        subscriptions: accounts.subscriptions,
        pins,
        roles: constraints.roles.clone(),
        stage: Stage::Choosing { tenant: None },
    };
    session.stage = match resolution {
        Resolution::Chosen {
            tenant,
            subscription,
        } => Stage::Ready(commit(az, &session, &tenant, subscription.as_ref()).await?),
        Resolution::Open { tenant } => Stage::Choosing { tenant },
    };
    Ok(session)
}

/// Signs `session` in to `tenant`, makes `subscription` the default for a
/// bare `az`, and checks the required roles there.
async fn commit<A: Az>(
    az: &A,
    session: &Session,
    tenant: &TenantId,
    subscription: Option<&SubscriptionId>,
) -> Result<Chosen, PluginError> {
    let principal = az
        .principal(&session.dir, Some(&TenantRef::Id(tenant.clone())))
        .await?;
    if let Some(subscription) = subscription {
        az.set_subscription(&session.dir, subscription).await?;
    }
    check_roles(az, &session.dir, &principal, &session.roles, subscription).await?;
    let tenant = session
        .tenant(tenant)
        .cloned()
        .unwrap_or_else(|| crate::az::Tenant {
            id: tenant.clone(),
            name: None,
        });
    let subscription = subscription.and_then(|id| {
        session
            .subscriptions
            .iter()
            .find(|sub| &sub.id == id)
            .cloned()
    });
    Ok(Chosen {
        tenant,
        subscription,
        principal,
    })
}

async fn check_roles<A: Az>(
    az: &A,
    dir: &AzDir,
    principal: &Principal,
    required: &[RoleRequirement],
    subscription: Option<&SubscriptionId>,
) -> Result<(), PluginError> {
    let mut missing = Vec::new();
    let mut held: HashMap<String, BTreeSet<String>> = HashMap::new();
    for requirement in required {
        let Some(scope) = requirement.arm_scope(subscription) else {
            missing.push(MissingRole {
                role: requirement.role.clone(),
                scope: requirement.scope.clone(),
            });
            continue;
        };
        if !held.contains_key(&scope) {
            let names = az.role_names(dir, &scope, &principal.object_id).await?;
            held.insert(scope.clone(), names);
        }
        if !held
            .get(&scope)
            .is_some_and(|names| names.contains(&requirement.role.to_lowercase()))
        {
            missing.push(MissingRole {
                role: requirement.role.clone(),
                scope,
            });
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(roles::unmet(&missing, &principal.name))
    }
}

/// Runs the interactive `az login`, telling the person what to do.
async fn login<A: Az>(
    az: &A,
    method: SignInMethod,
    dir: &AzDir,
    tenant: Option<&TenantRef>,
    prompts: &Prompts,
) -> Result<(), PluginError> {
    let (sender, receiver) = oneshot::channel();
    match method {
        SignInMethod::Cli => {
            prompts.waiting().await?;
            az.login(dir, Interactive::Browser, tenant, sender).await
        }
        SignInMethod::DeviceCode => {
            let forward = async {
                match receiver.await {
                    Ok(code) => prompts.open_url(code.url, Some(code.code)).await,
                    // `az login` ended without printing a code.
                    Err(_ended) => Ok(()),
                }
            };
            tokio::try_join!(
                az.login(dir, Interactive::DeviceCode, tenant, sender),
                forward
            )
            .map(drop)
        }
    }
}

fn not_signed_in() -> PluginError {
    PluginError::new(
        ErrorKind::NotSignedIn,
        "This block isn't signed in to Azure. Sign in first.",
    )
}

/// Writes `message` to standard error, the protocol's log.
fn log(message: fmt::Arguments<'_>) {
    match writeln!(io::stderr().lock(), "runbooks-credential-azure: {message}") {
        // A log line standard error cannot take has nowhere else to go.
        Ok(()) | Err(_) => {}
    }
}

impl<C: Connect> CredentialPlugin for AzurePlugin<C> {
    fn configure(
        &self,
        params: ConfigureParams,
    ) -> impl Future<Output = Result<ConfigureResult, PluginError>> + Send {
        future::ready(self.configure_now(params))
    }

    async fn detect(&self, params: DetectParams) -> Result<DetectResult, PluginError> {
        let configured = self.configured()?;
        let constraints = params::constraints("detect", &params.pins, &params.requirements)?;
        let mut problems = params::Problems::default();
        for source in &params.sources {
            if let Source::Named { name } = source
                && name != CLI_SOURCE
            {
                problems.add(format!(
                    "source {name:?} is not one this plugin names: it names {CLI_SOURCE:?}"
                ));
            }
        }
        problems.check("detect")?;

        let mut first_error = None;
        for source in &params.sources {
            let found = match source {
                Source::Named { .. } => self.detect_cli(configured, &constraints).await,
                // These hold service principals, and no method here signs one in.
                Source::Env { .. } | Source::Values { .. } => Ok(None),
            };
            match found {
                Ok(Some(session)) => {
                    let identity = session.identity();
                    self.install(&configured.state, session).await?;
                    return Ok(DetectResult::found(identity, CLI_SOURCE));
                }
                Ok(None) => {}
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        first_error.map_or_else(|| Ok(DetectResult::not_found()), Err)
    }

    async fn sign_in(
        &self,
        params: SignInParams,
        prompts: Prompts,
    ) -> Result<SignInResult, PluginError> {
        let configured = self.configured()?;
        let method = SignInMethod::parse(&params.method).ok_or_else(|| {
            let names: Vec<&str> = SignInMethod::ALL.iter().map(|m| m.name()).collect();
            PluginError::new(
                ErrorKind::InvalidParams,
                format!(
                    "signIn: method {:?} is not one of {}",
                    params.method,
                    names.join(", ")
                ),
            )
        })?;
        let constraints = params::constraints("signIn", &params.pins, &params.requirements)?;
        let tenant = params::login_tenant(&params.fields, &constraints)?;

        let dir = AzDir {
            config: configured.state.create().await?,
            extensions: None,
        };
        let signed_in = async {
            login(&configured.az, method, &dir, tenant.as_ref(), &prompts).await?;
            establish(&configured.az, method, dir.clone(), &constraints).await
        }
        .await;
        match signed_in {
            Ok(session) => {
                let identity = session.identity();
                self.install(&configured.state, session).await?;
                Ok(SignInResult(identity))
            }
            Err(error) => {
                configured.state.remove(&dir.config).await?;
                Err(error)
            }
        }
    }

    async fn targets(&self, params: TargetsParams) -> Result<TargetsResult, PluginError> {
        let held = self.session.lock().await;
        let session = held.as_ref().ok_or_else(not_signed_in)?;
        let targets = match params.level.as_str() {
            TENANT_LEVEL => choose::tenant_targets(&session.tenants, &session.pins),
            SUBSCRIPTION_LEVEL => {
                let parent = params.parent.as_deref().unwrap_or_default();
                let tenant = TenantId::parse(parent).ok_or_else(|| {
                    PluginError::new(
                        ErrorKind::InvalidParams,
                        format!(
                            "targets: the {SUBSCRIPTION_LEVEL} level needs parent, a tenant id from the {TENANT_LEVEL} level, not {parent:?}"
                        ),
                    )
                })?;
                choose::subscription_targets(&session.subscriptions, &tenant, &session.pins)
            }
            other => {
                return Err(PluginError::new(
                    ErrorKind::InvalidParams,
                    format!(
                        "targets: {other:?} is not a level: the levels are {TENANT_LEVEL} and {SUBSCRIPTION_LEVEL}"
                    ),
                ));
            }
        };
        drop(held);
        Ok(TargetsResult { targets })
    }

    async fn select(&self, params: SelectParams) -> Result<SelectResult, PluginError> {
        let configured = self.configured()?;
        let (tenant, subscription) = params::choice(&params.targets)?;
        let mut held = self.session.lock().await;
        let session = held.as_mut().ok_or_else(not_signed_in)?;
        choose::check_choice(
            &session.tenants,
            &session.subscriptions,
            &session.pins,
            &tenant,
            subscription.as_ref(),
        )?;
        let chosen = commit(&configured.az, session, &tenant, subscription.as_ref()).await?;
        session.stage = Stage::Ready(chosen);
        let identity = session.identity();
        drop(held);
        Ok(SelectResult(identity))
    }

    async fn env(&self) -> Result<EnvResult, PluginError> {
        let held = self.session.lock().await;
        let session = held.as_ref().ok_or_else(not_signed_in)?;
        let Stage::Ready(chosen) = &session.stage else {
            return Err(PluginError::new(
                ErrorKind::NotSignedIn,
                "Choose a tenant and subscription first.",
            ));
        };
        let values = session.env(chosen);
        drop(held);
        Ok(EnvResult {
            expires_at: None,
            values,
        })
    }

    async fn sign_out(&self) -> Result<SignOutResult, PluginError> {
        let configured = self.configured()?;
        let mut session = self.session.lock().await;
        *session = None;
        configured.state.remove_all().await?;
        drop(session);
        Ok(SignOutResult(Map::new()))
    }
}
