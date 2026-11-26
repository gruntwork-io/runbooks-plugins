//! The credential protocol's methods for Azure.
//!
//! - Each sign-in gets its own `az` config directory under the block's state
//!   directory. A detected login is a copy of the person's own, so neither
//!   the block nor a script it runs changes `~/.azure`.
//! - `detect` and `signIn` both leave the plugin signed in: the credential
//!   they return is the one `targets`, `select` and `env` then use. One that
//!   replaces another deletes the other's directory.
//! - `env` calls nothing: `az` refreshes its own tokens during the run.
//! - A service principal signs in through `az` too, so a script's bare `az`
//!   works; `env` adds its credential for the tools that read it directly.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::future::{self, Future};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use runbooks_plugin_protocol::credential::{
    ConfigureParams, ConfigureResult, DetectParams, DetectResult, EnvResult, ErrorKind,
    SelectParams, SelectResult, SignInParams, SignInResult, SignOutResult, Source, TargetsParams,
    TargetsResult,
};
use runbooks_plugin_transport::{CredentialPlugin, PluginError, Prompts};
use serde_json::Map;
use tokio::sync::{Mutex, oneshot};

use crate::az::{Az, AzDir, Interactive, Listing};
use crate::choose::{self, Pins, Resolution, TenantPin};
use crate::claims::Principal;
use crate::describe::{self, CLI_SOURCE, SUBSCRIPTION_LEVEL, TENANT_LEVEL};
use crate::host::Host;
use crate::ids::{SubscriptionId, TenantId, TenantRef};
use crate::log;
use crate::params::{self, Constraints};
use crate::roles::{self, MissingRole, RoleRequirement};
use crate::service_principal::{self, Credential, Found, ServicePrincipal};
use crate::session::{Chosen, Session, SignInMethod, Stage};
use crate::state_dir::StateDir;

/// The `source` of a credential found in the environment.
const ENV_SOURCE: &str = "env";

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
    /// The environment `main` read: the `env` source, and where the
    /// person's own `az` login is.
    host: Host,
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
    /// `host` is the environment `main` read: the `cli` source copies its
    /// `az` login, and the `env` source reads its variables.
    pub fn new(host: Host, connect: C) -> Self {
        Self {
            host,
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
        if !params.settings.is_empty() {
            return Err(PluginError::new(
                ErrorKind::InvalidParams,
                "configure: Azure has no settings, so the block can set none",
            ));
        }
        let network = Network {
            ca_bundle_file: params.ca_bundle_file.map(PathBuf::from),
            proxy: params.proxy,
        };
        if let Some(configured) = self.configured.get() {
            return if configured.state.path() == state_dir && configured.network == network {
                Ok(describe::configure_result(&configured.az))
            } else {
                Err(PluginError::new(
                    ErrorKind::InvalidParams,
                    "configure: this plugin is already configured with another stateDir or network: start a new process for another block",
                ))
            };
        }
        let az = self.connect.connect(&network)?;
        let described = describe::configure_result(&az);
        // Two configures at once both reach here; the second one's clients
        // are dropped and it answers as the first did.
        let _first = self.configured.set(Configured {
            az,
            state: StateDir::new(state_dir),
            network,
        });
        Ok(described)
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

    /// A copy of the `az` login in `from`, with its subscriptions read by
    /// `listing`, if it is one the block can use.
    async fn detect_copy(
        &self,
        configured: &Configured<C::Az>,
        method: SignInMethod,
        from: &Path,
        extensions: Option<&Path>,
        listing: Listing,
        constraints: &Constraints,
    ) -> Result<Option<Session>, PluginError> {
        let Some(config) = configured.state.copy_login(from).await? else {
            return Ok(None);
        };
        let extensions = match extensions {
            Some(dir) if tokio::fs::try_exists(dir).await.unwrap_or(false) => Some(dir.to_owned()),
            Some(_) | None => None,
        };
        let dir = AzDir { config, extensions };
        let session = establish(
            &configured.az,
            method,
            dir.clone(),
            listing,
            constraints,
            None,
        )
        .await;
        let session = keep_or_remove(&configured.state, &dir, session).await;
        unusable_is_none(session, &[ErrorKind::NotSignedIn, ErrorKind::Expired])
    }

    /// The `cli` source: a copy of the person's own `az` login, if they have
    /// one the block can use.
    async fn detect_local(
        &self,
        configured: &Configured<C::Az>,
        constraints: &Constraints,
    ) -> Result<Option<Session>, PluginError> {
        let local = self.host.local_login();
        let Some(from) = &local.config_dir else {
            return Ok(None);
        };
        let extensions = local.extension_dir.as_deref();
        // The person's login lists the subscriptions az saw when they last
        // signed in, without any created since.
        self.detect_copy(
            configured,
            SignInMethod::Cli,
            from,
            extensions,
            Listing::Refreshed,
            constraints,
        )
        .await
    }

    /// The `env` source: a service principal in the variables whose names
    /// start with `prefix`, if they hold a whole one.
    async fn detect_env(
        &self,
        configured: &Configured<C::Az>,
        prefix: Option<&str>,
        constraints: &Constraints,
    ) -> Result<Option<Session>, PluginError> {
        let get = |name: &str| {
            self.host
                .var(name)
                .and_then(|value| value.to_str())
                .map(str::to_owned)
        };
        let Some(found) = service_principal::from_vars(prefix.unwrap_or_default(), get) else {
            return Ok(None);
        };
        self.detect_service_principal(configured, found, constraints)
            .await
    }

    /// A service principal from the environment or an earlier block, signed
    /// in to a new directory, if the pins allow it. Its subscription is the
    /// block's unless the block pins one.
    async fn detect_service_principal(
        &self,
        configured: &Configured<C::Az>,
        found: Found,
        constraints: &Constraints,
    ) -> Result<Option<Session>, PluginError> {
        if let (Some(TenantRef::Id(pin)), TenantRef::Id(tenant)) =
            (&constraints.tenant, &found.principal.tenant)
            && pin != tenant
        {
            return Ok(None);
        }
        let mut constraints = constraints.clone();
        if constraints.subscription.is_none() {
            constraints.subscription = found.subscription;
        }
        let session = self
            .sign_in_service_principal(configured, found.principal, &constraints)
            .await;
        // A secret that az refuses is an error the person should see.
        unusable_is_none(session, &[])
    }

    /// What an earlier block's outputs hold: a service principal, or else
    /// the `az` login in its `AZURE_CONFIG_DIR`, with its choice of tenant
    /// and subscription where the block pins none.
    async fn detect_values(
        &self,
        configured: &Configured<C::Az>,
        values: &HashMap<String, String>,
        constraints: &Constraints,
    ) -> Result<Option<Session>, PluginError> {
        let get = |name: &str| values.get(name).cloned();
        if let Some(found) = service_principal::from_vars("", get) {
            return self
                .detect_service_principal(configured, found, constraints)
                .await;
        }
        let Some(from) = values
            .get("AZURE_CONFIG_DIR")
            .map(PathBuf::from)
            .filter(|dir| dir.is_absolute())
        else {
            return Ok(None);
        };
        let mut constraints = constraints.clone();
        let tenant = values
            .get("AZURE_TENANT_ID")
            .and_then(|id| TenantRef::parse(id));
        if constraints.tenant.is_none() {
            constraints.tenant.clone_from(&tenant);
        }
        if constraints.subscription.is_none() && constraints.tenant == tenant {
            constraints.subscription = values.get("AZURE_SUBSCRIPTION_ID").cloned();
        }
        let method = values
            .get("AZURE_AUTH_TYPE")
            .and_then(|name| SignInMethod::parse(name))
            .filter(|method| *method != SignInMethod::ServicePrincipal)
            .unwrap_or(SignInMethod::Cli);
        let extensions = values.get("AZURE_EXTENSION_DIR").map(PathBuf::from);
        self.detect_copy(
            configured,
            method,
            &from,
            extensions.as_deref(),
            Listing::Saved,
            &constraints,
        )
        .await
    }

    /// Signs `principal` in to a new directory: `az` with its secret or
    /// with the block's own copy of its certificate.
    async fn sign_in_service_principal(
        &self,
        configured: &Configured<C::Az>,
        mut principal: ServicePrincipal,
        constraints: &Constraints,
    ) -> Result<Session, PluginError> {
        let dir = AzDir {
            config: configured.state.create().await?,
            extensions: None,
        };
        let session = async {
            if let Credential::Certificate(path) = &principal.credential {
                let copy = configured.state.copy_certificate(path, &dir.config).await?;
                principal.credential = Credential::Certificate(copy);
            }
            configured
                .az
                .login_service_principal(&dir, &principal)
                .await?;
            let method = SignInMethod::ServicePrincipal;
            establish(
                &configured.az,
                method,
                dir.clone(),
                Listing::Saved,
                constraints,
                Some(principal),
            )
            .await
        }
        .await;
        keep_or_remove(&configured.state, &dir, session).await
    }
}

/// `session`, or its directory removed if it failed.
async fn keep_or_remove(
    state: &StateDir,
    dir: &AzDir,
    session: Result<Session, PluginError>,
) -> Result<Session, PluginError> {
    if session.is_err() {
        state.remove(&dir.config).await?;
    }
    session
}

/// A detected credential the block cannot use as it is is not found: one
/// the pins rule out, one with no `az` to use it, or one of `unusable`'s
/// kinds. Any other error is the answer.
fn unusable_is_none(
    session: Result<Session, PluginError>,
    unusable: &[ErrorKind],
) -> Result<Option<Session>, PluginError> {
    match session {
        Ok(session) => Ok(Some(session)),
        Err(error) => match error.kind() {
            ErrorKind::PinMismatch | ErrorKind::ToolMissing => Ok(None),
            kind if unusable.contains(&kind) => Ok(None),
            ErrorKind::NotConfigured
            | ErrorKind::UnsupportedProtocolVersion
            | ErrorKind::InvalidParams
            | ErrorKind::NotSignedIn
            | ErrorKind::Expired
            | ErrorKind::RequirementNotMet
            | ErrorKind::AccessDenied
            | ErrorKind::Cancelled
            | ErrorKind::TimedOut
            | ErrorKind::Network
            | ErrorKind::TlsError
            | ErrorKind::Internal => Err(error),
        },
    }
}

/// Reads what a fresh sign-in in `dir` can see, and chooses what the pins
/// and the login leave no choice about.
async fn establish<A: Az>(
    az: &A,
    method: SignInMethod,
    dir: AzDir,
    listing: Listing,
    constraints: &Constraints,
    service_principal: Option<ServicePrincipal>,
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
    let accounts = az.accounts(&dir, listing).await?;
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
        service_principal,
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
    how: Interactive,
    dir: &AzDir,
    tenant: Option<&TenantRef>,
    prompts: &Prompts,
) -> Result<(), PluginError> {
    let (sender, receiver) = oneshot::channel();
    match how {
        Interactive::Browser => {
            prompts.waiting().await?;
            az.login(dir, Interactive::Browser, tenant, sender).await
        }
        Interactive::DeviceCode => {
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
            match source {
                Source::Named { name } if name != CLI_SOURCE => problems.add(format!(
                    "source {name:?} is not one this plugin names: it names {CLI_SOURCE:?}"
                )),
                Source::Env {
                    prefix: Some(prefix),
                } if !prefix.is_empty() && !service_principal::is_prefix(prefix) => {
                    problems.add(format!(
                        "the env source's prefix must be capital letters, digits and underscores, starting with a letter and ending with _, such as CI_, not {prefix:?}"
                    ));
                }
                Source::Named { .. } | Source::Env { .. } | Source::Values { .. } => {}
            }
        }
        problems.check("detect")?;

        let mut first_error = None;
        for source in &params.sources {
            let (found, name) = match source {
                Source::Named { .. } => (
                    self.detect_local(configured, &constraints).await,
                    CLI_SOURCE,
                ),
                Source::Env { prefix } => (
                    self.detect_env(configured, prefix.as_deref(), &constraints)
                        .await,
                    ENV_SOURCE,
                ),
                Source::Values { values, from } => (
                    self.detect_values(configured, values, &constraints).await,
                    from.as_str(),
                ),
            };
            match found {
                Ok(Some(session)) => {
                    let identity = session.identity();
                    self.install(&configured.state, session).await?;
                    return Ok(DetectResult::found(identity, name));
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
        let how = match method {
            SignInMethod::Cli => Interactive::Browser,
            SignInMethod::DeviceCode => Interactive::DeviceCode,
            SignInMethod::ServicePrincipal => {
                let principal = params::service_principal(&params.fields, &constraints)?;
                let session = self
                    .sign_in_service_principal(configured, principal, &constraints)
                    .await?;
                let identity = session.identity();
                self.install(&configured.state, session).await?;
                return Ok(SignInResult(identity));
            }
        };
        let tenant = params::login_tenant(&params.fields, &constraints)?;

        let dir = AzDir {
            config: configured.state.create().await?,
            extensions: None,
        };
        let session = async {
            login(&configured.az, how, &dir, tenant.as_ref(), &prompts).await?;
            establish(
                &configured.az,
                method,
                dir.clone(),
                Listing::Saved,
                &constraints,
                None,
            )
            .await
        }
        .await;
        let session = keep_or_remove(&configured.state, &dir, session).await?;
        let identity = session.identity();
        self.install(&configured.state, session).await?;
        Ok(SignInResult(identity))
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
