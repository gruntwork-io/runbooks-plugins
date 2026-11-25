use std::collections::HashMap;
use std::future::{self, Future};
use std::sync::{Mutex, MutexGuard, PoisonError};

use runbooks_plugin_protocol::credential::{
    ConfigureParams, ConfigureResult, DetectParams, DetectResult, EnvResult, EnvValue,
    EnvValueToItem, ErrorKind, Identity, Requirement, SelectParams, SelectResult, SignInParams,
    SignInResult, SignOutResult, Target, TargetsParams, TargetsResult,
};
use runbooks_plugin_transport::{CredentialPlugin, PluginError, Prompts};
use serde_json::Map;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::aws::{Aws, AwsCredentials, SsoAccount, read_profiles};
use crate::detect::{
    AWS_ACCESS_KEY_ID, AWS_REGION, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN, Environment,
    parse_sources,
};
use crate::error::{self, invalid_params};
use crate::identity::{ACCOUNT, AccountId, Pins, Principal, ROLE};
use crate::methods::{
    self, ACCESS_KEY_ID, DEFAULT_REGION, Fields, PROFILE, SECRET_ACCESS_KEY, SESSION_TOKEN,
    SSO_REGION, SignInMethod,
};
use crate::profile;
use crate::region::Region;
use crate::secret::Secret;
use crate::sso::{self, SsoLogin};

/// How long before a role's keys expire `env` gets fresh ones.
const REFRESH_MARGIN: time::Duration = time::Duration::minutes(5);

/// The wall clock, for expiry. Tests pass a fixed one.
pub trait Clock: Send + Sync + 'static {
    /// The current time.
    fn now(&self) -> OffsetDateTime;
}

/// The system's clock, in UTC.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// The AWS credential plugin for one block. It holds at most one credential:
/// the last one `detect` found or a sign-in produced.
#[derive(Debug)]
pub struct AwsPlugin<A, C> {
    aws: A,
    clock: C,
    env: Environment,
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    /// Counts every change of session, so a call that read the session
    /// before an await can tell whether it is still the same one.
    generation: u64,
    session: Session,
}

#[derive(Clone, Debug)]
enum Session {
    SignedOut,
    /// Signed in to IAM Identity Center, with no role chosen yet.
    Choosing(Box<SsoLogin>),
    Ready(Box<Ready>),
}

/// A credential AWS accepted, with what a run gets besides the keys.
#[derive(Clone, Debug)]
struct Ready {
    credentials: AwsCredentials,
    /// The run's `AWS_REGION`.
    region: Region,
    principal: Principal,
    /// The sign-in method or detection source it came from.
    method: String,
    /// For a role IAM Identity Center gave: the login, to list other
    /// targets and to get fresh keys.
    sso: Option<SsoRole>,
    /// For a profile's keys: the sign-in, to get fresh ones.
    profile: Option<ProfileSignIn>,
}

/// A sign-in with a profile, as it was asked for.
#[derive(Clone, Debug)]
struct ProfileSignIn {
    name: String,
    default_region: Option<Region>,
    pins: Pins,
}

#[derive(Clone, Debug)]
struct SsoRole {
    login: SsoLogin,
    account: AccountId,
    role: String,
}

impl Ready {
    fn identity(&self) -> Identity {
        self.principal
            .identity(&self.method, self.credentials.expires_at)
    }
}

/// The session a sign-in leaves, with the identity it answers.
fn ready(ready: Ready) -> (Session, Identity) {
    let identity = ready.identity();
    (Session::Ready(Box::new(ready)), identity)
}

impl<A: Aws, C: Clock> AwsPlugin<A, C> {
    /// `env` is the environment the `env` detection source reads.
    pub const fn new(aws: A, clock: C, env: Environment) -> Self {
        Self {
            aws,
            clock,
            env,
            state: Mutex::new(State {
                generation: 0,
                session: Session::SignedOut,
            }),
        }
    }

    // No guard is held across an await or a call that can panic.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn set(&self, session: Session) {
        let mut state = self.lock();
        state.generation += 1;
        state.session = session;
    }

    /// Sets `session` only if nothing changed it since `generation`.
    fn set_if(&self, generation: u64, session: Session) {
        let mut state = self.lock();
        if state.generation == generation {
            state.generation += 1;
            state.session = session;
        }
    }

    fn current(&self) -> (u64, Session) {
        let state = self.lock();
        (state.generation, state.session.clone())
    }

    /// The IAM Identity Center login that `level`'s targets are chosen from.
    fn sso_login(&self, level: &str) -> Result<SsoLogin, PluginError> {
        match self.current().1 {
            Session::SignedOut => Err(not_signed_in()),
            Session::Choosing(login) => Ok(*login),
            Session::Ready(ready) => match ready.sso {
                Some(sso) => Ok(sso.login),
                None => Err(invalid_params(&format!(
                    "AWS has no {level} to choose for these credentials: their account and role are fixed"
                ))),
            },
        }
    }

    /// Keeps account names for the identity card, whichever login is held.
    fn remember(&self, accounts: &[SsoAccount]) {
        let mut state = self.lock();
        match &mut state.session {
            Session::Choosing(login) => login.remember(accounts),
            Session::Ready(ready) => {
                if let Some(sso) = &mut ready.sso {
                    sso.login.remember(accounts);
                }
            }
            Session::SignedOut => {}
        }
    }

    /// Asks STS who `credentials` belong to, in the partition of
    /// `sts_region`, and checks that against the pins.
    async fn check(
        &self,
        credentials: AwsCredentials,
        region: Region,
        sts_region: &Region,
        method: String,
        pins: &Pins,
    ) -> Result<Ready, PluginError> {
        let home = sts_region.partition_home();
        let caller = self
            .aws
            .caller_identity(&credentials, &home)
            .await
            .map_err(|e| error::aws(&e, &format!("checking the credentials in {home}")))?;
        let principal = Principal::from_caller(caller);
        pins.check(&principal)
            .map_err(|mismatch| PluginError::new(ErrorKind::PinMismatch, mismatch.to_string()))?;
        Ok(Ready {
            credentials,
            region,
            principal,
            method,
            sso: None,
            profile: None,
        })
    }

    async fn sign_in_with_keys(
        &self,
        fields: Fields<'_>,
        pins: &Pins,
    ) -> Result<Ready, PluginError> {
        let region = fields
            .region(DEFAULT_REGION)
            .map_err(|error| invalid_params(&error))?
            .unwrap_or_else(Region::default_region);
        let credentials = AwsCredentials {
            access_key_id: fields.required(ACCESS_KEY_ID).to_owned(),
            secret_access_key: Secret::new(fields.required(SECRET_ACCESS_KEY)),
            session_token: fields.get(SESSION_TOKEN).map(Secret::new),
            expires_at: None,
        };
        let method = SignInMethod::Credentials.name().to_owned();
        self.check(credentials, region.clone(), &region, method, pins)
            .await
    }

    /// Reads the profile files where the environment says they are, gets the
    /// profile's keys, assuming each role in its chain in the partition of
    /// the run's region, and checks them. The run's region is the profile's,
    /// else the default region.
    async fn sign_in_with_profile(&self, sign_in: ProfileSignIn) -> Result<Ready, PluginError> {
        let profiles = read_profiles(profile::file_env(&self.env))
            .await
            .map_err(|e| invalid_params(&format!("{e}: fix the line it names")))?;
        let plan = profile::plan(&profiles, &sign_in.name, &self.env, self.clock.now())
            .map_err(|error| invalid_params(&error))?;
        let region = match plan.region.as_deref() {
            Some(region) => Region::parse(region).map_err(|e| {
                invalid_params(&format!(
                    "profile {:?}'s region is invalid: {e}",
                    sign_in.name
                ))
            })?,
            None => sign_in
                .default_region
                .clone()
                .unwrap_or_else(Region::default_region),
        };
        let home = region.partition_home();
        let mut credentials = plan.base;
        for role in &plan.roles {
            credentials = self
                .aws
                .assume_role(&credentials, role, &home)
                .await
                .map_err(|e| {
                    error::aws(&e, &format!("assuming role {} in {home}", role.role_arn))
                })?;
        }
        let mut ready = self
            .check(
                credentials,
                region.clone(),
                &region,
                profile::METHOD.to_owned(),
                &sign_in.pins,
            )
            .await?;
        ready.profile = Some(sign_in);
        Ok(ready)
    }

    /// The device authorization, then as far as the choice goes without the
    /// person: straight to the role when both are pinned, and to the only
    /// role of the only account. Otherwise the person chooses.
    async fn sign_in_with_sso(
        &self,
        fields: Fields<'_>,
        pins: Pins,
        prompts: &Prompts,
    ) -> Result<(Session, Identity), PluginError> {
        let start_url = fields
            .start_url()
            .map_err(|error| invalid_params(&error))?
            .to_owned();
        let sso_region = fields
            .region(SSO_REGION)
            .map_err(|error| invalid_params(&error))?
            .unwrap_or_else(Region::default_region);
        let run_region = fields
            .region(DEFAULT_REGION)
            .map_err(|error| invalid_params(&error))?
            .unwrap_or_else(Region::default_region);
        let token = sso::device_sign_in(&self.aws, prompts, &start_url, &sso_region).await?;
        let expires_at = token
            .expires_in
            .and_then(|lifetime| time::Duration::try_from(lifetime).ok())
            .and_then(|lifetime| self.clock.now().checked_add(lifetime));
        let mut login = SsoLogin {
            start_url,
            token,
            expires_at,
            sso_region,
            run_region,
            pins,
            account_names: HashMap::new(),
            account: None,
        };
        if let (Some(account), Some(role)) = (login.pins.account.clone(), login.pins.role.clone()) {
            return Ok(ready(self.sign_in_to_role(login, account, role).await?));
        }
        let accounts = sso::accounts(&self.aws, &login).await?;
        login.remember(&accounts);
        if let [only] = accounts.as_slice() {
            let roles = sso::roles(&self.aws, &login, &only.id).await?;
            if let [role] = roles.as_slice() {
                let (account, role) = (only.id.clone(), role.clone());
                return Ok(ready(self.sign_in_to_role(login, account, role).await?));
            }
        }
        let identity = login.identity();
        Ok((Session::Choosing(Box::new(login)), identity))
    }

    /// Gets `role`'s keys in `account` and checks them as any others.
    async fn sign_in_to_role(
        &self,
        mut login: SsoLogin,
        account: AccountId,
        role: String,
    ) -> Result<Ready, PluginError> {
        sso::check_choice(&login.pins, &account, Some(&role))?;
        let credentials = self
            .aws
            .role_credentials(&login.token, &account, &role, &login.sso_region)
            .await
            .map_err(|e| {
                sso::sso_error(
                    &e,
                    &format!("getting keys for role {role} in account {account}"),
                )
            })?;
        let mut ready = self
            .check(
                credentials,
                login.run_region.clone(),
                &login.sso_region,
                sso::METHOD.to_owned(),
                &login.pins,
            )
            .await?;
        // The name the person chose it by, over the IAM alias.
        if let Some(name) = login.account_names.get(&account) {
            ready.principal.account_name = Some(name.clone());
        }
        login.account = Some(account.clone());
        ready.sso = Some(SsoRole {
            login,
            account,
            role,
        });
        Ok(ready)
    }

    /// The keys, fresh ones first when these are about to expire: a role's
    /// from IAM Identity Center, a profile's by signing in with it again.
    /// Keys that still work are kept if fresh ones cannot be got.
    async fn refreshed(&self, generation: u64, ready: Ready) -> Result<Ready, PluginError> {
        let Some(expires_at) = ready.credentials.expires_at else {
            return Ok(ready);
        };
        let now = self.clock.now();
        if expires_at - now > REFRESH_MARGIN {
            return Ok(ready);
        }
        let fresh = if let Some(sso) = &ready.sso {
            self.aws
                .role_credentials(
                    &sso.login.token,
                    &sso.account,
                    &sso.role,
                    &sso.login.sso_region,
                )
                .await
                .map(|credentials| Ready {
                    credentials,
                    ..ready.clone()
                })
                .map_err(|e| sso::sso_error(&e, "getting fresh keys for the role"))
        } else if let Some(sign_in) = &ready.profile {
            self.sign_in_with_profile(sign_in.clone()).await
        } else {
            return Ok(ready);
        };
        match fresh {
            Ok(fresh) => {
                self.set_if(generation, Session::Ready(Box::new(fresh.clone())));
                Ok(fresh)
            }
            Err(_) if expires_at > now => Ok(ready),
            Err(e) => Err(e),
        }
    }
}

/// AWS has no requirement kinds: a request that names one is refused.
fn no_requirements(requirements: &[Requirement]) -> Result<(), PluginError> {
    if requirements.is_empty() {
        Ok(())
    } else {
        Err(invalid_params(
            &"AWS sign-in takes no requirements: remove them from the request",
        ))
    }
}

fn not_signed_in() -> PluginError {
    PluginError::new(
        ErrorKind::NotSignedIn,
        "not signed in to AWS: sign in first",
    )
}

fn known_level(level: &str) -> Result<(), PluginError> {
    if level == ACCOUNT || level == ROLE {
        Ok(())
    } else {
        Err(invalid_params(&format!(
            "AWS has no level {:?}: its levels are {ACCOUNT} and {ROLE}",
            level.chars().take(64).collect::<String>()
        )))
    }
}

impl<A: Aws, C: Clock> CredentialPlugin for AwsPlugin<A, C> {
    fn configure(
        &self,
        _params: ConfigureParams,
    ) -> impl Future<Output = Result<ConfigureResult, PluginError>> + Send {
        future::ready(Ok(methods::describe()))
    }

    /// Tries each source in order and keeps the first credential AWS accepts
    /// that matches the pins. When none does, a source whose credential AWS
    /// refused or the pins ruled out answers with that error, so the block
    /// can say why; with no credential in any source, nothing was found.
    async fn detect(&self, params: DetectParams) -> Result<DetectResult, PluginError> {
        let pins = Pins::parse(&params.pins).map_err(|error| invalid_params(&error))?;
        no_requirements(&params.requirements)?;
        let sources = parse_sources(params.sources).map_err(|error| invalid_params(&error))?;

        let mut first_failure = None;
        for source in &sources {
            let found = match source.read(&self.env) {
                Ok(Some(found)) => found,
                Ok(None) => continue,
                Err(unreadable) => {
                    first_failure.get_or_insert_with(|| invalid_params(&unreadable));
                    continue;
                }
            };
            let region = found.region.unwrap_or_else(Region::default_region);
            let origin = found.origin.to_string();
            let source = found.origin.source();
            match self
                .check(
                    found.credentials,
                    region.clone(),
                    &region,
                    origin.clone(),
                    &pins,
                )
                .await
            {
                Ok(ready) => {
                    let identity = ready.identity();
                    self.set(Session::Ready(Box::new(ready)));
                    return Ok(DetectResult::found(identity, source));
                }
                Err(error) => {
                    first_failure.get_or_insert(error);
                }
            }
        }
        first_failure.map_or_else(|| Ok(DetectResult::not_found()), Err)
    }

    async fn sign_in(
        &self,
        params: SignInParams,
        prompts: Prompts,
    ) -> Result<SignInResult, PluginError> {
        let Some(method) = SignInMethod::parse(&params.method) else {
            let known: Vec<&str> = SignInMethod::ALL.iter().map(|m| m.name()).collect();
            return Err(invalid_params(&format!(
                "AWS has no sign-in method {:?}: its methods are {}",
                params.method.chars().take(64).collect::<String>(),
                known.join(", ")
            )));
        };
        let pins = Pins::parse(&params.pins).map_err(|error| invalid_params(&error))?;
        no_requirements(&params.requirements)?;
        let fields =
            Fields::parse(method, &params.fields).map_err(|error| invalid_params(&error))?;
        let (session, identity) = match method {
            SignInMethod::Credentials => ready(self.sign_in_with_keys(fields, &pins).await?),
            SignInMethod::Sso => self.sign_in_with_sso(fields, pins, &prompts).await?,
            SignInMethod::Profile => {
                let sign_in = ProfileSignIn {
                    name: fields.required(PROFILE).to_owned(),
                    default_region: fields
                        .region(DEFAULT_REGION)
                        .map_err(|error| invalid_params(&error))?,
                    pins,
                };
                ready(self.sign_in_with_profile(sign_in).await?)
            }
        };
        self.set(session);
        Ok(SignInResult(identity))
    }

    /// The accounts of an IAM Identity Center login, or the roles in one of
    /// them: `parent`, else the account `select` chose.
    async fn targets(&self, params: TargetsParams) -> Result<TargetsResult, PluginError> {
        let level = params.level.as_str();
        known_level(level)?;
        let login = self.sso_login(level)?;
        let targets = if level == ACCOUNT {
            let accounts = sso::accounts(&self.aws, &login).await?;
            self.remember(&accounts);
            accounts
                .into_iter()
                .map(|account| Target {
                    id: account.id.to_string(),
                    name: account.name,
                })
                .collect()
        } else {
            let account = match params.parent.as_deref() {
                Some(parent) => AccountId::parse(parent).map_err(|error| invalid_params(&error))?,
                None => login.account.clone().ok_or_else(|| {
                    invalid_params(
                        &"the role level lists the roles of one account: pass its id as parent",
                    )
                })?,
            };
            sso::check_choice(&login.pins, &account, None)?;
            sso::roles(&self.aws, &login, &account)
                .await?
                .into_iter()
                .map(|role| Target {
                    id: role.clone(),
                    name: role,
                })
                .collect()
        };
        Ok(TargetsResult { targets })
    }

    /// An account alone is kept for choosing its role; an account with a
    /// role signs in to it.
    async fn select(&self, params: SelectParams) -> Result<SelectResult, PluginError> {
        for (level, id) in &params.targets {
            known_level(level)?;
            if id.is_none() {
                return Err(invalid_params(&format!(
                    "targets.{level} is null, but AWS's {level} level is not optional"
                )));
            }
        }
        let role = params.targets.get(ROLE).and_then(Option::as_ref);
        let mut login = self.sso_login(if role.is_some() { ROLE } else { ACCOUNT })?;
        let account = params
            .targets
            .get(ACCOUNT)
            .and_then(Option::as_ref)
            .ok_or_else(|| {
                invalid_params(&"select needs the account: a role is chosen within one")
            })?;
        let account = AccountId::parse(account).map_err(|error| invalid_params(&error))?;
        let Some(role) = role else {
            sso::check_choice(&login.pins, &account, None)?;
            login.account = Some(account);
            let identity = login.identity();
            self.set(Session::Choosing(Box::new(login)));
            return Ok(SelectResult(identity));
        };
        let (session, identity) = ready(self.sign_in_to_role(login, account, role.clone()).await?);
        self.set(session);
        Ok(SelectResult(identity))
    }

    async fn env(&self) -> Result<EnvResult, PluginError> {
        let (generation, session) = self.current();
        let ready = match session {
            Session::Ready(ready) => self.refreshed(generation, *ready).await?,
            Session::Choosing(_) => {
                return Err(PluginError::new(
                    ErrorKind::NotSignedIn,
                    "signed in to IAM Identity Center, but no role is chosen yet: choose an account and role first",
                ));
            }
            Session::SignedOut => return Err(not_signed_in()),
        };
        let expires_at = ready.credentials.expires_at;
        if let Some(expired) = expires_at.filter(|at| *at <= self.clock.now()) {
            let at = expired
                .format(&Rfc3339)
                .unwrap_or_else(|_| expired.to_string());
            return Err(PluginError::new(
                ErrorKind::Expired,
                format!("the AWS credentials expired at {at}: sign in again"),
            ));
        }
        Ok(EnvResult {
            expires_at: expires_at.map(Into::into),
            values: env_values(&ready),
        })
    }

    fn sign_out(&self) -> impl Future<Output = Result<SignOutResult, PluginError>> + Send {
        self.set(Session::SignedOut);
        future::ready(Ok(SignOutResult(Map::new())))
    }
}

/// What a run gets. A credential with no session token still sets the
/// output, empty, as the block always has; the variable is left unset.
fn env_values(ready: &Ready) -> Vec<EnvValue> {
    let both = || vec![EnvValueToItem::Env, EnvValueToItem::Output];
    let value = |name: &str, value: &str, sensitive, to| EnvValue {
        name: name.to_owned(),
        sensitive,
        to,
        value: value.to_owned(),
    };
    let credentials = &ready.credentials;
    vec![
        value(AWS_ACCESS_KEY_ID, &credentials.access_key_id, false, both()),
        value(
            AWS_SECRET_ACCESS_KEY,
            credentials.secret_access_key.expose(),
            true,
            both(),
        ),
        credentials.session_token.as_ref().map_or_else(
            || value(AWS_SESSION_TOKEN, "", true, vec![EnvValueToItem::Output]),
            |token| value(AWS_SESSION_TOKEN, token.expose(), true, both()),
        ),
        value(AWS_REGION, ready.region.as_str(), false, both()),
    ]
}
