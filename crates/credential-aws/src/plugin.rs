use std::future::{self, Future};
use std::sync::{Mutex, PoisonError};

use runbooks_plugin_protocol::credential::{
    ConfigureParams, ConfigureResult, DetectParams, DetectResult, EnvResult, EnvValue,
    EnvValueToItem, ErrorKind, Identity, Requirement, SelectParams, SelectResult, SignInParams,
    SignInResult, SignOutResult, TargetsParams, TargetsResult,
};
use runbooks_plugin_transport::{CredentialPlugin, PluginError, Prompts};
use serde_json::Map;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::aws::{Aws, AwsCredentials};
use crate::detect::{
    AWS_ACCESS_KEY_ID, AWS_REGION, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN, Environment,
    parse_sources,
};
use crate::error::{self, invalid_params};
use crate::identity::{ACCOUNT, Pins, Principal, ROLE};
use crate::methods::{
    self, ACCESS_KEY_ID, DEFAULT_REGION, Fields, SECRET_ACCESS_KEY, SESSION_TOKEN, SignInMethod,
};
use crate::region::Region;
use crate::secret::Secret;

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
    session: Mutex<Session>,
}

#[derive(Debug)]
enum Session {
    SignedOut,
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
}

impl Ready {
    fn identity(&self) -> Identity {
        self.principal
            .identity(&self.method, self.credentials.expires_at)
    }
}

impl<A: Aws, C: Clock> AwsPlugin<A, C> {
    /// `env` is the environment the `env` detection source reads.
    pub const fn new(aws: A, clock: C, env: Environment) -> Self {
        Self {
            aws,
            clock,
            env,
            session: Mutex::new(Session::SignedOut),
        }
    }

    fn set(&self, session: Session) {
        // No guard is held across an await or a call that can panic.
        *self.session.lock().unwrap_or_else(PoisonError::into_inner) = session;
    }

    fn ready(&self) -> Option<Ready> {
        match &*self.session.lock().unwrap_or_else(PoisonError::into_inner) {
            Session::SignedOut => None,
            Session::Ready(ready) => Some(Ready::clone(ready)),
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
        })
    }

    /// What `env` answers.
    fn env_now(&self) -> Result<EnvResult, PluginError> {
        let ready = self.ready().ok_or_else(|| {
            PluginError::new(
                ErrorKind::NotSignedIn,
                "not signed in to AWS: sign in first",
            )
        })?;
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
                    return Ok(DetectResult::found(identity, origin));
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
        _prompts: Prompts,
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
        let ready = match method {
            SignInMethod::Credentials => self.sign_in_with_keys(fields, &pins).await?,
        };
        let identity = ready.identity();
        self.set(Session::Ready(Box::new(ready)));
        Ok(SignInResult(identity))
    }

    fn targets(
        &self,
        params: TargetsParams,
    ) -> impl Future<Output = Result<TargetsResult, PluginError>> + Send {
        future::ready(Err(no_targets(&params.level)))
    }

    fn select(
        &self,
        params: SelectParams,
    ) -> impl Future<Output = Result<SelectResult, PluginError>> + Send {
        let level = params.targets.keys().next().map_or(ACCOUNT, String::as_str);
        future::ready(Err(no_targets(level)))
    }

    fn env(&self) -> impl Future<Output = Result<EnvResult, PluginError>> + Send {
        future::ready(self.env_now())
    }

    fn sign_out(&self) -> impl Future<Output = Result<SignOutResult, PluginError>> + Send {
        self.set(Session::SignedOut);
        future::ready(Ok(SignOutResult(Map::new())))
    }
}

fn no_targets(level: &str) -> PluginError {
    if level == ACCOUNT || level == ROLE {
        invalid_params(&format!(
            "AWS has no {level} to choose for these credentials: their account and role are fixed"
        ))
    } else {
        invalid_params(&format!(
            "AWS has no level {:?}: its levels are {ACCOUNT} and {ROLE}",
            level.chars().take(64).collect::<String>()
        ))
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
