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
use crate::methods;
use crate::region::Region;

/// The wall clock, for expiry. Tests pass a fixed one.
pub trait Clock: Send + Sync + 'static {
    fn now(&self) -> OffsetDateTime;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// The AWS credential plugin for one block. It holds at most one credential:
/// the last one `detect` found or a sign-in produced.
pub struct AwsPlugin<A, C> {
    aws: A,
    clock: C,
    env: Environment,
    session: Mutex<Session>,
}

enum Session {
    SignedOut,
    Ready(Box<Ready>),
}

/// A credential AWS accepted, with what a run gets besides the keys.
#[derive(Clone)]
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
    pub fn new(aws: A, clock: C, env: Environment) -> Self {
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
}

/// AWS has no requirement kinds: a request that names one is refused.
fn no_requirements(requirements: &[Requirement]) -> Result<(), PluginError> {
    if requirements.is_empty() {
        Ok(())
    } else {
        Err(invalid_params(
            "AWS sign-in takes no requirements: remove them from the request",
        ))
    }
}

impl<A: Aws, C: Clock> CredentialPlugin for AwsPlugin<A, C> {
    async fn configure(&self, _params: ConfigureParams) -> Result<ConfigureResult, PluginError> {
        Ok(methods::describe())
    }

    /// Tries each source in order and keeps the first credential AWS accepts
    /// that matches the pins. When none does, a source whose credential AWS
    /// refused or the pins ruled out answers with that error, so the block
    /// can say why; with no credential in any source, nothing was found.
    async fn detect(&self, params: DetectParams) -> Result<DetectResult, PluginError> {
        let pins = Pins::parse(&params.pins).map_err(invalid_params)?;
        no_requirements(&params.requirements)?;
        let sources = parse_sources(params.sources).map_err(invalid_params)?;

        let mut first_failure = None;
        for source in &sources {
            let found = match source.read(&self.env) {
                Ok(Some(found)) => found,
                Ok(None) => continue,
                Err(unreadable) => {
                    first_failure.get_or_insert(invalid_params(unreadable));
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
        match first_failure {
            Some(error) => Err(error),
            None => Ok(DetectResult::not_found()),
        }
    }

    async fn sign_in(
        &self,
        params: SignInParams,
        _prompts: Prompts,
    ) -> Result<SignInResult, PluginError> {
        Err(invalid_params(format!(
            "AWS has no sign-in method {:?}",
            params.method.chars().take(64).collect::<String>()
        )))
    }

    async fn targets(&self, params: TargetsParams) -> Result<TargetsResult, PluginError> {
        Err(no_targets(&params.level))
    }

    async fn select(&self, params: SelectParams) -> Result<SelectResult, PluginError> {
        let level = params.targets.keys().next().map_or(ACCOUNT, String::as_str);
        Err(no_targets(level))
    }

    async fn env(&self) -> Result<EnvResult, PluginError> {
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

    async fn sign_out(&self) -> Result<SignOutResult, PluginError> {
        self.set(Session::SignedOut);
        Ok(SignOutResult(Map::new()))
    }
}

fn no_targets(level: &str) -> PluginError {
    if level == ACCOUNT || level == ROLE {
        invalid_params(format!(
            "AWS has no {level} to choose for these credentials: their account and role are fixed"
        ))
    } else {
        invalid_params(format!(
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
        match &credentials.session_token {
            Some(token) => value(AWS_SESSION_TOKEN, token.expose(), true, both()),
            None => value(AWS_SESSION_TOKEN, "", true, vec![EnvValueToItem::Output]),
        },
        value(AWS_REGION, ready.region.as_str(), false, both()),
    ]
}
