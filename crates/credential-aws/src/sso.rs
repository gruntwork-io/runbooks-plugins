//! IAM Identity Center: the device authorization the person approves in the
//! browser, and the login it leaves, from which accounts and roles are listed
//! and a role's keys are got.

use std::collections::HashMap;
use std::time::Duration;

use runbooks_plugin_protocol::credential::{ErrorKind, Identity, IdentityKind, Target};
use runbooks_plugin_transport::{PluginError, Prompts};
use time::OffsetDateTime;
use tokio::time::{Instant, sleep};

use crate::aws::{Aws, AwsError, AwsErrorKind, SsoAccount, SsoToken, TokenPoll};
use crate::error;
use crate::identity::{ACCOUNT, AccountId, Pins};
use crate::region::Region;

/// The method an SSO identity names.
pub(crate) const METHOD: &str = "sso";

/// What RFC 8628 adds to the polling interval for each `slow_down`.
const SLOW_DOWN_STEP: Duration = Duration::from_secs(5);

/// A person signed in to IAM Identity Center.
#[derive(Clone, Debug)]
pub(crate) struct SsoLogin {
    pub start_url: String,
    pub token: SsoToken,
    pub expires_at: Option<OffsetDateTime>,
    /// Where IAM Identity Center runs: every SSO call goes here.
    pub sso_region: Region,
    /// The run's `AWS_REGION`.
    pub run_region: Region,
    pub pins: Pins,
    /// Account names as IAM Identity Center last listed them.
    pub account_names: HashMap<AccountId, String>,
    /// The account chosen, before or with its role.
    pub account: Option<AccountId>,
}

impl SsoLogin {
    /// The identity card while no role is chosen: the access portal, and the
    /// account once one is.
    pub(crate) fn identity(&self) -> Identity {
        let targets = self
            .account
            .iter()
            .map(|id| {
                let target = Target {
                    id: id.to_string(),
                    name: self.account_name(id),
                };
                (ACCOUNT.to_owned(), Some(target))
            })
            .collect();
        Identity {
            expires_at: self.expires_at.map(Into::into),
            kind: IdentityKind::User,
            method: METHOD.to_owned(),
            principal: self.start_url.clone(),
            targets,
            warnings: Vec::new(),
        }
    }

    pub(crate) fn account_name(&self, id: &AccountId) -> String {
        self.account_names
            .get(id)
            .cloned()
            .unwrap_or_else(|| id.to_string())
    }

    pub(crate) fn remember(&mut self, accounts: &[SsoAccount]) {
        for account in accounts {
            self.account_names
                .insert(account.id.clone(), account.name.clone());
        }
    }
}

/// Starts a device authorization, asks the person to approve it, and polls
/// at AWS's interval until they do, refuse, or it expires. Dropping the
/// future stops the polling.
///
/// # Errors
///
/// `accessDenied` when the person refuses, `timedOut` when the request
/// expires first, and the kind of any AWS failure.
pub(crate) async fn device_sign_in<A: Aws>(
    aws: &A,
    prompts: &Prompts,
    start_url: &str,
    region: &Region,
) -> Result<SsoToken, PluginError> {
    let device = aws
        .start_device_authorization(start_url, region)
        .await
        .map_err(|e| error::aws(&e, &format!("starting the SSO sign-in in {region}")))?;
    prompts
        .open_url(
            device.verification_url.clone(),
            Some(device.user_code.clone()),
        )
        .await?;
    let deadline = Instant::now() + device.expires_in;
    let mut interval = device.interval;
    loop {
        sleep(interval).await;
        match aws.create_token(&device, region).await {
            Ok(TokenPoll::Approved(token)) => return Ok(token),
            Ok(TokenPoll::Pending) => {}
            Ok(TokenPoll::SlowDown) => interval += SLOW_DOWN_STEP,
            Err(e) if e.kind == AwsErrorKind::Refused => {
                return Err(PluginError::new(
                    ErrorKind::AccessDenied,
                    "SSO sign-in was denied or cancelled in the browser: sign in again to retry",
                ));
            }
            Err(e) if e.kind == AwsErrorKind::Expired => return Err(request_expired()),
            Err(e) => return Err(error::aws(&e, "waiting for the SSO sign-in")),
        }
        if Instant::now() >= deadline {
            return Err(request_expired());
        }
    }
}

fn request_expired() -> PluginError {
    PluginError::new(
        ErrorKind::TimedOut,
        "The SSO sign-in request expired before it was approved: sign in again",
    )
}

/// The accounts the person may choose: those IAM Identity Center gives them
/// that the account pin allows.
///
/// # Errors
///
/// `accessDenied` with no accounts at all, `pinMismatch` when none is the
/// pinned one, and the kind of any AWS failure.
pub(crate) async fn accounts<A: Aws>(
    aws: &A,
    login: &SsoLogin,
) -> Result<Vec<SsoAccount>, PluginError> {
    let all = aws
        .sso_accounts(&login.token, &login.sso_region)
        .await
        .map_err(|e| sso_error(&e, "listing your AWS accounts"))?;
    if all.is_empty() {
        return Err(PluginError::new(
            ErrorKind::AccessDenied,
            "No AWS accounts are available to you in IAM Identity Center: ask an administrator to assign you one",
        ));
    }
    let Some(pinned) = &login.pins.account else {
        return Ok(all);
    };
    let allowed: Vec<SsoAccount> = all
        .into_iter()
        .filter(|account| account.id == *pinned)
        .collect();
    if allowed.is_empty() {
        return Err(PluginError::new(
            ErrorKind::PinMismatch,
            format!(
                "IAM Identity Center does not give you account {pinned}, which this block needs: ask an administrator for access, or sign in as someone who has it"
            ),
        ));
    }
    Ok(allowed)
}

/// The roles the person may choose in `account`: those IAM Identity Center
/// gives them that the role pin allows.
///
/// # Errors
///
/// `accessDenied` with no roles at all, `pinMismatch` when none is the
/// pinned one, and the kind of any AWS failure.
pub(crate) async fn roles<A: Aws>(
    aws: &A,
    login: &SsoLogin,
    account: &AccountId,
) -> Result<Vec<String>, PluginError> {
    let all = aws
        .sso_roles(&login.token, account, &login.sso_region)
        .await
        .map_err(|e| sso_error(&e, &format!("listing your roles in account {account}")))?;
    if all.is_empty() {
        return Err(PluginError::new(
            ErrorKind::AccessDenied,
            format!(
                "No roles are available to you in account {account}: ask an administrator to assign you one"
            ),
        ));
    }
    let Some(pinned) = &login.pins.role else {
        return Ok(all);
    };
    let allowed: Vec<String> = all.into_iter().filter(|role| role == pinned).collect();
    if allowed.is_empty() {
        return Err(PluginError::new(
            ErrorKind::PinMismatch,
            format!(
                "IAM Identity Center does not give you role {pinned} in account {account}, which this block needs: ask an administrator for access, or sign in as someone who has it"
            ),
        ));
    }
    Ok(allowed)
}

/// Whether the pins allow choosing `account`, and `role` in it.
///
/// # Errors
///
/// `pinMismatch` naming the pin the choice breaks.
pub(crate) fn check_choice(
    pins: &Pins,
    account: &AccountId,
    role: Option<&str>,
) -> Result<(), PluginError> {
    if let Some(pinned) = &pins.account
        && pinned != account
    {
        return Err(PluginError::new(
            ErrorKind::PinMismatch,
            format!("this block needs account {pinned}, not {account}: choose account {pinned}"),
        ));
    }
    if let (Some(pinned), Some(role)) = (&pins.role, role)
        && pinned != role
    {
        return Err(PluginError::new(
            ErrorKind::PinMismatch,
            format!("this block needs role {pinned}, not {role}: choose role {pinned}"),
        ));
    }
    Ok(())
}

/// An SSO call that failed while `doing` something. The token is the
/// person's sign-in, so a refused or expired one means signing in again.
pub(crate) fn sso_error(error: &AwsError, doing: &str) -> PluginError {
    let detail = &error.detail;
    match error.kind {
        AwsErrorKind::Expired => PluginError::new(
            ErrorKind::Expired,
            format!("your SSO sign-in has expired ({detail}): sign in again"),
        ),
        AwsErrorKind::Refused | AwsErrorKind::NotFound => PluginError::new(
            ErrorKind::AccessDenied,
            format!(
                "IAM Identity Center refused {doing} ({detail}): check that you are assigned it, or sign in again"
            ),
        ),
        AwsErrorKind::Unavailable
        | AwsErrorKind::Network
        | AwsErrorKind::TimedOut
        | AwsErrorKind::Tls
        | AwsErrorKind::Unexpected => error::aws(error, doing),
    }
}
