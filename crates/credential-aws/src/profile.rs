//! The `profile` method: a named profile from the shared AWS files, with
//! static keys, or a role it assumes with another profile's keys or the
//! environment's, as the AWS CLI resolves `role_arn` with `source_profile`
//! and `credential_source = Environment`.

use std::collections::HashMap;
use std::num::ParseIntError;
use std::time::Duration;

use time::OffsetDateTime;

use crate::aws::{AssumeRole, AwsCredentials, PROFILE_FILE_VARIABLES, ProfileSettings, Profiles};
use crate::detect::{AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN, Environment};
use crate::secret::Secret;

/// The method a profile's identity names.
pub(crate) const METHOD: &str = "profile";

/// How a profile's keys are got.
#[derive(Clone, Debug)]
pub(crate) struct Plan {
    pub base: AwsCredentials,
    /// The roles to assume, each with the keys the one before it gave,
    /// starting from `base`.
    pub roles: Vec<AssumeRole>,
    /// The named profile's own region.
    pub region: Option<String>,
}

/// A profile the block cannot sign in with. Names profiles and settings,
/// never a value from the files.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ProfileError {
    #[error("there is no AWS profile {name:?} in {files}: {}", listed(profiles))]
    Missing {
        name: String,
        files: String,
        profiles: Vec<String>,
    },
    #[error(
        "profile {name:?} signs in with IAM Identity Center (sso_start_url or sso_session): use the AWS SSO method"
    )]
    Sso { name: String },
    #[error(
        "profile {name:?} takes its keys from profile {from:?}, which signs in with IAM Identity Center: use the AWS SSO method"
    )]
    SsoSource { name: String, from: String },
    #[error(
        "profile {name:?} gets its keys with {setting}, which this block does not support: use a profile with aws_access_key_id, or with role_arn and source_profile"
    )]
    Unsupported { name: String, setting: &'static str },
    #[error(
        "profile {name:?} has no keys: give it aws_access_key_id and aws_secret_access_key, or role_arn with source_profile or credential_source"
    )]
    NoKeys { name: String },
    #[error("profile {name:?} has aws_access_key_id but no aws_secret_access_key: add it")]
    MissingSecret { name: String },
    #[error(
        "profile {name:?} has role_arn but neither source_profile nor credential_source: add one"
    )]
    NoSource { name: String },
    #[error("profile {name:?} has both source_profile and credential_source: keep one")]
    BothSources { name: String },
    #[error(
        "profile {name:?} takes its keys from credential_source {from:?}, which this block cannot reach: use credential_source = Environment, or source_profile"
    )]
    CredentialSource { name: String, from: String },
    #[error(
        "profile {name:?} takes its keys from the environment, which has no {AWS_ACCESS_KEY_ID} and {AWS_SECRET_ACCESS_KEY}"
    )]
    NoEnvironmentKeys { name: String },
    #[error(
        "profile {name:?} needs an MFA code (mfa_serial), which this block cannot ask for: use a profile without mfa_serial"
    )]
    Mfa { name: String },
    #[error("profile {name:?}'s source_profile chain comes back to itself: break the loop")]
    Cycle { name: String },
    #[error("profile {name:?}'s duration_seconds is not a whole number of seconds")]
    Duration {
        name: String,
        #[source]
        source: ParseIntError,
    },
}

fn listed(profiles: &[String]) -> String {
    if profiles.is_empty() {
        "there are no profiles".to_owned()
    } else {
        format!("the profiles are {}", profiles.join(", "))
    }
}

/// The variables of `env` that say where the files are.
pub(crate) fn file_env(env: &Environment) -> HashMap<String, String> {
    PROFILE_FILE_VARIABLES
        .into_iter()
        .filter_map(|name| Some((name.to_owned(), env.get(name)?.to_owned())))
        .collect()
}

/// The two files, for messages.
fn files(env: &Environment) -> String {
    let config = env.get("AWS_CONFIG_FILE").unwrap_or("~/.aws/config");
    let credentials = env
        .get("AWS_SHARED_CREDENTIALS_FILE")
        .unwrap_or("~/.aws/credentials");
    format!("{config} or {credentials}")
}

/// How to get `name`'s keys: its own, or the keys at the end of its
/// `source_profile` chain and the roles to assume from there.
///
/// # Errors
///
/// [`ProfileError`] for a profile that is missing or that the block cannot
/// sign in with.
pub(crate) fn plan<'a>(
    profiles: &'a Profiles,
    name: &'a str,
    env: &Environment,
    now: OffsetDateTime,
) -> Result<Plan, ProfileError> {
    let missing = |missing: &str| ProfileError::Missing {
        name: missing.to_owned(),
        files: files(env),
        profiles: profiles.names().map(str::to_owned).collect(),
    };
    let start = profiles.get(name).ok_or_else(|| missing(name))?;
    let mut roles = Vec::new();
    let mut seen: Vec<&str> = Vec::new();
    let (mut current, mut settings) = (name, start);
    let base = loop {
        seen.push(current);
        let at = || current.to_owned();
        // The AWS CLI's order: a role first, then static keys.
        let Some(role_arn) = &settings.role_arn else {
            if let Some(keys) = static_keys(current, settings)? {
                break keys;
            }
            return Err(match (settings.sso, settings.unsupported) {
                (true, _) if current == name => ProfileError::Sso { name: at() },
                (true, _) => ProfileError::SsoSource {
                    name: name.to_owned(),
                    from: at(),
                },
                (false, Some(setting)) => ProfileError::Unsupported {
                    name: at(),
                    setting,
                },
                (false, None) => ProfileError::NoKeys { name: at() },
            });
        };
        if settings.mfa_serial.is_some() {
            return Err(ProfileError::Mfa { name: at() });
        }
        let duration = settings
            .duration_seconds
            .as_deref()
            .map(|seconds| seconds.parse().map(Duration::from_secs))
            .transpose()
            .map_err(|source| ProfileError::Duration { name: at(), source })?;
        roles.push(AssumeRole {
            role_arn: role_arn.clone(),
            session_name: settings
                .role_session_name
                .clone()
                .unwrap_or_else(|| format!("runbooks-{}", now.unix_timestamp())),
            external_id: settings.external_id.clone(),
            duration,
        });
        match (&settings.source_profile, &settings.credential_source) {
            (Some(_), Some(_)) => return Err(ProfileError::BothSources { name: at() }),
            (None, None) => return Err(ProfileError::NoSource { name: at() }),
            (None, Some(source)) if source == "Environment" => {
                break environment_keys(current, env)?;
            }
            (None, Some(source)) => {
                return Err(ProfileError::CredentialSource {
                    name: at(),
                    from: source.chars().take(64).collect(),
                });
            }
            // A profile may name itself to assume its role with its own keys.
            (Some(source), None) if source == current => {
                break static_keys(current, settings)?
                    .ok_or_else(|| ProfileError::NoKeys { name: at() })?;
            }
            (Some(source), None) => {
                // Each step is to a profile not yet seen, so the walk ends.
                if seen.contains(&source.as_str()) {
                    return Err(ProfileError::Cycle {
                        name: name.to_owned(),
                    });
                }
                settings = profiles.get(source).ok_or_else(|| missing(source))?;
                current = source.as_str();
            }
        }
    };
    roles.reverse();
    Ok(Plan {
        base,
        roles,
        region: start.region.clone(),
    })
}

fn static_keys(
    name: &str,
    settings: &ProfileSettings,
) -> Result<Option<AwsCredentials>, ProfileError> {
    match (&settings.access_key_id, &settings.secret_access_key) {
        (Some(access_key_id), Some(secret_access_key)) => Ok(Some(AwsCredentials {
            access_key_id: access_key_id.clone(),
            secret_access_key: secret_access_key.clone(),
            session_token: settings.session_token.clone(),
            expires_at: None,
        })),
        (Some(_), None) => Err(ProfileError::MissingSecret {
            name: name.to_owned(),
        }),
        (None, _) => Ok(None),
    }
}

fn environment_keys(name: &str, env: &Environment) -> Result<AwsCredentials, ProfileError> {
    match (env.get(AWS_ACCESS_KEY_ID), env.get(AWS_SECRET_ACCESS_KEY)) {
        (Some(access_key_id), Some(secret_access_key)) => Ok(AwsCredentials {
            access_key_id: access_key_id.to_owned(),
            secret_access_key: Secret::new(secret_access_key),
            session_token: env.get(AWS_SESSION_TOKEN).map(Secret::new),
            expires_at: None,
        }),
        _ => Err(ProfileError::NoEnvironmentKeys {
            name: name.to_owned(),
        }),
    }
}
