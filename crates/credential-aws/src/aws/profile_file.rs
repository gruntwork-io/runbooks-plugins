//! The shared config and credentials files, read and parsed by aws-config
//! as the SDK and the AWS CLI read them: `AWS_CONFIG_FILE` and
//! `AWS_SHARED_CREDENTIALS_FILE`, else `~/.aws/config` and
//! `~/.aws/credentials`; `[profile x]` in config and `[x]` in credentials are
//! one profile, with both files' settings merged.
//!
//! aws-config reads only the environment it is handed: the variables in
//! [`PROFILE_FILE_VARIABLES`], from the plugin's own environment.

use std::collections::{BTreeMap, HashMap};
use std::error::Error as _;
use std::fmt;

use aws_config::profile::{self, ProfileSet};

use crate::secret::Secret;

/// What says where the files are: the two overrides, and the home directory
/// `~` stands for (`USERPROFILE`, or `HOMEDRIVE` and `HOMEPATH`, on Windows).
pub const PROFILE_FILE_VARIABLES: [&str; 6] = [
    "AWS_CONFIG_FILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "HOME",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
];

/// The settings of one profile that the plugin acts on. An empty value
/// counts as unset.
#[derive(Clone, Debug, Default)]
pub struct ProfileSettings {
    pub region: Option<String>,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<Secret>,
    pub session_token: Option<Secret>,
    pub role_arn: Option<String>,
    pub source_profile: Option<String>,
    pub credential_source: Option<String>,
    pub role_session_name: Option<String>,
    pub external_id: Option<String>,
    pub duration_seconds: Option<String>,
    pub mfa_serial: Option<String>,
    /// It has `sso_start_url` or `sso_session`: IAM Identity Center signs it in.
    pub sso: bool,
    /// The first setting it has that gets keys in a way the plugin does not.
    pub unsupported: Option<&'static str>,
}

/// Settings that get keys in ways the plugin does not: a command it would
/// run, a web identity token, `aws login`.
const UNSUPPORTED: [&str; 3] = [
    "credential_process",
    "web_identity_token_file",
    "login_session",
];

/// Every profile, by name. Prints only the names.
#[derive(Clone, Default)]
pub struct Profiles {
    by_name: BTreeMap<String, ProfileSettings>,
}

impl Profiles {
    pub fn get(&self, name: &str) -> Option<&ProfileSettings> {
        self.by_name.get(name)
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.by_name.keys().map(String::as_str)
    }

    fn from_set(set: &ProfileSet) -> Self {
        let by_name = set
            .profiles()
            .filter_map(|name| Some((name.to_owned(), set.get_profile(name)?)))
            .map(|(name, profile)| {
                let get = |key: &str| {
                    profile
                        .get(key)
                        .filter(|value| !value.is_empty())
                        .map(str::to_owned)
                };
                let settings = ProfileSettings {
                    region: get("region"),
                    access_key_id: get("aws_access_key_id"),
                    secret_access_key: get("aws_secret_access_key").map(Secret::new),
                    session_token: get("aws_session_token").map(Secret::new),
                    role_arn: get("role_arn"),
                    source_profile: get("source_profile"),
                    credential_source: get("credential_source"),
                    role_session_name: get("role_session_name"),
                    external_id: get("external_id"),
                    duration_seconds: get("duration_seconds"),
                    mfa_serial: get("mfa_serial"),
                    sso: get("sso_start_url").is_some() || get("sso_session").is_some(),
                    unsupported: UNSUPPORTED.into_iter().find(|key| get(key).is_some()),
                };
                (name, settings)
            })
            .collect();
        Self { by_name }
    }
}

impl fmt::Debug for Profiles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.names()).finish()
    }
}

/// A file aws-config could not parse. `reason` names the file, the line and
/// what is wrong with it, never what the line holds.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("an AWS profile file is invalid ({reason})")]
pub struct InvalidProfileFile {
    pub reason: String,
}

/// Reads and parses the two files where `env` says they are. A file that
/// is missing or unreadable is empty, as it is to the SDK.
///
/// # Errors
///
/// [`InvalidProfileFile`] for a file that does not parse.
pub async fn read_profiles(env: HashMap<String, String>) -> Result<Profiles, InvalidProfileFile> {
    // The default file set is the two files above. The real filesystem, and
    // no AWS_PROFILE in `env`: the plugin names the profile itself.
    profile::load(&Default::default(), &env.into(), &Default::default(), None)
        .await
        .map(|set| Profiles::from_set(&set))
        .map_err(|error| {
            // The file and the line are in the source: "error parsing <path>
            // on line <n>: <what is wrong>".
            let mut reason = error.to_string();
            let mut next = error.source();
            while let Some(source) = next {
                reason = format!("{reason}: {source}");
                next = source.source();
            }
            InvalidProfileFile {
                reason: reason.split_whitespace().collect::<Vec<_>>().join(" "),
            }
        })
}
