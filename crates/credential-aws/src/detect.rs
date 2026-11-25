//! Reading a credential from a detection source: the environment, with or
//! without a prefix, or the values the engine read from an earlier block's
//! outputs. Nothing here calls AWS.

use std::collections::HashMap;
use std::fmt;

use runbooks_plugin_protocol::credential::Source;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::aws::AwsCredentials;
use crate::region::{InvalidRegion, Region};
use crate::secret::Secret;

pub(crate) const AWS_ACCESS_KEY_ID: &str = "AWS_ACCESS_KEY_ID";
pub(crate) const AWS_SECRET_ACCESS_KEY: &str = "AWS_SECRET_ACCESS_KEY";
pub(crate) const AWS_SESSION_TOKEN: &str = "AWS_SESSION_TOKEN";
pub(crate) const AWS_REGION: &str = "AWS_REGION";
const AWS_DEFAULT_REGION: &str = "AWS_DEFAULT_REGION";
/// When temporary keys expire, as the AWS SDKs read it.
const AWS_CREDENTIAL_EXPIRATION: &str = "AWS_CREDENTIAL_EXPIRATION";

/// The process environment `main` read at start. Its values include keys,
/// so `Debug` shows only how many there are.
#[derive(Clone, Default)]
pub struct Environment(HashMap<String, String>);

impl Environment {
    /// An environment of `vars`.
    #[must_use]
    pub const fn new(vars: HashMap<String, String>) -> Self {
        Self(vars)
    }

    /// The variable's value. An empty one counts as unset, as it does for the
    /// AWS CLI.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        non_empty(self.0.get(name))
    }
}

impl fmt::Debug for Environment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Environment({} variables)", self.0.len())
    }
}

fn non_empty(value: Option<&String>) -> Option<&str> {
    value.map(String::as_str).filter(|value| !value.is_empty())
}

/// A prefix for the `env` source: `PROD_` reads `PROD_AWS_ACCESS_KEY_ID` and
/// the rest. Upper-case letters, digits and underscores, starting with a
/// letter and ending with an underscore.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EnvPrefix(String);

impl EnvPrefix {
    fn parse(value: &str) -> Option<Self> {
        let well_formed = value.starts_with(|c: char| c.is_ascii_uppercase())
            && value.ends_with('_')
            && value
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
        well_formed.then(|| Self(value.to_owned()))
    }
}

/// A detection source the plugin can read.
#[derive(Clone)]
pub(crate) enum DetectSource {
    Env(Option<EnvPrefix>),
    /// An earlier block's outputs, and that block's id.
    Values {
        values: HashMap<String, String>,
        from: String,
    },
}

impl fmt::Debug for DetectSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Env(prefix) => f.debug_tuple("Env").field(prefix).finish(),
            Self::Values { values, .. } => write!(f, "Values({} values)", values.len()),
        }
    }
}

/// A source the params name wrongly. Each displays only what the author
/// wrote, never a value.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum InvalidSource {
    #[error(
        "the env source's prefix {0:?} is invalid: use upper-case letters, digits and underscores, starting with a letter and ending with an underscore, like PROD_"
    )]
    Prefix(String),
    #[error("AWS has no detection source named {0:?}: it reads env and an earlier block's values")]
    Named(String),
}

/// A source's credential failed to read: its region is not a region name.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{variable}: {source}")]
pub(crate) struct UnreadableSource {
    pub variable: String,
    #[source]
    pub source: InvalidRegion,
}

/// Where a credential was found. It shows as the identity's method;
/// [`Origin::source`] is what `detectResult.source` names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Origin {
    Env(Option<EnvPrefix>),
    /// The outputs of the block `from`.
    Values {
        from: String,
    },
}

impl Origin {
    /// The source a detected credential names: a values source's block, or
    /// the origin as it shows.
    pub(crate) fn source(&self) -> String {
        match self {
            Self::Values { from } => from.clone(),
            Self::Env(_) => self.to_string(),
        }
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Env(None) => f.write_str("env"),
            Self::Env(Some(EnvPrefix(prefix))) => write!(f, "env:{prefix}"),
            Self::Values { .. } => f.write_str("values"),
        }
    }
}

/// A credential read from a source, not yet checked with AWS.
#[derive(Clone, Debug)]
pub(crate) struct Found {
    pub origin: Origin,
    pub credentials: AwsCredentials,
    /// The region the source names, if it names one.
    pub region: Option<Region>,
}

/// Every source, checked before any is read.
///
/// # Errors
///
/// [`InvalidSource`] for the first source the plugin cannot read.
pub(crate) fn parse_sources(sources: Vec<Source>) -> Result<Vec<DetectSource>, InvalidSource> {
    sources
        .into_iter()
        .map(|source| match source {
            Source::Env { prefix: None } => Ok(DetectSource::Env(None)),
            Source::Env {
                prefix: Some(prefix),
            } if prefix.is_empty() => Ok(DetectSource::Env(None)),
            Source::Env {
                prefix: Some(prefix),
            } => EnvPrefix::parse(&prefix)
                .map(|prefix| DetectSource::Env(Some(prefix)))
                .ok_or_else(|| InvalidSource::Prefix(prefix.chars().take(64).collect())),
            Source::Values { values, from } => Ok(DetectSource::Values { values, from }),
            Source::Named { name } => Err(InvalidSource::Named(name.chars().take(64).collect())),
        })
        .collect()
}

impl DetectSource {
    /// The credential this source holds: both keys must be set.
    ///
    /// # Errors
    ///
    /// [`UnreadableSource`] when it holds keys and a region that is not one.
    pub(crate) fn read(&self, env: &Environment) -> Result<Option<Found>, UnreadableSource> {
        match self {
            Self::Env(prefix) => {
                let p = prefix.as_ref().map_or("", |EnvPrefix(p)| p.as_str());
                let name = |base: &str| format!("{p}{base}");
                read(
                    |base| env.get(&name(base)),
                    |base| name(base),
                    &[AWS_REGION, AWS_DEFAULT_REGION],
                    Origin::Env(prefix.clone()),
                )
            }
            Self::Values { values, from } => read(
                |name| non_empty(values.get(name)),
                str::to_owned,
                &[AWS_REGION],
                Origin::Values { from: from.clone() },
            ),
        }
    }
}

fn read<'a>(
    get: impl Fn(&str) -> Option<&'a str>,
    name: impl Fn(&str) -> String,
    region_names: &[&str],
    origin: Origin,
) -> Result<Option<Found>, UnreadableSource> {
    let (Some(access_key_id), Some(secret_access_key)) =
        (get(AWS_ACCESS_KEY_ID), get(AWS_SECRET_ACCESS_KEY))
    else {
        return Ok(None);
    };
    let region = region_names
        .iter()
        .find_map(|base| get(base).map(|value| (base, value)))
        .map(|(base, value)| {
            Region::parse(value).map_err(|source| UnreadableSource {
                variable: name(base),
                source,
            })
        })
        .transpose()?;
    // One that is not a date is ignored, as the app did.
    let expires_at = get(AWS_CREDENTIAL_EXPIRATION)
        .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok());
    Ok(Some(Found {
        origin,
        credentials: AwsCredentials {
            access_key_id: access_key_id.to_owned(),
            secret_access_key: Secret::new(secret_access_key),
            session_token: get(AWS_SESSION_TOKEN).map(Secret::new),
            expires_at,
        },
        region,
    }))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use runbooks_plugin_protocol::credential::Source;

    use super::{DetectSource, Environment, InvalidSource, Origin, parse_sources};

    fn vars(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn a_prefix_reads_only_the_prefixed_names() -> Result<(), Box<dyn std::error::Error>> {
        let env = Environment::new(vars(&[
            ("AWS_ACCESS_KEY_ID", "AKIADEV"),
            ("AWS_SECRET_ACCESS_KEY", "dev-secret"),
            ("PROD_AWS_ACCESS_KEY_ID", "AKIAPROD"),
            ("PROD_AWS_DEFAULT_REGION", "us-gov-west-1"),
        ]));
        let sources = parse_sources(vec![Source::Env {
            prefix: Some("PROD_".to_owned()),
        }])?;
        let [prod] = sources.as_slice() else {
            return Err("one source".into());
        };
        // PROD_ has no secret key, and the unprefixed one is never used.
        assert!(prod.read(&env)?.is_none());

        let env = Environment::new(vars(&[
            ("PROD_AWS_ACCESS_KEY_ID", "AKIAPROD"),
            ("PROD_AWS_SECRET_ACCESS_KEY", "prod-secret"),
            ("PROD_AWS_DEFAULT_REGION", "us-gov-west-1"),
            ("PROD_AWS_CREDENTIAL_EXPIRATION", "2026-11-24T22:00:00Z"),
        ]));
        let found = prod.read(&env)?.ok_or("found")?;
        assert_eq!(found.origin.to_string(), "env:PROD_");
        assert_eq!(found.credentials.access_key_id, "AKIAPROD");
        assert_eq!(found.credentials.secret_access_key.expose(), "prod-secret");
        assert_eq!(
            found.region.map(|r| r.to_string()).as_deref(),
            Some("us-gov-west-1")
        );
        assert!(found.credentials.expires_at.is_some());
        Ok(())
    }

    #[test]
    fn values_read_the_output_names() -> Result<(), Box<dyn std::error::Error>> {
        let source = DetectSource::Values {
            values: vars(&[
                ("AWS_ACCESS_KEY_ID", "AKIA"),
                ("AWS_SECRET_ACCESS_KEY", "secret"),
                ("AWS_SESSION_TOKEN", ""),
                ("AWS_CREDENTIAL_EXPIRATION", "not a date"),
            ]),
            from: "keys".to_owned(),
        };
        let found = source.read(&Environment::default())?.ok_or("found")?;
        assert_eq!(
            found.origin,
            Origin::Values {
                from: "keys".to_owned()
            }
        );
        assert_eq!(
            (found.origin.to_string(), found.origin.source()),
            ("values".to_owned(), "keys".to_owned()),
            "the method is values, and the source is the block"
        );
        assert!(found.credentials.session_token.is_none());
        assert!(found.credentials.expires_at.is_none());
        assert!(found.region.is_none());
        Ok(())
    }

    #[test]
    fn a_bad_region_names_its_variable() -> Result<(), Box<dyn std::error::Error>> {
        let env = Environment::new(vars(&[
            ("AWS_ACCESS_KEY_ID", "AKIA"),
            ("AWS_SECRET_ACCESS_KEY", "secret"),
            ("AWS_REGION", "US-EAST-1"),
        ]));
        let error = DetectSource::Env(None).read(&env).err().ok_or("an error")?;
        assert_eq!(error.variable, "AWS_REGION");
        assert_eq!(error.source.value.as_deref(), Some("US-EAST-1"));
        Ok(())
    }

    #[test]
    fn invalid_sources_are_refused_before_any_is_read() {
        for (source, expected) in [
            (
                Source::Env {
                    prefix: Some("prod_".to_owned()),
                },
                InvalidSource::Prefix("prod_".to_owned()),
            ),
            (
                Source::Env {
                    prefix: Some("PROD".to_owned()),
                },
                InvalidSource::Prefix("PROD".to_owned()),
            ),
            (
                Source::Named {
                    name: "gcloud".to_owned(),
                },
                InvalidSource::Named("gcloud".to_owned()),
            ),
        ] {
            let sources = vec![Source::Env { prefix: None }, source];
            assert_eq!(parse_sources(sources).err(), Some(expected));
        }
    }

    #[test]
    fn debug_shows_no_values() {
        let secret = "do-not-print-this";
        let env = Environment::new(vars(&[("AWS_SECRET_ACCESS_KEY", secret)]));
        let source = DetectSource::Values {
            values: vars(&[("AWS_SECRET_ACCESS_KEY", secret)]),
            from: "keys".to_owned(),
        };
        assert_eq!(
            format!("{env:?} {source:?}"),
            "Environment(1 variables) Values(1 values)"
        );
    }

    #[test]
    fn an_empty_prefix_is_no_prefix() -> Result<(), InvalidSource> {
        let sources = parse_sources(vec![Source::Env {
            prefix: Some(String::new()),
        }])?;
        assert!(
            matches!(sources.as_slice(), [DetectSource::Env(None)]),
            "{sources:?}"
        );
        Ok(())
    }
}
