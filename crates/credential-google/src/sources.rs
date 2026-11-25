//! Detection from variables: the `env` source, with or without a prefix, and
//! the `values` an earlier block published. Both read the same names.

use std::collections::HashMap;

use crate::Secret;

/// Credential variables, in precedence order.
const CREDENTIAL_VARS: [(&str, Shape); 4] = [
    ("GOOGLE_APPLICATION_CREDENTIALS", Shape::Path),
    ("GOOGLE_CREDENTIALS", Shape::Json),
    ("GOOGLE_OAUTH_ACCESS_TOKEN", Shape::Token),
    ("CLOUDSDK_AUTH_ACCESS_TOKEN", Shape::Token),
];
/// Project variables, in precedence order: gcloud's own wins.
const PROJECT_VARS: [&str; 4] = [
    "CLOUDSDK_CORE_PROJECT",
    "GOOGLE_CLOUD_PROJECT",
    "GOOGLE_PROJECT",
    "GCLOUD_PROJECT",
];
const REGION_VARS: [&str; 2] = ["CLOUDSDK_COMPUTE_REGION", "GOOGLE_CLOUD_REGION"];
const ZONE_VARS: [&str; 1] = ["CLOUDSDK_COMPUTE_ZONE"];
const CONFIGURATION_VARS: [&str; 1] = ["CLOUDSDK_ACTIVE_CONFIG_NAME"];

#[derive(Clone, Copy)]
enum Shape {
    Path,
    Json,
    Token,
}

/// A credential found in variables, with the settings found beside it.
#[derive(Debug)]
pub(crate) struct FoundVars {
    pub(crate) credential: VarCredential,
    /// The variable it was read from, prefix included.
    pub(crate) var: String,
    pub(crate) project: Option<String>,
    pub(crate) region: Option<String>,
    pub(crate) zone: Option<String>,
    /// The gcloud configuration a run's gcloud uses.
    pub(crate) configuration: Option<String>,
}

#[derive(Debug)]
pub(crate) enum VarCredential {
    /// The path of a credentials document.
    Path(String),
    Json(Secret),
    Token(Secret),
}

/// An `env` source's prefix, checked against the pattern every auth block
/// shares: upper case, digits and underscores, ending in an underscore.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Prefix(String);

impl Prefix {
    /// # Errors
    ///
    /// The prefix back, if it doesn't match `^[A-Z][A-Z0-9_]*_$`.
    pub(crate) fn parse(prefix: Option<String>) -> Result<Self, String> {
        let Some(prefix) = prefix.filter(|prefix| !prefix.is_empty()) else {
            return Ok(Self::default());
        };
        let bytes = prefix.as_bytes();
        let valid = bytes.first().is_some_and(u8::is_ascii_uppercase)
            && bytes.last() == Some(&b'_')
            && bytes
                .iter()
                .all(|&byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_');
        if valid { Ok(Self(prefix)) } else { Err(prefix) }
    }
}

/// The first credential variable set in `vars`, read with `prefix`. A project
/// with no credential beside it authenticates nothing, so it finds nothing.
pub(crate) fn find(vars: &HashMap<String, String>, prefix: &Prefix) -> Option<FoundVars> {
    let get = |name: &str| {
        vars.get(&format!("{}{name}", prefix.0))
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
    };
    let first = |names: &[&str]| names.iter().find_map(|name| get(name)).map(str::to_owned);
    let (name, value, shape) = CREDENTIAL_VARS
        .iter()
        .find_map(|&(name, shape)| get(name).map(|value| (name, value, shape)))?;
    let credential = match shape {
        Shape::Path => VarCredential::Path(value.to_owned()),
        Shape::Json => VarCredential::Json(Secret::new(value)),
        Shape::Token => VarCredential::Token(Secret::new(value)),
    };
    Some(FoundVars {
        credential,
        var: format!("{}{name}", prefix.0),
        project: first(&PROJECT_VARS),
        region: first(&REGION_VARS),
        zone: first(&ZONE_VARS),
        configuration: first(&CONFIGURATION_VARS),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{Prefix, VarCredential, find};

    fn vars(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn a_path_wins_over_inline_json_and_a_token() -> Result<(), String> {
        let found = find(
            &vars(&[
                ("GOOGLE_OAUTH_ACCESS_TOKEN", "ya29.token"),
                ("GOOGLE_CREDENTIALS", "{}"),
                ("GOOGLE_APPLICATION_CREDENTIALS", "/keys/sa.json"),
                ("GCLOUD_PROJECT", "last"),
                ("GOOGLE_CLOUD_PROJECT", "second"),
            ]),
            &Prefix::default(),
        )
        .ok_or("expected a credential")?;
        assert!(
            matches!(found.credential, VarCredential::Path(ref path) if path == "/keys/sa.json")
        );
        assert_eq!(found.project.as_deref(), Some("second"));
        Ok(())
    }

    #[test]
    fn a_project_alone_is_not_a_credential() {
        assert!(find(&vars(&[("GOOGLE_CLOUD_PROJECT", "p")]), &Prefix::default()).is_none());
    }

    #[test]
    fn a_prefix_reads_only_prefixed_names() -> Result<(), String> {
        let prefix = Prefix::parse(Some("CI_".to_owned()))?;
        let env = vars(&[
            ("GOOGLE_OAUTH_ACCESS_TOKEN", "unprefixed"),
            ("CI_CLOUDSDK_AUTH_ACCESS_TOKEN", "prefixed"),
        ]);
        let found = find(&env, &prefix).ok_or("expected a credential")?;
        assert_eq!(found.var, "CI_CLOUDSDK_AUTH_ACCESS_TOKEN");
        assert!(
            matches!(found.credential, VarCredential::Token(ref token) if token.expose() == "prefixed")
        );
        assert!(find(&vars(&[("GOOGLE_CREDENTIALS", "{}")]), &prefix).is_none());
        Ok(())
    }

    #[test]
    fn a_prefix_must_match_the_shared_pattern() -> Result<(), String> {
        for bad in ["ci_", "CI", "_CI_", "C-I_", "CI_$(x)_"] {
            assert_eq!(Prefix::parse(Some(bad.to_owned())), Err(bad.to_owned()));
        }
        assert_eq!(Prefix::parse(None), Ok(Prefix::default()));
        Prefix::parse(Some("MY_APP2_".to_owned()))?;
        Ok(())
    }
}
