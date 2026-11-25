//! What `configure` answers: the sign-in methods and their fields, the
//! target levels, and the names a run may get.

use std::collections::HashMap;

use runbooks_plugin_protocol::PROTOCOL_VERSION;
use runbooks_plugin_protocol::credential::{
    ConfigureResult, ConfigureResultCloud, Field, Level, LevelChosen, Method,
};

use crate::detect::{AWS_ACCESS_KEY_ID, AWS_REGION, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN};
use crate::identity::{ACCOUNT, ROLE};
use crate::region::{InvalidRegion, Region};

/// Every name a run may get, as env and as outputs.
pub(crate) const NAMES: [&str; 4] = [
    AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY,
    AWS_SESSION_TOKEN,
    AWS_REGION,
];

pub(crate) const ACCESS_KEY_ID: &str = "accessKeyId";
pub(crate) const SECRET_ACCESS_KEY: &str = "secretAccessKey";
pub(crate) const SESSION_TOKEN: &str = "sessionToken";
/// The region a run gets as `AWS_REGION`, and that keys which name none are
/// checked in. The block's `defaultRegion` fills it in.
pub(crate) const DEFAULT_REGION: &str = "defaultRegion";
/// The AWS access portal, like `https://my-org.awsapps.com/start`, and the
/// region IAM Identity Center runs in. The block's `ssoStartUrl` and
/// `ssoRegion` fill them in.
pub(crate) const SSO_START_URL: &str = "ssoStartUrl";
pub(crate) const SSO_REGION: &str = "ssoRegion";
/// A profile in the shared AWS config and credentials files.
pub(crate) const PROFILE: &str = "profile";

/// The sign-in methods: the block's tabs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SignInMethod {
    Credentials,
    Sso,
    Profile,
}

/// One input of a sign-in method.
struct FieldSpec {
    name: &'static str,
    label: &'static str,
    required: bool,
    secret: bool,
}

const DEFAULT_REGION_FIELD: FieldSpec = FieldSpec {
    name: DEFAULT_REGION,
    label: "Default Region",
    required: false,
    secret: false,
};

impl SignInMethod {
    pub(crate) const ALL: [Self; 3] = [Self::Credentials, Self::Sso, Self::Profile];

    pub(crate) fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|method| method.name() == name)
    }

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Credentials => "credentials",
            Self::Sso => "sso",
            Self::Profile => "profile",
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Credentials => "Static Credentials",
            Self::Sso => "AWS SSO",
            Self::Profile => "Local Profile",
        }
    }

    const fn fields(self) -> &'static [FieldSpec] {
        match self {
            Self::Credentials => &[
                FieldSpec {
                    name: ACCESS_KEY_ID,
                    label: "Access Key ID",
                    required: true,
                    secret: false,
                },
                FieldSpec {
                    name: SECRET_ACCESS_KEY,
                    label: "Secret Access Key",
                    required: true,
                    secret: true,
                },
                FieldSpec {
                    name: SESSION_TOKEN,
                    label: "Session Token",
                    required: false,
                    secret: true,
                },
                DEFAULT_REGION_FIELD,
            ],
            Self::Sso => &[
                FieldSpec {
                    name: SSO_START_URL,
                    label: "SSO Start URL",
                    required: true,
                    secret: false,
                },
                FieldSpec {
                    name: SSO_REGION,
                    label: "SSO Region",
                    required: false,
                    secret: false,
                },
                DEFAULT_REGION_FIELD,
            ],
            Self::Profile => &[
                FieldSpec {
                    name: PROFILE,
                    label: "Profile",
                    required: true,
                    secret: false,
                },
                DEFAULT_REGION_FIELD,
            ],
        }
    }
}

/// The answer to `configure`.
pub(crate) fn describe() -> ConfigureResult {
    let level = |name: &str, label: &str| Level {
        chosen: LevelChosen::AfterSignIn,
        label: label.to_owned(),
        name: name.to_owned(),
    };
    ConfigureResult {
        cloud: Some(ConfigureResultCloud::Aws),
        driver_version: env!("CARGO_PKG_VERSION").to_owned(),
        levels: vec![level(ACCOUNT, "AWS account"), level(ROLE, "Role")],
        methods: SignInMethod::ALL
            .into_iter()
            .map(|method| Method {
                fields: method
                    .fields()
                    .iter()
                    .map(|field| Field {
                        choices: Vec::new(),
                        label: field.label.to_owned(),
                        name: field.name.to_owned(),
                        required: field.required,
                        secret: field.secret,
                    })
                    .collect(),
                label: method.label().to_owned(),
                name: method.name().to_owned(),
                one_of: Vec::new(),
            })
            .collect(),
        names: NAMES.map(str::to_owned).to_vec(),
        protocol_version: PROTOCOL_VERSION.to_owned(),
        requirements: Vec::new(),
        sources: Vec::new(),
    }
}

/// Longer than any access portal URL.
const MAX_URL_LEN: usize = 2048;

/// A sign-in's fields, checked against its method's. An empty value counts as
/// unset: the form sends one for an input left blank.
#[derive(Clone, Copy)]
pub(crate) struct Fields<'a> {
    values: &'a HashMap<String, String>,
}

/// What is wrong with a sign-in's fields: every problem at once. Holds field
/// names only, never a value.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum InvalidFields {
    #[error("{}", describe_fields(*method, missing, unknown))]
    Names {
        method: SignInMethod,
        missing: Vec<&'static str>,
        unknown: Vec<String>,
    },
    #[error("the {field} field is invalid: {source}")]
    Region {
        field: &'static str,
        #[source]
        source: InvalidRegion,
    },
    #[error(
        "the {SSO_START_URL} field should be your AWS access portal's https:// URL, like https://my-org.awsapps.com/start"
    )]
    StartUrl,
}

fn describe_fields(method: SignInMethod, missing: &[&str], unknown: &[String]) -> String {
    let mut parts = Vec::new();
    if !missing.is_empty() {
        parts.push(format!(
            "the {} method needs {}",
            method.name(),
            missing.join(", ")
        ));
    }
    if !unknown.is_empty() {
        let known: Vec<&str> = method.fields().iter().map(|field| field.name).collect();
        parts.push(format!(
            "the {} method has no field {}: its fields are {}",
            method.name(),
            unknown.join(", "),
            known.join(", ")
        ));
    }
    parts.join("; ")
}

impl<'a> Fields<'a> {
    /// # Errors
    ///
    /// [`InvalidFields::Names`] listing every required field left unset and
    /// every name the method does not have.
    pub(crate) fn parse(
        method: SignInMethod,
        values: &'a HashMap<String, String>,
    ) -> Result<Self, InvalidFields> {
        let specs = method.fields();
        let mut unknown: Vec<String> = values
            .keys()
            .filter(|name| !specs.iter().any(|spec| spec.name == name.as_str()))
            .map(|name| name.chars().take(64).collect())
            .collect();
        unknown.sort();
        let fields = Self { values };
        let missing: Vec<&'static str> = specs
            .iter()
            .filter(|spec| spec.required && fields.get(spec.name).is_none())
            .map(|spec| spec.name)
            .collect();
        if missing.is_empty() && unknown.is_empty() {
            Ok(fields)
        } else {
            Err(InvalidFields::Names {
                method,
                missing,
                unknown,
            })
        }
    }

    pub(crate) fn get(self, name: &str) -> Option<&'a str> {
        self.values
            .get(name)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    }

    /// A field `parse` checked is set.
    pub(crate) fn required(self, name: &str) -> &'a str {
        self.get(name).unwrap_or_default()
    }

    /// The access portal URL in [`SSO_START_URL`], which `parse` checked is set.
    ///
    /// # Errors
    ///
    /// [`InvalidFields::StartUrl`] for anything but an `https://` URL.
    pub(crate) fn start_url(self) -> Result<&'a str, InvalidFields> {
        let url = self.required(SSO_START_URL);
        let host = url.strip_prefix("https://").unwrap_or_default();
        if host.is_empty() || url.len() > MAX_URL_LEN || url.chars().any(char::is_whitespace) {
            Err(InvalidFields::StartUrl)
        } else {
            Ok(url)
        }
    }

    /// The region in `field`, or `None` when it is unset.
    ///
    /// # Errors
    ///
    /// [`InvalidFields::Region`] when it is set to something else.
    pub(crate) fn region(self, field: &'static str) -> Result<Option<Region>, InvalidFields> {
        self.get(field)
            .map(|value| {
                Region::parse(value).map_err(|source| InvalidFields::Region { field, source })
            })
            .transpose()
    }
}
