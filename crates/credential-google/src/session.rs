//! A signed-in credential: proving a candidate works against the block's pins
//! and requirements, the identity it shows, and the environment a run gets.

use std::collections::HashMap;

use runbooks_plugin_protocol::Timestamp;
use runbooks_plugin_protocol::credential::{
    EnvValue, EnvValueToItem, ErrorKind, Identity, IdentityKind, Pins, Requirement, Target,
};
use runbooks_plugin_transport::PluginError;
use time::OffsetDateTime;

use crate::api::GoogleApi;
use crate::credential::{
    Credential, CredentialType, Origin, access_token, api_error, denies_project,
};
use crate::crypto::Crypto;

/// The one target level: the project commands operate on.
pub(crate) const PROJECT: &str = "project";
const SERVICE_ACCOUNT_EMAIL_SUFFIX: &str = ".gserviceaccount.com";

const CREDENTIAL_FILE_VARS: [&str; 2] = [
    "GOOGLE_APPLICATION_CREDENTIALS",
    // gcloud keeps its own login and ignores GOOGLE_APPLICATION_CREDENTIALS;
    // this property makes it use the block's file instead.
    "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE",
];
const ACCESS_TOKEN_VARS: [&str; 2] = ["GOOGLE_OAUTH_ACCESS_TOKEN", "CLOUDSDK_AUTH_ACCESS_TOKEN"];
const PROJECT_VARS: [&str; 3] = [
    "GOOGLE_CLOUD_PROJECT",
    "CLOUDSDK_CORE_PROJECT",
    "GOOGLE_PROJECT",
];
const ACCOUNT_VAR: &str = "CLOUDSDK_CORE_ACCOUNT";
const REGION_VARS: [&str; 3] = [
    "GOOGLE_CLOUD_REGION",
    "CLOUDSDK_COMPUTE_REGION",
    "GOOGLE_REGION",
];
const ZONE_VARS: [&str; 2] = ["CLOUDSDK_COMPUTE_ZONE", "GOOGLE_ZONE"];
const CONFIGURATION_VAR: &str = "CLOUDSDK_ACTIVE_CONFIG_NAME";
const AUTH_TYPE_OUTPUT: &str = "GOOGLE_AUTH_TYPE";
/// Credential variables the plugin reads in detection but never sets. Named
/// so the base environment strips them: Terraform's google provider prefers
/// `GOOGLE_CREDENTIALS` to `GOOGLE_APPLICATION_CREDENTIALS`, so one left over
/// from the app's own environment would win over the block's credential.
const STRIPPED_VARS: [&str; 2] = ["GOOGLE_CREDENTIALS", "GCLOUD_PROJECT"];

/// Every env and output name the plugin may set, for `configure`.
pub(crate) fn names() -> Vec<String> {
    CREDENTIAL_FILE_VARS
        .iter()
        .chain(&ACCESS_TOKEN_VARS)
        .chain(&PROJECT_VARS)
        .chain(&[ACCOUNT_VAR])
        .chain(&REGION_VARS)
        .chain(&ZONE_VARS)
        .chain(&[CONFIGURATION_VAR, AUTH_TYPE_OUTPUT])
        .chain(&STRIPPED_VARS)
        .map(|&name| name.to_owned())
        .collect()
}

/// What a credential must satisfy: the block's pin and required scopes.
#[derive(Clone, Debug, Default)]
pub(crate) struct Constraints {
    pub(crate) pinned_project: Option<String>,
    pub(crate) scopes: Vec<String>,
}

impl Constraints {
    /// # Errors
    ///
    /// Kind `invalidParams` for a pin on a level other than `project`, or a
    /// requirement other than `scopes`.
    pub(crate) fn parse(pins: &Pins, requirements: &[Requirement]) -> Result<Self, PluginError> {
        let mut problems = Vec::new();
        for level in pins.keys().filter(|level| level.as_str() != PROJECT) {
            problems.push(format!(
                "pins has level {level:?}; this plugin's only level is \"project\""
            ));
        }
        let mut scopes = Vec::new();
        for requirement in requirements {
            match requirement {
                Requirement::Scopes { scopes: required } => scopes.extend(
                    required
                        .iter()
                        .flat_map(|entry| entry.split_whitespace())
                        .map(str::to_owned),
                ),
                Requirement::Roles { .. } => problems.push(
                    "requirements has kind \"roles\"; this plugin checks only \"scopes\""
                        .to_owned(),
                ),
            }
        }
        if !problems.is_empty() {
            return Err(invalid_params(problems.join("; ")));
        }
        Ok(Self {
            pinned_project: pins
                .get(PROJECT)
                .map(|project| project.trim().to_owned())
                .filter(|project| !project.is_empty()),
            scopes,
        })
    }
}

pub(crate) fn invalid_params(message: impl Into<String>) -> PluginError {
    PluginError::new(ErrorKind::InvalidParams, message)
}

/// A credential to prove, with what came with it.
#[derive(Clone, Debug)]
pub(crate) struct Candidate {
    pub(crate) credential: Credential,
    /// The sign-in method, or the detection source it was found in.
    pub(crate) method: String,
    /// A project named by a field, a variable or a gcloud configuration. The
    /// pin wins over it, and it wins over the credential's own.
    pub(crate) project: Option<String>,
    pub(crate) region: Option<String>,
    pub(crate) zone: Option<String>,
    pub(crate) configuration: Option<String>,
}

/// A proven credential: what `env` hands a run and what `identity` shows.
#[derive(Clone, Debug)]
pub(crate) struct Session {
    pub(crate) credential: Credential,
    pub(crate) method: String,
    pub(crate) principal: String,
    pub(crate) kind: IdentityKind,
    pub(crate) project: Option<Target>,
    pub(crate) pinned_project: Option<String>,
    /// Only a bare access token expires: every document refreshes itself.
    pub(crate) expires_at: Option<OffsetDateTime>,
    pub(crate) region: Option<String>,
    pub(crate) zone: Option<String>,
    pub(crate) configuration: Option<String>,
}

/// What proving a credential needs from the plugin.
pub(crate) struct Prover<'a, A, C> {
    pub(crate) api: &'a A,
    pub(crate) crypto: &'a C,
    pub(crate) now: OffsetDateTime,
}

impl<A: GoogleApi, C: Crypto> Prover<'_, A, C> {
    /// Mints a token for `candidate` and asks Google who it is, then checks
    /// the required scopes and that a pinned project is readable.
    ///
    /// # Errors
    ///
    /// The credential's failure as an error kind; `requirementNotMet` with the
    /// missing scopes; `pinMismatch` if Google says the identity can't see the
    /// pinned project.
    pub(crate) async fn prove(
        &self,
        candidate: Candidate,
        constraints: &Constraints,
    ) -> Result<Session, PluginError> {
        let credential = candidate.credential;
        let origin = Origin::of(&credential);
        let token = self.token(&credential).await?;
        let info = self
            .api
            .token_info(&token)
            .await
            .map_err(|error| api_error(error, origin))?;
        let credential_type = credential.credential_type();
        let principal = info
            .email
            .or_else(|| credential.own_email())
            .or(info.subject)
            .unwrap_or_default();
        let kind = if credential_type.is_service_account()
            || principal.ends_with(SERVICE_ACCOUNT_EMAIL_SUFFIX)
        {
            IdentityKind::ServiceAccount
        } else {
            IdentityKind::User
        };

        if kind == IdentityKind::User {
            let missing: Vec<String> = constraints
                .scopes
                .iter()
                .filter(|scope| !info.scopes.contains(scope))
                .cloned()
                .collect();
            if !missing.is_empty() {
                return Err(scopes_not_met(&missing, &constraints.scopes));
            }
        }

        let project_id = constraints
            .pinned_project
            .clone()
            .or(candidate.project)
            .or_else(|| credential.own_project());
        let project = match project_id {
            None => None,
            Some(id) => Some(self.project(&token, id, constraints, &principal).await?),
        };
        let expires_at = match credential_type {
            CredentialType::AccessToken => info
                .expires_at
                .and_then(|seconds| OffsetDateTime::from_unix_timestamp(seconds).ok()),
            CredentialType::ServiceAccount | CredentialType::AuthorizedUser => None,
        };
        Ok(Session {
            credential,
            method: candidate.method,
            principal,
            kind,
            project,
            pinned_project: constraints.pinned_project.clone(),
            expires_at,
            region: candidate.region,
            zone: candidate.zone,
            configuration: candidate.configuration,
        })
    }

    pub(crate) async fn token(
        &self,
        credential: &Credential,
    ) -> Result<crate::Secret, PluginError> {
        access_token(self.api, self.crypto, self.now.unix_timestamp(), credential).await
    }

    /// The project as a target, named by its display name when Google says it.
    async fn project(
        &self,
        token: &crate::Secret,
        id: String,
        constraints: &Constraints,
        principal: &str,
    ) -> Result<Target, PluginError> {
        match self.api.get_project(token, &id).await {
            Ok(project) => Ok(Target {
                name: project.display_name.unwrap_or_else(|| id.clone()),
                id,
            }),
            Err(error)
                if constraints.pinned_project.as_ref() == Some(&id) && denies_project(&error) =>
            {
                Err(PluginError::new(
                    ErrorKind::PinMismatch,
                    format!(
                        "The block uses project {id}, which {principal} can't read. Sign in as an identity with access to it."
                    ),
                ))
            }
            // A credential without resourcemanager.projects.get still works.
            Err(_) => Ok(Target {
                name: id.clone(),
                id,
            }),
        }
    }
}

fn scopes_not_met(missing: &[String], required: &[String]) -> PluginError {
    PluginError::requirement_not_met(
        vec![Requirement::Scopes {
            scopes: missing.to_vec(),
        }],
        format!(
            "These credentials are missing required OAuth scopes: {}. Sign in again with the required scopes, or run: gcloud auth application-default login --client-id-file=\"$GOOGLE_OAUTH_CLIENT_CREDENTIALS\" --scopes={}",
            missing.join(", "),
            required.join(",")
        ),
    )
}

impl Session {
    pub(crate) fn identity(&self) -> Identity {
        let mut targets = HashMap::new();
        if let Some(project) = &self.project {
            targets.insert(PROJECT.to_owned(), project.clone());
        }
        Identity {
            expires_at: self.expires_at.map(Timestamp::from),
            kind: self.kind,
            method: self.method.clone(),
            principal: self.principal.clone(),
            targets,
        }
    }

    /// The values a run gets. `credentials_file` is where the document was
    /// written, for a credential that is one.
    pub(crate) fn env_values(&self, credentials_file: Option<&str>) -> Vec<EnvValue> {
        let mut values = Vec::new();
        let mut set = |names: &[&str], value: &str, sensitive: bool, to: &[EnvValueToItem]| {
            for name in names {
                values.push(EnvValue {
                    name: (*name).to_owned(),
                    sensitive,
                    to: to.to_vec(),
                    value: value.to_owned(),
                });
            }
        };
        const BOTH: &[EnvValueToItem] = &[EnvValueToItem::Env, EnvValueToItem::Output];
        const ENV: &[EnvValueToItem] = &[EnvValueToItem::Env];
        match (&self.credential, credentials_file) {
            (Credential::AccessToken(token), _) => {
                set(&ACCESS_TOKEN_VARS, token.expose(), true, ENV)
            }
            (Credential::Document(_), Some(path)) => set(&CREDENTIAL_FILE_VARS, path, false, BOTH),
            (Credential::Document(_), None) => {}
        }
        if let Some(project) = &self.project {
            set(&PROJECT_VARS, &project.id, false, BOTH);
        }
        if !self.principal.is_empty() {
            set(&[ACCOUNT_VAR], &self.principal, false, BOTH);
        }
        if let Some(region) = &self.region {
            set(&REGION_VARS, region, false, BOTH);
        }
        if let Some(zone) = &self.zone {
            set(&ZONE_VARS, zone, false, BOTH);
        }
        if let Some(configuration) = &self.configuration {
            set(&[CONFIGURATION_VAR], configuration, false, ENV);
        }
        set(
            &[AUTH_TYPE_OUTPUT],
            self.credential.credential_type().name(),
            false,
            &[EnvValueToItem::Output],
        );
        values
    }
}
