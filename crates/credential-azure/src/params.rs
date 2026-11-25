//! A call's pins, requirements and fields, parsed into the plugin's types.
//! Every problem in one call is reported at once, each naming its key.

use std::collections::HashMap;

use runbooks_plugin_protocol::credential::{
    ErrorKind, Pins as WirePins, Requirement, RequirementRolesItem,
};
use runbooks_plugin_transport::PluginError;

use std::path::PathBuf;

use crate::describe::{
    CERTIFICATE_FIELD, CLIENT_ID_FIELD, CLIENT_SECRET_FIELD, SUBSCRIPTION_LEVEL, TENANT_FIELD,
    TENANT_LEVEL,
};
use crate::ids::{ClientId, SubscriptionId, TenantId, TenantRef};
use crate::roles::RoleRequirement;
use crate::service_principal::{Credential, Secret, ServicePrincipal, is_pkcs12, pkcs12_message};

/// What `detect` and `signIn` check a credential against, before a tenant
/// domain is resolved.
#[derive(Clone, Debug, Default)]
pub(crate) struct Constraints {
    pub tenant: Option<TenantRef>,
    pub subscription: Option<String>,
    pub roles: Vec<RoleRequirement>,
}

/// Problems with one call's params, collected so all are reported together.
#[derive(Default)]
pub(crate) struct Problems(Vec<String>);

impl Problems {
    pub(crate) fn add(&mut self, problem: String) {
        self.0.push(problem);
    }

    /// `Ok` if nothing was added, else one `invalidParams` naming each problem.
    pub(crate) fn check(self, call: &str) -> Result<(), PluginError> {
        if self.0.is_empty() {
            return Ok(());
        }
        Err(PluginError::new(
            ErrorKind::InvalidParams,
            format!("{call}: {}", self.0.join("; ")),
        ))
    }
}

const TENANT_EXPECTED: &str = "a tenant ID (a GUID) or a domain such as contoso.onmicrosoft.com";

/// A value that may come from a template: blank is the same as unset.
fn given(value: &str) -> Option<&str> {
    Some(value.trim()).filter(|value| !value.is_empty())
}

pub(crate) fn tenant(value: &str, key: &str, problems: &mut Problems) -> Option<TenantRef> {
    let value = given(value)?;
    let parsed = TenantRef::parse(value);
    if parsed.is_none() {
        problems.add(format!("{key} must be {TENANT_EXPECTED}, not {value:?}"));
    }
    parsed
}

/// # Errors
///
/// `invalidParams` for a pin on a level the plugin does not declare, a
/// tenant pin that is not a tenant, or a requirement kind other than roles.
pub(crate) fn constraints(
    call: &str,
    pins: &WirePins,
    requirements: &[Requirement],
) -> Result<Constraints, PluginError> {
    let mut problems = Problems::default();
    let mut constraints = Constraints::default();
    let mut levels: Vec<&String> = pins.0.keys().collect();
    levels.sort();
    for level in levels {
        let value = pins.0.get(level).map_or("", String::as_str);
        match level.as_str() {
            TENANT_LEVEL => {
                constraints.tenant = tenant(value, "pins.tenant", &mut problems);
            }
            SUBSCRIPTION_LEVEL => constraints.subscription = given(value).map(str::to_owned),
            other => problems.add(format!(
                "pins.{other} is not a level: the levels are {TENANT_LEVEL} and {SUBSCRIPTION_LEVEL}"
            )),
        }
    }
    for requirement in requirements {
        match requirement {
            Requirement::Roles { roles } => add_roles(roles, &mut constraints.roles, &mut problems),
            Requirement::Scopes { .. } => problems.add(
                "requirements of kind scopes are not supported: Azure checks roles".to_owned(),
            ),
        }
    }
    problems.check(call)?;
    Ok(constraints)
}

/// Adds each role in `roles` to `required`, and a problem for each with no name.
fn add_roles(
    roles: &[RequirementRolesItem],
    required: &mut Vec<RoleRequirement>,
    problems: &mut Problems,
) {
    for item in roles {
        if given(&item.role).is_none() {
            problems.add("a required role has no name".to_owned());
        } else {
            required.push(RoleRequirement::new(&item.role, item.scope.as_deref()));
        }
    }
}

/// The tenant an interactive sign-in goes to: the pinned one, or the one
/// typed into the `tenantId` field.
///
/// # Errors
///
/// `invalidParams` for a field that is not a tenant, and `pinMismatch` for
/// a field that names another tenant than the pin.
pub(crate) fn login_tenant(
    fields: &HashMap<String, String>,
    constraints: &Constraints,
) -> Result<Option<TenantRef>, PluginError> {
    let mut problems = Problems::default();
    let typed = fields
        .get(TENANT_FIELD)
        .and_then(|value| tenant(value, &format!("fields.{TENANT_FIELD}"), &mut problems));
    problems.check("signIn")?;
    match (&constraints.tenant, typed) {
        (Some(pin), Some(typed)) if pin != &typed => Err(PluginError::new(
            ErrorKind::PinMismatch,
            format!("The block pins tenant {pin}, but the Tenant ID field says {typed}."),
        )),
        (Some(pin), _) => Ok(Some(pin.clone())),
        (None, typed) => Ok(typed),
    }
}

/// A service principal from `signIn`'s fields. The tenant is the pinned
/// one when the block pins it.
///
/// # Errors
///
/// `invalidParams` naming each field that is missing or malformed, and
/// `pinMismatch` for a tenant that is not the pinned one. No message
/// repeats the secret.
pub(crate) fn service_principal(
    fields: &HashMap<String, String>,
    constraints: &Constraints,
) -> Result<ServicePrincipal, PluginError> {
    let tenant = login_tenant(fields, constraints)?
        .ok_or_else(|| format!("fields.{TENANT_FIELD} is required for a service principal"));
    let field = |name: &str| fields.get(name).and_then(|value| given(value));
    let client_id = field(CLIENT_ID_FIELD).map_or_else(
        || Err(format!("fields.{CLIENT_ID_FIELD} is required")),
        |value| {
            ClientId::parse(value).ok_or_else(|| {
                format!(
                    "fields.{CLIENT_ID_FIELD} must be the app's client ID, a GUID, not {value:?}"
                )
            })
        },
    );
    // The secret as typed: only a template's blank counts as unset.
    let secret = fields
        .get(CLIENT_SECRET_FIELD)
        .filter(|value| !value.trim().is_empty());
    let credential = match (secret, field(CERTIFICATE_FIELD).map(PathBuf::from)) {
        (Some(_), Some(_)) => Err(format!(
            "fill in fields.{CLIENT_SECRET_FIELD} or fields.{CERTIFICATE_FIELD}, not both"
        )),
        (None, None) => Err(format!(
            "a service principal needs fields.{CLIENT_SECRET_FIELD} or fields.{CERTIFICATE_FIELD}"
        )),
        (Some(secret), None) => Ok(Credential::Secret(Secret::new(secret.clone()))),
        (None, Some(path)) if is_pkcs12(&path) => Err(format!(
            "fields.{CERTIFICATE_FIELD}: {}",
            pkcs12_message(&path)
        )),
        (None, Some(path)) if !path.is_absolute() => Err(format!(
            "fields.{CERTIFICATE_FIELD} must be an absolute path, not {}",
            path.display()
        )),
        (None, Some(path)) => Ok(Credential::Certificate(path)),
    };
    let mut problems = Problems::default();
    for problem in [
        client_id.as_ref().err(),
        tenant.as_ref().err(),
        credential.as_ref().err(),
    ]
    .into_iter()
    .flatten()
    {
        problems.add(problem.clone());
    }
    problems.check("signIn")?;
    let invalid = |problem: String| PluginError::new(ErrorKind::InvalidParams, problem);
    Ok(ServicePrincipal {
        client_id: client_id.map_err(invalid)?,
        tenant: tenant.map_err(invalid)?,
        credential: credential.map_err(invalid)?,
    })
}

/// A `select` call's choice: a tenant, and a subscription unless the
/// sign-in is tenant-level.
///
/// # Errors
///
/// `invalidParams` for a level the plugin does not declare, a missing
/// tenant, a null at either level (neither is optional), or an id that is
/// not a GUID.
pub(crate) fn choice(
    targets: &HashMap<String, Option<String>>,
) -> Result<(TenantId, Option<SubscriptionId>), PluginError> {
    let mut problems = Problems::default();
    let mut levels: Vec<&String> = targets.keys().collect();
    levels.sort();
    for level in levels {
        if level != TENANT_LEVEL && level != SUBSCRIPTION_LEVEL {
            problems.add(format!(
                "targets.{level} is not a level: the levels are {TENANT_LEVEL} and {SUBSCRIPTION_LEVEL}"
            ));
        }
    }
    let tenant = targets.get(TENANT_LEVEL).map_or_else(
        || Err(format!("targets.{TENANT_LEVEL} is required")),
        |id| {
            let id = id.as_deref().ok_or_else(|| not_optional(TENANT_LEVEL))?;
            TenantId::parse(id).ok_or_else(|| {
                format!("targets.{TENANT_LEVEL} must be a tenant id from targets, not {id:?}")
            })
        },
    );
    if let Err(problem) = &tenant {
        problems.add(problem.clone());
    }
    let subscription = targets.get(SUBSCRIPTION_LEVEL).and_then(|id| {
        let Some(id) = id else {
            problems.add(not_optional(SUBSCRIPTION_LEVEL));
            return None;
        };
        let parsed = SubscriptionId::parse(id);
        if parsed.is_none() {
            problems.add(format!(
                "targets.{SUBSCRIPTION_LEVEL} must be a subscription id from targets, not {id:?}"
            ));
        }
        parsed
    });
    problems.check("select")?;
    let tenant = tenant.map_err(|problem| PluginError::new(ErrorKind::InvalidParams, problem))?;
    Ok((tenant, subscription))
}

/// The refusal of a null target at `level`, which is not optional.
fn not_optional(level: &str) -> String {
    format!("targets.{level} is null, but the {level} level is not optional")
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use runbooks_plugin_protocol::credential::{
        ErrorKind, Pins, Requirement, RequirementRolesItem,
    };

    use super::{Constraints, choice, constraints, login_tenant, service_principal};
    use crate::ids::TenantRef;
    use crate::service_principal::{Credential, Secret};

    const CLIENT: &str = "33333333-3333-4333-8333-333333333333";
    const TENANT: &str = "11111111-1111-4111-8111-111111111111";

    #[test]
    fn a_service_principal_takes_a_secret_or_a_pem_certificate()
    -> Result<(), Box<dyn std::error::Error>> {
        let pinned = Constraints {
            tenant: TenantRef::parse(TENANT),
            ..Constraints::default()
        };
        let fields = map(&[("clientId", CLIENT), ("clientSecret", " s3cr3t ")]);
        let principal = service_principal(&fields, &pinned)?;
        assert_eq!(
            principal.tenant.as_str(),
            TENANT,
            "the pin fills the tenant"
        );
        assert_eq!(
            principal.credential,
            Credential::Secret(Secret::new(" s3cr3t ".to_owned())),
            "a secret is taken as typed"
        );
        let pem = if cfg!(windows) {
            r"C:\sp.pem"
        } else {
            "/sp.pem"
        };
        let fields = map(&[
            ("clientId", CLIENT),
            ("tenantId", TENANT),
            ("clientCertificatePath", pem),
        ]);
        let principal = service_principal(&fields, &Constraints::default())?;
        assert_eq!(principal.credential, Credential::Certificate(pem.into()));
        Ok(())
    }

    #[test]
    fn a_service_principal_names_each_bad_field_and_never_the_secret()
    -> Result<(), Box<dyn std::error::Error>> {
        for (fields, expected) in [
            (
                map(&[("clientSecret", "s3cr3t")]),
                vec!["fields.clientId is required", "fields.tenantId is required"],
            ),
            (
                map(&[
                    ("clientId", "my-app"),
                    ("tenantId", TENANT),
                    ("clientSecret", "s3cr3t"),
                    ("clientCertificatePath", "/sp.pem"),
                ]),
                vec!["fields.clientId must be the app's client ID", "not both"],
            ),
            (
                map(&[
                    ("clientId", CLIENT),
                    ("tenantId", TENANT),
                    ("clientSecret", " "),
                ]),
                vec!["needs fields.clientSecret or"],
            ),
            (
                map(&[
                    ("clientId", CLIENT),
                    ("tenantId", TENANT),
                    ("clientCertificatePath", "/sp.pfx"),
                ]),
                vec!["PEM certificate, not /sp.pfx"],
            ),
            (
                map(&[
                    ("clientId", CLIENT),
                    ("tenantId", TENANT),
                    ("clientCertificatePath", "sp.pem"),
                ]),
                vec!["must be an absolute path"],
            ),
        ] {
            let error = service_principal(&fields, &Constraints::default())
                .err()
                .ok_or_else(|| format!("{:?} was accepted", fields.keys()))?;
            assert_eq!(error.kind(), ErrorKind::InvalidParams);
            for part in expected {
                assert!(
                    error.message().contains(part),
                    "{part:?} in {}",
                    error.message()
                );
            }
            assert!(!error.message().contains("s3cr3t"), "{}", error.message());
        }
        Ok(())
    }

    fn map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn blank_pins_are_unset() -> Result<(), Box<dyn std::error::Error>> {
        let parsed = constraints(
            "detect",
            &Pins(map(&[("tenant", " "), ("subscription", "")])),
            &[],
        )?;
        assert_eq!(parsed.tenant, None);
        assert_eq!(parsed.subscription, None);
        Ok(())
    }

    #[test]
    fn every_problem_is_reported_with_its_key() -> Result<(), Box<dyn std::error::Error>> {
        let error = constraints(
            "signIn",
            &Pins(map(&[("tenant", "not a tenant"), ("account", "1")])),
            &[
                Requirement::Scopes {
                    scopes: vec!["x".to_owned()],
                },
                Requirement::Roles {
                    roles: vec![RequirementRolesItem {
                        role: " ".to_owned(),
                        scope: None,
                    }],
                },
            ],
        )
        .err()
        .ok_or("the params were accepted")?;
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
        let message = error.message();
        for part in [
            "pins.account",
            "pins.tenant",
            "\"not a tenant\"",
            "scopes",
            "no name",
        ] {
            assert!(message.contains(part), "{part} in {message}");
        }
        Ok(())
    }

    #[test]
    fn the_pinned_tenant_wins_and_a_different_typed_one_is_a_mismatch()
    -> Result<(), Box<dyn std::error::Error>> {
        let pinned = constraints("signIn", &Pins(map(&[("tenant", "contoso.com")])), &[])?;
        let domain = Some(TenantRef::Domain("contoso.com".to_owned()));
        assert_eq!(login_tenant(&map(&[]), &pinned)?, domain);
        assert_eq!(
            login_tenant(&map(&[("tenantId", "CONTOSO.com")]), &pinned)?,
            domain
        );
        assert_eq!(
            login_tenant(&map(&[("tenantId", "fabrikam.com")]), &pinned)
                .err()
                .map(|e| e.kind()),
            Some(ErrorKind::PinMismatch)
        );
        let open = constraints("signIn", &Pins(map(&[])), &[])?;
        assert_eq!(
            login_tenant(&map(&[("tenantId", "--tenant")]), &open)
                .err()
                .map(|e| e.kind()),
            Some(ErrorKind::InvalidParams)
        );
        Ok(())
    }

    /// A select's targets: `None` is a null.
    fn targets(pairs: &[(&str, Option<&str>)]) -> HashMap<String, Option<String>> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.map(str::to_owned)))
            .collect()
    }

    #[test]
    fn a_choice_needs_a_tenant_and_declared_levels() -> Result<(), Box<dyn std::error::Error>> {
        let error = choice(&targets(&[
            ("subscription", Some("x")),
            ("role", Some("y")),
        ]))
        .err()
        .ok_or("the choice was accepted")?;
        let message = error.message();
        for part in [
            "targets.role",
            "targets.tenant is required",
            "targets.subscription",
        ] {
            assert!(message.contains(part), "{part} in {message}");
        }
        choice(&targets(&[(
            "tenant",
            Some("72f988bf-86f1-41af-91ab-2d7cd011db47"),
        )]))?;
        Ok(())
    }

    /// Neither level is optional, so a null at either is refused, not taken
    /// as no target.
    #[test]
    fn a_null_tenant_or_subscription_is_refused() -> Result<(), Box<dyn std::error::Error>> {
        let error = choice(&targets(&[("tenant", None), ("subscription", None)]))
            .err()
            .ok_or("the choice was accepted")?;
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
        for part in [
            "targets.tenant is null, but the tenant level is not optional",
            "targets.subscription is null, but the subscription level is not optional",
        ] {
            assert!(
                error.message().contains(part),
                "{part} in {}",
                error.message()
            );
        }
        let error = choice(&targets(&[
            ("tenant", Some("72f988bf-86f1-41af-91ab-2d7cd011db47")),
            ("subscription", None),
        ]))
        .err()
        .ok_or("a null subscription was taken as none")?;
        assert_eq!(error.kind(), ErrorKind::InvalidParams);
        Ok(())
    }
}
