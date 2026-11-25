//! A call's pins, requirements and fields, parsed into the plugin's types.
//! Every problem in one call is reported at once, each naming its key.

use std::collections::HashMap;

use runbooks_plugin_protocol::credential::{
    ErrorKind, Pins as WirePins, Requirement, RequirementRolesItem,
};
use runbooks_plugin_transport::PluginError;

use crate::describe::{SUBSCRIPTION_LEVEL, TENANT_FIELD, TENANT_LEVEL};
use crate::ids::{SubscriptionId, TenantId, TenantRef};
use crate::roles::RoleRequirement;

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

/// A `select` call's choice: a tenant, and a subscription unless the
/// sign-in is tenant-level.
///
/// # Errors
///
/// `invalidParams` for a level the plugin does not declare, a missing
/// tenant, or an id that is not a GUID.
pub(crate) fn choice(
    targets: &HashMap<String, String>,
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
            TenantId::parse(id).ok_or_else(|| {
                format!("targets.{TENANT_LEVEL} must be a tenant id from targets, not {id:?}")
            })
        },
    );
    if let Err(problem) = &tenant {
        problems.add(problem.clone());
    }
    let subscription = targets.get(SUBSCRIPTION_LEVEL).and_then(|id| {
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use runbooks_plugin_protocol::credential::{
        ErrorKind, Pins, Requirement, RequirementRolesItem,
    };

    use super::{choice, constraints, login_tenant};
    use crate::ids::TenantRef;

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

    #[test]
    fn a_choice_needs_a_tenant_and_declared_levels() -> Result<(), Box<dyn std::error::Error>> {
        let error = choice(&map(&[("subscription", "x"), ("role", "y")]))
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
        choice(&map(&[("tenant", "72f988bf-86f1-41af-91ab-2d7cd011db47")]))?;
        Ok(())
    }
}
