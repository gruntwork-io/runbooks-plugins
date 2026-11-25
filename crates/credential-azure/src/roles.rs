//! `requiredRoles`: the Azure roles the signed-in principal must hold.

use runbooks_plugin_protocol::credential::{Requirement, RequirementRolesItem};
use runbooks_plugin_transport::PluginError;

use crate::ids::SubscriptionId;

/// The scope a role defaults to: the chosen subscription.
pub const SUBSCRIPTION_SCOPE: &str = "subscription";

/// A role the block requires, and where.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleRequirement {
    /// The role's name.
    pub role: String,
    /// An ARM scope such as `/` or a management group, or
    /// [`SUBSCRIPTION_SCOPE`].
    pub scope: String,
}

impl RoleRequirement {
    /// `role` at `scope`, both trimmed; a missing or blank scope is
    /// [`SUBSCRIPTION_SCOPE`].
    #[must_use]
    pub fn new(role: &str, scope: Option<&str>) -> Self {
        let scope = scope.map(str::trim).filter(|scope| !scope.is_empty());
        Self {
            role: role.trim().to_owned(),
            scope: scope.unwrap_or(SUBSCRIPTION_SCOPE).to_owned(),
        }
    }

    /// The ARM scope to check: `None` for the subscription scope when no
    /// subscription is chosen.
    #[must_use]
    pub fn arm_scope(&self, subscription: Option<&SubscriptionId>) -> Option<String> {
        if self.scope == SUBSCRIPTION_SCOPE {
            return subscription.map(|id| format!("/subscriptions/{id}"));
        }
        Some(if self.scope.starts_with('/') {
            self.scope.clone()
        } else {
            format!("/{}", self.scope)
        })
    }
}

/// A role the principal lacks, at the scope it was checked at, or at
/// [`SUBSCRIPTION_SCOPE`] when no subscription was chosen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MissingRole {
    /// The role's name.
    pub role: String,
    /// The ARM scope it was checked at, or [`SUBSCRIPTION_SCOPE`].
    pub scope: String,
}

/// Kind `requirementNotMet`, naming each missing role and what to do.
#[must_use]
pub fn unmet(missing: &[MissingRole], principal: &str) -> PluginError {
    let list: Vec<String> = missing
        .iter()
        .map(|m| match m.scope.as_str() {
            SUBSCRIPTION_SCOPE => format!("{} at the subscription (none chosen)", m.role),
            scope => format!("{} at {scope}", m.role),
        })
        .collect();
    let plural = missing.len() > 1;
    let elevate = missing
        .iter()
        .any(|m| m.scope == "/" && m.role.eq_ignore_ascii_case("user access administrator"));
    let message = format!(
        "{principal} is missing the required role{}: {}. Ask an administrator to assign {}, then sign in again.{}",
        if plural { "s" } else { "" },
        list.join(", "),
        if plural { "them" } else { "it" },
        if elevate {
            " For User Access Administrator at /, a Global Administrator can turn on \"Access management for Azure resources\" in Entra ID > Properties, then sign in again."
        } else {
            ""
        }
    );
    let roles = missing
        .iter()
        .map(|m| RequirementRolesItem {
            role: m.role.clone(),
            scope: Some(m.scope.clone()),
        })
        .collect();
    PluginError::requirement_not_met(vec![Requirement::Roles { roles }], message)
}

#[cfg(test)]
mod tests {
    use runbooks_plugin_protocol::credential::ErrorKind;

    use super::{MissingRole, RoleRequirement, unmet};
    use crate::ids::SubscriptionId;

    #[test]
    fn a_role_defaults_to_the_chosen_subscription() {
        let sub = SubscriptionId::parse("aaaaaaaa-0000-0000-0000-000000000001");
        let owner = RoleRequirement::new("Owner", None);
        assert_eq!(owner.scope, "subscription");
        assert_eq!(
            owner.arm_scope(sub.as_ref()).as_deref(),
            Some("/subscriptions/aaaaaaaa-0000-0000-0000-000000000001")
        );
        assert_eq!(owner.arm_scope(None), None);
        let root = RoleRequirement::new(
            "Reader",
            Some("providers/Microsoft.Management/managementGroups/root"),
        );
        assert_eq!(
            root.arm_scope(None).as_deref(),
            Some("/providers/Microsoft.Management/managementGroups/root")
        );
    }

    #[test]
    fn the_unmet_error_names_each_role_and_how_to_get_user_access_administrator() {
        let error = unmet(
            &[
                MissingRole {
                    role: "User Access Administrator".to_owned(),
                    scope: "/".to_owned(),
                },
                MissingRole {
                    role: "Owner".to_owned(),
                    scope: "subscription".to_owned(),
                },
            ],
            "ana@contoso.com",
        );
        assert_eq!(error.kind(), ErrorKind::RequirementNotMet);
        let message = error.message();
        assert!(message.starts_with("ana@contoso.com is missing the required roles: User Access Administrator at /, Owner at the subscription (none chosen)."), "{message}");
        assert!(
            message.contains("Access management for Azure resources"),
            "{message}"
        );
    }
}
