//! One block's sign-in: who, through which method, what it can see, and
//! what is chosen. Building its identity and its env is pure.

use std::collections::HashMap;

use runbooks_plugin_protocol::credential::{EnvValue, EnvValueToItem, Identity, IdentityKind};

use crate::az::{AzDir, Subscription, Tenant};
use crate::choose::{Pins, subscription_target, tenant_target};
use crate::claims::{Principal, PrincipalKind};
use crate::describe::{SUBSCRIPTION_LEVEL, TENANT_LEVEL};
use crate::ids::TenantId;
use crate::roles::RoleRequirement;
use crate::service_principal::{Credential, ServicePrincipal};

/// A sign-in method: one tab in the auth view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SignInMethod {
    /// `az login` in a browser, or the person's own `az` login, detected.
    Cli,
    DeviceCode,
    ServicePrincipal,
}

impl SignInMethod {
    pub(crate) const ALL: [Self; 3] = [Self::Cli, Self::DeviceCode, Self::ServicePrincipal];

    /// Its name in the protocol, and the value of `AZURE_AUTH_TYPE`.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::DeviceCode => "device_code",
            Self::ServicePrincipal => "service_principal",
        }
    }

    pub(crate) fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|method| method.name() == name)
    }
}

pub(crate) struct Session {
    pub method: SignInMethod,
    pub dir: AzDir,
    /// Who signed in, in the tenant `az` signed in to.
    pub home: Principal,
    pub tenants: Vec<Tenant>,
    pub subscriptions: Vec<Subscription>,
    pub pins: Pins,
    pub roles: Vec<RoleRequirement>,
    pub stage: Stage,
    /// A service principal's credential, for the tools that read it from
    /// the environment rather than from `az`. A certificate is the block's
    /// own copy.
    pub service_principal: Option<ServicePrincipal>,
}

pub(crate) enum Stage {
    /// The person chooses. `tenant` is set when the pins fixed it.
    Choosing {
        tenant: Option<TenantId>,
    },
    Ready(Chosen),
}

/// A choice that has been checked: the principal holds the required roles.
pub(crate) struct Chosen {
    pub tenant: Tenant,
    pub subscription: Option<Subscription>,
    /// Who the sign-in is in the chosen tenant: a guest has an object id there.
    pub principal: Principal,
}

impl Session {
    pub(crate) fn identity(&self) -> Identity {
        let mut targets = HashMap::new();
        let principal = match &self.stage {
            Stage::Ready(chosen) => {
                targets.insert(TENANT_LEVEL.to_owned(), tenant_target(&chosen.tenant));
                if let Some(subscription) = &chosen.subscription {
                    targets.insert(
                        SUBSCRIPTION_LEVEL.to_owned(),
                        subscription_target(subscription),
                    );
                }
                &chosen.principal
            }
            Stage::Choosing { tenant } => {
                if let Some(tenant) = tenant.as_ref().and_then(|id| self.tenant(id)) {
                    targets.insert(TENANT_LEVEL.to_owned(), tenant_target(tenant));
                }
                &self.home
            }
        };
        Identity {
            expires_at: None,
            kind: match principal.kind {
                PrincipalKind::User => IdentityKind::User,
                PrincipalKind::Guest => IdentityKind::Guest,
                PrincipalKind::ServicePrincipal => IdentityKind::ServicePrincipal,
            },
            method: self.method.name().to_owned(),
            principal: principal.name.clone(),
            targets,
            warnings: Vec::new(),
        }
    }

    pub(crate) fn tenant(&self, id: &TenantId) -> Option<&Tenant> {
        self.tenants.iter().find(|tenant| &tenant.id == id)
    }

    /// What a run gets once `chosen` is ready. `azurerm`, `azuread` and
    /// `azapi` use the sign-in in `AZURE_CONFIG_DIR` through `ARM_USE_CLI`.
    pub(crate) fn env(&self, chosen: &Chosen) -> Vec<EnvValue> {
        let mut values = Values::default();
        values.both("AZURE_CONFIG_DIR", path(&self.dir.config));
        values.both(
            "AZURE_EXTENSION_DIR",
            path(
                &self
                    .dir
                    .extensions
                    .clone()
                    .unwrap_or_else(|| self.dir.config.join("cliextensions")),
            ),
        );
        values.both("AZURE_TENANT_ID", chosen.tenant.id.to_string());
        if let Some(subscription) = &chosen.subscription {
            values.both("AZURE_SUBSCRIPTION_ID", subscription.id.to_string());
            values.both("ARM_SUBSCRIPTION_ID", subscription.id.to_string());
            values.output("AZURE_SUBSCRIPTION_NAME", subscription.name.clone());
        }
        if let Some(principal) = &self.service_principal {
            values.both("ARM_CLIENT_ID", principal.client_id.to_string());
            values.both("AZURE_CLIENT_ID", principal.client_id.to_string());
        }
        match self.service_principal.as_ref().map(|sp| &sp.credential) {
            Some(Credential::Secret(secret)) => {
                values.secret("ARM_CLIENT_SECRET", secret.expose());
                values.secret("AZURE_CLIENT_SECRET", secret.expose());
                values.both("ARM_TENANT_ID", chosen.tenant.id.to_string());
            }
            certificate @ (Some(Credential::Certificate(_)) | None) => {
                // No ARM_TENANT_ID: the azurerm backend passes it to `az
                // account get-access-token` as --tenant beside --subscription,
                // which the Azure CLI refuses. The sign-in in AZURE_CONFIG_DIR
                // already has the tenant. azurerm reads only PKCS#12
                // certificates, so a PEM one goes through az too.
                values.both("ARM_USE_CLI", "true".to_owned());
                if let Some(Credential::Certificate(copy)) = certificate {
                    values.both("AZURE_CLIENT_CERTIFICATE_PATH", path(copy));
                }
            }
        }
        values.both("AZURE_AUTH_TYPE", self.method.name().to_owned());
        values.both("AZURE_PRINCIPAL_NAME", chosen.principal.name.clone());
        values.both(
            "AZURE_PRINCIPAL_OBJECT_ID",
            chosen.principal.object_id.to_string(),
        );
        values.both(
            "AZURE_PRINCIPAL_TYPE",
            chosen.principal.kind.as_str().to_owned(),
        );
        if let Some(name) = &chosen.tenant.name {
            values.output("AZURE_TENANT_NAME", name.clone());
        }
        values.0
    }
}

/// A path as a variable's value. The state directory's path came in as a
/// JSON string, so the paths under it are UTF-8; one that is not is dropped.
fn path(path: &std::path::Path) -> Option<String> {
    path.to_str().map(str::to_owned)
}

#[derive(Default)]
struct Values(Vec<EnvValue>);

impl Values {
    fn push(
        &mut self,
        name: &str,
        value: Option<String>,
        sensitive: bool,
        to: Vec<EnvValueToItem>,
    ) {
        if let Some(value) = value {
            self.0.push(EnvValue {
                name: name.to_owned(),
                sensitive,
                to,
                value,
            });
        }
    }

    fn both(&mut self, name: &str, value: impl Into<Option<String>>) {
        let to = vec![EnvValueToItem::Env, EnvValueToItem::Output];
        self.push(name, value.into(), false, to);
    }

    /// A sensitive output: a template that shows it shows `<redacted>`.
    fn secret(&mut self, name: &str, value: &str) {
        let to = vec![EnvValueToItem::Env, EnvValueToItem::Output];
        self.push(name, Some(value.to_owned()), true, to);
    }

    fn output(&mut self, name: &str, value: String) {
        self.push(name, Some(value), false, vec![EnvValueToItem::Output]);
    }
}
