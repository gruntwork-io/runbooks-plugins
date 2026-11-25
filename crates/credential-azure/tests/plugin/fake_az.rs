//! An in-memory Azure CLI. Like `az`, it keeps a login in the config
//! directory it is given: a directory holding `azureProfile.json` is signed
//! in, and `login` writes one.

use std::collections::{BTreeSet, HashMap};
use std::error::Error;
use std::fs;
use std::future::{self, Future};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use runbooks_credential_azure::az::{
    Accounts, Az, AzDir, DeviceCode, Interactive, Subscription, Tenant,
};
use runbooks_credential_azure::claims::{Principal, PrincipalKind};
use runbooks_credential_azure::ids::{ObjectId, SubscriptionId, TenantId, TenantRef};
use runbooks_credential_azure::{Connect, Network};
use runbooks_plugin_protocol::credential::ErrorKind;
use runbooks_plugin_transport::PluginError;
use tokio::sync::oneshot;

pub(crate) const CONTOSO: &str = "11111111-1111-4111-8111-111111111111";
pub(crate) const FABRIKAM: &str = "22222222-2222-4222-8222-222222222222";
pub(crate) const PROD: &str = "aaaaaaaa-0000-4000-8000-000000000001";
pub(crate) const DEV: &str = "aaaaaaaa-0000-4000-8000-000000000002";
pub(crate) const SHARED: &str = "aaaaaaaa-0000-4000-8000-000000000003";
pub(crate) const DEVICE_URL: &str = "https://microsoft.com/devicelogin";
pub(crate) const DEVICE_CODE: &str = "FAKECODE1";

fn tenant_id(id: &str) -> Result<TenantId, Box<dyn Error>> {
    Ok(TenantId::parse(id).ok_or_else(|| format!("{id} is not a GUID"))?)
}

fn subscription(id: &str, name: &str, tenant: &str) -> Result<Subscription, Box<dyn Error>> {
    Ok(Subscription {
        id: SubscriptionId::parse(id).ok_or_else(|| format!("{id} is not a GUID"))?,
        name: name.to_owned(),
        tenant_id: tenant_id(tenant)?,
    })
}

fn principal(
    name: &str,
    object_id: &str,
    kind: PrincipalKind,
    tenant: &str,
) -> Result<Principal, Box<dyn Error>> {
    Ok(Principal {
        name: name.to_owned(),
        object_id: ObjectId::parse(object_id)
            .ok_or_else(|| format!("{object_id} is not a GUID"))?,
        kind,
        tenant_id: tenant_id(tenant)?,
    })
}

/// What the fake was asked to do that changes something outside the plugin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Call {
    Login {
        config: PathBuf,
        how: Interactive,
        tenant: Option<String>,
    },
    SetSubscription {
        config: PathBuf,
        subscription: String,
    },
}

pub(crate) struct World {
    /// The tenant a login lands in.
    pub home: TenantId,
    /// Who the login is in each tenant it can get a token for.
    pub principals: HashMap<TenantId, Principal>,
    pub domains: HashMap<String, TenantId>,
    pub accounts: Accounts,
    pub listed: Vec<Tenant>,
    /// Roles the login holds, by ARM scope.
    pub roles: HashMap<String, BTreeSet<String>>,
    pub login_error: Option<PluginError>,
    pub calls: Vec<Call>,
}

impl World {
    /// Ana, a member of Contoso with one subscription, Prod.
    pub(crate) fn one_subscription() -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            home: tenant_id(CONTOSO)?,
            principals: HashMap::from([(
                tenant_id(CONTOSO)?,
                principal(
                    "ana@contoso.com",
                    "00000000-0000-4000-8000-0000000000a1",
                    PrincipalKind::User,
                    CONTOSO,
                )?,
            )]),
            domains: HashMap::from([("contoso.onmicrosoft.com".to_owned(), tenant_id(CONTOSO)?)]),
            accounts: Accounts {
                subscriptions: vec![subscription(PROD, "Prod", CONTOSO)?],
                tenants: vec![tenant_id(CONTOSO)?],
            },
            listed: vec![Tenant {
                id: tenant_id(CONTOSO)?,
                name: Some("Contoso".to_owned()),
            }],
            roles: HashMap::new(),
            login_error: None,
            calls: Vec::new(),
        })
    }

    /// Ana in Contoso with Prod and Dev, and a guest in Fabrikam with Shared.
    pub(crate) fn two_tenants() -> Result<Self, Box<dyn Error>> {
        let mut world = Self::one_subscription()?;
        world.principals.insert(
            tenant_id(FABRIKAM)?,
            principal(
                "ana@contoso.com",
                "00000000-0000-4000-8000-0000000000b2",
                PrincipalKind::Guest,
                FABRIKAM,
            )?,
        );
        world.accounts.subscriptions.extend([
            subscription(DEV, "Dev", CONTOSO)?,
            subscription(SHARED, "Shared", FABRIKAM)?,
        ]);
        world.accounts.tenants.push(tenant_id(FABRIKAM)?);
        world.listed.push(Tenant {
            id: tenant_id(FABRIKAM)?,
            name: Some("Fabrikam".to_owned()),
        });
        Ok(world)
    }

    pub(crate) fn grant(&mut self, scope: &str, role: &str) {
        self.roles
            .entry(scope.to_owned())
            .or_default()
            .insert(role.to_lowercase());
    }
}

#[derive(Clone)]
pub(crate) struct FakeAz(Arc<Mutex<World>>);

impl FakeAz {
    pub(crate) fn new(world: World) -> Self {
        Self(Arc::new(Mutex::new(world)))
    }

    /// The world, for a test to read or change between calls.
    pub(crate) fn world(&self) -> MutexGuard<'_, World> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Records the login, sends the device code, and signs `dir` in unless
    /// the world says the login fails.
    fn log_in(
        &self,
        dir: &AzDir,
        how: Interactive,
        tenant: Option<&TenantRef>,
        device_code: oneshot::Sender<DeviceCode>,
    ) -> Result<(), PluginError> {
        let error = {
            let mut world = self.world();
            world.calls.push(Call::Login {
                config: dir.config.clone(),
                how,
                tenant: tenant.map(|t| t.as_str().to_owned()),
            });
            world.login_error.clone()
        };
        if how == Interactive::DeviceCode {
            let _unread = device_code.send(DeviceCode {
                url: DEVICE_URL.to_owned(),
                code: DEVICE_CODE.to_owned(),
            });
        }
        if let Some(error) = error {
            return Err(error);
        }
        fs::write(dir.config.join("azureProfile.json"), "{}")
            .map_err(|e| PluginError::new(ErrorKind::Internal, e.to_string()))
    }

    /// Who the login is in `tenant`, or in its home tenant.
    fn principal_in(&self, tenant: Option<&TenantRef>) -> Result<Principal, PluginError> {
        let world = self.world();
        let id = match tenant {
            None => Some(world.home.clone()),
            Some(TenantRef::Id(id)) => Some(id.clone()),
            Some(TenantRef::Domain(domain)) => world.domains.get(domain).cloned(),
        };
        let principal = id.and_then(|id| world.principals.get(&id).cloned());
        drop(world);
        principal.ok_or_else(|| {
            PluginError::new(
                ErrorKind::AccessDenied,
                "az could not get a token for that tenant",
            )
        })
    }
}

impl Connect for FakeAz {
    type Az = Self;

    fn connect(&self, _network: &Network) -> Result<Self, PluginError> {
        Ok(self.clone())
    }
}

fn signed_in(dir: &AzDir) -> Result<(), PluginError> {
    if dir.config.join("azureProfile.json").is_file() {
        Ok(())
    } else {
        Err(PluginError::new(
            ErrorKind::NotSignedIn,
            "az account get-access-token failed: Please run 'az login' to setup account.",
        ))
    }
}

impl Az for FakeAz {
    fn login(
        &self,
        dir: &AzDir,
        how: Interactive,
        tenant: Option<&TenantRef>,
        device_code: oneshot::Sender<DeviceCode>,
    ) -> impl Future<Output = Result<(), PluginError>> + Send {
        future::ready(self.log_in(dir, how, tenant, device_code))
    }

    fn principal(
        &self,
        dir: &AzDir,
        tenant: Option<&TenantRef>,
    ) -> impl Future<Output = Result<Principal, PluginError>> + Send {
        future::ready(signed_in(dir).and_then(|()| self.principal_in(tenant)))
    }

    fn accounts(&self, dir: &AzDir) -> impl Future<Output = Result<Accounts, PluginError>> + Send {
        future::ready(signed_in(dir).map(|()| self.world().accounts.clone()))
    }

    fn tenants(
        &self,
        dir: &AzDir,
    ) -> impl Future<Output = Result<Vec<Tenant>, PluginError>> + Send {
        future::ready(signed_in(dir).map(|()| self.world().listed.clone()))
    }

    fn set_subscription(
        &self,
        dir: &AzDir,
        subscription: &SubscriptionId,
    ) -> impl Future<Output = Result<(), PluginError>> + Send {
        future::ready(signed_in(dir).map(|()| {
            self.world().calls.push(Call::SetSubscription {
                config: dir.config.clone(),
                subscription: subscription.to_string(),
            });
        }))
    }

    fn role_names(
        &self,
        dir: &AzDir,
        scope: &str,
        _principal: &ObjectId,
    ) -> impl Future<Output = Result<BTreeSet<String>, PluginError>> + Send {
        future::ready(
            signed_in(dir).map(|()| self.world().roles.get(scope).cloned().unwrap_or_default()),
        )
    }
}
