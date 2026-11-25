//! An in-memory Azure CLI. Like `az`, it keeps a login in the config
//! directory it is given: a directory holding `azureProfile.json` is signed
//! in, and `login` writes one.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use runbooks_credential_azure::az::{
    Accounts, Az, AzDir, DeviceCode, Interactive, Subscription, Tenant,
};
use runbooks_credential_azure::claims::{Principal, PrincipalKind};
use runbooks_credential_azure::ids::{ObjectId, SubscriptionId, TenantId, TenantRef};
use runbooks_credential_azure::{Connect, Network};
use runbooks_plugin_protocol::credential::ErrorKind;
use runbooks_plugin_transport::PluginError;
use tokio::sync::oneshot;

pub const CONTOSO: &str = "11111111-1111-4111-8111-111111111111";
pub const FABRIKAM: &str = "22222222-2222-4222-8222-222222222222";
pub const PROD: &str = "aaaaaaaa-0000-4000-8000-000000000001";
pub const DEV: &str = "aaaaaaaa-0000-4000-8000-000000000002";
pub const SHARED: &str = "aaaaaaaa-0000-4000-8000-000000000003";
pub const DEVICE_URL: &str = "https://microsoft.com/devicelogin";
pub const DEVICE_CODE: &str = "FAKECODE1";

pub fn tenant_id(id: &str) -> TenantId {
    TenantId::parse(id).unwrap_or_else(|| unreachable!("{id} is a GUID"))
}

fn subscription(id: &str, name: &str, tenant: &str) -> Subscription {
    Subscription {
        id: SubscriptionId::parse(id).unwrap_or_else(|| unreachable!("{id} is a GUID")),
        name: name.to_owned(),
        tenant_id: tenant_id(tenant),
    }
}

fn principal(name: &str, object_id: &str, kind: PrincipalKind, tenant: &str) -> Principal {
    Principal {
        name: name.to_owned(),
        object_id: ObjectId::parse(object_id).unwrap_or_else(|| unreachable!("a GUID")),
        kind,
        tenant_id: tenant_id(tenant),
    }
}

/// What the fake was asked to do that changes something outside the plugin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Call {
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

pub struct World {
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
    pub fn one_subscription() -> Self {
        Self {
            home: tenant_id(CONTOSO),
            principals: HashMap::from([(
                tenant_id(CONTOSO),
                principal(
                    "ana@contoso.com",
                    "00000000-0000-4000-8000-0000000000a1",
                    PrincipalKind::User,
                    CONTOSO,
                ),
            )]),
            domains: HashMap::from([("contoso.onmicrosoft.com".to_owned(), tenant_id(CONTOSO))]),
            accounts: Accounts {
                subscriptions: vec![subscription(PROD, "Prod", CONTOSO)],
                tenants: vec![tenant_id(CONTOSO)],
            },
            listed: vec![Tenant {
                id: tenant_id(CONTOSO),
                name: Some("Contoso".to_owned()),
            }],
            roles: HashMap::new(),
            login_error: None,
            calls: Vec::new(),
        }
    }

    /// Ana in Contoso with Prod and Dev, and a guest in Fabrikam with Shared.
    pub fn two_tenants() -> Self {
        let mut world = Self::one_subscription();
        world.principals.insert(
            tenant_id(FABRIKAM),
            principal(
                "ana@contoso.com",
                "00000000-0000-4000-8000-0000000000b2",
                PrincipalKind::Guest,
                FABRIKAM,
            ),
        );
        world.accounts.subscriptions.extend([
            subscription(DEV, "Dev", CONTOSO),
            subscription(SHARED, "Shared", FABRIKAM),
        ]);
        world.accounts.tenants.push(tenant_id(FABRIKAM));
        world.listed.push(Tenant {
            id: tenant_id(FABRIKAM),
            name: Some("Fabrikam".to_owned()),
        });
        world
    }

    pub fn grant(&mut self, scope: &str, role: &str) {
        self.roles
            .entry(scope.to_owned())
            .or_default()
            .insert(role.to_lowercase());
    }
}

#[derive(Clone)]
pub struct FakeAz(Arc<Mutex<World>>);

impl FakeAz {
    pub fn new(world: World) -> Self {
        Self(Arc::new(Mutex::new(world)))
    }

    /// The world, for a test to read or change between calls.
    pub fn world(&self) -> MutexGuard<'_, World> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
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
    async fn login(
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

    async fn principal(
        &self,
        dir: &AzDir,
        tenant: Option<&TenantRef>,
    ) -> Result<Principal, PluginError> {
        signed_in(dir)?;
        let world = self.world();
        let id = match tenant {
            None => Some(world.home.clone()),
            Some(TenantRef::Id(id)) => Some(id.clone()),
            Some(TenantRef::Domain(domain)) => world.domains.get(domain).cloned(),
        };
        id.and_then(|id| world.principals.get(&id).cloned())
            .ok_or_else(|| {
                PluginError::new(
                    ErrorKind::AccessDenied,
                    "az could not get a token for that tenant",
                )
            })
    }

    async fn accounts(&self, dir: &AzDir) -> Result<Accounts, PluginError> {
        signed_in(dir)?;
        Ok(self.world().accounts.clone())
    }

    async fn tenants(&self, dir: &AzDir) -> Result<Vec<Tenant>, PluginError> {
        signed_in(dir)?;
        Ok(self.world().listed.clone())
    }

    async fn set_subscription(
        &self,
        dir: &AzDir,
        subscription: &SubscriptionId,
    ) -> Result<(), PluginError> {
        signed_in(dir)?;
        self.world().calls.push(Call::SetSubscription {
            config: dir.config.clone(),
            subscription: subscription.to_string(),
        });
        Ok(())
    }

    async fn role_names(
        &self,
        dir: &AzDir,
        scope: &str,
        _principal: &ObjectId,
    ) -> Result<BTreeSet<String>, PluginError> {
        signed_in(dir)?;
        Ok(self.world().roles.get(scope).cloned().unwrap_or_default())
    }
}
