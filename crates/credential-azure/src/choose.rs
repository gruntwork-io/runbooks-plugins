//! Choosing a tenant and subscription: what the pins fix, what is left to
//! the person, and whether a choice is allowed. No I/O.

use runbooks_plugin_protocol::credential::{ErrorKind, Target};
use runbooks_plugin_transport::PluginError;

use crate::az::{Accounts, Subscription, Tenant};
use crate::ids::{SubscriptionId, TenantId};

/// The block's pins, with a tenant domain already resolved to its id.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Pins {
    /// The pinned tenant.
    pub tenant: Option<TenantPin>,
    /// A subscription's id or name, matched without case.
    pub subscription: Option<String>,
}

/// A pinned tenant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantPin {
    /// Its id.
    pub id: TenantId,
    /// As the block wrote it, for messages: an id or a domain.
    pub written: String,
}

/// What the pins and the login leave to choose.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolution {
    /// Nothing is left to choose.
    Chosen {
        /// The tenant.
        tenant: TenantId,
        /// The subscription, or `None` when the login can use none in
        /// `tenant`.
        subscription: Option<SubscriptionId>,
    },
    /// The person chooses. `tenant` is set when only the subscription is open.
    Open {
        /// The pinned tenant, when only the subscription is open.
        tenant: Option<TenantId>,
    },
}

/// The tenants a login can see: those Azure lists, then those `az` holds,
/// then the one it signed in to, each once.
#[must_use]
pub fn visible_tenants(
    listed: Vec<Tenant>,
    accounts: &Accounts,
    signed_in: &TenantId,
) -> Vec<Tenant> {
    let mut tenants: Vec<Tenant> = Vec::new();
    let unnamed = accounts.tenants.iter().chain([signed_in]).map(|id| Tenant {
        id: id.clone(),
        name: None,
    });
    for tenant in listed.into_iter().chain(unnamed) {
        if !tenants.iter().any(|seen| seen.id == tenant.id) {
            tenants.push(tenant);
        }
    }
    tenants
}

fn matches_pin(subscription: &Subscription, pin: &str) -> bool {
    subscription.id.as_str().eq_ignore_ascii_case(pin)
        || subscription.name.eq_ignore_ascii_case(pin)
}

/// Chooses what the pins fix, and what is the only option: one tenant
/// with at most one subscription, or a pinned tenant with at most one.
///
/// # Errors
///
/// Kind `pinMismatch` when the login cannot see a pinned tenant or
/// subscription.
pub fn resolve(
    tenants: &[Tenant],
    subscriptions: &[Subscription],
    pins: &Pins,
) -> Result<Resolution, PluginError> {
    let pinned_tenant = pins.tenant.as_ref();
    if let Some(wanted) = &pins.subscription {
        let found = subscriptions.iter().find(|sub| {
            matches_pin(sub, wanted) && pinned_tenant.is_none_or(|pin| sub.tenant_id == pin.id)
        });
        let Some(found) = found else {
            let message = pinned_tenant.map_or_else(
                || format!(
                    "Subscription {wanted} isn't one this account can use. Sign in as an account that can use it, or change the block's subscriptionId."
                ),
                |pin| format!(
                    "Subscription {wanted} isn't one this account can use in tenant {}. Sign in as an account that can use it, or change the block's subscriptionId.",
                    pin.written
                ),
            );
            return Err(PluginError::new(ErrorKind::PinMismatch, message));
        };
        return Ok(Resolution::Chosen {
            tenant: found.tenant_id.clone(),
            subscription: Some(found.id.clone()),
        });
    }

    if let Some(pin) = pinned_tenant {
        if !tenants.iter().any(|tenant| tenant.id == pin.id) {
            return Err(PluginError::new(
                ErrorKind::PinMismatch,
                format!(
                    "This account can't see tenant {}. Sign in to that tenant directly, or ask its admin to invite you.",
                    pin.written
                ),
            ));
        }
        let mut in_tenant = subscriptions.iter().filter(|sub| sub.tenant_id == pin.id);
        return Ok(match (in_tenant.next(), in_tenant.next()) {
            (first, None) => Resolution::Chosen {
                tenant: pin.id.clone(),
                subscription: first.map(|sub| sub.id.clone()),
            },
            (_, Some(_)) => Resolution::Open {
                tenant: Some(pin.id.clone()),
            },
        });
    }

    Ok(match (tenants, subscriptions) {
        ([only], [] | [_]) => Resolution::Chosen {
            tenant: only.id.clone(),
            subscription: subscriptions.first().map(|sub| sub.id.clone()),
        },
        _ => Resolution::Open { tenant: None },
    })
}

/// `tenant` as a target, named by its id when it has no name.
#[must_use]
pub fn tenant_target(tenant: &Tenant) -> Target {
    Target {
        id: tenant.id.to_string(),
        name: tenant.name.clone().unwrap_or_else(|| tenant.id.to_string()),
    }
}

/// `subscription` as a target.
#[must_use]
pub fn subscription_target(subscription: &Subscription) -> Target {
    Target {
        id: subscription.id.to_string(),
        name: subscription.name.clone(),
    }
}

/// The tenants the person may choose: the pinned one, or all of them.
pub fn tenant_targets(tenants: &[Tenant], pins: &Pins) -> Vec<Target> {
    tenants
        .iter()
        .filter(|tenant| pins.tenant.as_ref().is_none_or(|pin| pin.id == tenant.id))
        .map(tenant_target)
        .collect()
}

/// The subscriptions in `tenant` the person may choose.
pub fn subscription_targets(
    subscriptions: &[Subscription],
    tenant: &TenantId,
    pins: &Pins,
) -> Vec<Target> {
    subscriptions
        .iter()
        .filter(|sub| &sub.tenant_id == tenant)
        .filter(|sub| {
            pins.subscription
                .as_deref()
                .is_none_or(|pin| matches_pin(sub, pin))
        })
        .map(subscription_target)
        .collect()
}

/// Checks a choice from `select` against what the login can see and the pins.
///
/// # Errors
///
/// `invalidParams` for a tenant or subscription the login cannot see, and
/// `pinMismatch` for one the block's pins rule out.
pub fn check_choice(
    tenants: &[Tenant],
    subscriptions: &[Subscription],
    pins: &Pins,
    tenant: &TenantId,
    subscription: Option<&SubscriptionId>,
) -> Result<(), PluginError> {
    if !tenants.iter().any(|seen| &seen.id == tenant) {
        return Err(PluginError::new(
            ErrorKind::InvalidParams,
            format!("select: tenant {tenant} is not one this sign-in can see. targets lists them."),
        ));
    }
    if let Some(pin) = &pins.tenant
        && &pin.id != tenant
    {
        return Err(PluginError::new(
            ErrorKind::PinMismatch,
            format!("The block pins tenant {}, not {tenant}.", pin.written),
        ));
    }
    let chosen = match subscription {
        Some(id) => Some(
            subscriptions
                .iter()
                .find(|sub| &sub.id == id && &sub.tenant_id == tenant)
                .ok_or_else(|| {
                    PluginError::new(
                        ErrorKind::InvalidParams,
                        format!(
                            "select: subscription {id} is not one this sign-in can use in tenant {tenant}. targets lists them."
                        ),
                    )
                })?,
        ),
        None => None,
    };
    match (&pins.subscription, chosen) {
        (Some(pin), Some(sub)) if !matches_pin(sub, pin) => Err(PluginError::new(
            ErrorKind::PinMismatch,
            format!("The block pins subscription {pin}, not {}.", sub.name),
        )),
        (Some(pin), None) => Err(PluginError::new(
            ErrorKind::PinMismatch,
            format!("The block pins subscription {pin}: choose it."),
        )),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use runbooks_plugin_protocol::credential::ErrorKind;
    use runbooks_plugin_transport::PluginError;

    use super::{Pins, Resolution, TenantPin, check_choice, resolve, visible_tenants};
    use crate::az::{Accounts, Subscription, Tenant};
    use crate::ids::{SubscriptionId, TenantId};

    type TestResult = Result<(), Box<dyn Error>>;

    const T1: &str = "11111111-0000-0000-0000-000000000000";
    const T2: &str = "22222222-0000-0000-0000-000000000000";
    const S1: &str = "aaaaaaaa-0000-0000-0000-000000000001";
    const S2: &str = "aaaaaaaa-0000-0000-0000-000000000002";
    const S3: &str = "aaaaaaaa-0000-0000-0000-000000000003";

    fn tenant(id: &str) -> Result<TenantId, Box<dyn Error>> {
        Ok(TenantId::parse(id).ok_or_else(|| format!("{id} is not a GUID"))?)
    }

    fn sub(id: &str, name: &str, tenant_id: &str) -> Result<Subscription, Box<dyn Error>> {
        Ok(Subscription {
            id: SubscriptionId::parse(id).ok_or_else(|| format!("{id} is not a GUID"))?,
            name: name.to_owned(),
            tenant_id: tenant(tenant_id)?,
        })
    }

    fn tenants(ids: &[&str]) -> Result<Vec<Tenant>, Box<dyn Error>> {
        ids.iter()
            .map(|id| {
                Ok(Tenant {
                    id: tenant(id)?,
                    name: None,
                })
            })
            .collect()
    }

    fn pin_tenant(id: &str) -> Result<TenantPin, Box<dyn Error>> {
        Ok(TenantPin {
            id: tenant(id)?,
            written: id.to_owned(),
        })
    }

    fn chosen(tenant_id: &str, subscription: Option<&str>) -> Result<Resolution, Box<dyn Error>> {
        Ok(Resolution::Chosen {
            tenant: tenant(tenant_id)?,
            subscription: subscription.and_then(SubscriptionId::parse),
        })
    }

    #[test]
    fn one_tenant_with_at_most_one_subscription_is_chosen_alone() -> TestResult {
        let one = [sub(S1, "Prod", T1)?];
        assert_eq!(
            resolve(&tenants(&[T1])?, &one, &Pins::default()).ok(),
            Some(chosen(T1, Some(S1))?)
        );
        assert_eq!(
            resolve(&tenants(&[T1])?, &[], &Pins::default()).ok(),
            Some(chosen(T1, None)?)
        );
        let two = [sub(S1, "Prod", T1)?, sub(S2, "Dev", T1)?];
        assert_eq!(
            resolve(&tenants(&[T1])?, &two, &Pins::default()).ok(),
            Some(Resolution::Open { tenant: None })
        );
        assert_eq!(
            resolve(&tenants(&[T1, T2])?, &[], &Pins::default()).ok(),
            Some(Resolution::Open { tenant: None })
        );
        Ok(())
    }

    #[test]
    fn a_pinned_subscription_by_id_or_name_chooses_its_tenant() -> TestResult {
        let subs = [
            sub(S1, "Prod", T1)?,
            sub(S2, "Management", T2)?,
            sub(S3, "Dev", T2)?,
        ];
        let all = tenants(&[T1, T2])?;
        for wanted in ["management", S2, &S2.to_uppercase()] {
            let pins = Pins {
                subscription: Some(wanted.to_owned()),
                ..Pins::default()
            };
            assert_eq!(
                resolve(&all, &subs, &pins).ok(),
                Some(chosen(T2, Some(S2))?),
                "{wanted}"
            );
        }
        let pins = Pins {
            tenant: Some(pin_tenant(T1)?),
            subscription: Some("Management".to_owned()),
        };
        let error = resolve(&all, &subs, &pins).err();
        assert_eq!(
            error.as_ref().map(PluginError::kind),
            Some(ErrorKind::PinMismatch)
        );
        assert!(error.is_some_and(|e| e.message().contains("in tenant")));
        Ok(())
    }

    #[test]
    fn a_pinned_tenant_is_chosen_and_leaves_its_subscriptions_open_when_there_are_several()
    -> TestResult {
        let subs = [
            sub(S1, "Prod", T1)?,
            sub(S2, "Management", T2)?,
            sub(S3, "Dev", T2)?,
        ];
        let all = tenants(&[T1, T2])?;
        let pinned = |id| -> Result<Pins, Box<dyn Error>> {
            Ok(Pins {
                tenant: Some(pin_tenant(id)?),
                ..Pins::default()
            })
        };
        assert_eq!(
            resolve(&all, &subs, &pinned(T1)?).ok(),
            Some(chosen(T1, Some(S1))?)
        );
        assert_eq!(
            resolve(&all, &subs, &pinned(T2)?).ok(),
            Some(Resolution::Open {
                tenant: Some(tenant(T2)?)
            })
        );
        let unseen = "33333333-0000-0000-0000-000000000000";
        assert_eq!(
            resolve(&all, &subs, &pinned(unseen)?)
                .err()
                .map(|e| e.kind()),
            Some(ErrorKind::PinMismatch)
        );
        Ok(())
    }

    #[test]
    fn visible_tenants_merge_listed_held_and_signed_in_once_each() -> TestResult {
        let accounts = Accounts {
            subscriptions: Vec::new(),
            tenants: vec![tenant(T2)?, tenant(T1)?],
        };
        let listed = vec![Tenant {
            id: tenant(T1)?,
            name: Some("Contoso".to_owned()),
        }];
        let third = tenant("33333333-0000-0000-0000-000000000000")?;
        let merged = visible_tenants(listed, &accounts, &third);
        let ids: Vec<&str> = merged.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(ids, [T1, T2, third.as_str()]);
        assert_eq!(
            merged.first().and_then(|t| t.name.as_deref()),
            Some("Contoso")
        );
        Ok(())
    }

    #[test]
    fn a_choice_is_checked_against_the_login_and_the_pins() -> TestResult {
        let subs = [sub(S1, "Prod", T1)?, sub(S2, "Management", T2)?];
        let all = tenants(&[T1, T2])?;
        let s1 = SubscriptionId::parse(S1);
        let s2 = SubscriptionId::parse(S2);
        let kind = |pins: &Pins,
                    t: &str,
                    s: Option<&SubscriptionId>|
         -> Result<Option<ErrorKind>, Box<dyn Error>> {
            Ok(check_choice(&all, &subs, pins, &tenant(t)?, s)
                .err()
                .map(|e| e.kind()))
        };
        let none = Pins::default();
        assert_eq!(kind(&none, T1, s1.as_ref())?, None);
        assert_eq!(kind(&none, T1, None)?, None);
        assert_eq!(
            kind(&none, T1, s2.as_ref())?,
            Some(ErrorKind::InvalidParams)
        );
        assert_eq!(
            kind(&none, "33333333-0000-0000-0000-000000000000", None)?,
            Some(ErrorKind::InvalidParams)
        );
        let tenant_pinned = Pins {
            tenant: Some(pin_tenant(T2)?),
            ..Pins::default()
        };
        assert_eq!(
            kind(&tenant_pinned, T1, s1.as_ref())?,
            Some(ErrorKind::PinMismatch)
        );
        let sub_pinned = Pins {
            subscription: Some("prod".to_owned()),
            ..Pins::default()
        };
        assert_eq!(kind(&sub_pinned, T1, s1.as_ref())?, None);
        assert_eq!(kind(&sub_pinned, T1, None)?, Some(ErrorKind::PinMismatch));
        assert_eq!(
            kind(&sub_pinned, T2, s2.as_ref())?,
            Some(ErrorKind::PinMismatch)
        );
        Ok(())
    }
}
