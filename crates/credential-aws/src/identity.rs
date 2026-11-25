//! Accounts, roles, pins, and the identity the auth view draws its card from.

use std::collections::HashMap;
use std::fmt;

use runbooks_plugin_protocol::credential::{Identity, IdentityKind, Pins as WirePins, Target};
use time::OffsetDateTime;

use crate::aws::CallerIdentity;

/// The target levels, in the order they are chosen.
pub(crate) const ACCOUNT: &str = "account";
pub(crate) const ROLE: &str = "role";

/// A 12-digit AWS account id.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AccountId(String);

/// Displays the value: an account id is not a secret.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{value:?} is not an AWS account id: it should be 12 digits")]
pub struct InvalidAccountId {
    /// The refused value, cut to 32 characters.
    pub value: String,
}

impl AccountId {
    /// # Errors
    ///
    /// [`InvalidAccountId`] for anything but 12 ASCII digits.
    pub fn parse(value: &str) -> Result<Self, InvalidAccountId> {
        if value.len() == 12 && value.bytes().all(|b| b.is_ascii_digit()) {
            Ok(Self(value.to_owned()))
        } else {
            Err(InvalidAccountId {
                value: value.chars().take(32).collect(),
            })
        }
    }

    /// The 12 digits.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What a block pins: `ssoAccountId` and `ssoRoleName`, keyed by level.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Pins {
    pub account: Option<AccountId>,
    pub role: Option<String>,
}

/// A pin the protocol params name wrongly.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum InvalidPin {
    #[error("pins has level {level:?}, but AWS's levels are account and role")]
    UnknownLevel { level: String },
    #[error("the account pin is invalid: {0}")]
    Account(#[from] InvalidAccountId),
    #[error("the role pin is empty")]
    EmptyRole,
}

/// A credential that is not the one the block pins.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum Mismatch {
    #[error("these credentials are for account {found}, but this block needs account {pinned}")]
    Account { pinned: AccountId, found: AccountId },
    #[error("these credentials are for {found}, but this block needs role {pinned}")]
    Role { pinned: String, found: String },
}

impl Pins {
    /// # Errors
    ///
    /// [`InvalidPin`] for a level AWS does not have, or a value that cannot be one.
    pub(crate) fn parse(pins: &WirePins) -> Result<Self, InvalidPin> {
        let mut parsed = Self::default();
        for (level, value) in pins.iter() {
            match level.as_str() {
                ACCOUNT => parsed.account = Some(AccountId::parse(value)?),
                ROLE if value.is_empty() => return Err(InvalidPin::EmptyRole),
                ROLE => parsed.role = Some(value.clone()),
                _ => {
                    return Err(InvalidPin::UnknownLevel {
                        level: level.chars().take(64).collect(),
                    });
                }
            }
        }
        Ok(parsed)
    }

    /// Whether `principal` is the account and role the block pins. A role
    /// pin matches only a role session with that role name.
    ///
    /// # Errors
    ///
    /// [`Mismatch`] naming the first pin `principal` does not match.
    pub(crate) fn check(&self, principal: &Principal) -> Result<(), Mismatch> {
        if let Some(pinned) = &self.account
            && *pinned != principal.account
        {
            return Err(Mismatch::Account {
                pinned: pinned.clone(),
                found: principal.account.clone(),
            });
        }
        if let Some(pinned) = &self.role
            && principal.role.as_deref() != Some(pinned.as_str())
        {
            return Err(Mismatch::Role {
                pinned: pinned.clone(),
                found: principal
                    .role
                    .as_ref()
                    .map_or_else(|| principal.arn.clone(), |role| format!("role {role}")),
            });
        }
        Ok(())
    }
}

/// Who a set of keys belongs to, read from the ARN STS returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Principal {
    pub arn: String,
    pub account: AccountId,
    /// The account's name for the card: an SSO account name or IAM alias.
    pub account_name: Option<String>,
    /// The role of a role session. For a role IAM Identity Center made for a
    /// permission set, the permission set's name, which is what a block pins.
    pub role: Option<String>,
}

/// IAM Identity Center names the role it makes for a permission set
/// `AWSReservedSSO_<permission set>_<suffix>`.
const SSO_ROLE_PREFIX: &str = "AWSReservedSSO_";

impl Principal {
    pub(crate) fn from_caller(caller: CallerIdentity) -> Self {
        // arn:partition:service:region:account:resource. An assumed role's
        // resource is assumed-role/<role>/<session>.
        let role = caller
            .arn
            .splitn(6, ':')
            .nth(5)
            .and_then(|resource| resource.strip_prefix("assumed-role/"))
            .and_then(|rest| rest.split('/').next())
            .map(|role| {
                role.strip_prefix(SSO_ROLE_PREFIX)
                    .and_then(|named| named.rsplit_once('_'))
                    .map_or(role, |(permission_set, _suffix)| permission_set)
                    .to_owned()
            });
        Self {
            arn: caller.arn,
            account: caller.account,
            account_name: caller.alias,
            role,
        }
    }

    /// The identity card: the ARN, the account, and the role of a role session.
    pub(crate) fn identity(&self, method: &str, expires_at: Option<OffsetDateTime>) -> Identity {
        let mut targets = HashMap::from([(
            ACCOUNT.to_owned(),
            Target {
                id: self.account.to_string(),
                name: self
                    .account_name
                    .clone()
                    .unwrap_or_else(|| self.account.to_string()),
            },
        )]);
        if let Some(role) = &self.role {
            targets.insert(
                ROLE.to_owned(),
                Target {
                    id: role.clone(),
                    name: role.clone(),
                },
            );
        }
        Identity {
            expires_at: expires_at.map(Into::into),
            kind: if self.role.is_some() {
                IdentityKind::Role
            } else {
                IdentityKind::User
            },
            method: method.to_owned(),
            principal: self.arn.clone(),
            targets,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use runbooks_plugin_protocol::credential::Pins as WirePins;

    use super::{AccountId, InvalidPin, Mismatch, Pins, Principal};
    use crate::aws::CallerIdentity;

    fn principal(arn: &str) -> Result<Principal, Box<dyn std::error::Error>> {
        Ok(Principal::from_caller(CallerIdentity {
            account: AccountId::parse("123456789012")?,
            arn: arn.to_owned(),
            alias: None,
        }))
    }

    #[test]
    fn the_role_comes_from_an_assumed_role_arn() -> Result<(), Box<dyn std::error::Error>> {
        for (arn, role) in [
            (
                "arn:aws:sts::123456789012:assumed-role/deploy/ci",
                Some("deploy"),
            ),
            (
                "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_Admin_Access_0a1b2c3d4e5f6a7b/me@example.com",
                Some("Admin_Access"),
            ),
            (
                "arn:aws-us-gov:sts::123456789012:assumed-role/ops/x",
                Some("ops"),
            ),
            ("arn:aws:iam::123456789012:user/path/alice", None),
            ("arn:aws:iam::123456789012:root", None),
        ] {
            assert_eq!(principal(arn)?.role.as_deref(), role, "{arn}");
        }
        Ok(())
    }

    #[test]
    fn pins_parse_by_level_and_refuse_other_levels() -> Result<(), Box<dyn std::error::Error>> {
        let wire = |pairs: &[(&str, &str)]| {
            WirePins(
                pairs
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                    .collect::<HashMap<_, _>>(),
            )
        };
        assert_eq!(
            Pins::parse(&wire(&[("account", "123456789012"), ("role", "Admin")]))?,
            Pins {
                account: Some(AccountId::parse("123456789012")?),
                role: Some("Admin".to_owned()),
            }
        );
        assert!(matches!(
            Pins::parse(&wire(&[("project", "p")])),
            Err(InvalidPin::UnknownLevel { .. })
        ));
        assert!(matches!(
            Pins::parse(&wire(&[("account", "12345")])),
            Err(InvalidPin::Account(_))
        ));
        Ok(())
    }

    #[test]
    fn a_role_pin_needs_a_session_for_that_role() -> Result<(), Box<dyn std::error::Error>> {
        let pins = Pins {
            account: Some(AccountId::parse("123456789012")?),
            role: Some("Admin".to_owned()),
        };
        let admin = principal(
            "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_Admin_0a1b2c3d4e5f6a7b/me",
        )?;
        assert_eq!(pins.check(&admin), Ok(()));
        let user = principal("arn:aws:iam::123456789012:user/alice")?;
        assert!(matches!(pins.check(&user), Err(Mismatch::Role { .. })));
        let other_account = Principal {
            account: AccountId::parse("210987654321")?,
            ..admin
        };
        assert!(matches!(
            pins.check(&other_account),
            Err(Mismatch::Account { .. })
        ));
        Ok(())
    }
}
