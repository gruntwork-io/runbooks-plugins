//! Accounts, roles, pins, and the identity the auth view draws its card from.

use std::fmt;

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
