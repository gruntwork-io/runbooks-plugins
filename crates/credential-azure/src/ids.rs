//! Azure's identifiers, each parsed once where it enters the plugin.

use std::fmt;

/// `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`, in hex digits of either case.
fn is_guid(text: &str) -> bool {
    let groups: Vec<&str> = text.split('-').collect();
    groups.len() == 5
        && groups
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(group, len)| group.len() == len && group.bytes().all(|b| b.is_ascii_hexdigit()))
}

macro_rules! guid_type {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(String);

        impl $name {
            /// A GUID, kept in lower case so two spellings compare equal.
            pub fn parse(text: &str) -> Option<Self> {
                is_guid(text).then(|| Self(text.to_ascii_lowercase()))
            }

            /// The GUID, in lower case.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

guid_type!(
    /// A Microsoft Entra tenant's id.
    TenantId
);
guid_type!(
    /// An Azure subscription's id.
    SubscriptionId
);
guid_type!(
    /// A principal's object id in one tenant.
    ObjectId
);

/// A tenant as a person names it: its id, or one of its domains.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TenantRef {
    /// The tenant's GUID.
    Id(TenantId),
    /// `contoso.onmicrosoft.com`. `az` resolves it to an id.
    Domain(String),
}

impl TenantRef {
    /// `None` for text that is neither a GUID nor a domain name.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        if let Some(id) = TenantId::parse(text) {
            return Some(Self::Id(id));
        }
        is_domain(text).then(|| Self::Domain(text.to_ascii_lowercase()))
    }

    /// The id or the domain, in lower case.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Id(id) => id.as_str(),
            Self::Domain(domain) => domain,
        }
    }
}

impl fmt::Display for TenantRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Two or more dot-separated labels of letters, digits and inner hyphens.
fn is_domain(text: &str) -> bool {
    let labels: Vec<&str> = text.split('.').collect();
    text.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::{SubscriptionId, TenantId, TenantRef};

    #[test]
    fn a_guid_parses_in_either_case_and_compares_in_lower_case() {
        let upper = TenantId::parse("72F988BF-86F1-41AF-91AB-2D7CD011DB47");
        let lower = TenantId::parse("72f988bf-86f1-41af-91ab-2d7cd011db47");
        assert!(upper.is_some());
        assert_eq!(upper, lower);
        for bad in [
            "",
            "72f988bf86f141af91ab2d7cd011db47",
            "72f988bf-86f1-41af-91ab-2d7cd011db4",
            "72f988bf-86f1-41af-91ab-2d7cd011db4g",
            "72f988bf-86f1-41af-91ab-2d7cd011db47-0",
        ] {
            assert_eq!(SubscriptionId::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn a_tenant_is_an_id_or_a_domain() {
        assert!(matches!(
            TenantRef::parse("72f988bf-86f1-41af-91ab-2d7cd011db47"),
            Some(TenantRef::Id(_))
        ));
        assert_eq!(
            TenantRef::parse("Contoso.onmicrosoft.com"),
            Some(TenantRef::Domain("contoso.onmicrosoft.com".to_owned()))
        );
        for bad in [
            "contoso",
            "-contoso.com",
            "contoso..com",
            "contoso.com/x",
            "--tenant",
            "a b.com",
        ] {
            assert_eq!(TenantRef::parse(bad), None, "{bad:?}");
        }
    }
}
