//! A service principal: an app's client id in its tenant, with a client
//! secret or a PEM certificate. It comes from `signIn`'s fields, the
//! environment, or an earlier block's outputs.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::ids::{ClientId, TenantRef};

/// A client secret. It goes to `az` on standard input and to a run through
/// `env`, and nowhere else: `Debug` hides it and it has no `Display`.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    /// `text` with every copy of the secret replaced, for a message made
    /// from what another program printed.
    pub fn redact(&self, text: &str) -> String {
        if self.0.is_empty() {
            text.to_owned()
        } else {
            text.replace(&self.0, "<redacted>")
        }
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Credential {
    Secret(Secret),
    /// A PEM file holding the certificate and its private key.
    Certificate(PathBuf),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServicePrincipal {
    pub client_id: ClientId,
    pub tenant: TenantRef,
    pub credential: Credential,
}

/// A service principal read from variables, and the subscription they name.
#[derive(Debug)]
pub struct Found {
    pub principal: ServicePrincipal,
    pub subscription: Option<String>,
}

/// The variable families, in the order they are read: `azurerm`'s, then
/// the Azure SDKs'.
const FAMILIES: [&str; 2] = ["ARM_", "AZURE_"];

/// The Azure CLI reads only PEM certificates, not PKCS#12 files.
pub fn is_pkcs12(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("pfx") || ext.eq_ignore_ascii_case("p12"))
}

/// What a PKCS#12 certificate's message says to do.
pub fn pkcs12_message(path: &Path) -> String {
    format!(
        "The Azure CLI takes a PEM certificate, not {}. Convert it with openssl pkcs12 -in <file> -out <file>.pem -nodes.",
        path.display()
    )
}

/// A detection prefix: `CI_` reads `CI_ARM_CLIENT_ID` and so on.
pub fn is_prefix(prefix: &str) -> bool {
    let mut bytes = prefix.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_uppercase())
        && prefix.ends_with('_')
        && bytes.all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

/// The first family whose variables hold a client id, a tenant, and a
/// secret or a PEM certificate at an absolute path. `get` reads one
/// variable; `prefix` goes before every name.
pub fn from_vars(prefix: &str, get: impl Fn(&str) -> Option<String>) -> Option<Found> {
    FAMILIES.iter().find_map(|family| {
        let var = |name: &str| {
            get(&format!("{prefix}{family}{name}")).filter(|value| !value.trim().is_empty())
        };
        let client_id = ClientId::parse(var("CLIENT_ID")?.trim())?;
        let tenant = TenantRef::parse(&var("TENANT_ID")?)?;
        let certificate = var("CLIENT_CERTIFICATE_PATH").map(PathBuf::from);
        let credential = match (var("CLIENT_SECRET"), certificate) {
            (Some(secret), _) => Credential::Secret(Secret::new(secret)),
            (None, Some(path)) if path.is_absolute() && !is_pkcs12(&path) => {
                Credential::Certificate(path)
            }
            (None, Some(_) | None) => return None,
        };
        Some(Found {
            principal: ServicePrincipal {
                client_id,
                tenant,
                credential,
            },
            subscription: var("SUBSCRIPTION_ID").map(|id| id.trim().to_owned()),
        })
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::Path;

    use super::{Credential, Secret, from_vars, is_pkcs12, is_prefix};

    const CLIENT: &str = "33333333-3333-4333-8333-333333333333";
    const TENANT: &str = "11111111-1111-4111-8111-111111111111";

    fn vars(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn reads_arm_first_then_azure_with_the_prefix() {
        let env = vars(&[
            ("CI_AZURE_CLIENT_ID", CLIENT),
            ("CI_AZURE_TENANT_ID", TENANT),
            ("CI_AZURE_CLIENT_SECRET", "azure-secret"),
            ("CI_ARM_CLIENT_ID", CLIENT),
            ("CI_ARM_TENANT_ID", "contoso.onmicrosoft.com"),
            ("CI_ARM_CLIENT_SECRET", "arm-secret"),
            ("CI_ARM_SUBSCRIPTION_ID", " Prod "),
            ("ARM_CLIENT_SECRET", "unprefixed"),
        ]);
        let found = from_vars("CI_", |name| env.get(name).cloned());
        let found = found.unwrap_or_else(|| unreachable!("CI_ARM_ is complete"));
        assert_eq!(
            found.principal.credential,
            Credential::Secret(Secret::new("arm-secret".to_owned()))
        );
        assert_eq!(found.principal.tenant.as_str(), "contoso.onmicrosoft.com");
        assert_eq!(found.subscription.as_deref(), Some("Prod"));
    }

    #[test]
    fn an_incomplete_family_is_skipped() {
        let pem = if cfg!(windows) {
            r"C:\sp.pem"
        } else {
            "/sp.pem"
        };
        let env = vars(&[
            ("ARM_CLIENT_ID", CLIENT),
            ("ARM_TENANT_ID", TENANT),
            ("ARM_CLIENT_CERTIFICATE_PATH", "/sp.pfx"),
            ("AZURE_CLIENT_ID", CLIENT),
            ("AZURE_TENANT_ID", TENANT),
            ("AZURE_CLIENT_CERTIFICATE_PATH", pem),
        ]);
        let found = from_vars("", |name| env.get(name).cloned());
        assert_eq!(
            found.map(|found| found.principal.credential),
            Some(Credential::Certificate(pem.into()))
        );
        for missing in [
            vars(&[("ARM_CLIENT_ID", CLIENT), ("ARM_TENANT_ID", TENANT)]),
            vars(&[
                ("ARM_CLIENT_ID", "app"),
                ("ARM_TENANT_ID", TENANT),
                ("ARM_CLIENT_SECRET", "s"),
            ]),
            vars(&[
                ("ARM_CLIENT_ID", CLIENT),
                ("ARM_TENANT_ID", " "),
                ("ARM_CLIENT_SECRET", "s"),
            ]),
            vars(&[
                ("ARM_CLIENT_ID", CLIENT),
                ("ARM_TENANT_ID", TENANT),
                ("ARM_CLIENT_CERTIFICATE_PATH", "sp.pem"),
            ]),
        ] {
            assert!(
                from_vars("", |name| missing.get(name).cloned()).is_none(),
                "{:?}",
                missing.keys()
            );
        }
    }

    #[test]
    fn a_secret_never_shows_in_debug_and_is_redacted_from_text() {
        let secret = Secret::new("s3cr3t".to_owned());
        assert_eq!(format!("{secret:?}"), "Secret(<redacted>)");
        assert_eq!(
            secret.redact("bad s3cr3t, s3cr3t"),
            "bad <redacted>, <redacted>"
        );
        assert_eq!(Secret::new(String::new()).redact("text"), "text");
    }

    #[test]
    fn prefixes_and_pkcs12() {
        for prefix in ["CI_", "A_", "PROD2_X_"] {
            assert!(is_prefix(prefix), "{prefix}");
        }
        for prefix in ["", "_", "ci_", "CI", "1CI_", "C-I_"] {
            assert!(!is_prefix(prefix), "{prefix}");
        }
        assert!(is_pkcs12(Path::new("/a/sp.PFX")) && is_pkcs12(Path::new("sp.p12")));
        assert!(!is_pkcs12(Path::new("/a/sp.pem")));
    }
}
