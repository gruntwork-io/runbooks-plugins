//! Who a Microsoft Entra access token was issued to, read from its claims.
//! The token's signature is not checked: the token came straight from `az`
//! or Entra, and the plugin uses it only to describe the sign-in.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD_INDIFFERENT;
use serde::Deserialize;
use serde_json::Value;

use crate::ids::{ObjectId, TenantId};

/// The signed-in principal, in the tenant the token is for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    /// A user's sign-in name (UPN), or a service principal's client id.
    pub name: String,
    pub object_id: ObjectId,
    pub kind: PrincipalKind,
    pub tenant_id: TenantId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrincipalKind {
    User,
    /// A user signed in to a tenant other than their home tenant.
    Guest,
    ServicePrincipal,
}

impl PrincipalKind {
    /// The value of `AZURE_PRINCIPAL_TYPE`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Guest => "guest",
            Self::ServicePrincipal => "servicePrincipal",
        }
    }
}

#[derive(Deserialize)]
struct Claims {
    oid: Option<String>,
    tid: Option<String>,
    upn: Option<String>,
    unique_name: Option<String>,
    preferred_username: Option<String>,
    idtyp: Option<String>,
    appid: Option<String>,
    azp: Option<String>,
    idp: Option<String>,
    /// 1 for a guest. Entra sends a number; some tokens carry a string.
    acct: Option<Value>,
}

/// The principal a JWT's payload names, or `None` if it is not a JWT or
/// names no object id and tenant.
///
/// The payload is base64url, read with or without padding.
pub fn principal_of_token(token: &str) -> Option<Principal> {
    let payload = token.split('.').nth(1)?;
    let payload = URL_SAFE_NO_PAD_INDIFFERENT.decode(payload).ok()?;
    let claims: Claims = serde_json::from_slice(&payload).ok()?;
    principal_of_claims(claims)
}

fn principal_of_claims(claims: Claims) -> Option<Principal> {
    let present = |value: Option<String>| value.filter(|v| !v.is_empty());
    let object_id = ObjectId::parse(&present(claims.oid)?)?;
    let tenant_id = TenantId::parse(&present(claims.tid)?)?;
    let user_name = present(claims.upn)
        .or(present(claims.unique_name))
        .or(present(claims.preferred_username));

    let user_name = match user_name {
        Some(name) if claims.idtyp.as_deref() != Some("app") => name,
        _ => {
            let name = present(claims.appid)
                .or(present(claims.azp))
                .unwrap_or_else(|| object_id.to_string());
            return Some(Principal {
                name,
                object_id,
                kind: PrincipalKind::ServicePrincipal,
                tenant_id,
            });
        }
    };

    // A guest's identity provider is its home tenant's issuer, not this one.
    let idp = present(claims.idp);
    let from_other_tenant = idp
        .as_deref()
        .is_some_and(|idp| tenant_of_issuer(idp) != Some(tenant_id.clone()));
    let guest = from_other_tenant
        || user_name.to_ascii_lowercase().contains("#ext#@")
        || matches!(&claims.acct, Some(Value::Number(n)) if n.as_u64() == Some(1))
        || matches!(&claims.acct, Some(Value::String(s)) if s == "1");
    Some(Principal {
        name: user_name,
        object_id,
        kind: if guest {
            PrincipalKind::Guest
        } else {
            PrincipalKind::User
        },
        tenant_id,
    })
}

/// The tenant of an Entra issuer URL: `https://sts.windows.net/<tenant>/`.
fn tenant_of_issuer(issuer: &str) -> Option<TenantId> {
    let rest = issuer
        .strip_prefix("https://sts.windows.net/")
        .or_else(|| issuer.strip_prefix("https://login.microsoftonline.com/"))?;
    TenantId::parse(rest.split('/').next()?)
}

#[cfg(test)]
pub(crate) mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
    use serde_json::{Value, json};

    use super::{PrincipalKind, principal_of_token};

    pub(crate) const TENANT: &str = "72f988bf-86f1-41af-91ab-2d7cd011db47";
    const OTHER_TENANT: &str = "f8cdef31-a31e-4b4a-93e4-5f571e91255a";
    const OID: &str = "00000000-0000-0000-0000-0000000000a1";

    /// A JWT with `payload` as its payload and no real signature.
    fn jwt(payload: &str) -> String {
        format!(
            "{}.{payload}.sig",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#)
        )
    }

    /// A JWT with `claims` as its payload and no real signature.
    pub(crate) fn token(claims: &Value) -> String {
        jwt(&URL_SAFE_NO_PAD.encode(claims.to_string()))
    }

    #[test]
    fn a_member_is_a_user_named_by_upn() {
        let principal = principal_of_token(&token(&json!({
            "oid": OID, "tid": TENANT, "upn": "ana@contoso.com",
            "idp": format!("https://sts.windows.net/{TENANT}/"), "acct": 0
        })));
        let principal = principal.as_ref();
        assert_eq!(principal.map(|p| p.kind), Some(PrincipalKind::User));
        assert_eq!(principal.map(|p| p.name.as_str()), Some("ana@contoso.com"));
        assert_eq!(principal.map(|p| p.tenant_id.as_str()), Some(TENANT));
    }

    #[test]
    fn a_guest_is_told_by_its_issuer_its_name_or_acct() {
        for claims in [
            json!({"oid": OID, "tid": TENANT, "unique_name": "ana@fabrikam.com",
                   "idp": format!("https://sts.windows.net/{OTHER_TENANT}/")}),
            json!({"oid": OID, "tid": TENANT, "upn": "ana_fabrikam.com#EXT#@contoso.onmicrosoft.com"}),
            json!({"oid": OID, "tid": TENANT, "upn": "ana@fabrikam.com", "acct": 1}),
            json!({"oid": OID, "tid": TENANT, "upn": "ana@fabrikam.com", "idp": "live.com"}),
        ] {
            let principal = principal_of_token(&token(&claims));
            assert_eq!(
                principal.map(|p| p.kind),
                Some(PrincipalKind::Guest),
                "{claims}"
            );
        }
    }

    #[test]
    fn an_app_token_is_a_service_principal_named_by_its_client_id() {
        let principal = principal_of_token(&token(&json!({
            "oid": OID, "tid": TENANT, "idtyp": "app",
            "appid": "11111111-2222-3333-4444-555555555555"
        })));
        assert_eq!(
            principal.as_ref().map(|p| p.kind),
            Some(PrincipalKind::ServicePrincipal)
        );
        assert_eq!(
            principal.map(|p| p.name),
            Some("11111111-2222-3333-4444-555555555555".to_owned())
        );
    }

    #[test]
    fn a_token_without_an_object_id_or_tenant_names_nobody() {
        for text in [
            token(&json!({"tid": TENANT, "upn": "ana@contoso.com"})),
            token(&json!({"oid": OID, "upn": "ana@contoso.com"})),
            token(&json!({"oid": "not-a-guid", "tid": TENANT})),
            "not-a-jwt".to_owned(),
            "a.!!!.c".to_owned(),
        ] {
            assert_eq!(principal_of_token(&text), None, "{text}");
        }
    }

    /// A JWT leaves base64url's padding off, but a padded payload is read
    /// too.
    #[test]
    fn a_padded_payload_is_read_too() {
        let claims = json!({"oid": OID, "tid": TENANT, "upn": "ana@contoso.com"});
        let payload = URL_SAFE.encode(claims.to_string());
        assert!(payload.ends_with('='), "{payload} has no padding");
        let principal = principal_of_token(&jwt(&payload));
        assert_eq!(
            principal.map(|p| p.name),
            Some("ana@contoso.com".to_owned())
        );
    }
}
