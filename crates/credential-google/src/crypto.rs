//! The cryptography the plugin needs and the approved crates don't provide:
//! RS256 signing, SHA-256, base64url and a secure random source. Every use
//! goes through [`Crypto`], so filling it in later touches this module and
//! `main` only. Until then the binary runs with [`NoCrypto`], and the sign-ins
//! that need it fail with kind `internal`.

use serde::Serialize;

use crate::Secret;

/// The claims of a service account's JWT assertion, which Google's token
/// endpoint exchanges for an access token.
#[derive(Clone, Debug, Serialize)]
pub struct JwtClaims {
    #[serde(rename = "iss")]
    pub issuer: String,
    pub scope: String,
    #[serde(rename = "aud")]
    pub audience: String,
    /// Seconds since the Unix epoch.
    #[serde(rename = "iat")]
    pub issued_at: i64,
    /// Seconds since the Unix epoch.
    #[serde(rename = "exp")]
    pub expires_at: i64,
}

pub trait Crypto: Send + Sync + 'static {
    /// The compact JWS of `claims`: `header.claims.signature`, each part
    /// base64url without padding, signed RS256 with `private_key`, a PKCS #8
    /// RSA key in PEM as Google issues it.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidKey`] if `private_key` is not such a key.
    fn sign_jwt(&self, claims: &JwtClaims, private_key: &Secret) -> Result<Secret, CryptoError>;
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("this build cannot {0} yet: it needs a cryptography crate that has not been approved")]
    Unavailable(&'static str),
    #[error("the private key is not a PKCS #8 RSA key in PEM")]
    InvalidKey,
}

/// The binary's [`Crypto`] until a cryptography crate is approved.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoCrypto;

impl Crypto for NoCrypto {
    fn sign_jwt(&self, _claims: &JwtClaims, _private_key: &Secret) -> Result<Secret, CryptoError> {
        Err(CryptoError::Unavailable(
            "sign a service account key's token request",
        ))
    }
}
