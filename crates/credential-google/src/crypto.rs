//! The cryptography the plugin needs and the approved crates don't provide:
//! RS256 signing, SHA-256, base64url, a secure random source and a
//! constant-time comparison. Every use
//! goes through [`Crypto`], so filling it in later touches this module and
//! `main` only. Until then the binary runs with [`NoCrypto`], and the sign-ins
//! that need it fail with kind `internal`.

use serde::Serialize;

use crate::Secret;

/// The claims of a service account's JWT assertion, which Google's token
/// endpoint exchanges for an access token.
#[derive(Clone, Debug, Serialize)]
pub struct JwtClaims {
    /// The service account's email.
    #[serde(rename = "iss")]
    pub issuer: String,
    /// The scopes asked for, separated by spaces.
    pub scope: String,
    /// The token endpoint.
    #[serde(rename = "aud")]
    pub audience: String,
    /// Seconds since the Unix epoch.
    #[serde(rename = "iat")]
    pub issued_at: i64,
    /// Seconds since the Unix epoch.
    #[serde(rename = "exp")]
    pub expires_at: i64,
}

/// The signing the plugin does.
pub trait Crypto: Send + Sync + 'static {
    /// The compact JWS of `claims`: `header.claims.signature`, each part
    /// base64url without padding, signed RS256 with `private_key`, a PKCS #8
    /// RSA key in PEM as Google issues it.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidKey`] if `private_key` is not such a key.
    fn sign_jwt(&self, claims: &JwtClaims, private_key: &Secret) -> Result<Secret, CryptoError>;

    /// Fresh secrets for one browser sign-in: a random `state` and PKCE code
    /// verifier (RFC 7636: 43 to 128 unreserved characters, from at least
    /// 32 random bytes), and the verifier's S256 challenge, the base64url
    /// SHA-256 of it without padding.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Unavailable`] if there is no secure random source.
    fn flow_secrets(&self) -> Result<FlowSecrets, CryptoError>;

    /// Whether `left` and `right` are equal, taking time that depends on
    /// their lengths only, not on where they differ.
    fn same(&self, left: &[u8], right: &[u8]) -> bool;
}

/// The secrets of one browser sign-in.
#[derive(Clone, Debug)]
pub struct FlowSecrets {
    /// Sent to Google in the sign-in URL and checked on the way back, so it
    /// is shown to the person; it guards only this one sign-in.
    pub state: String,
    pub verifier: Secret,
    pub challenge: String,
}

/// Why a [`Crypto`] call failed.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// This build cannot do the named operation.
    #[error("this build cannot {0} yet: it needs a cryptography crate that has not been approved")]
    Unavailable(&'static str),
    /// The private key is not a PKCS #8 RSA key in PEM.
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

    fn flow_secrets(&self) -> Result<FlowSecrets, CryptoError> {
        Err(CryptoError::Unavailable("start a browser sign-in"))
    }

    /// Never reached: without `flow_secrets` no sign-in starts.
    fn same(&self, _left: &[u8], _right: &[u8]) -> bool {
        false
    }
}
