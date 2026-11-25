//! The cryptography the plugin needs: RS256 signing, SHA-256 and a secure
//! random source from rustls' aws-lc-rs provider, base64url from base64, and
//! a constant-time comparison from subtle.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rustls::SignatureScheme;
use rustls::SupportedCipherSuite;
use rustls::crypto::hash::{Hash, HashAlgorithm};
use rustls::crypto::{CryptoProvider, aws_lc_rs};
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::pki_types::pem::PemObject as _;
use serde_json::json;
use subtle::ConstantTimeEq as _;

use crate::Secret;

/// Random bytes in a `state` or a PKCE verifier: 43 characters of base64url.
const RANDOM_BYTES: usize = 32;
const JWT_HEADER: &str = r#"{"alg":"RS256","typ":"JWT"}"#;

/// The claims of a service account's JWT assertion, which Google's token
/// endpoint exchanges for an access token.
#[derive(Clone, Debug)]
pub(crate) struct JwtClaims {
    /// The service account's email.
    pub(crate) issuer: String,
    /// The scopes asked for, separated by spaces.
    pub(crate) scope: String,
    /// The token endpoint.
    pub(crate) audience: String,
    /// Seconds since the Unix epoch.
    pub(crate) issued_at: i64,
    /// Seconds since the Unix epoch.
    pub(crate) expires_at: i64,
}

/// The secrets of one browser sign-in.
#[derive(Clone, Debug)]
pub(crate) struct FlowSecrets {
    /// Sent to Google in the sign-in URL and checked on the way back, so it
    /// is shown to the person; it guards only this one sign-in.
    pub(crate) state: String,
    /// The PKCE code verifier, sent only in the token exchange.
    pub(crate) verifier: Secret,
    /// The verifier's S256 challenge, sent in the sign-in URL.
    pub(crate) challenge: String,
}

/// Why signing or making a sign-in's secrets failed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CryptoError {
    /// The system's cryptography failed at the named step.
    #[error("the system's cryptography could not {0}")]
    Failed(&'static str),
    /// The private key is not a PKCS #8 RSA key in PEM.
    #[error("the private key is not a PKCS #8 RSA key in PEM")]
    InvalidKey,
}

/// The compact JWS of `claims`: `header.claims.signature`, each part
/// base64url without padding, signed RS256 with `private_key`, a PKCS #8
/// RSA key in PEM as Google issues it.
///
/// # Errors
///
/// [`CryptoError::InvalidKey`] if `private_key` is not such a key.
pub(crate) fn sign_jwt(claims: &JwtClaims, private_key: &Secret) -> Result<Secret, CryptoError> {
    // The parse error is dropped: it can quote a line of the key.
    let key = PrivatePkcs8KeyDer::from_pem_slice(private_key.expose().as_bytes())
        .map_err(|_quotes_the_key| CryptoError::InvalidKey)?;
    let signer = aws_lc_rs::default_provider()
        .key_provider
        .load_private_key(key.into())
        .map_err(|_not_a_key| CryptoError::InvalidKey)?
        .choose_scheme(&[SignatureScheme::RSA_PKCS1_SHA256])
        .ok_or(CryptoError::InvalidKey)?;
    let claims = json!({
        "iss": claims.issuer,
        "scope": claims.scope,
        "aud": claims.audience,
        "iat": claims.issued_at,
        "exp": claims.expires_at,
    });
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(JWT_HEADER),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let signature = signer
        .sign(signing_input.as_bytes())
        .map_err(|_sign_failed| CryptoError::Failed("sign the token request"))?;
    Ok(Secret::new(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature)
    )))
}

/// Fresh secrets for one browser sign-in: a random `state` and PKCE code
/// verifier (RFC 7636: 43 to 128 unreserved characters, from at least 32
/// random bytes), and the verifier's S256 challenge, the base64url SHA-256
/// of it without padding.
///
/// # Errors
///
/// [`CryptoError::Failed`] if the random source fails.
pub(crate) fn flow_secrets() -> Result<FlowSecrets, CryptoError> {
    let provider = aws_lc_rs::default_provider();
    let verifier = random_text(&provider)?;
    Ok(FlowSecrets {
        state: random_text(&provider)?,
        challenge: challenge(&provider, &verifier)?,
        verifier: Secret::new(verifier),
    })
}

/// Whether `left` and `right` are equal, taking time that depends on their
/// lengths only, not on where they differ.
pub(crate) fn same(left: &[u8], right: &[u8]) -> bool {
    left.ct_eq(right).into()
}

/// [`RANDOM_BYTES`] from `provider`'s secure random source, in base64url.
fn random_text(provider: &CryptoProvider) -> Result<String, CryptoError> {
    let mut bytes = [0; RANDOM_BYTES];
    provider
        .secure_random
        .fill(&mut bytes)
        .map_err(|_no_randomness| CryptoError::Failed("read a secure random source"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// The S256 challenge of a PKCE `verifier`.
fn challenge(provider: &CryptoProvider, verifier: &str) -> Result<String, CryptoError> {
    let sha256 = provider
        .cipher_suites
        .iter()
        .filter_map(SupportedCipherSuite::tls13)
        .map(|suite| suite.common.hash_provider)
        .find(|hash| hash.algorithm() == HashAlgorithm::SHA256)
        .ok_or(CryptoError::Failed("hash with SHA-256"))?;
    Ok(URL_SAFE_NO_PAD.encode(Hash::hash(sha256, verifier.as_bytes())))
}

#[cfg(test)]
mod tests {
    use rustls::crypto::aws_lc_rs;

    use super::{CryptoError, JwtClaims, challenge, flow_secrets, same, sign_jwt};
    use crate::Secret;

    #[test]
    fn the_rfc_7636_verifier_gives_its_challenge() -> Result<(), CryptoError> {
        // RFC 7636, Appendix B.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            challenge(&aws_lc_rs::default_provider(), verifier)?,
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        Ok(())
    }

    #[test]
    fn each_sign_in_gets_new_unreserved_secrets() -> Result<(), CryptoError> {
        let first = flow_secrets()?;
        let second = flow_secrets()?;
        for secrets in [&first, &second] {
            let verifier = secrets.verifier.expose();
            assert!((43..=128).contains(&verifier.len()), "{verifier}");
            assert!(
                verifier
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-._~".contains(c)),
                "{verifier}"
            );
            assert_eq!(
                secrets.challenge,
                challenge(&aws_lc_rs::default_provider(), verifier)?
            );
            assert_eq!(secrets.state.len(), 43);
        }
        assert_ne!(first.state, second.state);
        assert_ne!(first.verifier, second.verifier);
        assert_ne!(first.state, first.verifier.expose());
        Ok(())
    }

    #[test]
    fn same_compares_whole_values() {
        assert!(same(b"state", b"state"));
        assert!(same(b"", b""));
        assert!(!same(b"state", b"statf"));
        assert!(!same(b"state", b"stat"));
        assert!(!same(b"stat", b"state"));
    }

    #[test]
    fn a_key_that_is_not_pkcs8_rsa_is_invalid_and_never_shown() -> Result<(), String> {
        let claims = JwtClaims {
            issuer: "a@b".to_owned(),
            scope: "s".to_owned(),
            audience: "a".to_owned(),
            issued_at: 0,
            expires_at: 1,
        };
        for key in [
            "SENTINEL-PRIVATE-KEY",
            "-----BEGIN PRIVATE KEY-----\nSENTINEL-PRIVATE-KEY\n-----END PRIVATE KEY-----\n",
            "-----BEGIN PRIVATE KEY-----\nU0VOVElORUwtUFJJVkFURS1LRVk=\n-----END PRIVATE KEY-----\n",
            "-----BEGIN RSA PRIVATE KEY-----\nU0VOVElORUwtUFJJVkFURS1LRVk=\n-----END RSA PRIVATE KEY-----\n",
        ] {
            let Err(error) = sign_jwt(&claims, &Secret::new(key)) else {
                return Err(format!("{key} signed"));
            };
            assert!(matches!(error, CryptoError::InvalidKey), "{key}");
            let shown = format!("{error:?} {error}");
            assert!(!shown.contains("SENTINEL"), "{shown}");
            assert!(!shown.contains("U0VOVElORUw"), "{shown}");
        }
        Ok(())
    }
}
