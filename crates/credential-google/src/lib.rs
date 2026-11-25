//! `runbooks-credential-google`: the Runbooks credential plugin for Google
//! Cloud, ported from the app's GoogleAuth block.
//!
//! The plugin reaches Google only through [`GoogleApi`], whose real
//! implementation is [`HttpApi`], and signs only through [`Crypto`], so its
//! tests run against fakes of both.

mod api;
mod crypto;
mod secret;

pub use api::{
    ApiError, GoogleApi, HttpApi, MAX_RESPONSE_BYTES, Network, NetworkError, OAuthError, Project,
    ProjectPage, TIMEOUT, TOKEN_URL, Token, TokenInfo, TokenRequest,
};
pub use crypto::{Crypto, CryptoError, JwtClaims, NoCrypto};
pub use secret::Secret;
