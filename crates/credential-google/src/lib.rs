//! `runbooks-credential-google`: the Runbooks credential plugin for Google
//! Cloud. It ports the app's GoogleAuth block: a service account key or any
//! Google credentials document, detection from the environment and an earlier
//! block's outputs, the project picker, and the variables a run gets.
//!
//! [`GooglePlugin`] implements the transport's
//! [`CredentialPlugin`](runbooks_plugin_transport::CredentialPlugin). Its
//! network is a [`GoogleApi`] and its cryptography a [`Crypto`], so tests run
//! it with fakes.

mod api;
mod credential;
mod crypto;
mod files;
mod gcloud;
mod plugin;
mod secret;
mod session;
mod sources;

pub use api::{
    ApiError, GoogleApi, HttpApi, MAX_RESPONSE_BYTES, Network, NetworkError, OAuthError, Project,
    ProjectPage, TIMEOUT, TOKEN_URL, Token, TokenInfo, TokenRequest,
};
pub use crypto::{Crypto, CryptoError, JwtClaims, NoCrypto};
pub use plugin::{Connect, GooglePlugin, Host, MAX_PROJECTS};
pub use secret::Secret;
