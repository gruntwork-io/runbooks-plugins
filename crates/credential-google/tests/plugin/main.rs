//! Drives the plugin as the app would, over in-memory pipes against a fake
//! Google, and checks every line it writes against the protocol schema.

mod detect;
mod gcloud;
mod oauth;
mod secrets;
mod sign_in;
mod support;
mod targets;
