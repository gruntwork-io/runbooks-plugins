//! The plugin as the app sees it: requests over in-memory pipes, every line
//! it writes checked against the protocol schema. `protocol` runs it on a
//! fake [`Az`](runbooks_credential_azure::az::Az); `real_az` runs it on the
//! real adapter, with a script standing in for `az`.

mod fake_az;
mod protocol;
mod real_az;
#[path = "../common/scripted_az.rs"]
mod scripted_az;
mod service_principal;
mod support;
