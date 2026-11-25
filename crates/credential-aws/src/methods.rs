//! What `configure` answers: the target levels, and the names a run may get.

use runbooks_plugin_protocol::PROTOCOL_VERSION;
use runbooks_plugin_protocol::credential::{
    ConfigureResult, ConfigureResultCloud, Level, LevelChosen,
};

use crate::detect::{AWS_ACCESS_KEY_ID, AWS_REGION, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN};
use crate::identity::{ACCOUNT, ROLE};

/// Every name a run may get, as env and as outputs.
pub const NAMES: [&str; 4] = [
    AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY,
    AWS_SESSION_TOKEN,
    AWS_REGION,
];

/// The answer to `configure`.
pub fn describe() -> ConfigureResult {
    let level = |name: &str, label: &str| Level {
        chosen: LevelChosen::AfterSignIn,
        label: label.to_owned(),
        name: name.to_owned(),
    };
    ConfigureResult {
        cloud: Some(ConfigureResultCloud::Aws),
        driver_version: env!("CARGO_PKG_VERSION").to_owned(),
        levels: vec![level(ACCOUNT, "AWS account"), level(ROLE, "Role")],
        methods: Vec::new(),
        names: NAMES.map(str::to_owned).to_vec(),
        protocol_version: PROTOCOL_VERSION.to_owned(),
        requirements: Vec::new(),
        sources: Vec::new(),
    }
}
