//! What the plugin offers, as `configure` answers it.

use runbooks_plugin_protocol::PROTOCOL_VERSION;
use runbooks_plugin_protocol::credential::{
    ConfigureResult, ConfigureResultCloud, Field, Level, LevelChosen, Method, RequirementKind,
};

use crate::session::SignInMethod;

pub(crate) const TENANT_LEVEL: &str = "tenant";
pub(crate) const SUBSCRIPTION_LEVEL: &str = "subscription";

/// The one detection source the plugin names itself: the person's own `az` login.
pub(crate) const CLI_SOURCE: &str = "cli";

/// The tenant field: optional for an interactive sign-in, required for a
/// service principal.
pub(crate) const TENANT_FIELD: &str = "tenantId";

/// A service principal's fields. It takes a secret or a certificate.
pub(crate) const CLIENT_ID_FIELD: &str = "clientId";
pub(crate) const CLIENT_SECRET_FIELD: &str = "clientSecret";
pub(crate) const CERTIFICATE_FIELD: &str = "clientCertificatePath";

/// Every env and output name the plugin may set. The base environment
/// strips them all, so a value from the app's own environment or an earlier
/// block never leaks into a run that this sign-in does not set it for.
pub(crate) const NAMES: [&str; 19] = [
    "AZURE_CONFIG_DIR",
    "AZURE_EXTENSION_DIR",
    "AZURE_TENANT_ID",
    "AZURE_SUBSCRIPTION_ID",
    "ARM_TENANT_ID",
    "ARM_SUBSCRIPTION_ID",
    "ARM_USE_CLI",
    "ARM_CLIENT_ID",
    "ARM_CLIENT_SECRET",
    "ARM_CLIENT_CERTIFICATE_PATH",
    "AZURE_CLIENT_ID",
    "AZURE_CLIENT_SECRET",
    "AZURE_CLIENT_CERTIFICATE_PATH",
    "AZURE_AUTH_TYPE",
    "AZURE_PRINCIPAL_NAME",
    "AZURE_PRINCIPAL_OBJECT_ID",
    "AZURE_PRINCIPAL_TYPE",
    "AZURE_TENANT_NAME",
    "AZURE_SUBSCRIPTION_NAME",
];

fn field(name: &str, label: &str, required: bool, secret: bool) -> Field {
    Field {
        choices: Vec::new(),
        label: label.to_owned(),
        name: name.to_owned(),
        required,
        secret,
    }
}

fn method(method: SignInMethod) -> Method {
    let (label, fields) = match method {
        SignInMethod::Cli => (
            "Azure CLI",
            vec![field(TENANT_FIELD, "Tenant ID", false, false)],
        ),
        SignInMethod::DeviceCode => (
            "Device Code",
            vec![field(TENANT_FIELD, "Tenant ID", false, false)],
        ),
        SignInMethod::ServicePrincipal => (
            "Service Principal",
            vec![
                field(CLIENT_ID_FIELD, "Client ID", true, false),
                field(TENANT_FIELD, "Tenant ID", true, false),
                field(CLIENT_SECRET_FIELD, "Client Secret", false, true),
                field(
                    CERTIFICATE_FIELD,
                    "Certificate (PEM file path)",
                    false,
                    false,
                ),
            ],
        ),
    };
    Method {
        fields,
        label: label.to_owned(),
        name: method.name().to_owned(),
        one_of: Vec::new(),
    }
}

fn level(name: &str, label: &str) -> Level {
    Level {
        chosen: LevelChosen::AfterSignIn,
        label: label.to_owned(),
        name: name.to_owned(),
    }
}

pub(crate) fn configure_result() -> ConfigureResult {
    ConfigureResult {
        cloud: Some(ConfigureResultCloud::Azure),
        driver_version: env!("CARGO_PKG_VERSION").to_owned(),
        levels: vec![
            level(TENANT_LEVEL, "Tenant"),
            level(SUBSCRIPTION_LEVEL, "Subscription"),
        ],
        methods: SignInMethod::ALL.into_iter().map(method).collect(),
        names: NAMES.iter().map(|name| (*name).to_owned()).collect(),
        protocol_version: PROTOCOL_VERSION.to_owned(),
        requirements: vec![RequirementKind::Roles],
        sources: vec![CLI_SOURCE.to_owned()],
    }
}
