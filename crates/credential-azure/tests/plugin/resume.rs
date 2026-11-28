//! A resumed session: after the app restarts, a new plugin process with the
//! block's own stateDir detects from the values its `env` gave before, from
//! the block's own id.

use std::error::Error;
use std::path::Path;

use runbooks_credential_azure::AzurePlugin;
use runbooks_credential_azure::service_principal::{Credential, Secret};
use runbooks_plugin_protocol::credential::ErrorKind;
use runbooks_plugin_transport::PluginError;
use serde_json::{Map, Value, json};

use crate::fake_az::{CLIENT, CONTOSO, Call, FakeAz, PROD, World};
use crate::support::{App, TestResult, at, detect_params, error_kind, host, sign_in_params};

const BLOCK: &str = "azure-auth";

async fn start(az: &FakeAz, state: &Path) -> Result<App, Box<dyn Error>> {
    let mut app = App::start(AzurePlugin::new(host([]), az.clone()))?;
    app.configure(state).await?;
    Ok(app)
}

/// `env`'s values by name, as the engine saves them.
fn saved(env: &Value) -> Result<Map<String, Value>, Box<dyn Error>> {
    let mut values = Map::new();
    for value in env["values"].as_array().ok_or("no values")? {
        let name = value["name"].as_str().ok_or("no name")?;
        values.insert(name.to_owned(), value["value"].clone());
    }
    Ok(values)
}

fn own_values(values: &Map<String, Value>) -> Value {
    detect_params(
        &json!([{"kind": "values", "from": BLOCK, "values": values}]),
        &json!({}),
        &json!([]),
    )
}

/// The browser sign-in's `az` config directory is under stateDir, which the
/// new process keeps.
#[tokio::test]
async fn a_new_process_takes_back_the_blocks_own_login() -> TestResult {
    let state = tempfile::tempdir()?;
    let az = FakeAz::new(World::one_subscription()?);
    let mut app = start(&az, state.path()).await?;
    app.request("signIn", sign_in_params("cli", &json!({}), &json!({})))
        .await?;
    app.receive().await?;
    let response = app.receive().await?;
    let identity = response.get("result").ok_or("signIn failed")?.clone();
    let given = app.result("env", json!({})).await?;
    app.close().await?;

    let mut resumed = start(&az, state.path()).await?;
    let found = resumed
        .result("detect", own_values(&saved(&given)?))
        .await?;
    assert_eq!(at(&found, "/source"), BLOCK);
    for field in ["/principal", "/kind", "/method", "/targets"] {
        assert_eq!(
            at(&found, &format!("/identity{field}")),
            at(&identity, field),
            "{field}"
        );
    }
    let (mut before, mut after) = (
        saved(&given)?,
        saved(&resumed.result("env", json!({})).await?)?,
    );
    for dir in ["AZURE_CONFIG_DIR", "AZURE_EXTENSION_DIR"] {
        before.remove(dir);
        let path = after.remove(dir).ok_or(dir)?;
        let path = path.as_str().ok_or(dir)?;
        assert!(Path::new(path).starts_with(state.path()), "{dir}: {path}");
    }
    assert_eq!(after, before);
    Ok(())
}

#[tokio::test]
async fn another_clouds_values_or_a_changed_secret_are_no_login() -> TestResult {
    let state = tempfile::tempdir()?;
    let az = FakeAz::new(World::service_principal()?);
    let mut app = start(&az, state.path()).await?;
    let aws = Map::from_iter([
        ("AWS_ACCESS_KEY_ID".to_owned(), json!("AKIATESTKEY")),
        (
            "AWS_SECRET_ACCESS_KEY".to_owned(),
            json!("test-secret-access-key"),
        ),
        ("AWS_REGION".to_owned(), json!("eu-west-1")),
    ]);
    assert_eq!(
        app.result("detect", own_values(&aws)).await?,
        json!({"found": false})
    );

    let fields =
        json!({"clientId": CLIENT, "tenantId": CONTOSO, "clientSecret": "test-client-secret"});
    app.result(
        "signIn",
        sign_in_params("service_principal", &fields, &json!({})),
    )
    .await?;
    app.result(
        "select",
        json!({"targets": {"tenant": CONTOSO, "subscription": PROD}}),
    )
    .await?;
    let mut values = saved(&app.result("env", json!({})).await?)?;
    app.close().await?;
    let changed = "test-changed-client-secret";
    for name in ["ARM_CLIENT_SECRET", "AZURE_CLIENT_SECRET"] {
        values.insert(name.to_owned(), json!(changed));
    }

    az.world().login_error = Some(PluginError::new(
        ErrorKind::AccessDenied,
        "az login --service-principal failed: AADSTS7000215: Invalid client secret provided.",
    ));
    let mut resumed = start(&az, state.path()).await?;
    let response = resumed.call("detect", own_values(&values)).await?;
    assert_eq!(error_kind(&response), Some("accessDenied"), "{response}");
    let last_login = az.world().calls.iter().rev().find_map(|call| match call {
        Call::LoginServicePrincipal { credential, .. } => Some(credential.clone()),
        Call::Login { .. } | Call::SetSubscription { .. } | Call::RefreshAccounts { .. } => None,
    });
    assert_eq!(
        last_login,
        Some(Credential::Secret(Secret::new(changed.to_owned()))),
        "az checks the changed secret"
    );
    let env = resumed.call("env", json!({})).await?;
    assert_eq!(error_kind(&env), Some("notSignedIn"), "{env}");
    for line in resumed.close().await? {
        assert!(!line.contains(changed), "{line}");
    }
    Ok(())
}
