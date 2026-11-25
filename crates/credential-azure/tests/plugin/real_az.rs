//! The plugin on the real adapter, as `main` builds it, on every OS CI
//! runs, with no Azure CLI installed: a missing `az`, and a script in its
//! place.

use std::error::Error;
use std::path::Path;

use runbooks_credential_azure::host::LocalLogin;
use runbooks_credential_azure::{AzurePlugin, InstalledAz};
use serde_json::json;

use crate::fake_az::{CONTOSO, PROD};
use crate::scripted_az::{DEVICE_LINE, ScriptedAz, token};
use crate::support::{
    App, TestResult, assert_valid, env_value, error_kind, sign_in_dirs, sign_in_params,
};

fn installed(scripted: &ScriptedAz) -> InstalledAz {
    InstalledAz::new(Some(scripted.program()), scripted.env())
}

async fn start(az: InstalledAz, state: &Path) -> Result<App, Box<dyn Error>> {
    let mut app = App::start(AzurePlugin::new(LocalLogin::default(), az))?;
    app.configure(state).await?;
    Ok(app)
}

#[tokio::test]
async fn with_no_az_on_path_a_sign_in_is_tool_missing() -> TestResult {
    let state = tempfile::tempdir()?;
    let missing = state.path().join("not-there").join("az");
    for az in [
        InstalledAz::new(None, Vec::new()),
        InstalledAz::new(Some(missing), Vec::new()),
    ] {
        let mut app = start(az, state.path()).await?;
        let response = app
            .call(
                "signIn",
                sign_in_params("device_code", json!({}), json!({})),
            )
            .await?;
        assert_eq!(error_kind(&response), Some("toolMissing"), "{response}");
        assert_valid("toolMissingData", &response["error"]["data"])?;
        assert_eq!(response["error"]["data"]["tool"], "az");
        let message = response["error"]["message"].as_str().unwrap_or_default();
        assert!(message.contains("Install it from https://"), "{message}");
        assert!(sign_in_dirs(state.path())?.is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn signs_in_through_the_az_on_path_with_the_blocks_own_config_dir() -> TestResult {
    let (scripted, state) = (ScriptedAz::new()?, tempfile::tempdir()?);
    scripted.respond("login.err", &format!("{DEVICE_LINE}\n"))?;
    scripted.respond(
        "account-get-access-token.out",
        &json!({"accessToken": token(), "tokenType": "Bearer"}).to_string(),
    )?;
    scripted.respond(
        "account-list.out",
        &json!([{"id": PROD, "name": "Prod", "tenantId": CONTOSO, "state": "Enabled", "isDefault": true}]).to_string(),
    )?;
    scripted.respond(
        "rest.out",
        &json!({"value": [{"tenantId": CONTOSO, "displayName": "Contoso"}]}).to_string(),
    )?;
    let mut app = start(installed(&scripted), state.path()).await?;

    let id = app
        .request(
            "signIn",
            sign_in_params("device_code", json!({}), json!({})),
        )
        .await?;
    let prompt = app.receive().await?;
    assert_eq!(
        prompt["params"],
        json!({"request": id, "kind": "openUrl", "url": "https://microsoft.com/devicelogin", "code": "SCRIPTED1"})
    );
    let response = app.receive().await?;
    assert_eq!(
        response["result"]["principal"], "ana@contoso.com",
        "{response}"
    );
    assert_eq!(response["result"]["targets"]["subscription"]["id"], PROD);
    let env = app.result("env", json!({})).await?;
    let config = env_value(&env, "AZURE_CONFIG_DIR")
        .ok_or("no AZURE_CONFIG_DIR")?
        .to_owned();
    assert!(Path::new(&config).starts_with(state.path()), "{config}");

    let calls = scripted.calls()?;
    assert!(calls.len() >= 4, "{calls:?}");
    for call in &calls {
        assert_eq!(call.config_dir, config, "{call:?}");
        assert_eq!(call.only_show_errors, "true", "{call:?}");
        assert!(call.args.contains("--only-show-errors"), "{call:?}");
        assert_eq!(
            call.extension_dir, "",
            "a fresh sign-in keeps az's own extensions: {call:?}"
        );
    }
    let args: Vec<&str> = calls.iter().map(|call| call.args.as_str()).collect();
    assert!(
        args.first()
            .is_some_and(|a| a.starts_with("login") && a.contains("--use-device-code")),
        "{args:?}"
    );
    assert!(
        args.iter()
            .any(|a| a.starts_with("account set --subscription") && a.contains(PROD)),
        "{args:?}"
    );

    let written = app.close().await?;
    assert!(
        written
            .iter()
            .all(|line| !line.contains("SECRET-SIGNATURE")),
        "the token reached the app: {written:?}"
    );
    Ok(())
}

#[tokio::test]
async fn a_failing_az_answers_with_its_error_line_and_kind() -> TestResult {
    let (scripted, state) = (ScriptedAz::new()?, tempfile::tempdir()?);
    scripted.respond("login.fail", "")?;
    scripted.respond(
        "login.err",
        "WARNING: Retrieving tenants and subscriptions.\nERROR: AADSTS50076: Due to a configuration change made by your administrator, you must use multi-factor authentication.\n",
    )?;
    let mut app = start(installed(&scripted), state.path()).await?;
    let response = app
        .call(
            "signIn",
            sign_in_params("device_code", json!({}), json!({})),
        )
        .await?;
    assert_eq!(error_kind(&response), Some("accessDenied"), "{response}");
    let message = response["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.starts_with("az login failed: AADSTS50076"),
        "{message}"
    );
    assert!(sign_in_dirs(state.path())?.is_empty());
    Ok(())
}
