//! The plugin on the real adapter, as `main` builds it, on every OS CI
//! runs, with no Azure CLI installed: a missing `az`, and a script in its
//! place.

use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::iter;
use std::path::Path;
use std::process::Stdio;

use runbooks_credential_azure::host::Host;
use runbooks_credential_azure::process_tree::Killer;
use runbooks_credential_azure::{AzurePlugin, InstalledAz};
use runbooks_plugin_protocol::PROTOCOL_VERSION;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdout, Command};
use tokio::time::timeout;

use crate::fake_az::{CLIENT, CONTOSO, PROD};
use crate::hanging_az::{self, HangingAz};
use crate::scripted_az::{self, DEVICE_LINE, ScriptedAz, token};
use crate::support::{
    App, TestResult, WAIT, assert_valid, at, detect_params, env_value, error_kind, error_message,
    runbooks_limits, sign_in_dirs, sign_in_params,
};

fn installed(scripted: &ScriptedAz) -> InstalledAz {
    InstalledAz::new(
        Some(scripted.program()),
        scripted.env(),
        scripted_az::killer(),
    )
}

async fn start(az: InstalledAz, state: &Path) -> Result<App, Box<dyn Error>> {
    let mut app = App::start(AzurePlugin::new(Host::new([], cfg!(windows)), az))?;
    app.configure(state).await?;
    Ok(app)
}

/// Starts the binary as the app does, with `env` and the script `program`
/// first on `PATH`.
fn spawn_binary(program: &Path, env: Vec<(OsString, OsString)>) -> Result<Child, Box<dyn Error>> {
    let dir = program.parent().ok_or("the script has no directory")?;
    let path = env::var_os("PATH").unwrap_or_default();
    let path = env::join_paths(iter::once(dir.to_owned()).chain(env::split_paths(&path)))?;
    Ok(
        Command::new(env!("CARGO_BIN_EXE_runbooks-credential-azure"))
            .env_clear()
            .envs(env)
            .env("PATH", path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?,
    )
}

/// The binary's answer to request `id`, past any notifications.
async fn answer(
    output: &mut Lines<BufReader<ChildStdout>>,
    id: i64,
) -> Result<Value, Box<dyn Error>> {
    loop {
        let line = timeout(WAIT, output.next_line())
            .await??
            .ok_or("the plugin's output ended")?;
        let message: Value = serde_json::from_str(&line)?;
        if at(&message, "/id") == id {
            return Ok(message);
        }
    }
}

/// Sends request `id` to the binary and returns its answer.
async fn ask(
    plugin: &mut Child,
    output: &mut Lines<BufReader<ChildStdout>>,
    (id, method, params): (i64, &str, Value),
) -> Result<Value, Box<dyn Error>> {
    let request = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
    let input = plugin
        .stdin
        .as_mut()
        .ok_or("the plugin's input is closed")?;
    input.write_all(format!("{request}\n").as_bytes()).await?;
    answer(output, id).await
}

#[tokio::test]
async fn the_binary_logs_a_tenant_list_az_refuses_and_signs_in_without_it() -> TestResult {
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
    scripted.respond("rest.fail", "")?;
    scripted.respond(
        "rest.err",
        "ERROR: Insufficient privileges to complete the operation.\n",
    )?;
    let mut plugin = spawn_binary(&scripted.program(), scripted.env())?;
    let mut output =
        BufReader::new(plugin.stdout.take().ok_or("the plugin has no output")?).lines();
    let state_dir = state
        .path()
        .to_str()
        .ok_or("the state directory is not UTF-8")?;

    let configured = ask(
        &mut plugin,
        &mut output,
        (
            1,
            "configure",
            json!({"protocolVersion": PROTOCOL_VERSION, "caller": "runbooks/0.31.0", "stateDir": state_dir, "callTimeoutsMillis": runbooks_limits()}),
        ),
    )
    .await?;
    assert_eq!(at(&configured, "/error"), Value::Null, "{configured}");
    let signed_in = ask(
        &mut plugin,
        &mut output,
        (
            2,
            "signIn",
            sign_in_params("device_code", &json!({}), &json!({})),
        ),
    )
    .await?;
    assert_eq!(
        at(&signed_in, "/result/targets/tenant/id"),
        CONTOSO,
        "{signed_in}"
    );

    drop(plugin.stdin.take());
    let ended = timeout(WAIT, plugin.wait_with_output()).await??;
    assert!(ended.status.success(), "{:?}", ended.status);
    let log = String::from_utf8(ended.stderr)?;
    assert!(
        log.contains(
            "signing in without Azure's tenant list: internal: az rest /tenants failed: Insufficient privileges to complete the operation."
        ),
        "{log}"
    );
    Ok(())
}

/// The app cancels a sign-in by closing the plugin's input, and the plugin
/// exits.
#[tokio::test]
async fn closing_the_input_during_a_sign_in_ends_az_and_what_it_started() -> TestResult {
    let (hanging, state) = (HangingAz::new()?, tempfile::tempdir()?);
    let mut plugin = spawn_binary(&hanging.program(), hanging.env())?;
    let mut output =
        BufReader::new(plugin.stdout.take().ok_or("the plugin has no output")?).lines();
    let state_dir = state
        .path()
        .to_str()
        .ok_or("the state directory is not UTF-8")?;
    let configured = ask(
        &mut plugin,
        &mut output,
        (
            1,
            "configure",
            json!({"protocolVersion": PROTOCOL_VERSION, "caller": "runbooks/0.31.0", "stateDir": state_dir, "callTimeoutsMillis": runbooks_limits()}),
        ),
    )
    .await?;
    assert_eq!(at(&configured, "/error"), Value::Null, "{configured}");
    let request = json!({"jsonrpc": "2.0", "id": 2, "method": "signIn", "params": sign_in_params("cli", &json!({}), &json!({}))});
    plugin
        .stdin
        .as_mut()
        .ok_or("the plugin's input is closed")?
        .write_all(format!("{request}\n").as_bytes())
        .await?;
    let pids = hanging.started().await?;

    drop(plugin.stdin.take());
    let ended = timeout(WAIT, plugin.wait()).await??;
    assert!(ended.success(), "{ended:?}");
    let running = HangingAz::still_running(&pids).await;
    assert!(
        running.is_empty(),
        "{running:?} of {pids:?} outlived the plugin by {:?}",
        hanging_az::GONE
    );
    Ok(())
}

#[tokio::test]
async fn with_no_az_on_path_a_sign_in_is_tool_missing() -> TestResult {
    let state = tempfile::tempdir()?;
    let missing = state.path().join("not-there").join("az");
    for az in [
        InstalledAz::new(None, Vec::new(), Killer::ChildOnly),
        InstalledAz::new(Some(missing), Vec::new(), Killer::ChildOnly),
    ] {
        let mut app = start(az, state.path()).await?;
        let response = app
            .call(
                "signIn",
                sign_in_params("device_code", &json!({}), &json!({})),
            )
            .await?;
        assert_eq!(error_kind(&response), Some("toolMissing"), "{response}");
        assert_valid("toolMissingData", &at(&response, "/error/data"))?;
        assert_eq!(at(&response, "/error/data/tool"), "az");
        let message = error_message(&response).unwrap_or_default();
        assert!(message.contains("Install it from https://"), "{message}");
        assert_eq!(sign_in_dirs(state.path())?, Vec::<String>::new());
    }
    Ok(())
}

/// Each method's `unavailable` in `configure`'s answer, or null.
async fn unavailable(az: InstalledAz, state: &Path) -> Result<Vec<Value>, Box<dyn Error>> {
    let mut app = App::start(AzurePlugin::new(Host::new([], cfg!(windows)), az))?;
    let configured = app.configure(state).await?;
    Ok(configured
        .pointer("/methods")
        .and_then(Value::as_array)
        .ok_or("methods")?
        .iter()
        .map(|method| at(method, "/unavailable"))
        .collect())
}

/// Every method signs in through `az`, a service principal too.
#[tokio::test]
async fn with_no_az_on_path_configure_lists_every_method_as_unavailable() -> TestResult {
    let (scripted, state) = (ScriptedAz::new()?, tempfile::tempdir()?);
    let without = unavailable(
        InstalledAz::new(None, Vec::new(), Killer::ChildOnly),
        state.path(),
    )
    .await?;
    assert_eq!(without.len(), 3);
    for why in &without {
        assert_eq!(at(why, "/kind"), "toolMissing", "{why}");
        let message = at(why, "/message");
        assert!(
            message.as_str().is_some_and(|message| message.contains(
                "Install it from https://learn.microsoft.com/cli/azure/install-azure-cli"
            )),
            "{message}"
        );
    }
    assert_eq!(
        unavailable(installed(&scripted), state.path()).await?,
        vec![Value::Null; 3]
    );
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
            sign_in_params("device_code", &json!({}), &json!({})),
        )
        .await?;
    let prompt = app.receive().await?;
    assert_eq!(
        at(&prompt, "/params"),
        json!({"request": id, "kind": "openUrl", "url": "https://microsoft.com/devicelogin", "code": "SCRIPTED1"})
    );
    let response = app.receive().await?;
    assert_eq!(
        at(&response, "/result/principal"),
        "ana@contoso.com",
        "{response}"
    );
    assert_eq!(at(&response, "/result/targets/subscription/id"), PROD);
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
        args.contains(&"account list --all -o json --only-show-errors"),
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

/// The copy lists the subscriptions az saw at the person's last az login,
/// so detect fetches them again, as the app does. A sign-in's own list is
/// fresh.
#[tokio::test]
async fn detect_fetches_the_subscriptions_of_the_persons_login_again() -> TestResult {
    let (scripted, state, local) = (
        ScriptedAz::new()?,
        tempfile::tempdir()?,
        tempfile::tempdir()?,
    );
    fs::write(local.path().join("azureProfile.json"), "{}")?;
    scripted.respond(
        "account-get-access-token.out",
        &json!({"accessToken": token()}).to_string(),
    )?;
    scripted.respond(
        "account-list.out",
        &json!([{"id": PROD, "name": "Prod", "tenantId": CONTOSO, "state": "Enabled"}]).to_string(),
    )?;
    let host = Host::new(
        [(
            "AZURE_CONFIG_DIR".into(),
            local.path().as_os_str().to_owned(),
        )],
        cfg!(windows),
    );
    let mut app = App::start(AzurePlugin::new(host, installed(&scripted)))?;
    app.configure(state.path()).await?;
    let cli = detect_params(
        &json!([{"kind": "named", "name": "cli"}]),
        &json!({}),
        &json!([]),
    );
    let detected = app.result("detect", cli).await?;
    assert_eq!(at(&detected, "/found"), true, "{detected}");
    let listed: Vec<String> = scripted
        .calls()?
        .into_iter()
        .map(|call| call.args)
        .filter(|args| args.starts_with("account list"))
        .collect();
    assert_eq!(
        listed,
        ["account list --all --refresh -o json --only-show-errors"]
    );
    Ok(())
}

/// A local login az says is signed out or expired is not found, and its
/// copy is gone.
#[tokio::test]
async fn a_local_login_az_cannot_use_is_not_found() -> TestResult {
    let (scripted, state, local) = (
        ScriptedAz::new()?,
        tempfile::tempdir()?,
        tempfile::tempdir()?,
    );
    fs::write(local.path().join("azureProfile.json"), "{}")?;
    scripted.respond("account-get-access-token.fail", "")?;
    let host = Host::new(
        [(
            "AZURE_CONFIG_DIR".into(),
            local.path().as_os_str().to_owned(),
        )],
        cfg!(windows),
    );
    let mut app = App::start(AzurePlugin::new(host, installed(&scripted)))?;
    app.configure(state.path()).await?;
    let cli = detect_params(
        &json!([{"kind": "named", "name": "cli"}]),
        &json!({}),
        &json!([]),
    );
    for error in [
        "ERROR: Please run 'az login' to setup account.",
        "ERROR: AADSTS700082: The refresh token has expired due to inactivity.",
    ] {
        scripted.respond("account-get-access-token.err", &format!("{error}\n"))?;
        let detected = app.result("detect", cli.clone()).await?;
        assert_eq!(at(&detected, "/found"), false, "{error}: {detected}");
        assert_eq!(sign_in_dirs(state.path())?, Vec::<String>::new());
    }
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
            sign_in_params("device_code", &json!({}), &json!({})),
        )
        .await?;
    assert_eq!(error_kind(&response), Some("accessDenied"), "{response}");
    let message = error_message(&response).unwrap_or_default();
    assert!(
        message.starts_with("az login failed: AADSTS50076"),
        "{message}"
    );
    assert_eq!(sign_in_dirs(state.path())?, Vec::<String>::new());
    Ok(())
}

#[tokio::test]
async fn a_service_principal_secret_goes_to_az_on_stdin_and_back_only_in_env() -> TestResult {
    // Letters and digits only, so the Windows script can echo it.
    const SECRET: &str = "Sp7SecretValue9";
    let (scripted, state) = (ScriptedAz::new()?, tempfile::tempdir()?);
    scripted.respond(
        "account-get-access-token.out",
        &json!({"accessToken": token()}).to_string(),
    )?;
    scripted.respond(
        "account-list.out",
        &json!([{"id": PROD, "name": "Prod", "tenantId": CONTOSO, "state": "Enabled"}]).to_string(),
    )?;
    let mut app = start(installed(&scripted), state.path()).await?;
    let fields = json!({"clientId": CLIENT, "tenantId": CONTOSO, "clientSecret": SECRET});
    let identity = app
        .result(
            "signIn",
            sign_in_params("service_principal", &fields, &json!({})),
        )
        .await?;
    assert_eq!(
        at(&identity, "/targets/subscription/id"),
        PROD,
        "{identity}"
    );
    assert_eq!(scripted.stdin()?, SECRET);
    for call in scripted.calls()? {
        assert!(!call.args.contains(SECRET), "{call:?}");
    }
    let env = app.result("env", json!({})).await?;
    assert_eq!(env_value(&env, "ARM_CLIENT_SECRET"), Some(SECRET));

    let written = app.close().await?;
    let carrying: Vec<&String> = written
        .iter()
        .filter(|line| line.contains(SECRET))
        .collect();
    assert_eq!(carrying.len(), 1, "only env's result: {carrying:?}");
    assert!(
        carrying.iter().all(|line| line.contains("\"values\"")),
        "{carrying:?}"
    );
    Ok(())
}
