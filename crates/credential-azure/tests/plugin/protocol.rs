//! The protocol's methods, run on the fake `az`.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use runbooks_credential_azure::AzurePlugin;
use runbooks_credential_azure::az::Interactive;
use runbooks_credential_azure::host::Host;
use runbooks_plugin_protocol::credential::{ConfigureResult, ErrorKind};
use serde_json::{Value, json};
use tempfile::TempDir;

use crate::fake_az::{
    CONTOSO, Call, DEV, DEVICE_CODE, DEVICE_URL, FABRIKAM, FakeAz, PROD, SHARED, World,
};
use crate::support::{
    App, TestResult, assert_valid, at, detect_params, env_value, error_kind, error_message,
    runbooks_limits, sign_in_dirs, sign_in_params,
};

struct Fixture {
    app: App,
    az: FakeAz,
    state: TempDir,
    /// The person's home directory, with `.azure` in it once they log in.
    home: TempDir,
}

impl Fixture {
    async fn new(world: World) -> Result<Self, Box<dyn Error>> {
        Self::with_env(world, &[]).await
    }

    /// The plugin started with `vars` in its environment, beside the
    /// person's own `az` config directory.
    async fn with_env(world: World, vars: &[(&str, &str)]) -> Result<Self, Box<dyn Error>> {
        let (state, home) = (tempfile::tempdir()?, tempfile::tempdir()?);
        let mut env = vec![(
            "AZURE_CONFIG_DIR".into(),
            home.path().join(".azure").into_os_string(),
        )];
        env.extend(
            vars.iter()
                .map(|(name, value)| ((*name).into(), (*value).into())),
        );
        let az = FakeAz::new(world);
        let host = Host::new(env, cfg!(windows));
        let mut app = App::start(AzurePlugin::new(host, az.clone()))?;
        app.configure(state.path()).await?;
        Ok(Self {
            app,
            az,
            state,
            home,
        })
    }

    fn local_dir(&self) -> PathBuf {
        self.home.path().join(".azure")
    }

    /// The person runs `az login` on their own.
    fn log_in_locally(&self) -> TestResult {
        let dir = self.local_dir();
        fs::create_dir_all(dir.join("cliextensions"))?;
        fs::write(dir.join("azureProfile.json"), "{}")?;
        fs::write(dir.join("msal_token_cache.json"), "the person's tokens")?;
        Ok(())
    }

    /// `az login` on a machine with no extensions: no `cliextensions`.
    fn log_in_locally_without_extensions(&self) -> TestResult {
        let dir = self.local_dir();
        fs::create_dir_all(&dir)?;
        fs::write(dir.join("azureProfile.json"), "{}")?;
        Ok(())
    }

    fn calls(&self) -> Vec<Call> {
        self.az.world().calls.clone()
    }

    async fn env(&mut self) -> Result<Value, Box<dyn Error>> {
        let env = self.app.result("env", json!({})).await?;
        assert_valid("envResult", &env)?;
        Ok(env)
    }
}

fn cli_detect() -> Value {
    detect_params(
        &json!([{"kind": "named", "name": "cli"}]),
        &json!({}),
        &json!([]),
    )
}

fn is_under(path: Option<&str>, dir: &Path) -> bool {
    path.is_some_and(|path| Path::new(path).starts_with(dir))
}

#[tokio::test]
async fn configure_offers_the_methods_levels_and_every_name() -> TestResult {
    let state = tempfile::tempdir()?;
    let mut app = App::start(AzurePlugin::new(
        Host::new([], cfg!(windows)),
        FakeAz::new(World::one_subscription()?),
    ))?;
    let result = app.configure(state.path()).await?;
    let methods: Vec<&Value> = result
        .pointer("/methods")
        .and_then(Value::as_array)
        .ok_or("methods")?
        .iter()
        .map(|m| &m["name"])
        .collect();
    assert_eq!(methods, ["cli", "device_code", "service_principal"]);
    let secret_fields: Vec<&Value> = result
        .pointer("/methods/2/fields")
        .and_then(Value::as_array)
        .ok_or("fields")?
        .iter()
        .filter(|field| field["secret"] == true)
        .map(|field| &field["name"])
        .collect();
    assert_eq!(secret_fields, ["clientSecret"]);
    let levels: Vec<&Value> = result
        .pointer("/levels")
        .and_then(Value::as_array)
        .ok_or("levels")?
        .iter()
        .map(|l| &l["name"])
        .collect();
    assert_eq!(levels, ["tenant", "subscription"]);
    assert_eq!(at(&result, "/levels/0/optional"), Value::Null);
    assert_eq!(
        at(&result, "/levels/1/optional"),
        true,
        "a tenant-level sign-in"
    );
    assert_eq!(at(&result, "/sources"), json!(["cli"]));
    assert_eq!(at(&result, "/requirements"), json!(["roles"]));
    assert_eq!(at(&result, "/cloud"), "azure");
    for name in [
        "AZURE_CONFIG_DIR",
        "ARM_USE_CLI",
        "ARM_CLIENT_SECRET",
        "AZURE_SUBSCRIPTION_NAME",
    ] {
        assert!(
            result
                .pointer("/names")
                .and_then(Value::as_array)
                .is_some_and(|n| n.contains(&json!(name))),
            "{name}"
        );
    }
    Ok(())
}

/// The schema can't say a group names only its own method's fields.
#[tokio::test]
async fn a_service_principal_takes_one_of_a_secret_and_a_certificate() -> TestResult {
    let state = tempfile::tempdir()?;
    let mut app = App::start(AzurePlugin::new(
        Host::new([], cfg!(windows)),
        FakeAz::new(World::one_subscription()?),
    ))?;
    let result: ConfigureResult = serde_json::from_value(app.configure(state.path()).await?)?;
    for method in &result.methods {
        for name in method.one_of.iter().flatten() {
            assert!(
                method.fields.iter().any(|field| &field.name == name),
                "{name} is not a field of {}",
                method.name
            );
        }
    }
    let groups: Vec<(&str, &[Vec<String>])> = result
        .methods
        .iter()
        .map(|method| (method.name.as_str(), method.one_of.as_slice()))
        .collect();
    let credential = [vec![
        "clientSecret".to_owned(),
        "clientCertificatePath".to_owned(),
    ]];
    assert_eq!(
        groups,
        [
            ("cli", &[][..]),
            ("device_code", &[][..]),
            ("service_principal", &credential[..]),
        ]
    );
    Ok(())
}

#[tokio::test]
async fn detect_uses_a_copy_of_the_local_login_and_its_only_subscription() -> TestResult {
    let mut fixture = Fixture::new(World::one_subscription()?).await?;
    fixture.log_in_locally()?;
    let detected = fixture.app.result("detect", cli_detect()).await?;
    assert_valid("detectResult", &detected)?;
    assert_eq!(at(&detected, "/found"), true);
    assert_eq!(at(&detected, "/source"), "cli");
    let identity = at(&detected, "/identity");
    assert_eq!(at(&identity, "/principal"), "ana@contoso.com");
    assert_eq!(at(&identity, "/kind"), "user");
    assert_eq!(at(&identity, "/method"), "cli");
    assert_eq!(
        at(&identity, "/targets/tenant"),
        json!({"id": CONTOSO, "name": "Contoso"})
    );
    assert_eq!(
        at(&identity, "/targets/subscription"),
        json!({"id": PROD, "name": "Prod"})
    );

    let env = fixture.env().await?;
    let config = env_value(&env, "AZURE_CONFIG_DIR");
    assert!(is_under(config, fixture.state.path()), "{config:?}");
    let config = PathBuf::from(config.ok_or("no AZURE_CONFIG_DIR")?);
    assert_eq!(
        fs::read_to_string(config.join("msal_token_cache.json"))?,
        "the person's tokens"
    );
    assert_eq!(
        env_value(&env, "AZURE_EXTENSION_DIR").map(PathBuf::from),
        Some(fixture.local_dir().join("cliextensions"))
    );
    assert_eq!(
        fixture.calls(),
        [
            Call::RefreshAccounts {
                config: config.clone()
            },
            Call::SetSubscription {
                config,
                subscription: PROD.to_owned()
            }
        ],
        "the copy's subscriptions are fetched again, and only its default changes"
    );
    for (name, value) in [
        ("AZURE_TENANT_ID", CONTOSO),
        ("AZURE_SUBSCRIPTION_ID", PROD),
        ("ARM_SUBSCRIPTION_ID", PROD),
        ("ARM_USE_CLI", "true"),
        ("AZURE_AUTH_TYPE", "cli"),
        ("AZURE_PRINCIPAL_NAME", "ana@contoso.com"),
        ("AZURE_PRINCIPAL_TYPE", "user"),
        ("AZURE_TENANT_NAME", "Contoso"),
        ("AZURE_SUBSCRIPTION_NAME", "Prod"),
    ] {
        assert_eq!(env_value(&env, name), Some(value), "{name}");
    }
    assert_eq!(env_value(&env, "ARM_TENANT_ID"), None);
    Ok(())
}

#[tokio::test]
async fn every_env_value_is_a_declared_name_and_only_names_go_to_outputs() -> TestResult {
    let mut fixture = Fixture::new(World::one_subscription()?).await?;
    let configured = fixture.app.configure(fixture.state.path()).await?;
    fixture.log_in_locally()?;
    fixture.app.result("detect", cli_detect()).await?;
    let env = fixture.env().await?;
    for value in env
        .pointer("/values")
        .and_then(Value::as_array)
        .ok_or("values")?
    {
        assert!(
            configured
                .pointer("/names")
                .and_then(Value::as_array)
                .is_some_and(|n| n.contains(&value["name"])),
            "{value} is not declared"
        );
        assert_eq!(value["sensitive"], false, "{value}");
        let to =
            if value["name"] == "AZURE_TENANT_NAME" || value["name"] == "AZURE_SUBSCRIPTION_NAME" {
                json!(["output"])
            } else {
                json!(["env", "output"])
            };
        assert_eq!(value["to"], to, "{value}");
    }
    Ok(())
}

#[tokio::test]
async fn detect_finds_nothing_without_a_local_login() -> TestResult {
    let mut fixture = Fixture::new(World::one_subscription()?).await?;
    let detected = fixture.app.result("detect", cli_detect()).await?;
    assert_eq!(detected, json!({"found": false}));
    assert_eq!(sign_in_dirs(fixture.state.path())?, Vec::<String>::new());
    Ok(())
}

#[tokio::test]
async fn detect_skips_a_login_the_pins_rule_out_and_leaves_no_copy() -> TestResult {
    let mut fixture = Fixture::new(World::one_subscription()?).await?;
    fixture.log_in_locally()?;
    for pins in [
        json!({"tenant": FABRIKAM}),
        json!({"subscription": "Staging"}),
    ] {
        let params = detect_params(
            &json!([{"kind": "named", "name": "cli"}]),
            &pins,
            &json!([]),
        );
        let detected = fixture.app.result("detect", params).await?;
        assert_eq!(detected, json!({"found": false}), "{pins}");
    }
    assert_eq!(sign_in_dirs(fixture.state.path())?, Vec::<String>::new());
    Ok(())
}

#[tokio::test]
async fn detect_reports_a_login_that_lacks_a_required_role() -> TestResult {
    let mut world = World::one_subscription()?;
    world.grant(&format!("/subscriptions/{PROD}"), "Reader");
    let mut fixture = Fixture::new(world).await?;
    fixture.log_in_locally()?;
    let params = detect_params(
        &json!([{"kind": "named", "name": "cli"}]),
        &json!({}),
        &json!([{"kind": "roles", "roles": [{"role": "reader"}, {"role": "Owner", "scope": "/"}]}]),
    );
    let response = fixture.app.call("detect", params).await?;
    assert_eq!(
        error_kind(&response),
        Some("requirementNotMet"),
        "{response}"
    );
    assert_valid("requirementNotMetData", &at(&response, "/error/data"))?;
    assert_eq!(
        at(&response, "/error/data/unmet"),
        json!([{"kind": "roles", "roles": [{"role": "Owner", "scope": "/"}]}])
    );
    Ok(())
}

#[tokio::test]
async fn a_device_code_sign_in_prompts_with_the_url_and_code_first() -> TestResult {
    let mut fixture = Fixture::new(World::one_subscription()?).await?;
    let id = fixture
        .app
        .request(
            "signIn",
            sign_in_params(
                "device_code",
                &json!({}),
                &json!({"tenant": "contoso.onmicrosoft.com"}),
            ),
        )
        .await?;
    let prompt = fixture.app.receive().await?;
    assert_eq!(at(&prompt, "/method"), "signIn.prompt", "{prompt}");
    assert_valid("signInPrompt", &at(&prompt, "/params"))?;
    assert_eq!(
        at(&prompt, "/params"),
        json!({"request": id, "kind": "openUrl", "url": DEVICE_URL, "code": DEVICE_CODE})
    );
    let response = fixture.app.receive().await?;
    assert_eq!(at(&response, "/id"), id);
    assert_valid("signInResult", &at(&response, "/result"))?;
    assert_eq!(at(&response, "/result/method"), "device_code");
    assert_eq!(at(&response, "/result/targets/tenant/id"), CONTOSO);

    let dirs = sign_in_dirs(fixture.state.path())?;
    assert_eq!(dirs.len(), 1);
    assert!(matches!(
        fixture.calls().first(),
        Some(Call::Login { how: Interactive::DeviceCode, tenant: Some(tenant), config })
            if tenant == "contoso.onmicrosoft.com" && config.starts_with(fixture.state.path())
    ));
    assert_eq!(
        env_value(&fixture.env().await?, "AZURE_AUTH_TYPE"),
        Some("device_code")
    );
    Ok(())
}

#[tokio::test]
async fn a_browser_sign_in_says_it_is_waiting() -> TestResult {
    let mut fixture = Fixture::new(World::one_subscription()?).await?;
    let id = fixture
        .app
        .request(
            "signIn",
            sign_in_params("cli", &json!({"tenantId": CONTOSO}), &json!({})),
        )
        .await?;
    let prompt = fixture.app.receive().await?;
    assert_eq!(
        at(&prompt, "/params"),
        json!({"request": id, "kind": "waiting"})
    );
    let response = fixture.app.receive().await?;
    assert_eq!(at(&response, "/result/method"), "cli", "{response}");
    assert!(matches!(
        fixture.calls().first(),
        Some(Call::Login { how: Interactive::Browser, tenant: Some(tenant), .. }) if tenant == CONTOSO
    ));
    assert!(
        !fixture
            .calls()
            .iter()
            .any(|call| matches!(call, Call::RefreshAccounts { .. })),
        "a sign-in's own list is fresh"
    );
    Ok(())
}

#[tokio::test]
async fn a_failed_sign_in_keeps_its_kind_and_leaves_no_directory() -> TestResult {
    let mut world = World::one_subscription()?;
    world.login_error = Some(runbooks_plugin_transport::PluginError::new(
        ErrorKind::Cancelled,
        "az login failed: User canceled authentication.",
    ));
    let mut fixture = Fixture::new(world).await?;
    let id = fixture
        .app
        .request("signIn", sign_in_params("cli", &json!({}), &json!({})))
        .await?;
    fixture.app.receive().await?;
    let response = fixture.app.receive().await?;
    assert_eq!(at(&response, "/id"), id);
    assert_eq!(error_kind(&response), Some("cancelled"), "{response}");
    assert_eq!(sign_in_dirs(fixture.state.path())?, Vec::<String>::new());
    let env = fixture.app.call("env", json!({})).await?;
    assert_eq!(error_kind(&env), Some("notSignedIn"));
    Ok(())
}

async fn sign_in(fixture: &mut Fixture, pins: &Value) -> Result<Value, Box<dyn Error>> {
    let id = fixture
        .app
        .request("signIn", sign_in_params("device_code", &json!({}), pins))
        .await?;
    fixture.app.receive().await?;
    let response = fixture.app.receive().await?;
    assert_eq!(at(&response, "/id"), id);
    response
        .get("result")
        .cloned()
        .ok_or_else(|| format!("signIn failed: {response}").into())
}

#[tokio::test]
async fn several_tenants_are_chosen_through_targets_and_select() -> TestResult {
    let mut fixture = Fixture::new(World::two_tenants()?).await?;
    let identity = sign_in(&mut fixture, &json!({})).await?;
    assert_eq!(at(&identity, "/targets"), json!({}));
    let env = fixture.app.call("env", json!({})).await?;
    assert_eq!(error_kind(&env), Some("notSignedIn"), "env before a choice");

    let tenants = fixture
        .app
        .result("targets", json!({"level": "tenant"}))
        .await?;
    assert_valid("targetsResult", &tenants)?;
    assert_eq!(
        at(&tenants, "/targets"),
        json!([{"id": CONTOSO, "name": "Contoso"}, {"id": FABRIKAM, "name": "Fabrikam"}])
    );
    let subs = fixture
        .app
        .result(
            "targets",
            json!({"level": "subscription", "parent": FABRIKAM}),
        )
        .await?;
    assert_eq!(
        at(&subs, "/targets"),
        json!([{"id": SHARED, "name": "Shared"}])
    );

    let selected = fixture
        .app
        .result(
            "select",
            json!({"targets": {"tenant": FABRIKAM, "subscription": SHARED}}),
        )
        .await?;
    assert_valid("selectResult", &selected)?;
    assert_eq!(at(&selected, "/kind"), "guest");
    assert_eq!(at(&selected, "/targets/subscription/name"), "Shared");
    let env = fixture.env().await?;
    assert_eq!(env_value(&env, "AZURE_TENANT_ID"), Some(FABRIKAM));
    assert_eq!(
        env_value(&env, "AZURE_PRINCIPAL_OBJECT_ID"),
        Some("00000000-0000-4000-8000-0000000000b2")
    );
    assert_eq!(env_value(&env, "AZURE_PRINCIPAL_TYPE"), Some("guest"));
    assert!(fixture.calls().iter().any(
        |call| matches!(call, Call::SetSubscription { subscription, .. } if subscription == SHARED)
    ));
    Ok(())
}

#[tokio::test]
async fn a_pinned_tenant_leaves_only_its_subscriptions_to_choose() -> TestResult {
    let mut fixture = Fixture::new(World::two_tenants()?).await?;
    let identity = sign_in(&mut fixture, &json!({"tenant": CONTOSO})).await?;
    assert_eq!(
        at(&identity, "/targets"),
        json!({"tenant": {"id": CONTOSO, "name": "Contoso"}})
    );
    let tenants = fixture
        .app
        .result("targets", json!({"level": "tenant"}))
        .await?;
    assert_eq!(
        at(&tenants, "/targets"),
        json!([{"id": CONTOSO, "name": "Contoso"}])
    );
    let subs = fixture
        .app
        .result(
            "targets",
            json!({"level": "subscription", "parent": CONTOSO}),
        )
        .await?;
    assert_eq!(
        subs.pointer("/targets")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(2)
    );

    let response = fixture
        .app
        .call(
            "select",
            json!({"targets": {"tenant": FABRIKAM, "subscription": SHARED}}),
        )
        .await?;
    assert_eq!(error_kind(&response), Some("pinMismatch"), "{response}");
    fixture
        .app
        .result(
            "select",
            json!({"targets": {"tenant": CONTOSO, "subscription": DEV}}),
        )
        .await?;
    assert_eq!(
        env_value(&fixture.env().await?, "AZURE_SUBSCRIPTION_ID"),
        Some(DEV)
    );
    Ok(())
}

#[tokio::test]
async fn a_pinned_subscription_by_name_is_chosen_with_its_tenant() -> TestResult {
    let mut fixture = Fixture::new(World::two_tenants()?).await?;
    let identity = sign_in(&mut fixture, &json!({"subscription": "shared"})).await?;
    assert_eq!(at(&identity, "/targets/tenant/id"), FABRIKAM);
    assert_eq!(at(&identity, "/targets/subscription/id"), SHARED);
    Ok(())
}

#[tokio::test]
async fn a_pinned_subscription_the_login_cannot_use_is_a_pin_mismatch() -> TestResult {
    let mut fixture = Fixture::new(World::two_tenants()?).await?;
    let id = fixture
        .app
        .request(
            "signIn",
            sign_in_params(
                "device_code",
                &json!({}),
                &json!({"subscription": "Staging"}),
            ),
        )
        .await?;
    fixture.app.receive().await?;
    let response = fixture.app.receive().await?;
    assert_eq!(at(&response, "/id"), id);
    assert_eq!(error_kind(&response), Some("pinMismatch"), "{response}");
    let message = error_message(&response).unwrap_or_default();
    assert!(message.contains("Staging"), "{message}");
    assert_eq!(sign_in_dirs(fixture.state.path())?, Vec::<String>::new());
    Ok(())
}

#[tokio::test]
async fn a_missing_role_fails_select_and_another_subscription_can_be_chosen() -> TestResult {
    let mut world = World::two_tenants()?;
    world.grant(&format!("/subscriptions/{DEV}"), "Owner");
    let mut fixture = Fixture::new(world).await?;
    let params = json!({"method": "device_code", "fields": {}, "pins": {"tenant": CONTOSO},
                        "requirements": [{"kind": "roles", "roles": [{"role": "owner"}]}]});
    fixture.app.request("signIn", params).await?;
    fixture.app.receive().await?;
    fixture.app.receive().await?;

    let response = fixture
        .app
        .call(
            "select",
            json!({"targets": {"tenant": CONTOSO, "subscription": PROD}}),
        )
        .await?;
    assert_eq!(
        error_kind(&response),
        Some("requirementNotMet"),
        "{response}"
    );
    let message = error_message(&response).unwrap_or_default();
    assert!(
        message.contains(&format!("owner at /subscriptions/{PROD}")),
        "{message}"
    );
    let env = fixture.app.call("env", json!({})).await?;
    assert_eq!(
        error_kind(&env),
        Some("notSignedIn"),
        "a refused choice is not kept"
    );

    fixture
        .app
        .result(
            "select",
            json!({"targets": {"tenant": CONTOSO, "subscription": DEV}}),
        )
        .await?;
    assert_eq!(
        env_value(&fixture.env().await?, "AZURE_SUBSCRIPTION_ID"),
        Some(DEV)
    );
    Ok(())
}

#[tokio::test]
async fn a_null_subscription_is_a_tenant_level_choice_that_can_be_changed() -> TestResult {
    let mut fixture = Fixture::new(World::two_tenants()?).await?;
    sign_in(&mut fixture, &json!({})).await?;
    let selected = fixture
        .app
        .result(
            "select",
            json!({"targets": {"tenant": CONTOSO, "subscription": null}}),
        )
        .await?;
    assert_valid("selectResult", &selected)?;
    assert_eq!(
        at(&selected, "/targets"),
        json!({"tenant": {"id": CONTOSO, "name": "Contoso"}, "subscription": null})
    );
    let env = fixture.env().await?;
    for name in [
        "AZURE_SUBSCRIPTION_ID",
        "ARM_SUBSCRIPTION_ID",
        "AZURE_SUBSCRIPTION_NAME",
    ] {
        assert_eq!(env_value(&env, name), None, "{name}");
    }

    let selected = fixture
        .app
        .result(
            "select",
            json!({"targets": {"tenant": CONTOSO, "subscription": DEV}}),
        )
        .await?;
    assert_eq!(at(&selected, "/targets/subscription/id"), DEV);
    assert_eq!(
        env_value(&fixture.env().await?, "AZURE_SUBSCRIPTION_ID"),
        Some(DEV)
    );
    Ok(())
}

/// A tenant-level sign-in has nothing to choose: it is ready with no
/// subscription.
#[tokio::test]
async fn a_tenant_with_no_subscription_signs_in_with_none() -> TestResult {
    let mut world = World::one_subscription()?;
    world.accounts.subscriptions.clear();
    let mut fixture = Fixture::new(world).await?;
    let identity = sign_in(&mut fixture, &json!({})).await?;
    assert_valid("signInResult", &identity)?;
    assert_eq!(
        at(&identity, "/targets"),
        json!({"tenant": {"id": CONTOSO, "name": "Contoso"}, "subscription": null})
    );
    let env = fixture.env().await?;
    assert_eq!(env_value(&env, "AZURE_TENANT_ID"), Some(CONTOSO));
    assert_eq!(env_value(&env, "AZURE_SUBSCRIPTION_ID"), None);
    Ok(())
}

#[tokio::test]
async fn select_and_targets_refuse_what_the_sign_in_cannot_see() -> TestResult {
    let mut fixture = Fixture::new(World::two_tenants()?).await?;
    let before = fixture
        .app
        .call("targets", json!({"level": "tenant"}))
        .await?;
    assert_eq!(error_kind(&before), Some("notSignedIn"));
    sign_in(&mut fixture, &json!({})).await?;
    for (method, params) in [
        (
            "select",
            json!({"targets": {"tenant": CONTOSO, "subscription": SHARED}}),
        ),
        ("select", json!({"targets": {"subscription": PROD}})),
        ("select", json!({"targets": {"tenant": CONTOSO}})),
        (
            "select",
            json!({"targets": {"tenant": CONTOSO, "role": "dev"}}),
        ),
        ("targets", json!({"level": "subscription"})),
        ("targets", json!({"level": "account"})),
    ] {
        let response = fixture.app.call(method, params.clone()).await?;
        assert_eq!(
            error_kind(&response),
            Some("invalidParams"),
            "{method} {params}: {response}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_new_sign_in_replaces_the_last_and_sign_out_clears_everything() -> TestResult {
    let mut fixture = Fixture::new(World::one_subscription()?).await?;
    fixture.log_in_locally()?;
    fixture.app.result("detect", cli_detect()).await?;
    let first = sign_in_dirs(fixture.state.path())?;
    sign_in(&mut fixture, &json!({})).await?;
    let second = sign_in_dirs(fixture.state.path())?;
    assert_eq!(second.len(), 1);
    assert_ne!(first, second);

    for _ in 0..2 {
        let signed_out = fixture.app.result("signOut", json!({})).await?;
        assert_eq!(signed_out, json!({}));
    }
    assert_eq!(sign_in_dirs(fixture.state.path())?, Vec::<String>::new());
    assert!(fixture.local_dir().join("msal_token_cache.json").exists());
    let env = fixture.app.call("env", json!({})).await?;
    assert_eq!(error_kind(&env), Some("notSignedIn"));
    Ok(())
}

#[tokio::test]
async fn bad_params_are_refused_before_anything_runs() -> TestResult {
    let mut fixture = Fixture::new(World::one_subscription()?).await?;
    for (method, params, kind, mentions) in [
        (
            "signIn",
            sign_in_params("password", &json!({}), &json!({})),
            "invalidParams",
            "device_code",
        ),
        (
            "signIn",
            sign_in_params("cli", &json!({"tenantId": "-x"}), &json!({})),
            "invalidParams",
            "fields.tenantId",
        ),
        (
            "signIn",
            sign_in_params(
                "cli",
                &json!({"tenantId": FABRIKAM}),
                &json!({"tenant": CONTOSO}),
            ),
            "pinMismatch",
            FABRIKAM,
        ),
        (
            "detect",
            detect_params(&json!([]), &json!({"account": "1"}), &json!([])),
            "invalidParams",
            "pins.account",
        ),
        (
            "detect",
            detect_params(
                &json!([{"kind": "named", "name": "adc"}]),
                &json!({}),
                &json!([]),
            ),
            "invalidParams",
            "adc",
        ),
    ] {
        let response = fixture.app.call(method, params).await?;
        assert_eq!(error_kind(&response), Some(kind), "{response}");
        let message = error_message(&response).unwrap_or_default();
        assert!(message.contains(mentions), "{mentions} in {message}");
    }
    assert_eq!(fixture.calls(), Vec::<Call>::new());
    assert_eq!(sign_in_dirs(fixture.state.path())?, Vec::<String>::new());
    Ok(())
}

/// Without the person's extension directory, the copy uses its own, not a
/// directory that isn't there.
#[tokio::test]
async fn detect_without_local_extensions_gives_the_copy_its_own() -> TestResult {
    let mut fixture = Fixture::new(World::one_subscription()?).await?;
    fixture.log_in_locally_without_extensions()?;
    let detected = fixture.app.result("detect", cli_detect()).await?;
    assert_eq!(at(&detected, "/found"), true, "{detected}");
    let env = fixture.env().await?;
    let config = PathBuf::from(env_value(&env, "AZURE_CONFIG_DIR").ok_or("no config dir")?);
    assert_eq!(
        env_value(&env, "AZURE_EXTENSION_DIR").map(PathBuf::from),
        Some(config.join("cliextensions"))
    );
    Ok(())
}

/// Neither shows a proxy password; the plugin shows only whether it is
/// configured.
#[test]
fn debug_shows_no_proxy_password_and_only_whether_configured() -> TestResult {
    let network = runbooks_credential_azure::Network {
        ca_bundle_file: Some(PathBuf::from("/etc/ca.pem")),
        proxy: Some("http://user:hunter2@proxy.example:8080".to_owned()),
    };
    assert_eq!(
        format!("{network:?}"),
        r#"Network { ca_bundle_file: Some("/etc/ca.pem"), proxy: Some("<set>") }"#
    );
    let plugin = AzurePlugin::new(
        Host::new([], cfg!(windows)),
        FakeAz::new(World::one_subscription()?),
    );
    assert_eq!(
        format!("{plugin:?}"),
        "AzurePlugin { configured: false, .. }"
    );
    Ok(())
}

#[tokio::test]
async fn configure_again_with_another_state_dir_is_refused() -> TestResult {
    let mut fixture = Fixture::new(World::one_subscription()?).await?;
    fixture.app.configure(fixture.state.path()).await?;
    let other = tempfile::tempdir()?;
    let other = other.path().to_str().ok_or("not UTF-8")?;
    let response = fixture
        .app
        .call(
            "configure",
            json!({"protocolVersion": "1", "caller": "runbooks/0.31.0", "stateDir": other, "callTimeoutsMillis": runbooks_limits()}),
        )
        .await?;
    assert_eq!(error_kind(&response), Some("invalidParams"), "{response}");
    let relative = fixture
        .app
        .call(
            "configure",
            json!({"protocolVersion": "1", "caller": "runbooks/0.31.0", "stateDir": "state", "callTimeoutsMillis": runbooks_limits()}),
        )
        .await?;
    assert_eq!(error_kind(&relative), Some("invalidParams"), "{relative}");
    Ok(())
}
