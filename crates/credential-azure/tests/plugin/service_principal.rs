//! Service principals, from `signIn`'s fields, the environment and an
//! earlier block's outputs, on the fake `az`.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use runbooks_credential_azure::AzurePlugin;
use runbooks_credential_azure::host::Host;
use runbooks_credential_azure::service_principal::{Credential, Secret};
use runbooks_plugin_protocol::credential::ErrorKind;
use runbooks_plugin_transport::PluginError;
use serde_json::{Value, json};
use tempfile::TempDir;

use crate::fake_az::{CLIENT, CONTOSO, Call, DEV, FABRIKAM, FakeAz, PROD, World};
use crate::support::{
    App, TestResult, assert_valid, detect_params, env_value, error_kind, sign_in_dirs,
    sign_in_params,
};

const SECRET: &str = "typed-Secret~value.42";

struct Fixture {
    app: App,
    az: FakeAz,
    state: TempDir,
}

impl Fixture {
    async fn new(world: World, vars: &[(&str, &str)]) -> Result<Self, Box<dyn Error>> {
        let state = tempfile::tempdir()?;
        let az = FakeAz::new(world);
        let env = vars
            .iter()
            .map(|(name, value)| ((*name).into(), (*value).into()));
        let host = Host::new(env, cfg!(windows));
        let mut app = App::start(AzurePlugin::new(host, az.clone()))?;
        app.configure(state.path()).await?;
        Ok(Self { app, az, state })
    }

    fn logins(&self) -> Vec<(PathBuf, String, String, Credential)> {
        self.az
            .world()
            .calls
            .iter()
            .filter_map(|call| match call {
                Call::LoginServicePrincipal {
                    config,
                    client_id,
                    tenant,
                    credential,
                } => Some((
                    config.clone(),
                    client_id.clone(),
                    tenant.clone(),
                    credential.clone(),
                )),
                Call::Login { .. } | Call::SetSubscription { .. } => None,
            })
            .collect()
    }

    async fn env(&mut self) -> Result<Value, Box<dyn Error>> {
        let env = self.app.result("env", json!({})).await?;
        assert_valid("envResult", &env)?;
        Ok(env)
    }
}

fn fields(pairs: &[(&str, &str)]) -> Value {
    pairs
        .iter()
        .map(|(name, value)| ((*name).to_owned(), json!(value)))
        .collect::<serde_json::Map<_, _>>()
        .into()
}

fn sensitive(env: &Value, name: &str) -> Option<bool> {
    env["values"]
        .as_array()?
        .iter()
        .find(|value| value["name"] == name)?["sensitive"]
        .as_bool()
}

#[tokio::test]
async fn a_typed_secret_reaches_az_and_env_and_no_other_line() -> TestResult {
    let mut fixture = Fixture::new(World::service_principal()?, &[]).await?;
    let typed = fields(&[
        ("clientId", CLIENT),
        ("tenantId", CONTOSO),
        ("clientSecret", SECRET),
    ]);

    // A refused sign-in, and a malformed one: neither repeats the secret.
    fixture.az.world().login_error = Some(PluginError::new(
        ErrorKind::AccessDenied,
        "az login --service-principal failed: AADSTS7000215: Invalid client secret provided.",
    ));
    let refused = fixture
        .app
        .call(
            "signIn",
            sign_in_params("service_principal", &typed, &json!({})),
        )
        .await?;
    assert_eq!(error_kind(&refused), Some("accessDenied"), "{refused}");
    let mut both = typed.clone();
    both["clientCertificatePath"] = json!("/sp.pem");
    let malformed = fixture
        .app
        .call(
            "signIn",
            sign_in_params("service_principal", &both, &json!({})),
        )
        .await?;
    assert_eq!(error_kind(&malformed), Some("invalidParams"), "{malformed}");
    assert!(sign_in_dirs(fixture.state.path())?.is_empty());

    fixture.az.world().login_error = None;
    let identity = fixture
        .app
        .result(
            "signIn",
            sign_in_params("service_principal", &typed, &json!({})),
        )
        .await?;
    assert_valid("signInResult", &identity)?;
    assert_eq!(identity["kind"], "servicePrincipal");
    assert_eq!(identity["principal"], CLIENT);
    assert_eq!(identity["method"], "service_principal");
    fixture
        .app
        .result(
            "select",
            json!({"targets": {"tenant": CONTOSO, "subscription": PROD}}),
        )
        .await?;
    let logins = fixture.logins();
    let (config, client_id, tenant, credential) = logins.last().ok_or("no login")?;
    assert!(config.starts_with(fixture.state.path()));
    assert_eq!((client_id.as_str(), tenant.as_str()), (CLIENT, CONTOSO));
    assert_eq!(
        credential,
        &Credential::Secret(Secret::new(SECRET.to_owned()))
    );

    let env = fixture.env().await?;
    for name in ["ARM_CLIENT_SECRET", "AZURE_CLIENT_SECRET"] {
        assert_eq!(env_value(&env, name), Some(SECRET), "{name}");
        assert_eq!(sensitive(&env, name), Some(true), "{name}");
    }
    for (name, value) in [
        ("ARM_CLIENT_ID", Some(CLIENT)),
        ("AZURE_CLIENT_ID", Some(CLIENT)),
        ("ARM_TENANT_ID", Some(CONTOSO)),
        ("AZURE_AUTH_TYPE", Some("service_principal")),
        ("AZURE_PRINCIPAL_TYPE", Some("servicePrincipal")),
        ("ARM_USE_CLI", None),
        ("AZURE_CLIENT_CERTIFICATE_PATH", None),
    ] {
        assert_eq!(env_value(&env, name), value, "{name}");
    }
    let env_line = env.to_string();

    let written = fixture.app.close().await?;
    let carrying: Vec<&String> = written
        .iter()
        .filter(|line| line.contains(SECRET))
        .collect();
    assert_eq!(carrying.len(), 1, "{carrying:?}");
    let line: Value = serde_json::from_str(carrying.first().ok_or("no env line")?)?;
    assert_eq!(
        line["result"].to_string(),
        env_line,
        "only env's result carries it"
    );
    Ok(())
}

#[tokio::test]
async fn a_certificate_is_used_through_the_blocks_own_copy() -> TestResult {
    let mut fixture = Fixture::new(World::service_principal()?, &[]).await?;
    let source = tempfile::tempdir()?;
    let pem = source.path().join("sp.pem");
    fs::write(&pem, "-----BEGIN CERTIFICATE-----")?;
    let typed = fields(&[
        ("clientId", CLIENT),
        ("clientCertificatePath", pem.to_str().ok_or("not UTF-8")?),
    ]);
    fixture
        .app
        .result(
            "signIn",
            sign_in_params(
                "service_principal",
                &typed,
                &json!({"tenant": CONTOSO, "subscription": "dev"}),
            ),
        )
        .await?;

    let logins = fixture.logins();
    let (config, _, tenant, credential) = logins.first().ok_or("no login")?;
    assert_eq!(tenant, CONTOSO, "the pinned tenant");
    let Credential::Certificate(copy) = credential else {
        return Err(format!("{credential:?} is not a certificate").into());
    };
    assert!(copy.starts_with(config), "{}", copy.display());
    assert_eq!(fs::read_to_string(copy)?, "-----BEGIN CERTIFICATE-----");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(copy)?.permissions().mode() & 0o777, 0o600);
    }

    let env = fixture.env().await?;
    assert_eq!(
        env_value(&env, "AZURE_CLIENT_CERTIFICATE_PATH").map(Path::new),
        Some(copy.as_path())
    );
    assert_eq!(env_value(&env, "AZURE_SUBSCRIPTION_ID"), Some(DEV));
    assert_eq!(env_value(&env, "ARM_USE_CLI"), Some("true"));
    for name in ["ARM_TENANT_ID", "ARM_CLIENT_SECRET", "AZURE_CLIENT_SECRET"] {
        assert_eq!(env_value(&env, name), None, "{name}");
    }
    Ok(())
}

#[tokio::test]
async fn detect_reads_a_service_principal_from_the_prefixed_environment() -> TestResult {
    let vars = [
        ("ARM_CLIENT_ID", "44444444-4444-4444-8444-444444444444"),
        ("ARM_TENANT_ID", CONTOSO),
        ("ARM_CLIENT_SECRET", "unprefixed-secret"),
        ("CI_AZURE_CLIENT_ID", CLIENT),
        ("CI_AZURE_TENANT_ID", CONTOSO),
        ("CI_AZURE_CLIENT_SECRET", SECRET),
        ("CI_AZURE_SUBSCRIPTION_ID", "Dev"),
    ];
    let mut fixture = Fixture::new(World::service_principal()?, &vars).await?;
    let env_source = json!([{"kind": "env", "prefix": "CI_"}]);
    let detected = fixture
        .app
        .result(
            "detect",
            detect_params(&env_source, &json!({}), &json!([])),
        )
        .await?;
    assert_valid("detectResult", &detected)?;
    assert_eq!(detected["found"], true);
    assert_eq!(detected["source"], "env");
    assert_eq!(detected["identity"]["method"], "service_principal");
    assert_eq!(detected["identity"]["targets"]["subscription"]["id"], DEV);
    assert!(!detected.to_string().contains(SECRET));
    let logins = fixture.logins();
    assert_eq!(logins.first().map(|login| login.1.as_str()), Some(CLIENT));
    let env = fixture.env().await?;
    assert_eq!(env_value(&env, "ARM_CLIENT_SECRET"), Some(SECRET));

    // A block that pins another tenant never signs it in.
    let pinned = detect_params(&env_source, &json!({"tenant": FABRIKAM}), &json!([]));
    assert_eq!(
        fixture.app.result("detect", pinned).await?,
        json!({"found": false})
    );
    assert_eq!(fixture.logins().len(), 1);

    let bad = detect_params(
        &json!([{"kind": "env", "prefix": "ci"}]),
        &json!({}),
        &json!([]),
    );
    let response = fixture.app.call("detect", bad).await?;
    assert_eq!(error_kind(&response), Some("invalidParams"), "{response}");
    Ok(())
}

#[tokio::test]
async fn detect_reuses_an_earlier_blocks_sign_in_and_its_choice() -> TestResult {
    let mut fixture = Fixture::new(World::service_principal()?, &[]).await?;
    let earlier = tempfile::tempdir()?;
    fs::write(earlier.path().join("azureProfile.json"), "{}")?;
    fs::write(
        earlier.path().join("msal_token_cache.json"),
        "earlier tokens",
    )?;
    let values = json!([{"kind": "values", "values": {
        "AZURE_CONFIG_DIR": earlier.path().to_str().ok_or("not UTF-8")?,
        "AZURE_TENANT_ID": CONTOSO,
        "AZURE_SUBSCRIPTION_ID": DEV,
        "AZURE_AUTH_TYPE": "device_code",
    }}]);
    let detected = fixture
        .app
        .result("detect", detect_params(&values, &json!({}), &json!([])))
        .await?;
    assert_eq!(detected["source"], "values", "{detected}");
    assert_eq!(detected["identity"]["method"], "device_code");
    assert_eq!(detected["identity"]["targets"]["subscription"]["id"], DEV);
    let env = fixture.env().await?;
    let config = PathBuf::from(env_value(&env, "AZURE_CONFIG_DIR").ok_or("no config dir")?);
    assert!(
        config.starts_with(fixture.state.path()),
        "a copy, not the earlier block's"
    );
    assert_eq!(
        fs::read_to_string(config.join("msal_token_cache.json"))?,
        "earlier tokens"
    );
    assert!(fixture.logins().is_empty());

    // Outputs that hold a service principal sign it in afresh.
    let values = json!([{"kind": "values", "values": {
        "AZURE_CONFIG_DIR": earlier.path().to_str().ok_or("not UTF-8")?,
        "ARM_CLIENT_ID": CLIENT,
        "ARM_TENANT_ID": CONTOSO,
        "ARM_CLIENT_SECRET": SECRET,
    }}]);
    let detected = fixture
        .app
        .result("detect", detect_params(&values, &json!({}), &json!([])))
        .await?;
    assert_eq!(
        detected["identity"]["method"], "service_principal",
        "{detected}"
    );
    assert_eq!(fixture.logins().len(), 1);
    assert_eq!(
        sign_in_dirs(fixture.state.path())?.len(),
        1,
        "the first copy is gone"
    );
    Ok(())
}
