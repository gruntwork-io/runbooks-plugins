use serde_json::{Value, json};

use crate::support::{
    App, BARE_TOKEN, FakeCrypto, TestResult, USER_ADC, USER_EMAIL, at, detect, env_value,
    gcloud_root, google, sign_in,
};

#[tokio::test]
async fn configure_offers_the_gcloud_method_and_named_sources() -> TestResult {
    let dir = tempfile::tempdir()?;
    let mut app = App::start(&[], &google(), FakeCrypto::default())?;
    let offered = app.configure(dir.path()).await?;
    assert_eq!(at(&offered, "/sources"), json!(["adc", "gcloud"]));
    assert_eq!(
        at(&offered, "/methods/2"),
        json!({
            "name": "gcloud",
            "label": "gcloud Config",
            "fields": [{"name": "configuration", "label": "gcloud configuration", "required": false, "secret": false}],
        })
    );
    Ok(())
}

#[tokio::test]
async fn the_adc_source_reads_gclouds_file_and_env_hands_a_run_a_copy() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = gcloud_root(dir.path(), Some(USER_ADC))?;
    let mut app = App::start(
        &[("CLOUDSDK_CONFIG", &root)],
        &google(),
        FakeCrypto::default(),
    )?;
    let state = dir.path().join("state");
    app.configure(&state).await?;

    let found = app
        .ok(
            "detect",
            "detectResult",
            detect(&json!([{"kind": "named", "name": "adc"}])),
        )
        .await?;
    assert_eq!(at(&found, "/source"), "adc");
    let identity = at(&found, "/identity");
    assert_eq!(
        (at(&identity, "/method"), at(&identity, "/principal")),
        (json!("adc"), json!(USER_EMAIL))
    );
    assert_eq!(
        at(&identity, "/targets/project/id"),
        "quota-5678",
        "the quota project"
    );

    let env = app.ok("env", "envResult", json!({})).await?;
    let (path, _, _) = env_value(&env, "GOOGLE_APPLICATION_CREDENTIALS").ok_or("no file")?;
    assert!(
        std::path::Path::new(path).starts_with(&state),
        "{path} isn't a copy"
    );
    assert_eq!(std::fs::read_to_string(path)?, USER_ADC);
    for absent in ["CLOUDSDK_ACTIVE_CONFIG_NAME", "CLOUDSDK_COMPUTE_REGION"] {
        assert!(
            env_value(&env, absent).is_none(),
            "adc read the configuration: {absent}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn the_gcloud_source_uses_the_active_configurations_settings() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = gcloud_root(dir.path(), Some(USER_ADC))?;
    let gcloud = json!([{"kind": "named", "name": "gcloud"}]);
    let mut app = App::start(
        &[("CLOUDSDK_CONFIG", &root)],
        &google(),
        FakeCrypto::default(),
    )?;
    app.configure(&dir.path().join("state")).await?;

    let found = app.ok("detect", "detectResult", detect(&gcloud)).await?;
    assert_eq!(at(&found, "/source"), "gcloud");
    assert_eq!(at(&found, "/identity/targets/project/id"), "sandbox-1234");
    let env = app.ok("env", "envResult", json!({})).await?;
    let configuration = env_value(&env, "CLOUDSDK_ACTIVE_CONFIG_NAME").ok_or("no configuration")?;
    assert_eq!((configuration.0, configuration.2), ("dev", &json!(["env"])));
    for (name, value) in [
        ("CLOUDSDK_COMPUTE_REGION", "europe-west1"),
        ("GOOGLE_CLOUD_REGION", "europe-west1"),
        ("CLOUDSDK_COMPUTE_ZONE", "europe-west1-b"),
        ("GOOGLE_ZONE", "europe-west1-b"),
        ("CLOUDSDK_CORE_PROJECT", "sandbox-1234"),
    ] {
        assert_eq!(env_value(&env, name).map(|v| v.0), Some(value), "{name}");
    }

    // The variable wins over the active_config file, as it does for gcloud.
    let env = [
        ("CLOUDSDK_CONFIG", root.as_str()),
        ("CLOUDSDK_ACTIVE_CONFIG_NAME", "default"),
    ];
    let mut app = App::start(&env, &google(), FakeCrypto::default())?;
    app.configure(&dir.path().join("state2")).await?;
    let found = app.ok("detect", "detectResult", detect(&gcloud)).await?;
    assert_eq!(at(&found, "/identity/targets/project/id"), "quota-5678");
    let env = app.ok("env", "envResult", json!({})).await?;
    assert_eq!(
        env_value(&env, "CLOUDSDK_ACTIVE_CONFIG_NAME").map(|v| v.0),
        Some("default")
    );
    assert!(env_value(&env, "CLOUDSDK_COMPUTE_REGION").is_none());
    Ok(())
}

#[tokio::test]
async fn gcloud_without_application_default_credentials_finds_nothing() -> TestResult {
    let dir = tempfile::tempdir()?;
    let both = json!([{"kind": "named", "name": "adc"}, {"kind": "named", "name": "gcloud"}]);

    let bare = gcloud_root(&dir.path().join("bare"), None)?;
    let mut app = App::start(
        &[("CLOUDSDK_CONFIG", &bare)],
        &google(),
        FakeCrypto::default(),
    )?;
    app.configure(&dir.path().join("state")).await?;
    let result = app.ok("detect", "detectResult", detect(&both)).await?;
    assert_eq!(result, json!({"found": false}));

    // The default directory is under the home directory the plugin is given:
    // `~/.config/gcloud`, or `%APPDATA%\gcloud` on Windows.
    let home = dir.path().join("home");
    gcloud_root(&home.join(".config"), Some(USER_ADC))?;
    let home = home.to_str().ok_or("utf-8")?;
    let app_data = format!("{home}{}.config", std::path::MAIN_SEPARATOR);
    let defaults = [("HOME", home), ("APPDATA", app_data.as_str())];
    let mut app = App::start(&defaults, &google(), FakeCrypto::default())?;
    app.configure(&dir.path().join("state")).await?;
    let found = app.ok("detect", "detectResult", detect(&both)).await?;
    assert_eq!(at(&found, "/source"), "adc");

    // CLOUDSDK_CONFIG set to nothing turns gcloud's configuration off.
    let off = [
        ("HOME", home),
        ("APPDATA", app_data.as_str()),
        ("CLOUDSDK_CONFIG", ""),
    ];
    let mut app = App::start(&off, &google(), FakeCrypto::default())?;
    app.configure(&dir.path().join("state")).await?;
    let result = app.ok("detect", "detectResult", detect(&both)).await?;
    assert_eq!(result, json!({"found": false}));
    Ok(())
}

#[tokio::test]
async fn a_broken_adc_file_is_skipped_for_the_next_source() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = gcloud_root(dir.path(), Some("{\"type\": \"authorized_user\", SENTINEL"))?;
    let env = [
        ("CLOUDSDK_CONFIG", root.as_str()),
        ("GOOGLE_OAUTH_ACCESS_TOKEN", BARE_TOKEN),
    ];
    let mut app = App::start(&env, &google(), FakeCrypto::default())?;
    app.configure(&dir.path().join("state")).await?;

    let sources = json!([{"kind": "named", "name": "adc"}, {"kind": "env"}]);
    let found = app.ok("detect", "detectResult", detect(&sources)).await?;
    assert_eq!(at(&found, "/source"), "env");

    let error = app
        .error(
            "detect",
            detect(&json!([{"kind": "named", "name": "gcloud"}])),
            "invalidParams",
        )
        .await?;
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(message.contains("is not JSON"), "{message}");
    assert!(
        message.contains("gcloud auth application-default login"),
        "{message}"
    );
    assert!(!message.contains("SENTINEL"), "{message}");

    let env = [
        ("CLOUDSDK_CONFIG", root.as_str()),
        ("CLOUDSDK_ACTIVE_CONFIG_NAME", "../dev"),
    ];
    let mut app = App::start(&env, &google(), FakeCrypto::default())?;
    app.configure(&dir.path().join("state")).await?;
    let error = app
        .error(
            "detect",
            detect(&json!([{"kind": "named", "name": "gcloud"}])),
            "invalidParams",
        )
        .await?;
    assert!(
        !at(&error, "/message")
            .as_str()
            .unwrap_or_default()
            .contains("../dev"),
        "{error}"
    );
    Ok(())
}

#[tokio::test]
async fn the_gcloud_method_signs_in_with_the_active_or_a_named_configuration() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = gcloud_root(dir.path(), Some(USER_ADC))?;
    let mut app = App::start(
        &[("CLOUDSDK_CONFIG", &root)],
        &google(),
        FakeCrypto::default(),
    )?;
    app.configure(&dir.path().join("state")).await?;

    let identity = app
        .ok("signIn", "signInResult", sign_in("gcloud", &json!({})))
        .await?;
    assert_eq!(at(&identity, "/method"), "gcloud");
    assert_eq!(at(&identity, "/targets/project/id"), "sandbox-1234");

    let named = sign_in("gcloud", &json!({"configuration": "default"}));
    let identity = app.ok("signIn", "signInResult", named).await?;
    assert_eq!(at(&identity, "/targets/project/id"), "quota-5678");

    let pinned = json!({"method": "gcloud", "fields": {"configuration": "default"}, "pins": {"project": "sandbox-1234"}, "requirements": []});
    let identity = app.ok("signIn", "signInResult", pinned).await?;
    assert_eq!(
        at(&identity, "/targets/project/id"),
        "sandbox-1234",
        "the pin wins"
    );

    let error = app
        .error(
            "signIn",
            sign_in("gcloud", &json!({"configuration": "prod"})),
            "invalidParams",
        )
        .await?;
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(
        message.contains("its configurations are default, dev"),
        "{message}"
    );
    let error = app
        .error(
            "signIn",
            sign_in("gcloud", &json!({"configuration": "Prod/../x"})),
            "invalidParams",
        )
        .await?;
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(
        message.contains("lower case") && !message.contains("Prod"),
        "{message}"
    );
    Ok(())
}

#[tokio::test]
async fn the_gcloud_method_says_what_to_run_when_gcloud_has_nothing() -> TestResult {
    let dir = tempfile::tempdir()?;
    let state = dir.path().join("state");

    let mut app = App::start(&[], &google(), FakeCrypto::default())?;
    app.configure(&state).await?;
    let error = app
        .error("signIn", sign_in("gcloud", &json!({})), "notSignedIn")
        .await?;
    assert!(
        at(&error, "/message")
            .as_str()
            .is_some_and(|m| m.contains("gcloud init")),
        "{error}"
    );

    let bare = gcloud_root(dir.path(), None)?;
    let mut app = App::start(
        &[("CLOUDSDK_CONFIG", &bare)],
        &google(),
        FakeCrypto::default(),
    )?;
    app.configure(&state).await?;
    let error = app
        .error("signIn", sign_in("gcloud", &json!({})), "notSignedIn")
        .await?;
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(
        message.contains("gcloud auth application-default login"),
        "{message}"
    );

    let env = [
        ("CLOUDSDK_CONFIG", bare.as_str()),
        ("CLOUDSDK_ACTIVE_CONFIG_NAME", "staging"),
    ];
    let mut app = App::start(&env, &google(), FakeCrypto::default())?;
    app.configure(&state).await?;
    let error = app
        .error("signIn", sign_in("gcloud", &json!({})), "notSignedIn")
        .await?;
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(message.contains("staging doesn't exist"), "{message}");
    Ok(())
}
