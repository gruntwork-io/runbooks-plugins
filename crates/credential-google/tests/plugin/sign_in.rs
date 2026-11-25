use runbooks_credential_google::{NoCrypto, TOKEN_URL, TokenRequest};
use serde_json::{Value, json};

use crate::support::{
    App, CLOUD_PLATFORM, FakeCrypto, NOW, SA_EMAIL, SA_KEY, TestResult, env_value, google, sign_in,
};

#[tokio::test]
async fn configure_offers_the_methods_project_level_scopes_and_every_name() -> TestResult {
    let dir = tempfile::tempdir()?;
    let mut app = App::start(&[], &google(), FakeCrypto::default())?;
    let offered = app.configure(dir.path()).await?;
    assert_eq!(offered["cloud"], "gcp");
    assert_eq!(offered["methods"][0]["name"], "service_account");
    let key = &offered["methods"][0]["fields"][0];
    assert_eq!(
        (&key["name"], &key["secret"]),
        (&json!("key"), &json!(true))
    );
    assert_eq!(
        offered["levels"],
        json!([{"name": "project", "label": "Project", "chosen": "afterSignIn"}])
    );
    assert_eq!(offered["requirements"], json!(["scopes"]));
    let names = offered["names"].as_array().ok_or("no names")?;
    for name in [
        "GOOGLE_APPLICATION_CREDENTIALS",
        "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE",
        "GOOGLE_OAUTH_ACCESS_TOKEN",
        "CLOUDSDK_CORE_PROJECT",
        "GOOGLE_CREDENTIALS",
    ] {
        assert!(names.contains(&json!(name)), "{name} is not declared");
    }
    Ok(())
}

#[tokio::test]
async fn configure_refuses_a_relative_state_dir() -> TestResult {
    let mut app = App::start(&[], &google(), FakeCrypto::default())?;
    let params =
        json!({"protocolVersion": "1", "caller": "runbooks/0.31.0", "stateDir": "state/block"});
    let error = app.error("configure", params, "invalidParams").await?;
    assert!(
        error["message"]
            .as_str()
            .is_some_and(|m| m.contains("stateDir")),
        "{error}"
    );
    Ok(())
}

#[tokio::test]
async fn a_pasted_key_signs_in_as_its_service_account_in_its_project() -> TestResult {
    let dir = tempfile::tempdir()?;
    let google = google();
    let crypto = FakeCrypto::default();
    let mut app = App::start(&[], &google, crypto.clone())?;
    app.configure(dir.path()).await?;

    let identity = app
        .ok(
            "signIn",
            "signInResult",
            sign_in("service_account", json!({"key": SA_KEY})),
        )
        .await?;
    assert_eq!(identity["principal"], SA_EMAIL);
    assert_eq!(identity["kind"], "serviceAccount");
    assert_eq!(identity["method"], "service_account");
    assert_eq!(
        identity["targets"]["project"],
        json!({"id": "sandbox-1234", "name": "Sandbox"})
    );
    assert!(identity.get("expiresAt").is_none(), "{identity}");

    // The assertion is for Google's own token endpoint, whatever the key says.
    let claims = crypto.claims.lock().map_err(|_| "poisoned")?.clone();
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].issuer, SA_EMAIL);
    assert_eq!(claims[0].audience, TOKEN_URL);
    assert_eq!(claims[0].scope, CLOUD_PLATFORM);
    assert_eq!(
        (claims[0].issued_at, claims[0].expires_at),
        (NOW, NOW + 3600)
    );
    assert!(matches!(
        google.token_requests().as_slice(),
        [TokenRequest::JwtBearer { assertion }] if assertion.expose() == format!("header.{SA_EMAIL}.signature")
    ));
    Ok(())
}

#[tokio::test]
async fn env_points_a_run_at_a_private_copy_of_the_key_and_sign_out_deletes_it() -> TestResult {
    let dir = tempfile::tempdir()?;
    let mut app = App::start(&[], &google(), FakeCrypto::default())?;
    app.configure(dir.path()).await?;
    app.ok(
        "signIn",
        "signInResult",
        sign_in("service_account", json!({"key": SA_KEY})),
    )
    .await?;

    let env = app.ok("env", "envResult", json!({})).await?;
    let (path, sensitive, to) =
        env_value(&env, "GOOGLE_APPLICATION_CREDENTIALS").ok_or("no credentials file")?;
    assert!(!sensitive);
    assert_eq!(to, &json!(["env", "output"]));
    assert!(std::path::Path::new(path).starts_with(dir.path()), "{path}");
    assert_eq!(std::fs::read_to_string(path)?, SA_KEY);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(path)?.permissions().mode() & 0o777, 0o600);
    }
    let bridge =
        env_value(&env, "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE").ok_or("no gcloud bridge")?;
    assert_eq!(bridge.0, path);
    for name in [
        "GOOGLE_CLOUD_PROJECT",
        "CLOUDSDK_CORE_PROJECT",
        "GOOGLE_PROJECT",
    ] {
        assert_eq!(
            env_value(&env, name).map(|v| v.0),
            Some("sandbox-1234"),
            "{name}"
        );
    }
    assert_eq!(
        env_value(&env, "CLOUDSDK_CORE_ACCOUNT").map(|v| v.0),
        Some(SA_EMAIL)
    );
    let auth_type = env_value(&env, "GOOGLE_AUTH_TYPE").ok_or("no auth type")?;
    assert_eq!(
        (auth_type.0, auth_type.2),
        ("service_account", &json!(["output"]))
    );
    for absent in [
        "GOOGLE_OAUTH_ACCESS_TOKEN",
        "CLOUDSDK_ACTIVE_CONFIG_NAME",
        "GOOGLE_CLOUD_REGION",
    ] {
        assert!(env_value(&env, absent).is_none(), "{absent} was set");
    }

    let path = path.to_owned();
    app.ok("signOut", "signOutResult", json!({})).await?;
    assert!(!std::path::Path::new(&path).exists());
    app.error("env", json!({}), "notSignedIn").await?;
    app.ok("signOut", "signOutResult", json!({})).await?;
    Ok(())
}

#[tokio::test]
async fn a_key_file_is_read_from_its_absolute_path() -> TestResult {
    let dir = tempfile::tempdir()?;
    let key_file = dir.path().join("key.json");
    std::fs::write(&key_file, SA_KEY)?;
    let mut app = App::start(&[], &google(), FakeCrypto::default())?;
    app.configure(&dir.path().join("state")).await?;

    let fields = json!({"keyFile": key_file.to_str().ok_or("utf-8")?, "project": "quota-5678"});
    let identity = app
        .ok("signIn", "signInResult", sign_in("service_account", fields))
        .await?;
    assert_eq!(
        identity["targets"]["project"]["id"], "quota-5678",
        "the field wins"
    );

    let missing = json!({"keyFile": dir.path().join("gone.json").to_str().ok_or("utf-8")?});
    let error = app
        .error("signIn", sign_in("service_account", missing), "notSignedIn")
        .await?;
    assert!(
        error["message"]
            .as_str()
            .is_some_and(|m| m.contains("gone.json")),
        "{error}"
    );
    Ok(())
}

#[tokio::test]
async fn service_account_fields_are_checked_before_anything_is_read() -> TestResult {
    let dir = tempfile::tempdir()?;
    let mut app = App::start(&[], &google(), FakeCrypto::default())?;
    app.configure(dir.path()).await?;
    for (fields, expect) in [
        (json!({}), "keyFile"),
        (json!({"key": SA_KEY, "keyFile": "/k.json"}), "not both"),
        (json!({"keyFile": "relative/key.json"}), "absolute"),
        (
            json!({"key": SA_KEY, "region": "us-east1"}),
            "no field region",
        ),
        (
            json!({"key": "{\"type\":\"external_account\"}"}),
            "external_account",
        ),
        (
            json!({"key": "{\"type\":\"service_account\",\"client_email\":\"a@b\",\"private_key\":\"not-a-key\"}"}),
            "PKCS #8",
        ),
    ] {
        let error = app
            .error(
                "signIn",
                sign_in("service_account", fields.clone()),
                "invalidParams",
            )
            .await?;
        let message = error["message"].as_str().unwrap_or_default();
        assert!(message.contains(expect), "{fields}: {message}");
    }
    app.error("signIn", sign_in("sso", json!({})), "invalidParams")
        .await?;
    Ok(())
}

#[tokio::test]
async fn without_a_signer_a_service_account_sign_in_says_what_is_missing() -> TestResult {
    let dir = tempfile::tempdir()?;
    let mut app = App::start(&[], &google(), NoCrypto)?;
    app.configure(dir.path()).await?;
    let error = app
        .error(
            "signIn",
            sign_in("service_account", json!({"key": SA_KEY})),
            "internal",
        )
        .await?;
    let message = error["message"].as_str().unwrap_or_default();
    assert!(message.contains("cannot sign"), "{message}");
    Ok(())
}

#[tokio::test]
async fn a_revoked_key_is_expired_with_what_to_do() -> TestResult {
    let dir = tempfile::tempdir()?;
    let google = google();
    google.grant(
        "jwt",
        Err(runbooks_credential_google::OAuthError::InvalidGrant),
    );
    let mut app = App::start(&[], &google, FakeCrypto::default())?;
    app.configure(dir.path()).await?;
    let error = app
        .error(
            "signIn",
            sign_in("service_account", json!({"key": SA_KEY})),
            "expired",
        )
        .await?;
    let message: &Value = &error["message"];
    assert!(
        message
            .as_str()
            .is_some_and(|m| m.contains("Generate a new key")),
        "{error}"
    );
    Ok(())
}
