use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use runbooks_credential_google::{TOKEN_URL, TokenRequest};
use serde_json::{Value, json};

use crate::support::{
    App, CLOUD_PLATFORM, NOW, SA_EMAIL, TestResult, USER_ADC, at, ec_key, env_value, google,
    rsa_key, runbooks_limits, sa_key, sign_in, verifies,
};

#[tokio::test]
async fn configure_offers_the_methods_project_level_scopes_and_every_name() -> TestResult {
    let dir = tempfile::tempdir()?;
    let mut app = App::start(&[], &google())?;
    let offered = app.configure(dir.path()).await?;
    assert_eq!(at(&offered, "/cloud"), "gcp");
    assert_eq!(at(&offered, "/methods/0/name"), "service_account");
    let key = at(&offered, "/methods/0/fields/0");
    assert_eq!(
        (at(&key, "/name"), at(&key, "/secret")),
        (json!("key"), json!(true))
    );
    assert_eq!(
        at(&offered, "/levels"),
        json!([{"name": "project", "label": "Project", "chosen": "afterSignIn"}])
    );
    assert_eq!(at(&offered, "/requirements"), json!(["scopes"]));
    let names = offered
        .get("names")
        .and_then(Value::as_array)
        .ok_or("no names")?;
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
    let mut app = App::start(&[], &google())?;
    let params = json!({"protocolVersion": "1", "caller": "runbooks/0.31.0", "stateDir": "state/block", "callTimeoutsMillis": runbooks_limits()});
    let error = app.error("configure", params, "invalidParams").await?;
    assert!(
        at(&error, "/message")
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
    let mut app = App::start(&[], &google)?;
    app.configure(dir.path()).await?;

    let private_key = rsa_key()?;
    let identity = app
        .ok(
            "signIn",
            "signInResult",
            sign_in("service_account", &json!({"key": sa_key(&private_key)})),
        )
        .await?;
    assert_eq!(at(&identity, "/principal"), SA_EMAIL);
    assert_eq!(at(&identity, "/kind"), "serviceAccount");
    assert_eq!(at(&identity, "/method"), "service_account");
    assert_eq!(
        at(&identity, "/targets/project"),
        json!({"id": "sandbox-1234", "name": "Sandbox"})
    );
    assert!(identity.get("expiresAt").is_none(), "{identity}");

    // Google gets an RS256 JWT the key signed, for its own token endpoint
    // whatever the key says.
    let requests = google.token_requests();
    let [TokenRequest::JwtBearer { assertion }] = requests.as_slice() else {
        return Err(format!("{requests:?}").into());
    };
    let (signed, signature) = assertion.expose().rsplit_once('.').ok_or("no signature")?;
    let signature = URL_SAFE_NO_PAD.decode(signature)?;
    assert!(verifies(&private_key, signed.as_bytes(), &signature)?);
    assert!(!verifies(&rsa_key()?, signed.as_bytes(), &signature)?);
    let (header, claims) = signed.split_once('.').ok_or("no claims")?;
    let decode = |part: &str| -> TestResult<Value> {
        Ok(serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part)?)?)
    };
    assert_eq!(decode(header)?, json!({"alg": "RS256", "typ": "JWT"}));
    assert_eq!(
        decode(claims)?,
        json!({
            "iss": SA_EMAIL,
            "aud": TOKEN_URL,
            "scope": CLOUD_PLATFORM,
            "iat": NOW,
            "exp": NOW + 3600,
        })
    );
    Ok(())
}

#[tokio::test]
async fn env_points_a_run_at_a_private_copy_of_the_key_and_sign_out_deletes_it() -> TestResult {
    let dir = tempfile::tempdir()?;
    let mut app = App::start(&[], &google())?;
    app.configure(dir.path()).await?;
    let key = sa_key(&rsa_key()?);
    app.ok(
        "signIn",
        "signInResult",
        sign_in("service_account", &json!({"key": key})),
    )
    .await?;

    let env = app.ok("env", "envResult", json!({})).await?;
    let (path, sensitive, to) =
        env_value(&env, "GOOGLE_APPLICATION_CREDENTIALS").ok_or("no credentials file")?;
    assert!(!sensitive);
    assert_eq!(to, &json!(["env", "output"]));
    assert!(std::path::Path::new(path).starts_with(dir.path()), "{path}");
    assert_eq!(std::fs::read_to_string(path)?, key);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(path)?.permissions().mode() & 0o777, 0o600);
    }
    let bridge =
        env_value(&env, "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE").ok_or("no gcloud bridge")?;
    assert_eq!(bridge.0, path);
    let mut files: Vec<&str> = env
        .get("values")
        .and_then(Value::as_array)
        .ok_or("no values")?
        .iter()
        .filter(|value| value["file"] == true)
        .filter_map(|value| value["name"].as_str())
        .collect();
    files.sort_unstable();
    assert_eq!(
        files,
        [
            "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE",
            "GOOGLE_APPLICATION_CREDENTIALS"
        ]
    );
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
    std::fs::write(&key_file, sa_key(&rsa_key()?))?;
    let mut app = App::start(&[], &google())?;
    app.configure(&dir.path().join("state")).await?;

    let fields = json!({"keyFile": key_file.to_str().ok_or("utf-8")?, "project": "quota-5678"});
    let identity = app
        .ok(
            "signIn",
            "signInResult",
            sign_in("service_account", &fields),
        )
        .await?;
    assert_eq!(
        at(&identity, "/targets/project/id"),
        "quota-5678",
        "the field wins"
    );

    let missing = json!({"keyFile": dir.path().join("gone.json").to_str().ok_or("utf-8")?});
    let error = app
        .error(
            "signIn",
            sign_in("service_account", &missing),
            "notSignedIn",
        )
        .await?;
    assert!(
        at(&error, "/message")
            .as_str()
            .is_some_and(|m| m.contains("gone.json")),
        "{error}"
    );
    Ok(())
}

#[tokio::test]
async fn service_account_fields_are_checked_before_anything_is_read() -> TestResult {
    let dir = tempfile::tempdir()?;
    let mut app = App::start(&[], &google())?;
    app.configure(dir.path()).await?;
    let key = sa_key(&rsa_key()?);
    let user_file = dir.path().join("user.json");
    std::fs::write(&user_file, USER_ADC)?;
    for (fields, expect) in [
        (json!({}), "keyFile"),
        (json!({"key": key, "keyFile": "/k.json"}), "not both"),
        (json!({"keyFile": "relative/key.json"}), "absolute"),
        (json!({"key": key, "region": "us-east1"}), "no field region"),
        (
            json!({"key": "{\"type\":\"external_account\"}"}),
            "has type \"external_account\": expected a service account key",
        ),
        (
            json!({"key": USER_ADC}),
            "has type \"authorized_user\": expected a service account key",
        ),
        (
            json!({"keyFile": user_file.to_str().ok_or("utf-8")?}),
            "has type \"authorized_user\": expected a service account key",
        ),
        (
            json!({"key": "{\"type\":\"authorized_user\",\"client_id\":\"c\"}"}),
            "has type \"authorized_user\": expected a service account key",
        ),
        (
            json!({"key": "{\"type\":\"service_account\",\"client_email\":\"a@b\",\"private_key\":\"not-a-key\"}"}),
            "PKCS #8",
        ),
        (
            json!({"key": sa_key(&ec_key()?)}),
            "private_key is not a PKCS #8 RSA key",
        ),
    ] {
        let error = app
            .error(
                "signIn",
                sign_in("service_account", &fields),
                "invalidParams",
            )
            .await?;
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(message.contains(expect), "{fields}: {message}");
    }
    app.error("signIn", sign_in("sso", &json!({})), "invalidParams")
        .await?;
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
    let mut app = App::start(&[], &google)?;
    app.configure(dir.path()).await?;
    let error = app
        .error(
            "signIn",
            sign_in("service_account", &json!({"key": sa_key(&rsa_key()?)})),
            "expired",
        )
        .await?;
    let message = at(&error, "/message");
    assert!(
        message
            .as_str()
            .is_some_and(|m| m.contains("Generate a new key")),
        "{error}"
    );
    Ok(())
}
