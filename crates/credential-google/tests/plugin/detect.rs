use runbooks_credential_google::{OAuthError, TokenRequest};
use serde_json::{Value, json};

use crate::support::{
    App, BARE_TOKEN, CLOUD_PLATFORM, FakeCrypto, SA_EMAIL, SA_KEY, TestResult, USER_ADC,
    USER_CLIENT_SECRET, USER_EMAIL, USER_REFRESH_TOKEN, at, detect, env_value, google,
};

#[tokio::test]
async fn an_access_token_in_the_environment_is_found_with_its_expiry() -> TestResult {
    let dir = tempfile::tempdir()?;
    let env = [
        ("GOOGLE_OAUTH_ACCESS_TOKEN", BARE_TOKEN),
        ("GOOGLE_CLOUD_PROJECT", "sandbox-1234"),
        ("CLOUDSDK_COMPUTE_REGION", "europe-west1"),
    ];
    let mut app = App::start(&env, &google(), FakeCrypto::default())?;
    app.configure(dir.path()).await?;

    let found = app
        .ok("detect", "detectResult", detect(&json!([{"kind": "env"}])))
        .await?;
    assert_eq!(at(&found, "/found"), true);
    assert_eq!(at(&found, "/source"), "env");
    let identity = at(&found, "/identity");
    assert_eq!(
        (at(&identity, "/principal"), at(&identity, "/kind")),
        (json!(USER_EMAIL), json!("user"))
    );
    assert_eq!(at(&identity, "/method"), "env");
    assert_eq!(at(&identity, "/targets/project/name"), "Sandbox");
    assert_eq!(
        at(&identity, "/expiresAt"),
        "2027-01-15T08:30:00Z",
        "{identity}"
    );

    let env = app.ok("env", "envResult", json!({})).await?;
    for name in ["GOOGLE_OAUTH_ACCESS_TOKEN", "CLOUDSDK_AUTH_ACCESS_TOKEN"] {
        let (value, sensitive, to) = env_value(&env, name).ok_or("no token")?;
        assert_eq!(
            (value, sensitive, to),
            (BARE_TOKEN, true, &json!(["env"])),
            "{name}"
        );
    }
    assert!(env_value(&env, "GOOGLE_APPLICATION_CREDENTIALS").is_none());
    assert!(env_value(&env, "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE").is_none());
    assert_eq!(
        env_value(&env, "CLOUDSDK_COMPUTE_REGION").map(|v| v.0),
        Some("europe-west1")
    );
    assert_eq!(
        env_value(&env, "GOOGLE_AUTH_TYPE").map(|v| v.0),
        Some("access_token")
    );
    assert_eq!(at(&env, "/expiresAt"), at(&identity, "/expiresAt"));
    Ok(())
}

#[tokio::test]
async fn nothing_set_is_not_found_and_a_project_alone_is_nothing() -> TestResult {
    let dir = tempfile::tempdir()?;
    let mut app = App::start(
        &[("GOOGLE_CLOUD_PROJECT", "p")],
        &google(),
        FakeCrypto::default(),
    )?;
    app.configure(dir.path()).await?;
    let result = app
        .ok("detect", "detectResult", detect(&json!([{"kind": "env"}])))
        .await?;
    assert_eq!(result, json!({"found": false}));
    app.error("env", json!({}), "notSignedIn").await?;
    Ok(())
}

#[tokio::test]
async fn a_file_in_the_environment_is_copied_into_the_state_dir() -> TestResult {
    let dir = tempfile::tempdir()?;
    let adc = dir.path().join("application_default_credentials.json");
    std::fs::write(&adc, USER_ADC)?;
    let adc_path = adc.to_str().ok_or("utf-8")?;
    let google = google();
    let mut app = App::start(
        &[("GOOGLE_APPLICATION_CREDENTIALS", adc_path)],
        &google,
        FakeCrypto::default(),
    )?;
    let state = dir.path().join("state");
    app.configure(&state).await?;

    let found = app
        .ok("detect", "detectResult", detect(&json!([{"kind": "env"}])))
        .await?;
    assert_eq!(
        at(&found, "/identity/targets/project/id"),
        "quota-5678",
        "the quota project"
    );
    assert!(matches!(
        google.token_requests().as_slice(),
        [TokenRequest::Refresh { client_id, client_secret, refresh_token }]
            if client_id == "client.apps.googleusercontent.com"
                && client_secret.expose() == USER_CLIENT_SECRET
                && refresh_token.expose() == USER_REFRESH_TOKEN
    ));

    let env = app.ok("env", "envResult", json!({})).await?;
    let (path, _, _) = env_value(&env, "GOOGLE_APPLICATION_CREDENTIALS").ok_or("no file")?;
    assert!(std::path::Path::new(path).starts_with(&state), "{path}");
    assert_eq!(std::fs::read_to_string(path)?, USER_ADC);
    assert_eq!(
        env_value(&env, "GOOGLE_AUTH_TYPE").map(|v| v.0),
        Some("authorized_user")
    );

    app.ok("signOut", "signOutResult", json!({})).await?;
    assert!(adc.exists(), "signOut deleted the person's own file");
    Ok(())
}

#[tokio::test]
async fn an_earlier_blocks_values_are_a_source() -> TestResult {
    let dir = tempfile::tempdir()?;
    let mut app = App::start(&[], &google(), FakeCrypto::default())?;
    app.configure(dir.path()).await?;
    let values = json!({"GOOGLE_CREDENTIALS": SA_KEY, "GOOGLE_PROJECT": "quota-5678"});
    let found = app
        .ok(
            "detect",
            "detectResult",
            detect(&json!([{"kind": "values", "from": "creds", "values": values}])),
        )
        .await?;
    assert_eq!(at(&found, "/source"), "creds");
    assert_eq!(at(&found, "/identity/method"), "values");
    assert_eq!(at(&found, "/identity/principal"), SA_EMAIL);
    assert_eq!(at(&found, "/identity/targets/project/id"), "quota-5678");
    Ok(())
}

#[tokio::test]
async fn a_prefix_reads_its_own_names_and_a_bad_one_is_refused_before_any_read() -> TestResult {
    let dir = tempfile::tempdir()?;
    let env = [
        ("GOOGLE_OAUTH_ACCESS_TOKEN", BARE_TOKEN),
        ("CI_GOOGLE_CREDENTIALS", SA_KEY),
    ];
    let mut app = App::start(&env, &google(), FakeCrypto::default())?;
    app.configure(dir.path()).await?;
    let found = app
        .ok(
            "detect",
            "detectResult",
            detect(&json!([{"kind": "env", "prefix": "CI_"}])),
        )
        .await?;
    assert_eq!(at(&found, "/identity/principal"), SA_EMAIL);

    let sources = json!([{"kind": "env"}, {"kind": "env", "prefix": "ci-"}, {"kind": "named", "name": "keychain"}]);
    let error = app
        .error("detect", detect(&sources), "invalidParams")
        .await?;
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(
        message.contains("\"ci-\"") && message.contains("\"keychain\""),
        "{message}"
    );
    Ok(())
}

#[tokio::test]
async fn a_credential_that_fails_is_skipped_for_the_next_source() -> TestResult {
    let dir = tempfile::tempdir()?;
    let google = google();
    google.grant(USER_REFRESH_TOKEN, Err(OAuthError::InvalidGrant));
    let env = [
        ("GOOGLE_CREDENTIALS", USER_ADC),
        ("CI_GOOGLE_OAUTH_ACCESS_TOKEN", BARE_TOKEN),
    ];
    let mut app = App::start(&env, &google, FakeCrypto::default())?;
    app.configure(dir.path()).await?;

    let sources = json!([{"kind": "env"}, {"kind": "env", "prefix": "CI_"}]);
    let found = app.ok("detect", "detectResult", detect(&sources)).await?;
    assert_eq!(at(&found, "/identity/principal"), USER_EMAIL);
    assert_eq!(at(&found, "/identity/method"), "env");

    // With nothing after it, the failure is the answer, saying what to do.
    let error = app
        .error("detect", detect(&json!([{"kind": "env"}])), "expired")
        .await?;
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(
        message.contains("gcloud auth application-default login"),
        "{message}"
    );
    Ok(())
}

#[tokio::test]
async fn a_user_credential_missing_a_required_scope_stops_detection() -> TestResult {
    let dir = tempfile::tempdir()?;
    let admin = "https://www.googleapis.com/auth/admin.directory.user";
    let env = [
        ("GOOGLE_CREDENTIALS", USER_ADC),
        ("CI_GOOGLE_CREDENTIALS", SA_KEY),
    ];
    let mut app = App::start(&env, &google(), FakeCrypto::default())?;
    app.configure(dir.path()).await?;

    let params = json!({
        "sources": [{"kind": "env"}, {"kind": "env", "prefix": "CI_"}],
        "pins": {},
        "requirements": [{"kind": "scopes", "scopes": [CLOUD_PLATFORM, admin]}],
    });
    let error = app.error("detect", params, "requirementNotMet").await?;
    assert_eq!(
        at(&error, "/data/unmet"),
        json!([{"kind": "scopes", "scopes": [admin]}])
    );
    crate::support::assert_valid("requirementNotMetData", &at(&error, "/data"))?;

    // A service account is exempt: its tokens are cloud-platform only.
    let params = json!({
        "sources": [{"kind": "env", "prefix": "CI_"}],
        "pins": {},
        "requirements": [{"kind": "scopes", "scopes": [admin]}],
    });
    let found = app.ok("detect", "detectResult", params).await?;
    assert_eq!(at(&found, "/identity/kind"), "serviceAccount");
    Ok(())
}

#[tokio::test]
async fn the_pinned_project_wins_and_one_the_identity_cannot_read_does_not_match() -> TestResult {
    let dir = tempfile::tempdir()?;
    let google = google();
    google.deny("locked-9999");
    let env = [
        ("GOOGLE_CREDENTIALS", USER_ADC),
        ("GOOGLE_CLOUD_PROJECT", "quota-5678"),
    ];
    let mut app = App::start(&env, &google, FakeCrypto::default())?;
    app.configure(dir.path()).await?;

    let pinned = |project: &str| json!({"sources": [{"kind": "env"}], "pins": {"project": project}, "requirements": []});
    let found = app
        .ok("detect", "detectResult", pinned("sandbox-1234"))
        .await?;
    assert_eq!(at(&found, "/identity/targets/project/id"), "sandbox-1234");

    let error = app
        .error("detect", pinned("locked-9999"), "pinMismatch")
        .await?;
    assert!(
        at(&error, "/message")
            .as_str()
            .is_some_and(|m| m.contains("locked-9999")),
        "{error}"
    );

    let bad_level = json!({"sources": [], "pins": {"account": "1"}, "requirements": []});
    app.error("detect", bad_level, "invalidParams").await?;
    Ok(())
}
