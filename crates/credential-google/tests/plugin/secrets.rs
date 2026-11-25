use runbooks_credential_google::OAuthError;
use serde_json::json;

use crate::support::{
    App, BARE_TOKEN, FakeCrypto, SA_KEY, SA_PRIVATE_KEY, TestResult, USER_ADC, USER_CLIENT_SECRET,
    USER_REFRESH_TOKEN, detect, gcloud_root, google, sign_in,
};

const SECRETS: [&str; 4] = [
    SA_PRIVATE_KEY,
    USER_REFRESH_TOKEN,
    USER_CLIENT_SECRET,
    BARE_TOKEN,
];

/// Every call, on its success and failure paths, with secrets in sign-in
/// fields, detection sources and gcloud's files. Only `env`'s result may
/// carry a secret.
#[tokio::test]
async fn no_line_but_envs_result_carries_a_secret() -> TestResult {
    let dir = tempfile::tempdir()?;
    let google = google();
    let root = gcloud_root(dir.path(), Some(USER_ADC))?;
    let env = [
        ("GOOGLE_OAUTH_ACCESS_TOKEN", BARE_TOKEN),
        ("CI_GOOGLE_CREDENTIALS", USER_ADC),
        ("CLOUDSDK_CONFIG", root.as_str()),
    ];
    let mut app = App::start(&env, &google, FakeCrypto::default())?;
    app.configure(&dir.path().join("state")).await?;

    // Malformed material, typed and detected.
    let half_key = &SA_KEY[..SA_KEY.len() / 2];
    app.error(
        "signIn",
        sign_in("service_account", json!({"key": half_key})),
        "invalidParams",
    )
    .await?;
    let typo = json!({"key": SA_KEY, format!("x{SA_PRIVATE_KEY}"): "1"});
    app.error("signIn", sign_in("service_account", typo), "invalidParams")
        .await?;
    let unsupported = json!({"key": format!("{{\"type\":\"{SA_PRIVATE_KEY}\"}}")});
    app.error(
        "signIn",
        sign_in("service_account", unsupported),
        "invalidParams",
    )
    .await?;
    let values = json!([{"kind": "values", "values": {"GOOGLE_CREDENTIALS": format!("{{{SA_PRIVATE_KEY}")}}]);
    app.error("detect", detect(values), "invalidParams").await?;
    let typed = json!({"configuration": SA_PRIVATE_KEY});
    app.error("signIn", sign_in("gcloud", typed), "invalidParams")
        .await?;
    let typed = json!({"configuration": "dev", SA_PRIVATE_KEY: "1"});
    app.error("signIn", sign_in("gcloud", typed), "invalidParams")
        .await?;

    // The happy paths, ending in env.
    app.ok("detect", "detectResult", detect(json!([{"kind": "env"}])))
        .await?;
    let gcloud = json!([{"kind": "named", "name": "adc"}, {"kind": "named", "name": "gcloud"}]);
    app.ok("detect", "detectResult", detect(gcloud)).await?;
    app.ok("signIn", "signInResult", sign_in("gcloud", json!({})))
        .await?;
    app.ok(
        "signIn",
        "signInResult",
        sign_in("service_account", json!({"key": SA_KEY})),
    )
    .await?;
    app.ok("targets", "targetsResult", json!({"level": "project"}))
        .await?;
    app.ok(
        "select",
        "selectResult",
        json!({"targets": {"project": "sandbox-1234"}}),
    )
    .await?;
    app.ok("env", "envResult", json!({})).await?;
    app.ok("signOut", "signOutResult", json!({})).await?;

    // Material Google refuses.
    google.grant(USER_REFRESH_TOKEN, Err(OAuthError::InvalidClient));
    app.error(
        "detect",
        detect(json!([{"kind": "env", "prefix": "CI_"}])),
        "accessDenied",
    )
    .await?;
    app.error("signIn", sign_in("gcloud", json!({})), "accessDenied")
        .await?;

    let transcript = app.close().await?;
    assert!(transcript.len() >= 17, "{}", transcript.len());
    for (method, line) in &transcript {
        if method == "env" {
            continue;
        }
        for secret in SECRETS {
            assert!(!line.contains(secret), "{method} wrote {secret}: {line}");
        }
    }
    Ok(())
}
