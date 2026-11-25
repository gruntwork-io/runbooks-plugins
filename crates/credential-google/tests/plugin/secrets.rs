use std::collections::HashMap;

use runbooks_credential_google::{GooglePlugin, Host, OAuthError};
use serde_json::json;

use crate::support::{
    App, BARE_TOKEN, FakeCrypto, SA_KEY, SA_PRIVATE_KEY, TestResult, USER_ADC, USER_CLIENT_SECRET,
    USER_REFRESH_TOKEN, detect, gcloud_root, google, now, sign_in,
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
    let half_key = SA_KEY.get(..SA_KEY.len() / 2).ok_or("SA_KEY is ASCII")?;
    app.error(
        "signIn",
        sign_in("service_account", &json!({"key": half_key})),
        "invalidParams",
    )
    .await?;
    let typo = json!({"key": SA_KEY, format!("x{SA_PRIVATE_KEY}"): "1"});
    app.error("signIn", sign_in("service_account", &typo), "invalidParams")
        .await?;
    let unsupported = json!({"key": format!("{{\"type\":\"{SA_PRIVATE_KEY}\"}}")});
    app.error(
        "signIn",
        sign_in("service_account", &unsupported),
        "invalidParams",
    )
    .await?;
    let values = json!([{"kind": "values", "values": {"GOOGLE_CREDENTIALS": format!("{{{SA_PRIVATE_KEY}")}}]);
    app.error("detect", detect(&values), "invalidParams")
        .await?;
    let typed = json!({"configuration": SA_PRIVATE_KEY});
    app.error("signIn", sign_in("gcloud", &typed), "invalidParams")
        .await?;
    let typed = json!({"configuration": "dev", SA_PRIVATE_KEY: "1"});
    app.error("signIn", sign_in("gcloud", &typed), "invalidParams")
        .await?;

    // The happy paths, ending in env.
    app.ok("detect", "detectResult", detect(&json!([{"kind": "env"}])))
        .await?;
    let gcloud = json!([{"kind": "named", "name": "adc"}, {"kind": "named", "name": "gcloud"}]);
    app.ok("detect", "detectResult", detect(&gcloud)).await?;
    app.ok("signIn", "signInResult", sign_in("gcloud", &json!({})))
        .await?;
    app.ok(
        "signIn",
        "signInResult",
        sign_in("service_account", &json!({"key": SA_KEY})),
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
        detect(&json!([{"kind": "env", "prefix": "CI_"}])),
        "accessDenied",
    )
    .await?;
    app.error("signIn", sign_in("gcloud", &json!({})), "accessDenied")
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

/// The host's environment may hold a credential, so its Debug names the
/// variables and shows no value.
#[test]
fn the_hosts_debug_names_its_variables_but_shows_no_value() {
    let host = Host {
        env: HashMap::from([(
            "GOOGLE_OAUTH_ACCESS_TOKEN".to_owned(),
            BARE_TOKEN.to_owned(),
        )]),
        now,
    };
    let shown = format!("{host:?}");
    assert!(shown.contains("GOOGLE_OAUTH_ACCESS_TOKEN"), "{shown}");
    assert!(!shown.contains(BARE_TOKEN), "Host's Debug shows the token");
}

/// The plugin holds the host's environment and, once signed in, the
/// session, so its Debug names it and shows nothing it holds.
#[test]
fn the_plugins_debug_names_it_and_shows_nothing_it_holds() {
    let host = Host {
        env: HashMap::from([(
            "GOOGLE_OAUTH_ACCESS_TOKEN".to_owned(),
            BARE_TOKEN.to_owned(),
        )]),
        now,
    };
    let google = google();
    let plugin = GooglePlugin::new(
        host,
        Box::new(move |_network| Ok(google.clone())),
        FakeCrypto::default(),
    );
    assert_eq!(format!("{plugin:?}"), "GooglePlugin { .. }");
}
