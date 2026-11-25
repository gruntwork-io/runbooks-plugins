use std::collections::HashMap;

use runbooks_credential_google::{GooglePlugin, Host, OAuthError};
use serde_json::json;

use crate::support::{
    App, BARE_TOKEN, FakeCrypto, OAUTH_CLIENT_ID, SA_KEY, SA_PRIVATE_KEY, STATE, TestResult,
    USER_ADC, USER_CLIENT_SECRET, USER_REFRESH_TOKEN, VERIFIER, WAIT, detect, gcloud_root, google,
    now, redirect, sign_in, start_oauth,
};

const CODE: &str = "SENTINEL-CODE";
const SECRETS: [&str; 6] = [
    SA_PRIVATE_KEY,
    USER_REFRESH_TOKEN,
    USER_CLIENT_SECRET,
    BARE_TOKEN,
    VERIFIER,
    CODE,
];

/// Every call, on its success and failure paths, with secrets in sign-in
/// fields, detection sources and gcloud's files. Only `env`'s result may
/// carry a secret.
#[tokio::test]
async fn no_line_but_envs_result_carries_a_secret() -> TestResult {
    let dir = tempfile::tempdir()?;
    let google = google();
    google.code(CODE, Ok(Some(USER_REFRESH_TOKEN)));
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
    let values = json!([{"kind": "values", "from": "creds", "values": {"GOOGLE_CREDENTIALS": format!("{{{SA_PRIVATE_KEY}")}}]);
    app.error("detect", detect(&values), "invalidParams")
        .await?;
    let typed = json!({"configuration": SA_PRIVATE_KEY});
    app.error("signIn", sign_in("gcloud", &typed), "invalidParams")
        .await?;
    let typed = json!({"configuration": "dev", SA_PRIVATE_KEY: "1"});
    app.error("signIn", sign_in("gcloud", &typed), "invalidParams")
        .await?;

    let half_client = json!({"clientSecret": USER_CLIENT_SECRET});
    app.error("signIn", sign_in("oauth", &half_client), "invalidParams")
        .await?;

    // The happy paths, ending in env.
    let fields = json!({"clientId": OAUTH_CLIENT_ID, "clientSecret": USER_CLIENT_SECRET});
    let (id, url) = start_oauth(&mut app, sign_in("oauth", &fields)).await?;
    let page = redirect(&url, &format!("state={STATE}&code={CODE}")).await?;
    for secret in SECRETS {
        assert!(
            !page.contains(secret),
            "the browser was shown {secret}: {page}"
        );
    }
    let response = app.response("signIn", id, WAIT).await?;
    assert!(response.get("result").is_some(), "{response}");
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
