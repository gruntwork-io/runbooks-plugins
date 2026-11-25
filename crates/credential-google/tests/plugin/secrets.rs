use std::collections::HashMap;

use runbooks_credential_google::{GooglePlugin, Host, OAuthError, TokenRequest};
use serde_json::json;

use crate::support::{
    App, BARE_TOKEN, OAUTH_CLIENT_ID, TestResult, USER_ADC, USER_CLIENT_SECRET, USER_REFRESH_TOKEN,
    WAIT, detect, gcloud_root, google, now, query, redirect, rsa_key, sa_key, sign_in, start_oauth,
};

const CODE: &str = "SENTINEL-CODE";
/// Typed where key material goes: in a field's name, a type, a document.
const TYPED_KEY: &str = "SENTINEL-PRIVATE-KEY";

/// Sends malformed material, typed and detected, around service account
/// `key`.
async fn refuse_malformed_material(app: &mut App, key: &str) -> TestResult {
    let half_key = key.get(..key.len() / 2).ok_or("the key is ASCII")?;
    app.error(
        "signIn",
        sign_in("service_account", &json!({"key": half_key})),
        "invalidParams",
    )
    .await?;
    let typo = json!({"key": key, format!("x{TYPED_KEY}"): "1"});
    app.error("signIn", sign_in("service_account", &typo), "invalidParams")
        .await?;
    let unsupported = json!({"key": format!("{{\"type\":\"{TYPED_KEY}\"}}")});
    app.error(
        "signIn",
        sign_in("service_account", &unsupported),
        "invalidParams",
    )
    .await?;
    let values = json!([{"kind": "values", "from": "creds", "values": {"GOOGLE_CREDENTIALS": format!("{{{TYPED_KEY}")}}]);
    app.error("detect", detect(&values), "invalidParams")
        .await?;
    let typed = json!({"configuration": TYPED_KEY});
    app.error("signIn", sign_in("gcloud", &typed), "invalidParams")
        .await?;
    let typed = json!({"configuration": "dev", TYPED_KEY: "1"});
    app.error("signIn", sign_in("gcloud", &typed), "invalidParams")
        .await?;
    let half_client = json!({"clientSecret": USER_CLIENT_SECRET});
    app.error("signIn", sign_in("oauth", &half_client), "invalidParams")
        .await?;
    Ok(())
}

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
    let mut app = App::start(&env, &google)?;
    app.configure(&dir.path().join("state")).await?;
    let private_key = rsa_key()?;
    let key = sa_key(&private_key);
    refuse_malformed_material(&mut app, &key).await?;

    // The happy paths, ending in env.
    let fields = json!({"clientId": OAUTH_CLIENT_ID, "clientSecret": USER_CLIENT_SECRET});
    let (id, url) = start_oauth(&mut app, sign_in("oauth", &fields)).await?;
    let state = query(&url, "state").ok_or("no state")?;
    let page = redirect(&url, &format!("state={state}&code={CODE}")).await?;
    let response = app.response("signIn", id, WAIT).await?;
    assert!(response.get("result").is_some(), "{response}");
    let requests = google.token_requests();
    let Some(TokenRequest::AuthorizationCode { code_verifier, .. }) = requests.first() else {
        return Err(format!("{requests:?}").into());
    };
    let mut secrets = vec![
        TYPED_KEY,
        USER_REFRESH_TOKEN,
        USER_CLIENT_SECRET,
        BARE_TOKEN,
        CODE,
        code_verifier.expose(),
    ];
    secrets.extend(
        private_key
            .lines()
            .filter(|line| !line.starts_with("-----")),
    );
    for secret in &secrets {
        assert!(
            !page.contains(secret),
            "the browser was shown {secret}: {page}"
        );
    }
    app.ok("detect", "detectResult", detect(&json!([{"kind": "env"}])))
        .await?;
    let gcloud = json!([{"kind": "named", "name": "adc"}, {"kind": "named", "name": "gcloud"}]);
    app.ok("detect", "detectResult", detect(&gcloud)).await?;
    app.ok("signIn", "signInResult", sign_in("gcloud", &json!({})))
        .await?;
    app.ok(
        "signIn",
        "signInResult",
        sign_in("service_account", &json!({"key": key})),
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
        for secret in &secrets {
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
    let plugin = GooglePlugin::new(host, Box::new(move |_network| Ok(google.clone())));
    assert_eq!(format!("{plugin:?}"), "GooglePlugin { .. }");
}
