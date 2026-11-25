//! A resumed session: after the app restarts, a new plugin process with the
//! block's own stateDir detects from the values its `env` gave before, from
//! the block's own id.

use serde_json::{Map, Value, json};

use crate::support::{
    App, BARE_TOKEN, TestResult, USER_ADC, at, detect, gcloud_root, google, sign_in,
};

const BLOCK: &str = "gcp-auth";

/// `env`'s values by name, as the engine saves them.
fn saved(env: &Value) -> TestResult<Map<String, Value>> {
    let mut values = Map::new();
    for value in env["values"].as_array().ok_or("no values")? {
        let name = value["name"].as_str().ok_or("no name")?;
        values.insert(name.to_owned(), value["value"].clone());
    }
    Ok(values)
}

fn own_values(values: &Map<String, Value>) -> Value {
    detect(&json!([{"kind": "values", "from": BLOCK, "values": values}]))
}

/// gcloud's configuration other than the active one: a run's gcloud must
/// still use it after the restart.
#[tokio::test]
async fn a_new_process_takes_back_the_blocks_own_login() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = gcloud_root(dir.path(), Some(USER_ADC))?;
    let env = [("CLOUDSDK_CONFIG", root.as_str())];
    let state = dir.path().join("state");
    let google = google();
    let mut app = App::start(&env, &google)?;
    app.configure(&state).await?;
    let identity = app
        .ok(
            "signIn",
            "signInResult",
            sign_in("gcloud", &json!({"configuration": "default"})),
        )
        .await?;
    let given = app.ok("env", "envResult", json!({})).await?;
    app.close().await?;

    let mut resumed = App::start(&env, &google)?;
    resumed.configure(&state).await?;
    let found = resumed
        .ok("detect", "detectResult", own_values(&saved(&given)?))
        .await?;
    assert_eq!(at(&found, "/source"), BLOCK);
    for field in ["/principal", "/kind", "/targets", "/expiresAt"] {
        assert_eq!(
            at(&found, &format!("/identity{field}")),
            at(&identity, field),
            "{field}"
        );
    }
    assert_eq!(resumed.ok("env", "envResult", json!({})).await?, given);
    Ok(())
}

#[tokio::test]
async fn another_clouds_values_or_a_changed_token_are_no_login() -> TestResult {
    let dir = tempfile::tempdir()?;
    let google = google();
    let mut app = App::start(&[], &google)?;
    app.configure(dir.path()).await?;
    let aws = Map::from_iter([
        ("AWS_ACCESS_KEY_ID".to_owned(), json!("AKIATESTKEY")),
        (
            "AWS_SECRET_ACCESS_KEY".to_owned(),
            json!("test-secret-access-key"),
        ),
        ("AWS_REGION".to_owned(), json!("eu-west-1")),
    ]);
    let found = app.ok("detect", "detectResult", own_values(&aws)).await?;
    assert_eq!(found, json!({"found": false}));
    app.close().await?;

    let mut app = App::start(&[("GOOGLE_OAUTH_ACCESS_TOKEN", BARE_TOKEN)], &google)?;
    app.configure(dir.path()).await?;
    app.ok("detect", "detectResult", detect(&json!([{"kind": "env"}])))
        .await?;
    let mut values = saved(&app.ok("env", "envResult", json!({})).await?)?;
    app.close().await?;
    let changed = "ya29.SENTINEL-CHANGED-TOKEN";
    for name in ["GOOGLE_OAUTH_ACCESS_TOKEN", "CLOUDSDK_AUTH_ACCESS_TOKEN"] {
        values.insert(name.to_owned(), json!(changed));
    }

    let mut resumed = App::start(&[], &google)?;
    resumed.configure(dir.path()).await?;
    let response = resumed.call("detect", own_values(&values)).await?;
    assert_ne!(at(&response, "/result/found"), true, "{response}");
    resumed.error("env", json!({}), "notSignedIn").await?;
    for (_, line) in resumed.close().await? {
        assert!(!line.contains(changed), "{line}");
    }
    Ok(())
}
