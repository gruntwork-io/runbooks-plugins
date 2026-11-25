use serde_json::{Value, json};

use crate::support::{
    App, BARE_TOKEN, TestResult, USER_ADC, at, configure_params, detect, env_value, gcloud_root,
    google, rsa_key, sa_key, sign_in,
};

const REGION_NAMES: [&str; 3] = [
    "GOOGLE_CLOUD_REGION",
    "CLOUDSDK_COMPUTE_REGION",
    "GOOGLE_REGION",
];
const ZONE_NAMES: [&str; 2] = ["CLOUDSDK_COMPUTE_ZONE", "GOOGLE_ZONE"];

/// The value under each region name, then each zone name, in `env`'s result.
fn region_and_zone(env: &Value) -> Vec<Option<&str>> {
    REGION_NAMES
        .iter()
        .chain(&ZONE_NAMES)
        .map(|name| env_value(env, name).map(|value| value.0))
        .collect()
}

fn expected(region: Option<&'static str>, zone: Option<&'static str>) -> Vec<Option<&'static str>> {
    [region; 3].into_iter().chain([zone; 2]).collect()
}

#[tokio::test]
async fn the_blocks_region_and_zone_reach_a_run_under_every_name() -> TestResult {
    let dir = tempfile::tempdir()?;
    let mut app = App::start(&[], &google())?;
    let settings = json!({"defaultRegion": " us-east1 ", "defaultZone": "us-east1-b"});
    app.configure_with(dir.path(), &settings).await?;
    let key = sa_key(&rsa_key()?);
    app.ok(
        "signIn",
        "signInResult",
        sign_in("service_account", &json!({"key": key})),
    )
    .await?;

    let env = app.ok("env", "envResult", json!({})).await?;
    assert_eq!(
        region_and_zone(&env),
        expected(Some("us-east1"), Some("us-east1-b"))
    );
    for name in REGION_NAMES.iter().chain(&ZONE_NAMES) {
        let (_, sensitive, to) = env_value(&env, name).ok_or("unset")?;
        assert_eq!(
            (sensitive, to),
            (false, &json!(["env", "output"])),
            "{name}"
        );
    }
    Ok(())
}

/// As in the app, the block's region and zone each win over the ones that
/// came with the credential, and leave the other alone.
#[tokio::test]
async fn the_blocks_region_or_zone_wins_over_gclouds_and_the_environments() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = gcloud_root(dir.path(), Some(USER_ADC))?;
    let mut app = App::start(&[("CLOUDSDK_CONFIG", &root)], &google())?;
    app.configure_with(&dir.path().join("a"), &json!({"defaultRegion": "us-east1"}))
        .await?;
    app.ok("signIn", "signInResult", sign_in("gcloud", &json!({})))
        .await?;
    let env = app.ok("env", "envResult", json!({})).await?;
    assert_eq!(
        region_and_zone(&env),
        expected(Some("us-east1"), Some("europe-west1-b"))
    );

    let vars = [
        ("GOOGLE_OAUTH_ACCESS_TOKEN", BARE_TOKEN),
        ("CLOUDSDK_COMPUTE_REGION", "europe-west1"),
        ("CLOUDSDK_COMPUTE_ZONE", "europe-west1-b"),
    ];
    let mut app = App::start(&vars, &google())?;
    app.configure_with(&dir.path().join("b"), &json!({"defaultZone": "us-east1-c"}))
        .await?;
    app.ok("detect", "detectResult", detect(&json!([{"kind": "env"}])))
        .await?;
    let env = app.ok("env", "envResult", json!({})).await?;
    assert_eq!(
        region_and_zone(&env),
        expected(Some("europe-west1"), Some("us-east1-c"))
    );
    Ok(())
}

#[tokio::test]
async fn an_empty_setting_is_no_setting() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = gcloud_root(dir.path(), Some(USER_ADC))?;
    let mut app = App::start(&[("CLOUDSDK_CONFIG", &root)], &google())?;
    let settings = json!({"defaultRegion": " ", "defaultZone": ""});
    app.configure_with(&dir.path().join("state"), &settings)
        .await?;
    app.ok("signIn", "signInResult", sign_in("gcloud", &json!({})))
        .await?;
    let env = app.ok("env", "envResult", json!({})).await?;
    assert_eq!(
        region_and_zone(&env),
        expected(Some("europe-west1"), Some("europe-west1-b"))
    );
    Ok(())
}

/// Region and zone names follow Compute Engine's rule for a name.
#[tokio::test]
async fn a_region_or_zone_may_be_any_compute_engine_name() -> TestResult {
    let dir = tempfile::tempdir()?;
    let longest = format!("a{}", "-0".repeat(31));
    for (region, zone) in [
        ("me-central2", "u-germany-northeast1-a"),
        ("a", longest.as_str()),
    ] {
        let mut app = App::start(&[], &google())?;
        let settings = json!({"defaultRegion": region, "defaultZone": zone});
        app.configure_with(&dir.path().join(region), &settings)
            .await?;
        let key = sa_key(&rsa_key()?);
        app.ok(
            "signIn",
            "signInResult",
            sign_in("service_account", &json!({"key": key})),
        )
        .await?;
        let env = app.ok("env", "envResult", json!({})).await?;
        assert_eq!(
            env_value(&env, "CLOUDSDK_COMPUTE_ZONE").map(|value| value.0),
            Some(zone)
        );
    }
    Ok(())
}

/// The error names the setting and never shows its value, nor a name that
/// could be pasted material. Nothing is configured.
#[tokio::test]
async fn an_unknown_setting_or_a_bad_value_is_refused_by_name() -> TestResult {
    let dir = tempfile::tempdir()?;
    let too_long = format!("a{}", "-0".repeat(31));
    let too_long = format!("{too_long}0");
    let longest_name = format!("shown_{}", "x".repeat(58));
    let longest_named = format!("settings has no {longest_name};");
    for (settings, expect) in [
        (json!({"region": "us-east1"}), "settings has no region"),
        (json!({longest_name.as_str(): "1"}), longest_named.as_str()),
        (
            json!({format!("SENTINEL_{}", "X".repeat(56)): "1"}),
            "settings has no (a name that is not an identifier)",
        ),
        (
            json!({"zone": "us-east1-b", "defaultZone": "us-east1-b"}),
            "settings has no zone; this plugin's settings are defaultRegion and defaultZone",
        ),
        (
            json!({"SENTINEL VALUE": "1"}),
            "settings has no (a name that is not an identifier)",
        ),
        (
            json!({"defaultRegion": "SENTINEL-VALUE"}),
            "settings.defaultRegion must be a Google Cloud region",
        ),
        (
            json!({"defaultZone": "1sentinel-value"}),
            "settings.defaultZone must be a Google Cloud zone",
        ),
        (
            json!({"defaultRegion": "sentinel-value-"}),
            "settings.defaultRegion must",
        ),
        (
            json!({"defaultZone": "sentinel_value"}),
            "settings.defaultZone must",
        ),
        (
            json!({"defaultZone": too_long}),
            "settings.defaultZone must",
        ),
        (
            json!({"defaultRegion": "SENTINEL-VALUE", "defaultZone": "-"}),
            "region, such as us-central1: up to 63 lower case letters, digits and hyphens, starting with a letter and ending with a letter or digit; settings.defaultZone must",
        ),
    ] {
        let mut app = App::start(&[], &google())?;
        let error = app
            .error(
                "configure",
                configure_params(dir.path(), &settings)?,
                "invalidParams",
            )
            .await?;
        let message = at(&error, "/message");
        let message = message.as_str().unwrap_or_default();
        assert!(message.contains(expect), "{settings}: {message}");
        assert!(
            !message.to_lowercase().contains("sentinel") && !message.contains(&too_long),
            "{message}"
        );
        app.error("env", json!({}), "notConfigured").await?;
    }
    Ok(())
}
