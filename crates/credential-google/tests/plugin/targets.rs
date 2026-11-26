use runbooks_credential_google::MAX_PAGES;
use serde_json::{Value, json};

use crate::support::{App, Google, TestResult, USER_ADC, at, google, rsa_key, sa_key, sign_in};

fn ids(result: &Value) -> Vec<&str> {
    result["targets"]
        .as_array()
        .map_or_default(|targets| targets.iter().filter_map(|t| t["id"].as_str()).collect())
}

#[tokio::test]
async fn targets_lists_live_projects_across_pages_up_to_the_cap() -> TestResult {
    let dir = tempfile::tempdir()?;
    let google = google();
    google.project("going-away", "Going", Some("DELETE_REQUESTED"));
    for n in 0..600 {
        google.project(
            &format!("p-{n:03}"),
            &format!("Project {n}"),
            Some("ACTIVE"),
        );
    }
    let mut app = App::start(&[("GOOGLE_CREDENTIALS", USER_ADC)], &google)?;
    app.configure(dir.path()).await?;
    app.ok(
        "detect",
        "detectResult",
        json!({"sources": [{"kind": "env"}], "pins": {}, "requirements": []}),
    )
    .await?;

    let listed = app
        .ok("targets", "targetsResult", json!({"level": "project"}))
        .await?;
    let ids = ids(&listed);
    assert_eq!(ids.len(), runbooks_credential_google::MAX_PROJECTS);
    assert_eq!(
        ids.get(..3),
        Some(&["sandbox-1234", "quota-5678", "p-000"][..])
    );
    assert!(
        !ids.contains(&"going-away"),
        "a project pending deletion was listed"
    );
    assert_eq!(
        google.page_sizes(),
        [500, 1],
        "asks for no more than the cap"
    );
    Ok(())
}

#[tokio::test]
async fn targets_stops_at_the_page_cap_when_pages_never_end() -> TestResult {
    let dir = tempfile::tempdir()?;
    let google = google();
    google.endless();
    let mut app = App::start(&[("GOOGLE_CREDENTIALS", USER_ADC)], &google)?;
    app.configure(dir.path()).await?;
    app.ok(
        "detect",
        "detectResult",
        json!({"sources": [{"kind": "env"}], "pins": {}, "requirements": []}),
    )
    .await?;

    let error = app
        .error("targets", json!({"level": "project"}), "internal")
        .await?;
    assert_eq!(
        at(&error, "/message"),
        format!("searchProjects kept paging past {MAX_PAGES} pages")
    );
    assert_eq!(google.page_sizes().len(), MAX_PAGES);
    Ok(())
}

#[tokio::test]
async fn select_names_a_listed_project_and_env_follows_it() -> TestResult {
    let dir = tempfile::tempdir()?;
    let mut app = App::start(&[], &google())?;
    app.configure(dir.path()).await?;
    app.ok(
        "signIn",
        "signInResult",
        sign_in("service_account", &json!({"key": sa_key(&rsa_key()?)})),
    )
    .await?;
    app.ok("targets", "targetsResult", json!({"level": "project"}))
        .await?;

    let identity = app
        .ok(
            "select",
            "selectResult",
            json!({"targets": {"project": "quota-5678"}}),
        )
        .await?;
    assert_eq!(
        at(&identity, "/targets/project"),
        json!({"id": "quota-5678", "name": "Quota"})
    );
    let env = app.ok("env", "envResult", json!({})).await?;
    assert_eq!(
        crate::support::env_value(&env, "CLOUDSDK_CORE_PROJECT").map(|v| v.0),
        Some("quota-5678")
    );

    // An unlisted project is still selectable: a service account often can't list.
    let identity = app
        .ok(
            "select",
            "selectResult",
            json!({"targets": {"project": "typed-0001"}}),
        )
        .await?;
    assert_eq!(
        at(&identity, "/targets/project"),
        json!({"id": "typed-0001", "name": "typed-0001"})
    );
    Ok(())
}

#[tokio::test]
async fn a_pinned_project_cannot_be_changed_or_reached_without_access() -> TestResult {
    let dir = tempfile::tempdir()?;
    let google = google();
    google.deny("locked-9999");
    let mut app = App::start(&[], &google)?;
    app.configure(dir.path()).await?;

    let key = sa_key(&rsa_key()?);
    let pinned = |project: &str| json!({"method": "service_account", "fields": {"key": key}, "pins": {"project": project}, "requirements": []});
    app.error("signIn", pinned("locked-9999"), "pinMismatch")
        .await?;
    // An API that can't answer doesn't stop a pinned project.
    let identity = app
        .ok("signIn", "signInResult", pinned("unknown-0002"))
        .await?;
    assert_eq!(at(&identity, "/targets/project/id"), "unknown-0002");

    app.error(
        "select",
        json!({"targets": {"project": "sandbox-1234"}}),
        "pinMismatch",
    )
    .await?;
    let same = app
        .ok(
            "select",
            "selectResult",
            json!({"targets": {"project": "unknown-0002"}}),
        )
        .await?;
    assert_eq!(at(&same, "/targets/project/id"), "unknown-0002");
    Ok(())
}

#[tokio::test]
async fn targets_and_select_check_their_level_and_the_sign_in() -> TestResult {
    let dir = tempfile::tempdir()?;
    let mut app = App::start(&[], &Google::default())?;
    app.configure(dir.path()).await?;
    app.error("targets", json!({"level": "project"}), "notSignedIn")
        .await?;
    app.error(
        "select",
        json!({"targets": {"project": "p"}}),
        "notSignedIn",
    )
    .await?;
    app.error("targets", json!({"level": "account"}), "invalidParams")
        .await?;
    app.error(
        "select",
        json!({"targets": {"account": "1"}}),
        "invalidParams",
    )
    .await?;
    app.error("select", json!({"targets": {}}), "invalidParams")
        .await?;
    // The project level is not optional, so a null is no project.
    app.error(
        "select",
        json!({"targets": {"project": null}}),
        "invalidParams",
    )
    .await?;
    Ok(())
}
