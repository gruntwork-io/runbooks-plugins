use std::time::Duration;

use runbooks_credential_google::{NoCrypto, OAuthError, TokenRequest};
use serde_json::{Value, json};

use crate::support::{
    App, CHALLENGE, CLOUD_PLATFORM, FakeCrypto, OAUTH_CLIENT_ID, STATE, TestResult,
    USER_CLIENT_SECRET, USER_EMAIL, USER_REFRESH_TOKEN, VERIFIER, at, env_value, google, query,
    redirect, request, sign_in, start_oauth,
};

fn client_fields() -> Value {
    json!({"clientId": OAUTH_CLIENT_ID, "clientSecret": USER_CLIENT_SECRET})
}

#[tokio::test]
async fn a_browser_sign_in_ends_in_a_credential_that_refreshes_itself() -> TestResult {
    let dir = tempfile::tempdir()?;
    let google = google();
    google.code("4/0-code", Ok(Some(USER_REFRESH_TOKEN)));
    let mut app = App::start(&[], &google, FakeCrypto::default())?;
    let state_dir = dir.path().join("state");
    app.configure(&state_dir).await?;

    let (id, url) = start_oauth(&mut app, sign_in("oauth", &client_fields())).await?;
    assert_eq!(
        (url.scheme(), url.host_str(), url.path()),
        ("https", Some("accounts.google.com"), "/o/oauth2/v2/auth")
    );
    for (name, value) in [
        ("client_id", OAUTH_CLIENT_ID),
        ("response_type", "code"),
        ("access_type", "offline"),
        ("prompt", "consent"),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
        ("state", STATE),
        (
            "scope",
            "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email openid",
        ),
    ] {
        assert_eq!(query(&url, name).as_deref(), Some(value), "{name}");
    }
    let redirect_uri = query(&url, "redirect_uri").ok_or("no redirect_uri")?;
    assert!(
        redirect_uri.starts_with("http://127.0.0.1:") && redirect_uri.ends_with("/oauth2callback"),
        "{redirect_uri}"
    );

    // Neither a stray request nor a wrong state ends the sign-in.
    let wrong = redirect(&url, "state=guess&code=4%2F0-code").await?;
    assert!(wrong.starts_with("HTTP/1.1 400"), "{wrong}");
    let host = redirect_uri
        .trim_start_matches("http://")
        .trim_end_matches("/oauth2callback");
    let probe = format!(
        "GET /oauth2callback?state={STATE}&code=x HTTP/1.1\r\nHost: {host}\r\nSec-Fetch-Dest: image\r\nSec-Fetch-Mode: no-cors\r\n\r\n"
    );
    assert!(request(host, &probe).await?.starts_with("HTTP/1.1 404"));
    let favicon = format!("GET /favicon.ico HTTP/1.1\r\nHost: {host}\r\n\r\n");
    assert!(request(host, &favicon).await?.starts_with("HTTP/1.1 404"));

    let page = redirect(&url, &format!("state={STATE}&code=4%2F0-code&scope=openid")).await?;
    assert!(
        page.starts_with("HTTP/1.1 200") && page.contains("signed in"),
        "{page}"
    );
    let response = app.response("signIn", id, crate::support::WAIT).await?;
    let identity = &at(&response, "/result");
    crate::support::assert_valid("signInResult", identity)?;
    assert_eq!(identity["method"], "oauth");
    assert_eq!(
        (&identity["principal"], &identity["kind"]),
        (&json!(USER_EMAIL), &json!("user"))
    );
    assert_eq!(
        identity["targets"],
        json!({}),
        "the project is chosen after sign-in"
    );

    let requests = google.token_requests();
    assert!(
        matches!(
            requests.first(),
            Some(TokenRequest::AuthorizationCode { client_id, client_secret, code, code_verifier, redirect_uri: sent })
                if client_id == OAUTH_CLIENT_ID
                    && client_secret.expose() == USER_CLIENT_SECRET
                    && code.expose() == "4/0-code"
                    && code_verifier.expose() == VERIFIER
                    && *sent == redirect_uri
        ),
        "{requests:?}"
    );

    let env = app.ok("env", "envResult", json!({})).await?;
    let (path, _, _) = env_value(&env, "GOOGLE_APPLICATION_CREDENTIALS").ok_or("no file")?;
    assert!(std::path::Path::new(path).starts_with(&state_dir), "{path}");
    let document: Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    assert_eq!(
        document,
        json!({
            "type": "authorized_user",
            "client_id": OAUTH_CLIENT_ID,
            "client_secret": USER_CLIENT_SECRET,
            "refresh_token": USER_REFRESH_TOKEN,
        })
    );
    Ok(())
}

/// Starts a sign-in, checks the client it uses, and declines it.
async fn client_used(app: &mut App, fields: Value) -> TestResult<Option<String>> {
    let (id, url) = start_oauth(app, sign_in("oauth", &fields)).await?;
    redirect(&url, &format!("state={STATE}&error=access_denied")).await?;
    let response = app.response("signIn", id, crate::support::WAIT).await?;
    assert_eq!(at(&response, "/error/data/kind"), "cancelled", "{response}");
    Ok(query(&url, "client_id"))
}

#[tokio::test]
async fn the_client_comes_from_the_fields_a_file_or_the_environment() -> TestResult {
    let dir = tempfile::tempdir()?;
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home)?;
    let file = |id: &str| json!({"installed": {"client_id": id, "client_secret": "s"}}).to_string();
    std::fs::write(home.join("client.json"), file("from-field-file"))?;
    std::fs::write(home.join("env-client.json"), file("from-env-file"))?;
    let home = home.to_str().ok_or("utf-8")?;
    let env_file = format!("{home}{}env-client.json", std::path::MAIN_SEPARATOR);
    let env = [
        ("HOME", home),
        ("GOOGLE_OAUTH_CLIENT_CREDENTIALS", env_file.as_str()),
        ("GOOGLE_OAUTH_CLIENT_ID", "from-env-id"),
        ("GOOGLE_OAUTH_CLIENT_SECRET", "s"),
    ];
    let mut app = App::start(&env, &google(), FakeCrypto::default())?;
    app.configure(&dir.path().join("state")).await?;

    let fields = json!({"clientId": "from-fields", "clientSecret": "s"});
    assert_eq!(
        client_used(&mut app, fields).await?.as_deref(),
        Some("from-fields")
    );
    let fields = json!({"clientFile": "~/client.json"});
    assert_eq!(
        client_used(&mut app, fields).await?.as_deref(),
        Some("from-field-file")
    );
    assert_eq!(
        client_used(&mut app, json!({})).await?.as_deref(),
        Some("from-env-file")
    );

    let env = [
        ("GOOGLE_OAUTH_CLIENT_ID", "from-env-id"),
        ("GOOGLE_OAUTH_CLIENT_SECRET", "s"),
    ];
    let mut app = App::start(&env, &google(), FakeCrypto::default())?;
    app.configure(&dir.path().join("state")).await?;
    assert_eq!(
        client_used(&mut app, json!({})).await?.as_deref(),
        Some("from-env-id")
    );
    Ok(())
}

#[tokio::test]
async fn without_a_whole_client_sign_in_says_how_to_give_one() -> TestResult {
    let dir = tempfile::tempdir()?;
    let web = dir.path().join("web.json");
    std::fs::write(&web, r#"{"web": {"client_id": "a", "client_secret": "b"}}"#)?;
    let web = web.to_str().ok_or("utf-8")?;
    let mut app = App::start(&[], &google(), FakeCrypto::default())?;
    app.configure(&dir.path().join("state")).await?;
    for (fields, expect) in [
        (json!({}), "GOOGLE_OAUTH_CLIENT_CREDENTIALS"),
        (json!({"clientId": "a"}), "without clientSecret"),
        (json!({"clientSecret": "b"}), "without clientId"),
        (json!({"clientId": "a", "clientFile": web}), "not both"),
        (json!({"clientFile": web}), "Desktop app"),
        (json!({"clientFile": "client.json"}), "absolute"),
        (json!({"clientFile": "~/client.json"}), "no home directory"),
    ] {
        let error = app
            .error("signIn", sign_in("oauth", &fields), "invalidParams")
            .await?;
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(message.contains(expect), "{fields}: {message}");
    }

    let mut app = App::start(
        &[("GOOGLE_OAUTH_CLIENT_ID", "a")],
        &google(),
        FakeCrypto::default(),
    )?;
    app.configure(&dir.path().join("state")).await?;
    let error = app
        .error("signIn", sign_in("oauth", &json!({})), "invalidParams")
        .await?;
    assert!(
        at(&error, "/message")
            .as_str()
            .is_some_and(|m| m.contains("GOOGLE_OAUTH_CLIENT_SECRET"))
    );
    Ok(())
}

#[tokio::test]
async fn the_blocks_required_scopes_are_asked_for_and_checked() -> TestResult {
    let dir = tempfile::tempdir()?;
    let admin = "https://www.googleapis.com/auth/admin.directory.user";
    let google = google();
    google.code("4/0-code", Ok(Some(USER_REFRESH_TOKEN)));
    let mut app = App::start(&[], &google, FakeCrypto::default())?;
    app.configure(&dir.path().join("state")).await?;

    let params = json!({
        "method": "oauth",
        "fields": client_fields(),
        "pins": {},
        "requirements": [{"kind": "scopes", "scopes": [CLOUD_PLATFORM, admin]}],
    });
    let (id, url) = start_oauth(&mut app, params).await?;
    assert_eq!(
        query(&url, "scope"),
        Some(format!("{CLOUD_PLATFORM} {admin}"))
    );
    // The person unticks the admin scope on Google's consent screen.
    redirect(&url, &format!("state={STATE}&code=4%2F0-code")).await?;
    let response = app.response("signIn", id, crate::support::WAIT).await?;
    assert_eq!(
        at(&response, "/error/data/kind"),
        "requirementNotMet",
        "{response}"
    );
    assert_eq!(
        at(&response, "/error/data/unmet"),
        json!([{"kind": "scopes", "scopes": [admin]}])
    );
    Ok(())
}

#[tokio::test]
async fn a_declined_or_refused_sign_in_says_what_happened() -> TestResult {
    let dir = tempfile::tempdir()?;
    let google = google();
    google
        .code("no-refresh", Ok(None))
        .code("bad-client", Err(OAuthError::InvalidClient));
    let mut app = App::start(&[], &google, FakeCrypto::default())?;
    app.configure(&dir.path().join("state")).await?;

    for (callback, kind, expect, page) in [
        ("error=access_denied", "cancelled", "declined", "200"),
        (
            "error=invalid_scope",
            "accessDenied",
            "(invalid_scope)",
            "200",
        ),
        (
            "error=%3Cscript%3E",
            "accessDenied",
            "an unknown error",
            "200",
        ),
        (
            "scope=openid",
            "accessDenied",
            "no authorization code",
            "400",
        ),
        (
            "code=no-refresh",
            "accessDenied",
            "myaccount.google.com/permissions",
            "200",
        ),
        ("code=used-already", "expired", "Sign in again", "200"),
        ("code=bad-client", "accessDenied", "OAuth client", "200"),
    ] {
        let (id, url) = start_oauth(&mut app, sign_in("oauth", &client_fields())).await?;
        let shown = redirect(&url, &format!("state={STATE}&{callback}")).await?;
        assert!(
            shown.starts_with(&format!("HTTP/1.1 {page}")),
            "{callback}: {shown}"
        );
        assert!(!shown.contains("script"), "{shown}");
        let response = app.response("signIn", id, crate::support::WAIT).await?;
        assert_eq!(
            at(&response, "/error/data/kind"),
            kind,
            "{callback}: {response}"
        );
        let message = response
            .pointer("/error/message")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(message.contains(expect), "{callback}: {message}");
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn the_sign_in_window_closes_after_five_minutes() -> TestResult {
    let dir = tempfile::tempdir()?;
    let mut app = App::start(&[], &google(), FakeCrypto::default())?;
    app.configure(&dir.path().join("state")).await?;
    let (id, url) = start_oauth(&mut app, sign_in("oauth", &client_fields())).await?;
    let response = app.response("signIn", id, Duration::from_mins(6)).await?;
    assert_eq!(at(&response, "/error/data/kind"), "timedOut", "{response}");
    // The listener is gone with the sign-in.
    let redirect_uri = query(&url, "redirect_uri").ok_or("no redirect_uri")?;
    let host = redirect_uri
        .trim_start_matches("http://")
        .trim_end_matches("/oauth2callback");
    let mut closed = false;
    for _ in 0..20 {
        if tokio::net::TcpStream::connect(host).await.is_err() {
            closed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(closed, "still listening");
    Ok(())
}

#[tokio::test]
async fn without_a_random_source_browser_sign_in_says_what_is_missing() -> TestResult {
    let dir = tempfile::tempdir()?;
    let mut app = App::start(&[], &google(), NoCrypto)?;
    app.configure(&dir.path().join("state")).await?;
    let error = app
        .error("signIn", sign_in("oauth", &client_fields()), "internal")
        .await?;
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(
        message.contains("cannot start a browser sign-in"),
        "{message}"
    );
    Ok(())
}
