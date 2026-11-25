//! The `sso` method: IAM Identity Center's device authorization, then an
//! account and a role. Time is paused, so a test polls for minutes of
//! simulated time at once and every poll lands on its exact second.

use super::*;

const SSO_ARN: &str =
    "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_deploy_0123456789abcdef/alice";
const ADMIN_ARN: &str =
    "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_admin_fedcba9876543210/alice";
/// A role's keys: they may leave the plugin only in `env`'s result.
const ROLE_SECRET: &str = "test-role-secret-access-key";
const ROLE_TOKEN: &str = "test-role-session-token";

const A_MINUTE_AGO: &str = "2026-11-24T17:59:00Z";
const IN_TWO_MINUTES: &str = "2026-11-24T18:02:00Z";
const IN_AN_HOUR: &str = "2026-11-24T19:00:00Z";
/// When the token `approved` gives expires, from `NOW`.
const TOKEN_EXPIRES: &str = "2026-11-25T02:00:00Z";

/// Longer than any sign-in here takes in paused time. A hang still fails at
/// once: with nothing left to run, paused time jumps to the timeout.
const PAUSED_WAIT: Duration = Duration::from_secs(3600);

async fn paused(aws: FakeAws) -> Result<App, Box<dyn Error>> {
    let mut app = App::start(aws, Environment::default()).await?;
    app.wait = PAUSED_WAIT;
    Ok(app)
}

fn sso_sign_in(pins: &Value) -> Value {
    json!({
        "method": "sso",
        "fields": {"ssoStartUrl": START_URL, "ssoRegion": "eu-west-1", "defaultRegion": "eu-central-1"},
        "pins": pins,
        "requirements": [],
    })
}

fn keys(access_key_id: &str, expires_at: &str) -> AwsCredentials {
    AwsCredentials {
        access_key_id: access_key_id.to_owned(),
        secret_access_key: Secret::new(ROLE_SECRET),
        session_token: Some(Secret::new(ROLE_TOKEN)),
        expires_at: OffsetDateTime::parse(expires_at, &Rfc3339).ok(),
    }
}

fn message(error: &Value) -> Result<&str, Box<dyn Error>> {
    Ok(error["message"].as_str().ok_or("message")?)
}

#[tokio::test(start_paused = true)]
async fn sso_shows_the_url_and_code_polls_at_awss_pace_and_takes_the_only_role() -> TestResult {
    let aws = FakeAws::default()
        .polls(vec![
            Ok(TokenPoll::Pending),
            Ok(TokenPoll::SlowDown),
            Ok(TokenPoll::Pending),
            Ok(approved()),
        ])
        .account(ACCOUNT, "Production", &["deploy"])?
        .role_keys(ACCOUNT, "deploy", vec![Ok(keys("ASIASSO", IN_AN_HOUR))])
        .caller("ASIASSO", ACCOUNT, SSO_ARN)?;
    let mut app = paused(aws.clone()).await?;
    let identity = app
        .ok("signIn", sso_sign_in(&json!({})), "signInResult")
        .await?;

    // One prompt, for the signIn request: the page and the code to check.
    assert_eq!(
        app.notifications,
        [
            json!({"request": app.next_id, "kind": "openUrl", "url": VERIFICATION_URL, "code": USER_CODE})
        ]
    );
    // AWS's 5-second interval, 5 more after slow_down, and every SSO call in
    // the SSO region.
    assert_eq!(
        aws.sso_log(),
        [
            "start https://my-org.awsapps.com/start in eu-west-1",
            "poll at 5s in eu-west-1",
            "poll at 10s in eu-west-1",
            "poll at 20s in eu-west-1",
            "poll at 30s in eu-west-1",
            "accounts in eu-west-1",
            "roles 123456789012 in eu-west-1",
            "keys 123456789012/deploy in eu-west-1",
        ]
    );
    // STS checks the role's keys in the SSO region's partition.
    assert_eq!(
        aws.calls(),
        [Call {
            access_key_id: "ASIASSO".to_owned(),
            region: "us-east-1".to_owned(),
        }]
    );
    assert_eq!(at(&identity, "/method"), "sso");
    assert_eq!(at(&identity, "/kind"), "role");
    assert_eq!(at(&identity, "/principal"), SSO_ARN);
    assert_eq!(at(&identity, "/expiresAt"), IN_AN_HOUR);
    // The account by the name the person knows it, not the IAM alias.
    assert_eq!(
        at(&identity, "/targets"),
        json!({"account": {"id": ACCOUNT, "name": "Production"}, "role": {"id": "deploy", "name": "deploy"}})
    );

    let env = app.ok("env", json!({}), "envResult").await?;
    let values = values_of(&env)?;
    assert_eq!(
        values.get("AWS_ACCESS_KEY_ID").ok_or("no key")?.0,
        "ASIASSO"
    );
    assert_eq!(
        values.get("AWS_SECRET_ACCESS_KEY"),
        Some(&(
            ROLE_SECRET.to_owned(),
            true,
            vec!["env".to_owned(), "output".to_owned()]
        ))
    );
    assert_eq!(
        values.get("AWS_SESSION_TOKEN").ok_or("no token")?.0,
        ROLE_TOKEN
    );
    assert_eq!(
        values.get("AWS_REGION").ok_or("no region")?.0,
        "eu-central-1"
    );
    assert_eq!(at(&env, "/expiresAt"), IN_AN_HOUR);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn a_pinned_account_and_role_are_signed_in_to_directly() -> TestResult {
    let aws = FakeAws::default()
        .polls(vec![Ok(approved())])
        .account(ACCOUNT, "Production", &["deploy", "admin"])?
        .account(OTHER_ACCOUNT, "Staging", &["deploy"])?
        .role_keys(ACCOUNT, "deploy", vec![Ok(keys("ASIASSO", IN_AN_HOUR))])
        .caller("ASIASSO", ACCOUNT, SSO_ARN)?;
    let mut app = paused(aws.clone()).await?;
    let identity = app
        .ok(
            "signIn",
            sso_sign_in(&json!({"account": ACCOUNT, "role": "deploy"})),
            "signInResult",
        )
        .await?;
    assert_eq!(
        aws.sso_log(),
        [
            "start https://my-org.awsapps.com/start in eu-west-1",
            "poll at 5s in eu-west-1",
            "keys 123456789012/deploy in eu-west-1",
        ]
    );
    // Never listed, so the account goes by its IAM alias.
    assert_eq!(at(&identity, "/targets/account/name"), "sandbox");
    assert_eq!(at(&identity, "/targets/role/id"), "deploy");

    // Once listed, it goes by its name in IAM Identity Center.
    app.ok("targets", json!({"level": "account"}), "targetsResult")
        .await?;
    let identity = app
        .ok(
            "select",
            json!({"targets": {"account": ACCOUNT, "role": "deploy"}}),
            "selectResult",
        )
        .await?;
    assert_eq!(at(&identity, "/targets/account/name"), "Production");
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn with_a_choice_the_person_picks_an_account_then_a_role() -> TestResult {
    let aws = FakeAws::default()
        .polls(vec![Ok(approved())])
        .account(ACCOUNT, "Production", &["deploy", "admin"])?
        .account(OTHER_ACCOUNT, "Staging", &["deploy"])?
        .role_keys(ACCOUNT, "admin", vec![Ok(keys("ASIAADMIN", IN_AN_HOUR))])
        .caller("ASIAADMIN", ACCOUNT, ADMIN_ARN)?;
    let mut app = paused(aws.clone()).await?;
    let identity = app
        .ok("signIn", sso_sign_in(&json!({})), "signInResult")
        .await?;
    assert_eq!(
        identity,
        json!({"principal": START_URL, "kind": "user", "method": "sso", "targets": {}, "expiresAt": TOKEN_EXPIRES})
    );
    let error = app.fails("env", json!({}), "notSignedIn").await?;
    assert!(
        message(&error)?.contains("choose an account and role"),
        "{error}"
    );

    let accounts = app
        .ok("targets", json!({"level": "account"}), "targetsResult")
        .await?;
    assert_eq!(
        at(&accounts, "/targets"),
        json!([{"id": ACCOUNT, "name": "Production"}, {"id": OTHER_ACCOUNT, "name": "Staging"}])
    );
    let roles = app
        .ok(
            "targets",
            json!({"level": "role", "parent": OTHER_ACCOUNT}),
            "targetsResult",
        )
        .await?;
    assert_eq!(
        at(&roles, "/targets"),
        json!([{"id": "deploy", "name": "deploy"}])
    );
    // Without a parent, the role level needs an account chosen first.
    app.fails("targets", json!({"level": "role"}), "invalidParams")
        .await?;
    // AWS has two levels, and a call naming another is refused for it.
    for (method, params) in [
        ("targets", json!({"level": "region"})),
        (
            "select",
            json!({"targets": {"account": ACCOUNT, "region": "eu-west-1"}}),
        ),
    ] {
        let error = app.fails(method, params, "invalidParams").await?;
        assert!(
            message(&error)?.contains("AWS has no level \"region\""),
            "{error}"
        );
    }

    let identity = app
        .ok(
            "select",
            json!({"targets": {"account": ACCOUNT}}),
            "selectResult",
        )
        .await?;
    assert_eq!(
        at(&identity, "/targets"),
        json!({"account": {"id": ACCOUNT, "name": "Production"}})
    );
    let roles = app
        .ok("targets", json!({"level": "role"}), "targetsResult")
        .await?;
    assert_eq!(
        at(&roles, "/targets"),
        json!([{"id": "deploy", "name": "deploy"}, {"id": "admin", "name": "admin"}])
    );
    let identity = app
        .ok(
            "select",
            json!({"targets": {"account": ACCOUNT, "role": "admin"}}),
            "selectResult",
        )
        .await?;
    assert_eq!(at(&identity, "/principal"), ADMIN_ARN);
    assert_eq!(at(&identity, "/targets/role/id"), "admin");
    assert_eq!(at(&identity, "/targets/account/name"), "Production");
    let values = values_of(&app.ok("env", json!({}), "envResult").await?)?;
    assert_eq!(
        values.get("AWS_ACCESS_KEY_ID").ok_or("no key")?.0,
        "ASIAADMIN"
    );

    // Signed in to a role, the login still lists the others.
    app.ok("targets", json!({"level": "account"}), "targetsResult")
        .await?;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn pins_narrow_the_choice_and_refuse_anything_else() -> TestResult {
    let aws = FakeAws::default()
        .polls(vec![Ok(approved())])
        .account(ACCOUNT, "Production", &["deploy", "admin"])?
        .account(OTHER_ACCOUNT, "Staging", &["deploy"])?;
    let mut app = paused(aws.clone()).await?;
    // One account is left, with two roles: the person picks the role.
    let identity = app
        .ok(
            "signIn",
            sso_sign_in(&json!({"account": ACCOUNT})),
            "signInResult",
        )
        .await?;
    assert_eq!(at(&identity, "/targets"), json!({}));
    let accounts = app
        .ok("targets", json!({"level": "account"}), "targetsResult")
        .await?;
    assert_eq!(
        at(&accounts, "/targets"),
        json!([{"id": ACCOUNT, "name": "Production"}])
    );
    app.fails(
        "targets",
        json!({"level": "role", "parent": OTHER_ACCOUNT}),
        "pinMismatch",
    )
    .await?;
    app.fails(
        "select",
        json!({"targets": {"account": OTHER_ACCOUNT}}),
        "pinMismatch",
    )
    .await?;
    let error = app
        .fails(
            "select",
            json!({"targets": {"account": OTHER_ACCOUNT, "role": "deploy"}}),
            "pinMismatch",
        )
        .await?;
    assert!(
        message(&error)?.contains("needs account 123456789012"),
        "{error}"
    );
    assert!(
        !aws.sso_log().iter().any(|call| call.starts_with("keys")),
        "{:?}",
        aws.sso_log()
    );

    // A pin IAM Identity Center does not give the person fails the sign-in.
    for (pins, named) in [
        (
            json!({"role": "readonly"}),
            "role readonly in account 123456789012",
        ),
        (json!({"account": "999999999999"}), "account 999999999999"),
    ] {
        let aws = FakeAws::default().polls(vec![Ok(approved())]).account(
            ACCOUNT,
            "Production",
            &["deploy", "admin"],
        )?;
        let mut app = paused(aws).await?;
        let error = app
            .fails("signIn", sso_sign_in(&pins), "pinMismatch")
            .await?;
        assert!(
            message(&error)?.contains(&format!("does not give you {named}")),
            "{error}"
        );
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn a_refused_expired_or_unanswered_sign_in_says_which() -> TestResult {
    let refused = FakeAws::default().polls(vec![
        Ok(TokenPoll::Pending),
        Err(AwsError::new(
            Service::SsoOidc,
            AwsErrorKind::Refused,
            "AccessDeniedException",
        )),
    ]);
    let mut app = paused(refused).await?;
    let error = app
        .fails("signIn", sso_sign_in(&json!({})), "accessDenied")
        .await?;
    assert!(
        message(&error)?.contains("SSO sign-in was denied or cancelled in the browser"),
        "{error}"
    );

    let expired = FakeAws::default().polls(vec![Err(AwsError::new(
        Service::SsoOidc,
        AwsErrorKind::Expired,
        "ExpiredTokenException",
    ))]);
    let mut app = paused(expired).await?;
    let error = app
        .fails("signIn", sso_sign_in(&json!({})), "timedOut")
        .await?;
    assert!(
        message(&error)?.contains("The SSO sign-in request expired"),
        "{error}"
    );

    // Any other failed poll is that failure.
    let unreachable = FakeAws::default().polls(vec![Err(AwsError::new(
        Service::SsoOidc,
        AwsErrorKind::Network,
        "dispatch failure: connection refused",
    ))]);
    let mut app = paused(unreachable).await?;
    let error = app
        .fails("signIn", sso_sign_in(&json!({})), "network")
        .await?;
    assert!(
        message(&error)?.contains("while waiting for the SSO sign-in"),
        "{error}"
    );

    // Never approved: polling stops when the device code expires, 600s in.
    let unanswered = FakeAws::default();
    let mut app = paused(unanswered.clone()).await?;
    let started = Instant::now();
    app.fails("signIn", sso_sign_in(&json!({})), "timedOut")
        .await?;
    assert_eq!(started.elapsed(), Duration::from_secs(600));
    let log = unanswered.sso_log();
    assert_eq!(log.len(), 1 + 600 / 5, "{log:?}");
    assert_eq!(
        log.last().map(String::as_str),
        Some("poll at 600s in eu-west-1")
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn no_account_or_no_role_to_choose_is_access_denied() -> TestResult {
    let mut app = paused(FakeAws::default().polls(vec![Ok(approved())])).await?;
    let error = app
        .fails("signIn", sso_sign_in(&json!({})), "accessDenied")
        .await?;
    assert!(
        message(&error)?.contains("No AWS accounts are available to you in IAM Identity Center"),
        "{error}"
    );

    let aws = FakeAws::default()
        .polls(vec![Ok(approved())])
        .account(ACCOUNT, "Production", &[])?;
    let mut app = paused(aws).await?;
    let error = app
        .fails("signIn", sso_sign_in(&json!({})), "accessDenied")
        .await?;
    assert!(
        message(&error)?.contains("No roles are available to you in account 123456789012"),
        "{error}"
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn the_sso_fields_are_checked_before_aws_is_called() -> TestResult {
    let aws = FakeAws::default();
    let mut app = paused(aws.clone()).await?;
    for (fields, says) in [
        (
            json!({"ssoStartUrl": "http://my-org.awsapps.com/start"}),
            "https:// URL",
        ),
        (json!({"ssoStartUrl": "https://"}), "https:// URL"),
        (
            json!({"ssoStartUrl": "https://my-org.awsapps.com/ start"}),
            "https:// URL",
        ),
        (json!({"ssoStartUrl": start_url_of(2049)}), "https:// URL"),
        (
            json!({"ssoStartUrl": START_URL, "ssoRegion": "Ireland"}),
            "the ssoRegion field is invalid",
        ),
        (
            json!({"ssoRegion": "eu-west-1"}),
            "the sso method needs ssoStartUrl",
        ),
    ] {
        let error = app
            .fails(
                "signIn",
                json!({"method": "sso", "fields": fields, "pins": {}, "requirements": []}),
                "invalidParams",
            )
            .await?;
        assert!(message(&error)?.contains(says), "{error}");
    }
    assert_eq!(aws.sso_log(), Vec::<String>::new());
    Ok(())
}

/// An access portal URL of `len` bytes.
fn start_url_of(len: usize) -> String {
    let mut url = format!("{START_URL}/");
    url.push_str(&"a".repeat(len.saturating_sub(url.len())));
    url
}

#[tokio::test(start_paused = true)]
async fn an_access_portal_url_may_be_2048_bytes() -> TestResult {
    let aws = FakeAws::default().polls(vec![Ok(approved())]);
    let mut app = paused(aws.clone()).await?;
    let url = start_url_of(2048);
    let fields = json!({"ssoStartUrl": url, "ssoRegion": "eu-west-1"});
    // Signed in, with no account to choose.
    app.fails(
        "signIn",
        json!({"method": "sso", "fields": fields, "pins": {}, "requirements": []}),
        "accessDenied",
    )
    .await?;
    assert_eq!(
        aws.sso_log().first(),
        Some(&format!("start {url} in eu-west-1"))
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn env_gets_a_role_fresh_keys_before_its_keys_expire() -> TestResult {
    let aws = FakeAws::default()
        .polls(vec![Ok(approved())])
        .account(ACCOUNT, "Production", &["deploy"])?
        .role_keys(
            ACCOUNT,
            "deploy",
            vec![
                Ok(keys("ASIAOLD", IN_TWO_MINUTES)),
                Ok(keys("ASIANEW", IN_AN_HOUR)),
            ],
        )
        .caller("ASIAOLD", ACCOUNT, SSO_ARN)?;
    let mut app = paused(aws.clone()).await?;
    app.ok("signIn", sso_sign_in(&json!({})), "signInResult")
        .await?;
    let env = app.ok("env", json!({}), "envResult").await?;
    assert_eq!(
        values_of(&env)?.get("AWS_ACCESS_KEY_ID").ok_or("no key")?.0,
        "ASIANEW"
    );
    assert_eq!(at(&env, "/expiresAt"), IN_AN_HOUR);
    // Fresh keys are not due again for an hour.
    app.ok("env", json!({}), "envResult").await?;
    let fetched = aws
        .sso_log()
        .iter()
        .filter(|call| call.starts_with("keys"))
        .count();
    assert_eq!(fetched, 2);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn keys_due_in_exactly_five_minutes_are_refreshed() -> TestResult {
    let aws = FakeAws::default()
        .polls(vec![Ok(approved())])
        .account(ACCOUNT, "Production", &["deploy"])?
        .role_keys(
            ACCOUNT,
            "deploy",
            vec![
                Ok(keys("ASIAOLD", "2026-11-24T18:05:00Z")),
                Ok(keys("ASIANEW", IN_AN_HOUR)),
            ],
        )
        .caller("ASIAOLD", ACCOUNT, SSO_ARN)?;
    let mut app = paused(aws).await?;
    app.ok("signIn", sso_sign_in(&json!({})), "signInResult")
        .await?;
    let env = app.ok("env", json!({}), "envResult").await?;
    assert_eq!(
        values_of(&env)?.get("AWS_ACCESS_KEY_ID").ok_or("no key")?.0,
        "ASIANEW"
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn keys_that_cannot_be_refreshed_are_used_until_they_expire() -> TestResult {
    let token_expired = || {
        Err(sso_failure(
            AwsErrorKind::Expired,
            "UnauthorizedException: Session token not found or invalid",
        ))
    };
    let aws = FakeAws::default()
        .polls(vec![Ok(approved())])
        .account(ACCOUNT, "Production", &["deploy"])?
        .role_keys(
            ACCOUNT,
            "deploy",
            vec![Ok(keys("ASIAOLD", IN_TWO_MINUTES)), token_expired()],
        )
        .caller("ASIAOLD", ACCOUNT, SSO_ARN)?;
    let mut app = paused(aws).await?;
    app.ok("signIn", sso_sign_in(&json!({})), "signInResult")
        .await?;
    let env = app.ok("env", json!({}), "envResult").await?;
    assert_eq!(
        values_of(&env)?.get("AWS_ACCESS_KEY_ID").ok_or("no key")?.0,
        "ASIAOLD"
    );

    let aws = FakeAws::default()
        .polls(vec![Ok(approved())])
        .account(ACCOUNT, "Production", &["deploy"])?
        .role_keys(
            ACCOUNT,
            "deploy",
            vec![Ok(keys("ASIAOLD", A_MINUTE_AGO)), token_expired()],
        )
        .caller("ASIAOLD", ACCOUNT, SSO_ARN)?;
    let mut app = paused(aws).await?;
    app.ok("signIn", sso_sign_in(&json!({})), "signInResult")
        .await?;
    let error = app.fails("env", json!({}), "expired").await?;
    assert!(
        message(&error)?.contains("your SSO sign-in has expired"),
        "{error}"
    );

    // Keys that expire this second are not used: the refresh's failure is
    // the answer.
    let aws = FakeAws::default()
        .polls(vec![Ok(approved())])
        .account(ACCOUNT, "Production", &["deploy"])?
        .role_keys(
            ACCOUNT,
            "deploy",
            vec![
                Ok(keys("ASIAOLD", NOW)),
                Err(sso_failure(AwsErrorKind::Network, "dispatch failure")),
            ],
        )
        .caller("ASIAOLD", ACCOUNT, SSO_ARN)?;
    let mut app = paused(aws).await?;
    app.ok("signIn", sso_sign_in(&json!({})), "signInResult")
        .await?;
    let error = app.fails("env", json!({}), "network").await?;
    assert!(
        message(&error)?.contains("getting fresh keys for the role"),
        "{error}"
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn a_sign_out_during_a_refresh_stays_signed_out() -> TestResult {
    let aws = FakeAws::default()
        .polls(vec![Ok(approved())])
        .account(ACCOUNT, "Production", &["deploy"])?
        .role_keys(
            ACCOUNT,
            "deploy",
            vec![
                Ok(keys("ASIAOLD", IN_TWO_MINUTES)),
                Ok(keys("ASIANEW", IN_AN_HOUR)),
            ],
        )
        .caller("ASIAOLD", ACCOUNT, SSO_ARN)?;
    let mut app = paused(aws.clone()).await?;
    app.ok("signIn", sso_sign_in(&json!({})), "signInResult")
        .await?;

    let open = aws.hold_next_keys();
    let env = app.send("env", json!({})).await?;
    // Until env's refresh is waiting on AWS.
    let refreshing = |log: Vec<String>| log.iter().filter(|c| c.starts_with("keys")).count() == 2;
    for _ in 0..100 {
        if refreshing(aws.sso_log()) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(refreshing(aws.sso_log()), "{:?}", aws.sso_log());
    app.ok("signOut", json!({}), "signOutResult").await?;
    open.send(()).map_err(|()| "the refresh stopped waiting")?;
    // The env call that began before the sign-out may answer; nothing after it.
    app.response(env).await?;
    app.fails("env", json!({}), "notSignedIn").await?;
    Ok(())
}

/// Until the fake has had `count` `GetRoleCredentials` calls, each held or
/// answered.
async fn keys_calls(aws: &FakeAws, count: usize) -> TestResult {
    let calls = || {
        aws.sso_log()
            .iter()
            .filter(|call| call.starts_with("keys"))
            .count()
    };
    for _ in 0..100 {
        if calls() >= count {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err(format!("{} keys calls, not {count}: {:?}", calls(), aws.sso_log()).into())
}

/// Signed in to a role whose keys are about to expire, with two env calls
/// that each refresh them: one still waiting on AWS, and one after it that
/// has answered, its keys `ASIAFIRST` kept. The waiting one gets
/// `ASIASECOND` once the sender is used.
async fn two_refreshes() -> Result<(App, oneshot::Sender<()>, i64), Box<dyn Error>> {
    let aws = FakeAws::default()
        .polls(vec![Ok(approved())])
        .account(ACCOUNT, "Production", &["deploy"])?
        .role_keys(
            ACCOUNT,
            "deploy",
            vec![
                Ok(keys("ASIAOLD", IN_TWO_MINUTES)),
                Ok(keys("ASIAFIRST", IN_AN_HOUR)),
                Ok(keys("ASIASECOND", IN_AN_HOUR)),
            ],
        )
        .caller("ASIAOLD", ACCOUNT, SSO_ARN)?;
    let mut app = paused(aws.clone()).await?;
    app.ok("signIn", sso_sign_in(&json!({})), "signInResult")
        .await?;
    let open = aws.hold_next_keys();
    let waiting = app.send("env", json!({})).await?;
    keys_calls(&aws, 2).await?;
    let env = app.ok("env", json!({}), "envResult").await?;
    assert_eq!(
        values_of(&env)?.get("AWS_ACCESS_KEY_ID").ok_or("no key")?.0,
        "ASIAFIRST"
    );
    Ok((app, open, waiting))
}

#[tokio::test(start_paused = true)]
async fn a_refresh_that_ends_after_another_or_a_sign_out_changes_nothing() -> TestResult {
    // The keys of the refresh that ended first are kept.
    let (mut app, open, waiting) = two_refreshes().await?;
    open.send(()).map_err(|()| "the refresh stopped waiting")?;
    app.response(waiting).await?;
    let env = app.ok("env", json!({}), "envResult").await?;
    assert_eq!(
        values_of(&env)?.get("AWS_ACCESS_KEY_ID").ok_or("no key")?.0,
        "ASIAFIRST"
    );

    // A sign-out after it stays a sign-out.
    let (mut app, open, waiting) = two_refreshes().await?;
    app.ok("signOut", json!({}), "signOutResult").await?;
    open.send(()).map_err(|()| "the refresh stopped waiting")?;
    app.response(waiting).await?;
    app.fails("env", json!({}), "notSignedIn").await?;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn the_device_flows_secrets_never_leave_and_a_roles_keys_leave_only_in_env() -> TestResult {
    let aws = FakeAws::default()
        .polls(vec![Ok(approved())])
        .account(ACCOUNT, "Production", &["deploy", "admin"])?
        .account(OTHER_ACCOUNT, "Staging", &["deploy"])?
        .role_keys(ACCOUNT, "deploy", vec![Ok(keys("ASIASSO", IN_AN_HOUR))])
        .caller("ASIASSO", ACCOUNT, SSO_ARN)?;
    let mut app = paused(aws).await?;
    // Every SSO path: the prompt, listings, a choice the pins refuse, a role
    // AWS refuses, a role it gives, and env.
    app.call("signIn", sso_sign_in(&json!({"account": ACCOUNT})))
        .await?;
    app.call("targets", json!({"level": "account"})).await?;
    app.call("targets", json!({"level": "role", "parent": ACCOUNT}))
        .await?;
    app.call(
        "select",
        json!({"targets": {"account": OTHER_ACCOUNT, "role": "deploy"}}),
    )
    .await?;
    app.call(
        "select",
        json!({"targets": {"account": ACCOUNT, "role": "admin"}}),
    )
    .await?;
    app.call("env", json!({})).await?;
    app.call(
        "select",
        json!({"targets": {"account": ACCOUNT, "role": "deploy"}}),
    )
    .await?;
    app.call("env", json!({})).await?;

    let mut env_lines = 0;
    for (method, line) in &app.written {
        for never in [CLIENT_SECRET, DEVICE_CODE, ACCESS_TOKEN] {
            assert!(
                !line.contains(never),
                "{method} wrote a device-flow secret: {line}"
            );
        }
        if method == "env" && line.contains("\"result\"") {
            env_lines += 1;
            assert!(
                line.contains(ROLE_SECRET) && line.contains(ROLE_TOKEN),
                "{line}"
            );
        } else {
            assert!(
                !line.contains(ROLE_SECRET) && !line.contains(ROLE_TOKEN),
                "{method} wrote a role's key: {line}"
            );
        }
    }
    assert_eq!(env_lines, 1);
    Ok(())
}
