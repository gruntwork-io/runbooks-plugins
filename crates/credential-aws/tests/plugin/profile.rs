//! The `profile` method, with the real aws-config parser reading files in a
//! temporary home directory: never the real `~/.aws`.

use tempfile::TempDir;

use super::*;

const OPS_ROLE: &str = "arn:aws-us-gov:iam::123456789012:role/ops";
const DEPLOY_ROLE: &str = "arn:aws-us-gov:iam::123456789012:role/deploy";
const DEPLOY_ARN: &str = "arn:aws-us-gov:sts::123456789012:assumed-role/deploy/alice";
/// An assumed role's keys: they may leave the plugin only in `env`'s result.
const ASSUMED_SECRET: &str = "test-assumed-secret-access-key";
const ASSUMED_TOKEN: &str = "test-assumed-session-token";
const IN_TWO_MINUTES: &str = "2026-11-24T18:02:00Z";
const IN_AN_HOUR: &str = "2026-11-24T19:00:00Z";

/// A home directory holding `.aws/config` and `.aws/credentials`, and an
/// environment whose `HOME` is it, with `extra` besides.
fn home(
    config: &str,
    credentials: &str,
    extra: &[(&str, &str)],
) -> Result<(TempDir, Environment), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let aws = dir.path().join(".aws");
    fs::create_dir_all(&aws)?;
    fs::write(aws.join("config"), config)?;
    fs::write(aws.join("credentials"), credentials)?;
    let home = dir.path().to_str().ok_or("a UTF-8 temporary directory")?;
    let mut pairs = vec![("HOME", home)];
    pairs.extend_from_slice(extra);
    let env = environment(&pairs);
    Ok((dir, env))
}

fn profile_sign_in(profile: &str, extra: &[(&str, &str)]) -> Result<Value, Box<dyn Error>> {
    let mut fields = json!({"profile": profile});
    for (name, value) in extra {
        fields
            .as_object_mut()
            .ok_or("not an object")?
            .insert((*name).to_owned(), json!(value));
    }
    Ok(json!({"method": "profile", "fields": fields, "pins": {}, "requirements": []}))
}

fn assumed(access_key_id: &str, expires_at: &str) -> AwsCredentials {
    AwsCredentials {
        access_key_id: access_key_id.to_owned(),
        secret_access_key: Secret::new(ASSUMED_SECRET),
        session_token: Some(Secret::new(ASSUMED_TOKEN)),
        expires_at: OffsetDateTime::parse(expires_at, &Rfc3339).ok(),
    }
}

fn message(error: &Value) -> Result<&str, Box<dyn Error>> {
    Ok(error["message"].as_str().ok_or("message")?)
}

const KEYS: &str = "
[default]
aws_access_key_id = AKIADEFAULT
aws_secret_access_key = test-secret-access-key-value

[dev]
aws_access_key_id = AKIADEV
aws_secret_access_key = test-secret-access-key-value
aws_session_token = test-session-token
";

#[tokio::test]
async fn a_profile_with_keys_signs_in_and_a_run_gets_its_region() -> TestResult {
    let (_home, env) = home("[profile dev]\nregion = eu-west-2\n", KEYS, &[])?;
    let aws = FakeAws::default().caller("AKIADEV", OTHER_ACCOUNT, USER_ARN)?;
    let mut app = App::start(aws.clone(), env).await?;
    let identity = app
        .ok("signIn", profile_sign_in("dev", &[])?, "signInResult")
        .await?;
    assert_eq!(at(&identity, "/method"), "profile");
    assert_eq!(at(&identity, "/principal"), USER_ARN);
    // The config file's region, with the credentials file's keys: one profile.
    assert_eq!(
        aws.calls(),
        [Call {
            access_key_id: "AKIADEV".to_owned(),
            region: "us-east-1".to_owned(),
        }]
    );
    let values = values_of(&app.ok("env", json!({}), "envResult").await?)?;
    assert_eq!(
        values.get("AWS_ACCESS_KEY_ID").ok_or("no key")?.0,
        "AKIADEV"
    );
    assert_eq!(
        values.get("AWS_SECRET_ACCESS_KEY").ok_or("no secret")?.0,
        SECRET
    );
    assert_eq!(values.get("AWS_SESSION_TOKEN").ok_or("no token")?.0, TOKEN);
    assert_eq!(values.get("AWS_REGION").ok_or("no region")?.0, "eu-west-2");
    Ok(())
}

#[tokio::test]
async fn without_a_region_of_its_own_a_profile_takes_the_default_region() -> TestResult {
    let (_home, env) = home("", KEYS, &[])?;
    let aws = FakeAws::default().caller("AKIADEFAULT", OTHER_ACCOUNT, USER_ARN)?;
    let mut app = App::start(aws, env).await?;
    app.ok(
        "signIn",
        profile_sign_in("default", &[("defaultRegion", "ca-central-1")])?,
        "signInResult",
    )
    .await?;
    let values = values_of(&app.ok("env", json!({}), "envResult").await?)?;
    assert_eq!(
        values.get("AWS_REGION").ok_or("no region")?.0,
        "ca-central-1"
    );

    app.ok("signIn", profile_sign_in("default", &[])?, "signInResult")
        .await?;
    let values = values_of(&app.ok("env", json!({}), "envResult").await?)?;
    assert_eq!(values.get("AWS_REGION").ok_or("no region")?.0, "us-east-1");
    Ok(())
}

#[tokio::test]
async fn a_role_profile_assumes_each_role_of_its_chain_in_its_partition() -> TestResult {
    let config = "
[profile base]
region = eu-west-1

[profile ops]
role_arn = arn:aws-us-gov:iam::123456789012:role/ops
source_profile = base

[profile deploy]
role_arn = arn:aws-us-gov:iam::123456789012:role/deploy
source_profile = ops
role_session_name = alice
external_id = ext-123
duration_seconds = 900
region = us-gov-east-1
";
    let credentials = "[base]\naws_access_key_id = AKIABASE\naws_secret_access_key = test-secret-access-key-value\n";
    let (_home, env) = home(config, credentials, &[])?;
    let aws = FakeAws::default()
        .assumes(OPS_ROLE, vec![Ok(assumed("ASIAOPS", IN_AN_HOUR))])
        .assumes(DEPLOY_ROLE, vec![Ok(assumed("ASIADEPLOY", IN_AN_HOUR))])
        .caller("ASIADEPLOY", ACCOUNT, DEPLOY_ARN)?;
    let mut app = App::start(aws.clone(), env).await?;
    let identity = app
        .ok("signIn", profile_sign_in("deploy", &[])?, "signInResult")
        .await?;
    let now = OffsetDateTime::parse(NOW, &Rfc3339)?.unix_timestamp();
    // Innermost first, each signed with the keys before it, all in the
    // partition of the named profile's region.
    assert_eq!(
        aws.sso_log(),
        [
            format!("assume {OPS_ROLE} as runbooks-{now} with AKIABASE in us-gov-west-1"),
            format!(
                "assume {DEPLOY_ROLE} as alice with ASIAOPS in us-gov-west-1 external ext-123 for 900s"
            ),
        ]
    );
    assert_eq!(
        aws.calls().first().ok_or("no call")?.region,
        "us-gov-west-1"
    );
    assert_eq!(at(&identity, "/kind"), "role");
    assert_eq!(at(&identity, "/targets/role/id"), "deploy");
    assert_eq!(at(&identity, "/expiresAt"), IN_AN_HOUR);
    let values = values_of(&app.ok("env", json!({}), "envResult").await?)?;
    assert_eq!(
        values.get("AWS_ACCESS_KEY_ID").ok_or("no key")?.0,
        "ASIADEPLOY"
    );
    assert_eq!(
        values.get("AWS_SECRET_ACCESS_KEY").ok_or("no secret")?.0,
        ASSUMED_SECRET
    );
    assert_eq!(
        values.get("AWS_REGION").ok_or("no region")?.0,
        "us-gov-east-1"
    );
    Ok(())
}

#[tokio::test]
async fn a_role_takes_its_source_keys_from_the_plugins_environment_or_its_own() -> TestResult {
    let config = "
[profile ci]
role_arn = arn:aws-us-gov:iam::123456789012:role/deploy
credential_source = Environment

[profile itself]
role_arn = arn:aws-us-gov:iam::123456789012:role/ops
source_profile = itself
aws_access_key_id = AKIAITSELF
aws_secret_access_key = test-secret-access-key-value
";
    let (_home, env) = home(
        config,
        "",
        &[
            ("AWS_ACCESS_KEY_ID", "AKIAFROMENV"),
            ("AWS_SECRET_ACCESS_KEY", SECRET),
        ],
    )?;
    let aws = FakeAws::default()
        .assumes(DEPLOY_ROLE, vec![Ok(assumed("ASIADEPLOY", IN_AN_HOUR))])
        .assumes(OPS_ROLE, vec![Ok(assumed("ASIAOPS", IN_AN_HOUR))])
        .caller("ASIADEPLOY", ACCOUNT, DEPLOY_ARN)?
        .caller("ASIAOPS", ACCOUNT, ROLE_ARN)?;
    let mut app = App::start(aws.clone(), env).await?;
    app.ok("signIn", profile_sign_in("ci", &[])?, "signInResult")
        .await?;
    app.ok("signIn", profile_sign_in("itself", &[])?, "signInResult")
        .await?;
    let signers: Vec<String> = aws
        .sso_log()
        .iter()
        .filter_map(|entry| Some(entry.split(" with ").nth(1)?.split(' ').next()?.to_owned()))
        .collect();
    assert_eq!(signers, ["AKIAFROMENV", "AKIAITSELF"]);
    Ok(())
}

#[tokio::test]
async fn the_overrides_name_the_files_and_tilde_is_the_home_directory() -> TestResult {
    let (home_dir, _) = home("", "", &[])?;
    let custom = home_dir.path().join("custom");
    fs::create_dir_all(&custom)?;
    fs::write(
        custom.join("config"),
        "[profile elsewhere]\nregion = ap-south-1\n",
    )?;
    fs::write(
        custom.join("keys"),
        "[elsewhere]\naws_access_key_id = AKIAELSEWHERE\naws_secret_access_key = test-secret-access-key-value\n",
    )?;
    let home = home_dir
        .path()
        .to_str()
        .ok_or("a UTF-8 temporary directory")?;
    let keys = custom.join("keys");
    let env = environment(&[
        ("HOME", home),
        ("AWS_CONFIG_FILE", "~/custom/config"),
        (
            "AWS_SHARED_CREDENTIALS_FILE",
            keys.to_str().ok_or("a UTF-8 path")?,
        ),
    ]);
    let aws = FakeAws::default().caller("AKIAELSEWHERE", OTHER_ACCOUNT, USER_ARN)?;
    let mut app = App::start(aws, env).await?;
    app.ok("signIn", profile_sign_in("elsewhere", &[])?, "signInResult")
        .await?;
    let values = values_of(&app.ok("env", json!({}), "envResult").await?)?;
    assert_eq!(values.get("AWS_REGION").ok_or("no region")?.0, "ap-south-1");
    Ok(())
}

#[tokio::test]
async fn a_profile_the_block_cannot_use_says_why_before_aws_is_called() -> TestResult {
    let config = "
[profile sso]
sso_start_url = https://my-org.awsapps.com/start
sso_region = eu-west-1

[profile via-sso]
role_arn = arn:aws:iam::123456789012:role/deploy
source_profile = sso

[profile process]
credential_process = /usr/local/bin/get-keys

[profile mfa]
role_arn = arn:aws:iam::123456789012:role/deploy
source_profile = default
mfa_serial = arn:aws:iam::123456789012:mfa/alice

[profile loop-a]
role_arn = arn:aws:iam::123456789012:role/a
source_profile = loop-b

[profile loop-b]
role_arn = arn:aws:iam::123456789012:role/b
source_profile = loop-a

[profile half]
aws_access_key_id = AKIAHALF

[profile imds]
role_arn = arn:aws:iam::123456789012:role/deploy
credential_source = Ec2InstanceMetadata

[profile sourceless]
role_arn = arn:aws:iam::123456789012:role/deploy

[profile ghostly]
role_arn = arn:aws:iam::123456789012:role/deploy
source_profile = ghost

[profile slow]
role_arn = arn:aws:iam::123456789012:role/deploy
source_profile = default
duration_seconds = an hour

[profile nothing]
region = eu-west-1
";
    let (_home, env) = home(config, KEYS, &[])?;
    let aws = FakeAws::default();
    let mut app = App::start(aws.clone(), env).await?;
    for (profile, says) in [
        ("sso", "profile \"sso\" signs in with IAM Identity Center"),
        (
            "via-sso",
            "takes its keys from profile \"sso\", which signs in with IAM Identity Center: use the AWS SSO method",
        ),
        ("process", "gets its keys with credential_process"),
        ("mfa", "needs an MFA code"),
        ("loop-a", "comes back to itself"),
        ("half", "has aws_access_key_id but no aws_secret_access_key"),
        (
            "imds",
            "credential_source \"Ec2InstanceMetadata\", which this block cannot reach",
        ),
        ("sourceless", "neither source_profile nor credential_source"),
        ("ghostly", "there is no AWS profile \"ghost\""),
        ("slow", "duration_seconds is not a whole number"),
        ("nothing", "profile \"nothing\" has no keys"),
        (
            "nope",
            "there is no AWS profile \"nope\" in ~/.aws/config or ~/.aws/credentials: the profiles are default, dev, ghostly",
        ),
    ] {
        let error = app
            .fails("signIn", profile_sign_in(profile, &[])?, "invalidParams")
            .await?;
        assert!(message(&error)?.contains(says), "{profile}: {error}");
    }
    assert_eq!(aws.calls(), []);
    assert_eq!(aws.sso_log(), Vec::<String>::new());
    Ok(())
}

#[tokio::test]
async fn a_file_that_does_not_parse_names_its_line_and_never_its_values() -> TestResult {
    let (_home, env) = home(
        "",
        "[dev]\naws_secret_access_key test-secret-access-key-value\n",
        &[],
    )?;
    let mut app = App::start(FakeAws::default(), env).await?;
    let error = app
        .fails("signIn", profile_sign_in("dev", &[])?, "invalidParams")
        .await?;
    let message = message(&error)?;
    assert!(message.contains("credentials on line 2"), "{message}");
    assert!(!message.contains(SECRET), "{message}");
    Ok(())
}

#[tokio::test]
async fn an_assumed_roles_keys_are_refreshed_by_signing_in_again() -> TestResult {
    let config = "
[profile deploy]
role_arn = arn:aws-us-gov:iam::123456789012:role/deploy
source_profile = default
region = us-gov-east-1
";
    let (_home, env) = home(config, KEYS, &[])?;
    let aws = FakeAws::default()
        .assumes(
            DEPLOY_ROLE,
            vec![
                Ok(assumed("ASIAOLD", IN_TWO_MINUTES)),
                Ok(assumed("ASIANEW", IN_AN_HOUR)),
            ],
        )
        .caller("ASIAOLD", ACCOUNT, DEPLOY_ARN)?
        .caller("ASIANEW", ACCOUNT, DEPLOY_ARN)?;
    let mut app = App::start(aws.clone(), env).await?;
    app.ok("signIn", profile_sign_in("deploy", &[])?, "signInResult")
        .await?;
    let env = app.ok("env", json!({}), "envResult").await?;
    assert_eq!(
        values_of(&env)?.get("AWS_ACCESS_KEY_ID").ok_or("no key")?.0,
        "ASIANEW"
    );
    assert_eq!(at(&env, "/expiresAt"), IN_AN_HOUR);
    assert_eq!(aws.sso_log().len(), 2);
    // The fresh keys were checked against the pins like the first.
    assert_eq!(aws.calls().len(), 2);
    Ok(())
}

#[tokio::test]
async fn a_profiles_secrets_leave_the_plugin_only_in_envs_result() -> TestResult {
    let config = "
[profile deploy]
role_arn = arn:aws-us-gov:iam::123456789012:role/deploy
source_profile = dev

[profile mfa]
role_arn = arn:aws:iam::123456789012:role/deploy
source_profile = dev
mfa_serial = arn:aws:iam::123456789012:mfa/alice
";
    let credentials = format!("{KEYS}\n[broken]\naws_secret_access_key = {SECRET}\n");
    let (_home, env) = home(config, &credentials, &[])?;
    let aws = FakeAws::default()
        .assumes(DEPLOY_ROLE, vec![Ok(assumed("ASIADEPLOY", IN_AN_HOUR))])
        .caller("ASIADEPLOY", ACCOUNT, DEPLOY_ARN)?;
    let mut app = App::start(aws, env).await?;
    // Every profile path: keys AWS refuses, a refusal before AWS, a profile
    // with only a secret, and a role it gives.
    app.call("signIn", profile_sign_in("dev", &[])?).await?;
    app.call("signIn", profile_sign_in("mfa", &[])?).await?;
    app.call("signIn", profile_sign_in("broken", &[])?).await?;
    app.call("signIn", profile_sign_in("deploy", &[])?).await?;
    app.call("env", json!({})).await?;

    let mut env_lines = 0;
    for (method, line) in &app.written {
        for never in [SECRET, TOKEN] {
            assert!(
                !line.contains(never),
                "{method} wrote a profile's secret: {line}"
            );
        }
        if method == "env" {
            env_lines += 1;
            assert!(
                line.contains(ASSUMED_SECRET) && line.contains(ASSUMED_TOKEN),
                "{line}"
            );
        } else {
            assert!(
                !line.contains(ASSUMED_SECRET) && !line.contains(ASSUMED_TOKEN),
                "{method} wrote a role's key: {line}"
            );
        }
    }
    assert_eq!(env_lines, 1);
    Ok(())
}
