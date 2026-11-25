//! Drives the plugin as the app would: the transport's loop over in-memory
//! pipes, a fake AWS, and every line the plugin writes checked against the
//! protocol schema.

use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::future::{self, Future};
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use jsonschema::{Draft, Registry, Validator};
use runbooks_credential_aws::{
    AccountId, Aws, AwsCredentials, AwsError, AwsErrorKind, AwsPlugin, CallerIdentity, Clock,
    Environment, Region, Service,
};
use runbooks_plugin_protocol::PROTOCOL_VERSION;
use runbooks_plugin_protocol::credential::DetectParams;
use runbooks_plugin_transport::{CredentialPlugin, ServeError, serve};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, Lines, duplex};
use tokio::task::JoinHandle;
use tokio::time::timeout;

type TestResult = Result<(), Box<dyn Error>>;

/// Longer than any answer takes on a loaded runner; a hang fails the test.
const WAIT: Duration = Duration::from_secs(10);

const ACCOUNT: &str = "123456789012";
const OTHER_ACCOUNT: &str = "210987654321";
const ROLE_ARN: &str = "arn:aws:sts::123456789012:assumed-role/deploy/ci";
const USER_ARN: &str = "arn:aws:iam::210987654321:user/alice";
/// What the fixed clock reads.
const NOW: &str = "2026-11-24T18:00:00Z";

/// A secret access key the tests type into sign-in fields and put in the
/// environment. It must leave the plugin only in `env`'s result.
const SECRET: &str = "test-secret-access-key-value";
const TOKEN: &str = "test-session-token";

// The schema.

const SCHEMAS: [&str; 2] = ["base.schema.json", "credential.schema.json"];
const ROOT: &str = "json-schema:///";

fn validator(schema: &Value) -> Result<Validator, Box<dyn Error>> {
    let mut registry = Registry::new();
    for file in SCHEMAS {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../schema")
            .join(file);
        let contents: Value = serde_json::from_str(&fs::read_to_string(path)?)?;
        registry = registry.add(format!("{ROOT}{file}"), contents)?;
    }
    let registry = registry.prepare()?;
    Ok(jsonschema::options()
        .with_draft(Draft::Draft202012)
        .with_registry(&registry)
        .should_validate_formats(true)
        .build(schema)?)
}

fn assert_valid(def: &str, value: &Value) -> TestResult {
    validator(&json!({ "$ref": format!("{ROOT}credential.schema.json#/$defs/{def}") }))?
        .validate(value)
        .map_err(|e| format!("{def}: {e} in {value}"))?;
    Ok(())
}

/// The member of `value` at JSON Pointer `pointer`, or `null` if there is none.
fn at(value: &Value, pointer: &str) -> Value {
    value.pointer(pointer).cloned().unwrap_or(Value::Null)
}

// The fake AWS.

/// What the fake answers for each access key, and the calls it got.
#[derive(Clone, Debug, Default)]
struct FakeAws {
    callers: HashMap<String, Result<CallerIdentity, AwsError>>,
    calls: Arc<Mutex<Vec<Call>>>,
}

/// One `GetCallerIdentity`: the key it was signed with and the region it went to.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Call {
    access_key_id: String,
    region: String,
}

impl FakeAws {
    fn caller(
        mut self,
        access_key_id: &str,
        account: &str,
        arn: &str,
    ) -> Result<Self, Box<dyn Error>> {
        let identity = CallerIdentity {
            account: AccountId::parse(account)?,
            arn: arn.to_owned(),
            alias: Some("sandbox".to_owned()),
        };
        self.callers.insert(access_key_id.to_owned(), Ok(identity));
        Ok(self)
    }

    fn failing(mut self, access_key_id: &str, kind: AwsErrorKind, detail: &str) -> Self {
        self.callers.insert(
            access_key_id.to_owned(),
            Err(AwsError::new(Service::Sts, kind, detail)),
        );
        self
    }

    fn calls(&self) -> Vec<Call> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Aws for FakeAws {
    fn caller_identity(
        &self,
        credentials: &AwsCredentials,
        region: &Region,
    ) -> impl Future<Output = Result<CallerIdentity, AwsError>> + Send {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Call {
                access_key_id: credentials.access_key_id.clone(),
                region: region.to_string(),
            });
        future::ready(
            self.callers
                .get(&credentials.access_key_id)
                .cloned()
                .unwrap_or_else(|| {
                    Err(AwsError::new(
                        Service::Sts,
                        AwsErrorKind::Refused,
                        "InvalidClientTokenId: The security token included in the request is invalid.",
                    ))
                }),
        )
    }
}

#[derive(Debug)]
struct FixedClock(OffsetDateTime);

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

fn environment(pairs: &[(&str, &str)]) -> Environment {
    Environment::new(
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
    )
}

// The app's side.

struct App {
    stdin: Option<DuplexStream>,
    stdout: Lines<BufReader<DuplexStream>>,
    _serve: JoinHandle<Result<(), ServeError>>,
    message: Validator,
    next_id: i64,
    /// Every line the plugin wrote, with the method of the request it answers.
    written: Vec<(String, String)>,
}

impl App {
    async fn start(aws: FakeAws, env: Environment) -> Result<Self, Box<dyn Error>> {
        let (stdin, plugin_stdin) = duplex(64 * 1024);
        let (plugin_stdout, stdout) = duplex(64 * 1024);
        let message = json!({ "oneOf": [
            { "$ref": format!("{ROOT}base.schema.json#/$defs/resultResponse") },
            { "$ref": format!("{ROOT}base.schema.json#/$defs/errorResponse") },
            { "$ref": format!("{ROOT}base.schema.json#/$defs/notification") },
        ]});
        let clock = FixedClock(OffsetDateTime::parse(NOW, &Rfc3339)?);
        let plugin = AwsPlugin::new(aws, clock, env);
        let mut app = Self {
            stdin: Some(stdin),
            stdout: BufReader::new(stdout).lines(),
            _serve: tokio::spawn(serve(plugin, plugin_stdin, plugin_stdout)),
            message: validator(&message)?,
            next_id: 0,
            written: Vec::new(),
        };
        let configured = app
            .call(
                "configure",
                json!({"protocolVersion": PROTOCOL_VERSION, "caller": "runbooks/0.31.0", "stateDir": "/state/aws-auth"}),
            )
            .await?;
        assert_valid("configureResult", &at(&configured, "/result"))?;
        Ok(app)
    }

    async fn receive(&mut self, method: &str) -> Result<Value, Box<dyn Error>> {
        let line = timeout(WAIT, self.stdout.next_line())
            .await??
            .ok_or("the plugin's output ended")?;
        self.written.push((method.to_owned(), line.clone()));
        let message: Value = serde_json::from_str(&line)?;
        self.message
            .validate(&message)
            .map_err(|e| format!("{line}: {e}"))?;
        Ok(message)
    }

    /// Sends a request and returns its response, valid for the schema.
    async fn call(&mut self, method: &str, params: Value) -> Result<Value, Box<dyn Error>> {
        self.next_id += 1;
        let request =
            json!({"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params});
        let stdin = self.stdin.as_mut().ok_or("the plugin's input is closed")?;
        stdin.write_all(format!("{request}\n").as_bytes()).await?;
        let response = self.receive(method).await?;
        assert_eq!(at(&response, "/id"), self.next_id, "{response}");
        Ok(response)
    }

    /// The result of a call that should succeed, valid for `def`.
    async fn ok(
        &mut self,
        method: &str,
        params: Value,
        def: &str,
    ) -> Result<Value, Box<dyn Error>> {
        let response = self.call(method, params).await?;
        let result = response
            .get("result")
            .ok_or_else(|| format!("{method} failed: {response}"))?
            .clone();
        assert_valid(def, &result)?;
        Ok(result)
    }

    /// The error of a call that should fail with `kind`.
    async fn fails(
        &mut self,
        method: &str,
        params: Value,
        kind: &str,
    ) -> Result<Value, Box<dyn Error>> {
        let response = self.call(method, params).await?;
        let error = response
            .get("error")
            .ok_or_else(|| format!("{method} succeeded: {response}"))?
            .clone();
        assert_eq!(at(&error, "/data/kind"), kind, "{response}");
        Ok(error)
    }

    async fn detect(&mut self, sources: Value, pins: Value) -> Result<Value, Box<dyn Error>> {
        self.call(
            "detect",
            json!({"sources": sources, "pins": pins, "requirements": []}),
        )
        .await
    }
}

fn keys_sign_in(access_key_id: &str, extra: &[(&str, &str)]) -> Result<Value, Box<dyn Error>> {
    let mut fields = json!({"accessKeyId": access_key_id, "secretAccessKey": SECRET});
    for (name, value) in extra {
        fields
            .as_object_mut()
            .ok_or("not an object")?
            .insert((*name).to_owned(), json!(value));
    }
    Ok(json!({"method": "credentials", "fields": fields, "pins": {}, "requirements": []}))
}

/// One of `env`'s values: the value, whether it is sensitive, and where it goes.
type Delivered = (String, bool, Vec<String>);

/// The env values by name.
fn values_of(env: &Value) -> Result<HashMap<String, Delivered>, Box<dyn Error>> {
    let values = env["values"].as_array().ok_or("values")?;
    let mut out = HashMap::new();
    for value in values {
        let to = value["to"]
            .as_array()
            .ok_or("to")?
            .iter()
            .filter_map(|t| t.as_str().map(str::to_owned))
            .collect();
        out.insert(
            value["name"].as_str().ok_or("name")?.to_owned(),
            (
                value["value"].as_str().ok_or("value")?.to_owned(),
                value["sensitive"].as_bool().ok_or("sensitive")?,
                to,
            ),
        );
    }
    Ok(out)
}

// configure.

#[tokio::test]
async fn configure_offers_static_keys_the_levels_and_every_name_a_run_gets() -> TestResult {
    let mut app = App::start(FakeAws::default(), Environment::default()).await?;
    // App::start configured once; a second answer is the same.
    let result = app
        .ok(
            "configure",
            json!({"protocolVersion": PROTOCOL_VERSION, "caller": "runbooks/0.31.0", "stateDir": "/s"}),
            "configureResult",
        )
        .await?;
    assert_eq!(at(&result, "/cloud"), "aws");
    assert_eq!(
        at(&result, "/names"),
        json!([
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AWS_REGION"
        ])
    );
    let levels: Vec<&str> = result
        .get("levels")
        .and_then(Value::as_array)
        .ok_or("levels")?
        .iter()
        .filter_map(|l| l["name"].as_str())
        .collect();
    assert_eq!(levels, ["account", "role"]);

    let credentials = result
        .get("methods")
        .and_then(Value::as_array)
        .ok_or("methods")?
        .iter()
        .find(|m| m["name"] == "credentials")
        .ok_or("a credentials method")?;
    let secret_fields: Vec<&str> = credentials["fields"]
        .as_array()
        .ok_or("fields")?
        .iter()
        .filter(|f| f["secret"] == true)
        .filter_map(|f| f["name"].as_str())
        .collect();
    assert_eq!(secret_fields, ["secretAccessKey", "sessionToken"]);
    Ok(())
}

// detect.

#[tokio::test]
async fn detect_finds_env_keys_and_checks_them_in_the_partition_of_their_region() -> TestResult {
    let aws = FakeAws::default().caller("AKIAGOV", ACCOUNT, ROLE_ARN)?;
    let env = environment(&[
        ("AWS_ACCESS_KEY_ID", "AKIAGOV"),
        ("AWS_SECRET_ACCESS_KEY", SECRET),
        ("AWS_SESSION_TOKEN", TOKEN),
        ("AWS_REGION", "us-gov-east-1"),
    ]);
    let mut app = App::start(aws.clone(), env).await?;
    let response = app.detect(json!([{"kind": "env"}]), json!({})).await?;
    let result = &at(&response, "/result");
    assert_valid("detectResult", result)?;
    assert_eq!(result["found"], true, "{response}");
    assert_eq!(result["source"], "env");
    assert_eq!(at(result, "/identity/principal"), ROLE_ARN);
    assert_eq!(at(result, "/identity/kind"), "role");
    assert_eq!(at(result, "/identity/targets/account/id"), ACCOUNT);
    assert_eq!(at(result, "/identity/targets/account/name"), "sandbox");
    assert_eq!(at(result, "/identity/targets/role/id"), "deploy");
    assert_eq!(
        aws.calls(),
        [Call {
            access_key_id: "AKIAGOV".to_owned(),
            region: "us-gov-west-1".to_owned(),
        }]
    );

    // The run gets the detected keys and the environment's region, the
    // secret ones marked sensitive.
    let env = app.ok("env", json!({}), "envResult").await?;
    let values = values_of(&env)?;
    let both = vec!["env".to_owned(), "output".to_owned()];
    assert_eq!(
        values.get("AWS_ACCESS_KEY_ID"),
        Some(&("AKIAGOV".to_owned(), false, both.clone()))
    );
    assert_eq!(
        values.get("AWS_SECRET_ACCESS_KEY"),
        Some(&(SECRET.to_owned(), true, both.clone()))
    );
    assert_eq!(
        values.get("AWS_SESSION_TOKEN"),
        Some(&(TOKEN.to_owned(), true, both.clone()))
    );
    assert_eq!(
        values.get("AWS_REGION"),
        Some(&("us-gov-east-1".to_owned(), false, both))
    );
    assert_eq!(values.len(), 4);
    Ok(())
}

#[tokio::test]
async fn a_prefixed_source_reads_only_its_own_names_and_an_unset_region_is_us_east_1() -> TestResult
{
    let aws = FakeAws::default()
        .caller("AKIADEV", OTHER_ACCOUNT, USER_ARN)?
        .caller("AKIAPROD", ACCOUNT, ROLE_ARN)?;
    let env = environment(&[
        ("AWS_ACCESS_KEY_ID", "AKIADEV"),
        ("AWS_SECRET_ACCESS_KEY", SECRET),
        ("PROD_AWS_ACCESS_KEY_ID", "AKIAPROD"),
    ]);
    let mut app = App::start(aws.clone(), env).await?;
    // PROD_ has no secret key, and the unprefixed keys are never used for it.
    let response = app
        .detect(json!([{"kind": "env", "prefix": "PROD_"}]), json!({}))
        .await?;
    assert_eq!(
        at(&response, "/result"),
        json!({"found": false}),
        "{response}"
    );
    assert_eq!(aws.calls(), []);

    let env = environment(&[
        ("PROD_AWS_ACCESS_KEY_ID", "AKIAPROD"),
        ("PROD_AWS_SECRET_ACCESS_KEY", SECRET),
    ]);
    let mut app = App::start(aws.clone(), env).await?;
    let response = app
        .detect(json!([{"kind": "env", "prefix": "PROD_"}]), json!({}))
        .await?;
    assert_eq!(at(&response, "/result/source"), "env:PROD_", "{response}");
    assert_eq!(aws.calls().first().ok_or("no call")?.region, "us-east-1");
    let values = values_of(&app.ok("env", json!({}), "envResult").await?)?;
    assert_eq!(
        values.get("AWS_ACCESS_KEY_ID").ok_or("no key")?.0,
        "AKIAPROD"
    );
    assert_eq!(values.get("AWS_REGION").ok_or("no region")?.0, "us-east-1");
    // No session token: the output is empty and the variable unset.
    assert_eq!(
        values.get("AWS_SESSION_TOKEN"),
        Some(&(String::new(), true, vec!["output".to_owned()]))
    );
    Ok(())
}

#[tokio::test]
async fn detect_reads_an_earlier_blocks_values() -> TestResult {
    let aws = FakeAws::default().caller("ASIAOUT", ACCOUNT, ROLE_ARN)?;
    let mut app = App::start(aws, Environment::default()).await?;
    let values = json!({
        "AWS_ACCESS_KEY_ID": "ASIAOUT",
        "AWS_SECRET_ACCESS_KEY": SECRET,
        "AWS_SESSION_TOKEN": TOKEN,
        "AWS_REGION": "eu-west-1",
        "AWS_CREDENTIAL_EXPIRATION": "2026-11-24T19:00:00Z",
    });
    let response = app
        .detect(json!([{"kind": "values", "values": values}]), json!({}))
        .await?;
    assert_eq!(at(&response, "/result/source"), "values", "{response}");
    assert_eq!(
        at(&response, "/result/identity/expiresAt"),
        "2026-11-24T19:00:00Z"
    );
    let env = app.ok("env", json!({}), "envResult").await?;
    assert_eq!(at(&env, "/expiresAt"), "2026-11-24T19:00:00Z");
    assert_eq!(
        values_of(&env)?.get("AWS_REGION").ok_or("no region")?.0,
        "eu-west-1"
    );
    Ok(())
}

#[tokio::test]
async fn a_credential_the_pins_rule_out_is_skipped_for_the_next_source() -> TestResult {
    let aws = FakeAws::default()
        .caller("AKIADEV", OTHER_ACCOUNT, USER_ARN)?
        .caller("AKIAPROD", ACCOUNT, ROLE_ARN)?;
    let env = environment(&[
        ("AWS_ACCESS_KEY_ID", "AKIADEV"),
        ("AWS_SECRET_ACCESS_KEY", SECRET),
        ("PROD_AWS_ACCESS_KEY_ID", "AKIAPROD"),
        ("PROD_AWS_SECRET_ACCESS_KEY", SECRET),
    ]);
    let mut app = App::start(aws, env).await?;
    let both = json!([{"kind": "env"}, {"kind": "env", "prefix": "PROD_"}]);
    let response = app
        .detect(both.clone(), json!({"account": ACCOUNT, "role": "deploy"}))
        .await?;
    assert_eq!(at(&response, "/result/source"), "env:PROD_", "{response}");

    // With only the unprefixed source, the block learns why nothing matched.
    let error = app
        .fails(
            "detect",
            json!({"sources": [{"kind": "env"}], "pins": {"account": ACCOUNT}, "requirements": []}),
            "pinMismatch",
        )
        .await?;
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .ok_or("message")?;
    assert!(
        message.contains(OTHER_ACCOUNT) && message.contains(ACCOUNT),
        "{message}"
    );

    let error = app
        .fails(
            "detect",
            json!({"sources": [{"kind": "env"}], "pins": {"role": "deploy"}, "requirements": []}),
            "pinMismatch",
        )
        .await?;
    assert!(
        at(&error, "/message")
            .as_str()
            .ok_or("message")?
            .contains(USER_ARN),
        "{error}"
    );
    Ok(())
}

#[tokio::test]
async fn keys_aws_refuses_fail_detect_with_its_reason() -> TestResult {
    let aws = FakeAws::default().failing(
        "AKIAOLD",
        AwsErrorKind::Expired,
        "ExpiredToken: The security token included in the request is expired",
    );
    let env = environment(&[
        ("AWS_ACCESS_KEY_ID", "AKIAOLD"),
        ("AWS_SECRET_ACCESS_KEY", SECRET),
    ]);
    let mut app = App::start(aws, env).await?;
    let error = app
        .fails(
            "detect",
            json!({"sources": [{"kind": "env"}], "pins": {}, "requirements": []}),
            "expired",
        )
        .await?;
    assert!(
        at(&error, "/message")
            .as_str()
            .ok_or("message")?
            .contains("ExpiredToken"),
        "{error}"
    );

    let mut app = App::start(
        FakeAws::default().failing("AKIA", AwsErrorKind::Network, "dispatch failure"),
        environment(&[
            ("AWS_ACCESS_KEY_ID", "AKIA"),
            ("AWS_SECRET_ACCESS_KEY", SECRET),
        ]),
    )
    .await?;
    app.fails(
        "detect",
        json!({"sources": [{"kind": "env"}], "pins": {}, "requirements": []}),
        "network",
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn detect_refuses_bad_params_before_calling_aws() -> TestResult {
    let aws = FakeAws::default().caller("AKIA", ACCOUNT, ROLE_ARN)?;
    let env = environment(&[
        ("AWS_ACCESS_KEY_ID", "AKIA"),
        ("AWS_SECRET_ACCESS_KEY", SECRET),
    ]);
    let mut app = App::start(aws.clone(), env).await?;
    for (params, names) in [
        (
            json!({"sources": [{"kind": "env"}, {"kind": "env", "prefix": "prod"}], "pins": {}, "requirements": []}),
            "\"prod\"",
        ),
        (
            json!({"sources": [{"kind": "env"}, {"kind": "named", "name": "cli"}], "pins": {}, "requirements": []}),
            "\"cli\"",
        ),
        (
            json!({"sources": [{"kind": "env"}], "pins": {"project": "p"}, "requirements": []}),
            "\"project\"",
        ),
        (
            json!({"sources": [{"kind": "env"}], "pins": {"account": "12345"}, "requirements": []}),
            "\"12345\"",
        ),
        (
            json!({"sources": [{"kind": "env"}], "pins": {}, "requirements": [{"kind": "scopes", "scopes": ["s"]}]}),
            "requirements",
        ),
    ] {
        let error = app.fails("detect", params, "invalidParams").await?;
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .ok_or("message")?;
        assert!(message.contains(names), "{message} should name {names}");
    }
    assert_eq!(aws.calls(), []);
    Ok(())
}

#[tokio::test]
async fn a_region_that_is_not_one_names_its_variable() -> TestResult {
    let aws = FakeAws::default().caller("AKIA", ACCOUNT, ROLE_ARN)?;
    let env = environment(&[
        ("PROD_AWS_ACCESS_KEY_ID", "AKIA"),
        ("PROD_AWS_SECRET_ACCESS_KEY", SECRET),
        ("PROD_AWS_REGION", "Oregon"),
    ]);
    let mut app = App::start(aws.clone(), env).await?;
    let error = app
        .fails(
            "detect",
            json!({"sources": [{"kind": "env", "prefix": "PROD_"}], "pins": {}, "requirements": []}),
            "invalidParams",
        )
        .await?;
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .ok_or("message")?;
    assert!(
        message.contains("PROD_AWS_REGION") && message.contains("\"Oregon\""),
        "{message}"
    );
    assert_eq!(aws.calls(), []);
    Ok(())
}

// signIn with static keys.

#[tokio::test]
async fn static_keys_sign_in_and_a_run_gets_them_with_the_chosen_region() -> TestResult {
    let aws = FakeAws::default().caller("AKIAKEYS", OTHER_ACCOUNT, USER_ARN)?;
    let mut app = App::start(aws.clone(), Environment::default()).await?;
    let identity = app
        .ok(
            "signIn",
            keys_sign_in(
                "AKIAKEYS",
                &[("defaultRegion", "ca-central-1"), ("sessionToken", "")],
            )?,
            "signInResult",
        )
        .await?;
    assert_eq!(at(&identity, "/principal"), USER_ARN);
    assert_eq!(at(&identity, "/kind"), "user");
    assert_eq!(at(&identity, "/method"), "credentials");
    assert!(identity.get("expiresAt").is_none(), "{identity}");
    assert_eq!(aws.calls().first().ok_or("no call")?.region, "us-east-1");

    let env = app.ok("env", json!({}), "envResult").await?;
    let values = values_of(&env)?;
    let both = vec!["env".to_owned(), "output".to_owned()];
    assert_eq!(
        values.get("AWS_ACCESS_KEY_ID"),
        Some(&("AKIAKEYS".to_owned(), false, both.clone()))
    );
    assert_eq!(
        values.get("AWS_SECRET_ACCESS_KEY"),
        Some(&(SECRET.to_owned(), true, both.clone()))
    );
    assert_eq!(
        values.get("AWS_REGION"),
        Some(&("ca-central-1".to_owned(), false, both))
    );
    // No session token: the output is empty and the variable unset.
    assert_eq!(
        values.get("AWS_SESSION_TOKEN"),
        Some(&(String::new(), true, vec!["output".to_owned()]))
    );
    Ok(())
}

#[tokio::test]
async fn a_sign_in_names_every_missing_and_unknown_field() -> TestResult {
    let mut app = App::start(FakeAws::default(), Environment::default()).await?;
    let params = json!({"method": "credentials", "fields": {"accessKeyId": "", "region": "us-east-1"}, "pins": {}, "requirements": []});
    let error = app.fails("signIn", params, "invalidParams").await?;
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .ok_or("message")?;
    for name in ["accessKeyId", "secretAccessKey", "region", "defaultRegion"] {
        assert!(message.contains(name), "{message} should name {name}");
    }

    let error = app
        .fails(
            "signIn",
            keys_sign_in("AKIA", &[("defaultRegion", "Ohio")])?,
            "invalidParams",
        )
        .await?;
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .ok_or("message")?;
    assert!(
        message.contains("defaultRegion") && message.contains("\"Ohio\""),
        "{message}"
    );

    let error = app
        .fails(
            "signIn",
            json!({"method": "oauth", "fields": {}, "pins": {}, "requirements": []}),
            "invalidParams",
        )
        .await?;
    assert!(
        at(&error, "/message")
            .as_str()
            .ok_or("message")?
            .contains("credentials"),
        "{error}"
    );
    Ok(())
}

#[tokio::test]
async fn static_keys_for_another_account_than_the_pin_are_refused() -> TestResult {
    let aws = FakeAws::default().caller("AKIAKEYS", OTHER_ACCOUNT, USER_ARN)?;
    let mut app = App::start(aws, Environment::default()).await?;
    let mut params = keys_sign_in("AKIAKEYS", &[])?;
    params
        .as_object_mut()
        .ok_or("not an object")?
        .insert("pins".to_owned(), json!({"account": ACCOUNT}));
    app.fails("signIn", params, "pinMismatch").await?;
    app.fails("env", json!({}), "notSignedIn").await?;
    Ok(())
}

// env and signOut.

#[tokio::test]
async fn env_needs_a_sign_in_and_sign_out_drops_it() -> TestResult {
    let aws = FakeAws::default().caller("AKIAKEYS", OTHER_ACCOUNT, USER_ARN)?;
    let mut app = App::start(aws, Environment::default()).await?;
    app.fails("env", json!({}), "notSignedIn").await?;
    app.ok("signIn", keys_sign_in("AKIAKEYS", &[])?, "signInResult")
        .await?;
    app.ok("env", json!({}), "envResult").await?;
    app.ok("signOut", json!({}), "signOutResult").await?;
    app.fails("env", json!({}), "notSignedIn").await?;
    Ok(())
}

#[tokio::test]
async fn the_plugins_debug_shows_its_credential_but_never_a_secret() -> TestResult {
    let aws = FakeAws::default().caller("AKIADEBUG", ACCOUNT, ROLE_ARN)?;
    let env = environment(&[
        ("AWS_ACCESS_KEY_ID", "AKIADEBUG"),
        ("AWS_SECRET_ACCESS_KEY", SECRET),
        ("AWS_SESSION_TOKEN", TOKEN),
    ]);
    let plugin = AwsPlugin::new(aws, FixedClock(OffsetDateTime::parse(NOW, &Rfc3339)?), env);
    let params: DetectParams = serde_json::from_value(
        json!({"sources": [{"kind": "env"}], "pins": {}, "requirements": []}),
    )?;
    plugin.detect(params).await?;
    let shown = format!("{plugin:?}");
    // Only the detected credential's keys show as redacted secrets.
    assert!(shown.contains("Secret(redacted)"), "{shown}");
    assert!(!shown.contains(SECRET) && !shown.contains(TOKEN), "{shown}");
    Ok(())
}

#[tokio::test]
async fn keys_past_their_expiration_are_expired() -> TestResult {
    let aws = FakeAws::default().caller("ASIA", ACCOUNT, ROLE_ARN)?;
    let env = environment(&[
        ("AWS_ACCESS_KEY_ID", "ASIA"),
        ("AWS_SECRET_ACCESS_KEY", SECRET),
        ("AWS_CREDENTIAL_EXPIRATION", "2026-11-24T17:59:59Z"),
    ]);
    let mut app = App::start(aws, env).await?;
    let response = app.detect(json!([{"kind": "env"}]), json!({})).await?;
    assert_eq!(at(&response, "/result/found"), true, "{response}");
    let error = app.fails("env", json!({}), "expired").await?;
    assert!(
        at(&error, "/message")
            .as_str()
            .ok_or("message")?
            .contains("2026-11-24T17:59:59Z"),
        "{error}"
    );
    Ok(())
}

#[tokio::test]
async fn targets_and_select_have_nothing_to_choose_for_static_keys() -> TestResult {
    let mut app = App::start(FakeAws::default(), Environment::default()).await?;
    app.fails("targets", json!({"level": "account"}), "invalidParams")
        .await?;
    let error = app
        .fails("targets", json!({"level": "project"}), "invalidParams")
        .await?;
    assert!(
        at(&error, "/message")
            .as_str()
            .ok_or("message")?
            .contains("account and role"),
        "{error}"
    );
    app.fails(
        "select",
        json!({"targets": {"account": ACCOUNT}}),
        "invalidParams",
    )
    .await?;
    Ok(())
}

// Secrets.

#[tokio::test]
async fn a_secret_leaves_the_plugin_only_in_envs_result() -> TestResult {
    let aws = FakeAws::default()
        .caller("AKIAKEYS", OTHER_ACCOUNT, USER_ARN)?
        .caller("AKIAENV", ACCOUNT, ROLE_ARN)?;
    let env = environment(&[
        ("AWS_ACCESS_KEY_ID", "AKIAENV"),
        ("AWS_SECRET_ACCESS_KEY", SECRET),
        ("AWS_SESSION_TOKEN", TOKEN),
        ("BAD_AWS_ACCESS_KEY_ID", "AKIABAD"),
        ("BAD_AWS_SECRET_ACCESS_KEY", SECRET),
        ("BAD_AWS_REGION", SECRET),
    ]);
    let mut app = App::start(aws, env).await?;
    // Every path that handles a secret: detection that finds, refuses and
    // cannot read one; sign-ins that succeed and fail; each error.
    app.detect(json!([{"kind": "env", "prefix": "BAD_"}]), json!({}))
        .await?;
    app.detect(json!([{"kind": "env"}]), json!({"account": OTHER_ACCOUNT}))
        .await?;
    app.detect(
        json!([{"kind": "values", "values": {"AWS_ACCESS_KEY_ID": "AKIAWHO", "AWS_SECRET_ACCESS_KEY": SECRET, "AWS_SESSION_TOKEN": TOKEN}}]),
        json!({}),
    )
    .await?;
    app.detect(json!([{"kind": "env"}]), json!({})).await?;
    app.call(
        "signIn",
        keys_sign_in("AKIAWHO", &[("sessionToken", TOKEN)])?,
    )
    .await?;
    app.call(
        "signIn",
        keys_sign_in("AKIAKEYS", &[("sessionToken", TOKEN), ("nope", SECRET)])?,
    )
    .await?;
    app.call(
        "signIn",
        keys_sign_in("AKIAKEYS", &[("sessionToken", TOKEN)])?,
    )
    .await?;
    app.call("env", json!({})).await?;

    let mut env_lines = 0;
    for (method, line) in &app.written {
        if method == "env" {
            env_lines += 1;
            assert!(line.contains(SECRET) && line.contains(TOKEN), "{line}");
        } else {
            assert!(
                !line.contains(SECRET) && !line.contains(TOKEN),
                "{method} wrote a secret: {line}"
            );
        }
    }
    assert_eq!(env_lines, 1);
    Ok(())
}

/// Each refusal says which it is: a level AWS has, fixed for these keys, or
/// a level AWS does not have.
#[tokio::test]
async fn targets_says_whether_aws_has_the_level() -> TestResult {
    let mut app = App::start(FakeAws::default(), Environment::default()).await?;
    for (level, message) in [
        (
            "account",
            "AWS has no account to choose for these credentials: their account and role are fixed",
        ),
        (
            "role",
            "AWS has no role to choose for these credentials: their account and role are fixed",
        ),
        (
            "project",
            "AWS has no level \"project\": its levels are account and role",
        ),
    ] {
        let error = app
            .fails("targets", json!({"level": level}), "invalidParams")
            .await?;
        assert_eq!(at(&error, "/message"), message, "{level}");
    }
    Ok(())
}
