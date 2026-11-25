//! Drives the plugin as the app would: the transport's loop over in-memory
//! pipes, a fake AWS, and every line the plugin writes checked against the
//! protocol schema.

mod profile;
mod sso;

use std::collections::{HashMap, VecDeque};
use std::error::Error;
use std::fs;
use std::future::{self, Future};
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use jsonschema::{Draft, Registry, Validator};
use runbooks_credential_aws::{
    AccountId, AssumeRole, Aws, AwsCredentials, AwsError, AwsErrorKind, AwsPlugin, CallerIdentity,
    Clock, DeviceAuthorization, Environment, Region, Secret, Service, SsoAccount, SsoToken,
    TokenPoll,
};
use runbooks_plugin_protocol::PROTOCOL_VERSION;
use runbooks_plugin_protocol::credential::DetectParams;
use runbooks_plugin_transport::{CredentialPlugin, ServeError, serve};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, Lines, duplex};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout};

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
    /// AssumeRole's answers by role ARN, in order; the last repeats.
    assumed: Arc<Mutex<HashMap<String, VecDeque<KeysAnswer>>>>,
    sso: FakeSso,
}

type KeysAnswer = Result<AwsCredentials, AwsError>;

/// IAM Identity Center, as the fake answers it.
#[derive(Clone, Debug, Default)]
struct FakeSso {
    /// `CreateToken`'s answers, in order. Pending once they run out.
    polls: Arc<Mutex<VecDeque<Result<TokenPoll, AwsError>>>>,
    accounts: Vec<SsoAccount>,
    /// Role names by account id.
    roles: HashMap<String, Vec<String>>,
    /// `GetRoleCredentials`'s answers by "account/role", in order; the last repeats.
    keys: Arc<Mutex<HashMap<String, VecDeque<KeysAnswer>>>>,
    /// Holds the next `GetRoleCredentials` until it is sent.
    gate: Arc<Mutex<Option<oneshot::Receiver<()>>>>,
    /// Every call but GetCallerIdentity, as "<call> <detail> in <region>".
    log: Arc<Mutex<Vec<String>>>,
    started: Arc<Mutex<Option<Instant>>>,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
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

    /// AssumeRole for `role_arn` answers these, in order.
    fn assumes(self, role_arn: &str, keys: Vec<KeysAnswer>) -> Self {
        lock(&self.assumed).insert(role_arn.to_owned(), keys.into());
        self
    }

    /// `CreateToken` answers these, in order, then Pending.
    fn polls(self, polls: Vec<Result<TokenPoll, AwsError>>) -> Self {
        *lock(&self.sso.polls) = polls.into();
        self
    }

    fn account(mut self, id: &str, name: &str, roles: &[&str]) -> Result<Self, Box<dyn Error>> {
        self.sso.accounts.push(SsoAccount {
            id: AccountId::parse(id)?,
            name: name.to_owned(),
        });
        self.sso.roles.insert(
            id.to_owned(),
            roles.iter().map(|r| (*r).to_owned()).collect(),
        );
        Ok(self)
    }

    /// `GetRoleCredentials` for `role` in `account` answers these, in order.
    fn role_keys(self, account: &str, role: &str, keys: Vec<KeysAnswer>) -> Self {
        lock(&self.sso.keys).insert(format!("{account}/{role}"), keys.into());
        self
    }

    /// The next `GetRoleCredentials` waits until the returned sender is used.
    fn hold_next_keys(&self) -> oneshot::Sender<()> {
        let (open, gate) = oneshot::channel();
        *lock(&self.sso.gate) = Some(gate);
        open
    }

    fn sso_log(&self) -> Vec<String> {
        lock(&self.sso.log).clone()
    }

    fn record(&self, entry: String) {
        lock(&self.sso.log).push(entry);
    }
}

/// What every fake device authorization is.
const START_URL: &str = "https://my-org.awsapps.com/start";
const VERIFICATION_URL: &str = "https://device.sso.eu-west-1.amazonaws.com/?user_code=WDDD-HRQV";
const USER_CODE: &str = "WDDD-HRQV";
/// The secrets of the device flow: none may leave the plugin at all.
const CLIENT_SECRET: &str = "test-sso-client-secret";
const DEVICE_CODE: &str = "d3v1c3-c0d3-HrlZ8ptW0HgK";
const ACCESS_TOKEN: &str = "test-sso-access-token";

impl FakeSso {
    fn device() -> DeviceAuthorization {
        DeviceAuthorization {
            client_id: "client-id".to_owned(),
            client_secret: Secret::new(CLIENT_SECRET),
            device_code: Secret::new(DEVICE_CODE),
            user_code: USER_CODE.to_owned(),
            verification_url: VERIFICATION_URL.to_owned(),
            expires_in: Duration::from_secs(600),
            interval: Duration::from_secs(5),
        }
    }
}

/// The token a person's approval gives, good for eight hours.
fn approved() -> TokenPoll {
    TokenPoll::Approved(SsoToken {
        access_token: Secret::new(ACCESS_TOKEN),
        expires_in: Some(Duration::from_hours(8)),
    })
}

/// The next of a queue of answers: the last one repeats.
fn next_answer(queue: Option<&mut VecDeque<KeysAnswer>>) -> Option<KeysAnswer> {
    match queue {
        Some(queue) if queue.len() > 1 => queue.pop_front(),
        Some(queue) => queue.front().cloned(),
        None => None,
    }
}

fn sso_failure(kind: AwsErrorKind, detail: &str) -> AwsError {
    AwsError::new(Service::Sso, kind, detail)
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

    async fn assume_role(
        &self,
        credentials: &AwsCredentials,
        request: &AssumeRole,
        region: &Region,
    ) -> Result<AwsCredentials, AwsError> {
        let mut entry = format!(
            "assume {} as {} with {} in {region}",
            request.role_arn, request.session_name, credentials.access_key_id
        );
        if let Some(external_id) = &request.external_id {
            entry.push_str(&format!(" external {external_id}"));
        }
        if let Some(duration) = request.duration {
            entry.push_str(&format!(" for {}s", duration.as_secs()));
        }
        self.record(entry);
        next_answer(lock(&self.assumed).get_mut(&request.role_arn)).unwrap_or_else(|| {
            Err(AwsError::new(
                Service::Sts,
                AwsErrorKind::Refused,
                "AccessDenied: not authorized to perform sts:AssumeRole",
            ))
        })
    }

    fn start_device_authorization(
        &self,
        start_url: &str,
        region: &Region,
    ) -> impl Future<Output = Result<DeviceAuthorization, AwsError>> + Send {
        *lock(&self.sso.started) = Some(Instant::now());
        self.record(format!("start {start_url} in {region}"));
        future::ready(Ok(FakeSso::device()))
    }

    fn create_token(
        &self,
        device: &DeviceAuthorization,
        region: &Region,
    ) -> impl Future<Output = Result<TokenPoll, AwsError>> + Send {
        assert_eq!(device.device_code.expose(), DEVICE_CODE);
        let started = (*lock(&self.sso.started)).ok_or("polled before starting");
        let after = started.map_or(0, |at| at.elapsed().as_secs());
        self.record(format!("poll at {after}s in {region}"));
        future::ready(
            lock(&self.sso.polls)
                .pop_front()
                .unwrap_or(Ok(TokenPoll::Pending)),
        )
    }

    fn sso_accounts(
        &self,
        token: &SsoToken,
        region: &Region,
    ) -> impl Future<Output = Result<Vec<SsoAccount>, AwsError>> + Send {
        assert_eq!(token.access_token.expose(), ACCESS_TOKEN);
        self.record(format!("accounts in {region}"));
        future::ready(Ok(self.sso.accounts.clone()))
    }

    fn sso_roles(
        &self,
        token: &SsoToken,
        account: &AccountId,
        region: &Region,
    ) -> impl Future<Output = Result<Vec<String>, AwsError>> + Send {
        assert_eq!(token.access_token.expose(), ACCESS_TOKEN);
        self.record(format!("roles {account} in {region}"));
        future::ready(Ok(self
            .sso
            .roles
            .get(account.as_str())
            .cloned()
            .unwrap_or_default()))
    }

    async fn role_credentials(
        &self,
        token: &SsoToken,
        account: &AccountId,
        role: &str,
        region: &Region,
    ) -> Result<AwsCredentials, AwsError> {
        assert_eq!(token.access_token.expose(), ACCESS_TOKEN);
        self.record(format!("keys {account}/{role} in {region}"));
        let gate = lock(&self.sso.gate).take();
        if let Some(gate) = gate {
            let _opened = gate.await;
        }
        next_answer(lock(&self.sso.keys).get_mut(&format!("{account}/{role}"))).unwrap_or_else(
            || {
                Err(sso_failure(
                    AwsErrorKind::Refused,
                    "ForbiddenException: No access",
                ))
            },
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
    /// The method of each request sent, by id.
    methods: HashMap<i64, String>,
    /// Responses read while waiting for another, by id.
    early: HashMap<i64, Value>,
    /// Every notification's params, in order.
    notifications: Vec<Value>,
    /// Every line the plugin wrote, with the method of the request it
    /// answers or the notification's method.
    written: Vec<(String, String)>,
    /// How long to wait for a response. Tests with paused time wait for
    /// longer than the sign-in they drive takes.
    wait: Duration,
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
            methods: HashMap::new(),
            early: HashMap::new(),
            notifications: Vec::new(),
            written: Vec::new(),
            wait: WAIT,
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

    /// Sends a request without waiting for its response.
    async fn send(&mut self, method: &str, params: Value) -> Result<i64, Box<dyn Error>> {
        self.next_id += 1;
        let id = self.next_id;
        self.methods.insert(id, method.to_owned());
        let request = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let stdin = self.stdin.as_mut().ok_or("the plugin's input is closed")?;
        stdin.write_all(format!("{request}\n").as_bytes()).await?;
        Ok(id)
    }

    /// The response to request `id`, valid for the schema. Lines before it
    /// are kept: notifications, and responses to other requests.
    async fn response(&mut self, id: i64) -> Result<Value, Box<dyn Error>> {
        loop {
            if let Some(response) = self.early.remove(&id) {
                return Ok(response);
            }
            let line = timeout(self.wait, self.stdout.next_line())
                .await??
                .ok_or("the plugin's output ended")?;
            let message: Value = serde_json::from_str(&line)?;
            self.message
                .validate(&message)
                .map_err(|e| format!("{line}: {e}"))?;
            if let Some(answered) = message.get("id").and_then(Value::as_i64) {
                let method = self.methods.get(&answered).cloned().unwrap_or_default();
                self.written.push((method, line));
                self.early.insert(answered, message);
            } else {
                let method = message
                    .get("method")
                    .and_then(Value::as_str)
                    .ok_or("method")?
                    .to_owned();
                assert_eq!(method, "signIn.prompt", "{line}");
                let params = at(&message, "/params");
                assert_valid("signInPrompt", &params)?;
                self.written.push((method, line));
                self.notifications.push(params);
            }
        }
    }

    /// Sends a request and returns its response, valid for the schema.
    async fn call(&mut self, method: &str, params: Value) -> Result<Value, Box<dyn Error>> {
        let id = self.send(method, params).await?;
        self.response(id).await
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

    let sso = result
        .get("methods")
        .and_then(Value::as_array)
        .ok_or("methods")?
        .iter()
        .find(|m| m["name"] == "sso")
        .ok_or("an sso method")?;
    assert_eq!(sso["label"], "AWS SSO");
    let fields: Vec<(&str, bool)> = sso["fields"]
        .as_array()
        .ok_or("fields")?
        .iter()
        .filter_map(|f| Some((f["name"].as_str()?, f["required"].as_bool()?)))
        .collect();
    assert_eq!(
        fields,
        [
            ("ssoStartUrl", true),
            ("ssoRegion", false),
            ("defaultRegion", false)
        ]
    );
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
    let aws = FakeAws::default().caller("AKIAKEYS", OTHER_ACCOUNT, USER_ARN)?;
    let mut app = App::start(aws, Environment::default()).await?;
    app.fails("targets", json!({"level": "account"}), "notSignedIn")
        .await?;
    app.ok("signIn", keys_sign_in("AKIAKEYS", &[])?, "signInResult")
        .await?;
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
/// a level AWS does not have. Before a sign-in there is nothing to choose.
#[tokio::test]
async fn targets_says_whether_aws_has_the_level() -> TestResult {
    let aws = FakeAws::default().caller("AKIAKEYS", OTHER_ACCOUNT, USER_ARN)?;
    let mut app = App::start(aws, Environment::default()).await?;
    app.fails("targets", json!({"level": "account"}), "notSignedIn")
        .await?;
    app.ok("signIn", keys_sign_in("AKIAKEYS", &[])?, "signInResult")
        .await?;
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

/// What the form shows for static keys: the method's label, and each field's
/// name, label and whether it is required.
#[tokio::test]
async fn the_static_keys_method_is_labelled_for_the_form() -> TestResult {
    let mut app = App::start(FakeAws::default(), Environment::default()).await?;
    let result = app
        .ok(
            "configure",
            json!({"protocolVersion": PROTOCOL_VERSION, "caller": "runbooks/0.31.0", "stateDir": "/s"}),
            "configureResult",
        )
        .await?;
    let credentials = result
        .get("methods")
        .and_then(Value::as_array)
        .ok_or("methods")?
        .iter()
        .find(|m| m["name"] == "credentials")
        .ok_or("a credentials method")?;
    assert_eq!(credentials["label"], "Static Credentials");
    let fields: Vec<(&str, &str, bool)> = credentials["fields"]
        .as_array()
        .ok_or("fields")?
        .iter()
        .filter_map(|f| {
            Some((
                f["name"].as_str()?,
                f["label"].as_str()?,
                f["required"].as_bool()?,
            ))
        })
        .collect();
    assert_eq!(
        fields,
        [
            ("accessKeyId", "Access Key ID", true),
            ("secretAccessKey", "Secret Access Key", true),
            ("sessionToken", "Session Token", false),
            ("defaultRegion", "Default Region", false),
        ]
    );
    Ok(())
}

/// A field the method doesn't have refuses a sign-in even when every field
/// it needs is set, and each refusal says only what is wrong.
#[tokio::test]
async fn an_unknown_field_alone_refuses_a_sign_in() -> TestResult {
    let mut app = App::start(FakeAws::default(), Environment::default()).await?;
    let error = app
        .fails(
            "signIn",
            keys_sign_in("AKIA", &[("nope", "x")])?,
            "invalidParams",
        )
        .await?;
    assert_eq!(
        at(&error, "/message"),
        "the credentials method has no field nope: its fields are accessKeyId, secretAccessKey, sessionToken, defaultRegion"
    );
    let missing = json!({"method": "credentials", "fields": {"accessKeyId": "AKIA"}, "pins": {}, "requirements": []});
    let error = app.fails("signIn", missing, "invalidParams").await?;
    assert_eq!(
        at(&error, "/message"),
        "the credentials method needs secretAccessKey"
    );
    Ok(())
}
