//! Drives the loop as the app would, over in-memory pipes, and checks every
//! line the plugin writes against the protocol schema.

use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::future::{self, Future};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use jsonschema::{Draft, Registry, Validator};
use runbooks_plugin_protocol::PROTOCOL_VERSION;
use runbooks_plugin_protocol::credential::{
    ConfigureParams, ConfigureResult, DetectParams, DetectResult, EnvResult, ErrorKind, Identity,
    IdentityKind, Requirement, SelectParams, SelectResult, SignInParams, SignInResult,
    SignOutResult, Target, TargetsParams, TargetsResult,
};
use runbooks_plugin_transport::{
    CredentialPlugin, MAX_LINE_BYTES, PluginError, Prompts, ServeError, serve,
};
use serde_json::{Map, Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, Lines, duplex};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout};

type TestResult = Result<(), Box<dyn Error>>;

/// Longer than any answer takes on a loaded runner; a hang fails the test.
const WAIT: Duration = Duration::from_secs(10);

// The app's side.

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
    validator(&json!({ "$ref": format!("{ROOT}{def}") }))?
        .validate(value)
        .map_err(|e| format!("{def}: {e} in {value}"))?;
    Ok(())
}

/// The member of `value` at JSON Pointer `pointer`, or `null` if there is none.
fn at(value: &Value, pointer: &str) -> Value {
    value.pointer(pointer).cloned().unwrap_or(Value::Null)
}

/// Asserts `response` is an error answering `id`, with `code` and `kind`.
fn assert_error(response: &Value, id: &Value, code: i64, kind: &str) {
    assert_eq!(at(response, "/id"), *id, "{response}");
    assert_eq!(at(response, "/error/code"), code, "{response}");
    assert_eq!(at(response, "/error/data/kind"), kind, "{response}");
}

/// The app: it writes the plugin's input and reads its output.
struct App {
    stdin: Option<DuplexStream>,
    stdout: Lines<BufReader<DuplexStream>>,
    serve: JoinHandle<Result<(), ServeError>>,
    /// What every line the plugin writes must be.
    message: Validator,
}

impl App {
    fn start(plugin: Fake) -> Result<Self, Box<dyn Error>> {
        let (stdin, plugin_stdin) = duplex(64 * 1024);
        let (plugin_stdout, stdout) = duplex(64 * 1024);
        let message = json!({ "oneOf": [
            { "$ref": format!("{ROOT}base.schema.json#/$defs/resultResponse") },
            { "$ref": format!("{ROOT}base.schema.json#/$defs/errorResponse") },
            { "$ref": format!("{ROOT}base.schema.json#/$defs/notification") },
        ]});
        Ok(Self {
            stdin: Some(stdin),
            stdout: BufReader::new(stdout).lines(),
            serve: tokio::spawn(serve(plugin, plugin_stdin, plugin_stdout)),
            message: validator(&message)?,
        })
    }

    async fn send(&mut self, line: &str) -> TestResult {
        let stdin = self.stdin.as_mut().ok_or("the plugin's input is closed")?;
        stdin.write_all(line.as_bytes()).await?;
        stdin.write_all(b"\n").await?;
        Ok(())
    }

    async fn request(&mut self, id: Value, method: &str, params: Value) -> TestResult {
        let request = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        self.send(&request.to_string()).await
    }

    /// The plugin's next line: a response or a notification, valid for the schema.
    async fn receive(&mut self) -> Result<Value, Box<dyn Error>> {
        let line = timeout(WAIT, self.stdout.next_line())
            .await??
            .ok_or("the plugin's output ended")?;
        let message: Value = serde_json::from_str(&line)?;
        self.message
            .validate(&message)
            .map_err(|e| format!("{line}: {e}"))?;
        Ok(message)
    }

    async fn call(
        &mut self,
        id: Value,
        method: &str,
        params: Value,
    ) -> Result<Value, Box<dyn Error>> {
        self.request(id, method, params).await?;
        self.receive().await
    }

    async fn configure(&mut self) -> TestResult {
        self.configure_with(&runbooks_limits()).await
    }

    async fn configure_with(&mut self, limits: &Value) -> TestResult {
        let params = configure_params(PROTOCOL_VERSION, CALLER, limits);
        let response = self.call(json!(0), "configure", params).await?;
        assert_eq!(
            at(&response, "/result/protocolVersion"),
            PROTOCOL_VERSION,
            "{response}"
        );
        Ok(())
    }

    /// Closes the plugin's input, and waits for `serve` to return.
    async fn close(
        mut self,
    ) -> Result<(Result<(), ServeError>, Lines<BufReader<DuplexStream>>), Box<dyn Error>> {
        self.stdin = None;
        let served = timeout(WAIT, self.serve).await??;
        Ok((served, self.stdout))
    }
}

const CALLER: &str = "runbooks/0.31.0";

/// A caller whose `configure` the fake never finishes.
const HANGING_CALLER: &str = "runbooks/hangs";

fn configure_params(protocol_version: &str, caller: &str, limits: &Value) -> Value {
    json!({"protocolVersion": protocol_version, "caller": caller, "stateDir": "/state/block-1", "callTimeoutsMillis": limits})
}

/// What Runbooks sends in `callTimeoutsMillis`.
fn runbooks_limits() -> Value {
    json!({"configure": 30_000, "detect": 120_000, "targets": 120_000, "select": 120_000, "env": 120_000, "signOut": 60_000, "signIn": 900_000})
}

fn detect_params() -> Value {
    json!({"sources": [{"kind": "env"}], "pins": {}, "requirements": []})
}

fn sign_in_params() -> Value {
    json!({"method": "sso", "fields": {"startUrl": "https://example.awsapps.com/start"}, "pins": {}, "requirements": []})
}

// The plugin's side.

/// A plugin whose sign-in prompts, then waits until the test releases it.
#[derive(Default)]
struct Fake {
    release: Arc<Notify>,
    /// Sign-ins whose future was dropped before it finished.
    cancelled: Arc<AtomicUsize>,
    /// How long the name of level [`PADDED`]'s target is.
    padding: Arc<AtomicUsize>,
}

/// A level whose one target's name is as long as [`Fake::padding`] says.
const PADDED: &str = "padded";

/// A sign-in method whose prompt is longer than a line may be.
const OVERSIZED_PROMPT: &str = "oversized";

/// A level whose targets fail with a message longer than a line may be.
const OVERSIZED_ERROR: &str = "oversized";

struct CountIfCancelled {
    cancelled: Arc<AtomicUsize>,
    finished: bool,
}

impl Drop for CountIfCancelled {
    fn drop(&mut self) {
        if !self.finished {
            self.cancelled.fetch_add(1, Ordering::SeqCst);
        }
    }
}

fn identity(method: &str) -> Identity {
    Identity {
        expires_at: None,
        kind: IdentityKind::Role,
        method: method.to_owned(),
        principal: "arn:aws:sts::123456789012:assumed-role/dev/someone".to_owned(),
        targets: HashMap::new(),
        warnings: Vec::new(),
    }
}

impl CredentialPlugin for Fake {
    async fn configure(&self, params: ConfigureParams) -> Result<ConfigureResult, PluginError> {
        if params.caller == HANGING_CALLER {
            self.release.notified().await;
        }
        Ok(ConfigureResult {
            cloud: None,
            driver_version: "0.0.0".to_owned(),
            levels: Vec::new(),
            methods: Vec::new(),
            names: Vec::new(),
            protocol_version: PROTOCOL_VERSION.to_owned(),
            requirements: Vec::new(),
            sources: Vec::new(),
        })
    }

    fn detect(
        &self,
        _params: DetectParams,
    ) -> impl Future<Output = Result<DetectResult, PluginError>> + Send {
        future::ready(Ok(DetectResult::not_found()))
    }

    async fn sign_in(
        &self,
        params: SignInParams,
        prompts: Prompts,
    ) -> Result<SignInResult, PluginError> {
        let mut guard = CountIfCancelled {
            cancelled: Arc::clone(&self.cancelled),
            finished: false,
        };
        let url = if params.method == OVERSIZED_PROMPT {
            "x".repeat(MAX_LINE_BYTES)
        } else {
            "https://device.sso.us-east-1.amazonaws.com/".to_owned()
        };
        prompts.open_url(url, Some("ABCD-EFGH".to_owned())).await?;
        self.release.notified().await;
        guard.finished = true;
        Ok(SignInResult(identity(&params.method)))
    }

    fn targets(
        &self,
        params: TargetsParams,
    ) -> impl Future<Output = Result<TargetsResult, PluginError>> + Send {
        assert_ne!(params.level, "panic", "the test asked targets to panic");
        if params.level == OVERSIZED_ERROR {
            return future::ready(Err(PluginError::new(
                ErrorKind::Network,
                "x".repeat(MAX_LINE_BYTES),
            )));
        }
        let name = if params.level == PADDED {
            "x".repeat(self.padding.load(Ordering::SeqCst))
        } else {
            params.level.clone()
        };
        future::ready(Ok(TargetsResult {
            targets: vec![Target {
                id: params.level,
                name,
            }],
        }))
    }

    fn select(
        &self,
        _params: SelectParams,
    ) -> impl Future<Output = Result<SelectResult, PluginError>> + Send {
        future::ready(Err(PluginError::requirement_not_met(
            vec![Requirement::Scopes {
                scopes: vec!["https://www.googleapis.com/auth/cloud-platform".to_owned()],
            }],
            "the credential lacks a scope",
        )))
    }

    fn env(&self) -> impl Future<Output = Result<EnvResult, PluginError>> + Send {
        future::ready(Ok(EnvResult {
            expires_at: None,
            values: Vec::new(),
        }))
    }

    fn sign_out(&self) -> impl Future<Output = Result<SignOutResult, PluginError>> + Send {
        future::ready(Ok(SignOutResult(Map::new())))
    }
}

// The tests.

#[tokio::test]
async fn calls_before_configure_get_not_configured() -> TestResult {
    let mut app = App::start(Fake::default())?;
    let response = app.call(json!(1), "detect", detect_params()).await?;
    assert_error(&response, &json!(1), -32000, "notConfigured");

    app.configure().await?;
    let response = app.call(json!(2), "detect", detect_params()).await?;
    assert_eq!(
        response,
        json!({"jsonrpc": "2.0", "id": 2, "result": {"found": false}})
    );
    Ok(())
}

#[tokio::test]
async fn an_unsupported_protocol_version_is_refused_and_configures_nothing() -> TestResult {
    let mut app = App::start(Fake::default())?;
    let response = app
        .call(
            json!(1),
            "configure",
            configure_params("2", CALLER, &runbooks_limits()),
        )
        .await?;
    assert_error(&response, &json!(1), -32000, "unsupportedProtocolVersion");

    let response = app.call(json!(2), "detect", detect_params()).await?;
    assert_error(&response, &json!(2), -32000, "notConfigured");
    Ok(())
}

#[tokio::test]
async fn a_line_that_is_not_a_request_is_answered_and_the_next_is_read() -> TestResult {
    let mut app = App::start(Fake::default())?;
    app.configure().await?;
    for (line, id, code) in [
        ("{not json", json!(null), -32700),
        ("[1, 2]", json!(null), -32600),
        (
            r#"{"jsonrpc":"2.0","method":"detect","params":{}}"#,
            json!(null),
            -32600,
        ),
        (r#"{"jsonrpc":"2.0","id":5}"#, json!(5), -32600),
        (
            r#"{"jsonrpc":"1.0","id":6,"method":"detect","params":{}}"#,
            json!(6),
            -32600,
        ),
        (
            r#"{"jsonrpc":"2.0","id":7,"method":"detect","params":[]}"#,
            json!(7),
            -32600,
        ),
    ] {
        app.send(line).await?;
        assert_error(&app.receive().await?, &id, code, "invalidParams");
    }

    let response = app.call(json!(8), "detect", detect_params()).await?;
    assert_eq!(at(&response, "/result/found"), false, "{response}");
    Ok(())
}

#[tokio::test]
async fn a_line_over_the_limit_is_refused_and_the_next_is_read() -> TestResult {
    let mut app = App::start(Fake::default())?;
    app.configure().await?;
    app.send(&"x".repeat(MAX_LINE_BYTES + 1)).await?;
    assert_error(&app.receive().await?, &json!(null), -32600, "invalidParams");

    let response = app.call(json!(1), "detect", detect_params()).await?;
    assert_eq!(at(&response, "/result/found"), false, "{response}");
    Ok(())
}

#[tokio::test]
async fn an_unknown_method_is_not_found() -> TestResult {
    let mut app = App::start(Fake::default())?;
    app.configure().await?;
    let response = app.call(json!("x"), "describe", json!({})).await?;
    assert_error(&response, &json!("x"), -32601, "invalidParams");
    Ok(())
}

#[tokio::test]
async fn unknown_fields_are_ignored() -> TestResult {
    let mut app = App::start(Fake::default())?;
    app.configure().await?;
    app.send(r#"{"jsonrpc":"2.0","id":3,"method":"targets","params":{"level":"account","addedLater":1},"trace":"t"}"#)
        .await?;
    let response = app.receive().await?;
    assert_eq!(at(&response, "/id"), 3, "{response}");
    assert_eq!(
        at(&response, "/result/targets/0/id"),
        "account",
        "{response}"
    );
    Ok(())
}

#[tokio::test]
async fn a_sign_in_prompt_names_its_request_and_comes_before_the_response() -> TestResult {
    let fake = Fake::default();
    let release = Arc::clone(&fake.release);
    let mut app = App::start(fake)?;
    app.configure().await?;
    app.request(json!("a"), "signIn", sign_in_params()).await?;

    let prompt = app.receive().await?;
    assert_eq!(at(&prompt, "/method"), "signIn.prompt", "{prompt}");
    assert_eq!(at(&prompt, "/params/request"), "a", "{prompt}");
    assert_eq!(at(&prompt, "/params/code"), "ABCD-EFGH", "{prompt}");
    assert_valid(
        "credential.schema.json#/$defs/signInPrompt",
        &at(&prompt, "/params"),
    )?;

    release.notify_one();
    let response = app.receive().await?;
    assert_eq!(at(&response, "/id"), "a", "{response}");
    assert_valid(
        "credential.schema.json#/$defs/signInResult",
        &at(&response, "/result"),
    )
}

#[tokio::test]
async fn overlapping_calls_are_answered_by_id() -> TestResult {
    let fake = Fake::default();
    let release = Arc::clone(&fake.release);
    let mut app = App::start(fake)?;
    app.configure().await?;
    app.request(json!(1), "signIn", sign_in_params()).await?;
    let prompt = app.receive().await?;
    assert_eq!(at(&prompt, "/params/request"), 1, "{prompt}");

    let targets = app
        .call(json!(2), "targets", json!({"level": "account"}))
        .await?;
    assert_eq!(at(&targets, "/id"), 2, "{targets}");

    release.notify_one();
    let signed_in = app.receive().await?;
    assert_eq!(at(&signed_in, "/id"), 1, "{signed_in}");
    assert_eq!(at(&signed_in, "/result/method"), "sso", "{signed_in}");
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn a_call_still_running_a_second_before_its_limit_is_answered_timed_out() -> TestResult {
    let fake = Fake::default();
    let cancelled = Arc::clone(&fake.cancelled);
    let mut app = App::start(fake)?;
    app.configure_with(&json!({"signIn": 1_500})).await?;
    let started = Instant::now();
    app.request(json!(1), "signIn", sign_in_params()).await?;
    app.receive().await?;

    let response = app.receive().await?;
    assert_error(&response, &json!(1), -32000, "timedOut");
    assert_eq!(started.elapsed(), Duration::from_millis(500));
    assert_eq!(cancelled.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn configure_keeps_its_own_limit_and_one_that_times_out_configures_nothing() -> TestResult {
    let mut app = App::start(Fake::default())?;
    let started = Instant::now();
    let params = configure_params(
        PROTOCOL_VERSION,
        HANGING_CALLER,
        &json!({"configure": 1_200}),
    );
    let response = app.call(json!(1), "configure", params).await?;
    assert_error(&response, &json!(1), -32000, "timedOut");
    assert_eq!(started.elapsed(), Duration::from_millis(200));

    let response = app.call(json!(2), "detect", detect_params()).await?;
    assert_error(&response, &json!(2), -32000, "notConfigured");
    Ok(())
}

#[tokio::test]
async fn an_answer_up_to_the_line_limit_is_written_and_a_longer_one_is_internal() -> TestResult {
    let fake = Fake::default();
    let padding = Arc::clone(&fake.padding);
    let mut app = App::start(fake)?;
    app.configure().await?;
    let padded = json!({"level": PADDED});
    let short = app.call(json!(10), "targets", padded.clone()).await?;
    let room = MAX_LINE_BYTES - serde_json::to_string(&short)?.len();

    padding.store(room, Ordering::SeqCst);
    let full = app.call(json!(11), "targets", padded.clone()).await?;
    assert_eq!(serde_json::to_string(&full)?.len(), MAX_LINE_BYTES);
    assert_eq!(at(&full, "/id"), 11);

    padding.store(room + 1, Ordering::SeqCst);
    let over = app.call(json!(12), "targets", padded).await?;
    assert_error(&over, &json!(12), -32000, "internal");

    let failed = app
        .call(json!(13), "targets", json!({"level": OVERSIZED_ERROR}))
        .await?;
    assert_error(&failed, &json!(13), -32000, "internal");
    Ok(())
}

#[tokio::test]
async fn a_prompt_longer_than_a_line_is_not_written_and_fails_the_sign_in() -> TestResult {
    let mut app = App::start(Fake::default())?;
    app.configure().await?;
    let params = json!({"method": OVERSIZED_PROMPT, "fields": {}, "pins": {}, "requirements": []});
    let response = app.call(json!(1), "signIn", params).await?;
    assert_error(&response, &json!(1), -32000, "internal");
    Ok(())
}

#[tokio::test]
async fn closing_the_input_cancels_a_sign_in_in_flight() -> TestResult {
    let fake = Fake::default();
    let cancelled = Arc::clone(&fake.cancelled);
    let mut app = App::start(fake)?;
    app.configure().await?;
    app.request(json!(9), "signIn", sign_in_params()).await?;
    app.receive().await?;

    let (served, mut stdout) = app.close().await?;
    served?;
    assert_eq!(cancelled.load(Ordering::SeqCst), 1);
    assert_eq!(
        timeout(WAIT, stdout.next_line()).await??,
        None,
        "the cancelled sign-in was answered"
    );
    Ok(())
}

#[tokio::test]
async fn a_call_that_panics_is_answered_internal() -> TestResult {
    let mut app = App::start(Fake::default())?;
    app.configure().await?;
    let response = app
        .call(json!(4), "targets", json!({"level": "panic"}))
        .await?;
    assert_error(&response, &json!(4), -32000, "internal");

    let response = app
        .call(json!(5), "targets", json!({"level": "account"}))
        .await?;
    assert_eq!(
        at(&response, "/result/targets/0/id"),
        "account",
        "{response}"
    );
    Ok(())
}

#[tokio::test]
async fn invalid_params_name_the_definition_and_not_the_value() -> TestResult {
    let mut app = App::start(Fake::default())?;
    app.configure().await?;
    let params = json!({"method": "credentials", "fields": "hunter2-secret-access-key", "pins": {}, "requirements": []});
    let response = app.call(json!(6), "signIn", params).await?;
    assert_error(&response, &json!(6), -32602, "invalidParams");
    let message = response
        .pointer("/error/message")
        .and_then(Value::as_str)
        .ok_or("no message")?;
    assert!(message.contains("#/$defs/signInParams"), "{message}");
    assert!(!response.to_string().contains("hunter2"), "{response}");
    Ok(())
}

#[tokio::test]
async fn an_error_keeps_its_kinds_own_fields() -> TestResult {
    let mut app = App::start(Fake::default())?;
    app.configure().await?;
    let response = app
        .call(
            json!(7),
            "select",
            json!({"targets": {"project": "sandbox-1234"}}),
        )
        .await?;
    assert_error(&response, &json!(7), -32000, "requirementNotMet");
    assert_valid(
        "credential.schema.json#/$defs/requirementNotMetData",
        &at(&response, "/error/data"),
    )
}
