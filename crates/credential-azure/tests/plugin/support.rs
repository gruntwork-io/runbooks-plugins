//! The app's side of the protocol, as the transport's own tests drive it:
//! requests over in-memory pipes, and every line the plugin writes checked
//! against the schema.

use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::time::Duration;

use jsonschema::{Draft, Registry, Validator};
use runbooks_credential_azure::host::Host;
use runbooks_plugin_protocol::PROTOCOL_VERSION;
use runbooks_plugin_transport::{CredentialPlugin, ServeError, serve};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, Lines, duplex};
use tokio::task::JoinHandle;
use tokio::time::timeout;

pub(crate) type TestResult = Result<(), Box<dyn Error>>;

/// A host with `vars` on this platform. On Windows it adds the real
/// `SystemRoot`, where the plugin finds icacls.
pub(crate) fn host(vars: impl IntoIterator<Item = (OsString, OsString)>) -> Host {
    let system_root = std::env::var_os("SystemRoot").map(|root| ("SystemRoot".into(), root));
    Host::new(vars.into_iter().chain(system_root), cfg!(windows))
}

/// Longer than any answer takes on a loaded runner; a hang fails the test.
/// Under cargo-mutants' 20-second test timeout, so a mutant that leaves a
/// call unanswered fails the run instead of timing it out.
pub(crate) const WAIT: Duration = Duration::from_secs(10);

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

/// Asserts `value` is valid for a definition in the credential schema.
pub(crate) fn assert_valid(def: &str, value: &Value) -> TestResult {
    validator(&json!({ "$ref": format!("{ROOT}credential.schema.json#/$defs/{def}") }))?
        .validate(value)
        .map_err(|e| format!("{def}: {e} in {value}"))?;
    Ok(())
}

/// The member of `value` at JSON Pointer `pointer`, or `null` if there is none.
pub(crate) fn at(value: &Value, pointer: &str) -> Value {
    value.pointer(pointer).cloned().unwrap_or(Value::Null)
}

/// What Runbooks sends in `callTimeoutsMillis`.
pub(crate) fn runbooks_limits() -> Value {
    json!({"configure": 30_000, "detect": 120_000, "targets": 120_000, "select": 120_000, "env": 120_000, "signOut": 60_000, "signIn": 900_000})
}

/// The error kind of a response, or `None` for a result.
pub(crate) fn error_kind(response: &Value) -> Option<&str> {
    response.pointer("/error/data/kind").and_then(Value::as_str)
}

/// The error message of a response, or `None` for a result.
pub(crate) fn error_message(response: &Value) -> Option<&str> {
    response.pointer("/error/message").and_then(Value::as_str)
}

pub(crate) struct App {
    stdin: Option<DuplexStream>,
    stdout: Lines<BufReader<DuplexStream>>,
    serve: JoinHandle<Result<(), ServeError>>,
    message: Validator,
    /// Every line the plugin wrote, in order.
    pub written: Vec<String>,
    next_id: i64,
}

impl App {
    pub(crate) fn start(plugin: impl CredentialPlugin) -> Result<Self, Box<dyn Error>> {
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
            written: Vec::new(),
            next_id: 0,
        })
    }

    /// Sends a request and returns its id.
    pub(crate) async fn request(
        &mut self,
        method: &str,
        params: Value,
    ) -> Result<i64, Box<dyn Error>> {
        self.next_id += 1;
        let request =
            json!({"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params});
        let stdin = self.stdin.as_mut().ok_or("the plugin's input is closed")?;
        stdin.write_all(request.to_string().as_bytes()).await?;
        stdin.write_all(b"\n").await?;
        Ok(self.next_id)
    }

    /// The plugin's next line, valid for the schema.
    pub(crate) async fn receive(&mut self) -> Result<Value, Box<dyn Error>> {
        let line = timeout(WAIT, self.stdout.next_line())
            .await??
            .ok_or("the plugin's output ended")?;
        let message: Value = serde_json::from_str(&line)?;
        self.message
            .validate(&message)
            .map_err(|e| format!("{line}: {e}"))?;
        self.written.push(line);
        Ok(message)
    }

    /// Calls `method` and returns its response, checking it answers the call.
    pub(crate) async fn call(
        &mut self,
        method: &str,
        params: Value,
    ) -> Result<Value, Box<dyn Error>> {
        let id = self.request(method, params).await?;
        let response = self.receive().await?;
        if at(&response, "/id") != id {
            return Err(format!("expected the response to {id}, got {response}").into());
        }
        Ok(response)
    }

    /// Calls `method` and returns its result, failing on an error response.
    pub(crate) async fn result(
        &mut self,
        method: &str,
        params: Value,
    ) -> Result<Value, Box<dyn Error>> {
        let response = self.call(method, params).await?;
        response
            .get("result")
            .cloned()
            .ok_or_else(|| format!("{method} failed: {response}").into())
    }

    pub(crate) async fn configure(&mut self, state_dir: &Path) -> Result<Value, Box<dyn Error>> {
        let state_dir = state_dir
            .to_str()
            .ok_or("the state directory is not UTF-8")?;
        let result = self
            .result(
                "configure",
                json!({"protocolVersion": PROTOCOL_VERSION, "caller": "runbooks/0.31.0", "stateDir": state_dir, "callTimeoutsMillis": runbooks_limits()}),
            )
            .await?;
        assert_valid("configureResult", &result)?;
        Ok(result)
    }

    /// Closes the plugin's input and waits for `serve` to return.
    pub(crate) async fn close(mut self) -> Result<Vec<String>, Box<dyn Error>> {
        self.stdin = None;
        timeout(WAIT, self.serve).await???;
        while let Some(line) = timeout(WAIT, self.stdout.next_line()).await?? {
            self.written.push(line);
        }
        Ok(self.written)
    }
}

pub(crate) fn detect_params(sources: &Value, pins: &Value, requirements: &Value) -> Value {
    json!({"sources": sources, "pins": pins, "requirements": requirements})
}

pub(crate) fn sign_in_params(method: &str, fields: &Value, pins: &Value) -> Value {
    json!({"method": method, "fields": fields, "pins": pins, "requirements": []})
}

/// The `az-*` sign-in directories in `state`.
pub(crate) fn sign_in_dirs(state: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let mut dirs = Vec::new();
    for entry in fs::read_dir(state)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if name.starts_with("az-") {
            dirs.push(name);
        }
    }
    dirs.sort();
    Ok(dirs)
}

/// An env result's value for `name`, if it set one.
pub(crate) fn env_value<'a>(env: &'a Value, name: &str) -> Option<&'a str> {
    env.pointer("/values")?
        .as_array()?
        .iter()
        .find(|value| value.get("name").is_some_and(|n| n == name))?
        .get("value")?
        .as_str()
}
