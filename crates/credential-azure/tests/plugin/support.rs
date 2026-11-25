//! The app's side of the protocol, as the transport's own tests drive it:
//! requests over in-memory pipes, and every line the plugin writes checked
//! against the schema.

use std::error::Error;
use std::fs;
use std::path::Path;
use std::time::Duration;

use jsonschema::{Draft, Registry, Validator};
use runbooks_plugin_protocol::PROTOCOL_VERSION;
use runbooks_plugin_transport::{CredentialPlugin, ServeError, serve};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, Lines, duplex};
use tokio::task::JoinHandle;
use tokio::time::timeout;

pub type TestResult = Result<(), Box<dyn Error>>;

/// Longer than any answer takes on a loaded runner; a hang fails the test.
const WAIT: Duration = Duration::from_secs(30);

const SCHEMAS: [&str; 2] = ["base.schema.json", "credential.schema.json"];
const ROOT: &str = "json-schema:///";

pub fn validator(schema: &Value) -> Result<Validator, Box<dyn Error>> {
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
pub fn assert_valid(def: &str, value: &Value) -> TestResult {
    validator(&json!({ "$ref": format!("{ROOT}credential.schema.json#/$defs/{def}") }))?
        .validate(value)
        .map_err(|e| format!("{def}: {e} in {value}"))?;
    Ok(())
}

/// The error kind of a response, or `None` for a result.
pub fn error_kind(response: &Value) -> Option<&str> {
    response["error"]["data"]["kind"].as_str()
}

pub struct App {
    stdin: Option<DuplexStream>,
    stdout: Lines<BufReader<DuplexStream>>,
    serve: JoinHandle<Result<(), ServeError>>,
    message: Validator,
    /// Every line the plugin wrote, in order.
    pub written: Vec<String>,
    next_id: i64,
}

impl App {
    pub fn start(plugin: impl CredentialPlugin) -> Result<Self, Box<dyn Error>> {
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
    pub async fn request(&mut self, method: &str, params: Value) -> Result<i64, Box<dyn Error>> {
        self.next_id += 1;
        let request =
            json!({"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params});
        let stdin = self.stdin.as_mut().ok_or("the plugin's input is closed")?;
        stdin.write_all(request.to_string().as_bytes()).await?;
        stdin.write_all(b"\n").await?;
        Ok(self.next_id)
    }

    /// The plugin's next line, valid for the schema.
    pub async fn receive(&mut self) -> Result<Value, Box<dyn Error>> {
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
    pub async fn call(&mut self, method: &str, params: Value) -> Result<Value, Box<dyn Error>> {
        let id = self.request(method, params).await?;
        let response = self.receive().await?;
        if response["id"] != id {
            return Err(format!("expected the response to {id}, got {response}").into());
        }
        Ok(response)
    }

    /// Calls `method` and returns its result, failing on an error response.
    pub async fn result(&mut self, method: &str, params: Value) -> Result<Value, Box<dyn Error>> {
        let response = self.call(method, params).await?;
        match response.get("result") {
            Some(result) => Ok(result.clone()),
            None => Err(format!("{method} failed: {response}").into()),
        }
    }

    pub async fn configure(&mut self, state_dir: &Path) -> Result<Value, Box<dyn Error>> {
        let state_dir = state_dir
            .to_str()
            .ok_or("the state directory is not UTF-8")?;
        let result = self
            .result(
                "configure",
                json!({"protocolVersion": PROTOCOL_VERSION, "caller": "runbooks/0.31.0", "stateDir": state_dir}),
            )
            .await?;
        assert_valid("configureResult", &result)?;
        Ok(result)
    }

    /// Closes the plugin's input and waits for `serve` to return.
    pub async fn close(mut self) -> Result<Vec<String>, Box<dyn Error>> {
        self.stdin = None;
        timeout(WAIT, self.serve).await???;
        while let Some(line) = timeout(WAIT, self.stdout.next_line()).await?? {
            self.written.push(line);
        }
        Ok(self.written)
    }
}

pub fn detect_params(sources: Value, pins: Value, requirements: Value) -> Value {
    json!({"sources": sources, "pins": pins, "requirements": requirements})
}

pub fn sign_in_params(method: &str, fields: Value, pins: Value) -> Value {
    json!({"method": method, "fields": fields, "pins": pins, "requirements": []})
}

/// The `az-*` sign-in directories in `state`.
pub fn sign_in_dirs(state: &Path) -> Result<Vec<String>, Box<dyn Error>> {
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
pub fn env_value<'a>(env: &'a Value, name: &str) -> Option<&'a str> {
    env["values"]
        .as_array()?
        .iter()
        .find(|value| value["name"] == name)?["value"]
        .as_str()
}
