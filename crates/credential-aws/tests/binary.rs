//! Runs the binary that ships, with the real AWS SDK, and no network: its
//! only route out is an HTTPS proxy on a loopback port nothing listens on.

use std::error::Error;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn Error>>;

/// Longer than a refused loopback connection takes, even on Windows.
const WAIT: Duration = Duration::from_secs(30);

/// The member of `value` at JSON Pointer `pointer`, or `null` if there is none.
fn at(value: &Value, pointer: &str) -> Value {
    value.pointer(pointer).cloned().unwrap_or(Value::Null)
}

#[test]
fn the_binary_answers_over_stdio_and_reports_an_unreachable_aws_as_network() -> TestResult {
    // A port that was free a moment ago: connecting to it is refused.
    let closed_port = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let mut command = Command::new(env!("CARGO_BIN_EXE_runbooks-credential-aws"));
    command
        .env_clear()
        .env("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
        .env(
            "AWS_SECRET_ACCESS_KEY",
            "test-secret-access-key-as-long-as-a-real",
        )
        .env("HTTPS_PROXY", format!("http://127.0.0.1:{closed_port}"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // Windows cannot open a socket without SystemRoot.
    if let Some(root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", root);
    }
    let mut child = command.spawn()?;
    let mut stdin = child.stdin.take().ok_or("stdin")?;
    let stdout = child.stdout.take().ok_or("stdout")?;

    let (lines, received) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if lines.send(line).is_err() {
                break;
            }
        }
    });
    let mut call = move |id: i64, method: &str, params: Value| -> Result<Value, Box<dyn Error>> {
        let request = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        writeln!(stdin, "{request}")?;
        let line = received.recv_timeout(WAIT)??;
        Ok(serde_json::from_str(&line)?)
    };

    let configured = call(
        1,
        "configure",
        json!({"protocolVersion": "1", "caller": "runbooks/0.31.0", "stateDir": "/unused"}),
    )?;
    assert_eq!(at(&configured, "/result/cloud"), "aws", "{configured}");

    let detected = call(
        2,
        "detect",
        json!({"sources": [{"kind": "env"}], "pins": {}, "requirements": []}),
    )?;
    assert_eq!(at(&detected, "/error/data/kind"), "network", "{detected}");
    let message = detected
        .pointer("/error/message")
        .and_then(Value::as_str)
        .ok_or("message")?;
    assert!(
        message.contains("STS") && message.contains("us-east-1"),
        "{message}"
    );

    // Closing standard input, which `call` owns, stops the plugin.
    drop(call);
    let (exited, status) = mpsc::channel();
    thread::spawn(move || {
        // The test has already failed if nothing is waiting for this.
        let _unwatched = exited.send(child.wait());
    });
    assert!(status.recv_timeout(WAIT)??.success());
    Ok(())
}

#[test]
fn the_binary_exits_with_failure_when_it_cannot_write_its_output_or_its_error() -> TestResult {
    let mut child = Command::new(env!("CARGO_BIN_EXE_runbooks-credential-aws"))
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    // With both readers gone, writing the answer fails, and so does writing
    // that failure to standard error.
    drop(child.stdout.take());
    drop(child.stderr.take());
    let mut stdin = child.stdin.take().ok_or("stdin")?;
    let request = json!({"jsonrpc": "2.0", "id": 1, "method": "configure", "params": {
        "protocolVersion": "1", "caller": "runbooks/0.31.0", "stateDir": "/unused"}});
    writeln!(stdin, "{request}")?;

    let (exited, status) = mpsc::channel();
    thread::spawn(move || {
        // The test has already failed if nothing is waiting for this.
        let _unwatched = exited.send(child.wait());
    });
    // Standard input stays open: the failed write alone ends the plugin.
    let status = status.recv_timeout(WAIT)??;
    drop(stdin);
    assert_eq!(status.code(), Some(1), "{status}");
    Ok(())
}
